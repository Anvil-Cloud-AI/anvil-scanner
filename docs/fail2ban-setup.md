# Fail2ban Setup Guide

Every server connected to the internet gets hit by bots constantly trying to guess SSH passwords. fail2ban watches your logs and automatically blocks IP addresses that are obviously trying to break in. It's one of the most effective and low-maintenance defenses you can deploy.

---

## What is fail2ban?

fail2ban monitors log files for patterns that indicate brute-force attacks — for example, multiple failed SSH login attempts from the same IP address. When it detects an attack, it automatically adds a temporary firewall rule (using `iptables` or `nftables`) to block that IP address.

**Key concepts:**

- **Jail** — a set of rules for one service (e.g., SSH). Defines what log to watch, what pattern means "failure", and how many failures trigger a ban.
- **Filter** — the regex pattern that defines what a "failure" looks like in the log.
- **Ban** — a firewall rule that drops traffic from the offending IP.
- `bantime` — how long (in seconds) an IP stays banned.
- `findtime` — the time window in which failures are counted.
- `maxretry` — number of failures within `findtime` that triggers a ban.

---

## Step 1: Install fail2ban

**Debian/Ubuntu:**

```bash
sudo apt-get update
sudo apt-get install fail2ban
```

**RHEL/CentOS/Fedora:**

```bash
sudo dnf install fail2ban
sudo systemctl enable fail2ban
```

**Verify it's running:**

```bash
sudo systemctl status fail2ban
```

---

## Step 2: Configure the SSH Jail

fail2ban comes with a built-in `sshd` filter. You just need to enable the jail.

Create or edit `/etc/fail2ban/jail.d/sshd.conf`:

```ini
[sshd]
enabled  = true
port     = ssh
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 5
bantime  = 3600
findtime = 600
```

**What this means:**
- Watch `/var/log/auth.log` (Debian/Ubuntu) — use `/var/log/secure` on RHEL/CentOS
- If an IP fails 5 times within 10 minutes (`findtime = 600`)...
- ...ban it for 1 hour (`bantime = 3600`)

> **Note:** On systems using `journald` instead of log files, use `logpath = %(sshd_log)s` and `backend = systemd` instead.

---

## Step 3: Configure the OpenClaw Jail

anvil-scanner can write this jail configuration automatically. Here's the exact config it deploys:

**Jail config** — `/etc/fail2ban/jail.d/openclaw.conf`:

```ini
[openclaw]
enabled  = true
port     = 18789,18791,9090,19001
filter   = openclaw
logpath  = /var/log/openclaw/access.log
maxretry = 10
bantime  = 3600
findtime = 300
```

**Filter config** — `/etc/fail2ban/filter.d/openclaw.conf`:

```ini
[Definition]
failregex = ^.*\[.*\] .*(401|403|429).*<HOST>.*$
            ^.*<HOST>.*(invalid|unauthorized|forbidden|rate.limit).*$
ignoreregex =
```

**What this means:**
- Watch OpenClaw's access log
- Block IPs that trigger 401 (Unauthorized), 403 (Forbidden), or 429 (Rate Limited) errors, or that show patterns like "invalid" or "unauthorized"
- If an IP does this 10 times within 5 minutes, ban for 1 hour

### Deploy automatically

The jail configuration files above can be copied into place manually following the steps in this guide. Anvil Scanner does not expose a `--fail2ban` flag; use the manual setup steps in Steps 2–3 above to deploy the jails.

---

## Step 4: Apply and Verify

**Restart fail2ban to pick up new jails:**

```bash
sudo systemctl restart fail2ban
```

**Check which jails are active:**

```bash
sudo fail2ban-client status
```

Should show:
```
Status
|- Number of jail:      2
`- Jail list:   openclaw, sshd
```

**Check status of a specific jail:**

```bash
sudo fail2ban-client status sshd
```

Shows: currently banned IPs, total bans since startup, number of failed attempts tracked.

---

## Viewing and Managing Banned IPs

**See currently banned IPs:**

```bash
sudo fail2ban-client status sshd
sudo fail2ban-client status openclaw
```

**See all bans via iptables:**

```bash
sudo iptables -L f2b-sshd -n --line-numbers
```

**Unban an IP address:**

```bash
# Replace 1.2.3.4 with the actual IP
sudo fail2ban-client set sshd unbanip 1.2.3.4
sudo fail2ban-client set openclaw unbanip 1.2.3.4
```

**Test if an IP would match a filter:**

```bash
sudo fail2ban-regex /var/log/auth.log /etc/fail2ban/filter.d/sshd.conf
```

---

## Tuning Recommendations

**Increase ban time for repeat offenders** — add this to your jail config to permanently ban IPs after repeated bans:

```ini
[sshd]
# ... existing config ...
bantime.increment   = true
bantime.factor      = 1
bantime.formula     = ban.Time * (1<<(ban.Count if ban.Count<20 else 20)) * banFactor
bantime.multiplier  = 24
bantime.maxtime     = 86400  # Max 24 hours
```

**Get email alerts** (requires working mail setup):

```ini
[DEFAULT]
destemail = admin@yourserver.com
action = %(action_mwl)s  # ban + send email with whois info and log lines
```

---

## Sources

- [fail2ban documentation](https://fail2ban.readthedocs.io/) — official docs including all configuration options
- [fail2ban GitHub](https://github.com/fail2ban/fail2ban) — source code and issue tracker
- [DigitalOcean: How To Protect SSH with Fail2Ban](https://www.digitalocean.com/community/tutorials/how-to-protect-ssh-with-fail2ban-on-ubuntu-22-04) — practical walkthrough

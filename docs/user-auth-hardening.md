# User & Authentication Hardening Guide

Weak authentication is the #1 way attackers get into systems. This guide covers the user and password checks that Anvil Scanner performs — from finding dangerous account configurations to enforcing strong password policies.

---

## Background: Key Files Explained

Before diving in, here's a plain-English explanation of the relevant files:

- **`/etc/passwd`** — list of all user accounts. Readable by everyone. Contains username, UID, home directory, shell.
- **`/etc/shadow`** — the *actual* password hashes plus expiry settings. Only readable by root. This is where password policy settings are stored per-user.
- **`/etc/login.defs`** — system-wide defaults for new accounts (password age, UID ranges, etc.)
- **`/etc/pam.d/`** — PAM (Pluggable Authentication Modules) configuration. PAM is the system that controls *how* authentication works — password complexity, lockouts, etc. Think of it as middleware between login programs and the actual authentication logic.

---

## AUTH-001 — No Empty Password Accounts

**Why it matters:** An account with no password can be logged into by anyone who knows the username. This is almost certainly a misconfiguration, and it's one of the first things attackers check.

**How to find them:**

```bash
sudo awk -F: '($2 == "" || $2 == "!!" ) {print $1}' /etc/shadow
```

Actually, empty password accounts specifically:

```bash
sudo awk -F: '$2 == "" {print $1}' /etc/shadow
```

**How to fix:**

Set a password for the account:

```bash
sudo passwd <username>
```

Or lock the account entirely if it's a service account that shouldn't log in interactively:

```bash
sudo usermod -L <username>      # Lock (prepends ! to password hash)
sudo usermod -s /usr/sbin/nologin <username>  # Prevent shell login
```

---

## AUTH-002 — No Extra UID 0 Accounts

**Why it matters:** UID 0 is root. Any account with UID 0 has complete, unrestricted access to the entire system. Only one account should ever have UID 0 — the `root` account itself. If you find other accounts with UID 0, they're either a misconfiguration or a backdoor left by an attacker.

**How to find them:**

```bash
awk -F: '$3 == 0 {print $1}' /etc/passwd
```

This should only ever return `root`. Anything else is a red flag.

**How to fix:**

If the account is legitimate but shouldn't have root access:

```bash
# Change their UID to something non-zero (pick an unused UID)
sudo usermod -u 1001 <username>
```

If the account is unknown or suspicious, investigate immediately before removing it:

```bash
# Check when it was last used
sudo lastlog -u <username>
sudo last <username>

# Then if safe to remove:
sudo userdel <username>
```

---

## AUTH-003 — Password Max Age (PASS_MAX_DAYS ≤ 90)

**Why it matters:** If an attacker steals a password hash and cracks it, mandatory password expiry limits how long that stolen credential is useful. 90 days is the industry standard.

### Setting the system-wide default for new accounts

Edit `/etc/login.defs`:

```
PASS_MAX_DAYS   90
PASS_MIN_DAYS   1
PASS_WARN_AGE   14
```

This only affects **new** accounts created after the change.

### Applying to existing accounts

```bash
# Set max age for a specific user
sudo chage -M 90 <username>

# Set for all human users (UID 1000+)
for user in $(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd); do
    sudo chage -M 90 "$user"
done

# Check current settings for a user
sudo chage -l <username>
```

---

## AUTH-004 — Password Minimum Length (≥ 12 characters)

**Why it matters:** Short passwords are easy to crack. Modern GPUs can try billions of passwords per second against an offline hash. A 12-character minimum with complexity requirements makes brute-force attacks impractical.

Password length is enforced by the `pam_pwquality` module (on modern systems) or `pam_cracklib` (older systems).

### Check if pam_pwquality is installed:

```bash
dpkg -l libpam-pwquality 2>/dev/null || rpm -q pam_pwquality 2>/dev/null
```

### Install it if missing:

```bash
# Debian/Ubuntu
sudo apt-get install libpam-pwquality

# RHEL/CentOS/Fedora
sudo dnf install pam_pwquality
```

### Configure `/etc/security/pwquality.conf`:

```
# Minimum length
minlen = 12

# Require at least 1 uppercase letter
ucredit = -1

# Require at least 1 lowercase letter
lcredit = -1

# Require at least 1 digit
dcredit = -1

# Require at least 1 special character
ocredit = -1

# Don't allow passwords that contain the username
usercheck = 1

# Reject passwords that appear in dictionaries
dictcheck = 1
```

### Wire it into PAM:

In `/etc/pam.d/common-password` (Debian/Ubuntu) or `/etc/pam.d/system-auth` (RHEL):

```
password requisite pam_pwquality.so retry=3
```

---

## AUTH-005 — Account Lockout (pam_faillock)

**Why it matters:** Without lockout, an attacker can try unlimited passwords against a local account. `pam_faillock` (or the older `pam_tally2`) counts failed login attempts and temporarily locks the account after too many failures.

### Configure `/etc/security/faillock.conf` (modern systems with pam_faillock):

```
# Lock after 5 failed attempts
deny = 5

# Keep account locked for 15 minutes (900 seconds)
unlock_time = 900

# Count failures within this window (10 minutes)
fail_interval = 600

# Also lock root account (careful with this)
# even_deny_root

# Where to store failure records
dir = /var/run/faillock
```

### Wire it into PAM:

In `/etc/pam.d/common-auth` (Debian/Ubuntu):

```
auth    required    pam_faillock.so preauth silent
auth    [success=1 default=bad] pam_unix.so
auth    [default=die] pam_faillock.so authfail
auth    sufficient  pam_faillock.so authsucc
```

In `/etc/pam.d/common-account`:

```
account required pam_faillock.so
```

### Check and manage locked accounts:

```bash
# View failed attempts for a user
sudo faillock --user <username>

# Unlock a user
sudo faillock --user <username> --reset

# View all currently locked users
sudo faillock
```

### Alternative: pam_tally2 (older systems)

If your system uses `pam_tally2` instead of `pam_faillock`:

```
# In /etc/pam.d/common-auth:
auth required pam_tally2.so deny=5 unlock_time=900 onerr=fail

# Check/reset:
sudo pam_tally2 --user=<username>
sudo pam_tally2 --user=<username> --reset
```

---

## Sources

- [CIS Benchmarks — PAM Configuration](https://www.cisecurity.org/cis-benchmarks/) — specific PAM settings and justifications
- [pam_pwquality documentation](https://github.com/libpwquality/libpwquality/blob/master/doc/man/pam_pwquality.8.pod) — all available options
- [pam_faillock manual](https://man7.org/linux/man-pages/man8/pam_faillock.8.html) — lockout configuration options
- [Linux PAM documentation](http://www.linux-pam.org/Linux-PAM-html/) — understanding how PAM works

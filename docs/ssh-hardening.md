# SSH Hardening Guide

SSH (Secure Shell) is the primary way administrators log into Linux servers remotely. A misconfigured SSH server is one of the most common ways attackers break into systems — either by brute-forcing passwords or exploiting weak encryption. This guide walks you through every SSH check Anvil Scanner performs and exactly how to fix each one.

---

## How to Apply Changes

All SSH settings live in `/etc/ssh/sshd_config`. After editing it:

```bash
# Test your config for syntax errors first (always do this!)
sudo sshd -t

# Then restart SSH to apply changes
sudo systemctl restart sshd
```

> ⚠️ **Warning:** Always test your config before restarting. A broken sshd_config will lock you out on next restart.

---

## SSH-006 — MaxAuthTries ≤ 4

**Why it matters:** This limits how many password attempts an attacker gets before SSH disconnects them. The default (6) gives attackers too many guesses per connection.

**How to fix:**

Open `/etc/ssh/sshd_config` and set:

```
MaxAuthTries 4
```

This means after 4 failed attempts, the connection is dropped.

---

## SSH-008 — LoginGraceTime ≤ 60s

**Why it matters:** This is the window of time an unauthenticated connection is allowed to stay open. A long grace time enables "slow" brute-force attacks that stay under rate-limit radar.

**How to fix:**

```
LoginGraceTime 60
```

60 seconds is plenty for a legitimate user to authenticate. Some guides recommend as low as 30.

---

## SSH-023 — X11Forwarding disabled

**Why it matters:** X11 forwarding lets remote users run graphical applications through your SSH connection. Almost no servers need this, and it creates an unnecessary attack surface (X11 itself has a long history of vulnerabilities).

**How to fix:**

```
X11Forwarding no
```

If you genuinely need GUI apps remotely, consider a VPN instead.

---

## SSH-024 — AllowTcpForwarding disabled

**Why it matters:** TCP forwarding lets SSH act as a tunnel/proxy for arbitrary network traffic. Attackers use this to bounce traffic through your server or bypass firewalls. Unless you specifically need port forwarding, disable it.

**How to fix:**

```
AllowTcpForwarding no
```

If you need it for specific users (e.g., a tunnel for a database), you can scope it:

```
Match User dbadmin
    AllowTcpForwarding yes
```

---

## SSH-029 — PermitUserEnvironment disabled

**Why it matters:** If enabled, this lets users set environment variables via `~/.ssh/environment`. An attacker with write access to that file could use it to manipulate PATH or LD_PRELOAD and escalate privileges.

**How to fix:**

```
PermitUserEnvironment no
```

---

## SSH-030 — LogLevel VERBOSE or INFO

**Why it matters:** SSH logs are your audit trail. If an attacker breaks in, you want to know exactly what they did and when. The default `INFO` is acceptable; `VERBOSE` gives you even more detail including fingerprints of client keys.

**How to fix:**

```
LogLevel VERBOSE
```

Logs go to `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL/CentOS).

---

## SSH-014 — KexAlgorithms (no weak KEX)

**Why it matters:** Key exchange algorithms (KEX) determine how SSH negotiates the session encryption key. Older algorithms like `diffie-hellman-group1-sha1` use 1024-bit keys which can be broken by well-resourced attackers (the LOGJAM attack).

**How to fix:**

Replace or restrict KexAlgorithms to modern ones only:

```
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521
```

Remove any of these weak algorithms if present: `diffie-hellman-group1-sha1`, `diffie-hellman-group14-sha1`, `diffie-hellman-group-exchange-sha1`.

---

## SSH-015 — Ciphers (no weak ciphers)

**Why it matters:** The cipher encrypts the actual data transmitted over the SSH session. Old ciphers like 3DES, RC4 (arcfour), and CBC-mode ciphers are vulnerable to known attacks.

**How to fix:**

```
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
```

**Avoid:** `3des-cbc`, `arcfour*`, `blowfish-cbc`, `cast128-cbc`, and any `*-cbc` cipher.

---

## SSH-016 — MACs (no weak MACs)

**Why it matters:** MACs (Message Authentication Codes) ensure the data hasn't been tampered with in transit. Weak MACs like MD5-based or truncated SHA1 variants are vulnerable.

**How to fix:**

```
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
```

**Avoid:** `hmac-md5*`, `hmac-sha1*`, `umac-64*`.

---

## SSH-041 — authorized_keys permissions

**Why it matters:** If your `~/.ssh/authorized_keys` file is world-readable or world-writable, other users on the system could read your authorized keys or add their own — effectively granting themselves SSH access as you.

**How to fix:**

```bash
chmod 600 ~/.ssh/authorized_keys
chmod 700 ~/.ssh
chown $USER:$USER ~/.ssh/authorized_keys
```

Do this for every user that has SSH access. For root:

```bash
chmod 600 /root/.ssh/authorized_keys
chmod 700 /root/.ssh
```

---

## SSH-042 — sshd_config ownership & permissions

**Why it matters:** If a non-root user can modify `/etc/ssh/sshd_config`, they could reconfigure SSH to allow weaker authentication or even their own backdoor keys.

**How to fix:**

```bash
sudo chown root:root /etc/ssh/sshd_config
sudo chmod 600 /etc/ssh/sshd_config
```

---

## SSH-043 — Host private key permissions (600)

**Why it matters:** SSH host keys (e.g., `/etc/ssh/ssh_host_rsa_key`) are the server's identity. If another user can read them, they could impersonate your server — enabling man-in-the-middle attacks.

**How to fix:**

```bash
sudo chmod 600 /etc/ssh/ssh_host_*_key
sudo chown root:root /etc/ssh/ssh_host_*_key
```

---

## Complete Recommended sshd_config Snippet

Here's a hardened configuration you can drop into `/etc/ssh/sshd_config`. Review it against your specific needs before applying.

```
# Authentication
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PermitUserEnvironment no

# Timeouts & limits
MaxAuthTries 4
LoginGraceTime 60
ClientAliveInterval 300
ClientAliveCountMax 2

# Disable unnecessary features
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
GatewayPorts no
PermitTunnel no

# Logging
LogLevel VERBOSE
SyslogFacility AUTH

# Crypto
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256

# Use Protocol 2 only (should be default on modern OpenSSH)
Protocol 2
```

After saving, always run `sudo sshd -t` to check for syntax errors, then `sudo systemctl restart sshd`.

---

## Sources

- [ssh-audit.com](https://www.ssh-audit.com/hardening_guides.html) — SSH hardening recommendations with version-specific configs
- [CIS Benchmark for Linux (SSH section)](https://www.cisecurity.org/cis-benchmarks/) — industry-standard hardening guide
- [OpenSSH Manual Pages](https://man.openbsd.org/sshd_config) — official documentation for every sshd_config directive
- [Mozilla SSH Guidelines](https://infosec.mozilla.org/guidelines/openssh) — practical, modern SSH config recommendations

# Kernel Hardening Guide

The Linux kernel has dozens of security settings that are turned off by default for compatibility reasons. Enabling them significantly raises the bar for attackers who have already gotten code running on your system. This guide covers the kernel sysctl settings that Anvil-Secure checks.

---

## What is `/etc/sysctl.conf`?

`sysctl` is a way to read and change kernel parameters while the system is running. Think of it as a settings panel for the Linux kernel.

- **Temporary change** (lost on reboot): `sudo sysctl -w net.ipv4.tcp_syncookies=1`
- **Permanent change**: Add the setting to `/etc/sysctl.conf` (or a file in `/etc/sysctl.d/`), then run `sudo sysctl -p` to apply it immediately.

Most distros also apply `/etc/sysctl.d/*.conf` files on boot. A clean approach is to create `/etc/sysctl.d/99-hardening.conf` for your settings.

---

## KERN-001 — ASLR (Address Space Layout Randomization)

**Why it matters:** ASLR randomizes where programs are loaded in memory. Without it, attackers who find a bug in a program can reliably predict where to send their exploit. With ASLR, they have to guess — and guessing wrong usually crashes the process instead of giving them control.

**Check the current value:**

```bash
cat /proc/sys/kernel/randomize_va_space
```

**Recommended value:** `2` (full randomization, including stack, heap, and MMAP)

**How to fix:**

```bash
echo "kernel.randomize_va_space = 2" | sudo tee -a /etc/sysctl.d/99-hardening.conf
sudo sysctl -p /etc/sysctl.d/99-hardening.conf
```

---

## KERN-002 — TCP SYN Cookies

**Why it matters:** A SYN flood attack overwhelms your server by sending thousands of half-open TCP connection requests, filling up the connection table and making the server unresponsive. SYN cookies let the kernel handle this gracefully without running out of memory.

**How to fix:**

```
net.ipv4.tcp_syncookies = 1
```

---

## KERN-003 — Reverse Path Filtering

**Why it matters:** Without this, your server will accept packets that claim to come from an IP address that couldn't have actually reached you via the interface they arrived on. This is used in IP spoofing attacks. Reverse path filtering rejects these obviously fake packets.

**How to fix:**

```
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
```

Value `1` = strict mode. Value `2` = loose mode (acceptable for complex multi-homed setups).

---

## KERN-004 — Disable ICMP Redirect Acceptance

**Why it matters:** ICMP redirects are messages that tell your server to use a different route for network traffic. Attackers on the local network can send fake ICMP redirects to silently redirect your traffic through a machine they control (man-in-the-middle).

**How to fix:**

```
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
```

---

## KERN-005 — Disable ICMP Redirect Sending

**Why it matters:** Your server shouldn't be telling other machines to change their routes. This setting prevents your server from being used to send ICMP redirects at all.

**How to fix:**

```
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
```

---

## KERN-006 — Disable Source Routing

**Why it matters:** Source routing allows a sender to dictate the exact path a packet takes through the network. This is almost never needed and can be abused to bypass network security controls.

**How to fix:**

```
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
```

---

## KERN-007 — Ignore ICMP Broadcast Pings (Smurf Attack Prevention)

**Why it matters:** In a "Smurf attack," an attacker sends a ping to a network's broadcast address with your server's IP spoofed as the source. Every machine on the network replies to your server, flooding it. Ignoring broadcast pings prevents your server from being a victim of this.

**How to fix:**

```
net.ipv4.icmp_echo_ignore_broadcasts = 1
```

---

## KERN-008 — Log Martian Packets

**Why it matters:** "Martian packets" are packets with impossible source addresses (like packets claiming to come from your own IP, from 127.0.0.1, or from non-routable ranges when they shouldn't be). Logging them helps you detect IP spoofing attempts.

**How to fix:**

```
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
```

---

## KERN-009 — Restrict dmesg Access (dmesg_restrict)

**Why it matters:** `dmesg` shows kernel boot and runtime messages, which contain memory addresses, hardware info, and other data useful to an attacker. Restricting access means only root can read it.

**How to fix:**

```
kernel.dmesg_restrict = 1
```

After this, unprivileged users get "Operation not permitted" when running `dmesg`. Use `sudo dmesg` instead.

---

## KERN-010 — Restrict Kernel Pointer Exposure (kptr_restrict)

**Why it matters:** Kernel pointer addresses (shown in `/proc/kallsyms` and other places) help attackers write exploits that defeat ASLR. Restricting access hides these addresses from unprivileged users.

**How to fix:**

```
kernel.kptr_restrict = 2
```

- `1` = hide from unprivileged users
- `2` = hide from everyone except processes with `CAP_SYSLOG` (recommended)

---

## KERN-011 — Disable IPv6 if Unused

**Why it matters:** If you're not using IPv6, it's an unnecessary attack surface. Every protocol that's enabled is another thing to patch, configure, and monitor. If your infrastructure doesn't use IPv6, turn it off.

**How to determine if you need it:**

```bash
ip -6 addr show   # If this shows no addresses except loopback, you probably don't need IPv6
```

**How to disable:**

```
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
```

> **Note:** Some systems rely on IPv6 for internal communication even if you don't use it externally. Test carefully before disabling in production.

---

## Complete Recommended sysctl.conf Snippet

Create `/etc/sysctl.d/99-hardening.conf` with the following content:

```ini
# /etc/sysctl.d/99-hardening.conf
# Kernel hardening settings — applied by Anvil-Secure recommendations

# ASLR - full randomization
kernel.randomize_va_space = 2

# TCP SYN flood protection
net.ipv4.tcp_syncookies = 1

# Reverse path filtering (anti-spoofing)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Disable ICMP redirect acceptance
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Disable sending ICMP redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Ignore ICMP broadcasts (Smurf attack protection)
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Log martian packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Restrict kernel messages (dmesg)
kernel.dmesg_restrict = 1

# Restrict kernel pointer exposure
kernel.kptr_restrict = 2

# Disable IPv6 if not needed (uncomment if applicable)
# net.ipv6.conf.all.disable_ipv6 = 1
# net.ipv6.conf.default.disable_ipv6 = 1
# net.ipv6.conf.lo.disable_ipv6 = 1
```

**Apply immediately:**

```bash
sudo sysctl -p /etc/sysctl.d/99-hardening.conf
```

**Verify a setting:**

```bash
sysctl kernel.randomize_va_space
```

---

## Sources

- [Linux Kernel Documentation — sysctl](https://www.kernel.org/doc/html/latest/admin-guide/sysctl/) — official kernel parameter reference
- [CIS Linux Benchmarks](https://www.cisecurity.org/cis-benchmarks/) — industry hardening standards with specific sysctl values
- [Red Hat Security Hardening Guide](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/security_hardening/index) — practical enterprise hardening guide

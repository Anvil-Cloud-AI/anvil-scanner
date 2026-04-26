# Filesystem Security Guide

Even if attackers can't break into your system from the outside, a misconfigured filesystem can let them escalate privileges once they have a foothold. This guide covers the filesystem checks Anvil-Secure performs — securing temp directories, finding dangerous permissions, and setting safe defaults.

---

## FS-001 / FS-002 — /tmp and /var/tmp Mount Options (noexec, nosuid, nodev)

**Why it matters:** `/tmp` and `/var/tmp` are world-writable directories — any user can write files there. Attackers commonly upload malicious scripts or executables to these directories and then run them. The `noexec`, `nosuid`, and `nodev` mount options prevent this:

- **`noexec`** — prevents executing programs directly from this filesystem
- **`nosuid`** — prevents setuid/setgid bits from taking effect (stops privilege escalation via binaries)
- **`nodev`** — prevents device files from being created or used here

### What is `/etc/fstab`?

`/etc/fstab` is the file that tells Linux how to mount filesystems at boot. Each line describes a filesystem: device, mount point, filesystem type, and options.

**Example `/etc/fstab` entry for /tmp:**

```
tmpfs   /tmp        tmpfs   defaults,rw,nosuid,nodev,noexec,relatime   0 0
tmpfs   /var/tmp    tmpfs   defaults,rw,nosuid,nodev,noexec,relatime   0 0
```

### How to fix:

1. Check if `/tmp` is already a separate mount:

    ```bash
    mount | grep /tmp
    ```

2. If `/tmp` uses `tmpfs`, edit `/etc/fstab` and add the options. If it's part of the root filesystem, you'll need to bind-mount it:

    ```
    tmpfs   /tmp   tmpfs   defaults,nosuid,nodev,noexec   0 0
    ```

3. Apply without rebooting:

    ```bash
    sudo mount -o remount /tmp
    sudo mount -o remount /var/tmp
    ```

4. Verify:

    ```bash
    mount | grep -E '/tmp|/var/tmp'
    # Should show: nosuid, nodev, noexec
    ```

> **Note:** Some applications (package managers, compilers) legitimately need to execute from `/tmp`. If remounting breaks something, you may need to use `/var/tmp` for those applications or mount with `noexec` only on `/tmp` and `nosuid,nodev` on `/var/tmp`.

---

## FS-003 — World-Writable Files (Outside /tmp)

**Why it matters:** A world-writable file is one that any user on the system can modify. If a system script, config file, or log file is world-writable, an attacker with any local account can tamper with it. Outside of `/tmp` and `/var/tmp`, world-writable files are almost always a mistake.

**How to find them:**

```bash
sudo find / -path /proc -prune -o -path /sys -prune -o -path /tmp -prune -o -path /var/tmp -prune \
  -o -perm -002 -not -type l -print 2>/dev/null
```

**How to fix each one:**

Remove world-write permission from the file:

```bash
sudo chmod o-w /path/to/suspicious/file
```

Investigate why the file is world-writable before removing the permission — it may be intentional for a specific application. Check with the application's documentation first.

---

## FS-004 — SUID/SGID Binary Audit

**Why it matters:** A SUID (Set User ID) binary runs with the permissions of the file's *owner*, regardless of who runs it. Many are owned by root — so any vulnerability in a SUID binary can be exploited by any user to gain root access. SGID works the same way but with the file's *group*. The fewer SUID/SGID binaries on your system, the smaller your attack surface.

### Common legitimate SUID binaries

These are expected and generally safe:

```
/usr/bin/passwd
/usr/bin/sudo
/usr/bin/su
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/pkexec
/bin/ping
/bin/mount
/bin/umount
```

### How to find ALL SUID/SGID binaries:

```bash
sudo find / -path /proc -prune -o -path /sys -prune \
  -o \( -perm -4000 -o -perm -2000 \) -type f -print 2>/dev/null
```

### How to audit them:

For each binary you don't recognize:

1. Check what it is: `ls -la /path/to/binary && dpkg -S /path/to/binary`
2. Check if it's needed: Is it installed by a package you use?
3. If not needed, either remove it or strip the SUID bit:

```bash
# Remove SUID bit (safer than deleting — the binary still works for root)
sudo chmod u-s /path/to/unnecessary/suid/binary

# Or remove SGID bit
sudo chmod g-s /path/to/unnecessary/sgid/binary
```

> **Be careful:** Removing SUID from something like `sudo` or `passwd` will break those programs. Only remove it from binaries you've confirmed are unnecessary.

---

## FS-005 — Default umask (≥ 027)

**Why it matters:** When a program creates a new file, the `umask` determines the default permissions. A weak umask (like the default `022`) means new files are world-readable. A tighter umask (`027` or `077`) means new files are only accessible to the owner and their group — limiting accidental data exposure.

### Understanding umask

umask is a *subtraction* from the maximum permissions (`666` for files, `777` for directories):

- `umask 022` → files get `644` (rw-r--r--), directories get `755`
- `umask 027` → files get `640` (rw-r-----), directories get `750`
- `umask 077` → files get `600` (rw-------), directories get `700`

### Where to set umask:

**System-wide for login sessions** — edit `/etc/login.defs`:

```
UMASK 027
```

**System-wide for all interactive shells** — edit `/etc/profile` or create `/etc/profile.d/umask.sh`:

```bash
# /etc/profile.d/umask.sh
umask 027
```

**Check current umask:**

```bash
umask
```

**Apply immediately in current shell:**

```bash
umask 027
```

> **Note:** A `umask` of `077` is most restrictive but can break applications that expect files to be group-readable. Start with `027` and test your applications.

---

## Sources

- [CIS Benchmarks — Linux Filesystem Security](https://www.cisecurity.org/cis-benchmarks/) — detailed mount option and permission requirements
- [Linux `fstab` manual](https://man7.org/linux/man-pages/man5/fstab.5.html) — official fstab documentation
- [NIST SP 800-123 — Guide to General Server Security](https://csrc.nist.gov/publications/detail/sp/800-123/final) — filesystem security in server hardening context

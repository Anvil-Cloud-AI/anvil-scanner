# macOS Hardening Guide

macOS comes with solid security foundations, but several important protections are either disabled by default or need verification. This guide covers the macOS checks Anvil-Secure performs and how to fix each one via the Terminal or System Settings.

---

## MACOS-001 — System Integrity Protection (SIP)

**Why it matters:** SIP (System Integrity Protection) prevents any process — even running as root — from modifying protected system files and directories like `/System`, `/usr`, and `/bin`. It was introduced in OS X El Capitan (10.11) to stop malware from permanently embedding itself in macOS.

**Check status:**

```bash
csrutil status
```

Should return: `System Integrity Protection status: enabled.`

**How to fix if disabled:**

SIP can only be enabled from Recovery Mode. Apple intentionally makes this hard to do accidentally:

1. Shut down your Mac
2. **Apple Silicon:** Hold the power button until "Loading startup options" appears → click Options → Continue
   **Intel Mac:** Hold `Command + R` while booting until the Apple logo appears
3. Open Terminal from the Utilities menu
4. Run:

```bash
csrutil enable
```

5. Restart

> ⚠️ There is almost no legitimate reason to disable SIP on a production machine. If SIP is disabled and you didn't do it, treat this as a potential security incident.

---

## MACOS-002 — FileVault (Full Disk Encryption)

**Why it matters:** FileVault encrypts your entire startup disk. Without it, anyone who steals your Mac can plug it into another computer and read every file on it — even without your login password.

**Check status:**

```bash
fdesetup status
```

Should return: `FileVault is On.`

**How to enable:**

**Via System Settings (macOS Ventura+):**
1. Open System Settings → Privacy & Security
2. Scroll to FileVault
3. Click "Turn On..."
4. Follow the prompts — save your recovery key somewhere safe (not on the Mac itself!)

**Via Terminal:**

```bash
sudo fdesetup enable
```

> **Note:** Encryption runs in the background and may take hours on a full drive. The Mac remains usable during this time.

---

## MACOS-003 — Gatekeeper

**Why it matters:** Gatekeeper checks that apps are signed by an identified developer and, for apps from outside the App Store, haven't been tampered with. Without it, malware masquerading as a legitimate app can run freely.

**Check status:**

```bash
spctl --status
```

Should return: `assessments enabled`

**How to enable:**

```bash
sudo spctl --master-enable
```

**Via System Settings (Ventura+):**
1. System Settings → Privacy & Security
2. Under "Security", set "Allow applications downloaded from" to "App Store and identified developers"

---

## MACOS-004 — Application Firewall

**Why it matters:** macOS's built-in application firewall controls which applications can receive incoming network connections. This is separate from the network-level firewall — it operates at the application layer and is particularly useful for laptops that connect to untrusted networks.

**Check status:**

```bash
/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
```

Should return: `Firewall is enabled.`

**How to enable:**

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on
```

**Via System Settings (Ventura+):**
1. System Settings → Network → Firewall
2. Toggle to On

**Enable stealth mode** (don't respond to ping/port probes):

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on
```

---

## MACOS-005 — Remote Login (SSH) Restricted

**Why it matters:** "Remote Login" is macOS's way of saying SSH is enabled. If SSH is enabled and not restricted, anyone who can reach your Mac on the network can attempt to log in. Restricting it to specific users limits the blast radius if an account is compromised.

**Check if SSH is running:**

```bash
sudo systemsetup -getremotelogin
```

**How to disable Remote Login entirely (if you don't need it):**

```bash
sudo systemsetup -setremotelogin off
```

**How to restrict to specific users only:**

Via System Settings (Ventura+):
1. System Settings → General → Sharing
2. Click the ℹ️ next to Remote Login
3. Change "Allow access for" from "All users" to "Only these users" and add the specific users

**Via Terminal:**

```bash
# Allow only specific users (replace user1, user2 with actual usernames)
sudo dscl . -create /Groups/com.apple.access_ssh
sudo dscl . -append /Groups/com.apple.access_ssh GroupMembership user1 user2
```

---

## MACOS-006 — Screen Sharing Disabled

**Why it matters:** Screen sharing (VNC) lets someone see and control your Mac remotely. Unless you specifically need this feature, it should be off. It's a common target for attackers on local networks.

**Check status:**

```bash
sudo launchctl list | grep screensharing
```

If this returns output, screen sharing is running.

**How to disable:**

```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.screensharing.plist
```

**Via System Settings (Ventura+):**
1. System Settings → General → Sharing
2. Toggle Screen Sharing off

---

## MACOS-007 — Automatic Login Disabled

**Why it matters:** Automatic login bypasses the login screen entirely — anyone who opens the lid or presses the power button gets straight to your desktop. This completely negates the benefit of a login password on a stolen device.

**Check:**

```bash
sudo defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null
```

If this returns a username, automatic login is enabled.

**How to disable:**

```bash
sudo defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser
```

**Via System Settings (Ventura+):**
1. System Settings → General → Login Items & Extensions (or Users & Groups on older macOS)
2. Under the Login Options section, set "Automatic login" to Off

---

## MACOS-008 — Firmware Password (Intel Macs)

**Why it matters:** A firmware password (called EFI password on Intel Macs) prevents someone from booting from a USB drive, entering Recovery Mode, or changing startup disk settings without the password. This protects against physical access attacks.

> **Note:** Apple Silicon Macs (M1/M2/M3/M4) use a different mechanism (Activation Lock) and don't have a traditional firmware password. This check only applies to Intel-based Macs.

**Check status (Intel only):**

```bash
sudo firmwarepasswd -check
```

**How to set a firmware password:**

1. Restart in Recovery Mode: hold `Command + R` while booting
2. From the Utilities menu, open Firmware Password Utility (or Security Utility on older versions)
3. Click "Turn On Firmware Password" and set a strong password
4. Restart

**Or via command line in Recovery Mode:**

```bash
firmwarepasswd -setpasswd
```

> ⚠️ **Store this password somewhere safe.** If you forget it, recovering access requires visiting an Apple Store with proof of purchase.

---

## Sources

- [Apple Platform Security Guide](https://support.apple.com/guide/security/welcome/web) — comprehensive Apple documentation on security features
- [CIS macOS Benchmark](https://www.cisecurity.org/cis-benchmarks/) — specific configuration requirements and test procedures
- [macOS Security and Privacy Guide](https://github.com/drduh/macOS-Security-and-Privacy-Guide) — community-maintained deep-dive hardening guide

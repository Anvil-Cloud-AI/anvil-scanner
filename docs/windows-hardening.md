# Windows Hardening Guide

Windows security depends on several key services and settings. This guide explains each Anvil Scanner Windows check and how to verify or fix it.

---

## WIN-000 — Windows Platform Detection

**What it is:** An informational check that detects and reports your Windows SKU — either **Windows 11 (Client)** or **Windows Server**.

**Why it matters:** Different Windows versions may have different hardening configurations available. Knowing your SKU helps tailor recommendations.

**Check status:** Run:

```powershell
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v InstallationType
```

Will show either `Client` or `Server Edition`.

---

## WIN-FW-001 — Windows Defender Firewall

**Why it matters:** The Windows Defender Firewall (formerly Windows Firewall) is your system's first line of defense against unauthorized network access. It must be enabled on all three profiles (Domain, Private, and Public) to protect you in any network context.

**Check status:** Run:

```powershell
Get-NetFirewallProfile | Select-Object Name,Enabled
```

Should show three profiles (Domain, Private, Public) all with `Enabled: True`.

**How to enable if disabled:**

**Via Settings (Windows 11):**
1. Open **Settings** → **Privacy & Security** → **Windows Security** → **Firewall & network protection**
2. For each profile (Domain network, Private network, Public network), click it and toggle the firewall **On**

**Via PowerShell:**

```powershell
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
```

> ⚠️ Enabling the firewall may block some applications you expect to use. If applications stop working, you can add exceptions in Firewall & network protection → **Allow an app through the firewall**.

---

## WIN-AV-001 — Microsoft Defender Antivirus

**Why it matters:** Microsoft Defender Antivirus provides real-time protection against malware, viruses, and other threats. Real-time protection (not just periodic scanning) catches threats immediately as they arrive.

**Check status:** Run:

```powershell
Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled
```

Should show:
- `AntivirusEnabled: True`
- `RealTimeProtectionEnabled: True`

**How to enable if disabled:**

**Via Settings (Windows 11):**
1. Open **Settings** → **Privacy & Security** → **Windows Security** → **Virus & threat protection**
2. Under "Virus & threat protection settings", toggle **Real-time protection** **On**

**Via PowerShell (admin):**

```powershell
Set-MpPreference -DisableRealtimeMonitoring $false
```

> **Note:** On some Windows Server configurations, Defender may not be installed at all. In this case, consider alternative antivirus solutions like Windows Defender for Server, or configure your organization's standard endpoint protection.

---

## WIN-SMB-001 — SMBv1 Protocol Disabled

**Why it matters:** SMB version 1 (SMBv1) is an old network file-sharing protocol with known critical vulnerabilities. Modern systems should use SMB2 or SMB3. Disabling SMBv1 prevents attacks that leverage decades-old exploits (WannaCry, NotPetya).

**Check status:** Run:

```powershell
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol
```

Should show `EnableSMB1Protocol: False`.

**How to disable if enabled:**

**Via Settings (Windows 11):**
1. Open **Settings** → **Apps** → **Optional features** → **More Windows features**
2. Find **SMB 1.0/CIFS File Sharing Support** and uncheck it
3. Restart your computer

**Via PowerShell (admin):**

```powershell
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
```

> ⚠️ If you have legacy systems that connect to your computer via SMB (e.g., very old printers or file servers), disabling SMBv1 may break those connections. Verify compatibility before disabling in production.

---

## WIN-RDP-001 — Remote Desktop Configuration

**Why it matters:** Remote Desktop Protocol (RDP) allows you to access your computer remotely, but it is a frequent attack target. This check ensures either RDP is disabled (if you don't use it) or requires Network Level Authentication (NLA), which adds an extra password layer before the RDP session begins.

**Check status:** Run:

```powershell
[pscustomobject]@{
  DenyTS=(Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction SilentlyContinue).fDenyTSConnections;
  NLA=(Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -ErrorAction SilentlyContinue).UserAuthentication
} | ConvertTo-Json
```

Should show one of:
- `fDenyTSConnections: 1` (RDP disabled) — PASS
- `UserAuthentication: 1` (NLA required) — PASS

**How to fix:**

**Option 1: Disable RDP (if you don't use it):**
1. Open **Settings** → **System** → **Remote Desktop**
2. Toggle **Remote Desktop** **Off**

**Option 2: Require Network Level Authentication (if you do use RDP):**
1. Open **Settings** → **System** → **Remote Desktop**
2. Enable **Require devices to use Network Level Authentication (NLA)**

**Via PowerShell (admin):**

```powershell
# Disable RDP:
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 1

# Or enable NLA (and enable RDP):
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1
```

> ⚠️ If you rely on RDP for remote access, only choose Option 1 if you have another way to access your system. Option 2 (NLA) is safer and maintains RDP functionality.

---

## WIN-UAC-001 — User Account Control (UAC)

**Why it matters:** User Account Control (UAC) is Windows's elevation prompt system. When enabled, it requires confirmation before programs can make system-wide changes, preventing malware from silently modifying your system without your knowledge.

**Check status:** Run:

```powershell
Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA | Select-Object EnableLUA
```

Should show `EnableLUA: 1` (or `True`).

**How to enable if disabled:**

**Via Settings (Windows 11):**
1. Open **Settings** → **Privacy & Security** → **User Account Control settings**
2. Drag the slider to the highest setting ("Always notify me when...")
3. Click **OK**

**Via PowerShell (admin):**

```powershell
Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1
```

Then restart your computer.

> **Note:** UAC prompts can feel intrusive, but they are a critical security feature. Avoid lowering the UAC level unless you are in a fully trusted environment.

---

## WIN-UPD-001 — Windows Update Service

**Why it matters:** The Windows Update service ensures your system receives critical security patches, driver updates, and feature updates. If this service is disabled, your system will not receive security updates — even if updates are available.

**Check status:** Run:

```powershell
Get-Service wuauserv | Select-Object Status,StartType
```

Should show:
- `Status: Running` (service is currently active)
- `StartType: Automatic` (service starts automatically at boot)

Avoid:
- `Status: Stopped` or `StartType: Disabled` (Windows Update is off)

**How to enable if disabled:**

**Via Settings (Windows 11):**
1. Open **Settings** → **System** → **Windows Update**
2. Click **Check for updates** to trigger an immediate update check
3. This will also restore the Windows Update service if it was disabled

**Via PowerShell (admin):**

```powershell
# Enable the Windows Update service
Set-Service -Name wuauserv -StartupType Automatic
Start-Service -Name wuauserv

# Trigger an update check
usoclient StartInstall
```

> ⚠️ Updates may require a restart. Schedule them at a convenient time, and ensure you have a backup or recovery plan before applying major updates to production systems.

---

## Summary

Anvil Scanner's Windows checks verify six key hardening controls. All are read-only — no admin required. Fixing them is straightforward:

1. **WIN-FW-001** — Enable Windows Defender Firewall on all profiles
2. **WIN-AV-001** — Enable Microsoft Defender Antivirus with real-time protection
3. **WIN-SMB-001** — Disable SMBv1 protocol
4. **WIN-RDP-001** — Disable RDP or require Network Level Authentication
5. **WIN-UAC-001** — Enable User Account Control
6. **WIN-UPD-001** — Keep Windows Update service enabled and set to automatic

See also: [Anvil Scanner README](../README.md) for usage on Windows and [Main Documentation Index](index.md).

# Lenovo + McAfee Debloat (Windows PowerShell)

Small, self-contained PowerShell scripts to find and remove the pre-installed
Lenovo + McAfee bloatware that slows down consumer/commercial Lenovo laptops.
No install, no dependencies — Windows PowerShell 5.1+.

## Scripts

| Script | What it does | Admin? |
|---|---|---|
| `Analyze-Lenovo.ps1` | **Read-only** report: removable bloat + sizes, what's kept, other Lenovo/McAfee software, and what runs at startup. Never removes anything. | No |
| `Debloat-Lenovo-Paste.ps1` | **Copy-paste** version. Paste the whole block into an elevated PowerShell; it shows the report, then asks you to type `YES` before removing. | Yes (to remove) |
| `Debloat-Lenovo.ps1` | File version with flags (`-Remove`, `-Force`, `-Yes`). Same report → type `YES` → uninstall. | Yes (with `-Remove`) |

## Usage

**Analyze (safe, no changes):**
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Analyze-Lenovo.ps1
```

**Remove (elevated PowerShell — Run as administrator):**
```powershell
.\Debloat-Lenovo.ps1 -Remove
```
…or open an elevated PowerShell and paste the entire contents of
`Debloat-Lenovo-Paste.ps1`. It prints the report, then waits for you to type
`YES` (capitals) before uninstalling.

## What it targets

**Lenovo:** Now / AI Now, App Explorer, Smart Note, Welcome, Migration Assistant,
Family Cloud, Smart Meeting / AI Meeting Manager, View / Smart Noise Cancellation,
Voice, WiFi Security (Coronet), Glance by Mirametrix, Quick Clean, Vantage +
Vantage Service, Speech, Universal Device Client (UDC — service + scheduled tasks).

**McAfee:** WebAdvisor, Security Scan Plus, Safe Connect (VPN), Personal Security
(Store), LiveSafe / Total Protection — the AV suite is removed **only when Windows
Defender is actively protecting the machine**, otherwise it is kept.

## Safety

Never touches: device drivers, audio/Dolby, power/battery/thermal, hotkeys,
TrackPoint/touchpad, chipset, BIOS/firmware, fingerprint/biometrics, TPM/BitLocker,
Management Engine, the **Lenovo System Interface Foundation / ImController**
(keeps battery charge-limit, Fn keys, and firmware updates working), or whatever
is registered as the **active antivirus**. Removal always requires typing `YES`.

> Test with `Analyze-Lenovo.ps1` first. Use at your own risk.

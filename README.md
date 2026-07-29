# Lenovo + McAfee Debloat (Windows PowerShell)

Small, self-contained PowerShell scripts to find and remove the pre-installed
Lenovo + McAfee bloatware that slows down consumer/commercial Lenovo laptops.
No install, no dependencies — Windows PowerShell 5.1+.

## Scripts

| Script | What it does | Admin? |
|---|---|---|
| `Debloat-Lenovo-Paste.ps1` | **Copy-paste version — this is the one to send people.** Paste the whole block into an elevated PowerShell; it shows the report, then asks you to type `YES` before removing. Not elevated = report only. | Yes (to remove) |
| `Analyze-Lenovo.ps1` | **Read-only** report: removable bloat + sizes, what's kept, other Lenovo/McAfee software, and what runs at startup. Cannot remove anything. | No |
| `Debloat-Lenovo.ps1` | File version with flags. Same report → type `YES` → uninstall. **Edit this one** — the other two are generated from it. | Yes (with `-Remove`) |
| `Build-Variants.ps1` | Regenerates the two derived scripts from `Debloat-Lenovo.ps1`. | No |

`Debloat-Lenovo-Paste.ps1` and `Analyze-Lenovo.ps1` are **generated**. Change
`Debloat-Lenovo.ps1`, then run `.\Build-Variants.ps1`. Editing a generated file
directly will be overwritten on the next build.

## Usage

**Analyze (safe, no changes):**
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Analyze-Lenovo.ps1
```

**Remove (elevated PowerShell — Run as administrator):**
```powershell
.\Debloat-Lenovo.ps1 -Remove
```
…or open an elevated **Windows PowerShell** and paste the entire contents of
`Debloat-Lenovo-Paste.ps1`. It prints the report, then waits for you to type
`YES` (capitals) before uninstalling.

Use Windows PowerShell 5.1, not PowerShell 7 — Store-app removal goes through a
compatibility shim in 7 and is less reliable.

### Flags (`Debloat-Lenovo.ps1`)

| Flag | Effect |
|---|---|
| `-Remove` | actually uninstall (still prompts for `YES`) |
| `-Force` | remove McAfee even when it is the *active* antivirus |
| `-Yes` | skip the `YES` prompt and the closing pause (unattended) |
| `-SkipOrphans` | leave vendor folders that have no uninstall entry alone |
| `-TimeoutSec` | per-uninstaller time limit, default 300 |

## How removal works

A plain "run the UninstallString" approach fails on most of these products. This
script:

1. **Stops the product's own services and processes first.** An uninstaller
   cannot delete files that are locked by a running process. This is why
   Smart Meeting (`VirtualCameraService`) and WebAdvisor (`uihost` + its
   service) used to fail with `exit 1`.
2. **Runs the vendor's own `QuietUninstallString` verbatim** when the registry
   provides one, instead of substituting invented switches.
3. Falls back to the silent switches that match the installer type — Inno
   Setup, NSIS, MSI, or generic — trying them one at a time.
4. **Confirms by checking the uninstall registry key is gone.** Exit codes are
   not trusted: some uninstallers relaunch themselves from `%TEMP%` and the
   first process exits immediately with a meaningless code.
5. **Cleans up the leftovers** — startup `Run` entries, scheduled tasks, and the
   emptied install folder.

It also finds vendor folders with **no uninstall entry at all** (Ready For
Assistant / SmartConnect, Warranty Viewer), which never appeared in any report
before because they are invisible to the uninstall registry.

## What it targets

**Lenovo:** Now / AI Now, App Explorer, Smart Note, Welcome, Migration Assistant,
Family Cloud, Smart Meeting / AI Meeting Manager, View / Smart Noise Cancellation,
Voice, WiFi Security (Coronet), Glance by Mirametrix, Quick Clean, Vantage +
Vantage Service, Speech, Universal Device Client (UDC — service + scheduled tasks),
Ready For Assistant / SmartConnect, Warranty Viewer.

**McAfee:** WebAdvisor, Security Scan Plus, Safe Connect (VPN), Personal Security
(Store), LiveSafe / Total Protection — the AV suite is removed **only when Windows
Defender is actively protecting the machine**, otherwise it is kept.

## Safety

Never touches: device drivers, audio/Dolby, power/battery/thermal, hotkeys,
TrackPoint/touchpad, chipset, BIOS/firmware, fingerprint/biometrics, TPM/BitLocker,
Management Engine, the **Lenovo System Interface Foundation / ImController**
(keeps battery charge-limit, Fn keys, and firmware updates working), or whatever
is registered as the **active antivirus**. Removal always requires typing `YES`.

Folder deletion is deliberately narrow: only strict subfolders of
`Program Files\Lenovo` / `Program Files\McAfee`, never a vendor root itself,
never a name matching the protected list, and never a folder that still has a
running process inside it.

> Test with `Analyze-Lenovo.ps1` first. Use at your own risk.

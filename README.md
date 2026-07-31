# Lenovo + McAfee Debloat (Windows PowerShell)

**One file: [`Debloat-Lenovo.ps1`](Debloat-Lenovo.ps1).** No install, no
dependencies, no flags to remember. Windows PowerShell 5.1+.

It decides what to do from the window it is running in:

| Window | What happens |
|---|---|
| Ordinary PowerShell | **Check only.** Full report of what would be cleaned. Changes nothing. |
| **Administrator** PowerShell | Same report, then asks you to type `YES`, and only then removes anything. |

It works pasted into a console **or** saved and run as a `.ps1`. Nothing is
deleted until you type `YES`.

## For a non-technical colleague

> 1. Copy the whole script.
> 2. Click **Start**, type `PowerShell`, open it, paste, press **Enter**.
>    You get a report. Nothing on your PC changes.
> 3. To actually clean up: open PowerShell again, but **right-click → Run as
>    administrator**, paste the same thing, and type `YES` when it asks.

Use **Windows PowerShell**, not PowerShell 7 — Store-app removal goes through a
compatibility shim in 7 and is less reliable.

The report ends with a plain-English summary: how much disk space would be
freed and from which programs, which apps would stop launching at boot, which
background processes would be closed, what is deliberately kept, and what is
never touched.

## Optional flags (only when run as a file)

| Flag | Effect |
|---|---|
| `-CheckOnly` | report even in an Administrator window |
| `-Force` | remove McAfee even when it is the *active* antivirus |
| `-Yes` | skip the `YES` prompt and the closing pause (unattended) |
| `-SkipOrphans` | leave vendor folders that have no uninstall entry alone |
| `-TimeoutSec` | per-uninstaller time limit, default 300 |

## How removal works

Running the `UninstallString` and trusting the exit code fails on most of these
products. This script:

1. **Stops the product's own services and processes first.** An uninstaller
   cannot delete files locked by a running process. This is why Smart Meeting
   (`VirtualCameraService`) and WebAdvisor (`uihost` + its service) used to
   fail with `exit 1`.
2. **Runs the vendor's own `QuietUninstallString` verbatim** when the registry
   provides one, instead of substituting invented switches.
3. Falls back to the silent switches matching the installer type — Inno Setup,
   NSIS, MSI, or generic — one at a time.
4. **Confirms by checking the uninstall registry key is gone.** Exit codes are
   not trusted: some uninstallers relaunch from `%TEMP%` and the first process
   exits immediately with a meaningless code.
5. **Cleans up the leftovers** — `Run`/`RunOnce` entries, Startup-folder
   shortcuts, scheduled tasks, and the emptied install folder.

Startup apps are handled as their own final step, so an entry still gets
switched off even if its program fails to uninstall.

It also finds vendor folders with **no uninstall entry at all** (Ready For
Assistant / SmartConnect, Warranty Viewer) — invisible to the uninstall
registry, so they never appeared in any report before.

## What it targets

**Lenovo:** Now / AI Now, App Explorer, Smart Note, Welcome, Migration Assistant,
Family Cloud, Smart Meeting / AI Meeting Manager, View / Smart Noise Cancellation,
Voice, WiFi Security (Coronet), Glance by Mirametrix, Quick Clean, Vantage +
Vantage Service, Speech, Universal Device Client (UDC), Ready For Assistant /
SmartConnect, Warranty Viewer.

**McAfee:** WebAdvisor, Security Scan Plus, Safe Connect (VPN), Personal Security
(Store), LiveSafe / Total Protection — the AV suite is removed **only when Windows
Defender is actively protecting the machine**, otherwise it is kept.

## Safety

Never touches: device drivers, audio/Dolby, power/battery/thermal, hotkeys,
TrackPoint/touchpad, chipset, BIOS/firmware, fingerprint/biometrics, TPM/BitLocker,
Management Engine, the **Lenovo System Interface Foundation / ImController**
(keeps battery charge-limit, Fn keys, and firmware updates working), or whatever
is registered as the **active antivirus**.

Folder deletion is deliberately narrow: only strict subfolders of
`Program Files\Lenovo` / `Program Files\McAfee`, never a vendor root itself,
never a name matching the protected list, and never a folder that still has a
running process inside it.

> Run it in an ordinary window first and read the report. Use at your own risk.

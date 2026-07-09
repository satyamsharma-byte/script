<#
    Analyze-Lenovo.ps1  -  READ-ONLY. Reports the Lenovo + McAfee software on this
    PC: what is removable bloat, what is kept (drivers / antivirus / dual-use), any
    other Lenovo/McAfee software present, and which of it runs at startup.

    It NEVER removes anything and needs no admin (run it anywhere). To actually
    uninstall, use  Debloat-Lenovo.ps1 -Remove  in an elevated PowerShell.

    HOW TO RUN (either works):
      powershell -NoProfile -ExecutionPolicy Bypass -File .\Analyze-Lenovo.ps1
    or right-click the file > Run with PowerShell.
    (Best with admin: seeing all-users Store apps needs admin; Win32 programs are
    detected either way.)
#>
$ErrorActionPreference = 'Stop'

# ── Bloat catalog ─────────────────────────────────────────────────────────
$Bloat = @(
  @{ Name='Lenovo Now / AI Now';            Kind='both'; Patterns=@('*Lenovo Now*','*LenovoNow*','*AINow*','*Lenovo AI Now*') }
  @{ Name='Lenovo App Explorer';            Kind='win32';Patterns=@('*App Explorer*') }
  @{ Name='Lenovo Smart Note';              Kind='both'; Patterns=@('*Smart Note*','*SmartNote*') }
  @{ Name='Lenovo Welcome';                 Kind='win32';Patterns=@('*Lenovo Welcome*') }
  @{ Name='Lenovo Migration Assistant';     Kind='win32';Patterns=@('*Migration Assistant*') }
  @{ Name='Lenovo Family Cloud';            Kind='win32';Patterns=@('*Family Cloud*','*FamilyCloud*') }
  @{ Name='Lenovo Smart Meeting / AI Meeting Manager'; Kind='both'; Patterns=@('*Smart Meeting*','*SmartMeeting*','*Meeting Manager*') }
  @{ Name='Lenovo View / Smart Noise Cancellation / Appearance'; Kind='both'; Patterns=@('*Lenovo View*','*Smart Noise Cancellation*','*SmartAppearance*') }
  @{ Name='Lenovo Voice';                   Kind='win32';Patterns=@('*Lenovo Voice*') }
  @{ Name='Lenovo WiFi Security (Coronet)'; Kind='win32';Patterns=@('*WiFi Security*','*Coronet*') }
  @{ Name='Glance by Mirametrix';           Kind='win32';Patterns=@('*Glance by Mirametrix*','*Mirametrix*') }
  @{ Name='Lenovo Quick Clean';             Kind='both'; Patterns=@('*Quick Clean*','*QuickClean*') }
  @{ Name='Lenovo Vantage / Commercial Vantage + Vantage Service'; Kind='both'; Patterns=@('*Lenovo Vantage*','*LenovoCompanion*','*Commercial Vantage*','*LenovoSettingsforEnterprise*') }
  @{ Name='Lenovo Speech';                  Kind='win32';Patterns=@('*Lenovo Speech*') }
  @{ Name='Lenovo Universal Device Client (UDC)'; Kind='service'; Service='UDCService'; TaskLike='*UDC*'; Patterns=@('*Universal Device Client*') }
  @{ Name='McAfee WebAdvisor';              Kind='win32';Patterns=@('*WebAdvisor*','*SiteAdvisor*') }
  @{ Name='McAfee Security Scan Plus';      Kind='win32';Patterns=@('*Security Scan Plus*','*Security Scan*') }
  @{ Name='McAfee Safe Connect (VPN)';      Kind='win32';Patterns=@('*Safe Connect*') }
  @{ Name='McAfee Personal Security (Store)';Kind='appx'; Patterns=@('*McAfeeSecurity*','*McAfee Personal Security*') }
  @{ Name='McAfee LiveSafe / Total Protection (AV suite)'; Kind='win32'; IsAV=$true; Patterns=@('*McAfee LiveSafe*','*McAfee Total Protection*','*McAfee*Protection*') }
)
$GuardRegex = '(?i)(\bdriver\b|realtek|\bintel\b|nvidia|\bamd\b|synaptics|\belan\b|dolby|\baudio\b|codec|System Interface Foundation|ImController|hotkey|Power Management|Power and Battery|Intelligent Thermal|thermal|cooling|TrackPoint|UltraNav|touchpad|chipset|\bbios\b|firmware|fingerprint|biometric|Management Engine|\bTPM\b|BitLocker)'

# ── Helpers (read-only) ─────────────────────────────────────────────────────
function Get-InstalledWin32 {
  $roots = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
    'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
  )
  $list = @()
  foreach ($r in $roots) { foreach ($p in (Get-ItemProperty -Path $r -ErrorAction SilentlyContinue)) {
    if (-not $p.DisplayName -or $p.SystemComponent -eq 1) { continue }
    $list += [pscustomobject]@{ Name=[string]$p.DisplayName; Publisher=[string]$p.Publisher; SizeMB= if ($p.EstimatedSize) { [math]::Round($p.EstimatedSize/1KB,1) } else { $null } } } }
  $list | Sort-Object Name -Unique
}
function Get-ActiveAvNames { try { Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop | ForEach-Object {
  $on=$false; try { $on = (([Convert]::ToInt32(('{0:x6}' -f [int]$_.productState).Substring(2,2),16)) -band 0x10) -ne 0 } catch {}
  if ($on) { $_.displayName } } } catch { @() } }
function Test-AnyLike { param($Value,$Patterns) foreach ($p in $Patterns) { if ($Value -and ($Value -like $p)) { return $true } } $false }

# ── Scan (read-only) ────────────────────────────────────────────────────────
Write-Host ""
Write-Host ("===== Lenovo + McAfee bloatware - ANALYSIS ({0}  {1}) =====" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyy-MM-dd HH:mm')) -ForegroundColor Cyan
Write-Host "READ-ONLY: this script only looks. It never removes anything." -ForegroundColor DarkGray
$win32 = Get-InstalledWin32
$activeAv = @(Get-ActiveAvNames)
if ($activeAv) { Write-Host ("Active antivirus: {0}" -f ($activeAv -join ', ')) -ForegroundColor DarkGray }
$defenderActive = (@($activeAv | Where-Object { $_ -match '(?i)defender|microsoft' }).Count -gt 0)
if (-not $defenderActive) { try { $mp = Get-MpComputerStatus -ErrorAction Stop; if ($mp.AMRunningMode -eq 'Normal' -or ($mp.AntivirusEnabled -and $mp.RealTimeProtectionEnabled)) { $defenderActive = $true } } catch {} }
Write-Host ("Windows Defender protecting: {0}" -f $(if ($defenderActive) { 'YES - McAfee (incl. AV suite) can be removed' } else { 'NO - McAfee AV suite will be KEPT for protection' })) -ForegroundColor DarkGray

$removable = @(); $kept = @(); $matchedNames = @()
foreach ($item in $Bloat) {
  $matchesW = @(); if ($item.Kind -ne 'appx') { $matchesW = @($win32 | Where-Object { Test-AnyLike $_.Name $item.Patterns }) }
  $appxNames = @()
  if ($item.Kind -eq 'appx' -or $item.Kind -eq 'both') {
    $pk=@(); try { $pk = Get-AppxPackage -AllUsers -ErrorAction Stop } catch { try { $pk = Get-AppxPackage -ErrorAction Stop } catch {} }
    $appxNames = @($pk | Where-Object { $n=$_.Name; ($item.Patterns | Where-Object { $n -like $_ }) } | Select-Object -Expand Name -Unique)
  }
  $svcHit = $null; if ($item.Service) { try { $svcHit = Get-Service -Name $item.Service -ErrorAction SilentlyContinue } catch {} }
  $taskHits = @(); if ($item.TaskLike) { try { $taskHits = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -like $item.TaskLike }) } catch {} }
  if ($matchesW.Count -eq 0 -and $appxNames.Count -eq 0 -and -not $svcHit -and $taskHits.Count -eq 0) { continue }
  $matchedNames += @($matchesW | Select-Object -Expand Name)
  $sz = ($matchesW | Measure-Object SizeMB -Sum).Sum
  $guardHit = $null; foreach ($m in $matchesW) { if (($m.Name -match $GuardRegex) -or ([string]$m.Publisher -match $GuardRegex)) { $guardHit = $m.Name; break } }
  if ($guardHit)   { $kept += "$($item.Name)  (protected: $guardHit)"; continue }
  if ($item.Caution) { $kept += "$($item.Name)  (dual-use - Vantage also does firmware/driver updates)"; continue }
  if ($item.IsAV -and -not $defenderActive) { $kept += "$($item.Name)  (kept - no active Windows Defender to fall back on)"; continue }
  $removable += [pscustomobject]@{ Name=$item.Name; SizeMB=[double]$sz }
}

# Every Lenovo/McAfee-published program present, so nothing looks hidden.
$vendorAll = @($win32 | Where-Object { $_.Name -match '(?i)lenovo|mcafee' -or $_.Publisher -match '(?i)lenovo|mcafee' })
$vendorOther = @($vendorAll | Where-Object { $matchedNames -notcontains $_.Name })

# Startup entries that belong to Lenovo/McAfee (a common slowness source).
$startup = @()
foreach ($k in @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run')) {
  try { $p = Get-ItemProperty -Path $k -ErrorAction Stop } catch { continue }
  $p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
    if (("$($_.Name) $($_.Value)") -match '(?i)lenovo|mcafee|vantage|mirametrix|glance') { $startup += ("Run: {0}" -f $_.Name) } }
}
try { Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.State -ne 'Disabled' -and ("$($_.TaskName) $($_.TaskPath)") -match '(?i)lenovo|mcafee|vantage|mirametrix' } |
  ForEach-Object { $startup += ("Task: {0}" -f $_.TaskName) } } catch {}
$startup = @($startup | Sort-Object -Unique)

# ── Report ──────────────────────────────────────────────────────────────────
$total = ($removable | Measure-Object SizeMB -Sum).Sum
Write-Host ""
if ($removable.Count) {
  Write-Host ("[1] REMOVABLE BLOAT  ({0} item(s), ~{1:n0} MB) - safe to uninstall:" -f $removable.Count, $total) -ForegroundColor Green
  foreach ($r in $removable) { $s = if ($r.SizeMB) { " (~{0:n0} MB)" -f $r.SizeMB } else { '' }; Write-Host ("     - {0}{1}" -f $r.Name, $s) }
} else {
  Write-Host "[1] REMOVABLE BLOAT: none found." -ForegroundColor Green
}

Write-Host ""
if ($kept.Count) {
  Write-Host "[2] KEPT ON PURPOSE (dual-use / antivirus / system):" -ForegroundColor DarkYellow
  $kept | ForEach-Object { Write-Host "     - $_" -ForegroundColor DarkYellow }
} else { Write-Host "[2] KEPT ON PURPOSE: none." -ForegroundColor DarkYellow }

Write-Host ""
if ($vendorOther.Count) {
  Write-Host ("[3] OTHER LENOVO / McAFEE SOFTWARE PRESENT (not targeted by this tool) - {0}:" -f $vendorOther.Count) -ForegroundColor Gray
  foreach ($v in $vendorOther) { $s = if ($v.SizeMB) { " (~{0:n0} MB)" -f $v.SizeMB } else { '' }; Write-Host ("     - {0}{1}" -f $v.Name, $s) -ForegroundColor Gray }
  Write-Host "     (mostly drivers/utilities - left alone on purpose.)" -ForegroundColor DarkGray
} else { Write-Host "[3] OTHER LENOVO / McAFEE SOFTWARE PRESENT: none." -ForegroundColor Gray }

Write-Host ""
if ($startup.Count) {
  Write-Host ("[4] OF THAT, RUNS AT STARTUP ({0}) - impacts boot/RAM:" -f $startup.Count) -ForegroundColor Magenta
  $startup | ForEach-Object { Write-Host "     - $_" -ForegroundColor Magenta }
} else { Write-Host "[4] RUNS AT STARTUP: no Lenovo/McAfee startup entries found." -ForegroundColor Magenta }

Write-Host ""
Write-Host "===== SUMMARY =====" -ForegroundColor Cyan
Write-Host ("  Removable bloat : {0} item(s), ~{1:n0} MB reclaimable" -f $removable.Count, $total)
Write-Host ("  Kept on purpose : {0}" -f $kept.Count)
Write-Host ("  Other vendor sw : {0}" -f $vendorOther.Count)
Write-Host ("  Startup entries : {0}" -f $startup.Count)
Write-Host "  Nothing was changed - this was analysis only." -ForegroundColor Green
if ($removable.Count) { Write-Host "  To remove [1]: run  Debloat-Lenovo.ps1 -Remove  in an elevated PowerShell." -ForegroundColor Yellow }
Write-Host ""

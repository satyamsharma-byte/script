# ============================================================================
#  Lenovo + McAfee de-bloat  -  COPY-PASTE version.
#  Share this whole block on chat. To use it:
#    1) Start menu > type PowerShell > right-click > Run as administrator
#    2) Paste this ENTIRE block into that window and press Enter.
#  It shows what it found; if the window is Administrator it asks you to type
#  YES before removing anything. Not admin = it only shows the report.
# ============================================================================
& {
  $ErrorActionPreference = 'Stop'

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

  function Test-Admin { try { (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch { $false } }
  function Get-InstalledWin32 {
    $roots = @('HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*')
    $list = @()
    foreach ($r in $roots) { foreach ($p in (Get-ItemProperty -Path $r -ErrorAction SilentlyContinue)) {
      if (-not $p.DisplayName -or $p.SystemComponent -eq 1) { continue }
      $list += [pscustomobject]@{ Name=[string]$p.DisplayName; Publisher=[string]$p.Publisher; SizeMB= if ($p.EstimatedSize) { [math]::Round($p.EstimatedSize/1KB,1) } else { $null }; Quiet=[string]$p.QuietUninstallString; Uninstall=[string]$p.UninstallString } } }
    $list | Sort-Object Name -Unique
  }
  function Get-ActiveAvNames { try { Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop | ForEach-Object {
    $on=$false; try { $on = (([Convert]::ToInt32(('{0:x6}' -f [int]$_.productState).Substring(2,2),16)) -band 0x10) -ne 0 } catch {}
    if ($on) { $_.displayName } } } catch { @() } }
  function Test-AnyLike { param($Value,$Patterns) foreach ($p in $Patterns) { if ($Value -and ($Value -like $p)) { return $true } } $false }
  function Remove-Win32Program { param($p)
    $u = if ($p.Quiet) { $p.Quiet } else { $p.Uninstall }
    if (-not $u) { return 'no uninstall command' }
    if ($u -match 'msiexec') { $g = [regex]::Match($u,'\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}'); if ($g.Success) { $pr = Start-Process msiexec.exe -ArgumentList "/x $($g.Value) /qn /norestart" -Wait -PassThru -WindowStyle Hidden; return "exit $($pr.ExitCode)" } }
    if ($u -match '(?i)unins\d*\.exe') { $exe = (($u -replace '(?i)(unins\d*\.exe).*$','$1')).Trim().Trim('"'); if (Test-Path -LiteralPath $exe) { $pr = Start-Process -FilePath $exe -ArgumentList '/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART' -Wait -PassThru; return "exit $($pr.ExitCode)" } }
    $pr = Start-Process cmd.exe -ArgumentList '/c', $u -Wait -PassThru; return "exit $($pr.ExitCode)"
  }
  function Remove-LenovoService { param($ServiceName,$TaskLike)
    $did=@()
    if ($ServiceName) { $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
      if ($svc) { if (($svc.DisplayName -match $GuardRegex) -or ($ServiceName -match $GuardRegex)) { return "protected service $ServiceName - kept" }
        try { Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue } catch {}; & sc.exe delete $ServiceName | Out-Null; $did += "service $ServiceName deleted" } }
    if ($TaskLike) { try { Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -like $TaskLike } | ForEach-Object { try { Unregister-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath -Confirm:$false -ErrorAction Stop; $did += "task $($_.TaskName) removed" } catch {} } } catch {} }
    if ($did) { $did -join '; ' } else { 'nothing to remove' }
  }
  function Remove-AppxByPattern { param($Pattern)
    $done = @()
    try { Get-AppxPackage -AllUsers -ErrorAction Stop | Where-Object { $_.Name -like $Pattern } | ForEach-Object { try { Remove-AppxPackage -Package $_.PackageFullName -AllUsers -ErrorAction Stop; $done += $_.Name } catch {} } } catch {}
    try { Get-AppxProvisionedPackage -Online -ErrorAction Stop | Where-Object { $_.DisplayName -like $Pattern -or $_.PackageName -like $Pattern } | ForEach-Object { try { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName -ErrorAction Stop | Out-Null; $done += ('prov:'+$_.DisplayName) } catch {} } } catch {}
    if ($done) { 'removed ' + ($done -join ', ') } else { 'no matching Store package' }
  }

  Write-Host ""
  Write-Host ("===== Lenovo + McAfee De-bloat  ({0}  {1}) =====" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyy-MM-dd HH:mm')) -ForegroundColor Cyan
  $isAdmin = Test-Admin
  Write-Host ("Administrator: {0}" -f $(if ($isAdmin) { 'YES' } else { 'NO (report only - re-open as Administrator to remove)' })) -ForegroundColor DarkGray
  $win32 = Get-InstalledWin32
  $activeAv = @(Get-ActiveAvNames)
  if ($activeAv) { Write-Host ("Active antivirus: {0}" -f ($activeAv -join ', ')) -ForegroundColor DarkGray }
  $defenderActive = (@($activeAv | Where-Object { $_ -match '(?i)defender|microsoft' }).Count -gt 0)
  if (-not $defenderActive) { try { $mp = Get-MpComputerStatus -ErrorAction Stop; if ($mp.AMRunningMode -eq 'Normal' -or ($mp.AntivirusEnabled -and $mp.RealTimeProtectionEnabled)) { $defenderActive = $true } } catch {} }
  Write-Host ("Windows Defender protecting: {0}" -f $(if ($defenderActive) { 'YES - McAfee (incl. AV suite) can be removed' } else { 'NO - McAfee AV suite will be KEPT for protection' })) -ForegroundColor DarkGray

  $targets = @(); $skipped = @(); $matchedNames = @()
  foreach ($item in $Bloat) {
    $matchesW = @(); if ($item.Kind -ne 'appx') { $matchesW = @($win32 | Where-Object { Test-AnyLike $_.Name $item.Patterns }) }
    $appxNames = @()
    if ($item.Kind -eq 'appx' -or $item.Kind -eq 'both') { $pk=@(); try { $pk = Get-AppxPackage -AllUsers -ErrorAction Stop } catch { try { $pk = Get-AppxPackage -ErrorAction Stop } catch {} }
      $appxNames = @($pk | Where-Object { $n=$_.Name; ($item.Patterns | Where-Object { $n -like $_ }) } | Select-Object -Expand Name -Unique) }
    $svcHit = $null; if ($item.Service) { try { $svcHit = Get-Service -Name $item.Service -ErrorAction SilentlyContinue } catch {} }
    $taskHits = @(); if ($item.TaskLike) { try { $taskHits = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -like $item.TaskLike }) } catch {} }
    if ($matchesW.Count -eq 0 -and $appxNames.Count -eq 0 -and -not $svcHit -and $taskHits.Count -eq 0) { continue }
    $matchedNames += @($matchesW | Select-Object -Expand Name)
    $guardHit = $null; foreach ($m in $matchesW) { if (($m.Name -match $GuardRegex) -or ([string]$m.Publisher -match $GuardRegex)) { $guardHit = $m.Name; break } }
    if ($guardHit)   { $skipped += "$($item.Name)  (protected: $guardHit)"; continue }
    if ($item.Caution) { $skipped += "$($item.Name)  (dual-use - kept)"; continue }
    if ($item.IsAV -and -not $defenderActive) { $skipped += "$($item.Name)  (kept - no active Windows Defender fallback)"; continue }
    $sz = ($matchesW | Measure-Object SizeMB -Sum).Sum
    $targets += [pscustomobject]@{ Name=$item.Name; Item=$item; Win32=$matchesW; SizeMB=[double]$sz }
  }

  $vendorAll   = @($win32 | Where-Object { $_.Name -match '(?i)lenovo|mcafee' -or $_.Publisher -match '(?i)lenovo|mcafee' })
  $vendorOther = @($vendorAll | Where-Object { $matchedNames -notcontains $_.Name })
  $startup = @()
  foreach ($k in @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run')) {
    try { $p = Get-ItemProperty -Path $k -ErrorAction Stop } catch { continue }
    $p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { if (("$($_.Name) $($_.Value)") -match '(?i)lenovo|mcafee|vantage|mirametrix|glance') { $startup += ("Run: {0}" -f $_.Name) } } }
  try { Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.State -ne 'Disabled' -and ("$($_.TaskName) $($_.TaskPath)") -match '(?i)lenovo|mcafee|vantage|mirametrix' } | ForEach-Object { $startup += ("Task: {0}" -f $_.TaskName) } } catch {}
  $startup = @($startup | Sort-Object -Unique)

  $total = ($targets | Measure-Object SizeMB -Sum).Sum
  Write-Host ""
  if ($targets.Count) { Write-Host ("[1] REMOVABLE BLOAT  ({0} item(s), ~{1:n0} MB):" -f $targets.Count, $total) -ForegroundColor Green
    foreach ($t in $targets) { $s = if ($t.SizeMB) { " (~{0:n0} MB)" -f $t.SizeMB } else { '' }; Write-Host ("     - {0}{1}" -f $t.Name, $s) } }
  else { Write-Host "[1] REMOVABLE BLOAT: none found." -ForegroundColor Green }
  Write-Host ""
  if ($skipped.Count) { Write-Host "[2] KEPT (dual-use / antivirus / protected):" -ForegroundColor DarkYellow; $skipped | ForEach-Object { Write-Host "     - $_" -ForegroundColor DarkYellow } } else { Write-Host "[2] KEPT: none." -ForegroundColor DarkYellow }
  Write-Host ""
  if ($vendorOther.Count) { Write-Host ("[3] OTHER LENOVO / McAFEE SOFTWARE PRESENT (not touched) - {0}:" -f $vendorOther.Count) -ForegroundColor Gray
    foreach ($v in $vendorOther) { $s = if ($v.SizeMB) { " (~{0:n0} MB)" -f $v.SizeMB } else { '' }; Write-Host ("     - {0}{1}" -f $v.Name, $s) -ForegroundColor Gray } } else { Write-Host "[3] OTHER LENOVO / McAFEE SOFTWARE PRESENT: none." -ForegroundColor Gray }
  Write-Host ""
  if ($startup.Count) { Write-Host ("[4] OF THAT, RUNS AT STARTUP ({0}):" -f $startup.Count) -ForegroundColor Magenta; $startup | ForEach-Object { Write-Host "     - $_" -ForegroundColor Magenta } } else { Write-Host "[4] RUNS AT STARTUP: none found." -ForegroundColor Magenta }
  Write-Host ""
  Write-Host "===== SUMMARY =====" -ForegroundColor Cyan
  Write-Host ("  Removable bloat : {0} item(s), ~{1:n0} MB" -f $targets.Count, $total)
  Write-Host ("  Kept            : {0}" -f $skipped.Count)
  Write-Host ("  Other vendor sw : {0}" -f $vendorOther.Count)
  Write-Host ("  Startup entries : {0}" -f $startup.Count)

  if ($targets.Count -eq 0) { Write-Host ""; Write-Host "Nothing to remove. Done." -ForegroundColor Green; return }
  if (-not $isAdmin) { Write-Host ""; Write-Host "Report only (not Administrator). To remove the [1] items:" -ForegroundColor Yellow; Write-Host "  re-open PowerShell as Administrator, paste this again, and type YES." -ForegroundColor Yellow; return }

  Write-Host ""
  $ans = Read-Host ("Type YES (capitals) to permanently remove the {0} item(s) above, ~{1:n0} MB - anything else keeps them" -f $targets.Count, $total)
  if ($ans -cne 'YES') { Write-Host "Kept - nothing was removed." -ForegroundColor Yellow; return }

  Write-Host ""
  $removed=0; $failed=0; $freed=0.0
  foreach ($t in $targets) {
    Write-Host ("Removing {0} ..." -f $t.Name) -ForegroundColor Green
    $ok=$false
    foreach ($m in $t.Win32) { try { $r = Remove-Win32Program $m; Write-Host ("   program '{0}' -> {1}" -f $m.Name, $r); if ($r -match 'exit 0|exit 3010') { $ok=$true } } catch { Write-Host ("   '{0}' FAILED: {1}" -f $m.Name, $_.Exception.Message) -ForegroundColor Red } }
    if ($t.Item.Kind -eq 'appx' -or $t.Item.Kind -eq 'both') { foreach ($pat in $t.Item.Patterns) { try { $r = Remove-AppxByPattern $pat; if ($r -notmatch '^no matching') { Write-Host ("   appx '{0}' -> {1}" -f $pat, $r); $ok=$true } } catch {} } }
    if ($t.Item.Kind -eq 'service') { try { $r = Remove-LenovoService $t.Item.Service $t.Item.TaskLike; Write-Host ("   service/tasks -> {0}" -f $r); if ($r -notmatch '^nothing') { $ok=$true } } catch { Write-Host ("   service/tasks FAILED: {0}" -f $_.Exception.Message) -ForegroundColor Red } }
    if ($ok) { $removed++; if ($t.SizeMB) { $freed += $t.SizeMB } } else { $failed++ }
  }
  Write-Host ""
  Write-Host "===== REMOVAL DONE =====" -ForegroundColor Cyan
  Write-Host ("  Removed: {0}   Failed: {1}   (~{2:n0} MB freed)" -f $removed, $failed, $freed) -ForegroundColor Green
  Write-Host "  A reboot is recommended to finish any pending removals." -ForegroundColor DarkCyan
}

<#
    Debloat-Lenovo.ps1  -  Remove Lenovo + McAfee bloatware.

    THE ONLY FILE YOU NEED. There are no flags to remember - it decides what to
    do from the window it is running in:

      Ordinary PowerShell window   ->  CHECK ONLY. Prints a full report of what
                                       would be cleaned up. Changes nothing.
      Administrator window         ->  Prints the same report, then asks you to
                                       type YES, and only then removes anything.

    It works BOTH ways: paste the whole file into a PowerShell window, or save
    it and run it as a .ps1 file. Nothing is deleted until you type YES.

    HOW TO USE IT (what to tell a non-technical colleague)
      1. Copy the whole thing.
      2. Click Start, type PowerShell, open it, paste, press Enter.
         -> you get a report. Nothing changes.
      3. To clean up: open PowerShell again but right-click > Run as
         administrator, paste the same thing, and type YES when asked.

    HOW REMOVAL WORKS (this is why it now succeeds where it used to fail)
      1. Stops the product's own services and processes first - an uninstaller
         cannot delete files that are still running / locked.
      2. Runs the vendor's own QuietUninstallString VERBATIM when the registry
         provides one, instead of inventing switches.
      3. If there is no quiet string, tries the silent switches that match the
         installer type (Inno / NSIS / MSI / generic), one at a time.
      4. Confirms the uninstall by checking the registry key is GONE - the exit
         code is not trusted, because some uninstallers relaunch themselves from
         %TEMP% and the first process exits immediately with a junk code.
      5. Cleans up what the uninstaller leaves behind: startup Run entries,
         scheduled tasks, and the now-empty install folder.

    OPTIONAL FLAGS (only when run as a .ps1 file - nobody needs these)
      -CheckOnly        report even in an Administrator window, change nothing.
      -Force            allow removing McAfee even if it's the ACTIVE antivirus
                        (otherwise skipped - prefer McAfee's MCPR tool).
      -Yes              skip the "type YES" prompt AND the "Press Enter to close"
                        pause (for unattended use).
      -SkipOrphans      do not touch leftover vendor folders that have no
                        uninstall entry (Ready For Assistant, Warranty Viewer...).
      -TimeoutSec       per-uninstaller time limit, default 300.

    SAFETY - never removes: drivers, power/thermal, hotkeys, touchpad, audio,
    TPM/BitLocker/biometrics, the Lenovo System Interface Foundation (ImController),
    or whatever is registered as the active antivirus. Never stops a service or
    kills a process whose name matches the protected list.
#>
# NOTE: no "#Requires" line. Pasted into a console it errors with "An error
# occurred while creating the pipeline" before anything runs, which looks like
# a broken script to a non-technical user. The version is checked at run time
# instead, further down.
[CmdletBinding()]
param([switch]$CheckOnly, [switch]$Force, [switch]$Yes,
      [switch]$SkipOrphans, [int]$TimeoutSec = 300)

$ErrorActionPreference = 'Stop'

# -- Bloat catalog ---------------------------------------------------------
# Kind: win32 | appx | both | service | folder   (folder = no uninstaller exists)
$Bloat = @(
  @{ Name='Lenovo Now / AI Now';            Kind='both'; Patterns=@('*Lenovo Now*','*LenovoNow*','*AINow*','*Lenovo AI Now*') }
  @{ Name='Lenovo App Explorer';            Kind='win32';Patterns=@('*App Explorer*') }
  @{ Name='Lenovo Smart Note';              Kind='both'; Patterns=@('*Smart Note*','*SmartNote*') }
  @{ Name='Lenovo Welcome';                 Kind='win32';Patterns=@('*Lenovo Welcome*') }
  @{ Name='Lenovo Migration Assistant';     Kind='win32';Patterns=@('*Migration Assistant*') }
  @{ Name='Lenovo Family Cloud';            Kind='win32';Patterns=@('*Family Cloud*','*FamilyCloud*') }
  # Interactive=$true: confirmed on a real machine to pop its own confirmation
  # window that no silent switch suppresses. The user has to click it.
  @{ Name='Lenovo Smart Meeting / AI Meeting Manager'; Kind='both'; Interactive=$true; Patterns=@('*Smart Meeting*','*SmartMeeting*','*Meeting Manager*') }
  # '*Smart Appearance*' with the space: the Store app E0469640.SmartAppearance
  # was being removed while "Lenovo Smart Appearance Components" (151 MB, the
  # Win32 half of the same product) sat untouched because only the space-less
  # spelling was listed.
  @{ Name='Lenovo View / Smart Noise Cancellation / Appearance'; Kind='both'; Patterns=@('*Lenovo View*','*Smart Noise Cancellation*','*SmartAppearance*','*Smart Appearance*') }
  @{ Name='Lenovo Voice';                   Kind='win32';Patterns=@('*Lenovo Voice*') }
  @{ Name='Lenovo WiFi Security (Coronet)'; Kind='win32';Patterns=@('*WiFi Security*','*Coronet*') }
  @{ Name='Glance by Mirametrix';           Kind='win32';Patterns=@('*Glance by Mirametrix*','*Mirametrix*') }
  @{ Name='Lenovo Quick Clean';             Kind='both'; Patterns=@('*Quick Clean*','*QuickClean*') }
  # Folders: Vantage's uninstaller leaves ~40 MB behind in VantageService.
  @{ Name='Lenovo Vantage / Commercial Vantage + Vantage Service'; Kind='both'
     Patterns=@('*Lenovo Vantage*','*LenovoCompanion*','*Commercial Vantage*','*LenovoSettingsforEnterprise*')
     Folders=@('%ProgramFiles(x86)%\Lenovo\VantageService','%ProgramFiles%\Lenovo\VantageService') }
  @{ Name='Lenovo Speech';                  Kind='win32';Patterns=@('*Lenovo Speech*') }
  @{ Name='Lenovo Universal Device Client (UDC)'; Kind='service'; Service='UDCService'; TaskLike='*UDC*'; Patterns=@('*Universal Device Client*') }
  @{ Name='McAfee WebAdvisor';              Kind='win32'; Interactive=$true; Patterns=@('*WebAdvisor*','*SiteAdvisor*') }
  @{ Name='McAfee Security Scan Plus';      Kind='win32';Patterns=@('*Security Scan Plus*','*Security Scan*') }
  @{ Name='McAfee Safe Connect (VPN)';      Kind='win32';Patterns=@('*Safe Connect*') }
  # IsAV: on current consumer stock the preinstalled McAfee is this MSIX package,
  # and once activated it is the SecurityCenter2-registered real-time antivirus.
  # Without IsAV the AV gate never evaluated it, so Remove-AppxPackage -AllUsers
  # stripped the live antivirus with no -Force, no keep and no warning - and on a
  # machine with both halves it removed the Store front-end of the very suite the
  # script had just decided to protect.
  @{ Name='McAfee Personal Security (Store)';Kind='appx'; IsAV=$true; Patterns=@('*McAfeeSecurity*','*McAfee Personal Security*') }
  @{ Name='McAfee LiveSafe / Total Protection (AV suite)'; Kind='win32'; IsAV=$true; Patterns=@('*McAfee LiveSafe*','*McAfee Total Protection*','*McAfee*Protection*') }
  # -- No uninstall entry in the registry: folder + startup entry only --
  @{ Name='Lenovo Ready For Assistant / SmartConnect'; Kind='folder'; Patterns=@('*Ready For*','*SmartConnect*')
     Folders=@('%ProgramFiles%\Lenovo\Ready For Assistant','%ProgramFiles(x86)%\Lenovo\Ready For Assistant') }
  @{ Name='Lenovo Warranty Viewer';         Kind='folder'; Patterns=@('*Warranty Viewer*')
     Folders=@('%ProgramFiles%\Lenovo\Warranty Viewer','%ProgramFiles(x86)%\Lenovo\Warranty Viewer') }
)

# -- Guard: NEVER remove / never kill ---------------------------------------
$GuardRegex = '(?i)(\bdriver\b|realtek|\bintel\b|nvidia|\bamd\b|synaptics|\belan\b|dolby|\baudio\b|codec|System Interface Foundation|ImController|hotkey|Power Management|Power and Battery|Intelligent Thermal|thermal|cooling|TrackPoint|UltraNav|touchpad|chipset|\bbios\b|firmware|fingerprint|biometric|Management Engine|\bTPM\b|BitLocker)'
# Folders we are willing to delete leftovers from - nothing outside these, ever.
$VendorRoots = @('%ProgramFiles%\Lenovo','%ProgramFiles(x86)%\Lenovo','%ProgramFiles%\McAfee','%ProgramFiles(x86)%\McAfee') |
  ForEach-Object { [Environment]::ExpandEnvironmentVariables($_) } | Where-Object { $_ -notmatch '%' }

# -- Helpers ----------------------------------------------------------------
# Pause only when run as a .ps1 (so a double-clicked window stays readable).
# $PSCommandPath is empty when the script was pasted into a console, and there
# the pause is just a confusing extra prompt.
function Hold { if (-not $script:Yes -and $PSCommandPath -and [Environment]::UserInteractive) { Write-Host ""; Read-Host 'Press Enter to close' | Out-Null } }

function Test-Admin { try { (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch { $false } }

function Test-UnderPath {
  param([string]$Child,[string]$Parent)
  if (-not $Child -or -not $Parent) { return $false }
  # Normalise BOTH sides. GetFullPath expands 8.3 short components, so running
  # it on the child only meant a short-form parent (e.g. an InstallLocation of
  # C:\PROGRA~2\Lenovo\X, or a service PathName) never matched its own folder.
  # It failed safe in Remove-LeftoverFolder but failed UNSAFE in the startup
  # classifier, where a miss reclassifies a kept product's entry as removable.
  $c = $Child.Trim().Trim('"')
  $p = $Parent.Trim().Trim('"')
  try { $c = [IO.Path]::GetFullPath($c) } catch {}
  try { $p = [IO.Path]::GetFullPath($p) } catch {}
  $p = $p.TrimEnd('\')
  $c.StartsWith($p + '\', [StringComparison]::OrdinalIgnoreCase) -or $c.Equals($p, [StringComparison]::OrdinalIgnoreCase)
}

function Get-InstalledWin32 {
  $roots = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
    'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
  )
  $list = @()
  foreach ($r in $roots) {
    foreach ($p in (Get-ItemProperty -Path $r -ErrorAction SilentlyContinue)) {
      if (-not $p.DisplayName -or $p.SystemComponent -eq 1) { continue }
      $list += [pscustomobject]@{
        Name=[string]$p.DisplayName; Publisher=[string]$p.Publisher
        SizeMB=$(if ($p.EstimatedSize) { [math]::Round($p.EstimatedSize/1KB,1) } else { $null })
        Quiet=[string]$p.QuietUninstallString; Uninstall=[string]$p.UninstallString
        InstallLocation=[string]$p.InstallLocation
        KeyPath=[string]$p.PSPath
      }
    }
  }
  $list | Sort-Object Name -Unique
}

function Get-ActiveAvNames {
  try { Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop | ForEach-Object {
    $on=$false; try { $on = (([Convert]::ToInt32(('{0:x6}' -f [int]$_.productState).Substring(2,2),16)) -band 0x10) -ne 0 } catch {}
    if ($on) { $_.displayName } } } catch { @() }
}

function Test-AnyLike { param($Value,$Patterns) foreach ($p in $Patterns) { if ($Value -and ($Value -like $p)) { return $true } } $false }

# Split a registry command line into the executable and its arguments. Handles
# both '"C:\dir with spaces\x.exe" /S' and the unquoted 'C:\dir with spaces\x.exe'
# form that broke McAfee WebAdvisor.
function Split-CommandLine {
  param([string]$Cmd)
  $Cmd = ([string]$Cmd).Trim()
  if (-not $Cmd) { return $null }
  if ($Cmd.StartsWith('"')) {
    $end = $Cmd.IndexOf('"',1)
    if ($end -gt 0) { return @{ File=$Cmd.Substring(1,$end-1); Args=$Cmd.Substring($end+1).Trim() } }
  }
  $parts = $Cmd -split ' '
  for ($i = $parts.Count; $i -ge 1; $i--) {
    $cand = ($parts[0..($i-1)] -join ' ')
    if ($cand -and (Test-Path -LiteralPath $cand -PathType Leaf -ErrorAction SilentlyContinue)) {
      $rest = if ($i -lt $parts.Count) { ($parts[$i..($parts.Count-1)] -join ' ').Trim() } else { '' }
      return @{ File=$cand; Args=$rest }
    }
  }
  $rest = if ($parts.Count -gt 1) { ($parts[1..($parts.Count-1)] -join ' ').Trim() } else { '' }
  @{ File=$parts[0]; Args=$rest }
}

# Where does this product live? InstallLocation if given, else the uninstaller's folder.
function Get-ProductRoot {
  param($p)
  $loc = ([string]$p.InstallLocation).Trim().Trim('"').TrimEnd('\')
  if ($loc -and (Test-Path -LiteralPath $loc -PathType Container -ErrorAction SilentlyContinue)) { return $loc }
  foreach ($cmd in @($p.Quiet,$p.Uninstall)) {
    if (-not $cmd) { continue }
    if ($cmd -match '(?i)msiexec') { continue }
    $s = Split-CommandLine $cmd
    if ($s -and $s.File -and (Test-Path -LiteralPath $s.File -PathType Leaf -ErrorAction SilentlyContinue)) {
      return (Split-Path -Parent $s.File)
    }
  }
  $null
}

# Stop everything running out of $Root so the uninstaller can delete its files.
function Stop-ProductRuntime {
  param([string]$Root)
  $stopped = @()
  if (-not $Root -or -not (Test-Path -LiteralPath $Root -ErrorAction SilentlyContinue)) { return $stopped }
  try {
    foreach ($svc in (Get-CimInstance Win32_Service -ErrorAction Stop)) {
      if (-not $svc.PathName) { continue }
      $s = Split-CommandLine $svc.PathName
      if (-not $s -or -not (Test-UnderPath $s.File $Root)) { continue }
      if (($svc.Name -match $GuardRegex) -or ([string]$svc.DisplayName -match $GuardRegex)) { $stopped += "service $($svc.Name) PROTECTED - left running"; continue }
      try { Stop-Service -Name $svc.Name -Force -ErrorAction Stop; $stopped += "stopped service $($svc.Name)" } catch { $stopped += "could not stop service $($svc.Name)" }
    }
  } catch {}
  try {
    foreach ($proc in (Get-Process -ErrorAction SilentlyContinue)) {
      $path = $null; try { $path = $proc.Path } catch {}
      if (-not $path -or -not (Test-UnderPath $path $Root)) { continue }
      if ($proc.Name -match $GuardRegex) { $stopped += "process $($proc.Name) PROTECTED - left running"; continue }
      try { Stop-Process -Id $proc.Id -Force -ErrorAction Stop; $stopped += "killed process $($proc.Name)" } catch { $stopped += "could not kill $($proc.Name)" }
    }
  } catch {}
  if ($stopped) { Start-Sleep -Seconds 2 }
  $stopped
}

# Can Start-Process actually launch this? A full path must exist on disk; a bare
# command name only has to resolve on PATH (rundll32.exe, cmd.exe, winget...).
function Test-Launchable {
  param([string]$File)
  if (-not $File) { return $false }
  if ($File -match '[\\/]' -or $File -match '^[A-Za-z]:') {
    return [bool](Test-Path -LiteralPath $File -PathType Leaf -ErrorAction SilentlyContinue)
  }
  [bool](Get-Command -Name $File -CommandType Application -ErrorAction SilentlyContinue)
}

# Ordered list of uninstall attempts, best first.
function Get-UninstallAttempts {
  param($p)
  $out = @()
  $src = "$($p.Quiet) $($p.Uninstall)"
  $g = [regex]::Match($src,'\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}')
  if ($g.Success -and $src -match '(?i)msiexec') {
    $out += @{ Desc="msiexec /x $($g.Value) /qn"; File='msiexec.exe'; Args="/x $($g.Value) /qn /norestart" }
  }
  # Split-CommandLine falls back to the first space-delimited token when it
  # cannot resolve an unquoted path, so a half-removed product whose exe is
  # already deleted yields File='C:\Program'. Launching that seven times over
  # wastes a minute and fills the log with nonsense - so require something
  # launchable. NOT a bare Test-Path: plenty of real uninstall strings invoke a
  # command by name (rundll32.exe advpack.dll,..., cmd.exe /c ..., winget
  # uninstall ..., powershell -c ...). Test-Path is false for all of those while
  # Start-Process resolves them fine, so a Test-Path-only guard silently threw
  # away every attempt for those products and then claimed the registry had no
  # uninstall command at all.
  if ($p.Quiet) {
    $s = Split-CommandLine $p.Quiet
    if ($s -and (Test-Launchable $s.File)) {
      $out += @{ Desc="quiet string: $(Split-Path $s.File -Leaf) $($s.Args)"; File=$s.File; Args=$s.Args }
    }
  }
  if ($p.Uninstall -and $p.Uninstall -notmatch '(?i)msiexec') {
    $s = Split-CommandLine $p.Uninstall
    if ($s -and (Test-Launchable $s.File)) {
      $leaf = try { Split-Path $s.File -Leaf } catch { '' }
      $flagSets = @()
      if     ($leaf -match '(?i)^unins\d*\.exe$') { $flagSets = @('/VERYSILENT /SUPPRESSMSGBOXES /NORESTART','/SILENT /SUPPRESSMSGBOXES /NORESTART') }  # Inno Setup
      elseif ($leaf -match '(?i)^uninst')         { $flagSets = @('/S','/silent') }                                                                     # NSIS
      else                                        { $flagSets = @('/S','/silent','/quiet','-silent','--silent','/uninstall /quiet') }                   # unknown
      foreach ($f in $flagSets) { $out += @{ Desc="$leaf $f"; File=$s.File; Args=(($s.Args + ' ' + $f).Trim()) } }
      $out += @{ Desc="$leaf (no switches)"; File=$s.File; Args=$s.Args }
    }
  }
  $out
}

# The only trustworthy success signal: the uninstall registry key is gone.
function Wait-KeyGone {
  param([string]$KeyPath,[int]$Seconds = 90)
  for ($i = 0; $i -lt $Seconds; $i++) {
    if (-not (Test-Path -LiteralPath $KeyPath -ErrorAction SilentlyContinue)) { return $true }
    Start-Sleep -Seconds 1
  }
  -not (Test-Path -LiteralPath $KeyPath -ErrorAction SilentlyContinue)
}

function Invoke-UninstallAttempt {
  param($Attempt,[int]$TimeoutSec)
  try {
    $sp = @{ FilePath=$Attempt.File; PassThru=$true; ErrorAction='Stop' }
    if ($Attempt.Args) { $sp.ArgumentList = $Attempt.Args }
    $pr = Start-Process @sp
    if (-not $pr.WaitForExit($TimeoutSec * 1000)) {
      try { $pr.Kill() } catch {}
      return "timed out after ${TimeoutSec}s"
    }
    "exit $($pr.ExitCode)"
  } catch { "could not start: $($_.Exception.Message)" }
}

function Remove-Win32Program {
  param($p,[int]$TimeoutSec)
  $key = $p.KeyPath
  if ($key -and -not (Test-Path -LiteralPath $key -ErrorAction SilentlyContinue)) { return @{ Success=$true; Detail='already gone' } }
  $attempts = @(Get-UninstallAttempts $p)
  if (-not $attempts.Count) { return @{ Success=$false; Detail='no uninstall command in the registry (remove via Settings > Apps)' } }
  $log = @()
  foreach ($a in $attempts) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $r  = Invoke-UninstallAttempt $a $TimeoutSec
    $sw.Stop()
    # An uninstaller that came back in a couple of seconds did nothing - it
    # rejected the switch. Don't sit on a 60s registry poll for it; with four
    # attempts that was three dead minutes before the one that works. A real
    # uninstall (or one waiting on its own dialog) runs far longer than this.
    $poll = if ($sw.Elapsed.TotalSeconds -lt 5) { 10 } else { 60 }
    if ($key -and (Wait-KeyGone $key $poll)) { return @{ Success=$true; Detail="$($a.Desc) -> $r, key removed" } }
    $log += "$($a.Desc) -> $r"
  }
  @{ Success=$false; Detail=($log -join ' | ') }
}

# Every way a program can auto-start: Run/RunOnce keys, the Startup folders
# (shortcuts - previously invisible to this script), and scheduled tasks.
function Get-StartupEntries {
  param($Tasks)   # pass the already-enumerated task list; re-querying is slow
  $out = @()
  $runKeys = @(
    @{ Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\Run';                  Scope='user' }
    @{ Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce';              Scope='user' }
    @{ Path='HKLM:\Software\Microsoft\Windows\CurrentVersion\Run';                  Scope='machine' }
    @{ Path='HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce';              Scope='machine' }
    @{ Path='HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run';      Scope='machine' }
    @{ Path='HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce';  Scope='machine' }
  )
  foreach ($k in $runKeys) {
    try { $p = Get-ItemProperty -Path $k.Path -ErrorAction Stop } catch { continue }
    $isRunOnce = $k.Path -match 'RunOnce$'
    foreach ($prop in ($p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' })) {
      $raw = [string]$prop.Value
      # RunOnce values may carry a '!' (keep until the command succeeds) or '*'
      # (also run in Safe Mode) prefix. Left in place they corrupt the parsed
      # path to '!C:\Program', which makes the "belongs to a program we are
      # keeping" test miss - so a protected product's entry was reclassified as
      # removable, and the user was told the file no longer exists when it does.
      $cmd = if ($isRunOnce) { $raw -replace '^[!*]+','' } else { $raw }
      $s = Split-CommandLine $cmd
      $out += [pscustomobject]@{ Kind=$(if ($isRunOnce) { 'RunOnce' } else { 'Run' }); Name=$prop.Name
                                 Target=$(if ($s) { $s.File } else { $cmd })
                                 Raw=$raw; Location=$k.Path; Scope=$k.Scope }
    }
  }
  foreach ($d in @(@{ P=[Environment]::GetFolderPath('Startup'); S='user' },
                   @{ P=[Environment]::GetFolderPath('CommonStartup'); S='machine' })) {
    if (-not $d.P -or -not (Test-Path -LiteralPath $d.P -ErrorAction SilentlyContinue)) { continue }
    foreach ($f in (Get-ChildItem -LiteralPath $d.P -File -ErrorAction SilentlyContinue)) {
      $target = $f.FullName
      if ($f.Extension -eq '.lnk') {
        try { $target = (New-Object -ComObject WScript.Shell).CreateShortcut($f.FullName).TargetPath } catch {}
      }
      $out += [pscustomobject]@{ Kind='StartupFolder'; Name=$f.Name; Target=$target
                                 Raw=$f.FullName; Location=$f.FullName; Scope=$d.S }
    }
  }
  foreach ($t in @($Tasks | Where-Object { $_.State -ne 'Disabled' })) {
    $exe = ''
    try { foreach ($act in @($t.Actions)) { if ($act.Execute) { $exe = [string]$act.Execute; break } } } catch {}
    $out += [pscustomobject]@{ Kind='Task'; Name=$t.TaskName; Target=($exe.Trim('"'))
                               Raw="$($t.TaskPath)$($t.TaskName)"; Location=$t.TaskPath; Scope='machine' }
  }
  $out
}

# Is the entry still there? The startup list is captured before anything is
# uninstalled, and a program's own uninstaller normally takes its Run keys and
# scheduled tasks with it. By the time we sweep, most are already gone.
function Test-StartupEntryExists {
  param($Entry)
  try {
    # 'Run' and 'RunOnce' are both registry values - same handling, different
    # label. Anything not matched here falls through to $false, which reads as
    # "already gone", so every Kind emitted by Get-StartupEntries must appear.
    switch ($Entry.Kind) {
      { $_ -eq 'Run' -or $_ -eq 'RunOnce' } {
                        $p = Get-ItemProperty -Path $Entry.Location -ErrorAction Stop
                        return ($null -ne $p.PSObject.Properties[$Entry.Name]) }
      'StartupFolder' { return [bool](Test-Path -LiteralPath $Entry.Location -ErrorAction SilentlyContinue) }
      'Task'          { return [bool](Get-ScheduledTask -TaskName $Entry.Name -TaskPath $Entry.Location -ErrorAction SilentlyContinue) }
    }
  } catch { return $false }
  $false
}

function Remove-StartupEntry {
  param($Entry)
  # Already gone means the uninstaller did our job for us. That is a success.
  # Reporting it as a failure turned a fully successful run into "0 of 13" plus
  # thirteen red CIM errors, which reads as a disaster to a non-technical user.
  if (-not (Test-StartupEntryExists $Entry)) { return "already gone with its program: $($Entry.Kind) '$($Entry.Name)'" }
  try {
    switch ($Entry.Kind) {
      { $_ -eq 'Run' -or $_ -eq 'RunOnce' } {
                        Remove-ItemProperty -Path $Entry.Location -Name $Entry.Name -Force -ErrorAction Stop
                        return "removed $($Entry.Kind) entry '$($Entry.Name)'" }
      'StartupFolder' { Remove-Item -LiteralPath $Entry.Location -Force -ErrorAction Stop
                        return "removed startup shortcut '$($Entry.Name)'" }
      'Task'          { Unregister-ScheduledTask -TaskName $Entry.Name -TaskPath $Entry.Location -Confirm:$false -ErrorAction Stop
                        return "removed scheduled task '$($Entry.Name)'" }
    }
  } catch {
    # It may have disappeared between the check and the delete.
    if (-not (Test-StartupEntryExists $Entry)) { return "already gone with its program: $($Entry.Kind) '$($Entry.Name)'" }
    return "could not remove $($Entry.Kind) '$($Entry.Name)': $($_.Exception.Message)"
  }
}

# Delete a leftover folder, but only inside a known vendor root and only after
# the runtime has been stopped.
function Remove-LeftoverFolder {
  param([string]$Root)
  if (-not $Root -or -not (Test-Path -LiteralPath $Root -ErrorAction SilentlyContinue)) { return $null }
  if ($Root -match $GuardRegex) { return "refused (protected name): $Root" }
  $norm = $Root.TrimEnd('\')
  # A product whose InstallLocation IS the vendor root would otherwise take the
  # whole of C:\Program Files\Lenovo with it. Only strict subfolders may go.
  foreach ($v in $VendorRoots) { if ($norm.Equals($v.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) { return "refused (is a vendor root, not a product folder): $Root" } }
  $allowed = $false
  foreach ($v in $VendorRoots) { if (Test-UnderPath $Root $v) { $allowed = $true; break } }
  if (-not $allowed) { return "refused (outside vendor folders): $Root" }
  # Never delete a folder that still has a live process inside it.
  try {
    foreach ($proc in (Get-Process -ErrorAction SilentlyContinue)) {
      $pp = $null; try { $pp = $proc.Path } catch {}
      if ($pp -and (Test-UnderPath $pp $Root)) { return "refused ($($proc.Name) still running in $Root)" }
    }
  } catch {}
  try { Remove-Item -LiteralPath $Root -Recurse -Force -ErrorAction Stop; "deleted folder $Root" }
  catch { "could not delete $Root ($($_.Exception.Message))" }
}

function Get-FolderSizeMB {
  param([string]$Path)
  try {
    $b = (Get-ChildItem -LiteralPath $Path -Recurse -File -Force -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
    if ($b) { [math]::Round($b/1MB,1) } else { 0 }
  } catch { 0 }
}

function Remove-LenovoService {
  param($ServiceName,$TaskLike)
  $did=@()
  if ($ServiceName) {
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
      if (($svc.DisplayName -match $GuardRegex) -or ($ServiceName -match $GuardRegex)) { return "protected service $ServiceName - kept" }
      try { Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue } catch {}
      # Check the exit code. sc.exe failing with ACCESS DENIED (5), DOES NOT
      # EXIST (1060) or MARKED FOR DELETION (1072) used to be reported as
      # "deleted" regardless, which then counted the whole product as removed.
      $scOut = (& sc.exe delete $ServiceName 2>&1) -join ' '
      $scCode = $LASTEXITCODE
      if ($scCode -eq 0) { $did += "service $ServiceName deleted" }
      else { $did += ("could NOT delete service {0} (sc.exe exit {1}: {2})" -f $ServiceName, $scCode, $scOut.Trim()) }
    }
  }
  if ($TaskLike) {
    try { Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -like $TaskLike } | ForEach-Object {
      try { Unregister-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath -Confirm:$false -ErrorAction Stop; $did += "task $($_.TaskName) removed" } catch {} } } catch {}
  }
  if ($did) { $did -join '; ' } else { 'nothing to remove' }
}

function Remove-AppxByPattern {
  param($Pattern)
  $done = @()
  try { Get-AppxPackage -AllUsers -ErrorAction Stop | Where-Object { $_.Name -like $Pattern } | ForEach-Object {
    try { Remove-AppxPackage -Package $_.PackageFullName -AllUsers -ErrorAction Stop; $done += $_.Name } catch {} } } catch {}
  try { Get-AppxProvisionedPackage -Online -ErrorAction Stop | Where-Object { $_.DisplayName -like $Pattern -or $_.PackageName -like $Pattern } | ForEach-Object {
    try { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName -ErrorAction Stop | Out-Null; $done += ('provisioned:'+$_.DisplayName) } catch {} } } catch {}
  if ($done) { 'removed ' + ($done -join ', ') } else { 'no matching Store package' }
}

# -- Go ----------------------------------------------------------------------
# Write a transcript. Rolling this out to people who cannot diagnose their own
# machine means "it broke my laptop" has to be answerable with a file rather
# than a memory. Kept as its own top-level statement so it survives pasting.
# Join-Path must be inside the try: $ErrorActionPreference is 'Stop', so an
# empty %TEMP% threw here and killed the whole script before it ran - the
# diagnostics feature taking down the tool it exists to diagnose.
$LhcLog = $null
try {
  $tmp = $env:TEMP; if (-not $tmp) { $tmp = $env:TMP }; if (-not $tmp) { $tmp = 'C:\Windows\Temp' }
  $LhcLog = Join-Path $tmp ('Debloat-Lenovo-{0}.log' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
} catch { $LhcLog = $null }

# Wrapped in & { } rather than closed with a finally block. A finally block is
# a separate statement to the console parser, so pasting this into a PowerShell
# window used to end with "The term 'finally' is not recognized". This form
# survives being pasted as well as being run as a file.
& {
try {
  # Transcription starts HERE, inside the block, not before it. When this file is
  # pasted, the console echoes every line of this block as it reads it and only
  # then executes - so starting the transcript outside meant the log captured the
  # whole script source: 452 KB / 6,251 lines instead of a 2 KB report, burying
  # the thing IT is supposed to read.
  if ($LhcLog) {
    try { Start-Transcript -Path $LhcLog -Force -ErrorAction Stop | Out-Null }
    catch { $script:LhcLog = $null; Write-Host ("  (could not start a log file: {0})" -f $_.Exception.Message) -ForegroundColor DarkYellow }
  }
  Write-Host ""
  Write-Host ("===== Lenovo + McAfee De-bloat  ({0}  {1}) =====" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyy-MM-dd HH:mm')) -ForegroundColor Cyan
  if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Host "This needs Windows PowerShell 5.1 or newer. Yours is $($PSVersionTable.PSVersion)." -ForegroundColor Red
    return
  }
  # No flags to remember: an ordinary window checks, an Administrator window cleans.
  $isAdmin = Test-Admin
  $Remove  = $isAdmin -and -not $CheckOnly
  Write-Host ("Administrator: {0}" -f $(if ($isAdmin) { 'YES' } else { 'NO' })) -ForegroundColor DarkGray
  Write-Host ""
  if ($Remove) {
    Write-Host "  *** CLEAN-UP MODE - it will ask you to type YES before anything is deleted. ***" -ForegroundColor Yellow
  } else {
    Write-Host "  *** CHECK ONLY - nothing on this PC will be changed by this run. ***" -ForegroundColor Green
  }

  $win32 = Get-InstalledWin32
  $activeAv = @(Get-ActiveAvNames)
  if ($activeAv) { Write-Host ("Active antivirus: {0}" -f ($activeAv -join ', ')) -ForegroundColor DarkGray }
  $defenderActive = (@($activeAv | Where-Object { $_ -match '(?i)defender|microsoft' }).Count -gt 0)
  if (-not $defenderActive) { try { $mp = Get-MpComputerStatus -ErrorAction Stop; if ($mp.AMRunningMode -eq 'Normal' -or ($mp.AntivirusEnabled -and $mp.RealTimeProtectionEnabled)) { $defenderActive = $true } } catch {} }
  Write-Host ("Windows Defender protecting: {0}" -f $(if ($defenderActive) { 'YES - McAfee (incl. AV suite) can be removed' } else { 'NO - McAfee AV suite will be KEPT for protection' })) -ForegroundColor DarkGray

  # ---- STEP 0: collect the expensive lists ONCE ----
  # These used to be queried inside the catalog loop, which meant enumerating
  # every Store package and every scheduled task ~8 times over. That is what
  # made the scan look like it had hung.
  Write-Host ""
  Write-Host "Scanning - this can take a minute or two on a slower PC. Please wait ..." -ForegroundColor DarkCyan
  Write-Host "   - Store apps ..." -ForegroundColor DarkGray
  # -AllUsers needs admin. Without it we only see the current user's packages,
  # so a non-admin check can under-count Store apps versus the admin run. Say so
  # rather than let the two reports quietly disagree.
  $appxAllUsers = $false
  $allAppx = @()
  try { $allAppx = @(Get-AppxPackage -AllUsers -ErrorAction Stop); $appxAllUsers = $true }
  catch { try { $allAppx = @(Get-AppxPackage -ErrorAction Stop) } catch {} }
  if (-not $appxAllUsers) { Write-Host "     (your account only - an Administrator run may find more Store apps)" -ForegroundColor DarkGray }
  Write-Host "   - scheduled tasks ..." -ForegroundColor DarkGray
  $allTasks = @(); try { $allTasks = @(Get-ScheduledTask -ErrorAction Stop) } catch {}
  Write-Host "   - services and running processes ..." -ForegroundColor DarkGray
  $allSvcs  = @(); try { $allSvcs  = @(Get-CimInstance Win32_Service -ErrorAction Stop) } catch {}
  $allProcs = @(); try { $allProcs = @(Get-Process -ErrorAction SilentlyContinue) } catch {}
  Write-Host "   - installed programs and folders ..." -ForegroundColor DarkGray

  # ---- STEP 1: SCAN ----
  # $keptRoots / $keptVendorRegex: anything we deliberately KEEP must keep its
  # startup entries too. Seen on a machine where McAfee was the active AV: the
  # suite was correctly kept, but its McAfeeLogon task was still being switched
  # off - crippling the very antivirus we chose to protect.
  $targets = @(); $skipped = @(); $matchedNames = @(); $claimedRoots = @()
  $keptRoots = @(); $keptVendorRegex = $null; $avForceRemoved = $false
  foreach ($item in $Bloat) {
    $matchesW = @(); if ($item.Kind -notin @('appx','folder')) { $matchesW = @($win32 | Where-Object { Test-AnyLike $_.Name $item.Patterns }) }
    $appxNames = @()
    if ($item.Kind -eq 'appx' -or $item.Kind -eq 'both') {
      $appxNames = @($allAppx | Where-Object { $n=$_.Name; ($item.Patterns | Where-Object { $n -like $_ }) } | Select-Object -Expand Name -Unique)
    }
    $svcHit = $null; if ($item.Service) { try { $svcHit = Get-Service -Name $item.Service -ErrorAction SilentlyContinue } catch {} }
    $taskHits = @(); if ($item.TaskLike) { $taskHits = @($allTasks | Where-Object { $_.TaskName -like $item.TaskLike }) }
    $folders = @()
    if ($item.Folders) {
      $folders = @($item.Folders | ForEach-Object { [Environment]::ExpandEnvironmentVariables($_) } |
                   Where-Object { $_ -notmatch '%' -and (Test-Path -LiteralPath $_ -PathType Container -ErrorAction SilentlyContinue) })
    }
    if ($matchesW.Count -eq 0 -and $appxNames.Count -eq 0 -and -not $svcHit -and $taskHits.Count -eq 0 -and $folders.Count -eq 0) { continue }
    if ($item.Kind -eq 'folder' -and $SkipOrphans) { $skipped += "$($item.Name)  (leftover folder - skipped by -SkipOrphans)"; continue }
    $matchedNames += @($matchesW | Select-Object -Expand Name)
    # Work out where it lives BEFORE deciding, so a kept item can protect its
    # own startup entries the same way a removed one can claim them.
    $roots = @()
    foreach ($m in $matchesW) { $r = Get-ProductRoot $m; if ($r) { $roots += $r } }
    $roots += $folders
    $roots = @($roots | Sort-Object -Unique)

    $guardHit = $null; foreach ($m in $matchesW) { if (($m.Name -match $GuardRegex) -or ([string]$m.Publisher -match $GuardRegex)) { $guardHit = $m.Name; break } }
    if ($guardHit)                                 { $skipped += "$($item.Name)  (protected: $guardHit)"; $keptRoots += $roots; continue }
    # Note: there is deliberately no "dual-use" gate. Vantage used to sit behind
    # -IncludeVantage; that was decided against, so the flag and its branch are
    # gone rather than left dangling and doing nothing.
    if ($item.IsAV -and -not $defenderActive -and $Force) { $avForceRemoved = $true }
    if ($item.IsAV -and -not $defenderActive -and -not $Force) {
                                                     $skipped += "$($item.Name)  (kept - no active Windows Defender fallback; use McAfee MCPR, or -Force)"
                                                     $keptRoots += $roots
                                                     # An AV scatters helpers outside its own folder (Common Files\...),
                                                     # so protect the whole vendor by name, not just its install path.
                                                     $keptVendorRegex = '(?i)mcafee'
                                                     continue }
    $claimedRoots += $roots
    $live = @()
    foreach ($r in $roots) {
      foreach ($pr in $allProcs) { $pp = $null; try { $pp = $pr.Path } catch {}; if ($pp -and (Test-UnderPath $pp $r)) { $live += $pr.Name } }
      foreach ($sv in $allSvcs)  { if ($sv.State -eq 'Running' -and $sv.PathName -and (Test-UnderPath (Split-CommandLine $sv.PathName).File $r)) { $live += "$($sv.Name) (background service)" } }
    }
    $sz = ($matchesW | Measure-Object SizeMB -Sum).Sum
    if (-not $sz -and $folders.Count) { $sz = ($folders | ForEach-Object { Get-FolderSizeMB $_ } | Measure-Object -Sum).Sum }
    $targets += [pscustomobject]@{ Name=$item.Name; Item=$item; Win32=$matchesW; Appx=$appxNames; Folders=$folders
                                   Roots=$roots; Live=@($live | Sort-Object -Unique); SizeMB=[double]$sz }
  }

  # Every Lenovo/McAfee-published program present, so nothing looks hidden.
  $vendorAll   = @($win32 | Where-Object { $_.Name -match '(?i)lenovo|mcafee' -or $_.Publisher -match '(?i)lenovo|mcafee' })
  $vendorOther = @($vendorAll | Where-Object { $matchedNames -notcontains $_.Name })

  # Vendor folders on disk with NO uninstall entry at all - the old blind spot.
  $registeredRoots = @($win32 | ForEach-Object { Get-ProductRoot $_ } | Where-Object { $_ })
  $orphanFolders = @()
  foreach ($v in $VendorRoots) {
    if (-not (Test-Path -LiteralPath $v -ErrorAction SilentlyContinue)) { continue }
    foreach ($d in (Get-ChildItem -LiteralPath $v -Directory -ErrorAction SilentlyContinue)) {
      $known = $false
      foreach ($rr in $registeredRoots) { if (Test-UnderPath $d.FullName $rr) { $known = $true; break } }
      foreach ($cr in $claimedRoots)    { if (Test-UnderPath $d.FullName $cr) { $known = $true; break } }
      if (-not $known) { $orphanFolders += $d.FullName }
    }
  }

  # ---- Startup entries: enumerate everything, then decide one by one ----
  $VendorRegex = '(?i)lenovo|mcafee|vantage|mirametrix|glance|webadvisor|smartconnect'
  $startupAll = @(Get-StartupEntries $allTasks)
  $startup = @()
  foreach ($e in $startupAll) {
    $blob = "$($e.Name) $($e.Raw) $($e.Target)"
    if ($blob -notmatch $VendorRegex) { continue }
    $why = $null
    # Order matters. "Owned by something being removed" is checked before the
    # kept-product rules, so e.g. McAfee WebAdvisor still goes even when the
    # McAfee AV suite is being kept.
    $owned = $false
    foreach ($t in $targets) { foreach ($r in $t.Roots) { if (Test-UnderPath $e.Target $r) { $owned = $true } } }
    $keptOwned = $false
    foreach ($r in $keptRoots) { if (Test-UnderPath $e.Target $r) { $keptOwned = $true } }

    if ($blob -match $GuardRegex) {
      $why = 'kept - protected (driver / hotkey / power / security component)'
    } elseif ($owned) {
      $why = 'will be removed with its program'
    } elseif ($keptOwned) {
      $why = 'kept - belongs to a program we are deliberately keeping'
    } elseif ($keptVendorRegex -and $blob -match $keptVendorRegex) {
      $why = 'kept - belongs to your active antivirus'
    } elseif ($e.Target -and -not (Test-Path -LiteralPath $e.Target -ErrorAction SilentlyContinue)) {
      $why = 'will be removed - points at a file that no longer exists'
    } else {
      $why = 'will be removed - vendor startup item'
    }
    $startup += [pscustomobject]@{ Entry=$e; Remove=($why -notlike 'kept*'); Why=$why }
  }
  $startupRemove = @($startup | Where-Object { $_.Remove })

  # ---- REPORT ----
  $total = ($targets | Measure-Object SizeMB -Sum).Sum
  Write-Host ""
  if ($targets.Count) {
    Write-Host ("[1] WILL BE REMOVED  ({0} item(s), ~{1:n0} MB):" -f $targets.Count, $total) -ForegroundColor Green
    foreach ($t in $targets) {
      $s = if ($t.SizeMB) { " (~{0:n0} MB)" -f $t.SizeMB } else { '' }
      $tag = if ($t.Item.Kind -eq 'folder') { ' [no uninstaller - folder + startup entry]' } else { '' }
      if ($t.Item.Interactive) { $tag += ' [WILL ASK YOU TO CONFIRM IN ITS OWN WINDOW]' }
      Write-Host ("     - {0}{1}{2}" -f $t.Name, $s, $tag)
      if ($t.Live.Count) { Write-Host ("         running now (will be stopped first): {0}" -f ($t.Live -join ', ')) -ForegroundColor DarkGray }
    }
  } else {
    Write-Host "[1] WILL BE REMOVED: nothing - no removable Lenovo/McAfee bloatware found." -ForegroundColor Green
  }

  Write-Host ""
  if ($skipped.Count) {
    Write-Host "[2] KEPT / SKIPPED (dual-use / antivirus / protected):" -ForegroundColor DarkYellow
    $skipped | ForEach-Object { Write-Host "     - $_" -ForegroundColor DarkYellow }
  } else { Write-Host "[2] KEPT / SKIPPED: none." -ForegroundColor DarkYellow }

  Write-Host ""
  if ($vendorOther.Count -or $orphanFolders.Count) {
    Write-Host ("[3] OTHER LENOVO / McAFEE SOFTWARE PRESENT (not touched) - {0}:" -f ($vendorOther.Count + $orphanFolders.Count)) -ForegroundColor Gray
    foreach ($v in $vendorOther) { $s = if ($v.SizeMB) { " (~{0:n0} MB)" -f $v.SizeMB } else { '' }; Write-Host ("     - {0}{1}" -f $v.Name, $s) -ForegroundColor Gray }
    foreach ($o in $orphanFolders) { Write-Host ("     - {0}  (~{1:n0} MB, folder only - no uninstall entry)" -f $o, (Get-FolderSizeMB $o)) -ForegroundColor Gray }
    Write-Host "     (mostly drivers/utilities - left alone on purpose.)" -ForegroundColor DarkGray
  } else { Write-Host "[3] OTHER LENOVO / McAFEE SOFTWARE PRESENT: none." -ForegroundColor Gray }

  Write-Host ""
  if ($startup.Count) {
    Write-Host ("[4] STARTUP APPS ({0} found, {1} will be removed) - impacts boot time / RAM:" -f $startup.Count, $startupRemove.Count) -ForegroundColor Magenta
    foreach ($s in $startup) {
      $col = if ($s.Remove) { 'Magenta' } else { 'DarkGray' }
      Write-Host ("     - [{0}] {1}" -f $s.Entry.Kind, $s.Entry.Name) -ForegroundColor $col
      Write-Host ("         {0}" -f $s.Entry.Target) -ForegroundColor DarkGray
      Write-Host ("         {0}" -f $s.Why) -ForegroundColor $col
    }
  } else { Write-Host "[4] STARTUP APPS: no Lenovo/McAfee startup entries found." -ForegroundColor Magenta }

  Write-Host ""
  Write-Host "=========================  SUMMARY  =========================" -ForegroundColor Cyan
  Write-Host ""
  Write-Host "  IN PLAIN ENGLISH - what a clean-up would do to this PC:" -ForegroundColor White
  Write-Host ""
  if ($targets.Count) {
    # Only mention GB once there is a GB to mention - "(0.0 GB)" reads as broken.
    $sizeText = if ($total -ge 1024) { "{0:n0} MB ({1:n1} GB)" -f $total, ($total/1024) } else { "{0:n0} MB" -f $total }
    Write-Host ("   *  Free about {0} of disk space" -f $sizeText) -ForegroundColor Green
    Write-Host ("      by uninstalling {0} program(s)/leftover folder(s):" -f $targets.Count) -ForegroundColor Green
    foreach ($t in $targets) { Write-Host ("         - {0}{1}" -f $t.Name, $(if ($t.SizeMB) { " (~{0:n0} MB)" -f $t.SizeMB } else { '' })) -ForegroundColor Green }
  } else {
    Write-Host "   *  No programs need removing - nothing to free up." -ForegroundColor Green
  }
  Write-Host ""
  if ($startupRemove.Count) {
    # Not "at every boot": a RunOnce value fires at most once, and Windows
    # deletes it itself. Saying "at every boot" was simply untrue for those.
    Write-Host ("   *  Stop {0} app(s) from launching automatically at startup" -f $startupRemove.Count) -ForegroundColor Green
    Write-Host  "      (this is what makes the laptop feel slow after login):" -ForegroundColor Green
    foreach ($s in $startupRemove) { Write-Host ("         - {0}  [{1}]" -f $s.Entry.Name, $s.Entry.Kind) -ForegroundColor Green }
  } else {
    Write-Host "   *  No startup apps need turning off." -ForegroundColor Green
  }
  Write-Host ""
  $liveTotal = @($targets | ForEach-Object { $_.Live } | Where-Object { $_ } | Sort-Object -Unique)
  if ($liveTotal.Count) {
    Write-Host ("   *  Close {0} background process(es)/service(s) that are running right now:" -f $liveTotal.Count) -ForegroundColor DarkYellow
    Write-Host ("         {0}" -f ($liveTotal -join ', ')) -ForegroundColor DarkYellow
  }
  if ($skipped.Count) {
    Write-Host ("   *  Deliberately KEEP {0} item(s) - antivirus / dual-use / protected." -f $skipped.Count) -ForegroundColor DarkYellow
  }
  if (($vendorOther.Count + $orphanFolders.Count)) {
    Write-Host ("   *  Leave {0} other Lenovo/McAfee item(s) completely untouched." -f ($vendorOther.Count + $orphanFolders.Count)) -ForegroundColor DarkYellow
  }
  Write-Host ""
  Write-Host "   NEVER touched: drivers, audio, battery/thermal, Fn hotkeys, touchpad," -ForegroundColor DarkGray
  if ($avForceRemoved) {
    # Do not promise the antivirus is safe on the one run where it is not.
    Write-Host "   fingerprint, TPM/BitLocker.  (-Force IS OVERRIDING ANTIVIRUS PROTECTION)" -ForegroundColor Red
  } else {
    Write-Host "   fingerprint, TPM/BitLocker, or your active antivirus." -ForegroundColor DarkGray
  }
  Write-Host "=============================================================" -ForegroundColor Cyan

  # Printed in CHECK mode too. The banner used to sit after the check-only
  # return, so a -Force preview listed the AV under "WILL BE REMOVED" and then
  # promised the antivirus is never touched, with no retraction anywhere.
  if ($avForceRemoved) {
    Write-Host ""
    Write-Host "  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" -ForegroundColor Red
    Write-Host "  !!  -Force WAS USED. An ANTIVIRUS PRODUCT is in the removal list.   !!" -ForegroundColor Red
    Write-Host "  !!  Windows Defender is NOT currently protecting this PC, so after  !!" -ForegroundColor Red
    Write-Host "  !!  this runs there may be NO real-time virus protection until      !!" -ForegroundColor Red
    Write-Host "  !!  Defender takes over - which needs a REBOOT, and does not happen !!" -ForegroundColor Red
    Write-Host "  !!  at all if the removal leaves remnants behind.                   !!" -ForegroundColor Red
    Write-Host "  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" -ForegroundColor Red
  }

  # Do not declare the PC clean off the back of a partial scan. Without admin,
  # Store apps were only enumerated for the current account, so "already clean"
  # was an absolute claim sitting a few lines under a caveat saying otherwise.
  if ($targets.Count -eq 0 -and $startupRemove.Count -eq 0) {
    Write-Host ""
    if ($appxAllUsers) {
      Write-Host "Nothing to remove. This PC is already clean." -ForegroundColor Green
    } else {
      Write-Host "Nothing to remove was found - but this was a limited check." -ForegroundColor Yellow
      Write-Host "Store apps could only be checked for your own account. Re-run as" -ForegroundColor Yellow
      Write-Host "Administrator for the complete picture." -ForegroundColor Yellow
    }
    return
  }

  # ---- ANALYZE-only ----
  if (-not $Remove) {
    Write-Host ""
    Write-Host "NOTHING WAS CHANGED. This was a check only." -ForegroundColor Green
    Write-Host ""
    if ($isAdmin) {
      Write-Host "  Check-only was requested. Run it again without -CheckOnly to clean up." -ForegroundColor Yellow
    } else {
      Write-Host "  TO ACTUALLY CLEAN THIS PC:" -ForegroundColor Yellow
      Write-Host "    1) Click Start and type:  PowerShell" -ForegroundColor Yellow
      Write-Host "    2) Right-click 'Windows PowerShell' and choose 'Run as administrator'" -ForegroundColor Yellow
      Write-Host "    3) Say Yes to the Windows pop-up that asks for permission" -ForegroundColor Yellow
      Write-Host "    4) Run this again in that window" -ForegroundColor Yellow
      Write-Host "    5) When it asks, type  YES  in capital letters and press Enter" -ForegroundColor Yellow
      Write-Host ""
      Write-Host "  You can stop at any point - nothing is deleted until you type YES." -ForegroundColor DarkGray
    }
    return
  }

  # ---- STEP 2: CONFIRM ----
  # Some vendors bolt a custom confirmation form onto their uninstaller that no
  # silent switch suppresses. Two are known (see Interactive in the catalog) and
  # others will exist, so warn unconditionally - picking "Keep" quietly defeats
  # the whole run, and the console looks frozen until the window is answered.
  Write-Host ""
  $askers = @($targets | Where-Object { $_.Item.Interactive } | ForEach-Object { $_.Name })
  Write-Host "  HEADS-UP: some uninstallers open their OWN window and ask you to confirm." -ForegroundColor Yellow
  if ($askers.Count) {
    Write-Host ("  On this PC, expect one from: {0}" -f ($askers -join '; ')) -ForegroundColor Yellow
  }
  Write-Host "  Always choose the option that CONTINUES removing, for example:" -ForegroundColor Yellow
  Write-Host "        'No thanks, just uninstall it'    'Uninstall'    'Yes'    'Remove'" -ForegroundColor White
  Write-Host "  Do NOT choose 'Keep web protection', 'Keep', or 'Cancel' - those leave it installed." -ForegroundColor Yellow
  Write-Host "  While such a window is open this screen will look frozen. That is normal -" -ForegroundColor DarkGray
  Write-Host "  answer the window and it carries on. Look behind this window if you see nothing." -ForegroundColor DarkGray

  Write-Host ""
  if (-not $Yes) {
    $ans = Read-Host ("Type YES (capital letters) to remove {0} program(s) (~{1:n0} MB) and {2} startup app(s) - anything else cancels" -f $targets.Count, $total, $startupRemove.Count)
    if ($ans -cne 'YES') { Write-Host "Cancelled - nothing was removed." -ForegroundColor Yellow; return }
  }

  # ---- STEP 3: REMOVE ----
  Write-Host ""
  $removed=0; $failed=0; $freed=0.0; $failNotes=@()
  foreach ($t in $targets) {
    Write-Host ("Removing {0} ..." -f $t.Name) -ForegroundColor Green
    # $ok = did anything at all succeed. $win32Failed = a PROGRAM uninstall
    # failed, which must veto every folder deletion for this item. They used to
    # be one flag, so on a Kind='both' item a successful Store-app removal
    # authorised recursively deleting the install folder of a Win32 program
    # whose uninstall had just failed - leaving a product Windows still thinks
    # is installed, with no files and a broken uninstaller, reported as success.
    $ok = $false
    $win32Failed = $false

    # 3a. stop the product's own services + processes so files unlock
    foreach ($r in $t.Roots) {
      foreach ($msg in (Stop-ProductRuntime $r)) { Write-Host ("   $msg") -ForegroundColor DarkGray }
    }

    # 3b. uninstall each matching program, verified by registry key removal
    foreach ($m in $t.Win32) {
      try {
        $res = Remove-Win32Program $m $TimeoutSec
        $colour = if ($res.Success) { 'Gray' } else { 'Red' }
        Write-Host ("   program '{0}' -> {1}" -f $m.Name, $res.Detail) -ForegroundColor $colour
        if ($res.Success) { $ok = $true } else { $win32Failed = $true; $failNotes += "$($m.Name): $($res.Detail)" }
      } catch { $win32Failed = $true; Write-Host ("   '{0}' FAILED: {1}" -f $m.Name, $_.Exception.Message) -ForegroundColor Red; $failNotes += "$($m.Name): $($_.Exception.Message)" }
    }

    # 3c. Store apps
    if ($t.Item.Kind -eq 'appx' -or $t.Item.Kind -eq 'both') {
      foreach ($pat in $t.Item.Patterns) { try { $r = Remove-AppxByPattern $pat; if ($r -notmatch '^no matching') { Write-Host ("   appx '{0}' -> {1}" -f $pat, $r); $ok=$true } } catch {} }
    }

    # 3d. bare services / tasks
    if ($t.Item.Kind -eq 'service') {
      try {
        $r = Remove-LenovoService $t.Item.Service $t.Item.TaskLike
        $svcBad = ($r -match 'could NOT delete')
        Write-Host ("   service/tasks -> {0}" -f $r) -ForegroundColor $(if ($svcBad) { 'Red' } else { 'Gray' })
        if ($svcBad) { $win32Failed = $true; $failNotes += "$($t.Name): $r" }
        elseif ($r -notmatch '^nothing') { $ok = $true }
      } catch { $win32Failed = $true; Write-Host ("   service/tasks FAILED: {0}" -f $_.Exception.Message) -ForegroundColor Red; $failNotes += "$($t.Name): $($_.Exception.Message)" }
    }

    # 3e. leftovers: the folder itself (startup apps are swept together, below).
    # Never delete files belonging to a program that is still registered.
    if ($win32Failed) {
      Write-Host "   left every folder alone - a program uninstall failed above" -ForegroundColor DarkYellow
    } else {
      foreach ($f in $t.Folders) {
        $r = Remove-LeftoverFolder $f
        if ($r) { Write-Host ("   $r") -ForegroundColor DarkGray; if ($r -like 'deleted*') { $ok = $true } else { $failNotes += $r } }
      }
      # for uninstalled programs, sweep the now-empty install folder too
      if ($ok -and $t.Item.Kind -ne 'folder') {
        foreach ($r in $t.Roots) {
          if (Test-Path -LiteralPath $r -ErrorAction SilentlyContinue) {
            $left = Remove-LeftoverFolder $r
            if ($left -like 'deleted*') { Write-Host ("   $left") -ForegroundColor DarkGray }
          }
        }
      }
    }

    # Partial success is a failure. Counting an item as removed while one of its
    # programs is still installed is how "Failed: 0" appeared next to a failure.
    if ($ok -and -not $win32Failed) { $removed++; if ($t.SizeMB) { $freed += $t.SizeMB } } else { $failed++ }
  }

  # ---- STEP 4: STARTUP APPS ----
  # Done last, so entries belonging to a program that failed to uninstall still
  # get switched off - the boot-time win does not depend on the uninstall.
  $startupGone = 0
  if ($startupRemove.Count) {
    Write-Host ""
    Write-Host ("Turning off {0} startup app(s) ..." -f $startupRemove.Count) -ForegroundColor Green
    foreach ($s in $startupRemove) {
      $r = Remove-StartupEntry $s.Entry
      $isOk = ($r -like 'removed*') -or ($r -like 'already gone*')
      Write-Host ("   $r") -ForegroundColor $(if ($isOk) { 'DarkGray' } else { 'Red' })
      if ($isOk) { $startupGone++ } else { $failNotes += $r }
    }
  }

  Write-Host ""
  Write-Host "===== REMOVAL DONE =====" -ForegroundColor Cyan
  Write-Host ("  Programs removed : {0}   Failed: {1}   (~{2:n0} MB freed)" -f $removed, $failed, $freed) -ForegroundColor Green
  Write-Host ("  Startup apps off : {0} of {1}" -f $startupGone, $startupRemove.Count) -ForegroundColor Green
  if ($failNotes.Count) {
    Write-Host "  Failures:" -ForegroundColor Red
    $failNotes | ForEach-Object { Write-Host "     - $_" -ForegroundColor Red }
    Write-Host "  Tip: reboot and re-run - some uninstallers finish their work at boot." -ForegroundColor DarkYellow
  }
  # Report what is ACTUALLY true now rather than replaying a scan-time guess.
  # The old version printed "THIS PC MAY NOW HAVE NO ANTIVIRUS" even when the AV
  # removal had failed and the product was still fully installed.
  if ($avForceRemoved) {
    Write-Host ""
    $avNow = @(Get-ActiveAvNames)
    if ($avNow.Count) {
      Write-Host ("  Antivirus check: still protected by {0}." -f ($avNow -join ', ')) -ForegroundColor Green
    } else {
      Write-Host "  *** NO ACTIVE ANTIVIRUS IS REGISTERED ON THIS PC RIGHT NOW ***" -ForegroundColor Red
      Write-Host "  Reboot now, then open Windows Security and confirm it says" -ForegroundColor Red
      Write-Host "  'Microsoft Defender Antivirus is on'. If it does not, turn it on there." -ForegroundColor Red
    }
  }
  Write-Host "  A reboot is recommended to finish any pending removals." -ForegroundColor DarkCyan
  Write-Host "  Run this again afterwards to confirm the lists come back empty." -ForegroundColor DarkCyan
}
catch {
  Write-Host ""
  Write-Host ("ERROR: {0}" -f $_.Exception.Message) -ForegroundColor Red
  if ($_.ScriptStackTrace) { Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray }
}
}
if ($LhcLog) {
  try { Stop-Transcript -ErrorAction Stop | Out-Null } catch {}
  Write-Host ""
  Write-Host ("A full log of this run was saved to:  {0}" -f $LhcLog) -ForegroundColor DarkCyan
  Write-Host "If anything went wrong, send that file to IT." -ForegroundColor DarkCyan
}
Hold

<#
    Build-Variants.ps1  -  generates the two derived scripts from the canonical
    one, so the same bug can never live in three files again.

        Debloat-Lenovo.ps1   (canonical - edit THIS one)
              |
              +--> Debloat-Lenovo-Paste.ps1   copy-paste block, auto-detects admin
              +--> Analyze-Lenovo.ps1         read-only, removal path disabled

    Run after every edit to Debloat-Lenovo.ps1:
        powershell -NoProfile -ExecutionPolicy Bypass -File .\Build-Variants.ps1
#>
[CmdletBinding()]
param([string]$Source)

$ErrorActionPreference = 'Stop'
if (-not $Source) {
  $here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
  $Source = Join-Path $here 'Debloat-Lenovo.ps1'
}
$dir = Split-Path -Parent $Source
# Read as UTF-8 explicitly: PS 5.1's Get-Content assumes ANSI for BOM-less files
# and would mangle any non-ASCII into mojibake in the generated copies.
$all = ([IO.File]::ReadAllText($Source, [Text.Encoding]::UTF8)) -split "`r?`n"

function Save-Ascii {
  param([string]$Path,[string]$Text)
  # These files get pasted into consoles and pasted through chat clients, so they
  # must stay pure ASCII with no BOM - anything else arrives corrupted.
  $bad = [regex]::Matches($Text,'[^\x00-\x7F\r\n\t]')
  if ($bad.Count) { throw "$([IO.Path]::GetFileName($Path)): $($bad.Count) non-ASCII character(s) - fix the canonical script" }
  [IO.File]::WriteAllText($Path, $Text, (New-Object Text.UTF8Encoding $false))
}

# Body = everything from $ErrorActionPreference onwards (drops #Requires/param).
$start = ($all | Select-String -SimpleMatch "`$ErrorActionPreference = 'Stop'" | Select-Object -First 1).LineNumber
if (-not $start) { throw "Could not find the start of the body in $Source" }
$body = $all[($start)..($all.Count-1)]   # skip the $ErrorActionPreference line itself

$adminGate = @(
  '  if ($Remove -and -not (Test-Admin)) {'
  '    Write-Host "REMOVE needs administrator rights. Open PowerShell as Administrator, then re-run with -Remove." -ForegroundColor Red'
  '    return'
  '  }'
) -join "`r`n"

# The body defines Hold; a later definition wins, so the stub must replace this
# one rather than sit above it.
$holdDef = "function Hold { if (-not `$script:Yes -and [Environment]::UserInteractive) { Write-Host `"`"; Read-Host 'Press Enter to close' | Out-Null } }"

function Convert-Body {
  param([string[]]$Lines, [hashtable]$Replace)
  $text = ($Lines -join "`r`n")
  foreach ($k in $Replace.Keys) {
    # .Contains, not -like: the anchors contain [1] which -like reads as a wildcard.
    if (-not $text.Contains($k)) { throw "Anchor not found while building: $($k.Substring(0,[Math]::Min(60,$k.Length)))" }
    $text = $text.Replace($k, $Replace[$k])
  }
  $text
}

# -- Debloat-Lenovo-Paste.ps1 ------------------------------------------------
$pasteHeader = @'
# ============================================================================
#  Lenovo + McAfee de-bloat  -  COPY-PASTE version.
#  Share this whole block on chat. To use it:
#    1) Start menu > type PowerShell > right-click > Run as administrator
#    2) Paste this ENTIRE block into that window and press Enter.
#  It shows what it found; if the window is Administrator it asks you to type
#  YES before removing anything. Not admin = it only shows the report.
#
#  It stops the product's own services/processes before uninstalling, runs the
#  vendor's own silent uninstall command, and confirms by checking the registry
#  key is gone - so "Failed" now means genuinely failed.
# ============================================================================
& {
$ErrorActionPreference = 'Stop'
$IncludeVantage = $false; $Force = $false; $Yes = $false; $SkipOrphans = $false; $TimeoutSec = 300
function Hold { }
'@

$pasteBody = Convert-Body $body @{
  $adminGate = @(
    '  $Remove = Test-Admin'
    '  Write-Host ("Administrator: {0}" -f $(if ($Remove) { ''YES'' } else { ''NO (report only - re-open as Administrator to remove)'' })) -ForegroundColor DarkGray'
  ) -join "`r`n"
  $holdDef = 'function Hold { }'
  'Write-Host "To remove the [1] items, run in an elevated PowerShell:  .\Debloat-Lenovo.ps1 -Remove" -ForegroundColor Yellow' =
    'Write-Host "  Re-open PowerShell as Administrator, paste this block again, and type YES." -ForegroundColor Yellow'
  'Write-Host "ANALYZE only - nothing was changed." -ForegroundColor Green' =
    'Write-Host "Report only (not Administrator) - nothing was changed." -ForegroundColor Green'
  # Nothing in the paste block may tell the user to run a FILE - they only have
  # the block. Every instruction has to be "paste this again".
  'Write-Host "  Re-run without -Remove afterwards to confirm the lists are empty." -ForegroundColor DarkCyan' =
    'Write-Host "  Paste this block again afterwards to confirm the lists are empty." -ForegroundColor DarkCyan'
}
# The recipient of the paste block has no files - only the block. Fail the build
# if any instruction slipped through telling them to run one.
foreach ($banned in '.ps1', ' -Remove') {
  if ($pasteBody.Contains($banned)) {
    $line = ($pasteBody -split "`r?`n" | Where-Object { $_.Contains($banned) }) -join ' // '
    throw "Paste block refers to '$banned' - it must be self-contained: $line"
  }
}
$pasteFooter = "`r`n}`r`n`r`n# (generated from Debloat-Lenovo.ps1 by Build-Variants.ps1 - edit that one, not this)`r`n"
Save-Ascii "$dir\Debloat-Lenovo-Paste.ps1" ($pasteHeader + "`r`n" + $pasteBody + $pasteFooter)

# -- Analyze-Lenovo.ps1 ------------------------------------------------------
$analyzeHeader = @'
<#
    Analyze-Lenovo.ps1  -  READ-ONLY. Reports the Lenovo + McAfee software on this
    PC: what is removable bloat, what is kept (drivers / antivirus / dual-use), any
    other Lenovo/McAfee software present (including folders with no uninstall
    entry), and which of it runs at startup.

    It NEVER removes anything and needs no admin: $Remove is hard-coded to
    $false here and the script returns before the removal step. To actually
    uninstall, use  Debloat-Lenovo.ps1 -Remove  in an elevated PowerShell.

    HOW TO RUN:
      powershell -NoProfile -ExecutionPolicy Bypass -File .\Analyze-Lenovo.ps1
    (Best with admin: seeing all-users Store apps needs admin; Win32 programs are
    detected either way.)

    GENERATED FROM Debloat-Lenovo.ps1 BY Build-Variants.ps1 - DO NOT EDIT HERE.
#>
#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
$Remove = $false; $IncludeVantage = $false; $Force = $false; $Yes = $true; $SkipOrphans = $false; $TimeoutSec = 300
'@

$analyzeBody = Convert-Body $body @{
  $adminGate = '  # removal is not available in the read-only variant'
  $holdDef = 'function Hold { }'
  'Mode: {0}" -f $(if ($Remove) { ''REMOVE (will ask you to type YES before deleting)'' } else { ''ANALYZE (read-only - nothing will be changed)'' })' =
    'Mode: {0}" -f ''ANALYZE (read-only - this script cannot remove anything)'''
  # A read-only tool must not say "WILL BE REMOVED".
  '===== Lenovo + McAfee De-bloat' = '===== Lenovo + McAfee bloatware - ANALYSIS'
  'WILL BE REMOVED'  = 'REMOVABLE BLOAT'
  'Will be removed :' = 'Removable bloat :'
}
Save-Ascii "$dir\Analyze-Lenovo.ps1" ($analyzeHeader + "`r`n" + $analyzeBody + "`r`n")

# -- Verify all three parse --------------------------------------------------
foreach ($f in 'Debloat-Lenovo.ps1','Debloat-Lenovo-Paste.ps1','Analyze-Lenovo.ps1') {
  $err = $null
  $null = [System.Management.Automation.Language.Parser]::ParseFile("$dir\$f", [ref]$null, [ref]$err)
  if ($err -and $err.Count) {
    Write-Host ("{0}: {1} PARSE ERROR(S)" -f $f, $err.Count) -ForegroundColor Red
    $err | ForEach-Object { Write-Host ("   L{0}: {1}" -f $_.Extent.StartLineNumber, $_.Message) -ForegroundColor Red }
  } else {
    Write-Host ("{0}: OK ({1} lines)" -f $f, (Get-Content -LiteralPath "$dir\$f").Count) -ForegroundColor Green
  }
}

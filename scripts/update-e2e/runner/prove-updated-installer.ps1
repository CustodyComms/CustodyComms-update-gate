#Requires -Version 7
<#
Runs an update installer the way an installed app's "Restart & Install" starts it, and checks it finishes by
itself.

PRECONDITION: CustodyComms is installed for the current user at -FromVersion.

PASS (without -Control), all of:
  1. the installer exits 0 inside the time box with nobody clicking;
  2. no "CustodyComms Setup" (or Uninstall) window is seen while it runs;
  3. -ExpectVersion is registered (Uninstall DisplayVersion) AND inside the installed app.asar, same folder;
  4. CustodyComms.exe is started again from that folder with --updated and is still running 30 s later.

-Control: the run is expected to WAIT with its setup window open (an installer without the silent-update fix).
It passes only if the window was seen and nothing changed on disk; if it finishes by itself the check cannot see
the defect and the control fails.

-ResultOut FILE writes {"observed": ..., "reason": ...} for the caller. The console gets one PASS/FAIL line.
#>
param(
  [Parameter(Mandatory)] [string] $NewInstaller,
  [string] $ExpectVersion = '',
  [string] $FromVersion = '',
  [string[]] $Arguments = @('--updated', '--force-run'),
  [int] $TimeoutSeconds = 600,
  [switch] $Control,
  [switch] $StartOldApp,
  [switch] $RequireSigned,
  [string] $ResultOut = ''
)
$ErrorActionPreference = 'Stop'

function Write-Result([string] $observed, [string] $reason) {
  if ($ResultOut) { @{ observed = $observed; reason = $reason } | ConvertTo-Json | Set-Content -LiteralPath $ResultOut -Encoding utf8 }
}
function Stop-With([string] $reason) { Write-Result '' $reason; Write-Host "FAIL: $reason"; exit 1 }

function Get-CCInstall {
  $u = @(Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall' -ErrorAction SilentlyContinue | Get-ItemProperty | Where-Object { $_.DisplayName -like 'CustodyComms*' })
  if ($u.Count -ne 1) { Stop-With 'precondition_failed' }
  [pscustomobject]@{ Version = $u[0].DisplayVersion; Dir = ([string]$u[0].InstallLocation).TrimEnd('\'); Uninstall = $u[0].UninstallString }
}

function Get-AsarVersion([string] $asar) {
  # asar: uint32 4, uint32 header size, then a pickle (uint32 payload size, uint32 JSON length, JSON);
  # file data starts at 8 + header size.
  $fs = [IO.File]::OpenRead($asar)
  try {
    $br = [IO.BinaryReader]::new($fs)
    $null = $br.ReadUInt32(); $headerSize = $br.ReadUInt32(); $null = $br.ReadUInt32(); $len = $br.ReadUInt32()
    $hdr = [Text.Encoding]::UTF8.GetString($br.ReadBytes($len)) | ConvertFrom-Json -Depth 200
    $e = $hdr.files.'package.json'
    $fs.Position = 8 + [int64]$headerSize + [int64]$e.offset
    ([Text.Encoding]::UTF8.GetString($br.ReadBytes([int]$e.size)) | ConvertFrom-Json).version
  } finally { $fs.Dispose() }
}

function Find-SetupWindow {
  Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowTitle -like 'CustodyComms*Setup*' -or $_.MainWindowTitle -like 'CustodyComms*Uninstall*' } | Select-Object -First 1
}

$before = Get-CCInstall
if ($FromVersion -and $before.Version -ne $FromVersion) { Stop-With 'precondition_failed' }
$exe = Join-Path $before.Dir 'CustodyComms.exe'
if (-not (Test-Path $exe)) { Stop-With 'precondition_failed' }
if ($FromVersion -and (Get-AsarVersion (Join-Path $before.Dir 'resources\app.asar')) -ne $FromVersion) { Stop-With 'precondition_failed' }
if ($RequireSigned) {
  $sig = Get-AuthenticodeSignature $NewInstaller
  if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'CN="?Custodycomms Inc\.') { Stop-With 'signature_invalid' }
}

if ($StartOldApp) { Start-Process -FilePath $exe | Out-Null; Start-Sleep -Seconds 20 }
else { Get-Process CustodyComms -ErrorAction SilentlyContinue | Stop-Process -Force }

$t0 = Get-Date
$p = Start-Process -FilePath $NewInstaller -ArgumentList $Arguments -PassThru
$null = $p.Handle   # keep the handle, or ExitCode reads back empty
$window = $false
$deadline = $t0.AddSeconds($TimeoutSeconds)
while (-not $p.HasExited -and (Get-Date) -lt $deadline) {
  Start-Sleep -Seconds 2
  if (Find-SetupWindow) { $window = $true }
}

if (-not $p.HasExited) {
  Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
  if ($Control) {
    if (-not $window) { Stop-With 'control_no_window' }
    if ((Get-CCInstall).Version -ne $FromVersion) { Stop-With 'wrong_version' }
    Write-Result 'wizard_seen' 'ok'; Write-Host 'PASS: control waited with its setup window open'; exit 0
  }
  Stop-With 'installer_timeout'
}
if ($Control) { Stop-With 'control_no_defect' }
if ($p.ExitCode -ne 0) { Stop-With 'installer_exit_nonzero' }
if ($window) { Stop-With 'setup_window_seen' }

$after = Get-CCInstall
if ($ExpectVersion -and $after.Version -ne $ExpectVersion) { Stop-With 'wrong_version' }
if ($after.Dir -ne $before.Dir) { Stop-With 'wrong_version' }
if ($ExpectVersion -and (Get-AsarVersion (Join-Path $after.Dir 'resources\app.asar')) -ne $ExpectVersion) { Stop-With 'wrong_version' }

if ($Arguments -contains '--force-run') {
  $app = $null
  $until = (Get-Date).AddSeconds(90)
  while (-not $app -and (Get-Date) -lt $until) {
    $app = Get-CimInstance Win32_Process -Filter "Name = 'CustodyComms.exe'" | Where-Object { $_.ExecutablePath -eq $exe -and $_.CreationDate -gt $t0 } | Select-Object -First 1
    if (-not $app) { Start-Sleep -Seconds 2 }
  }
  if (-not $app) { Stop-With 'not_reopened' }
  if ($app.CommandLine -notmatch '--updated') { Stop-With 'not_reopened' }
  Start-Sleep -Seconds 30
  if (-not (Get-Process -Id $app.ProcessId -ErrorAction SilentlyContinue)) { Stop-With 'reopened_exited' }
}
Write-Result 'installed' 'ok'
Write-Host 'PASS: the installer finished by itself with no window'
exit 0

# Installs a Hifaz MSI silently, checks the result, removes it, and checks
# that nothing is left. Needs administrator rights (CI runners have them).
#
#   scripts\test-install.ps1 -Msi dist\Hifaz-0.1.1-x64.msi
param([Parameter(Mandatory = $true)][string]$Msi)
$ErrorActionPreference = "Stop"

$msiPath = (Resolve-Path $Msi).Path
$dir     = Join-Path $env:ProgramFiles "Hifaz"
$runKey  = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
$nrpt    = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig\{DE105279-EF28-4AD4-A74D-47C351D88095}"
New-Item -ItemType Directory -Force -Path build | Out-Null

function Invoke-Msi([string]$action, [string]$log) {
  $p = Start-Process msiexec.exe -ArgumentList "$action `"$msiPath`" /qn /norestart /l*v `"$log`"" -Wait -PassThru
  if ($p.ExitCode -ne 0) {
    Get-Content $log -Tail 80
    throw "msiexec $action failed with exit code $($p.ExitCode)"
  }
}
function Check([bool]$ok, [string]$what) {
  if (-not $ok) { throw "FAILED: $what" }
  Write-Host "ok: $what"
}

# Install
Invoke-Msi "/i" "build\install.log"
foreach ($f in "hifaz.exe", "hifaz-service.exe", "wireguard.dll",
                "licenses\THIRD-PARTY-NOTICES.txt", "licenses\wireguard-nt-LICENSE.txt", "licenses\COPYRIGHT.txt") {
  Check (Test-Path (Join-Path $dir $f)) "installed $f"
}
$svc = Get-Service -Name Hifaz -ErrorAction SilentlyContinue
Check ($null -ne $svc) "service registered"
$deadline = (Get-Date).AddSeconds(30)
while ((Get-Service Hifaz).Status -ne "Running" -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 500 }
Check ((Get-Service Hifaz).Status -eq "Running") "service running"
$deadline = (Get-Date).AddSeconds(15)
while (-not (Test-Path "\\.\pipe\Hifaz") -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 500 }
Check (Test-Path "\\.\pipe\Hifaz") "service pipe open"
Check (Test-Path (Join-Path $dir "Data\service.log")) "service data folder and log"
$run = (Get-ItemProperty $runKey -Name Hifaz -ErrorAction SilentlyContinue).Hifaz
Check ($run -like "*hifaz.exe*--background*") "start-up entry for all users"
$recovery = (sc.exe qfailure Hifaz) -join "`n"
Check ($recovery -match "RESTART") "service restarts on failure"

# Remove
Invoke-Msi "/x" "build\uninstall.log"
Check ($null -eq (Get-Service -Name Hifaz -ErrorAction SilentlyContinue)) "service removed"
Check (-not (Test-Path $dir)) "install folder removed"
Check ($null -eq (Get-ItemProperty $runKey -Name Hifaz -ErrorAction SilentlyContinue)) "start-up entry removed"
Check (-not (Test-Path $nrpt)) "no DNS rule left"
Check ($null -eq (Get-NetAdapter -Name Hifaz -ErrorAction SilentlyContinue)) "no adapter left"
Write-Host "Install and removal checked."

# Builds Hifaz for Windows: both programs and the MSI, for x64 and arm64.
#
#   scripts\build.ps1 -Version 0.1.0 [-Arch x64,arm64] [-Release] [-NoMsi]
#
# Needs Go (the version in go.mod or newer), PowerShell 5+, and for the MSI
# the WiX Toolset ($WixVersion below; "dotnet tool install --global wix").
# -Release requires the pinned WireGuardNT hash (see third_party/wireguard-nt).
# Output: dist\Hifaz-<version>-<arch>.msi and .sha256 files.
param(
  [Parameter(Mandatory = $true)][string]$Version,
  [string[]]$Arch = @("x64", "arm64"),
  [switch]$Release,
  [switch]$NoMsi
)
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

# WiX 5 is the last release under its plain open-source licence (MS-RL);
# later releases add the Open Source Maintenance Fee EULA.
$WixVersion = "5.0.2"

if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw "Version must be X.Y.Z (got $Version)" }

& (Join-Path $PSScriptRoot "fetch-wireguard-nt.ps1") -Out build\wireguard-nt -RequirePin:$Release
$sdk = "build\wireguard-nt\sdk\wireguard-nt"

$env:CGO_ENABLED = "0"
$ldflags = "-s -w -X github.com/Yaman-Astaif/Hifaz-Windows-client/internal/version.Version=$Version"
New-Item -ItemType Directory -Force -Path dist | Out-Null

foreach ($a in $Arch) {
  $goarch = @{ x64 = "amd64"; arm64 = "arm64" }[$a]
  if (-not $goarch) { throw "unknown architecture $a" }
  $bin = "build\bin-$a"
  if (Test-Path $bin) { Remove-Item -Recurse -Force $bin }
  New-Item -ItemType Directory -Force -Path "$bin\licenses" | Out-Null

  $env:GOOS = "windows"; $env:GOARCH = $goarch
  go build -trimpath -ldflags "$ldflags -H windowsgui" -o "$bin\hifaz.exe" .\cmd\hifaz
  if ($LASTEXITCODE -ne 0) { throw "building hifaz.exe ($a) failed" }
  go build -trimpath -ldflags $ldflags -o "$bin\hifaz-service.exe" .\cmd\hifaz-service
  if ($LASTEXITCODE -ne 0) { throw "building hifaz-service.exe ($a) failed" }

  Copy-Item "$sdk\bin\$goarch\wireguard.dll" "$bin\wireguard.dll"
  Copy-Item "$sdk\LICENSE.txt" "$bin\licenses\wireguard-nt-LICENSE.txt"
  Copy-Item "THIRD-PARTY-NOTICES.txt" "$bin\licenses\THIRD-PARTY-NOTICES.txt"
  Copy-Item "COPYRIGHT" "$bin\licenses\COPYRIGHT.txt"

  if (-not $NoMsi) {
    $msi = "dist\Hifaz-$Version-$a.msi"
    wix build installer\hifaz.wxs -arch $a -d "Version=$Version" -d "BinDir=$bin" -o $msi
    if ($LASTEXITCODE -ne 0) { throw "building $msi failed" }
    $h = (Get-FileHash -Algorithm SHA256 $msi).Hash.ToLowerInvariant()
    Set-Content -Path "$msi.sha256" -Value "$h  $(Split-Path $msi -Leaf)" -Encoding ascii
    Write-Host "$msi  $h"
  }
}
Remove-Item Env:GOOS, Env:GOARCH

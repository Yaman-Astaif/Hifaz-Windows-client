# Downloads the official WireGuardNT SDK and checks it before use.
#
#   scripts\fetch-wireguard-nt.ps1 [-Out build\wireguard-nt] [-RequirePin]
#
# Checks, in this order:
#   1. SHA-256 of the zip against third_party\wireguard-nt\SHA256, if set
#      (required with -RequirePin, which release builds use);
#   2. every wireguard.dll carries a valid Authenticode signature by
#      WireGuard LLC.
# The DLL is never modified: its licence allows shipping it unmodified,
# next to a program that uses it only through wireguard.h.
param(
  [string]$Out = "build\wireguard-nt",
  [switch]$RequirePin
)
$ErrorActionPreference = "Stop"

$Version = "1.1"
$Url     = "https://download.wireguard.com/wireguard-nt/wireguard-nt-$Version.zip"
$PinFile = Join-Path $PSScriptRoot "..\third_party\wireguard-nt\SHA256"

New-Item -ItemType Directory -Force -Path $Out | Out-Null
$zip = Join-Path $Out "wireguard-nt-$Version.zip"
Invoke-WebRequest -Uri $Url -OutFile $zip -UseBasicParsing
$hash = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLowerInvariant()

$pin = ""
if (Test-Path $PinFile) {
  $pin = ((Get-Content $PinFile | Where-Object { $_ -notmatch '^\s*#' -and $_.Trim() -ne "" }) -join "").Trim().ToLowerInvariant()
}
if ($pin -ne "") {
  if ($hash -ne $pin) { throw "wireguard-nt-$Version.zip: SHA-256 $hash does not match the pinned $pin" }
  Write-Host "SHA-256 matches the pin."
} elseif ($RequirePin) {
  throw "No SHA-256 pinned in third_party\wireguard-nt\SHA256. Check the signature below on a trusted machine, then pin: $hash"
} else {
  Write-Warning "No SHA-256 pinned yet. Downloaded zip: $hash"
}

$dest = Join-Path $Out "sdk"
if (Test-Path $dest) { Remove-Item -Recurse -Force $dest }
Expand-Archive -Path $zip -DestinationPath $dest
$root = Join-Path $dest "wireguard-nt"

foreach ($arch in @("amd64", "arm64")) {
  $dll = Join-Path $root "bin\$arch\wireguard.dll"
  $sig = Get-AuthenticodeSignature -FilePath $dll
  if ($sig.Status -ne "Valid") { throw "$($dll): signature $($sig.Status)" }
  if ($sig.SignerCertificate.Subject -notmatch "O=WireGuard LLC") {
    throw "$($dll): signed by $($sig.SignerCertificate.Subject), not WireGuard LLC"
  }
  Write-Host "$arch wireguard.dll: signed by WireGuard LLC."
}
Write-Host "WireGuardNT $Version ready in $root"

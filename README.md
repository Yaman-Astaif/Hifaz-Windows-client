# Hifaz for Windows - حِفاظ

The Windows app for [Hifaz](https://github.com/Yaman-Astaif/Hifaz), the
WireGuard sign-in gateway: enroll this computer with the link your
administrator sends, sign in (password and MFA), and the tunnel opens; sign
out, go idle or reach the time limit, and it closes.

It speaks the Hifaz client protocol, version 1 (`docs/client-protocol.md` in
the Hifaz repository), so it works with any Hifaz server from 0.8.0 on
(`MinServerVersion` in `internal/protocol`).
Nothing in it is specific to one organisation: no server names, domains or
settings are built in.

Current release: **0.1.0**. Needs a Hifaz server **0.8.0 or later**; with
an older server the app says so.

## How it is built

| Part | Runs as | Does |
|---|---|---|
| `hifaz.exe` (the app) | the signed-in user, no admin rights | Window (WebView2) and tray icon. Holds the device keys (DPAPI, current user), talks to the server, verifies its signatures. |
| `hifaz-service.exe` (the Hifaz service) | LocalSystem | The only part that touches the network: one WireGuardNT adapter, its routes and DNS. Applies only what the server signed for the calling user. |
| `wireguard.dll` | loaded by the service | The official WireGuardNT driver and API, unmodified. |

The app and the service talk over a local pipe. Installing needs admin
rights once; using the app, enrolling, signing in and connecting do not.
The security model is in [docs/architecture.md](docs/architecture.md).

## Repository layout

```
cmd/hifaz/              the app (Windows)
cmd/hifaz-service/      the service (Windows)
internal/protocol/      client protocol v1: keys, signatures, sealed PSK, HTTP client
internal/app/           app logic: enrollment, sign-in, session, key renewal
internal/daemon/        service logic: nonces, server identities, policy, tunnel owner
internal/ipc/           app <-> service messages, the named pipe
internal/tunnel/        WireGuardNT adapter, routes, MTU, split DNS (NRPT)
internal/policy/        machine policy (allowed servers, full tunnel)
internal/keystore/      the user's enrolled servers, keys sealed with DPAPI
internal/winui/         window (WebView2), tray, preferences
internal/ui/web/        the window's pages: Arabic and English, RTL, light and dark
internal/service/       Windows service wrapper
internal/sysinfo/       Windows version text, user proxy settings
internal/fakeserver/    in-memory Hifaz server, for tests only
installer/hifaz.wxs     MSI definition (WiX)
scripts/                build, WireGuardNT download and checks, third-party updates
third_party/            WireGuard code and licences (see each README)
```

Platform-independent logic lives in files without `_windows`, so most of the
code is tested on any system. The Windows files only talk to Windows.

## Build and test

Everyday checks, on any system with Go (see `go.mod`):

```sh
make check        # gofmt, vet (Linux, Windows x64 and arm64), tests with -race, cross-builds
```

The installer, on Windows (PowerShell, Go, and `dotnet tool install --global wix --version 5.0.2`):

```powershell
scripts\build.ps1 -Version 0.1.0                 # dist\Hifaz-0.1.0-x64.msi and -arm64.msi
scripts\build.ps1 -Version 0.1.0 -Arch x64 -NoMsi
```

Against the real Hifaz server (any system, with a Hifaz checkout):

```sh
scripts/interop-hifaz.sh ../Hifaz
```

CI (`.github/workflows/ci.yml`) runs `make check` on Linux and, on Windows,
the full tests, a real WireGuardNT adapter test, and a test installer
(downloadable from the run for a test VM).

Testing against a real server: [docs/testing.md](docs/testing.md).

## Releases

Tags are `vX.Y.Z`. Publish the release in the browser with an empty title
and description; the release workflow builds both installers, attaches them
with their SHA-256 files, and fills the title and notes from
[CHANGELOG.md](CHANGELOG.md). Release builds need the WireGuardNT hash
pinned (`third_party/wireguard-nt/SHA256`).

## Administrators

Machine policy, optional, under `HKLM\SOFTWARE\Policies\Hifaz` (by hand,
Group Policy or device management):

| Value | Type | Meaning |
|---|---|---|
| `AllowFullTunnel` | REG_DWORD | `1` lets a server route all traffic through the tunnel. Off by default. |
| `Servers` | REG_MULTI_SZ | If set, the only servers allowed: `https://vpn.example.com` or `https://vpn.example.com <fingerprint>`. |

An entry that cannot be read makes the service allow no server.

## Decisions

- Our own app and tunnel on the official WireGuardNT components, not
  driving the WireGuard app. The WireGuard app and other VPNs keep working
  side by side: Hifaz has its own adapter, routes only the ranges the server
  sends, adds DNS rules only for the server's domains, and sets no firewall
  rules.
- Device key and WireGuard key are made on the device and sealed with
  DPAPI for the current user (no admin rights). A TPM-backed key is a later
  step.
- Full tunnel only when the machine policy allows it.
- Installer: MSI (WiX 5, the last release under its plain open-source
  licence). Builds are unsigned for now; Windows SmartScreen warns once.

## Copyright

Copyright (C) 2026 Yaman Astaif. All rights reserved (see `COPYRIGHT`).
Third-party parts keep their own licences: `THIRD-PARTY-NOTICES.txt`.

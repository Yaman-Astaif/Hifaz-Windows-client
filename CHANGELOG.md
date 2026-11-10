# Changelog

## 0.1.0 — 2026-11-11

First release. **Needs a Hifaz server 0.8.0 or later** (client protocol
version 1); with an older server the app says so and asks you to have the
server updated. Windows 10 or 11, x64 or ARM64.

**Enrollment**
- Paste the enrollment link from your administrator; the app checks the
  server's identity (fingerprint in the link, or compared by you for older
  links), asks for the password and sets up two-step verification.
- The device makes its own keys; they never leave this computer and are
  sealed for your Windows account.

**Connection**
- Sign in with password and code; the tunnel opens with only the networks
  your group may reach, and names in your organisation's domains resolve
  through Hifaz.
- Configuration changes apply by themselves; when the session ends (sign
  out, idle, time limit, administrator) the tunnel closes and the window
  says why.
- Keys are renewed by themselves when the server asks; the new tunnel keys
  are used from the next sign-in, and a crash during renewal never locks
  the device out.
- Groups that require a device certificate: the app makes its own
  certificate key, gets the certificate at enrollment and renewal, and
  presents it when the server's proxy asks.

**App**
- Arabic and English, right-to-left, light and dark themes, in the style of
  the Hifaz sign-in pages.
- Tray icon with connect, disconnect and quit; starts with Windows (can be
  turned off).
- Works for normal users; installing needs administrator rights once.
- Works next to the WireGuard app and other VPNs; removing Hifaz leaves
  nothing behind.
- Signing in again after a session ended reconnects at once: each sign-in
  gets a new tunnel, with no waiting on old WireGuard session keys.
- The About page shows the version, the developer, the server version the
  app needs, and the third-party components with their licences.

**Known limits**
- The installer is not code-signed yet: Windows SmartScreen warns once
  ("More info" → "Run anyway").
- Proxy auto-configuration (PAC) scripts are not used; a manual proxy set
  in Windows is.

**Administrators**
- Optional machine policy: allowed servers, and whether full tunnels are
  allowed (off by default).

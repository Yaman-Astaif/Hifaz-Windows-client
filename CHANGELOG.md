# Changelog

## 0.1.0 — unreleased

First version, for Hifaz 0.8.0 (client protocol version 1).

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
- Keys are renewed by themselves before they expire.

**App**
- Arabic and English, right-to-left, light and dark themes, in the style of
  the Hifaz sign-in pages.
- Tray icon with connect, disconnect and quit; starts with Windows (can be
  turned off).
- Works for normal users; installing needs administrator rights once.
- Works next to the WireGuard app and other VPNs; removing Hifaz leaves
  nothing behind.

**Administrators**
- Optional machine policy: allowed servers, and whether full tunnels are
  allowed (off by default).

# Architecture and security model

## Parts and trust

```
 user (no admin)                         system
┌──────────────────────────┐   pipe   ┌──────────────────────────────┐
│ hifaz.exe                │◄────────►│ hifaz-service.exe (SYSTEM)   │
│  window (WebView2), tray │          │  engine: nonces, identities, │
│  keystore (DPAPI)        │          │  policy, one tunnel          │
│  protocol client ────────┼──HTTPS──►│  WireGuardNT (wireguard.dll) │
└──────────────────────────┘  server  └──────────────────────────────┘
```

- The **app** holds the user's keys and talks to the server. It verifies
  every signed document against the server fingerprint pinned at
  enrollment.
- The **service** owns the adapter. It trusts nothing the app says by
  itself: it applies a configuration only from a document signed by the
  server identity *the same Windows user* recorded at enrollment, answering
  a nonce *the service* gave *that user*, and allowed by the machine policy.
- The **server** is identified by its Ed25519 identity key, not by TLS
  alone (TLS usually ends at a reverse proxy).

## What each check stops

| Threat | Stopped by |
|---|---|
| A copied config file used elsewhere | There is none: keys are made on the device and never leave it. Sign-in needs the device key. |
| Certificate groups | A separate ECDSA P-256 key made by the app, sealed with the other keys; the certificate is presented in the TLS handshake to the proxy, which checks it and tells Hifaz. |
| A proxy that ends TLS reads the preshared key | The PSK is sealed to the device's WireGuard key (protocol Appendix A). |
| A fake server behind a valid TLS certificate | Every document is checked against the pinned identity; links carry the fingerprint. |
| Replaying an old server answer to the service | Nonces are issued by the service per Windows user, used once, valid 10 minutes; answers must be fresh. |
| Another Windows user using my device | Keys are sealed with DPAPI for my account; the service records server identities per user SID. |
| Another Windows user taking over or ending my tunnel | The tunnel belongs to the connection that opened it; others get "busy" and see no details. |
| A user creating a fake pipe to steal keys | The app checks the pipe belongs to SYSTEM before sending anything. Users cannot add instances to the real pipe (no FILE_CREATE_PIPE_INSTANCE). The service creates it with FILE_FLAG_FIRST_PIPE_INSTANCE. |
| The service acting as the app's user | The app connects at identification level: the service can see who it is, not act as them. |
| Remote access to the pipe | Remote clients rejected; network logons denied. |
| A server routing all traffic without the administrator's consent | Full tunnels (however split) are refused unless the policy allows them. This covers routes only: while connected, all DNS goes to the server's DNS even when full tunnels are not allowed (see Limits). |
| A dead tunnel leaving the machine without DNS | The app's HTTP client remembers the first address it reached for the server in this sign-in, before the tunnel was up, and connects to it when the name no longer resolves, so it still learns the session has ended; the tunnel then closes and its DNS goes with it. An address learned through Hifaz DNS is never remembered (each sign-in builds a new client). One edge remains: a server name that already resolves, before sign-in, to a local address inside the tunnel's routes. |
| Endpoint lookup returns no usable address | The service skips unspecified, loopback and multicast addresses and chooses the first usable IPv4 answer, falling back to the first usable IPv6 answer. If none remain, sign-in fails and the error names the endpoint host. During reconfiguration, a failed lookup is logged and the current endpoint is kept. |
| Endpoint resolving inside the tunnel | When the endpoint name changes while connected, the lookup goes to the server's DNS. If the answer is a private, CGNAT, unique-local or link-local address inside the server's narrower routes, it is assumed to be a private answer from the server's DNS, reachable only through the tunnel. The driver does not send the encrypted packets into its own interface, so the tunnel would stop working. The service keeps the current endpoint and logs a line; the next sign-in resolves again. A public address, a literal IP endpoint, or any address when the routes cover its whole family (a full tunnel, however split, as for the full-tunnel policy) is followed. If only the port changes, the service keeps the address without a lookup. |
| Planting files where the service writes | Service data is in `Program Files\Hifaz\Data` (users cannot create anything there beforehand), with a protected ACL; links are refused. |
| Uninstall deleting the wrong folder | Per-user folders that are links are removed as links only. |
| Another VPN's kill switch | The WireGuard app's "Block untunneled traffic" drops Hifaz's packets before they reach the Hifaz adapter. Hifaz never changes or works around another app's firewall, routes or DNS. It applies its DNS only after the server's first handshake, so the user's DNS keeps working; the app says the server doesn't answer, and, from a read-only WFP check, names the WireGuard tunnel to change. |
| Script injection in the window | The page sets text only, never HTML; strict CSP; no external content; dev tools, context menu and password autosave off. |

Limits, stated plainly:

- DPAPI does not protect against other programs running **as the same
  user**. A TPM-backed key is the later step.
- A local user can enroll with a server of their choosing; the policy's
  server list is how an administrator prevents that.
- Up to 64 connections to the service at once, not per user.
- While connected, every name the machine looks up goes to the server's
  DNS: the server sees all of them and can answer any name with any
  address. This is so for every enrolled server while it is the one
  connected, and even where the policy
  does not allow full tunnels. HTTPS is still protected by certificates
  (a wrong address fails the certificate check); plain HTTP is not. The
  machine policy cannot yet keep the old split DNS (only the server's own
  domains sent to it).
- While Hifaz is connected, another VPN that relies on its adapter's DNS
  without an NRPT rule of its own loses its private names; another VPN's
  more specific NRPT rules still win. This ends when Hifaz disconnects.

## Session lifecycle

1. **Enroll**: paste link → info (fingerprint check) → password (+MFA setup)
   → keys made on the device → `enroll/finish` with a service nonce → the
   service records the identity from the signed answer → keys sealed.
2. **Sign in**: service nonce → `login` (signed by the device key) → OTP if
   asked → signed session document → the service checks it and brings the
   adapter up with the keys the app hands it (wiped from memory on
   disconnect).
3. **Follow**: long-poll `session` with the configuration version in use;
   every answer goes to the service, which applies a newer configuration
   or takes the tunnel down when the session ended.
4. **Renew**: when the server sends `renew_after` and it has passed, new
   WireGuard and device keys (and a new certificate in certificate groups).
   The new WireGuard keys are saved as *pending*; the tunnel keeps the old
   ones, and the next sign-in announces the new key (`wg_public_key`) and
   adopts it. The new device key is used once saved. The server keeps the
   old keys until the new ones are used, so a crash at any point never
   locks the device out.
5. **End**: sign-out, idle, time limit, the administrator, the app
   closing, or the Windows session ending all take the tunnel down, which
   deletes the adapter with its WireGuard session keys. The next sign-in
   always gets a new adapter, so it handshakes with the first packet instead
   of trying the old keys until WireGuard gives up on them (about 10–15
   seconds, as seen with clients that keep the tunnel configured). No
   persistent keepalive: the server detects idle sessions by silence.

While the tunnel is up the service checks, every second, whether the
server answers (`internal/daemon/link.go`), from WireGuard's last handshake
and the bytes sent:

- **Waiting**: after sign-in, the service sends one probe packet into the
  tunnel (a DNS query to the server's DNS address inside the routes, or else
  to the first address of the first route) so WireGuard makes a handshake.
  The app shows "Waiting for the Hifaz server to answer". DNS is not applied
  yet: the user's own DNS keeps working.
- **Up** (shown as Connected): the first handshake came. Hifaz DNS (interface
  DNS and the NRPT rule) is applied now. Nothing is sent to keep the link
  up; an idle tunnel with an old handshake stays up.
- **No answer**: no handshake within 10 seconds of sign-in, or more than 3
  minutes since the last one while traffic is being sent (plus 15 seconds'
  grace). Hifaz DNS is removed until the server answers again; the tunnel
  stays. The app
  says "Signed in, but the Hifaz server doesn't answer", and why when it can
  tell: when there is no answer, the service checks once a minute. It reads the
  Windows Filtering Platform (WFP), read-only, for the WireGuard app's kill
  switch: a provider named `WireGuard` with a block-all filter in the
  outbound connection layers; its permit filter for one adapter names the
  tunnel. When no blocker is known, the app shows the general text.

Probes are bounded: one every 10 seconds, only while waiting or with no
answer, and only for 90 seconds (`probeWindow`, WireGuard's own limit for
handshake retries) after sign-in, after a new server key, after the link
went from up to no answer, or when a blocker found while there was no
answer is gone (the user turned the other VPN's kill switch off; with DNS
off nothing else would start a handshake). They are never re-armed by a
timer, and a blocker going away re-arms them once per change. The server
counts received handshake initiations as activity, so endless probing could
keep a session whose handshake never completes from going idle (protocol
section 8). After the window only the user's own traffic makes WireGuard try
again, and a handshake then still brings Connected and DNS back; with no
blocker found, the general text tells the user to sign out and in once the
cause is fixed.

A new server key in a configuration starts waiting again. Idle, the time
limit, sign-out and the rest end the tunnel as before. While connected, the
service checks for the WireGuard kill switch every 30 seconds. If it finds
one, Hifaz removes its DNS settings and shows the blocker. It checks
again every minute and resumes probing when the blocker clears.

## Coexistence

- Own adapter (`Hifaz`, fixed GUID) next to any WireGuard or other VPN
  adapters. The driver skips its own interface when it routes to the
  server, so no extra host route is needed.
- Routes only for `allowed_ips`.
- DNS: when the server sends DNS servers, split and full tunnels alike set
  them on the interface (with the search domains) and add one NRPT rule
  (fixed key) for all names (`.`). So while connected every lookup goes to
  Hifaz DNS, as with the WireGuard app's `DNS =` line: Hifaz DNS can give a
  private answer for a name outside its zone, and in strict DNS mode it is
  the only DNS the user may use. Routes stay split. A DNS server outside
  `allowed_ips` is still applied (its queries leave by the normal network)
  and the service logs it. The rule and interface DNS go when the tunnel
  goes down, and the DNS cache is flushed, so the user's own DNS works again
  at once. If Group Policy sets NRPT rules, Windows ignores local ones; the
  service logs it rather than writing into the policy area. All of this
  waits for the server's first handshake and is removed while the server
  doesn't answer (see Session lifecycle), so a blocked tunnel never leaves
  the machine without DNS.
- No firewall rules, no kill switch, no keepalive (sessions must be able to
  go idle); probe packets only while the server doesn't answer, and for at
  most 90 seconds at a time. Other
  programs' firewall rules are only read, to say why the server doesn't
  answer.
- Uninstall removes the adapter, the rule, the driver if no other program
  uses it (the WireGuard app reinstalls it when it needs it), the service
  data and every user's Hifaz folder.

// Package daemon is the logic of the Hifaz service, without the Windows
// parts: it answers the app's requests, keeps the server identity each
// Windows user enrolled with, checks every signed document before acting on
// it, applies the machine policy, and owns the tunnel.
//
// What it guarantees:
//
//   - A tunnel is configured only from a session document signed by the
//     identity the same Windows user recorded at enrollment, answering a
//     nonce this service gave that user, and allowed by the machine policy.
//   - One tunnel at a time. It belongs to the connection that opened it and
//     ends when that connection closes or its Windows session ends.
//   - Another Windows user sees only that the tunnel is in use.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"slices"
	"sync"
	"time"

	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/ipc"
	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/policy"
	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/protocol"
)

// Caller identifies who sent a request: the Windows user and logon session
// of the process at the other end of the pipe.
type Caller struct {
	SID     string
	Session uint32
}

// Tunnel is the network side, implemented on Windows by internal/tunnel.
type Tunnel interface {
	// Up creates the adapter and applies cfg, all but DNS: the engine turns
	// DNS on once the server answers. It must leave nothing behind when it
	// fails.
	Up(cfg *protocol.TunnelConfig, private, psk protocol.Key) error
	// Reconfigure applies a newer configuration to the running tunnel;
	// DNS only while it is on.
	Reconfigure(cfg *protocol.TunnelConfig) error
	// SetDNS applies (on) or removes Hifaz's DNS: the interface DNS and
	// the name resolution rule.
	SetDNS(on bool) error
	// Probe sends one packet into the tunnel, so WireGuard starts a
	// handshake. It never waits for an answer.
	Probe() error
	// Down removes the adapter, its routes and its DNS rules.
	Down() error
	// Stats reads traffic counters.
	Stats() (Stats, error)
}

// Stats are the tunnel's counters.
type Stats struct {
	LastHandshake    time.Time
	RxBytes, TxBytes uint64
}

// Limits on outstanding nonces.
const (
	nonceTTL        = 10 * time.Minute
	noncesPerCaller = 32
	watchTimeout    = 30 * time.Second
)

// Engine is the service logic. It is safe for concurrent use.
type Engine struct {
	tunnel Tunnel
	pins   PinStore
	policy func() policy.Policy
	now    func() time.Time
	log    func(msg string, args ...any)
	// findBlocker looks for what keeps the server from answering; nil
	// where it cannot be told.
	findBlocker func() (*ipc.Blocker, error)
	// blockerErr is the last lookup error logged; only Run's goroutine
	// (checkLink) uses it.
	blockerErr string

	mu       sync.Mutex
	nonces   map[string][]issuedNonce // SID -> nonces, oldest first
	owner    *owner
	state    ipc.State
	gen      uint64
	changed  chan struct{} // closed when gen changes
	lastErrs map[string]string
}

type issuedNonce struct {
	value  string
	issued time.Time
}

type owner struct {
	conn        uint64
	caller      Caller
	server      string
	cfg         *protocol.TunnelConfig
	sessionID   string
	expiresAt   time.Time
	issuedAt    time.Time
	connectedAt time.Time
	link        *link
}

// Options configure an Engine.
type Options struct {
	Tunnel Tunnel
	Pins   PinStore
	Policy func() policy.Policy          // nil: the default policy
	Now    func() time.Time              // nil: time.Now
	Log    func(msg string, args ...any) // nil: no logging
	// FindBlocker reports what keeps the server from answering, if it can
	// tell: nil, nil when nothing is found. It must only read. nil: not
	// available.
	FindBlocker func() (*ipc.Blocker, error)
}

// New returns an Engine.
func New(o Options) *Engine {
	e := &Engine{
		tunnel: o.Tunnel, pins: o.Pins, policy: o.Policy, now: o.Now, log: o.Log, findBlocker: o.FindBlocker,
		nonces: map[string][]issuedNonce{}, state: ipc.StateIdle,
		changed: make(chan struct{}), lastErrs: map[string]string{},
	}
	if e.policy == nil {
		e.policy = func() policy.Policy { return policy.Policy{} }
	}
	if e.now == nil {
		e.now = time.Now
	}
	if e.log == nil {
		e.log = func(string, ...any) {}
	}
	return e
}

// Handle answers one request from connection conn. It may block (watch)
// until ctx ends.
func (e *Engine) Handle(ctx context.Context, conn uint64, c Caller, req *ipc.Request) *ipc.Response {
	defer req.Wipe()
	if c.SID == "" {
		return fail(ipc.ErrBadRequest, "unknown caller")
	}
	switch req.Op {
	case ipc.OpStatus:
		return &ipc.Response{Status: e.status(c)}
	case ipc.OpWatch:
		return e.watch(ctx, c, req.Since)
	case ipc.OpNonce:
		return e.nonce(c)
	case ipc.OpRegister:
		return e.register(c, req)
	case ipc.OpForget:
		return e.forget(c, req)
	case ipc.OpConnect:
		return e.connect(conn, c, req)
	case ipc.OpUpdate:
		return e.update(conn, c, req)
	case ipc.OpDisconnect:
		return e.disconnect(conn, c)
	default:
		return fail(ipc.ErrBadRequest, "unknown request")
	}
}

// Closed is called when a connection ends; the tunnel it owns goes down.
func (e *Engine) Closed(conn uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.owner != nil && e.owner.conn == conn {
		e.log("tunnel owner disconnected; taking the tunnel down")
		e.downLocked("")
	}
}

// SessionEnded is called when a Windows logon session ends.
func (e *Engine) SessionEnded(session uint32) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.owner != nil && e.owner.caller.Session == session {
		e.log("owner's Windows session ended; taking the tunnel down", "session", session)
		e.downLocked("")
	}
}

// Shutdown takes the tunnel down; called when the service stops.
func (e *Engine) Shutdown() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.owner != nil {
		e.downLocked("")
	}
}

// --- requests ----------------------------------------------------------------------

func (e *Engine) status(c Caller) *ipc.Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.statusLocked(c)
}

func (e *Engine) statusLocked(c Caller) *ipc.Status {
	s := &ipc.Status{Generation: e.gen, State: e.state, Owner: ipc.OwnerNone, LastError: e.lastErrs[c.SID]}
	if e.owner == nil {
		return s
	}
	if e.owner.caller.SID != c.SID {
		s.Owner = ipc.OwnerOther
		return s
	}
	s.Owner = ipc.OwnerYou
	s.Server = e.owner.server
	s.ConfigVersion = e.owner.cfg.Version
	s.Address = e.owner.cfg.Address.String()
	for _, p := range e.owner.cfg.AllowedIPs {
		s.AllowedIPs = append(s.AllowedIPs, p.String())
	}
	s.ConnectedAt = e.owner.connectedAt
	s.Link, s.Blocker = e.owner.link.state, e.owner.link.blocker
	dnsActive := e.owner.link.dnsOn && len(e.owner.cfg.DNSServers) > 0
	for _, address := range e.owner.cfg.DNSServers {
		s.DNSServers = append(s.DNSServers, address.String())
	}
	s.DNSActive = &dnsActive
	if st, err := e.tunnel.Stats(); err == nil {
		s.LastHandshake, s.RxBytes, s.TxBytes = st.LastHandshake, st.RxBytes, st.TxBytes
	}
	return s
}

func (e *Engine) watch(ctx context.Context, c Caller, since uint64) *ipc.Response {
	e.mu.Lock()
	if e.gen != since {
		defer e.mu.Unlock()
		return &ipc.Response{Status: e.statusLocked(c)}
	}
	changed := e.changed
	e.mu.Unlock()
	t := time.NewTimer(watchTimeout)
	defer t.Stop()
	select {
	case <-changed:
	case <-t.C:
	case <-ctx.Done():
	}
	return &ipc.Response{Status: e.status(c)}
}

func (e *Engine) nonce(c Caller) *ipc.Response {
	n, err := protocol.NewNonce()
	if err != nil {
		return fail(ipc.ErrInternal, "")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()
	list := e.nonces[c.SID][:0:0]
	for _, x := range e.nonces[c.SID] {
		if now.Sub(x.issued) <= nonceTTL {
			list = append(list, x)
		}
	}
	if len(list) >= noncesPerCaller {
		list = list[len(list)-noncesPerCaller+1:] // drop the oldest
	}
	e.nonces[c.SID] = append(list, issuedNonce{value: n, issued: now})
	return &ipc.Response{Nonce: n}
}

// takeNonceLocked consumes a nonce issued to c, reporting whether it was
// valid and fresh.
func (e *Engine) takeNonceLocked(c Caller, n string) bool {
	list := e.nonces[c.SID]
	for i, x := range list {
		if x.value == n {
			e.nonces[c.SID] = append(list[:i:i], list[i+1:]...)
			return e.now().Sub(x.issued) <= nonceTTL
		}
	}
	return false
}

func (e *Engine) register(c Caller, req *ipc.Request) *ipc.Response {
	server, err := protocol.NormalizeServerURL(req.Server)
	if err != nil || req.Document == nil {
		return fail(ipc.ErrBadRequest, "server and document required")
	}
	key, err := protocol.ParseEd25519PublicKey(req.IdentityKey)
	if err != nil {
		return fail(ipc.ErrBadRequest, "invalid identity key")
	}
	pin := protocol.Pin{Fingerprint: protocol.FingerprintOf(key), Key: key}
	if err := e.policy().AllowsServer(server, pin.Fingerprint); err != nil {
		return fail(ipc.ErrServerNotAllowed, "")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	var enrolled protocol.Enrolled
	if err := e.verifyLocked(c, *req.Document, pin, protocol.TypeEnrolled, server, &enrolled); err != nil {
		return fail(ipc.ErrVerify, err.Error())
	}
	if enrolled.DeviceID == "" {
		return fail(ipc.ErrVerify, "enrollment answer has no device")
	}
	rec := PinRecord{Server: server, Fingerprint: pin.Fingerprint,
		IdentityKey: req.IdentityKey, DeviceID: enrolled.DeviceID, Registered: e.now().UTC()}
	if err := e.pins.Save(c.SID, rec); err != nil {
		e.log("saving server identity failed", "err", err)
		return fail(ipc.ErrInternal, "")
	}
	e.log("server identity recorded", "sid", c.SID, "server", server, "fingerprint", pin.Fingerprint.Display())
	return &ipc.Response{}
}

func (e *Engine) forget(c Caller, req *ipc.Request) *ipc.Response {
	server, err := protocol.NormalizeServerURL(req.Server)
	if err != nil {
		return fail(ipc.ErrBadRequest, "server required")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.owner != nil && e.owner.caller.SID == c.SID && e.owner.server == server {
		e.downLocked("")
	}
	if err := e.pins.Delete(c.SID, server); err != nil {
		return fail(ipc.ErrInternal, "")
	}
	return &ipc.Response{}
}

func (e *Engine) connect(conn uint64, c Caller, req *ipc.Request) *ipc.Response {
	server, err := protocol.NormalizeServerURL(req.Server)
	if err != nil || req.Document == nil || len(req.PrivateKey) != protocol.KeyLen || len(req.PSK) != protocol.KeyLen {
		return fail(ipc.ErrBadRequest, "server, document and keys required")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.owner != nil && e.owner.caller.SID != c.SID {
		return fail(ipc.ErrBusy, "")
	}
	var session protocol.Session
	cfg, errResp := e.checkSessionLocked(c, server, req.Document, &session, true)
	if errResp != nil {
		return errResp
	}
	if e.owner != nil { // the same user again (the app restarted): replace
		e.downLocked("")
	}
	var priv, psk protocol.Key
	copy(priv[:], req.PrivateKey)
	copy(psk[:], req.PSK)
	defer priv.Wipe()
	defer psk.Wipe()

	e.setStateLocked(ipc.StateConnecting)
	if err := e.tunnel.Up(cfg, priv, psk); err != nil {
		e.log("bringing the tunnel up failed", "err", err)
		e.lastErrs[c.SID] = ipc.ErrTunnel
		e.setStateLocked(ipc.StateIdle)
		return fail(ipc.ErrTunnel, err.Error())
	}
	now := e.now()
	e.owner = &owner{conn: conn, caller: c, server: server, cfg: cfg, sessionID: session.SessionID,
		expiresAt: session.ExpiresAt, issuedAt: session.IssuedAt, connectedAt: now.UTC(), link: newLink(now)}
	if e.expireLocked(now) {
		return fail(ipc.ErrVerify, "session expired")
	}
	delete(e.lastErrs, c.SID)
	e.setStateLocked(ipc.StateConnected)
	e.log("tunnel up; waiting for the server to answer", "sid", c.SID, "server", server, "config", cfg.Version)
	e.probeLocked(e.owner.link)
	return &ipc.Response{Status: e.statusLocked(c)}
}

func (e *Engine) update(conn uint64, c Caller, req *ipc.Request) *ipc.Response {
	if req.Document == nil {
		return fail(ipc.ErrBadRequest, "document required")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.expireLocked(e.now()) || e.owner == nil || e.owner.conn != conn {
		return fail(ipc.ErrNotOwner, "")
	}
	var session protocol.Session
	cfg, errResp := e.checkSessionLocked(c, e.owner.server, req.Document, &session, false)
	if errResp != nil {
		return errResp
	}
	if cfg == nil { // the session ended; the reason is in lastErrs
		return &ipc.Response{Status: e.statusLocked(c)}
	}
	e.owner.expiresAt, e.owner.issuedAt = session.ExpiresAt, session.IssuedAt
	if cfg.Version > e.owner.cfg.Version {
		newKey := cfg.ServerPublicKey != e.owner.cfg.ServerPublicKey
		if err := e.tunnel.Reconfigure(cfg); err != nil {
			e.log("applying the new configuration failed; taking the tunnel down", "err", err)
			e.downLocked(ipc.ErrTunnel)
			return fail(ipc.ErrTunnel, err.Error())
		}
		e.owner.cfg = cfg
		e.log("tunnel reconfigured", "config", cfg.Version)
		if newKey {
			// A new peer has no handshake yet: wait for it again.
			e.owner.link.wait(e.now())
			e.log("new server key; waiting for the server to answer")
			e.probeLocked(e.owner.link)
		}
		e.bumpLocked()
	}
	return &ipc.Response{Status: e.statusLocked(c)}
}

func (e *Engine) disconnect(conn uint64, c Caller) *ipc.Response {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.owner == nil {
		return &ipc.Response{Status: e.statusLocked(c)}
	}
	if e.owner.conn != conn {
		return fail(ipc.ErrNotOwner, "")
	}
	e.downLocked("")
	return &ipc.Response{Status: e.statusLocked(c)}
}

// checkSessionLocked verifies a session document from c for server and
// returns its configuration, checked against the policy. For a session that
// has ended it takes the tunnel down and returns (nil, nil); at connect time
// an ended session is an error.
func (e *Engine) checkSessionLocked(c Caller, server string, doc *protocol.SignedDocument, s *protocol.Session, connecting bool) (*protocol.TunnelConfig, *ipc.Response) {
	rec, ok, err := e.pins.Load(c.SID, server)
	if err != nil {
		e.log("reading server identities failed", "err", err)
		return nil, fail(ipc.ErrInternal, "")
	}
	if !ok {
		return nil, fail(ipc.ErrNotRegistered, "")
	}
	pin, err := rec.Pin()
	if err != nil {
		return nil, fail(ipc.ErrInternal, "")
	}
	pol := e.policy()
	if err := pol.AllowsServer(server, pin.Fingerprint); err != nil {
		e.failLocked(c, connecting, ipc.ErrServerNotAllowed)
		return nil, fail(ipc.ErrServerNotAllowed, "")
	}
	if err := e.verifyLocked(c, *doc, pin, protocol.TypeSession, server, s); err != nil {
		return nil, fail(ipc.ErrVerify, err.Error())
	}
	if !connecting && (s.SessionID != e.owner.sessionID || s.IssuedAt.Before(e.owner.issuedAt)) {
		return nil, fail(ipc.ErrVerify, "session update does not match the active session or is older")
	}
	if s.Status != protocol.StatusConnected {
		if connecting {
			return nil, fail(ipc.ErrVerify, "session is not connected")
		}
		reason := s.Reason
		if reason == "" {
			reason = protocol.StatusEnded
		}
		e.log("session ended by the server", "reason", reason)
		e.downLocked(reason)
		return nil, nil
	}
	if s.SessionID == "" || s.ExpiresAt.IsZero() {
		return nil, fail(ipc.ErrVerify, "session ID and deadline required")
	}
	if !e.now().Before(s.ExpiresAt) {
		e.failLocked(c, connecting, protocol.ReasonTimeLimit)
		return nil, fail(ipc.ErrVerify, "session expired")
	}
	cfg, err := s.Config.Parse()
	if err != nil {
		e.failLocked(c, connecting, ipc.ErrBadConfig)
		return nil, fail(ipc.ErrBadConfig, err.Error())
	}
	if err := pol.CheckConfig(cfg); err != nil {
		e.failLocked(c, connecting, ipc.ErrFullTunnel)
		return nil, fail(ipc.ErrFullTunnel, "")
	}
	return cfg, nil
}

// failLocked records a refusal; a refused update also ends the tunnel, since
// the server's configuration is no longer one this computer may apply.
func (e *Engine) failLocked(c Caller, connecting bool, code string) {
	if connecting {
		e.lastErrs[c.SID] = code
		e.bumpLocked()
		return
	}
	e.downLocked(code)
}

// verifyLocked checks a signed document from c: the pinned signature, the
// type, the server, a nonce this service issued to c, and freshness.
func (e *Engine) verifyLocked(c Caller, doc protocol.SignedDocument, pin protocol.Pin, typ, server string, out any) error {
	payload, err := doc.Open(pin)
	if err != nil {
		return err
	}
	h, err := protocol.ParseHeader(payload)
	if err != nil {
		return err
	}
	if !e.takeNonceLocked(c, h.Nonce) {
		return errors.New("the answer does not match a request from this user")
	}
	return doc.Verify(pin, protocol.Expect{Type: typ, Server: server, Nonce: h.Nonce,
		Now: e.now(), MaxSkew: protocol.DefaultMaxSkew}, out)
}

// Run checks every second whether the server answers, until ctx ends.
func (e *Engine) Run(ctx context.Context) {
	t := time.NewTicker(linkPoll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.checkLink()
		}
	}
}

// expireLocked tears down a tunnel whose signed session deadline has passed.
func (e *Engine) expireLocked(now time.Time) bool {
	if e.owner == nil || now.Before(e.owner.expiresAt) {
		return false
	}
	e.log("signed session deadline reached")
	e.downLocked(protocol.ReasonTimeLimit)
	return true
}

// checkLink moves the owner's link state on: DNS on when the server
// answers, off when it does not, a probe while it does not, and a look for
// what blocks it. Only Run calls it.
func (e *Engine) checkLink() {
	e.mu.Lock()
	o := e.owner
	if o == nil || e.expireLocked(e.now()) {
		e.mu.Unlock()
		return
	}
	st, err := e.tunnel.Stats()
	if err != nil {
		e.mu.Unlock()
		return
	}
	before := o.link.state
	a := o.link.step(st, e.now())
	if a.dnsOff {
		e.removeLinkDNSLocked(o.link)
	}
	if a.dnsOn {
		if err := e.tunnel.SetDNS(true); err != nil {
			e.log("applying DNS failed; taking the tunnel down", "err", err)
			e.downLocked(ipc.ErrTunnel)
			e.mu.Unlock()
			return
		}
		o.link.dnsOn = true
	}
	if a.probe {
		e.probeLocked(o.link)
	}
	if a.changed {
		e.bumpLocked()
		e.log("server link", "state", o.link.state, "was", before, "last_handshake", st.LastHandshake)
	}
	lookupState := o.link.state
	check := a.checkBlocker && e.findBlocker != nil
	e.mu.Unlock()
	if !check {
		return
	}

	// Outside the lock: reading the firewall state may take a moment.
	b, err := e.lookForBlocker()
	found := err == nil
	if err != nil {
		if err.Error() != e.blockerErr { // once, not every minute
			e.blockerErr = err.Error()
			e.log("looking for what blocks the server failed", "err", err)
		}
		b = nil
	} else {
		e.blockerErr = ""
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.owner != o || o.link.state != lookupState {
		return
	}
	if lookupState == ipc.LinkUp {
		if b == nil {
			return
		}
		o.link.blocked(e.now())
		e.removeLinkDNSLocked(o.link)
	} else if !found && o.link.blockedWhileUp {
		return // keep the last confirmed blocker until a successful lookup
	}
	blockedWhileUp := o.link.blockedWhileUp
	if found && o.link.blockerFound(b, e.now()) {
		e.log("the block is gone; probing the server again")
		if blockedWhileUp {
			e.probeLocked(o.link)
			o.link.lastProbe = e.now()
		}
	}
	if sameBlocker(o.link.blocker, b) {
		return
	}
	o.link.blocker = b
	e.bumpLocked()
	if b != nil {
		e.log("the server is blocked", "app", b.App, "tunnels", b.Tunnels)
	}
}

func (e *Engine) removeLinkDNSLocked(l *link) {
	if err := e.tunnel.SetDNS(false); err != nil {
		if err.Error() != l.dnsErr { // once per error, not every second
			l.dnsErr = err.Error()
			e.log("removing DNS failed; trying again", "err", err)
		}
	} else {
		l.dnsOn, l.dnsErr = false, ""
	}
}

func sameBlocker(a, b *ipc.Blocker) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.App == b.App && slices.Equal(a.Tunnels, b.Tunnels)
}

// lookForBlocker calls findBlocker; a panic in it (it reads the system's
// firewall state) becomes an error, so the app shows the general text.
func (e *Engine) lookForBlocker() (b *ipc.Blocker, err error) {
	defer func() {
		if r := recover(); r != nil {
			b, err = nil, fmt.Errorf("panic: %v", r)
		}
	}()
	// A fault at a bad address in the system's memory becomes a panic too.
	defer debug.SetPanicOnFault(debug.SetPanicOnFault(true))
	return e.findBlocker()
}

// probeLocked sends a probe for l, logging a failure only the first time in
// the probe window or when the error changes.
func (e *Engine) probeLocked(l *link) {
	if err := e.tunnel.Probe(); err != nil && err.Error() != l.probeErr {
		l.probeErr = err.Error()
		e.log("probe packet not sent", "err", err)
	}
}

// downLocked takes the tunnel down; reason, if set, is recorded for the owner.
func (e *Engine) downLocked(reason string) {
	if e.owner == nil {
		return
	}
	if err := e.tunnel.Down(); err != nil {
		e.log("taking the tunnel down failed", "err", err)
	}
	if reason != "" {
		e.lastErrs[e.owner.caller.SID] = reason
	}
	e.owner = nil
	e.setStateLocked(ipc.StateIdle)
	e.log("tunnel down", "reason", reason)
}

func (e *Engine) setStateLocked(s ipc.State) {
	e.state = s
	e.bumpLocked()
}

func (e *Engine) bumpLocked() {
	e.gen++
	close(e.changed)
	e.changed = make(chan struct{})
}

func fail(code, msg string) *ipc.Response {
	return &ipc.Response{Error: &ipc.Error{Code: code, Message: msg}}
}

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
	// Up creates the adapter and applies cfg. It must leave nothing behind
	// when it fails.
	Up(cfg *protocol.TunnelConfig, private, psk protocol.Key) error
	// Reconfigure applies a newer configuration to the running tunnel.
	Reconfigure(cfg *protocol.TunnelConfig) error
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
	connectedAt time.Time
}

// Options configure an Engine.
type Options struct {
	Tunnel Tunnel
	Pins   PinStore
	Policy func() policy.Policy          // nil: the default policy
	Now    func() time.Time              // nil: time.Now
	Log    func(msg string, args ...any) // nil: no logging
}

// New returns an Engine.
func New(o Options) *Engine {
	e := &Engine{
		tunnel: o.Tunnel, pins: o.Pins, policy: o.Policy, now: o.Now, log: o.Log,
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
	cfg, errResp := e.checkSessionLocked(c, server, req.Document, true)
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
	e.owner = &owner{conn: conn, caller: c, server: server, cfg: cfg, connectedAt: e.now().UTC()}
	delete(e.lastErrs, c.SID)
	e.setStateLocked(ipc.StateConnected)
	e.log("tunnel up", "sid", c.SID, "server", server, "config", cfg.Version)
	return &ipc.Response{Status: e.statusLocked(c)}
}

func (e *Engine) update(conn uint64, c Caller, req *ipc.Request) *ipc.Response {
	if req.Document == nil {
		return fail(ipc.ErrBadRequest, "document required")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.owner == nil || e.owner.conn != conn {
		return fail(ipc.ErrNotOwner, "")
	}
	cfg, errResp := e.checkSessionLocked(c, e.owner.server, req.Document, false)
	if errResp != nil {
		return errResp
	}
	if cfg == nil { // the session ended; the reason is in lastErrs
		return &ipc.Response{Status: e.statusLocked(c)}
	}
	if cfg.Version > e.owner.cfg.Version {
		if err := e.tunnel.Reconfigure(cfg); err != nil {
			e.log("applying the new configuration failed; taking the tunnel down", "err", err)
			e.downLocked(ipc.ErrTunnel)
			return fail(ipc.ErrTunnel, err.Error())
		}
		e.owner.cfg = cfg
		e.bumpLocked()
		e.log("tunnel reconfigured", "config", cfg.Version)
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
func (e *Engine) checkSessionLocked(c Caller, server string, doc *protocol.SignedDocument, connecting bool) (*protocol.TunnelConfig, *ipc.Response) {
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
	var s protocol.Session
	if err := e.verifyLocked(c, *doc, pin, protocol.TypeSession, server, &s); err != nil {
		return nil, fail(ipc.ErrVerify, err.Error())
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

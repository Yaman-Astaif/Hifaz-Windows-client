package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/ipc"
	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/policy"
	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/protocol"
)

const server = "https://vpn.example.com"

var (
	alice = Caller{SID: "S-1-5-21-1-1001", Session: 1}
	bob   = Caller{SID: "S-1-5-21-1-1002", Session: 2}
)

type fakeTunnel struct {
	mu          sync.Mutex
	up          bool
	cfg         *protocol.TunnelConfig
	priv, psk   protocol.Key
	failUp      error
	downs, ups  int
	reconfigure int
	events      []string // "up" and "down", in order
	stats       Stats
	dns         bool
	dnsCalls    []bool
	failDNS     error
	failProbe   error
	probes      int
}

func (f *fakeTunnel) Up(cfg *protocol.TunnelConfig, priv, psk protocol.Key) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failUp != nil {
		return f.failUp
	}
	f.up, f.cfg, f.priv, f.psk = true, cfg, priv, psk
	f.stats, f.dns = Stats{}, false
	f.ups++
	f.events = append(f.events, "up")
	return nil
}

func (f *fakeTunnel) Reconfigure(cfg *protocol.TunnelConfig) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cfg = cfg
	f.reconfigure++
	return nil
}

func (f *fakeTunnel) Down() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.up, f.dns = false, false
	f.downs++
	f.events = append(f.events, "down")
	return nil
}

func (f *fakeTunnel) Stats() (Stats, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	st := f.stats
	st.RxBytes += 10
	st.TxBytes += 20
	return st, nil
}

func (f *fakeTunnel) SetDNS(on bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dnsCalls = append(f.dnsCalls, on)
	if f.failDNS != nil {
		return f.failDNS
	}
	f.dns = on
	return nil
}

func (f *fakeTunnel) Probe() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.probes++
	return f.failProbe
}

type harness struct {
	t       *testing.T
	blocker *ipc.Blocker
	findErr error
	finds   int
	onFind  func() // runs inside FindBlocker, outside the engine's lock
	logs    []string
	e       *Engine
	tun     *fakeTunnel
	id      ed25519.PrivateKey
	pol     policy.Policy
	now     time.Time
	keyB64  string
}

func newHarness(t *testing.T) *harness {
	_, id, _ := ed25519.GenerateKey(rand.Reader)
	h := &harness{t: t, tun: &fakeTunnel{}, id: id, now: time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)}
	h.keyB64 = protocol.EncodeEd25519PublicKey(id.Public().(ed25519.PublicKey))
	h.e = New(Options{Tunnel: h.tun, Pins: NewFileStore(filepath.Join(t.TempDir(), "pins.json")),
		Policy: func() policy.Policy { return h.pol }, Now: func() time.Time { return h.now },
		Log: func(msg string, _ ...any) { h.logs = append(h.logs, msg) },
		FindBlocker: func() (*ipc.Blocker, error) {
			h.finds++
			if h.onFind != nil {
				h.onFind()
			}
			return h.blocker, h.findErr
		}})
	return h
}

func (h *harness) do(conn uint64, c Caller, req ipc.Request) *ipc.Response {
	return h.e.Handle(context.Background(), conn, c, &req)
}

func (h *harness) nonce(c Caller) string {
	r := h.do(1, c, ipc.Request{Op: ipc.OpNonce})
	if r.Error != nil || !protocol.ValidNonce(r.Nonce) {
		h.t.Fatalf("nonce: %+v", r)
	}
	return r.Nonce
}

func (h *harness) sign(key ed25519.PrivateKey, payload map[string]any) *protocol.SignedDocument {
	if _, ok := payload["server"]; !ok {
		payload["server"] = server
	}
	if _, ok := payload["issued_at"]; !ok {
		payload["issued_at"] = h.now
	}
	data, _ := json.Marshal(payload)
	doc := protocol.Sign(key, data)
	return &doc
}

func (h *harness) enrolledDoc(nonce string) *protocol.SignedDocument {
	return h.sign(h.id, map[string]any{"type": protocol.TypeEnrolled, "nonce": nonce, "device_id": "d_1"})
}

func config(version int64, allowed ...string) map[string]any {
	if len(allowed) == 0 {
		allowed = []string{"10.98.0.0/16"}
	}
	return map[string]any{
		"version": version, "address": "10.98.10.4/32",
		"server_public_key": "mkk2/n0976hg+yS1HkmS3Jr4EphDhzmX+vOZ02alXlY=",
		"endpoint":          "vpn.example.com:51820", "allowed_ips": allowed,
		"dns": map[string]any{"servers": []string{"10.98.0.1"}, "search": []string{"corp"}}, "mtu": 1420,
	}
}

func (h *harness) sessionDoc(nonce string, cfg map[string]any) *protocol.SignedDocument {
	return h.sign(h.id, map[string]any{"type": protocol.TypeSession, "nonce": nonce,
		"status": protocol.StatusConnected, "session_token": "tok", "config": cfg})
}

func (h *harness) register(c Caller) {
	r := h.do(1, c, ipc.Request{Op: ipc.OpRegister, Server: server, IdentityKey: h.keyB64, Document: h.enrolledDoc(h.nonce(c))})
	if r.Error != nil {
		h.t.Fatalf("register: %v", r.Error)
	}
}

func (h *harness) connect(conn uint64, c Caller, cfg map[string]any) *ipc.Response {
	return h.do(conn, c, ipc.Request{Op: ipc.OpConnect, Server: server, Document: h.sessionDoc(h.nonce(c), cfg),
		PrivateKey: make32(1), PSK: make32(2)})
}

func make32(b byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b
	}
	return k
}

func code(r *ipc.Response) string {
	if r.Error == nil {
		return ""
	}
	return r.Error.Code
}

func TestRegisterNeedsServiceNonce(t *testing.T) {
	h := newHarness(t)
	req := func(doc *protocol.SignedDocument) *ipc.Response {
		return h.do(1, alice, ipc.Request{Op: ipc.OpRegister, Server: server, IdentityKey: h.keyB64, Document: doc})
	}
	fresh, _ := protocol.NewNonce()
	if code(req(h.enrolledDoc(fresh))) != ipc.ErrVerify {
		t.Fatal("nonce not issued by the service accepted")
	}
	n := h.nonce(alice)
	doc := h.enrolledDoc(n)
	if r := req(doc); r.Error != nil {
		t.Fatal(r.Error)
	}
	if code(req(doc)) != ipc.ErrVerify {
		t.Fatal("replayed enrollment answer accepted")
	}
	// A nonce issued to another Windows user does not count.
	if code(req(h.enrolledDoc(h.nonce(bob)))) != ipc.ErrVerify {
		t.Fatal("another user's nonce accepted")
	}
	// A document signed by another key than the announced identity.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	if code(req(h.sign(other, map[string]any{"type": protocol.TypeEnrolled, "nonce": h.nonce(alice), "device_id": "d_1"}))) != ipc.ErrVerify {
		t.Fatal("document signed by another key accepted")
	}
	// Expired nonce.
	n = h.nonce(alice)
	h.now = h.now.Add(nonceTTL + time.Minute)
	if code(req(h.enrolledDoc(n))) != ipc.ErrVerify {
		t.Fatal("expired nonce accepted")
	}
}

func TestConnectUpdateDisconnect(t *testing.T) {
	h := newHarness(t)
	if code(h.connect(1, alice, config(1))) != ipc.ErrNotRegistered {
		t.Fatal("connect without a recorded identity")
	}
	h.register(alice)
	r := h.connect(7, alice, config(1))
	if r.Error != nil || r.Status.State != ipc.StateConnected || r.Status.Owner != ipc.OwnerYou {
		t.Fatalf("connect: %+v %v", r.Status, r.Error)
	}
	if !h.tun.up || h.tun.priv != protocol.Key(make32(1)) || h.tun.psk != protocol.Key(make32(2)) {
		t.Fatal("tunnel not up with the given keys")
	}

	// Another Windows user sees only that the tunnel is in use.
	st := h.do(9, bob, ipc.Request{Op: ipc.OpStatus}).Status
	if st.Owner != ipc.OwnerOther || st.Server != "" || st.Address != "" || len(st.AllowedIPs) != 0 {
		t.Fatalf("bob sees %+v", st)
	}
	h.register(bob)
	if code(h.connect(9, bob, config(1))) != ipc.ErrBusy {
		t.Fatal("bob took alice's tunnel")
	}
	if code(h.do(9, bob, ipc.Request{Op: ipc.OpDisconnect})) != ipc.ErrNotOwner {
		t.Fatal("bob disconnected alice's tunnel")
	}
	// Only the owning connection may update or disconnect.
	if code(h.do(8, alice, ipc.Request{Op: ipc.OpUpdate, Document: h.sessionDoc(h.nonce(alice), config(2))})) != ipc.ErrNotOwner {
		t.Fatal("update from another connection")
	}

	// Same version: nothing to do; newer version: reconfigure.
	if r := h.do(7, alice, ipc.Request{Op: ipc.OpUpdate, Document: h.sessionDoc(h.nonce(alice), config(1))}); r.Error != nil || h.tun.reconfigure != 0 {
		t.Fatalf("same version: %v, %d", r.Error, h.tun.reconfigure)
	}
	r = h.do(7, alice, ipc.Request{Op: ipc.OpUpdate, Document: h.sessionDoc(h.nonce(alice), config(2, "10.98.0.0/16", "10.20.0.0/16"))})
	if r.Error != nil || h.tun.reconfigure != 1 || len(h.tun.cfg.AllowedIPs) != 2 || r.Status.ConfigVersion != 2 {
		t.Fatalf("reconfigure: %v %+v", r.Error, r.Status)
	}

	// The server ends the session: the tunnel goes down with the reason.
	ended := h.sign(h.id, map[string]any{"type": protocol.TypeSession, "nonce": h.nonce(alice),
		"status": protocol.StatusEnded, "reason": protocol.ReasonIdle})
	r = h.do(7, alice, ipc.Request{Op: ipc.OpUpdate, Document: ended})
	if r.Error != nil || h.tun.up || r.Status.State != ipc.StateIdle || r.Status.LastError != protocol.ReasonIdle {
		t.Fatalf("ended: %v %+v", r.Error, r.Status)
	}
}

func TestOwnerGoneTakesTunnelDown(t *testing.T) {
	h := newHarness(t)
	h.register(alice)
	h.connect(7, alice, config(1))
	h.e.Closed(8) // another connection
	if !h.tun.up {
		t.Fatal("unrelated connection closed the tunnel")
	}
	h.e.Closed(7)
	if h.tun.up {
		t.Fatal("tunnel still up after its owner left")
	}
	h.connect(7, alice, config(1))
	h.e.SessionEnded(bob.Session)
	if !h.tun.up {
		t.Fatal("another session's logoff closed the tunnel")
	}
	h.e.SessionEnded(alice.Session)
	if h.tun.up {
		t.Fatal("tunnel still up after its owner's logoff")
	}
	// The same user reconnecting (app restarted) replaces the tunnel.
	h.connect(7, alice, config(1))
	if r := h.connect(11, alice, config(1)); r.Error != nil || h.tun.downs != 3 || h.tun.ups != 4 {
		t.Fatalf("reconnect: %v downs=%d ups=%d", r.Error, h.tun.downs, h.tun.ups)
	}
	h.e.Closed(7) // the old connection no longer owns it
	if !h.tun.up {
		t.Fatal("the replaced connection closed the new tunnel")
	}
}

func TestPolicy(t *testing.T) {
	h := newHarness(t)
	h.register(alice)
	full := config(1, "0.0.0.0/1", "128.0.0.0/1")
	if code(h.connect(1, alice, full)) != ipc.ErrFullTunnel || h.tun.up {
		t.Fatal("full tunnel applied without policy")
	}
	if st := h.do(1, alice, ipc.Request{Op: ipc.OpStatus}).Status; st.LastError != ipc.ErrFullTunnel {
		t.Fatalf("last error %q", st.LastError)
	}
	h.pol.AllowFullTunnel = true
	if r := h.connect(1, alice, full); r.Error != nil {
		t.Fatal(r.Error)
	}
	// Policy changes while connected: the next update ends the tunnel.
	h.pol.AllowFullTunnel = false
	if code(h.do(1, alice, ipc.Request{Op: ipc.OpUpdate, Document: h.sessionDoc(h.nonce(alice), full)})) != ipc.ErrFullTunnel || h.tun.up {
		t.Fatal("full tunnel kept after the policy changed")
	}

	other, _ := policy.ParseServer("https://other.example.com")
	h.pol.Servers = []policy.Server{other}
	if code(h.do(1, alice, ipc.Request{Op: ipc.OpRegister, Server: server, IdentityKey: h.keyB64, Document: h.enrolledDoc(h.nonce(alice))})) != ipc.ErrServerNotAllowed {
		t.Fatal("register with a server outside the policy")
	}
	if code(h.connect(1, alice, config(1))) != ipc.ErrServerNotAllowed {
		t.Fatal("connect to a server outside the policy")
	}
}

func TestRefusedDocuments(t *testing.T) {
	h := newHarness(t)
	h.register(alice)
	connect := func(doc *protocol.SignedDocument) string {
		return code(h.do(1, alice, ipc.Request{Op: ipc.OpConnect, Server: server, Document: doc, PrivateKey: make32(1), PSK: make32(2)}))
	}
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	for name, doc := range map[string]*protocol.SignedDocument{
		"other key":    h.sign(other, map[string]any{"type": protocol.TypeSession, "nonce": h.nonce(alice), "status": "connected", "config": config(1)}),
		"other server": h.sign(h.id, map[string]any{"type": protocol.TypeSession, "nonce": h.nonce(alice), "status": "connected", "config": config(1), "server": "https://evil.example.com"}),
		"wrong type":   h.sign(h.id, map[string]any{"type": protocol.TypeRenewed, "nonce": h.nonce(alice), "status": "connected", "config": config(1)}),
		"stale":        h.sign(h.id, map[string]any{"type": protocol.TypeSession, "nonce": h.nonce(alice), "status": "connected", "config": config(1), "issued_at": h.now.Add(-time.Hour)}),
		"ended":        h.sign(h.id, map[string]any{"type": protocol.TypeSession, "nonce": h.nonce(alice), "status": "ended"}),
	} {
		if got := connect(doc); got != ipc.ErrVerify {
			t.Errorf("%s: %q", name, got)
		}
	}
	bad := config(1)
	bad["endpoint"] = "no-port"
	if got := connect(h.sessionDoc(h.nonce(alice), bad)); got != ipc.ErrBadConfig {
		t.Errorf("bad config: %q", got)
	}
	if got := code(h.do(1, alice, ipc.Request{Op: ipc.OpConnect, Server: server, Document: h.sessionDoc(h.nonce(alice), config(1)), PrivateKey: []byte{1}})); got != ipc.ErrBadRequest {
		t.Errorf("short key: %q", got)
	}
	if h.tun.ups != 0 {
		t.Fatal("tunnel brought up from a refused document")
	}
	h.tun.failUp = errors.New("adapter failed")
	if got := connect(h.sessionDoc(h.nonce(alice), config(1))); got != ipc.ErrTunnel {
		t.Errorf("failing tunnel: %q", got)
	}
	if st := h.do(1, alice, ipc.Request{Op: ipc.OpStatus}).Status; st.State != ipc.StateIdle || st.LastError != ipc.ErrTunnel {
		t.Fatalf("after failure: %+v", st)
	}
}

func TestWatch(t *testing.T) {
	h := newHarness(t)
	h.register(alice)
	gen := h.do(1, alice, ipc.Request{Op: ipc.OpStatus}).Status.Generation
	done := make(chan *ipc.Status)
	go func() { done <- h.do(2, alice, ipc.Request{Op: ipc.OpWatch, Since: gen}).Status }()
	time.Sleep(50 * time.Millisecond)
	h.connect(1, alice, config(1))
	select {
	case st := <-done:
		if st.Generation == gen || st.State != ipc.StateConnected {
			t.Fatalf("%+v", st)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("watch did not return on change")
	}
	// A stale generation returns at once.
	if st := h.do(2, alice, ipc.Request{Op: ipc.OpWatch, Since: gen}).Status; st.Generation == gen {
		t.Fatal("stale watch blocked")
	}
}

func TestNonceLimit(t *testing.T) {
	h := newHarness(t)
	first := h.nonce(alice)
	for range noncesPerCaller {
		h.nonce(alice)
	}
	if len(h.e.nonces[alice.SID]) != noncesPerCaller {
		t.Fatalf("%d nonces kept", len(h.e.nonces[alice.SID]))
	}
	if h.e.takeNonceLocked(alice, first) {
		t.Fatal("oldest nonce not dropped")
	}
}

func TestFileStore(t *testing.T) {
	s := NewFileStore(filepath.Join(t.TempDir(), "pins.json"))
	if _, ok, err := s.Load("S-1", server); ok || err != nil {
		t.Fatal("empty store")
	}
	rec := PinRecord{Server: server, Fingerprint: "fp", IdentityKey: "k", DeviceID: "d_1"}
	if err := s.Save("S-1", rec); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.Load("S-1", server)
	if err != nil || !ok || got.DeviceID != "d_1" {
		t.Fatalf("%+v %v %v", got, ok, err)
	}
	if _, ok, _ := s.Load("S-2", server); ok {
		t.Fatal("record visible to another SID")
	}
	if err := s.Delete("S-1", server); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.Load("S-1", server); ok {
		t.Fatal("deleted record still there")
	}
}

// Every sign-in gets a new tunnel: whatever ended the previous session, the
// tunnel was taken down (the adapter and its WireGuard session keys deleted)
// before the next one comes up, so the first packet starts a new handshake
// instead of using the old session's keys.
func TestEverySignInStartsAFreshTunnel(t *testing.T) {
	h := newHarness(t)
	h.register(alice)
	ended := func(reason string) {
		doc := h.sign(h.id, map[string]any{"type": protocol.TypeSession, "nonce": h.nonce(alice),
			"status": protocol.StatusEnded, "reason": reason})
		if r := h.do(7, alice, ipc.Request{Op: ipc.OpUpdate, Document: doc}); r.Error != nil {
			t.Fatal(r.Error)
		}
	}
	steps := []func(){
		func() { ended(protocol.ReasonEndedByAdmin) },
		func() { ended(protocol.ReasonIdle) },
		func() { ended(protocol.ReasonSignedOut) },
		func() { h.do(7, alice, ipc.Request{Op: ipc.OpDisconnect}) },
		func() { h.e.Closed(7) },                   // the app closed
		func() { h.e.SessionEnded(alice.Session) }, // Windows sign-out
		func() {}, // signing in again while still up
	}
	for i, end := range steps {
		if r := h.connect(7, alice, config(1)); r.Error != nil {
			t.Fatalf("step %d: %v", i, r.Error)
		}
		end()
	}
	h.connect(7, alice, config(1))
	ev := h.tun.events
	if len(ev) != 2*len(steps)+1 || ev[0] != "up" {
		t.Fatalf("events %v", ev)
	}
	for i := 1; i < len(ev); i += 2 {
		if ev[i] != "down" || ev[i+1] != "up" {
			t.Fatalf("a tunnel came up without the previous one going down first: %v", ev)
		}
	}
}

// tick advances the clock by d, checking the link every second as Run does.
func (h *harness) tick(d time.Duration) {
	for end := h.now.Add(d); h.now.Before(end); {
		h.now = h.now.Add(linkPoll)
		h.e.checkLink()
	}
}

func (h *harness) status(c Caller) *ipc.Status {
	return h.do(1, c, ipc.Request{Op: ipc.OpStatus}).Status
}

func TestLinkDNSAfterFirstAnswer(t *testing.T) {
	h := newHarness(t)
	h.register(alice)
	r := h.connect(7, alice, config(1))
	if r.Error != nil || r.Status.State != ipc.StateConnected || r.Status.Link != ipc.LinkWaiting {
		t.Fatalf("connect: %+v %v", r.Status, r.Error)
	}
	if h.tun.dns || len(h.tun.dnsCalls) != 0 || h.tun.probes != 1 {
		t.Fatalf("at sign-in: dns=%v calls=%v probes=%d", h.tun.dns, h.tun.dnsCalls, h.tun.probes)
	}
	gen := r.Status.Generation
	h.tick(3 * time.Second)
	if st := h.status(alice); st.Generation != gen || st.Link != ipc.LinkWaiting {
		t.Fatalf("still waiting: %+v", st)
	}
	h.tun.stats.LastHandshake = h.now
	h.tick(time.Second)
	st := h.status(alice)
	if st.Link != ipc.LinkUp || st.Generation == gen || !h.tun.dns || st.State != ipc.StateConnected {
		t.Fatalf("after the handshake: %+v dns=%v", st, h.tun.dns)
	}
	if h.tun.probes != 1 || h.finds != 0 {
		t.Fatalf("%d probes, %d blocker checks", h.tun.probes, h.finds)
	}
	// Another Windows user sees nothing of it.
	if st := h.status(bob); st.Link != "" || st.Blocker != nil {
		t.Fatalf("bob sees %+v", st)
	}
}

func TestLinkNoAnswerFindsBlocker(t *testing.T) {
	h := newHarness(t)
	h.register(alice)
	h.blocker = &ipc.Blocker{App: ipc.BlockerWireGuard, Tunnels: []string{"wg-client-10"}}
	gen := h.connect(7, alice, config(1)).Status.Generation
	h.tick(firstAnswerTimeout)
	st := h.status(alice)
	if st.Link != ipc.LinkNoAnswer || st.Generation == gen || h.tun.dns || h.finds != 1 {
		t.Fatalf("no answer: %+v dns=%v finds=%d", st, h.tun.dns, h.finds)
	}
	if st.Blocker == nil || st.Blocker.App != ipc.BlockerWireGuard || len(st.Blocker.Tunnels) != 1 || st.Blocker.Tunnels[0] != "wg-client-10" {
		t.Fatalf("blocker %+v", st.Blocker)
	}
	if h.tun.probes != 2 {
		t.Fatalf("%d probes", h.tun.probes)
	}
	if st := h.status(bob); st.Link != "" || st.Blocker != nil {
		t.Fatalf("bob sees %+v", st)
	}
	// The kill switch goes; the next check finds nothing.
	h.blocker = nil
	h.tick(blockerRecheck)
	if st := h.status(alice); st.Blocker != nil || h.finds != 2 {
		t.Fatalf("after recheck: %+v finds=%d", st.Blocker, h.finds)
	}
	// The server answers: DNS on, Connected.
	h.blocker = &ipc.Blocker{App: ipc.BlockerWireGuard}
	h.tick(blockerRecheck)
	h.tun.stats.LastHandshake = h.now
	h.tick(time.Second)
	if st := h.status(alice); st.Link != ipc.LinkUp || st.Blocker != nil || !h.tun.dns {
		t.Fatalf("answered: %+v dns=%v", st, h.tun.dns)
	}
}

func TestLinkBlockerCheckFails(t *testing.T) {
	h := newHarness(t)
	h.register(alice)
	h.blocker, h.findErr = &ipc.Blocker{App: ipc.BlockerWireGuard}, errors.New("access denied")
	h.connect(7, alice, config(1))
	h.tick(firstAnswerTimeout)
	if st := h.status(alice); st.Link != ipc.LinkNoAnswer || st.Blocker != nil {
		t.Fatalf("%+v", st)
	}
}

func TestLinkLostRemovesDNS(t *testing.T) {
	h := newHarness(t)
	h.register(alice)
	h.connect(7, alice, config(1))
	h.tun.stats.LastHandshake = h.now
	h.tick(time.Second)
	h.tick(handshakeLost + time.Minute) // idle
	if !h.tun.dns || h.status(alice).Link != ipc.LinkUp {
		t.Fatal("idle tunnel lost its DNS")
	}
	h.tun.stats.TxBytes = 1000   // sending, no handshake
	h.tick(lostGrace + linkPoll) // the first second sees the bytes grow
	if st := h.status(alice); st.Link != ipc.LinkNoAnswer || h.tun.dns {
		t.Fatalf("lost: %+v dns=%v", st, h.tun.dns)
	}
	h.tun.stats.LastHandshake = h.now
	h.tick(time.Second)
	if st := h.status(alice); st.Link != ipc.LinkUp || !h.tun.dns {
		t.Fatalf("back: %+v dns=%v", st, h.tun.dns)
	}
}

func TestLinkNewServerKeyWaitsAgain(t *testing.T) {
	h := newHarness(t)
	h.register(alice)
	h.connect(7, alice, config(1))
	h.tun.stats.LastHandshake = h.now
	h.tick(time.Second)
	// A newer configuration with the same key: the link stays up.
	h.do(7, alice, ipc.Request{Op: ipc.OpUpdate, Document: h.sessionDoc(h.nonce(alice), config(2))})
	if st := h.status(alice); st.Link != ipc.LinkUp || h.tun.probes != 1 {
		t.Fatalf("same key: %+v probes=%d", st, h.tun.probes)
	}
	newKey := config(3)
	newKey["server_public_key"] = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
	h.tun.stats.LastHandshake = time.Time{} // the driver's new peer has none
	r := h.do(7, alice, ipc.Request{Op: ipc.OpUpdate, Document: h.sessionDoc(h.nonce(alice), newKey)})
	if r.Error != nil || r.Status.Link != ipc.LinkWaiting || h.tun.probes != 2 || !h.tun.dns {
		t.Fatalf("new key: %+v %v probes=%d dns=%v", r.Status, r.Error, h.tun.probes, h.tun.dns)
	}
	h.tick(firstAnswerTimeout)
	if st := h.status(alice); st.Link != ipc.LinkNoAnswer || h.tun.dns {
		t.Fatalf("no answer with the new key: %+v dns=%v", st, h.tun.dns)
	}
}

func TestLinkDNSFailureTakesTunnelDown(t *testing.T) {
	h := newHarness(t)
	h.register(alice)
	h.connect(7, alice, config(1))
	h.tun.failDNS = errors.New("registry")
	h.tun.stats.LastHandshake = h.now
	h.tick(time.Second)
	if st := h.status(alice); h.tun.up || st.State != ipc.StateIdle || st.LastError != ipc.ErrTunnel {
		t.Fatalf("%+v up=%v", st, h.tun.up)
	}
}

func TestLinkWithoutOwner(t *testing.T) {
	h := newHarness(t)
	h.tick(time.Minute)
	if h.tun.probes != 0 || len(h.tun.dnsCalls) != 0 || h.finds != 0 {
		t.Fatal("tunnel touched without an owner")
	}
	h.register(alice)
	h.connect(7, alice, config(1))
	h.do(7, alice, ipc.Request{Op: ipc.OpDisconnect})
	h.tick(time.Minute)
	if h.tun.probes != 1 || len(h.tun.dnsCalls) != 0 || h.finds != 0 {
		t.Fatalf("after sign-out: probes=%d dns=%v finds=%d", h.tun.probes, h.tun.dnsCalls, h.finds)
	}
}

func TestRunChecksLink(t *testing.T) {
	h := newHarness(t)
	h.register(alice)
	h.connect(7, alice, config(1))
	h.tun.mu.Lock()
	h.tun.stats.LastHandshake = h.now
	h.tun.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { h.e.Run(ctx); close(done) }()
	for deadline := time.Now().Add(5 * time.Second); h.status(alice).Link != ipc.LinkUp; {
		if time.Now().After(deadline) {
			t.Fatal("Run did not check the link")
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
}

func count(list []string, s string) int {
	n := 0
	for _, x := range list {
		if x == s {
			n++
		}
	}
	return n
}

func TestLinkBlockerCheckPanics(t *testing.T) {
	h := newHarness(t)
	h.register(alice)
	h.blocker = &ipc.Blocker{App: ipc.BlockerWireGuard}
	h.onFind = func() { panic("bad layout") }
	h.connect(7, alice, config(1))
	h.tick(firstAnswerTimeout + 3*blockerRecheck)
	if st := h.status(alice); st.Link != ipc.LinkNoAnswer || st.Blocker != nil || h.finds != 4 {
		t.Fatalf("%+v finds=%d", st, h.finds)
	}
	if n := count(h.logs, "looking for what blocks the server failed"); n != 1 {
		t.Fatalf("logged %d times", n)
	}
}

func TestLinkBlockerResultDropped(t *testing.T) {
	newKey := config(2)
	newKey["server_public_key"] = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
	for name, during := range map[string]func(h *harness){
		"owner signed out": func(h *harness) { h.do(7, alice, ipc.Request{Op: ipc.OpDisconnect}) },
		"signed in again":  func(h *harness) { h.connect(8, alice, config(1)) },
		"new server key": func(h *harness) {
			h.do(7, alice, ipc.Request{Op: ipc.OpUpdate, Document: h.sessionDoc(h.nonce(alice), newKey)})
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			h.register(alice)
			h.blocker = &ipc.Blocker{App: ipc.BlockerWireGuard}
			h.connect(7, alice, config(1))
			h.onFind = func() { h.onFind = nil; during(h) }
			gen := h.status(alice).Generation
			h.now = h.now.Add(firstAnswerTimeout)
			h.e.checkLink()
			st := h.status(alice)
			if st.Blocker != nil || h.finds != 1 {
				t.Fatalf("%+v finds=%d", st, h.finds)
			}
			if st.Generation == gen {
				t.Fatal("the change during the lookup was not seen")
			}
		})
	}
}

func TestProbeFailureLoggedOnce(t *testing.T) {
	h := newHarness(t)
	h.register(alice)
	h.tun.failProbe = errors.New("no address inside the tunnel")
	h.connect(7, alice, config(1))
	h.tick(10 * time.Minute)
	if n := count(h.logs, "probe packet not sent"); n != 1 {
		t.Fatalf("logged %d times", n)
	}
	h.tun.stats.LastHandshake = h.now
	h.tick(time.Second) // up, DNS on
	h.tun.failDNS = errors.New("registry")
	h.tun.stats.TxBytes = 5000
	h.tun.stats.LastHandshake = h.now.Add(-handshakeLost - time.Minute)
	h.tick(lostGrace + time.Minute) // no answer; DNS can't be removed
	if n := count(h.logs, "removing DNS failed; trying again"); n != 1 {
		t.Fatalf("DNS failure logged %d times", n)
	}
	// A new episode logs the probe failure again.
	if n := count(h.logs, "probe packet not sent"); n != 2 {
		t.Fatalf("probe failure logged %d times in two episodes", n)
	}
}

// The user follows the warning after the probe window is over: the next
// lookup finds the kill switch gone, probing starts again, and the link
// comes up with DNS.
func TestLinkBlockerGoneProbesAgain(t *testing.T) {
	h := newHarness(t)
	h.register(alice)
	h.blocker = &ipc.Blocker{App: ipc.BlockerWireGuard, Tunnels: []string{"wg-client-10"}}
	h.connect(7, alice, config(1))
	h.tick(probeWindow + 2*time.Minute)
	if st := h.status(alice); st.Link != ipc.LinkNoAnswer || st.Blocker == nil {
		t.Fatalf("%+v", st)
	}
	probes := h.tun.probes
	h.tick(time.Minute)
	if h.tun.probes != probes {
		t.Fatal("probes after the window")
	}
	// A failed lookup is not a change.
	h.findErr = errors.New("access denied")
	h.tick(blockerRecheck)
	if h.tun.probes != probes {
		t.Fatal("a failed lookup re-armed the probes")
	}
	h.findErr = nil
	h.tick(blockerRecheck)
	if h.tun.probes != probes {
		t.Fatal("re-armed while the blocker is still there")
	}
	h.blocker = nil // the kill switch is turned off
	for finds := h.finds; h.finds == finds; {
		h.tick(time.Second) // until the next lookup
	}
	if h.tun.probes != probes {
		t.Fatal("probed before the lookup")
	}
	h.tick(time.Second)
	if h.tun.probes != probes+1 {
		t.Fatalf("%d probes after the blocker went, want 1", h.tun.probes-probes)
	}
	if st := h.status(alice); st.Blocker != nil || st.Link != ipc.LinkNoAnswer {
		t.Fatalf("%+v", st)
	}
	h.tun.stats.LastHandshake = h.now
	h.tick(time.Second)
	if st := h.status(alice); st.Link != ipc.LinkUp || st.Blocker != nil || !h.tun.dns {
		t.Fatalf("after the handshake: %+v dns=%v", st, h.tun.dns)
	}
}

func TestLinkNoBlockerNoRearm(t *testing.T) {
	h := newHarness(t)
	h.register(alice)
	h.connect(7, alice, config(1))
	h.tick(probeWindow)
	probes := h.tun.probes
	h.tick(10 * time.Minute)
	if h.tun.probes != probes {
		t.Fatalf("%d probes after the window with no blocker ever found", h.tun.probes-probes)
	}
}

func TestKillSwitchEnabledWhileConnected(t *testing.T) {
	h := newHarness(t)
	h.register(alice)
	if r := h.connect(7, alice, config(1)); r.Error != nil {
		t.Fatal(r.Error)
	}
	h.tun.stats.LastHandshake = h.now
	h.tick(linkPoll)
	h.blocker = &ipc.Blocker{App: ipc.BlockerWireGuard, Tunnels: []string{"wg-client-10"}}
	h.tick(blockerWatch - linkPoll)
	if st := h.status(alice); st.Link != ipc.LinkUp || !h.tun.dns || h.finds != 0 {
		t.Fatalf("before the poll: %+v, DNS %v, checks %d", st, h.tun.dns, h.finds)
	}
	h.tick(linkPoll)
	if st := h.status(alice); st.Link != ipc.LinkNoAnswer || !sameBlocker(st.Blocker, h.blocker) || h.tun.dns {
		t.Fatalf("after detection: %+v, DNS %v", st, h.tun.dns)
	}
	probes := h.tun.probes
	h.findErr = errors.New("access denied")
	h.tick(blockerRecheck)
	if st := h.status(alice); st.Link != ipc.LinkNoAnswer || !sameBlocker(st.Blocker, h.blocker) || h.tun.dns || h.tun.probes != probes {
		t.Fatalf("after failed recheck with a recent handshake: %+v, DNS %v, probes %d", st, h.tun.dns, h.tun.probes)
	}
	h.findErr, h.blocker = nil, nil
	h.tick(blockerRecheck)
	if h.tun.probes != probes+1 {
		t.Fatalf("after blocker clears: got %d new probes, want one", h.tun.probes-probes)
	}
	h.tick(linkPoll)
	if st := h.status(alice); st.Link != ipc.LinkUp || st.Blocker != nil || !h.tun.dns {
		t.Fatalf("after recovery: %+v, DNS %v", st, h.tun.dns)
	}
}

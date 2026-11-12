package app

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/daemon"
	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/fakeserver"
	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/ipc"
	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/keystore"
	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/policy"
	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/protocol"
)

// --- the service, in process -------------------------------------------------------

type fakeTunnel struct {
	mu          sync.Mutex
	up          bool
	cfg         *protocol.TunnelConfig
	psk         protocol.Key
	reconfigure int
}

func (f *fakeTunnel) Up(cfg *protocol.TunnelConfig, _, psk protocol.Key) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.up, f.cfg, f.psk = true, cfg, psk
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
	f.up = false
	return nil
}

func (f *fakeTunnel) Stats() (daemon.Stats, error) { return daemon.Stats{}, nil }

func (f *fakeTunnel) state() (bool, *protocol.TunnelConfig, protocol.Key, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.up, f.cfg, f.psk, f.reconfigure
}

// engineService is the Service interface over the real engine, the way the
// pipe client uses it: one control connection, one for everything else.
// While down is set, every call fails the way the pipe client does when the
// service cannot be reached.
type engineService struct {
	e      *daemon.Engine
	caller daemon.Caller
	down   atomic.Bool
}

const (
	controlConn = 1
	queryConn   = 2
)

func (s *engineService) do(conn uint64, req ipc.Request) (*ipc.Response, error) {
	if s.down.Load() {
		return nil, fmt.Errorf("%w: Access is denied", ipc.ErrUnavailable)
	}
	r := s.e.Handle(context.Background(), conn, s.caller, &req)
	if r.Error != nil {
		return nil, r.Error
	}
	return r, nil
}

func (s *engineService) Nonce() (string, error) {
	r, err := s.do(queryConn, ipc.Request{Op: ipc.OpNonce})
	if err != nil {
		return "", err
	}
	return r.Nonce, nil
}

func (s *engineService) Register(server, key string, doc protocol.SignedDocument) error {
	_, err := s.do(queryConn, ipc.Request{Op: ipc.OpRegister, Server: server, IdentityKey: key, Document: &doc})
	return err
}

func (s *engineService) Forget(server string) error {
	_, err := s.do(queryConn, ipc.Request{Op: ipc.OpForget, Server: server})
	return err
}

func (s *engineService) Connect(server string, doc protocol.SignedDocument, priv, psk protocol.Key) (*ipc.Status, error) {
	r, err := s.do(controlConn, ipc.Request{Op: ipc.OpConnect, Server: server, Document: &doc,
		PrivateKey: priv[:], PSK: psk[:]})
	if err != nil {
		return nil, err
	}
	return r.Status, nil
}

func (s *engineService) Update(doc protocol.SignedDocument) (*ipc.Status, error) {
	r, err := s.do(controlConn, ipc.Request{Op: ipc.OpUpdate, Document: &doc})
	if err != nil {
		return nil, err
	}
	return r.Status, nil
}

func (s *engineService) Disconnect() error {
	_, err := s.do(controlConn, ipc.Request{Op: ipc.OpDisconnect})
	return err
}

func (s *engineService) Status() (*ipc.Status, error) {
	r, err := s.do(queryConn, ipc.Request{Op: ipc.OpStatus})
	if err != nil {
		return nil, err
	}
	return r.Status, nil
}

// --- harness -----------------------------------------------------------------------

type testProtector struct{ aead cipher.AEAD }

func (p *testProtector) Protect(b []byte) ([]byte, error) {
	n := make([]byte, p.aead.NonceSize())
	rand.Read(n)
	return p.aead.Seal(n, n, b, nil), nil
}

func (p *testProtector) Unprotect(b []byte) ([]byte, error) {
	if len(b) < p.aead.NonceSize() {
		return nil, errors.New("short")
	}
	return p.aead.Open(nil, b[:p.aead.NonceSize()], b[p.aead.NonceSize():], nil)
}

type harness struct {
	t      *testing.T
	srv    *fakeserver.Server
	svc    *engineService
	tun    *fakeTunnel
	pol    policy.Policy
	ctrl   *Controller
	views  chan View
	cancel context.CancelFunc
	done   chan struct{}
}

func newHarness(t *testing.T) *harness {
	h := &harness{t: t, srv: fakeserver.New(t, fakeserver.Options{}), tun: &fakeTunnel{},
		views: make(chan View, 256), done: make(chan struct{})}
	key := make([]byte, 32)
	rand.Read(key)
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	store, err := keystore.Open(filepath.Join(t.TempDir(), "accounts.json"), &testProtector{aead})
	if err != nil {
		t.Fatal(err)
	}
	engine := daemon.New(daemon.Options{Tunnel: h.tun,
		Pins: daemon.NewFileStore(filepath.Join(t.TempDir(), "servers.json")), Policy: func() policy.Policy { return h.pol }})
	h.svc = &engineService{e: engine, caller: daemon.Caller{SID: "S-1-5-21-1", Session: 1}}
	h.ctrl = New(Options{Store: store, Service: h.svc,
		HTTPClient: h.srv.HTTPClientWith, OSName: "Windows 11 Pro", OnView: func(v View) { h.views <- v },
		Log: func(msg string, args ...any) { t.Log(append([]any{msg}, args...)...) }})
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	go func() { h.ctrl.Run(ctx); close(h.done) }()
	t.Cleanup(h.stop)
	h.wait(ScreenSetup)
	return h
}

func (h *harness) stop() {
	h.cancel()
	<-h.done
}

// wait returns the first view on screen that is not busy.
func (h *harness) wait(screen Screen) View {
	h.t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case v := <-h.views:
			if v.Screen == screen && !v.Busy {
				return v
			}
		case <-deadline:
			h.t.Fatalf("no %q view", screen)
		}
	}
}

// waitError returns the first view with an error.
func (h *harness) waitError() *ViewError {
	h.t.Helper()
	return h.waitErrorView().Error
}

// waitErrorView returns the first view with an error, whole.
func (h *harness) waitErrorView() View {
	h.t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case v := <-h.views:
			if v.Error != nil && !v.Busy {
				return v
			}
		case <-deadline:
			h.t.Fatal("no error view")
		}
	}
}

// enroll runs enrollment for a new user with MFA set up during enrollment.
func (h *harness) enroll() {
	h.t.Helper()
	h.srv.AddUser("alice", "pw", false)
	link, _ := h.srv.NewLink(protocol.LinkDevice, "alice", "")
	h.ctrl.Do(Action{Name: "enroll_link", Link: link})
	v := h.wait(ScreenEnrollPassword)
	if v.Enroll.Username != "alice" || !v.Enroll.NameEditable || v.Enroll.Kind != protocol.LinkDevice {
		h.t.Fatalf("enroll view %+v", v.Enroll)
	}
	h.ctrl.Do(Action{Name: "enroll_password", Password: "pw"})
	v = h.wait(ScreenEnrollMFA)
	if v.Enroll.MFAURI == "" || v.Enroll.MFASecret == "" {
		h.t.Fatalf("mfa view %+v", v.Enroll)
	}
	h.ctrl.Do(Action{Name: "enroll_mfa", Code: fakeserver.OTP, DeviceName: "Work laptop"})
	v = h.wait(ScreenSignIn)
	if v.Account == nil || v.Account.Device != "Work laptop" || v.Notice != "enrolled" {
		h.t.Fatalf("after enrollment %+v", v)
	}
}

func (h *harness) signIn() View {
	h.t.Helper()
	h.ctrl.Do(Action{Name: "signin", Password: "pw"})
	h.wait(ScreenSignInOTP)
	h.ctrl.Do(Action{Name: "signin_otp", OTP: fakeserver.OTP})
	return h.wait(ScreenConnected)
}

// --- tests -------------------------------------------------------------------------

// A renewal link (reinstall on the same computer) tells the page it is a
// renewal, names the device, and enrolls with the user's own password and code.
func TestEnrollRenewLink(t *testing.T) {
	h := newHarness(t)
	h.srv.AddUser("alice", "pw", true)
	link, _ := h.srv.NewLink(protocol.LinkRenew, "alice", "Work laptop")
	h.ctrl.Do(Action{Name: "enroll_link", Link: link})
	v := h.wait(ScreenEnrollPassword)
	if v.Enroll == nil || v.Enroll.Kind != protocol.LinkRenew || v.Enroll.Device != "Work laptop" ||
		v.Enroll.Username != "alice" || v.Enroll.NameEditable {
		t.Fatalf("renew view %+v", v.Enroll)
	}
	h.ctrl.Do(Action{Name: "enroll_password", Password: "pw", OTP: fakeserver.OTP})
	v = h.wait(ScreenSignIn)
	if v.Account == nil || v.Account.Device != "Work laptop" {
		t.Fatalf("after renewal %+v", v)
	}
}

func TestEnrollSignInAndFollow(t *testing.T) {
	h := newHarness(t)
	h.enroll()
	v := h.signIn()
	if v.Session == nil || v.Session.Address != "10.98.10.4/32" {
		t.Fatalf("connected view %+v", v.Session)
	}
	up, cfg, psk, _ := h.tun.state()
	if !up || cfg.Version != 1 || psk != h.srv.Device("d_0001").PSK {
		t.Fatal("tunnel not up with the enrolled preshared key")
	}

	// A configuration change reaches the tunnel without user action.
	h.srv.SetAllowedIPs("10.98.0.0/16", "10.20.0.0/16")
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, cfg, _, n := h.tun.state(); n == 1 && len(cfg.AllowedIPs) == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("configuration change not applied")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// The server ends the session: the window says why, the tunnel is down.
	h.srv.EndSessions(protocol.ReasonIdle)
	v = h.wait(ScreenSignIn)
	if v.Notice != protocol.ReasonIdle {
		t.Fatalf("notice %q", v.Notice)
	}
	if up, _, _, _ := h.tun.state(); up {
		t.Fatal("tunnel still up after the session ended")
	}
}

func TestDisconnectSignsOut(t *testing.T) {
	h := newHarness(t)
	h.enroll()
	h.signIn()
	if h.srv.ActiveSessions() != 1 {
		t.Fatal("no server session")
	}
	h.ctrl.Do(Action{Name: "disconnect"})
	h.wait(ScreenSignIn)
	if up, _, _, _ := h.tun.state(); up || h.srv.ActiveSessions() != 0 {
		t.Fatalf("after disconnect: tunnel up=%v, sessions=%d", up, h.srv.ActiveSessions())
	}
}

func TestQuitSignsOut(t *testing.T) {
	h := newHarness(t)
	h.enroll()
	h.signIn()
	done := make(chan struct{})
	h.ctrl.Quit(func() { close(done) })
	<-done
	if up, _, _, _ := h.tun.state(); up || h.srv.ActiveSessions() != 0 {
		t.Fatal("quit left the session running")
	}
}

func TestFullTunnelRefusedAndSignedOut(t *testing.T) {
	h := newHarness(t)
	h.enroll()
	h.srv.SetAllowedIPs("0.0.0.0/0")
	h.ctrl.Do(Action{Name: "signin", Password: "pw"})
	h.wait(ScreenSignInOTP)
	h.ctrl.Do(Action{Name: "signin_otp", OTP: fakeserver.OTP})
	if e := h.waitError(); e.Code != ipc.ErrFullTunnel {
		t.Fatalf("error %q", e.Code)
	}
	if up, _, _, _ := h.tun.state(); up || h.srv.ActiveSessions() != 0 {
		t.Fatal("refused tunnel left a server session or tunnel")
	}
}

func TestWrongFingerprintRefused(t *testing.T) {
	h := newHarness(t)
	other := fakeserver.New(t, fakeserver.Options{})
	h.srv.AddUser("alice", "pw", false)
	_, token := h.srv.NewLink(protocol.LinkDevice, "alice", "")
	forged := h.srv.URL() + "/login/enroll#" + token + "." + string(other.Pin().Fingerprint)
	h.ctrl.Do(Action{Name: "enroll_link", Link: forged})
	if e := h.waitError(); e.Code != ErrIdentityMismatch {
		t.Fatalf("error %q", e.Code)
	}
}

func TestOldLinkAsksForFingerprint(t *testing.T) {
	h := newHarness(t)
	h.srv.AddUser("alice", "pw", false)
	_, token := h.srv.NewLink(protocol.LinkDevice, "alice", "Laptop")
	h.ctrl.Do(Action{Name: "enroll_link", Link: h.srv.URL() + "/login/enroll#" + token})
	v := h.wait(ScreenEnrollFingerprint)
	if v.Enroll.Fingerprint != string(h.srv.Pin().Fingerprint) {
		t.Fatalf("shown fingerprint %q", v.Enroll.Fingerprint)
	}
	h.ctrl.Do(Action{Name: "enroll_confirm_fingerprint"})
	h.wait(ScreenEnrollPassword)
}

func TestKeyRenewal(t *testing.T) {
	h := newHarness(t)
	h.enroll()
	h.srv.SetRenewAfter(-time.Hour)
	h.signIn()
	deadline := time.Now().Add(10 * time.Second)
	for h.srv.Renewals() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("keys not renewed")
		}
		time.Sleep(20 * time.Millisecond)
	}
	// The session keeps working with the new device key...
	h.srv.SetAllowedIPs("10.98.0.0/16", "10.30.0.0/16")
	deadline = time.Now().Add(10 * time.Second)
	for {
		if _, cfg, _, _ := h.tun.state(); len(cfg.AllowedIPs) == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("session stopped working after renewal")
		}
		time.Sleep(20 * time.Millisecond)
	}
	// ...and the next sign-in announces and adopts the renewed tunnel keys.
	h.srv.SetRenewAfter(time.Hour)
	if d := h.srv.Device("d_0001"); d.NextWGPublicKey.IsZero() {
		t.Fatal("renewed keys not pending on the server")
	}
	h.ctrl.Do(Action{Name: "disconnect"})
	h.wait(ScreenSignIn)
	h.signIn()
	d := h.srv.Device("d_0001")
	if _, _, psk, _ := h.tun.state(); !d.NextWGPublicKey.IsZero() || psk != d.PSK {
		t.Fatal("second sign-in did not adopt the renewed keys")
	}
	// And the one after that uses them as current.
	h.ctrl.Do(Action{Name: "disconnect"})
	h.wait(ScreenSignIn)
	h.signIn()
	if _, _, psk, _ := h.tun.state(); psk != h.srv.Device("d_0001").PSK {
		t.Fatal("adopted keys not kept")
	}
}

func TestCertificateGroup(t *testing.T) {
	h := newHarness(t)
	h.srv.AddUser("alice", "pw", false)
	h.srv.RequireCertificate("alice")
	link, _ := h.srv.NewLink(protocol.LinkDevice, "alice", "Laptop")
	h.ctrl.Do(Action{Name: "enroll_link", Link: link})
	h.wait(ScreenEnrollPassword)
	h.ctrl.Do(Action{Name: "enroll_password", Password: "pw"})
	h.wait(ScreenEnrollMFA)
	h.ctrl.Do(Action{Name: "enroll_mfa", Code: fakeserver.OTP})
	h.wait(ScreenSignIn)
	if h.srv.Device("d_0001").Cert == nil {
		t.Fatal("no certificate issued")
	}
	// Signed calls only pass with the certificate presented over TLS.
	h.signIn()
	// Renewal brings a new certificate, which the next session presents.
	h.srv.SetRenewAfter(-time.Hour)
	h.ctrl.Do(Action{Name: "disconnect"})
	h.wait(ScreenSignIn)
	h.signIn()
	deadline := time.Now().Add(10 * time.Second)
	for h.srv.Renewals() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("keys not renewed")
		}
		time.Sleep(20 * time.Millisecond)
	}
	h.srv.SetRenewAfter(time.Hour)
	h.ctrl.Do(Action{Name: "disconnect"})
	h.wait(ScreenSignIn)
	h.signIn()
}

func TestAppTooOld(t *testing.T) {
	h := newHarness(t)
	h.srv.SetMinAppVersion("99.0.0")
	h.srv.SetAppDownload("https://downloads.example.com/hifaz/")
	h.srv.AddUser("alice", "pw", false)
	link, _ := h.srv.NewLink(protocol.LinkDevice, "alice", "")
	h.ctrl.Do(Action{Name: "enroll_link", Link: link})
	v := h.wait(ScreenUpdateRequired)
	if v.Update.MinVersion != "99.0.0" || v.Update.DownloadURL != "https://downloads.example.com/hifaz/" {
		t.Fatalf("%+v", v.Update)
	}
}

func TestRemoveAccount(t *testing.T) {
	h := newHarness(t)
	h.enroll()
	h.ctrl.Do(Action{Name: "remove_account"})
	v := h.wait(ScreenSetup)
	if v.Account != nil {
		t.Fatal("account still shown")
	}
}

func TestBrowserLinks(t *testing.T) {
	h := newHarness(t)
	h.srv.AddUser("alice", "pw", false)
	link, _ := h.srv.NewLink(protocol.LinkMFA, "alice", "")
	h.ctrl.Do(Action{Name: "enroll_link", Link: link})
	if e := h.waitError(); e.Code != protocol.ErrCodeUseBrowser {
		t.Fatalf("error %q", e.Code)
	}
	h.ctrl.Do(Action{Name: "enroll_link", Link: "not a link"})
	if e := h.waitError(); e.Code != ErrInvalidLink {
		t.Fatalf("error %q", e.Code)
	}
}

func TestServerTooOld(t *testing.T) {
	h := newHarness(t)
	h.srv.SetServerVersion("0.7.2")
	h.srv.AddUser("alice", "pw", false)
	link, _ := h.srv.NewLink(protocol.LinkDevice, "alice", "")
	h.ctrl.Do(Action{Name: "enroll_link", Link: link})
	if e := h.waitError(); e.Code != protocol.ErrCodeServerTooOld {
		t.Fatalf("error %q", e.Code)
	}
}

// A service that cannot be reached is found when the link is pasted, before
// the server uses up any step; once it answers, the same link works.
func TestEnrollServiceDownAtLink(t *testing.T) {
	h := newHarness(t)
	h.srv.AddUser("alice", "pw", false)
	link, _ := h.srv.NewLink(protocol.LinkDevice, "alice", "")
	h.svc.down.Store(true)
	h.ctrl.Do(Action{Name: "enroll_link", Link: link})
	v := h.waitErrorView()
	if v.Screen != ScreenSetup || v.Error.Code != ErrServiceUnavailable {
		t.Fatalf("view %s, error %q", v.Screen, v.Error.Code)
	}
	if n := h.srv.Requests(); n != 0 {
		t.Fatalf("%d requests sent to the server with the service down", n)
	}
	h.svc.down.Store(false)
	h.ctrl.Do(Action{Name: "enroll_link", Link: link})
	h.wait(ScreenEnrollPassword)
}

// The service fails only at the end: the user stays on the step and sees
// the service error. When the server's step has timed out by the retry, the
// app goes back to the setup screen with the link filled in.
func TestEnrollStepExpiredReturnsToSetup(t *testing.T) {
	h := newHarness(t)
	h.srv.AddUser("alice", "pw", false)
	link, _ := h.srv.NewLink(protocol.LinkDevice, "alice", "")
	h.ctrl.Do(Action{Name: "enroll_link", Link: link})
	h.wait(ScreenEnrollPassword)
	h.ctrl.Do(Action{Name: "enroll_password", Password: "pw"})
	h.wait(ScreenEnrollMFA)

	h.svc.down.Store(true)
	h.ctrl.Do(Action{Name: "enroll_mfa", Code: fakeserver.OTP, DeviceName: "Laptop"})
	v := h.waitErrorView()
	if v.Screen != ScreenEnrollMFA || v.Error.Code != ErrServiceUnavailable {
		t.Fatalf("view %s, error %q", v.Screen, v.Error.Code)
	}

	h.svc.down.Store(false)
	h.srv.ExpireSteps()
	h.ctrl.Do(Action{Name: "enroll_mfa", Code: fakeserver.OTP, DeviceName: "Laptop"})
	v = h.waitErrorView()
	if v.Screen != ScreenSetup || v.Error.Code != protocol.ErrCodeInvalidStep || v.Link != link || v.Replacing {
		t.Fatalf("after the step timed out: screen %s, error %q, link %q, replacing %v",
			v.Screen, v.Error.Code, v.Link, v.Replacing)
	}

	// Continue with the kept link; the user set up MFA in the first attempt.
	h.ctrl.Do(Action{Name: "enroll_link", Link: v.Link})
	h.wait(ScreenEnrollPassword)
	h.ctrl.Do(Action{Name: "enroll_password", Password: "pw", OTP: fakeserver.OTP, DeviceName: "Laptop"})
	if v := h.wait(ScreenSignIn); v.Account == nil || v.Account.Device != "Laptop" {
		t.Fatalf("after enrollment %+v", v)
	}
}

// Adding a server: a timed-out step goes back to setup still replacing.
func TestEnrollStepExpiredWhileReplacing(t *testing.T) {
	h := newHarness(t)
	h.enroll()
	h.ctrl.Do(Action{Name: "add_server"})
	if v := h.wait(ScreenSetup); !v.Replacing {
		t.Fatal("add_server not replacing")
	}
	h.srv.AddUser("bob", "pw2", false)
	link, _ := h.srv.NewLink(protocol.LinkDevice, "bob", "")
	h.ctrl.Do(Action{Name: "enroll_link", Link: link})
	h.wait(ScreenEnrollPassword)
	h.ctrl.Do(Action{Name: "enroll_password", Password: "pw2"})
	h.wait(ScreenEnrollMFA)
	h.srv.ExpireSteps()
	h.ctrl.Do(Action{Name: "enroll_mfa", Code: fakeserver.OTP, DeviceName: "Laptop"})
	v := h.waitErrorView()
	if v.Screen != ScreenSetup || v.Error.Code != protocol.ErrCodeInvalidStep || v.Link != link || !v.Replacing {
		t.Fatalf("after the step timed out: screen %s, error %q, link %q, replacing %v",
			v.Screen, v.Error.Code, v.Link, v.Replacing)
	}
}

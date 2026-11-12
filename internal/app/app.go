// Package app is the logic of the Hifaz window and tray: enrollment,
// sign-in, the session and key renewal. It talks to the server through
// internal/protocol and to the Hifaz service through the Service interface,
// and describes what to show as a View. It has no Windows code, so it is
// tested end to end with a fake server and the real service engine.
package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/ipc"
	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/keystore"
	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/protocol"
	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/version"
)

// Service is the app's side of the Hifaz service. Connect, Update and
// Disconnect go over one connection that stays open while the tunnel is up.
type Service interface {
	Nonce() (string, error)
	Register(server, identityKey string, doc protocol.SignedDocument) error
	Forget(server string) error
	Connect(server string, doc protocol.SignedDocument, priv, psk protocol.Key) (*ipc.Status, error)
	Update(doc protocol.SignedDocument) (*ipc.Status, error)
	Disconnect() error
	Status() (*ipc.Status, error)
}

// Options configure a Controller.
type Options struct {
	Store   *keystore.Store
	Service Service
	// HTTPClient returns the client for server calls, presenting cert (the
	// device certificate, nil if none); nil uses the protocol's default
	// with no proxy.
	HTTPClient func(cert *tls.Certificate) *http.Client
	Now        func() time.Time
	OSName     string // sent at enrollment, for example "Windows 11 Pro 24H2"
	OnView     func(View)
	Log        func(msg string, args ...any)
}

// Timeouts for calls the user waits on, and the session long-poll.
const (
	callTimeout  = 30 * time.Second
	pollWait     = 50 * time.Second
	pollTimeout  = pollWait + 30*time.Second
	retryMin     = 2 * time.Second
	retryMax     = 30 * time.Second
	statsRefresh = 5 * time.Second
	renewTimeout = 10 * time.Second
)

// Controller runs the app. All state is owned by one goroutine (Run);
// everything else posts functions to it.
type Controller struct {
	o       Options
	actions chan func()

	// Owned by the Run goroutine.
	view    View
	account *keystore.Account
	enroll  *enrollment
	signin  *signinStep
	session *session
	// mfaSetLink is the link token of a user who set up two-step
	// verification in an enrollment that was then interrupted: with that
	// link the code is required. Memory only, never logged.
	mfaSetLink string
}

type enrollment struct {
	raw          string // the link as pasted, to fill in again if a step times out
	link         protocol.EnrollLink
	client       *protocol.Client
	pin          protocol.Pin
	info         *protocol.EnrollLinkInfo
	stepToken    string
	certRequired bool
	replacing    bool
	mfaDone      bool // two-step setup succeeded on the server in this attempt
	codeRequired bool // two-step setup was saved in an earlier attempt with this link
}

type signinStep struct {
	stepToken string
}

type session struct {
	client  *protocol.Client
	signer  atomic.Pointer[protocol.KeySigner] // replaced when the device key is renewed
	version atomic.Int64                       // configuration version in use
	token   string
	cancel  context.CancelFunc
	doc     *protocol.Session
	renewed bool
}

// New returns a Controller; call Run to start it.
func New(o Options) *Controller {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Log == nil {
		o.Log = func(string, ...any) {}
	}
	if o.OnView == nil {
		o.OnView = func(View) {}
	}
	if o.HTTPClient == nil {
		o.HTTPClient = func(cert *tls.Certificate) *http.Client { return protocol.NewHTTPClient(nil, cert) }
	}
	return &Controller{o: o, actions: make(chan func(), 64), view: View{Screen: ScreenLoading}}
}

// Run processes actions until ctx ends; it then signs out if connected.
func (c *Controller) Run(ctx context.Context) {
	c.post(c.load)
	for {
		select {
		case f := <-c.actions:
			f()
		case <-ctx.Done():
			c.endSession(true, "")
			return
		}
	}
}

// post queues f to run on the controller goroutine.
func (c *Controller) post(f func()) { c.actions <- f }

// show sends the current view.
func (c *Controller) show() {
	v := c.view
	c.o.OnView(v)
}

// setView replaces the view and sends it.
func (c *Controller) setView(v View) {
	if v.Account == nil && c.account != nil {
		v.Account = accountView(c.account)
	}
	c.view = v
	c.show()
}

func (c *Controller) setBusy(busy bool) {
	c.view.Busy = busy
	if busy {
		c.view.Error = nil
	}
	c.show()
}

func (c *Controller) fail(err error) {
	c.o.Log("action failed", "err", err)
	c.view.Busy = false
	c.view.Error = viewError(err)
	c.show()
}

func accountView(a *keystore.Account) *AccountView {
	return &AccountView{Server: a.Server, Fingerprint: a.Fingerprint.Display(), Username: a.Username,
		Device: a.DeviceName, KeysExpireAt: a.KeysExpireAt}
}

func (c *Controller) ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), callTimeout)
}

func (c *Controller) newClient(server string, pin protocol.Pin, cert *tls.Certificate) (*protocol.Client, error) {
	return protocol.NewClient(server, pin, protocol.Options{HTTPClient: c.o.HTTPClient(cert), Now: c.o.Now,
		UserAgent: version.UserAgent(), App: version.AppHeader()})
}

// --- start ------------------------------------------------------------------------

func (c *Controller) load() {
	accounts, err := c.o.Store.Accounts()
	if err != nil {
		c.setView(View{Screen: ScreenSetup, Error: &ViewError{Code: ErrKeystore}})
		return
	}
	if len(accounts) == 0 {
		c.setView(View{Screen: ScreenSetup})
		return
	}
	c.account = accounts[0]
	c.setView(View{Screen: ScreenSignIn})
}

// --- actions from the window ------------------------------------------------------

// Action names the window sends, with their parameters.
type Action struct {
	Name       string `json:"action"`
	Link       string `json:"link,omitempty"`
	Password   string `json:"password,omitempty"`
	OTP        string `json:"otp,omitempty"`
	Code       string `json:"code,omitempty"`
	DeviceName string `json:"device_name,omitempty"`
}

// Do queues an action from the window; it never blocks the window. Unknown
// actions are ignored, and so are actions while the queue is full (the user
// clicking faster than the app can answer).
func (c *Controller) Do(a Action) {
	f := func() {
		switch a.Name {
		case "refresh":
			c.show()
		case "enroll_link":
			c.enrollLink(a.Link)
		case "enroll_confirm_fingerprint":
			c.enrollConfirmFingerprint()
		case "enroll_password":
			c.enrollPassword(a.Password, a.OTP, a.DeviceName)
		case "enroll_mfa":
			c.enrollMFA(a.Code, a.DeviceName)
		case "enroll_cancel":
			c.enrollCancel()
		case "add_server":
			c.addServer()
		case "signin":
			c.signIn(a.Password, a.OTP)
		case "signin_otp":
			c.signInOTP(a.OTP)
		case "signin_cancel":
			c.signin = nil
			c.setView(View{Screen: ScreenSignIn})
		case "disconnect":
			c.endSession(true, "")
			c.setView(View{Screen: ScreenSignIn})
		case "remove_account":
			c.removeAccount()
		}
	}
	select {
	case c.actions <- f:
	default:
		c.o.Log("action dropped: queue full", "action", a.Name)
	}
}

// Quit signs out (if connected) and then calls done, on the controller
// goroutine.
func (c *Controller) Quit(done func()) {
	c.post(func() {
		c.endSession(true, "")
		done()
	})
}

// --- enrollment -------------------------------------------------------------------

var (
	errInvalidLink = errors.New("invalid enrollment link")
	errNoAccount   = errors.New("no enrolled server")
)

func (c *Controller) addServer() {
	c.endSession(true, "")
	c.enroll = nil
	c.setView(View{Screen: ScreenSetup, Replacing: c.account != nil})
}

func (c *Controller) enrollCancel() {
	c.enroll = nil
	if c.account != nil {
		c.setView(View{Screen: ScreenSignIn})
		return
	}
	c.setView(View{Screen: ScreenSetup})
}

func (c *Controller) enrollLink(raw string) {
	replacing := c.view.Replacing
	raw = strings.TrimSpace(raw)
	link, err := protocol.ParseEnrollLink(raw)
	if err != nil {
		c.fail(errInvalidLink)
		return
	}
	c.setBusy(true)
	// The service is needed only at the end, but by then the server has used
	// up its steps: check it answers before anything is sent. Status stores
	// nothing in the service; the nonce is asked for at the end, as usual.
	if _, err := c.o.Service.Status(); err != nil {
		c.fail(err)
		return
	}
	client, err := c.newClient(link.Server, protocol.Pin{Fingerprint: link.Fingerprint}, nil)
	if err != nil {
		c.fail(errInvalidLink)
		return
	}
	ctx, cancel := c.ctx()
	defer cancel()
	info, pin, err := client.FetchIdentity(ctx)
	if err != nil {
		c.fail(err)
		return
	}
	if link.Fingerprint != "" && pin.Fingerprint != link.Fingerprint {
		c.fail(protocol.ErrIdentityMismatch)
		return
	}
	if err := protocol.CheckCompatible(info, version.Platform, version.Version, version.Compare); err != nil {
		if protocol.ErrorCode(err) == protocol.ErrCodeAppTooOld {
			c.showUpdate(info)
			return
		}
		c.fail(err)
		return
	}
	client.SetPin(pin)
	li, err := client.EnrollInfo(ctx, link.Token)
	if err != nil {
		c.fail(err)
		return
	}
	if li.Kind != protocol.LinkDevice && li.Kind != protocol.LinkRenew {
		c.fail(&protocol.APIError{Code: protocol.ErrCodeUseBrowser})
		return
	}
	codeRequired := c.mfaSetLink != "" && c.mfaSetLink == link.Token
	if !codeRequired {
		c.mfaSetLink = ""
	}
	c.enroll = &enrollment{raw: raw, link: link, client: client, pin: pin, info: li, replacing: replacing,
		codeRequired: codeRequired}
	screen := ScreenEnrollPassword
	if link.Fingerprint == "" {
		screen = ScreenEnrollFingerprint // an older link: the user compares the fingerprint
	}
	c.setView(View{Screen: screen, Enroll: c.enrollView(), Replacing: replacing})
}

func (c *Controller) showUpdate(info *protocol.Info) {
	u := &UpdateView{MinVersion: info.MinAppVersion[version.Platform]}
	if d := info.AppDownload[version.Platform]; strings.HasPrefix(d, "https://") {
		u.DownloadURL = d
	}
	c.setView(View{Screen: ScreenUpdateRequired, Update: u})
}

func (c *Controller) enrollView() *EnrollView {
	e := c.enroll
	return &EnrollView{Server: e.link.Server, Fingerprint: string(e.pin.Fingerprint), Kind: e.info.Kind,
		Username: e.info.Username, Device: e.info.Device, NameEditable: e.info.NameEditable,
		CodeRequired: e.codeRequired}
}

func (c *Controller) enrollConfirmFingerprint() {
	if c.enroll == nil {
		return
	}
	c.setView(View{Screen: ScreenEnrollPassword, Enroll: c.enrollView(), Replacing: c.enroll.replacing})
}

func (c *Controller) enrollPassword(password, otp, deviceName string) {
	e := c.enroll
	if e == nil {
		return
	}
	// Two-step verification is set up: an empty code would only count
	// toward the lockout on the server, so it is refused here.
	if e.codeRequired && strings.TrimSpace(otp) == "" {
		c.fail(errCodeRequired)
		return
	}
	c.setBusy(true)
	ctx, cancel := c.ctx()
	defer cancel()
	st, err := e.client.EnrollStart(ctx, e.link.Token, password, strings.TrimSpace(otp))
	if err != nil {
		c.enrollFail(err)
		return
	}
	e.stepToken, e.certRequired = st.StepToken, st.CertRequired
	if st.NeedsMFASetup {
		v := c.enrollView()
		v.MFAURI, v.MFASecret = st.MFAURI, st.MFASecret
		c.setView(View{Screen: ScreenEnrollMFA, Enroll: v, Replacing: e.replacing})
		return
	}
	c.enrollFinish(ctx, deviceName)
}

func (c *Controller) enrollMFA(code, deviceName string) {
	e := c.enroll
	if e == nil || e.stepToken == "" {
		return
	}
	c.setBusy(true)
	ctx, cancel := c.ctx()
	defer cancel()
	if err := e.client.EnrollMFA(ctx, e.stepToken, strings.TrimSpace(code)); err != nil {
		c.enrollFail(err)
		return
	}
	e.mfaDone = true
	c.enrollFinish(ctx, deviceName)
}

// enrollFail shows the error of an enrollment call to the server. When the
// server's step has timed out, or was used up by a two-step setup that
// succeeded before the enrollment failed, retrying on this screen cannot
// work: the app goes back to the setup screen with the link filled in, so
// the user only presses Continue. If two-step verification is set up, the
// next try with that link requires the code.
func (c *Controller) enrollFail(err error) {
	e := c.enroll
	if protocol.ErrorCode(err) != protocol.ErrCodeInvalidStep || e == nil {
		c.fail(err)
		return
	}
	if e.mfaDone || e.codeRequired {
		c.mfaSetLink = e.link.Token
	}
	verr := viewError(err)
	if e.mfaDone {
		verr = &ViewError{Code: ErrEnrollInterrupted}
		c.o.Log("enrollment interrupted after MFA setup; back to the link", "err", err)
	} else {
		c.o.Log("enrollment step timed out; back to the link", "err", err)
	}
	c.enroll = nil
	c.setView(View{Screen: ScreenSetup, Error: verr, Replacing: e.replacing, Link: e.raw})
}

// enrollFinish makes the device's keys, registers them with the server and
// the service, and saves the account.
func (c *Controller) enrollFinish(ctx context.Context, deviceName string) {
	e := c.enroll
	wgPriv, wgPub, err := protocol.GenerateWireGuardKey()
	if err != nil {
		c.fail(err)
		return
	}
	defer wgPriv.Wipe()
	devPub, devPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		c.fail(err)
		return
	}
	defer clear(devPriv)
	nonce, err := c.o.Service.Nonce()
	if err != nil {
		c.fail(err)
		return
	}
	req := protocol.EnrollFinishRequest{
		StepToken: e.stepToken, Nonce: nonce, Platform: version.Platform,
		WGPublicKey: wgPub.String(), DeviceKey: protocol.EncodeEd25519PublicKey(devPub),
		App: protocol.AppIdentity{Name: version.AppName, Version: version.Version}, OS: c.o.OSName,
	}
	if e.info.NameEditable {
		req.DeviceName = strings.TrimSpace(deviceName)
	}
	var certKey []byte
	if e.certRequired {
		var csr []byte
		if certKey, csr, err = protocol.NewCertificateRequest(); err != nil {
			c.fail(err)
			return
		}
		defer clear(certKey)
		req.CSR = base64.StdEncoding.EncodeToString(csr)
	}
	enrolled, doc, err := e.client.EnrollFinish(ctx, req)
	if err != nil {
		c.enrollFail(err)
		return
	}
	var cert []byte
	if certKey != nil {
		if cert, err = checkedCertificate(enrolled.Certificate, certKey); err != nil {
			c.fail(err)
			return
		}
	}
	psk, err := protocol.OpenSealedPSK(enrolled.PSKSealed, wgPriv, enrolled.DeviceID)
	if err != nil {
		c.fail(err)
		return
	}
	defer psk.Wipe()
	identityKey := protocol.EncodeEd25519PublicKey(e.pin.Key)
	if err := c.o.Service.Register(e.link.Server, identityKey, doc); err != nil {
		c.fail(err)
		return
	}
	account := &keystore.Account{
		Server: e.link.Server, Fingerprint: e.pin.Fingerprint, IdentityKey: identityKey,
		DeviceID: enrolled.DeviceID, Username: enrolled.Username, DeviceName: enrolled.Device,
		EnrolledAt: c.o.Now().UTC(), KeysExpireAt: enrolled.KeysExpireAt, RenewAfter: enrolled.RenewAfter,
	}
	secrets := &keystore.Secrets{DeviceSeed: devPriv.Seed(), WGPrivate: wgPriv, PSK: psk,
		CertKey: append([]byte(nil), certKey...), Certificate: cert}
	defer secrets.Wipe()
	saved, err := c.o.Store.Save(account, secrets)
	if err != nil {
		c.fail(err)
		return
	}
	if old := c.account; old != nil && old.Server != account.Server {
		c.forget(old.Server)
	}
	c.o.Log("enrolled", "server", account.Server, "device", account.DeviceID)
	c.account, c.enroll, c.mfaSetLink = saved, nil, ""
	c.setView(View{Screen: ScreenSignIn, Notice: "enrolled"})
}

// checkedCertificate decodes the certificate the server issued and checks
// it matches the key the app made for it.
func checkedCertificate(certB64 string, key []byte) ([]byte, error) {
	cert, err := base64.StdEncoding.DecodeString(certB64)
	if err != nil || len(cert) == 0 {
		return nil, errors.New("the server sent no usable certificate")
	}
	if _, err := protocol.ClientCertificate(cert, key); err != nil {
		return nil, err
	}
	return cert, nil
}

// forget removes an account from the store and the service.
func (c *Controller) forget(server string) {
	if err := c.o.Service.Forget(server); err != nil {
		c.o.Log("removing the server from the service failed", "err", err)
	}
	if err := c.o.Store.Delete(server); err != nil {
		c.o.Log("removing the account failed", "err", err)
	}
}

func (c *Controller) removeAccount() {
	if c.account == nil {
		return
	}
	c.endSession(true, "")
	c.forget(c.account.Server)
	c.account = nil
	c.setView(View{Screen: ScreenSetup})
}

// --- sign-in and session ------------------------------------------------------------

// credentials opens the account's keys and makes a client for its server.
func (c *Controller) credentials() (*protocol.Client, *keystore.Secrets, *protocol.KeySigner, error) {
	if c.account == nil {
		return nil, nil, nil, errNoAccount
	}
	pin, err := c.account.Pin()
	if err != nil {
		return nil, nil, nil, err
	}
	sec, err := c.o.Store.Secrets(c.account)
	if err != nil {
		return nil, nil, nil, err
	}
	var cert *tls.Certificate
	if sec.HasCertificate() {
		if cert, err = protocol.ClientCertificate(sec.Certificate, sec.CertKey); err != nil {
			sec.Wipe()
			return nil, nil, nil, err
		}
	}
	client, err := c.newClient(c.account.Server, pin, cert)
	if err != nil {
		sec.Wipe()
		return nil, nil, nil, err
	}
	signer, err := sec.Signer(c.account.DeviceID)
	if err != nil {
		sec.Wipe()
		return nil, nil, nil, err
	}
	return client, sec, signer, nil
}

func (c *Controller) signIn(password, otp string) {
	c.startSession(func(ctx context.Context, client *protocol.Client, auth protocol.Auth, wgPublic string) (*protocol.LoginResult, error) {
		return client.Login(ctx, auth, protocol.LoginRequest{Username: c.account.Username,
			Password: password, OTP: strings.TrimSpace(otp), WGPublicKey: wgPublic})
	})
}

func (c *Controller) signInOTP(otp string) {
	step := c.signin
	if step == nil {
		return
	}
	// The WireGuard key was announced with the password; the server keeps it
	// for this step.
	c.startSession(func(ctx context.Context, client *protocol.Client, auth protocol.Auth, _ string) (*protocol.LoginResult, error) {
		return client.LoginOTP(ctx, auth, step.stepToken, strings.TrimSpace(otp))
	})
}

// startSession runs one sign-in call and, on success, brings the tunnel up.
// call gets the public key of the WireGuard key this sign-in uses: the
// renewed one if a renewal is pending, which the sign-in then adopts.
func (c *Controller) startSession(call func(context.Context, *protocol.Client, protocol.Auth, string) (*protocol.LoginResult, error)) {
	if c.session != nil {
		return
	}
	c.setBusy(true)
	client, sec, signer, err := c.credentials()
	if err != nil {
		c.fail(err)
		return
	}
	defer sec.Wipe()
	ctx, cancel := c.ctx()
	defer cancel()
	info, err := client.Info(ctx)
	if err != nil {
		c.fail(err)
		return
	}
	if err := protocol.CheckCompatible(info, version.Platform, version.Version, version.Compare); err != nil {
		if protocol.ErrorCode(err) == protocol.ErrCodeAppTooOld {
			c.showUpdate(info)
			return
		}
		c.fail(err)
		return
	}
	wgPriv, psk := sec.TunnelKeys()
	wgPub, err := protocol.WireGuardPublicKey(wgPriv)
	if err != nil {
		c.fail(err)
		return
	}
	nonce, err := c.o.Service.Nonce()
	if err != nil {
		c.fail(err)
		return
	}
	res, err := call(ctx, client, protocol.Auth{Signer: signer, Nonce: nonce}, wgPub.String())
	if err != nil {
		c.signin = nil
		switch protocol.ErrorCode(err) {
		case protocol.ErrCodeKeysExpired:
			c.setView(View{Screen: ScreenSetup, Error: viewError(err), Replacing: true})
			return
		case protocol.ErrCodeAppTooOld:
			c.showUpdate(info)
			return
		}
		c.fail(err)
		if c.view.Screen == ScreenSignInOTP && protocol.ErrorCode(err) == protocol.ErrCodeInvalidCredentials {
			c.view.Screen = ScreenSignIn // the step is used up: start again
			c.show()
		}
		return
	}
	if res.OTPRequired {
		c.signin = &signinStep{stepToken: res.StepToken}
		c.setView(View{Screen: ScreenSignInOTP})
		return
	}
	c.signin = nil
	if sec.Pending != nil { // the server has seen the renewed keys in use
		sec.AdoptPending()
		if saved, err := c.o.Store.Save(c.account, sec); err == nil {
			c.account = saved
		} else {
			c.o.Log("saving the adopted keys failed", "err", err)
		}
	}
	st, err := c.o.Service.Connect(c.account.Server, res.Document, wgPriv, psk)
	if err != nil {
		// The server session exists but this computer has no tunnel: end it.
		lctx, lcancel := c.ctx()
		client.Logout(lctx, protocol.Auth{Signer: signer, Nonce: mustNonce(), SessionToken: res.Session.SessionToken})
		lcancel()
		c.fail(err)
		return
	}
	sctx, scancel := context.WithCancel(context.Background())
	s := &session{client: client, token: res.Session.SessionToken, cancel: scancel, doc: res.Session}
	s.signer.Store(signer)
	s.version.Store(res.Session.Config.Version)
	c.session = s
	c.setView(View{Screen: ScreenConnected, Session: sessionView(res.Session, st)})
	go c.follow(sctx, s)
	go c.refreshStats(sctx, s)
	c.maybeRenew(s)
}

func mustNonce() string {
	n, err := protocol.NewNonce()
	if err != nil {
		panic(err) // the system's random source failed
	}
	return n
}

func sessionView(s *protocol.Session, st *ipc.Status) *SessionView {
	v := &SessionView{ExpiresAt: s.ExpiresAt, IdleTimeout: s.IdleTimeoutSeconds}
	if st != nil {
		v.ConnectedAt, v.Address, v.AllowedIPs = st.ConnectedAt, st.Address, st.AllowedIPs
		v.LastHandshake, v.RxBytes, v.TxBytes = st.LastHandshake, st.RxBytes, st.TxBytes
	}
	return v
}

// follow long-polls the session and hands every answer to the service.
// It runs on its own goroutine and reports back through post.
func (c *Controller) follow(ctx context.Context, s *session) {
	delay := retryMin
	for ctx.Err() == nil {
		nonce, err := c.o.Service.Nonce()
		if err != nil {
			c.post(func() { c.sessionLost(s, errServiceUnavailable) })
			return
		}
		signer := s.signer.Load()
		pctx, cancel := context.WithTimeout(ctx, pollTimeout)
		doc, raw, err := s.client.Session(pctx, protocol.Auth{Signer: signer, Nonce: nonce, SessionToken: s.token},
			pollWait, s.version.Load())
		cancel()
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			code := protocol.ErrorCode(err)
			if code == protocol.ErrCodeInvalidSignature && s.signer.Load() != signer {
				continue // signed with the old key while it was being renewed: again with the new one
			}
			if code == protocol.ErrCodeInvalidSession || code == protocol.ErrCodeInvalidSignature {
				c.post(func() { c.sessionLost(s, err) })
				return
			}
			// The server is unreachable for now; the tunnel stays as it is.
			c.o.Log("session status failed; retrying", "err", err, "in", delay)
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return
			}
			delay = min(delay*2, retryMax)
			continue
		}
		delay = retryMin
		st, uerr := c.o.Service.Update(raw)
		if uerr == nil && doc.Config != nil {
			s.version.Store(doc.Config.Version)
		}
		c.post(func() { c.sessionUpdated(s, doc, st, uerr) })
		if uerr != nil || doc.Status != protocol.StatusConnected {
			return
		}
	}
}

// sessionUpdated runs on the controller goroutine after a status answer.
func (c *Controller) sessionUpdated(s *session, doc *protocol.Session, st *ipc.Status, err error) {
	if c.session != s {
		return // an old session
	}
	if err != nil {
		c.sessionLost(s, err)
		return
	}
	if doc.Status != protocol.StatusConnected {
		reason := doc.Reason
		c.endSession(false, reason)
		c.setView(View{Screen: ScreenSignIn, Notice: reason})
		return
	}
	s.doc = doc
	if c.view.Screen == ScreenConnected {
		c.view.Session = sessionView(doc, st)
		c.show()
	}
	c.maybeRenew(s)
}

// sessionLost ends a session that can no longer be followed.
func (c *Controller) sessionLost(s *session, err error) {
	if c.session != s {
		return
	}
	c.endSession(true, "")
	c.setView(View{Screen: ScreenSignIn, Error: viewError(err)})
}

// refreshStats updates the traffic counters while the window shows them.
func (c *Controller) refreshStats(ctx context.Context, s *session) {
	t := time.NewTicker(statsRefresh)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		st, err := c.o.Service.Status()
		if err != nil {
			continue
		}
		c.post(func() {
			if c.session != s || c.view.Screen != ScreenConnected {
				return
			}
			if st.Owner != ipc.OwnerYou || st.State != ipc.StateConnected {
				// The service took the tunnel down (policy change, failure).
				c.sessionLost(s, &ipc.Error{Code: firstNonEmpty(st.LastError, ipc.ErrTunnel)})
				return
			}
			c.view.Session = sessionView(s.doc, st)
			c.show()
		})
	}
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// endSession stops following the session and takes the tunnel down. With
// logout it also ends the session on the server (best effort). reason is
// recorded as the notice.
func (c *Controller) endSession(logout bool, reason string) {
	s := c.session
	if s == nil {
		return
	}
	c.session = nil
	s.cancel()
	if err := c.o.Service.Disconnect(); err != nil {
		c.o.Log("disconnecting the tunnel failed", "err", err)
	}
	if logout {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := s.client.Logout(ctx, protocol.Auth{Signer: s.signer.Load(), Nonce: mustNonce(), SessionToken: s.token})
		cancel()
		if err != nil {
			c.o.Log("signing out on the server failed", "err", err)
		}
	}
	c.o.Log("session ended", "logout", logout, "reason", reason)
}

// --- key renewal ------------------------------------------------------------------

// maybeRenew renews the keys once per session when the server allows it.
// It runs on the controller goroutine, so no sign-in or other action can
// come between the server accepting the new keys and the app using them;
// it happens once every few months, right after sign-in.
func (c *Controller) maybeRenew(s *session) {
	if s.renewed || s.doc.RenewAfter.IsZero() || c.o.Now().Before(s.doc.RenewAfter) {
		return
	}
	s.renewed = true
	account := *c.account
	saved, err := c.renew(s, &account)
	if protocol.ErrorCode(err) == protocol.ErrCodeRenewNotDue {
		return
	}
	if err != nil {
		c.o.Log("renewing the keys failed; will try again next session", "err", err)
		return
	}
	c.account = saved
	if c.view.Screen == ScreenConnected {
		c.view.Account = accountView(c.account)
		c.show()
	}
}

// renew makes new keys and registers them. The new WireGuard keys are kept
// as pending: the tunnel keeps the current ones, and the next sign-in
// announces and adopts the new ones. The new device key signs once it is
// saved; the server keeps the old one until the new one is first used
// (protocol section 10), so a crash at any point leaves the device able to
// sign in.
func (c *Controller) renew(s *session, account *keystore.Account) (*keystore.Account, error) {
	sec, err := c.o.Store.Secrets(account)
	if err != nil {
		return nil, err
	}
	defer sec.Wipe()
	wgPriv, wgPub, err := protocol.GenerateWireGuardKey()
	if err != nil {
		return nil, err
	}
	defer wgPriv.Wipe()
	devPub, devPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	defer clear(devPriv)
	req := protocol.RenewRequest{WGPublicKey: wgPub.String(), DeviceKey: protocol.EncodeEd25519PublicKey(devPub)}
	var certKey []byte
	if sec.HasCertificate() {
		var csr []byte
		if certKey, csr, err = protocol.NewCertificateRequest(); err != nil {
			return nil, err
		}
		defer clear(certKey)
		req.CSR = base64.StdEncoding.EncodeToString(csr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), renewTimeout)
	defer cancel()
	renewed, _, err := s.client.Renew(ctx, protocol.Auth{Signer: s.signer.Load(), Nonce: mustNonce()}, req)
	if err != nil {
		return nil, err
	}
	psk, err := protocol.OpenSealedPSK(renewed.PSKSealed, wgPriv, account.DeviceID)
	if err != nil {
		return nil, err
	}
	clear(sec.DeviceSeed)
	sec.DeviceSeed = devPriv.Seed()
	if sec.Pending != nil {
		sec.Pending.WGPrivate.Wipe()
		sec.Pending.PSK.Wipe()
	}
	sec.Pending = &keystore.PendingKeys{WGPrivate: wgPriv, PSK: psk}
	if certKey != nil {
		cert, err := checkedCertificate(renewed.Certificate, certKey)
		if err != nil {
			return nil, err
		}
		clear(sec.CertKey)
		sec.CertKey, sec.Certificate = append([]byte(nil), certKey...), cert
	}
	account.KeysExpireAt, account.RenewAfter = renewed.KeysExpireAt, renewed.RenewAfter
	saved, err := c.o.Store.Save(account, sec)
	if err != nil {
		return nil, err // the old keys are still saved, and still valid
	}
	// Only once the new device key is saved does the app sign with it: its
	// first use ends the old one on the server.
	signer, err := protocol.NewKeySigner(account.DeviceID, ed25519.NewKeyFromSeed(devPriv.Seed()))
	if err != nil {
		return nil, err
	}
	s.signer.Store(signer)
	c.o.Log("keys renewed; the new tunnel keys are used from the next sign-in", "expire", account.KeysExpireAt)
	return saved, nil
}

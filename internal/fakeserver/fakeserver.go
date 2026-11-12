// Package fakeserver is an in-memory Hifaz server that speaks the client
// protocol, for tests only. It checks requests as strictly as the protocol
// document says the real server does (signatures, nonces, clock, tokens), so
// tests against it catch client mistakes; it is not a model of the server's
// internals.
package fakeserver

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/protocol"
	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/version"
)

// OTP is the one code every MFA user's authenticator shows.
const OTP = "123456"

// The sign-in code step, as on the real server (protocol section 8): it
// lasts five minutes and ends at the third wrong code.
const (
	loginStepTTL   = 5 * time.Minute
	loginStepTries = 3
)

// Server is a running fake server.
type Server struct {
	ts       *httptest.Server
	prefix   string // path prefix of the public URL, "" or like "/vpn"
	identity ed25519.PrivateKey
	requests atomic.Int64      // every HTTP request, answered or not
	caKey    *ecdsa.PrivateKey // signs device certificates
	caCert   *x509.Certificate

	mu            sync.Mutex
	now           func() time.Time
	users         map[string]*user
	links         map[string]*link
	steps         map[string]*step
	devices       map[string]*Device
	sessions      map[string]*session // by token
	seen          map[string]time.Time
	config        protocol.Config
	changed       chan struct{}
	minAppVersion string
	appDownload   string
	renewAfter    time.Duration
	renewals      int
	serverVersion string
	nextID        int
}

type user struct {
	password string
	mfa      bool
	cert     bool // the user's group requires device certificates
}

type link struct {
	kind, username, device string
}

type step struct {
	link       string
	needsSetup bool         // cleared once two-step setup succeeds, as on the real server
	wgKey      protocol.Key // sign-in: the WireGuard key announced
	expires    time.Time    // sign-in: when the step ends
	tries      int          // sign-in: wrong codes so far
}

// Device is an enrolled app device as the server records it. After a
// renewal the new keys are pending (Next*) until they are used, as the
// protocol says (section 10).
type Device struct {
	ID, Username, Name string
	Key                ed25519.PublicKey
	WGPublicKey        protocol.Key
	PSK                protocol.Key
	Cert               []byte // the certificate the device must present, if any
	Disabled           bool

	NextKey         ed25519.PublicKey
	NextWGPublicKey protocol.Key
	NextPSK         protocol.Key
}

type session struct {
	id, token, device string
	status, reason    string
}

// Options configure New.
type Options struct {
	Prefix string           // public URL path prefix, for example "/vpn"
	Now    func() time.Time // server clock; nil means time.Now
}

// New starts a fake server; it stops when the test ends.
func New(t testing.TB, opts Options) *Server {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		prefix: strings.TrimRight(opts.Prefix, "/"), identity: priv, now: opts.Now,
		users: map[string]*user{}, links: map[string]*link{}, steps: map[string]*step{},
		devices: map[string]*Device{}, sessions: map[string]*session{}, seen: map[string]time.Time{},
		changed: make(chan struct{}), renewAfter: 76 * 24 * time.Hour, serverVersion: "0.8.0",
		config: protocol.Config{
			Version: 1, Address: "10.98.10.4/32", Endpoint: "vpn.example.com:51820",
			ServerPublicKey: "mkk2/n0976hg+yS1HkmS3Jr4EphDhzmX+vOZ02alXlY=",
			AllowedIPs:      []string{"10.98.0.0/16"},
			DNS:             protocol.DNS{Servers: []string{"10.98.0.1"}, Search: []string{"corp"}},
			MTU:             1420,
		},
	}
	if s.now == nil {
		s.now = time.Now
	}
	s.newCA(t)
	mux := http.NewServeMux()
	api := s.prefix + protocol.APIPrefix
	mux.HandleFunc("GET "+api+"/info", s.handleInfo)
	mux.HandleFunc("POST "+api+"/enroll/info", s.handleEnrollInfo)
	mux.HandleFunc("POST "+api+"/enroll/start", s.handleEnrollStart)
	mux.HandleFunc("POST "+api+"/enroll/mfa", s.handleEnrollMFA)
	mux.HandleFunc("POST "+api+"/enroll/finish", s.handleEnrollFinish)
	mux.HandleFunc("POST "+api+"/login", s.signed(s.handleLogin))
	mux.HandleFunc("POST "+api+"/login/otp", s.signed(s.handleLoginOTP))
	mux.HandleFunc("GET "+api+"/session", s.signed(s.handleSession))
	mux.HandleFunc("POST "+api+"/logout", s.signed(s.handleLogout))
	mux.HandleFunc("POST "+api+"/keys/renew", s.signed(s.handleRenew))
	s.ts = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.requests.Add(1)
		mux.ServeHTTP(w, r)
	}))
	s.ts.TLS = &tls.Config{ClientAuth: tls.RequestClientCert} // as a proxy for certificate groups
	s.ts.StartTLS()
	t.Cleanup(s.ts.Close)
	return s
}

func (s *Server) newCA(t testing.TB) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Fake Hifaz CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	s.caKey = key
	s.caCert, _ = x509.ParseCertificate(der)
}

// issue signs a device certificate for a P-256 CSR (section 6).
func (s *Server) issue(csrB64, username string) ([]byte, bool) {
	der, err := base64.StdEncoding.DecodeString(csrB64)
	if err != nil {
		return nil, false
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil || csr.CheckSignature() != nil {
		return nil, false
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, false
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: username},
		NotBefore: s.now().Add(-time.Minute), NotAfter: s.now().Add(90 * 24 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	cert, err := x509.CreateCertificate(rand.Reader, tmpl, s.caCert, pub, s.caKey)
	return cert, err == nil
}

// appTooOld applies min_app_version to the Hifaz-App header, as the real
// server does: on signed calls and at enroll/finish only, so an old app can
// still read the info document and its download link (section 3). It
// writes the error and reports true when the app is too old. s.mu is held.
func (s *Server) appTooOld(w http.ResponseWriter, r *http.Request) bool {
	platform, v, ok := strings.Cut(r.Header.Get(protocol.HeaderApp), "/")
	if s.minAppVersion == "" || !ok || platform != "windows" {
		return false
	}
	if cmp, err := version.Compare(v, s.minAppVersion); err == nil && cmp >= 0 {
		return false
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(403)
	json.NewEncoder(w).Encode(map[string]string{"error": protocol.ErrCodeAppTooOld, "min_version": s.minAppVersion})
	return true
}

// URL is the server's public URL.
func (s *Server) URL() string { return s.ts.URL + s.prefix }

// HTTPClient returns a protocol HTTP client that trusts the test certificate.
func (s *Server) HTTPClient() *http.Client { return s.HTTPClientWith(nil) }

// HTTPClientWith is HTTPClient presenting a device certificate.
func (s *Server) HTTPClientWith(cert *tls.Certificate) *http.Client {
	hc := protocol.NewHTTPClient(nil, cert)
	hc.Transport.(*http.Transport).TLSClientConfig.RootCAs = s.ts.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	return hc
}

// Pin is the server's identity.
func (s *Server) Pin() protocol.Pin {
	pub := s.identity.Public().(ed25519.PublicKey)
	return protocol.Pin{Fingerprint: protocol.FingerprintOf(pub), Key: pub}
}

// Requests is the number of HTTP requests the server has received.
func (s *Server) Requests() int { return int(s.requests.Load()) }

// ExpireSteps ends every enrollment and sign-in step, as if they had timed
// out: the next call with a step token gets invalid_step.
func (s *Server) ExpireSteps() {
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.steps)
}

// AddUser creates a user.
func (s *Server) AddUser(name, password string, mfa bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[name] = &user{password: password, mfa: mfa}
}

// RequireCertificate puts a user in a group that requires device
// certificates.
func (s *Server) RequireCertificate(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[name].cert = true
}

// NewLink creates an enrollment link and returns it as the app gets it
// (with the fingerprint) and its bare token.
func (s *Server) NewLink(kind, username, device string) (url, token string) {
	token = s.random()
	s.mu.Lock()
	s.links[token] = &link{kind: kind, username: username, device: device}
	s.mu.Unlock()
	return s.URL() + "/login/enroll#" + token + "." + string(s.Pin().Fingerprint), token
}

// Device returns an enrolled device.
func (s *Server) Device(id string) *Device {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d := s.devices[id]; d != nil {
		cp := *d
		return &cp
	}
	return nil
}

// DisableDevice stops a device's signed requests and ends its session.
func (s *Server) DisableDevice(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d := s.devices[id]; d != nil {
		d.Disabled = true
	}
	s.endLocked(protocol.ReasonDeviceDisabled)
}

// EndSessions ends every session with reason.
func (s *Server) EndSessions(reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.endLocked(reason)
}

func (s *Server) endLocked(reason string) {
	for _, se := range s.sessions {
		if se.status == protocol.StatusConnected {
			se.status, se.reason = protocol.StatusEnded, reason
		}
	}
	s.notifyLocked()
}

// SetAllowedIPs changes the configuration (and its version).
func (s *Server) SetAllowedIPs(ips ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.config.AllowedIPs = ips
	s.config.Version++
	s.notifyLocked()
}

// SetMinAppVersion sets min_app_version for Windows.
func (s *Server) SetMinAppVersion(v string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.minAppVersion = v
}

// SetServerVersion sets server_version in the info document.
func (s *Server) SetServerVersion(v string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.serverVersion = v
}

// SetAppDownload sets app_download for Windows.
func (s *Server) SetAppDownload(url string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.appDownload = url
}

// SetRenewAfter sets how long after now renew_after lies (negative: renewal
// is due).
func (s *Server) SetRenewAfter(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.renewAfter = d
}

// ActiveSessions counts connected sessions.
func (s *Server) ActiveSessions() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, se := range s.sessions {
		if se.status == protocol.StatusConnected {
			n++
		}
	}
	return n
}

// Renewals counts key renewals.
func (s *Server) Renewals() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.renewals
}

func (s *Server) notifyLocked() {
	close(s.changed)
	s.changed = make(chan struct{})
}

// --- handlers --------------------------------------------------------------------

func (s *Server) handleInfo(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	minVersion, download, serverVersion := map[string]string{}, map[string]string{}, s.serverVersion
	if s.minAppVersion != "" {
		minVersion["windows"] = s.minAppVersion
	}
	if s.appDownload != "" {
		download["windows"] = s.appDownload
	}
	s.mu.Unlock()
	s.writeSigned(w, map[string]any{
		"type": protocol.TypeInfo, "server": s.URL(), "issued_at": s.now(),
		"name":     map[string]string{"en": "Hifaz", "ar": "حِفاظ"},
		"protocol": map[string]int{"min": 1, "max": 1}, "server_version": serverVersion,
		"identity_key":    protocol.EncodeEd25519PublicKey(s.identity.Public().(ed25519.PublicKey)),
		"min_app_version": minVersion, "features": []string{"enroll", "login", "session", "renew"},
		"app_download": download,
	})
}

func (s *Server) handleEnrollInfo(w http.ResponseWriter, r *http.Request) {
	var req struct{ Link string }
	if !decode(w, r, &req) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	l := s.links[req.Link]
	if l == nil {
		writeError(w, 400, protocol.ErrCodeInvalidLink)
		return
	}
	if l.kind != protocol.LinkDevice && l.kind != protocol.LinkRenew {
		writeError(w, 400, protocol.ErrCodeUseBrowser)
		return
	}
	writeJSON(w, protocol.EnrollLinkInfo{Kind: l.kind, Username: l.username, Device: l.device,
		ExpiresAt: s.now().Add(24 * time.Hour), NameEditable: l.device == ""})
}

func (s *Server) handleEnrollStart(w http.ResponseWriter, r *http.Request) {
	var req struct{ Link, Password, OTP string }
	if !decode(w, r, &req) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	l := s.links[req.Link]
	if l == nil {
		writeError(w, 400, protocol.ErrCodeInvalidLink)
		return
	}
	u := s.users[l.username]
	if u == nil || u.password != req.Password {
		writeError(w, 401, protocol.ErrCodeInvalidCredentials)
		return
	}
	token := s.random()
	st := &step{link: req.Link, needsSetup: !u.mfa}
	s.steps[token] = st
	out := protocol.EnrollStartResult{StepToken: token, Kind: l.kind, Username: l.username, Device: l.device,
		NeedsMFASetup: st.needsSetup, CertRequired: u.cert}
	if st.needsSetup {
		out.MFASecret = "JBSWY3DPEHPK3PXP"
		out.MFAURI = "otpauth://totp/Hifaz:" + l.username + "?secret=JBSWY3DPEHPK3PXP&issuer=Hifaz"
	} else if req.OTP != OTP {
		delete(s.steps, token)
		writeError(w, 401, protocol.ErrCodeInvalidCredentials)
		return
	}
	writeJSON(w, out)
}

func (s *Server) handleEnrollMFA(w http.ResponseWriter, r *http.Request) {
	var req struct {
		StepToken string `json:"step_token"`
		Code      string `json:"code"`
	}
	if !decode(w, r, &req) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.steps[req.StepToken]
	if st == nil || !st.needsSetup {
		writeError(w, 400, protocol.ErrCodeInvalidStep)
		return
	}
	if req.Code != OTP {
		writeError(w, 400, protocol.ErrCodeInvalidCode)
		return
	}
	st.needsSetup = false
	s.users[s.links[st.link].username].mfa = true
	writeJSON(w, map[string]bool{"done": false})
}

func (s *Server) handleEnrollFinish(w http.ResponseWriter, r *http.Request) {
	var req protocol.EnrollFinishRequest
	if !decode(w, r, &req) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.appTooOld(w, r) {
		return
	}
	st := s.steps[req.StepToken]
	if st == nil || st.needsSetup {
		writeError(w, 400, protocol.ErrCodeInvalidStep)
		return
	}
	l := s.links[st.link]
	wgPub, err1 := protocol.ParseKey(req.WGPublicKey)
	devKey, err2 := protocol.ParseEd25519PublicKey(req.DeviceKey)
	if err1 != nil || err2 != nil || !protocol.ValidNonce(req.Nonce) || req.Platform != "windows" {
		writeError(w, 400, "invalid_request")
		return
	}
	name := l.device
	if name == "" {
		name = req.DeviceName
	}
	if name == "" {
		writeError(w, 400, protocol.ErrCodeInvalidDeviceChoice)
		return
	}
	var cert []byte
	if s.users[l.username].cert {
		var ok bool
		if cert, ok = s.issue(req.CSR, l.username); !ok {
			writeError(w, 400, protocol.ErrCodeInvalidCSR)
			return
		}
	}
	var psk protocol.Key
	rand.Read(psk[:])
	s.nextID++
	d := &Device{ID: fmt.Sprintf("d_%04d", s.nextID), Username: l.username, Name: name,
		Key: devKey, WGPublicKey: wgPub, PSK: psk, Cert: cert}
	s.devices[d.ID] = d
	delete(s.steps, req.StepToken)
	delete(s.links, st.link)
	sealed, _ := protocol.SealPSK(psk, wgPub, d.ID, rand.Reader)
	s.writeSigned(w, map[string]any{
		"type": protocol.TypeEnrolled, "nonce": req.Nonce, "server": s.URL(), "issued_at": s.now(),
		"device_id": d.ID, "username": d.Username, "device": d.Name,
		"keys_expire_at": s.now().Add(90 * 24 * time.Hour), "renew_after": s.now().Add(s.renewAfter),
		"psk_sealed": sealed, "config": s.config, "certificate": b64OrNil(cert),
	})
}

// request is a verified signed request.
type request struct {
	device *Device
	nonce  string
	body   []byte
	r      *http.Request
	wgKey  protocol.Key // sign-in: the WireGuard key announced, if any
}

// signed checks the device signature (section 7) before calling h, with
// s.mu held.
func (s *Server) signed(h func(http.ResponseWriter, *request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			writeError(w, 400, "invalid_request")
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		now := s.now()
		d := s.devices[r.Header.Get(protocol.HeaderDevice)]
		ts, terr := time.Parse(time.RFC3339, r.Header.Get(protocol.HeaderTime))
		nonce := r.Header.Get(protocol.HeaderNonce)
		sig, serr := base64.RawURLEncoding.DecodeString(r.Header.Get(protocol.HeaderSignature))
		if terr == nil && (now.Sub(ts) > 5*time.Minute || ts.Sub(now) > 5*time.Minute) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(401)
			json.NewEncoder(w).Encode(map[string]any{"error": protocol.ErrCodeClockSkew,
				"message": "device clock is off", "server_time": now.UTC()})
			return
		}
		path := strings.TrimPrefix(r.URL.RequestURI(), s.prefix)
		if d == nil || d.Disabled || terr != nil || serr != nil || !protocol.ValidNonce(nonce) {
			writeError(w, 401, protocol.ErrCodeInvalidSignature)
			return
		}
		sts := protocol.StringToSign(r.Method, path, r.Header.Get(protocol.HeaderTime), nonce, body)
		switch {
		case ed25519.Verify(d.Key, sts, sig):
		case d.NextKey != nil && ed25519.Verify(d.NextKey, sts, sig):
			d.Key, d.NextKey = d.NextKey, nil // the renewed key is in use: the old one ends
		default:
			writeError(w, 401, protocol.ErrCodeInvalidSignature)
			return
		}
		if s.appTooOld(w, r) {
			return
		}
		if d.Cert != nil && (r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || !bytes.Equal(r.TLS.PeerCertificates[0].Raw, d.Cert)) {
			writeError(w, 400, protocol.ErrCodeCertRequired)
			return
		}
		if _, dup := s.seen[nonce]; dup {
			writeError(w, 401, protocol.ErrCodeInvalidSignature)
			return
		}
		s.seen[nonce] = now
		h(w, &request{device: d, nonce: nonce, body: body, r: r})
	}
}

func (s *Server) handleLogin(w http.ResponseWriter, q *request) {
	var req protocol.LoginRequest
	if json.Unmarshal(q.body, &req) != nil {
		writeError(w, 400, "invalid_request")
		return
	}
	u := s.users[req.Username]
	if u == nil || u.password != req.Password || q.device.Username != req.Username {
		writeError(w, 401, protocol.ErrCodeInvalidCredentials)
		return
	}
	if req.WGPublicKey != "" {
		k, err := protocol.ParseKey(req.WGPublicKey)
		if err != nil || (k != q.device.WGPublicKey && (q.device.NextWGPublicKey.IsZero() || k != q.device.NextWGPublicKey)) {
			writeError(w, 400, protocol.ErrCodeUnknownDevice)
			return
		}
		q.wgKey = k
	}
	if u.mfa && req.OTP == "" {
		token := s.random()
		s.steps[token] = &step{link: "login:" + q.device.ID, wgKey: q.wgKey, expires: s.now().Add(loginStepTTL)}
		writeJSON(w, map[string]string{"status": protocol.StatusOTPRequired, "step_token": token})
		return
	}
	if u.mfa && req.OTP != OTP {
		writeError(w, 401, protocol.ErrCodeInvalidCredentials)
		return
	}
	s.startSession(w, q)
}

func (s *Server) handleLoginOTP(w http.ResponseWriter, q *request) {
	var req struct {
		StepToken string `json:"step_token"`
		OTP       string `json:"otp"`
	}
	if json.Unmarshal(q.body, &req) != nil {
		writeError(w, 400, "invalid_request")
		return
	}
	st := s.steps[req.StepToken]
	if st == nil || st.link != "login:"+q.device.ID || !s.now().Before(st.expires) {
		delete(s.steps, req.StepToken)
		writeError(w, 400, protocol.ErrCodeInvalidStep)
		return
	}
	if req.OTP != OTP {
		if st.tries++; st.tries >= loginStepTries {
			delete(s.steps, req.StepToken)
		}
		writeError(w, 401, protocol.ErrCodeInvalidCredentials)
		return
	}
	delete(s.steps, req.StepToken)
	q.wgKey = st.wgKey
	s.startSession(w, q)
}

func (s *Server) startSession(w http.ResponseWriter, q *request) {
	if d := q.device; !d.NextWGPublicKey.IsZero() && q.wgKey == d.NextWGPublicKey {
		// The renewed WireGuard keys are in use now.
		d.WGPublicKey, d.PSK, d.NextWGPublicKey, d.NextPSK = d.NextWGPublicKey, d.NextPSK, protocol.Key{}, protocol.Key{}
	}
	for _, se := range s.sessions { // one session per device
		if se.device == q.device.ID && se.status == protocol.StatusConnected {
			se.status, se.reason = protocol.StatusEnded, protocol.ReasonSignedOut
		}
	}
	se := &session{id: s.random()[:16], token: s.random(), device: q.device.ID, status: protocol.StatusConnected}
	s.sessions[se.token] = se
	s.notifyLocked()
	s.writeSession(w, q, se)
}

func (s *Server) handleSession(w http.ResponseWriter, q *request) {
	se := s.sessionOf(q)
	if se == nil {
		writeError(w, 401, protocol.ErrCodeInvalidSession)
		return
	}
	query := q.r.URL.Query()
	known, _ := strconv.ParseInt(query.Get("version"), 10, 64)
	if wait := query.Get("wait"); wait != "" && se.status == protocol.StatusConnected &&
		(known == 0 || known == s.config.Version) {
		secs, _ := strconv.Atoi(wait)
		changed := s.changed
		s.mu.Unlock()
		select {
		case <-changed:
		case <-time.After(time.Duration(min(secs, 55)) * time.Second):
		case <-q.r.Context().Done():
		}
		s.mu.Lock()
	}
	s.writeSession(w, q, se)
}

func (s *Server) handleLogout(w http.ResponseWriter, q *request) {
	se := s.sessionOf(q)
	if se == nil {
		writeError(w, 401, protocol.ErrCodeInvalidSession)
		return
	}
	se.status, se.reason = protocol.StatusEnded, protocol.ReasonSignedOut
	s.notifyLocked()
	writeJSON(w, map[string]string{"status": "logged_out"})
}

func (s *Server) handleRenew(w http.ResponseWriter, q *request) {
	var req protocol.RenewRequest
	if json.Unmarshal(q.body, &req) != nil {
		writeError(w, 400, "invalid_request")
		return
	}
	wgPub, err := protocol.ParseKey(req.WGPublicKey)
	if err != nil {
		writeError(w, 400, protocol.ErrCodeBadRequest)
		return
	}
	if s.renewAfter > 0 && q.device.NextWGPublicKey.IsZero() {
		writeError(w, 400, protocol.ErrCodeRenewNotDue)
		return
	}
	var cert []byte
	if q.device.Cert != nil {
		var ok bool
		if cert, ok = s.issue(req.CSR, q.device.Username); !ok {
			writeError(w, 400, protocol.ErrCodeInvalidCSR)
			return
		}
	}
	if req.DeviceKey != "" {
		k, err := protocol.ParseEd25519PublicKey(req.DeviceKey)
		if err != nil {
			writeError(w, 400, protocol.ErrCodeBadRequest)
			return
		}
		q.device.NextKey = k
	}
	var psk protocol.Key
	rand.Read(psk[:])
	q.device.NextWGPublicKey, q.device.NextPSK = wgPub, psk // pending until used
	if cert != nil {
		q.device.Cert = cert
	}
	s.renewals++
	sealed, _ := protocol.SealPSK(psk, wgPub, q.device.ID, rand.Reader)
	s.writeSigned(w, map[string]any{
		"type": protocol.TypeRenewed, "nonce": q.nonce, "server": s.URL(), "issued_at": s.now(),
		"keys_expire_at": s.now().Add(90 * 24 * time.Hour), "renew_after": s.now().Add(s.renewAfter),
		"psk_sealed": sealed, "config": s.config, "certificate": b64OrNil(cert),
	})
}

func b64OrNil(b []byte) any {
	if b == nil {
		return nil
	}
	return base64.StdEncoding.EncodeToString(b)
}

func (s *Server) sessionOf(q *request) *session {
	token, ok := strings.CutPrefix(q.r.Header.Get("Authorization"), "Bearer ")
	se := s.sessions[token]
	if !ok || se == nil || se.device != q.device.ID {
		return nil
	}
	return se
}

func (s *Server) writeSession(w http.ResponseWriter, q *request, se *session) {
	doc := map[string]any{
		"type": protocol.TypeSession, "nonce": q.nonce, "server": s.URL(), "issued_at": s.now(),
		"status": se.status, "session_id": se.id, "session_token": se.token,
		"expires_at": s.now().Add(8 * time.Hour), "idle_timeout_seconds": 900,
		"keys_expire_at": s.now().Add(90 * 24 * time.Hour), "renew_after": s.now().Add(s.renewAfter),
	}
	if se.status == protocol.StatusConnected {
		doc["config"] = s.config
	} else {
		doc["reason"] = se.reason
	}
	s.writeSigned(w, doc)
}

// --- helpers --------------------------------------------------------------------

func (s *Server) writeSigned(w http.ResponseWriter, payload map[string]any) {
	data, err := json.Marshal(payload)
	if err != nil {
		writeError(w, 500, "internal")
		return
	}
	writeJSON(w, protocol.Sign(s.identity, data))
}

func (s *Server) random() string {
	b := make([]byte, 32)
	rand.Read(b)
	sum := sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(v); err != nil {
		writeError(w, 400, "invalid_request")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": code, "message": code})
}

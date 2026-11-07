// Package fakeserver is an in-memory Hifaz server that speaks the client
// protocol, for tests only. It checks requests as strictly as the protocol
// document says the real server does (signatures, nonces, clock, tokens), so
// tests against it catch client mistakes; it is not a model of the server's
// internals.
package fakeserver

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/protocol"
)

// OTP is the one code every MFA user's authenticator shows.
const OTP = "123456"

// Server is a running fake server.
type Server struct {
	ts       *httptest.Server
	prefix   string // path prefix of the public URL, "" or like "/vpn"
	identity ed25519.PrivateKey

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
	nextID        int
}

type user struct {
	password string
	mfa      bool
}

type link struct {
	kind, username, device string
}

type step struct {
	link       string
	needsSetup bool
	mfaDone    bool
}

// Device is an enrolled app device as the server records it.
type Device struct {
	ID, Username, Name string
	Key                ed25519.PublicKey
	WGPublicKey        protocol.Key
	PSK                protocol.Key
	Disabled           bool
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
		changed: make(chan struct{}), renewAfter: 76 * 24 * time.Hour,
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
	s.ts = httptest.NewTLSServer(mux)
	t.Cleanup(s.ts.Close)
	return s
}

// URL is the server's public URL.
func (s *Server) URL() string { return s.ts.URL + s.prefix }

// HTTPClient returns a protocol HTTP client that trusts the test certificate.
func (s *Server) HTTPClient() *http.Client {
	hc := protocol.NewHTTPClient(nil)
	hc.Transport.(*http.Transport).TLSClientConfig.RootCAs = s.ts.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	return hc
}

// Pin is the server's identity.
func (s *Server) Pin() protocol.Pin {
	pub := s.identity.Public().(ed25519.PublicKey)
	return protocol.Pin{Fingerprint: protocol.FingerprintOf(pub), Key: pub}
}

// AddUser creates a user.
func (s *Server) AddUser(name, password string, mfa bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[name] = &user{password: password, mfa: mfa}
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
	minVersion, download := map[string]string{}, map[string]string{}
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
		"protocol": map[string]int{"min": 1, "max": 1}, "server_version": "0.8.0",
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
		NeedsMFASetup: st.needsSetup}
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
	st.mfaDone = true
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
	st := s.steps[req.StepToken]
	if st == nil || (st.needsSetup && !st.mfaDone) {
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
	var psk protocol.Key
	rand.Read(psk[:])
	s.nextID++
	d := &Device{ID: fmt.Sprintf("d_%04d", s.nextID), Username: l.username, Name: name,
		Key: devKey, WGPublicKey: wgPub, PSK: psk}
	s.devices[d.ID] = d
	delete(s.steps, req.StepToken)
	delete(s.links, st.link)
	sealed, _ := protocol.SealPSK(psk, wgPub, d.ID, rand.Reader)
	s.writeSigned(w, map[string]any{
		"type": protocol.TypeEnrolled, "nonce": req.Nonce, "server": s.URL(), "issued_at": s.now(),
		"device_id": d.ID, "username": d.Username, "device": d.Name,
		"keys_expire_at": s.now().Add(90 * 24 * time.Hour), "psk_sealed": sealed, "config": s.config,
	})
}

// request is a verified signed request.
type request struct {
	device *Device
	nonce  string
	body   []byte
	r      *http.Request
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
		if d == nil || d.Disabled || terr != nil || serr != nil || !protocol.ValidNonce(nonce) ||
			!ed25519.Verify(d.Key, protocol.StringToSign(r.Method, path, r.Header.Get(protocol.HeaderTime), nonce, body), sig) {
			writeError(w, 401, protocol.ErrCodeInvalidSignature)
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
	if u.mfa && req.OTP == "" {
		token := s.random()
		s.steps[token] = &step{link: "login:" + q.device.ID}
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
	if st == nil || st.link != "login:"+q.device.ID || req.OTP != OTP {
		writeError(w, 401, protocol.ErrCodeInvalidCredentials)
		return
	}
	delete(s.steps, req.StepToken)
	s.startSession(w, q)
}

func (s *Server) startSession(w http.ResponseWriter, q *request) {
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
		writeError(w, 400, "invalid_request")
		return
	}
	if req.DeviceKey != "" {
		k, err := protocol.ParseEd25519PublicKey(req.DeviceKey)
		if err != nil {
			writeError(w, 400, "invalid_request")
			return
		}
		q.device.Key = k
	}
	var psk protocol.Key
	rand.Read(psk[:])
	q.device.WGPublicKey, q.device.PSK = wgPub, psk
	s.renewals++
	sealed, _ := protocol.SealPSK(psk, wgPub, q.device.ID, rand.Reader)
	s.writeSigned(w, map[string]any{
		"type": protocol.TypeRenewed, "nonce": q.nonce, "server": s.URL(), "issued_at": s.now(),
		"keys_expire_at": s.now().Add(90 * 24 * time.Hour), "renew_after": s.now().Add(s.renewAfter),
		"psk_sealed": sealed, "config": s.config,
	})
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

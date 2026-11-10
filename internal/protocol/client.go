package protocol

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// maxResponse bounds every answer read from the server.
const maxResponse = 1 << 20

// MaxWait is the longest a session status call may wait for a change.
const MaxWait = 55 * time.Second

// ErrIdentityMismatch means the server's identity key is not the pinned one.
var ErrIdentityMismatch = errors.New("the server identity does not match")

// Options configure a Client.
type Options struct {
	// HTTPClient sends the requests; nil means NewHTTPClient(nil).
	HTTPClient *http.Client
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// UserAgent names the app, for example "Hifaz-Windows/0.1.0".
	UserAgent string
	// App is the Hifaz-App header, "<platform>/<version>" (section 3).
	App string
}

// Client talks to one Hifaz server. Once its pin is set, it is safe for
// concurrent use; SetPin and Info, which change the pin, are not.
type Client struct {
	server    string
	pin       Pin
	http      *http.Client
	now       func() time.Time
	userAgent string
	app       string
}

// NewHTTPClient returns the HTTP client the protocol needs: TLS 1.2 or
// newer with the system's trust store, and no redirects (the API never
// redirects, and following one could leave the pinned server). proxy picks
// a proxy per request; nil means none. cert, if set, is the device
// certificate, presented when the server's proxy asks for one.
func NewHTTPClient(proxy func(*http.Request) (*url.URL, error), cert *tls.Certificate) *http.Client {
	dialer := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if cert != nil {
		tc.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return cert, nil }
	}
	return &http.Client{
		Transport: &http.Transport{
			Proxy:                 proxy,
			DialContext:           dialer.DialContext,
			TLSClientConfig:       tc,
			TLSHandshakeTimeout:   15 * time.Second,
			ExpectContinueTimeout: time.Second,
			IdleConnTimeout:       90 * time.Second,
			MaxIdleConnsPerHost:   2,
			ForceAttemptHTTP2:     true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// NewClient returns a client for the server at publicURL. pin may be empty
// until the server identity has been confirmed (see FetchIdentity).
func NewClient(publicURL string, pin Pin, opts Options) (*Client, error) {
	server, err := NormalizeServerURL(publicURL)
	if err != nil {
		return nil, err
	}
	c := &Client{server: server, pin: pin, http: opts.HTTPClient, now: opts.Now, userAgent: opts.UserAgent, app: opts.App}
	if c.http == nil {
		c.http = NewHTTPClient(nil, nil)
	}
	if c.now == nil {
		c.now = time.Now
	}
	return c, nil
}

// Server returns the normalized public URL.
func (c *Client) Server() string { return c.server }

// Pin returns the pinned server identity.
func (c *Client) Pin() Pin { return c.pin }

// --- server identity -----------------------------------------------------------

// FetchIdentity reads the info document without a pin and checks that it is
// signed by the identity key it announces. It returns the document and the
// pin it implies; the caller compares that pin with the fingerprint from the
// link, or shows it to the user, before trusting it.
func (c *Client) FetchIdentity(ctx context.Context) (*Info, Pin, error) {
	var doc SignedDocument
	if err := c.call(ctx, http.MethodGet, APIPrefix+"/info", nil, nil, &doc); err != nil {
		var e *APIError
		if errors.As(err, &e) && e.Status == http.StatusNotFound {
			// No client API: a Hifaz older than MinServerVersion.
			return nil, Pin{}, &APIError{Status: e.Status, Code: ErrCodeServerTooOld}
		}
		return nil, Pin{}, err
	}
	payload, err := b64url.DecodeString(doc.Payload)
	if err != nil {
		return nil, Pin{}, ErrBadSignature
	}
	var announced struct {
		IdentityKey string `json:"identity_key"`
	}
	if err := json.Unmarshal(payload, &announced); err != nil {
		return nil, Pin{}, ErrBadSignature
	}
	key, err := ParseEd25519PublicKey(announced.IdentityKey)
	if err != nil {
		return nil, Pin{}, ErrBadSignature
	}
	pin := Pin{Fingerprint: FingerprintOf(key), Key: key}
	var info Info
	if err := doc.Verify(pin, Expect{Type: TypeInfo, Server: c.server}, &info); err != nil {
		return nil, Pin{}, err
	}
	return &info, pin, nil
}

// Info reads the info document and checks it against the pinned
// fingerprint; it also records the key in the pin.
func (c *Client) Info(ctx context.Context) (*Info, error) {
	if c.pin.Fingerprint == "" {
		return nil, errors.New("no server fingerprint pinned")
	}
	info, pin, err := c.FetchIdentity(ctx)
	if err != nil {
		return nil, err
	}
	if pin.Fingerprint != c.pin.Fingerprint {
		return nil, ErrIdentityMismatch
	}
	c.pin = pin
	return info, nil
}

// SetPin replaces the pinned identity, after the user confirmed it.
func (c *Client) SetPin(pin Pin) { c.pin = pin }

// MinServerVersion is the first Hifaz release with this protocol.
const MinServerVersion = "0.8.0"

// CheckCompatible reports whether an app of this version can use the
// server: Hifaz MinServerVersion or later, a protocol range that includes
// Version, and the app at or above the server's min_app_version.
func CheckCompatible(info *Info, platform, appVersion string, compare func(a, b string) (int, error)) error {
	// The release part only: a test or pre-release build of 0.8.0 is 0.8.0.
	server, _, _ := strings.Cut(info.ServerVersion, "-")
	if cmp, err := compare(server, MinServerVersion); err != nil || cmp < 0 {
		return &APIError{Code: ErrCodeServerTooOld}
	}
	if info.Protocol.Min > Version || info.Protocol.Max < Version {
		return &APIError{Code: ErrCodeUnsupportedProtocol}
	}
	if minVersion := info.MinAppVersion[platform]; minVersion != "" {
		if cmp, err := compare(appVersion, minVersion); err != nil || cmp < 0 {
			return &APIError{Code: ErrCodeAppTooOld, MinVersion: minVersion}
		}
	}
	return nil
}

// --- enrollment (unsigned) ---------------------------------------------------------

// EnrollInfo describes an enrollment link.
func (c *Client) EnrollInfo(ctx context.Context, token string) (*EnrollLinkInfo, error) {
	var out EnrollLinkInfo
	err := c.call(ctx, http.MethodPost, APIPrefix+"/enroll/info", map[string]string{"link": token}, nil, &out)
	return &out, err
}

// EnrollStart checks the password (and code, if the user already has MFA).
func (c *Client) EnrollStart(ctx context.Context, token, password, otp string) (*EnrollStartResult, error) {
	var out EnrollStartResult
	body := map[string]string{"link": token, "password": password, "otp": otp}
	err := c.call(ctx, http.MethodPost, APIPrefix+"/enroll/start", body, nil, &out)
	return &out, err
}

// EnrollMFA confirms the authenticator app with one code.
func (c *Client) EnrollMFA(ctx context.Context, stepToken, code string) error {
	var out struct {
		Done bool `json:"done"`
	}
	body := map[string]string{"step_token": stepToken, "code": code}
	return c.call(ctx, http.MethodPost, APIPrefix+"/enroll/mfa", body, nil, &out)
}

// EnrollFinish registers the device's keys. The answer is verified against
// the pin and the request's nonce; the raw document is returned as well so
// it can be shown to the local service.
func (c *Client) EnrollFinish(ctx context.Context, req EnrollFinishRequest) (*Enrolled, SignedDocument, error) {
	var doc SignedDocument
	if !ValidNonce(req.Nonce) {
		return nil, doc, errors.New("invalid request nonce")
	}
	if err := c.call(ctx, http.MethodPost, APIPrefix+"/enroll/finish", req, nil, &doc); err != nil {
		return nil, doc, err
	}
	var out Enrolled
	if err := doc.Verify(c.pin, c.expect(TypeEnrolled, req.Nonce), &out); err != nil {
		return nil, doc, err
	}
	return &out, doc, nil
}

// --- signed calls ---------------------------------------------------------------

// Auth is what a signed call needs: the device signer, a fresh nonce, and
// for session calls the session token.
type Auth struct {
	Signer       Signer
	Nonce        string
	SessionToken string
}

// LoginRequest is the body of a sign-in. WGPublicKey is the WireGuard key
// the app will use: after a renewal it tells the server the new keys are in
// use (section 8).
type LoginRequest struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	OTP         string `json:"otp,omitempty"`
	WGPublicKey string `json:"wg_public_key,omitempty"`
}

// LoginResult is either a session or a request for the MFA code.
type LoginResult struct {
	OTPRequired bool
	StepToken   string
	Session     *Session
	Document    SignedDocument
}

// Login signs in from this device.
func (c *Client) Login(ctx context.Context, auth Auth, req LoginRequest) (*LoginResult, error) {
	return c.login(ctx, auth, APIPrefix+"/login", req)
}

// LoginOTP sends the MFA code after an otp_required answer.
func (c *Client) LoginOTP(ctx context.Context, auth Auth, stepToken, otp string) (*LoginResult, error) {
	return c.login(ctx, auth, APIPrefix+"/login/otp", map[string]string{"step_token": stepToken, "otp": otp})
}

func (c *Client) login(ctx context.Context, auth Auth, path string, body any) (*LoginResult, error) {
	var answer struct {
		SignedDocument
		Status    string `json:"status"`
		StepToken string `json:"step_token"`
	}
	if err := c.call(ctx, http.MethodPost, path, body, &auth, &answer); err != nil {
		return nil, err
	}
	if answer.Payload == "" {
		if answer.Status != StatusOTPRequired || answer.StepToken == "" {
			return nil, errors.New("unexpected sign-in answer")
		}
		return &LoginResult{OTPRequired: true, StepToken: answer.StepToken}, nil
	}
	s, err := c.verifySession(answer.SignedDocument, auth.Nonce)
	if err != nil {
		return nil, err
	}
	if s.Status != StatusConnected {
		return nil, fmt.Errorf("sign-in answered with session status %q", s.Status)
	}
	return &LoginResult{Session: s, Document: answer.SignedDocument}, nil
}

// Session reads the session status. With wait > 0 the server holds the
// answer up to wait until something changes; known is the configuration
// version in use (0 if none), so the server answers at once when it has a
// different one.
func (c *Client) Session(ctx context.Context, auth Auth, wait time.Duration, known int64) (*Session, SignedDocument, error) {
	var doc SignedDocument
	q := url.Values{}
	if wait > 0 {
		q.Set("wait", strconv.Itoa(int(min(wait, MaxWait)/time.Second)))
	}
	if known > 0 {
		q.Set("version", strconv.FormatInt(known, 10))
	}
	path := APIPrefix + "/session"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	if err := c.call(ctx, http.MethodGet, path, nil, &auth, &doc); err != nil {
		return nil, doc, err
	}
	s, err := c.verifySession(doc, auth.Nonce)
	return s, doc, err
}

// Logout ends the session; the server removes the tunnel peer at once.
func (c *Client) Logout(ctx context.Context, auth Auth) error {
	var out struct {
		Status string `json:"status"`
	}
	return c.call(ctx, http.MethodPost, APIPrefix+"/logout", nil, &auth, &out)
}

// Renew replaces the device's keys.
func (c *Client) Renew(ctx context.Context, auth Auth, req RenewRequest) (*Renewed, SignedDocument, error) {
	var doc SignedDocument
	if err := c.call(ctx, http.MethodPost, APIPrefix+"/keys/renew", req, &auth, &doc); err != nil {
		return nil, doc, err
	}
	var out Renewed
	if err := doc.Verify(c.pin, c.expect(TypeRenewed, auth.Nonce), &out); err != nil {
		return nil, doc, err
	}
	return &out, doc, nil
}

func (c *Client) verifySession(doc SignedDocument, nonce string) (*Session, error) {
	var s Session
	if err := doc.Verify(c.pin, c.expect(TypeSession, nonce), &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func (c *Client) expect(typ, nonce string) Expect {
	return Expect{Type: typ, Server: c.server, Nonce: nonce, Now: c.now(), MaxSkew: DefaultMaxSkew}
}

// --- transport --------------------------------------------------------------------

// call sends one request. path is the API path from APIPrefix on (it is
// also what a signed request signs); body, if not nil, is sent as JSON;
// auth, if not nil, signs the request. A 2xx answer is decoded into out,
// any other into an *APIError.
func (c *Client) call(ctx context.Context, method, path string, body any, auth *Auth, out any) error {
	var raw []byte
	if body != nil {
		var err error
		if raw, err = json.Marshal(body); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.server+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}
	if c.app != "" {
		req.Header.Set(HeaderApp, c.app)
	}
	if auth != nil {
		if auth.Signer == nil {
			return errors.New("signed call without a signer")
		}
		if err := signRequest(req, path, raw, auth.Signer, c.now(), auth.Nonce); err != nil {
			return err
		}
		if auth.SessionToken != "" {
			req.Header.Set("Authorization", "Bearer "+auth.SessionToken)
		}
	}
	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, maxResponse+1))
	if err != nil {
		return err
	}
	if len(data) > maxResponse {
		return errors.New("server answer too large")
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		e := &APIError{Status: res.StatusCode}
		if json.Unmarshal(data, e) != nil || e.Code == "" {
			e.Code, e.Message = "http_"+strconv.Itoa(res.StatusCode), ""
		}
		if e.RetryAfter == 0 {
			e.RetryAfter, _ = strconv.Atoi(res.Header.Get("Retry-After"))
		}
		return e
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("unexpected server answer: %w", err)
	}
	return nil
}

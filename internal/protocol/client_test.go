package protocol_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/fakeserver"
	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/protocol"
	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/version"
)

// device is what an enrolled app holds.
type device struct {
	signer *protocol.KeySigner
	wgPriv protocol.Key
	psk    protocol.Key
}

func nonce(t *testing.T) string {
	t.Helper()
	n, err := protocol.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func newClient(t *testing.T, srv *fakeserver.Server, pin protocol.Pin, now func() time.Time) *protocol.Client {
	t.Helper()
	c, err := protocol.NewClient(srv.URL(), pin, protocol.Options{HTTPClient: srv.HTTPClient(), Now: now, UserAgent: "test"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// enroll runs the whole enrollment flow from a pasted link.
func enroll(t *testing.T, srv *fakeserver.Server, username string) (*protocol.Client, *device) {
	t.Helper()
	ctx := context.Background()
	raw, _ := srv.NewLink(protocol.LinkDevice, username, "")
	link, err := protocol.ParseEnrollLink(raw)
	if err != nil {
		t.Fatal(err)
	}
	if link.Server != srv.URL() {
		t.Fatalf("link server %q, want %q", link.Server, srv.URL())
	}
	c := newClient(t, srv, protocol.Pin{Fingerprint: link.Fingerprint}, nil)
	info, err := c.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.CheckCompatible(info, "windows", "0.1.0", version.Compare); err != nil {
		t.Fatal(err)
	}
	li, err := c.EnrollInfo(ctx, link.Token)
	if err != nil || li.Kind != protocol.LinkDevice || !li.NameEditable {
		t.Fatalf("enroll info %+v, %v", li, err)
	}
	st, err := c.EnrollStart(ctx, link.Token, "pw", "")
	if err != nil || !st.NeedsMFASetup || st.MFAURI == "" {
		t.Fatalf("enroll start %+v, %v", st, err)
	}
	if err := c.EnrollMFA(ctx, st.StepToken, "000000"); protocol.ErrorCode(err) != protocol.ErrCodeInvalidCode {
		t.Fatalf("wrong code: %v", err)
	}
	if err := c.EnrollMFA(ctx, st.StepToken, fakeserver.OTP); err != nil {
		t.Fatal(err)
	}
	wgPriv, wgPub, _ := protocol.GenerateWireGuardKey()
	devPub, devPriv, _ := ed25519.GenerateKey(rand.Reader)
	enrolled, doc, err := c.EnrollFinish(ctx, protocol.EnrollFinishRequest{
		StepToken: st.StepToken, Nonce: nonce(t), Platform: "windows", DeviceName: "Work laptop",
		WGPublicKey: wgPub.String(), DeviceKey: protocol.EncodeEd25519PublicKey(devPub),
		App: protocol.AppIdentity{Name: "Hifaz for Windows", Version: "0.1.0"}, OS: "Windows 11",
	})
	if err != nil {
		t.Fatal(err)
	}
	if doc.Payload == "" || enrolled.Device != "Work laptop" {
		t.Fatalf("enrolled %+v", enrolled)
	}
	if _, err := enrolled.Config.Parse(); err != nil {
		t.Fatal(err)
	}
	psk, err := protocol.OpenSealedPSK(enrolled.PSKSealed, wgPriv, enrolled.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	if psk != srv.Device(enrolled.DeviceID).PSK {
		t.Fatal("opened PSK differs from the server's")
	}
	signer, _ := protocol.NewKeySigner(enrolled.DeviceID, devPriv)
	return c, &device{signer: signer, wgPriv: wgPriv, psk: psk}
}

func TestFullFlow(t *testing.T) {
	for _, prefix := range []string{"", "/vpn"} {
		t.Run("prefix="+prefix, func(t *testing.T) {
			srv := fakeserver.New(t, fakeserver.Options{Prefix: prefix})
			srv.AddUser("alice", "pw", false)
			c, dev := enroll(t, srv, "alice")
			ctx := context.Background()

			if _, err := c.Login(ctx, protocol.Auth{Signer: dev.signer, Nonce: nonce(t)},
				protocol.LoginRequest{Username: "alice", Password: "wrong"}); protocol.ErrorCode(err) != protocol.ErrCodeInvalidCredentials {
				t.Fatalf("wrong password: %v", err)
			}
			res, err := c.Login(ctx, protocol.Auth{Signer: dev.signer, Nonce: nonce(t)},
				protocol.LoginRequest{Username: "alice", Password: "pw"})
			if err != nil || !res.OTPRequired {
				t.Fatalf("login: %+v %v", res, err)
			}
			res, err = c.LoginOTP(ctx, protocol.Auth{Signer: dev.signer, Nonce: nonce(t)}, res.StepToken, fakeserver.OTP)
			if err != nil || res.Session == nil || res.Session.Status != protocol.StatusConnected {
				t.Fatalf("otp: %+v %v", res, err)
			}
			token := res.Session.SessionToken
			v1 := res.Session.Config.Version

			// A long-poll returns as soon as the configuration changes.
			go func() {
				time.Sleep(100 * time.Millisecond)
				srv.SetAllowedIPs("10.98.0.0/16", "10.20.0.0/16")
			}()
			start := time.Now()
			s, _, err := c.Session(ctx, protocol.Auth{Signer: dev.signer, Nonce: nonce(t), SessionToken: token}, 30*time.Second)
			if err != nil || s.Config == nil || s.Config.Version != v1+1 || len(s.Config.AllowedIPs) != 2 {
				t.Fatalf("session: %+v %v", s, err)
			}
			if time.Since(start) > 10*time.Second {
				t.Fatal("long-poll did not return on change")
			}

			if err := c.Logout(ctx, protocol.Auth{Signer: dev.signer, Nonce: nonce(t), SessionToken: token}); err != nil {
				t.Fatal(err)
			}
			s, _, err = c.Session(ctx, protocol.Auth{Signer: dev.signer, Nonce: nonce(t), SessionToken: token}, 0)
			if err != nil || s.Status != protocol.StatusEnded || s.Reason != protocol.ReasonSignedOut || s.Config != nil {
				t.Fatalf("after logout: %+v %v", s, err)
			}
		})
	}
}

func TestSignedRequestChecks(t *testing.T) {
	srv := fakeserver.New(t, fakeserver.Options{})
	srv.AddUser("alice", "pw", false)
	c, dev := enroll(t, srv, "alice")
	ctx := context.Background()
	login := protocol.LoginRequest{Username: "alice", Password: "pw", OTP: fakeserver.OTP}

	n := nonce(t)
	if _, err := c.Login(ctx, protocol.Auth{Signer: dev.signer, Nonce: n}, login); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Login(ctx, protocol.Auth{Signer: dev.signer, Nonce: n}, login); protocol.ErrorCode(err) != protocol.ErrCodeInvalidSignature {
		t.Fatalf("reused nonce: %v", err)
	}

	skewed := newClient(t, srv, c.Pin(), func() time.Time { return time.Now().Add(10 * time.Minute) })
	_, err := skewed.Login(ctx, protocol.Auth{Signer: dev.signer, Nonce: nonce(t)}, login)
	var apiErr *protocol.APIError
	if !errors.As(err, &apiErr) || apiErr.Code != protocol.ErrCodeClockSkew || apiErr.ServerTime.IsZero() {
		t.Fatalf("clock skew: %v", err)
	}

	_, other, _ := ed25519.GenerateKey(rand.Reader)
	forged, _ := protocol.NewKeySigner(dev.signer.DeviceID(), other)
	if _, err := c.Login(ctx, protocol.Auth{Signer: forged, Nonce: nonce(t)}, login); protocol.ErrorCode(err) != protocol.ErrCodeInvalidSignature {
		t.Fatalf("wrong key: %v", err)
	}
	if _, err := c.Login(ctx, protocol.Auth{Signer: dev.signer, Nonce: "bad"}, login); err == nil {
		t.Fatal("bad nonce sent")
	}

	srv.DisableDevice(dev.signer.DeviceID())
	if _, err := c.Login(ctx, protocol.Auth{Signer: dev.signer, Nonce: nonce(t)}, login); protocol.ErrorCode(err) != protocol.ErrCodeInvalidSignature {
		t.Fatalf("disabled device: %v", err)
	}
}

func TestRenewReplacesKeys(t *testing.T) {
	srv := fakeserver.New(t, fakeserver.Options{})
	srv.AddUser("alice", "pw", false)
	c, dev := enroll(t, srv, "alice")
	ctx := context.Background()

	wgPriv, wgPub, _ := protocol.GenerateWireGuardKey()
	newPub, newPriv, _ := ed25519.GenerateKey(rand.Reader)
	renewed, _, err := c.Renew(ctx, protocol.Auth{Signer: dev.signer, Nonce: nonce(t)}, protocol.RenewRequest{
		WGPublicKey: wgPub.String(), DeviceKey: protocol.EncodeEd25519PublicKey(newPub)})
	if err != nil {
		t.Fatal(err)
	}
	psk, err := protocol.OpenSealedPSK(renewed.PSKSealed, wgPriv, dev.signer.DeviceID())
	if err != nil || psk != srv.Device(dev.signer.DeviceID()).PSK {
		t.Fatalf("renewed psk: %v", err)
	}
	login := protocol.LoginRequest{Username: "alice", Password: "pw", OTP: fakeserver.OTP}
	if _, err := c.Login(ctx, protocol.Auth{Signer: dev.signer, Nonce: nonce(t)}, login); protocol.ErrorCode(err) != protocol.ErrCodeInvalidSignature {
		t.Fatalf("old device key still accepted: %v", err)
	}
	signer, _ := protocol.NewKeySigner(dev.signer.DeviceID(), newPriv)
	if _, err := c.Login(ctx, protocol.Auth{Signer: signer, Nonce: nonce(t)}, login); err != nil {
		t.Fatalf("new device key: %v", err)
	}
}

func TestIdentityPinning(t *testing.T) {
	srv := fakeserver.New(t, fakeserver.Options{})
	other := fakeserver.New(t, fakeserver.Options{})
	c := newClient(t, srv, other.Pin(), nil)
	if _, err := c.Info(context.Background()); !errors.Is(err, protocol.ErrIdentityMismatch) {
		t.Fatalf("other server's pin: %v", err)
	}
	// Without a pin, FetchIdentity reports the fingerprint for the user to check.
	_, pin, err := newClient(t, srv, protocol.Pin{}, nil).FetchIdentity(context.Background())
	if err != nil || pin.Fingerprint != srv.Pin().Fingerprint {
		t.Fatalf("fetch identity: %v", err)
	}
}

func TestAppTooOld(t *testing.T) {
	srv := fakeserver.New(t, fakeserver.Options{})
	srv.SetMinAppVersion("0.2.0")
	info, err := newClient(t, srv, srv.Pin(), nil).Info(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	err = protocol.CheckCompatible(info, "windows", "0.1.9", version.Compare)
	var apiErr *protocol.APIError
	if !errors.As(err, &apiErr) || apiErr.Code != protocol.ErrCodeAppTooOld || apiErr.MinVersion != "0.2.0" {
		t.Fatalf("too old: %v", err)
	}
	if err := protocol.CheckCompatible(info, "windows", "0.2.0", version.Compare); err != nil {
		t.Fatal(err)
	}
}

func TestNoRedirectsAndLimits(t *testing.T) {
	big := strings.Repeat("x", 2<<20)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == protocol.APIPrefix+"/info" {
			http.Redirect(w, r, "https://elsewhere.example.com/", http.StatusFound)
			return
		}
		w.Write([]byte(`{"x":"` + big + `"}`))
	}))
	defer ts.Close()
	hc := protocol.NewHTTPClient(nil)
	hc.Transport.(*http.Transport).TLSClientConfig.RootCAs = ts.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	c, _ := protocol.NewClient(ts.URL, protocol.Pin{}, protocol.Options{HTTPClient: hc})
	if _, _, err := c.FetchIdentity(context.Background()); protocol.ErrorCode(err) != "http_302" {
		t.Fatalf("redirect: %v", err)
	}
	if _, err := c.EnrollInfo(context.Background(), "tok"); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("large answer: %v", err)
	}
}

package app

import (
	"context"
	"errors"
	"net"
	"net/url"
	"time"

	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/ipc"
	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/protocol"
)

// Screen names what the window shows.
type Screen string

// Screens.
const (
	ScreenLoading           Screen = "loading"
	ScreenSetup             Screen = "setup"              // paste an enrollment link
	ScreenEnrollFingerprint Screen = "enroll_fingerprint" // compare the server fingerprint
	ScreenEnrollPassword    Screen = "enroll_password"
	ScreenEnrollMFA         Screen = "enroll_mfa"
	ScreenSignIn            Screen = "signin"
	ScreenSignInOTP         Screen = "signin_otp"
	ScreenConnected         Screen = "connected"
	ScreenUpdateRequired    Screen = "update_required"
)

// View is everything the window needs to draw itself. The app sends a new
// View after every change; the window keeps no state of its own.
type View struct {
	Screen        Screen       `json:"screen"`
	ServiceStatus string       `json:"service_status,omitempty"`
	Busy          bool         `json:"busy"`
	Error         *ViewError   `json:"error,omitempty"`
	Notice        string       `json:"notice,omitempty"` // why a session ended, for example "idle"
	Account       *AccountView `json:"account,omitempty"`
	Enroll        *EnrollView  `json:"enroll,omitempty"`
	Session       *SessionView `json:"session,omitempty"`
	Update        *UpdateView  `json:"update,omitempty"`
	// Replacing: the user is adding a server while one is enrolled; the
	// old one is removed when the new enrollment succeeds.
	Replacing bool `json:"replacing,omitempty"`
	// Link prefills the setup screen after an enrollment step timed out or
	// was interrupted, so the user only presses Continue. It is never logged.
	Link string `json:"link,omitempty"`
}

// ViewError is a failure, by code; the window translates it.
type ViewError struct {
	Code       string    `json:"code"`
	ServerTime time.Time `json:"server_time,omitzero"`
	RetryAfter int       `json:"retry_after,omitempty"`
}

// AccountView describes the enrolled server.
type AccountView struct {
	Server       string    `json:"server"`
	Fingerprint  string    `json:"fingerprint"` // the part shown to people
	Username     string    `json:"username"`
	Device       string    `json:"device"`
	KeysExpireAt time.Time `json:"keys_expire_at,omitzero"`
}

// EnrollView describes the enrollment in progress.
type EnrollView struct {
	Server       string `json:"server"`
	Fingerprint  string `json:"fingerprint"` // full, for comparison
	Kind         string `json:"kind"`
	Username     string `json:"username"`
	Device       string `json:"device,omitempty"`
	NameEditable bool   `json:"name_editable"`
	MFAURI       string `json:"mfa_uri,omitempty"`
	MFASecret    string `json:"mfa_secret,omitempty"`
	// CodeRequired: two-step verification was set up in an earlier,
	// interrupted attempt with this link, so the code is no longer optional.
	CodeRequired bool `json:"code_required,omitempty"`
}

// SessionView describes the connected session.
type SessionView struct {
	ConnectedAt   time.Time `json:"connected_at,omitzero"`
	ExpiresAt     time.Time `json:"expires_at,omitzero"`
	IdleTimeout   int       `json:"idle_timeout_seconds,omitempty"`
	Address       string    `json:"address,omitempty"`
	AllowedIPs    []string  `json:"allowed_ips,omitempty"`
	LastHandshake time.Time `json:"last_handshake,omitzero"`
	DNSActive     *bool     `json:"dns_active,omitempty"`
	DNSServers    []string  `json:"dns_servers,omitempty"`
	RxBytes       uint64    `json:"rx_bytes"`
	TxBytes       uint64    `json:"tx_bytes"`
	// Link: "waiting" for the server's first answer, "up", or "no_answer";
	// empty from a service that does not tell (treated as up). Blocker
	// says what keeps the server from answering, when known.
	Link    string       `json:"link,omitempty"`
	Blocker *BlockerView `json:"blocker,omitempty"`
}

// BlockerView names what blocks the server: App "wireguard" (the WireGuard
// app's kill switch) and, if known, the names of its tunnels.
type BlockerView struct {
	App     string   `json:"app"`
	Tunnels []string `json:"tunnels,omitempty"`
}

// UpdateView says which version the server needs and where to get it.
type UpdateView struct {
	MinVersion  string `json:"min_version"`
	DownloadURL string `json:"download_url,omitempty"`
}

// Local error codes, besides the server's and the service's.
const (
	ErrNetwork            = "network"
	ErrInvalidLink        = "invalid_link"
	ErrIdentityMismatch   = "identity_mismatch"
	ErrBadSignature       = "bad_signature"
	ErrServiceUnavailable = "service_unavailable" // the service is not running
	ErrServiceRefused     = "service_refused"     // the service denied the app, or speaks another version
	ErrServiceUntrusted   = "service_untrusted"   // the pipe is not the service's; nothing was sent
	ErrUnsupportedLink    = "unsupported_link"    // an MFA or certificate link: use the browser
	ErrNoAccount          = "no_account"
	ErrKeystore           = "keystore"
	ErrInternal           = "internal"
	ErrEnrollInterrupted  = "enroll_interrupted"  // two-step setup was saved, then the enrollment failed
	ErrCodeRequired       = "code_required"       // the verification code was left empty
	ErrSignInStepExpired  = "signin_step_expired" // the sign-in code step ended: sign in again
)

// errServiceUnavailable wraps failures to reach the local service.
var errServiceUnavailable = errors.New("the Hifaz service is not available")

// errCodeRequired: the user left the verification code empty where it is
// required; nothing was sent to the server.
var errCodeRequired = errors.New("the verification code is required")

// viewError turns an error into what the window shows.
func viewError(err error) *ViewError {
	if err == nil {
		return nil
	}
	var api *protocol.APIError
	if errors.As(err, &api) {
		return &ViewError{Code: api.Code, ServerTime: api.ServerTime, RetryAfter: api.RetryAfter}
	}
	var svc *ipc.Error
	if errors.As(err, &svc) {
		if svc.Code == ipc.ErrBadRequest {
			// The service did not understand the app: another version.
			return &ViewError{Code: ErrServiceRefused}
		}
		return &ViewError{Code: svc.Code}
	}
	var netErr net.Error
	var urlErr *url.Error
	switch {
	// The causes first: each also matches ipc.ErrUnavailable.
	case errors.Is(err, ipc.ErrServiceUntrusted):
		return &ViewError{Code: ErrServiceUntrusted}
	case errors.Is(err, ipc.ErrServiceRefused):
		return &ViewError{Code: ErrServiceRefused}
	case errors.Is(err, errServiceUnavailable), errors.Is(err, ipc.ErrUnavailable):
		return &ViewError{Code: ErrServiceUnavailable}
	case errors.Is(err, protocol.ErrIdentityMismatch):
		return &ViewError{Code: ErrIdentityMismatch}
	case errors.Is(err, protocol.ErrBadSignature):
		return &ViewError{Code: ErrBadSignature}
	case errors.Is(err, errInvalidLink):
		return &ViewError{Code: ErrInvalidLink}
	case errors.Is(err, errNoAccount):
		return &ViewError{Code: ErrNoAccount}
	case errors.Is(err, errCodeRequired):
		return &ViewError{Code: ErrCodeRequired}
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr), errors.As(err, &urlErr):
		return &ViewError{Code: ErrNetwork}
	}
	return &ViewError{Code: ErrInternal}
}

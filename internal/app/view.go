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
	Screen  Screen       `json:"screen"`
	Busy    bool         `json:"busy"`
	Error   *ViewError   `json:"error,omitempty"`
	Notice  string       `json:"notice,omitempty"` // why a session ended, for example "idle"
	Account *AccountView `json:"account,omitempty"`
	Enroll  *EnrollView  `json:"enroll,omitempty"`
	Session *SessionView `json:"session,omitempty"`
	Update  *UpdateView  `json:"update,omitempty"`
	// Replacing: the user is adding a server while one is enrolled; the
	// old one is removed when the new enrollment succeeds.
	Replacing bool `json:"replacing,omitempty"`
	// Link prefills the setup screen after an enrollment step timed out on
	// the server, so the user only presses Continue. It is never logged.
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
}

// SessionView describes the connected session.
type SessionView struct {
	ConnectedAt   time.Time `json:"connected_at,omitzero"`
	ExpiresAt     time.Time `json:"expires_at,omitzero"`
	IdleTimeout   int       `json:"idle_timeout_seconds,omitempty"`
	Address       string    `json:"address,omitempty"`
	AllowedIPs    []string  `json:"allowed_ips,omitempty"`
	LastHandshake time.Time `json:"last_handshake,omitzero"`
	RxBytes       uint64    `json:"rx_bytes"`
	TxBytes       uint64    `json:"tx_bytes"`
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
	ErrServiceUnavailable = "service_unavailable"
	ErrUnsupportedLink    = "unsupported_link" // an MFA or certificate link: use the browser
	ErrNoAccount          = "no_account"
	ErrKeystore           = "keystore"
	ErrInternal           = "internal"
)

// errServiceUnavailable wraps failures to reach the local service.
var errServiceUnavailable = errors.New("the Hifaz service is not available")

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
		return &ViewError{Code: svc.Code}
	}
	var netErr net.Error
	var urlErr *url.Error
	switch {
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
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr), errors.As(err, &urlErr):
		return &ViewError{Code: ErrNetwork}
	}
	return &ViewError{Code: ErrInternal}
}

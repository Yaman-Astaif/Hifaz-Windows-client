package protocol

import (
	"errors"
	"fmt"
	"time"
)

// Error codes the server returns (section 12). Apps translate by code.
const (
	ErrCodeInvalidCredentials  = "invalid_credentials"
	ErrCodeInvalidSignature    = "invalid_signature"
	ErrCodeClockSkew           = "clock_skew"
	ErrCodeInvalidSession      = "invalid_session"
	ErrCodeInvalidLink         = "invalid_link"
	ErrCodeInvalidStep         = "invalid_step"
	ErrCodeInvalidCode         = "invalid_code"
	ErrCodeInvalidDeviceChoice = "invalid_device_choice"
	ErrCodeDeviceNameTaken     = "device_name_taken"
	ErrCodeUseBrowser          = "use_browser"
	ErrCodeKeysExpired         = "keys_expired"
	ErrCodeMethodNotAllowed    = "method_not_allowed"
	ErrCodeAppTooOld           = "app_too_old"
	ErrCodeUnsupportedProtocol = "unsupported_protocol"
	ErrCodeRateLimited         = "rate_limited"
	ErrCodeInvalidCSR          = "invalid_csr"
	ErrCodeRenewNotDue         = "renew_not_due"
	ErrCodeUnknownDevice       = "unknown_device"
	ErrCodeCertRequired        = "cert_required"
	ErrCodeCertInvalid         = "cert_invalid"
	ErrCodeCertUnchecked       = "cert_unchecked"
	ErrCodeBadRequest          = "bad_request"
	ErrCodeNotFound            = "not_found"
	ErrCodeTimeout             = "timeout"

	// ErrCodeServerTooOld is the app's own: the server is older than
	// MinServerVersion (or has no client API at all).
	ErrCodeServerTooOld = "server_too_old"
)

// APIError is an error answer from the server.
type APIError struct {
	Status     int       `json:"-"`
	Code       string    `json:"error"`
	Message    string    `json:"message"`
	ServerTime time.Time `json:"server_time,omitzero"`
	RetryAfter int       `json:"retry_after,omitempty"`
	MinVersion string    `json:"min_version,omitempty"`
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("server: %s (%s)", e.Code, e.Message)
	}
	return "server: " + e.Code
}

// ErrorCode returns the server's error code in err, or "".
func ErrorCode(err error) string {
	var e *APIError
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

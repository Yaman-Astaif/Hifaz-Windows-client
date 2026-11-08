package protocol

import "time"

// Info is the signed server information document (section 5).
type Info struct {
	Header
	Name          map[string]string `json:"name"`
	Protocol      ProtocolRange     `json:"protocol"`
	ServerVersion string            `json:"server_version"`
	IdentityKey   string            `json:"identity_key"`
	MinAppVersion map[string]string `json:"min_app_version"`
	Features      []string          `json:"features"`
	AppDownload   map[string]string `json:"app_download"`
}

// ProtocolRange is the range of protocol versions a server speaks.
type ProtocolRange struct {
	Min int `json:"min"`
	Max int `json:"max"`
}

// HasFeature reports whether the server lists a feature.
func (i *Info) HasFeature(name string) bool {
	for _, f := range i.Features {
		if f == name {
			return true
		}
	}
	return false
}

// Enrollment link kinds.
const (
	LinkDevice = "device"
	LinkRenew  = "renew"
	LinkMFA    = "mfa"
	LinkCert   = "cert"
)

// EnrollLinkInfo answers enroll/info.
type EnrollLinkInfo struct {
	Kind         string    `json:"kind"`
	Username     string    `json:"username"`
	Device       string    `json:"device,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
	NameEditable bool      `json:"name_editable,omitempty"`
	Platform     string    `json:"platform,omitempty"`
}

// EnrollStartResult answers enroll/start.
type EnrollStartResult struct {
	StepToken     string `json:"step_token"`
	Kind          string `json:"kind"`
	Username      string `json:"username"`
	Device        string `json:"device,omitempty"`
	NeedsMFASetup bool   `json:"needs_mfa_setup"`
	CertRequired  bool   `json:"cert_required,omitempty"` // send a CSR at enroll/finish
	MFAURI        string `json:"mfa_uri,omitempty"`
	MFASecret     string `json:"mfa_secret,omitempty"`
}

// AppIdentity names the app in enroll/finish.
type AppIdentity struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// EnrollFinishRequest is the body of enroll/finish.
type EnrollFinishRequest struct {
	StepToken   string      `json:"step_token"`
	Nonce       string      `json:"nonce"`
	Platform    string      `json:"platform"`
	DeviceName  string      `json:"device_name,omitempty"`
	WGPublicKey string      `json:"wg_public_key"`
	DeviceKey   string      `json:"device_key"`
	CSR         string      `json:"csr,omitempty"`
	App         AppIdentity `json:"app"`
	OS          string      `json:"os"`
}

// Enrolled is the signed answer to enroll/finish.
type Enrolled struct {
	Header
	DeviceID     string    `json:"device_id"`
	Username     string    `json:"username"`
	Device       string    `json:"device"`
	KeysExpireAt time.Time `json:"keys_expire_at"`
	RenewAfter   time.Time `json:"renew_after"`
	PSKSealed    string    `json:"psk_sealed"`
	Certificate  string    `json:"certificate,omitempty"`
	Config       *Config   `json:"config"`
}

// Session statuses and end reasons (section 8).
const (
	StatusConnected   = "connected"
	StatusEnded       = "ended"
	StatusOTPRequired = "otp_required"

	ReasonSignedOut      = "signed_out"
	ReasonIdle           = "idle"
	ReasonTimeLimit      = "time_limit"
	ReasonEndedByAdmin   = "ended_by_admin"
	ReasonDeviceDisabled = "device_disabled"
	ReasonUserDisabled   = "user_disabled"
	ReasonKeysExpired    = "keys_expired"
	ReasonGroupChanged   = "group_changed"
)

// Session is the signed session document.
type Session struct {
	Header
	Status             string    `json:"status"`
	Reason             string    `json:"reason,omitempty"`
	SessionID          string    `json:"session_id"`
	SessionToken       string    `json:"session_token"`
	ExpiresAt          time.Time `json:"expires_at"`
	IdleTimeoutSeconds int       `json:"idle_timeout_seconds"`
	KeysExpireAt       time.Time `json:"keys_expire_at"`
	RenewAfter         time.Time `json:"renew_after"`
	Config             *Config   `json:"config,omitempty"`
}

// RenewRequest is the body of keys/renew.
type RenewRequest struct {
	WGPublicKey string `json:"wg_public_key"`
	CSR         string `json:"csr,omitempty"`
	DeviceKey   string `json:"device_key,omitempty"`
}

// Renewed is the signed answer to keys/renew.
type Renewed struct {
	Header
	KeysExpireAt time.Time `json:"keys_expire_at"`
	RenewAfter   time.Time `json:"renew_after"`
	PSKSealed    string    `json:"psk_sealed"`
	Certificate  string    `json:"certificate,omitempty"`
	Config       *Config   `json:"config"`
}

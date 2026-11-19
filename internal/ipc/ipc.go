// Package ipc defines the messages between the Hifaz app (running as the
// user) and the Hifaz service (running as the system), and their framing on
// the local pipe. The pipe itself is in pipe_windows.go.
//
// Each message is a 4-byte big-endian length followed by that many bytes of
// JSON. A connection carries one request at a time; the service answers each
// with one response.
package ipc

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/protocol"
)

// PipeName is the service's pipe.
const PipeName = `\\.\pipe\Hifaz`

// MaxMessage bounds one message in either direction.
const MaxMessage = 256 << 10

// Op names a request.
type Op string

// Requests. Connect makes the calling connection the tunnel's owner: the
// tunnel stays up only while that connection is open, and only it may send
// Update and Disconnect.
const (
	OpStatus     Op = "status"     // current state
	OpWatch      Op = "watch"      // wait until the state generation differs from Since
	OpNonce      Op = "nonce"      // a fresh nonce for one signed server request
	OpRegister   Op = "register"   // record the server identity from a signed enrollment answer
	OpForget     Op = "forget"     // remove the caller's record for Server
	OpConnect    Op = "connect"    // bring the tunnel up from a signed session document
	OpUpdate     Op = "update"     // apply a newer signed session document
	OpDisconnect Op = "disconnect" // take the tunnel down
)

// Request is a message from the app.
type Request struct {
	Op     Op     `json:"op"`
	Server string `json:"server,omitempty"` // normalized public URL
	// Register: the server identity key (standard base64) and the signed
	// enrollment answer. Connect, Update: the signed session document.
	IdentityKey string                   `json:"identity_key,omitempty"`
	Document    *protocol.SignedDocument `json:"document,omitempty"`
	// Connect: the device's WireGuard private key and preshared key. The
	// service wipes them once the tunnel holds them.
	PrivateKey []byte `json:"private_key,omitempty"`
	PSK        []byte `json:"psk,omitempty"`
	// Watch: the generation the app last saw.
	Since uint64 `json:"since,omitempty"`
}

// Wipe overwrites the key material in the request.
func (r *Request) Wipe() {
	clear(r.PrivateKey)
	clear(r.PSK)
}

// Response is the service's answer.
type Response struct {
	Error  *Error  `json:"error,omitempty"`
	Nonce  string  `json:"nonce,omitempty"`
	Status *Status `json:"status,omitempty"`
}

// Error codes in responses. The app translates them for the user.
const (
	ErrBadRequest       = "bad_request"
	ErrNotOwner         = "not_owner"          // the tunnel belongs to another connection
	ErrBusy             = "busy"               // another Windows user has the tunnel
	ErrNotRegistered    = "not_registered"     // no recorded identity for this server
	ErrVerify           = "verify_failed"      // the signed document did not check out
	ErrServerNotAllowed = "server_not_allowed" // machine policy
	ErrFullTunnel       = "full_tunnel"        // machine policy
	ErrBadConfig        = "bad_config"         // the server sent an unusable configuration
	ErrTunnel           = "tunnel_failed"      // the adapter, routes or DNS could not be set
	ErrInternal         = "internal"
)

// Error is a failed request.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message,omitempty"`
}

func (e *Error) Error() string {
	if e.Message == "" {
		return "service: " + e.Code
	}
	return fmt.Sprintf("service: %s (%s)", e.Code, e.Message)
}

// State of the tunnel.
type State string

// States.
const (
	StateIdle       State = "idle"
	StateConnecting State = "connecting"
	StateConnected  State = "connected"
)

// Link says whether the server answers through the tunnel, while State is
// connected. The tunnel is up in every case; DNS is applied only while the
// link is up.
type Link string

// Links.
const (
	LinkWaiting  Link = "waiting"   // no handshake yet since sign-in
	LinkUp       Link = "up"        // WireGuard has a recent handshake
	LinkNoAnswer Link = "no_answer" // no handshake when one was due
)

// Blocker says what keeps the server from answering, when it can be told.
type Blocker struct {
	App     string   `json:"app"`               // BlockerWireGuard
	Tunnels []string `json:"tunnels,omitempty"` // its tunnels' names, if known
}

// Blocker apps.
const (
	// The WireGuard app's "Block untunneled traffic" (kill switch).
	BlockerWireGuard = "wireguard"
)

// Owner says whose the tunnel is, from the caller's point of view.
type Owner string

// Owners.
const (
	OwnerNone  Owner = "none"
	OwnerYou   Owner = "you"   // the calling Windows user
	OwnerOther Owner = "other" // another Windows user; no details are shown
)

// Status describes the tunnel. Details are filled only for its owner.
type Status struct {
	Generation    uint64    `json:"generation"`
	State         State     `json:"state"`
	Owner         Owner     `json:"owner"`
	Server        string    `json:"server,omitempty"`
	ConfigVersion int64     `json:"config_version,omitempty"`
	Address       string    `json:"address,omitempty"`
	AllowedIPs    []string  `json:"allowed_ips,omitempty"`
	ConnectedAt   time.Time `json:"connected_at,omitzero"`
	LastHandshake time.Time `json:"last_handshake,omitzero"`
	RxBytes       uint64    `json:"rx_bytes,omitempty"`
	TxBytes       uint64    `json:"tx_bytes,omitempty"`
	// Link and Blocker: whether the server answers, and if not, why (when
	// known).
	Link    Link     `json:"link,omitempty"`
	Blocker *Blocker `json:"blocker,omitempty"`
	// LastError is the code of the last failure or end reason seen by the
	// caller's tunnel, for example "full_tunnel" or "idle".
	LastError string `json:"last_error,omitempty"`
}

// Write sends one message.
func Write(w io.Writer, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(data) > MaxMessage {
		return errors.New("ipc: message too large")
	}
	buf := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(buf, uint32(len(data)))
	copy(buf[4:], data)
	_, err = w.Write(buf)
	clear(buf) // requests may hold keys
	clear(data)
	return err
}

// Read receives one message into v.
func Read(r io.Reader, v any) error {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > MaxMessage {
		return errBadFrame
	}
	data := make([]byte, n)
	defer clear(data)
	if _, err := io.ReadFull(r, data); err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

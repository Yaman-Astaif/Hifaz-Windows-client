package protocol

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Document types.
const (
	TypeInfo     = "info"
	TypeEnrolled = "enrolled"
	TypeSession  = "session"
	TypeRenewed  = "renewed"
)

// DefaultMaxSkew is how far a signed answer's issued_at may be from the
// local clock. The server refuses requests more than five minutes off, so a
// fresh answer is always well inside this.
const DefaultMaxSkew = 10 * time.Minute

// maxPayload bounds the decoded payload of a signed document.
const maxPayload = 256 << 10

// SignedDocument is the envelope the server signs with its identity key.
type SignedDocument struct {
	Payload   string `json:"payload"`
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}

// Header holds the fields every signed payload carries.
type Header struct {
	Type     string    `json:"type"`
	Server   string    `json:"server"`
	IssuedAt time.Time `json:"issued_at"`
	Nonce    string    `json:"nonce,omitempty"`
}

// Expect describes the document a caller is waiting for.
type Expect struct {
	Type   string // required
	Server string // normalized public URL; required
	// Nonce the answer must carry. Empty only for documents that answer no
	// request (the info document).
	Nonce string
	// Now and MaxSkew bound issued_at; MaxSkew 0 skips the check (used for
	// the info document, which holds nothing secret, so that a wrong device
	// clock is reported by the server instead).
	Now     time.Time
	MaxSkew time.Duration
}

// ErrBadSignature means a document is not signed by the pinned key.
var ErrBadSignature = errors.New("server signature is not valid")

// Open checks the signature with the pinned key and returns the payload bytes.
func (d SignedDocument) Open(pin Pin) ([]byte, error) {
	if !pin.Valid() {
		return nil, errors.New("no valid server key pinned")
	}
	if d.KeyID != string(pin.Fingerprint) {
		return nil, ErrBadSignature
	}
	if len(d.Payload) > b64url.EncodedLen(maxPayload) {
		return nil, errors.New("signed document too large")
	}
	payload, err := b64url.DecodeString(d.Payload)
	if err != nil {
		return nil, ErrBadSignature
	}
	sig, err := b64url.DecodeString(d.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(pin.Key, payload, sig) {
		return nil, ErrBadSignature
	}
	return payload, nil
}

// Verify opens d with the pinned key, checks its header against exp, and
// decodes the payload into out.
func (d SignedDocument) Verify(pin Pin, exp Expect, out any) error {
	payload, err := d.Open(pin)
	if err != nil {
		return err
	}
	if err := checkHeader(payload, exp); err != nil {
		return err
	}
	if err := json.Unmarshal(payload, out); err != nil {
		return fmt.Errorf("signed %s document: %w", exp.Type, err)
	}
	return nil
}

// ParseHeader reads the header of a payload returned by Open, for callers
// that must look at the nonce before they know what to expect.
func ParseHeader(payload []byte) (Header, error) {
	var h Header
	err := json.Unmarshal(payload, &h)
	return h, err
}

func checkHeader(payload []byte, exp Expect) error {
	if exp.Type == "" || exp.Server == "" {
		return errors.New("expectation needs a type and a server")
	}
	var h Header
	if err := json.Unmarshal(payload, &h); err != nil {
		return fmt.Errorf("signed document: %w", err)
	}
	if h.Type != exp.Type {
		return fmt.Errorf("signed document has type %q, want %q", h.Type, exp.Type)
	}
	if server, err := NormalizeServerURL(h.Server); err != nil || server != exp.Server {
		return errors.New("signed document is for another server")
	}
	if h.Nonce != exp.Nonce {
		return errors.New("signed document does not answer this request")
	}
	if exp.MaxSkew > 0 {
		if h.IssuedAt.IsZero() {
			return errors.New("signed document has no issue time")
		}
		if d := exp.Now.Sub(h.IssuedAt); d > exp.MaxSkew || d < -exp.MaxSkew {
			return errors.New("signed document is not fresh")
		}
	}
	return nil
}

// Sign makes a signed document; the server side of Open, used by tests.
func Sign(priv ed25519.PrivateKey, payload []byte) SignedDocument {
	pub := priv.Public().(ed25519.PublicKey)
	return SignedDocument{
		Payload:   b64url.EncodeToString(payload),
		KeyID:     string(FingerprintOf(pub)),
		Signature: b64url.EncodeToString(ed25519.Sign(priv, payload)),
	}
}

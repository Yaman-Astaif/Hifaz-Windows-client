package protocol

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"
)

// Request signature headers.
const (
	HeaderDevice    = "Hifaz-Device"
	HeaderTime      = "Hifaz-Time"
	HeaderNonce     = "Hifaz-Nonce"
	HeaderSignature = "Hifaz-Signature"

	signContext = "hifaz-client-v1"
)

// Signer signs requests for one enrolled device. Implementations keep the
// private key to themselves.
type Signer interface {
	DeviceID() string
	Sign(message []byte) ([]byte, error)
}

// StringToSign builds the bytes a device signs (section 7). path is the API
// path from APIPrefix on, with its query if any.
func StringToSign(method, path, timestamp, nonce string, body []byte) []byte {
	sum := sha256.Sum256(body)
	return []byte(strings.Join([]string{
		signContext, strings.ToUpper(method), path, timestamp, nonce, hex.EncodeToString(sum[:]),
	}, "\n"))
}

// FormatTime is the time format of Hifaz-Time and every protocol time.
func FormatTime(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// signRequest sets the signature headers on r. path must be the API path as
// sent (see StringToSign).
func signRequest(r *http.Request, path string, body []byte, s Signer, now time.Time, nonce string) error {
	if !ValidNonce(nonce) {
		return errors.New("invalid request nonce")
	}
	if !strings.HasPrefix(path, APIPrefix+"/") {
		return errors.New("signed path outside the client API")
	}
	ts := FormatTime(now)
	sig, err := s.Sign(StringToSign(r.Method, path, ts, nonce, body))
	if err != nil {
		return err
	}
	r.Header.Set(HeaderDevice, s.DeviceID())
	r.Header.Set(HeaderTime, ts)
	r.Header.Set(HeaderNonce, nonce)
	r.Header.Set(HeaderSignature, b64url.EncodeToString(sig))
	return nil
}

var _ Signer = (*KeySigner)(nil)

// KeySigner signs with an Ed25519 private key held in memory.
type KeySigner struct {
	id  string
	key ed25519.PrivateKey
}

// NewKeySigner returns a signer for device id with the given key.
func NewKeySigner(id string, key ed25519.PrivateKey) (*KeySigner, error) {
	if id == "" || len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("signer needs a device id and an Ed25519 key")
	}
	return &KeySigner{id: id, key: key}, nil
}

// DeviceID implements Signer.
func (s *KeySigner) DeviceID() string { return s.id }

// Sign implements Signer.
func (s *KeySigner) Sign(message []byte) ([]byte, error) { return ed25519.Sign(s.key, message), nil }

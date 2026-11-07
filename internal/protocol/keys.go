// Package protocol implements the Hifaz client protocol, version 1
// (docs/client-protocol.md in the Hifaz repository): keys and their
// encodings, signed requests, signed documents, the sealed preshared key,
// enrollment links, and a typed HTTP client.
//
// The package has no platform-specific code, so all of it is tested on any
// system.
package protocol

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

// Version is the protocol version this package speaks.
const Version = 1

// APIPrefix is the path of the client API below the server's public URL.
const APIPrefix = "/api/client/v1"

// Strict decoding: every value has exactly one accepted text form, which
// matters where values are compared as text (nonces, fingerprints).
var (
	b64    = base64.StdEncoding.Strict()
	b64url = base64.RawURLEncoding.Strict()
)

// KeyLen is the length of WireGuard keys and Ed25519 public keys and seeds.
const KeyLen = 32

// Key is a 32-byte key: a WireGuard private, public or preshared key.
// Its text form is standard base64 with padding, as WireGuard writes keys.
type Key [KeyLen]byte

// ParseKey decodes a key from standard base64.
func ParseKey(s string) (Key, error) {
	var k Key
	b, err := b64.DecodeString(s)
	if err != nil || len(b) != KeyLen {
		return k, errors.New("invalid key encoding")
	}
	copy(k[:], b)
	return k, nil
}

// String returns the standard base64 form.
func (k Key) String() string { return b64.EncodeToString(k[:]) }

// IsZero reports whether every byte is zero.
func (k Key) IsZero() bool { return k == Key{} }

// Wipe overwrites the key with zeros.
func (k *Key) Wipe() { clear(k[:]) }

// GenerateWireGuardKey makes a new WireGuard private key (clamped, as
// WireGuard stores them) and returns it with its public key.
func GenerateWireGuardKey() (private, public Key, err error) {
	if _, err = rand.Read(private[:]); err != nil {
		return private, public, err
	}
	private[0] &= 248
	private[31] = private[31]&127 | 64
	public, err = WireGuardPublicKey(private)
	return private, public, err
}

// WireGuardPublicKey derives the public key of a WireGuard private key.
func WireGuardPublicKey(private Key) (Key, error) {
	var pub Key
	priv, err := ecdh.X25519().NewPrivateKey(private[:])
	if err != nil {
		return pub, err
	}
	copy(pub[:], priv.PublicKey().Bytes())
	return pub, nil
}

// ParseEd25519PublicKey decodes an Ed25519 public key from standard base64.
func ParseEd25519PublicKey(s string) (ed25519.PublicKey, error) {
	k, err := ParseKey(s)
	if err != nil {
		return nil, errors.New("invalid Ed25519 public key")
	}
	return ed25519.PublicKey(k[:]), nil
}

// EncodeEd25519PublicKey returns the standard base64 form of a public key.
func EncodeEd25519PublicKey(pub ed25519.PublicKey) string { return b64.EncodeToString(pub) }

// FingerprintLen is the length of a fingerprint in text form, and
// FingerprintDisplayLen the part shown to people.
const (
	FingerprintLen        = 43
	FingerprintDisplayLen = 22
)

// Fingerprint identifies a server identity key: SHA-256 of the raw public
// key, base64url without padding.
type Fingerprint string

// FingerprintOf computes the fingerprint of an identity public key.
func FingerprintOf(pub ed25519.PublicKey) Fingerprint {
	sum := sha256.Sum256(pub)
	return Fingerprint(b64url.EncodeToString(sum[:]))
}

// ParseFingerprint checks the text form of a fingerprint.
func ParseFingerprint(s string) (Fingerprint, error) {
	if len(s) != FingerprintLen {
		return "", fmt.Errorf("fingerprint must be %d characters", FingerprintLen)
	}
	if b, err := b64url.DecodeString(s); err != nil || len(b) != sha256.Size {
		return "", errors.New("invalid fingerprint encoding")
	}
	return Fingerprint(s), nil
}

// Display returns the part of the fingerprint shown to people.
func (f Fingerprint) Display() string {
	if len(f) < FingerprintDisplayLen {
		return string(f)
	}
	return string(f[:FingerprintDisplayLen])
}

// Matches reports whether pub is the key this fingerprint identifies.
func (f Fingerprint) Matches(pub ed25519.PublicKey) bool {
	return len(pub) == ed25519.PublicKeySize && FingerprintOf(pub) == f
}

// Pin is the server identity an app device trusts: the fingerprint from
// enrollment and, once seen, the public key it identifies.
type Pin struct {
	Fingerprint Fingerprint
	Key         ed25519.PublicKey
}

// Valid reports whether the pin holds a key matching its fingerprint.
func (p Pin) Valid() bool { return p.Fingerprint.Matches(p.Key) }

// NonceLen is the number of random bytes in a nonce.
const NonceLen = 16

// NewNonce returns a fresh random nonce in its text form.
func NewNonce() (string, error) {
	b := make([]byte, NonceLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return b64url.EncodeToString(b), nil
}

// ValidNonce reports whether s is the text form of a nonce.
func ValidNonce(s string) bool {
	b, err := b64url.DecodeString(s)
	return err == nil && len(b) == NonceLen
}

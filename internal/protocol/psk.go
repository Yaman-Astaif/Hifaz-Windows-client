package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"io"
)

// The sealed preshared key (Appendix A):
//
//	eph_pub || AES-256-GCM(key, nonce = 12 zero bytes, psk, ad = device_id)
//	key = HKDF-SHA256(X25519(eph, device_wg), salt = eph_pub || device_wg_pub,
//	                  info = "hifaz-psk-v1", 32 bytes)
const pskInfo = "hifaz-psk-v1"

const sealedLen = KeyLen + KeyLen + 16 // ephemeral key, psk, GCM tag

// ErrSealedPSK means the sealed preshared key could not be opened.
var ErrSealedPSK = errors.New("the preshared key could not be opened")

// OpenSealedPSK opens psk_sealed with the device's WireGuard private key.
func OpenSealedPSK(sealed string, wgPrivate Key, deviceID string) (Key, error) {
	var psk Key
	raw, err := b64.DecodeString(sealed)
	if err != nil || len(raw) != sealedLen {
		return psk, ErrSealedPSK
	}
	x := ecdh.X25519()
	priv, err := x.NewPrivateKey(wgPrivate[:])
	if err != nil {
		return psk, ErrSealedPSK
	}
	eph, err := x.NewPublicKey(raw[:KeyLen])
	if err != nil {
		return psk, ErrSealedPSK
	}
	shared, err := priv.ECDH(eph)
	if err != nil {
		return psk, ErrSealedPSK // low-order point
	}
	gcm, err := pskCipher(shared, raw[:KeyLen], priv.PublicKey().Bytes())
	if err != nil {
		return psk, ErrSealedPSK
	}
	out, err := gcm.Open(psk[:0], make([]byte, gcm.NonceSize()), raw[KeyLen:], []byte(deviceID))
	if err != nil || len(out) != KeyLen {
		psk.Wipe()
		return Key{}, ErrSealedPSK
	}
	return psk, nil
}

// SealPSK seals psk to a device; the server side of OpenSealedPSK, used by
// tests.
func SealPSK(psk, wgPublic Key, deviceID string, random io.Reader) (string, error) {
	x := ecdh.X25519()
	eph, err := x.GenerateKey(random)
	if err != nil {
		return "", err
	}
	dev, err := x.NewPublicKey(wgPublic[:])
	if err != nil {
		return "", err
	}
	shared, err := eph.ECDH(dev)
	if err != nil {
		return "", err
	}
	ephPub := eph.PublicKey().Bytes()
	gcm, err := pskCipher(shared, ephPub, wgPublic[:])
	if err != nil {
		return "", err
	}
	sealed := gcm.Seal(ephPub, make([]byte, gcm.NonceSize()), psk[:], []byte(deviceID))
	return b64.EncodeToString(sealed), nil
}

// pskCipher derives the AES-GCM key from the X25519 result and wipes it.
func pskCipher(shared, ephPub, devicePub []byte) (cipher.AEAD, error) {
	salt := append(append(make([]byte, 0, 2*KeyLen), ephPub...), devicePub...)
	key, err := hkdf.Key(sha256.New, shared, salt, pskInfo, 32)
	clear(shared)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	clear(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

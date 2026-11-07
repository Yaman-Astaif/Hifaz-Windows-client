package protocol

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// vectors mirrors docs/client-protocol-vectors.json in the Hifaz repository
// (copied to testdata/vectors.json; keep the two identical).
type vectors struct {
	Version  int `json:"version"`
	Identity struct {
		SeedHex            string `json:"seed_hex"`
		PublicKey          string `json:"public_key"`
		Fingerprint        string `json:"fingerprint"`
		FingerprintDisplay string `json:"fingerprint_display"`
	} `json:"identity"`
	SignedDocument struct {
		PayloadJSON string         `json:"payload_json"`
		Document    SignedDocument `json:"document"`
	} `json:"signed_document"`
	Device struct {
		DeviceID  string `json:"device_id"`
		SeedHex   string `json:"seed_hex"`
		PublicKey string `json:"public_key"`
	} `json:"device"`
	Requests []struct {
		Method, Path, Time, Nonce, Body string
		BodySHA256Hex                   string `json:"body_sha256_hex"`
		StringToSign                    string `json:"string_to_sign"`
		Signature                       string `json:"signature"`
	} `json:"requests"`
	SealedPSK struct {
		DeviceID     string `json:"device_id"`
		WGPrivateKey string `json:"wg_private_key"`
		WGPublicKey  string `json:"wg_public_key"`
		PSK          string `json:"psk"`
		PSKSealed    string `json:"psk_sealed"`
	} `json:"sealed_psk"`
}

func loadVectors(t *testing.T) *vectors {
	t.Helper()
	data, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	if v.Version != Version {
		t.Fatalf("vectors for protocol %d, package speaks %d", v.Version, Version)
	}
	return &v
}

func seedKey(t *testing.T, seedHex string) ed25519.PrivateKey {
	t.Helper()
	seed, err := hex.DecodeString(seedHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatalf("bad seed %q", seedHex)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func TestVectorIdentity(t *testing.T) {
	v := loadVectors(t)
	priv := seedKey(t, v.Identity.SeedHex)
	pub := priv.Public().(ed25519.PublicKey)
	if got := EncodeEd25519PublicKey(pub); got != v.Identity.PublicKey {
		t.Fatalf("public key %s, want %s", got, v.Identity.PublicKey)
	}
	fp := FingerprintOf(pub)
	if string(fp) != v.Identity.Fingerprint || fp.Display() != v.Identity.FingerprintDisplay {
		t.Fatalf("fingerprint %s / %s", fp, fp.Display())
	}
	if _, err := ParseFingerprint(string(fp)); err != nil {
		t.Fatal(err)
	}
}

func TestVectorSignedDocument(t *testing.T) {
	v := loadVectors(t)
	priv := seedKey(t, v.Identity.SeedHex)
	pin := Pin{Fingerprint: FingerprintOf(priv.Public().(ed25519.PublicKey)), Key: priv.Public().(ed25519.PublicKey)}

	doc := v.SignedDocument.Document
	if got := Sign(priv, []byte(v.SignedDocument.PayloadJSON)); got != doc {
		t.Fatalf("Sign = %+v, want %+v", got, doc)
	}
	var s Session
	exp := Expect{Type: TypeSession, Server: "https://vpn.example.com", Nonce: "AAECAwQFBgcICQoLDA0ODw",
		Now: time.Date(2026, 11, 7, 10, 1, 0, 0, time.UTC), MaxSkew: DefaultMaxSkew}
	if err := doc.Verify(pin, exp, &s); err != nil {
		t.Fatal(err)
	}
	if s.Status != StatusConnected {
		t.Fatalf("status %q", s.Status)
	}

	// Any change is refused.
	tampered := doc
	raw, _ := b64url.DecodeString(doc.Payload)
	raw[10] ^= 1
	tampered.Payload = b64url.EncodeToString(raw)
	if err := tampered.Verify(pin, exp, &s); err != ErrBadSignature {
		t.Fatalf("tampered payload: %v", err)
	}
	other := exp
	other.Nonce = "EBESExQVFhcYGRobHB0eHw"
	if err := doc.Verify(pin, other, &s); err == nil {
		t.Fatal("wrong nonce accepted")
	}
	other = exp
	other.Server = "https://other.example.com"
	if err := doc.Verify(pin, other, &s); err == nil {
		t.Fatal("wrong server accepted")
	}
	other = exp
	other.Type = TypeRenewed
	if err := doc.Verify(pin, other, &s); err == nil {
		t.Fatal("wrong type accepted")
	}
	other = exp
	other.Now = other.Now.Add(time.Hour)
	if err := doc.Verify(pin, other, &s); err == nil {
		t.Fatal("stale document accepted")
	}
	otherKey := ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey)
	if err := doc.Verify(Pin{Fingerprint: pin.Fingerprint, Key: otherKey}, exp, &s); err == nil {
		t.Fatal("pin with a key that does not match its fingerprint accepted")
	}
}

func TestVectorRequests(t *testing.T) {
	v := loadVectors(t)
	priv := seedKey(t, v.Device.SeedHex)
	if got := EncodeEd25519PublicKey(priv.Public().(ed25519.PublicKey)); got != v.Device.PublicKey {
		t.Fatalf("device key %s", got)
	}
	signer, err := NewKeySigner(v.Device.DeviceID, priv)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range v.Requests {
		sts := StringToSign(r.Method, r.Path, r.Time, r.Nonce, []byte(r.Body))
		if string(sts) != r.StringToSign {
			t.Errorf("%s %s: string to sign\n%q\nwant\n%q", r.Method, r.Path, sts, r.StringToSign)
		}
		sig, _ := signer.Sign(sts)
		if got := b64url.EncodeToString(sig); got != r.Signature {
			t.Errorf("%s %s: signature %s", r.Method, r.Path, got)
		}
	}
}

func TestVectorSealedPSK(t *testing.T) {
	v := loadVectors(t).SealedPSK
	priv, err := ParseKey(v.WGPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := WireGuardPublicKey(priv)
	if err != nil || pub.String() != v.WGPublicKey {
		t.Fatalf("public key %s, %v", pub, err)
	}
	psk, err := OpenSealedPSK(v.PSKSealed, priv, v.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	if psk.String() != v.PSK {
		t.Fatalf("psk %s, want %s", psk, v.PSK)
	}
	if _, err := OpenSealedPSK(v.PSKSealed, priv, "d_other"); err != ErrSealedPSK {
		t.Fatalf("other device id: %v", err)
	}
	other, _, _ := GenerateWireGuardKey()
	if _, err := OpenSealedPSK(v.PSKSealed, other, v.DeviceID); err != ErrSealedPSK {
		t.Fatalf("other key: %v", err)
	}
}

package keystore

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// testProtector stands in for DPAPI: AES-GCM with a key of its own.
type testProtector struct{ aead cipher.AEAD }

func newTestProtector(t *testing.T) *testProtector {
	key := make([]byte, 32)
	rand.Read(key)
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	return &testProtector{aead: aead}
}

func (p *testProtector) Protect(plain []byte) ([]byte, error) {
	nonce := make([]byte, p.aead.NonceSize())
	rand.Read(nonce)
	return p.aead.Seal(nonce, nonce, plain, nil), nil
}

func (p *testProtector) Unprotect(sealed []byte) ([]byte, error) {
	if len(sealed) < p.aead.NonceSize() {
		return nil, errors.New("short")
	}
	return p.aead.Open(nil, sealed[:p.aead.NonceSize()], sealed[p.aead.NonceSize():], nil)
}

func TestStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Hifaz", "accounts.json")
	prot := newTestProtector(t)
	s, err := Open(path, prot)
	if err != nil {
		t.Fatal(err)
	}
	seed := bytes.Repeat([]byte{7}, 32)
	sec := &Secrets{DeviceSeed: seed, WGPrivate: [32]byte{1}, PSK: [32]byte{2}}
	a := &Account{Server: "https://vpn.example.com", DeviceID: "d_1", Username: "alice"}
	saved, err := s.Save(a, sec)
	if err != nil {
		t.Fatal(err)
	}
	if a.Sealed != nil || saved.Sealed == nil {
		t.Fatal("Save must return the sealed account and leave the argument alone")
	}
	if sec2, err := s.Secrets(saved); err != nil || !bytes.Equal(sec2.DeviceSeed, seed) {
		t.Fatalf("returned account does not open: %v", err)
	}
	raw, _ := os.ReadFile(path)
	if bytes.Contains(raw, seed) || bytes.Contains(raw, []byte("BwcHBwcH")) {
		t.Fatal("device key stored in the clear")
	}

	got, err := s.Account("https://vpn.example.com")
	if err != nil || got == nil || got.Username != "alice" {
		t.Fatalf("%+v %v", got, err)
	}
	opened, err := s.Secrets(got)
	if err != nil || !bytes.Equal(opened.DeviceSeed, seed) || opened.WGPrivate != sec.WGPrivate || opened.PSK != sec.PSK {
		t.Fatalf("secrets %+v %v", opened, err)
	}
	signer, err := opened.Signer("d_1")
	if err != nil || signer.DeviceID() != "d_1" {
		t.Fatal(err)
	}
	opened.Wipe()
	if !bytes.Equal(opened.DeviceSeed, make([]byte, 32)) || !opened.WGPrivate.IsZero() {
		t.Fatal("not wiped")
	}

	// Pending keys are used next, and adopted after.
	opened, _ = s.Secrets(got)
	opened.Pending = &PendingKeys{WGPrivate: [32]byte{9}, PSK: [32]byte{8}}
	if wg, psk := opened.TunnelKeys(); wg != [32]byte{9} || psk != [32]byte{8} {
		t.Fatal("pending keys not used")
	}
	opened.AdoptPending()
	if opened.Pending != nil || opened.WGPrivate != [32]byte{9} || opened.PSK != [32]byte{8} {
		t.Fatal("pending keys not adopted")
	}

	// Another protector (another Windows user) cannot open them.
	other, _ := Open(path, newTestProtector(t))
	if _, err := other.Secrets(got); err == nil {
		t.Fatal("secrets opened with another key")
	}

	// Replace, then delete.
	a.Username = "alice2"
	if _, err := s.Save(a, sec); err != nil {
		t.Fatal(err)
	}
	list, _ := s.Accounts()
	if len(list) != 1 || list[0].Username != "alice2" {
		t.Fatalf("%+v", list)
	}
	if err := s.Delete(a.Server); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Account(a.Server); got != nil {
		t.Fatal("not deleted")
	}
}

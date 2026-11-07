package keystore

import (
	"bytes"
	"testing"
)

func TestDPAPI(t *testing.T) {
	plain := []byte("device keys")
	sealed, err := DPAPI{}.Protect(plain)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, plain) {
		t.Fatal("not encrypted")
	}
	got, err := DPAPI{}.Unprotect(sealed)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("%q %v", got, err)
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := (DPAPI{}).Unprotect(sealed); err == nil {
		t.Fatal("tampered data opened")
	}
}

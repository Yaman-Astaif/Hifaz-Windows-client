package keystore

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

// dpapiEntropy ties the protected data to Hifaz: another program running as
// the same user must know it to call CryptUnprotectData successfully.
var dpapiEntropy = []byte("hifaz-keystore-v1")

// DPAPI protects data for the current Windows user (no admin rights
// needed). It does not protect against other programs running as that same
// user; a TPM-backed key is the later step for that.
type DPAPI struct{}

// Protect implements Protector.
func (DPAPI) Protect(plain []byte) ([]byte, error) {
	if len(plain) == 0 {
		return nil, errors.New("nothing to protect")
	}
	in := blob(plain)
	entropy := blob(dpapiEntropy)
	var out windows.DataBlob
	if err := windows.CryptProtectData(&in, nil, &entropy, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	return takeBlob(&out), nil
}

// Unprotect implements Protector.
func (DPAPI) Unprotect(sealed []byte) ([]byte, error) {
	if len(sealed) == 0 {
		return nil, errors.New("nothing to unprotect")
	}
	in := blob(sealed)
	entropy := blob(dpapiEntropy)
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, &entropy, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	return takeBlob(&out), nil
}

func blob(b []byte) windows.DataBlob {
	return windows.DataBlob{Size: uint32(len(b)), Data: unsafe.SliceData(b)}
}

// takeBlob copies a DPAPI result into Go memory, wipes it and frees it.
func takeBlob(b *windows.DataBlob) []byte {
	src := unsafe.Slice(b.Data, b.Size)
	out := make([]byte, len(src))
	copy(out, src)
	clear(src)
	windows.LocalFree(windows.Handle(unsafe.Pointer(b.Data)))
	return out
}

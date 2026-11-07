// Package keystore keeps the user's enrolled Hifaz servers ("accounts"):
// the server identity, the device's details, and its private keys. The keys
// are encrypted with a Protector (on Windows: DPAPI for the current user),
// so other Windows users and copies of the file elsewhere cannot use them.
package keystore

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/protocol"
)

// Protector encrypts and decrypts the key material.
type Protector interface {
	Protect(plain []byte) ([]byte, error)
	Unprotect(sealed []byte) ([]byte, error)
}

// Account is one enrolled server.
type Account struct {
	Server       string               `json:"server"`
	Fingerprint  protocol.Fingerprint `json:"fingerprint"`
	IdentityKey  string               `json:"identity_key"`
	DeviceID     string               `json:"device_id"`
	Username     string               `json:"username"`
	DeviceName   string               `json:"device_name"`
	EnrolledAt   time.Time            `json:"enrolled_at"`
	KeysExpireAt time.Time            `json:"keys_expire_at"`
	RenewAfter   time.Time            `json:"renew_after,omitzero"`
	// Sealed holds the protected Secrets.
	Sealed []byte `json:"sealed"`
}

// Pin returns the account's server identity.
func (a *Account) Pin() (protocol.Pin, error) {
	key, err := protocol.ParseEd25519PublicKey(a.IdentityKey)
	if err != nil {
		return protocol.Pin{}, err
	}
	pin := protocol.Pin{Fingerprint: a.Fingerprint, Key: key}
	if !pin.Valid() {
		return protocol.Pin{}, errors.New("stored server key does not match its fingerprint")
	}
	return pin, nil
}

// Secrets are the device's private keys.
type Secrets struct {
	DeviceSeed  []byte       `json:"device_seed"` // Ed25519 seed
	WGPrivate   protocol.Key `json:"wg_private"`
	PSK         protocol.Key `json:"psk"`
	Certificate []byte       `json:"certificate,omitempty"`
}

// Signer returns a request signer for the device.
func (s *Secrets) Signer(deviceID string) (*protocol.KeySigner, error) {
	if len(s.DeviceSeed) != ed25519.SeedSize {
		return nil, errors.New("invalid device key")
	}
	return protocol.NewKeySigner(deviceID, ed25519.NewKeyFromSeed(s.DeviceSeed))
}

// Wipe overwrites the secrets.
func (s *Secrets) Wipe() {
	clear(s.DeviceSeed)
	s.WGPrivate.Wipe()
	s.PSK.Wipe()
}

// Store is the accounts file of one Windows user.
type Store struct {
	path string
	prot Protector
	mu   sync.Mutex
}

// Open uses the file at path, creating its folder if needed.
func Open(path string, prot Protector) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	return &Store{path: path, prot: prot}, nil
}

type file struct {
	Version  int        `json:"version"`
	Accounts []*Account `json:"accounts"`
}

const fileVersion = 1

// Accounts lists the enrolled servers.
func (s *Store) Accounts() ([]*Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.read()
	if err != nil {
		return nil, err
	}
	return f.Accounts, nil
}

// Account returns the account for server, or nil.
func (s *Store) Account(server string) (*Account, error) {
	accounts, err := s.Accounts()
	if err != nil {
		return nil, err
	}
	for _, a := range accounts {
		if a.Server == server {
			return a, nil
		}
	}
	return nil, nil
}

// Save adds or replaces the account for a.Server with sec sealed into it,
// and returns the account as saved; a itself is not changed.
func (s *Store) Save(a *Account, sec *Secrets) (*Account, error) {
	plain, err := json.Marshal(sec)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	sealed, err := s.prot.Protect(plain)
	if err != nil {
		return nil, fmt.Errorf("protecting the keys: %w", err)
	}
	cp := *a
	cp.Sealed = sealed
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.read()
	if err != nil {
		return nil, err
	}
	replaced := false
	for i, x := range f.Accounts {
		if x.Server == cp.Server {
			f.Accounts[i], replaced = &cp, true
		}
	}
	if !replaced {
		f.Accounts = append(f.Accounts, &cp)
	}
	if err := s.write(f); err != nil {
		return nil, err
	}
	saved := cp
	return &saved, nil
}

// Secrets opens the account's keys. Wipe them when done.
func (s *Store) Secrets(a *Account) (*Secrets, error) {
	plain, err := s.prot.Unprotect(a.Sealed)
	if err != nil {
		return nil, fmt.Errorf("opening the keys: %w", err)
	}
	defer clear(plain)
	var sec Secrets
	if err := json.Unmarshal(plain, &sec); err != nil {
		return nil, err
	}
	return &sec, nil
}

// Delete removes the account for server.
func (s *Store) Delete(server string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.read()
	if err != nil {
		return err
	}
	kept := f.Accounts[:0]
	for _, a := range f.Accounts {
		if a.Server != server {
			kept = append(kept, a)
		}
	}
	f.Accounts = kept
	return s.write(f)
}

func (s *Store) read() (*file, error) {
	f := &file{Version: fileVersion}
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, f); err != nil {
		return nil, fmt.Errorf("%s: %w", s.path, err)
	}
	if f.Version != fileVersion {
		return nil, fmt.Errorf("%s: unknown version %d", s.path, f.Version)
	}
	return f, nil
}

func (s *Store) write(f *file) error {
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".accounts-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}

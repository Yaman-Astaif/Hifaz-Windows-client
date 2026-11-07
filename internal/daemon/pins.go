package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/protocol"
)

// PinRecord is the server identity a Windows user enrolled with.
type PinRecord struct {
	Server      string               `json:"server"`
	Fingerprint protocol.Fingerprint `json:"fingerprint"`
	IdentityKey string               `json:"identity_key"`
	DeviceID    string               `json:"device_id"`
	Registered  time.Time            `json:"registered"`
}

// Pin returns the record as a checked protocol pin.
func (r PinRecord) Pin() (protocol.Pin, error) {
	key, err := protocol.ParseEd25519PublicKey(r.IdentityKey)
	if err != nil {
		return protocol.Pin{}, err
	}
	pin := protocol.Pin{Fingerprint: r.Fingerprint, Key: key}
	if !pin.Valid() {
		return protocol.Pin{}, errors.New("stored identity key does not match its fingerprint")
	}
	return pin, nil
}

// PinStore keeps PinRecords per Windows user (by SID) and server.
type PinStore interface {
	Load(sid, server string) (PinRecord, bool, error)
	Save(sid string, rec PinRecord) error
	Delete(sid, server string) error
}

// FileStore is a PinStore in one JSON file. The service keeps it in a
// folder only the system and administrators can read or write (set up on
// Windows by the service when it starts).
type FileStore struct {
	path string
	mu   sync.Mutex
}

// NewFileStore uses the file at path.
func NewFileStore(path string) *FileStore { return &FileStore{path: path} }

type pinFile struct {
	Version int                             `json:"version"`
	Users   map[string]map[string]PinRecord `json:"users"` // SID -> server -> record
}

const pinFileVersion = 1

func (s *FileStore) read() (*pinFile, error) {
	f := &pinFile{Version: pinFileVersion, Users: map[string]map[string]PinRecord{}}
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
	if f.Version != pinFileVersion {
		return nil, fmt.Errorf("%s: unknown version %d", s.path, f.Version)
	}
	if f.Users == nil {
		f.Users = map[string]map[string]PinRecord{}
	}
	return f, nil
}

// write replaces the file atomically (write a temporary file, then rename).
func (s *FileStore) write(f *pinFile) error {
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".pins-*.tmp")
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

// Load implements PinStore.
func (s *FileStore) Load(sid, server string) (PinRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.read()
	if err != nil {
		return PinRecord{}, false, err
	}
	rec, ok := f.Users[sid][server]
	return rec, ok, nil
}

// Save implements PinStore.
func (s *FileStore) Save(sid string, rec PinRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.read()
	if err != nil {
		return err
	}
	if f.Users[sid] == nil {
		f.Users[sid] = map[string]PinRecord{}
	}
	f.Users[sid][rec.Server] = rec
	return s.write(f)
}

// Delete implements PinStore.
func (s *FileStore) Delete(sid, server string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.read()
	if err != nil {
		return err
	}
	if _, ok := f.Users[sid][server]; !ok {
		return nil
	}
	delete(f.Users[sid], server)
	if len(f.Users[sid]) == 0 {
		delete(f.Users, sid)
	}
	return s.write(f)
}

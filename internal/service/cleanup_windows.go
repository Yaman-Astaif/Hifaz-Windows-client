package service

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// removeUserData deletes every user's Hifaz folder (%LOCALAPPDATA%\Hifaz:
// the device keys, preferences, logs and the window's browser data), so
// removing Hifaz leaves nothing behind. Profiles are found in the registry,
// whether or not their users are signed in.
func removeUserData() error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return err
	}
	defer k.Close()
	sids, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return err
	}
	var firstErr error
	for _, sid := range sids {
		if !strings.HasPrefix(sid, "S-1-5-21-") { // real user accounts only
			continue
		}
		p, err := registry.OpenKey(k, sid, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		profile, _, err := p.GetStringValue("ProfileImagePath")
		p.Close()
		if err != nil || profile == "" {
			continue
		}
		if err := removeFolder(filepath.Join(profile, "AppData", "Local", "Hifaz")); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// removeFolder deletes dir unless it is a link of any kind: a user could
// otherwise point their own folder elsewhere and have the system delete it.
// Links inside it are removed as links (Go does not follow them).
func removeFolder(dir string) error {
	path, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	attrs, err := windows.GetFileAttributes(path)
	if err != nil {
		return nil // not there
	}
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return os.Remove(dir) // the link itself only
	}
	return os.RemoveAll(dir)
}

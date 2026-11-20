package service

import (
	"os"

	"golang.org/x/sys/windows"
)

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

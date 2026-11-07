// Package logfile is a log file of bounded size: when it reaches its limit
// it is renamed to <name>.1 (replacing an older one) and started again, so
// logs never take more than twice the limit.
package logfile

import (
	"os"
	"sync"
)

// File is an io.Writer safe for concurrent use.
type File struct {
	path  string
	limit int64

	mu   sync.Mutex
	f    *os.File
	size int64
}

// Open opens or creates the log at path.
func Open(path string, limit int64) (*File, error) {
	l := &File{path: path, limit: limit}
	if err := l.open(); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *File) open() error {
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	l.f, l.size = f, st.Size()
	return nil
}

// Write implements io.Writer.
func (l *File) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return 0, os.ErrClosed
	}
	if l.size+int64(len(p)) > l.limit && l.size > 0 {
		l.f.Close()
		os.Rename(l.path, l.path+".1")
		if err := l.open(); err != nil {
			l.f = nil
			return 0, err
		}
	}
	n, err := l.f.Write(p)
	l.size += int64(n)
	return n, err
}

// Close closes the file.
func (l *File) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}

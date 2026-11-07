package logfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "service.log")
	l, err := Open(path, 100)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.Repeat("x", 39) + "\n"
	for range 5 {
		if _, err := l.Write([]byte(line)); err != nil {
			t.Fatal(err)
		}
	}
	l.Close()
	cur, _ := os.ReadFile(path)
	old, _ := os.ReadFile(path + ".1")
	// 40-byte lines, limit 100: rotate before the 3rd and the 5th line.
	if len(cur) != 40 || len(old) != 80 {
		t.Fatalf("current %d bytes, old %d bytes", len(cur), len(old))
	}
	if _, err := l.Write([]byte("x")); err == nil {
		t.Fatal("write after close")
	}
}

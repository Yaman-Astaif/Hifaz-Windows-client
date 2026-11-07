package ipc_test

import (
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/daemon"
	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/ipc"
	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/protocol"
)

type nopTunnel struct {
	mu sync.Mutex
	up bool
}

func (t *nopTunnel) Up(*protocol.TunnelConfig, protocol.Key, protocol.Key) error {
	t.mu.Lock()
	t.up = true
	t.mu.Unlock()
	return nil
}
func (t *nopTunnel) Reconfigure(*protocol.TunnelConfig) error { return nil }
func (t *nopTunnel) Down() error {
	t.mu.Lock()
	t.up = false
	t.mu.Unlock()
	return nil
}
func (t *nopTunnel) Stats() (daemon.Stats, error) { return daemon.Stats{}, nil }
func (t *nopTunnel) isUp() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.up
}

// serve runs the service loop on one end of a net.Pipe, as the Windows
// service does on the pipe.
func serve(e *daemon.Engine, id uint64, conn net.Conn) {
	defer func() { e.Closed(id); conn.Close() }()
	caller := daemon.Caller{SID: "S-1-5-21-7", Session: 1}
	for {
		var req ipc.Request
		if err := ipc.Read(conn, &req); err != nil {
			return
		}
		if err := ipc.Write(conn, e.Handle(context.Background(), id, caller, &req)); err != nil {
			return
		}
	}
}

func TestClientOverPipe(t *testing.T) {
	tun := &nopTunnel{}
	e := daemon.New(daemon.Options{Tunnel: tun, Pins: daemon.NewFileStore(filepath.Join(t.TempDir(), "p.json"))})
	var ids atomic.Uint64
	var down atomic.Bool
	c := ipc.NewClient(func() (io.ReadWriteCloser, error) {
		if down.Load() {
			return nil, errors.New("no pipe")
		}
		a, b := net.Pipe()
		go serve(e, ids.Add(1), b)
		return a, nil
	})
	defer c.Close()

	n, err := c.Nonce()
	if err != nil || !protocol.ValidNonce(n) {
		t.Fatalf("nonce %q %v", n, err)
	}
	st, err := c.Status()
	if err != nil || st.State != ipc.StateIdle {
		t.Fatalf("status %+v %v", st, err)
	}
	// A service error passes through as *ipc.Error, not as unavailable.
	_, err = c.Connect("https://vpn.example.com", protocol.SignedDocument{}, protocol.Key{}, protocol.Key{})
	var svcErr *ipc.Error
	if !errors.As(err, &svcErr) || svcErr.Code != ipc.ErrNotRegistered || errors.Is(err, ipc.ErrUnavailable) {
		t.Fatalf("connect: %v", err)
	}
	if _, err := c.Update(protocol.SignedDocument{}); !errors.As(err, &svcErr) || svcErr.Code != ipc.ErrNotOwner {
		t.Fatalf("update without connect: %v", err)
	}
	if err := c.Disconnect(); err != nil {
		t.Fatal(err)
	}

	// With the service gone, calls fail as unavailable.
	c.Close()
	down.Store(true)
	if _, err := c.Nonce(); !errors.Is(err, ipc.ErrUnavailable) {
		t.Fatalf("service down: %v", err)
	}
}

package ipc_test

import (
	"context"
	"errors"
	"fmt"
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

// A dial error that already says why the service could not be reached keeps
// its cause through the client.
func TestClientKeepsDialCause(t *testing.T) {
	for _, cause := range []error{ipc.ErrServiceNotRunning, ipc.ErrServiceRefused, ipc.ErrServiceUntrusted} {
		dialErr := fmt.Errorf("%w: %w", cause, errors.New("windows said no"))
		c := ipc.NewClient(func() (io.ReadWriteCloser, error) { return nil, dialErr })
		if _, err := c.Nonce(); !errors.Is(err, cause) || !errors.Is(err, ipc.ErrUnavailable) || err.Error() != dialErr.Error() {
			t.Errorf("nonce: %v, want %v", err, dialErr)
		}
		_, err := c.Connect("https://vpn.example.com", protocol.SignedDocument{}, protocol.Key{}, protocol.Key{})
		if !errors.Is(err, cause) || err.Error() != dialErr.Error() {
			t.Errorf("connect: %v, want %v", err, dialErr)
		}
	}
	// Any other dial error is unavailable, with its text kept.
	plain := errors.New("no pipe")
	c := ipc.NewClient(func() (io.ReadWriteCloser, error) { return nil, plain })
	if _, err := c.Nonce(); !errors.Is(err, ipc.ErrUnavailable) || !errors.Is(err, plain) {
		t.Fatalf("nonce: %v", err)
	}
}

// Something on the pipe that does not speak the protocol refuses the app;
// a service that hangs up is not running.
func TestClientTransportCause(t *testing.T) {
	for _, tc := range []struct {
		name  string
		serve func(net.Conn)
		want  error
	}{
		{"garbage", func(conn net.Conn) {
			var req ipc.Request
			ipc.Read(conn, &req)
			conn.Write([]byte{0, 0, 0, 3, 'x', 'y', 'z'})
		}, ipc.ErrServiceRefused},
		{"bad length", func(conn net.Conn) {
			var req ipc.Request
			ipc.Read(conn, &req)
			conn.Write([]byte{0xff, 0xff, 0xff, 0xff})
		}, ipc.ErrServiceRefused},
		{"hang up", func(conn net.Conn) {
			var req ipc.Request
			ipc.Read(conn, &req)
		}, ipc.ErrServiceNotRunning},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dial := func() (io.ReadWriteCloser, error) {
				a, b := net.Pipe()
				go func() { defer b.Close(); tc.serve(b) }()
				return a, nil
			}
			c := ipc.NewClient(dial)
			defer c.Close()
			if _, err := c.Nonce(); !errors.Is(err, tc.want) || !errors.Is(err, ipc.ErrUnavailable) {
				t.Errorf("nonce: %v, want %v", err, tc.want)
			}
			if _, err := c.Connect("https://vpn.example.com", protocol.SignedDocument{}, protocol.Key{}, protocol.Key{}); !errors.Is(err, tc.want) {
				t.Errorf("connect: %v, want %v", err, tc.want)
			}
		})
	}
}

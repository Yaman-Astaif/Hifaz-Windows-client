// Package service runs the Hifaz service on Windows: it starts under the
// Service Control Manager, serves the app's pipe, and hands requests to the
// engine in internal/daemon.
package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/daemon"
	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/ipc"
	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/logfile"
	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/policy"
	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/tunnel"
	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/version"
)

// Name is the service name the installer registers.
const Name = "Hifaz"

const (
	maxConns          = 64
	maxPending        = 8
	maxConnsPerSID    = 4
	firstFrameTimeout = 5 * time.Second
	idleFrameTimeout  = 5 * time.Minute
	writeFrameTimeout = 5 * time.Second
	logLimit          = 1 << 20 // bytes per log file
)

// dataSDDL protects the service's folder: SYSTEM and administrators only,
// not inherited from above.
const dataSDDL = "O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

// DataDir is the service's folder: Data next to the program, inside the
// install folder, where normal users cannot create anything beforehand.
func DataDir() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(exe), "Data"), nil
}

// Run runs the service; it returns when the service stops.
func Run() error { return svc.Run(Name, &handler{}) }

type handler struct{}

func (h *handler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	s, err := start()
	if err != nil {
		slog.Error("service failed to start", "err", err)
		return true, 1
	}
	status <- svc.Status{State: svc.Running,
		Accepts: svc.AcceptStop | svc.AcceptShutdown | svc.AcceptSessionChange}
	for r := range requests {
		switch r.Cmd {
		case svc.Interrogate:
			status <- r.CurrentStatus
		case svc.Stop, svc.Shutdown:
			status <- svc.Status{State: svc.StopPending}
			s.stop()
			return false, 0
		case svc.SessionChange:
			if r.EventType == windows.WTS_SESSION_LOGOFF && r.EventData != 0 {
				s.engine.SessionEnded(sessionOf(r.EventData))
			}
		}
	}
	s.stop()
	return false, 0
}

// sessionOf reads the session ID from a session-change notification. The
// address comes from Windows and points to memory it owns for the duration
// of the call, not to Go memory.
func sessionOf(eventData uintptr) uint32 {
	n := (*windows.WTSSESSION_NOTIFICATION)(unsafe.Add(unsafe.Pointer(nil), eventData))
	return n.SessionID
}

type server struct {
	engine *daemon.Engine
	ln     *ipc.Listener
	logf   *logfile.File
	ctx    context.Context
	cancel context.CancelFunc
	nextID atomic.Uint64
	wg     sync.WaitGroup

	mu      sync.Mutex
	conns   map[*ipc.Conn]string // empty SID while awaiting the first frame
	pending int
	bySID   map[string]int
}

func start() (*server, error) {
	dir, err := DataDir()
	if err != nil {
		return nil, err
	}
	if err := secureDir(dir); err != nil {
		return nil, fmt.Errorf("preparing %s: %w", dir, err)
	}
	logf, err := logfile.Open(filepath.Join(dir, "service.log"), logLimit)
	if err != nil {
		return nil, err
	}
	logger := slog.New(slog.NewTextHandler(logf, nil))
	slog.SetDefault(logger)
	log.SetOutput(logf) // the WireGuardNT driver logs through the standard logger
	slog.Info("starting", "version", version.Version)

	if err := tunnel.Cleanup(); err != nil {
		slog.Warn("cleaning up after an earlier run", "err", err)
	}
	if err := setRecovery(); err != nil {
		slog.Warn("setting restart on failure", "err", err)
	}
	ln, err := ipc.Listen(ipc.PipeName)
	if err != nil {
		logf.Close()
		return nil, fmt.Errorf("creating the pipe: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	tun := tunnel.New(func(msg string, args ...any) { slog.Info(msg, args...) })
	s := &server{
		ln: ln, logf: logf, ctx: ctx, cancel: cancel,
		conns: make(map[*ipc.Conn]string), bySID: make(map[string]int),
		engine: daemon.New(daemon.Options{
			Tunnel:      tun,
			Pins:        daemon.NewFileStore(filepath.Join(dir, "servers.json")),
			Policy:      loadPolicy,
			Log:         func(msg string, args ...any) { slog.Info(msg, args...) },
			FindBlocker: tun.FindKillSwitch, // read-only
		}),
	}
	s.wg.Add(2)
	go s.serve()
	go func() {
		defer s.wg.Done()
		s.engine.Run(ctx) // until stop cancels ctx
	}()
	return s, nil
}

// setRecovery makes Windows restart the service if it fails: after 5
// seconds twice, then after a minute; the count resets after a day.
func setRecovery() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(Name)
	if err != nil {
		return err
	}
	defer s.Close()
	return s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: time.Minute},
	}, 24*60*60)
}

// loadPolicy reads the machine policy on every use, so a change applies to
// the next request without restarting the service.
func loadPolicy() policy.Policy {
	p, err := policy.Load()
	if err != nil {
		slog.Error("the machine policy cannot be read; refusing all servers", "err", err)
	}
	return p
}

func (s *server) serve() {
	defer s.wg.Done()
	for {
		conn, err := s.ln.Accept()
		if errors.Is(err, ipc.ErrClosed) {
			return
		}
		if err != nil {
			slog.Warn("accepting a connection", "err", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		s.mu.Lock()
		if s.ctx.Err() != nil || s.pending >= maxPending || len(s.conns) >= maxConns {
			s.mu.Unlock()
			conn.Close()
			continue
		}
		s.conns[conn] = ""
		s.pending++
		s.mu.Unlock()
		s.wg.Add(1)
		go s.handle(conn)
	}
}

func (s *server) handle(conn *ipc.Conn) {
	id := s.nextID.Add(1)
	defer func() {
		s.engine.Closed(id)
		conn.Close()
		s.mu.Lock()
		if sid := s.conns[conn]; sid == "" {
			s.pending--
		} else {
			s.bySID[sid]--
			if s.bySID[sid] == 0 {
				delete(s.bySID, sid)
			}
		}
		delete(s.conns, conn)
		s.mu.Unlock()
		s.wg.Done()
	}()
	var caller daemon.Caller
	for {
		var req ipc.Request
		timeout := idleFrameTimeout
		if caller.SID == "" {
			timeout = firstFrameTimeout
		}
		if err := pipeFrame(conn, timeout, func() error { return ipc.Read(conn, &req) }); err != nil {
			req.Wipe()
			return
		}
		if caller.SID == "" { // Windows tells who the client is once it has written
			sid, session, err := conn.ClientIdentity()
			if err != nil {
				req.Wipe()
				slog.Warn("identifying a client", "err", err)
				return
			}
			s.mu.Lock()
			if s.bySID[sid] >= maxConnsPerSID {
				s.mu.Unlock()
				req.Wipe()
				return
			}
			s.pending--
			s.bySID[sid]++
			s.conns[conn] = sid
			s.mu.Unlock()
			caller = daemon.Caller{SID: sid, Session: session}
		}
		resp := s.engine.Handle(s.ctx, id, caller, &req)
		if err := pipeFrame(conn, writeFrameTimeout, func() error { return ipc.Write(conn, resp) }); err != nil {
			return
		}
	}
}

// pipeFrame bounds a whole frame, including partial reads and writes.
// Closing the connection cancels its pending overlapped I/O. Request
// processing runs outside this deadline, including long-poll watches.
func pipeFrame(conn *ipc.Conn, timeout time.Duration, transfer func() error) error {
	done := make(chan struct{})
	timer := time.AfterFunc(timeout, func() {
		conn.Close()
		close(done)
	})
	err := transfer()
	if !timer.Stop() {
		<-done
		return context.DeadlineExceeded
	}
	return err
}

func (s *server) stop() {
	slog.Info("stopping")
	s.cancel()
	s.ln.Close()
	s.mu.Lock()
	for c := range s.conns {
		c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
	s.engine.Shutdown()
	s.logf.Close()
}

// secureDir makes dir (creating it if needed) a real folder owned by SYSTEM
// that only SYSTEM and administrators can use.
func secureDir(dir string) error {
	sd, err := windows.SecurityDescriptorFromString(dataSDDL)
	if err != nil {
		return err
	}
	path, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	if err := windows.CreateDirectory(path, sa); err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return err
	}
	attrs, err := windows.GetFileAttributes(path)
	if err != nil {
		return err
	}
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || attrs&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return errors.New("not a plain folder")
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, nil, dacl, nil)
}

// Cleanup removes the machine-wide Hifaz resources: the tunnel adapter,
// the DNS rule, the WireGuardNT driver if unused, and the service's folder.
// The installer runs it on full uninstall. Per-user data stays in each profile.
func Cleanup() error {
	errs := []error{tunnel.Cleanup(), tunnel.RemoveDriverIfUnused()}
	if dir, err := DataDir(); err == nil {
		errs = append(errs, removeFolder(dir))
	}
	return errors.Join(errs...)
}

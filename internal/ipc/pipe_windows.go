package ipc

import (
	"errors"
	"io"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// pipeSDDL is the pipe's security descriptor:
//
//   - owner and group SYSTEM, which the app checks before it trusts the pipe;
//   - network logons denied;
//   - SYSTEM and administrators full access;
//   - interactive users (local and Remote Desktop) read and write data only:
//     0x12008b is FILE_GENERIC_READ | FILE_WRITE_DATA, without
//     FILE_CREATE_PIPE_INSTANCE, so a user cannot add a server end of their
//     own to this pipe.
const pipeSDDL = "O:SYG:SYD:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12008b;;;IU)"

const pipeBuffer = 64 << 10

// ErrClosed is returned by Accept after Close.
var ErrClosed = errors.New("ipc: listener closed")

var (
	modkernel32                    = windows.NewLazySystemDLL("kernel32.dll")
	modadvapi32                    = windows.NewLazySystemDLL("advapi32.dll")
	procWaitNamedPipeW             = modkernel32.NewProc("WaitNamedPipeW")
	procImpersonateNamedPipeClient = modadvapi32.NewProc("ImpersonateNamedPipeClient")
)

// Listener is the service end of the pipe.
type Listener struct {
	name  string
	sa    *windows.SecurityAttributes
	close windows.Handle // event, set by Close

	mu     sync.Mutex
	next   windows.Handle // the instance the next Accept waits on
	closed bool
}

// Listen creates the pipe. The first instance is created with
// FILE_FLAG_FIRST_PIPE_INSTANCE, so Listen fails if anyone else already
// created a pipe of that name.
func Listen(name string) (*Listener, error) { return listen(name, pipeSDDL) }

// listen creates the pipe with the given security descriptor (tests use
// one a non-SYSTEM process may set).
func listen(name, sddl string) (*Listener, error) {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, err
	}
	l := &Listener{name: name, sa: &windows.SecurityAttributes{
		Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}}
	if l.close, err = windows.CreateEvent(nil, 1, 0, nil); err != nil {
		return nil, err
	}
	if l.next, err = l.instance(true); err != nil {
		windows.CloseHandle(l.close)
		return nil, err
	}
	return l, nil
}

func (l *Listener) instance(first bool) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(l.name)
	if err != nil {
		return 0, err
	}
	flags := uint32(windows.PIPE_ACCESS_DUPLEX | windows.FILE_FLAG_OVERLAPPED)
	if first {
		flags |= windows.FILE_FLAG_FIRST_PIPE_INSTANCE
	}
	return windows.CreateNamedPipe(name, flags,
		windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS,
		windows.PIPE_UNLIMITED_INSTANCES, pipeBuffer, pipeBuffer, 0, l.sa)
}

// Accept waits for the next client.
func (l *Listener) Accept() (*Conn, error) {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil, ErrClosed
	}
	h := l.next
	l.next = 0
	l.mu.Unlock()
	if h == 0 {
		var err error
		if h, err = l.instance(false); err != nil {
			return nil, err
		}
	}
	if err := l.connect(h); err != nil {
		windows.CloseHandle(h)
		return nil, err
	}
	return newConn(h)
}

// connect waits for a client on instance h, or for Close.
func (l *Listener) connect(h windows.Handle) error {
	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(ev)
	ov := &windows.Overlapped{HEvent: ev}
	err = windows.ConnectNamedPipe(h, ov)
	switch err {
	case nil, windows.ERROR_PIPE_CONNECTED:
		return nil
	case windows.ERROR_IO_PENDING:
	default:
		return err
	}
	which, err := windows.WaitForMultipleObjects([]windows.Handle{ev, l.close}, false, windows.INFINITE)
	if err != nil {
		return err
	}
	if which == windows.WAIT_OBJECT_0+1 { // closed
		windows.CancelIoEx(h, ov)
		var n uint32
		windows.GetOverlappedResult(h, ov, &n, true)
		return ErrClosed
	}
	var n uint32
	return windows.GetOverlappedResult(h, ov, &n, false)
}

// Close stops Accept. Open connections are not affected.
func (l *Listener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	windows.SetEvent(l.close)
	if l.next != 0 {
		windows.CloseHandle(l.next)
		l.next = 0
	}
	return nil
}

// Dial connects to the service. It checks that the pipe belongs to SYSTEM
// before returning, so the app never sends keys to a pipe someone else made.
// The service may identify the app but cannot act as it
// (SECURITY_IDENTIFICATION).
func Dial(name string, timeout time.Duration) (*Conn, error) {
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return nil, err
	}
	return dial(name, timeout, system)
}

// dial connects and checks that the pipe's owner is owner.
func dial(name string, timeout time.Duration, owner *windows.SID) (*Conn, error) {
	path, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(timeout)
	for {
		h, err := windows.CreateFile(path, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil,
			windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
		if err == nil {
			if err := checkServerOwner(h, owner); err != nil {
				windows.CloseHandle(h)
				return nil, err
			}
			return newConn(h)
		}
		if err != windows.ERROR_PIPE_BUSY && err != windows.ERROR_FILE_NOT_FOUND {
			return nil, err
		}
		left := time.Until(deadline)
		if left <= 0 {
			return nil, err
		}
		if err == windows.ERROR_PIPE_BUSY {
			procWaitNamedPipeW.Call(uintptr(unsafe.Pointer(path)), uintptr(min(left, time.Second)/time.Millisecond))
		} else {
			time.Sleep(min(left, 250*time.Millisecond))
		}
	}
}

// ErrNotService means the pipe does not belong to SYSTEM.
var ErrNotService = errors.New("ipc: the pipe does not belong to the Hifaz service")

func checkServerOwner(h windows.Handle, want *windows.SID) error {
	sd, err := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	if owner == nil || !owner.Equals(want) {
		return ErrNotService
	}
	return nil
}

// Conn is one end of a pipe connection.
type Conn struct {
	h windows.Handle

	readMu, writeMu sync.Mutex
	rov, wov        *windows.Overlapped

	mu       sync.Mutex
	closed   bool
	inflight sync.WaitGroup
}

func newConn(h windows.Handle) (*Conn, error) {
	c := &Conn{h: h}
	for _, ov := range []**windows.Overlapped{&c.rov, &c.wov} {
		ev, err := windows.CreateEvent(nil, 1, 0, nil)
		if err != nil {
			c.closeEvents()
			windows.CloseHandle(h)
			return nil, err
		}
		*ov = &windows.Overlapped{HEvent: ev}
	}
	return c, nil
}

func (c *Conn) closeEvents() {
	for _, ov := range []*windows.Overlapped{c.rov, c.wov} {
		if ov != nil && ov.HEvent != 0 {
			windows.CloseHandle(ov.HEvent)
		}
	}
}

// begin registers an operation; it fails once the connection is closed.
func (c *Conn) begin() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return false
	}
	c.inflight.Add(1)
	return true
}

func (c *Conn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if !c.begin() {
		return 0, io.ErrClosedPipe
	}
	defer c.inflight.Done()
	var n uint32
	err := windows.ReadFile(c.h, p, &n, c.rov)
	if err == windows.ERROR_IO_PENDING {
		err = windows.GetOverlappedResult(c.h, c.rov, &n, true)
	}
	switch err {
	case nil:
		if n == 0 && len(p) > 0 {
			return 0, io.EOF
		}
		return int(n), nil
	case windows.ERROR_BROKEN_PIPE, windows.ERROR_PIPE_NOT_CONNECTED, windows.ERROR_OPERATION_ABORTED:
		return int(n), io.EOF
	default:
		return int(n), err
	}
}

func (c *Conn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if !c.begin() {
		return 0, io.ErrClosedPipe
	}
	defer c.inflight.Done()
	written := 0
	for written < len(p) {
		var n uint32
		err := windows.WriteFile(c.h, p[written:], &n, c.wov)
		if err == windows.ERROR_IO_PENDING {
			err = windows.GetOverlappedResult(c.h, c.wov, &n, true)
		}
		written += int(n)
		if err != nil {
			if err == windows.ERROR_BROKEN_PIPE || err == windows.ERROR_NO_DATA || err == windows.ERROR_OPERATION_ABORTED {
				return written, io.ErrClosedPipe
			}
			return written, err
		}
	}
	return written, nil
}

// Close cancels pending reads and writes and closes the handle once they
// have returned.
func (c *Conn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()
	// A Read or Write may be between begin and issuing its I/O, so one
	// cancel can miss it: cancel until every operation has returned.
	done := make(chan struct{})
	go func() { c.inflight.Wait(); close(done) }()
	for {
		windows.CancelIoEx(c.h, nil)
		select {
		case <-done:
		case <-time.After(20 * time.Millisecond):
			continue
		}
		break
	}
	// No DisconnectNamedPipe: it would throw away a reply the other end has
	// not read yet. Closing the handle keeps it readable, then ends the pipe.
	err := windows.CloseHandle(c.h)
	c.closeEvents()
	return err
}

// ClientIdentity returns the Windows user (SID) and logon session of the
// process at the client end. Windows allows this only after the client has
// written to the pipe, so call it after the first message has been read.
func (c *Conn) ClientIdentity() (sid string, session uint32, err error) {
	// Impersonation applies to the calling OS thread; keep it to this one.
	runtime.LockOSThread()
	if r, _, e := procImpersonateNamedPipeClient.Call(uintptr(c.h)); r == 0 {
		runtime.UnlockOSThread()
		return "", 0, e
	}
	var tok windows.Token
	err = windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &tok)
	if rerr := windows.RevertToSelf(); rerr != nil {
		// The thread may still carry the client's identity: never run
		// anything else on it. It ends with this goroutine, because it
		// stays locked.
		if err == nil {
			tok.Close()
		}
		return "", 0, rerr
	}
	runtime.UnlockOSThread()
	if err != nil {
		return "", 0, err
	}
	defer tok.Close()
	user, err := tok.GetTokenUser()
	if err != nil {
		return "", 0, err
	}
	var n uint32
	err = windows.GetTokenInformation(tok, windows.TokenSessionId, (*byte)(unsafe.Pointer(&session)), uint32(unsafe.Sizeof(session)), &n)
	if err != nil {
		return "", 0, err
	}
	return user.User.Sid.String(), session, nil
}

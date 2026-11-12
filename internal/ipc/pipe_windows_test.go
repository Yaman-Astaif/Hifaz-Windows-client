package ipc

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// currentUser returns the SID of the user running the test.
func currentUser(t *testing.T) *windows.SID {
	t.Helper()
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	return u.User.Sid
}

// testPipe creates a pipe owned by the current user (the service's own
// descriptor needs SYSTEM), with the same access rules otherwise.
func testPipe(t *testing.T) (string, *Listener, *windows.SID) {
	t.Helper()
	me := currentUser(t)
	name := fmt.Sprintf(`\\.\pipe\Hifaz-test-%d-%d`, os.Getpid(), time.Now().UnixNano())
	sddl := "O:" + me.String() + "D:P(A;;GA;;;" + me.String() + ")"
	l, err := listen(name, sddl)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return name, l, me
}

// restrictedPipe creates a pipe whose only grant is userAccess, given to the
// current user: what a normal user gets on the service's pipe. The grant
// goes to the user's SID rather than IU because the test runner's token may
// not carry INTERACTIVE, and there is no BA entry so an elevated runner gets
// nothing more. As owner, the user implicitly has only READ_CONTROL and
// WRITE_DAC, which do not include any write or create-instance bits.
func restrictedPipe(t *testing.T) (string, *Listener, *windows.SID) {
	t.Helper()
	me := currentUser(t)
	name := fmt.Sprintf(`\\.\pipe\Hifaz-test-restricted-%d-%d`, os.Getpid(), time.Now().UnixNano())
	sddl := "O:" + me.String() + "G:" + me.String() + "D:P(A;;" + userAccess + ";;;" + me.String() + ")"
	l, err := listen(name, sddl)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return name, l, me
}

// fileCreatePipeInstance is FILE_CREATE_PIPE_INSTANCE (the same bit as
// FILE_APPEND_DATA): the right to add a server end to an existing pipe.
const fileCreatePipeInstance = 0x4

func TestUserAccessMask(t *testing.T) {
	mask, err := strconv.ParseUint(userAccess, 0, 32)
	if err != nil {
		t.Fatal(err)
	}
	if want := uint64(windows.FILE_GENERIC_READ | windows.FILE_WRITE_DATA); mask != want {
		t.Fatalf("userAccess %#x, want FILE_GENERIC_READ|FILE_WRITE_DATA %#x", mask, want)
	}
	if mask&fileCreatePipeInstance != 0 {
		t.Fatal("userAccess grants FILE_CREATE_PIPE_INSTANCE")
	}
}

// A normal user, with only userAccess, can open the pipe and exchange a
// message.
func TestDialWithUserAccess(t *testing.T) {
	name, l, me := restrictedPipe(t)
	served := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			served <- err
			return
		}
		defer c.Close()
		var req Request
		if err := Read(c, &req); err != nil {
			served <- err
			return
		}
		served <- Write(c, Response{Nonce: "pong"})
	}()

	c, err := dial(name, 5*time.Second, me)
	if err != nil {
		t.Fatalf("dial with user access: %v", err)
	}
	defer c.Close()
	if err := Write(c, Request{Op: OpNonce}); err != nil {
		t.Fatal(err)
	}
	var resp Response
	if err := Read(c, &resp); err != nil || resp.Nonce != "pong" {
		t.Fatalf("response %+v %v", resp, err)
	}
	if err := <-served; err != nil {
		t.Fatalf("server: %v", err)
	}
}

// A user with only userAccess cannot add a server end of their own to the
// pipe: a further instance is checked against the existing pipe's DACL for
// FILE_CREATE_PIPE_INSTANCE.
func TestUserCannotAddServerInstance(t *testing.T) {
	_, l, _ := restrictedPipe(t)
	if h, err := l.instance(false); !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		if err == nil {
			windows.CloseHandle(h)
		}
		t.Fatalf("second instance with user access: %v, want access denied", err)
	}

	// Control: with full access the same call works.
	_, full, _ := testPipe(t)
	h, err := full.instance(false)
	if err != nil {
		t.Fatalf("second instance with full access: %v", err)
	}
	windows.CloseHandle(h)
}

func TestPipeRoundTripAndIdentity(t *testing.T) {
	name, l, me := testPipe(t)
	type result struct {
		sid     string
		session uint32
		req     Request
		err     error
	}
	got := make(chan result, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			got <- result{err: err}
			return
		}
		defer c.Close()
		var r result
		if r.err = Read(c, &r.req); r.err == nil {
			r.sid, r.session, r.err = c.ClientIdentity()
			Write(c, Response{Nonce: "pong"})
		}
		got <- r
	}()

	c, err := dial(name, 5*time.Second, me)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := Write(c, Request{Op: OpNonce}); err != nil {
		t.Fatal(err)
	}
	var resp Response
	if err := Read(c, &resp); err != nil || resp.Nonce != "pong" {
		t.Fatalf("response %+v %v", resp, err)
	}
	r := <-got
	if r.err != nil || r.req.Op != OpNonce {
		t.Fatalf("server: %+v", r)
	}
	if r.sid != me.String() {
		t.Fatalf("client identity %s, want %s", r.sid, me)
	}
	var session uint32
	windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &session)
	if r.session != session {
		t.Fatalf("session %d, want %d", r.session, session)
	}
}

func TestDialChecksOwner(t *testing.T) {
	name, _, _ := testPipe(t)
	system, _ := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if _, err := dial(name, time.Second, system); !errors.Is(err, ErrNotService) {
		t.Fatalf("pipe not owned by SYSTEM accepted: %v", err)
	}
}

func TestListenRefusesSecondServer(t *testing.T) {
	name, _, me := testPipe(t)
	if _, err := listen(name, "O:"+me.String()+"D:P(A;;GA;;;"+me.String()+")"); err == nil {
		t.Fatal("a second listener on the same pipe name was allowed")
	}
}

func TestCloseUnblocks(t *testing.T) {
	_, l, _ := testPipe(t)
	done := make(chan error, 1)
	go func() { _, err := l.Accept(); done <- err }()
	time.Sleep(100 * time.Millisecond)
	l.Close()
	select {
	case err := <-done:
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("Accept after Close: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not unblock Accept")
	}
}

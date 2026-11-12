package ipc

import (
	"encoding/json"
	"errors"
	"fmt"
	"syscall"
)

// serviceCause is one reason the service could not be reached. Every cause
// also counts as ErrUnavailable.
type serviceCause struct{ msg string }

func (e *serviceCause) Error() string { return e.msg }

// Is makes errors.Is(cause, ErrUnavailable) true.
func (e *serviceCause) Is(target error) bool { return target == ErrUnavailable }

// Why the service could not be reached. Each matches ErrUnavailable too.
var (
	// ErrServiceNotRunning: there is no pipe, it stayed busy, or the
	// service hung up.
	ErrServiceNotRunning error = &serviceCause{"ipc: the Hifaz service is not running"}
	// ErrServiceRefused: the pipe denied access, or the answer was not
	// something this app understands (another version of the service).
	ErrServiceRefused error = &serviceCause{"ipc: the Hifaz service refused the app"}
	// ErrServiceUntrusted: the pipe does not belong to SYSTEM. Nothing was
	// written to it.
	ErrServiceUntrusted error = &serviceCause{"ipc: the pipe does not belong to the Hifaz service"}
)

// ErrNotService means the pipe does not belong to SYSTEM.
var ErrNotService = ErrServiceUntrusted

// errBadFrame: a message on the pipe had an impossible length.
var errBadFrame = errors.New("ipc: invalid message length")

// Windows error numbers from opening the pipe. syscall.Errno is
// windows.Errno, so these compare equal to the windows package's values.
const (
	errFileNotFound = syscall.Errno(2)   // ERROR_FILE_NOT_FOUND: no pipe
	errAccessDenied = syscall.Errno(5)   // ERROR_ACCESS_DENIED
	errSemTimeout   = syscall.Errno(121) // ERROR_SEM_TIMEOUT: the wait ran out
	errPipeBusy     = syscall.Errno(231) // ERROR_PIPE_BUSY, still after the wait
)

// dialFailure says why opening the pipe failed, keeping the original error
// (and its Windows text) underneath.
func dialFailure(err error) error {
	if err == nil || errors.Is(err, ErrUnavailable) {
		return err
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case errFileNotFound, errPipeBusy, errSemTimeout:
			return fmt.Errorf("%w: %w", ErrServiceNotRunning, err)
		case errAccessDenied:
			return fmt.Errorf("%w: %w", ErrServiceRefused, err)
		}
	}
	return fmt.Errorf("%w: %w", ErrUnavailable, err)
}

// transportFailure says why a call on an open connection failed. A
// service's answer (*Error) passes through untouched.
func transportFailure(err error) error {
	var svcErr *Error
	if err == nil || errors.As(err, &svcErr) || errors.Is(err, ErrUnavailable) {
		return err
	}
	var syntax *json.SyntaxError
	var typeErr *json.UnmarshalTypeError
	if errors.Is(err, errBadFrame) || errors.As(err, &syntax) || errors.As(err, &typeErr) {
		return fmt.Errorf("%w: %w", ErrServiceRefused, err)
	}
	return fmt.Errorf("%w: %w", ErrServiceNotRunning, err)
}

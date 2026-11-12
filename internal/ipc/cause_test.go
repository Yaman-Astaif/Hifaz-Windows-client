package ipc

import (
	"encoding/json"
	"errors"
	"io"
	"syscall"
	"testing"
)

// Windows error numbers, spelled out so the test runs on any system.
const (
	errnoFileNotFound = syscall.Errno(2)
	errnoAccessDenied = syscall.Errno(5)
	errnoSemTimeout   = syscall.Errno(121)
	errnoPipeBusy     = syscall.Errno(231)
)

func TestServiceCausesAreUnavailable(t *testing.T) {
	for _, cause := range []error{ErrServiceNotRunning, ErrServiceRefused, ErrServiceUntrusted} {
		if !errors.Is(cause, ErrUnavailable) {
			t.Errorf("%v does not match ErrUnavailable", cause)
		}
		if !errors.Is(cause, cause) {
			t.Errorf("%v does not match itself", cause)
		}
	}
	if errors.Is(ErrServiceRefused, ErrServiceNotRunning) || errors.Is(ErrServiceUntrusted, ErrServiceRefused) {
		t.Error("causes match each other")
	}
	if !errors.Is(ErrNotService, ErrServiceUntrusted) {
		t.Error("ErrNotService is not ErrServiceUntrusted")
	}
}

func TestDialFailure(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want error
	}{
		{errnoFileNotFound, ErrServiceNotRunning},
		{errnoPipeBusy, ErrServiceNotRunning},
		{errnoSemTimeout, ErrServiceNotRunning},
		{errnoAccessDenied, ErrServiceRefused},
		{ErrServiceUntrusted, ErrServiceUntrusted},
	} {
		got := dialFailure(tc.err)
		if !errors.Is(got, tc.want) || !errors.Is(got, ErrUnavailable) {
			t.Errorf("dialFailure(%v) = %v, want %v", tc.err, got, tc.want)
		}
		if !errors.Is(got, tc.err) {
			t.Errorf("dialFailure(%v) = %v lost the cause", tc.err, got)
		}
	}
	other := errors.New("something else")
	got := dialFailure(other)
	if !errors.Is(got, ErrUnavailable) || !errors.Is(got, other) {
		t.Fatalf("dialFailure(other) = %v", got)
	}
	for _, c := range []error{ErrServiceNotRunning, ErrServiceRefused, ErrServiceUntrusted} {
		if errors.Is(got, c) {
			t.Fatalf("dialFailure(other) = %v, matches %v", got, c)
		}
	}
	if dialFailure(nil) != nil {
		t.Fatal("dialFailure(nil) is not nil")
	}
}

func TestTransportFailure(t *testing.T) {
	var syntax error
	if err := json.Unmarshal([]byte("{"), &struct{}{}); err != nil {
		syntax = err
	}
	var typeErr error
	if err := json.Unmarshal([]byte(`{"op":1}`), &Request{}); err != nil {
		typeErr = err
	}
	for _, tc := range []struct {
		err  error
		want error
	}{
		{io.EOF, ErrServiceNotRunning},
		{io.ErrUnexpectedEOF, ErrServiceNotRunning},
		{io.ErrClosedPipe, ErrServiceNotRunning},
		{errBadFrame, ErrServiceRefused},
		{syntax, ErrServiceRefused},
		{typeErr, ErrServiceRefused},
	} {
		got := transportFailure(tc.err)
		if !errors.Is(got, tc.want) || !errors.Is(got, tc.err) {
			t.Errorf("transportFailure(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
	svc := &Error{Code: ErrBadRequest}
	if got := transportFailure(svc); got != svc {
		t.Fatalf("service error changed: %v", got)
	}
}

func TestReadBadFrame(t *testing.T) {
	var r Response
	if err := Read(&zeroReader{}, &r); !errors.Is(err, errBadFrame) {
		t.Fatalf("zero length: %v", err)
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }

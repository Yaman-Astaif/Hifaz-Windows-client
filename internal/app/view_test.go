package app

import (
	"context"
	"errors"
	"fmt"
	"syscall"
	"testing"

	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/ipc"
	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/protocol"
)

func TestViewErrorServiceCauses(t *testing.T) {
	denied := syscall.Errno(5)
	for _, tc := range []struct {
		name string
		err  error
		code string
	}{
		{"unavailable", fmt.Errorf("%w: Access is denied", ipc.ErrUnavailable), ErrServiceUnavailable},
		{"app's own", errServiceUnavailable, ErrServiceUnavailable},
		{"not running", fmt.Errorf("%w: %w", ipc.ErrServiceNotRunning, syscall.Errno(2)), ErrServiceUnavailable},
		{"refused", fmt.Errorf("%w: %w", ipc.ErrServiceRefused, denied), ErrServiceRefused},
		{"refused, wrapped again", fmt.Errorf("enroll: %w", fmt.Errorf("%w: %w", ipc.ErrServiceRefused, denied)), ErrServiceRefused},
		{"untrusted", fmt.Errorf("%w: owner S-1-5-21-9", ipc.ErrServiceUntrusted), ErrServiceUntrusted},
		{"untrusted, old name", ipc.ErrNotService, ErrServiceUntrusted},
		{"service bad_request", &ipc.Error{Code: ipc.ErrBadRequest, Message: "unknown request"}, ErrServiceRefused},
		{"service other", &ipc.Error{Code: ipc.ErrBusy}, ipc.ErrBusy},
		{"server bad_request", &protocol.APIError{Code: "bad_request"}, "bad_request"},
		{"timeout", context.DeadlineExceeded, ErrNetwork},
		{"other", errors.New("boom"), ErrInternal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := viewError(tc.err); got == nil || got.Code != tc.code {
				t.Fatalf("viewError(%v) = %+v, want %q", tc.err, got, tc.code)
			}
		})
	}
}

// Command hifaz is the Hifaz app: the window and the tray icon. It runs as
// the signed-in user and needs no admin rights; the Hifaz service does the
// network part.
package main

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"

	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/app"
	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/ipc"
	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/keystore"
	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/logfile"
	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/protocol"
	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/sysinfo"
	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/ui"
	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/version"
	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/winui"
)

// One app per Windows session.
const instanceMutex = `Local\Hifaz-App-6A1E0C5B`

func main() {
	os.Exit(run())
}

func run() int {
	mutex, err := windows.CreateMutex(nil, false, windows.StringToUTF16Ptr(instanceMutex))
	if err == windows.ERROR_ALREADY_EXISTS {
		winui.ShowExisting()
		return 0
	}
	if err != nil {
		return 1
	}
	defer windows.CloseHandle(mutex)

	base, err := os.UserCacheDir() // %LOCALAPPDATA%
	if err != nil {
		return 1
	}
	dir := filepath.Join(base, "Hifaz")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return 1
	}
	logf, err := logfile.Open(filepath.Join(dir, "app.log"), 1<<20)
	var logOut io.Writer = io.Discard
	if err == nil {
		defer logf.Close()
		logOut = logf
	}
	log := slog.New(slog.NewTextHandler(logOut, nil))
	logFn := func(msg string, args ...any) { log.Info(msg, args...) }
	log.Info("starting", "version", version.Version)

	store, err := keystore.Open(filepath.Join(dir, "accounts.json"), keystore.DPAPI{})
	if err != nil {
		log.Error("opening the key store", "err", err)
		return 1
	}
	service := ipc.NewClient(func() (io.ReadWriteCloser, error) { return ipc.Dial(ipc.PipeName, 5*time.Second) })
	defer service.Close()

	prefsPath := filepath.Join(dir, "settings.json")
	background := len(os.Args) > 1 && os.Args[1] == winui.BackgroundFlag
	if background && !winui.LoadPrefs(prefsPath).Autostart {
		return 0 // started with Windows, but this user turned that off
	}

	ctrl := app.New(app.Options{
		Store: store, Service: service, OSName: sysinfo.OSName(), Log: logFn,
		OnView: winui.OnView,
		HTTPClient: func(cert *tls.Certificate) *http.Client {
			proxy, pac := sysinfo.UserProxy()
			if pac {
				log.Warn("a proxy auto-configuration script is set; it is not used")
			}
			return protocol.NewHTTPClient(proxy, cert)
		},
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { ctrl.Run(ctx); close(done) }()

	err = winui.Run(winui.Options{
		Controller: ctrl, Files: ui.Files, PrefsPath: prefsPath,
		DataDir:    filepath.Join(dir, "WebView2"),
		Background: background, Log: logFn,
	})
	cancel()
	<-done
	if err != nil {
		log.Error("window", "err", err)
		return 1
	}
	return 0
}

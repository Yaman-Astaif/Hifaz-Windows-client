package winui

import (
	"encoding/json"
	"errors"
	"io/fs"
	"mime"
	"net/url"
	"path"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/wailsapp/go-webview2/pkg/edge"
	"golang.org/x/sys/windows"

	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/app"
	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/protocol"
	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/version"
)

// ClassName is the window class; a second start of the app finds the first
// by it.
const ClassName = "HifazWindow"

// The page is served under a reserved name (.invalid never resolves), from
// files embedded in the app; nothing is loaded from anywhere else.
const (
	pageOrigin = "https://hifaz.invalid"
	pageURL    = pageOrigin + "/index.html"
	pageCSP    = "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'none'; frame-ancestors 'none'; form-action 'none'; base-uri 'none'"
)

// Messages the window posts to itself.
const (
	wmAppView = wmApp + 1 // a new view is waiting
	wmAppTray = wmApp + 2 // tray icon events
	wmAppShow = wmApp + 3 // show the window (another start of the app)
	wmAppQuit = wmApp + 4 // the app has signed out: close for good
)

const (
	trayID         = 1
	menuOpen       = 1
	menuConnect    = 2
	menuDisconnect = 3
	menuQuit       = 4
	baseWidth      = 460 // window size at 96 DPI
	baseHeight     = 780
	minWidth       = 380
	minHeight      = 560
)

// Options configure Run.
type Options struct {
	Controller   *app.Controller
	Files        fs.FS  // the page tree (internal/ui)
	PrefsPath    string // the preferences file
	DataDir      string // the WebView2 profile folder
	Background   bool   // started with Windows: stay in the tray
	SetAutostart func(bool) error
	Log          func(msg string, args ...any)
}

// theHost is the one window of the process. The Win32 window procedure is
// a plain function, so it reaches the host through this variable. OnView
// reads it from the app's goroutine, hence atomic.
var theHost atomic.Pointer[windowHost]

type windowHost struct {
	o       Options
	hwnd    windows.HWND
	webview *edge.Chromium
	prefs   Prefs

	icons          [2]windows.Handle // [not connected, connected], tray size
	bigIcons       [2]windows.Handle
	trayAdded      bool
	taskbarCreated uint32

	// Set by the app's goroutine, read on the window thread.
	mu       sync.Mutex
	view     app.View
	quitDone bool

	quitting bool
}

// Run shows the window (unless Background) and runs the message loop until
// the user quits. It must be called from the main goroutine.
func Run(o Options) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	pSetProcessDpiAwarenessContext.Call(dpiPerMonitorV2)

	h := &windowHost{o: o, prefs: LoadPrefs(o.PrefsPath)}
	if h.o.Log == nil {
		h.o.Log = func(string, ...any) {}
	}
	theHost.Store(h)
	if err := h.createWindow(); err != nil {
		return err
	}
	if err := h.createWebView(); err != nil {
		messageBox(version.Name, text(h.prefs.Lang, "noWebView"))
		pDestroyWindow.Call(uintptr(h.hwnd))
		return err
	}
	h.addTray()
	if !o.Background {
		h.show()
	}
	var m msg
	for {
		r, _, _ := pGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		pTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		pDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
	return nil
}

// OnView is the app's OnView callback: it may be called from any goroutine.
func OnView(v app.View) {
	h := theHost.Load()
	if h == nil {
		return
	}
	h.mu.Lock()
	h.view = v
	hwnd := h.hwnd
	h.mu.Unlock()
	if hwnd != 0 { // before the window exists, the page asks for it when ready
		postMessage(hwnd, wmAppView, 0, 0)
	}
}

// ShowExisting asks a running instance to show its window; it reports
// whether one was found.
func ShowExisting() bool {
	w, _, _ := pFindWindowW.Call(uintptr(unsafe.Pointer(utf16(ClassName))), 0)
	if w == 0 {
		return false
	}
	postMessage(windows.HWND(w), wmAppShow, 0, 0)
	return true
}

// --- window ----------------------------------------------------------------------

func (h *windowHost) createWindow() error {
	var instance windows.Handle
	if err := windows.GetModuleHandleEx(0, nil, &instance); err != nil {
		return err
	}
	cursor, _, _ := pLoadCursorW.Call(0, idcArrow)
	wc := wndClassEx{
		Size: uint32(unsafe.Sizeof(wndClassEx{})), WndProc: windows.NewCallback(wndProc),
		Instance: instance, Cursor: windows.Handle(cursor), ClassName: utf16(ClassName),
	}
	if r, _, err := pRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
		return err
	}
	tc, _, _ := pRegisterWindowMessageW.Call(uintptr(unsafe.Pointer(utf16("TaskbarCreated"))))
	h.taskbarCreated = uint32(tc)
	w, _, err := pCreateWindowExW.Call(0, uintptr(unsafe.Pointer(utf16(ClassName))),
		uintptr(unsafe.Pointer(utf16(version.Name))), wsOverlappedWindow,
		cwUseDefault, cwUseDefault, baseWidth, baseHeight, 0, 0, uintptr(instance), 0)
	if w == 0 {
		return err
	}
	h.mu.Lock()
	h.hwnd = windows.HWND(w)
	h.mu.Unlock()
	h.scaleWindow()
	h.makeIcons()
	pSendMessageW.Call(uintptr(h.hwnd), wmSetIcon, iconSmall, uintptr(h.icons[0]))
	pSendMessageW.Call(uintptr(h.hwnd), wmSetIcon, iconBig, uintptr(h.bigIcons[0]))
	return nil
}

func (h *windowHost) dpi() int {
	d, _, _ := pGetDpiForWindow.Call(uintptr(h.hwnd))
	if d == 0 {
		return 96
	}
	return int(d)
}

func (h *windowHost) scale(v int) int { return v * h.dpi() / 96 }

// scaleWindow sizes the window for the monitor's DPI.
func (h *windowHost) scaleWindow() {
	pSetWindowPos.Call(uintptr(h.hwnd), 0, 0, 0, uintptr(h.scale(baseWidth)), uintptr(h.scale(baseHeight)),
		swpNoZOrder|swpNoActivate|0x0002 /* SWP_NOMOVE */)
}

func (h *windowHost) makeIcons() {
	for _, i := range h.icons {
		destroyIcon(i)
	}
	for _, i := range h.bigIcons {
		destroyIcon(i)
	}
	small, _, _ := pGetSystemMetricsForDpi.Call(smCxSmIcon, uintptr(h.dpi()))
	big, _, _ := pGetSystemMetricsForDpi.Call(smCxIcon, uintptr(h.dpi()))
	if small == 0 {
		small = 16
	}
	if big == 0 {
		big = 32
	}
	for i, connected := range []bool{false, true} {
		h.icons[i] = makeIcon(int(small), connected)
		h.bigIcons[i] = makeIcon(int(big), connected)
	}
}

func (h *windowHost) show() {
	pShowWindow.Call(uintptr(h.hwnd), swRestore)
	pShowWindow.Call(uintptr(h.hwnd), swShow)
	pSetForegroundWindow.Call(uintptr(h.hwnd))
	if h.webview != nil {
		h.webview.Focus()
	}
}

func (h *windowHost) hide() { pShowWindow.Call(uintptr(h.hwnd), swHide) }

func (h *windowHost) visible() bool {
	r, _, _ := pIsWindowVisible.Call(uintptr(h.hwnd))
	return r != 0
}

// quit signs out through the app, then closes the window.
func (h *windowHost) quit() {
	if h.quitting {
		return
	}
	h.quitting = true
	h.o.Controller.Quit(func() { postMessage(h.hwnd, wmAppQuit, 0, 0) })
}

func wndProc(hwnd windows.HWND, m uint32, w, l uintptr) uintptr {
	h := theHost.Load()
	if h == nil || hwnd != h.hwnd { // also during CreateWindowEx, before hwnd is set
		r, _, _ := pDefWindowProcW.Call(uintptr(hwnd), uintptr(m), w, l)
		return r
	}
	switch m {
	case wmAppView:
		h.pushView()
		return 0
	case wmAppTray:
		h.onTray(uint32(l & 0xffff))
		return 0
	case wmAppShow:
		h.show()
		return 0
	case wmAppQuit:
		pDestroyWindow.Call(uintptr(hwnd))
		return 0
	case wmSize:
		if h.webview != nil {
			h.webview.Resize()
		}
		return 0
	case wmDpiChanged:
		// Take the size Windows suggests for the new monitor.
		r := (*rect)(osPointer(l))
		pSetWindowPos.Call(uintptr(hwnd), 0, uintptr(r.Left), uintptr(r.Top),
			uintptr(r.Right-r.Left), uintptr(r.Bottom-r.Top), swpNoZOrder|swpNoActivate)
		h.makeIcons()
		h.updateTray()
		return 0
	case wmGetMinMaxInfo:
		mm := (*minMaxInfo)(osPointer(l))
		mm.MinTrackSize = point{int32(h.scale(minWidth)), int32(h.scale(minHeight))}
		return 0
	case wmClose:
		h.hide() // the app keeps running in the tray
		return 0
	case wmQueryEndSession:
		return 1
	case wmEndSession:
		if w != 0 { // Windows is signing out or shutting down: sign out first
			done := make(chan struct{})
			h.o.Controller.Quit(func() { close(done) })
			<-done
		}
		return 0
	case wmDestroy:
		h.removeTray()
		pPostQuitMessage.Call(0)
		return 0
	}
	if h.taskbarCreated != 0 && m == h.taskbarCreated { // Explorer restarted
		h.trayAdded = false
		h.addTray()
	}
	r, _, _ := pDefWindowProcW.Call(uintptr(hwnd), uintptr(m), w, l)
	return r
}

// --- web view ---------------------------------------------------------------------

func (h *windowHost) createWebView() error {
	wv := edge.NewChromium()
	wv.DataPath = h.o.DataDir
	wv.SetErrorCallback(func(err error) { h.o.Log("web view", "err", err) })
	wv.MessageCallback = func(message string, _ *edge.ICoreWebView2, _ *edge.ICoreWebView2WebMessageReceivedEventArgs) {
		h.onPageMessage(message)
	}
	wv.WebResourceRequestedCallback = h.serve
	wv.ProcessFailedCallback = func(*edge.ICoreWebView2, *edge.ICoreWebView2ProcessFailedEventArgs) {
		h.o.Log("the web view process failed; reloading")
		wv.Navigate(pageURL)
	}
	if !wv.Embed(uintptr(h.hwnd)) {
		return errors.New("WebView2 is not available")
	}
	h.webview = wv
	if s, err := wv.GetSettings(); err == nil {
		s.PutAreDevToolsEnabled(false)
		s.PutAreDefaultContextMenusEnabled(false)
		s.PutIsStatusBarEnabled(false)
		s.PutIsZoomControlEnabled(false)
		s.PutAreHostObjectsAllowed(false)
		s.PutIsSwipeNavigationEnabled(false)
		s.PutAreBrowserAcceleratorKeysEnabled(false)
		s.PutAreDefaultScriptDialogsEnabled(false)
	}
	// Passwords typed into the window are never stored by the browser.
	wv.PutIsPasswordAutosaveEnabled(false)
	wv.PutIsGeneralAutofillEnabled(false)
	wv.AddWebResourceRequestedFilter(pageOrigin+"/*", edge.COREWEBVIEW2_WEB_RESOURCE_CONTEXT_ALL)
	wv.Resize()
	wv.Navigate(pageURL)
	return nil
}

// serve answers the page's requests from the embedded files.
func (h *windowHost) serve(req *edge.ICoreWebView2WebResourceRequest, args *edge.ICoreWebView2WebResourceRequestedEventArgs) {
	status, reason, body, ctype := 404, "Not Found", []byte(nil), "text/plain"
	if raw, err := req.GetUri(); err == nil {
		if u, err := url.Parse(raw); err == nil && strings.HasPrefix(raw, pageOrigin+"/") {
			name := strings.TrimPrefix(path.Clean(u.Path), "/")
			if data, err := fs.ReadFile(h.o.Files, name); err == nil {
				status, reason, body = 200, "OK", data
				if t := mime.TypeByExtension(path.Ext(name)); t != "" {
					ctype = t
				}
			}
		}
	}
	headers := "Content-Type: " + ctype + "\r\nContent-Security-Policy: " + pageCSP +
		"\r\nX-Content-Type-Options: nosniff\r\nCache-Control: no-store"
	resp, err := h.webview.Environment().CreateWebResourceResponse(body, status, reason, headers)
	if err != nil {
		h.o.Log("serving the page", "err", err)
		return
	}
	defer resp.Release()
	args.PutResponse(resp)
}

// onPageMessage handles a message from the page (on the window thread).
func (h *windowHost) onPageMessage(raw string) {
	h.mu.Lock()
	allowed := allowedDownload(&h.view)
	h.mu.Unlock()
	r, ok := route(raw, allowed)
	if !ok {
		return
	}
	switch {
	case r.ready:
		h.pushApp()
		h.pushPrefs()
		h.pushView()
	case r.prefs != nil:
		h.setPrefs(*r.prefs)
	case r.url != "":
		windows.ShellExecute(windows.Handle(h.hwnd), utf16("open"), utf16(r.url), nil, nil, swShow)
	case r.action != nil:
		h.o.Controller.Do(*r.action)
	}
}

func (h *windowHost) eval(fn string, v any) {
	if h.webview == nil {
		return
	}
	data, err := json.Marshal(v) // JSON is a valid JavaScript expression
	if err != nil {
		return
	}
	h.webview.Eval("window.hifaz && window.hifaz." + fn + "(" + string(data) + ")")
}

func (h *windowHost) pushView() {
	h.mu.Lock()
	v := h.view
	h.mu.Unlock()
	h.eval("onView", v)
	h.updateTray()
}

func (h *windowHost) pushPrefs() { h.eval("onPrefs", h.prefs) }

func (h *windowHost) pushApp() {
	h.eval("onApp", map[string]string{"version": version.Version, "developer": version.Developer,
		"min_server": protocol.MinServerVersion})
}

func (h *windowHost) setPrefs(p Prefs) {
	h.prefs = p
	if err := SavePrefs(h.o.PrefsPath, p); err != nil {
		h.o.Log("saving preferences failed", "err", err)
	}
	h.pushPrefs()
	h.updateTray()
}

// --- tray ---------------------------------------------------------------------------

func (h *windowHost) connected() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.view.Screen == app.ScreenConnected
}

func (h *windowHost) trayData() *notifyIconData {
	d := &notifyIconData{Size: uint32(unsafe.Sizeof(notifyIconData{})), Wnd: h.hwnd, ID: trayID,
		Flags: nifMessage | nifIcon | nifTip | nifShowTip, CallbackMessage: wmAppTray}
	tip := "disconnected"
	d.Icon = h.icons[0]
	if h.connected() {
		tip, d.Icon = "connected", h.icons[1]
	}
	s, _ := windows.UTF16FromString(text(h.prefs.Lang, tip))
	copy(d.Tip[:len(d.Tip)-1], s)
	return d
}

func (h *windowHost) addTray() {
	d := h.trayData()
	if r, _, _ := pShellNotifyIconW.Call(nimAdd, uintptr(unsafe.Pointer(d))); r == 0 {
		h.o.Log("adding the tray icon failed")
		return
	}
	d.Version = notifyIconV4
	pShellNotifyIconW.Call(nimSetVersion, uintptr(unsafe.Pointer(d)))
	h.trayAdded = true
}

func (h *windowHost) updateTray() {
	if !h.trayAdded {
		return
	}
	pShellNotifyIconW.Call(nimModify, uintptr(unsafe.Pointer(h.trayData())))
	icon := h.icons[0]
	if h.connected() {
		icon = h.icons[1]
	}
	pSendMessageW.Call(uintptr(h.hwnd), wmSetIcon, iconSmall, uintptr(icon))
}

func (h *windowHost) removeTray() {
	if h.trayAdded {
		pShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(h.trayData())))
		h.trayAdded = false
	}
}

func (h *windowHost) onTray(event uint32) {
	switch event {
	case ninSelect, ninKeySelect, wmLButtonUp:
		if h.visible() {
			h.hide()
		} else {
			h.show()
		}
	case wmContextMenu:
		h.trayMenu()
	}
}

func (h *windowHost) trayMenu() {
	menu, _, _ := pCreatePopupMenu.Call()
	if menu == 0 {
		return
	}
	defer pDestroyMenu.Call(menu)
	add := func(id uintptr, key string, flags uintptr) {
		pAppendMenuW.Call(menu, mfString|flags, id, uintptr(unsafe.Pointer(utf16(text(h.prefs.Lang, key)))))
	}
	add(menuOpen, "open", 0)
	pAppendMenuW.Call(menu, mfSeparator, 0, 0)
	if h.connected() {
		add(menuDisconnect, "disconnect", 0)
	} else {
		add(menuConnect, "connect", 0)
	}
	pAppendMenuW.Call(menu, mfSeparator, 0, 0)
	add(menuQuit, "quit", 0)
	pSetMenuDefaultItem.Call(menu, menuOpen, 0)

	var pt point
	pGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	// The menu closes properly only if the window is in the foreground.
	pSetForegroundWindow.Call(uintptr(h.hwnd))
	cmd, _, _ := pTrackPopupMenu.Call(menu, tpmRightButton|tpmReturnCmd|tpmBottomAlign,
		uintptr(pt.X), uintptr(pt.Y), 0, uintptr(h.hwnd), 0)
	postMessage(h.hwnd, wmNull, 0, 0)
	switch cmd {
	case menuOpen, menuConnect:
		h.show()
	case menuDisconnect:
		h.o.Controller.Do(app.Action{Name: "disconnect"})
	case menuQuit:
		h.quit()
	}
}

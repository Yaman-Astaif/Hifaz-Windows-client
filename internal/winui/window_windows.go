package winui

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"unsafe"

	"github.com/wailsapp/go-webview2/pkg/edge"
	"golang.org/x/sys/windows"

	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/icon"

	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/app"
	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/protocol"
	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/version"
)

// ClassName is the window class; a second start of the app finds the first
// by it.
const ClassName = "HifazWindow"

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

	icons               [2]windows.Handle // tray: [not connected, connected]
	appIcons            [2]windows.Handle // the window's: [small, big]
	trayAdded           bool
	lastTrayView        app.View
	blockedNotification bool
	notificationPage    string
	taskbarCreated      uint32

	quitting          bool
	moving            bool
	dpiChangedOnMove  bool
	dpiPendingRestore bool
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
		h.o.Log("creating the window failed", "err", err)
		return err
	}
	h.o.Log("window created")
	if err := h.createWebView(); err != nil {
		h.o.Log("the web view could not be created", "err", err)
		messageBox(version.Name, text(h.prefs.Lang, "noWebView"))
		pDestroyWindow.Call(uintptr(h.hwnd))
		return err
	}
	h.addTray()
	hwnd := h.hwnd
	views.attach(func() { postMessage(hwnd, wmAppView, 0, 0) })
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

// views is the app's latest view; see viewBox.
var views = newViewBox()

// OnView is the app's OnView callback: it may be called from any
// goroutine, also before Run has created the window.
func OnView(v app.View) { views.set(v) }

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
		uintptr(unsafe.Pointer(utf16(version.Name))), wsWindow,
		cwUseDefault, cwUseDefault, baseWidth, baseHeight, 0, 0, uintptr(instance), 0)
	if w == 0 {
		return err
	}
	h.hwnd = windows.HWND(w)
	h.placeWindow()
	h.makeIcons()
	return nil
}

func (h *windowHost) dpi() int {
	d, _, _ := pGetDpiForWindow.Call(uintptr(h.hwnd))
	if d == 0 {
		return 96
	}
	return int(d)
}

// frame is what the title bar and borders add to the client area at dpi.
func frame(dpi int) (w, h int32) {
	var r rect
	pAdjustWindowRectExForDpi.Call(uintptr(unsafe.Pointer(&r)), wsWindow, 0, 0, uintptr(dpi))
	return r.Right - r.Left, r.Bottom - r.Top
}

// workArea is the work area of the window's monitor (without the taskbar);
// empty if it cannot be found.
func workArea(hwnd windows.HWND) rect {
	mon, _, _ := pMonitorFromWindow.Call(uintptr(hwnd), 2 /* MONITOR_DEFAULTTONEAREST */)
	return monitorWork(mon)
}

// workAreaAt is the work area of the monitor nearest to r; empty if it
// cannot be found.
func workAreaAt(r rect) rect {
	mon, _, _ := pMonitorFromRect.Call(uintptr(unsafe.Pointer(&r)), 2 /* MONITOR_DEFAULTTONEAREST */)
	return monitorWork(mon)
}

func monitorWork(mon uintptr) rect {
	if mon == 0 {
		return rect{}
	}
	mi := monitorInfo{Size: uint32(unsafe.Sizeof(monitorInfo{}))}
	if r, _, _ := pGetMonitorInfoW.Call(mon, uintptr(unsafe.Pointer(&mi))); r == 0 {
		return rect{}
	}
	return mi.Work
}

// placeWindow sizes the window for the monitor's DPI, no larger than the
// monitor's work area, and centres it there.
func (h *windowHost) placeWindow() {
	dpi := h.dpi()
	fw, fh := frame(dpi)
	r := placement(dpi, fw, fh, workArea(h.hwnd))
	pSetWindowPos.Call(uintptr(h.hwnd), 0, uintptr(r.Left), uintptr(r.Top),
		uintptr(r.Right-r.Left), uintptr(r.Bottom-r.Top), swpNoZOrder|swpNoActivate)
}

// applyDPI sizes the window for its monitor while keeping the cursor-relative
// position Windows supplies during a drag.
func (h *windowHost) applyDPI(s rect, dpi int) {
	fw, fh := frame(dpi)
	r := dpiChanged(s, dpi, fw, fh, workAreaAt(s), h.moving)
	pSetWindowPos.Call(uintptr(h.hwnd), 0, uintptr(r.Left), uintptr(r.Top),
		uintptr(r.Right-r.Left), uintptr(r.Bottom-r.Top), swpNoZOrder|swpNoActivate)
}

func (h *windowHost) fitCurrentMonitor() {
	var r rect
	if ok, _, _ := pGetWindowRect.Call(uintptr(h.hwnd), uintptr(unsafe.Pointer(&r))); ok != 0 {
		h.applyDPI(r, h.dpi())
	}
}

// makeIcons draws the icons for the window's current scaling. The old ones
// are destroyed only once the window (and, after updateTray, the shell)
// holds the new ones.
func (h *windowHost) makeIcons() {
	oldTray, oldApp := h.icons, h.appIcons
	small, _, _ := pGetSystemMetricsForDpi.Call(smCxSmIcon, uintptr(h.dpi()))
	big, _, _ := pGetSystemMetricsForDpi.Call(smCxIcon, uintptr(h.dpi()))
	if small == 0 {
		small = 16
	}
	if big == 0 {
		big = 32
	}
	h.icons = [2]windows.Handle{makeIcon(int(small), icon.Disconnected), makeIcon(int(small), icon.Connected)}
	h.appIcons = [2]windows.Handle{makeIcon(int(small), icon.App), makeIcon(int(big), icon.App)}
	pSendMessageW.Call(uintptr(h.hwnd), wmSetIcon, iconSmall, uintptr(h.appIcons[0]))
	pSendMessageW.Call(uintptr(h.hwnd), wmSetIcon, iconBig, uintptr(h.appIcons[1]))
	if h.trayAdded {
		h.updateTray()
	}
	for _, i := range append(oldTray[:], oldApp[:]...) {
		destroyIcon(i)
	}
}

// show restores a minimized window and shows a hidden one.
func (h *windowHost) show() {
	pShowWindow.Call(uintptr(h.hwnd), swRestore)
	pSetForegroundWindow.Call(uintptr(h.hwnd))
	h.fitWebView(true)
	if h.webview != nil {
		h.webview.Focus()
	}
}

func (h *windowHost) hide() {
	h.fitWebView(false)
	pShowWindow.Call(uintptr(h.hwnd), swHide)
}

// fitWebView makes the web view fill the window and sets whether it is
// visible: WebView2 is told explicitly whenever the window is shown,
// hidden or minimized, since the window starts hidden.
func (h *windowHost) fitWebView(visible bool) {
	if h.webview == nil {
		return
	}
	if !visible {
		h.webview.Hide()
		return
	}
	h.webview.Resize()
	if err := h.webview.Show(); err != nil {
		h.o.Log("showing the web view", "err", err)
	}
}

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
		if w == 2 /* SIZE_MAXIMIZED */ {
			// Maximized anyway (ShowWindow from a shortcut set to "Run:
			// Maximized", or another program): back to the fixed size.
			pShowWindow.Call(uintptr(hwnd), swRestore)
			return 0
		}
		if w == 0 /* SIZE_RESTORED */ && h.dpiPendingRestore {
			h.dpiPendingRestore = false // SetWindowPos can send WM_SIZE again.
			h.fitCurrentMonitor()
			h.makeIcons()
		}
		h.fitWebView(w != 1 /* SIZE_MINIMIZED */)
		return 0
	case wmSysCommand:
		// The window has one fixed size: no sizing, no maximizing.
		if !allowSysCommand(w) {
			return 0
		}
	case wmEnterSizeMove:
		h.moving = true
	case wmExitSizeMove:
		h.moving = false
		if h.dpiChangedOnMove {
			h.dpiChangedOnMove = false
			h.fitCurrentMonitor()
		}
	case wmDpiChanged:
		if iconic, _, _ := pIsIconic.Call(uintptr(hwnd)); iconic != 0 {
			h.dpiPendingRestore = true
			return 0
		}
		h.dpiPendingRestore = false
		h.dpiChangedOnMove = h.moving
		h.applyDPI(*(*rect)(osPointer(l)), int(w>>16&0xffff))
		h.makeIcons()
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
	// A local debugging port, only when asked for (see debugEnv).
	debugArg := debugPortArg(os.Getenv(debugEnv))
	if debugArg != "" {
		wv.AdditionalBrowserArgs = []string{debugArg}
		h.o.Log("the page can be inspected on a local debugging port", "arg", debugArg)
	}
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
	wv.SetBackgroundColour(0xf6, 0xf5, 0xef, 0xff) // the page's colour: no white flash
	if s, err := wv.GetSettings(); err == nil {
		s.PutAreDevToolsEnabled(debugArg != "")
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
	h.fitWebView(true)
	wv.Navigate(pageURL)
	var rc rect
	pGetClientRect.Call(uintptr(h.hwnd), uintptr(unsafe.Pointer(&rc)))
	h.o.Log("web view ready; loading the page", "width", rc.Right-rc.Left, "height", rc.Bottom-rc.Top)
	return nil
}

// serve answers the page's requests from the embedded files.
func (h *windowHost) serve(req *edge.ICoreWebView2WebResourceRequest, args *edge.ICoreWebView2WebResourceRequestedEventArgs) {
	status, reason, body, ctype := 404, "Not Found", []byte(nil), "text/plain"
	raw, err := req.GetUri()
	if err == nil && strings.EqualFold(raw, pageOrigin+"/favicon.ico") {
		status, reason, err = 204, "No Content", nil // the window has its own icon
	} else if err == nil {
		var b []byte
		if b, ctype, err = resolvePage(h.o.Files, raw); err == nil {
			status, reason, body = 200, "OK", b
		}
	}
	if status == 404 {
		ctype = "text/plain"
		h.o.Log("page request not served", "uri", raw, "err", err)
	}
	headers := "Content-Type: " + ctype + "\r\nContent-Security-Policy: " + pageCSP +
		"\r\nX-Content-Type-Options: nosniff\r\nCache-Control: no-store"
	// The library's CreateWebResourceResponse drops the content it is given
	// (it assigns the stream to a shadowed variable), so the response is
	// created empty and the content set with PutByteContent, which works.
	resp, err := h.webview.Environment().CreateWebResourceResponse(nil, status, reason, headers)
	if err != nil {
		h.o.Log("serving the page", "err", err)
		return
	}
	defer resp.Release()
	if len(body) > 0 {
		if err := resp.PutByteContent(body); err != nil {
			h.o.Log("serving the page", "err", err)
			return
		}
	}
	args.PutResponse(resp)
}

// onPageMessage handles a message from the page (on the window thread).
func (h *windowHost) onPageMessage(raw string) {
	v := views.get()
	allowed := allowedDownload(&v)
	r, ok := route(raw, allowed)
	if !ok {
		return
	}
	switch {
	case r.ready:
		h.o.Log("page loaded")
		h.pushApp()
		h.pushPrefs()
		h.pushView()
	case r.prefs != nil:
		h.setPrefs(*r.prefs)
	case r.err != "":
		h.o.Log("page error", "err", r.err)
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
	v := views.get()
	h.eval("onView", v)
	h.updateTray()
	key, page := connectionNotification(h.lastTrayView, v, h.blockedNotification)
	h.lastTrayView = v
	if v.Screen != app.ScreenConnected || key == "notifyRestored" {
		h.blockedNotification = false
	}
	iconic, _, _ := pIsIconic.Call(uintptr(h.hwnd))
	if key != "" && h.prefs.Notifications && (!h.visible() || iconic != 0) && h.showNotification(key, page) {
		h.blockedNotification = key == "notifyBlocked"
	}
}

func (h *windowHost) pushPrefs() { h.eval("onPrefs", h.prefs) }

func (h *windowHost) pushApp() {
	h.eval("onApp", map[string]string{"version": version.Version, "developer": version.Developer,
		"min_server": protocol.MinServerVersion})
}

func (h *windowHost) setPrefs(p Prefs) {
	h.prefs = p
	if !p.Notifications {
		h.blockedNotification = false
	}
	if err := SavePrefs(h.o.PrefsPath, p); err != nil {
		h.o.Log("saving preferences failed", "err", err)
	}
	h.pushPrefs()
	h.updateTray()
}

// --- tray ---------------------------------------------------------------------------

func (h *windowHost) connected() bool {
	return views.get().Screen == app.ScreenConnected
}

func (h *windowHost) trayData() *notifyIconData {
	d := &notifyIconData{Size: uint32(unsafe.Sizeof(notifyIconData{})), Wnd: h.hwnd, ID: trayID,
		Flags: nifMessage | nifIcon | nifTip | nifShowTip, CallbackMessage: wmAppTray}
	tip, up := trayState(views.get())
	d.Icon = h.icons[0]
	if up {
		d.Icon = h.icons[1]
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
}

func (h *windowHost) removeTray() {
	if h.trayAdded {
		pShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(h.trayData())))
		h.trayAdded = false
	}
}

func (h *windowHost) showNotification(key, page string) bool {
	if !h.trayAdded {
		return false
	}
	d := h.trayData()
	d.Flags = nifInfo
	d.InfoFlags = 1 | 0x80 // NIIF_INFO | NIIF_RESPECT_QUIET_TIME
	message, _ := windows.UTF16FromString(text(h.prefs.Lang, key))
	title, _ := windows.UTF16FromString(text(h.prefs.Lang, "notifyTitle"))
	copy(d.Info[:len(d.Info)-1], message)
	copy(d.InfoTitle[:len(d.InfoTitle)-1], title)
	if r, _, _ := pShellNotifyIconW.Call(nimModify, uintptr(unsafe.Pointer(d))); r == 0 {
		return false
	}
	h.notificationPage = page
	return true
}

func (h *windowHost) onTray(event uint32) {
	switch event {
	case ninBalloonUserClick:
		h.show()
		h.eval("showPage", h.notificationPage)
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

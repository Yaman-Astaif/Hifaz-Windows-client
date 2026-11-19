package winui

import (
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/icon"
)

// The few Win32 calls the window and tray need, beyond x/sys/windows.
var (
	user32  = windows.NewLazySystemDLL("user32.dll")
	gdi32   = windows.NewLazySystemDLL("gdi32.dll")
	shell32 = windows.NewLazySystemDLL("shell32.dll")

	pRegisterClassExW              = user32.NewProc("RegisterClassExW")
	pCreateWindowExW               = user32.NewProc("CreateWindowExW")
	pDefWindowProcW                = user32.NewProc("DefWindowProcW")
	pDestroyWindow                 = user32.NewProc("DestroyWindow")
	pShowWindow                    = user32.NewProc("ShowWindow")
	pIsWindowVisible               = user32.NewProc("IsWindowVisible")
	pSetForegroundWindow           = user32.NewProc("SetForegroundWindow")
	pGetMessageW                   = user32.NewProc("GetMessageW")
	pTranslateMessage              = user32.NewProc("TranslateMessage")
	pDispatchMessageW              = user32.NewProc("DispatchMessageW")
	pPostMessageW                  = user32.NewProc("PostMessageW")
	pSendMessageW                  = user32.NewProc("SendMessageW")
	pPostQuitMessage               = user32.NewProc("PostQuitMessage")
	pRegisterWindowMessageW        = user32.NewProc("RegisterWindowMessageW")
	pFindWindowW                   = user32.NewProc("FindWindowW")
	pLoadCursorW                   = user32.NewProc("LoadCursorW")
	pCreatePopupMenu               = user32.NewProc("CreatePopupMenu")
	pAppendMenuW                   = user32.NewProc("AppendMenuW")
	pSetMenuDefaultItem            = user32.NewProc("SetMenuDefaultItem")
	pTrackPopupMenu                = user32.NewProc("TrackPopupMenu")
	pDestroyMenu                   = user32.NewProc("DestroyMenu")
	pGetCursorPos                  = user32.NewProc("GetCursorPos")
	pCreateIconIndirect            = user32.NewProc("CreateIconIndirect")
	pDestroyIcon                   = user32.NewProc("DestroyIcon")
	pGetDpiForWindow               = user32.NewProc("GetDpiForWindow")
	pGetSystemMetricsForDpi        = user32.NewProc("GetSystemMetricsForDpi")
	pSetProcessDpiAwarenessContext = user32.NewProc("SetProcessDpiAwarenessContext")
	pSetWindowPos                  = user32.NewProc("SetWindowPos")
	pMessageBoxW                   = user32.NewProc("MessageBoxW")
	pGetWindowRect                 = user32.NewProc("GetWindowRect")
	pIsIconic                      = user32.NewProc("IsIconic")
	pGetClientRect                 = user32.NewProc("GetClientRect")
	pMonitorFromWindow             = user32.NewProc("MonitorFromWindow")
	pMonitorFromRect               = user32.NewProc("MonitorFromRect")
	pGetMonitorInfoW               = user32.NewProc("GetMonitorInfoW")
	pAdjustWindowRectExForDpi      = user32.NewProc("AdjustWindowRectExForDpi")
	pCreateDIBSection              = gdi32.NewProc("CreateDIBSection")
	pCreateBitmap                  = gdi32.NewProc("CreateBitmap")
	pDeleteObject                  = gdi32.NewProc("DeleteObject")
	pShellNotifyIconW              = shell32.NewProc("Shell_NotifyIconW")
)

const (
	wmDestroy         = 0x0002
	wmSize            = 0x0005
	wmClose           = 0x0010
	wmQueryEndSession = 0x0011
	wmEndSession      = 0x0016
	wmSetIcon         = 0x0080
	wmCommand         = 0x0111
	wmSysCommand      = 0x0112
	wmNull            = 0x0000
	wmContextMenu     = 0x007B
	wmLButtonUp       = 0x0202
	wmEnterSizeMove   = 0x0231
	wmExitSizeMove    = 0x0232
	wmDpiChanged      = 0x02E0
	wmApp             = 0x8000

	// A fixed window: title bar, system menu, minimize and close. No resize
	// border (no Snap, no edge dragging) and no maximize box (DefWindowProc
	// ignores a caption double-click); WM_SYSCOMMAND refuses the rest.
	wsWindow     = 0x00CA0000 // WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX
	cwUseDefault = 0x80000000 // CW_USEDEFAULT

	swHide    = 0
	swShow    = 5
	swRestore = 9

	mfString    = 0x0000
	mfGrayed    = 0x0001
	mfSeparator = 0x0800

	tpmRightButton = 0x0002
	tpmReturnCmd   = 0x0100
	tpmBottomAlign = 0x0020

	iconSmall = 0
	iconBig   = 1

	smCxSmIcon = 49
	smCxIcon   = 11

	mbIconError = 0x10

	swpNoZOrder   = 0x0004
	swpNoActivate = 0x0010

	nimAdd              = 0
	nimModify           = 1
	nimDelete           = 2
	nimSetVersion       = 4
	nifMessage          = 0x01
	nifIcon             = 0x02
	nifTip              = 0x04
	nifInfo             = 0x10
	ninBalloonUserClick = 0x0405
	nifShowTip          = 0x80
	ninSelect           = 0x0400
	ninKeySelect        = 0x0401
	notifyIconV4        = 4

	idcArrow = 32512
)

// DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
var dpiPerMonitorV2 = ^uintptr(3) // (HANDLE)-4

type wndClassEx struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   windows.Handle
	Icon       windows.Handle
	Cursor     windows.Handle
	Background windows.Handle
	MenuName   *uint16
	ClassName  *uint16
	IconSm     windows.Handle
}

type monitorInfo struct {
	Size    uint32
	Monitor rect
	Work    rect
	Flags   uint32
}

type msg struct {
	HWnd    windows.HWND
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      point
	private uint32
}

type iconInfo struct {
	FIcon    int32
	XHotspot uint32
	YHotspot uint32
	HbmMask  windows.Handle
	HbmColor windows.Handle
}

type bitmapInfoHeader struct {
	Size          uint32
	Width         int32
	Height        int32
	Planes        uint16
	BitCount      uint16
	Compression   uint32
	SizeImage     uint32
	XPelsPerMeter int32
	YPelsPerMeter int32
	ClrUsed       uint32
	ClrImportant  uint32
}

type notifyIconData struct {
	Size            uint32
	Wnd             windows.HWND
	ID              uint32
	Flags           uint32
	CallbackMessage uint32
	Icon            windows.Handle
	Tip             [128]uint16
	State           uint32
	StateMask       uint32
	Info            [256]uint16
	Version         uint32
	InfoTitle       [64]uint16
	InfoFlags       uint32
	GUIDItem        windows.GUID
	BalloonIcon     windows.Handle
}

// osPointer turns an address Windows passed in a message parameter into a
// pointer. The memory belongs to Windows for the duration of the message,
// not to Go.
func osPointer(addr uintptr) unsafe.Pointer { return unsafe.Add(unsafe.Pointer(nil), addr) }

func utf16(s string) *uint16 {
	p, err := windows.UTF16PtrFromString(s)
	if err != nil {
		p, _ = windows.UTF16PtrFromString("")
	}
	return p
}

func postMessage(hwnd windows.HWND, m uint32, w, l uintptr) {
	pPostMessageW.Call(uintptr(hwnd), uintptr(m), w, l)
}

// makeIcon builds a Windows icon of the Hifaz icon in style s.
func makeIcon(size int, s icon.Style) windows.Handle {
	px := icon.Pixels(size, s)
	hdr := bitmapInfoHeader{Size: uint32(unsafe.Sizeof(bitmapInfoHeader{})), Width: int32(size),
		Height: -int32(size), Planes: 1, BitCount: 32} // top-down
	var bits unsafe.Pointer
	color, _, _ := pCreateDIBSection.Call(0, uintptr(unsafe.Pointer(&hdr)), 0, uintptr(unsafe.Pointer(&bits)), 0, 0)
	if color == 0 || bits == nil {
		return 0
	}
	copy(unsafe.Slice((*byte)(bits), len(px)), px)
	mask, _, _ := pCreateBitmap.Call(uintptr(size), uintptr(size), 1, 1, 0)
	info := iconInfo{FIcon: 1, HbmMask: windows.Handle(mask), HbmColor: windows.Handle(color)}
	icon, _, _ := pCreateIconIndirect.Call(uintptr(unsafe.Pointer(&info)))
	pDeleteObject.Call(color)
	pDeleteObject.Call(mask)
	return windows.Handle(icon)
}

func destroyIcon(h windows.Handle) {
	if h != 0 {
		pDestroyIcon.Call(uintptr(h))
	}
}

func messageBox(title, body string) {
	pMessageBoxW.Call(0, uintptr(unsafe.Pointer(utf16(body))), uintptr(unsafe.Pointer(utf16(title))), mbIconError)
}

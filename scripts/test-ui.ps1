# UI test on Windows: installs the MSI, starts the real app (as the current
# user) with WebView2's debugging port open, checks the window and the page,
# and saves screenshots and logs to -Out. Needs administrator rights to
# install, an interactive desktop (CI runners have one) and Node 22+.
#
#   scripts\test-ui.ps1 -Msi dist\Hifaz-0.1.2-x64.msi -Out build\ui
param(
  [Parameter(Mandatory = $true)][string]$Msi,
  [string]$Out = "build\ui"
)
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$Out = (Resolve-Path $Out).Path
$msiPath = (Resolve-Path $Msi).Path
$exe = Join-Path $env:ProgramFiles "Hifaz\hifaz.exe"
$port = 9222
$failed = @()
function Check([bool]$ok, [string]$what) {
  if ($ok) { Write-Host "ok: $what" } else { Write-Host "FAILED: $what"; $script:failed += $what }
}

Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class W {
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr FindWindow(string cls, string title);
  [DllImport("user32.dll")] public static extern int GetWindowLong(IntPtr h, int index);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr h, int msg, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern IntPtr GetClassLongPtr(IntPtr h, int index);
  [DllImport("user32.dll")] public static extern bool GetClientRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern uint GetDpiForWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr h, IntPtr after, int x, int y, int cx, int cy, uint flags);
  [DllImport("user32.dll")] public static extern IntPtr SetThreadDpiAwarenessContext(IntPtr ctx);
  [DllImport("user32.dll")] public static extern IntPtr MonitorFromWindow(IntPtr h, uint flags);
  [DllImport("user32.dll")] public static extern bool GetMonitorInfo(IntPtr mon, ref MONITORINFO mi);
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
  [StructLayout(LayoutKind.Sequential)] public struct MONITORINFO { public int Size; public RECT Monitor, Work; public uint Flags; }

  [DllImport("user32.dll")] public static extern bool IsZoomed(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int cmd);

  // Measure returns the client width and height, window width and height,
  // the window's DPI, and the work area's width and height. All in
  // physical pixels (per-monitor DPI aware on this thread), as the app.
  public static int[] Measure(IntPtr h) {
    IntPtr old = SetThreadDpiAwarenessContext(new IntPtr(-4));
    try {
      RECT c; GetClientRect(h, out c);
      RECT w; GetWindowRect(h, out w);
      int dpi = (int)GetDpiForWindow(h);
      MONITORINFO mi = new MONITORINFO(); mi.Size = Marshal.SizeOf(mi);
      GetMonitorInfo(MonitorFromWindow(h, 2), ref mi);
      return new int[] { c.Right - c.Left, c.Bottom - c.Top, w.Right - w.Left, w.Bottom - w.Top, dpi,
        mi.Work.Right - mi.Work.Left, mi.Work.Bottom - mi.Work.Top };
    } finally {
      if (old != IntPtr.Zero) SetThreadDpiAwarenessContext(old);
    }
  }

  // Unchanged sends the window a message (with a point on its title bar if
  // caption is set) and reports whether it stayed as it was: not maximized,
  // the same place and size. A maximized window is restored afterwards.
  public static bool Unchanged(IntPtr h, int msg, int wparam, bool caption) {
    IntPtr old = SetThreadDpiAwarenessContext(new IntPtr(-4));
    try {
      RECT before; GetWindowRect(h, out before);
      IntPtr l = IntPtr.Zero;
      if (caption) {
        int x = before.Left + 60, y = before.Top + 10;
        l = new IntPtr((int)(((uint)(y & 0xFFFF) << 16) | (uint)(x & 0xFFFF)));
      }
      SendMessage(h, msg, new IntPtr(wparam), l);
      System.Threading.Thread.Sleep(500);
      RECT after; GetWindowRect(h, out after);
      bool zoomed = IsZoomed(h);
      if (zoomed) ShowWindow(h, 9); // SW_RESTORE, for the page checks
      return !zoomed && before.Left == after.Left && before.Top == after.Top &&
        before.Right == after.Right && before.Bottom == after.Bottom;
    } finally {
      if (old != IntPtr.Zero) SetThreadDpiAwarenessContext(old);
    }
  }
}
"@

function Save-Screen([string]$name) {
  $b = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
  $bmp = New-Object System.Drawing.Bitmap $b.Width, $b.Height
  $g = [System.Drawing.Graphics]::FromImage($bmp)
  $g.CopyFromScreen($b.Location, [System.Drawing.Point]::Empty, $b.Size)
  $bmp.Save((Join-Path $Out $name), [System.Drawing.Imaging.ImageFormat]::Png)
  $g.Dispose(); $bmp.Dispose()
}
Add-Type -AssemblyName System.Windows.Forms

try {
  $p = Start-Process msiexec.exe -ArgumentList "/i `"$msiPath`" /qn /norestart /l*v `"$Out\install.log`"" -Wait -PassThru
  if ($p.ExitCode -ne 0) { throw "install failed: $($p.ExitCode)" }

  $env:HIFAZ_WEBVIEW_DEBUG_PORT = "$port"
  $app = Start-Process $exe -PassThru
  Start-Sleep -Seconds 2

  # The window: found by its class, visible, one fixed size.
  $hwnd = [IntPtr]::Zero
  $deadline = (Get-Date).AddSeconds(30)
  while ($hwnd -eq [IntPtr]::Zero -and (Get-Date) -lt $deadline) {
    $hwnd = [W]::FindWindow("HifazWindow", [NullString]::Value); Start-Sleep -Milliseconds 300
  }
  if ($app.HasExited) { Write-Host "the app exited with code $($app.ExitCode)" }
  Check ($hwnd -ne [IntPtr]::Zero) "window created"
  $deadline = (Get-Date).AddSeconds(30)
  while (-not [W]::IsWindowVisible($hwnd) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 300 }
  Check ([W]::IsWindowVisible($hwnd)) "window shown"
  $style = [W]::GetWindowLong($hwnd, -16)
  Write-Host ("window style 0x{0:X8}" -f $style)
  Check (($style -band 0x00010000) -eq 0) "no maximize button (WS_MAXIMIZEBOX)"
  Check (($style -band 0x00040000) -eq 0) "no resize border (WS_THICKFRAME)"
  Check (($style -band 0x00020000) -ne 0) "minimize button (WS_MINIMIZEBOX)"
  Check (($style -band 0x00080000) -ne 0) "system menu (WS_SYSMENU)"
  Check (($style -band 0x00C00000) -eq 0x00C00000) "title bar (WS_CAPTION)"
  $r = New-Object W+RECT; [void][W]::GetWindowRect($hwnd, [ref]$r)
  $wa = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
  Write-Host "window $($r.Right - $r.Left)x$($r.Bottom - $r.Top) at $($r.Left),$($r.Top); work area $($wa.Width)x$($wa.Height)"
  Check (($r.Bottom - $r.Top) -le $wa.Height -and $r.Top -ge $wa.Top) "window fits the screen"
  # The page is 460x680 page pixels (scaled for the DPI), unless the
  # window is as tall as the monitor's work area (clamped; the page scrolls).
  $m = [W]::Measure($hwnd)
  $wantW = [int][math]::Floor(460 * $m[4] / 96); $wantH = [int][math]::Floor(680 * $m[4] / 96)
  Write-Host "client $($m[0])x$($m[1]) (window $($m[2])x$($m[3])) at $($m[4]) DPI; expected $($wantW)x$($wantH); work area $($m[5])x$($m[6])"
  Check ($m[0] -eq $wantW -and ($m[1] -eq $wantH -or $m[3] -eq $m[6])) "window has the page's fixed size"
  # Maximizing is ignored: from the window menu or Win+Up (SC_MAXIMIZE),
  # and a double-click on the title bar (WM_NCLBUTTONDBLCLK, HTCAPTION).
  # SC_SIZE is not sent: if it were not ignored, its sizing loop would wait
  # for the mouse.
  Check ([W]::Unchanged($hwnd, 0x0112, 0xF030, $false)) "SC_MAXIMIZE is ignored"
  Check ([W]::Unchanged($hwnd, 0x00A3, 2, $true)) "a double-click on the title bar is ignored"
  $bigIcon = [W]::SendMessage($hwnd, 0x7F, [IntPtr]1, [IntPtr]0)   # WM_GETICON, ICON_BIG
  $smallIcon = [W]::SendMessage($hwnd, 0x7F, [IntPtr]0, [IntPtr]0)
  Check ($bigIcon -ne [IntPtr]::Zero -and $smallIcon -ne [IntPtr]::Zero) "window has icons"
  $exeIcon = [System.Drawing.Icon]::ExtractAssociatedIcon($exe)
  $exeIcon.ToBitmap().Save((Join-Path $Out "exe-icon.png"), [System.Drawing.Imaging.ImageFormat]::Png)
  $ver = (Get-Item $exe).VersionInfo
  Write-Host "file version: $($ver.FileVersion) product: $($ver.ProductName) $($ver.ProductVersion)"
  Check ($ver.ProductName -eq "Hifaz") "program carries version information"

  # The page, through WebView2's debugging port.
  node scripts\ui\check-start.mjs $Out $port
  Check ($LASTEXITCODE -eq 0) "page checks (scripts\ui\check-start.mjs)"
  node scripts\ui\check-screens.mjs $Out $port
  Check ($LASTEXITCODE -eq 0) "every screen at the window's size (scripts\ui\check-screens.mjs)"

  [void][W]::SetForegroundWindow($hwnd); Start-Sleep -Milliseconds 800
  Save-Screen "00-desktop.png"
}
catch {
  Write-Host "ERROR: $_"
  $failed += "$_"
  try { Save-Screen "00-desktop-error.png" } catch {}
}
finally {
  Get-Process hifaz -ErrorAction SilentlyContinue | Stop-Process -Force
  Copy-Item "$env:LOCALAPPDATA\Hifaz\app.log" $Out -ErrorAction SilentlyContinue
  Copy-Item (Join-Path $env:ProgramFiles "Hifaz\Data\service.log") $Out -ErrorAction SilentlyContinue
  foreach ($log in "app.log", "service.log") {
    $f = Join-Path $Out $log
    Write-Host "----- $log -----"
    if (Test-Path $f) { Get-Content $f -Tail 60 } else { Write-Host "(none)" }
  }
  Remove-Item Env:HIFAZ_WEBVIEW_DEBUG_PORT -ErrorAction SilentlyContinue
  $p = Start-Process msiexec.exe -ArgumentList "/x `"$msiPath`" /qn /norestart" -Wait -PassThru
}
if ($failed.Count) { throw "$($failed.Count) UI check(s) failed" }
Write-Host "UI checks passed."

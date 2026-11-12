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

  // Shrink asks the window to become 100x100, measures what it allowed, and
  // puts it back. All in physical pixels (per-monitor DPI aware on this
  // thread), the same as the app. Returns client width and height, window
  // width and height, the window's DPI, work area width and height.
  public static int[] Shrink(IntPtr h) {
    IntPtr old = SetThreadDpiAwarenessContext(new IntPtr(-4));
    try {
      RECT before; GetWindowRect(h, out before);
      SetWindowPos(h, IntPtr.Zero, 0, 0, 100, 100, 0x0002 | 0x0004 | 0x0010); // NOMOVE, NOZORDER, NOACTIVATE
      RECT c; GetClientRect(h, out c);
      RECT w; GetWindowRect(h, out w);
      int dpi = (int)GetDpiForWindow(h);
      MONITORINFO mi = new MONITORINFO(); mi.Size = Marshal.SizeOf(mi);
      GetMonitorInfo(MonitorFromWindow(h, 2), ref mi);
      SetWindowPos(h, IntPtr.Zero, before.Left, before.Top, before.Right - before.Left, before.Bottom - before.Top, 0x0004 | 0x0010);
      return new int[] { c.Right - c.Left, c.Bottom - c.Top, w.Right - w.Left, w.Bottom - w.Top, dpi,
        mi.Work.Right - mi.Work.Left, mi.Work.Bottom - mi.Work.Top };
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

  # The window: found by its class, visible, resizable with a minimum size.
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
  Check (($style -band 0x00010000) -ne 0) "maximize button (WS_MAXIMIZEBOX)"
  Check (($style -band 0x00040000) -ne 0) "resizable (WS_THICKFRAME)"
  Check (($style -band 0x00020000) -ne 0) "minimize button"
  $r = New-Object W+RECT; [void][W]::GetWindowRect($hwnd, [ref]$r)
  $wa = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
  Write-Host "window $($r.Right - $r.Left)x$($r.Bottom - $r.Top) at $($r.Left),$($r.Top); work area $($wa.Width)x$($wa.Height)"
  Check (($r.Bottom - $r.Top) -le $wa.Height -and $r.Top -ge $wa.Top) "window fits the screen"
  # Not smaller than 400x560 page pixels (scaled for the DPI), unless the
  # monitor's work area is smaller still.
  $m = [W]::Shrink($hwnd)
  $minW = [int][math]::Floor(400 * $m[4] / 96); $minH = [int][math]::Floor(560 * $m[4] / 96)
  Write-Host "shrunk to client $($m[0])x$($m[1]) (window $($m[2])x$($m[3])) at $($m[4]) DPI; minimum $($minW)x$($minH); work area $($m[5])x$($m[6])"
  Check (($m[0] -ge $minW -or $m[2] -ge $m[5]) -and ($m[1] -ge $minH -or $m[3] -ge $m[6])) "window keeps its minimum size"
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

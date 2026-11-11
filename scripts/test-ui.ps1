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
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
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

  $env:WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS = "--remote-debugging-port=$port"
  $app = Start-Process $exe -PassThru
  Start-Sleep -Seconds 2

  # The window: found by its class, visible, fixed size, no maximize.
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
  Check (($style -band 0x00010000) -eq 0) "no maximize button (WS_MAXIMIZEBOX off)"
  Check (($style -band 0x00040000) -eq 0) "fixed size (WS_THICKFRAME off)"
  Check (($style -band 0x00020000) -ne 0) "minimize button"
  $r = New-Object W+RECT; [void][W]::GetWindowRect($hwnd, [ref]$r)
  $wa = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
  Write-Host "window $($r.Right - $r.Left)x$($r.Bottom - $r.Top) at $($r.Left),$($r.Top); work area $($wa.Width)x$($wa.Height)"
  Check (($r.Bottom - $r.Top) -le $wa.Height -and $r.Top -ge $wa.Top) "window fits the screen"
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
  Remove-Item Env:WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS -ErrorAction SilentlyContinue
  $p = Start-Process msiexec.exe -ArgumentList "/x `"$msiPath`" /qn /norestart" -Wait -PassThru
}
if ($failed.Count) { throw "$($failed.Count) UI check(s) failed" }
Write-Host "UI checks passed."

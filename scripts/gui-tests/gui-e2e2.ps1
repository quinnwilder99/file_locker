# Second GUI test: auto-lock triggers, drive removal, Move into vault, tray menu.
# Run after gui-e2e.ps1 (reuses its vault "Test Vault").
param([string]$Exe = (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) "target\debug\FileLocker.exe"))
$ErrorActionPreference = "Stop"
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$S = Join-Path $env:TEMP "FileLockerGuiTest"
New-Item -ItemType Directory -Force $S | Out-Null
. "$Here\uia.ps1"
$shot = "$Here\shot.ps1"
$data = "$S\appdata"; $vaults = "$S\vaults"; $vault = "$vaults\Test Vault"
$env:FILE_LOCKER_DATA_DIR = $data
$PW = "CorrectHorse42"
if (-not ("Native" -as [type])) {
Add-Type @"
using System; using System.Runtime.InteropServices;
public static class Native {
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr FindWindowW(string cls, IntPtr title);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
}
"@
}
function Step($t) { Write-Host "== $t" }
function Wait-Until([scriptblock]$cond, [string]$what, [int]$ms = 20000) {
  $deadline = (Get-Date).AddMilliseconds($ms)
  while (-not (& $cond)) { if ((Get-Date) -gt $deadline) { throw "timed out waiting for: $what" }; Start-Sleep -Milliseconds 200 }
}
function Texts($root) {
  $cond = New-Object System.Windows.Automation.PropertyCondition($A::ControlTypeProperty, [System.Windows.Automation.ControlType]::Text)
  @($root.FindAll($TS::Descendants, $cond) | ForEach-Object { $_.Current.Name })
}
function Send-ShellMessage([uint32]$msg, [int64]$w, [int64]$l = 0) {
  $h = [Native]::FindWindowW("FileLocker.Shell", [IntPtr]::Zero)
  if ($h -eq [IntPtr]::Zero) { throw "shell window not found" }
  [Native]::PostMessageW($h, $msg, [IntPtr]$w, [IntPtr]$l) | Out-Null
}
function Unlock-Test-Vault($main) {
  if ((Texts $main) -match '^Unlocked as drive') { return }
  Click $main "Unlock"
  $u = Get-Win "Unlock vault"
  Set-Text (Get-Edits $u)[0] $PW
  Click $u "Unlock"
  Wait-Until { (Texts $main) -match '^Unlocked as drive' } "unlocked"
}
function Drive($main) { (((Texts $main) -match '^Unlocked as drive ([A-Z]:)$')[0]) -replace 'Unlocked as drive ', '' }

if (-not (Get-Process FileLocker -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $Exe })) { Start-Process $Exe }
$main = Get-Win "File Locker"

Step "auto-lock when Windows is locked"
Unlock-Test-Vault $main
Send-ShellMessage 0x02B1 7          # WM_WTSSESSION_CHANGE, WTS_SESSION_LOCK
Wait-Until { (Texts $main) -contains "Locked" } "locked on session lock"

Step "auto-lock when the PC sleeps"
Unlock-Test-Vault $main
Send-ShellMessage 0x0218 4          # WM_POWERBROADCAST, PBT_APMSUSPEND
Wait-Until { (Texts $main) -contains "Locked" } "locked on suspend"

Step "lock-all hotkey"
Unlock-Test-Vault $main
Send-ShellMessage 0x0312 1          # WM_HOTKEY, id 1
Wait-Until { (Texts $main) -contains "Locked" } "locked on hotkey"

Step "lock when the vault's drive disappears"
Unlock-Test-Vault $main
$drive = Drive $main
Rename-Item $vault "$vaults\Moved Away"
Wait-Until { (Texts $main) -contains "Locked" } "locked after the folder vanished" 15000
Wait-Until { -not (Test-Path "$drive\") } "drive gone"
Rename-Item "$vaults\Moved Away" $vault

Step "move into vault (vault locked: unlock on the way)"
$src = "$S\to-move"; Remove-Item -Recurse -Force $src -ErrorAction SilentlyContinue
New-Item -ItemType Directory "$src\Holiday Photos" | Out-Null
1..5 | ForEach-Object { [IO.File]::WriteAllBytes("$src\Holiday Photos\img$_.jpg", (New-Object byte[] (200KB + $_))) }
Set-Content "$src\notes.txt" "move me" -Encoding ascii
Start-Process $Exe -ArgumentList "--move-into", "`"$src\Holiday Photos`"" -Wait
Start-Process $Exe -ArgumentList "--move-into", "`"$src\notes.txt`"" -Wait
$move = Get-Win "Move into vault"
Wait-Until { (Texts $move) -contains "Move 2 items into a vault" } "both items collected"
& $shot -Title "Move into vault" -Out (Join-Path $S "10-move.png") | Out-Null
Click $move "Move"
$u = Get-Win "Unlock vault"
Set-Text (Get-Edits $u)[0] $PW
Click $u "Unlock"
Wait-Until { (Texts $move) -match '^Moved 2 items into' } "move finished" 60000
& $shot -Title "Move into vault" -Out (Join-Path $S "11-move-done.png") | Out-Null
$drive = Drive $main
if ((Test-Path "$src\Holiday Photos") -or (Test-Path "$src\notes.txt")) { throw "originals still present" }
if (@(Get-ChildItem "$drive\Holiday Photos").Count -ne 5) { throw "photos missing in vault" }
if ((Get-Content "$drive\notes.txt") -ne "move me") { throw "notes wrong in vault" }
Click $move "Close"

Step "tray menu: Lock all vaults"
Send-ShellMessage (0x8000 + 1) 0 0x007B   # WM_TRAY with WM_CONTEXTMENU
$menu = $null
Wait-Until { $script:menu = $A::RootElement.FindFirst($TS::Children, (New-Object System.Windows.Automation.PropertyCondition($A::ClassNameProperty, "#32768"))); $null -ne $script:menu } "tray menu"
# Classic Win32 menu items are not exposed to UI Automation, and a menu opened
# by a synthetic message gets no keyboard focus. Find the item through the
# menu handle and click it with the mouse, as a person would.
if (-not ("TrayMenu" -as [type])) {
Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices;
public static class TrayMenu {
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L, T, R, B; }
  [DllImport("user32.dll")] static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] static extern int GetMenuItemCount(IntPtr m);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetMenuStringW(IntPtr m, uint id, StringBuilder s, int n, uint flags);
  [DllImport("user32.dll")] static extern bool GetMenuItemRect(IntPtr h, IntPtr m, uint i, out RECT r);
  [DllImport("user32.dll")] static extern bool SetCursorPos(int x, int y);
  [DllImport("user32.dll")] static extern void mouse_event(uint f, int x, int y, uint d, UIntPtr e);
  [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
  public static bool Click(IntPtr menuWindow, string text) {
    IntPtr menu = SendMessageW(menuWindow, 0x01E1, IntPtr.Zero, IntPtr.Zero); // MN_GETHMENU
    int n = GetMenuItemCount(menu);
    for (uint i = 0; i < n; i++) {
      var sb = new StringBuilder(256);
      GetMenuStringW(menu, i, sb, 256, 0x400); // MF_BYPOSITION
      if (sb.ToString() != text) continue;
      RECT r; if (!GetMenuItemRect(menuWindow, menu, i, out r)) return false;
      SetCursorPos((r.L + r.R) / 2, (r.T + r.B) / 2);
      System.Threading.Thread.Sleep(150);
      mouse_event(0x2, 0, 0, 0, UIntPtr.Zero); mouse_event(0x4, 0, 0, 0, UIntPtr.Zero);
      return true;
    }
    return false;
  }
}
"@
}
[TrayMenu]::SetProcessDPIAware() | Out-Null
Start-Sleep -Milliseconds 300
if (-not [TrayMenu]::Click([IntPtr]$menu.Current.NativeWindowHandle, "Lock all vaults")) { throw "menu item not found" }
Wait-Until { (Texts $main) -contains "Locked" } "locked from tray"

Write-Host "ALL GUI CHECKS (2) PASSED"

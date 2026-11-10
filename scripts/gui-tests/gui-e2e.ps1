# End-to-end GUI test of FileLocker.exe through UI Automation.
param([string]$Exe = (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) "target\debug\FileLocker.exe"))
$ErrorActionPreference = "Stop"
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$S = Join-Path $env:TEMP "FileLockerGuiTest"
New-Item -ItemType Directory -Force $S | Out-Null
. "$Here\uia.ps1"
$shot = "$Here\shot.ps1"
$data = "$S\appdata"; $vaults = "$S\vaults"
Get-Process FileLocker -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $Exe } | Stop-Process -Force
Start-Sleep 1
Remove-Item -Recurse -Force $data, $vaults -ErrorAction SilentlyContinue
New-Item -ItemType Directory $data, $vaults | Out-Null
# Test settings: no Explorer windows, no hotkey.
'{"open_explorer": false, "hotkey": false}' | Set-Content -Encoding ascii "$data\settings.json"
$env:FILE_LOCKER_DATA_DIR = $data
$PW = "CorrectHorse42"

function Step($text) { Write-Host "== $text" }
function Wait-Until([scriptblock]$cond, [string]$what, [int]$ms = 20000) {
  $deadline = (Get-Date).AddMilliseconds($ms)
  while (-not (& $cond)) { if ((Get-Date) -gt $deadline) { throw "timed out waiting for: $what" }; Start-Sleep -Milliseconds 200 }
}
function Has-Text($root, $text) {
  $cond = New-Object System.Windows.Automation.PropertyCondition($A::NameProperty, $text)
  [bool]$root.FindFirst($TS::Descendants, $cond)
}
function Texts($root) {
  $cond = New-Object System.Windows.Automation.PropertyCondition($A::ControlTypeProperty, [System.Windows.Automation.ControlType]::Text)
  @($root.FindAll($TS::Descendants, $cond) | ForEach-Object { $_.Current.Name })
}

Step "launch"
$proc = Start-Process $Exe -PassThru
$main = Get-Win "File Locker"
& $shot -Title "File Locker" -Out "$S\01-main-empty.png" | Out-Null

Step "create a vault"
Click $main "Create a vault"
$create = Get-Win "Create a vault"
& $shot -Title "Create a vault" -Out "$S\02-create.png" | Out-Null
$e = Get-Edits $create
"edits: $($e.Count)"
Set-Text $e[0] "Test Vault"
Set-Text $e[1] $vaults
Set-Text $e[2] $PW
Set-Text $e[3] $PW
Start-Sleep -Milliseconds 300
& $shot -Title "Create a vault" -Out "$S\03-create-filled.png" | Out-Null
Click $create "Create"
Wait-Until { Has-Text $create "Save your recovery key" } "recovery key page"
& $shot -Title "Create a vault" -Out "$S\04-recovery.png" | Out-Null
$key = (Texts $create | Where-Object { $_ -match '^[0-9A-Z]{4}(-[0-9A-Z]{4})+$' }) -join "-"
"recovery key: $key"
if (-not (Test-Path "$vaults\Test Vault\vault.json")) { throw "vault folder not created" }
if (-not (Test-Path "$vaults\Test Vault\Unlock vault.flkvault")) { throw "marker file missing" }
Click $create "I saved my recovery key somewhere safe"
Click $create "Finish"

Step "vault unlocks after the wizard"
Wait-Until { (Texts $main) -match '^Unlocked as drive [A-Z]:$' } "unlocked card"
$drive = ((Texts $main) -match '^Unlocked as drive ([A-Z]:)$')[0] -replace 'Unlocked as drive ', ''
"drive: $drive"
& $shot -Title "File Locker" -Out "$S\05-main-unlocked.png" | Out-Null
Set-Content -Path "$drive\secret.txt" -Value "top secret 7f3a" -Encoding ascii
if ((Get-Content "$drive\secret.txt") -ne "top secret 7f3a") { throw "drive read-back failed" }
$leak = Get-ChildItem -Recurse -File "$vaults\Test Vault" | Where-Object { (Get-Content -Raw $_.FullName -ErrorAction SilentlyContinue) -match "top secret" }
if ($leak) { throw "plaintext found on disk: $($leak.FullName)" }

Step "a genuinely open file blocks a plain lock"
$held = [System.IO.File]::Open("$drive\secret.txt", 'Open', 'Read', 'ReadWrite')
Click $main "Lock"
Wait-Until { $null -ne $main.FindFirst($TS::Children, (New-Object System.Windows.Automation.PropertyCondition($A::NameProperty, "Files are still open"))) } "open-files warning"
$box = $main.FindFirst($TS::Children, (New-Object System.Windows.Automation.PropertyCondition($A::NameProperty, "Files are still open")))
& $shot -Title "Files are still open" -Out (Join-Path $S "05b-open-files.png") | Out-Null
if (-not ("MsgBox" -as [type])) { Add-Type 'using System; using System.Runtime.InteropServices; public static class MsgBox { [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint m, IntPtr w, IntPtr l); }' }
[MsgBox]::PostMessage([IntPtr]$box.Current.NativeWindowHandle, 0x111, [IntPtr]7, [IntPtr]::Zero) | Out-Null  # WM_COMMAND, IDNO
Start-Sleep -Milliseconds 500
if (-not (Test-Path "$drive\")) { throw "vault locked although the user said No" }
$held.Close()

Step "lock from the main window"
Click $main "Lock"
Wait-Until { (Texts $main) -contains "Locked" } "locked card"
Wait-Until { -not (Test-Path "$drive\") } "drive removed"

Step "wrong password, then the right one"
Click $main "Unlock"
$unlock = Get-Win "Unlock vault"
$pwEdit = (Get-Edits $unlock)[0]
Set-Text $pwEdit "wrong password"
Click $unlock "Unlock"
Wait-Until { Has-Text $unlock "That password is not correct." } "wrong-password error"
& $shot -Title "Unlock vault" -Out "$S\06-unlock-error.png" | Out-Null
Set-Text (Get-Edits $unlock)[0] $PW
Click $unlock "Unlock"
Wait-Until { (Texts $main) -match '^Unlocked as drive' } "unlocked again"
if ((Get-Content "$drive\secret.txt") -ne "top secret 7f3a") { throw "file missing after relock" }

Step "a second launch hands over its command (double-clicked vault file)"
Click $main "Lock"
Wait-Until { (Texts $main) -contains "Locked" } "locked again"
Start-Process $Exe -ArgumentList "--unlock", "`"$vaults\Test Vault\Unlock vault.flkvault`"" -Wait
$unlock = Get-Win "Unlock vault"
if (-not ((Texts $unlock) -like "*Test Vault*")) { throw "unlock dialog shows the wrong vault" }
Click $unlock "Cancel"

Step "settings window"
Click $main "Settings"
$settings = Get-Win "File Locker settings"
& $shot -Title "File Locker settings" -Out "$S\07-settings.png" | Out-Null
Click $settings "About File Locker"
$about = Get-Win "About File Locker"
& $shot -Title "About File Locker" -Out (Join-Path $S "08-about.png") | Out-Null
Click $about "Close"
Click $settings "Cancel"
& $shot -Title "File Locker" -Out (Join-Path $S "09-main-locked.png") | Out-Null

Step "only one process"
$count = @(Get-Process FileLocker | Where-Object { $_.Path -eq $Exe }).Count
if ($count -ne 1) { throw "expected one FileLocker process, found $count" }

Write-Host "ALL GUI CHECKS PASSED"

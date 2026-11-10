# UI Automation helpers for driving File Locker's windows.
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes, System.Windows.Forms
$A = [System.Windows.Automation.AutomationElement]
$TS = [System.Windows.Automation.TreeScope]

function Get-Win([string]$title, [int]$timeoutMs = 10000) {
  $deadline = (Get-Date).AddMilliseconds($timeoutMs)
  do {
    $cond = New-Object System.Windows.Automation.PropertyCondition($A::NameProperty, $title)
    $w = $A::RootElement.FindFirst($TS::Children, $cond)
    if ($w) { return $w }
    Start-Sleep -Milliseconds 200
  } while ((Get-Date) -lt $deadline)
  throw "window '$title' not found"
}

function Dump($el, [int]$depth = 0) {
  $kids = $el.FindAll($TS::Children, [System.Windows.Automation.Condition]::TrueCondition)
  foreach ($k in $kids) {
    $c = $k.Current
    "{0}{1} '{2}' enabled={3}" -f ("  " * $depth), $c.ControlType.ProgrammaticName, $c.Name, $c.IsEnabled
    if ($depth -lt 12) { Dump $k ($depth + 1) }
  }
}

function Find-Named($root, [string]$name) {
  $cond = New-Object System.Windows.Automation.PropertyCondition($A::NameProperty, $name)
  $el = $null
  for ($i = 0; $i -lt 30 -and -not $el; $i++) {
    $el = $root.FindFirst($TS::Descendants, $cond)
    if (-not $el) { Start-Sleep -Milliseconds 100 }
  }
  if (-not $el) { throw "element '$name' not found" }
  $el
}

function Click($root, [string]$name) {
  $el = Find-Named $root $name
  for ($i = 0; $i -lt 30 -and -not $el.Current.IsEnabled; $i++) { Start-Sleep -Milliseconds 100; $el = Find-Named $root $name }
  $p = $null
  if ($el.TryGetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern, [ref]$p)) { $p.Invoke(); return }
  if ($el.TryGetCurrentPattern([System.Windows.Automation.TogglePattern]::Pattern, [ref]$p)) { $p.Toggle(); return }
  throw "element '$name' cannot be clicked"
}

# Edit controls in document order.
function Get-Edits($root) {
  $cond = New-Object System.Windows.Automation.PropertyCondition($A::ControlTypeProperty, [System.Windows.Automation.ControlType]::Edit)
  @($root.FindAll($TS::Descendants, $cond))
}

function Set-Text($el, [string]$text) {
  $p = $null
  if ($el.TryGetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern, [ref]$p)) { $p.SetValue($text); return }
  $el.SetFocus(); Start-Sleep -Milliseconds 100
  [System.Windows.Forms.SendKeys]::SendWait("^a"); [System.Windows.Forms.SendKeys]::SendWait($text)
}

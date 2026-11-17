<#
.SYNOPSIS
  Schedules Get-BreachWire.ps1 three times a day at varying times (Windows Task Scheduler, current user).

.DESCRIPTION
  Three daily triggers, each with a random start delay, so runs land at different times every day:

    morning    06:00 + up to 2h   ->  06:00-08:00
    afternoon  13:00 + up to 2h   ->  13:00-15:00
    evening    20:00 + up to 2h   ->  20:00-22:00

  Runs as the current user, only while logged on (no stored password), hidden, with network required.
  Missed runs (laptop asleep) start as soon as the machine is available.

.PARAMETER Times
  Base times (24h). Default 06:00, 13:00, 20:00.

.PARAMETER JitterHours
  Maximum random delay added to each base time. Default 2.

.PARAMETER Remove
  Unregister the task.

.EXAMPLE
  ./scripts/Register-BreachWireSchedule.ps1
  ./scripts/Register-BreachWireSchedule.ps1 -Times 07:30,12:00,18:45 -JitterHours 1
  ./scripts/Register-BreachWireSchedule.ps1 -Remove
#>
[CmdletBinding()]
param(
  [string[]]$Times = @('06:00', '13:00', '20:00'),
  [int]$JitterHours = 2,
  [string]$TaskName = 'BreachWire',
  [switch]$Remove
)
$ErrorActionPreference = 'Stop'

if ($Remove) {
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
  Write-Host "Removed scheduled task '$TaskName'."
  return
}

$script = Join-Path $PSScriptRoot 'Invoke-BreachWireRun.ps1'   # refresh feed, then commit + push
if (-not (Test-Path $script)) { throw "Not found: $script" }

# conhost --headless keeps the console window from flashing up on each run (Windows 11)
$psArgs = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$script`""
$action = New-ScheduledTaskAction -Execute 'conhost.exe' -Argument "--headless powershell.exe $psArgs" -WorkingDirectory (Split-Path -Parent $PSScriptRoot)

$triggers = foreach ($t in $Times) {
  $tr = New-ScheduledTaskTrigger -Daily -At ([datetime]::ParseExact($t, 'HH:mm', $null))
  $tr.RandomDelay = 'PT{0}H' -f $JitterHours
  $tr
}

$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RunOnlyIfNetworkAvailable -AllowStartIfOnBatteries `
  -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 20) -MultipleInstances IgnoreNew
$principal = New-ScheduledTaskPrincipal -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType Interactive -RunLevel Limited

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $triggers -Settings $settings -Principal $principal `
  -Description 'Breach Wire: one-line cyber-attack OSINT feed (leak sites, dark-web monitors, Telegram, security press, news, SEC 8-K).' -Force | Out-Null

$info = Get-ScheduledTask -TaskName $TaskName
Write-Host "Registered '$TaskName':"
foreach ($t in $Times) { Write-Host ("  daily {0} + random 0-{1}h" -f $t, $JitterHours) }
Write-Host ("  next run: {0}" -f (Get-ScheduledTaskInfo -TaskName $TaskName).NextRunTime)

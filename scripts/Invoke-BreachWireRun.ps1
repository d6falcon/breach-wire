<#
.SYNOPSIS
  Scheduled entry point: refresh the feed, then commit and push it to the private repo.

.DESCRIPTION
  Runs Get-BreachWire.ps1, commits breach-wire.md and state/wire.tsv if they changed, and pushes to origin.
  Never prompts: if the push fails (offline, credentials expired), the commit stays local and the next run
  pushes it. Outcomes are appended to state/run.log.

.PARAMETER NoPush
  Refresh and commit locally, but do not push.
#>
[CmdletBinding()]
param([switch]$NoPush)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$logFile = Join-Path $root 'state/run.log'
function Write-RunLog([string]$m) { Add-Content -Path $logFile -Value ('{0:u} git  {1}' -f [DateTime]::UtcNow, $m) -Encoding UTF8 }

& (Join-Path $PSScriptRoot 'Get-BreachWire.ps1')

$env:GIT_TERMINAL_PROMPT = '0'
$env:GCM_INTERACTIVE = 'never'
Push-Location $root
try {
  git add -A
  git diff --cached --quiet
  if ($LASTEXITCODE -ne 0) {
    git commit -q -m ('feed: {0:yyyy-MM-dd HH:mm} UTC' -f [DateTime]::UtcNow)
    if ($LASTEXITCODE -ne 0) { Write-RunLog 'commit FAILED'; return }
    Write-RunLog 'committed'
  } else {
    Write-RunLog 'no changes'
  }
  if ($NoPush) { return }
  $ahead = git rev-list --count '@{u}..HEAD' 2>$null
  if ($LASTEXITCODE -ne 0 -or [int]$ahead -gt 0) {
    git push -q origin HEAD 2>$null
    if ($LASTEXITCODE -eq 0) { Write-RunLog 'pushed' } else { Write-RunLog 'push FAILED (will retry next run)' }
  }
} finally {
  Pop-Location
}

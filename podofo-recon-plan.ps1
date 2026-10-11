#!/usr/bin/env pwsh
<#
.SYNOPSIS
Vulnerability audit reconnaissance pass: analyses every file in podofo-recon-plan.json,
one after another, and records proposed investigation targets for a later audit pass.

.DESCRIPTION
The JSON database is the work list only: files grouped by tier, each with an optional
description. It holds no run state and this script never writes it, so it can be
edited while a pass is running. Full recon output goes to
governance/security-audit/scan/targets/<file-key>/recon.json, and that file is the
progress state: a file is done when its recon.json exists, and the result shown on the
checklist is read back from it. The pass resumes where it left off.

A file entry may be written either as an object or as a bare path string. Setting
"ignore": true on an entry takes the file out of the run: it is never analysed and
never counted, but it stays on the checklist, marked as ignored, so the decision
stays visible. Files missing on disk or generated are skipped the same way, decided
afresh on every run rather than recorded.

The model analyses one file per call and returns structured recon only. This script
owns the recon files and renders the checklist.

Press 'q' at any time to stop after the current file finishes. Creating the file
governance/security-audit/scan/STOP has the same effect, for non-interactive runs.

Each model call streams its events to scan/runs/recon/<file-key>.jsonl as it happens,
overwritten on a re-run. Press 'm' while a call is in flight to open that log in
Notepad++ with -monitor, which tails it live. 'm' is offered only when Notepad++ is
found on the machine.

.NOTES
The model seam is dot-sourced from model-seam-claude.ps1 (override with
-ModelScript). Recon reads source, so it must be an agent invocation with repository
read access and schema-constrained output, not a plain completion:

    function Invoke-ModelPrompt
    {
        param(
            [Parameter(Mandatory)][string]$Prompt,
            [hashtable]$Schema,
            [string]$Label,
            [string[]]$AllowDir,
            [string]$Effort
        )
        # returns a PSCustomObject (or JSON string) matching $Schema
    }
#>

[CmdletBinding()]
param(
    [string]$RepoRoot,
    [string]$DatabasePath,
    [string]$ScanRoot,
    [string]$ModelScript,
    [string]$Model = 'claude-fable-5-1',
    [ValidateSet('low', 'medium', 'high', 'xhigh', 'max')][string]$Effort = 'xhigh',
    [string]$Only,
    [switch]$Redo,
    [switch]$DryRun
)

$PSNativeCommandUseErrorActionPreference = $true
$ErrorActionPreference = 'stop'
Set-StrictMode -Version Latest

if ([string]::IsNullOrEmpty($RepoRoot))
    { $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path }   # governance/security-audit -> repository root
if ([string]::IsNullOrEmpty($ModelScript))
    { $ModelScript = Join-Path $PSScriptRoot 'model-seam-claude.ps1' }
if ([string]::IsNullOrEmpty($ScanRoot))
    { $ScanRoot = Join-Path $PSScriptRoot 'scan' }
if ([string]::IsNullOrEmpty($DatabasePath))
    { $DatabasePath = Join-Path $ScanRoot 'podofo-recon-plan.json' }

$targetsRoot = Join-Path $ScanRoot 'targets'
$stopFile = Join-Path $ScanRoot 'STOP'
$runsRoot = Join-Path $ScanRoot 'runs/recon'
# Raw streamed events go to one reused working file; the readable transcript per file
# is what is kept and what 'm' opens.
$rawLog = Join-Path $ScanRoot 'runs/recon-monitor.jsonl'

. (Join-Path $PSScriptRoot 'audit-common.ps1')

if (Test-Path $ModelScript)
    { . $ModelScript }

$palette = Get-AuditPalette

# Set by the activity ticker when q is pressed mid-call, so the keypress is not lost
# to the ticker's own key draining.
$keySignal = @{ Stop = $false }

#region Database

function Read-Database
{
    if (-not (Test-Path $DatabasePath))
        { throw "Audit planning database not found: $DatabasePath" }

    $db = Get-Content -LiteralPath $DatabasePath -Raw -Encoding utf8 | ConvertFrom-Json
    if (@($db.tiers).Count -eq 0)
        { throw "No tiers in $DatabasePath" }

    # A file may be written as a bare path string, which means exactly a non-ignored
    # entry with no description. Expanded here, once, so everything downstream sees
    # one shape.
    foreach ($tier in $db.tiers)
    {
        $tier.files = @(foreach ($file in $tier.files)
        {
            if ($file -is [string]) { [pscustomobject]@{ path = $file } } else { $file }
        })
    }

    return $db
}

# Absent means false. An ignored file is never analysed and never counted, but it
# stays in the database and on the checklist so the decision remains visible.
function Test-FileIgnored
{
    param([Parameter(Mandatory)][psobject]$File)

    return [bool](Get-Field -Object $File -Name 'ignore')
}

# The recon a previous pass wrote for this file, or $null when it has not been
# analysed. Its existence is what marks the file done. The origin check catches two
# plan paths that flatten to the same scan folder, which would otherwise have one
# file's recon stand in for, and then be overwritten by, the other's.
function Read-ReconRecord
{
    param([Parameter(Mandatory)][string]$RelativePath)

    $path = Join-Path (Join-Path $targetsRoot (Get-ScanFileKey $RelativePath)) 'recon.json'
    if (-not (Test-Path -LiteralPath $path))
        { return $null }

    $record = Get-Content -LiteralPath $path -Raw -Encoding utf8 | ConvertFrom-Json
    if ($record.origin_file -ne $RelativePath)
        { throw "$path was written for $($record.origin_file), not $RelativePath. Both map to the same scan folder." }

    return $record
}

# Why a file cannot be analysed as it stands, or $null when it can. Cheap enough to
# decide on every run, so it is never recorded and a file that comes back is picked up.
function Get-SkipReason
{
    param([Parameter(Mandatory)][string]$RelativePath)

    $fullPath = Join-Path $RepoRoot $RelativePath
    if (-not (Test-Path -LiteralPath $fullPath))
        { return 'missing on disk' }

    $header = (Get-Content -LiteralPath $fullPath -TotalCount 5) -join "`n"
    if ($header -match 'was generated\. DO NOT EDIT')
    {
        $lineCount = (Get-Content -LiteralPath $fullPath | Measure-Object -Line).Lines
        return "generated, $lineCount lines"
    }

    return $null
}

# Flat iteration order over the tiers. Recon and Skip are derived from disk here and
# live only in memory; nothing about a run is written back to the database.
function Get-Entries
{
    param([Parameter(Mandatory)][psobject]$Database)

    $entries = [System.Collections.Generic.List[psobject]]::new()
    foreach ($tier in $Database.tiers)
    {
        foreach ($file in $tier.files)
        {
            $ignored = Test-FileIgnored -File $file
            $entries.Add([pscustomobject]@{
                Tier            = $tier.tier
                TierDescription = $tier.description
                File            = $file
                Recon           = if ($ignored) { $null } else { Read-ReconRecord -RelativePath $file.path }
                Skip            = if ($ignored) { $null } else { Get-SkipReason -RelativePath $file.path }
            })
        }
    }

    return $entries
}

# Ignored is the plan's own decision, done means a recon exists, skipped is a file
# that cannot be analysed as it stands. A recon outranks a skip: it is still the
# result of that file even if the file has since gone.
function Get-EntryState
{
    param([Parameter(Mandatory)][psobject]$Entry)

    if (Test-FileIgnored -File $Entry.File)
        { return 'ignored' }
    if ($null -ne $Entry.Recon)
        { return 'done' }
    if ($null -ne $Entry.Skip)
        { return 'skipped' }

    return 'pending'
}

#endregion

#region Rendering

function Get-EntryStatusText
{
    param([Parameter(Mandatory)][psobject]$Entry, [switch]$Current)

    if ($Current)
        { return 'analysing...' }

    switch (Get-EntryState -Entry $Entry)
    {
        'ignored' { return 'ignored' }
        'done'    { return (Format-ResultAnnotation -Recon $Entry.Recon.recon) }
        'skipped' { return "skipped ($($Entry.Skip))" }
    }

    $description = Get-Field -Object $Entry.File -Name 'description'
    if (-not [string]::IsNullOrEmpty($description))
        { return "($description)" }

    return ''
}

function Get-EntryColor
{
    param([Parameter(Mandatory)][psobject]$Entry, [switch]$Current)

    if ($Current)
        { return $palette.Current }
    if ((Get-EntryState -Entry $Entry) -ne 'done')
        { return $palette.Muted }

    switch ([string]$Entry.Recon.recon.audit_priority)
    {
        'high'   { return $palette.High }
        'medium' { return $palette.Medium }
        'low'    { return $palette.Low }
        default  { return $palette.Hint }
    }
}

function Show-Checklist
{
    param(
        [Parameter(Mandatory)][psobject]$Entries,
        [int]$CurrentIndex = -1,
        [Parameter(Mandatory)][datetime]$StartedAt,
        [int]$AnalysedThisRun = 0
    )

    $nameWidth = ($Entries | ForEach-Object { [System.IO.Path]::GetFileName($_.File.path).Length } | Measure-Object -Maximum).Maximum

    # Flatten to renderable rows first, so the viewport can be centred on the
    # current file when the whole list does not fit the window.
    $rows = [System.Collections.Generic.List[psobject]]::new()
    $currentRow = -1
    $lastTier = -1
    for ($i = 0; $i -lt $Entries.Count; $i++)
    {
        $entry = $Entries[$i]
        if ($entry.Tier -ne $lastTier)
        {
            if ($rows.Count -gt 0)
                { $rows.Add([pscustomobject]@{ Text = ''; Color = $palette.Muted }) }

            $rows.Add([pscustomobject]@{ Text = ('  Tier {0} - {1}' -f $entry.Tier, $entry.TierDescription); Color = $palette.Group })
            $lastTier = $entry.Tier
        }

        $isCurrent = ($i -eq $CurrentIndex)
        $mark = if ($isCurrent) { '>' }
            else
            {
                switch (Get-EntryState -Entry $entry)
                {
                    'done'    { 'x' }
                    'pending' { ' ' }
                    default   { '-' }
                }
            }
        $text = '  [{0}] {1}  {2}' -f $mark,
            ([System.IO.Path]::GetFileName($entry.File.path).PadRight($nameWidth)),
            (Get-EntryStatusText -Entry $entry -Current:$isCurrent)

        if ($isCurrent)
            { $currentRow = $rows.Count }

        $rows.Add([pscustomobject]@{ Text = $text.TrimEnd(); Color = (Get-EntryColor -Entry $entry -Current:$isCurrent) })
    }

    # Ignored and skipped files are shown but not counted, so the ratio tracks the
    # real work.
    $states = @($Entries | ForEach-Object { Get-EntryState -Entry $_ })
    $done = @($states | Where-Object { $_ -eq 'done' }).Count
    $counted = $done + @($states | Where-Object { $_ -eq 'pending' }).Count
    $aside = @(foreach ($state in @('ignored', 'skipped'))
    {
        $count = @($states | Where-Object { $_ -eq $state }).Count
        if ($count -gt 0) { "$count $state" }
    })
    $setAside = if ($aside.Count -gt 0) { '   ' + ($aside -join ', ') } else { '' }
    $elapsed = (Get-Date) - $StartedAt
    $rate = if ($AnalysedThisRun -gt 0) { ' | {0:n0}s/file' -f ($elapsed.TotalSeconds / $AnalysedThisRun) } else { '' }

    try { Clear-Host } catch { }
    Write-Host ('PoDoFo recon   {0}/{1} analysed{2}   {3:hh\:mm\:ss} elapsed{4}' -f $done, $counted, $setAside, $elapsed, $rate) -ForegroundColor $palette.Header

    # The tier header can scroll out of the viewport, so keep it on the status line.
    if ($CurrentIndex -ge 0)
    {
        $currentEntry = $Entries[$CurrentIndex]
        Write-Host ('  Tier {0} - {1}' -f $currentEntry.Tier, $currentEntry.TierDescription) -ForegroundColor $palette.Group
    }

    Write-Host ''

    # Reserves the header, the tier line, the two status rows, a blank line and
    # some slack.
    Write-Viewport -Rows $rows -CurrentRow $currentRow -Reserved 8
}

function Write-EntryResult
{
    param(
        [Parameter(Mandatory)][psobject]$Entry,
        [Parameter(Mandatory)][int]$Index,
        [Parameter(Mandatory)][int]$Total
    )

    Write-Host ('[{0,4}/{1}] T{2,-2} {3,-42} {4}' -f ($Index + 1), $Total, $Entry.Tier,
        [System.IO.Path]::GetFileName($Entry.File.path), (Get-EntryStatusText -Entry $Entry))
}

# Non-interactive runs cannot poll for a keypress, so telling them to press q would
# be a lie. They get the STOP file instead.
function Write-StopHint
{
    param([bool]$Interactive, [switch]$Terse)

    if ($Interactive)
    {
        Write-Host "  Press 'q' to stop after the current file finishes." -ForegroundColor $palette.Hint
        return
    }

    # The full path is worth spelling out once; repeating it after every file is not.
    if ($Terse)
        { Write-Host '  (create the STOP file to stop after the current file)' -ForegroundColor $palette.Hint }
    else
        { Write-Host "  Create $stopFile to stop after the current file finishes." -ForegroundColor $palette.Hint }
}

#endregion

#region Stop handling

function Test-StopRequested
{
    param([bool]$Already)

    if ($Already)
        { return $true }
    if ($keySignal.Stop)
        { return $true }
    if (Test-Path $stopFile)
        { return $true }

    # Keystrokes pressed while the model call was running are still buffered here,
    # so this catches a q pressed at any point during the previous file.
    try
    {
        if ([Console]::IsInputRedirected)
            { return $false }

        while ([Console]::KeyAvailable)
        {
            $key = [Console]::ReadKey($true)
            if ($key.KeyChar -eq 'q' -or $key.KeyChar -eq 'Q')
                { return $true }
        }
    }
    catch
    {
        # No usable console (host without a key buffer). Fall back to the stop file.
    }

    return $false
}

# Polls and acknowledges the request the first time it is seen. Without this, q takes
# effect silently and the run looks unresponsive until the current file finishes.
function Update-StopRequest
{
    param([bool]$Current)

    if ($Current)
        { return $true }
    if (-not (Test-StopRequested -Already $false))
        { return $false }

    Write-Host ''
    Write-Host '  Stop requested. The current file will finish; no further files will be started.' -ForegroundColor $palette.Warning
    return $true
}

#endregion

#region Recon

$reconSchema = @{
    type                 = 'object'
    additionalProperties = $false
    required             = @('input_exposure', 'entry_points', 'risky_constructs', 'assumed_invariants', 'audit_priority', 'proposed_targets', 'summary')
    properties           = @{
        input_exposure     = @{ type = 'string'; enum = @('direct', 'indirect', 'none') }
        entry_points       = @{ type = 'array'; items = @{ type = 'string' } }
        risky_constructs   = @{
            type  = 'array'
            items = @{
                type                 = 'object'
                additionalProperties = $false
                required             = @('function', 'observation')
                properties           = @{ function = @{ type = 'string' }; observation = @{ type = 'string' } }
            }
        }
        assumed_invariants = @{
            type  = 'array'
            items = @{
                type                 = 'object'
                additionalProperties = $false
                required             = @('invariant', 'guaranteed_by')
                properties           = @{ invariant = @{ type = 'string' }; guaranteed_by = @{ type = 'string' } }
            }
        }
        audit_priority     = @{ type = 'string'; enum = @('none', 'low', 'medium', 'high') }
        proposed_targets   = @{
            type  = 'array'
            items = @{
                type                 = 'object'
                additionalProperties = $false
                required             = @('target', 'rationale', 'confidence')
                properties           = @{
                    target     = @{ type = 'string' }
                    rationale  = @{ type = 'string' }
                    confidence = @{ type = 'string'; enum = @('low', 'medium', 'high') }
                }
            }
        }
        summary            = @{ type = 'string' }
    }
}

function New-ReconPrompt
{
    param(
        [Parameter(Mandatory)][psobject]$Entry,
        [Parameter(Mandatory)][int]$LineCount,
        [Parameter(Mandatory)][int]$Index,
        [Parameter(Mandatory)][int]$Total
    )

    return @"
You are performing audit reconnaissance and planning on one PoDoFo source file.

Repository root: $RepoRoot
File under analysis: $($Entry.File.path) ($LineCount lines)
Position in review order: tier $($Entry.Tier), file $Index of $Total

Read the file, plus any header or caller you need to understand how it is reached.
Do not modify any PoDoFo source file.

Threat model:
- In scope: anything reachable by loading, parsing or writing a corrupted or hostile
  PDF, and anything reachable through documented PoDoFo API usage.
- Out of scope: specially crafted PoDoFo modules, third-party module API misuse,
  loading attacker-controlled module code.
- Crash classes of interest: buffer overflow, out-of-bounds read or write,
  use-after-free, double free, uninitialized read, integer overflow or truncation
  feeding an allocation or an index, unbounded recursion, data structure corruption.

Characterise this file as an audit surface and propose investigation targets for a
later audit pass. You are not auditing it now. Do not write a vulnerability report.

Assess honestly. Most files will not deserve an audit. Proposing no target is a
useful and expected outcome for construction-only code, thin wrappers, generated
tables and trivial accessors. Do not invent a target to fill the field.

Any target you do propose must be narrow enough that an auditor can confirm or
reject it by reading a bounded amount of code: name the function, the state
transition, the buffer, or the invariant. "Review the parsing logic" is not a
target. "GetNextToken assumes the buffer stays NUL terminated after a partial
read" is.

Output rules:
- input_exposure: direct, indirect, or none. direct means attacker-controlled bytes
  or objects from a PDF reach this code. indirect means it is reached only with data
  another component already validated or constructed.
- entry_points: functions through which untrusted data enters. Empty if none.
- risky_constructs: concrete observations, each naming a function and what it does
  that is memory-unsafe by construction (raw indexing, pointer arithmetic, casts,
  manual allocation, size arithmetic, reinterpreting caller buffers).
- assumed_invariants: what the code trusts without checking, and who is supposed to
  guarantee it.
- audit_priority: none, low, medium, or high. Use none when you propose no target.
- proposed_targets: zero or more, each with target, rationale, confidence.
- summary: two or three sentences orienting an auditor before they audit this file.

Write plain ASCII throughout, matching the repository convention: a regular hyphen
rather than an em dash, and three dots rather than an ellipsis character.
"@
}

function Save-Recon
{
    param(
        [Parameter(Mandatory)][psobject]$Entry,
        [Parameter(Mandatory)][psobject]$Recon
    )

    $targetDir = Join-Path $targetsRoot (Get-ScanFileKey $Entry.File.path)

    # Rebuilt rather than annotated in place, so the id leads each target object.
    $targets = foreach ($target in @($Recon.proposed_targets))
    {
        [ordered]@{
            id         = Get-TargetId -OriginFile $Entry.File.path -Target $target.target
            target     = $target.target
            rationale  = $target.rationale
            confidence = $target.confidence
        }
    }

    $record = [ordered]@{
        origin_file  = $Entry.File.path
        tier         = $Entry.Tier
        analysed_utc = (Get-Date).ToUniversalTime().ToString('o')
        recon        = [ordered]@{
            input_exposure     = $Recon.input_exposure
            entry_points       = @($Recon.entry_points)
            risky_constructs   = @($Recon.risky_constructs)
            assumed_invariants = @($Recon.assumed_invariants)
            audit_priority     = $Recon.audit_priority
            proposed_targets   = @($targets)
            summary            = $Recon.summary
        }
    }

    Write-FileAtomic -Path (Join-Path $targetDir 'recon.json') -Content ($record | ConvertTo-Json -Depth 12)
}

function Format-ResultAnnotation
{
    param([Parameter(Mandatory)][psobject]$Recon)

    $count = @($Recon.proposed_targets).Count
    $targets = if ($count -eq 0) { 'no targets' } elseif ($count -eq 1) { '1 target' } else { "$count targets" }
    return ('{0}, {1}, {2}' -f $Recon.audit_priority, $Recon.input_exposure, $targets)
}

#endregion

#region Main

$db = Read-Database
$entries = @(Get-Entries -Database $db)

# Ignored and skipped files stay in $entries so the checklist still shows them, but
# they are not work and they are not part of the total the run reports against.
$active = @($entries | Where-Object { (Get-EntryState -Entry $_) -in @('done', 'pending') })
$total = $active.Count

# -Redo reaches files already done, but never one that cannot be analysed now.
$pending = @($active | Where-Object { $null -eq $_.Skip -and ($Redo -or (Get-EntryState -Entry $_) -eq 'pending') })
if (-not [string]::IsNullOrEmpty($Only))
    { $pending = @($pending | Where-Object { $_.File.path -match $Only }) }

if ($DryRun)
{
    if ($pending.Count -eq 0)
        { Write-Host 'Nothing pending.'; return }

    $entry = $pending[0]
    $lineCount = (Get-Content -LiteralPath (Join-Path $RepoRoot $entry.File.path) | Measure-Object -Line).Lines
    Write-Host (New-ReconPrompt -Entry $entry -LineCount $lineCount -Index 1 -Total $total)
    return
}

if ($null -eq (Get-Command Invoke-ModelPrompt -ErrorAction SilentlyContinue))
    { throw 'Invoke-ModelPrompt is not defined. Dot-source your model wrapper first (see the .NOTES block).' }

if (-not (Test-Path $ScanRoot))
    { New-Item -ItemType Directory -Path $ScanRoot -Force | Out-Null }
if (Test-Path $stopFile)
    { Remove-Item -LiteralPath $stopFile -Force }

$startedAt = Get-Date
$analysed = 0
$stopRequested = $false
$limitMessage = ''
$interactive = Test-ConsoleInteractive

# 'm' is only worth offering when something can actually tail the run log.
$runHint = if ($null -eq (Get-MonitorProgram)) { "'q' stops after the current file" }
    else { "'q' stops after the current file, 'm' monitors this run" }

Write-Host ("Analysing {0} pending file(s) of {1} with {3} at effort '{2}'." -f $pending.Count, $total, $Effort, $Model)
Write-StopHint -Interactive $interactive

# The status row would otherwise open blank: the log a call writes has no usage
# reading in it until the first response comes back. The previous run's log is still
# on disk at this point, and its closing figures are a better opening than nothing.
Update-UsageStatus -RawLog $rawLog

foreach ($entry in $pending)
{
    $stopRequested = Update-StopRequest -Current $stopRequested
    if ($stopRequested)
        { break }

    $index = $entries.IndexOf($entry)
    if ($interactive)
        { Show-Checklist -Entries $entries -CurrentIndex $index -StartedAt $startedAt -AnalysedThisRun $analysed }

    $fullPath = Join-Path $RepoRoot $entry.File.path
    $lineCount = (Get-Content -LiteralPath $fullPath | Measure-Object -Line).Lines

    # Numbered against the files that are actually being analysed, so the prompt's
    # "file n of m" matches what the run reports.
    $prompt = New-ReconPrompt -Entry $entry -LineCount $lineCount -Index ([array]::IndexOf($active, $entry) + 1) -Total $total
    $transcript = Join-Path $runsRoot ('{0}.log' -f (Get-ScanFileKey $entry.File.path))
    $transcriptState = Start-RunTranscript -Transcript $transcript -Header "recon | $($entry.File.path)" -Effort $Effort
    $ticker = New-ActivityTicker -Color $palette.Current -Hint $runHint -Signal $keySignal `
        -MonitorPath $transcript -RawLog $rawLog -Transcript $transcript -TranscriptState $transcriptState `
        -Text ("Analysing {0} ({1} lines)..." -f [System.IO.Path]::GetFileName($entry.File.path), $lineCount)
    try
    {
        $recon = Invoke-ModelPrompt -Prompt $prompt -Schema $reconSchema -Model $Model -Effort $Effort `
            -Label "recon:$($entry.File.path)" -AllowDir $RepoRoot -OnWait $ticker -RunLog $rawLog
    }
    catch
    {
        # A drained subscription window is a pause, not a failure. No recon is
        # written, so the file is still pending and a run started after the reset
        # picks it up again here; anything else is a real error and stands.
        if (-not (Test-RateLimitError -ErrorRecord $_))
            { throw }

        Update-RunTranscript -RawLog $rawLog -Transcript $transcript -State $transcriptState
        $limitMessage = $_.Exception.Message
        break
    }

    Update-RunTranscript -RawLog $rawLog -Transcript $transcript -State $transcriptState

    # The log has just gained this call's closing figures, so the next file starts
    # its status row current rather than a cache interval behind.
    Update-UsageStatus -RawLog $rawLog

    if ($recon -is [string])
    {
        $text = $recon.Trim()
        if ($text -match '(?s)^```(?:json)?\s*(?<body>.*?)\s*```$')
            { $text = $Matches['body'] }

        $recon = $text | ConvertFrom-Json
    }

    # Writing the recon is what marks the file done. Read back rather than kept from
    # the call, so the checklist shows exactly what a later run will find on disk.
    Save-Recon -Entry $entry -Recon $recon
    $entry.Recon = Read-ReconRecord -RelativePath $entry.File.path
    $analysed++

    # Poll again here so a q pressed during the model call is acknowledged as soon as
    # the call returns, rather than silently at the top of the next iteration.
    $stopRequested = Update-StopRequest -Current $stopRequested

    if (-not $interactive)
    {
        Write-EntryResult -Entry $entry -Index ([array]::IndexOf($active, $entry)) -Total $total
        Write-StopHint -Interactive $interactive -Terse
    }
}

if ($interactive)
    { Show-Checklist -Entries $entries -StartedAt $startedAt -AnalysedThisRun $analysed }

Write-Host ''
if (-not [string]::IsNullOrEmpty($limitMessage))
{
    Write-Host "  $limitMessage" -ForegroundColor $palette.Warning
    Write-Host "Stopped on the subscription limit. $analysed file(s) analysed this run. Re-run after the reset to continue." -ForegroundColor $palette.Warning
}
elseif ($stopRequested)
    { Write-Host "Stopped early. $analysed file(s) analysed this run. Re-run to continue." -ForegroundColor $palette.Warning }
else
    { Write-Host "Pass complete. $analysed file(s) analysed this run." -ForegroundColor $palette.Success }

#endregion

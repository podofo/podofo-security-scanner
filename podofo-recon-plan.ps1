#!/usr/bin/env pwsh
<#
.SYNOPSIS
Vulnerability audit reconnaissance pass: analyses every file in podofo-recon-plan.json,
one after another, and records proposed investigation targets for a later audit pass.

.DESCRIPTION
The JSON database is both the work list and the progress state. Files are grouped by
tier; each file carries a completion flag, an optional description, and the short
result of its analysis. The database is saved after every file, so the pass resumes
where it left off. Full recon output goes to
governance/security-audit/scan/targets/<file-key>/recon.json.

A file entry may be written either as an object or as a bare path string, which means
a pending, non-ignored file and is written back that way. Setting "ignore": true on
an entry takes the file out of the run: it is never analysed and never counted, but
it stays on the checklist, marked as ignored, so the decision stays visible.

The model analyses one file per call and returns structured recon only. This script
owns the database and renders the checklist.

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
if ([string]::IsNullOrEmpty($DatabasePath))
    { $DatabasePath = Join-Path $PSScriptRoot 'podofo-recon-plan.json' }
if ([string]::IsNullOrEmpty($ScanRoot))
    { $ScanRoot = Join-Path $PSScriptRoot 'scan' }

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

    # A file may be written as a bare path string, which means exactly a pending,
    # non-ignored entry. Everything downstream holds a live reference into the tier,
    # so the expansion has to happen here, once, before Get-Entries reads it.
    foreach ($tier in $db.tiers)
    {
        $tier.files = @(foreach ($file in $tier.files)
        {
            if ($file -is [string]) { [pscustomobject]@{ path = $file } } else { $file }
        })
    }

    return $db
}

# Absent means null, and absent "done" means false, so a field is written only when
# it carries a value. An entry that carries nothing but a path is written back as the
# bare string it may have been typed as, which keeps a hand-edited list readable.
function Save-Database
{
    param([Parameter(Mandatory)][psobject]$Database)

    $tiers = foreach ($tier in $Database.tiers)
    {
        $files = foreach ($file in $tier.files)
        {
            $entry = [ordered]@{ path = $file.path }
            if (Test-FileIgnored -File $file)
                { $entry.ignore = $true }

            if (Test-FileDone -File $file)
                { $entry.done = $true }

            foreach ($name in @('description', 'result'))
            {
                $value = Get-Field -Object $file -Name $name
                if (-not [string]::IsNullOrEmpty($value))
                    { $entry[$name] = $value }
            }

            if ($entry.Count -eq 1) { $file.path } else { $entry }
        }

        [ordered]@{ tier = $tier.tier; description = $tier.description; files = @($files) }
    }

    Write-FileAtomic -Path $DatabasePath -Content (
        [ordered]@{ version = $Database.version; tiers = @($tiers) } | ConvertTo-Json -Depth 8)
}

# Absent means false: an entry is pending until something marks it done.
function Test-FileDone
{
    param([Parameter(Mandatory)][psobject]$File)

    return [bool](Get-Field -Object $File -Name 'done')
}

# Absent means false. An ignored file is never analysed and never counted, but it
# stays in the database and on the checklist so the decision remains visible.
function Test-FileIgnored
{
    param([Parameter(Mandatory)][psobject]$File)

    return [bool](Get-Field -Object $File -Name 'ignore')
}

# Flat iteration order over the tiers. Each row holds a live reference to the file
# object inside the database, so updating a row and saving the database is enough.
function Get-Entries
{
    param([Parameter(Mandatory)][psobject]$Database)

    $entries = [System.Collections.Generic.List[psobject]]::new()
    foreach ($tier in $Database.tiers)
    {
        foreach ($file in $tier.files)
        {
            $entries.Add([pscustomobject]@{
                Tier            = $tier.tier
                TierDescription = $tier.description
                File            = $file
            })
        }
    }

    return $entries
}

#endregion

#region Rendering

function Get-EntryStatusText
{
    param([Parameter(Mandatory)][psobject]$Entry, [switch]$Current)

    if ($Current)
        { return 'analysing...' }
    if (Test-FileIgnored -File $Entry.File)
        { return 'ignored' }
    if (Test-FileDone -File $Entry.File)
        { return (Get-Field -Object $Entry.File -Name 'result') }

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
    if (Test-FileIgnored -File $Entry.File)
        { return $palette.Muted }
    if (-not (Test-FileDone -File $Entry.File))
        { return $palette.Muted }

    switch -Regex ([string](Get-Field -Object $Entry.File -Name 'result'))
    {
        '^high'    { return $palette.High }
        '^medium'  { return $palette.Medium }
        '^low'     { return $palette.Low }
        '^skipped' { return $palette.Muted }
        default    { return $palette.Hint }
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
            elseif (Test-FileIgnored -File $entry.File) { '-' }
            elseif (Test-FileDone -File $entry.File) { 'x' }
            else { ' ' }
        $text = '  [{0}] {1}  {2}' -f $mark,
            ([System.IO.Path]::GetFileName($entry.File.path).PadRight($nameWidth)),
            (Get-EntryStatusText -Entry $entry -Current:$isCurrent)

        if ($isCurrent)
            { $currentRow = $rows.Count }

        $rows.Add([pscustomobject]@{ Text = $text.TrimEnd(); Color = (Get-EntryColor -Entry $entry -Current:$isCurrent) })
    }

    # Ignored files are shown but not counted, so the ratio tracks the real work.
    $active = @($Entries | Where-Object { -not (Test-FileIgnored -File $_.File) })
    $done = @($active | Where-Object { Test-FileDone -File $_.File }).Count
    $ignored = $Entries.Count - $active.Count
    $skipped = if ($ignored -gt 0) { "   $ignored ignored" } else { '' }
    $elapsed = (Get-Date) - $StartedAt
    $rate = if ($AnalysedThisRun -gt 0) { ' | {0:n0}s/file' -f ($elapsed.TotalSeconds / $AnalysedThisRun) } else { '' }

    try { Clear-Host } catch { }
    Write-Host ('PoDoFo recon   {0}/{1} analysed{2}   {3:hh\:mm\:ss} elapsed{4}' -f $done, $active.Count, $skipped, $elapsed, $rate) -ForegroundColor $palette.Header

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
        [System.IO.Path]::GetFileName($Entry.File.path), (Get-Field -Object $Entry.File -Name 'result'))
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
    Write-Host '  Stop requested. Saving the current file; no further files will be started.' -ForegroundColor $palette.Warning
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
    if (-not (Test-Path $targetDir))
        { New-Item -ItemType Directory -Path $targetDir -Force | Out-Null }

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
$entries = Get-Entries -Database $db

# Ignored files stay in $entries so the checklist still shows them, but they are not
# work and they are not part of the total the run reports against.
$active = @($entries | Where-Object { -not (Test-FileIgnored -File $_.File) })
$total = $active.Count

$pending = @($active | Where-Object { $Redo -or -not (Test-FileDone -File $_.File) })
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

Write-Host ("Analysing {0} pending file(s) of {1} at effort '{2}'." -f $pending.Count, $total, $Effort)
Write-StopHint -Interactive $interactive

foreach ($entry in $pending)
{
    $stopRequested = Update-StopRequest -Current $stopRequested
    if ($stopRequested)
        { break }

    $index = $entries.IndexOf($entry)
    if ($interactive)
        { Show-Checklist -Entries $entries -CurrentIndex $index -StartedAt $startedAt -AnalysedThisRun $analysed }

    $fullPath = Join-Path $RepoRoot $entry.File.path
    if (-not (Test-Path $fullPath))
    {
        Set-Field -Object $entry.File -Name 'result' -Value 'skipped (missing on disk)'
    }
    else
    {
        $lineCount = (Get-Content -LiteralPath $fullPath | Measure-Object -Line).Lines
        $header = (Get-Content -LiteralPath $fullPath -TotalCount 5) -join "`n"
        if ($header -match 'was generated\. DO NOT EDIT')
        {
            Set-Field -Object $entry.File -Name 'result' -Value "skipped (generated, $lineCount lines)"
        }
        else
        {
            # Numbered against the files that are actually being analysed, so the
            # prompt's "file n of m" matches what the run reports.
            $prompt = New-ReconPrompt -Entry $entry -LineCount $lineCount -Index ([array]::IndexOf($active, $entry) + 1) -Total $total
            $transcript = Join-Path $runsRoot ('{0}.log' -f (Get-ScanFileKey $entry.File.path))
            $transcriptState = Start-RunTranscript -Transcript $transcript -Header "recon | $($entry.File.path)" -Effort $Effort
            $ticker = New-ActivityTicker -Color $palette.Current -Hint $runHint -Signal $keySignal `
                -MonitorPath $transcript -RawLog $rawLog -Transcript $transcript -TranscriptState $transcriptState `
                -Text ("Analysing {0} ({1} lines)..." -f [System.IO.Path]::GetFileName($entry.File.path), $lineCount)
            try
            {
                $recon = Invoke-ModelPrompt -Prompt $prompt -Schema $reconSchema -Effort $Effort `
                    -Label "recon:$($entry.File.path)" -AllowDir $RepoRoot -OnWait $ticker -RunLog $rawLog
            }
            catch
            {
                # A drained subscription window is a pause, not a failure. The file
                # is left pending and untouched, so a run started after the reset
                # picks it up again here; anything else is a real error and stands.
                if (-not (Test-RateLimitError -ErrorRecord $_))
                    { throw }

                Update-RunTranscript -RawLog $rawLog -Transcript $transcript -State $transcriptState
                $limitMessage = $_.Exception.Message
                break
            }

            Update-RunTranscript -RawLog $rawLog -Transcript $transcript -State $transcriptState
            if ($recon -is [string])
            {
                $text = $recon.Trim()
                if ($text -match '(?s)^```(?:json)?\s*(?<body>.*?)\s*```$')
                    { $text = $Matches['body'] }

                $recon = $text | ConvertFrom-Json
            }

            Save-Recon -Entry $entry -Recon $recon
            Set-Field -Object $entry.File -Name 'result' -Value (Format-ResultAnnotation -Recon $recon)
            $analysed++
        }
    }

    # Poll again here so a q pressed during the model call is acknowledged as soon as
    # the call returns, rather than silently at the top of the next iteration.
    $stopRequested = Update-StopRequest -Current $stopRequested

    Set-Field -Object $entry.File -Name 'done' -Value $true
    Save-Database -Database $db
    if (-not $interactive)
    {
        Write-EntryResult -Entry $entry -Index $index -Total $total
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

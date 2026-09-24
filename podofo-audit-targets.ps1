#!/usr/bin/env pwsh
<#
.SYNOPSIS
Audit pass: works the investigation targets produced by the recon phase, auditing and
then validating each one, and leaves a report per target.

.DESCRIPTION
Every run begins by syncing podofo-audit-targets.json against the recon files under
scan/targets. Unseen targets are inserted as pending, existing rows keep their state
untouched, and a row whose recon target has vanished is flagged orphaned rather than
deleted. Reconciliation only touches rows with source "recon", so targets spawned by
the validator survive. That makes the phases interleavable: resume the recon pass,
run this again, and the new targets are simply there.

Each target then gets two model calls. The audit call looks for one candidate
vulnerability; the validate call, a separate process that cannot see the auditor's
reasoning, accepts or rejects it. The report at scan/targets/<file-key>/<id>.md is
written by this script from structured output, not by the model, which keeps the
model read-only.

Press 'q' at any time to stop after the current target finishes. Creating the file
scan/STOP has the same effect, for non-interactive runs.

Each model call streams its events to scan/runs/audit/<id>-audit.jsonl and
<id>-validate.jsonl as it happens, overwritten on a re-run. Press 'm' while a call is
in flight to open the log for whichever stage is running in Notepad++ with -monitor,
which tails it live. 'm' is offered only when Notepad++ is found on the machine.

.NOTES
The model seam is dot-sourced from model-seam-claude.ps1 (override with
-ModelScript). Both stages read source, so it must be an agent invocation with
repository read access and schema-constrained output.
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
    [string]$Id,
    [ValidateSet('high', 'medium', 'low')][string]$MinPriority,
    [int]$MaxTargets,
    [double]$MaxSpendUsd,
    [switch]$Redo,
    [switch]$SyncOnly,
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
    { $DatabasePath = Join-Path $PSScriptRoot 'podofo-audit-targets.json' }
if ([string]::IsNullOrEmpty($ScanRoot))
    { $ScanRoot = Join-Path $PSScriptRoot 'scan' }

$targetsRoot = Join-Path $ScanRoot 'targets'
$stopFile = Join-Path $ScanRoot 'STOP'
$runsRoot = Join-Path $ScanRoot 'runs/audit'
# Raw streamed events go to one reused working file; the readable transcript per run
# is what is kept and what 'm' opens.
$rawLog = Join-Path $ScanRoot 'runs/audit-monitor.jsonl'

. (Join-Path $PSScriptRoot 'audit-common.ps1')

if (Test-Path $ModelScript)
    { . $ModelScript }

$priorityRank = @{ high = 0; medium = 1; low = 2; none = 3 }
$confidenceRank = @{ high = 0; medium = 1; low = 2 }
$palette = Get-AuditPalette

# Set by the activity ticker when q is pressed mid-call, so the keypress is not lost
# to the ticker's own key draining.
$keySignal = @{ Stop = $false }

#region Database

function Read-TargetDatabase
{
    if (-not (Test-Path $DatabasePath))
        { return [pscustomobject]@{ version = 1; targets = @() } }

    return (Get-Content -LiteralPath $DatabasePath -Raw -Encoding utf8 | ConvertFrom-Json)
}

# Absent means null, so a field is written only when it carries a value.
function Save-TargetDatabase
{
    param([Parameter(Mandatory)][psobject]$Database)

    $rows = foreach ($target in $Database.targets)
    {
        $row = [ordered]@{
            seq         = $target.seq
            id          = $target.id
            source      = $target.source
            origin_file = $target.origin_file
            priority    = $target.priority
            confidence  = $target.confidence
            state       = $target.state
            target      = $target.target
        }

        foreach ($name in @('rationale', 'verdict', 'severity', 'slug', 'report',
                            'validation_rationale', 'duplicate_of', 'audited_utc', 'validated_utc'))
        {
            $value = Get-Field -Object $target -Name $name
            if (-not [string]::IsNullOrEmpty($value))
                { $row[$name] = $value }
        }

        if (Get-Field -Object $target -Name 'orphaned')
            { $row.orphaned = $true }

        $row
    }

    Write-FileAtomic -Path $DatabasePath -Content (
        [ordered]@{ version = 1; targets = @($rows) } | ConvertTo-Json -Depth 8)
}

#endregion

#region Sync

function Read-AllRecon
{
    if (-not (Test-Path $targetsRoot))
        { return @() }

    $records = foreach ($file in Get-ChildItem -Path $targetsRoot -Filter 'recon.json' -Recurse -File)
        { Get-Content -LiteralPath $file.FullName -Raw -Encoding utf8 | ConvertFrom-Json }

    return @($records)
}

function Get-ReconFor
{
    param([Parameter(Mandatory)][string]$OriginFile)

    $path = Join-Path (Join-Path $targetsRoot (Get-ScanFileKey $OriginFile)) 'recon.json'
    if (-not (Test-Path $path))
        { return $null }

    return (Get-Content -LiteralPath $path -Raw -Encoding utf8 | ConvertFrom-Json)
}

# Inserts unseen targets, never touches the state of an existing row, and flags rows
# whose recon target has vanished. Spawned targets are skipped entirely, since they
# have no recon backing them and would otherwise be orphaned on every run.
function Sync-Targets
{
    param([Parameter(Mandatory)][psobject]$Database)

    $byId = @{}
    foreach ($row in $Database.targets)
        { $byId[$row.id] = $row }

    $seen = @{}
    $added = 0
    # Measure-Object yields a double, and seq is an identifier, not a measurement.
    $nextSeq = 1
    if (@($Database.targets).Count -gt 0)
        { $nextSeq = [int](@($Database.targets | ForEach-Object { $_.seq }) | Measure-Object -Maximum).Maximum + 1 }

    $rows = [System.Collections.Generic.List[psobject]]::new()
    foreach ($row in $Database.targets)
        { $rows.Add($row) }

    foreach ($recon in Read-AllRecon)
    {
        foreach ($target in @($recon.recon.proposed_targets))
        {
            $seen[$target.id] = $true
            if ($byId.ContainsKey($target.id))
                { continue }

            $rows.Add([pscustomobject]@{
                seq         = $nextSeq++
                id          = $target.id
                source      = 'recon'
                origin_file = $recon.origin_file
                priority    = $recon.recon.audit_priority
                confidence  = $target.confidence
                state       = 'pending'
                target      = $target.target
                rationale   = $target.rationale
            })
            $added++
        }
    }

    $orphaned = 0
    foreach ($row in $rows)
    {
        if ($row.source -ne 'recon')
            { continue }

        $isOrphan = -not $seen.ContainsKey($row.id)
        if ($isOrphan -and -not (Get-Field -Object $row -Name 'orphaned'))
            { $orphaned++ }

        Set-Field -Object $row -Name 'orphaned' -Value $isOrphan
    }

    $Database.targets = @($rows)
    return [pscustomobject]@{ Added = $added; Orphaned = $orphaned; Total = $rows.Count }
}

#endregion

#region Queue

function Get-QueueOrder
{
    param([Parameter(Mandatory)][AllowEmptyCollection()][psobject[]]$Targets)

    return @($Targets | Sort-Object `
        @{ Expression = { $priorityRank[[string]$_.priority] } },
        @{ Expression = { $confidenceRank[[string]$_.confidence] } },
        @{ Expression = { $_.seq } })
}

function Test-TargetPending
{
    param([Parameter(Mandatory)][psobject]$Target)

    return ($Target.state -eq 'pending' -or $Target.state -eq 'audited')
}

# A seam is not required to track spend, so an absent counter means "unknown" rather
# than zero. Testing the variable's existence avoids StrictMode throwing on it.
function Get-ModelSpend
{
    if (-not (Test-Path 'variable:global:PodofoModelStats'))
        { return $null }

    return [double]$global:PodofoModelStats.CostUsd
}

#endregion

#region Prompts

# Findings already stored for this origin file, in full: duplicates cluster within a
# file, so this is where the dedup pressure needs to be. Everything accepted
# elsewhere gets one line, which keeps the prompt bounded as the run grows.
function Format-DedupContext
{
    param(
        [Parameter(Mandatory)][psobject]$Database,
        [Parameter(Mandatory)][string]$OriginFile,
        [Parameter(Mandatory)][string]$ExcludeId
    )

    $sameFile = @($Database.targets | Where-Object {
        $_.origin_file -eq $OriginFile -and $_.id -ne $ExcludeId -and
        (Get-Field -Object $_ -Name 'verdict') })

    $lines = @()
    if ($sameFile.Count -eq 0)
    {
        $lines += 'Findings already recorded for this file: (none)'
    }
    else
    {
        $lines += 'Findings already recorded for this file:'
        foreach ($row in $sameFile)
        {
            $lines += ('- [{0}] {1} ({2}) id {3}' -f $row.verdict, (Get-Field -Object $row -Name 'slug'),
                (Get-Field -Object $row -Name 'severity'), $row.id)
            $lines += ('  target: {0}' -f $row.target)
            $lines += ('  outcome: {0}' -f (Get-Field -Object $row -Name 'validation_rationale'))
        }
    }

    $elsewhere = @($Database.targets | Where-Object {
        $_.origin_file -ne $OriginFile -and (Get-Field -Object $_ -Name 'verdict') -eq 'accepted' })

    $lines += ''
    if ($elsewhere.Count -eq 0)
    {
        $lines += 'Accepted findings elsewhere in the codebase: (none)'
    }
    else
    {
        $lines += 'Accepted findings elsewhere in the codebase:'
        foreach ($row in $elsewhere)
            { $lines += ('- [{0}] {1} in {2}' -f (Get-Field -Object $row -Name 'severity'), (Get-Field -Object $row -Name 'slug'), $row.origin_file) }
    }

    return ($lines -join "`n")
}

# The recon this target came from, so the auditor does not spend its first turns
# rediscovering the shape of a file we have already characterised.
function Format-ReconContext
{
    param([Parameter(Mandatory)][string]$OriginFile)

    $recon = Get-ReconFor -OriginFile $OriginFile
    if ($null -eq $recon)
        { return '(no recon on file)' }

    $lines = @("Summary: $($recon.recon.summary)", "Input exposure: $($recon.recon.input_exposure)")

    $entryPoints = @($recon.recon.entry_points)
    if ($entryPoints.Count -gt 0)
    {
        $lines += 'Entry points for untrusted data:'
        foreach ($entry in $entryPoints) { $lines += "- $entry" }
    }

    $risky = @($recon.recon.risky_constructs)
    if ($risky.Count -gt 0)
    {
        $lines += 'Risky constructs noted during recon:'
        foreach ($item in $risky) { $lines += "- $($item.function): $($item.observation)" }
    }

    $invariants = @($recon.recon.assumed_invariants)
    if ($invariants.Count -gt 0)
    {
        $lines += 'Invariants the code assumes:'
        foreach ($item in $invariants) { $lines += "- $($item.invariant) (guaranteed by: $($item.guaranteed_by))" }
    }

    return ($lines -join "`n")
}

$auditSchema = @{
    type                 = 'object'
    additionalProperties = $false
    required             = @('candidate_found', 'candidate_name', 'severity', 'reachability', 'confidence',
                             'crash_claim', 'root_cause', 'trigger_path', 'evidence', 'reproduction_sketch',
                             'constraints', 'final_assessment')
    properties           = @{
        candidate_found     = @{ type = 'boolean' }
        candidate_name      = @{ type = 'string' }
        severity            = @{ type = 'string'; enum = @('critical', 'high', 'medium', 'low', 'info', 'none') }
        reachability        = @{ type = 'string' }
        confidence          = @{ type = 'string'; enum = @('low', 'medium', 'high') }
        crash_claim         = @{ type = 'string' }
        root_cause          = @{ type = 'string' }
        trigger_path        = @{ type = 'string' }
        evidence            = @{ type = 'string' }
        reproduction_sketch = @{ type = 'string' }
        constraints         = @{ type = 'string' }
        final_assessment    = @{ type = 'string' }
    }
}

function New-AuditPrompt
{
    param(
        [Parameter(Mandatory)][psobject]$Target,
        [Parameter(Mandatory)][psobject]$Database
    )

    return @"
You are auditing PoDoFo for crash-class vulnerabilities.

Repository root: $RepoRoot
Target file: $($Target.origin_file)
Investigation target: $($Target.target)
Why recon proposed it: $(Get-Field -Object $Target -Name 'rationale')

What recon already established about this file:
$(Format-ReconContext -OriginFile $Target.origin_file)

$(Format-DedupContext -Database $Database -OriginFile $Target.origin_file -ExcludeId $Target.id)

Your task:
- Investigate this one target. Read the file and whatever related PoDoFo code you
  need to confirm or reject the hypothesis.
- Find at most one candidate vulnerability: data structure corruption, buffer
  overflow, use-after-free, invalid memory access, integer overflow leading to
  memory corruption, unbounded recursion, or a comparable bug that can realistically
  crash PoDoFo.
- Only consider attack surfaces reachable through documented PoDoFo API usage, or
  through loading, parsing or writing corrupted PDF files.
- Reject anything requiring a specially crafted PoDoFo module, module API misuse by
  a third party, or loading attacker-controlled module code.
- Reject speculative issues that depend on impossible states, debug-only conditions
  or obviously broken assumptions.
- Do not materially duplicate a finding already recorded above.
- Do not modify any PoDoFo source file.

Finding nothing is a valid and expected result. If the target does not hold up, set
candidate_found to false, say plainly why in final_assessment, and set severity to
none. Do not manufacture a finding to fill the fields.

Output rules:
- candidate_found: true only if you are putting forward a real candidate.
- candidate_name: short descriptive name, empty when candidate_found is false.
- crash_claim: what concretely goes wrong, and what the observable failure is.
- root_cause: the specific code defect, naming functions and lines.
- trigger_path: the reachable path from attacker input or API call to the defect.
- evidence: the code you read that supports the claim, with file and line references.
- reproduction_sketch: how one would construct the input or call sequence.
- constraints: what must hold for this to fire, and what you could not verify.
- final_assessment: your honest overall judgement, including the case against.

Write plain ASCII throughout, matching the repository convention: a regular hyphen
rather than an em dash, and three dots rather than an ellipsis character.
"@
}

$validateSchema = @{
    type                 = 'object'
    additionalProperties = $false
    required             = @('verdict', 'severity', 'slug', 'rationale')
    properties           = @{
        verdict          = @{ type = 'string'; enum = @('accepted', 'rejected') }
        severity         = @{ type = 'string'; enum = @('critical', 'high', 'medium', 'low', 'info', 'none') }
        slug             = @{ type = 'string' }
        rationale        = @{ type = 'string' }
        duplicate_of     = @{ type = 'string' }
        spawned_targets  = @{ type = 'array'; items = @{ type = 'string' } }
    }
}

function New-ValidatePrompt
{
    param(
        [Parameter(Mandatory)][psobject]$Target,
        [Parameter(Mandatory)][psobject]$Database,
        [Parameter(Mandatory)][string]$ReportPath
    )

    return @"
You are validating a PoDoFo crash-class vulnerability report.

Repository root: $RepoRoot
Report to validate: $ReportPath
Target file: $($Target.origin_file)
Investigation target: $($Target.target)

$(Format-DedupContext -Database $Database -OriginFile $Target.origin_file -ExcludeId $Target.id)

Read the report and inspect PoDoFo code as needed to check it. Do not modify any
PoDoFo source file.

Validation bar:
- Accept only if the claimed issue can realistically happen.
- There must be a concrete path from reachable input or state to a crash, memory
  corruption or comparable fatal failure.
- The trigger must come from documented PoDoFo API usage, or from corrupted PDF
  files being loaded, parsed or written.
- Reject anything that materially duplicates a finding already recorded above, even
  if worded differently. Name the duplicated id in duplicate_of when you do.
- Reject anything depending on a specially crafted PoDoFo module, malicious module
  loading, or third-party module API misuse.
- Reject issues that are purely theoretical, depend on an impossible invariant
  breaking first, or lack a convincing trigger path.
- A report that already concluded no candidate exists should be rejected, with a
  rationale confirming or correcting that conclusion.

Be adversarial. The auditor was asked to look for a bug and had every incentive to
find one; your job is to be the reader who does not. Rejecting is a good outcome.

Output rules:
- verdict: accepted or rejected.
- severity: the severity you judge correct, which may differ from the report's.
  Use none when rejecting.
- slug: lowercase hyphenated vulnerability name of at most six words, for example
  pdfencrypt-tree-memory-corruption. It names the report file, so make the words
  specific to this finding. Use rejected-no-credible-crash when rejecting.
- rationale: concise explanation of why the finding survives or fails.
- duplicate_of: the id of the finding this duplicates, only when rejecting as one.
- spawned_targets: optional. If your review surfaced a genuinely different lead
  worth auditing separately, state each as a narrow investigation target. Leave
  empty unless the lead is concrete.

Write plain ASCII throughout, matching the repository convention: a regular hyphen
rather than an em dash, and three dots rather than an ellipsis character.
"@
}

#endregion

#region Report

# A few descriptive words, lowercase and hyphenated. The id trails so listings sort
# by subject rather than by hash, and so the report stays addressable by its stable
# identity after the validator renames the finding.
function ConvertTo-ReportSlug
{
    param([string]$Text, [int]$MaxWords = 6)

    if ([string]::IsNullOrWhiteSpace($Text))
        { return 'no-candidate' }

    $words = @(($Text.ToLowerInvariant() -replace '[^a-z0-9]+', ' ').Trim() -split '\s+' |
        Where-Object { $_.Length -gt 0 } | Select-Object -First $MaxWords)

    if ($words.Count -eq 0)
        { return 'no-candidate' }

    return ($words -join '-')
}

function Get-TargetDir
{
    param([Parameter(Mandatory)][psobject]$Target)

    return (Join-Path $targetsRoot (Get-ScanFileKey $Target.origin_file))
}

function Get-ReportPath
{
    param([Parameter(Mandatory)][psobject]$Target, [string]$Slug)

    return (Join-Path (Get-TargetDir -Target $Target) ('{0}-{1}.md' -f (ConvertTo-ReportSlug $Slug), $Target.id))
}

# The report is addressed by target id, so it can be found again whatever the
# descriptive part currently says.
function Find-ExistingReports
{
    param([Parameter(Mandatory)][psobject]$Target)

    $directory = Get-TargetDir -Target $Target
    if (-not (Test-Path $directory))
        { return @() }

    return @(Get-ChildItem -LiteralPath $directory -File -Filter "*$($Target.id).md")
}

# Written by the script rather than by the model, so the model stays read-only and
# the report shape stays consistent across the whole run.
function Write-Report
{
    param(
        [Parameter(Mandatory)][psobject]$Target,
        [Parameter(Mandatory)][psobject]$Audit,
        [psobject]$Validation
    )

    $status = if ($null -eq $Validation) { 'UNVALIDATED' } else { $Validation.verdict.ToUpperInvariant() }
    $severity = if ($null -eq $Validation) { $Audit.severity } else { $Validation.severity }
    $name = if ([string]::IsNullOrEmpty($Audit.candidate_name)) { 'No candidate found' } else { $Audit.candidate_name }

    $lines = @(
        "# $name"
        ''
        "- Status: $status"
        "- Severity: $severity"
        "- Target file: $($Target.origin_file)"
        "- Target id: $($Target.id)"
        "- Investigation target: $($Target.target)"
        "- Reachability: $($Audit.reachability)"
        "- Auditor confidence: $($Audit.confidence)"
        "- Candidate put forward: $($Audit.candidate_found)"
        ''
        '## Crash claim'
        ''
        $Audit.crash_claim
        ''
        '## Root cause'
        ''
        $Audit.root_cause
        ''
        '## Trigger path'
        ''
        $Audit.trigger_path
        ''
        '## Evidence'
        ''
        $Audit.evidence
        ''
        '## Reproduction sketch'
        ''
        $Audit.reproduction_sketch
        ''
        '## Constraints and assumptions'
        ''
        $Audit.constraints
        ''
        '## Final assessment'
        ''
        $Audit.final_assessment
    )

    if ($null -ne $Validation)
    {
        $lines += @('', '## Validation', '', "Verdict: $($Validation.verdict)", '', $Validation.rationale)
        $duplicate = Get-Field -Object $Validation -Name 'duplicate_of'
        if (-not [string]::IsNullOrEmpty($duplicate))
            { $lines += @('', "Duplicate of: $duplicate") }
    }

    # The validator's slug wins once it exists; before that the auditor's candidate
    # name gives the report a readable name straight away.
    $slug = if ($null -ne $Validation) { $Validation.slug } else { $Audit.candidate_name }

    $path = Get-ReportPath -Target $Target -Slug $slug
    $directory = Split-Path -Parent $path
    if (-not (Test-Path $directory))
        { New-Item -ItemType Directory -Path $directory -Force | Out-Null }

    Write-FileAtomic -Path $path -Content (($lines -join "`n") + "`n")

    # Validation usually renames the report, so drop the earlier name for this id.
    foreach ($stale in Find-ExistingReports -Target $Target)
    {
        if ($stale.FullName -ne (Resolve-Path -LiteralPath $path).Path)
            { Remove-Item -LiteralPath $stale.FullName -Force }
    }

    return $path
}

#endregion

#region Rendering

function Get-TargetColor
{
    param([Parameter(Mandatory)][psobject]$Target, [switch]$Current)

    if ($Current)
        { return $palette.Current }

    switch ([string]$Target.state)
    {
        'accepted' { return $palette.High }
        'rejected' { return $palette.Muted }
        'audited'  { return $palette.Medium }
        default    { return $palette.Muted }
    }
}

function Get-TargetStatusText
{
    param([Parameter(Mandatory)][psobject]$Target, [string]$Activity)

    if (-not [string]::IsNullOrEmpty($Activity))
        { return $Activity }

    switch ([string]$Target.state)
    {
        'accepted' { return "accepted, $(Get-Field -Object $Target -Name 'severity'), $(Get-Field -Object $Target -Name 'slug')" }
        'rejected' { return "rejected, $(Get-Field -Object $Target -Name 'slug')" }
        'audited'  { return 'audited, awaiting validation' }
        default    { return "$($Target.priority)/$($Target.confidence)" }
    }
}

function Show-Queue
{
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][psobject[]]$Queue,
        [int]$CurrentIndex = -1,
        [string]$Activity,
        [Parameter(Mandatory)][datetime]$StartedAt,
        [int]$DoneThisRun = 0
    )

    $rows = [System.Collections.Generic.List[psobject]]::new()
    $currentRow = -1
    $lastFile = ''
    for ($i = 0; $i -lt $Queue.Count; $i++)
    {
        $target = $Queue[$i]
        if ($target.origin_file -ne $lastFile)
        {
            if ($rows.Count -gt 0)
                { $rows.Add([pscustomobject]@{ Text = ''; Color = $palette.Muted }) }

            $rows.Add([pscustomobject]@{ Text = "  $($target.origin_file)"; Color = $palette.Group })
            $lastFile = $target.origin_file
        }

        $isCurrent = ($i -eq $CurrentIndex)
        $mark = if ($isCurrent) { '>' } elseif ($target.state -eq 'pending') { ' ' } else { 'x' }
        $text = '  [{0}] {1} {2}  {3}' -f $mark, $target.id, ('#' + $target.seq).PadRight(5),
            (Get-TargetStatusText -Target $target -Activity $(if ($isCurrent) { $Activity } else { '' }))

        if ($isCurrent)
            { $currentRow = $rows.Count }

        $rows.Add([pscustomobject]@{ Text = $text.TrimEnd(); Color = (Get-TargetColor -Target $target -Current:$isCurrent) })
    }

    $accepted = @($Queue | Where-Object { $_.state -eq 'accepted' }).Count
    $rejected = @($Queue | Where-Object { $_.state -eq 'rejected' }).Count
    $settled = $accepted + $rejected
    $rate = if ($settled -gt 0) { ' | {0:p0} accepted' -f ($accepted / $settled) } else { '' }
    $spent = Get-ModelSpend
    $spend = if ($null -ne $spent) { ' | {0:n2} USD' -f $spent } else { '' }
    $elapsed = (Get-Date) - $StartedAt

    try { Clear-Host } catch { }
    Write-Host ('PoDoFo audit   {0} accepted / {1} rejected of {2}   {3:hh\:mm\:ss}{4}{5}' -f
        $accepted, $rejected, $Queue.Count, $elapsed, $rate, $spend) -ForegroundColor $palette.Header

    if ($CurrentIndex -ge 0)
        { Write-Host ('  ' + $Queue[$CurrentIndex].origin_file) -ForegroundColor $palette.Group }

    Write-Host ''
    # Reserves the header, the file line, the two status rows and some slack.
    Write-Viewport -Rows $rows -CurrentRow $currentRow -Reserved 8
}

function Write-TargetResult
{
    param([Parameter(Mandatory)][psobject]$Target)

    Write-Host ('[#{0,-4}] {1} {2,-46} {3}' -f $Target.seq, $Target.id,
        [System.IO.Path]::GetFileName($Target.origin_file), (Get-TargetStatusText -Target $Target))
}

function Write-StopHint
{
    param([bool]$Interactive, [switch]$Terse)

    if ($Interactive)
    {
        Write-Host "  Press 'q' to stop after the current target finishes." -ForegroundColor $palette.Hint
        return
    }

    if ($Terse)
        { Write-Host '  (create the STOP file to stop after the current target)' -ForegroundColor $palette.Hint }
    else
        { Write-Host "  Create $stopFile to stop after the current target finishes." -ForegroundColor $palette.Hint }
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

    # Keystrokes pressed while a model call was running are still buffered here.
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
        # No usable console. Fall back to the stop file.
    }

    return $false
}

# Acknowledges the request the first time it is seen, so q does not take effect
# silently while a long model call is still running.
function Update-StopRequest
{
    param([bool]$Current)

    if ($Current)
        { return $true }
    if (-not (Test-StopRequested -Already $false))
        { return $false }

    Write-Host ''
    Write-Host '  Stop requested. Finishing the current target; no further targets will be started.' -ForegroundColor $palette.Warning
    return $true
}

#endregion

#region Main

$db = Read-TargetDatabase
$syncResult = Sync-Targets -Database $db
Save-TargetDatabase -Database $db

Write-Host ("Synced from recon: {0} target(s) total, {1} newly added, {2} newly orphaned." -f
    $syncResult.Total, $syncResult.Added, $syncResult.Orphaned)

if ($SyncOnly)
{
    $pendingCount = @($db.targets | Where-Object { Test-TargetPending -Target $_ }).Count
    Write-Host "$pendingCount target(s) pending."
    return
}

# Wrapped: a single-target database unrolls to a bare object, and the [array]
# lookups the display does need an array either way.
$queue = @(Get-QueueOrder -Targets @($db.targets))
$work = @($queue | Where-Object { $Redo -or (Test-TargetPending -Target $_) })
if (-not [string]::IsNullOrEmpty($Only))
    { $work = @($work | Where-Object { $_.origin_file -match $Only }) }
if (-not [string]::IsNullOrEmpty($Id))
    { $work = @($work | Where-Object { $_.id -eq $Id }) }
if (-not [string]::IsNullOrEmpty($MinPriority))
    { $work = @($work | Where-Object { $priorityRank[[string]$_.priority] -le $priorityRank[$MinPriority] }) }
if ($MaxTargets -gt 0)
    { $work = @($work | Select-Object -First $MaxTargets) }

if ($DryRun)
{
    if ($work.Count -eq 0)
        { Write-Host 'Nothing pending.'; return }

    Write-Host (New-AuditPrompt -Target $work[0] -Database $db)
    return
}

if ($null -eq (Get-Command Invoke-ModelPrompt -ErrorAction SilentlyContinue))
    { throw 'Invoke-ModelPrompt is not defined. Dot-source your model wrapper first (see the .NOTES block).' }

if (-not (Test-Path $ScanRoot))
    { New-Item -ItemType Directory -Path $ScanRoot -Force | Out-Null }
if (Test-Path $stopFile)
    { Remove-Item -LiteralPath $stopFile -Force }

$startedAt = Get-Date
$doneThisRun = 0
$stopRequested = $false
$limitMessage = ''
$interactive = Test-ConsoleInteractive

# 'm' is only worth offering when something can actually tail the run log.
$runHint = if ($null -eq (Get-MonitorProgram)) { "'q' stops after the current target" }
    else { "'q' stops after the current target, 'm' monitors this run" }

Write-Host ("Working {0} target(s) of {1} with {3} at effort '{2}'." -f $work.Count, @($db.targets).Count, $Effort, $Model)
Write-StopHint -Interactive $interactive

# The status row would otherwise open blank: the log a call writes has no usage
# reading in it until the first response comes back. The previous run's log is still
# on disk at this point, and its closing figures are a better opening than nothing.
Update-UsageStatus -RawLog $rawLog

foreach ($target in $work)
{
    $stopRequested = Update-StopRequest -Current $stopRequested
    if ($stopRequested)
        { break }

    $spentSoFar = Get-ModelSpend
    if ($MaxSpendUsd -gt 0 -and $null -ne $spentSoFar -and $spentSoFar -ge $MaxSpendUsd)
    {
        Write-Host ''
        Write-Host ('  Spend cap reached ({0:n2} of {1:n2} USD). Stopping.' -f $spentSoFar, $MaxSpendUsd) -ForegroundColor $palette.Warning
        break
    }

    $index = [array]::IndexOf($queue, $target)
    $label = "$($target.id):$([System.IO.Path]::GetFileName($target.origin_file))"

    if ($interactive)
        { Show-Queue -Queue $queue -CurrentIndex $index -Activity 'auditing...' -StartedAt $startedAt -DoneThisRun $doneThisRun }

    $auditTranscript = Join-Path $runsRoot "$($target.id)-audit.log"
    $auditState = Start-RunTranscript -Transcript $auditTranscript -Header "audit | #$($target.seq) $($target.id) | $($target.origin_file)" -Effort $Effort
    $ticker = New-ActivityTicker -Color $palette.Current -Hint $runHint -Signal $keySignal `
        -MonitorPath $auditTranscript -RawLog $rawLog -Transcript $auditTranscript -TranscriptState $auditState `
        -Text ("Auditing #{0} {1} in {2}..." -f $target.seq, $target.id, [System.IO.Path]::GetFileName($target.origin_file))
    try
    {
        $audit = Invoke-ModelPrompt -Prompt (New-AuditPrompt -Target $target -Database $db) `
            -Schema $auditSchema -Model $Model -Effort $Effort -Label "audit:$label" -AllowDir $RepoRoot -OnWait $ticker -RunLog $rawLog
    }
    catch
    {
        # A drained subscription window is a pause, not a failure. The target keeps
        # the state it had, so a run started after the reset takes it from here;
        # anything else is a real error and stands.
        if (-not (Test-RateLimitError -ErrorRecord $_))
            { throw }

        Update-RunTranscript -RawLog $rawLog -Transcript $auditTranscript -State $auditState
        $limitMessage = $_.Exception.Message
        break
    }

    Update-RunTranscript -RawLog $rawLog -Transcript $auditTranscript -State $auditState

    # The log has just gained this call's closing figures, so validation starts its
    # status row current rather than a cache interval behind.
    Update-UsageStatus -RawLog $rawLog

    $reportPath = Write-Report -Target $target -Audit $audit
    Set-Field -Object $target -Name 'state' -Value 'audited'
    Set-Field -Object $target -Name 'report' -Value $reportPath
    Set-Field -Object $target -Name 'audited_utc' -Value ((Get-Date).ToUniversalTime().ToString('o'))
    Save-TargetDatabase -Database $db

    if ($interactive)
        { Show-Queue -Queue $queue -CurrentIndex $index -Activity 'validating...' -StartedAt $startedAt -DoneThisRun $doneThisRun }

    # A separate process, so the validator cannot see the auditor's reasoning.
    $validateTranscript = Join-Path $runsRoot "$($target.id)-validate.log"
    $validateState = Start-RunTranscript -Transcript $validateTranscript -Header "validate | #$($target.seq) $($target.id) | $($target.origin_file)" -Effort $Effort
    $ticker = New-ActivityTicker -Color $palette.Current -Hint $runHint -Signal $keySignal `
        -MonitorPath $validateTranscript -RawLog $rawLog -Transcript $validateTranscript -TranscriptState $validateState `
        -Text ("Validating #{0} {1} in {2}..." -f $target.seq, $target.id, [System.IO.Path]::GetFileName($target.origin_file))
    try
    {
        $validation = Invoke-ModelPrompt -Prompt (New-ValidatePrompt -Target $target -Database $db -ReportPath $reportPath) `
            -Schema $validateSchema -Model $Model -Effort $Effort -Label "validate:$label" -AllowDir $RepoRoot -OnWait $ticker -RunLog $rawLog
    }
    catch
    {
        # The target is already saved as 'audited', which still counts as pending, so
        # it is re-audited and validated in one piece after the reset.
        if (-not (Test-RateLimitError -ErrorRecord $_))
            { throw }

        Update-RunTranscript -RawLog $rawLog -Transcript $validateTranscript -State $validateState
        $limitMessage = $_.Exception.Message
        break
    }

    Update-RunTranscript -RawLog $rawLog -Transcript $validateTranscript -State $validateState
    Update-UsageStatus -RawLog $rawLog

    # Validation renames the report, so the recorded path has to be refreshed.
    $reportPath = Write-Report -Target $target -Audit $audit -Validation $validation
    Set-Field -Object $target -Name 'report' -Value $reportPath
    Set-Field -Object $target -Name 'state' -Value $validation.verdict
    Set-Field -Object $target -Name 'verdict' -Value $validation.verdict
    Set-Field -Object $target -Name 'severity' -Value $validation.severity
    Set-Field -Object $target -Name 'slug' -Value $validation.slug
    Set-Field -Object $target -Name 'validation_rationale' -Value $validation.rationale
    Set-Field -Object $target -Name 'validated_utc' -Value ((Get-Date).ToUniversalTime().ToString('o'))

    $duplicate = Get-Field -Object $validation -Name 'duplicate_of'
    if (-not [string]::IsNullOrEmpty($duplicate))
        { Set-Field -Object $target -Name 'duplicate_of' -Value $duplicate }

    # Leads the validator surfaced become new targets, kept out of recon sync.
    foreach ($spawned in @(Get-Field -Object $validation -Name 'spawned_targets'))
    {
        if ([string]::IsNullOrEmpty($spawned))
            { continue }

        $spawnedId = Get-TargetId -OriginFile $target.origin_file -Target $spawned
        if (@($db.targets | Where-Object { $_.id -eq $spawnedId }).Count -gt 0)
            { continue }

        $nextSeq = [int](@($db.targets | ForEach-Object { $_.seq }) | Measure-Object -Maximum).Maximum + 1
        $db.targets = @($db.targets) + [pscustomobject]@{
            seq         = $nextSeq
            id          = $spawnedId
            source      = 'spawned'
            origin_file = $target.origin_file
            priority    = $target.priority
            confidence  = 'medium'
            state       = 'pending'
            target      = $spawned
            rationale   = "Spawned while validating $($target.id)."
        }
    }

    Save-TargetDatabase -Database $db
    $doneThisRun++

    $stopRequested = Update-StopRequest -Current $stopRequested
    if (-not $interactive)
    {
        Write-TargetResult -Target $target
        Write-StopHint -Interactive $interactive -Terse
    }
}

if ($interactive)
    { Show-Queue -Queue $queue -StartedAt $startedAt -DoneThisRun $doneThisRun }

Write-Host ''
$total = Get-ModelSpend
$spent = if ($null -ne $total) { ' {0:n2} USD spent.' -f $total } else { '' }
if (-not [string]::IsNullOrEmpty($limitMessage))
{
    Write-Host "  $limitMessage" -ForegroundColor $palette.Warning
    Write-Host "Stopped on the subscription limit. $doneThisRun target(s) completed this run.$spent Re-run after the reset to continue." -ForegroundColor $palette.Warning
}
elseif ($stopRequested)
    { Write-Host "Stopped early. $doneThisRun target(s) completed this run.$spent" -ForegroundColor $palette.Warning }
else
    { Write-Host "Pass complete. $doneThisRun target(s) completed this run.$spent" -ForegroundColor $palette.Success }

#endregion

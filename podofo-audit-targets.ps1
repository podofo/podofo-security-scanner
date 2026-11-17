#!/usr/bin/env pwsh
<#
.SYNOPSIS
Audit pass: works the investigation targets produced by the recon phase, auditing and
then validating each one, and leaves a report per target.

.DESCRIPTION
Each kind of state has one home. podofo-audit-targets.json is only the registry: one
row per target with its seq, id, source and origin file, so numbering stays stable.
What a target asks comes from its source - the recon file for source "recon", the
validation record of the target that spawned it for source "spawned". What happened
to it is its record, scan/targets/<file-key>/<id>.json, holding the full structured
audit and validation output. No record means pending.

Every run begins by registering the targets that recon files and validation records
define and the registry has not seen yet. A registered target its source no longer
defines is orphaned: kept, shown with the verdict it had, and never worked. That makes
the phases interleavable: resume the recon pass, run this again, and the new targets
are simply there.

Each target then gets two model calls. The audit call looks for one candidate
vulnerability; the validate call, a separate process that cannot see the auditor's
reasoning (the transcripts under scan/runs are denied to the model), accepts or
rejects it. The record is saved after each, so a run stopped in
between resumes at validation. The report at scan/targets/<file-key>/<slug>-<id>.md is
rendered by this script from the record, not written by the model, which keeps the
model read-only. Every run first renders again any report that does not match its
record; -RenderReports does only that, for when the report format changes.

Press 'q' at any time to stop after the current target finishes. Creating the file
scan/STOP has the same effect, for non-interactive runs.

Each model call's transcript is written to scan/runs/audit/<id>-audit.log and
<id>-validate.log as it happens, overwritten on a re-run. Press 'm' while a call is
in flight to open the transcript for whichever stage is running in Notepad++ with
-monitor, which tails it live. 'm' is offered only when Notepad++ is found on the
machine.

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
    [switch]$RenderReports,
    [switch]$DryRun
)

$PSNativeCommandUseErrorActionPreference = $true
$ErrorActionPreference = 'stop'
Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot 'audit-common.ps1')

if ([string]::IsNullOrEmpty($RepoRoot))
    { $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path }   # governance/security-audit -> repository root
if ([string]::IsNullOrEmpty($ModelScript))
    { $ModelScript = Join-Path $PSScriptRoot 'model-seam-claude.ps1' }
if ([string]::IsNullOrEmpty($ScanRoot))
    { $ScanRoot = Join-Path $PSScriptRoot 'scan' }
if ([string]::IsNullOrEmpty($DatabasePath))
    { $DatabasePath = Join-Path $ScanRoot 'podofo-audit-targets.json' }

# Made absolute against the current location before anything uses them. Left
# relative, each consumer would resolve them its own way - .NET against the process
# directory, the CLI against the child's working directory - and the deny rules could
# name a different directory from the one the transcripts are written to.
$RepoRoot = Resolve-FullPath $RepoRoot
$ModelScript = Resolve-FullPath $ModelScript
$DatabasePath = Resolve-FullPath $DatabasePath
$ScanRoot = Resolve-FullPath $ScanRoot

$targetsRoot = Join-Path $ScanRoot 'targets'
$stopFile = Join-Path $ScanRoot 'STOP'
$runsRoot = Join-Path $ScanRoot 'runs/audit'
# Raw streamed events go to one reused working file; the readable transcript per run
# is what is kept and what 'm' opens.
$rawLog = Join-Path $ScanRoot 'runs/audit-monitor.jsonl'

$deniedDirs = Get-DeniedDirs -ScriptRoot $PSScriptRoot -ScanRoot $ScanRoot

if (Test-Path $ModelScript)
    { . $ModelScript }

$priorityRank = @{ high = 0; medium = 1; low = 2; none = 3 }
$confidenceRank = @{ high = 0; medium = 1; low = 2 }
$palette = Get-AuditPalette

# Set by the activity ticker when q is pressed mid-call, so the keypress is not lost
# to the ticker's own key draining.
$keySignal = @{ Stop = $false }

#region Registry

function Save-TargetRegistry
{
    param([Parameter(Mandatory)][psobject]$Registry)

    $rows = foreach ($row in $Registry.Targets)
        { [ordered]@{ seq = $row.seq; id = $row.id; source = $row.source; origin_file = $row.origin_file } }

    Write-FileAtomic -Path $Registry.Path -Content (
        [ordered]@{ version = 2; targets = @($rows) } | ConvertTo-Json -Depth 4)
}

# Measure-Object yields a double, and seq is an identifier, not a measurement.
function Get-NextSeq
{
    param([Parameter(Mandatory)][psobject]$Registry)

    if ($Registry.Targets.Count -eq 0)
        { return 1 }

    return ([int](@($Registry.Targets | ForEach-Object { $_.seq }) | Measure-Object -Maximum).Maximum + 1)
}

function Test-Registered
{
    param([Parameter(Mandatory)][psobject]$Registry, [Parameter(Mandatory)][string]$Id)

    return (@($Registry.Targets | Where-Object { $_.id -eq $Id }).Count -gt 0)
}

# Registers every target a source defines that the registry has not seen, in the
# order the sources list them. Nothing is ever removed: a row its source stopped
# defining comes out orphaned when the targets are built.
function Sync-TargetRegistry
{
    param(
        [Parameter(Mandatory)][psobject]$Registry,
        [Parameter(Mandatory)][psobject]$Sources
    )

    $known = @{}
    foreach ($row in $Registry.Targets)
        { $known[$row.id] = $true }

    $nextSeq = Get-NextSeq -Registry $Registry
    $added = 0
    foreach ($definition in $Sources.Definitions.Values)
    {
        if ($known.ContainsKey($definition.id))
            { continue }

        $Registry.Targets.Add([pscustomobject]@{
            seq         = $nextSeq++
            id          = $definition.id
            source      = $definition.source
            origin_file = $definition.origin_file
        })
        $known[$definition.id] = $true
        $added++
    }

    return $added
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

    return (-not $Target.orphaned -and ($Target.state -eq 'pending' -or $Target.state -eq 'audited'))
}

function Get-TargetValidation
{
    param([Parameter(Mandatory)][psobject]$Target)

    if ($null -eq $Target.Record)
        { return $null }

    return (Get-Field -Object $Target.Record -Name 'validation')
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
        [Parameter(Mandatory)][AllowEmptyCollection()][psobject[]]$Targets,
        [Parameter(Mandatory)][string]$OriginFile,
        [Parameter(Mandatory)][string]$ExcludeId
    )

    $sameFile = @($Targets | Where-Object {
        $_.origin_file -eq $OriginFile -and $_.id -ne $ExcludeId -and
        $null -ne (Get-TargetValidation -Target $_) })

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
            $validation = Get-TargetValidation -Target $row
            $lines += ('- [{0}] {1} ({2}) id {3}' -f $validation.verdict, $validation.slug, $validation.severity, $row.id)
            $lines += ('  target: {0}' -f $row.target)
            $lines += ('  outcome: {0}' -f $validation.rationale)
        }
    }

    $elsewhere = @($Targets | Where-Object { $_.origin_file -ne $OriginFile -and $_.state -eq 'accepted' })

    $lines += ''
    if ($elsewhere.Count -eq 0)
    {
        $lines += 'Accepted findings elsewhere in the codebase: (none)'
    }
    else
    {
        $lines += 'Accepted findings elsewhere in the codebase:'
        foreach ($row in $elsewhere)
        {
            $validation = Get-TargetValidation -Target $row
            $lines += ('- [{0}] {1} in {2}, id {3}' -f $validation.severity, $validation.slug, $row.origin_file, $row.id)
        }
    }

    # A reset target is still cited by rows validated against its earlier verdict, and
    # without this the auditor reads those citations as a prior record of itself.
    $lines += ''
    $lines += ("This target is id {0} and has no recorded verdict. Any mention of {0} in the findings " +
        "above, in recon notes or in files under scan/ refers to this same investigation, not to an " +
        "existing finding, so it can never make this target a duplicate.") -f $ExcludeId

    return ($lines -join "`n")
}

# The recon this target came from, so the auditor does not spend its first turns
# rediscovering the shape of a file we have already characterised.
function Format-ReconContext
{
    param([Parameter(Mandatory)][string]$OriginFile)

    $recon = $sources.Recon[$OriginFile]
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
        [Parameter(Mandatory)][AllowEmptyCollection()][psobject[]]$Targets
    )

    return @"
You are auditing PoDoFo for crash-class vulnerabilities.

Repository root: $RepoRoot
Target file: $($Target.origin_file)
Investigation target: $($Target.target)
Why recon proposed it: $($Target.rationale)

What recon already established about this file:
$(Format-ReconContext -OriginFile $Target.origin_file)

$(Format-DedupContext -Targets $Targets -OriginFile $Target.origin_file -ExcludeId $Target.id)

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
        [Parameter(Mandatory)][AllowEmptyCollection()][psobject[]]$Targets,
        [Parameter(Mandatory)][string]$ReportPath
    )

    return @"
You are validating a PoDoFo crash-class vulnerability report.

Repository root: $RepoRoot
Report to validate: $ReportPath
Target file: $($Target.origin_file)
Investigation target: $($Target.target)

$(Format-DedupContext -Targets $Targets -OriginFile $Target.origin_file -ExcludeId $Target.id)

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

# The validator's slug wins once it exists; before that the auditor's candidate name
# gives the report a readable name straight away.
function Get-RecordReportPath
{
    param([Parameter(Mandatory)][psobject]$Target, [Parameter(Mandatory)][psobject]$Record)

    $validation = Get-Field -Object $Record -Name 'validation'
    $slug = if ($null -ne $validation) { $validation.slug } else { $Record.audit.candidate_name }
    return (Get-ReportPath -Target $Target -Slug $slug)
}

# Rendered by the script from the record rather than written by the model, so the
# model stays read-only and the report shape stays consistent across the whole run.
function Format-Report
{
    param(
        [Parameter(Mandatory)][psobject]$Target,
        [Parameter(Mandatory)][psobject]$Record
    )

    $Audit = $Record.audit
    $Validation = Get-Field -Object $Record -Name 'validation'

    # The auditor's own severity is optional in a record, and shown only until the
    # validator's replaces it.
    $status = if ($null -eq $Validation) { 'UNVALIDATED' } else { $Validation.verdict.ToUpperInvariant() }
    $severity = if ($null -eq $Validation) { Get-Field -Object $Audit -Name 'severity' } else { $Validation.severity }
    $name = if ([string]::IsNullOrEmpty($Audit.candidate_name)) { 'No candidate found' } else { $Audit.candidate_name }

    $lines = @(
        "# $name"
        ''
        "- Status: $status"
        "- Severity: $severity"
        "- Target file: $($Target.origin_file)"
        "- Target id: $($Target.id)"
        "- Investigation target: $($Record.target)"
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

    return (($lines -join "`n") + "`n")
}

function Write-Report
{
    param(
        [Parameter(Mandatory)][psobject]$Target,
        [Parameter(Mandatory)][psobject]$Record
    )

    $path = Get-RecordReportPath -Target $Target -Record $Record
    Write-FileAtomic -Path $path -Content (Format-Report -Target $Target -Record $Record)

    # Validation usually renames the report, so drop the earlier name for this id.
    foreach ($stale in Find-ExistingReports -Target $Target)
    {
        if ($stale.FullName -ne (Resolve-Path -LiteralPath $path).Path)
            { Remove-Item -LiteralPath $stale.FullName -Force }
    }

    return $path
}

# The record is what a target's state is read from, so saving it is the commit point,
# and the report is rendered from it afterwards. A stop between the two leaves a report
# behind its record, which Repair-Reports puts right before the next run works anything.
function Save-TargetRecord
{
    param(
        [Parameter(Mandatory)][psobject]$Target,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Data
    )

    # Round-tripped, so the record held in memory has the shape a later run reads.
    $json = $Data | ConvertTo-Json -Depth 8
    $record = $json | ConvertFrom-Json
    Write-FileAtomic -Path (Join-Path (Get-TargetDir -Target $Target) "$($Target.id).json") -Content $json

    $sources.Records[$Target.id] = $record
    $Target.Record = $record

    # The new record may define spawned targets or stop defining them, and a target
    # this run has queued can be orphaned by it before its turn comes.
    Update-SpawnedDefinitions -Sources $sources
    foreach ($other in $targets)
    {
        $other.orphaned = -not $sources.Definitions.Contains($other.id)
        $other.state = Get-TargetState -Record $other.Record -Orphaned $other.orphaned
    }

    return (Write-Report -Target $Target -Record $record)
}

# What a record keeps besides the model output: the target as it was asked, so an
# orphan can still be listed and deduplicated against after its source moves on.
function New-RecordData
{
    param(
        [Parameter(Mandatory)][psobject]$Target,
        [Parameter(Mandatory)]$Audit,
        $Validation
    )

    $data = [ordered]@{
        id          = $Target.id
        origin_file = $Target.origin_file
        target      = $Target.target
        rationale   = $Target.rationale
        confidence  = $Target.confidence
        audit       = $Audit
    }

    if ($null -ne $Validation)
        { $data.validation = $Validation }

    return $data
}

# Renders every report that does not say what its record says: one missing, one left
# behind by a stop between saving a record and rendering it, or every one of them after
# the report format changes. Run before anything is worked, so a validator resuming a
# target is never handed a report carrying an earlier verdict. Only reports that differ
# are written. Trailing whitespace is not compared, since Set-Content ends a file with
# the platform newline and a report written on one platform is not stale on another.
function Repair-Reports
{
    param([Parameter(Mandatory)][AllowEmptyCollection()][psobject[]]$Targets)

    $repaired = 0
    foreach ($target in $Targets)
    {
        if ($null -eq $target.Record)
            { continue }

        $path = Get-RecordReportPath -Target $target -Record $target.Record
        if (Test-Path -LiteralPath $path)
        {
            $current = [string](Get-Content -LiteralPath $path -Raw -Encoding utf8)
            if ($current.TrimEnd() -ceq (Format-Report -Target $target -Record $target.Record).TrimEnd())
                { continue }
        }

        Write-Report -Target $target -Record $target.Record | Out-Null
        $repaired++
    }

    return $repaired
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

    $validation = Get-TargetValidation -Target $Target
    switch ([string]$Target.state)
    {
        'accepted' { return "accepted, $($validation.severity), $($validation.slug)" }
        'rejected' { return "rejected, $($validation.slug)" }
        'audited'  { return 'audited, awaiting validation' }
        'orphaned' { return 'orphaned, no longer proposed' }
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
        $mark = if ($isCurrent) { '>' }
            elseif ($target.state -eq 'pending') { ' ' }
            elseif ($target.state -eq 'orphaned') { '-' }
            else { 'x' }
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

$registry = Read-TargetRegistry -Path $DatabasePath
$sources = Read-AuditSources -TargetsRoot $targetsRoot
$added = Sync-TargetRegistry -Registry $registry -Sources $sources
if ($added -gt 0)
    { Save-TargetRegistry -Registry $registry }

# Wrapped: a single target unrolls to a bare object, and the [array] lookups the
# display does need an array either way.
$targets = @(Get-AuditTargets -Registry $registry -Sources $sources)
$orphanCount = @($targets | Where-Object { $_.orphaned }).Count

Write-Host ("Synced: {0} target(s) registered, {1} newly added, {2} orphaned." -f
    $targets.Count, $added, $orphanCount)

if ($SyncOnly)
{
    $pendingCount = @($targets | Where-Object { Test-TargetPending -Target $_ }).Count
    Write-Host "$pendingCount target(s) pending."
    return
}

if ($RenderReports)
{
    $rendered = Repair-Reports -Targets $targets
    Write-Host "Rendered $rendered report(s) that did not match their records."
    return
}

$queue = @(Get-QueueOrder -Targets $targets)
# -Redo reaches targets already worked, but never an orphan: nothing asks for it any more.
$work = @($queue | Where-Object { -not $_.orphaned -and ($Redo -or (Test-TargetPending -Target $_)) })
if (-not [string]::IsNullOrEmpty($Only))
    { $work = @($work | Where-Object { $_.origin_file -match $Only }) }
if (-not [string]::IsNullOrEmpty($Id))
    { $work = @($work | Where-Object { $_.id -eq $Id }) }
if (-not [string]::IsNullOrEmpty($MinPriority))
    { $work = @($work | Where-Object { $priorityRank[[string]$_.priority] -le $priorityRank[$MinPriority] }) }

# The model cannot read a file in a denied directory, so a target there is left as it
# is until the file or the denial moves, and does not count against -MaxTargets.
$denied = @($work | Where-Object { Test-PathUnder -Path (Join-Path $RepoRoot $_.origin_file) -Directory $deniedDirs })
if ($denied.Count -gt 0)
{
    Write-Host ('Skipping {0} target(s) whose file is in a denied directory.' -f $denied.Count) -ForegroundColor $palette.Warning
    $work = @($work | Where-Object { $denied -notcontains $_ })
}

if ($MaxTargets -gt 0)
    { $work = @($work | Select-Object -First $MaxTargets) }

if ($DryRun)
{
    if ($work.Count -eq 0)
        { Write-Host 'Nothing pending.'; return }

    Write-Host (New-AuditPrompt -Target $work[0] -Targets $targets)
    return
}

if ($null -eq (Get-Command Invoke-ModelPrompt -ErrorAction SilentlyContinue))
    { throw 'Invoke-ModelPrompt is not defined. Dot-source your model wrapper first (see the .NOTES block).' }

if (-not (Test-Path $ScanRoot))
    { New-Item -ItemType Directory -Path $ScanRoot -Force | Out-Null }
if (Test-Path $stopFile)
    { Remove-Item -LiteralPath $stopFile -Force }

$repaired = Repair-Reports -Targets $targets
if ($repaired -gt 0)
    { Write-Host "Rendered $repaired report(s) that did not match their records." }

$startedAt = Get-Date
$doneThisRun = 0
$stopRequested = $false
$limitMessage = ''
$interactive = Test-ConsoleInteractive

# 'm' is only worth offering when something can actually tail the run log.
$runHint = if ($null -eq (Get-MonitorProgram)) { "'q' stops after the current target" }
    else { "'q' stops after the current target, 'm' monitors this run" }

Write-Host ("Working {0} target(s) of {1} with {3} at effort '{2}'." -f $work.Count, $targets.Count, $Effort, $Model)
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

    # Orphaned after the queue was built, when -Redo re-audited the target that had
    # spawned it and the old validation went with the old audit.
    if ($target.orphaned)
        { continue }

    $spentSoFar = Get-ModelSpend
    if ($MaxSpendUsd -gt 0 -and $null -ne $spentSoFar -and $spentSoFar -ge $MaxSpendUsd)
    {
        Write-Host ''
        Write-Host ('  Spend cap reached ({0:n2} of {1:n2} USD). Stopping.' -f $spentSoFar, $MaxSpendUsd) -ForegroundColor $palette.Warning
        break
    }

    $index = [array]::IndexOf($queue, $target)
    $label = "$($target.id):$([System.IO.Path]::GetFileName($target.origin_file))"

    # A target whose audit is already on record goes straight to validation; -Redo
    # starts it over.
    if ($Redo -or $target.state -ne 'audited')
    {
        if ($interactive)
            { Show-Queue -Queue $queue -CurrentIndex $index -Activity 'auditing...' -StartedAt $startedAt -DoneThisRun $doneThisRun }

        $auditTranscript = Join-Path $runsRoot "$($target.id)-audit.log"
        $auditState = Start-RunTranscript -Transcript $auditTranscript -Header "audit | #$($target.seq) $($target.id) | $($target.origin_file)" -Effort $Effort
        $ticker = New-ActivityTicker -Color $palette.Current -Hint $runHint -Signal $keySignal `
            -MonitorPath $auditTranscript -RawLog $rawLog -Transcript $auditTranscript -TranscriptState $auditState `
            -Text ("Auditing #{0} {1} in {2}..." -f $target.seq, $target.id, [System.IO.Path]::GetFileName($target.origin_file))
        try
        {
            $audit = Invoke-ModelPrompt -Prompt (New-AuditPrompt -Target $target -Targets $targets) `
                -Schema $auditSchema -Model $Model -Effort $Effort -Label "audit:$label" -AllowDir $RepoRoot `
                -DenyDir $deniedDirs -WorkDir $RepoRoot -OnWait $ticker -RunLog $rawLog
        }
        catch
        {
            # A drained subscription window is a pause, not a failure. The target keeps
            # the record it had, so a run started after the reset takes it from here;
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

        # Kept whole and in schema order, so the report can be rendered again from it.
        $auditData = [ordered]@{ utc = (Get-Date).ToUniversalTime().ToString('o') }
        foreach ($name in $auditSchema.required)
            { $auditData[$name] = $audit.$name }

        # A redone target loses its old validation here, and with it the targets that
        # validation spawned, unless the new one proposes them again.
        $reportPath = Save-TargetRecord -Target $target -Data (New-RecordData -Target $target -Audit $auditData)
    }
    else
    {
        $reportPath = Get-RecordReportPath -Target $target -Record $target.Record
    }

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
        $validation = Invoke-ModelPrompt -Prompt (New-ValidatePrompt -Target $target -Targets $targets -ReportPath $reportPath) `
            -Schema $validateSchema -Model $Model -Effort $Effort -Label "validate:$label" -AllowDir $RepoRoot `
            -DenyDir $deniedDirs -WorkDir $RepoRoot -OnWait $ticker -RunLog $rawLog
    }
    catch
    {
        # The audit is already on record, so after the reset the target resumes here
        # and the audit is not paid for twice.
        if (-not (Test-RateLimitError -ErrorRecord $_))
            { throw }

        Update-RunTranscript -RawLog $rawLog -Transcript $validateTranscript -State $validateState
        $limitMessage = $_.Exception.Message
        break
    }

    Update-RunTranscript -RawLog $rawLog -Transcript $validateTranscript -State $validateState
    Update-UsageStatus -RawLog $rawLog

    $validationData = [ordered]@{
        utc       = (Get-Date).ToUniversalTime().ToString('o')
        verdict   = $validation.verdict
        severity  = $validation.severity
        slug      = $validation.slug
        rationale = $validation.rationale
    }

    $duplicate = Get-Field -Object $validation -Name 'duplicate_of'
    if (-not [string]::IsNullOrEmpty($duplicate))
        { $validationData.duplicate_of = $duplicate }

    # Leads the validator surfaced become targets defined by this record, the way
    # recon targets are defined by a recon file.
    $spawned = @(Get-Field -Object $validation -Name 'spawned_targets' | Where-Object { -not [string]::IsNullOrEmpty($_) })
    if ($spawned.Count -gt 0)
        { $validationData.spawned_targets = $spawned }

    # Validation usually renames the report, which Write-Report cleans up after.
    Save-TargetRecord -Target $target -Data (
        New-RecordData -Target $target -Audit $target.Record.audit -Validation $validationData) | Out-Null

    # Registered now so they take the next seq numbers, as they would have at the next
    # sync; a stop before this line leaves that sync to do it. They are worked by the
    # next run, not this one.
    $nextSeq = Get-NextSeq -Registry $registry
    $registered = 0
    foreach ($text in $spawned)
    {
        $spawnedId = Get-TargetId -OriginFile $target.origin_file -Target $text
        if (Test-Registered -Registry $registry -Id $spawnedId)
            { continue }

        $registry.Targets.Add([pscustomobject]@{ seq = $nextSeq++; id = $spawnedId; source = 'spawned'; origin_file = $target.origin_file })
        $registered++
    }

    if ($registered -gt 0)
        { Save-TargetRegistry -Registry $registry }

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

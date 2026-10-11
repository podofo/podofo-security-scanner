# AGENTS.md

## Overview

A two-phase security audit scanner for PoDoFo, driven by an agentic model. Phase one
walks every source file and proposes investigation targets; phase two audits each
target and has a second, independent model call validate the finding. Both phases are
resumable and are meant to be interrupted and restarted.

The model never writes to the repository. It is invoked read-only and returns
schema-constrained JSON; the scripts own every file that gets written.

Everything here is PowerShell 7, `Set-StrictMode -Version Latest`,
`$ErrorActionPreference = 'stop'`.

## The two scripts

### `podofo-recon-plan.ps1` - phase one, reconnaissance

Reads `scan/podofo-recon-plan.json`, a work list of 157 source files grouped into
tiers, and analyses one file per model call. Each call characterises the file as an
audit surface and proposes investigation targets.

Full recon output goes to `scan/targets/<file-key>/recon.json`, where `<file-key>`
is the path with `src/podofo/` stripped and `/` flattened to `-`. That file is the
progress state: a file is done exactly when its `recon.json` exists, and the result
on the checklist is read back from it. Writing it is the single commit point, so a
stopped run resumes where it left off. A `recon.json` whose `origin_file` differs from
the plan path stops the run, since it means two paths flatten to the same folder.

The plan itself holds no run state and the script never writes it, so it can be
edited while a run is going. An entry in `files` is either an object or a bare path
string; objects carry an optional `description` or `"ignore": true`. An ignored file
is never analysed and never part of the count the run reports against, but it stays
on the checklist marked `[-]`, so the decision stays visible rather than being lost by
deleting the line. Files missing on disk or generated are skipped the same way,
decided afresh on every run rather than recorded.

### `podofo-audit-targets.ps1` - phase two, audit and validation

Works the target queue in priority order. Each target gets two separate model
calls: an audit that produces the report, then a validation that accepts or rejects
it. They are separate processes so the validator structurally cannot see the
auditor's reasoning.

Each kind of state has one home:

- `scan/podofo-audit-targets.json` is only a registry: `seq`, `id`, `source` and
  `origin_file` per target. `seq` is the one thing that cannot be derived; it gives
  each target a stable number in the order it first appeared.
- What a target asks (`target`, `rationale`, `confidence`) comes from its source:
  the `recon.json` of its file for `source: recon`, the validation record of the
  target that spawned it for `source: spawned`. `priority` is always the current
  `audit_priority` of the origin file's recon, so a redone recon re-ranks its targets.
- What happened to it is its record, `scan/targets/<file-key>/<id>.json`: the target
  as asked, the full structured audit output and the full validation output, each
  with a `utc` stamp; `audit.severity` is optional, as the earliest records lack it.
  A validator's `spawned_targets` live in its record and define the spawned targets,
  the way `proposed_targets` in `recon.json` define recon ones.

State machine, derived rather than stored: no record is `pending`, a record with only
an audit is `audited`, a validated record is its verdict. A registered target that its
source no longer defines is `orphaned`: it keeps its verdict if it had one, shows as
`orphaned` otherwise, and is never worked, even with `-Redo`. That applies to spawned
targets too, when a redone parent no longer proposes them, including partway through
the `-Redo` run that re-audits the parent.

Targets carry a content-derived id (`SHA256(origin_file + "\n" + target)`, first 8
hex characters), so the registry can be synced while phase one is still running:
every run starts by registering targets that sources define and the registry has not
seen, and nothing is ever removed from it.

The record is the commit point and is saved after each of the two calls, so a run
stopped between them resumes at validation without paying for the audit again. The
report is rendered after the record is saved.

Reports land next to the recon that produced them, at
`scan/targets/<file-key>/<descriptive-slug>-<id>.md`, rendered by the script from the
record. The slug comes from the finding, so it changes when validation revises it; the
id is the stable handle, and report lookup globs `*<id>.md` so renames clean up after
themselves. Before working anything, a run renders again every report that does not
match its record, so a stop between saving a record and rendering it is put right,
and a validator resuming a target never reads a report carrying an earlier verdict.
`-RenderReports` does only that, for when the report format changes.

### `podofo-audit-status.ps1` - progress report

Read-only. Prints the target queue as two tables: per priority by state, and per
priority by recon confidence as pending/total, followed by how many pending targets
the validator spawned. It derives state through the same loader as the audit script,
so targets a recon file defines but no audit run has registered yet count as pending.
Safe to run alongside a live audit pass.

### Running them

Both take `-Model` (default `claude-fable-5-1`), `-Effort` (`low` to `max`, default
`xhigh`), `-Only`, `-Redo` and `-DryRun`;
the audit script adds `-Id`, `-MinPriority`, `-MaxTargets`, `-MaxSpendUsd`,
`-SyncOnly` and `-RenderReports`. Paths (`-RepoRoot`, `-ScanRoot`, `-DatabasePath`, `-ModelScript`) all
default relative to the script.

The activity display is two rows: the spinner and the current item, then a status
row with subscription usage and the key hints, e.g.
`usage week 13%, 5h 64%   |   'q' stops after the current file`. Usage is on screen
from the first frame, seeded from the previous run's log, and is re-read after every
call and at most every 30 seconds within one.

Press `q` to stop cleanly after the current item, or `m` to open the running model
call's transcript in Notepad++ with `-monitor`. Creating `scan/STOP` has the same
effect as `q` for non-interactive runs. Running out of subscription quota stops a run
the same way, reporting which window ran out and when it resets.

## Common infrastructure

### `audit-common.ps1`

Shared helpers, dot-sourced by both scripts. Identity derivation lives here so the
two phases cannot drift apart:

- `Get-ScanFileKey`, `Get-TargetId` - the path and target identity rules above
- `Read-TargetRegistry`, `Read-AuditSources`, `Get-AuditTargets` - the audit target
  state derivation above, shared with the status script so the two cannot disagree
- `Write-FileAtomic` - write to a temp file, then `File.Move(..., overwrite)`, so
  Ctrl-C cannot leave a half-written database
- `Get-Field` / `Set-Field` - StrictMode throws on both reading and writing an absent
  property of a `PSCustomObject`, so all optional database fields go through these
- `Start-RunTranscript`, `Update-RunTranscript`, `Format-RunEvent` - turn the raw
  NDJSON event stream into readable chat text, appended incrementally while the call
  is still running
- `New-ActivityTicker` - the in-place spinner, and the only place keys pressed during
  a model call are noticed. It owns two rows, and reserves the second by emitting a
  line when it starts, which also absorbs the scroll when the cursor was on the last
  row. Rendering and key polling are gated separately, on output and input
  redirection respectively
- `Get-UsageStatus`, `Update-UsageStatus` - the seven-day and five-hour subscription
  figures for the status row. The CLI emits `rate_limit_event` records into the same
  stream the transcript is built from, so they are read out of the run itself: no API
  query, no credential. The last reading is cached in `$global:PodofoUsage` and
  rescanned at most every 30 seconds, so it survives between calls and across both
  phases. A call's log carries no reading until its first response comes back, so
  the drivers force a read through `Update-UsageStatus` before the run starts, off
  the previous run's log, and again after each call; while the cache is still empty
  the interval drops to 3 seconds, because booking the full 30 on a miss left the
  row blank long after the figures had arrived
- `Get-RateLimitBlock`, `Format-RateLimitBlock`, `Test-RateLimitError` - the same
  `rate_limit_event` channel reports a drained window, with `status` `rejected`,
  the window that ran out in `rateLimitType` and its `resetsAt` in Unix seconds.
  These read that event and turn it into the sentence a stopped run prints, naming
  the window only when the source was explicit about it: guessing "weekly" at a
  five-hour pause would send someone away for days. A refusal that arrives before
  the session has reported any usage carries no such event, so the provider's own
  notice ("resets 4:50pm (Europe/Rome)") is parsed as a second source, against a
  fixed list of formats - a loose `TryParse` accepts those strings and answers with
  something unrelated
- `Read-SharedLines` - reads the raw log with `FileShare.ReadWrite` while the child
  still holds it open, returning `$null` instead of throwing on a momentary failure
- `Get-AuditPalette`, `Write-Viewport`, `Test-ConsoleInteractive` - checklist
  rendering, with colours chosen to stay legible on a white terminal background

### `model-seam-claude.ps1`

Defines `Invoke-ModelPrompt` on top of the Claude Code CLI. Recon and audit both read
source, so this has to be an agent invocation, not a plain completion.

Read-only is enforced by the harness rather than by asking the prompt nicely:
`--restricted` drops the shell tools and confines the file tools to the passed
`--add-dir`, and `Edit`, `Write` and `NotebookEdit` are denied outright.
`--json-schema` constrains the answer, which comes back already parsed in the
envelope's `structured_output`.

The CLI runs as a child process with output redirected to a file rather than piped,
so the caller can animate progress through `-OnWait` and the log is watchable while
the call is in flight. Running totals accumulate in `$global:PodofoModelStats`.

A drained subscription window is not a failed call: it comes back as a 429 with the
limit notice in place of the answer, and the CLI still exits 1. So the result
envelope is read and classified before the exit code is judged - the other way round
buries the reason under a bare `claude exited 1` - and stderr is checked too, for a
refusal that lands before anything is streamed. The seam raises it with the error id
`PodofoRateLimitReached`, its message naming the window and when it reopens. Both
drivers catch that one id, print it, and stop after the item they were on, leaving it
where it was - pending, or audited when the audit was already saved; every other error
still ends the run loudly.

Swapping in another provider means replacing only this file
(`-ModelScript <path>`); the contract is `-Prompt -Schema -Label -AllowDir -OnWait
-RunLog -Model -Effort -MaxBudgetUsd`, and raising `PodofoRateLimitReached` for an
exhausted quota if it wants the same clean stop.

Note: the CLI returns thinking blocks with the text stripped (only the encrypted
signature survives), so run transcripts cannot include model reasoning.

## Layout

```
governance/security-audit/
├── podofo-recon-plan.ps1      phase one driver
├── podofo-audit-targets.ps1   phase two driver
├── podofo-audit-status.ps1    progress tables for the audit queue
├── audit-common.ps1           shared helpers
├── model-seam-claude.ps1      Invoke-ModelPrompt for Claude
├── .editorconfig              LF, UTF-8, 4-space indent
└── scan/                      all generated output and state     (gitignored)
    ├── podofo-recon-plan.json                 file work list
    ├── podofo-audit-targets.json              audit target registry
    ├── targets/<file-key>/recon.json          phase one output
    ├── targets/<file-key>/<id>.json           audit and validation record
    ├── targets/<file-key>/<slug>-<id>.md      reports, rendered from the record
    ├── runs/{recon,audit}/*.log               formatted transcripts
    └── runs/{recon,audit}-monitor.jsonl       raw event stream, current call
```

The databases live in `scan/`, created if missing, because they belong to one audit
run, not to the source. The reports are the deliverable.

## Working on these scripts

- StrictMode is on and the scripts run unattended for hours; a property access on a
  field that has not been set yet is the most common way to break a run. Use
  `Get-Field` / `Set-Field` for anything optional.
- Save after every item. A run that loses an hour of model spend to a crash is worse
  than one that writes its state too often.
- Changes to the console rendering are hard to test in a captured shell, where both
  `[Console]::IsOutputRedirected` and `Clear-Host` behave differently. Parse-check
  with `[System.Management.Automation.Language.Parser]::ParseFile` at minimum.
- The prompts tell the model not to modify PoDoFo sources, but that instruction is
  not what enforces it. Keep the `--restricted` and `--disallowedTools` flags.
- Use `.editorconfig`

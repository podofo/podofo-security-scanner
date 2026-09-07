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

Reads `podofo-recon-plan.json`, a work list of 157 source files grouped into tiers,
and analyses one file per model call. Each call characterises the file as an audit
surface and proposes investigation targets. The database doubles as progress state:
a file carries `done`, an optional `description` and a short `result`, and is saved
after every file, so a stopped run resumes where it left off.

An entry in `files` is either an object or a bare path string; the string means a
pending, non-ignored file, and an entry that carries nothing else is written back as
one. `"ignore": true` drops a file from the run - it is never analysed and never part
of the count the run reports against, but it stays on the checklist marked `[-]`, so
the decision stays visible rather than being lost by deleting the line.

Full recon output goes to `scan/targets/<file-key>/recon.json`, where `<file-key>`
is the path with `src/podofo/` stripped and `/` flattened to `-`.

### `podofo-audit-targets.ps1` - phase two, audit and validation

Syncs `podofo-audit-targets.json` from the `recon.json` files, then works the queue
in priority order. Each target gets two separate model calls: an audit that produces
the report, then a validation that accepts or rejects it. They are separate processes
so the validator structurally cannot see the auditor's reasoning.

Targets carry a content-derived id (`SHA256(origin_file + "\n" + target)`, first 8
hex characters), so the queue can be re-synced while phase one is still running: new
targets are appended as `pending`, existing rows are never touched, and targets whose
recon entry vanished are flagged `orphaned` rather than deleted. Targets the
validator spawns are marked `source: spawned` so a later sync cannot orphan them.

State machine: `pending` -> `audited` -> `accepted` or `rejected`.

Reports land next to the recon that produced them, at
`scan/targets/<file-key>/<descriptive-slug>-<id>.md`. The slug comes from the
finding, so it changes when validation revises it; the id is the stable handle, and
report lookup globs `*<id>.md` so renames clean up after themselves.

### Running them

Both take `-Effort` (`low` to `max`, default `xhigh`), `-Only`, `-Redo` and `-DryRun`;
the audit script adds `-Id`, `-MinPriority`, `-MaxTargets`, `-MaxSpendUsd` and
`-SyncOnly`. Paths (`-RepoRoot`, `-ScanRoot`, `-DatabasePath`, `-ModelScript`) all
default relative to the script.

The activity display is two rows: the spinner and the current item, then a status
row with subscription usage and the key hints, e.g.
`usage week 13%, 5h 64%   |   'q' stops after the current file`. Usage is refreshed
every 30 seconds.

Press `q` to stop cleanly after the current item, or `m` to open the running model
call's transcript in Notepad++ with `-monitor`. Creating `scan/STOP` has the same
effect as `q` for non-interactive runs. Running out of subscription quota stops a run
the same way, reporting which window ran out and when it resets.

## Common infrastructure

### `audit-common.ps1`

Shared helpers, dot-sourced by both scripts. Identity derivation lives here so the
two phases cannot drift apart:

- `Get-ScanFileKey`, `Get-TargetId` - the path and target identity rules above
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
- `Get-UsageStatus` - the seven-day and five-hour subscription figures for the status
  row. The CLI emits `rate_limit_event` records into the same stream the transcript
  is built from, so they are read out of the run itself: no API query, no credential.
  The last reading is cached in `$global:PodofoUsage` and rescanned at most every 30
  seconds, so it survives between calls and across both phases
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
pending; every other error still ends the run loudly.

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
├── podofo-recon-plan.json     file work list and progress        (gitignored)
├── podofo-audit-targets.ps1   phase two driver
├── podofo-audit-targets.json  target queue and verdicts          (gitignored)
├── audit-common.ps1           shared helpers
├── model-seam-claude.ps1      Invoke-ModelPrompt for Claude
├── .editorconfig              LF, UTF-8, 4-space indent
└── scan/                      all generated output               (gitignored)
    ├── targets/<file-key>/recon.json          phase one output
    ├── targets/<file-key>/<slug>-<id>.md      reports
    ├── runs/{recon,audit}/*.log               formatted transcripts
    └── runs/{recon,audit}-monitor.jsonl       raw event stream, current call
```

The databases are gitignored because they are progress state for a long run, not
source. The reports are the deliverable.

## Working on these scripts

- StrictMode is on and the scripts run unattended for hours; a property access on a
  field that has not been set yet is the most common way to break a run. Use
  `Get-Field` / `Set-Field` for anything optional.
- Save after every item. A run that loses an hour of model spend to a crash is worse
  than one that writes the database too often.
- Changes to the console rendering are hard to test in a captured shell, where both
  `[Console]::IsOutputRedirected` and `Clear-Host` behave differently. Parse-check
  with `[System.Management.Automation.Language.Parser]::ParseFile` at minimum.
- The prompts tell the model not to modify PoDoFo sources, but that instruction is
  not what enforces it. Keep the `--restricted` and `--disallowedTools` flags.
- Use `.editorconfig`

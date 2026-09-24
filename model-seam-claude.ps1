<#
.SYNOPSIS
Claude implementation of the Invoke-ModelPrompt seam used by the audit scripts.

.DESCRIPTION
Dot-source this file to define Invoke-ModelPrompt on top of the Claude Code CLI.
Recon and audit both read source files, so this has to be an agent invocation rather
than a plain completion. The CLI supplies the agent loop and the file tools;
--json-schema constrains the final answer and returns it already parsed in the
envelope's structured_output field.

Read-only is enforced by the harness, not by asking the prompt nicely:
--restricted drops Bash, PowerShell and the REPL and confines the file tools to the
working directories, and Edit/Write/NotebookEdit are denied outright.

The CLI runs as a child process with its output redirected to a file rather than
piped, so the caller can animate progress through -OnWait while it works. Reading a
file also sidesteps console code page decoding entirely.

-Effort maps to the CLI's --effort, so the reasoning level is set explicitly rather
than inherited from whatever the CLI defaults to; the callers record it in the run
transcript header.

Running totals land in $global:PodofoModelStats so a batch run can be costed.

A drained subscription window (five-hour or weekly) is told apart from a real
failure - it reaches the caller as a 429 in the result envelope, whatever the exit
code - and raised with the error id PodofoRateLimitReached, carrying the window and
its reset time in the message. Test-RateLimitError recognises it on the caller's
side; a replacement seam has to raise the same id to get the same clean stop.
#>

Set-Variable -Name PodofoModelStats -Scope Global -Value ([pscustomobject]@{
    Calls   = 0
    CostUsd = 0.0
    Turns   = 0
}) -Force

# Start-Process joins ArgumentList into one command line without quoting it, so an
# argument carrying quotes (the JSON schema) or spaces has to be prepared by hand.
function ConvertTo-ProcessArgument
{
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)

    $escaped = $Value -replace '"', '\"'
    if ($escaped -notmatch '\s')
        { return $escaped }

    # A trailing backslash would otherwise escape the closing quote.
    $escaped = $escaped -replace '(\\+)$', '$1$1'
    return '"' + $escaped + '"'
}

# A drained subscription window is reported in the result envelope as a 429 with the
# limit notice in place of the answer; the CLI exits non-zero for it, so the envelope
# and not the exit code is what tells a pause apart from a broken call. Returns the
# notice text, or $null when the failure is something else.
function Get-RateLimitNotice
{
    param([psobject]$Envelope, [string]$Stderr)

    # StrictMode throws on an absent property, so the fields come off the property
    # bag; api_error_status only appears on an API failure.
    if ($null -ne $Envelope)
    {
        $status = $Envelope.PSObject.Properties['api_error_status']
        $result = $Envelope.PSObject.Properties['result']
        $text = if ($null -eq $result) { '' } else { [string]$result.Value }

        if (($null -ne $status) -and ([int]$status.Value -eq 429))
            { return $text }

        if (Test-LimitWording -Text $text)
            { return $text }
    }

    # Nothing was streamed: a refusal that lands before the session starts leaves
    # only what the CLI printed.
    if (Test-LimitWording -Text $Stderr)
        { return $Stderr.Trim() }

    return $null
}

function Test-LimitWording
{
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text))
        { return $false }

    return ($Text -match '(?i)(hit|reached|exceeded) your [^.]{0,40}limit|usage limit reached|rate.?limit')
}

# Collects whatever explains a failed call: the envelope subtype, its errors list
# and result text, and stderr. Returns an empty string when none is available.
function Get-FailureReason
{
    param([psobject]$Envelope, [string]$Stderr)

    $parts = [System.Collections.Generic.List[string]]::new()
    if ($null -ne $Envelope)
    {
        # StrictMode throws on an absent property, so the fields come off the property bag.
        foreach ($name in @('subtype', 'errors', 'result'))
        {
            $property = $Envelope.PSObject.Properties[$name]
            if ($null -eq $property)
                { continue }

            # A failed call can still report subtype "success", which explains nothing.
            $text = (@($property.Value) | ForEach-Object { [string]$_ }) -join '; '
            if (($name -eq 'subtype') -and ($text -eq 'success'))
                { continue }

            if (-not [string]::IsNullOrWhiteSpace($text))
                { $parts.Add($text.Trim()) }
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($Stderr))
        { $parts.Add($Stderr.Trim()) }

    return ($parts -join ' | ')
}

function Invoke-ModelPrompt
{
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [hashtable]$Schema,
        [string]$Label,
        [string[]]$AllowDir,
        [scriptblock]$OnWait,
        [string]$RunLog,
        [string]$Model = 'claude-opus-5-5[1m]',
        [ValidateSet('low', 'medium', 'high', 'xhigh', 'max')][string]$Effort = 'high',
        [double]$MaxBudgetUsd = 10.0
    )

    $work = Join-Path ([System.IO.Path]::GetTempPath()) ("podofo-audit-" + [guid]::NewGuid().ToString('N'))
    $promptFile = "$work.prompt.txt"
    $errFile = "$work.err.txt"

    # stream-json writes events as they happen, so the log is watchable while the
    # call is still running. A run log is kept; a temp file is cleaned up.
    $outFile = if ([string]::IsNullOrEmpty($RunLog)) { "$work.out.jsonl" } else { $RunLog }
    $keepOutput = -not [string]::IsNullOrEmpty($RunLog)

    try
    {
        Set-Content -LiteralPath $promptFile -Value $Prompt -Encoding utf8

        if ($keepOutput)
        {
            $logDirectory = Split-Path -Parent $outFile
            if (-not (Test-Path $logDirectory))
                { New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null }
        }

        $arguments = @(
            '-p'
            '--output-format', 'stream-json'
            '--verbose'
            '--model', $Model
            '--effort', $Effort
            '--restricted'
            '--disallowedTools', 'Edit', 'Write', 'NotebookEdit'
            '--max-budget-usd', $MaxBudgetUsd
        )

        foreach ($dir in $AllowDir)
            { $arguments += @('--add-dir', $dir) }

        if ($null -ne $Schema)
            { $arguments += @('--json-schema', ($Schema | ConvertTo-Json -Depth 12 -Compress)) }

        $commandLine = @($arguments | ForEach-Object { ConvertTo-ProcessArgument ([string]$_) })

        $process = Start-Process -FilePath 'claude' -ArgumentList $commandLine `
            -RedirectStandardInput $promptFile -RedirectStandardOutput $outFile `
            -RedirectStandardError $errFile -NoNewWindow -PassThru

        while (-not $process.HasExited)
        {
            if ($null -ne $OnWait)
                { & $OnWait }

            Start-Sleep -Milliseconds 150
        }

        $stderr = if (Test-Path $errFile) { [string](Get-Content -LiteralPath $errFile -Raw) } else { '' }

        # One JSON event per line; the final "result" event carries the envelope. It
        # is read before the exit code is judged: a drained subscription window is
        # reported in the envelope as a 429 with the limit notice in place of the
        # answer, and the CLI exits non-zero for it, so testing the code first would
        # bury the reason under a bare "claude exited 1".
        $envelope = $null
        foreach ($line in Get-Content -LiteralPath $outFile -Encoding utf8)
        {
            if ([string]::IsNullOrWhiteSpace($line))
                { continue }

            try
                { $record = $line | ConvertFrom-Json }
            catch
                { continue }

            if ($record.type -eq 'result')
                { $envelope = $record }
        }

        if ($null -ne $envelope)
        {
            $global:PodofoModelStats.Calls++
            $global:PodofoModelStats.CostUsd += $envelope.total_cost_usd
            $global:PodofoModelStats.Turns += $envelope.num_turns
        }

        # A refused call is a pause, not a failure, so it is raised under its own
        # error id: a driver wants to stop and say when the window reopens rather
        # than treat the item as broken. Checked whatever the exit code turned out to
        # be, and off stderr too, in case the refusal arrives before any event.
        $notice = Get-RateLimitNotice -Envelope $envelope -Stderr $stderr
        if ($null -ne $notice)
        {
            # The event stream carries the window and its reset; the notice wording
            # is read when it does not. Both helpers live in audit-common, so a seam
            # used on its own still raises the same id with the raw notice.
            $message = if ($null -ne (Get-Command Format-RateLimitBlock -ErrorAction SilentlyContinue))
                { Format-RateLimitBlock -Block (Get-RateLimitBlock -RawLog $outFile -Notice $notice) -Fallback $notice }
            else
                { "Subscription limit reached: $notice" }

            throw [System.Management.Automation.ErrorRecord]::new(
                [System.Exception]::new("$message ('$Label' did not run.)"),
                'PodofoRateLimitReached',
                [System.Management.Automation.ErrorCategory]::LimitsExceeded,
                $Label)
        }

        # The exit code is always 1 on failure, so the reason comes from the envelope
        # (e.g. error_max_budget_usd) and from stderr.
        if (($process.ExitCode -ne 0) -or (($null -ne $envelope) -and $envelope.is_error))
        {
            $reason = Get-FailureReason -Envelope $envelope -Stderr $stderr
            if ([string]::IsNullOrEmpty($reason))
                { $reason = 'no error details reported' }

            throw "Model call failed for '$Label' (claude exited $($process.ExitCode)): $reason. Run log: $outFile"
        }

        if ($null -eq $envelope)
            { throw "No result event in the run log for '$Label' ($outFile)." }

        if (@($envelope.permission_denials).Count -gt 0)
            { Write-Warning "'$Label': $(@($envelope.permission_denials).Count) permission denial(s); the model was blocked from something it tried." }

        Write-Verbose ("'{0}': {1}/{2}, {3} turn(s), {4:n4} USD, {5:n1}s" -f $Label, $Model, $Effort,
            $envelope.num_turns, $envelope.total_cost_usd, ($envelope.duration_ms / 1000))

        # With a schema the constrained answer arrives already parsed; without one the
        # caller gets raw text and does its own parsing.
        if ($null -ne $Schema)
            { return $envelope.structured_output }

        return $envelope.result
    }
    finally
    {
        $temporary = @($promptFile, $errFile)
        if (-not $keepOutput)
            { $temporary += $outFile }

        foreach ($file in $temporary)
        {
            if (Test-Path $file)
                { Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue }
        }
    }
}

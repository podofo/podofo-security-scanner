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

function Invoke-ModelPrompt
{
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [hashtable]$Schema,
        [string]$Label,
        [string[]]$AllowDir,
        [scriptblock]$OnWait,
        [string]$RunLog,
        [string]$Model = 'claude-opus-5',
        [ValidateSet('low', 'medium', 'high', 'xhigh', 'max')][string]$Effort = 'high',
        [double]$MaxBudgetUsd = 2.0
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

        if ($process.ExitCode -ne 0)
        {
            $stderr = if (Test-Path $errFile) { (Get-Content -LiteralPath $errFile -Raw) } else { '' }
            throw "claude exited $($process.ExitCode) for '$Label'. $stderr"
        }

        # One JSON event per line; the final "result" event carries the envelope.
        $envelope = $null
        foreach ($line in Get-Content -LiteralPath $outFile -Encoding utf8)
        {
            if ([string]::IsNullOrWhiteSpace($line))
                { continue }

            $record = $line | ConvertFrom-Json
            if ($record.type -eq 'result')
                { $envelope = $record }
        }

        if ($null -eq $envelope)
            { throw "No result event in the run log for '$Label' ($outFile)." }

        $global:PodofoModelStats.Calls++
        $global:PodofoModelStats.CostUsd += $envelope.total_cost_usd
        $global:PodofoModelStats.Turns += $envelope.num_turns

        if ($envelope.is_error)
            { throw "Model call failed for '$Label': $($envelope.subtype) / $($envelope.result)" }

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

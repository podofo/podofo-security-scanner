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
working directories, --tools narrows what is left to Read, Glob and Grep,
--strict-mcp-config loads no MCP server, and Edit/Write/NotebookEdit are denied
outright as well.

-DenyDir takes directories out of reach entirely. Each becomes a Read deny rule,
which the CLI applies to every file tool: Read is refused, Grep and Glob aimed inside
are refused, and Grep and Glob run over a parent silently leave its contents out, a
glob argument pointing inside included. The CLI tests a rule against the path the
model names and against that path resolved, so case, '..' and a junction inside the
tree do not get around it, and an 8.3 short name is refused as suspicious. It also
resolves the working directories, so when the repository is reached through a
junction or symbolic link its real path is readable too; each directory is therefore
denied under the spelling given and under its resolved one. A path the rule
syntax would misread ('[ ]' is a character class, '{ }' alternation) or a UNC path is
refused with an error rather than turned into a rule that matches nothing.

-WorkDir sets the child's working directory, which --restricted also counts as
readable; left empty, it inherits the caller's. Relative directories are taken
against the current PowerShell location.

--no-session-persistence keeps the CLI from saving each call under ~/.claude/projects,
which would be a copy of the auditor's transcript outside scan/runs.

--restricted skips CLAUDE.md discovery, which would leave the model without the
project's conventions and its rules on what does not count as a vulnerability.
CLAUDE_CODE_ADDITIONAL_DIRECTORIES_CLAUDE_MD brings back the CLAUDE.md of each
-AllowDir directory, @-imports included; parent directories stay out, and a nested
CLAUDE.md is not picked up when the model reads a file beside it.

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
        $isError = $Envelope.PSObject.Properties['is_error']
        $result = $Envelope.PSObject.Properties['result']
        $text = if ($null -eq $result) { '' } else { [string]$result.Value }

        # On a successful call 'result' is the model's own answer, which can say
        # anything: "degenerate limits" once matched the wording below and stopped a
        # healthy run. Only a failed envelope can be a refusal.
        if (($null -eq $isError) -or (-not [bool]$isError.Value))
            { return $null }

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

    return ($Text -match '(?i)\b(hit|reached|exceeded) your [^.]{0,40}limit|\busage limit reached|\brate.?limit')
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

# Relative paths are taken against the current PowerShell location. GetFullPath alone
# would use the process directory, which Set-Location does not move, and the CLI would
# resolve a relative --add-dir against the child's working directory. audit-common has
# the same helper; the seam does not depend on it.
function Resolve-SeamPath
{
    param([Parameter(Mandatory)][string]$Path)

    return [System.IO.Path]::GetFullPath($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path))
}

# GetFinalPathNameByHandle resolves junctions, symbolic links and subst drives in one
# call, but it needs a handle, and .NET will not open one on a directory.
if (-not ('PodofoSeam.FinalPath' -as [type]))
{
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace PodofoSeam
{
    public static class FinalPath
    {
        const uint FileReadAttributes = 0x80;
        const uint FileShareAll = 0x7;
        const uint OpenExisting = 3;
        const uint FileFlagBackupSemantics = 0x02000000;

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security,
            uint disposition, uint flags, IntPtr template);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern uint GetFinalPathNameByHandleW(SafeFileHandle handle, StringBuilder path, uint length, uint flags);

        public static string Get(string path)
        {
            using (SafeFileHandle handle = CreateFileW(path, FileReadAttributes, FileShareAll, IntPtr.Zero,
                OpenExisting, FileFlagBackupSemantics, IntPtr.Zero))
            {
                if (handle.IsInvalid)
                    throw new Win32Exception();

                // Too small a buffer returns the size needed, terminator included.
                var buffer = new StringBuilder(512);
                uint length = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Capacity, 0);
                if (length >= buffer.Capacity)
                {
                    buffer.Capacity = (int)length + 1;
                    length = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Capacity, 0);
                }

                if (length == 0)
                    throw new Win32Exception();

                return buffer.ToString();
            }
        }
    }
}
'@
}

# The directory as the file system resolves it, in drive-letter form, or a UNC path
# for a network drive. One not created yet resolves through its nearest existing
# parent, so archive/ is covered before it exists.
function Get-FinalPath
{
    param([Parameter(Mandatory)][string]$Path)

    $existing = $Path
    $rest = [System.Collections.Generic.List[string]]::new()
    while (-not [System.IO.Directory]::Exists($existing))
    {
        $parent = [System.IO.Path]::GetDirectoryName($existing)
        if ([string]::IsNullOrEmpty($parent))
            { return $Path }

        $rest.Insert(0, [System.IO.Path]::GetFileName($existing))
        $existing = $parent
    }

    $final = [PodofoSeam.FinalPath]::Get($existing)
    if ($final.StartsWith('\\?\UNC\'))
        { $final = '\\' + $final.Substring(8) }
    elseif ($final.StartsWith('\\?\'))
        { $final = $final.Substring(4) }

    return [System.IO.Path]::Combine([string[]](@($final) + $rest))
}

# Permission rules take an absolute path as //<path>, with a Windows drive turned into
# a leading segment: D:\Staging\x -> Read(//d/Staging/x/**).
#
# The CLI resolves the working directories, so through a junction or symbolic link
# the directory is readable under its real path as well as the one given, and a rule
# on the given spelling alone does not cover the real one. Returns a rule for each
# spelling.
function ConvertTo-ReadDenyRule
{
    param([Parameter(Mandatory)][string]$Directory)

    # Trimmed only once resolved: 'D:' without its separator means the current
    # directory on D:, not the drive root. The resolved spelling also carries the
    # on-disk case, so it is the one kept when the two differ in case alone.
    $given = (Resolve-SeamPath $Directory)
    $final = (Get-FinalPath -Path $given).TrimEnd('\', '/')
    $given = $given.TrimEnd('\', '/')
    $spellings = @($final)
    if ($given -ne $final)
        { $spellings += $given }

    foreach ($spelling in $spellings)
    {
        # A rule that silently matches nothing would leave the directory readable, so
        # a path the rule cannot express stops the call instead: '[ ]' reads as a
        # character class and '{ }' as alternation, and the rule form for a UNC path
        # has not been established.
        if (($spelling -match '[\[\]{}]') -or $spelling.StartsWith('\\'))
            { throw "Cannot deny '$spelling' to the model: a permission rule cannot express this path." }

        $path = $spelling -replace '\\', '/'
        if ($path -match '^(?<drive>[A-Za-z]):(?<rest>.*)$')
            { $path = '/' + $Matches['drive'].ToLowerInvariant() + $Matches['rest'] }

        "Read(/$path/**)"
    }
}

function Invoke-ModelPrompt
{
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [hashtable]$Schema,
        [string]$Label,
        [string[]]$AllowDir,
        [string[]]$DenyDir,
        [string]$WorkDir,
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

        # The tool set is an allowlist. A restricted session still carries the agent,
        # publishing, messaging and web search tools and the user's MCP connectors,
        # several of which send content off the machine. Edit, Write and NotebookEdit
        # are outside the list already; the explicit deny stays as a second line.
        # --no-session-persistence: a saved session would be a copy of the auditor's
        # transcript outside scan/runs.
        $arguments = @(
            '-p'
            '--output-format', 'stream-json'
            '--verbose'
            '--model', $Model
            '--effort', $Effort
            '--restricted'
            '--no-session-persistence'
            '--strict-mcp-config'
            '--tools', 'Read', 'Glob', 'Grep'
            '--disallowedTools', 'Edit', 'Write', 'NotebookEdit'
        )

        # The flag takes a list, so the deny rules have to follow it directly.
        foreach ($dir in $DenyDir)
            { $arguments += ConvertTo-ReadDenyRule -Directory $dir }

        $arguments += @('--max-budget-usd', $MaxBudgetUsd)

        foreach ($dir in $AllowDir)
            { $arguments += @('--add-dir', (Resolve-SeamPath $dir)) }

        if ($null -ne $Schema)
            { $arguments += @('--json-schema', ($Schema | ConvertTo-Json -Depth 12 -Compress)) }

        $commandLine = @($arguments | ForEach-Object { ConvertTo-ProcessArgument ([string]$_) })

        $start = @{
            FilePath               = 'claude'
            ArgumentList           = $commandLine
            RedirectStandardInput  = $promptFile
            RedirectStandardOutput = $outFile
            RedirectStandardError  = $errFile
            Environment            = @{ CLAUDE_CODE_ADDITIONAL_DIRECTORIES_CLAUDE_MD = '1' }
            NoNewWindow            = $true
            PassThru               = $true
        }
        if (-not [string]::IsNullOrEmpty($WorkDir))
            { $start.WorkingDirectory = Resolve-SeamPath $WorkDir }

        $process = Start-Process @start

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

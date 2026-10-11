<#
.SYNOPSIS
Helpers shared by podofo-recon-plan.ps1 and podofo-audit-targets.ps1.

.DESCRIPTION
Identity derivation lives here rather than in each script: if Get-ScanFileKey or
Get-TargetId drifted between the two phases the store would silently split, with the
audit phase unable to find the recon it is working from. The same goes for how an
audit target's state is derived from disk, which podofo-audit-status.ps1 shares.
#>

# Set-Content truncates the target and then writes, so an interrupt landing in that
# window leaves a partial file. Writing beside the target and replacing it makes the
# swap atomic on NTFS, which matters most for the databases: they hold the whole run.
function Write-FileAtomic
{
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Content
    )

    $full = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    $temp = "$full.tmp"
    [System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($full)) | Out-Null
    Set-Content -LiteralPath $temp -Value $Content -Encoding utf8
    [System.IO.File]::Move($temp, $full, $true)
}

# Under StrictMode both reading and writing an absent property throw, so optional
# fields go through these two helpers rather than plain member access.
function Get-Field
{
    param([Parameter(Mandatory)][psobject]$Object, [Parameter(Mandatory)][string]$Name)

    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property)
        { return $null }

    return $property.Value
}

function Set-Field
{
    param(
        [Parameter(Mandatory)][psobject]$Object,
        [Parameter(Mandatory)][string]$Name,
        $Value
    )

    $Object | Add-Member -NotePropertyName $Name -NotePropertyValue $Value -Force
}

# src/podofo/main/PdfEncrypt.cpp -> main-PdfEncrypt.cpp
# Paths outside src/podofo keep their full relative path, flattened the same way.
function Get-ScanFileKey
{
    param([Parameter(Mandatory)][string]$RelativePath)

    $normalized = ($RelativePath -replace '\\', '/').Trim('/')
    $normalized = $normalized -replace '^src/podofo/', ''
    return ($normalized -replace '/', '-')
}

# Derived from the origin file and the target text rather than from position, so the
# same target keeps its id when recon is regenerated and the audit phase can bind
# work state to it. Assigned by script rather than by the model, so it is deterministic.
function Get-TargetId
{
    param(
        [Parameter(Mandatory)][string]$OriginFile,
        [Parameter(Mandatory)][string]$Target
    )

    $bytes = [System.Text.Encoding]::UTF8.GetBytes("$OriginFile`n$Target")
    $hash = [System.Security.Cryptography.SHA256]::HashData($bytes)
    return ((($hash[0..3]) | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Read-JsonFile
{
    param([Parameter(Mandatory)][string]$Path)

    return (Get-Content -LiteralPath $Path -Raw -Encoding utf8 | ConvertFrom-Json)
}

# The audit target registry holds only what cannot be derived: the seq each target was
# given, plus its id, source and origin file to keep the list readable.
function Read-TargetRegistry
{
    param([Parameter(Mandatory)][string]$Path)

    $rows = [System.Collections.Generic.List[psobject]]::new()
    if (Test-Path -LiteralPath $Path)
    {
        foreach ($row in @((Read-JsonFile -Path $Path).targets))
            { $rows.Add($row) }
    }

    return [pscustomobject]@{ Path = $Path; Targets = $rows }
}

# Everything under scan/targets the audit phase derives its state from: the recon of
# each file, the record of each target worked so far, and the definition of every
# target either of them proposes. Recon targets come first, in a stable order; spawned
# targets follow, see Update-SpawnedDefinitions.
function Read-AuditSources
{
    param([Parameter(Mandatory)][string]$TargetsRoot)

    $recon = @{}
    $records = @{}
    if (Test-Path -LiteralPath $TargetsRoot)
    {
        foreach ($file in Get-ChildItem -LiteralPath $TargetsRoot -Filter '*.json' -Recurse -File | Sort-Object FullName)
        {
            if ($file.Name -eq 'recon.json')
            {
                $data = Read-JsonFile -Path $file.FullName
                $recon[$data.origin_file] = $data
            }
            elseif ($file.Name -match '^[0-9a-f]{8}\.json$')
            {
                $data = Read-JsonFile -Path $file.FullName
                $records[$data.id] = $data
            }
        }
    }

    $definitions = [ordered]@{}
    foreach ($origin in @($recon.Keys | Sort-Object))
    {
        foreach ($target in @($recon[$origin].recon.proposed_targets))
        {
            $definitions[$target.id] = [pscustomobject]@{
                id          = $target.id
                source      = 'recon'
                origin_file = $origin
                target      = $target.target
                rationale   = $target.rationale
                confidence  = $target.confidence
            }
        }
    }

    $sources = [pscustomobject]@{ Recon = $recon; Records = $records; Definitions = $definitions }
    Update-SpawnedDefinitions -Sources $sources
    return $sources
}

# Spawned targets are defined by the validation records of their parents, so they
# change whenever a record does: an audit redone mid-run drops the old validation, and
# with it the targets that validation spawned. Rebuilt whole rather than patched, since
# two parents can spawn the same target. Listed in the order their parents were
# validated, which is the order a live run registers them in.
function Update-SpawnedDefinitions
{
    param([Parameter(Mandatory)][psobject]$Sources)

    $definitions = $Sources.Definitions
    foreach ($id in @($definitions.Keys | Where-Object { $definitions[$_].source -eq 'spawned' }))
        { $definitions.Remove($id) }

    $validated = @($Sources.Records.Values | Where-Object { $null -ne (Get-Field -Object $_ -Name 'validation') } |
        Sort-Object { $_.validation.utc })
    foreach ($parent in $validated)
    {
        foreach ($text in @(Get-Field -Object $parent.validation -Name 'spawned_targets'))
        {
            if ([string]::IsNullOrEmpty($text))
                { continue }

            $id = Get-TargetId -OriginFile $parent.origin_file -Target $text
            if ($definitions.Contains($id))
                { continue }

            $definitions[$id] = [pscustomobject]@{
                id          = $id
                source      = 'spawned'
                origin_file = $parent.origin_file
                target      = $text
                rationale   = "Spawned while validating $($parent.id)."
                confidence  = 'medium'
            }
        }
    }
}

# No record means the target has not been worked; a record without a validation means
# the audit is in and the validation is not. An orphan is a target nothing defines any
# more: it keeps the verdict it had, and one without a verdict will never get one, so
# it is not shown as waiting for one.
function Get-TargetState
{
    param([psobject]$Record, [bool]$Orphaned)

    $validation = if ($null -ne $Record) { Get-Field -Object $Record -Name 'validation' } else { $null }
    if ($null -ne $validation)
        { return [string]$validation.verdict }
    if ($Orphaned)
        { return 'orphaned' }
    if ($null -ne $Record)
        { return 'audited' }

    return 'pending'
}

function New-AuditTarget
{
    param(
        $Seq,
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$OriginFile,
        [Parameter(Mandatory)][psobject]$Sources
    )

    $definition = if ($Sources.Definitions.Contains($Id)) { $Sources.Definitions[$Id] } else { $null }
    $record = $Sources.Records[$Id]
    $recon = $Sources.Recon[$OriginFile]

    # An orphan has nothing defining it any more, but if it was worked its record still
    # says what it asked.
    $asked = if ($null -ne $definition) { $definition } else { $record }

    return [pscustomobject]@{
        seq         = $Seq
        id          = $Id
        source      = $Source
        origin_file = $OriginFile
        priority    = if ($null -ne $recon) { [string]$recon.recon.audit_priority } else { 'none' }
        confidence  = if ($null -ne $asked) { [string](Get-Field -Object $asked -Name 'confidence') } else { '' }
        target      = if ($null -ne $asked) { [string](Get-Field -Object $asked -Name 'target') } else { '' }
        rationale   = if ($null -ne $asked) { [string](Get-Field -Object $asked -Name 'rationale') } else { '' }
        orphaned    = ($null -eq $definition)
        state       = Get-TargetState -Record $record -Orphaned ($null -eq $definition)
        Record      = $record
    }
}

# One object per registered target: what it asks from its source, what happened to it
# from its record. Targets a source defines that the registry has not seen yet follow
# with no seq; only a reader that does not register them, such as the status script,
# ever meets one.
function Get-AuditTargets
{
    param(
        [Parameter(Mandatory)][psobject]$Registry,
        [Parameter(Mandatory)][psobject]$Sources
    )

    $targets = [System.Collections.Generic.List[psobject]]::new()
    $registered = @{}
    foreach ($row in $Registry.Targets)
    {
        $registered[$row.id] = $true
        $targets.Add((New-AuditTarget -Seq $row.seq -Id $row.id -Source $row.source -OriginFile $row.origin_file -Sources $Sources))
    }

    foreach ($definition in $Sources.Definitions.Values)
    {
        if (-not $registered.ContainsKey($definition.id))
            { $targets.Add((New-AuditTarget -Seq $null -Id $definition.id -Source $definition.source -OriginFile $definition.origin_file -Sources $Sources)) }
    }

    return $targets
}

# Tuned for a light terminal background, so White, Yellow, Cyan, Green and Gray are
# all avoided: they wash out on white. Set PODOFO_AUDIT_THEME=dark for the inverse.
function Get-AuditPalette
{
    if ($env:PODOFO_AUDIT_THEME -eq 'dark')
    {
        return @{
            Header = 'White';   Group   = 'Cyan';     Hint    = 'DarkGray'
            Current = 'Cyan';   High    = 'Red';      Medium  = 'Yellow'
            Low = 'DarkYellow'; Muted   = 'DarkGray'; Warning = 'Yellow'
            Success = 'Green'
        }
    }

    return @{
        Header = 'DarkBlue';  Group   = 'DarkMagenta'; Hint    = 'DarkGray'
        Current = 'Blue';     High    = 'Red';         Medium  = 'DarkYellow'
        Low = 'DarkGreen';    Muted   = 'DarkGray';    Warning = 'DarkRed'
        Success = 'DarkGreen'
    }
}


#region Run transcripts

# Notepad++ tails a growing file with -monitor, which is what makes a live run log
# watchable. Absent, the 'm' key is simply not offered.
function Get-MonitorProgram
{
    $candidates = @(
        'C:\Program Files\Notepad++\notepad++.exe'
        'C:\Program Files (x86)\Notepad++\notepad++.exe'
    )

    foreach ($candidate in $candidates)
    {
        if (Test-Path $candidate)
            { return $candidate }
    }

    $command = Get-Command 'notepad++.exe' -ErrorAction SilentlyContinue
    if ($null -ne $command)
        { return $command.Source }

    return $null
}

function Start-RunMonitor
{
    param([Parameter(Mandatory)][string]$Path)

    $program = Get-MonitorProgram
    if ($null -eq $program -or -not (Test-Path $Path))
        { return $false }

    Start-Process -FilePath $program -ArgumentList @('-monitor', $Path)
    return $true
}

# The transcript is the only lasting record of a call: the raw stream is overwritten
# by the next one. So nothing the model produced is shortened here, only laid out;
# the one exception is what read-like tools showed it, see Format-ToolResult. Parsed JSON values are laid out the way YAML would, one entry
# per line with strings keeping their own line breaks, which reads far better than
# escaped JSON for the prose the structured answers are made of.
function Format-LogEntry
{
    param([string]$Prefix, $Value, [string]$Indent)

    $child = $Indent + '    '

    if ($Value -is [System.Management.Automation.PSCustomObject])
    {
        if (@($Value.PSObject.Properties).Count -eq 0)
            { return @($Prefix + '{}') }

        return @($Prefix.TrimEnd()) + @(Format-LogProperties -Object $Value -Indent $child)
    }

    if ($Value -is [array])
    {
        if ($Value.Count -eq 0)
            { return @($Prefix + '[]') }

        $lines = @($Prefix.TrimEnd())
        foreach ($item in $Value)
        {
            if ($item -is [System.Management.Automation.PSCustomObject] -and @($item.PSObject.Properties).Count -gt 0)
            {
                # An object in a list opens on the dash line, its first entry beside it.
                $entries = @(Format-LogProperties -Object $item -Indent "$child  ")
                $entries[0] = "$child- " + $entries[0].Substring($child.Length + 2)
                $lines += $entries
            }
            else
                { $lines += Format-LogEntry -Prefix "$child- " -Value $item -Indent "$child  " }
        }

        return $lines
    }

    $text = if ($null -eq $Value) { 'null' } else { [string]$Value }
    $parts = @($text -split '\r?\n')
    $lines = @(($Prefix + $parts[0]).TrimEnd())
    foreach ($part in $parts | Select-Object -Skip 1)
        { $lines += ($child + $part).TrimEnd() }

    return $lines
}

function Format-LogProperties
{
    param([Parameter(Mandatory)][psobject]$Object, [string]$Indent)

    $lines = @()
    foreach ($property in $Object.PSObject.Properties)
        { $lines += Format-LogEntry -Prefix "$Indent$($property.Name): " -Value $property.Value -Indent $Indent }

    return $lines
}

# Short scalar arguments stay on the call line, the way a session view shows them;
# anything long, multi-line or nested is laid out below it, one argument per line.
function Format-ToolCall
{
    param([Parameter(Mandatory)][string]$Name, $InputObject)

    $properties = if ($null -eq $InputObject) { @() } else { @($InputObject.PSObject.Properties) }

    $inline = @()
    foreach ($property in $properties)
    {
        $value = $property.Value
        if ($value -is [array] -or $value -is [System.Management.Automation.PSCustomObject] -or
            ([string]$value) -match '[\r\n]')
            { $inline = $null; break }

        $inline += ('{0}={1}' -f $property.Name, $value)
    }

    if ($null -ne $inline)
    {
        $line = '* {0}({1})' -f $Name, ($inline -join ', ')
        if ($line.Length -le 160)
            { return @($line) }
    }

    return @("* $Name") + @(Format-LogProperties -Object $InputObject -Indent '    ')
}

# A content part the formatter has no layout for is still logged, as compact JSON.
function Format-UnknownPart
{
    param([string]$Kind, [Parameter(Mandatory)][psobject]$Part)

    return ('[{0}] {1}' -f $Kind, ($Part | ConvertTo-Json -Depth 32 -Compress))
}

# Read-like tools return what is still on disk or on the web, so only the first lines
# of their results are kept, enough to show what came back. Every other result, a
# subagent's report above all, is logged whole. Binary payloads are described rather
# than copied: base64 image data says nothing in a log.
function Format-ToolResult
{
    param($Block, [string]$ToolName, [int]$MaxReadLines = 10)

    $readLikeTools = @('Read', 'Grep', 'Glob', 'LS', 'NotebookRead', 'WebFetch', 'WebSearch', 'ToolSearch')

    $label = $ToolName
    if ($true -eq (Get-Field -Object $Block -Name 'is_error'))
        { $label = if ([string]::IsNullOrEmpty($label)) { 'error' } else { "$label, error" } }

    # Tool calls are often issued in parallel, so both requests print before either
    # result. Naming the tool on the result line keeps the pairing readable.
    $tag = if ([string]::IsNullOrEmpty($label)) { '    -> ' } else { "    -> [$label] " }
    $pad = ' ' * $tag.Length

    $content = Get-Field -Object $Block -Name 'content'
    $texts = @()
    foreach ($part in @($content))
    {
        if ($null -eq $part)
            { continue }

        if ($part -is [string])
            { $texts += $part; continue }

        $kind = [string](Get-Field -Object $part -Name 'type')
        if ($kind -eq 'text')
            { $texts += [string](Get-Field -Object $part -Name 'text') }
        elseif ($kind -eq 'image')
        {
            $source = Get-Field -Object $part -Name 'source'
            $mediaType = if ($null -ne $source) { Get-Field -Object $source -Name 'media_type' } else { $null }
            $data = if ($null -ne $source) { [string](Get-Field -Object $source -Name 'data') } else { '' }
            $texts += ('[image {0}, {1} base64 characters not logged]' -f $mediaType, $data.Length)
        }
        else
            { $texts += Format-UnknownPart -Kind $kind -Part $part }
    }

    $text = $texts -join "`n"
    if ([string]::IsNullOrWhiteSpace($text))
        { return @($tag + '(no output)') }

    $all = @($text -split '\r?\n')
    $shown = if ($ToolName -in $readLikeTools) { @($all | Select-Object -First $MaxReadLines) } else { $all }

    $lines = @($tag + $shown[0])
    foreach ($line in $shown | Select-Object -Skip 1)
        { $lines += $pad + $line }

    if ($all.Count -gt $shown.Count)
        { $lines += ($pad + ('... {0} more line(s)' -f ($all.Count - $shown.Count))) }

    return $lines
}

# One streamed event becomes zero or more transcript lines. Only bookkeeping yields
# nothing: rate limit notices, read elsewhere for the status row, and the running
# thinking estimates, which are folded into the thinking block they lead up to.
# An event of a kind not known here is logged as compact JSON rather than dropped.
function Format-RunEvent
{
    param([Parameter(Mandatory)][psobject]$Record, [Parameter(Mandatory)][hashtable]$State)

    $type = [string](Get-Field -Object $Record -Name 'type')
    switch ($type)
    {
        'system'
        {
            $subtype = [string](Get-Field -Object $Record -Name 'subtype')
            if ($subtype -eq 'init')
            {
                # The init event carries the model but not the reasoning level, so the
                # effort the caller asked for is threaded in through the transcript state.
                $model = "model $($Record.model)"
                if (-not [string]::IsNullOrEmpty($State.Effort))
                    { $model += " | effort $($State.Effort)" }

                return @($model, "session $($Record.session_id)", '')
            }

            # The estimate is cumulative within one thinking block.
            if ($subtype -eq 'thinking_tokens')
            {
                $State.ThinkingTokens = Get-Field -Object $Record -Name 'estimated_tokens'
                return @()
            }

            $rest = $Record | Select-Object -Property * -ExcludeProperty 'type', 'subtype', 'session_id', 'uuid'
            return @(('[system {0}] {1}' -f $subtype, ($rest | ConvertTo-Json -Depth 32 -Compress)), '')
        }

        'assistant'
        {
            $lines = @()
            foreach ($block in @($Record.message.content))
            {
                if ($block -is [string])
                    { $block = [pscustomobject]@{ type = 'text'; text = $block } }

                $kind = [string](Get-Field -Object $block -Name 'type')
                if ($kind -eq 'text')
                {
                    $text = [string](Get-Field -Object $block -Name 'text')
                    if (-not [string]::IsNullOrWhiteSpace($text))
                        { $lines += @($text.TrimEnd(), '') }
                }
                elseif ($kind -eq 'thinking' -or $kind -eq 'redacted_thinking')
                {
                    # The reasoning itself comes back stripped, leaving only an encrypted
                    # signature; some blocks carry a short summary in its place.
                    $notes = @()
                    if ($null -ne $State.ThinkingTokens)
                        { $notes += ('~{0} tokens' -f $State.ThinkingTokens) }

                    $State.ThinkingTokens = $null

                    $text = if ($kind -eq 'thinking') { [string](Get-Field -Object $block -Name 'thinking') } else { '' }
                    if ($kind -eq 'redacted_thinking')
                        { $notes += 'redacted' }
                    elseif ([string]::IsNullOrWhiteSpace($text))
                        { $notes += 'no text returned' }

                    $lines += ('~ thinking ({0})' -f ($notes -join ', '))
                    if (-not [string]::IsNullOrWhiteSpace($text))
                    {
                        foreach ($line in $text.Trim() -split '\r?\n')
                            { $lines += ('  ' + $line).TrimEnd() }
                    }

                    $lines += ''
                }
                elseif ($kind -eq 'tool_use')
                {
                    $State.ToolNames[[string]$block.id] = [string]$block.name
                    $lines += Format-ToolCall -Name ([string]$block.name) -InputObject (Get-Field -Object $block -Name 'input')
                }
                else
                    { $lines += @((Format-UnknownPart -Kind $kind -Part $block), '') }
            }

            return $lines
        }

        'user'
        {
            $lines = @()
            foreach ($block in @($Record.message.content))
            {
                if ($block -is [string])
                    { $block = [pscustomobject]@{ type = 'text'; text = $block } }

                $kind = [string](Get-Field -Object $block -Name 'type')
                if ($kind -eq 'tool_result')
                {
                    $name = ''
                    $id = [string](Get-Field -Object $block -Name 'tool_use_id')
                    if (-not [string]::IsNullOrEmpty($id) -and $State.ToolNames.ContainsKey($id))
                        { $name = $State.ToolNames[$id] }

                    $lines += (Format-ToolResult -Block $block -ToolName $name) + @('')
                }
                elseif ($kind -eq 'text')
                {
                    $text = [string](Get-Field -Object $block -Name 'text')
                    if (-not [string]::IsNullOrWhiteSpace($text))
                    {
                        foreach ($line in $text.TrimEnd() -split '\r?\n')
                            { $lines += ('> ' + $line).TrimEnd() }

                        $lines += ''
                    }
                }
                else
                    { $lines += @((Format-UnknownPart -Kind $kind -Part $block), '') }
            }

            return $lines
        }

        'result'
        {
            $lines = @('')

            # On success the result text is the structured answer, already logged as
            # the StructuredOutput call. On failure it is the reason.
            $subtype = [string](Get-Field -Object $Record -Name 'subtype')
            if ($subtype -ne 'success' -or $true -eq (Get-Field -Object $Record -Name 'is_error'))
            {
                $message = [string](Get-Field -Object $Record -Name 'result')
                foreach ($line in @($message -split '\r?\n') + @(Get-Field -Object $Record -Name 'errors'))
                {
                    if (-not [string]::IsNullOrWhiteSpace([string]$line))
                        { $lines += "! $line" }
                }
            }

            $denials = Get-Field -Object $Record -Name 'permission_denials'
            foreach ($denial in @($denials))
            {
                if ($null -ne $denial)
                    { $lines += ('! permission denied: {0}' -f ($denial | ConvertTo-Json -Depth 32 -Compress)) }
            }

            $segments = @($subtype, ('{0} turn(s)' -f (Get-Field -Object $Record -Name 'num_turns')))

            $usage = Get-Field -Object $Record -Name 'usage'
            $outputTokens = if ($null -ne $usage) { Get-Field -Object $usage -Name 'output_tokens' } else { $null }
            if ($null -ne $outputTokens)
            {
                $tokens = '{0} output tokens' -f $outputTokens
                $details = Get-Field -Object $usage -Name 'output_tokens_details'
                $thinking = if ($null -ne $details) { Get-Field -Object $details -Name 'thinking_tokens' } else { $null }
                if ($null -ne $thinking)
                    { $tokens += (', {0} thinking' -f $thinking) }

                $segments += $tokens
            }

            $segments += ('{0:n4} USD' -f (Get-Field -Object $Record -Name 'total_cost_usd'))
            $segments += ('{0:n1}s' -f ((Get-Field -Object $Record -Name 'duration_ms') / 1000))
            $lines += ('=== {0} ===' -f ($segments -join ' | '))
            return $lines
        }

        'rate_limit_event'
            { return @() }
    }

    $rest = $Record | Select-Object -Property * -ExcludeProperty 'type', 'session_id', 'uuid'
    return @(('[{0}] {1}' -f $type, ($rest | ConvertTo-Json -Depth 32 -Compress)), '')
}

# Converts whatever is new in the raw stream into readable text and appends it. The
# offset in $State makes this cheap to call every tick while the model is running,
# which is what lets the transcript be monitored live.
# The child process still holds the raw log open for writing, so it can only be read
# with FileShare.ReadWrite. Returns $null rather than throwing when the file is
# momentarily unreadable; every caller here is on a tick and will try again.
function Read-SharedLines
{
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path $Path))
        { return $null }

    try
    {
        $stream = [System.IO.FileStream]::new($Path, [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try
        {
            $reader = [System.IO.StreamReader]::new($stream, [System.Text.Encoding]::UTF8)
            $all = @()
            while ($null -ne ($line = $reader.ReadLine()))
                { $all += $line }

            return ,$all
        }
        finally
        {
            $stream.Dispose()
        }
    }
    catch
    {
        return $null
    }
}

function Update-RunTranscript
{
    param(
        [Parameter(Mandatory)][string]$RawLog,
        [Parameter(Mandatory)][string]$Transcript,
        [Parameter(Mandatory)][hashtable]$State
    )

    $all = Read-SharedLines -Path $RawLog
    if ($null -eq $all)
        { return }

    if ($all.Count -le $State.Offset)
        { return }

    $new = @()
    for ($i = $State.Offset; $i -lt $all.Count; $i++)
    {
        if ([string]::IsNullOrWhiteSpace($all[$i]))
            { continue }

        try
            { $record = $all[$i] | ConvertFrom-Json }
        catch
            { continue }   # A half-written trailing line; it will be picked up next tick.

        # A fault in the formatter must not cost the event, so it is logged as received.
        try
            { $new += Format-RunEvent -Record $record -State $State }
        catch
            { $new += @("[event not formatted: $($_.Exception.Message)]", $all[$i], '') }
    }

    # Only advance past lines that parsed, so a torn final line is retried.
    $State.Offset = $all.Count
    if ($all.Count -gt 0 -and -not (Test-JsonLine $all[$all.Count - 1]))
        { $State.Offset = $all.Count - 1 }

    if ($new.Count -eq 0)
        { return }

    Add-Content -LiteralPath $Transcript -Value $new -Encoding utf8
}

function Test-JsonLine
{
    param([string]$Line)

    if ([string]::IsNullOrWhiteSpace($Line))
        { return $true }

    try
        { $null = $Line | ConvertFrom-Json; return $true }
    catch
        { return $false }
}

function Start-RunTranscript
{
    param(
        [Parameter(Mandatory)][string]$Transcript,
        [Parameter(Mandatory)][string]$Header,
        [string]$Effort = ''
    )

    $directory = Split-Path -Parent $Transcript
    if (-not (Test-Path $directory))
        { New-Item -ItemType Directory -Path $directory -Force | Out-Null }

    Set-Content -LiteralPath $Transcript -Value @("=== $Header ===", '') -Encoding utf8
    return @{ Offset = 0; ToolNames = @{}; Effort = $Effort; ThinkingTokens = $null }
}

#endregion

#region Subscription usage

# The CLI reports subscription usage as rate_limit_event records in the same stream
# the transcript is built from, so the weekly figure is a by-product of the run
# rather than a separate query: nothing has to be asked of the API, and no
# credential is read. It only moves while a call is in flight, so the last reading is
# kept globally and stays on screen across calls and across both phases.
Set-Variable -Name PodofoUsage -Scope Global -Value @{
    Text      = ''
    CheckedAt = [datetime]::MinValue
} -Force

# Rescans the raw log at most every -IntervalSeconds and returns the cached string in
# between, so this can be called on every spinner frame without re-reading the file.
function Get-UsageStatus
{
    param([string]$RawLog, [int]$IntervalSeconds = 30, [switch]$Force)

    # A blank row is worth more effort than a stale one. A call's log starts empty
    # and only gains a reading once the first response comes back, so booking the
    # full interval on a miss left the row empty long after the figures had arrived.
    if ([string]::IsNullOrEmpty($global:PodofoUsage.Text))
        { $IntervalSeconds = 3 }

    $now = Get-Date
    if ((-not $Force) -and (($now - $global:PodofoUsage.CheckedAt).TotalSeconds -lt $IntervalSeconds))
        { return $global:PodofoUsage.Text }

    $global:PodofoUsage.CheckedAt = $now
    if ([string]::IsNullOrEmpty($RawLog))
        { return $global:PodofoUsage.Text }

    $all = Read-SharedLines -Path $RawLog
    if ($null -eq $all)
        { return $global:PodofoUsage.Text }

    # Only the newest reading matters, so scan backwards and stop at the first one
    # that parses; a torn trailing line is skipped rather than retried.
    for ($i = $all.Count - 1; $i -ge 0; $i--)
    {
        if ($all[$i] -notmatch '"rate_limit_event"')
            { continue }

        try
            { $record = $all[$i] | ConvertFrom-Json }
        catch
            { continue }

        $info = Get-Field -Object $record -Name 'rate_limit_info'
        if ($null -eq $info)
            { continue }

        $windows = Get-Field -Object $info -Name 'unifiedWindows'
        if ($null -eq $windows)
            { continue }

        $parts = @()
        foreach ($window in @(@{ Name = 'seven_day'; Label = 'week' }, @{ Name = 'five_hour'; Label = '5h' }))
        {
            $bucket = Get-Field -Object $windows -Name $window.Name
            if ($null -eq $bucket)
                { continue }

            $used = Get-Field -Object $bucket -Name 'utilization'
            if ($null -eq $used)
                { continue }

            $parts += '{0} {1}%' -f $window.Label, [int][Math]::Round(100 * [double]$used)
        }

        if ($parts.Count -eq 0)
            { continue }

        $global:PodofoUsage.Text = 'Usage ' + ($parts -join ', ')
        break
    }

    return $global:PodofoUsage.Text
}

# Reads now rather than waiting out the interval. Called once before a run starts,
# where the previous run's log is still on disk and its last figures are a better
# opening than an empty row, and again after each model call, where the log has just
# gained that call's closing figures. Returns nothing; the ticker reads the cache.
function Update-UsageStatus
{
    param([string]$RawLog)

    $null = Get-UsageStatus -RawLog $RawLog -Force
}

# An exhausted subscription window arrives on the same channel as the usage figures:
# a rate_limit_event, this time with status 'rejected'. The event names the window
# that ran out and when it comes back, so a run stopped by a limit can say which
# limit and how long the wait is instead of just echoing an HTTP status.
#
# The event is not always there: a refusal that comes back before the session has
# reported any usage carries only the provider's notice text, so -Notice is read as
# a second source. Unlike Get-UsageStatus nothing is cached here; this runs once,
# after the call has already failed, and the newest event is the refusal itself.
function Get-RateLimitBlock
{
    param([string]$RawLog, [string]$Notice)

    $block = Get-RateLimitEventBlock -RawLog $RawLog
    if ($null -ne $block)
        { return $block }

    return Get-RateLimitNoticeBlock -Notice $Notice
}

function Get-RateLimitEventBlock
{
    param([string]$RawLog)

    if ([string]::IsNullOrEmpty($RawLog))
        { return $null }

    $all = Read-SharedLines -Path $RawLog
    if ($null -eq $all)
        { return $null }

    $labels = @{ five_hour = 'five-hour session'; seven_day = 'weekly' }

    for ($i = $all.Count - 1; $i -ge 0; $i--)
    {
        if ($all[$i] -notmatch '"rate_limit_event"')
            { continue }

        try
            { $record = $all[$i] | ConvertFrom-Json }
        catch
            { continue }

        $info = Get-Field -Object $record -Name 'rate_limit_info'
        if ($null -eq $info)
            { continue }

        # Only the newest reading counts, and only when it is the refusal: an older
        # 'allowed' event says nothing about what has just run out, and reporting the
        # window it names would blame the wrong limit. The notice is tried instead.
        if ((Get-Field -Object $info -Name 'status') -ne 'rejected')
            { return $null }

        $window = [string](Get-Field -Object $info -Name 'rateLimitType')
        $resetsAt = Get-Field -Object $info -Name 'resetsAt'

        # Both carry a reset; the per-window figure is the one that belongs to the
        # window being reported, so prefer it when the pair disagree.
        $windows = Get-Field -Object $info -Name 'unifiedWindows'
        if (($null -ne $windows) -and (-not [string]::IsNullOrEmpty($window)))
        {
            $bucket = Get-Field -Object $windows -Name $window
            if ($null -ne $bucket)
            {
                $own = Get-Field -Object $bucket -Name 'resetsAt'
                if ($null -ne $own)
                    { $resetsAt = $own }
            }
        }

        # Unix seconds, UTC. A shape that does not convert is treated as no reset
        # rather than allowed to throw inside failure handling.
        $reset = $null
        if ($null -ne $resetsAt)
        {
            try
                { $reset = [datetimeoffset]::FromUnixTimeSeconds([long]$resetsAt).ToLocalTime().DateTime }
            catch
                { $reset = $null }
        }

        $label = if ($labels.ContainsKey($window)) { $labels[$window] } else { '' }
        return [pscustomobject]@{
            Window   = $window
            Label    = $label
            ResetsAt = $reset
        }
    }

    return $null
}

# The notice is a provider's UI string ("You've hit your session limit - resets
# 4:50pm (Europe/Rome)"), so it is parsed defensively: an unrecognised shape yields
# nothing rather than a wrong reset. The bracketed zone is the caller's own, which is
# why the clock is read as local time.
function Get-RateLimitNoticeBlock
{
    param([string]$Notice)

    if ([string]::IsNullOrWhiteSpace($Notice))
        { return $null }

    $label = if ($Notice -match '(?i)\bweek')
        { 'weekly' }
    elseif ($Notice -match '(?i)\bsession\b')
        { 'five-hour session' }
    else
        { '' }

    $reset = $null
    if ($Notice -match '(?i)resets?\s+(?:at\s+)?(?<when>[^()]+?)\s*(?:\([^()]*\))?\s*$')
    {
        $when = ($Matches['when'] -replace '(?i)\s+at\s+', ' ').Trim()

        # A 12-hour clock arrives with the meridiem attached; .NET wants it apart.
        $when = $when -replace '(?i)(\d)\s*(am|pm)', '$1 $2'

        # Exact formats only. A loose TryParse accepts these strings and then
        # answers with something unrelated - 'Sep 14 4:50 pm' came back as the
        # current time - which is worse than reporting no reset at all.
        # Typed: an object[] of formats binds to the single-format overload and
        # every parse then fails.
        [string[]]$formats = @('h:mm tt', 'h tt', 'H:mm', 'MMM d h:mm tt', 'MMM d h tt',
            'MMM d, h:mm tt', 'MMM d yyyy h:mm tt', 'MMM d, yyyy h:mm tt')

        $parsed = [datetime]::MinValue
        if ([datetime]::TryParseExact($when, $formats, [cultureinfo]::InvariantCulture,
                [System.Globalization.DateTimeStyles]::AllowWhiteSpaces, [ref]$parsed))
        {
            # A clock with no date parses onto today, and a date with no year onto
            # this year; either lands in the past when the window reopens across the
            # boundary, and rolling it forward is the only reading that makes sense
            # for a reset.
            $timeOnly = $when -match '^\d{1,2}(:\d{2})?\s*(?i:am|pm)?$'
            if ($parsed -lt (Get-Date).AddMinutes(-5))
            {
                $parsed = if ($timeOnly) { $parsed.AddDays(1) } else { $parsed.AddYears(1) }
            }

            $reset = $parsed
        }
    }

    if (($label -eq '') -and ($null -eq $reset))
        { return $null }

    return [pscustomobject]@{
        Window   = ''
        Label    = $label
        ResetsAt = $reset
    }
}

# The sentence a run prints when it stops on a limit. The window is only named when
# the event was explicit about it: guessing 'weekly' at a five-hour pause would send
# someone away for days. -Fallback is the provider's own wording, used when the event
# is missing or says nothing useful.
function Format-RateLimitBlock
{
    param([psobject]$Block, [string]$Fallback)

    $limit = 'Subscription limit reached'
    if (($null -ne $Block) -and (-not [string]::IsNullOrEmpty($Block.Label)))
        { $limit = 'The {0} limit is used up' -f $Block.Label }

    if (($null -eq $Block) -or ($null -eq $Block.ResetsAt))
    {
        if (-not [string]::IsNullOrEmpty($Fallback))
            { return '{0}: {1}' -f $limit, $Fallback.Trim() }

        return '{0}; the reset time was not reported.' -f $limit
    }

    $when = $Block.ResetsAt.ToString('yyyy-MM-dd HH:mm')
    $wait = $Block.ResetsAt - (Get-Date)
    if ($wait.TotalMinutes -lt 1)
        { return '{0}. Resets at {1}, any moment now.' -f $limit, $when }

    # A weekly window can be days out, where minutes are noise.
    $waitText = if ($wait.TotalHours -lt 1)
        { '{0}m' -f [int]$wait.TotalMinutes }
    elseif ($wait.TotalDays -lt 1)
        { '{0}h {1}m' -f $wait.Hours, $wait.Minutes }
    else
        { '{0}d {1}h' -f [int][Math]::Floor($wait.TotalDays), $wait.Hours }

    return '{0}. Resets at {1}, {2} from now.' -f $limit, $when, $waitText
}

# The seam signals an exhausted window with this error id, so a driver can tell a
# pause apart from a failure without matching on message text. A replacement seam
# has to raise the same id to get the clean stop; anything else is a hard error.
function Test-RateLimitError
{
    param([Parameter(Mandatory)][System.Management.Automation.ErrorRecord]$ErrorRecord)

    return ([string]$ErrorRecord.FullyQualifiedErrorId).StartsWith('PodofoRateLimitReached')
}

#endregion

#region Activity line

# A one-line activity indicator that rewrites itself in place, and the place where
# keys pressed during a model call are noticed.
#
# Rendering and key polling are gated separately and on the right signals: output
# redirection decides whether the line can be drawn, input redirection decides
# whether keys can be read. Gating both on one flag meant a host that could not draw
# also silently stopped listening, which is why 'm' appeared dead.
function New-ActivityTicker
{
    param(
        [Parameter(Mandatory)][string]$Text,
        [string]$Color = 'Blue',
        [string]$Hint = '',
        [string]$MonitorPath,
        [string]$RawLog,
        [string]$Transcript,
        [hashtable]$Signal,
        [hashtable]$TranscriptState
    )

    $palette = Get-AuditPalette

    # The closure is invoked from the model seam's scope, where these names do not
    # resolve. Capturing the command objects as variables makes them travel with it.
    $monitorCommand = Get-Command Start-RunMonitor
    $transcriptCommand = Get-Command Update-RunTranscript
    $usageCommand = Get-Command Get-UsageStatus

    # Once 'q' is pressed only 'm' is still actionable, so the hint narrows to it.
    $stopHint = if ((-not [string]::IsNullOrEmpty($MonitorPath)) -and ($null -ne (Get-MonitorProgram)))
        { "press 'm' to monitor" } else { '' }

    $state = @{
        Row       = 0
        Frame     = 0
        Frames    = @('|', '/', '-', '\')
        CanRender = $false
        CanPoll   = $false
    }

    try
    {
        $state.CanRender = -not [Console]::IsOutputRedirected
        if ($state.CanRender)
        {
            # The status is two rows. Emitting one line now reserves the second and,
            # when the cursor was already on the last row, absorbs the scroll that
            # would otherwise leave $state.Row pointing one line too low.
            Write-Host ''
            $state.Row = [Math]::Max(0, [Console]::CursorTop - 1)
        }
    }
    catch
    {
        $state.CanRender = $false
    }

    try
        { $state.CanPoll = -not [Console]::IsInputRedirected }
    catch
        { $state.CanPoll = $false }

    return {
        # Keys first, and never behind the render gate.
        if ($state.CanPoll)
        {
            try
            {
                while ([Console]::KeyAvailable)
                {
                    $key = [Console]::ReadKey($true)
                    switch ([char]::ToLowerInvariant($key.KeyChar))
                    {
                        'q'
                        {
                            if ($null -ne $Signal)
                                { $Signal.Stop = $true }
                        }
                        'm'
                        {
                            if (-not [string]::IsNullOrEmpty($MonitorPath))
                                { $null = & $monitorCommand -Path $MonitorPath }
                        }
                    }
                }
            }
            catch
            {
                $state.CanPoll = $false
            }
        }

        if (-not [string]::IsNullOrEmpty($RawLog) -and -not [string]::IsNullOrEmpty($Transcript) -and $null -ne $TranscriptState)
            { & $transcriptCommand -RawLog $RawLog -Transcript $Transcript -State $TranscriptState }

        if (-not $state.CanRender)
            { return }

        # A pressed 'q' takes effect at the end of the current item, so say so on the
        # spot rather than letting the run look unresponsive.
        $stopping = ($null -ne $Signal -and $Signal.Stop)
        $body = if ($stopping) { "Stopping after this one... ($Text)" } else { $Text }
        $shade = if ($stopping) { $palette.Warning } else { $Color }

        try
        {
            $width = [Math]::Max(20, [Console]::WindowWidth - 1)
            $spinner = $state.Frames[$state.Frame % $state.Frames.Count]
            $state.Frame++

            $line = "  $spinner $body"
            if ($line.Length -gt $width)
                { $line = $line.Substring(0, $width) }

            # Second row: what the run is costing and what can be pressed, indented
            # under the activity text. Get-UsageStatus throttles itself, so this
            # costs a cached string on all but one frame in thirty seconds.
            $segments = @()
            $usage = & $usageCommand -RawLog $RawLog
            if (-not [string]::IsNullOrEmpty($usage))
                { $segments += $usage }

            $tail = if ($stopping) { $stopHint } else { $Hint }
            if (-not [string]::IsNullOrEmpty($tail))
                { $segments += $tail }

            $status = if ($segments.Count -gt 0) { '    ' + ($segments -join '   |   ') } else { '' }
            if ($status.Length -gt $width)
                { $status = $status.Substring(0, $width) }

            [Console]::SetCursorPosition(0, $state.Row)
            Write-Host $line.PadRight($width) -ForegroundColor $shade -NoNewline
            [Console]::SetCursorPosition(0, $state.Row + 1)
            Write-Host $status.PadRight($width) -ForegroundColor $palette.Muted -NoNewline
            [Console]::SetCursorPosition(0, $state.Row)
        }
        catch
        {
            # Window resized or the cursor moved out from under us; stop drawing
            # rather than scribbling over the display. Key polling continues.
            $state.CanRender = $false
        }
    }.GetNewClosure()
}

# Redrawing and key polling both need a real console. When output is piped or
# captured, callers fall back to append-only lines and to the STOP file.
function Test-ConsoleInteractive
{
    try
    {
        if ([Console]::IsOutputRedirected)
            { return $false }

        $null = [Console]::WindowHeight
        return $true
    }
    catch
    {
        return $false
    }
}

# Viewport over pre-rendered rows, centred on the current one when the whole list
# does not fit the window. Rows are objects with Text and Color.
function Write-Viewport
{
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][psobject[]]$Rows,
        [int]$CurrentRow = -1,
        [int]$Reserved = 7
    )

    $available = 8
    try { $available = [Console]::WindowHeight - $Reserved } catch { }
    if ($available -lt 8)
        { $available = 8 }

    $first = 0
    if ($Rows.Count -gt $available)
    {
        $anchor = if ($CurrentRow -ge 0) { $CurrentRow } else { $Rows.Count - 1 }
        $first = $anchor - [int]($available / 2)
        if ($first -lt 0) { $first = 0 }
        if ($first + $available -gt $Rows.Count) { $first = $Rows.Count - $available }
    }

    $muted = (Get-AuditPalette).Muted
    $last = [Math]::Min($first + $available, $Rows.Count) - 1
    if ($first -gt 0)
        { Write-Host ('  ... {0} more above' -f $first) -ForegroundColor $muted }

    for ($r = $first; $r -le $last; $r++)
        { Write-Host $Rows[$r].Text -ForegroundColor $Rows[$r].Color }

    if ($last -lt $Rows.Count - 1)
        { Write-Host ('  ... {0} more below' -f ($Rows.Count - 1 - $last)) -ForegroundColor $muted }
}

#endregion

#!/usr/bin/env pwsh
<#
.SYNOPSIS
Prints the progress of the audit pass.

.DESCRIPTION
Read-only. State is derived the same way podofo-audit-targets.ps1 derives it: the
registry podofo-audit-targets.json, the recon files, and the per-target records under
scan/targets. Targets a recon file defines but no audit run has registered yet are
counted as pending. The first table counts targets per priority and state; the second
breaks each priority down by recon confidence, as pending/total. Safe to run while an
audit pass is working, since every file it reads is only ever replaced whole.
#>

[CmdletBinding()]
param(
    [string]$DatabasePath,
    [string]$ScanRoot
)

$ErrorActionPreference = 'stop'
Set-StrictMode -Version Latest

if ([string]::IsNullOrEmpty($ScanRoot))
    { $ScanRoot = Join-Path $PSScriptRoot 'scan' }
if ([string]::IsNullOrEmpty($DatabasePath))
    { $DatabasePath = Join-Path $ScanRoot 'podofo-audit-targets.json' }

. (Join-Path $PSScriptRoot 'audit-common.ps1')

$targetsRoot = Join-Path $ScanRoot 'targets'
$registry = Read-TargetRegistry -Path $DatabasePath
# Wrapped: a single target unrolls to a bare object.
$targets = @(Get-AuditTargets -Registry $registry -Sources (Read-AuditSources -TargetsRoot $targetsRoot))

$priorities = @('high', 'medium', 'low', 'none') |
    Where-Object { $p = $_; @($targets | Where-Object { $_.priority -eq $p }).Count -gt 0 }
$states = @('pending', 'audited', 'accepted', 'rejected')
# Orphaned rows are rare, so the column only appears when there is one.
if (@($targets | Where-Object { $_.state -eq 'orphaned' }).Count -gt 0)
    { $states += 'orphaned' }
$confidences = @('high', 'medium', 'low')

function Get-Count
{
    param([string]$Priority, [string]$State, [string]$Confidence)

    return @($targets | Where-Object {
        (($Priority -eq '') -or ($_.priority -eq $Priority)) -and
        (($State -eq '') -or ($_.state -eq $State)) -and
        (($Confidence -eq '') -or ($_.confidence -eq $Confidence)) }).Count
}

$stateRows = foreach ($priority in @($priorities) + '') {
    $row = [ordered]@{ Priority = if ($priority -eq '') { 'total' } else { $priority } }
    foreach ($state in $states)
        { $row[(Get-Culture).TextInfo.ToTitleCase($state)] = Get-Count -Priority $priority -State $state }
    $row['Total'] = Get-Count -Priority $priority
    [pscustomobject]$row
}

$confidenceRows = foreach ($priority in @($priorities) + '') {
    $row = [ordered]@{ Priority = if ($priority -eq '') { 'total' } else { $priority } }
    foreach ($confidence in $confidences)
    {
        $pending = Get-Count -Priority $priority -State 'pending' -Confidence $confidence
        $total = Get-Count -Priority $priority -Confidence $confidence
        $row[(Get-Culture).TextInfo.ToTitleCase($confidence)] = "$pending/$total"
    }
    [pscustomobject]$row
}

# Draws rows as a box-drawing table. The first column is left-aligned and the rest
# right-aligned, and the last row is ruled off as the totals.
function Write-BoxTable
{
    param([Parameter(Mandatory)][psobject[]]$Rows)

    $columns = @($Rows[0].PSObject.Properties.Name)
    $widths = foreach ($column in $columns)
        { (@($column.Length) + @($Rows | ForEach-Object { "$($_.$column)".Length }) | Measure-Object -Maximum).Maximum }

    $rule = {
        param([string]$Left, [string]$Middle, [string]$Right)
        $Left + (($widths | ForEach-Object { [string]::new([char]0x2500, $_ + 2) }) -join $Middle) + $Right
    }
    $line = {
        param([string[]]$Cells)
        $padded = for ($i = 0; $i -lt $Cells.Count; $i++)
            { if ($i -eq 0) { $Cells[$i].PadRight($widths[$i]) } else { $Cells[$i].PadLeft($widths[$i]) } }
        [char]0x2502 + ' ' + ($padded -join " $([char]0x2502) ") + ' ' + [char]0x2502
    }

    Write-Host (& $rule ([char]0x250C) ([char]0x252C) ([char]0x2510))
    Write-Host (& $line $columns)
    Write-Host (& $rule ([char]0x251C) ([char]0x253C) ([char]0x2524))
    for ($r = 0; $r -lt $Rows.Count; $r++)
    {
        if ($r -eq $Rows.Count - 1 -and $Rows.Count -gt 1)
            { Write-Host (& $rule ([char]0x251C) ([char]0x253C) ([char]0x2524)) }
        Write-Host (& $line @($columns | ForEach-Object { "$($Rows[$r].$_)" }))
    }
    Write-Host (& $rule ([char]0x2514) ([char]0x2534) ([char]0x2518))
}

# A Windows console may still be on a legacy code page, which has no box characters.
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$spawnedPending = @($targets | Where-Object { $_.source -eq 'spawned' -and $_.state -eq 'pending' }).Count

# The registry changes only when targets appear; the records change with every step.
$records = @(Get-ChildItem -LiteralPath $targetsRoot -Filter '*.json' -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match '^[0-9a-f]{8}\.json$' })
$activity = if ($records.Count -gt 0)
    { "  (last record written $((($records | Measure-Object LastWriteTime -Maximum).Maximum).ToString('yyyy-MM-dd HH:mm')))" }
    else { '' }

Write-Host "Targets by state$activity"
Write-BoxTable -Rows @($stateRows)
Write-Host ''
Write-Host 'Targets by confidence  (pending/total)'
Write-BoxTable -Rows @($confidenceRows)
Write-Host ''
Write-Host "Pending: $(Get-Count -State 'pending'), of which $spawnedPending spawned by the validator"

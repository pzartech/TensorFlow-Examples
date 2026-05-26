<#
.SYNOPSIS
    Audits every git repo under a folder (default: C:\Users\jerem\code\github).
.DESCRIPTION
    For each repository it reports branch, uncommitted changes, ahead/behind vs
    upstream, whether a remote is configured, last-commit age (stale flag), and
    on-disk size. It also surfaces large files and repos with no remote.
.USAGE
    powershell -ExecutionPolicy Bypass -File .\audit-github-folder.ps1
    powershell -ExecutionPolicy Bypass -File .\audit-github-folder.ps1 -Root "D:\src" -StaleDays 60 -BigFileMB 25
#>

param(
    [string]$Root = "$env:USERPROFILE\code\github",
    [int]$StaleDays = 90,
    [int]$BigFileMB = 50
)

if (-not (Test-Path $Root)) {
    Write-Host "Folder not found: $Root" -ForegroundColor Red
    exit 1
}
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Host "git is not on PATH. Install Git for Windows first." -ForegroundColor Red
    exit 1
}

Write-Host "Auditing repos under: $Root" -ForegroundColor Cyan
Write-Host ("Stale threshold: {0} days | Big-file threshold: {1} MB`n" -f $StaleDays, $BigFileMB)

$repos = Get-ChildItem -LiteralPath $Root -Directory |
         Where-Object { Test-Path (Join-Path $_.FullName ".git") }

if (-not $repos) {
    Write-Host "No git repositories found directly under $Root." -ForegroundColor Yellow
    exit 0
}

$rows = foreach ($repo in $repos) {
    $p = $repo.FullName

    $branch = (git -C $p rev-parse --abbrev-ref HEAD 2>$null)

    # uncommitted changes
    $dirty = (git -C $p status --porcelain 2>$null)
    $dirtyCount = if ($dirty) { ($dirty | Measure-Object).Count } else { 0 }

    # remotes
    $remotes = (git -C $p remote 2>$null)
    $hasRemote = [bool]$remotes
    $originUrl = (git -C $p remote get-url origin 2>$null)

    # ahead / behind upstream
    $ahead = 0; $behind = 0; $hasUpstream = $false
    $counts = (git -C $p rev-list --left-right --count '@{u}...HEAD' 2>$null)
    if ($LASTEXITCODE -eq 0 -and $counts) {
        $hasUpstream = $true
        $parts = $counts -split '\s+'
        $behind = [int]$parts[0]
        $ahead  = [int]$parts[1]
    }

    # last commit age
    $lastEpoch = (git -C $p log -1 --format=%ct 2>$null)
    $ageDays = $null; $lastDate = $null
    if ($lastEpoch) {
        $dt = [DateTimeOffset]::FromUnixTimeSeconds([int64]$lastEpoch).LocalDateTime
        $lastDate = $dt.ToString('yyyy-MM-dd')
        $ageDays = [int]((Get-Date) - $dt).TotalDays
    }

    # on-disk size (MB)
    $sizeMB = [math]::Round(
        ((Get-ChildItem -LiteralPath $p -Recurse -File -Force -ErrorAction SilentlyContinue |
          Measure-Object Length -Sum).Sum / 1MB), 1)

    # flags
    $flags = New-Object System.Collections.Generic.List[string]
    if ($dirtyCount -gt 0)              { $flags.Add("DIRTY($dirtyCount)") }
    if (-not $hasRemote)                { $flags.Add("NO-REMOTE") }
    if ($hasUpstream -and $ahead -gt 0) { $flags.Add("UNPUSHED($ahead)") }
    if ($hasRemote -and -not $hasUpstream) { $flags.Add("NO-UPSTREAM") }
    if ($ageDays -ne $null -and $ageDays -gt $StaleDays) { $flags.Add("STALE(${ageDays}d)") }

    [PSCustomObject]@{
        Repo     = $repo.Name
        Branch   = $branch
        Dirty    = $dirtyCount
        Ahead    = $ahead
        Behind   = $behind
        Remote   = if ($hasRemote) { 'yes' } else { 'NO' }
        LastCommit = $lastDate
        AgeDays  = $ageDays
        SizeMB   = $sizeMB
        Flags    = ($flags -join ' ')
        Path     = $p
        Origin   = $originUrl
    }
}

Write-Host "================ REPO INVENTORY ================" -ForegroundColor Green
$rows | Sort-Object Repo |
    Format-Table Repo, Branch, Dirty, Ahead, Behind, Remote, LastCommit, AgeDays, SizeMB, Flags -AutoSize

Write-Host "`n================ NEEDS ATTENTION ================" -ForegroundColor Yellow
$attention = $rows | Where-Object { $_.Flags }
if ($attention) {
    $attention | Sort-Object Repo | Format-Table Repo, Flags, Origin -AutoSize -Wrap
} else {
    Write-Host "All clean - nothing flagged." -ForegroundColor Green
}

Write-Host "`n================ SUMMARY ================" -ForegroundColor Cyan
"{0,-22} {1}" -f "Total repos:",     ($rows | Measure-Object).Count
"{0,-22} {1}" -f "With changes:",    (($rows | Where-Object { $_.Dirty -gt 0 }) | Measure-Object).Count
"{0,-22} {1}" -f "With unpushed:",   (($rows | Where-Object { $_.Ahead -gt 0 }) | Measure-Object).Count
"{0,-22} {1}" -f "No remote:",       (($rows | Where-Object { $_.Remote -eq 'NO' }) | Measure-Object).Count
"{0,-22} {1}" -f "Stale (>$StaleDays d):", (($rows | Where-Object { $_.AgeDays -gt $StaleDays }) | Measure-Object).Count
"{0,-22} {1} MB" -f "Total size:",   [math]::Round((($rows | Measure-Object SizeMB -Sum).Sum), 1)

Write-Host "`n================ LARGE FILES (>$BigFileMB MB) ================" -ForegroundColor Magenta
$big = Get-ChildItem -LiteralPath $Root -Recurse -File -Force -ErrorAction SilentlyContinue |
       Where-Object { $_.Length -gt ($BigFileMB * 1MB) -and $_.FullName -notmatch '\\\.git\\' } |
       Sort-Object Length -Descending |
       Select-Object -First 25
if ($big) {
    $big | ForEach-Object {
        "{0,8:N1} MB  {1}" -f ($_.Length / 1MB), $_.FullName.Replace($Root, '.')
    }
} else {
    Write-Host "None." -ForegroundColor Green
}

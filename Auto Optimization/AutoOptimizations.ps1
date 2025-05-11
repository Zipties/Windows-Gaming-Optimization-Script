<#
 AutoOptimization.ps1  –  Full script with visible console logging
#>

#region ─ Elevation check ──────────────────────────────────────────────────────
$cur = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal $cur).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell.exe -Verb RunAs `
        -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" 
    exit
}
#endregion

#region ─ Configuration ───────────────────────────────────────────────────────
$ScriptDir    = Split-Path -Parent $PSCommandPath
$TaskFile     = Join-Path $ScriptDir 'tasklist.txt'
$SvcFile      = Join-Path $ScriptDir 'servicelist.txt'
$KillFile     = Join-Path $ScriptDir 'killlist.txt'
$BackupFile   = Join-Path $env:APPDATA 'Gaming Optimization\service_backup.json'
$LogFile      = Join-Path $ScriptDir 'AutoOptimization.log'

function Load-List {
    param([string]$path)

    if (Test-Path $path) {
        Get-Content $path |
          ForEach-Object { $_ -replace '\.exe$','' } |
          Where-Object { $_.Trim() -ne '' }
    }
    else {
        @()
    }
}


$WatchList   = Load-List $TaskFile
$ServiceList = Load-List $SvcFile
$KillList    = Load-List $KillFile
#endregion

#region ─ Logger & Banner ────────────────────────────────────────────────────
function Write-Log {
    param([string]$msg,[ConsoleColor]$col='White')
    $ts   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "$ts  $msg"
    $line | Out-File -FilePath $LogFile -Append -Encoding UTF8
    Write-Host $line -ForegroundColor $col
}

function Show-Banner {
    Write-Host ''
    Write-Host '  ////////////////////////' -ForegroundColor Magenta
    Write-Host ' //   Auto Optimization  //' -ForegroundColor Magenta
    Write-Host '////////////////////////'  -ForegroundColor Magenta
    Write-Host ''
}
#endregion

#region ─ Helpers ──────────────────────────────────────────────────────────────
function Backup-Services {
    Write-Log "Backing up $($ServiceList.Count) services…" Cyan
    $data = foreach ($name in $ServiceList) {
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($svc) {
            Write-Log "  -> $name : start=$($svc.StartType), status=$($svc.Status)" DarkGray
            [pscustomobject]@{Name=$name;StartType=$svc.StartType;WasRunning=($svc.Status -eq 'Running')}
        } else {
            Write-Log "  !! $name not installed" DarkGray
        }
    }
    if ($data) { $data | ConvertTo-Json | Set-Content $BackupFile -Encoding UTF8 }
}

function Disable-Services {
    Write-Log 'Disabling & stopping services…' Cyan
    foreach ($name in $ServiceList) {
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($svc) {
            if ($svc.Status -eq 'Running') {
                Stop-Service $svc -Force -ErrorAction SilentlyContinue
                Write-Log "  stopped  $name" DarkGray
            }
            Set-Service $svc -StartupType Disabled -ErrorAction SilentlyContinue
            Write-Log "  disabled $name" DarkGray
        }
    }
}

function Kill-Procs {
    Write-Log 'Killing overlay/shell processes…' Cyan
    foreach ($name in $KillList) {
        $k = Get-Process -Name $name -ErrorAction SilentlyContinue | Stop-Process -Force -PassThru -ErrorAction SilentlyContinue
        if ($k) { Write-Log "  killed $name (instances=$($k.Count))" DarkGray }
    }
}

function Set-Priority {
    param([string[]]$names,[string]$class)
    Write-Log "Setting priority $class on: $($names -join ', ')" Cyan
    foreach ($name in $names) {
        Get-Process -Name $name -ErrorAction SilentlyContinue |
            ForEach-Object { $_.PriorityClass = $class; Write-Log "  $_.ProcessName pid=$($_.Id)" DarkGray }
    }
}

function Purge-Temp {
    Write-Log 'Purging Temp, Prefetch, Recycle Bin & flushing DNS…' Cyan
    $dirs = 'C:\$Recycle.Bin','C:\Windows\Prefetch','C:\Windows\Temp',
            'C:\Windows\SoftwareDistribution\Download',"$env:LOCALAPPDATA\Temp"
    foreach ($d in $dirs) {
        Remove-Item $d -Recurse -Force -ErrorAction SilentlyContinue
        New-Item  $d -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    }
    Clear-RecycleBin -Force -ErrorAction SilentlyContinue
    Clear-DnsClientCache
    Write-Log '  Cleanup complete' DarkGray
}

function Restore-Services {
    if (-not (Test-Path $BackupFile)) { return }
    Write-Log 'Restoring services…' Yellow
    $data = Get-Content $BackupFile -Raw | ConvertFrom-Json
    foreach ($e in $data) {
        $svc = Get-Service -Name $e.Name -ErrorAction SilentlyContinue
        if ($svc) {
            Set-Service $svc -StartupType $e.StartType -ErrorAction SilentlyContinue
            if ($e.WasRunning) { Start-Service $svc -ErrorAction SilentlyContinue }
            Write-Log "  restored $($e.Name): start=$($e.StartType), running=$($e.WasRunning)" DarkGray
        }
    }
}
#endregion

#region ─ Startup ───────────────────────────────────────────────────────────────
Clear-Host
Show-Banner
if ($WatchList.Count -eq 0) { Write-Log 'No tasks to watch (tasklist.txt empty).' Red; Pause; exit }
Write-Log "Watching for: $($WatchList -join ', ')" Green
Write-Log "Services to manage: $($ServiceList.Count)" Green
Write-Log "Processes to kill: $($KillList.Count)" Green
#endregion

#region ─ Main loop ────────────────────────────────────────────────────────────
$browserNames = @('chrome','firefox')
$steamNames   = @('steam','steamservice','steamwebhelper','GameOverlayUI')

while ($true) {
    # wait for any watched process
    $game = $null
    while (-not $game) {
        foreach ($exe in $WatchList) {
            if (Get-Process -Name $exe -ErrorAction SilentlyContinue) { $game = $exe; break }
        }
        Start-Sleep 1
    }

    Clear-Host
    Show-Banner
    Write-Log "Detected $game – Gaming Mode ON" Green

    Backup-Services
    Disable-Services
    Kill-Procs
    Set-Priority -names $browserNames -class 'BelowNormal'
    Set-Priority -names $steamNames   -class 'Idle'
    Purge-Temp

    # wait for exit
    while (Get-Process -Name $game -ErrorAction SilentlyContinue) { Start-Sleep 1 }

    Clear-Host
    Show-Banner
    Write-Log "$game exited – restoring…" Yellow

    Restore-Services
    Set-Priority -names ($browserNames + $steamNames) -class 'Normal'
    Start-Process explorer.exe

    Write-Log 'Restored. Monitoring again…' Cyan
}
#endregion

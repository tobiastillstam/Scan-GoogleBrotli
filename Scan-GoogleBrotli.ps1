#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Read-only audit that searches servers for the Google Brotli library in all common locations.

.DESCRIPTION
    Searches each target for signs of Google Brotli (the "brotli" / "google-brotli" packages):
      1. Files and folders named *brotli* on all fixed drives
      2. Python installs: Brotli-*.dist-info, brotli*.egg-info and their METADATA name
      3. Node.js installs: node_modules\brotli or node_modules\google-brotli (package.json name)
      4. Environment variables (machine, user and process scope) whose name or value contains brotli
      5. Installed programs (uninstall registry) whose name contains brotli

    Runs locally by default. With -ComputerName it runs remotely over WinRM.
    Read-only: nothing is installed, removed or changed.

.PARAMETER ComputerName
    One or more server names. Default: the local computer.

.PARAMETER ListPath
    Path to a text file with one server name per line. Lines starting with # are ignored.

.PARAMETER Drives
    Drive letters to scan for files and folders. Default: all fixed drives.

.PARAMETER ExcludePath
    Path fragments to skip during the file scan (for example a backup share).

.PARAMETER ThrottleLimit
    Maximum number of parallel remote sessions. Default: 16.

.PARAMETER OutputPath
    Folder for the CSV report and transcript log. Default: a 'Reports' folder next to the script.

.EXAMPLE
    .\Scan-GoogleBrotli.ps1

    Scans the local computer and writes the report to .\Reports.

.EXAMPLE
    .\Scan-GoogleBrotli.ps1 -ListPath .\servers.txt -Verbose

    Scans every server in servers.txt and shows progress.

.EXAMPLE
    .\Scan-GoogleBrotli.ps1 -ComputerName SRV01,SRV02 -Drives C,D -ExcludePath 'D:\Backup'

    Scans two servers, only C: and D:, and skips D:\Backup.

.NOTES
    Author : Tobias Tillstam / Tillnet
    License: MIT
    Version: 1.0
    Output : Reports\GoogleBrotli-<timestamp>.csv and Reports\GoogleBrotli-<timestamp>.log
#>
[CmdletBinding()]
param(
    [string[]]$ComputerName,
    [string]$ListPath,
    [string[]]$Drives,
    [string[]]$ExcludePath = @(),
    [ValidateRange(1, 64)]
    [int]$ThrottleLimit = 16,
    [string]$OutputPath = (Join-Path $PSScriptRoot 'Reports')
)

# ============================================================================
# Section: Scan block (runs on each target, locally or via Invoke-Command)
# ============================================================================
$ScanBlock = {
    param(
        [string[]]$Drives,
        [string[]]$ExcludePath
    )

    $pattern = 'brotli'
    $findings = New-Object System.Collections.Generic.List[object]

    function Add-Finding {
        param($Category, $Location, $Detail)
        $findings.Add([pscustomobject]@{
            Computer = $env:COMPUTERNAME
            Category = $Category
            Location = $Location
            Detail   = $Detail
        })
    }

    # --- 1. Files and folders named *brotli* -------------------------------
    if (-not $Drives) {
        $Drives = Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' |
            ForEach-Object { $_.DeviceID.TrimEnd(':') }
    }
    foreach ($d in $Drives) {
        $root = "$($d.TrimEnd(':')):\"
        if (-not (Test-Path -LiteralPath $root)) { continue }
        Get-ChildItem -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object {
                $full = $_.FullName
                $skip = $false
                foreach ($ex in $ExcludePath) {
                    if ($ex -and $full.StartsWith($ex, [StringComparison]::OrdinalIgnoreCase)) { $skip = $true; break }
                }
                -not $skip -and $_.Name -match $pattern
            } |
            ForEach-Object {
                $kind = if ($_.PSIsContainer) { 'Folder' } else { 'File' }
                Add-Finding -Category 'FileSystem' -Location $_.FullName -Detail $kind
            }
    }

    # --- 2. Python packages -------------------------------------------------
    $pyRoots = New-Object System.Collections.Generic.List[string]
    foreach ($base in @("$env:LOCALAPPDATA\Programs\Python", "$env:ProgramFiles", "${env:ProgramFiles(x86)}", "$env:ProgramData\anaconda3", "$env:USERPROFILE\anaconda3", "$env:USERPROFILE\miniconda3")) {
        if ($base -and (Test-Path -LiteralPath $base)) { $pyRoots.Add($base) }
    }
    # Virtual environments and site-packages are found by a name-based scan above, plus explicit METADATA reads here
    foreach ($root in $pyRoots) {
        Get-ChildItem -LiteralPath $root -Recurse -Directory -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^(Brotli|brotli|google_brotli|google-brotli).*\.(dist-info|egg-info)$' } |
            ForEach-Object {
                $meta = Join-Path $_.FullName 'METADATA'
                if (-not (Test-Path -LiteralPath $meta)) { $meta = Join-Path $_.FullName 'PKG-INFO' }
                $name = ''; $version = ''
                if (Test-Path -LiteralPath $meta) {
                    $head = Get-Content -LiteralPath $meta -TotalCount 15 -ErrorAction SilentlyContinue
                    $name    = ($head | Where-Object { $_ -like 'Name:*' }    | Select-Object -First 1) -replace '^Name:\s*', ''
                    $version = ($head | Where-Object { $_ -like 'Version:*' } | Select-Object -First 1) -replace '^Version:\s*', ''
                }
                Add-Finding -Category 'Python' -Location $_.FullName -Detail "Name=$name Version=$version"
            }
    }
    # Any pip-installed brotli module folder (module name is "brotli" or "_brotli")
    foreach ($root in $pyRoots) {
        Get-ChildItem -LiteralPath $root -Recurse -Directory -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -in @('brotli', 'brotlicffi') -and $_.Parent.Name -eq 'site-packages' } |
            ForEach-Object {
                Add-Finding -Category 'Python' -Location $_.FullName -Detail 'site-packages module folder'
            }
    }

    # --- 3. Node.js packages ------------------------------------------------
    $nodeRoots = New-Object System.Collections.Generic.List[string]
    foreach ($base in @("$env:ProgramFiles\nodejs", "$env:APPDATA\npm", "$env:USERPROFILE", "$env:ProgramData")) {
        if ($base -and (Test-Path -LiteralPath $base)) { $nodeRoots.Add($base) }
    }
    foreach ($root in $nodeRoots) {
        Get-ChildItem -LiteralPath $root -Recurse -Directory -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -in @('brotli', 'google-brotli') -and $_.Parent.Name -eq 'node_modules' } |
            ForEach-Object {
                $pkg = Join-Path $_.FullName 'package.json'
                $ver = ''
                if (Test-Path -LiteralPath $pkg) {
                    try { $ver = (Get-Content -LiteralPath $pkg -Raw | ConvertFrom-Json).version } catch { $ver = 'unreadable' }
                }
                Add-Finding -Category 'Node' -Location $_.FullName -Detail "Version=$ver"
            }
    }

    # --- 4. Environment variables -------------------------------------------
    foreach ($scope in 'Machine', 'User') {
        [System.Environment]::GetEnvironmentVariables($scope.ToLower()) | Out-Null
        $vars = [System.Environment]::GetEnvironmentVariables([System.EnvironmentVariableTarget]::$scope)
        foreach ($key in $vars.Keys) {
            $val = [string]$vars[$key]
            if ($key -match $pattern -or $val -match $pattern) {
                Add-Finding -Category 'EnvVar' -Location "$scope\$key" -Detail $val
            }
        }
    }
    foreach ($key in (Get-ChildItem Env: -ErrorAction SilentlyContinue)) {
        if ($key.Name -match $pattern -or [string]$key.Value -match $pattern) {
            Add-Finding -Category 'EnvVar' -Location "Process\$($key.Name)" -Detail ([string]$key.Value)
        }
    }

    # --- 5. Installed programs ----------------------------------------------
    $uninstallKeys = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    Get-ItemProperty -Path $uninstallKeys -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -match $pattern } |
        ForEach-Object {
            Add-Finding -Category 'InstalledProgram' -Location $_.PSPath -Detail "$($_.DisplayName) $($_.DisplayVersion)"
        }

    return $findings
}

# ============================================================================
# Section: Resolve target list
# ============================================================================
Write-Verbose '--- Resolving target list ---'
$targets = @()
if ($ListPath) {
    if (-not (Test-Path -LiteralPath $ListPath)) { throw "ListPath not found: $ListPath" }
    $targets += Get-Content -LiteralPath $ListPath |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ -and -not $_.StartsWith('#') }
}
if ($ComputerName) { $targets += $ComputerName }
$targets = $targets | Select-Object -Unique
$runLocal = -not $targets
if ($runLocal) { $targets = @($env:COMPUTERNAME) }
Write-Verbose ("Targets: {0}" -f ($targets -join ', '))

# ============================================================================
# Section: Logging setup
# ============================================================================
if (-not (Test-Path -LiteralPath $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$stamp   = Get-Date -Format 'yyyyMMdd-HHmmss'
$csvPath = Join-Path $OutputPath "GoogleBrotli-$stamp.csv"
$logPath = Join-Path $OutputPath "GoogleBrotli-$stamp.log"
Start-Transcript -Path $logPath -Force | Out-Null

# ============================================================================
# Section: Scan
# ============================================================================
$all = New-Object System.Collections.Generic.List[object]
$failed = New-Object System.Collections.Generic.List[string]

try {
    if ($runLocal) {
        Write-Verbose '--- Scanning local computer ---'
        try {
            $r = & $ScanBlock $Drives $ExcludePath
            foreach ($f in $r) { $all.Add($f) }
        } catch {
            Write-Warning "Local scan failed: $($_.Exception.Message)"
            $failed.Add($env:COMPUTERNAME)
        }
    }
    else {
        Write-Verbose '--- Scanning remote targets ---'
        $sessionResults = Invoke-Command -ComputerName $targets -ScriptBlock $ScanBlock `
            -ArgumentList (, $Drives), (, $ExcludePath) -ThrottleLimit $ThrottleLimit `
            -ErrorVariable connErrors -ErrorAction SilentlyContinue
        foreach ($f in $sessionResults) { $all.Add($f) }
        foreach ($e in $connErrors) {
            Write-Warning "Remote error: $($e.Exception.Message)"
            $failed.Add([string]$e.TargetObject)
        }
    }
}
catch {
    Write-Error "Scan aborted: $($_.Exception.Message)"
}
finally {
    # ========================================================================
    # Section: Report
    # ========================================================================
    Write-Verbose '--- Writing report ---'
    if ($all.Count -gt 0) {
        $all | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding ASCII
        Write-Host ("Found {0} item(s). Report: {1}" -f $all.Count, $csvPath)
    }
    else {
        Write-Host 'No Google Brotli traces found on the scanned targets.'
    }
    $uniqueFailed = $failed | Select-Object -Unique
    if ($uniqueFailed) {
        Write-Warning ("Could not scan: {0}" -f ($uniqueFailed -join ', '))
    }
    Write-Host ("Log: {0}" -f $logPath)
    Stop-Transcript | Out-Null
}
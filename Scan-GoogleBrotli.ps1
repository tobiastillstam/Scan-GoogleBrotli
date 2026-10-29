#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Read-only audit that searches servers for the Google Brotli library in all common locations.

.DESCRIPTION
    Searches each target for signs of Google Brotli (the "brotli" / "google-brotli" packages):
      1. Files and folders named *brotli* on all fixed drives (or -Drives)
      2. Python installs found by the same walk: Brotli-*.dist-info / *.egg-info
         (Name and Version from METADATA / PKG-INFO), site-packages\brotli.py,
         site-packages\_brotli*.pyd, site-packages\brotli and site-packages\brotlicffi
      3. Node.js installs found by the same walk: node_modules\brotli,
         node_modules\google-brotli and scoped node_modules\@scope\brotli
         (Name and Version from package.json)
      4. Environment variables (machine, user and process scope) whose name or value contains brotli
      5. Installed programs (uninstall registry: HKLM, WOW6432Node and every loaded
         user hive under HKEY_USERS) whose name contains brotli

    Each drive is walked once; every path is reported once, under its most specific category.
    Runs locally by default. With -ComputerName or -ListPath it runs remotely over WinRM.
    Names that refer to this computer (localhost, ., 127.0.0.1, ::1, its own short or
    DNS name) are scanned locally instead of over WinRM.

    Read-only: nothing is installed, removed or changed on any target. The only files
    written are the CSV report and the transcript log in -OutputPath. A CSV is written
    on every run; it has only a header row when nothing was found.

    Exit codes (highest applicable wins: 3 > 2 > 1 > 0):
      0 = Scan complete, no Google Brotli traces found
      1 = Scan complete, Google Brotli traces found (see CSV)
      2 = One or more targets could not be scanned (CSV still holds any findings)
      3 = Script error (invalid input, unexpected failure)

    Supports -WhatIf and -Confirm. The script makes no state changes, so neither has an
    effect on the scan; the report and log are always written as audit evidence.

.PARAMETER ComputerName
    One or more server names. Default: the local computer.

.PARAMETER ListPath
    Path to a text file with one server name per line. Blank lines and text after # are ignored.
    The file must contain at least one name.

.PARAMETER Drives
    Drive letters to scan for files and folders, as C, C: or C:\. Default: all fixed drives.
    Python and Node classification follows the same scope.

.PARAMETER ExcludePath
    Paths to skip during the file scan, for example D:\Backup. A path excludes itself and
    everything below it (D:\Backup does not exclude D:\Backup2).

.PARAMETER ThrottleLimit
    Maximum number of parallel remote sessions, 1-64. Default: 16.

.PARAMETER Credential
    Credential for the remote WinRM sessions. Default: the current user. Not used for a local scan.

.PARAMETER OutputPath
    Folder for the CSV report and transcript log. Default: a 'Reports' folder next to the
    script, or under the current directory when the script path is unavailable.

.EXAMPLE
    .\Scan-GoogleBrotli.ps1

    Scans the local computer and writes the report to .\Reports.

.EXAMPLE
    .\Scan-GoogleBrotli.ps1 -ListPath .\servers.txt -Verbose

    Scans every server in servers.txt and shows progress.

.EXAMPLE
    .\Scan-GoogleBrotli.ps1 -ComputerName SRV01,SRV02 -Drives C,D -ExcludePath 'D:\Backup'

    Scans two servers, only C: and D:, and skips D:\Backup.

.EXAMPLE
    .\Scan-GoogleBrotli.ps1 -ListPath .\servers.txt; "Exit code: $LASTEXITCODE"

    Scans a list and shows the exit code for use in a scheduler or pipeline.

.NOTES
    Author        : Tobias Tillstam, Tillnet
    Webpage       : https://tillnet.se
    GitHub        : https://github.com/tobiastillstam
    Version       : 1.1.0
    Date Created  : 2026-10-29
    Last Modified : 2026-10-29

    Change Log
    ----------
    1.1.0 (2026-10-29) - Aligned to the Tillnet template. Single walk per drive with
                         Python/Node classified from it. Exit codes 0/1/2/3. CSV always
                         written (header-only when clean), explicit columns, UTF-8.
                         Local names scanned locally. Python module files, egg-info files,
                         package.json names and scoped Node packages detected. ExcludePath
                         prunes on path boundaries. Junctions and symlinks are not followed.
                         HKEY_USERS uninstall keys. -Credential. Input validated in the body.
                         Duplicate drive letters walked once. Report names include the
                         scanning host and milliseconds and never overwrite earlier runs.
    1.0.0 (2026-10-29) - Initial import.

    Operational notes:
    - Output: <OutputPath>\GoogleBrotli-<COMPUTER>-<yyyyMMdd-HHmmss-fff>.csv and .log,
      where COMPUTER is the host running the scan. The CSV name is reserved atomically;
      if it is taken, -1, -2 ... is appended, so a run never overwrites earlier evidence.
    - CSV columns: Computer, Category, Location, Detail. UTF-8 with BOM so non-ASCII
      paths survive and Excel opens it correctly.
    - A full walk of every fixed drive can take a long time on large file servers;
      narrow it with -Drives and -ExcludePath.
    - Junctions, symlinks and volume mount points are reported if their name matches but
      are not followed. Volumes mounted only into a folder (no drive letter) are not walked.
    - Folders that cannot be read are skipped and counted per target (see the log, and
      -Verbose for the paths). They do not change the exit code.
    - "User" environment variables and HKCU are those of the account running the scan.
    - Process scope is the scanner's own process. A Process variable is only reported when
      no Machine/User variable of the same name was (PATH is a merge of both), so extra
      entries the launching session added to an already reported PATH are not listed.
    - Brotli is bundled inside many products (browsers, web servers, runtimes). A
      FileSystem hit is a lead to review, not proof of a vulnerable install.
    - Parameter binding errors (unknown parameter name, value of the wrong type) are raised
      by PowerShell before the script runs and exit with code 1, not 3.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    # One or more server names to scan. Default: the local computer.
    [Parameter(Mandatory = $false)]
    [string[]]$ComputerName,

    # Text file with one server name per line; blank lines and text after # are ignored.
    [Parameter(Mandatory = $false)]
    [string]$ListPath,

    # Drive letters to walk (C, C: or C:\). Default: all fixed drives on each target.
    [Parameter(Mandatory = $false)]
    [string[]]$Drives,

    # Paths to skip during the file walk; each excludes itself and everything below it.
    [Parameter(Mandatory = $false)]
    [string[]]$ExcludePath = @(),

    # Maximum number of parallel remote sessions (1-64).
    [Parameter(Mandatory = $false)]
    [int]$ThrottleLimit = 16,

    # Credential for remote WinRM sessions. Default: the current user.
    [Parameter(Mandatory = $false)]
    [System.Management.Automation.PSCredential]$Credential,

    # Folder for the CSV report and transcript log. Default: <script folder>\Reports.
    [Parameter(Mandatory = $false)]
    [string]$OutputPath
)

# -------------------------------------------------------------------------
# Scan block (runs on each target, locally or via Invoke-Command)
# -------------------------------------------------------------------------
# Emits one 'Finding' record per hit, then exactly one 'Status' record. A target
# without a Status record was not scanned.
$ScanBlock = {
    param(
        [string[]]$Drives,
        [string[]]$ExcludePath,
        [string]$VerbosePref = 'SilentlyContinue'
    )

    $VerbosePreference = $VerbosePref
    $pattern      = 'brotli'
    $ignoreCase   = [System.StringComparison]::OrdinalIgnoreCase
    $findings     = New-Object System.Collections.Generic.List[object]
    $warnings     = New-Object System.Collections.Generic.List[string]
    $accessErrors = 0
    $drivesDone   = 0
    $excludes     = @($ExcludePath | Where-Object { $_ } | ForEach-Object { $_.Trim().TrimEnd('\') })

    function Add-Finding {
        param($Category, $Location, $Detail)
        $findings.Add([pscustomobject]@{
            RecordType = 'Finding'
            Computer   = $env:COMPUTERNAME
            Category   = $Category
            Location   = $Location
            Detail     = [string]$Detail
        })
    }

    function Test-Excluded {
        param([string]$FullName)
        foreach ($ex in $excludes) {
            if ($FullName.Equals($ex, $ignoreCase) -or $FullName.StartsWith($ex + '\', $ignoreCase)) { return $true }
        }
        return $false
    }

    function Read-PackageInfo {
        # Returns "Name=<n> Version=<v>" from the first lines of a METADATA / PKG-INFO file
        param([string]$Path)
        $name = ''; $version = ''
        if ([System.IO.File]::Exists($Path)) {
            $head    = Get-Content -LiteralPath $Path -TotalCount 20 -ErrorAction SilentlyContinue
            $name    = ($head | Where-Object { $_ -like 'Name:*' }    | Select-Object -First 1) -replace '^Name:\s*', ''
            $version = ($head | Where-Object { $_ -like 'Version:*' } | Select-Object -First 1) -replace '^Version:\s*', ''
        }
        return "Name=$name Version=$version"
    }

    function Add-Classified {
        # Records a *brotli* path under its most specific category
        param([System.IO.FileSystemInfo]$Item, [bool]$IsDir)
        $name       = $Item.Name
        $parent     = if ($IsDir) { $Item.Parent } else { $Item.Directory }
        $parentName = if ($parent) { $parent.Name } else { '' }

        if ($name -match '^(google[_-])?brotli.*\.(dist-info|egg-info)$') {
            # dist-info / egg-info folder, or an old-style egg-info file holding PKG-INFO itself
            $meta = $Item.FullName
            if ($IsDir) {
                $meta = Join-Path $Item.FullName 'METADATA'
                if (-not [System.IO.File]::Exists($meta)) { $meta = Join-Path $Item.FullName 'PKG-INFO' }
            }
            Add-Finding -Category 'Python' -Location $Item.FullName -Detail (Read-PackageInfo -Path $meta)
        }
        elseif ($parentName -eq 'site-packages' -and $IsDir -and $name -in @('brotli', 'brotlicffi')) {
            Add-Finding -Category 'Python' -Location $Item.FullName -Detail 'site-packages module folder'
        }
        elseif ($parentName -eq 'site-packages' -and -not $IsDir -and $name -match '^_?brotli(\.[^.]+)*\.(py|pyd)$') {
            Add-Finding -Category 'Python' -Location $Item.FullName -Detail 'site-packages module file'
        }
        elseif ($IsDir -and $name -in @('brotli', 'google-brotli') -and
                ($parentName -eq 'node_modules' -or
                 ($parentName.StartsWith('@') -and $parent.Parent -and $parent.Parent.Name -eq 'node_modules'))) {
            $pkg = Join-Path $Item.FullName 'package.json'
            $pkgName = ''; $pkgVersion = ''
            if ([System.IO.File]::Exists($pkg)) {
                $json = $null
                try { $json = Get-Content -LiteralPath $pkg -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop } catch { $pkgVersion = 'unreadable' }
                if ($json) { $pkgName = $json.name; $pkgVersion = $json.version }
            }
            Add-Finding -Category 'Node' -Location $Item.FullName -Detail "Name=$pkgName Version=$pkgVersion"
        }
        else {
            $kind = if ($IsDir) { 'Folder' } else { 'File' }
            Add-Finding -Category 'FileSystem' -Location $Item.FullName -Detail $kind
        }
    }

    # --- 1-3. Single walk per drive: file system, Python, Node ---------------
    if (-not ($Drives | Where-Object { $_ })) {
        $Drives = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue |
            ForEach-Object { $_.DeviceID.Substring(0, 1) })
        if (-not $Drives) { $warnings.Add('No fixed drives could be enumerated (Win32_LogicalDisk)') }
    }
    $dirFlag     = [System.IO.FileAttributes]::Directory
    $reparseFlag = [System.IO.FileAttributes]::ReparsePoint
    foreach ($d in $Drives) {
        $root = "$($d.Trim().Substring(0, 1).ToUpper()):\"
        if (-not [System.IO.Directory]::Exists($root)) { $warnings.Add("Drive not found: $root"); continue }
        $drivesDone++
        if (Test-Excluded -FullName $root) { Write-Verbose "Excluded drive: $root"; continue }
        Write-Verbose "Walking $root on $env:COMPUTERNAME"
        $stack = New-Object System.Collections.Generic.Stack[System.IO.DirectoryInfo]
        $stack.Push((New-Object System.IO.DirectoryInfo -ArgumentList $root))
        while ($stack.Count -gt 0) {
            $dir = $stack.Pop()
            try { $entries = $dir.GetFileSystemInfos() }
            catch {
                $accessErrors++
                Write-Verbose "Cannot read: $($dir.FullName) - $($_.Exception.Message)"
                continue
            }
            foreach ($e in $entries) {
                $isDir = ($e.Attributes -band $dirFlag) -ne 0
                if ($e.Name.IndexOf($pattern, $ignoreCase) -ge 0 -and -not (Test-Excluded -FullName $e.FullName)) {
                    Add-Classified -Item $e -IsDir $isDir
                }
                # Junctions, symlinks and mount points are not followed (loops, double counting)
                if ($isDir -and ($e.Attributes -band $reparseFlag) -eq 0) {
                    if ($excludes.Count -eq 0 -or -not (Test-Excluded -FullName $e.FullName)) { $stack.Push($e) }
                }
            }
        }
    }

    # --- 4. Environment variables -------------------------------------------
    $reportedNames = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($scope in 'Machine', 'User') {
        $vars = [System.Environment]::GetEnvironmentVariables([System.EnvironmentVariableTarget]::$scope)
        foreach ($key in $vars.Keys) {
            $val = [string]$vars[$key]
            if ($key -match $pattern -or $val -match $pattern) {
                Add-Finding -Category 'EnvVar' -Location "$scope\$key" -Detail $val
                [void]$reportedNames.Add($key)
            }
        }
    }
    # Process scope only adds variables not already reported from Machine / User (PATH is merged)
    foreach ($var in (Get-ChildItem Env: -ErrorAction SilentlyContinue)) {
        if ($reportedNames.Contains($var.Name)) { continue }
        if ($var.Name -match $pattern -or [string]$var.Value -match $pattern) {
            Add-Finding -Category 'EnvVar' -Location "Process\$($var.Name)" -Detail ([string]$var.Value)
        }
    }

    # --- 5. Installed programs ----------------------------------------------
    $uninstallKeys = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'Registry::HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    Get-ItemProperty -Path $uninstallKeys -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -match $pattern } |
        ForEach-Object {
            $location = $_.PSPath -replace '^Microsoft\.PowerShell\.Core\\Registry::', ''
            Add-Finding -Category 'InstalledProgram' -Location $location -Detail ("$($_.DisplayName) $($_.DisplayVersion)".Trim())
        }

    # --- Emit ---------------------------------------------------------------
    foreach ($f in $findings) { $f }
    [pscustomobject]@{
        RecordType   = 'Status'
        Computer     = $env:COMPUTERNAME
        Complete     = ($drivesDone -gt 0)
        Findings     = $findings.Count
        AccessErrors = $accessErrors
        Warnings     = ($warnings -join '; ')
    }
}

# -------------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------------
function New-ReportBaseName {
    # Reserves <Prefix>.csv (or <Prefix>-1.csv, -2 ...) by creating it with CreateNew, which
    # fails if the file exists - so concurrent runs into one folder never share a name.
    param([string]$Folder, [string]$Prefix)
    for ($n = 0; $n -lt 1000; $n++) {
        $name = if ($n -eq 0) { $Prefix } else { "$Prefix-$n" }
        $csv  = Join-Path $Folder "$name.csv"
        if ([System.IO.File]::Exists($csv) -or [System.IO.File]::Exists((Join-Path $Folder "$name.log"))) { continue }
        try {
            [System.IO.File]::Open($csv, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write).Dispose()
            return $name
        }
        catch [System.IO.IOException] {
            # Taken by a concurrent run between the check and the create; try the next suffix
        }
    }
    throw "No free report name for '$Prefix' in $Folder"
}

# -------------------------------------------------------------------------
# Begin script body
# -------------------------------------------------------------------------

Write-Verbose "Starting $($MyInvocation.MyCommand.Name)"

$exitCode          = 3
$transcriptStarted = $false
$csvPath           = $null
$logPath           = $null
$csvHeader         = '"Computer","Category","Location","Detail"'
$csvEncoding       = if ($PSVersionTable.PSVersion.Major -ge 6) { 'utf8BOM' } else { 'UTF8' }
$allFindings       = New-Object System.Collections.Generic.List[object]
$failed            = New-Object System.Collections.Generic.List[string]
$scannedCount      = 0

try {
    # --- Output paths and transcript -------------------------------------
    # Report files are audit evidence, not state changes: written even under -WhatIf / -Confirm.
    if (-not $OutputPath) {
        $baseDir    = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
        $OutputPath = Join-Path $baseDir 'Reports'
    }
    if (-not (Test-Path -LiteralPath $OutputPath -PathType Container)) {
        New-Item -ItemType Directory -Path $OutputPath -Force -WhatIf:$false -Confirm:$false -ErrorAction Stop | Out-Null
    }
    $baseName = New-ReportBaseName -Folder $OutputPath -Prefix "GoogleBrotli-$env:COMPUTERNAME-$(Get-Date -Format 'yyyyMMdd-HHmmss-fff')"
    $csvPath  = Join-Path $OutputPath "$baseName.csv"
    $logPath  = Join-Path $OutputPath "$baseName.log"
    Start-Transcript -LiteralPath $logPath -Force -WhatIf:$false -Confirm:$false -ErrorAction Stop | Out-Null
    $transcriptStarted = $true
    Write-Verbose "Scan-GoogleBrotli 1.1.0 on $env:COMPUTERNAME as $([Environment]::UserDomainName)\$([Environment]::UserName)"
    if ($WhatIfPreference) { Write-Host 'Read-only scan: -WhatIf has no effect; the report and log are still written.' }

    # --- Input validation ------------------------------------------------
    # powershell.exe -File passes "A,B" as one string; names and drive letters never hold commas
    $ComputerName = @($ComputerName | ForEach-Object { ([string]$_) -split ',' } | Where-Object { $_.Trim() })
    $Drives       = @($Drives | ForEach-Object { ([string]$_) -split ',' } | Where-Object { $_.Trim() })
    if ($ThrottleLimit -lt 1 -or $ThrottleLimit -gt 64) { throw "ThrottleLimit must be 1-64, got $ThrottleLimit" }
    foreach ($d in $Drives) {
        if ([string]$d -notmatch '^\s*[A-Za-z](:\\?)?\s*$') { throw "Invalid drive '$d'. Use a letter such as C, C: or C:\" }
    }
    # C, C: and c are the same drive: walk it once
    $Drives = @($Drives | ForEach-Object { $_.Trim().Substring(0, 1).ToUpper() } | Select-Object -Unique)

    # --- Resolve target list ---------------------------------------------
    Write-Verbose '--- Resolving target list ---'
    $targets = New-Object System.Collections.Generic.List[string]
    $seen    = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $names   = @()
    if ($PSBoundParameters.ContainsKey('ListPath')) {
        if (-not $ListPath -or -not (Test-Path -LiteralPath $ListPath -PathType Leaf)) { throw "ListPath not found: $ListPath" }
        $fromList = @(Get-Content -LiteralPath $ListPath -ErrorAction Stop |
            ForEach-Object { ($_ -replace '#.*$', '').Trim() } |
            Where-Object { $_ })
        if ($fromList.Count -eq 0) { throw "ListPath contains no target names: $ListPath" }
        $names += $fromList
    }
    if ($ComputerName) { $names += @($ComputerName | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ }) }
    foreach ($n in $names) { if ($seen.Add($n)) { $targets.Add($n) } }
    if ($targets.Count -eq 0) { $targets.Add($env:COMPUTERNAME) }

    # Names that mean "this computer" are scanned in-process, never over WinRM
    $localNames = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($n in @('localhost', '.', '127.0.0.1', '::1', $env:COMPUTERNAME)) { [void]$localNames.Add($n) }
    $dnsDomain = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName
    if ($dnsDomain) { [void]$localNames.Add("$env:COMPUTERNAME.$dnsDomain") }
    $localTargets  = @($targets | Where-Object { $localNames.Contains($_) })
    $remoteTargets = @($targets | Where-Object { -not $localNames.Contains($_) })
    Write-Verbose ("Targets: {0}" -f ($targets -join ', '))

    # --- Scan ------------------------------------------------------------
    $statusRecords = New-Object System.Collections.Generic.List[object]
    if ($localTargets.Count -gt 0) {
        Write-Verbose "--- Scanning local computer ($($localTargets -join ', ')) ---"
        foreach ($rec in (& $ScanBlock $Drives $ExcludePath ([string]$VerbosePreference))) {
            if ($rec.RecordType -eq 'Status') {
                $rec | Add-Member -NotePropertyName Target -NotePropertyValue $localTargets[0]
                $statusRecords.Add($rec)
            }
            else { $allFindings.Add($rec) }
        }
    }
    if ($remoteTargets.Count -gt 0) {
        Write-Verbose "--- Scanning remote targets ($($remoteTargets -join ', ')) ---"
        $icmParams = @{
            ComputerName  = $remoteTargets
            ScriptBlock   = $ScanBlock
            ArgumentList  = $Drives, $ExcludePath, ([string]$VerbosePreference)
            ThrottleLimit = $ThrottleLimit
            ErrorAction   = 'SilentlyContinue'
            ErrorVariable = 'remoteErrors'
        }
        if ($Credential) { $icmParams.Credential = $Credential }
        $remoteResults = Invoke-Command @icmParams
        foreach ($rec in $remoteResults) {
            if ($rec.RecordType -eq 'Status') {
                $rec | Add-Member -NotePropertyName Target -NotePropertyValue $rec.PSComputerName -Force
                $statusRecords.Add($rec)
            }
            elseif ($rec.RecordType -eq 'Finding') { $allFindings.Add($rec) }
        }
        foreach ($err in $remoteErrors) { Write-Warning "Remote error: $($err.Exception.Message)" }
        $answered = @($statusRecords | ForEach-Object { [string]$_.Target })
        foreach ($t in $remoteTargets) {
            if ($answered -notcontains $t) { $failed.Add($t) }
        }
    }

    # --- Per-target summary ----------------------------------------------
    foreach ($s in $statusRecords) {
        $line = "{0}: {1} finding(s), {2} unreadable folder(s)" -f $s.Target, $s.Findings, $s.AccessErrors
        if ($s.Warnings) { $line += "; $($s.Warnings)" }
        Write-Host $line
        if (-not $s.Complete) { $failed.Add([string]$s.Target) }
        else { $scannedCount++ }
    }

    if ($failed.Count -gt 0)          { $exitCode = 2 }
    elseif ($allFindings.Count -gt 0) { $exitCode = 1 }
    else                              { $exitCode = 0 }
}
catch {
    $exitCode = 3
    Write-Error $_
    throw
}
finally {
    # --- Report ----------------------------------------------------------
    if ($csvPath) {
        $rows = @($allFindings |
            Sort-Object -Property Computer, Category, Location |
            Select-Object -Property Computer, Category, Location, Detail)
        if ($rows.Count -gt 0) {
            $rows | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding $csvEncoding -WhatIf:$false -Confirm:$false
        }
        else {
            Set-Content -LiteralPath $csvPath -Value $csvHeader -Encoding $csvEncoding -WhatIf:$false -Confirm:$false
        }
        if ($failed.Count -gt 0) { Write-Warning ("Could not scan: {0}" -f (($failed | Sort-Object -Unique) -join ', ')) }
        if ($allFindings.Count -gt 0) { Write-Host ("Found {0} item(s) on {1} scanned target(s)." -f $allFindings.Count, $scannedCount) }
        elseif ($exitCode -ne 3)      { Write-Host ("No Google Brotli traces found on {0} scanned target(s)." -f $scannedCount) }
        Write-Host ("Report: {0}" -f $csvPath)
        Write-Host ("Log: {0}" -f $logPath)
    }
    Write-Host ("Exit code: {0}" -f $exitCode)
    if ($transcriptStarted) { Stop-Transcript | Out-Null }
    Write-Verbose "Finished $($MyInvocation.MyCommand.Name)"
    exit $exitCode
}

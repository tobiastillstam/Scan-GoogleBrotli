# Scan-GoogleBrotli

Read-only PowerShell audit that searches Windows servers for traces of the
Google Brotli compression library. Part of the Tillnet toolset.

## What it checks

| # | Category           | What is searched                                                         |
|---|--------------------|--------------------------------------------------------------------------|
| 1 | `FileSystem`       | Files and folders named `*brotli*` on all fixed drives (or `-Drives`)     |
| 2 | `Python`           | `Brotli-*.dist-info` / `*.egg-info` folders or files (Name + Version from METADATA / PKG-INFO), `site-packages\brotli.py`, `site-packages\_brotli*.pyd`, `site-packages\brotli\`, `site-packages\brotlicffi\` |
| 3 | `Node`             | `node_modules\brotli`, `node_modules\google-brotli`, scoped `node_modules\@scope\brotli` (Name + Version from `package.json`) |
| 4 | `EnvVar`           | Machine, User and Process environment variables whose name or value contains `brotli` |
| 5 | `InstalledProgram` | Uninstall registry entries (HKLM, WOW6432Node, every loaded hive under HKEY_USERS) whose name contains `brotli` |

Each drive is walked once and every path is reported once, under its most
specific category. Python and Node detection follows the `-Drives` /
`-ExcludePath` scope. Nothing is installed, removed or changed.

## Requirements

- Windows PowerShell 5.1 or PowerShell 7
- Elevated session (`#Requires -RunAsAdministrator`)
- For remote scans: WinRM / PowerShell Remoting enabled on the targets

## Usage

```powershell
# Local computer
.\Scan-GoogleBrotli.ps1

# Every server in a list file (one name per line, blank lines and text after '#' ignored)
.\Scan-GoogleBrotli.ps1 -ListPath .\servers.txt -Verbose

# Two servers, only C: and D:, skipping a backup folder
.\Scan-GoogleBrotli.ps1 -ComputerName SRV01,SRV02 -Drives C,D -ExcludePath 'D:\Backup'

# From a scheduled task (comma lists work with -File too)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Scan-GoogleBrotli.ps1 -ComputerName SRV01,SRV02
```

Names that mean this computer (`localhost`, `.`, `127.0.0.1`, `::1`, its own
short or DNS name) are scanned locally, not over WinRM.

## Parameters

| Parameter       | Description                                                   | Default               |
|-----------------|---------------------------------------------------------------|-----------------------|
| `-ComputerName` | One or more server names                                      | Local computer        |
| `-ListPath`     | Text file with one server name per line (must not be empty)   | -                     |
| `-Drives`       | Drive letters to walk: `C`, `C:` or `C:\`                     | All fixed drives      |
| `-ExcludePath`  | Paths to skip; each excludes itself and everything below it   | none                  |
| `-ThrottleLimit`| Maximum parallel remote sessions (1-64)                       | 16                    |
| `-Credential`   | Credential for the remote WinRM sessions                      | Current user          |
| `-OutputPath`   | Folder for the CSV report and transcript log                  | `Reports\` next to the script |

## Output

- `Reports\GoogleBrotli-<timestamp>.csv` - one row per finding
  (`Computer`, `Category`, `Location`, `Detail`), UTF-8 with BOM.
  **Written on every run**; header row only when nothing is found.
- `Reports\GoogleBrotli-<timestamp>.log` - transcript of the run, with a
  per-target line (findings, unreadable folders, warnings).
- Targets that could not be scanned are listed as a warning at the end.

## Exit codes

| Code | Meaning                                                                 |
|------|-------------------------------------------------------------------------|
| 0    | Scan complete, no Google Brotli traces found                            |
| 1    | Scan complete, Google Brotli traces found (see CSV)                     |
| 2    | One or more targets could not be scanned (CSV still holds any findings) |
| 3    | Script error (invalid input, unexpected failure)                        |

When several apply, the highest wins (3 > 2 > 1 > 0). A target counts as
"not scanned" when it is unreachable over WinRM or none of its requested
drives exist. Unreadable folders on a scanned target are counted in the log
but do not change the exit code. PowerShell's own parameter binding errors
(unknown parameter, wrong value type) happen before the script runs and exit 1.

## Notes

- A full walk of every fixed drive can take a long time on large file servers;
  use `-Drives` and `-ExcludePath` to narrow it.
- Junctions, symlinks and mount points are reported when their name matches
  but are not followed. Volumes mounted only into a folder are not walked.
- "User" environment variables and HKCU belong to the account running the scan.
- Brotli is bundled inside many products (browsers, web servers, runtimes).
  A `FileSystem` hit is a lead to review, not proof of a vulnerable install.
- `-WhatIf` is accepted but has no effect: the scan is read-only and the
  report and log are always written as audit evidence.

## License

MIT - see [LICENSE](LICENSE).

Tobias Tillstam, [Tillnet](https://tillnet.se) - [github.com/tobiastillstam](https://github.com/tobiastillstam)

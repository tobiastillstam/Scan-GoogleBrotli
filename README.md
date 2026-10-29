# Scan-GoogleBrotli

Read-only PowerShell audit that searches Windows servers for traces of the
Google Brotli compression library. Part of the Tillnet toolset.

## What it checks

| # | Category           | What is searched                                                         |
|---|--------------------|--------------------------------------------------------------------------|
| 1 | `FileSystem`       | Files and folders named `*brotli*` on all fixed drives (or `-Drives`)     |
| 2 | `Python`           | `Brotli-*.dist-info` / `*.egg-info` (Name + Version from METADATA), `site-packages\brotli`, `site-packages\brotlicffi` |
| 3 | `Node`             | `node_modules\brotli`, `node_modules\google-brotli` (version from `package.json`) |
| 4 | `EnvVar`           | Machine, User and Process environment variables whose name or value contains `brotli` |
| 5 | `InstalledProgram` | Uninstall registry entries (HKLM, WOW6432Node, HKCU) whose name contains `brotli` |

Nothing is installed, removed or changed.

## Requirements

- Windows PowerShell 5.1 or later
- Elevated session (`#Requires -RunAsAdministrator`)
- For remote scans: WinRM / PowerShell Remoting enabled on the targets

## Usage

```powershell
# Local computer
.\Scan-GoogleBrotli.ps1

# Every server in a list file (one name per line, '#' lines ignored)
.\Scan-GoogleBrotli.ps1 -ListPath .\servers.txt -Verbose

# Two servers, only C: and D:, skipping a backup folder
.\Scan-GoogleBrotli.ps1 -ComputerName SRV01,SRV02 -Drives C,D -ExcludePath 'D:\Backup'
```

## Parameters

| Parameter       | Description                                                   | Default               |
|-----------------|---------------------------------------------------------------|-----------------------|
| `-ComputerName` | One or more server names                                      | Local computer        |
| `-ListPath`     | Text file with one server name per line                       | -                     |
| `-Drives`       | Drive letters to scan for files and folders                   | All fixed drives      |
| `-ExcludePath`  | Path prefixes to skip during the file scan                    | none                  |
| `-ThrottleLimit`| Maximum parallel remote sessions (1-64)                       | 16                    |
| `-OutputPath`   | Folder for the CSV report and transcript log                  | `Reports\` next to the script |

## Output

- `Reports\GoogleBrotli-<timestamp>.csv` - one row per finding
  (`Computer`, `Category`, `Location`, `Detail`); only written when something is found
- `Reports\GoogleBrotli-<timestamp>.log` - transcript of the run
- Targets that could not be scanned are listed as a warning at the end

## Notes

- A full recursive scan of every fixed drive can take a long time on large
  file servers; use `-Drives` and `-ExcludePath` to narrow it.
- Brotli is bundled inside many products (browsers, web servers, runtimes).
  A `FileSystem` hit is a lead to review, not proof of a vulnerable install.

## License

MIT - see [LICENSE](LICENSE).

Tobias Tillstam, [Tillnet](https://tillnet.se) - [github.com/tobiastillstam](https://github.com/tobiastillstam)

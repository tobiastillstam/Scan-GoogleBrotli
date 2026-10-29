# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-10-29

### Added
- Exit codes: 0 clean, 1 Brotli found, 2 target(s) not scanned, 3 error.
- CSV written on every run (header-only when clean) as audit evidence.
- `-Credential` for remote sessions.
- Detection of Python module files (`brotli.py`, `_brotli*.pyd`), old-style
  `*.egg-info` files, `package.json` names and scoped Node packages.
- Uninstall keys of every loaded user hive (HKEY_USERS) instead of HKCU only.
- Per-target summary line (findings, unreadable folders, warnings).

### Changed
- Aligned to the Tillnet script template (CmdletBinding/ShouldProcess,
  parameter attributes and comments, full .NOTES, Verbose bookends, single
  flat try/catch/finally).
- One walk per drive; Python and Node are classified from it (was up to three
  walks of USERPROFILE / ProgramData / Program Files). Python/Node detection
  now follows `-Drives` / `-ExcludePath`.
- Each path is reported once under its most specific category.
- CSV has explicit columns only (no PSComputerName / RunspaceId) and is UTF-8
  with BOM, so non-ASCII paths are preserved (was ASCII, which turned them into `?`).
- Local names (`localhost`, `.`, own name/FQDN) are scanned locally, not over WinRM.
- `-ExcludePath` prunes whole subtrees and matches on path boundaries
  (`D:\Backup` no longer excludes `D:\Backup2`).
- Junctions, symlinks and mount points are not followed.
- Input is validated inside the script so bad input exits 3, not 1.

### Fixed
- `-Drives 'C:\'` silently scanned nothing.
- Duplicate target names differing only in case were scanned twice.
- An empty `-ListPath` file silently fell back to a local scan (now exit 3).
- `-ComputerName A,B` / `-Drives C,D` via `powershell.exe -File` were taken as one value.
- Process environment variables duplicated Machine/User findings.
- Errors in target resolution and output setup happened outside the try block
  and were not logged.
- Removed dead `GetEnvironmentVariables($scope.ToLower())` line.

## [1.0.0] - 2026-10-29

### Added
- Initial import of `Scan-GoogleBrotli.ps1`: read-only audit for Google Brotli
  traces (file system names, Python dist-info/egg-info and site-packages,
  Node.js `node_modules`, environment variables, installed programs).
- Local scan by default; remote scan over WinRM via `-ComputerName` or
  `-ListPath`, with `-ThrottleLimit`.
- CSV report and transcript log under `Reports\`.

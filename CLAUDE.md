# Scan-GoogleBrotli - project notes

Read-only audit for Google Brotli traces on Windows servers (local or WinRM).
Single script: `Scan-GoogleBrotli.ps1`.

Test suite: `Tests\Invoke-ScanTests.ps1` (local only, `Tests/` is gitignored).
Static template checks + functional runs on subst-mapped fixtures under
powershell.exe and pwsh. Exit 0 = all pass.

## Conventions

- Follows the Tillnet PowerShell script template: `#Requires` lines,
  `CmdletBinding(SupportsShouldProcess)`, commented parameters, full `.NOTES`
  block, `Write-Verbose` bookends, single flat try/catch/finally.
- Script source and console output are pure ASCII.
- The scanner is read-only: it changes nothing on the scanned hosts.

## Design decisions

- Exit codes 0 clean / 1 found / 2 not scanned / 3 error;
  highest wins (3 > 2 > 1 > 0), so "found + some unreachable" = 2.
- "Not scanned" = WinRM unreachable or no requested drive exists.
  Unreadable folders are counted in the log only (every C:\ walk hits some).
- CSV written on every run, including error runs (exit 3);
  the exit code and log distinguish an aborted run from a clean one.
- CSV is UTF-8 with BOM (not ASCII) so non-ASCII paths survive.
  Script source and console output stay pure ASCII.
- No ShouldProcess gates in the scanner - it changes nothing;
  report/log are always written (-WhatIf:$false) as audit evidence.
- No [Validate*] attributes - binding errors exit 1 (collides
  with "found"); validation is done in the body to exit 3.
- One walk per drive; Python/Node locations are classified from it.
  Junctions are not followed.
- Names that mean this computer are scanned locally, never over WinRM.
- CSV columns are selected explicitly so remoting properties never leak in.
- Test harness omits `#Requires -RunAsAdministrator` (deviation
  from template) so it runs in a normal session.

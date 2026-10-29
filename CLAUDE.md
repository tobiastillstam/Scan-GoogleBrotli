# Scan-GoogleBrotli - project notes

Read-only audit for Google Brotli traces on Windows servers (local or WinRM).
Single script: `Scan-GoogleBrotli.ps1`.

## Conventions

- Follows the Tillnet PowerShell script template: `#Requires` lines,
  `CmdletBinding(SupportsShouldProcess)`, commented parameters, full `.NOTES`
  block, `Write-Verbose` bookends, single flat try/catch/finally.
- Script source and console output are pure ASCII.
- The scanner is read-only: it changes nothing on the scanned hosts.

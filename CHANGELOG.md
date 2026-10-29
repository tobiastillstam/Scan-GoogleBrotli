# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-10-29

### Added
- Initial import of `Scan-GoogleBrotli.ps1`: read-only audit for Google Brotli
  traces (file system names, Python dist-info/egg-info and site-packages,
  Node.js `node_modules`, environment variables, installed programs).
- Local scan by default; remote scan over WinRM via `-ComputerName` or
  `-ListPath`, with `-ThrottleLimit`.
- CSV report and transcript log under `Reports\`.

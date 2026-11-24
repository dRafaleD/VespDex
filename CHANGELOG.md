# Changelog

## Unreleased

- Reopen saved v1 behavior reports in the Windows desktop, terminal, and CLI. Rebuild summaries from validated events.

## 0.3.0-rc.1

- Added the Windows desktop workspace for JSON telemetry and exported Sysmon EVTX.
- Added offline EVTX import on Windows without a local Sysmon installation.
- Updated the desktop and terminal with the new VespDex mask.
- Added live Sysmon collection, process attribution, a process tree, event filters, keyboard shortcuts and capture coverage.
- Added the built-in synthetic demo and safe report saving across desktop, terminal and CLI.
- Moved Windows desktop rendering to Direct3D 12 with software-adapter support.
- Added Windows and Linux build checks and a disposable Windows Sysmon acceptance workflow.
- Added the unsigned Windows x64 portable package with archive and file checksums, plus Turkish and English usage guides.

## 0.2.0

- Introduced the VespDex name and process-attributed behavior reports.
- Preserved support for the existing v1 AsphDex and Banshee report format.

## 0.1.0

- Added the initial capture analyzer, sorted timeline and event counts.

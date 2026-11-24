# VespDex Windows x64

Extract the ZIP to a folder you can write to. Open **Start-VespDex.cmd**,
or run `./vespdex.exe --gui` in PowerShell from that folder. Rust is not
required.
The desktop requires a Direct3D 12 hardware or Windows software adapter.

Use **ÖRNEK KAYDI AÇ** (Open example) to open the built-in synthetic capture. The overview
shows four events and two processes. Use the timeline to filter DNS activity,
the process view to isolate a process tree, and **RAPORU KAYDET** (Save report)
to export JSON. Use `./vespdex.exe --demo` for the CLI report. You can also
open `examples/capture.json` directly.

Keyboard shortcuts: **Ctrl+O** opens a capture, **Ctrl+F** focuses timeline
search, **Ctrl+S** saves a report and **Esc** cancels an active import.

Sysmon must be configured in the Windows environment where telemetry is
recorded. The desktop can open exported Sysmon EVTX files on a computer
without Sysmon. VespDex reads records and does not launch the analyzed program.

Use `Get-FileHash -Algorithm SHA256 <zip>` and compare its digest against
`SHA256SUMS.txt`. `PACKAGE-SHA256SUMS.txt` lists the individual packaged
files. This candidate is unsigned.

Close VespDex and remove the extracted directory to uninstall. Save reports
elsewhere first if you want to keep them.

## Troubleshooting

- If the desktop does not open, run `./vespdex.exe --gui` in PowerShell to
  see the startup error. Use `./vespdex.exe --demo` to test the CLI separately.
- If the EVTX has no selectable processes, check that it contains Sysmon
  Event ID 1 for the process you want, with SHA-256 in the `Hashes` field.
  For a size or time limit error, export a shorter time range that still
  includes that process creation.
- If saving fails because a file already exists, choose a new filename.
  The application keeps the existing report file.
- If the ZIP checksum differs, download the ZIP and checksum together
  from the same release and verify them again before opening the program.

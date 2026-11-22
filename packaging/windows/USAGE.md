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
recorded. VespDex reads records and does not launch the analyzed program.

Use `Get-FileHash -Algorithm SHA256 <zip>` and compare its digest against
`SHA256SUMS.txt`. `PACKAGE-SHA256SUMS.txt` lists the individual packaged
files. This candidate is unsigned.

Close VespDex and remove the extracted directory to uninstall. Save reports
elsewhere first if you want to keep them.

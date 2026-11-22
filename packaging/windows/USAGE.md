# VespDex Windows x64

Extract the ZIP to a folder you can write to. Open **Start-VespDex.cmd**,
or run `./vespdex.exe --gui` in PowerShell from that folder. Rust is not
required.

Use **DOSYA SEÇ** (Choose file) to open `examples/capture.json`. The overview
shows four events and two processes. Use the timeline to filter DNS activity,
the process view to isolate a process tree, and **RAPORU KAYDET** (Save report)
to export JSON. The CLI also accepts `./vespdex.exe ./examples/capture.json`.

Sysmon must be configured in the Windows environment where telemetry is
recorded. VespDex reads records and does not launch the analyzed program.

Use `Get-FileHash -Algorithm SHA256 <zip>` and compare its digest against
`SHA256SUMS.txt`. `PACKAGE-SHA256SUMS.txt` lists the individual packaged
files. This candidate is unsigned.

Close VespDex and remove the extracted directory to uninstall. Save reports
elsewhere first if you want to keep them.

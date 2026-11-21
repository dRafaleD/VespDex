# VespDex

VespDex analyzes recorded runtime telemetry in Rust and exchanges reports with AsphDex and Banshee. It builds a timeline, groups events by process and accepts recordings from Windows Sysmon. Use the fictional capture for demonstration.

## Windows desktop workspace

Run `vespdex --gui` and choose **Kayıt aç** to open telemetry JSON. The
timeline can be filtered by event type. In the process view, **Olayları göster**
opens the timeline filtered to that process. **Raporu kaydet** exports the same
JSON report used by the CLI. Open the example directly with:

```powershell
cargo run --locked -- --gui examples/capture.json
```

This desktop view analyzes saved telemetry. Collect Sysmon events separately
using the collector below.

## Terminal workspace

Install from the source checkout with `cargo install --path . --locked`.
Make sure Cargo's bin directory is on `PATH` (`%USERPROFILE%\.cargo\bin` on
Windows by default), then run `vespdex` with no arguments in an interactive
terminal. To open the workspace from the checkout without installing, run
`cargo run --locked`. From the checkout directory, use `open examples/capture.json`
then `analyze` to view the sample. `export behavior.json` saves the report to a
new file. Use `lang tr|en` to switch the interface language, `help` for the
available commands, and `quit` to return to the shell.

The welcome screen uses AsphDex's 3.4-second scan and all seven original
portrait sizes, choosing a size for the available terminal space. Press
Esc to skip it. After analysis, use `timeline` for all events,
`timeline dns-query` for DNS events, or `timeline all <GUID>` for one
process. `processes` lists process GUIDs, recorded images, parents and event
counts. Page Up and Page Down scroll through the results.

Passing a capture path keeps the direct JSON output for scripts.

```powershell
# PowerShell 7+
cargo run --locked -- examples/capture.json | Set-Content -Encoding utf8NoBOM behavior.json
banshee behavior behavior.json
```

In AsphDex, analyze the corresponding file and choose **Import behavior report** on the Report screen. The import matches the currently analyzed file by SHA-256. The demo uses a placeholder hash and does not match an actual file.

## Format v1

Input is UTF-8 JSON without a byte order mark. The capture contains `schemaVersion` (1), `caseId` (1–64 ASCII letters, digits, underscore or hyphen), `sampleSha256` (64 hex digits), `source` (collector or capture label, up to 128 bytes), and `events` (up to 2,000). Each event has a `timestamp` in RFC 3339, a `kind`, and a single-line `detail` of up to 1,024 UTF-8 bytes. Supported kinds are `process-start`, `file-write`, `registry-write`, `network-connection` and `dns-query`. The size limit is 4 MiB.

The output adds `tool: "vespdex"`, `toolVersion` and `counts`. It retains the `asphdex-behavior-report` format identifier for compatibility. It contains recorded event text, so avoid placing secrets in captures you intend to share. The case ID, source label and sample hash are supplied by the capture producer. A matching hash links the report to a file but does not verify who collected the events or prove they came from that file. Counts describe captured coverage only.

## Import an exported Windows Sysmon log

Events can include a `processGuid`. A process creation event can also name a
`parentProcessGuid`. The report groups event counts by process and records the
image and parent when the capture contains the corresponding process creation.
`unattributedEventCount` shows how many events arrived without a process GUID.
These fields are additive. Older captures and existing v1 report readers
remain compatible.

Pass a saved Sysmon Operational EVTX and the `ProcessGuid` from the Event ID 1
record for the process you want to inspect. The adapter uses the SHA-256
recorded in that event, follows child process GUIDs and selects supported events
from that process tree. It never queries the local live log. The input log needs
to include the root process creation with SHA-256 recording enabled.

```powershell
# Run in PowerShell 7+ from the VespDex directory.
# Replace the GUID below with the ProcessGuid from the exported log.
./scripts/convert-sysmon.ps1 -Evtx ./capture.evtx -ProcessGuid '11111111-1111-1111-1111-111111111111' -CaseId case-001 |
    Set-Content -Encoding utf8NoBOM capture.json
cargo run --locked -- capture.json | Set-Content -Encoding utf8NoBOM behavior.json
```

The selected IDs are 1 (process creation), 3 (network connection), 11 (file
creation or overwrite), 13 (registry value set) and 22 (DNS query). Availability
depends on the Sysmon configuration. The adapter rejects oversized exports
instead of reporting a silently truncated process tree. Event descriptions are
in the [Sysmon documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).

## Collect a time window from the local Sysmon log

Run the collector inside the Windows analysis environment where Sysmon is
already enabled. Use the target's process GUID from Event ID 1 and set the
start before that event. Optionally wait up to 300 seconds for more events
before reading the log. The collector does not launch a process or change
Sysmon settings.

```powershell
$start = [DateTimeOffset]::UtcNow.AddMinutes(-2)
$processGuid = '11111111-1111-1111-1111-111111111111' # Replace with the recorded GUID.
./scripts/convert-sysmon.ps1 -Live -StartTime $start -ObserveSeconds 30 -ProcessGuid $processGuid -CaseId case-001 |
    Set-Content -Encoding utf8NoBOM capture.json
cargo run --locked -- capture.json | Set-Content -Encoding utf8NoBOM behavior.json
```

Live captures record the requested start and actual collection cutoff in
`captureWindow`. A completed query covers events still present in the channel
and enabled by the Sysmon configuration. Late, filtered or overwritten events
may be absent. The analyzer keeps the time window in the report and rejects
events whose timestamps fall outside it.

## Read the report in other tools

Banshee's `behavior` command reports candidate DNS domains and destination IPs
found in event detail. Its IOC line numbers are one-based positions in the
sorted report's `events` array. AsphDex displays event counts for the current
sample for the duration of the analysis view. Capture data and artifacts are
not included in AsphDex's static report.

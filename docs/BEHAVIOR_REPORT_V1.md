# Behavior report v1

VespDex emits one UTF-8 JSON object followed by a newline. It is limited to
4 MiB including the newline. Readers must allow additive fields in v1 and
reject unsupported versions. The input capture is a distinct v1 JSON object.

| Report field | Meaning |
| --- | --- |
| `kind` | `asphdex-behavior-report` |
| `schemaVersion` | Integer `1` |
| `caseId` | 1–64 ASCII letters, digits, hyphen or underscore |
| `sampleSha256` | SHA-256 of the subject file, 64 lowercase hexadecimal digits |
| `source` | Capture producer label |
| `tool`, `toolVersion` | Producer identity and version |
| `captureWindow` | Optional inclusive start and end as RFC 3339 instants |
| `events` | At most 2,000 observations in ascending instant order |
| `counts`, `processes`, `unattributedEventCount` | Summaries derived from the observations |

Each event has `timestamp` (RFC 3339), `kind` and nonblank, single-line
`detail` (at most 1,024 UTF-8 bytes). Event types are `process-start`,
`file-write`, `registry-write`, `network-connection` and `dns-query`.
`processGuid` is optional. `parentProcessGuid` is optional on process
creation only. GUIDs are lowercase and have no braces. An unavailable
parent may be outside the capture. The report does not contain sample bytes.

AsphDex matches the report to its current static analysis by SHA-256 and
recounts events from the array. Banshee extracts network indicators from
`network-connection` and `dns-query`. Banshee's one-based positions refer
to the VespDex `events` array.

A hash match establishes a shared file identifier. Sysmon configuration,
retention and the observation window determine which events are visible.
The report provides no malware verdict or proof of full capture.

## Interoperability check

Build VespDex and Banshee and use an AsphDex checkout with the behavior
report importer. Run the command below from the VespDex checkout. It
generates harmless text and synthetic observations in a temporary directory.

```powershell
node scripts/verify-ecosystem.js ./target/release/vespdex.exe ../MalScannerDesktop ../Banshee/target/debug/banshee.exe
```

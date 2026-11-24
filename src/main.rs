use std::{
    collections::{BTreeMap, HashSet},
    fs::File,
    io::{self, IsTerminal, Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use clap::Parser;
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

#[cfg(windows)]
mod gui;
mod terminal;

const MAX_BYTES: u64 = 4 * 1024 * 1024;
const MAX_EVENTS: usize = 2_000;
const MAX_DETAIL: usize = 1_024;
const REPORT_KIND: &str = "asphdex-behavior-report";

#[derive(Parser)]
#[command(version, about = "Analyze recorded runtime telemetry offline")]
struct Args {
    /// Version 1 telemetry capture or behavior report JSON
    #[arg(required_unless_present_any = ["gui", "demo"], conflicts_with = "demo")]
    capture: Option<PathBuf>,
    /// Open or analyze the built-in synthetic example
    #[arg(long)]
    demo: bool,
    /// Save the JSON report to a new file instead of writing to stdout
    #[arg(short, long, conflicts_with = "gui")]
    output: Option<PathBuf>,
    /// Open the Windows desktop workspace
    #[arg(long)]
    gui: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Capture {
    schema_version: u32,
    case_id: String,
    sample_sha256: String,
    source: String,
    capture_window: Option<CaptureWindow>,
    events: Vec<Event>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReportInput {
    schema_version: u32,
    case_id: String,
    sample_sha256: String,
    source: String,
    capture_window: Option<CaptureWindow>,
    events: Vec<Event>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CaptureWindow {
    start: String,
    end: String,
}

impl CaptureWindow {
    fn bounds(&self) -> Result<(OffsetDateTime, OffsetDateTime)> {
        let start =
            OffsetDateTime::parse(&self.start, &Rfc3339).context("invalid capture start")?;
        let end = OffsetDateTime::parse(&self.end, &Rfc3339).context("invalid capture end")?;
        ensure!(start <= end, "capture end precedes capture start");
        Ok((start, end))
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Event {
    timestamp: String,
    kind: EventKind,
    detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    process_guid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_process_guid: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum EventKind {
    ProcessStart,
    FileWrite,
    RegistryWrite,
    NetworkConnection,
    DnsQuery,
}

impl EventKind {
    const ALL: [Self; 5] = [
        Self::ProcessStart,
        Self::FileWrite,
        Self::RegistryWrite,
        Self::NetworkConnection,
        Self::DnsQuery,
    ];

    fn key(self) -> &'static str {
        match self {
            Self::ProcessStart => "process-start",
            Self::FileWrite => "file-write",
            Self::RegistryWrite => "registry-write",
            Self::NetworkConnection => "network-connection",
            Self::DnsQuery => "dns-query",
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Report {
    kind: &'static str,
    schema_version: u32,
    case_id: String,
    sample_sha256: String,
    source: String,
    tool: &'static str,
    tool_version: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    capture_window: Option<CaptureWindow>,
    counts: BTreeMap<&'static str, usize>,
    processes: BTreeMap<String, ProcessSummary>,
    unattributed_event_count: usize,
    coverage: Coverage,
    events: Vec<Event>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Coverage {
    completeness: &'static str,
    observed_kind_counts: BTreeMap<&'static str, usize>,
    processes_without_start: usize,
    processes_with_unseen_parent: usize,
}

#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProcessSummary {
    image: Option<String>,
    parent_process_guid: Option<String>,
    counts: BTreeMap<&'static str, usize>,
}

fn normalize_guid(value: &str) -> Result<String> {
    let guid = value
        .strip_prefix('{')
        .and_then(|value| value.strip_suffix('}'))
        .unwrap_or(value);
    ensure!(
        guid.len() == 36
            && guid.bytes().enumerate().all(|(index, byte)| {
                if matches!(index, 8 | 13 | 18 | 23) {
                    byte == b'-'
                } else {
                    byte.is_ascii_hexdigit()
                }
            })
            && guid != "00000000-0000-0000-0000-000000000000",
        "invalid process GUID"
    );
    Ok(guid.to_ascii_lowercase())
}

fn read_recording(path: &Path) -> Result<Capture> {
    #[derive(Deserialize)]
    struct RecordingFormat {
        kind: Option<String>,
    }

    ensure!(
        path.metadata()?.is_file(),
        "recording must be a regular file"
    );
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    ensure!(metadata.is_file(), "recording must be a regular file");
    ensure!(metadata.len() <= MAX_BYTES, "capture exceeds 4 MiB");
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= MAX_BYTES, "capture exceeds 4 MiB");
    let format: RecordingFormat =
        serde_json::from_slice(&bytes).context("invalid recording JSON")?;
    let Some(kind) = format.kind else {
        return serde_json::from_slice(&bytes).context("invalid telemetry capture JSON");
    };
    ensure!(kind == REPORT_KIND, "unsupported behavior report kind");
    let report: ReportInput =
        serde_json::from_slice(&bytes).context("invalid behavior report JSON")?;
    // Analyze events again so stored counts, trees and coverage cannot override them.
    Ok(Capture {
        schema_version: report.schema_version,
        case_id: report.case_id,
        sample_sha256: report.sample_sha256,
        source: report.source,
        capture_window: report.capture_window,
        events: report.events,
    })
}

fn validate_process_relationships(processes: &BTreeMap<String, ProcessSummary>) -> Result<()> {
    let mut checked = HashSet::new();
    for guid in processes.keys() {
        let mut current = Some(guid.as_str());
        let mut path = HashSet::new();
        while let Some(guid) = current {
            if checked.contains(guid) {
                break;
            }
            ensure!(
                path.insert(guid),
                "cycle in recorded process ancestry at {guid}"
            );
            current = processes
                .get(guid)
                .and_then(|process| process.parent_process_guid.as_deref());
        }
        checked.extend(path);
    }
    Ok(())
}

fn analyze(capture: Capture) -> Result<Report> {
    ensure!(
        capture.schema_version == 1,
        "unsupported capture schema version"
    );
    ensure!(
        (1..=64).contains(&capture.case_id.len())
            && capture
                .case_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
        "case ID must contain 1–64 ASCII letters, digits, hyphens or underscores"
    );
    ensure!(
        capture.sample_sha256.len() == 64
            && capture.sample_sha256.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid sample SHA-256"
    );
    ensure!(
        !capture.source.trim().is_empty()
            && capture.source.len() <= 128
            && !capture.source.chars().any(char::is_control),
        "invalid capture source"
    );
    ensure!(capture.events.len() <= MAX_EVENTS, "too many events");

    let bounds = capture
        .capture_window
        .as_ref()
        .map(CaptureWindow::bounds)
        .transpose()?;
    let mut timeline = Vec::with_capacity(capture.events.len());
    let mut counts = BTreeMap::new();
    let mut processes = BTreeMap::<String, ProcessSummary>::new();
    let mut unattributed_event_count = 0;
    for (index, mut event) in capture.events.into_iter().enumerate() {
        ensure!(
            !event.detail.trim().is_empty()
                && event.detail.len() <= MAX_DETAIL
                && !event.detail.chars().any(char::is_control),
            "invalid detail in event {}",
            index + 1
        );
        let timestamp = OffsetDateTime::parse(&event.timestamp, &Rfc3339)
            .with_context(|| format!("invalid RFC 3339 timestamp in event {}", index + 1))?;
        if let Some((start, end)) = bounds {
            ensure!(
                (start..=end).contains(&timestamp),
                "event {} is outside the capture window",
                index + 1
            );
        }
        event.process_guid = event
            .process_guid
            .as_deref()
            .map(normalize_guid)
            .transpose()
            .with_context(|| format!("invalid processGuid in event {}", index + 1))?;
        event.parent_process_guid = event
            .parent_process_guid
            .as_deref()
            .map(normalize_guid)
            .transpose()
            .with_context(|| format!("invalid parentProcessGuid in event {}", index + 1))?;
        if let Some(parent) = &event.parent_process_guid {
            ensure!(
                matches!(event.kind, EventKind::ProcessStart)
                    && event
                        .process_guid
                        .as_ref()
                        .is_some_and(|guid| guid != parent),
                "invalid parent attribution in event {}",
                index + 1
            );
        }
        *counts.entry(event.kind.key()).or_insert(0) += 1;
        if let Some(guid) = &event.process_guid {
            let process = processes.entry(guid.clone()).or_default();
            *process.counts.entry(event.kind.key()).or_insert(0) += 1;
            if matches!(event.kind, EventKind::ProcessStart) {
                ensure!(
                    process.image.is_none(),
                    "duplicate process start in event {}",
                    index + 1
                );
                process.image = Some(event.detail.clone());
                process
                    .parent_process_guid
                    .clone_from(&event.parent_process_guid);
            }
        } else {
            unattributed_event_count += 1;
        }
        timeline.push((timestamp, event));
    }
    validate_process_relationships(&processes)?;
    timeline.sort_by_key(|(timestamp, _)| *timestamp);
    let coverage = Coverage {
        // The report knows which events it saw, but not what the collector missed.
        completeness: "unknown",
        observed_kind_counts: EventKind::ALL
            .into_iter()
            .map(|kind| {
                (
                    kind.key(),
                    counts.get(kind.key()).copied().unwrap_or_default(),
                )
            })
            .collect(),
        processes_without_start: processes
            .values()
            .filter(|process| process.image.is_none())
            .count(),
        processes_with_unseen_parent: processes
            .values()
            .filter(|process| {
                process
                    .parent_process_guid
                    .as_ref()
                    .is_some_and(|parent| !processes.contains_key(parent))
            })
            .count(),
    };

    Ok(Report {
        kind: REPORT_KIND,
        schema_version: 1,
        case_id: capture.case_id,
        sample_sha256: capture.sample_sha256.to_ascii_lowercase(),
        source: capture.source,
        tool: env!("CARGO_PKG_NAME"),
        tool_version: env!("CARGO_PKG_VERSION"),
        capture_window: capture.capture_window,
        counts,
        processes,
        unattributed_event_count,
        coverage,
        events: timeline.into_iter().map(|(_, event)| event).collect(),
    })
}

fn encoded_report(report: &Report) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(report)?;
    ensure!((bytes.len() as u64) < MAX_BYTES, "report exceeds 4 MiB");
    bytes.push(b'\n');
    Ok(bytes)
}

fn demo_report() -> Result<Report> {
    analyze(serde_json::from_str(include_str!(
        "../examples/capture.json"
    ))?)
}

fn save_report(report: &Report, destination: &Path) -> Result<()> {
    ensure!(
        destination.file_name().is_some(),
        "select a report filename"
    );
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let bytes = encoded_report(report)?;
    let mut staged = tempfile::Builder::new()
        .prefix(".vespdex-report-")
        .suffix(".tmp")
        .tempfile_in(parent)
        .context("could not create a temporary report beside the destination")?;
    staged
        .write_all(&bytes)
        .context("could not write the report")?;
    staged
        .as_file()
        .sync_all()
        .context("could not flush the report")?;
    staged
        .persist_noclobber(destination)
        .map_err(|failure| failure.error)
        .with_context(|| format!("could not save a new report at {}", destination.display()))?;
    Ok(())
}

fn main() -> Result<()> {
    if std::env::args_os().len() == 1 && io::stdin().is_terminal() && io::stdout().is_terminal() {
        return terminal::run();
    }
    let args = Args::parse();
    if args.gui {
        #[cfg(windows)]
        return gui::run(args.capture, args.demo);
        #[cfg(not(windows))]
        anyhow::bail!("the desktop workspace is available on Windows");
    }
    let report = if args.demo {
        demo_report()?
    } else {
        let recording = args.capture.context("a telemetry recording is required")?;
        analyze(read_recording(&recording).context("unable to read recording")?)?
    };
    if let Some(destination) = args.output {
        save_report(&report, &destination)?;
    } else {
        io::stdout().lock().write_all(&encoded_report(&report)?)?;
    }
    Ok(())
}

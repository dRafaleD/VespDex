use std::{
    collections::BTreeMap,
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

#[derive(Parser)]
#[command(version, about = "Analyze recorded runtime telemetry offline")]
struct Args {
    /// Version 1 telemetry capture JSON
    #[arg(required_unless_present = "gui")]
    capture: Option<PathBuf>,
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
    events: Vec<Event>,
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

fn read_capture(path: &Path) -> Result<Capture> {
    ensure!(path.metadata()?.is_file(), "capture must be a regular file");
    let mut bytes = Vec::new();
    File::open(path)?
        .take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= MAX_BYTES, "capture exceeds 4 MiB");
    serde_json::from_slice(&bytes).context("invalid telemetry capture JSON")
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
    timeline.sort_by_key(|(timestamp, _)| *timestamp);

    Ok(Report {
        kind: "asphdex-behavior-report",
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
        events: timeline.into_iter().map(|(_, event)| event).collect(),
    })
}

fn encoded_report(report: &Report) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(report)?;
    ensure!(bytes.len() as u64 + 1 <= MAX_BYTES, "report exceeds 4 MiB");
    bytes.push(b'\n');
    Ok(bytes)
}

fn main() -> Result<()> {
    if std::env::args_os().len() == 1 && io::stdin().is_terminal() && io::stdout().is_terminal() {
        return terminal::run();
    }
    let args = Args::parse();
    if args.gui {
        #[cfg(windows)]
        return gui::run(args.capture);
        #[cfg(not(windows))]
        anyhow::bail!("the desktop workspace is available on Windows");
    }
    let capture = args.capture.context("a telemetry capture is required")?;
    let report = analyze(read_capture(&capture).context("unable to read capture")?)?;
    io::stdout().lock().write_all(&encoded_report(&report)?)?;
    Ok(())
}

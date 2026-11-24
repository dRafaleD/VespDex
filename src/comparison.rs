use std::collections::BTreeMap;

use serde::Serialize;

use crate::{CaptureWindow, EventKind, Report};

#[derive(Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Identity {
    Same,
    Different,
    Unknown,
}

pub(crate) fn identity(base: &Report, other: &Report) -> Identity {
    let is_placeholder = |hash: &str| hash.bytes().all(|byte| byte == b'0');
    if is_placeholder(&base.sample_sha256) || is_placeholder(&other.sample_sha256) {
        Identity::Unknown
    } else if base.sample_sha256 == other.sample_sha256 {
        Identity::Same
    } else {
        Identity::Different
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Recording<'a> {
    case_id: &'a str,
    sample_sha256: &'a str,
    source: &'a str,
    capture_window: Option<&'a CaptureWindow>,
}

impl<'a> From<&'a Report> for Recording<'a> {
    fn from(report: &'a Report) -> Self {
        Self {
            case_id: &report.case_id,
            sample_sha256: &report.sample_sha256,
            source: &report.source,
            capture_window: report.capture_window.as_ref(),
        }
    }
}

#[derive(Serialize)]
struct Count {
    base: usize,
    other: usize,
    delta: isize,
}

impl Count {
    fn new(base: usize, other: usize) -> Self {
        Self {
            base,
            other,
            delta: other as isize - base as isize,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Summary<'a> {
    kind: &'static str,
    schema_version: u32,
    sample_identity: Identity,
    base: Recording<'a>,
    other: Recording<'a>,
    total_events: Count,
    event_counts: BTreeMap<&'static str, Count>,
    processes: Count,
    unattributed_events: Count,
    processes_without_start: Count,
    processes_with_unseen_parent: Count,
}

impl<'a> Summary<'a> {
    pub(crate) fn new(base: &'a Report, other: &'a Report) -> Self {
        let event_counts = EventKind::ALL
            .into_iter()
            .map(|kind| {
                let key = kind.key();
                (
                    key,
                    Count::new(
                        base.coverage.observed_kind_counts[key],
                        other.coverage.observed_kind_counts[key],
                    ),
                )
            })
            .collect();
        Self {
            kind: "vespdex-behavior-comparison",
            schema_version: 1,
            sample_identity: identity(base, other),
            base: base.into(),
            other: other.into(),
            total_events: Count::new(base.events.len(), other.events.len()),
            event_counts,
            processes: Count::new(base.processes.len(), other.processes.len()),
            unattributed_events: Count::new(
                base.unattributed_event_count,
                other.unattributed_event_count,
            ),
            processes_without_start: Count::new(
                base.coverage.processes_without_start,
                other.coverage.processes_without_start,
            ),
            processes_with_unseen_parent: Count::new(
                base.coverage.processes_with_unseen_parent,
                other.coverage.processes_with_unseen_parent,
            ),
        }
    }
}

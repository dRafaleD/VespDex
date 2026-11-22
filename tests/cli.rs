use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
    sync::atomic::{AtomicUsize, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::{Value, json};

fn capture() -> Value {
    serde_json::from_str(include_str!("../examples/capture.json")).unwrap()
}

fn run(bytes: &[u8]) -> Output {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let index = NEXT.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "vespdex-{}-{stamp}-{index}.json",
        std::process::id()
    ));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    let cleanup = TempCapture(path);
    std::io::Write::write_all(&mut file, bytes).unwrap();
    drop(file);
    Command::new(env!("CARGO_BIN_EXE_vespdex"))
        .arg(&cleanup.0)
        .output()
        .unwrap()
}

struct TempCapture(PathBuf);

impl Drop for TempCapture {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn assert_rejected(input: &Value, message: &str) {
    let output = run(&serde_json::to_vec(input).unwrap());
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(message), "{stderr}");
}

#[test]
fn reports_the_sorted_timeline_and_process_relationships() {
    let output = run(include_bytes!("../examples/capture.json"));
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["kind"], "asphdex-behavior-report");
    assert_eq!(report["schemaVersion"], 1);
    assert_eq!(report["tool"], "vespdex");
    assert_eq!(
        report["counts"],
        json!({"process-start": 2, "dns-query": 1, "file-write": 1})
    );
    let events = report["events"].as_array().unwrap();
    assert_eq!(events[0]["detail"], "demo.exe");
    assert_eq!(events[1]["detail"], "demo-worker.exe");
    assert_eq!(events[2]["detail"], "demo-output.txt");
    assert_eq!(events[3]["detail"], "example.org");
    assert_eq!(
        report["processes"]["22222222-2222-2222-2222-222222222222"]["parentProcessGuid"],
        "11111111-1111-1111-1111-111111111111"
    );
}

#[test]
fn uses_absolute_time_and_preserves_events_without_a_process() {
    let mut input = capture();
    input["events"] = json!([
        {"timestamp": "2026-11-21T12:00:00+02:00", "kind": "dns-query", "detail": "second.example"},
        {"timestamp": "2026-11-21T09:59:59Z", "kind": "dns-query", "detail": "first.example"}
    ]);
    let output = run(&serde_json::to_vec(&input).unwrap());
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["unattributedEventCount"], 2);
    assert_eq!(report["events"][0]["detail"], "first.example");
    assert_eq!(report["processes"], json!({}));
}

#[test]
fn rejects_events_outside_the_recorded_window() {
    let mut input = capture();
    input["captureWindow"] =
        json!({"start": "2026-11-21T10:00:00Z", "end": "2026-11-21T10:00:01Z"});
    assert_rejected(&input, "outside the capture window");
}

#[test]
fn coverage_distinguishes_unseen_events_from_unknown_collection_completeness() {
    let mut input = capture();
    input["events"] = json!([
        {
            "timestamp": "2026-11-21T10:00:00Z", "kind": "process-start", "detail": "demo.exe",
            "processGuid": "11111111-1111-1111-1111-111111111111",
            "parentProcessGuid": "22222222-2222-2222-2222-222222222222"
        },
        {
            "timestamp": "2026-11-21T10:00:01Z", "kind": "file-write", "detail": "marker.txt",
            "processGuid": "33333333-3333-3333-3333-333333333333"
        }
    ]);
    let output = run(&serde_json::to_vec(&input).unwrap());
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report["counts"],
        json!({"process-start": 1, "file-write": 1})
    );
    assert_eq!(
        report["coverage"],
        json!({
            "completeness": "unknown",
            "observedKindCounts": {
                "process-start": 1, "file-write": 1, "registry-write": 0, "network-connection": 0, "dns-query": 0
            },
            "processesWithoutStart": 1,
            "processesWithUnseenParent": 1
        })
    );
}

#[test]
fn rejects_cycles_in_the_process_tree() {
    let mut input = capture();
    input["events"][1]["parentProcessGuid"] = json!("22222222-2222-2222-2222-222222222222");
    assert_rejected(&input, "cycle in recorded process ancestry");
}

#[test]
fn refuses_unsupported_versions_and_malformed_metadata() {
    let mut input = capture();
    input["schemaVersion"] = json!(2);
    assert_rejected(&input, "unsupported capture schema version");
    input["schemaVersion"] = json!(1);
    input["sampleSha256"] = json!("incorrect");
    assert_rejected(&input, "invalid sample SHA-256");
    input = capture();
    input["events"][0]["detail"] = json!("line\nline");
    assert_rejected(&input, "invalid detail");
}

#[test]
fn enforces_the_capture_byte_and_event_limits() {
    let output = run(&vec![b' '; 4 * 1024 * 1024 + 1]);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("capture exceeds 4 MiB"));
    let mut input = capture();
    input["events"] = json!(vec![input["events"][0].clone(); 2001]);
    assert_rejected(&input, "too many events");
}

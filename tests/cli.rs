use std::{
    fs,
    process::{Command, Output, Stdio},
};

use serde_json::{Value, json};

fn capture() -> Value {
    serde_json::from_str(include_str!("../examples/capture.json")).unwrap()
}

fn run(bytes: &[u8]) -> Output {
    let workspace = tempfile::tempdir().unwrap();
    let path = workspace.path().join("capture.json");
    fs::write(&path, bytes).unwrap();
    Command::new(env!("CARGO_BIN_EXE_vespdex"))
        .arg(&path)
        .output()
        .unwrap()
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

#[test]
fn concurrent_exports_never_replace_another_report_or_leave_staging_files() {
    let workspace = tempfile::tempdir().unwrap();
    let capture = workspace.path().join("capture.json");
    let report = workspace.path().join("report.json");
    fs::write(&capture, include_bytes!("../examples/capture.json")).unwrap();

    let export = || {
        Command::new(env!("CARGO_BIN_EXE_vespdex"))
            .arg(&capture)
            .arg("--output")
            .arg(&report)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    };
    let first = export();
    let second = export();
    let a = first.wait_with_output().unwrap();
    let b = second.wait_with_output().unwrap();
    assert_ne!(a.status.success(), b.status.success());
    assert!(a.stdout.is_empty() && b.stdout.is_empty());
    let saved = fs::read(&report).unwrap();
    let value: Value = serde_json::from_slice(&saved).unwrap();
    assert_eq!(value["events"].as_array().unwrap().len(), 4);

    let replacement = export().wait_with_output().unwrap();
    assert!(!replacement.status.success());
    assert_eq!(fs::read(&report).unwrap(), saved);
    assert_eq!(fs::read_dir(workspace.path()).unwrap().count(), 2);
}

#[test]
fn invalid_capture_does_not_create_an_output_file() {
    let workspace = tempfile::tempdir().unwrap();
    let capture = workspace.path().join("capture.json");
    let report = workspace.path().join("report.json");
    fs::write(&capture, b"{}").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_vespdex"))
        .arg(&capture)
        .arg("-o")
        .arg(&report)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!report.exists());
    assert_eq!(fs::read_dir(workspace.path()).unwrap().count(), 1);
}

use std::{
    env,
    io::Read,
    os::windows::process::CommandExt,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Output, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, de::DeserializeOwned};

use crate::{MAX_BYTES, Report, analyze};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const READER_TIMEOUT: Duration = Duration::from_secs(45);
const STDERR_LIMIT: u64 = 16 * 1024;
const RUN_CONVERTER: &str = concat!(
    "[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false); ",
    "$ErrorActionPreference = 'Stop'; try { $convert = {\n",
    include_str!("../../scripts/convert-sysmon.ps1"),
    "\n}; ",
    "if ($env:VESPDEX_PROCESS_GUID) { ",
    "& $convert -Evtx $env:VESPDEX_EVTX_PATH -ProcessGuid $env:VESPDEX_PROCESS_GUID -CaseId ('case-' + $env:VESPDEX_PROCESS_GUID)",
    " } else { & $convert -Evtx $env:VESPDEX_EVTX_PATH -ListProcesses }",
    " } catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }"
);

#[derive(Deserialize)]
pub(super) struct Candidate {
    pub guid: String,
    pub image: String,
    pub sha256: String,
    pub timestamp: String,
}

pub(super) fn list(path: &Path, cancelled: &AtomicBool) -> Result<Vec<Candidate>> {
    let candidates: Vec<Candidate> = read(path, None, cancelled)?;
    ensure!(
        !candidates.is_empty(),
        "no process creation events with a SHA-256 value were found"
    );
    Ok(candidates)
}

pub(super) fn convert(path: &Path, guid: &str, cancelled: &AtomicBool) -> Result<Report> {
    analyze(read(path, Some(guid), cancelled)?)
}

fn read<T: DeserializeOwned>(path: &Path, guid: Option<&str>, cancelled: &AtomicBool) -> Result<T> {
    // The command is fixed source. Paths and process IDs are passed as data.
    let output = bounded_output(
        powershell_command(RUN_CONVERTER)?
            .env("VESPDEX_EVTX_PATH", path)
            .env("VESPDEX_PROCESS_GUID", guid.unwrap_or_default()),
        READER_TIMEOUT,
        MAX_BYTES + 2,
        cancelled,
    )?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr);
        let detail: String = detail.trim().chars().take(600).collect();
        anyhow::bail!("Sysmon EVTX: {detail}");
    }
    serde_json::from_slice(&output.stdout).context("invalid JSON from the Windows EVTX reader")
}

fn powershell_command(script: &str) -> Result<Command> {
    let windows = env::var_os("SystemRoot").context("Windows system directory unavailable")?;
    let powershell = PathBuf::from(windows).join("System32/WindowsPowerShell/v1.0/powershell.exe");
    let mut command = Command::new(powershell);
    command
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .stdin(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW);
    Ok(command)
}

fn read_prefix(stream: impl Read, limit: u64) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    stream.take(limit + 1).read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn bounded_output(
    command: &mut Command,
    timeout: Duration,
    stdout_limit: u64,
    cancelled: &AtomicBool,
) -> Result<Output> {
    ensure!(
        !cancelled.load(Ordering::Relaxed),
        "Windows EVTX reader was cancelled"
    );
    let mut reader = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("could not open the Windows EVTX reader")?;
    let stdout = reader.stdout.take().expect("stdout is piped");
    let stderr = reader.stderr.take().expect("stderr is piped");
    let stdout = thread::spawn(move || read_prefix(stdout, stdout_limit));
    let stderr = thread::spawn(move || read_prefix(stderr, STDERR_LIMIT));

    // Drain both streams while waiting so neither pipe can stall the child.
    let status = wait_for_exit(&mut reader, timeout, cancelled)?;
    let stdout = stdout
        .join()
        .map_err(|_| anyhow::anyhow!("EVTX output reader stopped"))??;
    let stderr = stderr
        .join()
        .map_err(|_| anyhow::anyhow!("EVTX diagnostic reader stopped"))??;
    ensure!(
        stdout.len() as u64 <= stdout_limit,
        "EVTX output exceeds the allowed size"
    );
    ensure!(
        stderr.len() as u64 <= STDERR_LIMIT,
        "EVTX diagnostics exceed the allowed size"
    );
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

fn wait_for_exit(
    reader: &mut Child,
    timeout: Duration,
    cancelled: &AtomicBool,
) -> Result<ExitStatus> {
    let start = Instant::now();
    let error = loop {
        if cancelled.load(Ordering::Relaxed) {
            break anyhow::anyhow!("Windows EVTX reader was cancelled");
        }
        match reader.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if start.elapsed() < timeout => thread::sleep(Duration::from_millis(25)),
            Ok(None) => break anyhow::anyhow!("Windows EVTX reader exceeded its time limit"),
            Err(error) => break anyhow::anyhow!("could not wait for Windows EVTX reader: {error}"),
        }
    };
    // A successful kill is followed by wait to reap the reader. If it already
    // exited, the final try_wait also collects its status.
    if reader.kill().is_ok() {
        reader
            .wait()
            .context("could not reap Windows EVTX reader")?;
    } else {
        reader
            .try_wait()
            .context("could not reap Windows EVTX reader")?;
    }
    Err(error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launches_the_embedded_reader_with_a_windows_path() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/capture.json");
        let error = list(&path, &AtomicBool::new(false))
            .err()
            .expect("capture JSON is not an EVTX");
        assert!(
            error
                .to_string()
                .contains("Select an exported Sysmon .evtx file."),
            "{error:#}"
        );
    }

    #[test]
    fn stops_an_overdue_reader() {
        let error = bounded_output(
            &mut powershell_command("Start-Sleep -Seconds 20").unwrap(),
            Duration::from_millis(500),
            1024,
            &AtomicBool::new(false),
        )
        .unwrap_err();
        assert!(error.to_string().contains("time limit"), "{error:#}");
    }

    #[test]
    fn rejects_large_stdout_and_stderr() {
        for (script, message) in [
            ("[Console]::WriteLine(('a' * 2048))", "output exceeds"),
            (
                "[Console]::Error.WriteLine(('a' * 32768))",
                "diagnostics exceed",
            ),
        ] {
            let error = bounded_output(
                &mut powershell_command(script).unwrap(),
                Duration::from_secs(10),
                1024,
                &AtomicBool::new(false),
            )
            .unwrap_err();
            assert!(error.to_string().contains(message), "{error:#}");
        }
    }

    #[test]
    fn cancellation_reaps_a_running_reader() {
        let mut process = powershell_command("Start-Sleep -Seconds 20")
            .unwrap()
            .spawn()
            .unwrap();
        let error = wait_for_exit(
            &mut process,
            Duration::from_secs(20),
            &AtomicBool::new(true),
        )
        .unwrap_err();
        assert!(error.to_string().contains("cancelled"), "{error:#}");
        assert!(process.try_wait().unwrap().is_some());
    }
}

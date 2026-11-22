use std::{
    env,
    os::windows::process::CommandExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, de::DeserializeOwned};

use crate::{MAX_BYTES, Report, analyze};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
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

pub(super) fn list(path: &Path) -> Result<Vec<Candidate>> {
    let candidates: Vec<Candidate> = read(path, None)?;
    ensure!(
        !candidates.is_empty(),
        "no process creation events with a SHA-256 value were found"
    );
    Ok(candidates)
}

pub(super) fn convert(path: &Path, guid: &str) -> Result<Report> {
    analyze(read(path, Some(guid))?)
}

fn read<T: DeserializeOwned>(path: &Path, guid: Option<&str>) -> Result<T> {
    let windows = env::var_os("SystemRoot").context("Windows system directory unavailable")?;
    let powershell = PathBuf::from(windows).join("System32/WindowsPowerShell/v1.0/powershell.exe");
    let output = Command::new(powershell)
        .args(["-NoProfile", "-NonInteractive", "-Command", RUN_CONVERTER])
        .env("VESPDEX_EVTX_PATH", path)
        .env("VESPDEX_PROCESS_GUID", guid.unwrap_or_default())
        .stdin(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .context("could not open the Windows EVTX reader")?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr);
        let detail: String = detail.trim().chars().take(600).collect();
        anyhow::bail!("Sysmon EVTX: {detail}");
    }
    ensure!(
        output.stdout.len() as u64 <= MAX_BYTES + 2,
        "EVTX output exceeds 4 MiB"
    );
    serde_json::from_slice(&output.stdout).context("invalid JSON from the Windows EVTX reader")
}

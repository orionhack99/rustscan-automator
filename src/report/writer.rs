//! Output directory layout and per-mode result files.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::json;

use crate::model::error::AppError;
use crate::model::finding::Finding;
use crate::model::scan_mode::ScanMode;
use crate::util::{unique_path, utc_now_compact};

/// The per-run output layout under `<output_dir>/<target_label>/`.
pub struct OutputLayout {
    pub target_dir: PathBuf,
    pub target_label: String,
    pub timestamp: String,
}

impl OutputLayout {
    /// Create the target directory and capture the run timestamp.
    pub fn create(output_dir: &Path, target_label: &str) -> Result<Self, AppError> {
        let target_dir = output_dir.join(target_label);
        fs::create_dir_all(&target_dir).map_err(|error| {
            AppError::Config(format!(
                "cannot create output directory '{}': {error}",
                target_dir.display()
            ))
        })?;

        Ok(Self {
            target_dir,
            target_label: target_label.to_string(),
            timestamp: utc_now_compact(),
        })
    }

    fn stem(&self, mode: ScanMode) -> String {
        format!("{}_{}_{}", self.target_label, mode.suffix(), self.timestamp)
    }

    /// Per-mode result path with the given extension, collision-safe.
    pub fn mode_path(&self, mode: ScanMode, extension: &str) -> PathBuf {
        unique_path(
            &self
                .target_dir
                .join(format!("{}.{extension}", self.stem(mode))),
        )
    }

    /// Summary path with the given extension, collision-safe.
    pub fn summary_path(&self, extension: &str) -> PathBuf {
        unique_path(&self.target_dir.join(format!(
            "{}_summary_{}.{extension}",
            self.target_label, self.timestamp
        )))
    }

    /// Session log path, collision-safe.
    pub fn session_path(&self) -> PathBuf {
        unique_path(&self.target_dir.join(format!(
            "{}_session_{}.log",
            self.target_label, self.timestamp
        )))
    }
}

/// Write the human-readable and JSON per-mode result files.
#[allow(clippy::too_many_arguments)]
pub fn write_mode_result(
    layout: &OutputLayout,
    mode: ScanMode,
    findings: &[Finding],
    target: &str,
    started_at: &str,
    finished_at: &str,
    warnings: usize,
    notes: &[String],
) -> Result<Vec<PathBuf>, AppError> {
    let mut text = String::new();
    text.push_str("# rustscan-automator\n");
    text.push_str(&format!("Target : {target}\n"));
    text.push_str(&format!("Mode   : {}\n", mode.as_str()));
    text.push_str(&format!("Started: {started_at}\n"));
    text.push_str(&format!("Finished: {finished_at}\n\n"));

    if findings.is_empty() {
        text.push_str("[*] no findings\n");
    }
    for finding in findings {
        text.push_str(&format!("{}\n", format_finding(finding)));
    }
    if !notes.is_empty() {
        text.push('\n');
        for note in notes {
            text.push_str(&format!("[i] {note}\n"));
        }
    }
    text.push_str(&format!("\n[!] parse warnings: {warnings}\n"));

    let text_path = layout.mode_path(mode, "txt");
    fs::write(&text_path, text).map_err(|error| {
        AppError::Config(format!("cannot write '{}': {error}", text_path.display()))
    })?;

    let document = json!({
        "target": target,
        "mode": mode.as_str(),
        "started_at": started_at,
        "finished_at": finished_at,
        "parse_warnings": warnings,
        "findings": findings,
    });
    let json_path = layout.mode_path(mode, "json");
    let serialized = serde_json::to_string_pretty(&document)
        .map_err(|error| AppError::Scan(format!("cannot serialize findings: {error}")))?;
    fs::write(&json_path, serialized).map_err(|error| {
        AppError::Config(format!("cannot write '{}': {error}", json_path.display()))
    })?;

    Ok(vec![text_path, json_path])
}

/// Human-readable one-line rendering of a finding.
pub fn format_finding(finding: &Finding) -> String {
    match finding.port {
        Some(port) => {
            let protocol = finding
                .protocol
                .map(|value| format!("{value:?}").to_ascii_lowercase())
                .unwrap_or_else(|| "tcp".to_string());
            let state = finding
                .state
                .map(|value| format!("{value:?}").to_ascii_lowercase())
                .unwrap_or_else(|| "open".to_string());
            let mut line = format!("[+] {}:{port}/{protocol} {state}", finding.host);
            if let Some(service) = &finding.service {
                line.push_str(&format!("  {service}"));
            }
            if let Some(version) = &finding.version {
                line.push_str(&format!(" {version}"));
            }
            line
        }
        None => format!("[+] {} live", finding.host),
    }
}

//! Consolidated run summary rendering (JSON and text).

use std::fs;
use std::path::{Path, PathBuf};

use crate::model::error::AppError;
use crate::model::run::RunSummary;

/// Serialize the summary to pretty JSON.
pub fn to_json(summary: &RunSummary) -> Result<String, AppError> {
    serde_json::to_string_pretty(summary)
        .map_err(|error| AppError::Scan(format!("cannot serialize summary: {error}")))
}

/// Render the summary as human-readable text.
pub fn to_text(summary: &RunSummary) -> String {
    let mut text = String::new();
    text.push_str("# rustscan-automator summary\n");
    text.push_str(&format!("Target   : {}\n", summary.target));
    text.push_str(&format!("Mode     : {}\n", summary.mode));
    text.push_str(&format!("Started  : {}\n", summary.started_at));
    text.push_str(&format!("Finished : {}\n", summary.finished_at));
    text.push_str(&format!(
        "Counts   : live_hosts={}, open_tcp={}, open_udp={}, services={}\n",
        summary.counts.live_hosts,
        summary.counts.open_tcp_ports,
        summary.counts.open_udp_ports,
        summary.counts.identified_services
    ));

    text.push_str("\nPhases:\n");
    if summary.phases.is_empty() {
        text.push_str("  (none)\n");
    }
    for phase in &summary.phases {
        let status = match phase.status {
            crate::model::run::PhaseStatus::Completed => "completed",
            crate::model::run::PhaseStatus::Skipped => "skipped",
            crate::model::run::PhaseStatus::Failed => "failed",
        };
        match &phase.detail {
            Some(detail) => text.push_str(&format!("  - {} [{status}] {detail}\n", phase.name)),
            None => text.push_str(&format!("  - {} [{status}]\n", phase.name)),
        }
    }

    text.push_str("\nFailures:\n");
    if summary.failures.is_empty() {
        text.push_str("  (none)\n");
    }
    for failure in &summary.failures {
        text.push_str(&format!("  - {failure}\n"));
    }

    text.push_str("\nArtifacts:\n");
    for artifact in &summary.artifacts {
        text.push_str(&format!("  - {artifact}\n"));
    }

    text
}

/// Write the summary as both JSON and text; returns the artifact paths.
pub fn write_summary(
    json_path: &Path,
    text_path: &Path,
    summary: &RunSummary,
) -> Result<Vec<PathBuf>, AppError> {
    let json = to_json(summary)?;
    fs::write(json_path, json).map_err(|error| {
        AppError::Config(format!("cannot write '{}': {error}", json_path.display()))
    })?;

    fs::write(text_path, to_text(summary)).map_err(|error| {
        AppError::Config(format!("cannot write '{}': {error}", text_path.display()))
    })?;

    Ok(vec![json_path.to_path_buf(), text_path.to_path_buf()])
}

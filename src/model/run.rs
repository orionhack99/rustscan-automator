//! Run configuration and the consolidated run summary.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::model::scan_mode::ScanMode;
use crate::model::target::Target;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunConfiguration {
    pub target: Target,
    pub mode: ScanMode,
    pub output_dir: PathBuf,
    pub dns_server: Option<String>,
    pub rustscan_path: Option<PathBuf>,
    pub batch_size: Option<u32>,
    pub timeout_ms: Option<u32>,
    pub extra_ports: Option<String>,
    pub interactive: bool,
    pub no_color: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PhaseStatus {
    Completed,
    Skipped,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseRecord {
    pub name: String,
    pub status: PhaseStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl PhaseRecord {
    pub fn completed(name: impl Into<String>, detail: Option<String>) -> Self {
        Self {
            name: name.into(),
            status: PhaseStatus::Completed,
            detail,
        }
    }

    pub fn skipped(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: PhaseStatus::Skipped,
            detail: Some(detail.into()),
        }
    }

    pub fn failed(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: PhaseStatus::Failed,
            detail: Some(detail.into()),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RunCounts {
    pub live_hosts: usize,
    pub open_tcp_ports: usize,
    pub open_udp_ports: usize,
    pub identified_services: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunSummary {
    pub target: String,
    pub mode: String,
    pub started_at: String,
    pub finished_at: String,
    pub phases: Vec<PhaseRecord>,
    pub counts: RunCounts,
    pub failures: Vec<String>,
    pub artifacts: Vec<String>,
}

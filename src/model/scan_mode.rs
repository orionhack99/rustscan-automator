//! Scan modes and their static properties.

use serde::{Deserialize, Serialize};

use crate::model::error::AppError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanMode {
    Network,
    Port,
    Service,
    Vuln,
    Udp,
    Full,
    Guidance,
}

impl ScanMode {
    /// Parse a user-supplied mode name or alias.
    pub fn parse(value: &str) -> Result<Self, AppError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "network" => Ok(ScanMode::Network),
            "port" => Ok(ScanMode::Port),
            "service" | "script" => Ok(ScanMode::Service),
            "vuln" | "vulns" => Ok(ScanMode::Vuln),
            "udp" => Ok(ScanMode::Udp),
            "full" | "all" => Ok(ScanMode::Full),
            "recon" | "guidance" => Ok(ScanMode::Guidance),
            other => Err(AppError::Config(format!(
                "unknown scan type '{other}' (valid: network, port, service, vuln, udp, full, all, recon)"
            ))),
        }
    }

    /// Canonical name used in output and summaries.
    pub fn as_str(&self) -> &'static str {
        match self {
            ScanMode::Network => "network",
            ScanMode::Port => "port",
            ScanMode::Service => "service",
            ScanMode::Vuln => "vuln",
            ScanMode::Udp => "udp",
            ScanMode::Full => "full",
            ScanMode::Guidance => "guidance",
        }
    }

    /// Short suffix used in output file names.
    pub fn suffix(&self) -> &'static str {
        match self {
            ScanMode::Network => "network",
            ScanMode::Port => "ports",
            ScanMode::Service => "service",
            ScanMode::Vuln => "vuln",
            ScanMode::Udp => "udp",
            ScanMode::Full => "full",
            ScanMode::Guidance => "guidance",
        }
    }

    /// Whether the mode requires nmap during its reconnaissance phase.
    pub fn requires_nmap(&self) -> bool {
        matches!(self, ScanMode::Service | ScanMode::Vuln | ScanMode::Full)
    }

    /// Whether the mode usually requires elevated privileges.
    pub fn requires_privileges(&self) -> bool {
        matches!(self, ScanMode::Udp)
    }
}

/// All accepted mode names/aliases, for help text.
pub const MODE_NAMES: &[&str] = &[
    "network", "port", "service", "vuln", "udp", "full", "all", "recon",
];

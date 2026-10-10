//! Findings: live hosts and open ports with optional service/version data.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PortState {
    Open,
    OpenFiltered,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<Protocol>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<PortState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
}

impl Finding {
    /// A host-only finding (used by network discovery).
    pub fn host(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port: None,
            protocol: None,
            state: None,
            service: None,
            version: None,
            evidence: None,
        }
    }

    /// An open-port finding.
    pub fn port(host: impl Into<String>, port: u16, protocol: Protocol) -> Self {
        Self {
            host: host.into(),
            port: Some(port),
            protocol: Some(protocol),
            state: Some(PortState::Open),
            service: None,
            version: None,
            evidence: None,
        }
    }
}

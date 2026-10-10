//! Target value object: parsing, classification, and filesystem-safe labelling.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::model::error::AppError;
use crate::util::slugify;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TargetKind {
    Ip,
    Hostname,
    Cidr,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    /// Exactly what the user supplied, trimmed.
    pub raw: String,
    /// How the target was classified.
    pub kind: TargetKind,
    /// Addresses the target resolves to, populated best-effort when resolution occurs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolved: Vec<String>,
    /// Filesystem-safe slug derived from `raw`.
    pub label: String,
}

impl Target {
    /// Parse and validate a user-supplied target.
    pub fn parse(raw: &str) -> Result<Self, AppError> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err(AppError::Config("target must not be empty".to_string()));
        }

        let kind = classify(raw)?;
        Ok(Self {
            raw: raw.to_string(),
            kind,
            resolved: Vec::new(),
            label: slugify(raw),
        })
    }

    /// Whether the target covers more than one address.
    pub fn is_network_range(&self) -> bool {
        matches!(self.kind, TargetKind::Cidr)
    }
}

fn invalid(raw: &str) -> AppError {
    AppError::Config(format!(
        "'{raw}' is not a valid IP address, hostname, or CIDR range"
    ))
}

fn classify(raw: &str) -> Result<TargetKind, AppError> {
    if let Some((address, prefix)) = raw.split_once('/') {
        let ip: IpAddr = address.parse().map_err(|_| invalid(raw))?;
        let prefix: u8 = prefix.parse().map_err(|_| invalid(raw))?;
        let max = if ip.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(invalid(raw));
        }
        return Ok(TargetKind::Cidr);
    }

    if raw.parse::<IpAddr>().is_ok() {
        return Ok(TargetKind::Ip);
    }

    if is_valid_hostname(raw) {
        return Ok(TargetKind::Hostname);
    }

    Err(invalid(raw))
}

/// RFC 1123-style hostname validation.
fn is_valid_hostname(value: &str) -> bool {
    if value.is_empty() || value.len() > 253 {
        return false;
    }

    value.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

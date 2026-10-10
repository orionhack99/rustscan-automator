//! Parser for nmap normal output (used during RustScan's nmap handoff).
//!
//! Example line:
//! `8321/tcp open  http    syn-ack ttl 64 SimpleHTTPServer 0.6 (Python 3.14.7)`
//!
//! The columns are `PORT/PROTO STATE SERVICE REASON VERSION`; the reason token
//! (`syn-ack ttl 64`) is stripped from the reported version.

use std::sync::OnceLock;

use regex::Regex;

use crate::model::finding::{Finding, PortState, Protocol};

fn service_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^(\d{1,5})/(tcp|udp)\s+(\S+)\s+(\S+)(?:\s+(.+?))?\s*$").expect("valid regex")
    })
}

fn reason_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^(?:syn-ack|conn-refused|reset|no-response|filtered|closed|open)\b(?:\s+ttl\s+\d+)?\s+")
            .expect("valid regex")
    })
}

/// Parse an nmap-style service line into a service finding.
///
/// Only `open` and `open|filtered` states produce findings; other states return `None`.
pub fn parse_service_line(line: &str) -> Option<Finding> {
    let captures = service_regex().captures(line.trim())?;

    let port: u16 = captures.get(1)?.as_str().parse().ok()?;
    if port == 0 {
        return None;
    }

    let protocol = match captures.get(2)?.as_str() {
        "udp" => Protocol::Udp,
        _ => Protocol::Tcp,
    };

    let state = match captures.get(3)?.as_str() {
        "open" => PortState::Open,
        "open|filtered" => PortState::OpenFiltered,
        _ => return None,
    };

    let service = captures.get(4).map(|m| m.as_str().to_string());
    let version = captures
        .get(5)
        .map(|m| strip_reason(m.as_str()).trim().to_string())
        .filter(|value| !value.is_empty() && value != "unknown");

    let mut finding = Finding::port(String::new(), port, protocol);
    finding.state = Some(state);
    finding.service = service;
    finding.version = version;
    Some(finding)
}

fn strip_reason(text: &str) -> String {
    reason_regex().replace(text, "").into_owned()
}

//! Parser for RustScan greppable output (`host -> [port, ...]`).
//!
//! RustScan 2.x `--greppable` emits one line per host with the open ports in
//! brackets, e.g. `10.0.0.5 -> [22,80,443]`. Older/alternate `Open
//! <host>:<port>` and bare `<host>:<port>` lines are also accepted.

use std::sync::OnceLock;

use regex::Regex;

use crate::model::finding::{Finding, Protocol};

fn arrow_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^\s*(\S+)\s*->\s*\[([0-9,\s]+)\]\s*$").expect("valid regex"))
}

fn prefixed_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^Open\s+(\S+):(\d{1,5})$").expect("valid regex"))
}

fn bare_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$").expect("valid regex"))
}

/// Parse a single greppable line into zero or more open-port findings.
///
/// A `host -> [ports]` line may carry several ports, so this returns a `Vec`.
pub fn parse_greppable_lines(line: &str) -> Vec<Finding> {
    let trimmed = line.trim();

    if let Some(captures) = arrow_regex().captures(trimmed) {
        let host = captures[1].to_string();
        let mut findings = Vec::new();
        for token in captures[2].split(',') {
            if let Ok(port) = token.trim().parse::<u16>() {
                if port > 0 {
                    findings.push(Finding::port(host.clone(), port, Protocol::Tcp));
                }
            }
        }
        return findings;
    }

    let captures = prefixed_regex()
        .captures(trimmed)
        .or_else(|| bare_regex().captures(trimmed));

    if let Some(captures) = captures {
        let host = captures[1].to_string();
        if let Ok(port) = captures[2].parse::<u16>() {
            if port > 0 {
                return vec![Finding::port(host, port, Protocol::Tcp)];
            }
        }
    }

    Vec::new()
}

/// Whether a line looks like greppable output (used for parse-warning counts).
pub fn looks_like_finding(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.starts_with("Open ") || arrow_regex().is_match(trimmed)
}

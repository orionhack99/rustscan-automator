//! Builds the RustScan argument vector per scan mode and enforces the
//! reconnaissance-only nmap allowlist (see `contracts/rustscan-invocation.md`).

use crate::config::defaults;
use crate::model::error::AppError;
use crate::model::scan_mode::ScanMode;

/// Inputs required to build a RustScan invocation.
pub struct ScanArgs<'a> {
    pub mode: ScanMode,
    pub target: &'a str,
    pub ports: Option<String>,
    pub dns: Option<&'a str>,
    pub batch_size: Option<u32>,
    pub timeout_ms: Option<u32>,
}

/// nmap arguments that must never be passed through RustScan.
const FORBIDDEN_FRAGMENTS: &[&str] = &[
    "brute",
    "exploit",
    "intrusive",
    "nikto",
    "dirb",
    "gobuster",
    "ffuf",
    "wpscan",
    "smbmap",
    "enum4linux",
    "dnsrecon",
    "metasploit",
    "msf",
];

/// nmap `--script` categories allowed during reconnaissance.
const ALLOWED_SCRIPT_CATEGORIES: &[&str] = &["default", "vuln", "safe", "discovery"];

/// Build the argument list for a single RustScan invocation.
pub fn build_rustscan_args(request: &ScanArgs) -> Result<Vec<String>, AppError> {
    let mut args: Vec<String> = vec!["--no-banner".to_string()];
    let mut nmap_phase: Option<Vec<String>> = None;

    match request.mode {
        ScanMode::Port | ScanMode::Full | ScanMode::Guidance => {
            args.push("-g".to_string());
            args.push("-r".to_string());
            args.push(request.ports.clone().unwrap_or_else(|| {
                if matches!(request.mode, ScanMode::Guidance) {
                    defaults::TOP_RANGE.to_string()
                } else {
                    defaults::FULL_RANGE.to_string()
                }
            }));
        }
        ScanMode::Network => {
            args.push("-g".to_string());
            args.push("-p".to_string());
            args.push(
                request
                    .ports
                    .clone()
                    .unwrap_or_else(|| defaults::DISCOVERY_PORTS.to_string()),
            );
        }
        ScanMode::Service => {
            args.push("-p".to_string());
            args.push(require_ports(request)?);
            args.push("--scripts".to_string());
            args.push("default".to_string());
            nmap_phase = Some(vec![
                "-sV".to_string(),
                "-sC".to_string(),
                "-Pn".to_string(),
            ]);
        }
        ScanMode::Vuln => {
            args.push("-p".to_string());
            args.push(require_ports(request)?);
            args.push("--scripts".to_string());
            args.push("default".to_string());
            nmap_phase = Some(vec![
                "--script".to_string(),
                "vuln".to_string(),
                "-sV".to_string(),
                "-Pn".to_string(),
            ]);
        }
        ScanMode::Udp => {
            args.push("--udp".to_string());
            args.push("-r".to_string());
            args.push(
                request
                    .ports
                    .clone()
                    .unwrap_or_else(|| defaults::FULL_RANGE.to_string()),
            );
        }
    }

    if let Some(dns) = request.dns {
        args.push("--resolver".to_string());
        args.push(dns.to_string());
    }
    if let Some(batch) = request.batch_size {
        args.push("--batch-size".to_string());
        args.push(batch.to_string());
    }
    if let Some(timeout) = request.timeout_ms {
        args.push("--timeout".to_string());
        args.push(timeout.to_string());
    }

    args.push("-a".to_string());
    args.push(request.target.to_string());

    if let Some(nmap_args) = nmap_phase {
        validate_nmap_args(&nmap_args)?;
        args.push("--".to_string());
        args.extend(nmap_args);
    }

    Ok(args)
}

fn require_ports(request: &ScanArgs) -> Result<String, AppError> {
    request
        .ports
        .clone()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| AppError::Config("this scan type requires a port list".to_string()))
}

/// Reject any nmap argument outside the reconnaissance allowlist.
pub fn validate_nmap_args(args: &[String]) -> Result<(), AppError> {
    let joined = args.join(" ").to_ascii_lowercase();
    for fragment in FORBIDDEN_FRAGMENTS {
        if joined.contains(fragment) {
            return Err(AppError::Config(format!(
                "forbidden reconnaissance argument '{fragment}' (exploitation and third-party tools are out of scope)"
            )));
        }
    }

    let mut index = 0;
    while index < args.len() {
        if args[index] == "--script" {
            let value = args
                .get(index + 1)
                .ok_or_else(|| AppError::Config("--script requires a value".to_string()))?;
            if !ALLOWED_SCRIPT_CATEGORIES.contains(&value.as_str()) {
                return Err(AppError::Config(format!(
                    "script category '{value}' is not allowed during reconnaissance"
                )));
            }
        }
        index += 1;
    }

    Ok(())
}

//! Guidance mode: built-in reconnaissance suggestions derived from a quick scan.
//!
//! No external enumeration tools are ever invoked; suggestions are advisory text.

use crate::model::error::AppError;
use crate::model::run::PhaseRecord;
use crate::model::scan_mode::ScanMode;

use super::super::Executor;

pub fn run(exec: &mut Executor) -> Result<(), AppError> {
    let args = exec.args(ScanMode::Guidance, exec.config.extra_ports.clone())?;
    let status = exec.run_scan(&args)?;

    exec.phases.push(PhaseRecord::completed(
        "guidance-scan",
        Some(format!("exit status {status}")),
    ));

    if exec.findings.is_empty() {
        exec.note("No open ports in the scanned range; nothing to suggest.");
        return Ok(());
    }

    let mut ports: Vec<u16> = exec
        .findings
        .iter()
        .filter_map(|finding| finding.port)
        .collect();
    ports.sort_unstable();
    ports.dedup();

    exec.note("Built-in reconnaissance suggestions (no external tools are invoked):");
    for port in ports {
        exec.note(&suggest(port));
    }

    Ok(())
}

fn suggest(port: u16) -> String {
    match port {
        21 => "FTP (21): check for anonymous login and banner version".to_string(),
        22 => "SSH (22): review the banner for version and supported auth methods".to_string(),
        80 | 8080 => {
            "HTTP: inspect response headers, default pages, and the server version".to_string()
        }
        443 => "HTTPS (443): review TLS configuration and the certificate subject".to_string(),
        139 | 445 => "SMB (139/445): review the SMB dialect and signing configuration (recon only)"
            .to_string(),
        3306 => "MySQL (3306): review the exposed version (recon only)".to_string(),
        3389 => "RDP (3389): review the exposed RDP configuration (recon only)".to_string(),
        other => {
            format!("port {other}: identify the service and review its version for known issues")
        }
    }
}

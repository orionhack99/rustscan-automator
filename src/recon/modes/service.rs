//! Service and version reconnaissance mode (User Story 2).

use crate::model::error::AppError;
use crate::model::run::PhaseRecord;
use crate::model::scan_mode::ScanMode;
use crate::scanner::dependency::{nmap_available, recon_skip_reason};

use super::super::{dedupe_findings, discovered_ports, fill_hosts, Executor};

pub fn run(exec: &mut Executor) -> Result<(), AppError> {
    let ports = match exec.config.extra_ports.clone() {
        Some(ports) => ports,
        None => {
            exec.emit("[*] no ports supplied; running a quick port discovery first");
            let discovery_args = exec.args(ScanMode::Port, None)?;
            exec.run_scan(&discovery_args)?;
            let ports = discovered_ports(&exec.findings).join(",");
            exec.findings.clear();
            if ports.is_empty() {
                exec.emit("[*] no open ports to analyze");
                exec.phases.push(PhaseRecord::completed(
                    "service",
                    Some("no open ports".to_string()),
                ));
                return Ok(());
            }
            ports
        }
    };

    if let Some(reason) = recon_skip_reason(nmap_available()) {
        exec.emit(&format!("[!] {reason}"));
        exec.phases.push(PhaseRecord::skipped("service", reason));
        return Ok(());
    }

    let args = exec.args(ScanMode::Service, Some(ports))?;
    let status = exec.run_scan(&args)?;
    let host = exec.config.target.raw.clone();
    fill_hosts(exec, &host);
    dedupe_findings(exec);

    exec.phases.push(PhaseRecord::completed(
        "service",
        Some(format!("exit status {status}")),
    ));
    exec.emit(&format!(
        "[*] service reconnaissance complete ({} finding(s))",
        exec.findings.len()
    ));

    Ok(())
}

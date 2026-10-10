//! Network host-discovery mode (User Story 3).

use crate::model::error::AppError;
use crate::model::finding::Finding;
use crate::model::run::PhaseRecord;
use crate::model::scan_mode::ScanMode;

use super::super::Executor;

pub fn run(exec: &mut Executor) -> Result<(), AppError> {
    let args = exec.args(ScanMode::Network, exec.config.extra_ports.clone())?;
    let status = exec.run_scan(&args)?;

    // Collapse port findings into host-only liveness findings.
    let mut hosts: Vec<String> = Vec::new();
    for finding in &exec.findings {
        if !hosts.contains(&finding.host) {
            hosts.push(finding.host.clone());
        }
    }
    exec.findings = hosts
        .iter()
        .map(|host| Finding::host(host.clone()))
        .collect();

    exec.phases.push(PhaseRecord::completed(
        "network",
        Some(format!("{} live host(s)", exec.findings.len())),
    ));
    exec.emit(&format!(
        "[*] {} live host(s) discovered",
        exec.findings.len()
    ));

    let _ = status;
    Ok(())
}

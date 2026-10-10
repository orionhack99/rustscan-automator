//! Comprehensive workflow: full-range sweep then deep reconnaissance (User Story 4).

use crate::config::defaults;
use crate::model::error::AppError;
use crate::model::run::PhaseRecord;
use crate::model::scan_mode::ScanMode;
use crate::scanner::dependency::{nmap_available, recon_skip_reason};

use super::super::{dedupe_findings, discovered_ports, fill_hosts, record_failure, Executor};

pub fn run(exec: &mut Executor) -> Result<(), AppError> {
    // Phase 1: full-range port sweep.
    let discovered = match run_port_sweep(exec) {
        Ok(ports) => {
            exec.phases.push(PhaseRecord::completed(
                "full-port-sweep",
                Some(format!("{} open port(s)", ports.len())),
            ));
            ports
        }
        Err(error) => {
            record_failure(exec, "full-port-sweep", error);
            return Ok(());
        }
    };

    if discovered.is_empty() {
        exec.emit("[*] no ports found for deep reconnaissance");
        return Ok(());
    }

    let ports = discovered.join(",");

    // Phase 2: service/version reconnaissance (non-fatal on failure).
    if let Some(reason) = recon_skip_reason(nmap_available()) {
        exec.phases.push(PhaseRecord::skipped("service", reason));
    } else {
        match run_recon_phase(exec, ScanMode::Service, &ports) {
            Ok(()) => exec.phases.push(PhaseRecord::completed("service", None)),
            Err(error) => record_failure(exec, "service", error),
        }
    }

    // Phase 3: vulnerability reconnaissance (non-fatal on failure).
    if let Some(reason) = recon_skip_reason(nmap_available()) {
        exec.phases.push(PhaseRecord::skipped("vuln", reason));
    } else {
        match run_recon_phase(exec, ScanMode::Vuln, &ports) {
            Ok(()) => exec.phases.push(PhaseRecord::completed("vuln", None)),
            Err(error) => record_failure(exec, "vuln", error),
        }
    }

    Ok(())
}

fn run_port_sweep(exec: &mut Executor) -> Result<Vec<String>, AppError> {
    exec.findings.clear();
    let args = exec.args(ScanMode::Port, Some(defaults::FULL_RANGE.to_string()))?;
    exec.run_scan(&args)?;
    Ok(discovered_ports(&exec.findings))
}

fn run_recon_phase(exec: &mut Executor, mode: ScanMode, ports: &str) -> Result<(), AppError> {
    let args = exec.args(mode, Some(ports.to_string()))?;
    exec.run_scan(&args)?;
    let host = exec.config.target.raw.clone();
    fill_hosts(exec, &host);
    dedupe_findings(exec);
    Ok(())
}

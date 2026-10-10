//! UDP reconnaissance mode.

use crate::model::error::AppError;
use crate::model::finding::Protocol;
use crate::model::run::PhaseRecord;
use crate::model::scan_mode::ScanMode;

use super::super::{fill_hosts, Executor};

pub fn run(exec: &mut Executor) -> Result<(), AppError> {
    let args = exec.args(ScanMode::Udp, exec.config.extra_ports.clone())?;
    let status = exec.run_scan(&args)?;
    // Greppable output carries no protocol; UDP mode results are UDP by definition.
    for finding in &mut exec.findings {
        finding.protocol = Some(Protocol::Udp);
    }
    let host = exec.config.target.raw.clone();
    fill_hosts(exec, &host);

    exec.phases.push(PhaseRecord::completed(
        "udp",
        Some(format!("exit status {status}")),
    ));
    Ok(())
}

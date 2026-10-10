//! Port discovery mode (User Story 1).

use crate::model::error::AppError;
use crate::model::run::PhaseRecord;
use crate::model::scan_mode::ScanMode;

use super::super::Executor;

pub fn run(exec: &mut Executor) -> Result<(), AppError> {
    let args = exec.args(ScanMode::Port, exec.config.extra_ports.clone())?;
    let status = exec.run_scan(&args)?;

    exec.phases.push(PhaseRecord::completed(
        "port",
        Some(format!("exit status {status}")),
    ));

    if exec.findings.is_empty() {
        exec.emit("[*] no open ports found");
    } else {
        exec.emit(&format!(
            "[*] {} open port(s) discovered",
            exec.findings.len()
        ));
    }

    Ok(())
}

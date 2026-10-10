//! One orchestrator per scan mode.

pub mod comprehensive;
pub mod guidance;
pub mod network;
pub mod port;
pub mod service;
pub mod udp;
pub mod vuln;

use crate::model::error::AppError;
use crate::model::scan_mode::ScanMode;

use super::Executor;

/// Dispatch to the orchestrator for the configured mode.
pub fn dispatch(exec: &mut Executor) -> Result<(), AppError> {
    match exec.config.mode {
        ScanMode::Port => port::run(exec),
        ScanMode::Network => network::run(exec),
        ScanMode::Service => service::run(exec),
        ScanMode::Vuln => vuln::run(exec),
        ScanMode::Udp => udp::run(exec),
        ScanMode::Full => comprehensive::run(exec),
        ScanMode::Guidance => guidance::run(exec),
    }
}

//! External dependency resolution and privilege detection.

use std::env;
use std::path::{Path, PathBuf};

use crate::config::defaults;
use crate::model::error::AppError;
use crate::model::scan_mode::ScanMode;

/// Locate an executable by name on `PATH` (or by explicit path).
pub fn find_in_path(binary: &str) -> Option<PathBuf> {
    if binary.contains(std::path::MAIN_SEPARATOR) {
        let candidate = PathBuf::from(binary);
        return is_executable(&candidate).then_some(candidate);
    }

    let path = env::var_os("PATH")?;
    env::split_paths(&path)
        .map(|dir| dir.join(binary))
        .find(|candidate| is_executable(candidate))
}

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    path.is_file()
        && path
            .metadata()
            .map(|meta| meta.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
}

/// Resolve the RustScan binary, honoring an explicit `--static-rustscan` path.
pub fn resolve_rustscan(explicit: Option<&Path>) -> Result<PathBuf, AppError> {
    if let Some(path) = explicit {
        let as_str = path.to_string_lossy();
        return find_in_path(&as_str).ok_or_else(|| {
            AppError::Dependency(format!(
                "RustScan binary '{}' was not found or is not executable (pass --static-rustscan <path>)",
                path.display()
            ))
        });
    }

    find_in_path(defaults::RUSTSCAN_BIN).ok_or_else(|| {
        AppError::Dependency(
            "RustScan ('rustscan') was not found on PATH. Install it: https://github.com/RustScan/RustScan"
                .to_string(),
        )
    })
}

/// Whether nmap is available for the service/vuln reconnaissance phases.
pub fn nmap_available() -> bool {
    find_in_path(defaults::NMAP_BIN).is_some()
}

/// Reason a reconnaissance phase must be skipped, if any.
pub fn recon_skip_reason(nmap_present: bool) -> Option<&'static str> {
    (!nmap_present).then_some("nmap is not installed; service/version reconnaissance was skipped")
}

/// Effective user id on Linux, when it can be determined.
pub fn effective_uid() -> Option<u32> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

/// Reject privileged-only modes when elevation is unavailable.
pub fn ensure_privileges(mode: ScanMode) -> Result<(), AppError> {
    if mode.requires_privileges() {
        if let Some(uid) = effective_uid() {
            if uid != 0 {
                return Err(AppError::Privilege(format!(
                    "scan type '{}' requires elevated privileges; re-run with sudo",
                    mode.as_str()
                )));
            }
        }
    }
    Ok(())
}

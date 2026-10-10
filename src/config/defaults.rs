//! Default values for the tool.

use std::path::{Path, PathBuf};

/// Default output directory when `--output` is not supplied.
pub const DEFAULT_OUTPUT_DIR: &str = "rustscan-automator-output";

/// Ports probed by the network host-discovery mode.
pub const DISCOVERY_PORTS: &str = "21,22,23,25,53,80,110,139,143,443,445,3389,8080";

/// Full TCP port range used by full/comprehensive scans.
pub const FULL_RANGE: &str = "1-65535";

/// Top-ports range used by the guidance mode.
pub const TOP_RANGE: &str = "1-1000";

/// Default RustScan binary name.
pub const RUSTSCAN_BIN: &str = "rustscan";

/// Default nmap binary name (used for service/vuln reconnaissance).
pub const NMAP_BIN: &str = "nmap";

/// Resolve the output directory, applying the default when omitted.
pub fn resolve_output_dir(explicit: Option<&Path>) -> PathBuf {
    match explicit {
        Some(path) => path.to_path_buf(),
        None => PathBuf::from(DEFAULT_OUTPUT_DIR),
    }
}

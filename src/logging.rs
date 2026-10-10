//! Leveled logging setup.
//!
//! Diagnostics go to stderr so they never pollute the machine-readable stdout
//! stream. The default level is `warn`; set `RUST_LOG` (e.g. `RUST_LOG=debug`)
//! to raise verbosity.

use tracing_subscriber::fmt;
use tracing_subscriber::EnvFilter;

/// Initialize the global tracing subscriber. Safe to call more than once.
pub fn init() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    let _ = fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

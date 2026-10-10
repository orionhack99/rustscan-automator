//! Shared domain model for the tool.

pub mod error;
pub mod finding;
pub mod run;
pub mod scan_mode;
pub mod target;

pub use error::AppError;
pub use finding::{Finding, PortState, Protocol};
pub use run::{PhaseRecord, PhaseStatus, RunConfiguration, RunCounts, RunSummary};
pub use scan_mode::ScanMode;
pub use target::{Target, TargetKind};

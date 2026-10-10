//! RustScan Recon Automator library surface.
//!
//! The library is organized in layers: `cli` parses arguments, `recon` orchestrates
//! scan modes, `scanner` is the boundary to the RustScan process, `report` persists
//! artifacts, and `model` holds the shared domain types.

pub mod cli;
pub mod config;
pub mod logging;
pub mod model;
pub mod recon;
pub mod report;
pub mod scanner;
pub mod util;

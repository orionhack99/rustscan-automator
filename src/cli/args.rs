//! Command-line argument definitions (see `contracts/cli.md`).

use std::path::PathBuf;

use clap::Parser;

/// Reconnaissance automation that orchestrates RustScan in place of nmap.
#[derive(Debug, Parser)]
#[command(
    name = "rustscan-automator",
    version,
    about = "Reconnaissance automation tool that uses RustScan in place of nmap",
    long_about = "Runs reconnaissance-only scans (network, port, service, vuln, udp, full/all, recon) \
by orchestrating the RustScan engine. Exploitation and third-party enumeration tools are out of scope."
)]
pub struct Cli {
    /// Target: single IP, hostname, or CIDR range.
    #[arg(short = 'H', long = "host", value_name = "TARGET")]
    pub host: String,

    /// Scan type: network, port, service, vuln, udp, full, all, recon.
    #[arg(short = 't', long = "type", value_name = "MODE")]
    pub scan_type: String,

    /// Output directory (default: ./rustscan-automator-output).
    #[arg(short = 'o', long = "output", value_name = "DIR")]
    pub output: Option<PathBuf>,

    /// DNS resolver to use for name resolution.
    #[arg(short = 'd', long = "dns", value_name = "SERVER")]
    pub dns: Option<String>,

    /// Explicit path to the RustScan binary.
    #[arg(short = 's', long = "static-rustscan", value_name = "PATH")]
    pub static_rustscan: Option<PathBuf>,

    /// Explicit comma-separated ports for discovery modes.
    #[arg(long = "ports", value_name = "LIST", conflicts_with = "ports_file")]
    pub ports: Option<String>,

    /// File with one port or range per line.
    #[arg(long = "ports-file", value_name = "PATH")]
    pub ports_file: Option<PathBuf>,

    /// Engine concurrency tuning (positive integer).
    #[arg(long = "batch-size", value_name = "N", value_parser = clap::value_parser!(u32).range(1..))]
    pub batch_size: Option<u32>,

    /// Per-port timeout in milliseconds (positive integer).
    #[arg(long = "timeout", value_name = "MS", value_parser = clap::value_parser!(u32).range(1..))]
    pub timeout: Option<u32>,

    /// Non-interactive mode; never prompt.
    #[arg(long = "yes")]
    pub yes: bool,

    /// Disable ANSI colors (also honors NO_COLOR).
    #[arg(long = "no-color")]
    pub no_color: bool,
}

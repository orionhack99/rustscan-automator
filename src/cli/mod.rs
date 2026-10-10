//! CLI entry point: parse arguments, build configuration, and run.

pub mod args;

use clap::Parser;

use crate::config::defaults;
use crate::model::error::AppError;
use crate::model::run::RunConfiguration;
use crate::model::scan_mode::ScanMode;
use crate::model::target::Target;
use crate::recon;
use crate::scanner::runner::ProcessRunner;

/// Parse process arguments, execute the scan, and report a summary.
pub fn run() -> Result<(), AppError> {
    let cli = args::Cli::parse();
    let config = build_config(&cli)?;

    let runner = ProcessRunner;
    let summary = recon::execute(&config, &runner)?;

    println!(
        "[*] done: {} live host(s), {} open TCP port(s), {} identified service(s)",
        summary.counts.live_hosts,
        summary.counts.open_tcp_ports,
        summary.counts.identified_services
    );

    Ok(())
}

/// Translate parsed arguments into a validated run configuration.
pub fn build_config(cli: &args::Cli) -> Result<RunConfiguration, AppError> {
    let target = Target::parse(&cli.host)?;
    let mode = ScanMode::parse(&cli.scan_type)?;
    let extra_ports = resolve_ports(cli)?;
    let output_dir = defaults::resolve_output_dir(cli.output.as_deref());

    Ok(RunConfiguration {
        target,
        mode,
        output_dir,
        dns_server: cli.dns.clone(),
        rustscan_path: cli.static_rustscan.clone(),
        batch_size: cli.batch_size,
        timeout_ms: cli.timeout,
        extra_ports,
        interactive: !cli.yes,
        no_color: cli.no_color || std::env::var_os("NO_COLOR").is_some(),
    })
}

fn resolve_ports(cli: &args::Cli) -> Result<Option<String>, AppError> {
    if let Some(ports) = &cli.ports {
        return Ok(Some(ports.clone()));
    }

    if let Some(path) = &cli.ports_file {
        let content = std::fs::read_to_string(path).map_err(|error| {
            AppError::Config(format!(
                "cannot read ports file '{}': {error}",
                path.display()
            ))
        })?;
        let ports: Vec<String> = content
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_string)
            .collect();
        if ports.is_empty() {
            return Err(AppError::Config(format!(
                "ports file '{}' is empty",
                path.display()
            )));
        }
        return Ok(Some(ports.join(",")));
    }

    Ok(None)
}

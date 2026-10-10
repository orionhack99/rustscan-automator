//! Scan-mode orchestration: validation, dependency checks, scanning, and reporting.

pub mod modes;

use std::collections::BTreeSet;
use std::path::PathBuf;

use crate::model::error::AppError;
use crate::model::finding::{Finding, Protocol};
use crate::model::run::{PhaseRecord, RunConfiguration, RunCounts, RunSummary};
use crate::model::scan_mode::ScanMode;
use crate::report::session_log::SessionLog;
use crate::report::summary;
use crate::report::writer::{self, OutputLayout};
use crate::scanner::command::{build_rustscan_args, ScanArgs};
use crate::scanner::{dependency, parser, service_parser};
use crate::util::utc_now_iso;

use crate::scanner::runner::CommandRunner;

/// Shared state threaded through a single run.
pub struct Executor<'a> {
    pub config: &'a RunConfiguration,
    pub runner: &'a dyn CommandRunner,
    pub rustscan: PathBuf,
    pub session: &'a mut SessionLog,
    pub findings: Vec<Finding>,
    pub warnings: usize,
    pub phases: Vec<PhaseRecord>,
    pub failures: Vec<String>,
    pub notes: Vec<String>,
}

impl<'a> Executor<'a> {
    pub fn new(
        config: &'a RunConfiguration,
        runner: &'a dyn CommandRunner,
        rustscan: PathBuf,
        session: &'a mut SessionLog,
    ) -> Self {
        Self {
            config,
            runner,
            rustscan,
            session,
            findings: Vec::new(),
            warnings: 0,
            phases: Vec::new(),
            failures: Vec::new(),
            notes: Vec::new(),
        }
    }

    /// Print a line to the console and the session log.
    pub fn emit(&mut self, line: &str) {
        println!("{line}");
        self.session.log(line);
    }

    /// Record and print a guidance note.
    pub fn note(&mut self, line: &str) {
        self.notes.push(line.to_string());
        self.emit(&format!("[i] {line}"));
    }

    /// Build the RustScan arguments for a mode.
    pub fn args(&self, mode: ScanMode, ports: Option<String>) -> Result<Vec<String>, AppError> {
        build_rustscan_args(&ScanArgs {
            mode,
            target: &self.config.target.raw,
            ports,
            dns: self.config.dns_server.as_deref(),
            batch_size: self.config.batch_size,
            timeout_ms: self.config.timeout_ms,
        })
    }

    /// Run a RustScan invocation, streaming and parsing each output line.
    pub fn run_scan(&mut self, args: &[String]) -> Result<i32, AppError> {
        tracing::debug!(program = %self.rustscan.display(), args = ?args, "invoking engine");
        self.emit(&format!(
            "[*] {} {}",
            self.rustscan.display(),
            args.join(" ")
        ));

        let program = self.rustscan.clone();
        let parse_service = matches!(
            self.config.mode,
            ScanMode::Service | ScanMode::Vuln | ScanMode::Udp
        );

        let runner = self.runner;
        let session = &mut *self.session;
        let findings = &mut self.findings;
        let warnings = &mut self.warnings;

        let status = runner.run(&program.to_string_lossy(), args, &mut |line| {
            println!("{line}");
            session.log(line);

            let parsed = if parse_service {
                service_parser::parse_service_line(line)
            } else {
                None
            };

            if let Some(finding) = parsed {
                findings.push(finding);
                return;
            }

            let greppable = parser::parse_greppable_lines(line);
            if greppable.is_empty() {
                if parser::looks_like_finding(line) {
                    *warnings += 1;
                }
            } else {
                findings.extend(greppable);
            }
        })?;

        if status != 0 {
            return Err(AppError::Scan(format!(
                "rustscan exited with status {status}"
            )));
        }

        Ok(status)
    }
}

/// Execute a full run and return the consolidated summary.
pub fn execute(
    config: &RunConfiguration,
    runner: &dyn CommandRunner,
) -> Result<RunSummary, AppError> {
    dependency::ensure_privileges(config.mode)?;
    let rustscan = dependency::resolve_rustscan(config.rustscan_path.as_deref())?;

    let layout = OutputLayout::create(&config.output_dir, &config.target.label)?;
    let session_path = layout.session_path();
    let mut session = SessionLog::create(session_path.clone())?;

    let started_at = utc_now_iso();

    let mut exec = Executor::new(config, runner, rustscan.clone(), &mut session);
    tracing::debug!(
        target = %config.target.raw,
        mode = config.mode.as_str(),
        engine = %rustscan.display(),
        "starting reconnaissance run"
    );
    exec.emit(&format!("[*] target: {}", config.target.raw));
    exec.emit(&format!("[*] mode: {}", config.mode.as_str()));
    exec.emit(&format!("[*] engine: {}", rustscan.display()));

    let dispatch_result = modes::dispatch(&mut exec);

    let finished_at = utc_now_iso();
    let findings = exec.findings.clone();
    let warnings = exec.warnings;
    let notes = exec.notes.clone();
    let phases = exec.phases.clone();
    let failures = exec.failures.clone();
    let counts = counts(&findings);

    let artifacts = writer::write_mode_result(
        &layout,
        config.mode,
        &findings,
        &config.target.raw,
        &started_at,
        &finished_at,
        warnings,
        &notes,
    )?;

    let summary_json_path = layout.summary_path("json");
    let summary_text_path = layout.summary_path("txt");

    let mut artifact_paths: Vec<String> = artifacts
        .iter()
        .map(|path| path.display().to_string())
        .collect();
    artifact_paths.push(session_path.display().to_string());
    artifact_paths.push(summary_json_path.display().to_string());
    artifact_paths.push(summary_text_path.display().to_string());

    let summary = RunSummary {
        target: config.target.raw.clone(),
        mode: config.mode.as_str().to_string(),
        started_at,
        finished_at,
        phases,
        counts,
        failures,
        artifacts: artifact_paths,
    };

    summary::write_summary(&summary_json_path, &summary_text_path, &summary)?;
    exec.session.flush();
    exec.emit(&format!(
        "[*] summary written to {}",
        summary_text_path.display()
    ));

    dispatch_result?;
    Ok(summary)
}

/// Collect the unique open-port numbers from findings, sorted ascending.
pub(crate) fn discovered_ports(findings: &[Finding]) -> Vec<String> {
    let mut ports: Vec<u16> = findings.iter().filter_map(|finding| finding.port).collect();
    ports.sort_unstable();
    ports.dedup();
    ports.into_iter().map(|port| port.to_string()).collect()
}

/// Backfill findings produced by the nmap handoff, which omit the host.
pub(crate) fn fill_hosts(exec: &mut Executor, host: &str) {
    for finding in &mut exec.findings {
        if finding.host.is_empty() {
            finding.host = host.to_string();
        }
    }
}

/// Merge findings that describe the same host/port/protocol.
///
/// RustScan emits a `host -> [ports]` line before the nmap handoff and nmap
/// then reports the same ports with service details, so the annotated entry
/// must win.
pub(crate) fn dedupe_findings(exec: &mut Executor) {
    let mut merged: Vec<Finding> = Vec::new();

    for finding in exec.findings.drain(..) {
        match merged.iter_mut().find(|existing| {
            existing.host == finding.host
                && existing.port == finding.port
                && existing.protocol == finding.protocol
        }) {
            Some(existing) => {
                if existing.service.is_none() && finding.service.is_some() {
                    *existing = finding;
                } else if existing.version.is_none() && finding.version.is_some() {
                    existing.version = finding.version;
                }
            }
            None => merged.push(finding),
        }
    }

    exec.findings = merged;
}

/// Record a non-fatal phase failure.
pub(crate) fn record_failure(exec: &mut Executor, phase: &str, error: AppError) {
    let message = format!("{phase} failed: {error}");
    exec.failures.push(message.clone());
    exec.phases
        .push(PhaseRecord::failed(phase, message.clone()));
    exec.emit(&format!("[!] {message}"));
}

fn counts(findings: &[Finding]) -> RunCounts {
    let mut hosts: BTreeSet<String> = BTreeSet::new();
    let mut open_tcp_ports = 0;
    let mut open_udp_ports = 0;
    let mut identified_services = 0;

    for finding in findings {
        hosts.insert(finding.host.clone());
        match finding.protocol {
            Some(Protocol::Tcp) => open_tcp_ports += 1,
            Some(Protocol::Udp) => open_udp_ports += 1,
            None => {}
        }
        if finding
            .service
            .as_deref()
            .map(|service| service != "unknown")
            .unwrap_or(false)
        {
            identified_services += 1;
        }
    }

    RunCounts {
        live_hosts: hosts.len(),
        open_tcp_ports,
        open_udp_ports,
        identified_services,
    }
}

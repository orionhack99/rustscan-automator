//! Shared hermetic test double for the RustScan process boundary.
//!
//! Tests never touch a live network: they inject [`FakeRunner`] into
//! `recon::execute`, which replays canned output lines instead of spawning a
//! real RustScan process.

#![allow(dead_code)]

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Mutex;

use rustscan_automator::model::error::AppError;
use rustscan_automator::model::run::RunConfiguration;
use rustscan_automator::model::scan_mode::ScanMode;
use rustscan_automator::model::target::Target;
use rustscan_automator::scanner::runner::CommandRunner;

/// A single scripted process result.
struct Response {
    status: i32,
    lines: Vec<String>,
}

/// A [`CommandRunner`] that replays scripted responses and records its calls.
pub struct FakeRunner {
    responses: Mutex<VecDeque<Response>>,
    fallback: Response,
    calls: Mutex<Vec<Vec<String>>>,
}

impl FakeRunner {
    /// A runner that always returns the same lines with exit status 0.
    pub fn new(lines: &[&str]) -> Self {
        Self::with_status(0, lines)
    }

    /// A runner with an explicit default status and lines.
    pub fn with_status(status: i32, lines: &[&str]) -> Self {
        Self {
            responses: Mutex::new(VecDeque::new()),
            fallback: Response {
                status,
                lines: lines.iter().map(|line| line.to_string()).collect(),
            },
            calls: Mutex::new(Vec::new()),
        }
    }

    /// Queue a response consumed (FIFO) before the default.
    pub fn queue(mut self, status: i32, lines: &[&str]) -> Self {
        self.responses.get_mut().unwrap().push_back(Response {
            status,
            lines: lines.iter().map(|line| line.to_string()).collect(),
        });
        self
    }

    /// The argument vectors passed to each `run` call, in order.
    pub fn calls(&self) -> Vec<Vec<String>> {
        self.calls.lock().unwrap().clone()
    }
}

impl CommandRunner for FakeRunner {
    fn run(
        &self,
        _program: &str,
        args: &[String],
        on_line: &mut dyn FnMut(&str),
    ) -> Result<i32, AppError> {
        self.calls.lock().unwrap().push(args.to_vec());

        let response = self
            .responses
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| Response {
                status: self.fallback.status,
                lines: self.fallback.lines.clone(),
            });

        for line in &response.lines {
            on_line(line);
        }

        Ok(response.status)
    }
}

/// Build a hermetic run configuration for `mode` writing into `output`.
///
/// `rustscan_path` points at the current test executable: it always exists and
/// is executable, so dependency resolution succeeds without requiring a real
/// RustScan installation (nothing is actually spawned under `FakeRunner`).
pub fn config(mode: ScanMode, output: PathBuf) -> RunConfiguration {
    let target = Target::parse("10.0.0.5").expect("valid test target");
    RunConfiguration {
        target,
        mode,
        output_dir: output,
        dns_server: None,
        rustscan_path: Some(std::env::current_exe().expect("test exe path")),
        batch_size: None,
        timeout_ms: None,
        extra_ports: None,
        interactive: false,
        no_color: true,
    }
}

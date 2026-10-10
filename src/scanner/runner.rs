//! Process execution boundary. Production uses [`ProcessRunner`]; tests inject a fake.

use std::io::{BufRead, BufReader, ErrorKind};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;

use crate::model::error::AppError;

/// Abstraction over running the RustScan binary.
///
/// Implementations must stream every output line to `on_line` as it becomes
/// available and return the child's exit status.
pub trait CommandRunner: Send + Sync {
    fn run(
        &self,
        program: &str,
        args: &[String],
        on_line: &mut dyn FnMut(&str),
    ) -> Result<i32, AppError>;
}

/// The real runner: spawns a child process and streams stdout/stderr.
pub struct ProcessRunner;

impl CommandRunner for ProcessRunner {
    fn run(
        &self,
        program: &str,
        args: &[String],
        on_line: &mut dyn FnMut(&str),
    ) -> Result<i32, AppError> {
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| match error.kind() {
                ErrorKind::NotFound => {
                    AppError::Dependency(format!("'{program}' was not found or is not executable"))
                }
                ErrorKind::PermissionDenied => AppError::Privilege(format!(
                    "'{program}' could not be executed (permission denied)"
                )),
                _ => AppError::Scan(format!("failed to start '{program}': {error}")),
            })?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| AppError::Scan("failed to capture child stdout".to_string()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| AppError::Scan("failed to capture child stderr".to_string()))?;

        let (sender, receiver) = mpsc::channel::<String>();
        let stderr_sender = sender.clone();

        let stdout_thread = thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                let _ = sender.send(line);
            }
        });
        let stderr_thread = thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                let _ = stderr_sender.send(line);
            }
        });

        for line in receiver {
            on_line(&line);
        }

        let _ = stdout_thread.join();
        let _ = stderr_thread.join();

        let status = child
            .wait()
            .map_err(|error| AppError::Scan(format!("failed to wait for '{program}': {error}")))?;

        Ok(status.code().unwrap_or(1))
    }
}

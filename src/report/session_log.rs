//! Session log: a byte-for-byte tee of everything written to the console.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::model::error::AppError;

/// A write-through log file for the current run.
pub struct SessionLog {
    path: PathBuf,
    file: File,
}

impl SessionLog {
    /// Create (or truncate) the session log at `path`.
    pub fn create(path: PathBuf) -> Result<Self, AppError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                AppError::Config(format!(
                    "cannot create output directory '{}': {error}",
                    parent.display()
                ))
            })?;
        }

        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .map_err(|error| {
                AppError::Config(format!(
                    "cannot open session log '{}': {error}",
                    path.display()
                ))
            })?;

        Ok(Self { path, file })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append a line to the log and flush it immediately so partial results
    /// survive abrupt termination (e.g. Ctrl-C).
    pub fn log(&mut self, line: &str) {
        let _ = writeln!(self.file, "{line}");
        let _ = self.file.flush();
    }

    /// Flush buffered content (called on completion and interruption).
    pub fn flush(&mut self) {
        let _ = self.file.flush();
    }
}

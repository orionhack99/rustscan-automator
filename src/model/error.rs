//! Typed application errors with a fixed mapping to process exit codes.

/// Exit codes defined in `contracts/cli.md`.
pub const EXIT_SUCCESS: i32 = 0;
pub const EXIT_RUNTIME: i32 = 1;
pub const EXIT_INVALID_INPUT: i32 = 2;
pub const EXIT_MISSING_DEPENDENCY: i32 = 3;
pub const EXIT_PRIVILEGE_REQUIRED: i32 = 4;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    /// Invalid user input (bad target, unknown mode, conflicting options).
    #[error("invalid input: {0}")]
    Config(String),

    /// A required external binary is missing or not executable.
    #[error("missing dependency: {0}")]
    Dependency(String),

    /// The selected scan mode needs elevated privileges that are unavailable.
    #[error("privilege required: {0}")]
    Privilege(String),

    /// A scan phase failed.
    #[error("scan failed: {0}")]
    Scan(String),

    /// Output could not be parsed.
    #[error("parse error: {0}")]
    Parse(String),

    /// Any other error surfaced from lower layers.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl AppError {
    /// Map the error to the documented process exit code.
    pub fn exit_code(&self) -> i32 {
        match self {
            AppError::Config(_) => EXIT_INVALID_INPUT,
            AppError::Dependency(_) => EXIT_MISSING_DEPENDENCY,
            AppError::Privilege(_) => EXIT_PRIVILEGE_REQUIRED,
            AppError::Scan(_) | AppError::Parse(_) | AppError::Other(_) => EXIT_RUNTIME,
        }
    }
}

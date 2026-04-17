pub mod ansi;
pub mod dedup;
pub mod prompt_injection;
pub mod stderr_only;
pub mod truncate;

/// Result of applying a single filter.
#[derive(Debug, Clone)]
pub struct FilterResult {
    pub stdout: String,
    pub stderr: String,
    /// Whether the filter actually modified the output.
    pub modified: bool,
    /// Human-readable note about what changed (e.g., "stripped 42 ANSI sequences").
    pub note: Option<String>,
}

/// Trait for output filters. Implementations must not panic.
pub trait OutputFilter: Send + Sync {
    /// Unique name for logging/stats.
    fn name(&self) -> &'static str;

    /// Whether this filter should run for the given context.
    /// `command` is the Bash command string (empty for non-Bash tools).
    fn applies_to(&self, command: &str, exit_code: Option<i32>) -> bool;

    /// Apply the filter, returning the transformed output.
    fn filter(&self, stdout: &str, stderr: &str, exit_code: Option<i32>) -> FilterResult;
}

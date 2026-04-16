use super::{FilterResult, OutputFilter};

/// When a command fails (exit_code != 0) and stderr is non-empty,
/// discard stdout and return only stderr. Falls back to stdout if stderr is empty.
pub struct StderrOnlyFilter;

impl OutputFilter for StderrOnlyFilter {
    fn name(&self) -> &'static str {
        "stderr_only"
    }

    fn applies_to(&self, _command: &str, exit_code: Option<i32>) -> bool {
        match exit_code {
            Some(code) => code != 0,
            None => false,
        }
    }

    fn filter(&self, stdout: &str, stderr: &str, _exit_code: Option<i32>) -> FilterResult {
        // Only discard stdout if stderr has meaningful content
        let stderr_trimmed = stderr.trim();
        if stderr_trimmed.is_empty() {
            return FilterResult {
                stdout: stdout.to_string(),
                stderr: stderr.to_string(),
                modified: false,
                note: None,
            };
        }

        let stdout_chars = stdout.len();
        FilterResult {
            stdout: String::new(),
            stderr: stderr.to_string(),
            modified: !stdout.is_empty(),
            note: if !stdout.is_empty() {
                Some(format!(
                    "discarded {} stdout chars on failure",
                    stdout_chars
                ))
            } else {
                None
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discards_stdout_on_failure() {
        let result = StderrOnlyFilter.filter(
            "lots of build output here...",
            "error: compilation failed",
            Some(1),
        );
        assert!(result.stdout.is_empty());
        assert_eq!(result.stderr, "error: compilation failed");
        assert!(result.modified);
        assert!(result.note.unwrap().contains("discarded"));
    }

    #[test]
    fn test_keeps_stdout_when_stderr_empty() {
        let result = StderrOnlyFilter.filter("some output", "", Some(1));
        assert_eq!(result.stdout, "some output");
        assert!(!result.modified);
    }

    #[test]
    fn test_not_applicable_on_success() {
        assert!(!StderrOnlyFilter.applies_to("ls", Some(0)));
    }

    #[test]
    fn test_applicable_on_failure() {
        assert!(StderrOnlyFilter.applies_to("cargo build", Some(1)));
        assert!(StderrOnlyFilter.applies_to("npm test", Some(2)));
    }

    #[test]
    fn test_not_applicable_when_no_exit_code() {
        assert!(!StderrOnlyFilter.applies_to("ls", None));
    }
}

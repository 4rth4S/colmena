use std::sync::OnceLock;

use regex::Regex;

use super::{FilterResult, OutputFilter};

static ANSI_RE: OnceLock<Regex> = OnceLock::new();

fn ansi_regex() -> &'static Regex {
    ANSI_RE.get_or_init(|| {
        // Matches CSI sequences, OSC sequences, and simple escape sequences
        Regex::new(r"\x1b\[[0-9;]*[a-zA-Z]|\x1b\][^\x07]*\x07|\x1b\[[\d;]*m").unwrap()
    })
}

/// Strips ANSI escape sequences from output.
pub struct AnsiStripFilter;

impl OutputFilter for AnsiStripFilter {
    fn name(&self) -> &'static str {
        "ansi_strip"
    }

    fn applies_to(&self, _command: &str, _exit_code: Option<i32>) -> bool {
        true
    }

    fn filter(&self, stdout: &str, stderr: &str, _exit_code: Option<i32>) -> FilterResult {
        let re = ansi_regex();
        let new_stdout = re.replace_all(stdout, "");
        let new_stderr = re.replace_all(stderr, "");

        let stdout_changed = new_stdout.len() != stdout.len();
        let stderr_changed = new_stderr.len() != stderr.len();
        let modified = stdout_changed || stderr_changed;

        let chars_removed =
            (stdout.len() - new_stdout.len()) + (stderr.len() - new_stderr.len());

        FilterResult {
            stdout: new_stdout.into_owned(),
            stderr: new_stderr.into_owned(),
            modified,
            note: if modified {
                Some(format!("stripped {} ANSI chars", chars_removed))
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
    fn test_strips_color_codes() {
        let input = "\x1b[31merror\x1b[0m: something failed";
        let result = AnsiStripFilter.filter(input, "", None);
        assert_eq!(result.stdout, "error: something failed");
        assert!(result.modified);
        assert!(result.note.unwrap().contains("stripped"));
    }

    #[test]
    fn test_no_ansi_passthrough() {
        let input = "clean output";
        let result = AnsiStripFilter.filter(input, "", None);
        assert_eq!(result.stdout, "clean output");
        assert!(!result.modified);
        assert!(result.note.is_none());
    }

    #[test]
    fn test_strips_from_stderr_too() {
        let result = AnsiStripFilter.filter("", "\x1b[1mbold\x1b[0m", None);
        assert_eq!(result.stderr, "bold");
        assert!(result.modified);
    }

    #[test]
    fn test_applies_to_everything() {
        assert!(AnsiStripFilter.applies_to("ls", Some(0)));
        assert!(AnsiStripFilter.applies_to("", None));
    }
}

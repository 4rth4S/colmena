use super::{FilterResult, OutputFilter};

/// Truncates output that exceeds line or character limits,
/// preserving the start and end for context.
pub struct TruncateFilter {
    pub max_lines: usize,
    pub max_chars: usize,
}

impl TruncateFilter {
    pub fn new(max_lines: usize, max_chars: usize) -> Self {
        Self { max_lines, max_chars }
    }
}

impl OutputFilter for TruncateFilter {
    fn name(&self) -> &'static str {
        "truncate"
    }

    fn applies_to(&self, _command: &str, _exit_code: Option<i32>) -> bool {
        true
    }

    fn filter(&self, stdout: &str, stderr: &str, _exit_code: Option<i32>) -> FilterResult {
        let new_stdout = truncate_smart(stdout, self.max_lines, self.max_chars);
        let new_stderr = truncate_smart(stderr, self.max_lines, self.max_chars);

        let modified = new_stdout != stdout || new_stderr != stderr;
        let chars_saved =
            (stdout.len() + stderr.len()) - (new_stdout.len() + new_stderr.len());

        FilterResult {
            stdout: new_stdout,
            stderr: new_stderr,
            modified,
            note: if modified {
                Some(format!("truncated, saved {} chars", chars_saved))
            } else {
                None
            },
        }
    }
}

fn truncate_smart(input: &str, max_lines: usize, max_chars: usize) -> String {
    if input.is_empty() {
        return String::new();
    }

    let lines: Vec<&str> = input.lines().collect();

    // Apply line limit first
    let line_truncated = if lines.len() > max_lines {
        let keep_start = max_lines / 2;
        let keep_end = max_lines - keep_start;
        let omitted = lines.len() - keep_start - keep_end;

        let mut result = Vec::with_capacity(max_lines + 1);
        result.extend_from_slice(&lines[..keep_start]);
        result.push("");
        let marker = format!(
            "--- [colmena: truncated {} lines ({} total)] ---",
            omitted,
            lines.len()
        );
        // We'll insert marker as a special line
        let end_start = lines.len() - keep_end;
        let mut output = result.join("\n");
        output.push('\n');
        output.push_str(&marker);
        output.push('\n');
        output.push_str(&lines[end_start..].join("\n"));
        if input.ends_with('\n') {
            output.push('\n');
        }
        output
    } else {
        input.to_string()
    };

    // Apply character limit as hard cap
    if line_truncated.len() > max_chars {
        let keep_start = max_chars * 2 / 3;
        let keep_end = max_chars - keep_start - 80; // reserve space for marker

        let keep_end = keep_end.min(line_truncated.len().saturating_sub(keep_start));

        // Find safe UTF-8 boundaries
        let start_end = safe_char_boundary(&line_truncated, keep_start);
        let end_begin = safe_char_boundary(&line_truncated, line_truncated.len() - keep_end);

        let chars_omitted = end_begin - start_end;
        let marker = format!(
            "\n--- [colmena: truncated {} chars ({} total)] ---\n",
            chars_omitted,
            line_truncated.len()
        );

        let mut output = String::with_capacity(max_chars + 80);
        output.push_str(&line_truncated[..start_end]);
        output.push_str(&marker);
        output.push_str(&line_truncated[end_begin..]);
        output
    } else {
        line_truncated
    }
}

/// Find the nearest char boundary at or before `index`.
fn safe_char_boundary(s: &str, index: usize) -> usize {
    if index >= s.len() {
        return s.len();
    }
    let mut i = index;
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_truncation_small_output() {
        let input = "line1\nline2\nline3";
        let filter = TruncateFilter::new(150, 30_000);
        let result = filter.filter(input, "", None);
        assert!(!result.modified);
        assert_eq!(result.stdout, input);
    }

    #[test]
    fn test_line_truncation() {
        let lines: Vec<String> = (0..300).map(|i| format!("line {i}")).collect();
        let input = lines.join("\n");
        let filter = TruncateFilter::new(150, 100_000);
        let result = filter.filter(&input, "", None);
        assert!(result.modified);
        assert!(result.stdout.contains("[colmena: truncated"));
        assert!(result.stdout.contains("line 0")); // start preserved
        assert!(result.stdout.contains("line 299")); // end preserved
    }

    #[test]
    fn test_char_truncation() {
        let input = "x".repeat(50_000);
        let filter = TruncateFilter::new(1000, 30_000);
        let result = filter.filter(&input, "", None);
        assert!(result.modified);
        assert!(result.stdout.len() < 35_000); // under limit + marker
        assert!(result.stdout.contains("[colmena: truncated"));
    }

    #[test]
    fn test_empty_input() {
        let filter = TruncateFilter::new(150, 30_000);
        let result = filter.filter("", "", None);
        assert!(!result.modified);
    }

    #[test]
    fn test_utf8_safety() {
        // Emoji are multi-byte
        let input = "🔥".repeat(20_000);
        let filter = TruncateFilter::new(1000, 30_000);
        let result = filter.filter(&input, "", None);
        // Should not panic on char boundaries
        assert!(result.modified);
    }
}

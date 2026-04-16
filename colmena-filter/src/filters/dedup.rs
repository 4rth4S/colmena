use super::{FilterResult, OutputFilter};

/// Collapses consecutive runs of identical lines when they exceed a threshold.
pub struct DedupFilter {
    pub threshold: usize,
}

impl DedupFilter {
    pub fn new(threshold: usize) -> Self {
        Self {
            threshold: threshold.max(2),
        }
    }
}

impl OutputFilter for DedupFilter {
    fn name(&self) -> &'static str {
        "dedup"
    }

    fn applies_to(&self, _command: &str, _exit_code: Option<i32>) -> bool {
        true
    }

    fn filter(&self, stdout: &str, stderr: &str, _exit_code: Option<i32>) -> FilterResult {
        let new_stdout = dedup_lines(stdout, self.threshold);
        let new_stderr = dedup_lines(stderr, self.threshold);

        let modified = new_stdout != stdout || new_stderr != stderr;
        let lines_saved = stdout.lines().count() + stderr.lines().count()
            - new_stdout.lines().count()
            - new_stderr.lines().count();

        FilterResult {
            stdout: new_stdout,
            stderr: new_stderr,
            modified,
            note: if modified {
                Some(format!("collapsed {} duplicate lines", lines_saved))
            } else {
                None
            },
        }
    }
}

fn dedup_lines(input: &str, threshold: usize) -> String {
    if input.is_empty() {
        return String::new();
    }

    let lines: Vec<&str> = input.lines().collect();
    let mut result = Vec::with_capacity(lines.len());
    let mut i = 0;

    while i < lines.len() {
        let current = lines[i];

        // Count consecutive identical lines
        let mut run_len = 1;
        while i + run_len < lines.len() && lines[i + run_len] == current {
            run_len += 1;
        }

        if run_len >= threshold {
            result.push(current.to_string());
            result.push(format!("... ({} identical lines omitted)", run_len - 2));
            result.push(current.to_string());
            i += run_len;
        } else {
            for j in 0..run_len {
                result.push(lines[i + j].to_string());
            }
            i += run_len;
        }
    }

    // Preserve trailing newline if original had one
    let mut output = result.join("\n");
    if input.ends_with('\n') {
        output.push('\n');
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collapses_repeated_lines() {
        let input = "Downloading crate...\n\
                      Downloading crate...\n\
                      Downloading crate...\n\
                      Downloading crate...\n\
                      Downloading crate...\n\
                      Done.";
        let filter = DedupFilter::new(3);
        let result = filter.filter(input, "", None);
        assert!(result.modified);
        assert!(result.stdout.contains("(3 identical lines omitted)"));
        assert!(result.stdout.contains("Done."));
        // First and last of the run preserved
        assert!(result.stdout.starts_with("Downloading crate..."));
    }

    #[test]
    fn test_no_dedup_below_threshold() {
        let input = "line1\nline1\nline2";
        let filter = DedupFilter::new(3);
        let result = filter.filter(input, "", None);
        assert!(!result.modified);
        assert_eq!(result.stdout, input);
    }

    #[test]
    fn test_empty_input() {
        let filter = DedupFilter::new(3);
        let result = filter.filter("", "", None);
        assert!(!result.modified);
    }

    #[test]
    fn test_dedup_stderr() {
        let stderr = "warn: unused\nwarn: unused\nwarn: unused\nwarn: unused";
        let filter = DedupFilter::new(3);
        let result = filter.filter("", stderr, None);
        assert!(result.modified);
        assert!(result.stderr.contains("identical lines omitted"));
    }

    #[test]
    fn test_preserves_trailing_newline() {
        let input = "a\na\na\na\n";
        let filter = DedupFilter::new(3);
        let result = filter.filter(input, "", None);
        assert!(result.stdout.ends_with('\n'));
    }
}

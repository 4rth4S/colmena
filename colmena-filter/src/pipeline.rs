use std::panic;

use crate::config::FilterConfig;
use crate::filters::ansi::AnsiStripFilter;
use crate::filters::dedup::DedupFilter;
use crate::filters::prompt_injection::{PromptInjectionConfig, PromptInjectionFilter};
use crate::filters::stderr_only::StderrOnlyFilter;
use crate::filters::truncate::TruncateFilter;
use crate::filters::OutputFilter;

/// Result of running the full filter pipeline.
#[derive(Debug, Clone)]
pub struct PipelineResult {
    /// Combined filtered output to return to CC.
    pub output: String,
    /// Whether any filter modified the output.
    pub modified: bool,
    /// Names of filters that actually modified the output.
    pub notes: Vec<String>,
    /// Original combined character count (stdout + stderr).
    pub original_chars: usize,
    /// Filtered combined character count.
    pub filtered_chars: usize,
}

/// Chains output filters in order, with panic safety per filter.
pub struct FilterPipeline {
    filters: Vec<Box<dyn OutputFilter>>,
}

impl FilterPipeline {
    /// Build a pipeline from config.
    /// Order: ANSI → StderrOnly → Dedup → PromptInjection → Truncate
    ///
    /// PromptInjection sits after the cleaning filters so it scans already
    /// ANSI-stripped / deduped content (real text an agent would see), and
    /// before Truncate so the warning banner is always visible even when
    /// the output gets capped.
    pub fn from_config(config: &FilterConfig) -> Self {
        let mut filters: Vec<Box<dyn OutputFilter>> = Vec::new();

        if config.strip_ansi {
            filters.push(Box::new(AnsiStripFilter));
        }

        if config.error_only_on_failure {
            filters.push(Box::new(StderrOnlyFilter));
        }

        filters.push(Box::new(DedupFilter::new(config.dedup_threshold)));
        filters.push(Box::new(PromptInjectionFilter::new(
            PromptInjectionConfig::default(),
        )));
        filters.push(Box::new(TruncateFilter::new(
            config.max_output_lines,
            config.max_output_chars,
        )));

        Self { filters }
    }

    /// Run all applicable filters in sequence.
    pub fn run(
        &self,
        stdout: &str,
        stderr: &str,
        command: &str,
        exit_code: Option<i32>,
    ) -> PipelineResult {
        let original_chars = stdout.len() + stderr.len();
        let mut current_stdout = stdout.to_string();
        let mut current_stderr = stderr.to_string();
        let mut modified = false;
        let mut notes = Vec::new();

        for filter in &self.filters {
            if !filter.applies_to(command, exit_code) {
                continue;
            }

            let filter_name = filter.name();

            // catch_unwind: a buggy filter must never crash the hook
            let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
                filter.filter(&current_stdout, &current_stderr, exit_code)
            }));

            match result {
                Ok(filter_result) => {
                    if filter_result.modified {
                        current_stdout = filter_result.stdout;
                        current_stderr = filter_result.stderr;
                        modified = true;
                        notes.push(filter_name.to_string());
                    }
                }
                Err(_) => {
                    // Filter panicked — skip it, continue with previous output
                    notes.push(format!("{filter_name}:PANICKED"));
                }
            }
        }

        // Combine output: stderr first (errors more important), then stdout
        let output = if current_stderr.is_empty() {
            current_stdout
        } else if current_stdout.is_empty() {
            current_stderr
        } else {
            format!("{}\n{}", current_stderr.trim_end(), current_stdout)
        };

        let filtered_chars = output.len();

        PipelineResult {
            output,
            modified,
            notes,
            original_chars,
            filtered_chars,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pipeline_from_default_config() {
        let config = FilterConfig::default();
        let pipeline = FilterPipeline::from_config(&config);
        // ANSI + StderrOnly + Dedup + PromptInjection + Truncate
        assert_eq!(pipeline.filters.len(), 5);
    }

    #[test]
    fn test_pipeline_strips_ansi_and_truncates() {
        let config = FilterConfig::default();
        let pipeline = FilterPipeline::from_config(&config);

        let stdout = "\x1b[32mOK\x1b[0m: test passed";
        let result = pipeline.run(stdout, "", "cargo test", Some(0));
        assert!(result.modified);
        assert_eq!(result.output, "OK: test passed");
        assert!(result.notes.contains(&"ansi_strip".to_string()));
    }

    #[test]
    fn test_pipeline_stderr_only_on_failure() {
        let config = FilterConfig::default();
        let pipeline = FilterPipeline::from_config(&config);

        let result = pipeline.run(
            "lots of stdout noise",
            "error: build failed",
            "cargo build",
            Some(1),
        );
        assert!(result.modified);
        // stderr_only should have discarded stdout
        assert!(result.output.contains("error: build failed"));
        assert!(!result.output.contains("lots of stdout noise"));
    }

    #[test]
    fn test_pipeline_passthrough_clean_output() {
        let config = FilterConfig {
            strip_ansi: false,
            error_only_on_failure: false,
            ..FilterConfig::default()
        };
        let pipeline = FilterPipeline::from_config(&config);

        let result = pipeline.run("short output", "", "ls", Some(0));
        assert!(!result.modified);
    }

    #[test]
    fn test_pipeline_disabled_filters() {
        let config = FilterConfig {
            strip_ansi: false,
            error_only_on_failure: false,
            ..FilterConfig::default()
        };
        let pipeline = FilterPipeline::from_config(&config);
        // Dedup + PromptInjection + Truncate
        assert_eq!(pipeline.filters.len(), 3);
    }

    #[test]
    fn test_pipeline_combines_stderr_stdout() {
        let config = FilterConfig {
            error_only_on_failure: false,
            strip_ansi: false,
            ..FilterConfig::default()
        };
        let pipeline = FilterPipeline::from_config(&config);

        let result = pipeline.run("stdout here", "stderr here", "cmd", Some(0));
        // stderr first, then stdout
        assert!(result.output.starts_with("stderr here"));
        assert!(result.output.contains("stdout here"));
    }
}

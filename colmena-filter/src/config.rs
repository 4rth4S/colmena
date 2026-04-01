use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};

fn default_max_output_lines() -> usize {
    150
}
fn default_max_output_chars() -> usize {
    30_000
}
fn default_dedup_threshold() -> usize {
    3
}
fn default_true() -> bool {
    true
}

/// Configuration for the output filter pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterConfig {
    #[serde(default = "default_max_output_lines")]
    pub max_output_lines: usize,
    #[serde(default = "default_max_output_chars")]
    pub max_output_chars: usize,
    #[serde(default = "default_dedup_threshold")]
    pub dedup_threshold: usize,
    #[serde(default = "default_true")]
    pub error_only_on_failure: bool,
    #[serde(default = "default_true")]
    pub strip_ansi: bool,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self {
            max_output_lines: default_max_output_lines(),
            max_output_chars: default_max_output_chars(),
            dedup_threshold: default_dedup_threshold(),
            error_only_on_failure: true,
            strip_ansi: true,
            enabled: true,
        }
    }
}

/// Load filter config from YAML. Returns defaults if file doesn't exist.
pub fn load_filter_config(path: &Path) -> Result<FilterConfig> {
    if !path.exists() {
        return Ok(FilterConfig::default());
    }
    let contents = std::fs::read_to_string(path)?;
    let config: FilterConfig = serde_yml::from_str(&contents)?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_defaults() {
        let config = FilterConfig::default();
        assert_eq!(config.max_output_lines, 150);
        assert_eq!(config.max_output_chars, 30_000);
        assert_eq!(config.dedup_threshold, 3);
        assert!(config.error_only_on_failure);
        assert!(config.strip_ansi);
        assert!(config.enabled);
    }

    #[test]
    fn test_load_missing_file() {
        let config = load_filter_config(Path::new("/nonexistent/filter.yaml")).unwrap();
        assert_eq!(config.max_output_lines, 150);
    }

    #[test]
    fn test_deserialize_partial_yaml() {
        let yaml = "max_output_lines: 200\nenabled: false\n";
        let config: FilterConfig = serde_yml::from_str(yaml).unwrap();
        assert_eq!(config.max_output_lines, 200);
        assert!(!config.enabled);
        // defaults for missing fields
        assert_eq!(config.max_output_chars, 30_000);
        assert!(config.strip_ansi);
    }
}

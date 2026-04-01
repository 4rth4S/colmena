use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A single filter stats event, logged as one JSONL line.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterStatsEvent {
    pub ts: DateTime<Utc>,
    pub session_id: String,
    pub tool_use_id: String,
    pub command_prefix: String,
    pub original_chars: usize,
    pub filtered_chars: usize,
    pub chars_saved: usize,
    pub filters_applied: Vec<String>,
}

/// Aggregated summary of filter stats.
#[derive(Debug)]
pub struct FilterStatsSummary {
    pub total_events: usize,
    pub total_chars_saved: usize,
    pub total_original_chars: usize,
    pub avg_reduction_pct: f64,
    pub top_commands: Vec<(String, usize)>,
}

/// Append a stats event to the JSONL log. Best-effort, never fails caller.
pub fn log_filter_stats(log_path: &Path, event: &FilterStatsEvent) -> std::io::Result<()> {
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let line = serde_json::to_string(event)?;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)?;
    writeln!(file, "{}", line)?;
    Ok(())
}

/// Read all stats events from JSONL. Skips malformed lines.
pub fn read_filter_stats(log_path: &Path) -> anyhow::Result<Vec<FilterStatsEvent>> {
    if !log_path.exists() {
        return Ok(Vec::new());
    }

    let file = std::fs::File::open(log_path)?;
    let reader = std::io::BufReader::new(file);
    let mut events = Vec::new();

    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(event) = serde_json::from_str::<FilterStatsEvent>(trimmed) {
            events.push(event);
        }
        // Silently skip malformed lines
    }

    Ok(events)
}

/// Aggregate stats for display.
pub fn summarize(events: &[FilterStatsEvent]) -> FilterStatsSummary {
    let total_events = events.len();
    let total_chars_saved: usize = events.iter().map(|e| e.chars_saved).sum();
    let total_original_chars: usize = events.iter().map(|e| e.original_chars).sum();

    let avg_reduction_pct = if total_original_chars > 0 {
        (total_chars_saved as f64 / total_original_chars as f64) * 100.0
    } else {
        0.0
    };

    // Top commands by chars saved
    let mut cmd_savings: HashMap<String, usize> = HashMap::new();
    for event in events {
        *cmd_savings.entry(event.command_prefix.clone()).or_default() += event.chars_saved;
    }
    let mut top_commands: Vec<(String, usize)> = cmd_savings.into_iter().collect();
    top_commands.sort_by(|a, b| b.1.cmp(&a.1));
    top_commands.truncate(10);

    FilterStatsSummary {
        total_events,
        total_chars_saved,
        total_original_chars,
        avg_reduction_pct,
        top_commands,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(cmd: &str, original: usize, filtered: usize) -> FilterStatsEvent {
        FilterStatsEvent {
            ts: Utc::now(),
            session_id: "test".to_string(),
            tool_use_id: "tu_001".to_string(),
            command_prefix: cmd.to_string(),
            original_chars: original,
            filtered_chars: filtered,
            chars_saved: original - filtered,
            filters_applied: vec!["ansi_strip".to_string()],
        }
    }

    #[test]
    fn test_jsonl_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stats.jsonl");

        let event = make_event("cargo build", 10000, 7000);
        log_filter_stats(&path, &event).unwrap();
        log_filter_stats(&path, &event).unwrap();

        let events = read_filter_stats(&path).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].command_prefix, "cargo build");
        assert_eq!(events[0].chars_saved, 3000);
    }

    #[test]
    fn test_read_missing_file() {
        let events = read_filter_stats(Path::new("/nonexistent/stats.jsonl")).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn test_summarize() {
        let events = vec![
            make_event("cargo build", 10000, 7000),
            make_event("git log", 5000, 2000),
            make_event("cargo build", 8000, 5000),
        ];
        let summary = summarize(&events);
        assert_eq!(summary.total_events, 3);
        assert_eq!(summary.total_chars_saved, 9000);
        assert_eq!(summary.total_original_chars, 23000);
        assert!(summary.avg_reduction_pct > 39.0 && summary.avg_reduction_pct < 40.0);
        assert_eq!(summary.top_commands[0].0, "cargo build");
        assert_eq!(summary.top_commands[0].1, 6000);
    }

    #[test]
    fn test_summarize_empty() {
        let summary = summarize(&[]);
        assert_eq!(summary.total_events, 0);
        assert_eq!(summary.avg_reduction_pct, 0.0);
    }
}

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A single finding within a review.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub category: String,
    pub severity: String,
    pub description: String,
    pub recommendation: String,
}

/// A complete finding record for one review.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingRecord {
    pub review_id: String,
    pub mission: String,
    pub author_role: String,
    pub reviewer_role: String,
    pub artifact_path: String,
    pub artifact_hash: String,
    pub timestamp: DateTime<Utc>,
    pub scores: HashMap<String, u32>,
    pub score_average: f64,
    pub findings: Vec<Finding>,
}

/// Filter criteria for querying findings.
#[derive(Debug, Clone, Default)]
pub struct FindingsFilter {
    pub author_role: Option<String>,
    pub reviewer_role: Option<String>,
    pub severity: Option<String>,
    pub category: Option<String>,
    pub mission: Option<String>,
    pub after: Option<DateTime<Utc>>,
    pub before: Option<DateTime<Utc>>,
    pub limit: Option<usize>,
}

/// Save a finding record to `findings_dir/<mission>/<review_id>.json`.
/// Creates directories as needed.
pub fn save_finding_record(findings_dir: &Path, record: &FindingRecord) -> Result<()> {
    let mission_dir = findings_dir.join(&record.mission);
    std::fs::create_dir_all(&mission_dir)
        .with_context(|| format!("creating findings dir {}", mission_dir.display()))?;

    let file_path = mission_dir.join(format!("{}.json", record.review_id));
    let json = serde_json::to_string_pretty(record)
        .context("serializing finding record")?;

    // Atomic write: temp + rename
    let tmp_path = mission_dir.join(format!(".{}.tmp", record.review_id));
    std::fs::write(&tmp_path, &json)
        .with_context(|| format!("writing temp file {}", tmp_path.display()))?;
    std::fs::rename(&tmp_path, &file_path)
        .with_context(|| format!("renaming {} -> {}", tmp_path.display(), file_path.display()))?;

    Ok(())
}

/// Load all finding records from `findings_dir`, apply filters, sort by timestamp DESC,
/// and apply limit.
pub fn load_findings(findings_dir: &Path, filter: &FindingsFilter) -> Result<Vec<FindingRecord>> {
    if !findings_dir.exists() {
        return Ok(Vec::new());
    }

    let mut records = Vec::new();

    // Iterate mission directories
    let entries = std::fs::read_dir(findings_dir)
        .with_context(|| format!("reading findings dir {}", findings_dir.display()))?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        // Iterate JSON files inside mission dir
        let files = std::fs::read_dir(&path)
            .with_context(|| format!("reading mission dir {}", path.display()))?;

        for file_entry in files {
            let file_entry = file_entry?;
            let file_path = file_entry.path();

            if file_path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }

            let content = std::fs::read_to_string(&file_path)
                .with_context(|| format!("reading {}", file_path.display()))?;

            match serde_json::from_str::<FindingRecord>(&content) {
                Ok(record) => {
                    if matches_filter(&record, filter) {
                        records.push(record);
                    }
                }
                Err(_) => {
                    // Skip malformed files silently
                    continue;
                }
            }
        }
    }

    // Sort by timestamp descending
    records.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

    // Apply limit
    if let Some(limit) = filter.limit {
        records.truncate(limit);
    }

    Ok(records)
}

/// Check if a record matches all filter criteria.
/// For severity/category: matches if ANY finding in the record matches.
fn matches_filter(record: &FindingRecord, filter: &FindingsFilter) -> bool {
    if let Some(ref author_role) = filter.author_role {
        if record.author_role != *author_role {
            return false;
        }
    }

    if let Some(ref reviewer_role) = filter.reviewer_role {
        if record.reviewer_role != *reviewer_role {
            return false;
        }
    }

    if let Some(ref mission) = filter.mission {
        if record.mission != *mission {
            return false;
        }
    }

    if let Some(ref severity) = filter.severity {
        if !record.findings.iter().any(|f| f.severity == *severity) {
            return false;
        }
    }

    if let Some(ref category) = filter.category {
        if !record.findings.iter().any(|f| f.category == *category) {
            return false;
        }
    }

    if let Some(after) = filter.after {
        if record.timestamp <= after {
            return false;
        }
    }

    if let Some(before) = filter.before {
        if record.timestamp >= before {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use tempfile::TempDir;

    fn make_finding(category: &str, severity: &str) -> Finding {
        Finding {
            category: category.to_string(),
            severity: severity.to_string(),
            description: format!("{} {} finding", severity, category),
            recommendation: "Fix it".to_string(),
        }
    }

    fn make_record(
        review_id: &str,
        mission: &str,
        author_role: &str,
        reviewer_role: &str,
        timestamp: DateTime<Utc>,
        findings: Vec<Finding>,
    ) -> FindingRecord {
        let mut scores = HashMap::new();
        scores.insert("correctness".to_string(), 7);
        scores.insert("security".to_string(), 8);
        FindingRecord {
            review_id: review_id.to_string(),
            mission: mission.to_string(),
            author_role: author_role.to_string(),
            reviewer_role: reviewer_role.to_string(),
            artifact_path: "src/main.rs".to_string(),
            artifact_hash: "abc123".to_string(),
            timestamp,
            scores,
            score_average: 7.5,
            findings,
        }
    }

    #[test]
    fn test_save_and_load_finding_record() {
        let tmp = TempDir::new().unwrap();
        let findings_dir = tmp.path().join("findings");
        let now = Utc::now();

        let record = make_record(
            "rev-001",
            "audit-payments",
            "coder",
            "pentester",
            now,
            vec![make_finding("injection", "high")],
        );

        save_finding_record(&findings_dir, &record).unwrap();

        let filter = FindingsFilter::default();
        let loaded = load_findings(&findings_dir, &filter).unwrap();

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].review_id, "rev-001");
        assert_eq!(loaded[0].mission, "audit-payments");
        assert_eq!(loaded[0].author_role, "coder");
        assert_eq!(loaded[0].reviewer_role, "pentester");
        assert_eq!(loaded[0].findings.len(), 1);
        assert_eq!(loaded[0].findings[0].severity, "high");
    }

    #[test]
    fn test_filter_by_severity() {
        let tmp = TempDir::new().unwrap();
        let findings_dir = tmp.path().join("findings");
        let now = Utc::now();

        let r1 = make_record(
            "rev-001", "m1", "coder", "pentester", now,
            vec![make_finding("injection", "critical")],
        );
        let r2 = make_record(
            "rev-002", "m1", "coder", "pentester", now - Duration::seconds(1),
            vec![make_finding("xss", "low")],
        );
        let r3 = make_record(
            "rev-003", "m1", "coder", "pentester", now - Duration::seconds(2),
            vec![
                make_finding("auth", "medium"),
                make_finding("injection", "critical"),
            ],
        );

        save_finding_record(&findings_dir, &r1).unwrap();
        save_finding_record(&findings_dir, &r2).unwrap();
        save_finding_record(&findings_dir, &r3).unwrap();

        let filter = FindingsFilter {
            severity: Some("critical".to_string()),
            ..Default::default()
        };
        let results = load_findings(&findings_dir, &filter).unwrap();

        assert_eq!(results.len(), 2);
        // Both rev-001 and rev-003 have critical findings
        let ids: Vec<&str> = results.iter().map(|r| r.review_id.as_str()).collect();
        assert!(ids.contains(&"rev-001"));
        assert!(ids.contains(&"rev-003"));
    }

    #[test]
    fn test_filter_by_author_role() {
        let tmp = TempDir::new().unwrap();
        let findings_dir = tmp.path().join("findings");
        let now = Utc::now();

        let r1 = make_record(
            "rev-001", "m1", "coder", "pentester", now,
            vec![make_finding("bug", "medium")],
        );
        let r2 = make_record(
            "rev-002", "m1", "architect", "pentester", now - Duration::seconds(1),
            vec![make_finding("design", "low")],
        );

        save_finding_record(&findings_dir, &r1).unwrap();
        save_finding_record(&findings_dir, &r2).unwrap();

        let filter = FindingsFilter {
            author_role: Some("coder".to_string()),
            ..Default::default()
        };
        let results = load_findings(&findings_dir, &filter).unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].review_id, "rev-001");
    }

    #[test]
    fn test_filter_by_mission() {
        let tmp = TempDir::new().unwrap();
        let findings_dir = tmp.path().join("findings");
        let now = Utc::now();

        let r1 = make_record(
            "rev-001", "audit-payments", "coder", "pentester", now,
            vec![make_finding("sqli", "high")],
        );
        let r2 = make_record(
            "rev-002", "audit-auth", "coder", "pentester", now - Duration::seconds(1),
            vec![make_finding("csrf", "medium")],
        );

        save_finding_record(&findings_dir, &r1).unwrap();
        save_finding_record(&findings_dir, &r2).unwrap();

        let filter = FindingsFilter {
            mission: Some("audit-payments".to_string()),
            ..Default::default()
        };
        let results = load_findings(&findings_dir, &filter).unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].review_id, "rev-001");
        assert_eq!(results[0].mission, "audit-payments");
    }

    #[test]
    fn test_filter_by_date_range() {
        let tmp = TempDir::new().unwrap();
        let findings_dir = tmp.path().join("findings");
        let now = Utc::now();

        let r1 = make_record(
            "rev-001", "m1", "coder", "pentester", now - Duration::hours(1),
            vec![make_finding("bug", "medium")],
        );
        let r2 = make_record(
            "rev-002", "m1", "coder", "pentester", now - Duration::days(3),
            vec![make_finding("bug", "low")],
        );
        let r3 = make_record(
            "rev-003", "m1", "coder", "pentester", now - Duration::days(10),
            vec![make_finding("bug", "high")],
        );

        save_finding_record(&findings_dir, &r1).unwrap();
        save_finding_record(&findings_dir, &r2).unwrap();
        save_finding_record(&findings_dir, &r3).unwrap();

        // Only records after 5 days ago
        let filter = FindingsFilter {
            after: Some(now - Duration::days(5)),
            ..Default::default()
        };
        let results = load_findings(&findings_dir, &filter).unwrap();

        assert_eq!(results.len(), 2);
        let ids: Vec<&str> = results.iter().map(|r| r.review_id.as_str()).collect();
        assert!(ids.contains(&"rev-001"));
        assert!(ids.contains(&"rev-002"));
        assert!(!ids.contains(&"rev-003"));
    }

    #[test]
    fn test_filter_with_limit() {
        let tmp = TempDir::new().unwrap();
        let findings_dir = tmp.path().join("findings");
        let now = Utc::now();

        for i in 0..5 {
            let record = make_record(
                &format!("rev-{:03}", i),
                "m1",
                "coder",
                "pentester",
                now - Duration::seconds(i as i64),
                vec![make_finding("bug", "medium")],
            );
            save_finding_record(&findings_dir, &record).unwrap();
        }

        let filter = FindingsFilter {
            limit: Some(2),
            ..Default::default()
        };
        let results = load_findings(&findings_dir, &filter).unwrap();

        assert_eq!(results.len(), 2);
        // Should be the 2 most recent (sorted DESC)
        assert_eq!(results[0].review_id, "rev-000");
        assert_eq!(results[1].review_id, "rev-001");
    }

    #[test]
    fn test_empty_findings_dir() {
        let tmp = TempDir::new().unwrap();
        let findings_dir = tmp.path().join("nonexistent-findings");

        let filter = FindingsFilter::default();
        let results = load_findings(&findings_dir, &filter).unwrap();

        assert!(results.is_empty());
    }

    #[test]
    fn test_filter_by_category() {
        let tmp = TempDir::new().unwrap();
        let findings_dir = tmp.path().join("findings");
        let now = Utc::now();

        let r1 = make_record(
            "rev-001", "m1", "coder", "pentester", now,
            vec![make_finding("injection", "high")],
        );
        let r2 = make_record(
            "rev-002", "m1", "coder", "pentester", now - Duration::seconds(1),
            vec![make_finding("xss", "medium")],
        );

        save_finding_record(&findings_dir, &r1).unwrap();
        save_finding_record(&findings_dir, &r2).unwrap();

        let filter = FindingsFilter {
            category: Some("injection".to_string()),
            ..Default::default()
        };
        let results = load_findings(&findings_dir, &filter).unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].review_id, "rev-001");
    }

    #[test]
    fn test_results_sorted_by_timestamp_desc() {
        let tmp = TempDir::new().unwrap();
        let findings_dir = tmp.path().join("findings");
        let now = Utc::now();

        // Save in non-chronological order
        let r2 = make_record(
            "rev-002", "m1", "coder", "pentester", now - Duration::hours(2),
            vec![make_finding("bug", "low")],
        );
        let r1 = make_record(
            "rev-001", "m1", "coder", "pentester", now,
            vec![make_finding("bug", "low")],
        );
        let r3 = make_record(
            "rev-003", "m1", "coder", "pentester", now - Duration::hours(5),
            vec![make_finding("bug", "low")],
        );

        save_finding_record(&findings_dir, &r2).unwrap();
        save_finding_record(&findings_dir, &r1).unwrap();
        save_finding_record(&findings_dir, &r3).unwrap();

        let filter = FindingsFilter::default();
        let results = load_findings(&findings_dir, &filter).unwrap();

        assert_eq!(results.len(), 3);
        assert_eq!(results[0].review_id, "rev-001"); // most recent
        assert_eq!(results[1].review_id, "rev-002");
        assert_eq!(results[2].review_id, "rev-003"); // oldest
    }
}

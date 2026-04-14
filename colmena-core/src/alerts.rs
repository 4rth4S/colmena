use std::path::Path;

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ── Types ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub alert_id: String,
    pub timestamp: DateTime<Utc>,
    pub severity: String,
    pub mission_id: String,
    pub agent_id: String,
    pub review_id: String,
    pub score_average: f64,
    pub critical_findings: usize,
    pub message: String,
    pub acknowledged: bool,
}

/// Generate a unique alert ID: `a_{timestamp_millis}_{hex4}`
pub fn generate_alert_id() -> String {
    let now = Utc::now();
    format!("a_{}_{:04x}", now.timestamp_millis(), rand::random::<u16>())
}

// ── Public API ─────────────────────────────────────────────────────

/// Create an alert by appending it to the alerts JSON array file.
///
/// Uses atomic write (temp + rename) for concurrent safety.
pub fn create_alert(alerts_path: &Path, alert: Alert) -> Result<()> {
    let mut alerts = load_alerts_from_file(alerts_path)?;
    alerts.push(alert);
    save_alerts(alerts_path, &alerts)
}

/// List alerts, optionally filtering by acknowledged state.
///
/// Returns an empty vec if the file doesn't exist.
pub fn list_alerts(alerts_path: &Path, acknowledged: Option<bool>) -> Result<Vec<Alert>> {
    let alerts = load_alerts_from_file(alerts_path)?;

    match acknowledged {
        Some(ack) => Ok(alerts.into_iter().filter(|a| a.acknowledged == ack).collect()),
        None => Ok(alerts),
    }
}

/// Acknowledge a single alert by ID. Sets `acknowledged = true`.
pub fn acknowledge_alert(alerts_path: &Path, alert_id: &str) -> Result<()> {
    let mut alerts = load_alerts_from_file(alerts_path)?;

    let found = alerts.iter_mut().find(|a| a.alert_id == alert_id);
    match found {
        Some(alert) => {
            alert.acknowledged = true;
            save_alerts(alerts_path, &alerts)
        }
        None => bail!("Alert '{}' not found", alert_id),
    }
}

/// Acknowledge all alerts. Sets `acknowledged = true` on every entry.
pub fn acknowledge_all(alerts_path: &Path) -> Result<()> {
    let mut alerts = load_alerts_from_file(alerts_path)?;

    for alert in alerts.iter_mut() {
        alert.acknowledged = true;
    }

    save_alerts(alerts_path, &alerts)
}

// ── Private helpers ────────────────────────────────────────────────

/// Load alerts from JSON file. Returns empty vec if file doesn't exist.
fn load_alerts_from_file(alerts_path: &Path) -> Result<Vec<Alert>> {
    if !alerts_path.exists() {
        return Ok(Vec::new());
    }

    let content = std::fs::read_to_string(alerts_path)
        .with_context(|| format!("reading alerts file {}", alerts_path.display()))?;

    if content.trim().is_empty() {
        return Ok(Vec::new());
    }

    let alerts: Vec<Alert> = serde_json::from_str(&content)
        .with_context(|| format!("parsing alerts file {}", alerts_path.display()))?;

    Ok(alerts)
}

/// Save alerts to JSON file using atomic write (temp + rename).
fn save_alerts(alerts_path: &Path, alerts: &[Alert]) -> Result<()> {
    if let Some(parent) = alerts_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating alerts directory {}", parent.display()))?;
    }

    let json = serde_json::to_string_pretty(alerts)
        .context("serializing alerts")?;

    let tmp_path = alerts_path.with_extension("tmp");
    std::fs::write(&tmp_path, &json)
        .with_context(|| format!("writing temp alerts file {}", tmp_path.display()))?;
    std::fs::rename(&tmp_path, alerts_path)
        .with_context(|| format!("renaming {} -> {}", tmp_path.display(), alerts_path.display()))?;

    Ok(())
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_alert(id: &str, severity: &str, acknowledged: bool) -> Alert {
        Alert {
            alert_id: id.to_string(),
            timestamp: Utc::now(),
            severity: severity.to_string(),
            mission_id: "test-mission".to_string(),
            agent_id: "test-agent".to_string(),
            review_id: "r_12345_abcd".to_string(),
            score_average: 4.5,
            critical_findings: 2,
            message: format!("Test alert {}", id),
            acknowledged,
        }
    }

    #[test]
    fn test_alert_creation() {
        let tmp = TempDir::new().unwrap();
        let alerts_path = tmp.path().join("alerts.json");

        let alert = make_alert("a_100_0001", "critical", false);
        create_alert(&alerts_path, alert.clone()).unwrap();

        let alerts = list_alerts(&alerts_path, None).unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].alert_id, "a_100_0001");
        assert_eq!(alerts[0].severity, "critical");
        assert_eq!(alerts[0].mission_id, "test-mission");
        assert_eq!(alerts[0].agent_id, "test-agent");
        assert_eq!(alerts[0].score_average, 4.5);
        assert_eq!(alerts[0].critical_findings, 2);
        assert!(!alerts[0].acknowledged);
    }

    #[test]
    fn test_alert_acknowledge() {
        let tmp = TempDir::new().unwrap();
        let alerts_path = tmp.path().join("alerts.json");

        let alert = make_alert("a_200_0002", "warning", false);
        create_alert(&alerts_path, alert).unwrap();

        // Before acknowledgment
        let alerts = list_alerts(&alerts_path, None).unwrap();
        assert!(!alerts[0].acknowledged);

        // Acknowledge
        acknowledge_alert(&alerts_path, "a_200_0002").unwrap();

        // After acknowledgment
        let alerts = list_alerts(&alerts_path, None).unwrap();
        assert!(alerts[0].acknowledged);
    }

    #[test]
    fn test_alert_acknowledge_all() {
        let tmp = TempDir::new().unwrap();
        let alerts_path = tmp.path().join("alerts.json");

        create_alert(&alerts_path, make_alert("a_300_0001", "critical", false)).unwrap();
        create_alert(&alerts_path, make_alert("a_300_0002", "warning", false)).unwrap();

        // Both unacknowledged
        let alerts = list_alerts(&alerts_path, Some(false)).unwrap();
        assert_eq!(alerts.len(), 2);

        // Acknowledge all
        acknowledge_all(&alerts_path).unwrap();

        // Both acknowledged now
        let alerts = list_alerts(&alerts_path, Some(true)).unwrap();
        assert_eq!(alerts.len(), 2);

        let unacked = list_alerts(&alerts_path, Some(false)).unwrap();
        assert!(unacked.is_empty());
    }

    #[test]
    fn test_list_alerts_filter() {
        let tmp = TempDir::new().unwrap();
        let alerts_path = tmp.path().join("alerts.json");

        // Create one acknowledged and one unacknowledged
        create_alert(&alerts_path, make_alert("a_400_0001", "critical", false)).unwrap();
        create_alert(&alerts_path, make_alert("a_400_0002", "warning", true)).unwrap();

        // Filter for unacknowledged
        let unacked = list_alerts(&alerts_path, Some(false)).unwrap();
        assert_eq!(unacked.len(), 1);
        assert_eq!(unacked[0].alert_id, "a_400_0001");

        // Filter for acknowledged
        let acked = list_alerts(&alerts_path, Some(true)).unwrap();
        assert_eq!(acked.len(), 1);
        assert_eq!(acked[0].alert_id, "a_400_0002");

        // No filter
        let all = list_alerts(&alerts_path, None).unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_list_alerts_nonexistent_file() {
        let tmp = TempDir::new().unwrap();
        let alerts_path = tmp.path().join("nonexistent.json");

        let alerts = list_alerts(&alerts_path, None).unwrap();
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_acknowledge_nonexistent_alert() {
        let tmp = TempDir::new().unwrap();
        let alerts_path = tmp.path().join("alerts.json");

        create_alert(&alerts_path, make_alert("a_500_0001", "critical", false)).unwrap();

        let result = acknowledge_alert(&alerts_path, "nonexistent_id");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn test_generate_alert_id_format() {
        let id = generate_alert_id();
        assert!(id.starts_with("a_"), "alert ID should start with 'a_', got: {}", id);
        let parts: Vec<&str> = id.split('_').collect();
        assert_eq!(parts.len(), 3, "alert ID should have 3 parts: a_{{ts}}_{{hex4}}");
    }
}

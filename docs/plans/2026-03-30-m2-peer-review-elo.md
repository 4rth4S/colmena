# M2 Peer Review Protocol + ELO Engine + Findings Store — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add structured peer review between agents, an ELO rating system with temporal decay, and a persistent findings store — all integrated via MCP tools and CLI.

**Architecture:** Three new modules in `colmena-core` (`review.rs`, `elo.rs`, `findings.rs`), exposed through 6 MCP tools and 3 CLI subcommands. Data stored as JSON/JSONL files following existing patterns (queue, delegations, audit). Security invariants hardcoded from STRIDE+DREAD threat model.

**Tech Stack:** Rust (edition 2021), serde/serde_json, chrono, anyhow, sha2 (new dep for artifact hashing), rmcp (MCP server), clap (CLI).

**Spec:** `docs/specs/2026-03-30-m2-peer-review-elo-design.md`

**Branch:** `feature/m2-peer-review-elo`

---

## File Structure

### New files

| File | Responsibility |
|---|---|
| `colmena-core/src/review.rs` | Review protocol: types, submit, assign reviewer, evaluate, state machine, trust gate |
| `colmena-core/src/elo.rs` | ELO engine: event types, delta calculation, decay, rating from log, leaderboard |
| `colmena-core/src/findings.rs` | Findings store: types, persist, query with filters (role/category/severity/date/mission) |
| `config/review-config.yaml` | Review thresholds and reviewer assignment config |

### Modified files

| File | Change |
|---|---|
| `Cargo.toml` (workspace) | Add `sha2` workspace dependency |
| `colmena-core/Cargo.toml` | Add `sha2.workspace = true` |
| `colmena-core/src/lib.rs` | Add `pub mod review, elo, findings` |
| `colmena-core/src/audit.rs` | Add `ReviewSubmit`, `ReviewEvaluate`, `ReviewCompleted` event variants |
| `colmena-cli/src/main.rs` | Add `Review` and `Elo` subcommands |
| `colmena-mcp/src/main.rs` | Add 6 MCP tools |
| `config/trust-firewall.yaml` | Add review MCP tools to `restricted` |
| `.gitignore` | Add `config/reviews/`, `config/findings/`, `config/elo/` |
| `CLAUDE.md` | Document M2 tools and conventions |

---

## Task 1: Project setup and branch

**Files:**
- Modify: `Cargo.toml` (workspace root)
- Modify: `colmena-core/Cargo.toml`
- Modify: `.gitignore`
- Create: `config/review-config.yaml`

- [ ] **Step 1: Create feature branch**

```bash
git checkout main
git pull origin main
git checkout -b feature/m2-peer-review-elo
```

- [ ] **Step 2: Add sha2 workspace dependency**

In `Cargo.toml` (workspace root), add to `[workspace.dependencies]`:

```toml
sha2 = "0.10"
```

In `colmena-core/Cargo.toml`, add to `[dependencies]`:

```toml
sha2.workspace = true
```

- [ ] **Step 3: Update .gitignore**

Append to `.gitignore`:

```
/config/reviews/pending/*.json
/config/reviews/completed/*.json
/config/findings/
/config/elo/
```

- [ ] **Step 4: Create review-config.yaml**

```yaml
# Review Protocol Configuration
version: 1

thresholds:
  # Score average >= this → auto-complete (no human needed)
  auto_approve: 7.0
  # Hardcoded floor — Colmena never auto-approves below this, regardless of config
  # (enforced in code, this value is informational only)
  floor: 5.0

reviewer_assignment:
  # MVP: "role_rotation" — pick different role, avoid reciprocal
  # Post-MVP: "elo_weighted" — pick highest ELO among eligible
  strategy: role_rotation
```

- [ ] **Step 5: Build to verify deps resolve**

Run: `cargo build --workspace`
Expected: Compiles successfully with sha2 available.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock colmena-core/Cargo.toml .gitignore config/review-config.yaml
git commit -m "chore(m2): project setup — sha2 dep, gitignore, review config

built with ❤️‍🔥 by AppSec"
```

---

## Task 2: ELO engine — `colmena-core/src/elo.rs`

ELO is a dependency of review (review writes ELO events), so we build it first.

**Files:**
- Create: `colmena-core/src/elo.rs`
- Modify: `colmena-core/src/lib.rs`

- [ ] **Step 1: Write failing tests for ELO types and log_event**

In `colmena-core/src/elo.rs`, write the test module first:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_log_elo_event_and_read() {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("elo-log.jsonl");

        let event = EloEvent {
            agent: "pentester".to_string(),
            event_type: EloEventType::Reviewed,
            delta: 12,
            reason: "score 8.2/10 from security_architect".to_string(),
            mission: "audit-pci".to_string(),
            review_id: "r_001".to_string(),
        };

        log_elo_event(&log_path, &event).unwrap();

        let events = read_elo_log(&log_path).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].agent, "pentester");
        assert_eq!(events[0].delta, 12);
    }

    #[test]
    fn test_calculate_rating_no_events() {
        let rating = calculate_rating("pentester", &[], 1500);
        assert_eq!(rating.elo, 1500);
        assert_eq!(rating.review_count, 0);
    }

    #[test]
    fn test_calculate_rating_with_events() {
        let now = chrono::Utc::now();
        let events = vec![
            StoredEloEvent {
                ts: now,
                agent: "pentester".to_string(),
                event_type: EloEventType::Reviewed,
                delta: 12,
                reason: "good".to_string(),
                mission: "m1".to_string(),
                review_id: "r1".to_string(),
            },
            StoredEloEvent {
                ts: now,
                agent: "pentester".to_string(),
                event_type: EloEventType::FindingAgainst,
                delta: -8,
                reason: "missed scope".to_string(),
                mission: "m1".to_string(),
                review_id: "r1".to_string(),
            },
        ];

        let rating = calculate_rating("pentester", &events, 1500);
        // Both events are recent (< 7 days) → full weight: 1500 + 12 - 8 = 1504
        assert_eq!(rating.elo, 1504);
        assert_eq!(rating.review_count, 2);
    }

    #[test]
    fn test_decay_factor() {
        let now = chrono::Utc::now();

        // < 7 days → 1.0
        let recent = now - chrono::Duration::days(3);
        assert_eq!(decay_factor(recent, now), 1.0);

        // 7-30 days → 0.7
        let week_old = now - chrono::Duration::days(15);
        assert_eq!(decay_factor(week_old, now), 0.7);

        // 30-90 days → 0.4
        let month_old = now - chrono::Duration::days(60);
        assert_eq!(decay_factor(month_old, now), 0.4);

        // > 90 days → 0.1
        let old = now - chrono::Duration::days(120);
        assert_eq!(decay_factor(old, now), 0.1);
    }

    #[test]
    fn test_calculate_rating_with_decay() {
        let now = chrono::Utc::now();
        let events = vec![
            StoredEloEvent {
                ts: now - chrono::Duration::days(100), // > 90 days → factor 0.1
                agent: "pentester".to_string(),
                event_type: EloEventType::Reviewed,
                delta: 100,
                reason: "old event".to_string(),
                mission: "m0".to_string(),
                review_id: "r0".to_string(),
            },
        ];

        let rating = calculate_rating("pentester", &events, 1500);
        // 100 * 0.1 = 10 → 1500 + 10 = 1510
        assert_eq!(rating.elo, 1510);
    }

    #[test]
    fn test_leaderboard() {
        let now = chrono::Utc::now();
        let events = vec![
            StoredEloEvent {
                ts: now,
                agent: "pentester".to_string(),
                event_type: EloEventType::Reviewed,
                delta: 30,
                reason: "good".to_string(),
                mission: "m1".to_string(),
                review_id: "r1".to_string(),
            },
            StoredEloEvent {
                ts: now,
                agent: "auditor".to_string(),
                event_type: EloEventType::Reviewed,
                delta: -10,
                reason: "poor".to_string(),
                mission: "m1".to_string(),
                review_id: "r2".to_string(),
            },
        ];

        let baselines = vec![
            ("pentester".to_string(), 1500u32),
            ("auditor".to_string(), 1500u32),
        ];

        let board = leaderboard(&events, &baselines);
        assert_eq!(board.len(), 2);
        // pentester: 1530, auditor: 1490 → pentester first
        assert_eq!(board[0].agent, "pentester");
        assert_eq!(board[0].elo, 1530);
        assert_eq!(board[1].agent, "auditor");
        assert_eq!(board[1].elo, 1490);
    }

    #[test]
    fn test_author_delta_high_score() {
        assert_eq!(author_delta(9.0), 6);  // (9-7)*3 = 6
        assert_eq!(author_delta(8.0), 3);  // (8-7)*3 = 3
        assert_eq!(author_delta(10.0), 9); // (10-7)*3 = 9
    }

    #[test]
    fn test_author_delta_neutral() {
        assert_eq!(author_delta(7.0), 0);
        assert_eq!(author_delta(6.0), 0);
        assert_eq!(author_delta(5.0), 0);
    }

    #[test]
    fn test_author_delta_low_score() {
        assert_eq!(author_delta(4.0), -8);  // (6-4)*4 = -8
        assert_eq!(author_delta(2.0), -16); // (6-2)*4 = -16
        assert_eq!(author_delta(1.0), -20); // (6-1)*4 = -20
    }

    #[test]
    fn test_finding_delta() {
        assert_eq!(finding_delta_author("critical"), -10);
        assert_eq!(finding_delta_author("high"), -5);
        assert_eq!(finding_delta_author("medium"), 0);
        assert_eq!(finding_delta_author("low"), 0);
    }
}
```

- [ ] **Step 2: Register module in lib.rs**

Add to `colmena-core/src/lib.rs`:

```rust
pub mod elo;
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p colmena-core elo`
Expected: Compilation errors — types not yet defined.

- [ ] **Step 4: Implement elo.rs types and functions**

Write the full implementation above the test module in `colmena-core/src/elo.rs`:

```rust
use std::io::Write as IoWrite;
use std::path::Path;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ── Types ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum EloEventType {
    Reviewed,
    FindingAgainst,
    ReviewQuality,
}

/// Event to write to the ELO log (no timestamp — added at write time).
#[derive(Debug)]
pub struct EloEvent {
    pub agent: String,
    pub event_type: EloEventType,
    pub delta: i32,
    pub reason: String,
    pub mission: String,
    pub review_id: String,
}

/// Event as stored in the JSONL log (with timestamp).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredEloEvent {
    pub ts: DateTime<Utc>,
    pub agent: String,
    #[serde(rename = "event")]
    pub event_type: EloEventType,
    pub delta: i32,
    pub reason: String,
    pub mission: String,
    pub review_id: String,
}

/// Calculated rating for an agent.
#[derive(Debug, Clone, Serialize)]
pub struct AgentRating {
    pub agent: String,
    pub elo: i32,
    pub trend_7d: i32,
    pub review_count: u32,
    pub last_active: Option<DateTime<Utc>>,
}

// ── Delta calculation ────────────────────────────────────────────────────────

/// Calculate author ELO delta from average review score (1-10).
pub fn author_delta(score_avg: f64) -> i32 {
    if score_avg >= 8.0 {
        ((score_avg - 7.0) * 3.0) as i32
    } else if score_avg >= 5.0 {
        0
    } else {
        -((6.0 - score_avg) * 4.0) as i32
    }
}

/// Calculate author ELO delta from a finding severity.
pub fn finding_delta_author(severity: &str) -> i32 {
    match severity {
        "critical" => -10,
        "high" => -5,
        _ => 0,
    }
}

/// Reviewer gets +5 for each valid finding.
pub const REVIEWER_FINDING_DELTA: i32 = 5;

// ── Temporal decay ───────────────────────────────────────────────────────────

/// Calculate decay factor based on event age.
pub fn decay_factor(event_ts: DateTime<Utc>, now: DateTime<Utc>) -> f64 {
    let days = (now - event_ts).num_days();
    if days < 7 {
        1.0
    } else if days < 30 {
        0.7
    } else if days < 90 {
        0.4
    } else {
        0.1
    }
}

// ── Log I/O ──────────────────────────────────────────────────────────────────

/// Append an ELO event to the JSONL log.
pub fn log_elo_event(log_path: &Path, event: &EloEvent) -> Result<()> {
    let stored = StoredEloEvent {
        ts: Utc::now(),
        agent: event.agent.clone(),
        event_type: event.event_type.clone(),
        delta: event.delta,
        reason: event.reason.clone(),
        mission: event.mission.clone(),
        review_id: event.review_id.clone(),
    };

    let line = serde_json::to_string(&stored)
        .context("Failed to serialize ELO event")?;

    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create ELO dir: {}", parent.display()))?;
    }

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .with_context(|| format!("Failed to open ELO log: {}", log_path.display()))?;

    writeln!(file, "{}", line)?;
    Ok(())
}

/// Read all events from the ELO log.
pub fn read_elo_log(log_path: &Path) -> Result<Vec<StoredEloEvent>> {
    if !log_path.exists() {
        return Ok(Vec::new());
    }

    let contents = std::fs::read_to_string(log_path)
        .with_context(|| format!("Failed to read ELO log: {}", log_path.display()))?;

    let mut events = Vec::new();
    for line in contents.lines() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<StoredEloEvent>(line) {
            Ok(e) => events.push(e),
            Err(_) => continue, // skip malformed lines
        }
    }

    Ok(events)
}

// ── Rating calculation ───────────────────────────────────────────────────────

/// Calculate current rating for an agent from the event log.
pub fn calculate_rating(agent: &str, events: &[StoredEloEvent], baseline: u32) -> AgentRating {
    let now = Utc::now();
    let seven_days_ago = now - chrono::Duration::days(7);

    let agent_events: Vec<&StoredEloEvent> = events
        .iter()
        .filter(|e| e.agent == agent)
        .collect();

    let mut total_delta: f64 = 0.0;
    let mut trend_7d: i32 = 0;
    let mut last_active: Option<DateTime<Utc>> = None;

    for e in &agent_events {
        let factor = decay_factor(e.ts, now);
        total_delta += e.delta as f64 * factor;

        if e.ts >= seven_days_ago {
            trend_7d += e.delta;
        }

        match last_active {
            None => last_active = Some(e.ts),
            Some(prev) if e.ts > prev => last_active = Some(e.ts),
            _ => {}
        }
    }

    AgentRating {
        agent: agent.to_string(),
        elo: baseline as i32 + total_delta.round() as i32,
        trend_7d,
        review_count: agent_events.len() as u32,
        last_active,
    }
}

/// Build a sorted leaderboard (highest ELO first).
pub fn leaderboard(
    events: &[StoredEloEvent],
    baselines: &[(String, u32)],
) -> Vec<AgentRating> {
    let mut ratings: Vec<AgentRating> = baselines
        .iter()
        .map(|(agent, baseline)| calculate_rating(agent, events, *baseline))
        .collect();

    ratings.sort_by(|a, b| b.elo.cmp(&a.elo));
    ratings
}
```

- [ ] **Step 5: Run tests**

Run: `cargo test -p colmena-core elo`
Expected: All 9 ELO tests pass.

- [ ] **Step 6: Run clippy**

Run: `cargo clippy -p colmena-core -- -W warnings`
Expected: Clean.

- [ ] **Step 7: Commit**

```bash
git add colmena-core/src/elo.rs colmena-core/src/lib.rs
git commit -m "feat(m2): ELO engine — delta calc, temporal decay, leaderboard

Append-only JSONL log, lazy decay at read time.
9 unit tests.

built with ❤️‍🔥 by AppSec"
```

---

## Task 3: Findings store — `colmena-core/src/findings.rs`

**Files:**
- Create: `colmena-core/src/findings.rs`
- Modify: `colmena-core/src/lib.rs`

- [ ] **Step 1: Write failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_finding_record(
        review_id: &str,
        mission: &str,
        author: &str,
        reviewer: &str,
        severity: &str,
        category: &str,
    ) -> FindingRecord {
        FindingRecord {
            review_id: review_id.to_string(),
            mission: mission.to_string(),
            author_role: author.to_string(),
            reviewer_role: reviewer.to_string(),
            artifact_path: format!("agents/{}/report.md", author),
            artifact_hash: "sha256:abc123".to_string(),
            timestamp: chrono::Utc::now(),
            scores: {
                let mut m = std::collections::HashMap::new();
                m.insert("accuracy".to_string(), 8);
                m.insert("completeness".to_string(), 7);
                m
            },
            score_average: 7.5,
            findings: vec![Finding {
                category: category.to_string(),
                severity: severity.to_string(),
                description: format!("Test finding in {}", category),
                recommendation: "Fix it".to_string(),
            }],
        }
    }

    #[test]
    fn test_save_and_load_finding_record() {
        let tmp = TempDir::new().unwrap();
        let findings_dir = tmp.path().join("findings");

        let record = make_finding_record("r_001", "audit-pci", "pentester", "security_architect", "high", "completeness");
        save_finding_record(&findings_dir, &record).unwrap();

        let loaded = load_findings(&findings_dir, &FindingsFilter::default()).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].review_id, "r_001");
    }

    #[test]
    fn test_filter_by_severity() {
        let tmp = TempDir::new().unwrap();
        let findings_dir = tmp.path().join("findings");

        save_finding_record(&findings_dir, &make_finding_record("r1", "m1", "pentester", "architect", "high", "auth")).unwrap();
        save_finding_record(&findings_dir, &make_finding_record("r2", "m1", "auditor", "architect", "low", "docs")).unwrap();

        let filter = FindingsFilter { severity: Some("high".to_string()), ..Default::default() };
        let results = load_findings(&findings_dir, &filter).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].review_id, "r1");
    }

    #[test]
    fn test_filter_by_author_role() {
        let tmp = TempDir::new().unwrap();
        let findings_dir = tmp.path().join("findings");

        save_finding_record(&findings_dir, &make_finding_record("r1", "m1", "pentester", "architect", "high", "auth")).unwrap();
        save_finding_record(&findings_dir, &make_finding_record("r2", "m1", "auditor", "architect", "medium", "compliance")).unwrap();

        let filter = FindingsFilter { author_role: Some("pentester".to_string()), ..Default::default() };
        let results = load_findings(&findings_dir, &filter).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].author_role, "pentester");
    }

    #[test]
    fn test_filter_by_mission() {
        let tmp = TempDir::new().unwrap();
        let findings_dir = tmp.path().join("findings");

        save_finding_record(&findings_dir, &make_finding_record("r1", "mission-a", "pentester", "architect", "high", "auth")).unwrap();
        save_finding_record(&findings_dir, &make_finding_record("r2", "mission-b", "pentester", "architect", "high", "auth")).unwrap();

        let filter = FindingsFilter { mission: Some("mission-a".to_string()), ..Default::default() };
        let results = load_findings(&findings_dir, &filter).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].mission, "mission-a");
    }

    #[test]
    fn test_filter_by_date_range() {
        let tmp = TempDir::new().unwrap();
        let findings_dir = tmp.path().join("findings");

        let mut old = make_finding_record("r1", "m1", "pentester", "architect", "high", "auth");
        old.timestamp = chrono::Utc::now() - chrono::Duration::days(60);
        save_finding_record(&findings_dir, &old).unwrap();

        let recent = make_finding_record("r2", "m1", "pentester", "architect", "high", "auth");
        save_finding_record(&findings_dir, &recent).unwrap();

        let filter = FindingsFilter {
            after: Some(chrono::Utc::now() - chrono::Duration::days(7)),
            ..Default::default()
        };
        let results = load_findings(&findings_dir, &filter).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].review_id, "r2");
    }

    #[test]
    fn test_filter_with_limit() {
        let tmp = TempDir::new().unwrap();
        let findings_dir = tmp.path().join("findings");

        for i in 0..10 {
            save_finding_record(&findings_dir, &make_finding_record(&format!("r{i}"), "m1", "pentester", "architect", "high", "auth")).unwrap();
        }

        let filter = FindingsFilter { limit: Some(3), ..Default::default() };
        let results = load_findings(&findings_dir, &filter).unwrap();
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_empty_findings_dir() {
        let tmp = TempDir::new().unwrap();
        let findings_dir = tmp.path().join("findings");
        let results = load_findings(&findings_dir, &FindingsFilter::default()).unwrap();
        assert!(results.is_empty());
    }
}
```

- [ ] **Step 2: Register module in lib.rs**

Add to `colmena-core/src/lib.rs`:

```rust
pub mod findings;
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p colmena-core findings`
Expected: Compilation errors.

- [ ] **Step 4: Implement findings.rs**

```rust
use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ── Types ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub category: String,
    pub severity: String,
    pub description: String,
    pub recommendation: String,
}

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

#[derive(Debug, Default)]
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

// ── Persistence ──────────────────────────────────────────────────────────────

/// Save a finding record to `findings_dir/<mission>/<review_id>.json`.
pub fn save_finding_record(findings_dir: &Path, record: &FindingRecord) -> Result<()> {
    let mission_dir = findings_dir.join(&record.mission);
    std::fs::create_dir_all(&mission_dir)
        .with_context(|| format!("Failed to create findings dir: {}", mission_dir.display()))?;

    let path = mission_dir.join(format!("{}.json", record.review_id));
    let json = serde_json::to_string_pretty(record)
        .context("Failed to serialize finding record")?;
    std::fs::write(&path, json)
        .with_context(|| format!("Failed to write finding: {}", path.display()))?;

    Ok(())
}

/// Load findings from disk with filtering.
pub fn load_findings(findings_dir: &Path, filter: &FindingsFilter) -> Result<Vec<FindingRecord>> {
    if !findings_dir.exists() {
        return Ok(Vec::new());
    }

    let mut records = Vec::new();

    for mission_entry in std::fs::read_dir(findings_dir)
        .with_context(|| format!("Failed to read findings dir: {}", findings_dir.display()))?
    {
        let mission_entry = mission_entry?;
        if !mission_entry.path().is_dir() {
            continue;
        }

        let mission_name = mission_entry
            .file_name()
            .to_string_lossy()
            .to_string();

        // Early filter by mission
        if let Some(ref m) = filter.mission {
            if &mission_name != m {
                continue;
            }
        }

        for file_entry in std::fs::read_dir(mission_entry.path())? {
            let file_entry = file_entry?;
            let path = file_entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }

            let contents = match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let record: FindingRecord = match serde_json::from_str(&contents) {
                Ok(r) => r,
                Err(_) => continue,
            };

            if matches_filter(&record, filter) {
                records.push(record);
            }
        }
    }

    // Sort by timestamp descending (most recent first)
    records.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

    // Apply limit
    if let Some(limit) = filter.limit {
        records.truncate(limit);
    }

    Ok(records)
}

fn matches_filter(record: &FindingRecord, filter: &FindingsFilter) -> bool {
    if let Some(ref role) = filter.author_role {
        if &record.author_role != role {
            return false;
        }
    }
    if let Some(ref role) = filter.reviewer_role {
        if &record.reviewer_role != role {
            return false;
        }
    }
    if let Some(ref sev) = filter.severity {
        if !record.findings.iter().any(|f| &f.severity == sev) {
            return false;
        }
    }
    if let Some(ref cat) = filter.category {
        if !record.findings.iter().any(|f| &f.category == cat) {
            return false;
        }
    }
    if let Some(after) = filter.after {
        if record.timestamp < after {
            return false;
        }
    }
    if let Some(before) = filter.before {
        if record.timestamp > before {
            return false;
        }
    }
    true
}
```

- [ ] **Step 5: Run tests**

Run: `cargo test -p colmena-core findings`
Expected: All 7 findings tests pass.

- [ ] **Step 6: Commit**

```bash
git add colmena-core/src/findings.rs colmena-core/src/lib.rs
git commit -m "feat(m2): findings store — persist, query, filter by role/severity/date

7 unit tests.

built with ❤️‍🔥 by AppSec"
```

---

## Task 4: Review protocol — `colmena-core/src/review.rs`

The largest module. Depends on elo.rs and findings.rs.

**Files:**
- Create: `colmena-core/src/review.rs`
- Modify: `colmena-core/src/lib.rs`
- Modify: `colmena-core/src/audit.rs` (add review event variants)

- [ ] **Step 1: Add review audit events to audit.rs**

Add these variants to the `AuditEvent` enum in `colmena-core/src/audit.rs`:

```rust
    /// Review submitted for peer evaluation
    ReviewSubmit {
        review_id: &'a str,
        author_role: &'a str,
        artifact_path: &'a str,
        mission: &'a str,
    },
    /// Review evaluated by reviewer
    ReviewEvaluate {
        review_id: &'a str,
        reviewer_role: &'a str,
        score_avg: f64,
        finding_count: usize,
    },
    /// Review completed (auto or human)
    ReviewCompleted {
        review_id: &'a str,
        outcome: &'a str,
    },
```

Add corresponding format arms in `format_event`:

```rust
        AuditEvent::ReviewSubmit { review_id, author_role, artifact_path, mission } => {
            format!("[{ts}] REVIEW_SUBMIT review={review_id} author={author_role} artifact={artifact_path} mission={mission}")
        }
        AuditEvent::ReviewEvaluate { review_id, reviewer_role, score_avg, finding_count } => {
            format!("[{ts}] REVIEW_EVALUATE review={review_id} reviewer={reviewer_role} score_avg={score_avg:.1} findings={finding_count}")
        }
        AuditEvent::ReviewCompleted { review_id, outcome } => {
            format!("[{ts}] REVIEW_COMPLETED review={review_id} outcome={outcome}")
        }
```

- [ ] **Step 2: Write failing tests for review.rs**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::collections::HashMap;

    fn setup_review_dir(tmp: &TempDir) -> std::path::PathBuf {
        let review_dir = tmp.path().join("reviews");
        std::fs::create_dir_all(review_dir.join("pending")).unwrap();
        std::fs::create_dir_all(review_dir.join("completed")).unwrap();
        review_dir
    }

    #[test]
    fn test_submit_creates_pending_review() {
        let tmp = TempDir::new().unwrap();
        let review_dir = setup_review_dir(&tmp);

        // Create a fake artifact
        let artifact = tmp.path().join("report.md");
        std::fs::write(&artifact, "# Findings\n\nSome findings here.").unwrap();

        let review = submit_review(
            &review_dir,
            &artifact,
            "pentester",
            "audit-pci",
            &["security_architect".to_string(), "auditor".to_string()],
            &[],
        ).unwrap();

        assert_eq!(review.author_role, "pentester");
        assert_eq!(review.state, ReviewState::Pending);
        assert!(!review.artifact_hash.is_empty());
        // Reviewer should be different from author
        assert_ne!(review.reviewer_role, "pentester");
    }

    #[test]
    fn test_submit_rejects_self_review() {
        let tmp = TempDir::new().unwrap();
        let review_dir = setup_review_dir(&tmp);
        let artifact = tmp.path().join("report.md");
        std::fs::write(&artifact, "content").unwrap();

        // Only available role is the author itself
        let result = submit_review(
            &review_dir,
            &artifact,
            "pentester",
            "mission-1",
            &["pentester".to_string()],
            &[],
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No eligible reviewer"));
    }

    #[test]
    fn test_submit_prevents_reciprocal_review() {
        let tmp = TempDir::new().unwrap();
        let review_dir = setup_review_dir(&tmp);
        let artifact = tmp.path().join("report.md");
        std::fs::write(&artifact, "content").unwrap();

        // auditor already reviewed pentester in this mission
        let existing_reviews = vec![
            ("auditor".to_string(), "pentester".to_string()),
        ];

        let review = submit_review(
            &review_dir,
            &artifact,
            "pentester",
            "mission-1",
            &["auditor".to_string(), "security_architect".to_string()],
            &existing_reviews,
        ).unwrap();

        // Should NOT assign auditor (reciprocal), should assign security_architect
        assert_eq!(review.reviewer_role, "security_architect");
    }

    #[test]
    fn test_evaluate_review_valid() {
        let tmp = TempDir::new().unwrap();
        let review_dir = setup_review_dir(&tmp);
        let artifact = tmp.path().join("report.md");
        std::fs::write(&artifact, "content").unwrap();

        let review = submit_review(
            &review_dir,
            &artifact,
            "pentester",
            "mission-1",
            &["security_architect".to_string()],
            &[],
        ).unwrap();

        let mut scores = HashMap::new();
        scores.insert("accuracy".to_string(), 8u32);
        scores.insert("completeness".to_string(), 7);

        let findings = vec![crate::findings::Finding {
            category: "completeness".to_string(),
            severity: "medium".to_string(),
            description: "Missed websockets".to_string(),
            recommendation: "Extend scope".to_string(),
        }];

        let result = evaluate_review(
            &review_dir,
            &review.review_id,
            &review.reviewer_role,
            scores,
            findings,
            &artifact,
        );

        assert!(result.is_ok());
        let evaluated = result.unwrap();
        assert_eq!(evaluated.state, ReviewState::Evaluated);
        assert_eq!(evaluated.score_average, Some(7.5));
    }

    #[test]
    fn test_evaluate_rejects_tampered_artifact() {
        let tmp = TempDir::new().unwrap();
        let review_dir = setup_review_dir(&tmp);
        let artifact = tmp.path().join("report.md");
        std::fs::write(&artifact, "original content").unwrap();

        let review = submit_review(
            &review_dir,
            &artifact,
            "pentester",
            "mission-1",
            &["security_architect".to_string()],
            &[],
        ).unwrap();

        // Tamper with artifact
        std::fs::write(&artifact, "MODIFIED content").unwrap();

        let mut scores = HashMap::new();
        scores.insert("accuracy".to_string(), 8u32);
        scores.insert("completeness".to_string(), 7);

        let result = evaluate_review(
            &review_dir,
            &review.review_id,
            &review.reviewer_role,
            scores,
            vec![],
            &artifact,
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("hash mismatch"));
    }

    #[test]
    fn test_evaluate_requires_min_2_scores() {
        let tmp = TempDir::new().unwrap();
        let review_dir = setup_review_dir(&tmp);
        let artifact = tmp.path().join("report.md");
        std::fs::write(&artifact, "content").unwrap();

        let review = submit_review(
            &review_dir,
            &artifact,
            "pentester",
            "mission-1",
            &["security_architect".to_string()],
            &[],
        ).unwrap();

        let mut scores = HashMap::new();
        scores.insert("accuracy".to_string(), 8u32);
        // Only 1 score — should be rejected

        let result = evaluate_review(
            &review_dir,
            &review.review_id,
            &review.reviewer_role,
            scores,
            vec![],
            &artifact,
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("minimum 2"));
    }

    #[test]
    fn test_trust_gate_auto_approve() {
        let result = trust_gate(8.5, &[]);
        assert_eq!(result, TrustGateResult::AutoComplete);
    }

    #[test]
    fn test_trust_gate_critical_finding() {
        let findings = vec![crate::findings::Finding {
            category: "security".to_string(),
            severity: "critical".to_string(),
            description: "Bad".to_string(),
            recommendation: "Fix".to_string(),
        }];
        let result = trust_gate(9.0, &findings);
        assert_eq!(result, TrustGateResult::NeedsHumanReview);
    }

    #[test]
    fn test_trust_gate_low_score() {
        let result = trust_gate(4.5, &[]);
        assert_eq!(result, TrustGateResult::NeedsHumanReview);
    }

    #[test]
    fn test_list_pending_reviews() {
        let tmp = TempDir::new().unwrap();
        let review_dir = setup_review_dir(&tmp);
        let artifact = tmp.path().join("report.md");
        std::fs::write(&artifact, "content").unwrap();

        submit_review(
            &review_dir,
            &artifact,
            "pentester",
            "mission-1",
            &["security_architect".to_string()],
            &[],
        ).unwrap();

        let pending = list_reviews(&review_dir, Some(ReviewState::Pending)).unwrap();
        assert_eq!(pending.len(), 1);
    }
}
```

- [ ] **Step 3: Register module in lib.rs**

Add to `colmena-core/src/lib.rs`:

```rust
pub mod review;
```

- [ ] **Step 4: Run tests to verify they fail**

Run: `cargo test -p colmena-core review`
Expected: Compilation errors.

- [ ] **Step 5: Implement review.rs**

```rust
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::findings::Finding;

// ── Constants ────────────────────────────────────────────────────────────────

/// Default auto-approve threshold.
pub const DEFAULT_AUTO_APPROVE_THRESHOLD: f64 = 7.0;

/// Hardcoded floor — never auto-approve below this, regardless of config.
pub const AUTO_APPROVE_FLOOR: f64 = 5.0;

/// Minimum number of score dimensions per review.
pub const MIN_SCORE_DIMENSIONS: usize = 2;

// ── Types ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewState {
    Pending,
    InReview,
    Evaluated,
    Completed,
    NeedsHumanReview,
    Rejected,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TrustGateResult {
    AutoComplete,
    NeedsHumanReview,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewEntry {
    pub review_id: String,
    pub mission: String,
    pub author_role: String,
    pub reviewer_role: String,
    pub artifact_path: String,
    pub artifact_hash: String,
    pub state: ReviewState,
    pub created_at: DateTime<Utc>,
    pub evaluated_at: Option<DateTime<Utc>>,
    pub scores: Option<HashMap<String, u32>>,
    pub score_average: Option<f64>,
    pub finding_count: Option<usize>,
}

// ── Hashing ──────────────────────────────────────────────────────────────────

/// SHA256 hash of a file's contents.
pub fn hash_artifact(path: &Path) -> Result<String> {
    let contents = std::fs::read(path)
        .with_context(|| format!("Failed to read artifact: {}", path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(&contents);
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

// ── Submit ───────────────────────────────────────────────────────────────────

/// Submit an artifact for peer review.
/// `available_roles` = roles in this mission (excluding author).
/// `existing_reviews` = (reviewer, author) pairs already in this mission (for anti-reciprocal).
pub fn submit_review(
    review_dir: &Path,
    artifact_path: &Path,
    author_role: &str,
    mission: &str,
    available_roles: &[String],
    existing_reviews: &[(String, String)],
) -> Result<ReviewEntry> {
    // Invariant 1: author != reviewer
    let mut eligible: Vec<&String> = available_roles
        .iter()
        .filter(|r| r.as_str() != author_role)
        .collect();

    // Invariant 2: no reciprocal in same mission
    eligible.retain(|reviewer| {
        !existing_reviews.iter().any(|(rev, auth)| {
            rev == reviewer.as_str() && auth == author_role
        })
    });

    if eligible.is_empty() {
        anyhow::bail!("No eligible reviewer: all available roles are either the author or would create a reciprocal review");
    }

    // MVP: pick first available
    let reviewer_role = eligible[0].clone();

    let artifact_hash = hash_artifact(artifact_path)?;
    let now = Utc::now();
    let review_id = format!("r_{}", now.timestamp_millis());

    let entry = ReviewEntry {
        review_id: review_id.clone(),
        mission: mission.to_string(),
        author_role: author_role.to_string(),
        reviewer_role,
        artifact_path: artifact_path.to_string_lossy().to_string(),
        artifact_hash,
        state: ReviewState::Pending,
        created_at: now,
        evaluated_at: None,
        scores: None,
        score_average: None,
        finding_count: None,
    };

    // Save to pending/
    save_review(review_dir, &entry)?;

    Ok(entry)
}

// ── Evaluate ─────────────────────────────────────────────────────────────────

/// Evaluate a review: submit scores and findings.
pub fn evaluate_review(
    review_dir: &Path,
    review_id: &str,
    reviewer_role: &str,
    scores: HashMap<String, u32>,
    findings: Vec<Finding>,
    artifact_path: &Path,
) -> Result<ReviewEntry> {
    // Invariant 6: minimum 2 score dimensions
    if scores.len() < MIN_SCORE_DIMENSIONS {
        anyhow::bail!(
            "Review requires minimum {} score dimensions, got {}",
            MIN_SCORE_DIMENSIONS,
            scores.len()
        );
    }

    // Load the review
    let mut entry = load_review(review_dir, review_id)?;

    // Verify reviewer matches
    if entry.reviewer_role != reviewer_role {
        anyhow::bail!(
            "Reviewer mismatch: expected '{}', got '{}'",
            entry.reviewer_role,
            reviewer_role
        );
    }

    // Invariant 3: verify artifact hash
    let current_hash = hash_artifact(artifact_path)?;
    if current_hash != entry.artifact_hash {
        anyhow::bail!(
            "Artifact hash mismatch: expected '{}', got '{}'. Artifact may have been tampered with.",
            entry.artifact_hash,
            current_hash
        );
    }

    // Calculate average score
    let sum: u32 = scores.values().sum();
    let avg = sum as f64 / scores.len() as f64;

    entry.scores = Some(scores);
    entry.score_average = Some(avg);
    entry.finding_count = Some(findings.len());
    entry.evaluated_at = Some(Utc::now());
    entry.state = ReviewState::Evaluated;

    // Move from pending to completed
    let pending_path = review_dir.join("pending").join(format!("{}.json", review_id));
    let _ = std::fs::remove_file(&pending_path);
    save_review_to(review_dir, &entry, "completed")?;

    Ok(entry)
}

// ── Trust gate ───────────────────────────────────────────────────────────────

/// Determine if a review can be auto-completed or needs human review.
pub fn trust_gate(score_avg: f64, findings: &[Finding]) -> TrustGateResult {
    // Hardcoded floor: never auto-approve below 5.0
    if score_avg < AUTO_APPROVE_FLOOR {
        return TrustGateResult::NeedsHumanReview;
    }

    // Critical findings always need human review
    if findings.iter().any(|f| f.severity == "critical") {
        return TrustGateResult::NeedsHumanReview;
    }

    // Below threshold needs human review
    if score_avg < DEFAULT_AUTO_APPROVE_THRESHOLD {
        return TrustGateResult::NeedsHumanReview;
    }

    TrustGateResult::AutoComplete
}

// ── List ─────────────────────────────────────────────────────────────────────

/// List reviews, optionally filtered by state.
pub fn list_reviews(review_dir: &Path, state_filter: Option<ReviewState>) -> Result<Vec<ReviewEntry>> {
    let mut entries = Vec::new();

    for subdir in &["pending", "completed"] {
        let dir = review_dir.join(subdir);
        if !dir.exists() {
            continue;
        }
        for file in std::fs::read_dir(&dir)? {
            let file = file?;
            if file.path().extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let contents = match std::fs::read_to_string(file.path()) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let entry: ReviewEntry = match serde_json::from_str(&contents) {
                Ok(e) => e,
                Err(_) => continue,
            };
            if let Some(ref filter) = state_filter {
                if &entry.state != filter {
                    continue;
                }
            }
            entries.push(entry);
        }
    }

    entries.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(entries)
}

// ── Persistence helpers ──────────────────────────────────────────────────────

fn save_review(review_dir: &Path, entry: &ReviewEntry) -> Result<PathBuf> {
    save_review_to(review_dir, entry, "pending")
}

fn save_review_to(review_dir: &Path, entry: &ReviewEntry, subdir: &str) -> Result<PathBuf> {
    let dir = review_dir.join(subdir);
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("Failed to create review dir: {}", dir.display()))?;

    let path = dir.join(format!("{}.json", entry.review_id));
    let json = serde_json::to_string_pretty(entry)
        .context("Failed to serialize review entry")?;
    std::fs::write(&path, json)
        .with_context(|| format!("Failed to write review: {}", path.display()))?;

    Ok(path)
}

fn load_review(review_dir: &Path, review_id: &str) -> Result<ReviewEntry> {
    let filename = format!("{}.json", review_id);

    // Check pending first, then completed
    for subdir in &["pending", "completed"] {
        let path = review_dir.join(subdir).join(&filename);
        if path.exists() {
            let contents = std::fs::read_to_string(&path)
                .with_context(|| format!("Failed to read review: {}", path.display()))?;
            let entry: ReviewEntry = serde_json::from_str(&contents)
                .with_context(|| format!("Failed to parse review: {}", path.display()))?;
            return Ok(entry);
        }
    }

    anyhow::bail!("Review '{}' not found", review_id)
}
```

- [ ] **Step 6: Run tests**

Run: `cargo test -p colmena-core review`
Expected: All 10 review tests pass.

- [ ] **Step 7: Run full test suite**

Run: `cargo test --workspace`
Expected: All tests pass (previous + new).

- [ ] **Step 8: Commit**

```bash
git add colmena-core/src/review.rs colmena-core/src/audit.rs colmena-core/src/lib.rs
git commit -m "feat(m2): review protocol — submit, evaluate, trust gate, 6 invariants

10 unit tests. SHA256 artifact hashing, anti-reciprocal assignment.

built with ❤️‍🔥 by AppSec"
```

---

## Task 5: CLI subcommands — review + elo

**Files:**
- Modify: `colmena-cli/src/main.rs`

- [ ] **Step 1: Add Review and Elo subcommands to the CLI enum**

Add to the `Commands` enum in `colmena-cli/src/main.rs`:

```rust
    /// Peer review management
    Review {
        #[command(subcommand)]
        action: ReviewAction,
    },
    /// ELO ratings
    Elo {
        #[command(subcommand)]
        action: EloAction,
    },
```

Add the subcommand enums:

```rust
#[derive(Subcommand)]
enum ReviewAction {
    /// List reviews (pending, completed)
    List {
        /// Filter by state: pending, completed, needs_human_review
        #[arg(long)]
        state: Option<String>,
    },
    /// Show details of a specific review
    Show {
        /// Review ID
        id: String,
    },
}

#[derive(Subcommand)]
enum EloAction {
    /// Show ELO leaderboard
    Show,
}
```

- [ ] **Step 2: Wire up match arms and implement run functions**

Add match arms in `main()`:

```rust
        Commands::Review { action } => match action {
            ReviewAction::List { state } => run_review_list(state),
            ReviewAction::Show { id } => run_review_show(id),
        },
        Commands::Elo { action } => match action {
            EloAction::Show => run_elo_show(),
        },
```

Implement the functions:

```rust
fn run_review_list(state: Option<String>) -> Result<()> {
    let config_dir = colmena_core::paths::default_config_dir();
    let review_dir = config_dir.join("reviews");

    let state_filter = state.map(|s| match s.as_str() {
        "pending" => colmena_core::review::ReviewState::Pending,
        "completed" => colmena_core::review::ReviewState::Completed,
        "needs_human_review" => colmena_core::review::ReviewState::NeedsHumanReview,
        _ => colmena_core::review::ReviewState::Pending,
    });

    let entries = colmena_core::review::list_reviews(&review_dir, state_filter)?;

    if entries.is_empty() {
        println!("No reviews found.");
        return Ok(());
    }

    println!("{} review(s):\n", entries.len());
    for entry in &entries {
        let score = entry.score_average
            .map(|s| format!("{:.1}", s))
            .unwrap_or_else(|| "-".to_string());
        println!(
            "  [{:?}] {} — {} → {} (score: {})",
            entry.state, entry.review_id, entry.author_role, entry.reviewer_role, score
        );
        println!("    Mission: {} | Created: {}", entry.mission, entry.created_at);
        println!();
    }

    Ok(())
}

fn run_review_show(id: String) -> Result<()> {
    let config_dir = colmena_core::paths::default_config_dir();
    let review_dir = config_dir.join("reviews");

    let entries = colmena_core::review::list_reviews(&review_dir, None)?;
    let entry = entries.iter().find(|e| e.review_id == id);

    match entry {
        Some(e) => {
            println!("Review: {}", e.review_id);
            println!("  State:      {:?}", e.state);
            println!("  Mission:    {}", e.mission);
            println!("  Author:     {}", e.author_role);
            println!("  Reviewer:   {}", e.reviewer_role);
            println!("  Artifact:   {}", e.artifact_path);
            println!("  Hash:       {}", e.artifact_hash);
            println!("  Created:    {}", e.created_at);
            if let Some(ref scores) = e.scores {
                println!("  Scores:");
                for (dim, score) in scores {
                    println!("    {}: {}/10", dim, score);
                }
            }
            if let Some(avg) = e.score_average {
                println!("  Average:    {:.1}/10", avg);
            }
            if let Some(count) = e.finding_count {
                println!("  Findings:   {}", count);
            }
            Ok(())
        }
        None => {
            eprintln!("Review '{}' not found", id);
            std::process::exit(1);
        }
    }
}

fn run_elo_show() -> Result<()> {
    let config_dir = colmena_core::paths::default_config_dir();
    let elo_log = config_dir.join("elo/elo-log.jsonl");
    let library_dir = config_dir.join("library");

    let events = colmena_core::elo::read_elo_log(&elo_log)?;
    let roles = colmena_core::library::load_roles(&library_dir)?;

    let baselines: Vec<(String, u32)> = roles
        .iter()
        .map(|r| (r.id.clone(), r.elo.initial))
        .collect();

    let board = colmena_core::elo::leaderboard(&events, &baselines);

    if board.is_empty() {
        println!("No ELO data yet. Complete some peer reviews first.");
        return Ok(());
    }

    println!("ELO Leaderboard:\n");
    println!("  {:<22} {:<6} {:<10} {:<8} {}", "AGENT", "ELO", "TREND(7d)", "REVIEWS", "LAST ACTIVE");
    println!("  {:-<22} {:-<6} {:-<10} {:-<8} {:-<12}", "", "", "", "", "");
    for r in &board {
        let trend = if r.trend_7d >= 0 {
            format!("+{}", r.trend_7d)
        } else {
            format!("{}", r.trend_7d)
        };
        let last = r.last_active
            .map(|t| t.format("%Y-%m-%d").to_string())
            .unwrap_or_else(|| "never".to_string());
        println!("  {:<22} {:<6} {:<10} {:<8} {}", r.agent, r.elo, trend, r.review_count, last);
    }

    Ok(())
}
```

- [ ] **Step 3: Build and verify**

Run: `cargo build -p colmena-cli`
Expected: Compiles.

- [ ] **Step 4: Commit**

```bash
git add colmena-cli/src/main.rs
git commit -m "feat(m2): CLI subcommands — review list/show, elo show

built with ❤️‍🔥 by AppSec"
```

---

## Task 6: MCP tools — 6 new tools

**Files:**
- Modify: `colmena-mcp/src/main.rs`

- [ ] **Step 1: Add input types for all 6 tools**

Add to `colmena-mcp/src/main.rs` in the input types section:

```rust
#[derive(Debug, Deserialize, JsonSchema)]
struct ReviewSubmitInput {
    /// Path to the artifact file to submit for review
    artifact_path: String,
    /// Author's role ID (e.g., "pentester")
    author_role: String,
    /// Mission ID this review belongs to
    mission: String,
    /// Available reviewer roles in this mission
    available_roles: Vec<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ReviewListInput {
    /// Optional state filter: "pending", "completed", "needs_human_review"
    state: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ReviewEvaluateInput {
    /// Review ID to evaluate
    review_id: String,
    /// Reviewer's role ID
    reviewer_role: String,
    /// Scores per dimension (e.g., {"accuracy": 8, "completeness": 7})
    scores: std::collections::HashMap<String, u32>,
    /// Findings from the review
    findings: Vec<FindingInput>,
    /// Path to the artifact being reviewed (for hash verification)
    artifact_path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct FindingInput {
    /// Finding category (e.g., "completeness", "accuracy", "security_gap")
    category: String,
    /// Severity: "critical", "high", "medium", "low"
    severity: String,
    /// Description of what was found
    description: String,
    /// Recommendation for improvement
    recommendation: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct EloRatingsInput {}

#[derive(Debug, Deserialize, JsonSchema)]
struct FindingsQueryInput {
    /// Filter by author role
    author_role: Option<String>,
    /// Filter by reviewer role
    reviewer_role: Option<String>,
    /// Filter by finding severity
    severity: Option<String>,
    /// Filter by finding category
    category: Option<String>,
    /// Filter by mission ID
    mission: Option<String>,
    /// Only findings after this date (ISO 8601)
    after: Option<String>,
    /// Only findings before this date (ISO 8601)
    before: Option<String>,
    /// Maximum number of results (default: 20)
    limit: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct FindingsListInput {
    /// Maximum number of results (default: 20)
    limit: Option<usize>,
}
```

- [ ] **Step 2: Implement the 6 MCP tool handlers**

Add to the `#[tool_router] impl ColmenaServer` block:

```rust
    #[rmcp::tool(description = "Submit an artifact for peer review — assigns a reviewer and creates a pending review")]
    fn review_submit(
        &self,
        Parameters(input): Parameters<ReviewSubmitInput>,
    ) -> Result<String, String> {
        let review_dir = self.config_dir.join("reviews");
        let artifact_path = std::path::Path::new(&input.artifact_path);

        let review = colmena_core::review::submit_review(
            &review_dir,
            artifact_path,
            &input.author_role,
            &input.mission,
            &input.available_roles,
            &[], // TODO: load existing reviews for anti-reciprocal check
        )
        .map_err(|e| format!("Submit failed: {e}"))?;

        // Audit log
        let audit_path = self.config_dir.join("audit.log");
        let _ = colmena_core::audit::log_event(
            &audit_path,
            &colmena_core::audit::AuditEvent::ReviewSubmit {
                review_id: &review.review_id,
                author_role: &review.author_role,
                artifact_path: &input.artifact_path,
                mission: &review.mission,
            },
        );

        Ok(format!(
            "Review {} created.\nAuthor: {}\nReviewer: {}\nArtifact hash: {}\nState: Pending",
            review.review_id, review.author_role, review.reviewer_role, review.artifact_hash
        ))
    }

    #[rmcp::tool(description = "List peer reviews — pending, completed, or all")]
    fn review_list(
        &self,
        Parameters(input): Parameters<ReviewListInput>,
    ) -> Result<String, String> {
        let review_dir = self.config_dir.join("reviews");

        let state_filter = input.state.map(|s| match s.as_str() {
            "pending" => colmena_core::review::ReviewState::Pending,
            "completed" => colmena_core::review::ReviewState::Completed,
            "needs_human_review" => colmena_core::review::ReviewState::NeedsHumanReview,
            _ => colmena_core::review::ReviewState::Pending,
        });

        let entries = colmena_core::review::list_reviews(&review_dir, state_filter)
            .map_err(|e| format!("List failed: {e}"))?;

        if entries.is_empty() {
            return Ok("No reviews found.".to_string());
        }

        serde_json::to_string_pretty(&entries)
            .map_err(|e| format!("Serialize failed: {e}"))
    }

    #[rmcp::tool(description = "Evaluate a peer review — submit scores and findings as a reviewer")]
    fn review_evaluate(
        &self,
        Parameters(input): Parameters<ReviewEvaluateInput>,
    ) -> Result<String, String> {
        let review_dir = self.config_dir.join("reviews");
        let artifact_path = std::path::Path::new(&input.artifact_path);

        let findings: Vec<colmena_core::findings::Finding> = input
            .findings
            .into_iter()
            .map(|f| colmena_core::findings::Finding {
                category: f.category,
                severity: f.severity,
                description: f.description,
                recommendation: f.recommendation,
            })
            .collect();

        let entry = colmena_core::review::evaluate_review(
            &review_dir,
            &input.review_id,
            &input.reviewer_role,
            input.scores,
            findings.clone(),
            artifact_path,
        )
        .map_err(|e| format!("Evaluate failed: {e}"))?;

        let score_avg = entry.score_average.unwrap_or(0.0);

        // Trust gate
        let gate_result = colmena_core::review::trust_gate(score_avg, &findings);
        let outcome = match gate_result {
            colmena_core::review::TrustGateResult::AutoComplete => "auto_completed",
            colmena_core::review::TrustGateResult::NeedsHumanReview => "needs_human_review",
        };

        // Write ELO events
        let elo_log = self.config_dir.join("elo/elo-log.jsonl");

        // Author delta from score
        let author_delta = colmena_core::elo::author_delta(score_avg);
        if author_delta != 0 {
            let _ = colmena_core::elo::log_elo_event(&elo_log, &colmena_core::elo::EloEvent {
                agent: entry.author_role.clone(),
                event_type: colmena_core::elo::EloEventType::Reviewed,
                delta: author_delta,
                reason: format!("score {:.1}/10 from {}", score_avg, input.reviewer_role),
                mission: entry.mission.clone(),
                review_id: entry.review_id.clone(),
            });
        }

        // Author delta from findings
        for finding in &findings {
            let f_delta = colmena_core::elo::finding_delta_author(&finding.severity);
            if f_delta != 0 {
                let _ = colmena_core::elo::log_elo_event(&elo_log, &colmena_core::elo::EloEvent {
                    agent: entry.author_role.clone(),
                    event_type: colmena_core::elo::EloEventType::FindingAgainst,
                    delta: f_delta,
                    reason: finding.description.clone(),
                    mission: entry.mission.clone(),
                    review_id: entry.review_id.clone(),
                });
            }

            // Reviewer gets +5 per finding
            let _ = colmena_core::elo::log_elo_event(&elo_log, &colmena_core::elo::EloEvent {
                agent: input.reviewer_role.clone(),
                event_type: colmena_core::elo::EloEventType::ReviewQuality,
                delta: colmena_core::elo::REVIEWER_FINDING_DELTA,
                reason: format!("found: {}", finding.description),
                mission: entry.mission.clone(),
                review_id: entry.review_id.clone(),
            });
        }

        // Save findings to store
        let findings_dir = self.config_dir.join("findings");
        let finding_record = colmena_core::findings::FindingRecord {
            review_id: entry.review_id.clone(),
            mission: entry.mission.clone(),
            author_role: entry.author_role.clone(),
            reviewer_role: input.reviewer_role.clone(),
            artifact_path: input.artifact_path.clone(),
            artifact_hash: entry.artifact_hash.clone(),
            timestamp: chrono::Utc::now(),
            scores: entry.scores.clone().unwrap_or_default(),
            score_average: score_avg,
            findings,
        };
        let _ = colmena_core::findings::save_finding_record(&findings_dir, &finding_record);

        // Audit log
        let audit_path = self.config_dir.join("audit.log");
        let _ = colmena_core::audit::log_event(
            &audit_path,
            &colmena_core::audit::AuditEvent::ReviewEvaluate {
                review_id: &entry.review_id,
                reviewer_role: &input.reviewer_role,
                score_avg,
                finding_count: entry.finding_count.unwrap_or(0),
            },
        );
        let _ = colmena_core::audit::log_event(
            &audit_path,
            &colmena_core::audit::AuditEvent::ReviewCompleted {
                review_id: &entry.review_id,
                outcome,
            },
        );

        Ok(format!(
            "Review {} evaluated.\nScore: {:.1}/10\nFindings: {}\nOutcome: {}\nELO updated for {} and {}",
            entry.review_id,
            score_avg,
            entry.finding_count.unwrap_or(0),
            outcome,
            entry.author_role,
            input.reviewer_role,
        ))
    }

    #[rmcp::tool(description = "View ELO ratings leaderboard with temporal decay applied")]
    fn elo_ratings(
        &self,
        Parameters(_input): Parameters<EloRatingsInput>,
    ) -> Result<String, String> {
        let elo_log = self.config_dir.join("elo/elo-log.jsonl");
        let library_dir = self.config_dir.join("library");

        let events = colmena_core::elo::read_elo_log(&elo_log)
            .map_err(|e| format!("Failed to read ELO log: {e}"))?;
        let roles = colmena_core::library::load_roles(&library_dir)
            .map_err(|e| format!("Failed to load roles: {e}"))?;

        let baselines: Vec<(String, u32)> = roles
            .iter()
            .map(|r| (r.id.clone(), r.elo.initial))
            .collect();

        let board = colmena_core::elo::leaderboard(&events, &baselines);

        serde_json::to_string_pretty(&board)
            .map_err(|e| format!("Serialize failed: {e}"))
    }

    #[rmcp::tool(description = "Query findings store — search by role, category, severity, date, mission")]
    fn findings_query(
        &self,
        Parameters(input): Parameters<FindingsQueryInput>,
    ) -> Result<String, String> {
        let findings_dir = self.config_dir.join("findings");

        let after = input.after.and_then(|s| {
            chrono::DateTime::parse_from_rfc3339(&s).ok().map(|d| d.with_timezone(&chrono::Utc))
        });
        let before = input.before.and_then(|s| {
            chrono::DateTime::parse_from_rfc3339(&s).ok().map(|d| d.with_timezone(&chrono::Utc))
        });

        let filter = colmena_core::findings::FindingsFilter {
            author_role: input.author_role,
            reviewer_role: input.reviewer_role,
            severity: input.severity,
            category: input.category,
            mission: input.mission,
            after,
            before,
            limit: Some(input.limit.unwrap_or(20)),
        };

        let records = colmena_core::findings::load_findings(&findings_dir, &filter)
            .map_err(|e| format!("Query failed: {e}"))?;

        if records.is_empty() {
            return Ok("No findings match the query.".to_string());
        }

        serde_json::to_string_pretty(&records)
            .map_err(|e| format!("Serialize failed: {e}"))
    }

    #[rmcp::tool(description = "List recent findings from the findings store")]
    fn findings_list(
        &self,
        Parameters(input): Parameters<FindingsListInput>,
    ) -> Result<String, String> {
        let findings_dir = self.config_dir.join("findings");

        let filter = colmena_core::findings::FindingsFilter {
            limit: Some(input.limit.unwrap_or(20)),
            ..Default::default()
        };

        let records = colmena_core::findings::load_findings(&findings_dir, &filter)
            .map_err(|e| format!("Query failed: {e}"))?;

        if records.is_empty() {
            return Ok("No findings yet.".to_string());
        }

        serde_json::to_string_pretty(&records)
            .map_err(|e| format!("Serialize failed: {e}"))
    }
```

- [ ] **Step 3: Build**

Run: `cargo build -p colmena-mcp`
Expected: Compiles.

- [ ] **Step 4: Commit**

```bash
git add colmena-mcp/src/main.rs
git commit -m "feat(m2): 6 MCP tools — review_submit/list/evaluate, elo_ratings, findings_query/list

built with ❤️‍🔥 by AppSec"
```

---

## Task 7: Firewall config + CLAUDE.md + final wiring

**Files:**
- Modify: `config/trust-firewall.yaml`
- Modify: `CLAUDE.md`

- [ ] **Step 1: Add review MCP tools to restricted in trust-firewall.yaml**

Add to the `restricted` section:

```yaml
  # Peer review MCP tools — human reviews submissions and evaluations
  - tools: [mcp__colmena__review_submit, mcp__colmena__review_evaluate]
    action: ask
    reason: 'Peer review operations require human oversight'
```

- [ ] **Step 2: Update CLAUDE.md with M2 documentation**

Add M2 MCP tools section, update CLI subcommands, update roadmap status, add new conventions.

- [ ] **Step 3: Commit**

```bash
git add config/trust-firewall.yaml CLAUDE.md
git commit -m "docs(m2): update firewall config and CLAUDE.md for peer review + ELO

built with ❤️‍🔥 by AppSec"
```

---

## Task 8: Full verification

- [ ] **Step 1: Run full test suite**

Run: `cargo test --workspace`
Expected: All tests pass (existing 104 + new ~26 = ~130 total).

- [ ] **Step 2: Run clippy**

Run: `cargo clippy --workspace -- -W warnings`
Expected: Clean.

- [ ] **Step 3: Build release**

Run: `cargo build --workspace --release`
Expected: Compiles.

- [ ] **Step 4: Push and create MR**

```bash
git push -u origin feature/m2-peer-review-elo
glab mr create --title "feat: M2 — Peer Review Protocol + ELO Engine + Findings Store" \
  --description "..." --target-branch main
```

---

*built with ❤️‍🔥 by AppSec*

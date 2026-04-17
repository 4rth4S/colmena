use std::io::{BufRead, Write};
use std::path::Path;

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

/// ELO event types for the rating system.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum EloEventType {
    Reviewed,
    FindingAgainst,
    ReviewQuality,
}

/// An ELO event as submitted (no timestamp — added at write time).
#[derive(Debug, Clone)]
pub struct EloEvent {
    pub agent: String,
    pub event_type: EloEventType,
    pub delta: i32,
    pub reason: String,
    pub mission: String,
    pub review_id: String,
}

/// A stored ELO event (with timestamp, for JSONL persistence).
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

/// An agent's computed rating.
#[derive(Debug, Clone)]
pub struct AgentRating {
    pub agent: String,
    pub elo: i32,
    pub trend_7d: i32,
    pub review_count: u32,
    pub last_active: Option<DateTime<Utc>>,
}

/// Constant: ELO delta awarded to a reviewer for each finding.
pub const REVIEWER_FINDING_DELTA: i32 = 5;

/// Compute the ELO delta for an author based on average review score.
///
/// - score >= 8 → positive: +(score - 7) * 3
/// - score 5-7 → neutral: 0
/// - score < 5 → negative: -(6 - score) * 4
pub fn author_delta(score_avg: f64) -> i32 {
    if score_avg >= 8.0 {
        ((score_avg - 7.0) * 3.0) as i32
    } else if score_avg >= 5.0 {
        0
    } else {
        -((6.0 - score_avg) * 4.0) as i32
    }
}

/// Compute the ELO delta for an author based on finding severity.
///
/// - "critical" → -10
/// - "high" → -5
/// - anything else → 0
pub fn finding_delta_author(severity: &str) -> i32 {
    match severity {
        "critical" => -10,
        "high" => -5,
        _ => 0,
    }
}

/// Compute a temporal decay factor based on event age.
///
/// - < 7 days → 1.0
/// - 7-30 days → 0.7
/// - 30-90 days → 0.4
/// - > 90 days → 0.1
pub fn decay_factor(event_ts: DateTime<Utc>, now: DateTime<Utc>) -> f64 {
    let age = now - event_ts;
    if age < Duration::days(7) {
        1.0
    } else if age < Duration::days(30) {
        0.7
    } else if age < Duration::days(90) {
        0.4
    } else {
        0.1
    }
}

/// Maximum ELO log size before rotation (10 MiB).
const MAX_ELO_LOG_BYTES: u64 = 10 * 1024 * 1024;

/// Rotate the ELO log if it has exceeded MAX_ELO_LOG_BYTES.
/// The current log is renamed to `.jsonl.1`, overwriting any previous rotation.
/// Best-effort: silently ignores rotation errors (append still proceeds normally).
fn maybe_rotate(log_path: &Path) {
    let size = std::fs::metadata(log_path).map(|m| m.len()).unwrap_or(0);
    if size >= MAX_ELO_LOG_BYTES {
        let rotated = log_path.with_extension("jsonl.1");
        let _ = std::fs::rename(log_path, rotated);
    }
}

/// Append an ELO event to a JSONL log file. Creates parent dirs if needed.
pub fn log_elo_event(log_path: &Path, event: &EloEvent) -> Result<()> {
    maybe_rotate(log_path);

    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating parent dirs for {}", log_path.display()))?;
    }

    let stored = StoredEloEvent {
        ts: Utc::now(),
        agent: event.agent.clone(),
        event_type: event.event_type.clone(),
        delta: event.delta,
        reason: event.reason.clone(),
        mission: event.mission.clone(),
        review_id: event.review_id.clone(),
    };

    let line = serde_json::to_string(&stored).context("serializing ELO event")?;

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .with_context(|| format!("opening ELO log at {}", log_path.display()))?;

    writeln!(file, "{}", line)?;
    Ok(())
}

/// Read all ELO events from a JSONL log file. Skips malformed lines.
pub fn read_elo_log(log_path: &Path) -> Result<Vec<StoredEloEvent>> {
    if !log_path.exists() {
        return Ok(Vec::new());
    }

    let file = std::fs::File::open(log_path)
        .with_context(|| format!("opening ELO log at {}", log_path.display()))?;

    let reader = std::io::BufReader::new(file);
    let mut events = Vec::new();

    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(event) = serde_json::from_str::<StoredEloEvent>(trimmed) {
            events.push(event);
        }
        // Skip malformed lines silently
    }

    Ok(events)
}

/// Minimum activity window for ELO rehabilitation: agents must have positive
/// activity within this period for temporal decay to raise their ELO above
/// baseline. Prevents passive rehabilitation via inactivity.
const REHABILITATION_ACTIVITY_WINDOW_DAYS: i64 = 30;

/// Calculate an agent's rating from stored events with temporal decay.
///
/// - Starts from `baseline` ELO
/// - Each event's delta is multiplied by its decay factor
/// - `trend_7d` is the sum of deltas from events in the last 7 days (no decay)
/// - `review_count` is the number of `Reviewed` events for this agent
/// - `last_active` is the most recent event timestamp for this agent
///
/// Fix Finding #26 (DREAD 5.2): Temporal decay does not allow an agent's ELO
/// to rise above their last active rating without recent positive reviews.
/// An inactive agent in probation cannot passively rehabilitate by waiting for
/// negative events to decay.
pub fn calculate_rating(agent: &str, events: &[StoredEloEvent], baseline: u32) -> AgentRating {
    let now = Utc::now();
    let agent_events: Vec<&StoredEloEvent> = events.iter().filter(|e| e.agent == agent).collect();

    let mut elo = baseline as i32;
    let mut trend_7d: i32 = 0;
    let mut review_count: u32 = 0;
    let mut last_active: Option<DateTime<Utc>> = None;

    // Track whether agent has recent positive activity
    let has_recent_positive = agent_events
        .iter()
        .any(|e| e.delta > 0 && (now - e.ts) < Duration::days(REHABILITATION_ACTIVITY_WINDOW_DAYS));

    // Calculate ELO without decay to get the "undecayed floor"
    let mut elo_no_decay = baseline as i32;
    for event in &agent_events {
        elo_no_decay += event.delta;
    }

    for event in &agent_events {
        let decay = decay_factor(event.ts, now);
        elo += (event.delta as f64 * decay) as i32;

        if now - event.ts < Duration::days(7) {
            trend_7d += event.delta;
        }

        if event.event_type == EloEventType::Reviewed {
            review_count += 1;
        }

        match last_active {
            None => last_active = Some(event.ts),
            Some(prev) if event.ts > prev => last_active = Some(event.ts),
            _ => {}
        }
    }

    // Anti-rehabilitation: if agent has NO recent positive activity and their decayed
    // ELO is higher than their undecayed ELO, cap at the undecayed value.
    // This prevents passive rehabilitation: negative events decaying to 10% without
    // any improvement means the agent shouldn't rise above their actual performance.
    if !agent_events.is_empty() && !has_recent_positive && elo > elo_no_decay {
        elo = elo_no_decay;
    }

    AgentRating {
        agent: agent.to_string(),
        elo,
        trend_7d,
        review_count,
        last_active,
    }
}

/// Build a leaderboard from all events, sorted by ELO descending.
///
/// Each entry in `baselines` is (agent_name, baseline_elo).
/// Agents present in events but not in baselines get a baseline of 1000.
pub fn leaderboard(events: &[StoredEloEvent], baselines: &[(String, u32)]) -> Vec<AgentRating> {
    let baseline_map: std::collections::HashMap<&str, u32> = baselines
        .iter()
        .map(|(name, elo)| (name.as_str(), *elo))
        .collect();

    // Collect all unique agents from both baselines and events
    let mut agents: std::collections::HashSet<String> =
        baselines.iter().map(|(name, _)| name.clone()).collect();
    for event in events {
        agents.insert(event.agent.clone());
    }

    let mut ratings: Vec<AgentRating> = agents
        .into_iter()
        .map(|agent| {
            let base = baseline_map.get(agent.as_str()).copied().unwrap_or(1000);
            calculate_rating(&agent, events, base)
        })
        .collect();

    ratings.sort_by_key(|r| std::cmp::Reverse(r.elo));
    ratings
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use tempfile::TempDir;

    fn make_stored_event(
        agent: &str,
        event_type: EloEventType,
        delta: i32,
        ts: DateTime<Utc>,
    ) -> StoredEloEvent {
        StoredEloEvent {
            ts,
            agent: agent.to_string(),
            event_type,
            delta,
            reason: "test".to_string(),
            mission: "test-mission".to_string(),
            review_id: "rev-001".to_string(),
        }
    }

    #[test]
    fn test_log_elo_event_and_read() {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("elo/events.jsonl");

        let event = EloEvent {
            agent: "pentester".to_string(),
            event_type: EloEventType::Reviewed,
            delta: 9,
            reason: "solid code review".to_string(),
            mission: "audit-payments".to_string(),
            review_id: "rev-001".to_string(),
        };

        log_elo_event(&log_path, &event).unwrap();
        log_elo_event(&log_path, &event).unwrap();

        let events = read_elo_log(&log_path).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].agent, "pentester");
        assert_eq!(events[0].event_type, EloEventType::Reviewed);
        assert_eq!(events[0].delta, 9);
        assert_eq!(events[0].mission, "audit-payments");
    }

    #[test]
    fn test_calculate_rating_no_events() {
        let events: Vec<StoredEloEvent> = vec![];
        let rating = calculate_rating("ghost", &events, 1000);

        assert_eq!(rating.agent, "ghost");
        assert_eq!(rating.elo, 1000);
        assert_eq!(rating.trend_7d, 0);
        assert_eq!(rating.review_count, 0);
        assert!(rating.last_active.is_none());
    }

    #[test]
    fn test_calculate_rating_with_events() {
        let now = Utc::now();
        let events = vec![
            make_stored_event(
                "coder",
                EloEventType::Reviewed,
                10,
                now - Duration::hours(1),
            ),
            make_stored_event(
                "coder",
                EloEventType::FindingAgainst,
                -5,
                now - Duration::hours(2),
            ),
        ];

        let rating = calculate_rating("coder", &events, 1000);

        // Both events are recent (< 7d), decay = 1.0 → 1000 + 10 - 5 = 1005
        assert_eq!(rating.elo, 1005);
        assert_eq!(rating.trend_7d, 5); // 10 + (-5)
        assert_eq!(rating.review_count, 1);
        assert!(rating.last_active.is_some());
    }

    #[test]
    fn test_decay_factor() {
        let now = Utc::now();

        // < 7 days → 1.0
        assert_eq!(decay_factor(now - Duration::days(1), now), 1.0);
        assert_eq!(decay_factor(now - Duration::days(6), now), 1.0);

        // 7-30 days → 0.7
        assert_eq!(decay_factor(now - Duration::days(7), now), 0.7);
        assert_eq!(decay_factor(now - Duration::days(29), now), 0.7);

        // 30-90 days → 0.4
        assert_eq!(decay_factor(now - Duration::days(30), now), 0.4);
        assert_eq!(decay_factor(now - Duration::days(89), now), 0.4);

        // > 90 days → 0.1
        assert_eq!(decay_factor(now - Duration::days(90), now), 0.1);
        assert_eq!(decay_factor(now - Duration::days(365), now), 0.1);
    }

    #[test]
    fn test_calculate_rating_with_decay() {
        let now = Utc::now();
        let events = vec![
            // 60-day-old event → decay 0.4 → 10 * 0.4 = 4
            make_stored_event(
                "coder",
                EloEventType::Reviewed,
                10,
                now - Duration::days(60),
            ),
        ];

        let rating = calculate_rating("coder", &events, 1000);

        // 1000 + (10 * 0.4) = 1004
        assert_eq!(rating.elo, 1004);
        // Not within 7d, so trend is 0
        assert_eq!(rating.trend_7d, 0);
        assert_eq!(rating.review_count, 1);
    }

    #[test]
    fn test_leaderboard() {
        let now = Utc::now();
        let events = vec![
            make_stored_event(
                "alice",
                EloEventType::Reviewed,
                20,
                now - Duration::hours(1),
            ),
            make_stored_event("bob", EloEventType::Reviewed, -10, now - Duration::hours(1)),
            make_stored_event(
                "charlie",
                EloEventType::Reviewed,
                5,
                now - Duration::hours(1),
            ),
        ];

        let baselines = vec![
            ("alice".to_string(), 1000),
            ("bob".to_string(), 1000),
            ("charlie".to_string(), 1000),
        ];

        let board = leaderboard(&events, &baselines);

        assert_eq!(board.len(), 3);
        assert_eq!(board[0].agent, "alice"); // 1020
        assert_eq!(board[1].agent, "charlie"); // 1005
        assert_eq!(board[2].agent, "bob"); // 990
        assert_eq!(board[0].elo, 1020);
        assert_eq!(board[1].elo, 1005);
        assert_eq!(board[2].elo, 990);
    }

    #[test]
    fn test_author_delta_high_score() {
        // score >= 8 → +(score - 7) * 3
        assert_eq!(author_delta(8.0), 3); // (8-7)*3 = 3
        assert_eq!(author_delta(9.0), 6); // (9-7)*3 = 6
        assert_eq!(author_delta(10.0), 9); // (10-7)*3 = 9
    }

    #[test]
    fn test_author_delta_neutral() {
        // score 5-7 → 0
        assert_eq!(author_delta(5.0), 0);
        assert_eq!(author_delta(6.0), 0);
        assert_eq!(author_delta(7.0), 0);
        assert_eq!(author_delta(7.9), 0);
    }

    #[test]
    fn test_author_delta_low_score() {
        // score < 5 → -(6 - score) * 4
        assert_eq!(author_delta(4.0), -8); // -(6-4)*4 = -8
        assert_eq!(author_delta(2.0), -16); // -(6-2)*4 = -16
        assert_eq!(author_delta(1.0), -20); // -(6-1)*4 = -20
    }

    #[test]
    fn test_finding_delta() {
        assert_eq!(finding_delta_author("critical"), -10);
        assert_eq!(finding_delta_author("high"), -5);
        assert_eq!(finding_delta_author("medium"), 0);
        assert_eq!(finding_delta_author("low"), 0);
    }

    // ── Finding #26 (DREAD 5.2): Passive rehabilitation prevention tests ──

    #[test]
    fn test_passive_rehabilitation_blocked_without_recent_positive() {
        // Agent has only old negative events (> 90 days). Without the fix,
        // temporal decay (0.1) would raise ELO close to baseline.
        // With the fix, ELO is capped at the undecayed value.
        let now = Utc::now();
        let events = vec![
            // 100-day-old negative event: -50 * 0.1 = -5 (decayed)
            // Without cap: 1000 - 5 = 995
            // With cap (undecayed): 1000 - 50 = 950
            make_stored_event(
                "bad-agent",
                EloEventType::FindingAgainst,
                -50,
                now - Duration::days(100),
            ),
        ];

        let rating = calculate_rating("bad-agent", &events, 1000);

        // Undecayed: 1000 + (-50) = 950
        // Decayed would be: 1000 + (-50 * 0.1) = 995
        // Anti-rehabilitation cap should kick in: no recent positive activity
        assert_eq!(
            rating.elo, 950,
            "Without recent positive activity, ELO should be capped at undecayed value (950), not decayed value (~995)"
        );
    }

    #[test]
    fn test_rehabilitation_allowed_with_recent_positive() {
        // Agent has old negative events AND recent positive events.
        // Decay should apply normally — the agent has demonstrated improvement.
        let now = Utc::now();
        let events = vec![
            // Old negative: -50 * 0.1 = -5 (decayed)
            make_stored_event(
                "improving-agent",
                EloEventType::FindingAgainst,
                -50,
                now - Duration::days(100),
            ),
            // Recent positive: +10 * 1.0 = +10 (no decay, within 7 days)
            make_stored_event(
                "improving-agent",
                EloEventType::Reviewed,
                10,
                now - Duration::days(1),
            ),
        ];

        let rating = calculate_rating("improving-agent", &events, 1000);

        // With decay: 1000 + (-50 * 0.1) + (10 * 1.0) = 1000 - 5 + 10 = 1005
        // Undecayed: 1000 + (-50) + 10 = 960
        // Has recent positive → decay applies normally → 1005
        assert_eq!(
            rating.elo, 1005,
            "With recent positive activity, ELO should use decayed values normally"
        );
    }

    #[test]
    fn test_no_events_no_rehabilitation_cap() {
        // Agent with no events — baseline unchanged, no cap needed
        let events: Vec<StoredEloEvent> = vec![];
        let rating = calculate_rating("new-agent", &events, 1000);
        assert_eq!(
            rating.elo, 1000,
            "Agent with no events should stay at baseline"
        );
    }

    #[test]
    fn test_rehabilitation_cap_with_multiple_old_negatives() {
        // Agent with multiple old negative events, no positive activity at all
        let now = Utc::now();
        let events = vec![
            make_stored_event(
                "repeat-offender",
                EloEventType::FindingAgainst,
                -30,
                now - Duration::days(95),
            ),
            make_stored_event(
                "repeat-offender",
                EloEventType::FindingAgainst,
                -20,
                now - Duration::days(100),
            ),
            make_stored_event(
                "repeat-offender",
                EloEventType::FindingAgainst,
                -10,
                now - Duration::days(120),
            ),
        ];

        let rating = calculate_rating("repeat-offender", &events, 1000);

        // Undecayed: 1000 - 30 - 20 - 10 = 940
        // Decayed: 1000 + (-30*0.1) + (-20*0.1) + (-10*0.1) = 1000 - 3 - 2 - 1 = 994
        // Anti-rehabilitation: cap at 940
        assert_eq!(
            rating.elo, 940,
            "Multiple old negatives without positive activity should cap at undecayed floor"
        );
    }

    #[test]
    fn test_elo_log_rotation() {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("elo-log.jsonl");

        // Create an oversized log file (just over 10 MiB)
        let filler = "x".repeat(1024);
        {
            let mut f = std::fs::File::create(&log_path).unwrap();
            for _ in 0..(10 * 1024 + 1) {
                use std::io::Write;
                writeln!(f, "{}", filler).unwrap();
            }
        }
        assert!(std::fs::metadata(&log_path).unwrap().len() >= MAX_ELO_LOG_BYTES);

        let event = EloEvent {
            agent: "tester".to_string(),
            event_type: EloEventType::Reviewed,
            delta: 5,
            reason: "rotation test".to_string(),
            mission: "test-mission".to_string(),
            review_id: "rev-rot".to_string(),
        };

        log_elo_event(&log_path, &event).unwrap();

        // Old file should have been rotated
        let rotated = log_path.with_extension("jsonl.1");
        assert!(rotated.exists(), "rotated file should exist");

        // New log should contain only the fresh event
        let events = read_elo_log(&log_path).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].agent, "tester");
    }
}

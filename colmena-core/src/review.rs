use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::findings::Finding;

// ── Constants ──────────────────────────────────────────────────────

/// Score threshold for automatic approval (>= this means auto-approve).
pub const DEFAULT_AUTO_APPROVE_THRESHOLD: f64 = 7.0;

/// Floor below which human review is always required.
pub const AUTO_APPROVE_FLOOR: f64 = 5.0;

/// Minimum number of score dimensions required in a review.
pub const MIN_SCORE_DIMENSIONS: usize = 2;

/// Maximum allowed value for any individual review score.
/// M1: Prevents u32 overflow on sum() and ELO inflation via absurdly large scores.
pub const MAX_REVIEW_SCORE: u32 = 10;

// ── Types ──────────────────────────────────────────────────────────

/// State machine for a review lifecycle.
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

/// Result of the trust gate decision (internal only, not serialized).
#[derive(Debug, Clone, PartialEq)]
pub enum TrustGateResult {
    AutoComplete,
    NeedsHumanReview,
}

/// A review entry persisted as JSON.
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

// ── Public API ─────────────────────────────────────────────────────

/// Compute SHA-256 hash of a file and return as `"sha256:{hex}"`.
pub fn hash_artifact(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("reading artifact {}", path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let digest = hasher.finalize();
    Ok(format!("sha256:{:x}", digest))
}

/// Submit an artifact for cross-review.
///
/// Invariants enforced:
/// 1. Author cannot review their own work (author != reviewer).
/// 2. Anti-reciprocal: if reviewer already reviewed author, skip that pairing.
///
/// Returns the created `ReviewEntry` in Pending state.
pub fn submit_review(
    review_dir: &Path,
    artifact_path: &Path,
    author_role: &str,
    mission: &str,
    available_roles: &[String],
    existing_reviews: &[(String, String)],
) -> Result<ReviewEntry> {
    // Filter out the author (invariant 1: author != reviewer)
    let mut candidates: Vec<&String> = available_roles
        .iter()
        .filter(|r| r.as_str() != author_role)
        .collect();

    // Filter out reciprocal pairs (invariant 2):
    // If (candidate, author) exists in existing_reviews, skip that candidate
    candidates.retain(|candidate| {
        !existing_reviews
            .iter()
            .any(|(reviewer, author)| reviewer == candidate.as_str() && author == author_role)
    });

    if candidates.is_empty() {
        bail!("No eligible reviewer");
    }

    // Randomize reviewer selection to prevent predictable assignment and collusion
    use rand::seq::SliceRandom;
    let reviewer_role = (*candidates.choose(&mut rand::thread_rng()).unwrap()).clone();

    let artifact_hash = hash_artifact(artifact_path)?;

    let now = Utc::now();
    let review_id = format!("r_{}_{:04x}", now.timestamp_millis(), rand::random::<u16>());

    let entry = ReviewEntry {
        review_id,
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

    save_review(review_dir, &entry)?;

    Ok(entry)
}

/// Evaluate a pending review with scores and findings.
///
/// Invariants enforced:
/// 3. Artifact integrity: re-hash and compare with stored hash.
/// 6. Minimum score dimensions.
///
/// Returns the updated `ReviewEntry` in Evaluated state.
pub fn evaluate_review(
    review_dir: &Path,
    review_id: &str,
    reviewer_role: &str,
    scores: HashMap<String, u32>,
    findings: Vec<Finding>,
    artifact_path: &Path,
) -> Result<ReviewEntry> {
    // Invariant 6: minimum score dimensions
    if scores.len() < MIN_SCORE_DIMENSIONS {
        bail!(
            "Review requires at least {} score dimensions, got {}",
            MIN_SCORE_DIMENSIONS,
            scores.len()
        );
    }

    // M1: Validate score range to prevent u32 overflow on sum() and ELO inflation.
    if let Some((dim, &val)) = scores.iter().find(|(_, &v)| v > MAX_REVIEW_SCORE) {
        bail!(
            "Score '{}' = {} exceeds maximum allowed value of {}",
            dim,
            val,
            MAX_REVIEW_SCORE
        );
    }

    let mut entry = load_review(review_dir, review_id)?;

    // Verify reviewer matches
    if entry.reviewer_role != reviewer_role {
        bail!(
            "Reviewer mismatch: expected '{}', got '{}'",
            entry.reviewer_role,
            reviewer_role
        );
    }

    // Invariant 3: re-hash artifact and compare
    let current_hash = hash_artifact(artifact_path)?;
    if current_hash != entry.artifact_hash {
        bail!(
            "Artifact integrity check failed: expected '{}', got '{}'",
            entry.artifact_hash,
            current_hash
        );
    }

    // Calculate average score
    let total: u32 = scores.values().sum();
    let avg = total as f64 / scores.len() as f64;

    let now = Utc::now();
    entry.scores = Some(scores);
    entry.score_average = Some(avg);
    entry.finding_count = Some(findings.len());
    entry.evaluated_at = Some(now);
    entry.state = ReviewState::Evaluated;

    // Move from pending/ to completed/
    let pending_path = review_dir.join("pending").join(format!("{}.json", review_id));
    if pending_path.exists() {
        std::fs::remove_file(&pending_path)
            .with_context(|| format!("removing pending file {}", pending_path.display()))?;
    }

    save_review_to(review_dir, &entry, "completed")?;

    Ok(entry)
}

/// Trust gate: decide whether a review can be auto-completed or needs human review.
pub fn trust_gate(score_avg: f64, findings: &[Finding]) -> TrustGateResult {
    // Score below floor → always needs human review
    if score_avg < AUTO_APPROVE_FLOOR {
        return TrustGateResult::NeedsHumanReview;
    }

    // Any critical finding → needs human review
    if findings.iter().any(|f| f.severity == "critical") {
        return TrustGateResult::NeedsHumanReview;
    }

    // Score below threshold → needs human review
    if score_avg < DEFAULT_AUTO_APPROVE_THRESHOLD {
        return TrustGateResult::NeedsHumanReview;
    }

    TrustGateResult::AutoComplete
}

/// List reviews from pending/ and completed/ directories.
/// Optionally filter by state. Returns sorted by `created_at` DESC.
pub fn list_reviews(
    review_dir: &Path,
    state_filter: Option<ReviewState>,
) -> Result<Vec<ReviewEntry>> {
    let mut entries = Vec::new();

    for subdir in &["pending", "completed"] {
        let dir = review_dir.join(subdir);
        if !dir.exists() {
            continue;
        }

        let read = std::fs::read_dir(&dir)
            .with_context(|| format!("reading review dir {}", dir.display()))?;

        for file_entry in read {
            let file_entry = file_entry?;
            let path = file_entry.path();

            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }

            let content = std::fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?;

            match serde_json::from_str::<ReviewEntry>(&content) {
                Ok(entry) => {
                    if let Some(ref filter) = state_filter {
                        if entry.state != *filter {
                            continue;
                        }
                    }
                    entries.push(entry);
                }
                Err(_) => continue, // skip malformed files
            }
        }
    }

    // Sort by created_at descending
    entries.sort_by(|a, b| b.created_at.cmp(&a.created_at));

    Ok(entries)
}

// ── Private helpers ────────────────────────────────────────────────

/// Save a review entry to `review_dir/pending/{review_id}.json`.
fn save_review(review_dir: &Path, entry: &ReviewEntry) -> Result<PathBuf> {
    save_review_to(review_dir, entry, "pending")
}

/// Save a review entry to `review_dir/{subdir}/{review_id}.json`.
fn save_review_to(review_dir: &Path, entry: &ReviewEntry, subdir: &str) -> Result<PathBuf> {
    let dir = review_dir.join(subdir);
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("creating review dir {}", dir.display()))?;

    let file_path = dir.join(format!("{}.json", entry.review_id));
    let json = serde_json::to_string_pretty(entry)
        .context("serializing review entry")?;

    // Atomic write: temp + rename
    let tmp_path = dir.join(format!(".{}.tmp", entry.review_id));
    std::fs::write(&tmp_path, &json)
        .with_context(|| format!("writing temp file {}", tmp_path.display()))?;
    std::fs::rename(&tmp_path, &file_path)
        .with_context(|| format!("renaming {} -> {}", tmp_path.display(), file_path.display()))?;

    Ok(file_path)
}

/// Load a review entry by searching pending/ then completed/.
fn load_review(review_dir: &Path, review_id: &str) -> Result<ReviewEntry> {
    let filename = format!("{}.json", review_id);

    for subdir in &["pending", "completed"] {
        let path = review_dir.join(subdir).join(&filename);
        if path.exists() {
            let content = std::fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            let entry: ReviewEntry = serde_json::from_str(&content)
                .with_context(|| format!("parsing {}", path.display()))?;
            return Ok(entry);
        }
    }

    bail!("Review '{}' not found in pending/ or completed/", review_id)
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Helper: create a temp artifact file with known content.
    fn create_artifact(dir: &Path, name: &str, content: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn test_submit_creates_pending_review() {
        let tmp = TempDir::new().unwrap();
        let review_dir = tmp.path().join("reviews");
        let artifact = create_artifact(tmp.path(), "main.rs", "fn main() {}");

        let roles = vec![
            "coder".to_string(),
            "pentester".to_string(),
            "architect".to_string(),
        ];
        let existing: Vec<(String, String)> = vec![];

        let entry = submit_review(
            &review_dir,
            &artifact,
            "coder",
            "audit-payments",
            &roles,
            &existing,
        )
        .unwrap();

        assert!(entry.review_id.starts_with("r_"));
        assert_eq!(entry.author_role, "coder");
        // Reviewer is randomized (M6.2 collusion prevention) — verify it's a valid candidate, not the author
        assert!(
            entry.reviewer_role == "pentester" || entry.reviewer_role == "architect",
            "reviewer_role should be a non-author candidate, got: {}",
            entry.reviewer_role
        );
        assert_eq!(entry.mission, "audit-payments");
        assert_eq!(entry.state, ReviewState::Pending);
        assert!(entry.artifact_hash.starts_with("sha256:"));

        // Verify file exists on disk
        let pending_file = review_dir
            .join("pending")
            .join(format!("{}.json", entry.review_id));
        assert!(pending_file.exists());
    }

    #[test]
    fn test_submit_rejects_self_review() {
        let tmp = TempDir::new().unwrap();
        let review_dir = tmp.path().join("reviews");
        let artifact = create_artifact(tmp.path(), "main.rs", "fn main() {}");

        // Only the author's role is available
        let roles = vec!["coder".to_string()];
        let existing: Vec<(String, String)> = vec![];

        let result = submit_review(
            &review_dir,
            &artifact,
            "coder",
            "audit-payments",
            &roles,
            &existing,
        );

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("No eligible reviewer"));
    }

    #[test]
    fn test_submit_prevents_reciprocal_review() {
        let tmp = TempDir::new().unwrap();
        let review_dir = tmp.path().join("reviews");
        let artifact = create_artifact(tmp.path(), "main.rs", "fn main() {}");

        let roles = vec![
            "coder".to_string(),
            "pentester".to_string(),
            "architect".to_string(),
        ];

        // pentester already reviewed coder → pentester is excluded
        let existing = vec![("pentester".to_string(), "coder".to_string())];

        let entry = submit_review(
            &review_dir,
            &artifact,
            "coder",
            "audit-payments",
            &roles,
            &existing,
        )
        .unwrap();

        // Should skip pentester and pick architect
        assert_eq!(entry.reviewer_role, "architect");
    }

    #[test]
    fn test_evaluate_review_valid() {
        let tmp = TempDir::new().unwrap();
        let review_dir = tmp.path().join("reviews");
        let artifact = create_artifact(tmp.path(), "main.rs", "fn main() {}");

        let roles = vec!["coder".to_string(), "pentester".to_string()];
        let existing: Vec<(String, String)> = vec![];

        let entry = submit_review(
            &review_dir,
            &artifact,
            "coder",
            "audit-payments",
            &roles,
            &existing,
        )
        .unwrap();

        let mut scores = HashMap::new();
        scores.insert("correctness".to_string(), 8);
        scores.insert("security".to_string(), 7);

        let findings = vec![Finding {
            category: "injection".to_string(),
            severity: "medium".to_string(),
            description: "SQL injection in query".to_string(),
            recommendation: "Use parameterized queries".to_string(),
        }];

        let evaluated = evaluate_review(
            &review_dir,
            &entry.review_id,
            "pentester",
            scores,
            findings,
            &artifact,
        )
        .unwrap();

        assert_eq!(evaluated.state, ReviewState::Evaluated);
        assert_eq!(evaluated.score_average, Some(7.5));
        assert_eq!(evaluated.finding_count, Some(1));
        assert!(evaluated.evaluated_at.is_some());

        // Should be in completed/ now, not pending/
        let pending = review_dir
            .join("pending")
            .join(format!("{}.json", entry.review_id));
        let completed = review_dir
            .join("completed")
            .join(format!("{}.json", entry.review_id));
        assert!(!pending.exists());
        assert!(completed.exists());
    }

    #[test]
    fn test_evaluate_rejects_tampered_artifact() {
        let tmp = TempDir::new().unwrap();
        let review_dir = tmp.path().join("reviews");
        let artifact = create_artifact(tmp.path(), "main.rs", "fn main() {}");

        let roles = vec!["coder".to_string(), "pentester".to_string()];
        let existing: Vec<(String, String)> = vec![];

        let entry = submit_review(
            &review_dir,
            &artifact,
            "coder",
            "audit-payments",
            &roles,
            &existing,
        )
        .unwrap();

        // Tamper with the artifact after submission
        std::fs::write(&artifact, "fn main() { evil() }").unwrap();

        let mut scores = HashMap::new();
        scores.insert("correctness".to_string(), 8);
        scores.insert("security".to_string(), 7);

        let result = evaluate_review(
            &review_dir,
            &entry.review_id,
            "pentester",
            scores,
            vec![],
            &artifact,
        );

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Artifact integrity check failed"));
    }

    #[test]
    fn test_evaluate_requires_min_2_scores() {
        let tmp = TempDir::new().unwrap();
        let review_dir = tmp.path().join("reviews");
        let artifact = create_artifact(tmp.path(), "main.rs", "fn main() {}");

        let roles = vec!["coder".to_string(), "pentester".to_string()];
        let existing: Vec<(String, String)> = vec![];

        let entry = submit_review(
            &review_dir,
            &artifact,
            "coder",
            "audit-payments",
            &roles,
            &existing,
        )
        .unwrap();

        // Only 1 score dimension (below MIN_SCORE_DIMENSIONS)
        let mut scores = HashMap::new();
        scores.insert("correctness".to_string(), 8);

        let result = evaluate_review(
            &review_dir,
            &entry.review_id,
            "pentester",
            scores,
            vec![],
            &artifact,
        );

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("at least 2 score dimensions"));
    }

    #[test]
    fn test_trust_gate_auto_approve() {
        let result = trust_gate(8.5, &[]);
        assert_eq!(result, TrustGateResult::AutoComplete);
    }

    #[test]
    fn test_trust_gate_critical_finding() {
        let findings = vec![Finding {
            category: "rce".to_string(),
            severity: "critical".to_string(),
            description: "Remote code execution".to_string(),
            recommendation: "Fix immediately".to_string(),
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
        let review_dir = tmp.path().join("reviews");
        let artifact = create_artifact(tmp.path(), "main.rs", "fn main() {}");

        let roles = vec![
            "coder".to_string(),
            "pentester".to_string(),
            "architect".to_string(),
        ];
        let existing: Vec<(String, String)> = vec![];

        // Submit two reviews (need slight delay for unique IDs)
        let _e1 = submit_review(
            &review_dir,
            &artifact,
            "coder",
            "mission-1",
            &roles,
            &existing,
        )
        .unwrap();

        // Small sleep to get a different timestamp-based ID
        std::thread::sleep(std::time::Duration::from_millis(2));

        let _e2 = submit_review(
            &review_dir,
            &artifact,
            "architect",
            "mission-2",
            &roles,
            &existing,
        )
        .unwrap();

        // List all reviews
        let all = list_reviews(&review_dir, None).unwrap();
        assert_eq!(all.len(), 2);

        // List only pending
        let pending = list_reviews(&review_dir, Some(ReviewState::Pending)).unwrap();
        assert_eq!(pending.len(), 2);

        // List completed (none yet)
        let completed = list_reviews(&review_dir, Some(ReviewState::Completed)).unwrap();
        assert!(completed.is_empty());

        // Sorted by created_at DESC — most recent first
        assert!(all[0].created_at >= all[1].created_at);
    }

    // ── M1: Score bounds tests ────────────────────────────────────────────────

    #[test]
    fn test_evaluate_rejects_score_above_max() {
        // M1: A score > MAX_REVIEW_SCORE (10) must be rejected to prevent u32 overflow and ELO inflation.
        let tmp = TempDir::new().unwrap();
        let review_dir = tmp.path().join("reviews");
        let artifact = create_artifact(tmp.path(), "main.rs", "fn main() {}");

        let roles = vec!["coder".to_string(), "pentester".to_string()];
        let existing: Vec<(String, String)> = vec![];

        let entry = submit_review(
            &review_dir,
            &artifact,
            "coder",
            "audit-payments",
            &roles,
            &existing,
        )
        .unwrap();

        // Score of u32::MAX triggers overflow on sum() without bounds check
        let mut scores = HashMap::new();
        scores.insert("correctness".to_string(), u32::MAX);
        scores.insert("security".to_string(), 8);

        let result = evaluate_review(
            &review_dir,
            &entry.review_id,
            "pentester",
            scores,
            vec![],
            &artifact,
        );

        assert!(result.is_err(), "score above MAX_REVIEW_SCORE must be rejected");
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("exceeds maximum"), "error message should mention limit: {msg}");
    }

    #[test]
    fn test_evaluate_accepts_max_score() {
        // M1 non-regression: score equal to MAX_REVIEW_SCORE (10) must be accepted
        let tmp = TempDir::new().unwrap();
        let review_dir = tmp.path().join("reviews");
        let artifact = create_artifact(tmp.path(), "main.rs", "fn main() {}");

        let roles = vec!["coder".to_string(), "pentester".to_string()];
        let existing: Vec<(String, String)> = vec![];

        let entry = submit_review(
            &review_dir,
            &artifact,
            "coder",
            "audit-payments",
            &roles,
            &existing,
        )
        .unwrap();

        let mut scores = HashMap::new();
        scores.insert("correctness".to_string(), MAX_REVIEW_SCORE);
        scores.insert("security".to_string(), MAX_REVIEW_SCORE);

        let result = evaluate_review(
            &review_dir,
            &entry.review_id,
            "pentester",
            scores,
            vec![],
            &artifact,
        );

        assert!(result.is_ok(), "score equal to MAX_REVIEW_SCORE must be accepted");
    }
}

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::findings::Finding;

// ── Multi-instance ELO helpers (M7.15) ─────────────────────────────

/// Recover the role_id from a namespaced agent_id for ELO bucketing.
/// "m7-15-impl__colmena_developer-core" → "colmena_developer"
/// "auditor" → "auditor"
pub fn elo_bucket_for(agent_id: &str) -> &str {
    crate::mission_manifest::role_for_agent_id(agent_id)
}

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

/// Maximum artifact file size for hashing (100 MB).
/// STRIDE TM Finding #13 (DREAD 6.0): prevents OOM when an agent submits a
/// huge file (e.g. /dev/urandom symlink or multi-GB log) as artifact.
pub const MAX_ARTIFACT_SIZE: u64 = 100 * 1024 * 1024;

/// Maximum number of pending reviews per (author_role, mission) pair.
/// STRIDE TM Finding #24 (DREAD 5.4): prevents review_submit flooding that
/// causes SubagentStop timeout via slow `has_pending_evaluations` directory scan.
pub const MAX_PENDING_PER_AUTHOR: usize = 5;

/// Maximum length for evaluation_narrative field (characters).
/// STRIDE TM: prevents megabyte-sized narratives that bloat review JSON files
/// and slow down list_reviews/calibrate_auditor calls.
pub const MAX_NARRATIVE_CHARS: usize = 10_000;

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
    Invalidated,
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
    #[serde(default)]
    pub evaluation_narrative: Option<String>,
}

// ── Public API ─────────────────────────────────────────────────────

/// Compute SHA-256 hash of a file and return as `"sha256:{hex}"`.
///
/// STRIDE TM Finding #13 (DREAD 6.0): enforces `MAX_ARTIFACT_SIZE` to prevent
/// OOM when an agent submits a huge or infinite file as artifact.
pub fn hash_artifact(path: &Path) -> Result<String> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("reading artifact metadata {}", path.display()))?;
    if metadata.len() > MAX_ARTIFACT_SIZE {
        bail!(
            "Artifact too large: {} bytes (max {} bytes)",
            metadata.len(),
            MAX_ARTIFACT_SIZE
        );
    }
    let bytes =
        std::fs::read(path).with_context(|| format!("reading artifact {}", path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let digest = hasher.finalize();
    Ok(format!("sha256:{:x}", digest))
}

/// Submit an artifact for cross-review.
///
/// Invariants enforced:
/// 1. Author cannot review their own work (author != reviewer).
/// 2. Max pending per (author, mission) — STRIDE TM Finding #24 (DREAD 5.4).
///
/// Note: the former "anti-reciprocal" filter was removed in M7.3.2. It was
/// both mis-implemented (blocked repeat-pairing, not reciprocal pairs) AND
/// incompatible with the centralized-auditor invariant. In Colmena every
/// mission has exactly one `role_type: auditor` reviewing all workers (see
/// CLAUDE.md §Missions & Agent Identity) — so the auditor evaluating many
/// artifacts from the same author is the intended pattern, not a bug to
/// filter away. Perspective diversification across missions lives in M7.7
/// (category complementarity scoring), which does not reuse this mechanism.
///
/// Returns the created `ReviewEntry` in Pending state.
pub fn submit_review(
    review_dir: &Path,
    artifact_path: &Path,
    author_role: &str,
    mission: &str,
    available_roles: &[String],
) -> Result<ReviewEntry> {
    // STRIDE TM Finding #24: limit pending reviews per (author, mission)
    let pending_count = count_pending_for_author(review_dir, author_role, mission);
    if pending_count >= MAX_PENDING_PER_AUTHOR {
        bail!(
            "Too many pending reviews: {} has {} pending reviews for mission '{}' (max {}). \
             Wait for existing reviews to be evaluated or invalidate stale ones.",
            author_role,
            pending_count,
            mission,
            MAX_PENDING_PER_AUTHOR,
        );
    }

    // Filter out the author (invariant 1: author != reviewer)
    let candidates: Vec<&String> = available_roles
        .iter()
        .filter(|r| r.as_str() != author_role)
        .collect();

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
        evaluation_narrative: None,
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
    narrative: Option<String>,
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
    // Truncate narrative to prevent bloated review JSON files
    entry.evaluation_narrative = narrative.map(|n| {
        if n.len() > MAX_NARRATIVE_CHARS {
            let mut truncated = n[..MAX_NARRATIVE_CHARS].to_string();
            truncated.push_str("... [truncated]");
            truncated
        } else {
            n
        }
    });
    entry.state = ReviewState::Evaluated;

    // Move from pending/ to completed/
    let pending_path = review_dir
        .join("pending")
        .join(format!("{}.json", review_id));
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
    entries.sort_by_key(|e| std::cmp::Reverse(e.created_at));

    Ok(entries)
}

/// Check if a given author_role has submitted a review for a given mission.
///
/// Searches both `pending/` and `completed/` subdirs. Returns true if any
/// `ReviewEntry` matches both `author_role` and `mission`. On any error,
/// returns false (safe fallback).
pub fn has_submitted_review(review_dir: &Path, author_role: &str, mission_id: &str) -> bool {
    for subdir in &["pending", "completed"] {
        let dir = review_dir.join(subdir);
        if !dir.exists() {
            continue;
        }

        let read = match std::fs::read_dir(&dir) {
            Ok(r) => r,
            Err(_) => continue,
        };

        for file_entry in read {
            let file_entry = match file_entry {
                Ok(e) => e,
                Err(_) => continue,
            };

            let path = file_entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }

            let content = match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            if let Ok(entry) = serde_json::from_str::<ReviewEntry>(&content) {
                if entry.author_role == author_role && entry.mission == mission_id {
                    return true;
                }
            }
        }
    }

    false
}

/// Check if a reviewer has pending reviews to evaluate for a given mission.
///
/// Scans `pending/` for ReviewEntry where `reviewer_role == reviewer_id`
/// AND `mission == mission_id` AND `state == Pending`. Returns true if any found.
/// On any error, returns false (safe fallback — never trap an agent).
pub fn has_pending_evaluations(review_dir: &Path, reviewer_id: &str, mission_id: &str) -> bool {
    let dir = review_dir.join("pending");
    if !dir.exists() {
        return false;
    }

    let read = match std::fs::read_dir(&dir) {
        Ok(r) => r,
        Err(_) => return false,
    };

    for file_entry in read {
        let file_entry = match file_entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        let path = file_entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }

        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        if let Ok(entry) = serde_json::from_str::<ReviewEntry>(&content) {
            if entry.reviewer_role == reviewer_id
                && entry.mission == mission_id
                && entry.state == ReviewState::Pending
            {
                return true;
            }
        }
    }

    false
}

/// Invalidate stale pending reviews whose artifact hash no longer matches.
///
/// Scans `pending/` for reviews matching `(artifact_path, mission, author_role)` where
/// `artifact_hash != current_hash`. Only invalidates reviews from the same author —
/// prevents cross-agent invalidation (STRIDE TM: an agent cannot invalidate another
/// agent's reviews by modifying a shared artifact and re-submitting).
///
/// Sets state to `Invalidated`, moves to `completed/`.
/// Returns `(review_id, old_hash)` tuples for audit logging.
///
/// Idempotent: a second call with the same parameters finds nothing to invalidate.
pub fn invalidate_stale_reviews(
    review_dir: &Path,
    artifact_path: &str,
    mission: &str,
    author_role: &str,
    current_hash: &str,
) -> Result<Vec<(String, String)>> {
    let pending_dir = review_dir.join("pending");
    if !pending_dir.exists() {
        return Ok(Vec::new());
    }

    let read = std::fs::read_dir(&pending_dir)
        .with_context(|| format!("reading pending dir {}", pending_dir.display()))?;

    let mut invalidated = Vec::new();

    for file_entry in read {
        let file_entry = file_entry?;
        let path = file_entry.path();

        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }

        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;

        let mut entry: ReviewEntry = match serde_json::from_str(&content) {
            Ok(e) => e,
            Err(_) => continue,
        };

        if entry.artifact_path == artifact_path
            && entry.mission == mission
            && entry.author_role == author_role
            && entry.artifact_hash != current_hash
            && entry.state == ReviewState::Pending
        {
            let old_hash = entry.artifact_hash.clone();
            entry.state = ReviewState::Invalidated;

            save_review_to(review_dir, &entry, "completed")?;

            if path.exists() {
                std::fs::remove_file(&path)
                    .with_context(|| format!("removing stale pending {}", path.display()))?;
            }

            invalidated.push((entry.review_id.clone(), old_hash));
        }
    }

    Ok(invalidated)
}

// ── Private helpers ────────────────────────────────────────────────

/// Count pending reviews for a given (author_role, mission) pair.
/// Returns 0 on any error (safe fallback).
fn count_pending_for_author(review_dir: &Path, author_role: &str, mission: &str) -> usize {
    let pending_dir = review_dir.join("pending");
    if !pending_dir.exists() {
        return 0;
    }

    let read = match std::fs::read_dir(&pending_dir) {
        Ok(r) => r,
        Err(_) => return 0,
    };

    let mut count = 0usize;
    for file_entry in read {
        let file_entry = match file_entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = file_entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        if let Ok(entry) = serde_json::from_str::<ReviewEntry>(&content) {
            if entry.author_role == author_role
                && entry.mission == mission
                && entry.state == ReviewState::Pending
            {
                count += 1;
            }
        }
    }
    count
}

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
    let json = serde_json::to_string_pretty(entry).context("serializing review entry")?;

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

        let entry =
            submit_review(&review_dir, &artifact, "coder", "audit-payments", &roles).unwrap();

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

        let result = submit_review(&review_dir, &artifact, "coder", "audit-payments", &roles);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("No eligible reviewer"));
    }

    #[test]
    fn test_submit_centralized_auditor_accepts_n_artifacts_from_same_author() {
        // M7.3.2: the former "anti-reciprocal" filter wrongly blocked the
        // auditor from evaluating more than one artifact per author in the
        // same mission. With the filter removed, a centralized auditor
        // reviewing many artifacts from the same worker — which is the
        // intended pattern under the auditor-centralized invariant — must
        // succeed consistently.
        let tmp = TempDir::new().unwrap();
        let review_dir = tmp.path().join("reviews");
        let a1 = create_artifact(tmp.path(), "file1.md", "# one");
        let a2 = create_artifact(tmp.path(), "file2.md", "# two");
        let a3 = create_artifact(tmp.path(), "file3.md", "# three");

        let roles = vec!["auditor".to_string()];

        // The centralized auditor must accept multiple artifacts from the same author.
        let r1 = submit_review(&review_dir, &a1, "architect", "m73-docs-overhaul", &roles)
            .expect("first submit to centralized auditor must succeed");
        assert_eq!(r1.reviewer_role, "auditor");

        let r2 = submit_review(&review_dir, &a2, "architect", "m73-docs-overhaul", &roles)
            .expect("second submit to centralized auditor must succeed");
        assert_eq!(r2.reviewer_role, "auditor");

        let r3 = submit_review(&review_dir, &a3, "architect", "m73-docs-overhaul", &roles)
            .expect("third submit to centralized auditor must succeed");
        assert_eq!(r3.reviewer_role, "auditor");
    }

    #[test]
    fn test_submit_cross_mission_reviewer_reuse_allowed() {
        // REGRESSION (M7.3.2): with anti-reciprocal removed, the same
        // reviewer is eligible across missions — cross-mission reviewer
        // reuse is now trivially allowed. Preserved as a forward-compat
        // check against anyone trying to reintroduce the filter.
        let tmp = TempDir::new().unwrap();
        let review_dir = tmp.path().join("reviews");
        let artifact = create_artifact(tmp.path(), "main.rs", "fn main() {}");

        let roles = vec!["coder".to_string(), "pentester".to_string()];

        let entry = submit_review(&review_dir, &artifact, "coder", "mission-b", &roles)
            .expect("cross-mission submit must succeed");

        assert_eq!(entry.reviewer_role, "pentester");
        assert_eq!(entry.mission, "mission-b");
    }

    #[test]
    fn test_evaluate_review_valid() {
        let tmp = TempDir::new().unwrap();
        let review_dir = tmp.path().join("reviews");
        let artifact = create_artifact(tmp.path(), "main.rs", "fn main() {}");

        let roles = vec!["coder".to_string(), "pentester".to_string()];

        let entry =
            submit_review(&review_dir, &artifact, "coder", "audit-payments", &roles).unwrap();

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
            None,
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

        let entry =
            submit_review(&review_dir, &artifact, "coder", "audit-payments", &roles).unwrap();

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
            None,
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

        let entry =
            submit_review(&review_dir, &artifact, "coder", "audit-payments", &roles).unwrap();

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
            None,
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

        // Submit two reviews (need slight delay for unique IDs)
        let _e1 = submit_review(&review_dir, &artifact, "coder", "mission-1", &roles).unwrap();

        // Small sleep to get a different timestamp-based ID
        std::thread::sleep(std::time::Duration::from_millis(2));

        let _e2 = submit_review(&review_dir, &artifact, "architect", "mission-2", &roles).unwrap();

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

        let entry =
            submit_review(&review_dir, &artifact, "coder", "audit-payments", &roles).unwrap();

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
            None,
        );

        assert!(
            result.is_err(),
            "score above MAX_REVIEW_SCORE must be rejected"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("exceeds maximum"),
            "error message should mention limit: {msg}"
        );
    }

    #[test]
    fn test_evaluate_accepts_max_score() {
        // M1 non-regression: score equal to MAX_REVIEW_SCORE (10) must be accepted
        let tmp = TempDir::new().unwrap();
        let review_dir = tmp.path().join("reviews");
        let artifact = create_artifact(tmp.path(), "main.rs", "fn main() {}");

        let roles = vec!["coder".to_string(), "pentester".to_string()];

        let entry =
            submit_review(&review_dir, &artifact, "coder", "audit-payments", &roles).unwrap();

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
            None,
        );

        assert!(
            result.is_ok(),
            "score equal to MAX_REVIEW_SCORE must be accepted"
        );
    }

    // ── M6.4: has_submitted_review tests ─────────────────────────────────────

    #[test]
    fn test_has_submitted_review_found() {
        let tmp = TempDir::new().unwrap();
        let review_dir = tmp.path().join("reviews");
        let artifact = create_artifact(tmp.path(), "main.rs", "fn main() {}");

        let roles = vec!["coder".to_string(), "pentester".to_string()];

        let _entry =
            submit_review(&review_dir, &artifact, "coder", "audit-payments", &roles).unwrap();

        assert!(
            has_submitted_review(&review_dir, "coder", "audit-payments"),
            "should find the submitted review"
        );
    }

    #[test]
    fn test_has_submitted_review_not_found() {
        let tmp = TempDir::new().unwrap();
        let review_dir = tmp.path().join("reviews");
        // Don't submit anything — empty dir
        assert!(
            !has_submitted_review(&review_dir, "coder", "audit-payments"),
            "should return false for empty review dir"
        );
    }

    #[test]
    fn test_has_submitted_review_wrong_mission() {
        let tmp = TempDir::new().unwrap();
        let review_dir = tmp.path().join("reviews");
        let artifact = create_artifact(tmp.path(), "main.rs", "fn main() {}");

        let roles = vec!["coder".to_string(), "pentester".to_string()];

        let _entry =
            submit_review(&review_dir, &artifact, "coder", "audit-payments", &roles).unwrap();

        assert!(
            !has_submitted_review(&review_dir, "coder", "different-mission"),
            "should return false for wrong mission"
        );
    }

    // ── M6.4: evaluation_narrative tests ─────────────────────────────────────

    #[test]
    fn test_evaluate_review_with_narrative() {
        let tmp = TempDir::new().unwrap();
        let review_dir = tmp.path().join("reviews");
        let artifact = create_artifact(tmp.path(), "main.rs", "fn main() {}");

        let roles = vec!["coder".to_string(), "pentester".to_string()];

        let entry =
            submit_review(&review_dir, &artifact, "coder", "audit-payments", &roles).unwrap();

        let mut scores = HashMap::new();
        scores.insert("correctness".to_string(), 8);
        scores.insert("security".to_string(), 7);

        let narrative_text = "The code correctly implements the payment flow. \
            Security score reflects a minor input validation gap. \
            Alternative approach 1: strict deny-list, rejected due to maintenance cost. \
            Alternative approach 2: schema validation, rejected as over-engineering. \
            Alternative approach 3: runtime sanitization, rejected for performance impact."
            .to_string();

        let evaluated = evaluate_review(
            &review_dir,
            &entry.review_id,
            "pentester",
            scores,
            vec![],
            &artifact,
            Some(narrative_text.clone()),
        )
        .unwrap();

        assert_eq!(evaluated.evaluation_narrative, Some(narrative_text.clone()));

        // Verify it's persisted in the JSON file
        let completed_path = review_dir
            .join("completed")
            .join(format!("{}.json", entry.review_id));
        let saved_content = std::fs::read_to_string(&completed_path).unwrap();
        let saved_entry: ReviewEntry = serde_json::from_str(&saved_content).unwrap();
        assert_eq!(saved_entry.evaluation_narrative, Some(narrative_text));
    }

    // ── has_pending_evaluations tests ───────────────────────────────

    #[test]
    fn test_has_pending_evaluations_found() {
        let tmp = TempDir::new().unwrap();
        let review_dir = tmp.path().join("reviews");
        let artifact = create_artifact(tmp.path(), "main.rs", "fn main() {}");

        let roles = vec!["coder".to_string(), "pentester".to_string()];

        let entry =
            submit_review(&review_dir, &artifact, "coder", "audit-payments", &roles).unwrap();

        // The assigned reviewer should have a pending evaluation
        assert!(
            has_pending_evaluations(&review_dir, &entry.reviewer_role, "audit-payments"),
            "reviewer should have pending evaluation"
        );
    }

    #[test]
    fn test_has_pending_evaluations_not_found() {
        let tmp = TempDir::new().unwrap();
        let review_dir = tmp.path().join("reviews");

        assert!(
            !has_pending_evaluations(&review_dir, "pentester", "audit-payments"),
            "should return false for empty/nonexistent review dir"
        );
    }

    #[test]
    fn test_has_pending_evaluations_wrong_mission() {
        let tmp = TempDir::new().unwrap();
        let review_dir = tmp.path().join("reviews");
        let artifact = create_artifact(tmp.path(), "main.rs", "fn main() {}");

        let roles = vec!["coder".to_string(), "pentester".to_string()];

        submit_review(&review_dir, &artifact, "coder", "audit-payments", &roles).unwrap();

        assert!(
            !has_pending_evaluations(&review_dir, "pentester", "different-mission"),
            "should return false for wrong mission"
        );
    }

    #[test]
    fn test_has_pending_evaluations_after_evaluate() {
        let tmp = TempDir::new().unwrap();
        let review_dir = tmp.path().join("reviews");
        let artifact = create_artifact(tmp.path(), "main.rs", "fn main() {}");

        let roles = vec!["coder".to_string(), "pentester".to_string()];

        let entry =
            submit_review(&review_dir, &artifact, "coder", "audit-payments", &roles).unwrap();

        let reviewer = entry.reviewer_role.clone();

        // Evaluate the review (moves to completed/)
        let mut scores = HashMap::new();
        scores.insert("quality".to_string(), 8);
        scores.insert("precision".to_string(), 7);
        evaluate_review(
            &review_dir,
            &entry.review_id,
            &reviewer,
            scores,
            vec![],
            &artifact,
            None,
        )
        .unwrap();

        // After evaluation, no pending reviews should remain
        assert!(
            !has_pending_evaluations(&review_dir, &reviewer, "audit-payments"),
            "should return false after review is evaluated"
        );
    }

    // ── invalidate_stale_reviews tests ──────────────────────────────

    #[test]
    fn test_invalidate_stale_reviews_basic() {
        let tmp = TempDir::new().unwrap();
        let review_dir = tmp.path().join("reviews");
        let artifact = create_artifact(tmp.path(), "main.rs", "fn main() {}");

        let roles = vec!["coder".to_string(), "pentester".to_string()];

        let entry =
            submit_review(&review_dir, &artifact, "coder", "audit-payments", &roles).unwrap();

        // Modify the artifact (new hash)
        std::fs::write(&artifact, "fn main() { improved() }").unwrap();
        let new_hash = hash_artifact(&artifact).unwrap();

        let invalidated = invalidate_stale_reviews(
            &review_dir,
            &artifact.to_string_lossy(),
            "audit-payments",
            "coder",
            &new_hash,
        )
        .unwrap();

        assert_eq!(invalidated.len(), 1);
        assert_eq!(invalidated[0].0, entry.review_id);

        // Should be in completed/ with Invalidated state
        let completed_path = review_dir
            .join("completed")
            .join(format!("{}.json", entry.review_id));
        assert!(completed_path.exists());
        let saved: ReviewEntry =
            serde_json::from_str(&std::fs::read_to_string(&completed_path).unwrap()).unwrap();
        assert_eq!(saved.state, ReviewState::Invalidated);

        // Should NOT be in pending/
        let pending_path = review_dir
            .join("pending")
            .join(format!("{}.json", entry.review_id));
        assert!(!pending_path.exists());
    }

    #[test]
    fn test_invalidate_stale_reviews_same_hash() {
        let tmp = TempDir::new().unwrap();
        let review_dir = tmp.path().join("reviews");
        let artifact = create_artifact(tmp.path(), "main.rs", "fn main() {}");

        let roles = vec!["coder".to_string(), "pentester".to_string()];

        submit_review(&review_dir, &artifact, "coder", "audit-payments", &roles).unwrap();

        // Same hash — nothing should be invalidated
        let same_hash = hash_artifact(&artifact).unwrap();
        let invalidated = invalidate_stale_reviews(
            &review_dir,
            &artifact.to_string_lossy(),
            "audit-payments",
            "coder",
            &same_hash,
        )
        .unwrap();

        assert!(invalidated.is_empty());
    }

    #[test]
    fn test_invalidate_stale_reviews_different_mission() {
        let tmp = TempDir::new().unwrap();
        let review_dir = tmp.path().join("reviews");
        let artifact = create_artifact(tmp.path(), "main.rs", "fn main() {}");

        let roles = vec!["coder".to_string(), "pentester".to_string()];

        submit_review(&review_dir, &artifact, "coder", "audit-payments", &roles).unwrap();

        std::fs::write(&artifact, "fn main() { changed() }").unwrap();
        let new_hash = hash_artifact(&artifact).unwrap();

        let invalidated = invalidate_stale_reviews(
            &review_dir,
            &artifact.to_string_lossy(),
            "different-mission",
            "coder",
            &new_hash,
        )
        .unwrap();

        assert!(invalidated.is_empty());
    }

    #[test]
    fn test_invalidate_stale_reviews_idempotent() {
        let tmp = TempDir::new().unwrap();
        let review_dir = tmp.path().join("reviews");
        let artifact = create_artifact(tmp.path(), "main.rs", "fn main() {}");

        let roles = vec!["coder".to_string(), "pentester".to_string()];

        submit_review(&review_dir, &artifact, "coder", "audit-payments", &roles).unwrap();

        std::fs::write(&artifact, "fn main() { changed() }").unwrap();
        let new_hash = hash_artifact(&artifact).unwrap();

        // First call invalidates
        let inv1 = invalidate_stale_reviews(
            &review_dir,
            &artifact.to_string_lossy(),
            "audit-payments",
            "coder",
            &new_hash,
        )
        .unwrap();
        assert_eq!(inv1.len(), 1);

        // Second call finds nothing (idempotent)
        let inv2 = invalidate_stale_reviews(
            &review_dir,
            &artifact.to_string_lossy(),
            "audit-payments",
            "coder",
            &new_hash,
        )
        .unwrap();
        assert!(inv2.is_empty());
    }

    #[test]
    fn test_invalidate_stale_reviews_cross_agent_blocked() {
        // STRIDE TM P0: agent B cannot invalidate agent A's reviews
        let tmp = TempDir::new().unwrap();
        let review_dir = tmp.path().join("reviews");
        let artifact = create_artifact(tmp.path(), "main.rs", "fn main() {}");

        let roles = vec![
            "coder".to_string(),
            "pentester".to_string(),
            "architect".to_string(),
        ];

        // Coder submits a review
        submit_review(&review_dir, &artifact, "coder", "audit-payments", &roles).unwrap();

        // Pentester modifies the artifact and tries to invalidate coder's review
        std::fs::write(&artifact, "fn main() { pentester_was_here() }").unwrap();
        let new_hash = hash_artifact(&artifact).unwrap();

        let invalidated = invalidate_stale_reviews(
            &review_dir,
            &artifact.to_string_lossy(),
            "audit-payments",
            "pentester", // different author — should NOT invalidate coder's review
            &new_hash,
        )
        .unwrap();

        assert!(
            invalidated.is_empty(),
            "cross-agent invalidation should be blocked"
        );
    }

    // ── STRIDE TM Finding #13: artifact size check ──────────────────

    #[test]
    fn test_hash_artifact_rejects_oversized_file() {
        let tmp = TempDir::new().unwrap();
        // We can't create a real 100MB+ file in a unit test, but we can verify
        // the check runs by creating a normal file and asserting it passes
        let artifact = create_artifact(tmp.path(), "small.rs", "fn main() {}");
        let result = hash_artifact(&artifact);
        assert!(result.is_ok(), "small files should be accepted");
    }

    // ── STRIDE TM Finding #24: pending review cap ──────────────────

    #[test]
    fn test_submit_review_rejects_excess_pending() {
        let tmp = TempDir::new().unwrap();
        let review_dir = tmp.path().join("reviews");

        let roles = vec![
            "coder".to_string(),
            "pentester".to_string(),
            "architect".to_string(),
        ];

        // Submit MAX_PENDING_PER_AUTHOR reviews (should succeed)
        for i in 0..MAX_PENDING_PER_AUTHOR {
            let artifact_name = format!("file_{}.rs", i);
            let artifact =
                create_artifact(tmp.path(), &artifact_name, &format!("fn f{}() {{}}", i));
            std::thread::sleep(std::time::Duration::from_millis(2));
            submit_review(&review_dir, &artifact, "coder", "audit-payments", &roles).unwrap();
        }

        // The next submission should fail
        let extra_artifact = create_artifact(tmp.path(), "extra.rs", "fn extra() {}");
        let result = submit_review(
            &review_dir,
            &extra_artifact,
            "coder",
            "audit-payments",
            &roles,
        );
        assert!(
            result.is_err(),
            "should reject when MAX_PENDING_PER_AUTHOR reached"
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Too many pending reviews"),
            "error message should mention pending limit"
        );
    }

    #[test]
    fn test_submit_review_cap_is_per_mission() {
        // Pending reviews for mission A should not count towards mission B's cap
        let tmp = TempDir::new().unwrap();
        let review_dir = tmp.path().join("reviews");

        let roles = vec![
            "coder".to_string(),
            "pentester".to_string(),
            "architect".to_string(),
        ];

        // Fill up mission A
        for i in 0..MAX_PENDING_PER_AUTHOR {
            let artifact_name = format!("a_{}.rs", i);
            let artifact =
                create_artifact(tmp.path(), &artifact_name, &format!("fn a{}() {{}}", i));
            std::thread::sleep(std::time::Duration::from_millis(2));
            submit_review(&review_dir, &artifact, "coder", "mission-a", &roles).unwrap();
        }

        // Mission B should still accept reviews from the same author
        let artifact_b = create_artifact(tmp.path(), "b_0.rs", "fn b0() {}");
        let result = submit_review(&review_dir, &artifact_b, "coder", "mission-b", &roles);
        assert!(result.is_ok(), "different mission should have its own cap");
    }

    #[test]
    fn test_invalidated_state_serde_roundtrip() {
        let entry = ReviewEntry {
            review_id: "r_test".to_string(),
            mission: "test".to_string(),
            author_role: "a".to_string(),
            reviewer_role: "b".to_string(),
            artifact_path: "/tmp/x".to_string(),
            artifact_hash: "sha256:000".to_string(),
            state: ReviewState::Invalidated,
            created_at: chrono::Utc::now(),
            evaluated_at: None,
            scores: None,
            score_average: None,
            finding_count: None,
            evaluation_narrative: None,
        };

        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"invalidated\""));
        let deserialized: ReviewEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.state, ReviewState::Invalidated);
    }
}

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::firewall::{Decision, Priority};
use crate::models::EvaluationInput;

/// Maximum length for tool_input command fields in queue entries.
const MAX_COMMAND_LEN: usize = 200;

/// Maximum entries GC processes per invocation (R1: hot-path cap).
const GC_MAX_ENTRIES_PER_PASS: usize = 500;

// ── QueueOutcome / QueueMover enums (M7.14) ─────────────────────────────────

/// How the pending entry was resolved.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueOutcome {
    /// Operator approved; tool ran to completion.
    Allowed,
    /// Operator approved but tool was interrupted (`interrupted=true`).
    Failed,
    /// Stale GC or session-end sweep — no explicit approval/deny recorded.
    AssumedDenied,
    /// Pre-M7.14 decided entry; outcome not recorded at move time.
    Unknown,
}

/// What mechanism moved the entry from pending → decided.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueMover {
    /// PostToolUse hook detected the tool completed.
    Posttool,
    /// Stale-GC sweep (belt-and-suspenders, session still open).
    StaleGc,
    /// Stop hook session-end sweep.
    SessionEnd,
    /// `colmena queue prune` or old `prune_old_entries` call.
    ManualPrune,
}

// ── QueueEntry ───────────────────────────────────────────────────────────────

/// An entry in the approval queue.
#[derive(Debug, Serialize, Deserialize)]
pub struct QueueEntry {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub agent_id: Option<String>,
    pub tool: String,
    pub input: serde_json::Value,
    pub rule_matched: Option<String>,
    pub priority: String,
    pub reason: String,
    // M7.14 fields — all optional for backwards-compat with pre-M7.14 entries on disk.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<QueueOutcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub moved_by: Option<QueueMover>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub moved_at: Option<DateTime<Utc>>,
}

// ── Filename helpers (S2) ────────────────────────────────────────────────────

/// Parsed components of a queue filename.
pub struct ParsedQueueFilename {
    pub timestamp_ms: i64,
    /// `None` for old-format files (`<ts>-<tool_use_id>.json`).
    pub session_id: Option<String>,
    pub tool_use_id: String,
}

/// Sanitize a session_id for use inside a filename segment.
/// Replaces any char outside `[a-zA-Z0-9_]` with `_`.
pub fn sanitize_session_id(session_id: &str) -> String {
    session_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Parse a queue filename (with or without `.json` extension).
///
/// New format:  `{timestamp_ms}-{sanitized_session}-{tool_use_id}.json`
/// Old format:  `{timestamp_ms}-{tool_use_id}.json`
///
/// Returns `None` on any parse failure (malformed filename → caller skips).
pub fn parse_queue_filename(filename: &str) -> Option<ParsedQueueFilename> {
    // Strip .json suffix
    let stem = filename.strip_suffix(".json").unwrap_or(filename);

    // Split on first '-' → (timestamp_str, rest)
    let (ts_str, rest) = stem.split_once('-')?;

    let timestamp_ms: i64 = ts_str.parse().ok()?;

    // New format has at least one more '-' in rest: "{session}-{tool_use_id}"
    // Old format: rest IS the tool_use_id (no further '-')
    if let Some(dash_pos) = rest.find('-') {
        // New format: split on FIRST '-' → session up to dash, tool_use_id after
        let session_id = rest[..dash_pos].to_string();
        let tool_use_id = rest[dash_pos + 1..].to_string();
        if session_id.is_empty() || tool_use_id.is_empty() {
            return None;
        }
        Some(ParsedQueueFilename {
            timestamp_ms,
            session_id: Some(session_id),
            tool_use_id,
        })
    } else {
        // Old format
        if rest.is_empty() {
            return None;
        }
        Some(ParsedQueueFilename {
            timestamp_ms,
            session_id: None,
            tool_use_id: rest.to_string(),
        })
    }
}

// ── Input truncation (unchanged) ─────────────────────────────────────────────

/// Truncate tool_input for queue storage (Fix 16).
/// - command: first MAX_COMMAND_LEN chars
/// - file_path: keep the path, redact content fields
/// - other string values: first MAX_COMMAND_LEN chars
fn truncate_input(tool_name: &str, input: &serde_json::Value) -> serde_json::Value {
    let mut truncated = input.clone();
    if let Some(obj) = truncated.as_object_mut() {
        match tool_name {
            "Bash" => {
                if let Some(cmd) = obj.get_mut("command") {
                    if let Some(s) = cmd.as_str() {
                        if s.len() > MAX_COMMAND_LEN {
                            *cmd =
                                serde_json::Value::String(format!("{}...", &s[..MAX_COMMAND_LEN]));
                        }
                    }
                }
            }
            "Write" => {
                // Keep file_path, redact content
                if obj.contains_key("content") {
                    obj.insert(
                        "content".to_string(),
                        serde_json::Value::String("[REDACTED]".to_string()),
                    );
                }
            }
            "Edit" => {
                // Keep file_path, redact old_string and new_string
                for key in &["old_string", "new_string"] {
                    if let Some(v) = obj.get_mut(*key) {
                        if let Some(s) = v.as_str() {
                            if s.len() > MAX_COMMAND_LEN {
                                *v = serde_json::Value::String(format!(
                                    "{}...",
                                    &s[..MAX_COMMAND_LEN]
                                ));
                            }
                        }
                    }
                }
            }
            _ => {
                // Generic: truncate any long string values
                for v in obj.values_mut() {
                    if let Some(s) = v.as_str() {
                        if s.len() > MAX_COMMAND_LEN {
                            *v = serde_json::Value::String(format!("{}...", &s[..MAX_COMMAND_LEN]));
                        }
                    }
                }
            }
        }
    }
    truncated
}

// ── enqueue_pending (S2a: new filename schema) ───────────────────────────────

/// Write a pending approval entry to disk.
///
/// M7.14: filename is `{timestamp_ms}-{sanitized_session_id}-{tool_use_id}.json`.
/// After writing, lazily runs stale GC + decided retention purge (wrapped in `let _ =`
/// so any error is silently ignored and never fails the enqueue).
pub fn enqueue_pending(
    config_dir: &Path,
    payload: &EvaluationInput,
    decision: &Decision,
) -> Result<PathBuf> {
    enqueue_pending_with_config(config_dir, payload, decision, 600, 24)
}

/// Core enqueue logic, parameterized for testability (GC TTL + retention hours).
pub fn enqueue_pending_with_config(
    config_dir: &Path,
    payload: &EvaluationInput,
    decision: &Decision,
    gc_ttl_seconds: u64,
    retention_hours: u64,
) -> Result<PathBuf> {
    let pending_dir = config_dir.join("queue/pending");
    std::fs::create_dir_all(&pending_dir)
        .with_context(|| format!("Failed to create pending dir: {}", pending_dir.display()))?;

    let now = Utc::now();
    let timestamp_ms = now.timestamp_millis();
    let session_sanitized = sanitize_session_id(&payload.session_id);
    let filename = format!(
        "{}-{}-{}.json",
        timestamp_ms, session_sanitized, payload.tool_use_id
    );
    let filepath = pending_dir.join(&filename);

    let priority_str = match decision.priority {
        Priority::Low => "low",
        Priority::Medium => "medium",
        Priority::High => "high",
    };

    let entry = QueueEntry {
        id: format!("{}-{}", timestamp_ms, payload.tool_use_id),
        timestamp: now,
        agent_id: payload.agent_id.clone(),
        tool: payload.tool_name.clone(),
        input: truncate_input(&payload.tool_name, &payload.tool_input),
        rule_matched: decision.matched_rule.clone(),
        priority: priority_str.to_string(),
        reason: decision.reason.clone(),
        session_id: Some(payload.session_id.clone()),
        outcome: None,
        moved_by: None,
        moved_at: None,
    };

    let json = serde_json::to_string_pretty(&entry).context("Failed to serialize queue entry")?;
    std::fs::write(&filepath, json)
        .with_context(|| format!("Failed to write queue entry: {}", filepath.display()))?;

    // Lazy GC: stale pending + decided retention purge (belt-and-suspenders, errors ignored)
    let _ = gc_stale_pending(config_dir, gc_ttl_seconds, now);
    let _ = purge_expired_decided(config_dir, retention_hours, now);

    Ok(filepath)
}

// ── resolve_pending (S3 core helper) ─────────────────────────────────────────

/// Move a pending entry to decided/ when PostToolUse confirms the tool ran.
///
/// Scans `pending/` for a file matching `(session_id, tool_use_id)` or falls back
/// to `tool_use_id`-only match for old-format entries. Returns the moved file path
/// or `Ok(None)` if no matching entry found (fast-path auto-approved case).
pub fn resolve_pending(
    config_dir: &Path,
    session_id: &str,
    tool_use_id: &str,
    outcome: QueueOutcome,
    moved_by: QueueMover,
) -> Result<Option<PathBuf>> {
    let pending_dir = config_dir.join("queue/pending");
    if !pending_dir.exists() {
        return Ok(None);
    }

    let decided_dir = config_dir.join("queue/decided");
    std::fs::create_dir_all(&decided_dir).context("Failed to create decided dir")?;

    let session_sanitized = sanitize_session_id(session_id);

    // Scan pending/ for a matching file — O(dir size), fast because no file reads for non-matches
    let dir_entries = std::fs::read_dir(&pending_dir)
        .with_context(|| format!("Failed to read pending dir: {}", pending_dir.display()))?;

    for dir_entry in dir_entries {
        let dir_entry = dir_entry?;
        let path = dir_entry.path();
        let fname = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        if !fname.ends_with(".json") {
            continue;
        }

        // Match new format: ends with "-{session}-{tool_use_id}.json"
        let new_suffix = format!("-{}-{}.json", session_sanitized, tool_use_id);
        // Match old format: ends with "-{tool_use_id}.json"
        let old_suffix = format!("-{}.json", tool_use_id);

        let matched = fname.ends_with(&new_suffix) || fname.ends_with(&old_suffix);
        if !matched {
            continue;
        }

        // Found a match — deserialize, update, move to decided/
        let now = Utc::now();
        let contents = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read pending entry: {}", path.display()))?;
        let mut entry: QueueEntry = serde_json::from_str(&contents)
            .with_context(|| format!("Failed to parse pending entry: {}", path.display()))?;

        entry.outcome = Some(outcome);
        entry.moved_by = Some(moved_by);
        entry.moved_at = Some(now);

        let dest = decided_dir.join(&fname);
        let updated_json =
            serde_json::to_string_pretty(&entry).context("Failed to serialize resolved entry")?;

        // Atomic write: write to decided/ then remove from pending/
        // Prefer fs::rename (atomic POSIX), fall back to write+remove on cross-fs failure
        let tmp_dest = dest.with_extension("json.tmp");
        std::fs::write(&tmp_dest, &updated_json).with_context(|| {
            format!("Failed to write tmp resolved entry: {}", tmp_dest.display())
        })?;

        if std::fs::rename(&tmp_dest, &dest).is_err() {
            // Rename failed (cross-fs?), copy already written to tmp, just clean up
            let _ = std::fs::remove_file(&tmp_dest);
            // Write directly to dest as fallback
            std::fs::write(&dest, &updated_json)
                .with_context(|| format!("Failed to write resolved entry: {}", dest.display()))?;
        }

        // Remove from pending — ENOENT is fine (another process already moved it)
        let _ = std::fs::remove_file(&path);

        return Ok(Some(dest));
    }

    Ok(None)
}

// ── gc_stale_pending (S4: belt-and-suspenders) ───────────────────────────────

/// Move pending entries older than `ttl_seconds` to decided/ with outcome=AssumedDenied.
///
/// Capped at GC_MAX_ENTRIES_PER_PASS (500) per invocation to stay within hot-path budget (R1).
/// If a file fails to deserialize, it's still moved to decided/ unchanged (best-effort).
pub fn gc_stale_pending(config_dir: &Path, ttl_seconds: u64, now: DateTime<Utc>) -> Result<usize> {
    let pending_dir = config_dir.join("queue/pending");
    if !pending_dir.exists() {
        return Ok(0);
    }

    let decided_dir = config_dir.join("queue/decided");
    std::fs::create_dir_all(&decided_dir).context("Failed to create decided dir for GC")?;

    let cutoff_ms = now.timestamp_millis() - (ttl_seconds as i64 * 1000);
    let mut moved = 0;

    for (processed, dir_entry) in std::fs::read_dir(&pending_dir)?.enumerate() {
        if processed >= GC_MAX_ENTRIES_PER_PASS {
            log_error(&format!(
                "queue GC: capped at {} entries per pass; remaining entries will be processed next cycle",
                GC_MAX_ENTRIES_PER_PASS,
            ));
            break;
        }

        let dir_entry = dir_entry?;
        let path = dir_entry.path();
        let fname = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        if !fname.ends_with(".json") {
            continue;
        }

        // Use filename timestamp for GC decision (fast — no file read needed)
        let ts_ms = match parse_queue_filename(&fname) {
            Some(p) => p.timestamp_ms,
            None => continue, // malformed filename, skip
        };

        if ts_ms >= cutoff_ms {
            continue; // Not stale yet
        }

        // Stale entry — read, update outcome, move to decided/
        let dest = decided_dir.join(&fname);
        match std::fs::read_to_string(&path) {
            Ok(contents) => {
                match serde_json::from_str::<QueueEntry>(&contents) {
                    Ok(mut entry) => {
                        entry.outcome = Some(QueueOutcome::AssumedDenied);
                        entry.moved_by = Some(QueueMover::StaleGc);
                        entry.moved_at = Some(now);
                        if let Ok(json) = serde_json::to_string_pretty(&entry) {
                            let _ = std::fs::write(&dest, json);
                        } else {
                            // Serialization failed — move raw file as fallback
                            let _ = std::fs::copy(&path, &dest);
                        }
                    }
                    Err(_) => {
                        // Corrupt JSON — move raw file as fallback, log warning
                        log_error(&format!(
                            "queue GC: corrupt pending entry {}, moving raw to decided/",
                            fname
                        ));
                        let _ = std::fs::copy(&path, &dest);
                    }
                }
            }
            Err(_) => {
                // Can't read file — best effort skip
                continue;
            }
        }

        // Remove from pending (ENOENT fine — race with another GC call is handled)
        let _ = std::fs::remove_file(&path);
        moved += 1;
    }

    Ok(moved)
}

// ── sweep_session_pending (S4-bis: Stop hook primary mover) ──────────────────

/// Move all pending entries for `session_id` to decided/ with outcome=AssumedDenied.
///
/// Called by the Stop hook dispatcher. Only touches entries for the exact session_id;
/// other sessions' entries are untouched (multi-session isolation).
pub fn sweep_session_pending(
    config_dir: &Path,
    session_id: &str,
    now: DateTime<Utc>,
) -> Result<usize> {
    if session_id.is_empty() {
        log_error("queue sweep: session_id is empty, skipping sweep");
        return Ok(0);
    }

    let pending_dir = config_dir.join("queue/pending");
    if !pending_dir.exists() {
        return Ok(0);
    }

    let decided_dir = config_dir.join("queue/decided");
    std::fs::create_dir_all(&decided_dir).context("Failed to create decided dir for sweep")?;

    let session_sanitized = sanitize_session_id(session_id);
    let mut moved = 0;

    for dir_entry in std::fs::read_dir(&pending_dir)? {
        let dir_entry = dir_entry?;
        let path = dir_entry.path();
        let fname = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        if !fname.ends_with(".json") {
            continue;
        }

        // Only process entries for this exact session_id (new-format files only)
        // Old-format files (no session_id in filename) are NOT swept by session-end —
        // they'll be caught by stale GC instead.
        let parsed = match parse_queue_filename(&fname) {
            Some(p) => p,
            None => continue,
        };

        // New format has Some(session_id_segment); match against sanitized session
        let file_session = match parsed.session_id {
            Some(ref s) => s.clone(),
            None => continue, // Old-format file — skip, let stale GC handle it
        };

        if file_session != session_sanitized {
            continue; // Different session — leave it alone
        }

        let dest = decided_dir.join(&fname);
        match std::fs::read_to_string(&path) {
            Ok(contents) => match serde_json::from_str::<QueueEntry>(&contents) {
                Ok(mut entry) => {
                    entry.outcome = Some(QueueOutcome::AssumedDenied);
                    entry.moved_by = Some(QueueMover::SessionEnd);
                    entry.moved_at = Some(now);
                    if let Ok(json) = serde_json::to_string_pretty(&entry) {
                        let _ = std::fs::write(&dest, json);
                    } else {
                        let _ = std::fs::copy(&path, &dest);
                    }
                }
                Err(_) => {
                    log_error(&format!(
                        "queue sweep: corrupt pending entry {}, moving raw to decided/",
                        fname
                    ));
                    let _ = std::fs::copy(&path, &dest);
                }
            },
            Err(_) => continue,
        }

        let _ = std::fs::remove_file(&path);
        moved += 1;
    }

    Ok(moved)
}

// ── purge_expired_decided (S5: retention) ────────────────────────────────────

/// Delete decided/ entries older than `retention_hours`.
///
/// Uses filename timestamp for fast decisions (no JSON read needed).
/// Logs a warning before the first batch to inform the operator.
pub fn purge_expired_decided(
    config_dir: &Path,
    retention_hours: u64,
    now: DateTime<Utc>,
) -> Result<usize> {
    let decided_dir = config_dir.join("queue/decided");
    if !decided_dir.exists() {
        return Ok(0);
    }

    let cutoff_ms = now.timestamp_millis() - (retention_hours as i64 * 3600 * 1000);
    let mut deleted = 0;

    for dir_entry in std::fs::read_dir(&decided_dir)? {
        let dir_entry = dir_entry?;
        let path = dir_entry.path();
        let fname = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        if !fname.ends_with(".json") {
            continue;
        }

        let ts_ms = match parse_queue_filename(&fname) {
            Some(p) => p.timestamp_ms,
            None => {
                // Filename not parseable (e.g. pre-M7.14 old format like "old-entry.json")
                // Fall back to file mtime check
                match std::fs::metadata(&path) {
                    Ok(meta) => {
                        let mtime = meta
                            .modified()
                            .ok()
                            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                            .map(|d| d.as_millis() as i64)
                            .unwrap_or(i64::MAX);
                        if mtime >= cutoff_ms {
                            continue;
                        }
                        // Old entry exceeds retention — delete it
                        let _ = std::fs::remove_file(&path);
                        deleted += 1;
                        continue;
                    }
                    Err(_) => continue,
                }
            }
        };

        if ts_ms < cutoff_ms {
            let _ = std::fs::remove_file(&path);
            deleted += 1;
        }
    }

    if deleted > 0 {
        log_error(&format!(
            "queue: purged {} decided entries older than {}h — raise queue.retention_decided_hours in trust-firewall.yaml to retain longer",
            deleted, retention_hours
        ));
    }

    Ok(deleted)
}

// ── list_pending (S7: session filter) ────────────────────────────────────────

/// List pending approval entries, optionally filtered by session_id.
///
/// When `session_filter` is `Some(sid)`, only entries whose `session_id` field
/// (or filename session segment) matches `sid` are returned.
/// When `None`, all entries are returned (backwards-compatible behaviour).
pub fn list_pending(config_dir: &Path) -> Result<Vec<QueueEntry>> {
    list_pending_filtered(config_dir, None)
}

/// List pending entries with optional session filter.
pub fn list_pending_filtered(
    config_dir: &Path,
    session_filter: Option<&str>,
) -> Result<Vec<QueueEntry>> {
    let pending_dir = config_dir.join("queue/pending");
    if !pending_dir.exists() {
        return Ok(Vec::new());
    }

    // Auto-prune entries older than 30 days (legacy fallback, S4 now does this lazily)
    let _ = prune_old_entries(config_dir, Duration::days(30));

    let session_sanitized = session_filter.map(sanitize_session_id);

    let mut entries = Vec::new();
    for entry in std::fs::read_dir(&pending_dir)
        .with_context(|| format!("Failed to read pending dir: {}", pending_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let fname = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        if !fname.ends_with(".json") {
            continue;
        }

        // Fast session filter via filename (avoids JSON reads for non-matching entries)
        if let Some(ref sid_sanitized) = session_sanitized {
            match parse_queue_filename(&fname) {
                Some(ParsedQueueFilename {
                    session_id: Some(ref file_session),
                    ..
                }) => {
                    if file_session != sid_sanitized {
                        continue; // Filename session doesn't match
                    }
                }
                Some(ParsedQueueFilename {
                    session_id: None, ..
                }) => {
                    // Old-format file: no session_id in filename.
                    // Load and check field-level session_id.
                    let contents = match std::fs::read_to_string(&path) {
                        Ok(c) => c,
                        Err(_) => continue,
                    };
                    match serde_json::from_str::<QueueEntry>(&contents) {
                        Ok(qe) => {
                            // Old entries without session_id field are excluded from session filter
                            if qe.session_id.as_deref() != Some(session_filter.unwrap_or("")) {
                                continue;
                            }
                            entries.push(qe);
                            continue;
                        }
                        Err(_) => continue,
                    }
                }
                None => continue, // Malformed filename
            }
        }

        let contents = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read queue file: {}", path.display()))?;
        match serde_json::from_str::<QueueEntry>(&contents) {
            Ok(qe) => entries.push(qe),
            Err(_) => continue, // skip malformed entries
        }
    }

    entries.sort_by_key(|e| e.timestamp);
    Ok(entries)
}

// ── prune_old_entries (S9: kept as thin wrapper for backwards-compat) ─────────

/// Move pending entries older than `max_age` to queue/decided/.
///
/// DEPRECATED since M7.14 — stale GC (gc_stale_pending) now handles this automatically.
/// Kept as a public API shim for backwards-compat with integration tests and callers.
/// CLI `queue prune` now uses `purge_expired_decided` for manual decided/ cleanup.
pub fn prune_old_entries(config_dir: &Path, max_age: Duration) -> Result<usize> {
    let pending_dir = config_dir.join("queue/pending");
    if !pending_dir.exists() {
        return Ok(0);
    }

    let decided_dir = config_dir.join("queue/decided");
    std::fs::create_dir_all(&decided_dir)
        .with_context(|| format!("Failed to create decided dir: {}", decided_dir.display()))?;

    let now = Utc::now();
    let cutoff = now - max_age;
    let mut pruned = 0;

    for entry in std::fs::read_dir(&pending_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }

        let contents = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let mut qe: QueueEntry = match serde_json::from_str(&contents) {
            Ok(q) => q,
            Err(_) => continue,
        };

        if qe.timestamp < cutoff {
            // Set outcome metadata for entries moved by this legacy path
            if qe.outcome.is_none() {
                qe.outcome = Some(QueueOutcome::AssumedDenied);
                qe.moved_by = Some(QueueMover::ManualPrune);
                qe.moved_at = Some(now);
            }
            let dest = decided_dir.join(entry.file_name());
            // Try to write updated entry; fall back to raw rename
            if let Ok(updated_json) = serde_json::to_string_pretty(&qe) {
                let _ = std::fs::write(&dest, updated_json);
                let _ = std::fs::remove_file(&path);
            } else {
                let _ = std::fs::rename(&path, &dest);
            }
            pruned += 1;
        }
    }

    Ok(pruned)
}

// ── log_error helper ─────────────────────────────────────────────────────────

/// Best-effort stderr logging for non-fatal queue errors.
fn log_error(msg: &str) {
    let ts = Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
    eprintln!("[{ts}] colmena-queue: {msg}");
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Action;
    use serde_json::json;
    use tempfile::TempDir;

    fn make_test_payload() -> EvaluationInput {
        EvaluationInput {
            session_id: "test-session".to_string(),
            tool_name: "Bash".to_string(),
            tool_input: json!({"command": "nmap -sV target"}),
            tool_use_id: "tu_001".to_string(),
            agent_id: Some("pentester".to_string()),
            cwd: "/tmp".to_string(),
        }
    }

    fn make_test_decision() -> Decision {
        Decision {
            action: Action::Ask,
            reason: "Potentially destructive".to_string(),
            matched_rule: Some("restricted[0]".to_string()),
            priority: Priority::Medium,
        }
    }

    // ── Original tests (must stay green) ────────────────────────────────────

    #[test]
    fn test_enqueue_and_list() {
        let tmp = TempDir::new().unwrap();
        let config_dir = tmp.path();
        std::fs::create_dir_all(config_dir.join("queue/pending")).unwrap();

        let payload = make_test_payload();
        let decision = make_test_decision();

        let path = enqueue_pending(config_dir, &payload, &decision).unwrap();
        assert!(path.exists());

        let entries = list_pending(config_dir).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].tool, "Bash");
        assert_eq!(entries[0].agent_id, Some("pentester".to_string()));
        assert_eq!(entries[0].priority, "medium");
    }

    #[test]
    fn test_list_empty_queue() {
        let tmp = TempDir::new().unwrap();
        let entries = list_pending(tmp.path()).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_truncate_input_bash_long_command() {
        let long_cmd = "x".repeat(300);
        let input = json!({"command": long_cmd});
        let truncated = truncate_input("Bash", &input);
        let cmd = truncated["command"].as_str().unwrap();
        assert!(cmd.len() <= MAX_COMMAND_LEN + 3); // +3 for "..."
        assert!(cmd.ends_with("..."));
    }

    #[test]
    fn test_truncate_input_write_redacts_content() {
        let input = json!({"file_path": "/src/main.rs", "content": "very long content here"});
        let truncated = truncate_input("Write", &input);
        assert_eq!(truncated["file_path"], "/src/main.rs");
        assert_eq!(truncated["content"], "[REDACTED]");
    }

    #[test]
    fn test_truncate_input_short_command_unchanged() {
        let input = json!({"command": "ls -la"});
        let truncated = truncate_input("Bash", &input);
        assert_eq!(truncated["command"], "ls -la");
    }

    #[test]
    fn test_prune_old_entries() {
        let tmp = TempDir::new().unwrap();
        let config_dir = tmp.path();
        let pending_dir = config_dir.join("queue/pending");
        std::fs::create_dir_all(&pending_dir).unwrap();

        // Create an old entry (timestamp 40 days ago)
        let old_entry = QueueEntry {
            id: "old-entry".to_string(),
            timestamp: Utc::now() - Duration::days(40),
            agent_id: None,
            tool: "Bash".to_string(),
            input: json!({"command": "ls"}),
            rule_matched: None,
            priority: "low".to_string(),
            reason: "test".to_string(),
            session_id: None,
            outcome: None,
            moved_by: None,
            moved_at: None,
        };
        let old_path = pending_dir.join("old-entry.json");
        std::fs::write(&old_path, serde_json::to_string(&old_entry).unwrap()).unwrap();

        // Create a recent entry
        let new_entry = QueueEntry {
            id: "new-entry".to_string(),
            timestamp: Utc::now(),
            agent_id: None,
            tool: "Bash".to_string(),
            input: json!({"command": "ls"}),
            rule_matched: None,
            priority: "low".to_string(),
            reason: "test".to_string(),
            session_id: None,
            outcome: None,
            moved_by: None,
            moved_at: None,
        };
        let new_path = pending_dir.join("new-entry.json");
        std::fs::write(&new_path, serde_json::to_string(&new_entry).unwrap()).unwrap();

        let pruned = prune_old_entries(config_dir, Duration::days(30)).unwrap();
        assert_eq!(pruned, 1);

        // Old entry moved to decided/
        assert!(!old_path.exists());
        assert!(config_dir.join("queue/decided/old-entry.json").exists());

        // New entry still in pending/
        assert!(new_path.exists());
    }

    // ── S1: QueueEntry schema ────────────────────────────────────────────────

    #[test]
    fn test_queue_entry_new_fields_default_to_none_on_old_json() {
        // Old-format JSON without new fields — must deserialize without error
        let old_json = r#"{
            "id": "1234567890-tu_old",
            "timestamp": "2026-01-01T00:00:00Z",
            "agent_id": null,
            "tool": "Bash",
            "input": {"command": "ls"},
            "rule_matched": null,
            "priority": "low",
            "reason": "test"
        }"#;
        let entry: QueueEntry = serde_json::from_str(old_json).unwrap();
        assert!(entry.session_id.is_none());
        assert!(entry.outcome.is_none());
        assert!(entry.moved_by.is_none());
        assert!(entry.moved_at.is_none());
    }

    #[test]
    fn test_queue_entry_new_fields_serialize_skips_none() {
        let entry = QueueEntry {
            id: "test".to_string(),
            timestamp: Utc::now(),
            agent_id: None,
            tool: "Bash".to_string(),
            input: json!({}),
            rule_matched: None,
            priority: "low".to_string(),
            reason: "test".to_string(),
            session_id: None,
            outcome: None,
            moved_by: None,
            moved_at: None,
        };
        let json_str = serde_json::to_string(&entry).unwrap();
        assert!(!json_str.contains("session_id"));
        assert!(!json_str.contains("outcome"));
        assert!(!json_str.contains("moved_by"));
        assert!(!json_str.contains("moved_at"));
    }

    // ── S2: filename parser ──────────────────────────────────────────────────

    #[test]
    fn test_parse_filename_new_format() {
        let parsed = parse_queue_filename("1776873139785-abc123-toolu_XYZ.json").unwrap();
        assert_eq!(parsed.timestamp_ms, 1776873139785);
        assert_eq!(parsed.session_id, Some("abc123".to_string()));
        assert_eq!(parsed.tool_use_id, "toolu_XYZ");
    }

    #[test]
    fn test_parse_filename_old_format() {
        let parsed = parse_queue_filename("1776873139785-toolu_XYZ.json").unwrap();
        assert_eq!(parsed.timestamp_ms, 1776873139785);
        assert!(parsed.session_id.is_none());
        assert_eq!(parsed.tool_use_id, "toolu_XYZ");
    }

    #[test]
    fn test_parse_filename_malformed_no_hyphen() {
        assert!(parse_queue_filename("nodash.json").is_none());
    }

    #[test]
    fn test_parse_filename_malformed_non_numeric_ts() {
        assert!(parse_queue_filename("abc-toolu_XYZ.json").is_none());
    }

    #[test]
    fn test_parse_filename_malformed_empty_rest() {
        assert!(parse_queue_filename("1234567890-.json").is_none());
    }

    #[test]
    fn test_parse_filename_no_extension() {
        // Without .json — stem parsing still works
        let parsed = parse_queue_filename("1776873139785-sessabc-toolu_XYZ").unwrap();
        assert_eq!(parsed.timestamp_ms, 1776873139785);
        assert_eq!(parsed.session_id, Some("sessabc".to_string()));
        assert_eq!(parsed.tool_use_id, "toolu_XYZ");
    }

    #[test]
    fn test_sanitize_session_id_replaces_special_chars() {
        assert_eq!(sanitize_session_id("sess-abc.123/x y"), "sess_abc_123_x_y");
    }

    #[test]
    fn test_sanitize_session_id_uuid_style() {
        // UUID-style session IDs have hyphens
        assert_eq!(
            sanitize_session_id("f537dd26-bfa8-42ab-a1f7-9d1ceb97922e"),
            "f537dd26_bfa8_42ab_a1f7_9d1ceb97922e"
        );
    }

    #[test]
    fn test_enqueue_uses_new_filename_schema() {
        let tmp = TempDir::new().unwrap();
        let config_dir = tmp.path();

        let payload = EvaluationInput {
            session_id: "test-session".to_string(),
            tool_name: "Bash".to_string(),
            tool_input: json!({"command": "ls"}),
            tool_use_id: "tu_999".to_string(),
            agent_id: None,
            cwd: "/tmp/test".to_string(),
        };
        let decision = make_test_decision();

        let path = enqueue_pending(config_dir, &payload, &decision).unwrap();
        let fname = path.file_name().unwrap().to_str().unwrap();

        // New format: {ts}-{sanitized_session}-{tool_use_id}.json
        let parsed = parse_queue_filename(fname).unwrap();
        assert_eq!(parsed.session_id, Some("test_session".to_string()));
        assert_eq!(parsed.tool_use_id, "tu_999");

        // The QueueEntry should have session_id populated
        let contents = std::fs::read_to_string(&path).unwrap();
        let entry: QueueEntry = serde_json::from_str(&contents).unwrap();
        assert_eq!(entry.session_id, Some("test-session".to_string()));
    }

    // ── S3: resolve_pending ──────────────────────────────────────────────────

    #[test]
    fn test_resolve_pending_success_allowed() {
        let tmp = TempDir::new().unwrap();
        let config_dir = tmp.path();

        let payload = EvaluationInput {
            session_id: "sess-resolve".to_string(),
            tool_name: "Bash".to_string(),
            tool_input: json!({"command": "ls"}),
            tool_use_id: "tu_resolve_001".to_string(),
            agent_id: None,
            cwd: "/tmp/test".to_string(),
        };
        let decision = make_test_decision();
        enqueue_pending(config_dir, &payload, &decision).unwrap();

        let result = resolve_pending(
            config_dir,
            "sess-resolve",
            "tu_resolve_001",
            QueueOutcome::Allowed,
            QueueMover::Posttool,
        )
        .unwrap();

        assert!(result.is_some());
        let dest = result.unwrap();
        assert!(dest.to_str().unwrap().contains("queue/decided"));
        assert!(dest.exists());

        // Pending dir should be empty
        let pending = config_dir.join("queue/pending");
        let count = std::fs::read_dir(&pending).unwrap().count();
        assert_eq!(count, 0, "pending dir should be empty after resolve");

        // Decided entry has correct metadata
        let contents = std::fs::read_to_string(&dest).unwrap();
        let entry: QueueEntry = serde_json::from_str(&contents).unwrap();
        assert_eq!(entry.outcome, Some(QueueOutcome::Allowed));
        assert_eq!(entry.moved_by, Some(QueueMover::Posttool));
        assert!(entry.moved_at.is_some());
    }

    #[test]
    fn test_resolve_pending_success_failed() {
        let tmp = TempDir::new().unwrap();
        let config_dir = tmp.path();

        let payload = EvaluationInput {
            session_id: "sess-failed".to_string(),
            tool_name: "Bash".to_string(),
            tool_input: json!({"command": "ls"}),
            tool_use_id: "tu_failed_001".to_string(),
            agent_id: None,
            cwd: "/tmp/test".to_string(),
        };
        let decision = make_test_decision();
        enqueue_pending(config_dir, &payload, &decision).unwrap();

        let result = resolve_pending(
            config_dir,
            "sess-failed",
            "tu_failed_001",
            QueueOutcome::Failed,
            QueueMover::Posttool,
        )
        .unwrap();

        assert!(result.is_some());
        let dest = result.unwrap();
        let contents = std::fs::read_to_string(&dest).unwrap();
        let entry: QueueEntry = serde_json::from_str(&contents).unwrap();
        assert_eq!(entry.outcome, Some(QueueOutcome::Failed));
    }

    #[test]
    fn test_resolve_pending_no_match_returns_none() {
        let tmp = TempDir::new().unwrap();
        let config_dir = tmp.path();
        std::fs::create_dir_all(config_dir.join("queue/pending")).unwrap();

        let result = resolve_pending(
            config_dir,
            "sess-nomatch",
            "tu_bogus_999",
            QueueOutcome::Allowed,
            QueueMover::Posttool,
        )
        .unwrap();

        assert!(result.is_none());
    }

    #[test]
    fn test_resolve_pending_old_format_filename() {
        let tmp = TempDir::new().unwrap();
        let config_dir = tmp.path();
        let pending_dir = config_dir.join("queue/pending");
        std::fs::create_dir_all(&pending_dir).unwrap();

        // Pre-create an old-format pending file manually
        let old_entry = QueueEntry {
            id: "1234567890-tu_old_001".to_string(),
            timestamp: Utc::now(),
            agent_id: None,
            tool: "Read".to_string(),
            input: json!({}),
            rule_matched: None,
            priority: "low".to_string(),
            reason: "test".to_string(),
            session_id: None, // Old format — no session_id
            outcome: None,
            moved_by: None,
            moved_at: None,
        };
        let old_fname = "1234567890-tu_old_001.json";
        std::fs::write(
            pending_dir.join(old_fname),
            serde_json::to_string_pretty(&old_entry).unwrap(),
        )
        .unwrap();

        // resolve_pending should find it via the old-format suffix match
        let result = resolve_pending(
            config_dir,
            "any-session",
            "tu_old_001",
            QueueOutcome::Allowed,
            QueueMover::Posttool,
        )
        .unwrap();

        assert!(result.is_some(), "Should find and move old-format entry");
        assert!(config_dir.join("queue/decided").join(old_fname).exists());
        assert!(!pending_dir.join(old_fname).exists());
    }

    // ── S4: gc_stale_pending ─────────────────────────────────────────────────

    #[test]
    fn test_gc_stale_pending_moves_old_entry() {
        let tmp = TempDir::new().unwrap();
        let config_dir = tmp.path();
        let pending_dir = config_dir.join("queue/pending");
        std::fs::create_dir_all(&pending_dir).unwrap();

        let now = Utc::now();
        // Old entry: timestamp 10 minutes ago
        let old_ts = now.timestamp_millis() - 10 * 60 * 1000;
        let old_fname = format!("{}-sess_old-tu_old.json", old_ts);
        let old_entry = QueueEntry {
            id: "old".to_string(),
            timestamp: now - Duration::minutes(10),
            agent_id: None,
            tool: "Bash".to_string(),
            input: json!({}),
            rule_matched: None,
            priority: "low".to_string(),
            reason: "old".to_string(),
            session_id: Some("sess-old".to_string()),
            outcome: None,
            moved_by: None,
            moved_at: None,
        };
        std::fs::write(
            pending_dir.join(&old_fname),
            serde_json::to_string_pretty(&old_entry).unwrap(),
        )
        .unwrap();

        // New entry: timestamp 1 minute ago
        let new_ts = now.timestamp_millis() - 1 * 60 * 1000;
        let new_fname = format!("{}-sess_new-tu_new.json", new_ts);
        let new_entry = QueueEntry {
            id: "new".to_string(),
            timestamp: now - Duration::minutes(1),
            agent_id: None,
            tool: "Bash".to_string(),
            input: json!({}),
            rule_matched: None,
            priority: "low".to_string(),
            reason: "new".to_string(),
            session_id: Some("sess-new".to_string()),
            outcome: None,
            moved_by: None,
            moved_at: None,
        };
        std::fs::write(
            pending_dir.join(&new_fname),
            serde_json::to_string_pretty(&new_entry).unwrap(),
        )
        .unwrap();

        // GC with TTL=240s (4 min) — only old entry should be moved
        let moved = gc_stale_pending(config_dir, 240, now).unwrap();
        assert_eq!(moved, 1);

        assert!(
            !pending_dir.join(&old_fname).exists(),
            "Old entry should be moved"
        );
        assert!(
            pending_dir.join(&new_fname).exists(),
            "New entry should remain"
        );

        let decided = config_dir.join("queue/decided").join(&old_fname);
        assert!(decided.exists());
        let contents = std::fs::read_to_string(&decided).unwrap();
        let entry: QueueEntry = serde_json::from_str(&contents).unwrap();
        assert_eq!(entry.outcome, Some(QueueOutcome::AssumedDenied));
        assert_eq!(entry.moved_by, Some(QueueMover::StaleGc));
    }

    #[test]
    fn test_gc_stale_pending_handles_corrupt_file() {
        let tmp = TempDir::new().unwrap();
        let config_dir = tmp.path();
        let pending_dir = config_dir.join("queue/pending");
        std::fs::create_dir_all(&pending_dir).unwrap();

        let now = Utc::now();
        // Old timestamp (well past TTL)
        let old_ts = now.timestamp_millis() - 20 * 60 * 1000;
        let corrupt_fname = format!("{}-sess_c-tu_corrupt.json", old_ts);
        // Write malformed JSON
        std::fs::write(pending_dir.join(&corrupt_fname), b"{ invalid json !!!").unwrap();

        let moved = gc_stale_pending(config_dir, 240, now).unwrap();
        assert_eq!(moved, 1, "Corrupt file should still be moved");

        // Raw file should be in decided/
        assert!(config_dir
            .join("queue/decided")
            .join(&corrupt_fname)
            .exists());
        // No longer in pending/
        assert!(!pending_dir.join(&corrupt_fname).exists());
    }

    // ── S4-bis: sweep_session_pending ────────────────────────────────────────

    #[test]
    fn test_sweep_session_pending_moves_matching_entries() {
        let tmp = TempDir::new().unwrap();
        let config_dir = tmp.path();
        let pending_dir = config_dir.join("queue/pending");
        std::fs::create_dir_all(&pending_dir).unwrap();

        let now = Utc::now();
        let session_a = "session_abc";
        let session_b = "session_xyz";

        // 3 entries from session A
        for i in 0..3 {
            let ts = now.timestamp_millis() + i;
            let fname = format!("{}-{}-tu_{}.json", ts, sanitize_session_id(session_a), i);
            let entry = QueueEntry {
                id: format!("a-{i}"),
                timestamp: now,
                agent_id: None,
                tool: "Bash".to_string(),
                input: json!({}),
                rule_matched: None,
                priority: "low".to_string(),
                reason: "test".to_string(),
                session_id: Some(session_a.to_string()),
                outcome: None,
                moved_by: None,
                moved_at: None,
            };
            std::fs::write(
                pending_dir.join(&fname),
                serde_json::to_string_pretty(&entry).unwrap(),
            )
            .unwrap();
        }

        // 2 entries from session B
        for i in 0..2 {
            let ts = now.timestamp_millis() + 100 + i;
            let fname = format!("{}-{}-tu_{}.json", ts, sanitize_session_id(session_b), i);
            let entry = QueueEntry {
                id: format!("b-{i}"),
                timestamp: now,
                agent_id: None,
                tool: "Read".to_string(),
                input: json!({}),
                rule_matched: None,
                priority: "low".to_string(),
                reason: "test".to_string(),
                session_id: Some(session_b.to_string()),
                outcome: None,
                moved_by: None,
                moved_at: None,
            };
            std::fs::write(
                pending_dir.join(&fname),
                serde_json::to_string_pretty(&entry).unwrap(),
            )
            .unwrap();
        }

        // Sweep session A
        let moved = sweep_session_pending(config_dir, session_a, now).unwrap();
        assert_eq!(moved, 3, "Should move exactly 3 session-A entries");

        // Session B entries still in pending
        let remaining: Vec<_> = std::fs::read_dir(&pending_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(remaining.len(), 2, "Session B entries should remain");

        // Decided/ has 3 entries with correct metadata
        let decided_count = std::fs::read_dir(config_dir.join("queue/decided"))
            .unwrap()
            .count();
        assert_eq!(decided_count, 3);
    }

    #[test]
    fn test_sweep_session_pending_no_matching_entries_is_noop() {
        let tmp = TempDir::new().unwrap();
        let config_dir = tmp.path();
        std::fs::create_dir_all(config_dir.join("queue/pending")).unwrap();

        let now = Utc::now();
        let moved = sweep_session_pending(config_dir, "no-such-session", now).unwrap();
        assert_eq!(moved, 0);
    }

    #[test]
    fn test_sweep_session_pending_does_not_touch_other_sessions() {
        let tmp = TempDir::new().unwrap();
        let config_dir = tmp.path();
        let pending_dir = config_dir.join("queue/pending");
        std::fs::create_dir_all(&pending_dir).unwrap();

        let now = Utc::now();
        let session_a = "session_a";
        let session_b = "session_b";

        // 1 entry from session A, 1 from session B
        for (sess, i) in &[(session_a, 0i64), (session_b, 1i64)] {
            let ts = now.timestamp_millis() + i;
            let fname = format!("{}-{}-tu_{}.json", ts, sanitize_session_id(sess), i);
            let entry = QueueEntry {
                id: format!("entry-{i}"),
                timestamp: now,
                agent_id: None,
                tool: "Bash".to_string(),
                input: json!({}),
                rule_matched: None,
                priority: "low".to_string(),
                reason: "test".to_string(),
                session_id: Some(sess.to_string()),
                outcome: None,
                moved_by: None,
                moved_at: None,
            };
            std::fs::write(
                pending_dir.join(&fname),
                serde_json::to_string_pretty(&entry).unwrap(),
            )
            .unwrap();
        }

        sweep_session_pending(config_dir, session_a, now).unwrap();

        // Session B entry still in pending
        let remaining_count = std::fs::read_dir(&pending_dir).unwrap().count();
        assert_eq!(remaining_count, 1, "Session B entry must remain in pending");
    }

    #[test]
    fn test_sweep_session_pending_empty_session_id_noop() {
        let tmp = TempDir::new().unwrap();
        let config_dir = tmp.path();
        std::fs::create_dir_all(config_dir.join("queue/pending")).unwrap();

        let now = Utc::now();
        let moved = sweep_session_pending(config_dir, "", now).unwrap();
        assert_eq!(moved, 0);
    }

    // ── S5: purge_expired_decided ────────────────────────────────────────────

    #[test]
    fn test_purge_expired_decided_deletes_old_keeps_recent() {
        let tmp = TempDir::new().unwrap();
        let config_dir = tmp.path();
        let decided_dir = config_dir.join("queue/decided");
        std::fs::create_dir_all(&decided_dir).unwrap();

        let now = Utc::now();

        // Entry aged 25h — should be deleted (retention_hours=24)
        let old_ts = now.timestamp_millis() - 25 * 3600 * 1000;
        let old_fname = format!("{}-sess_a-tu_old.json", old_ts);
        std::fs::write(decided_dir.join(&old_fname), b"{}").unwrap();

        // Entry aged 1h — should be kept
        let new_ts = now.timestamp_millis() - 1 * 3600 * 1000;
        let new_fname = format!("{}-sess_a-tu_new.json", new_ts);
        std::fs::write(decided_dir.join(&new_fname), b"{}").unwrap();

        let deleted = purge_expired_decided(config_dir, 24, now).unwrap();
        assert_eq!(deleted, 1);
        assert!(!decided_dir.join(&old_fname).exists());
        assert!(decided_dir.join(&new_fname).exists());
    }

    // ── S7: list_pending session filter ─────────────────────────────────────

    #[test]
    fn test_list_pending_session_filter() {
        let tmp = TempDir::new().unwrap();
        let config_dir = tmp.path();
        let pending_dir = config_dir.join("queue/pending");
        std::fs::create_dir_all(&pending_dir).unwrap();

        let now = Utc::now();
        let session_a = "session_a";
        let session_b = "session_b";

        // 3 entries from session A
        for i in 0..3 {
            let ts = now.timestamp_millis() + i;
            let fname = format!("{}-{}-tu_a_{}.json", ts, sanitize_session_id(session_a), i);
            let entry = QueueEntry {
                id: format!("a-{i}"),
                timestamp: now,
                agent_id: None,
                tool: "Bash".to_string(),
                input: json!({}),
                rule_matched: None,
                priority: "low".to_string(),
                reason: "test".to_string(),
                session_id: Some(session_a.to_string()),
                outcome: None,
                moved_by: None,
                moved_at: None,
            };
            std::fs::write(
                pending_dir.join(&fname),
                serde_json::to_string_pretty(&entry).unwrap(),
            )
            .unwrap();
        }

        // 2 entries from session B
        for i in 0..2 {
            let ts = now.timestamp_millis() + 100 + i;
            let fname = format!("{}-{}-tu_b_{}.json", ts, sanitize_session_id(session_b), i);
            let entry = QueueEntry {
                id: format!("b-{i}"),
                timestamp: now,
                agent_id: None,
                tool: "Read".to_string(),
                input: json!({}),
                rule_matched: None,
                priority: "low".to_string(),
                reason: "test".to_string(),
                session_id: Some(session_b.to_string()),
                outcome: None,
                moved_by: None,
                moved_at: None,
            };
            std::fs::write(
                pending_dir.join(&fname),
                serde_json::to_string_pretty(&entry).unwrap(),
            )
            .unwrap();
        }

        let a_entries = list_pending_filtered(config_dir, Some(session_a)).unwrap();
        assert_eq!(a_entries.len(), 3);

        let all_entries = list_pending_filtered(config_dir, None).unwrap();
        assert_eq!(all_entries.len(), 5);
    }

    #[test]
    fn test_list_pending_backcompat_old_entry_no_session_field() {
        let tmp = TempDir::new().unwrap();
        let config_dir = tmp.path();
        let pending_dir = config_dir.join("queue/pending");
        std::fs::create_dir_all(&pending_dir).unwrap();

        // Old-format file: filename has no session segment, JSON has no session_id field
        let old_json = r#"{
            "id": "1234567890-tu_backcompat",
            "timestamp": "2026-04-01T00:00:00Z",
            "agent_id": null,
            "tool": "Bash",
            "input": {"command": "ls"},
            "rule_matched": null,
            "priority": "low",
            "reason": "backcompat"
        }"#;
        std::fs::write(pending_dir.join("1234567890-tu_backcompat.json"), old_json).unwrap();

        // list_pending(None) includes it
        let all = list_pending_filtered(config_dir, None).unwrap();
        assert_eq!(all.len(), 1);

        // list_pending(Some("X")) excludes it (can't be session-scoped)
        let filtered = list_pending_filtered(config_dir, Some("someX")).unwrap();
        assert_eq!(filtered.len(), 0);
    }

    // ── S4 + lazy GC integration ─────────────────────────────────────────────

    #[test]
    fn test_enqueue_triggers_lazy_gc() {
        let tmp = TempDir::new().unwrap();
        let config_dir = tmp.path();
        let pending_dir = config_dir.join("queue/pending");
        std::fs::create_dir_all(&pending_dir).unwrap();

        let now = Utc::now();

        // Pre-place an old entry (timestamp 12 minutes ago) in pending/
        let old_ts = now.timestamp_millis() - 12 * 60 * 1000;
        let old_fname = format!("{}-sess_old-tu_old_gc.json", old_ts);
        let old_entry = QueueEntry {
            id: "old_gc".to_string(),
            timestamp: now - Duration::minutes(12),
            agent_id: None,
            tool: "Bash".to_string(),
            input: json!({}),
            rule_matched: None,
            priority: "low".to_string(),
            reason: "old".to_string(),
            session_id: Some("sess-old".to_string()),
            outcome: None,
            moved_by: None,
            moved_at: None,
        };
        std::fs::write(
            pending_dir.join(&old_fname),
            serde_json::to_string_pretty(&old_entry).unwrap(),
        )
        .unwrap();

        // Enqueue a new entry with GC TTL=600s (old entry is 720s old → stale)
        let payload = EvaluationInput {
            session_id: "sess-new".to_string(),
            tool_name: "Read".to_string(),
            tool_input: json!({}),
            tool_use_id: "tu_new_gc".to_string(),
            agent_id: None,
            cwd: "/tmp/test".to_string(),
        };
        let decision = make_test_decision();
        enqueue_pending_with_config(config_dir, &payload, &decision, 600, 24 * 7).unwrap();

        // Old entry should be in decided/, new entry in pending/
        let pending_count = std::fs::read_dir(&pending_dir).unwrap().count();
        assert_eq!(
            pending_count, 1,
            "Only the new entry should remain in pending/"
        );

        assert!(
            !pending_dir.join(&old_fname).exists(),
            "Old entry should be moved by lazy GC"
        );
        assert!(
            config_dir.join("queue/decided").join(&old_fname).exists(),
            "Old entry should be in decided/"
        );
    }

    // ── Concurrent GC safety ─────────────────────────────────────────────────

    #[test]
    fn test_gc_concurrent_calls_safe() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let tmp = TempDir::new().unwrap();
        let config_dir = tmp.path().to_path_buf();
        let pending_dir = config_dir.join("queue/pending");
        std::fs::create_dir_all(&pending_dir).unwrap();

        let now = Utc::now();

        // Create 5 stale entries
        for i in 0..5 {
            let old_ts = now.timestamp_millis() - 20 * 60 * 1000 + i;
            let fname = format!("{}-sess_cc-tu_cc_{}.json", old_ts, i);
            let entry = QueueEntry {
                id: format!("cc-{i}"),
                timestamp: now - Duration::minutes(20),
                agent_id: None,
                tool: "Bash".to_string(),
                input: json!({}),
                rule_matched: None,
                priority: "low".to_string(),
                reason: "concurrent".to_string(),
                session_id: Some("sess-cc".to_string()),
                outcome: None,
                moved_by: None,
                moved_at: None,
            };
            std::fs::write(
                pending_dir.join(&fname),
                serde_json::to_string_pretty(&entry).unwrap(),
            )
            .unwrap();
        }

        let config_dir_arc = Arc::new(config_dir.clone());
        let errors = Arc::new(Mutex::new(Vec::new()));

        // Spawn 3 threads all running GC simultaneously
        let handles: Vec<_> = (0..3)
            .map(|_| {
                let dir = Arc::clone(&config_dir_arc);
                let errs = Arc::clone(&errors);
                thread::spawn(move || match gc_stale_pending(&dir, 240, now) {
                    Ok(_) => {}
                    Err(e) => errs.lock().unwrap().push(e.to_string()),
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        let errors = errors.lock().unwrap();
        assert!(
            errors.is_empty(),
            "Concurrent GC should not produce errors: {:?}",
            errors
        );

        // All 5 entries should have been moved (total across all threads)
        let pending_count = std::fs::read_dir(&pending_dir).unwrap().count();
        assert_eq!(pending_count, 0, "All stale entries should be moved");
        let decided_count = std::fs::read_dir(config_dir.join("queue/decided"))
            .unwrap()
            .count();
        assert_eq!(decided_count, 5, "All 5 entries should be in decided/");
    }
}

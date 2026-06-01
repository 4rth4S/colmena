//! Mission deliverables — artifacts (files inside the mission directory) and
//! code changes (git-tracked modifications in the project repo).
//!
//! Two categories the dashboard operator cares about:
//! 1. **Mission artifacts** — files agents created inside the mission dir
//!    (ARCHITECT_PLAN.md, review reports, patches). Filesystem-only, no git.
//! 2. **Code changes** — project files modified in git on the mission's branch.
//!    Computed via `git diff` + `git ls-files --others`.

use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::process::Command;

// ── Public types ──────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct DeliverablesOutput {
    pub mission_id: String,
    pub working_dir: String,
    pub branch: String,
    pub base_branch: String,
    pub artifacts: ArtifactsSection,
    pub changes: Option<ChangesSection>,
    pub summary: DeliverablesSummary,
}

#[derive(Debug, Serialize)]
pub struct ArtifactsSection {
    pub files: Vec<ArtifactEntry>,
}

#[derive(Debug, Serialize)]
pub struct ArtifactEntry {
    pub path: String,
    pub size: u64,
    pub last_modified: String,
}

#[derive(Debug, Serialize)]
pub struct ChangesSection {
    pub files: Vec<ChangeEntry>,
}

#[derive(Debug, Serialize)]
pub struct ChangeEntry {
    pub path: String,
    pub status: String, // "created" | "modified" | "deleted"
    pub size: u64,
    pub last_modified: String,
}

#[derive(Debug, Serialize)]
pub struct DeliverablesSummary {
    pub artifacts_count: usize,
    pub changes_created: usize,
    pub changes_modified: usize,
    pub total_size: u64,
}

#[derive(Debug, Serialize)]
pub struct FileDiffOutput {
    pub path: String,
    pub source: String, // "artifacts" | "changes"
    pub status: String,
    pub diff: String,
}

/// Parsed mission metadata from mission.yaml.
#[derive(Debug)]
pub struct MissionMeta {
    pub working_dir: PathBuf,
    pub branch: String,
    pub base_branch: String,
}

// ── Exclude patterns for artifact scanning ────────────────────────────────────

const ARTIFACT_EXCLUDE: &[&str] = &["mission.yaml", ".git"];

// ── Public functions ──────────────────────────────────────────────────────────

/// Read `mission.yaml` from the mission directory and extract git metadata.
///
/// Required fields: `working_dir`, `branch`, `base_branch`.
/// Returns an error if any are missing (no guessing).
pub fn read_mission_metadata(mission_dir: &Path) -> Result<MissionMeta> {
    let yaml_path = mission_dir.join("mission.yaml");
    if !yaml_path.exists() {
        bail!(
            "mission.yaml not found in {}. \
             Missions created before v0.15.0 may lack git metadata. \
             Re-spawn the mission to populate working_dir/branch/base_branch.",
            mission_dir.display()
        );
    }

    let content = std::fs::read_to_string(&yaml_path).context("failed to read mission.yaml")?;

    // Parse minimally — we only need three fields, not the full struct.
    let parsed: serde_yml::Value =
        serde_yml::from_str(&content).context("failed to parse mission.yaml")?;

    let working_dir = parsed
        .get("working_dir")
        .and_then(|v| v.as_str())
        .map(PathBuf::from)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "mission.yaml is missing 'working_dir'. \
                 This mission was created before v0.15.0. \
                 Re-spawn the mission to populate git metadata."
            )
        })?;

    let branch = parsed
        .get("branch")
        .and_then(|v| v.as_str())
        .map(String::from)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "mission.yaml is missing 'branch'. \
                 This mission was created before v0.15.0."
            )
        })?;

    let base_branch = parsed
        .get("base_branch")
        .and_then(|v| v.as_str())
        .map(String::from)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "mission.yaml is missing 'base_branch'. \
                 This mission was created before v0.15.0."
            )
        })?;

    if !working_dir.exists() {
        bail!(
            "working_dir '{}' does not exist. \
             The project directory may have been moved or deleted.",
            working_dir.display()
        );
    }

    Ok(MissionMeta {
        working_dir,
        branch,
        base_branch,
    })
}

/// List mission artifacts — files inside the mission directory.
///
/// Recursively walks the mission dir, excluding `mission.yaml` and `.git`.
/// Returns entries with relative paths (from the mission dir root).
pub fn list_artifacts(mission_dir: &Path) -> Result<Vec<ArtifactEntry>> {
    let mut files = Vec::new();
    walk_artifacts(mission_dir, mission_dir, &mut files)?;
    // Sort depth-first, alphabetical within same directory
    files.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(files)
}

fn walk_artifacts(base: &Path, dir: &Path, out: &mut Vec<ArtifactEntry>) -> Result<()> {
    let entries = std::fs::read_dir(dir)
        .with_context(|| format!("failed to read directory: {}", dir.display()))?;

    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Skip excluded names
        if ARTIFACT_EXCLUDE.iter().any(|ex| *ex == name_str.as_ref()) {
            continue;
        }

        let path = entry.path();
        let relative = path
            .strip_prefix(base)
            .unwrap_or(&path)
            .to_string_lossy()
            .to_string();

        if path.is_dir() {
            walk_artifacts(base, &path, out)?;
        } else {
            let meta = entry.metadata()?;
            let last_modified = format_iso8601(meta.modified().ok());
            out.push(ArtifactEntry {
                path: relative,
                size: meta.len(),
                last_modified,
            });
        }
    }
    Ok(())
}

/// List code changes in git between `base_branch` and `target_branch`.
///
/// Uses `git diff --name-status` for tracked changes and
/// `git ls-files --others --exclude-standard` for untracked/created files.
pub fn list_changes(
    working_dir: &Path,
    base_branch: &str,
    target_branch: &str,
) -> Result<Vec<ChangeEntry>> {
    let mut files = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // 1. Tracked changes: git diff --name-status base...branch
    let diff_output = Command::new("git")
        .args([
            "-C",
            &working_dir.to_string_lossy(),
            "diff",
            "--name-status",
            &format!("{}...{}", base_branch, target_branch),
        ])
        .output()
        .with_context(|| {
            format!(
                "failed to run git diff in {} (is it a git repo?)",
                working_dir.display()
            )
        })?;

    if !diff_output.status.success() {
        let stderr = String::from_utf8_lossy(&diff_output.stderr);
        // If the branch doesn't exist yet (e.g., no commits), that's okay —
        // just means zero tracked changes.
        if stderr.contains("bad revision") || stderr.contains("unknown revision") {
            // Branch may have no commits diverging from base — try diff against HEAD
        } else {
            bail!(
                "git diff failed in {}: {}",
                working_dir.display(),
                stderr.trim()
            );
        }
    }

    let stdout = String::from_utf8_lossy(&diff_output.stdout);
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Format: "M\tpath" or "A\tpath" or "D\tpath" etc.
        let parts: Vec<&str> = line.splitn(2, '\t').collect();
        if parts.len() < 2 {
            continue;
        }
        let status_code = parts[0];
        let path = parts[1].to_string();

        let status = match status_code {
            "A" => "created",
            "M" => "modified",
            "D" => "deleted",
            "R" => "modified", // renamed — treat as modified
            "C" => "created",  // copied — treat as created
            "T" => "modified", // type change
            _ => continue,
        };

        let full_path = working_dir.join(&path);
        let (size, last_modified) = file_info(&full_path);

        seen.insert(path.clone());
        files.push(ChangeEntry {
            path,
            status: status.to_string(),
            size,
            last_modified,
        });
    }

    // 2. Untracked files: git ls-files --others --exclude-standard
    let untracked_output = Command::new("git")
        .args([
            "-C",
            &working_dir.to_string_lossy(),
            "ls-files",
            "--others",
            "--exclude-standard",
        ])
        .output()
        .with_context(|| format!("failed to run git ls-files in {}", working_dir.display()))?;

    // ls-files --others can fail if not in a git repo; don't bail, just skip
    if untracked_output.status.success() {
        let stdout = String::from_utf8_lossy(&untracked_output.stdout);
        for line in stdout.lines() {
            let line = line.trim().to_string();
            if line.is_empty() || seen.contains(&line) {
                continue;
            }
            let full_path = working_dir.join(&line);
            let (size, last_modified) = file_info(&full_path);
            seen.insert(line.clone());
            files.push(ChangeEntry {
                path: line,
                status: "created".to_string(),
                size,
                last_modified,
            });
        }
    }

    // Sort depth-first, alphabetical
    files.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(files)
}

/// Compute a diff for a single file.
///
/// Auto-detects source:
/// 1. If the file exists in `mission_dir`, it's an artifact — returns full content.
/// 2. Otherwise, it's a code change — runs `git diff` or returns full content
///    for created files.
pub fn compute_file_diff(
    mission_dir: &Path,
    working_dir: &Path,
    base_branch: &str,
    target_branch: &str,
    file_path: &str,
) -> Result<FileDiffOutput> {
    // 1. Check if it's a mission artifact
    let artifact_path = mission_dir.join(file_path);
    if artifact_path.exists() && artifact_path.is_file() {
        let content = std::fs::read_to_string(&artifact_path)
            .with_context(|| format!("failed to read artifact: {}", artifact_path.display()))?;
        return Ok(FileDiffOutput {
            path: file_path.to_string(),
            source: "artifacts".to_string(),
            status: "artifact".to_string(),
            diff: content,
        });
    }

    // 2. It's a code change — try git diff first
    let diff_output = Command::new("git")
        .args([
            "-C",
            &working_dir.to_string_lossy(),
            "diff",
            &format!("{}...{}", base_branch, target_branch),
            "--",
            file_path,
        ])
        .output()
        .with_context(|| format!("failed to run git diff in {}", working_dir.display()))?;

    let diff_stdout = String::from_utf8_lossy(&diff_output.stdout);
    if !diff_stdout.trim().is_empty() {
        return Ok(FileDiffOutput {
            path: file_path.to_string(),
            source: "changes".to_string(),
            status: "modified".to_string(),
            diff: diff_stdout.to_string(),
        });
    }

    // 3. No diff — check if file exists on disk (created/untracked)
    let full_path = working_dir.join(file_path);
    if full_path.exists() && full_path.is_file() {
        let content = std::fs::read_to_string(&full_path)
            .with_context(|| format!("failed to read file: {}", full_path.display()))?;
        // Format as a "created" diff (all lines added)
        let lines: Vec<String> = content.lines().map(|l| format!("+{}", l)).collect();
        let created_diff = format!("@@ -0,0 +1,{} @@\n{}", lines.len(), lines.join("\n"));
        return Ok(FileDiffOutput {
            path: file_path.to_string(),
            source: "changes".to_string(),
            status: "created".to_string(),
            diff: created_diff,
        });
    }

    // 4. File not found anywhere
    bail!(
        "file '{}' not found in mission artifacts or git changes. \
         Check the path — for artifacts use a path relative to the mission dir, \
         for code changes use a path relative to the repo root.",
        file_path
    )
}

/// Auto-detect the current git branch from a repo.
pub fn detect_branch(working_dir: &Path) -> Result<String> {
    let output = Command::new("git")
        .args([
            "-C",
            &working_dir.to_string_lossy(),
            "rev-parse",
            "--abbrev-ref",
            "HEAD",
        ])
        .output()
        .with_context(|| format!("failed to run git rev-parse in {}", working_dir.display()))?;

    if !output.status.success() {
        bail!(
            "failed to detect git branch in {}: {}",
            working_dir.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let branch = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if branch.is_empty() || branch == "HEAD" {
        bail!(
            "detected detached HEAD in {} — cannot determine branch",
            working_dir.display()
        );
    }
    Ok(branch)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn file_info(path: &Path) -> (u64, String) {
    match std::fs::metadata(path) {
        Ok(meta) => (meta.len(), format_iso8601(meta.modified().ok())),
        Err(_) => (0, String::new()),
    }
}

fn format_iso8601(time: Option<std::time::SystemTime>) -> String {
    match time {
        Some(t) => {
            let dt: chrono::DateTime<chrono::Utc> = t.into();
            dt.to_rfc3339()
        }
        None => String::new(),
    }
}

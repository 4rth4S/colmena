//! Auto-detect project type from a directory for `colmena mission go`.
//!
//! Scans for known manifest files (`package.json`, `Cargo.toml`, `go.mod`, etc.)
//! and maps the detected project type to a suggested Colmena pattern + role list.

use anyhow::Result;
use std::fmt;
use std::path::{Path, PathBuf};

// ── Public types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum ProjectType {
    NextJs,
    React,
    RustBinary,
    RustLib,
    Go,
    Python,
    Node,
    Unknown,
}

impl fmt::Display for ProjectType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NextJs => write!(f, "Next.js"),
            Self::React => write!(f, "React"),
            Self::RustBinary => write!(f, "Rust (binary)"),
            Self::RustLib => write!(f, "Rust (library)"),
            Self::Go => write!(f, "Go"),
            Self::Python => write!(f, "Python"),
            Self::Node => write!(f, "Node.js"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProjectInfo {
    pub project_type: ProjectType,
    pub language: String,
    pub framework: Option<String>,
    pub project_name: String,
    pub working_dir: PathBuf,
    pub suggested_pattern: String,
    pub suggested_roles: Vec<String>,
    pub has_tests: bool,
    pub has_payments: bool,
}

// ── File markers per project type ─────────────────────────────────────────────

const NEXTJS_MARKERS: &[&str] = &["next.config.ts", "next.config.js", "next.config.mjs"];
const RUST_MARKERS: &[&str] = &["Cargo.toml"];
const GO_MARKERS: &[&str] = &["go.mod"];
const PYTHON_MARKERS: &[&str] = &["pyproject.toml", "setup.py", "requirements.txt"];
const NODE_MARKERS: &[&str] = &["package.json"];

// ── Public API ────────────────────────────────────────────────────────────────

/// Detect the project type from a directory.
///
/// Scans for known manifest files and returns a `ProjectInfo` with
/// suggested Colmena pattern and roles. Falls back to `Unknown` if
/// nothing is detected (but still suggests a safe default).
pub fn detect_project(dir: &Path) -> Result<ProjectInfo> {
    let dir = if dir.is_absolute() {
        dir.to_path_buf()
    } else {
        std::env::current_dir()?.join(dir)
    };
    let dir = dir.canonicalize().unwrap_or(dir);

    // Detect from files
    let has_rust = RUST_MARKERS.iter().any(|m| dir.join(m).exists());
    let has_go = GO_MARKERS.iter().any(|m| dir.join(m).exists());
    let has_python = PYTHON_MARKERS.iter().any(|m| dir.join(m).exists());
    let has_node = NODE_MARKERS.iter().any(|m| dir.join(m).exists());
    let has_nextjs = NEXTJS_MARKERS.iter().any(|m| dir.join(m).exists());
    let has_react = has_node && !has_nextjs && has_react_dep(&dir);

    // Additional signals
    let has_tests = dir.join("tests").exists()
        || dir.join("__tests__").exists()
        || dir.join("src").join("__tests__").exists();
    let has_payments = detect_payments(&dir);

    let project_type;
    let language;
    let framework: Option<String>;
    let suggested_pattern;
    let suggested_roles;

    if has_rust {
        project_type = if is_rust_binary(&dir) {
            ProjectType::RustBinary
        } else {
            ProjectType::RustLib
        };
        language = "Rust".to_string();
        framework = None;
        suggested_pattern = "code-review-cycle".to_string();
        suggested_roles = vec![
            "architect".to_string(),
            "developer".to_string(),
            "code_reviewer".to_string(),
            "auditor".to_string(),
        ];
    } else if has_nextjs {
        project_type = ProjectType::NextJs;
        language = "TypeScript/JavaScript".to_string();
        framework = Some("Next.js".to_string());
        suggested_pattern = "plan-then-execute".to_string();
        suggested_roles = vec![
            "architect".to_string(),
            "ui_ux_designer".to_string(),
            "frontend_engineer".to_string(),
            "developer".to_string(),
            "auditor".to_string(),
        ];
    } else if has_react {
        project_type = ProjectType::React;
        language = "TypeScript/JavaScript".to_string();
        framework = Some("React".to_string());
        suggested_pattern = "frontend-design-squad".to_string();
        suggested_roles = vec![
            "ui_ux_designer".to_string(),
            "frontend_engineer".to_string(),
            "code_reviewer".to_string(),
            "auditor".to_string(),
        ];
    } else if has_go {
        project_type = ProjectType::Go;
        language = "Go".to_string();
        framework = None;
        suggested_pattern = "code-review-cycle".to_string();
        suggested_roles = vec![
            "developer".to_string(),
            "code_reviewer".to_string(),
            "auditor".to_string(),
        ];
    } else if has_python {
        project_type = ProjectType::Python;
        language = "Python".to_string();
        framework = None;
        suggested_pattern = "code-review-cycle".to_string();
        suggested_roles = vec![
            "developer".to_string(),
            "tester".to_string(),
            "auditor".to_string(),
        ];
    } else if has_node {
        project_type = ProjectType::Node;
        language = "TypeScript/JavaScript".to_string();
        framework = None;
        suggested_pattern = "code-review-cycle".to_string();
        suggested_roles = vec![
            "developer".to_string(),
            "code_reviewer".to_string(),
            "auditor".to_string(),
        ];
    } else {
        project_type = ProjectType::Unknown;
        language = "unknown".to_string();
        framework = None;
        suggested_pattern = "code-review-cycle".to_string();
        suggested_roles = vec![
            "developer".to_string(),
            "code_reviewer".to_string(),
            "auditor".to_string(),
        ];
    }

    // Project name from manifest file
    let project_name = detect_project_name(&dir).unwrap_or_else(|| "unnamed".to_string());

    Ok(ProjectInfo {
        project_type,
        language,
        framework,
        project_name,
        working_dir: dir,
        suggested_pattern,
        suggested_roles,
        has_tests,
        has_payments,
    })
}

/// Suggest a mission ID from the project name and current date.
pub fn suggest_mission_id(project_name: &str, description: &str) -> String {
    let date = chrono::Utc::now().format("%Y-%m-%d");
    let slug: String = description
        .to_lowercase()
        .split_whitespace()
        .take(4)
        .collect::<Vec<_>>()
        .join("-")
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-')
        .take(32)
        .collect();
    if slug.is_empty() {
        format!("{}-{}", date, project_name)
    } else {
        format!("{}-{}-{}", date, project_name, slug)
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn has_react_dep(dir: &Path) -> bool {
    let pkg = dir.join("package.json");
    if let Ok(content) = std::fs::read_to_string(&pkg) {
        // Quick string check — full JSON parse overkill for detection
        content.contains("\"react\"") || content.contains("\"react-dom\"")
    } else {
        false
    }
}

fn is_rust_binary(dir: &Path) -> bool {
    let cargo = dir.join("Cargo.toml");
    if let Ok(content) = std::fs::read_to_string(&cargo) {
        // Check for [[bin]] section or absence of [lib]
        content.contains("[[bin]]") || (!content.contains("[lib]") && content.contains("name ="))
    } else {
        true // default to binary
    }
}

fn detect_project_name(dir: &Path) -> Option<String> {
    // Try package.json
    let pkg = dir.join("package.json");
    if let Ok(content) = std::fs::read_to_string(&pkg) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&content) {
            if let Some(name) = v.get("name").and_then(|n| n.as_str()) {
                return Some(name.to_string());
            }
        }
    }
    // Try Cargo.toml
    let cargo = dir.join("Cargo.toml");
    if let Ok(content) = std::fs::read_to_string(&cargo) {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("name = ") {
                let name = trimmed
                    .trim_start_matches("name = ")
                    .trim_matches('"')
                    .trim_matches('\'');
                return Some(name.to_string());
            }
        }
    }
    // Fallback: directory name
    dir.file_name().map(|n| n.to_string_lossy().to_string())
}

fn detect_payments(dir: &Path) -> bool {
    // Check package.json for payment-related deps
    let pkg = dir.join("package.json");
    if let Ok(content) = std::fs::read_to_string(&pkg) {
        let payment_keywords = ["mercadopago", "stripe", "paypal", "square", "checkout"];
        return payment_keywords
            .iter()
            .any(|kw| content.to_lowercase().contains(kw));
    }
    false
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_rust_project() {
        // This repo itself is Rust
        let info = detect_project(Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap())
            .expect("detect_project should succeed on Colmena repo");
        // Workspace root Cargo.toml has no [lib]/[[bin]]/name= → detected as RustLib
        assert!(
            info.project_type == ProjectType::RustBinary
                || info.project_type == ProjectType::RustLib,
            "Expected Rust project, got {:?}",
            info.project_type
        );
        assert_eq!(info.language, "Rust");
        assert!(info.suggested_roles.contains(&"developer".to_string()));
        assert!(info.suggested_roles.contains(&"auditor".to_string()));
    }

    #[test]
    fn test_suggest_mission_id() {
        let id = suggest_mission_id("pirq", "portfolio artista grafitero");
        assert!(id.contains("pirq"));
        assert!(id.contains("portfolio"));
    }
}

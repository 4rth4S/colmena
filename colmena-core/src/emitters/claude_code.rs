//! Claude Code-specific emitter helpers.
//!
//! Pure functions: no I/O. PR 2 uses the prompt-composition helpers only.
//! PR 3 will extend this module with `~/.claude/agents/<role>.md` writer
//! and minimums check.

/// Compose the `[SCOPE]` section of a generated prompt.
///
/// `owns` is the list of files this role can touch; `forbidden` is the explicit
/// "do NOT touch" list. Empty lists yield an empty string (no section emitted).
pub fn scope_block(owns: &[String], forbidden: &[String]) -> String {
    if owns.is_empty() && forbidden.is_empty() {
        return String::new();
    }
    let mut s = String::from("\n## Scope — ONLY these files\n\n");
    if owns.is_empty() {
        s.push_str("_(no file ownership declared — ask the operator before writing)_\n");
    } else {
        for o in owns {
            s.push_str(&format!("- {}\n", o));
        }
    }
    if !forbidden.is_empty() {
        s.push_str("\nDo NOT touch:\n");
        for f in forbidden {
            s.push_str(&format!("- {}\n", f));
        }
    }
    s
}

/// Compose the `[TASK]` section. Empty task → empty string.
pub fn task_block(task: &str) -> String {
    if task.trim().is_empty() {
        String::new()
    } else {
        format!("\n## Task\n\n{}\n", task.trim())
    }
}

/// Compose the `[REVIEW PROTOCOL]` section with review_submit parameters pre-filled.
///
/// `author_role` is this role's id. `mission_id` is the current mission.
/// `available_roles` is the reviewer pool to pass in the review_submit call.
pub fn review_protocol_block(
    mission_id: &str,
    author_role: &str,
    available_roles: &[String],
) -> String {
    let roles_arr = available_roles
        .iter()
        .map(|r| format!("\"{}\"", r))
        .collect::<Vec<_>>()
        .join(", ");

    format!(
        "\n## Review Protocol — MANDATORY\n\n\
         When you finish, call:\n\n\
         ```\n\
         mcp__colmena__review_submit(\n  \
             mission: \"{mission}\",\n  \
             author_role: \"{author}\",\n  \
             artifact_paths: [<files you touched>],\n  \
             available_roles: [{roles}]\n\
         )\n\
         ```\n\n\
         If `review_submit` fails: DO NOT Stop. Report the error to the operator and wait.\n\
         Your Stop is gated until `review_submit` succeeds (when `enforce_missions` is active).\n",
        mission = mission_id,
        author = author_role,
        roles = roles_arr,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scope_block_empty() {
        assert!(scope_block(&[], &[]).is_empty());
    }

    #[test]
    fn test_scope_block_owns_only() {
        let owns = vec!["Cargo.toml".to_string(), "docs/user/*.md".to_string()];
        let out = scope_block(&owns, &[]);
        assert!(out.contains("Cargo.toml"));
        assert!(out.contains("docs/user/*.md"));
        assert!(!out.contains("Do NOT touch"));
    }

    #[test]
    fn test_scope_block_owns_and_forbidden() {
        let owns = vec!["Cargo.toml".to_string()];
        let forbidden = vec!["colmena-core/src/**".to_string()];
        let out = scope_block(&owns, &forbidden);
        assert!(out.contains("Cargo.toml"));
        assert!(out.contains("Do NOT touch"));
        assert!(out.contains("colmena-core/src/**"));
    }

    #[test]
    fn test_task_block_empty() {
        assert!(task_block("").is_empty());
        assert!(task_block("   ").is_empty());
    }

    #[test]
    fn test_task_block_with_content() {
        let out = task_block("Implement mission_spawn auto-closure");
        assert!(out.contains("## Task"));
        assert!(out.contains("Implement mission_spawn auto-closure"));
    }

    #[test]
    fn test_review_protocol_contains_pre_filled_params() {
        let roles = vec!["auditor".to_string(), "code_reviewer".to_string()];
        let out = review_protocol_block("m-42", "developer", &roles);
        assert!(out.contains("mission: \"m-42\""));
        assert!(out.contains("author_role: \"developer\""));
        assert!(out.contains("[\"auditor\", \"code_reviewer\"]"));
        assert!(out.contains("DO NOT Stop"));
    }
}

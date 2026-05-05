//! Embedded default config + library files.
//! All content compiled into the binary via `include_str!()` (~46KB total).

pub struct DefaultFile {
    pub rel_path: &'static str,
    pub content: &'static str,
}

/// Return all default config + library files embedded in the binary.
pub fn all_defaults() -> Vec<DefaultFile> {
    vec![
        // ── Config files ─────────────────────────────────────────────────────
        DefaultFile {
            rel_path: "trust-firewall.yaml",
            content: include_str!("../embedded/config/trust-firewall.yaml"),
        },
        DefaultFile {
            rel_path: "filter-config.yaml",
            content: include_str!("../embedded/config/filter-config.yaml"),
        },
        DefaultFile {
            rel_path: "review-config.yaml",
            content: include_str!("../embedded/config/review-config.yaml"),
        },
        // ── Library: roles ───────────────────────────────────────────────────
        DefaultFile {
            rel_path: "library/roles/pentester.yaml",
            content: include_str!("../embedded/config/library/roles/pentester.yaml"),
        },
        DefaultFile {
            rel_path: "library/roles/auditor.yaml",
            content: include_str!("../embedded/config/library/roles/auditor.yaml"),
        },
        DefaultFile {
            rel_path: "library/roles/researcher.yaml",
            content: include_str!("../embedded/config/library/roles/researcher.yaml"),
        },
        DefaultFile {
            rel_path: "library/roles/security-architect.yaml",
            content: include_str!("../embedded/config/library/roles/security-architect.yaml"),
        },
        DefaultFile {
            rel_path: "library/roles/web-pentester.yaml",
            content: include_str!("../embedded/config/library/roles/web-pentester.yaml"),
        },
        DefaultFile {
            rel_path: "library/roles/api-pentester.yaml",
            content: include_str!("../embedded/config/library/roles/api-pentester.yaml"),
        },
        DefaultFile {
            rel_path: "library/roles/developer.yaml",
            content: include_str!("../embedded/config/library/roles/developer.yaml"),
        },
        DefaultFile {
            rel_path: "library/roles/code-reviewer.yaml",
            content: include_str!("../embedded/config/library/roles/code-reviewer.yaml"),
        },
        DefaultFile {
            rel_path: "library/roles/tester.yaml",
            content: include_str!("../embedded/config/library/roles/tester.yaml"),
        },
        DefaultFile {
            rel_path: "library/roles/architect.yaml",
            content: include_str!("../embedded/config/library/roles/architect.yaml"),
        },
        // ── Library: patterns ────────────────────────────────────────────────
        DefaultFile {
            rel_path: "library/patterns/oracle-workers.yaml",
            content: include_str!("../embedded/config/library/patterns/oracle-workers.yaml"),
        },
        DefaultFile {
            rel_path: "library/patterns/debate.yaml",
            content: include_str!("../embedded/config/library/patterns/debate.yaml"),
        },
        DefaultFile {
            rel_path: "library/patterns/mentored-execution.yaml",
            content: include_str!("../embedded/config/library/patterns/mentored-execution.yaml"),
        },
        DefaultFile {
            rel_path: "library/patterns/pipeline.yaml",
            content: include_str!("../embedded/config/library/patterns/pipeline.yaml"),
        },
        DefaultFile {
            rel_path: "library/patterns/plan-then-execute.yaml",
            content: include_str!("../embedded/config/library/patterns/plan-then-execute.yaml"),
        },
        DefaultFile {
            rel_path: "library/patterns/swarm-consensus.yaml",
            content: include_str!("../embedded/config/library/patterns/swarm-consensus.yaml"),
        },
        DefaultFile {
            rel_path: "library/patterns/caido-pentest.yaml",
            content: include_str!("../embedded/config/library/patterns/caido-pentest.yaml"),
        },
        DefaultFile {
            rel_path: "library/patterns/code-review-cycle.yaml",
            content: include_str!("../embedded/config/library/patterns/code-review-cycle.yaml"),
        },
        DefaultFile {
            rel_path: "library/patterns/docs-from-code.yaml",
            content: include_str!("../embedded/config/library/patterns/docs-from-code.yaml"),
        },
        DefaultFile {
            rel_path: "library/patterns/refactor-safe.yaml",
            content: include_str!("../embedded/config/library/patterns/refactor-safe.yaml"),
        },
        // ── Library: prompts ─────────────────────────────────────────────────
        DefaultFile {
            rel_path: "library/prompts/pentester.md",
            content: include_str!("../embedded/config/library/prompts/pentester.md"),
        },
        DefaultFile {
            rel_path: "library/prompts/auditor.md",
            content: include_str!("../embedded/config/library/prompts/auditor.md"),
        },
        DefaultFile {
            rel_path: "library/prompts/researcher.md",
            content: include_str!("../embedded/config/library/prompts/researcher.md"),
        },
        DefaultFile {
            rel_path: "library/prompts/security-architect.md",
            content: include_str!("../embedded/config/library/prompts/security-architect.md"),
        },
        DefaultFile {
            rel_path: "library/prompts/web-pentester.md",
            content: include_str!("../embedded/config/library/prompts/web-pentester.md"),
        },
        DefaultFile {
            rel_path: "library/prompts/api-pentester.md",
            content: include_str!("../embedded/config/library/prompts/api-pentester.md"),
        },
        DefaultFile {
            rel_path: "library/prompts/developer.md",
            content: include_str!("../embedded/config/library/prompts/developer.md"),
        },
        DefaultFile {
            rel_path: "library/prompts/code-reviewer.md",
            content: include_str!("../embedded/config/library/prompts/code-reviewer.md"),
        },
        DefaultFile {
            rel_path: "library/prompts/tester.md",
            content: include_str!("../embedded/config/library/prompts/tester.md"),
        },
        DefaultFile {
            rel_path: "library/prompts/architect.md",
            content: include_str!("../embedded/config/library/prompts/architect.md"),
        },
        DefaultFile {
            rel_path: "library/prompts/review-worker-instructions.md",
            content: include_str!(
                "../embedded/config/library/prompts/review-worker-instructions.md"
            ),
        },
        DefaultFile {
            rel_path: "library/prompts/review-lead-instructions.md",
            content: include_str!("../embedded/config/library/prompts/review-lead-instructions.md"),
        },
        DefaultFile {
            rel_path: "library/prompts/prompt-review-context.md",
            content: include_str!("../embedded/config/library/prompts/prompt-review-context.md"),
        },
    ]
}

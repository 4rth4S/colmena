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
            content: include_str!("../../config/trust-firewall.yaml"),
        },
        DefaultFile {
            rel_path: "filter-config.yaml",
            content: include_str!("../../config/filter-config.yaml"),
        },
        DefaultFile {
            rel_path: "review-config.yaml",
            content: include_str!("../../config/review-config.yaml"),
        },
        // ── Library: roles ───────────────────────────────────────────────────
        DefaultFile {
            rel_path: "library/roles/pentester.yaml",
            content: include_str!("../../config/library/roles/pentester.yaml"),
        },
        DefaultFile {
            rel_path: "library/roles/auditor.yaml",
            content: include_str!("../../config/library/roles/auditor.yaml"),
        },
        DefaultFile {
            rel_path: "library/roles/researcher.yaml",
            content: include_str!("../../config/library/roles/researcher.yaml"),
        },
        DefaultFile {
            rel_path: "library/roles/security-architect.yaml",
            content: include_str!("../../config/library/roles/security-architect.yaml"),
        },
        DefaultFile {
            rel_path: "library/roles/web-pentester.yaml",
            content: include_str!("../../config/library/roles/web-pentester.yaml"),
        },
        DefaultFile {
            rel_path: "library/roles/api-pentester.yaml",
            content: include_str!("../../config/library/roles/api-pentester.yaml"),
        },
        // ── Library: patterns ────────────────────────────────────────────────
        DefaultFile {
            rel_path: "library/patterns/oracle-workers.yaml",
            content: include_str!("../../config/library/patterns/oracle-workers.yaml"),
        },
        DefaultFile {
            rel_path: "library/patterns/debate.yaml",
            content: include_str!("../../config/library/patterns/debate.yaml"),
        },
        DefaultFile {
            rel_path: "library/patterns/mentored-execution.yaml",
            content: include_str!("../../config/library/patterns/mentored-execution.yaml"),
        },
        DefaultFile {
            rel_path: "library/patterns/pipeline.yaml",
            content: include_str!("../../config/library/patterns/pipeline.yaml"),
        },
        DefaultFile {
            rel_path: "library/patterns/plan-then-execute.yaml",
            content: include_str!("../../config/library/patterns/plan-then-execute.yaml"),
        },
        DefaultFile {
            rel_path: "library/patterns/swarm-consensus.yaml",
            content: include_str!("../../config/library/patterns/swarm-consensus.yaml"),
        },
        DefaultFile {
            rel_path: "library/patterns/caido-pentest.yaml",
            content: include_str!("../../config/library/patterns/caido-pentest.yaml"),
        },
        // ── Library: prompts ─────────────────────────────────────────────────
        DefaultFile {
            rel_path: "library/prompts/pentester.md",
            content: include_str!("../../config/library/prompts/pentester.md"),
        },
        DefaultFile {
            rel_path: "library/prompts/auditor.md",
            content: include_str!("../../config/library/prompts/auditor.md"),
        },
        DefaultFile {
            rel_path: "library/prompts/researcher.md",
            content: include_str!("../../config/library/prompts/researcher.md"),
        },
        DefaultFile {
            rel_path: "library/prompts/security-architect.md",
            content: include_str!("../../config/library/prompts/security-architect.md"),
        },
        DefaultFile {
            rel_path: "library/prompts/web-pentester.md",
            content: include_str!("../../config/library/prompts/web-pentester.md"),
        },
        DefaultFile {
            rel_path: "library/prompts/api-pentester.md",
            content: include_str!("../../config/library/prompts/api-pentester.md"),
        },
        DefaultFile {
            rel_path: "library/prompts/review-worker-instructions.md",
            content: include_str!("../../config/library/prompts/review-worker-instructions.md"),
        },
        DefaultFile {
            rel_path: "library/prompts/review-lead-instructions.md",
            content: include_str!("../../config/library/prompts/review-lead-instructions.md"),
        },
        DefaultFile {
            rel_path: "library/prompts/prompt-review-context.md",
            content: include_str!("../../config/library/prompts/prompt-review-context.md"),
        },
    ]
}

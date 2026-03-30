# Colmena M1 — Dark Corners Analysis

> Edge cases, security gaps, and hidden assumptions in the Wisdom Library + Pattern Selector.
> Generated: 2026-03-29

---

## Critical (must-fix before merge)

### 1. Path traversal via `system_prompt_ref`

**File:** `colmena-core/src/library.rs` — `load_prompt()`

`load_prompt(library_dir, prompt_ref)` does `library_dir.join(prompt_ref)` without sanitization. A role with `system_prompt_ref: "../../../etc/passwd"` reads arbitrary files.

**Fix:** Canonicalize the resolved path and verify it stays within `library_dir/prompts/`.

### 2. Mission slug path traversal

**File:** `colmena-core/src/selector.rs` — `generate_mission()`

Mission text is slugified with `.split_whitespace().take(4).join("-")` but not sanitized against `..` segments. Mission `"test .. .. /etc"` creates a directory that could escape the missions dir.

**Fix:** Filter slug to alphanumeric + dash only. Verify resolved path stays within missions_dir.

### 3. Role ID injection in scaffold

**File:** `colmena-core/src/selector.rs` — `scaffold_role()`

Role ID is injected directly into YAML format string without validation. A role ID with newlines or YAML special chars corrupts the output file.

**Fix:** Validate role ID: `[a-zA-Z0-9_-]` only, 1-64 chars. Reject everything else.

---

## High (fix before production use)

### 4. Silent failure on undefined roles in mission generation

`generate_mission()` falls back to "System prompt not found" when a pattern references a non-existent role. The agent gets a broken CLAUDE.md with no useful prompt.

**Fix:** Fail fast if any role in the pattern is not found in the library.

### 5. Scaffold overwrites existing roles without warning

`scaffold_role()` writes directly without checking if the role already exists. Running `create-role --id pentester` silently destroys the original pentester definition.

**Fix:** Check if file exists, require `--force` flag to overwrite.

### 6. Missing test coverage for security issues

No tests for: path traversal in `load_prompt`, injection in `scaffold_role`, mission slug traversal. These are the 3 critical issues above — all untested.

---

## Medium

### 7. Empty mission returns empty list instead of error

`select_patterns("")` returns `Vec::new()`. User sees "No matching patterns" with no explanation of why. Should return an error explaining the mission needs keywords.

### 8. CLAUDE.md markdown injection

Mission text is inserted raw into generated CLAUDE.md files. Backticks, code fences, or YAML frontmatter in the mission could break agent prompts.

**Fix:** Escape markdown special characters before insertion.

### 9. Role gap detection uses hardcoded domain keywords

`detect_role_gaps()` has a static list of ~25 domain keywords. Keywords like "llm", "ai", "saas", "serverless" are missing. Should derive gap detection from role specializations dynamically.

### 10. Pipeline pattern doesn't enforce sequencing

The pipeline pattern defines `stage_1`, `stage_2`, etc. but the generated CLAUDE.md doesn't explain ordering or dependencies. Agents don't know they should wait for the previous stage.

### 11. Debate pattern judge shouldn't use ELO lead selection

`elo_lead_selection: true` on the debate pattern means the judge is selected by category-specific ELO. A pentester with high web_vulnerabilities ELO would judge a web audit debate — biased. Judge should be neutral.

---

## Low

### 12. O(n^2) keyword overlap in scoring

`keyword_overlap()` uses linear search. Use HashSet for O(n) lookup.

### 13. Parse errors don't suggest valid options

MCP `library_generate` returns "Pattern not found" without listing available patterns.

### 14. Invalid input defaults silently to choice 1

CLI `library select` parses user input with `unwrap_or(1)` — no feedback when input is invalid.

### 15. Scoring imbalance with sparse `when_not_to_use`

Anti-match weight (-3.0) can be overwhelmed by many `when_to_use` matches (+2.0 each). May not always produce 2-3 recommendations.

---

## Recommended Fix Order

1. **Path traversal** (load_prompt, mission slug) — security critical
2. **Role ID validation** in scaffold — security
3. **Fail fast on undefined roles** — correctness
4. **Overwrite protection** — data safety
5. **Add security tests** — coverage
6. **Markdown escaping** in CLAUDE.md — correctness
7. **Error messages** — UX

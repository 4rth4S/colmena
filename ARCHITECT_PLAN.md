# ARCHITECT_PLAN: CLI `--json` Support + 3 New Subcommands

## 1. Overview of Changes

This plan adds structured JSON output to 5 existing read-only CLI commands and introduces 3 new CLI subcommands that reuse existing `colmena-core` functions already called by the MCP server. All changes are confined to `colmena-cli/src/main.rs` and `colmena-core` with minimal additions (new `Serialize` derives on a few types).

### Files Modified

| File | Change Type | Reason |
|------|-------------|--------|
| `colmena-cli/src/main.rs` | Heavy edits | Add `--json` global flag, add `Alerts` / `Review` subcommands, modify `run_*` functions |
| `colmena-core/src/elo.rs` | Light edit | Add `#[derive(Serialize)]` to `AgentRating` |
| `colmena-core/src/library.rs` | Light edit | Add `#[derive(Serialize)]` to `Role`, `Pattern`, `EloConfig`, `MentoringConfig`, `RolePermissions`, `RolesSuggested` |
| `colmena-core/src/findings.rs` | No change | `Finding` already has `Serialize` |
| `colmena-core/src/alerts.rs` | No change | `Alert` already has `Serialize` |
| `colmena-core/src/review.rs` | No change | `ReviewEntry` already has `Serialize` |

### Files Created

None. All changes are in-place in existing files.

---

## 2. Detailed Design for the `--json` Flag

### 2.1 Where in the clap struct

Add `#[arg(global = true, long, short)]` to the top-level `Cli` struct. This makes it accessible as `colmena --json elo show` and `colmena elo show --json`.

```rust
#[derive(Parser)]
#[command(name = "colmena", version, about)]
struct Cli {
    /// Output structured JSON instead of human-readable tables
    #[arg(global = true, long, short, action = clap::ArgAction::SetTrue)]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}
```

### 2.2 How it flows through dispatch

1. `main()` parses `Cli` and holds `cli.json`.
2. Each `run_*` function that supports JSON output receives a `json: bool` parameter (or the `cli.json` flag is passed via the match arm).
3. In `main()`, the match arms for the 5 affected commands pass `cli.json` to their `run_*` function:

```rust
Commands::Elo { action } => match action {
    EloAction::Show => run_elo_show(cli.json),
},
// etc.
```

4. Inside each `run_*` function, the existing table-printing code runs when `json == false`. When `json == true`, the function collects the data, serializes it via `serde_json::to_string_pretty` or `to_writer`, and prints to stdout.

### 2.3 Error handling in JSON mode

When `--json` is passed AND an error occurs:

- **Do not exit via `process::exit(1)`** inside `run_*` functions — those are hard exits that bypass the error handler.
- Instead, if `json == true` and a recoverable error is detected (e.g., "not found"), print `{"error": "message"}` to stdout and return `Ok(())`.
- For hard errors that bail out via `?` / `bail!`, the existing `main()` error handling stays, but the JSON-mode error should also go to stdout as `{"error": "..."}`.

**Approach**: Add a helper function at the bottom of `main.rs`:

```rust
fn json_error(msg: &str) {
    serde_json::to_writer(std::io::stdout(), &serde_json::json!({"error": msg})).ok();
}
```

And change the `main()` error path to use it when `cli.json` is set. Replace the current `eprintln`+`exit` calls with:

```rust
fn exit_with_error(msg: &str, json: bool) -> ! {
    if json {
        let _ = serde_json::to_writer(std::io::stdout(), &serde_json::json!({"error": msg}));
    } else {
        eprintln!("{msg}");
    }
    std::process::exit(1);
}
```

Then replace all `eprintln!("..."); std::process::exit(1);` in the 5 affected `run_*` functions with `exit_with_error("...", json);`.

---

## 3. Per-Command Changes: JSON Output Shape

### 3.1 `colmena elo show --json`

**Type needing Serialize**: `colmena_core::elo::AgentRating`

Currently `#[derive(Debug, Clone)]` only. Change to `#[derive(Debug, Clone, Serialize)]`. This is a trivially safe change — `AgentRating` contains `String`, `i32`, `u32`, and `Option<DateTime<Utc>>`, all of which already implement `Serialize`.

**JSON output** (array):
```json
[
  {
    "agent": "pentester",
    "elo": 1050,
    "trend_7d": 12,
    "review_count": 5,
    "last_active": "2026-05-15T10:30:00Z"
  }
]
```

**Implementation**: After `leaderboard()` returns, if `json`:

```rust
if json {
    serde_json::to_writer(std::io::stdout(), &ratings)?;
    println!();  // trailing newline
    return Ok(());
}
// ... existing table output ...
```

### 3.2 `colmena review list --json`

**Type**: `ReviewEntry` already has `#[derive(Serialize)]` in `colmena-core/src/review.rs`. No core change needed.

**JSON output** (array):
```json
[
  {
    "review_id": "r_1712345678_abcd",
    "mission": "audit-pci",
    "author_role": "pentester",
    "reviewer_role": "auditor",
    "artifact_path": "/path/to/file",
    "artifact_hash": "sha256:abc...",
    "state": "pending",
    "created_at": "2026-05-15T10:00:00Z",
    "evaluated_at": null,
    "scores": null,
    "score_average": null,
    "finding_count": null,
    "evaluation_narrative": null
  }
]
```

The dashboard only needs a subset, but outputting the full `ReviewEntry` is clean and forward-compatible. If minimization is desired, a thin view struct can be added in `main.rs`.

### 3.3 `colmena review show <id> --json`

Same `ReviewEntry` type. Output a single object (not an array).

**Implementation**: The function currently loads all reviews and iterates to find the one with the matching ID. If `json`, serialize that single entry directly.

### 3.4 `colmena mission status <id> --json`

**No MissionStatus struct exists**. The `run_mission_status()` function assembles data from multiple sources:
- `RuntimeAgentOverrides` for spawn metadata
- Delegation count
- Subagent file count
- Unread alert count

**Strategy**: Define a local struct in `main.rs` (or a thin module) to hold the status data:

```rust
#[derive(Serialize)]
struct MissionStatusJson {
    mission_id: String,
    spawned_at: Option<String>,
    manifest_sha256: Option<String>,
    mission_ttl_hours: Option<i64>,
    elapsed_hours: Option<i64>,
    remaining_hours: Option<i64>,
    subagent_files: usize,
    active_delegations: usize,
    budget_overrides: usize,
    unread_alerts: usize,
}
```

**JSON output**:
```json
{
  "mission_id": "audit-pci",
  "spawned_at": "2026-05-15T10:00:00+00:00",
  "manifest_sha256": "a1b2c3d4...",
  "mission_ttl_hours": 8,
  "elapsed_hours": 3,
  "remaining_hours": 5,
  "subagent_files": 3,
  "active_delegations": 5,
  "budget_overrides": 3,
  "unread_alerts": 1
}
```

### 3.5 `colmena library list --json`

**Types needing Serialize**: `library::Role`, `library::Pattern`, and their sub-structs (`EloConfig`, `MentoringConfig`, `RolePermissions`, `RolesSuggested`). Currently these derive `Deserialize` only. Add `Serialize`.

Note: `Pattern` already serializes all its fields, and the `RolesSuggested` wrapper has a manual serde implementation. Adding `Serialize` derives should be straightforward.

**JSON output**:
```json
{
  "roles": [
    {
      "id": "pentester",
      "name": "Pentester",
      "icon": "\u{1f575}",
      "description": "...",
      "system_prompt_ref": "roles/pentester/prompt.md",
      "default_trust_level": "restricted",
      "tools_allowed": ["Bash", "Read", ...],
      "specializations": ["web", "network"],
      "permissions": null,
      "role_type": null,
      "model": null,
      "elo": { "initial": 1000, "categories": {} },
      "mentoring": { "can_mentor": [], "mentored_by": [] }
    }
  ],
  "patterns": [
    {
      "id": "parallel-audit",
      "name": "Parallel Audit",
      "source": null,
      "description": "...",
      "topology": "hierarchical",
      "communication": "...",
      "when_to_use": [...],
      "when_not_to_use": [],
      "pros": [...],
      "cons": [...],
      "estimated_token_cost": "~50K",
      "estimated_agents": "3-5",
      "roles_suggested": { "worker": ["pentester"], "auditor": ["auditor"] }
    }
  ]
}
```

---

## 4. Three New CLI Subcommands

### 4.1 `colmena alerts ack <alert_id|all>`

**Purpose**: Acknowledge one or all alerts.

**CLI wiring**: Add a new variant to the `Commands` enum:

```rust
/// Manage review alerts
Alerts {
    #[command(subcommand)]
    action: AlertsAction,
},

#[derive(Subcommand)]
enum AlertsAction {
    /// Acknowledge an alert by ID, or "all" for all
    Ack {
        /// Alert ID, or "all" to acknowledge everything
        alert_id: String,
    },
}
```

**Dispatch** (in `main()`):
```rust
Commands::Alerts { action } => match action {
    AlertsAction::Ack { alert_id } => run_alerts_ack(cli.json, &alert_id),
},
```

**Implementation** (`run_alerts_ack`):
```rust
fn run_alerts_ack(json: bool, alert_id: &str) -> Result<()> {
    let config_dir = default_config_dir();
    let alerts_path = config_dir.join("alerts.json");

    if alert_id == "all" {
        colmena_core::alerts::acknowledge_all(&alerts_path)?;
        if json {
            println!("{}", serde_json::json!({"acknowledged": "all", "status": "ok"}));
        } else {
            println!("All alerts acknowledged.");
        }
    } else {
        colmena_core::alerts::acknowledge_alert(&alerts_path, alert_id)?;
        if json {
            println!("{}", serde_json::json!({"acknowledged": alert_id, "status": "ok"}));
        } else {
            println!("Alert '{alert_id}' acknowledged.");
        }
    }
    Ok(())
}
```

Both core functions (`acknowledge_alert`, `acknowledge_all`) take `&Path` and return `Result<()>`. They already exist in `colmena-core/src/alerts.rs`.

### 4.2 `colmena review submit --artifact <path> --author <role> --mission <id> --available-roles <roles>`

**Purpose**: Submit an artifact for cross-review, reusing `colmena_core::review::submit_review()`.

**CLI wiring**: Add a new variant to the existing `ReviewAction` enum:

```rust
#[derive(Subcommand)]
enum ReviewAction {
    // ... existing List, Show ...
    /// Submit an artifact for auditor review
    Submit {
        /// Path to the artifact file
        #[arg(long)]
        artifact: String,
        /// Author's role ID (e.g., "pentester")
        #[arg(long)]
        author: String,
        /// Mission ID
        #[arg(long)]
        mission: String,
        /// Available reviewer roles (comma-separated)
        #[arg(long)]
        available_roles: String,
    },
}
```

**Dispatch**:
```rust
ReviewAction::Submit { artifact, author, mission, available_roles } => {
    run_review_submit(cli.json, &artifact, &author, &mission, &available_roles)
}
```

**Implementation**:
```rust
fn run_review_submit(json: bool, artifact: &str, author: &str, mission: &str, available_roles: &str) -> Result<()> {
    let review_dir = default_config_dir().join("reviews");
    let artifact_path = std::path::PathBuf::from(artifact);
    let roles: Vec<String> = available_roles.split(',').map(|s| s.trim().to_string()).collect();

    // MCP handler also validates artifact_path is within project dir —
    // the CLI should too, but for now the core function handles security checks.
    let entry = colmena_core::review::submit_review(&review_dir, &artifact_path, author, mission, &roles)?;

    if json {
        serde_json::to_writer(std::io::stdout(), &entry)?;
        println!();
    } else {
        println!("Review created:");
        println!("  review_id:  {}", entry.review_id);
        println!("  author:     {}", entry.author_role);
        println!("  reviewer:   {}", entry.reviewer_role);
        println!("  hash:       {}", entry.artifact_hash);
        println!("  state:      {}", format_review_state(&entry.state));
    }
    Ok(())
}
```

### 4.3 `colmena review evaluate <review_id> --reviewer <role> --scores <json> --findings <json> --artifact <path>`

**Purpose**: Evaluate a review with scores and findings.

**CLI wiring**: Add to `ReviewAction`:

```rust
/// Evaluate a pending review (submit scores and findings)
Evaluate {
    /// Review ID to evaluate
    review_id: String,
    /// Reviewer's role ID
    #[arg(long)]
    reviewer: String,
    /// Scores as JSON string, e.g. '{"accuracy":8,"completeness":7}'
    #[arg(long)]
    scores: String,
    /// Findings as JSON string, e.g. '[{"category":"completeness","severity":"medium","description":"...","recommendation":"..."}]'
    #[arg(long)]
    findings: String,
    /// Path to artifact file (for hash verification)
    #[arg(long)]
    artifact: String,
    /// Optional evaluation narrative
    #[arg(long)]
    narrative: Option<String>,
}
```

**Dispatch**:
```rust
ReviewAction::Evaluate { review_id, reviewer, scores, findings, artifact, narrative } => {
    run_review_evaluate(cli.json, &review_id, &reviewer, &scores, &findings, &artifact, narrative.as_deref())
}
```

**Implementation**:
```rust
fn run_review_evaluate(
    json: bool,
    review_id: &str,
    reviewer_role: &str,
    scores_json: &str,
    findings_json: &str,
    artifact_path: &str,
    narrative: Option<&str>,
) -> Result<()> {
    let review_dir = default_config_dir().join("reviews");

    // Parse JSON inputs
    let scores: HashMap<String, u32> = serde_json::from_str(scores_json)
        .context("--scores must be a JSON object like {\"accuracy\":8,\"completeness\":7}")?;
    let finding_inputs: Vec<colmena_core::findings::Finding> = serde_json::from_str(findings_json)
        .context("--findings must be a JSON array of finding objects")?;

    // Validate finding fields
    for f in &finding_inputs {
        colmena_core::findings::validate_severity(&f.severity)
            .context(format!("invalid severity '{}'", f.severity))?;
        colmena_core::findings::validate_category(&f.category)
            .context(format!("invalid category '{}'", f.category))?;
    }

    let artifact = std::path::PathBuf::from(artifact_path);
    let entry = colmena_core::review::evaluate_review(
        &review_dir,
        review_id,
        reviewer_role,
        scores,
        finding_inputs,
        &artifact,
        narrative.map(|s| s.to_string()),
    )?;

    if json {
        serde_json::to_writer(std::io::stdout(), &entry)?;
        println!();
    } else {
        let avg = entry.score_average.unwrap_or(0.0);
        let count = entry.finding_count.unwrap_or(0);
        println!("Review evaluated:");
        println!("  review_id:  {}", entry.review_id);
        println!("  state:      {}", format_review_state(&entry.state));
        println!("  score_avg:  {avg:.1}");
        println!("  findings:   {count}");
        println!("  reviewer:   {}", entry.reviewer_role);
        // Run trust gate to show outcome
        // (already handled in core — state reflects trust gate)
    }
    Ok(())
}
```

---

## 5. File-by-File Change List

### 5.1 `colmena-cli/src/main.rs`

| Location | Change |
|----------|--------|
| `struct Cli` (~line 30) | Add `#[arg(global = true, long, short)] json: bool` field |
| `enum Commands` (~after line 86) | Add `Alerts { action: AlertsAction }` variant |
| New `enum AlertsAction` | Add with `Ack { alert_id: String }` variant |
| `enum ReviewAction` (line 240) | Add `Submit { ... }` and `Evaluate { ... }` variants |
| `main()` dispatch (line ~420) | Pass `cli.json` to `run_elo_show`, `run_review_list`, `run_review_show`, `run_mission_status`, `run_library_list` |
| `main()` dispatch (line ~420) | Add match arms for `AlertsAction::Ack`, `ReviewAction::Submit`, `ReviewAction::Evaluate` |
| `run_review_list` (line 2006) | Add `json: bool` param; add JSON serialization path |
| `run_review_show` (line 2065) | Add `json: bool` param; add JSON serialization path |
| `run_elo_show` (line 2120) | Add `json: bool` param; add JSON serialization path |
| `run_library_list` (line 1495) | Add `json: bool` param; add JSON serialization path |
| `run_mission_status` (line 3165) | Add `json: bool` param; construct `MissionStatusJson`; serialize |
| New `run_alerts_ack` | Implement |
| New `run_review_submit` | Implement |
| New `run_review_evaluate` | Implement |
| New helper `exit_with_error` | Replace `eprintln!()+exit(1)` calls in affected functions |
| New `#[derive(Serialize)] struct MissionStatusJson` | Local struct for mission status JSON output |

### 5.2 `colmena-core/src/elo.rs`

| Line | Change |
|------|--------|
| `struct AgentRating` (~line 43) | Add `Serialize` to derive list: `#[derive(Debug, Clone, Serialize)]` |

### 5.3 `colmena-core/src/library.rs`

| Line | Change |
|------|--------|
| `struct RolePermissions` (~line 11) | Add `Serialize` to derive list |
| `struct Role` (~line 24) | Add `Serialize` to derive list |
| `struct EloConfig` (~line 48) | Add `Serialize` to derive list |
| `struct MentoringConfig` (~line 55) | Add `Serialize` to derive list |
| `struct Pattern` (~line 65) | Add `Serialize` to derive list |

---

## 6. Implementation Order

This order minimizes rework and allows incremental testing:

### Phase A: Core serialization (no behavior change)

1. **`colmena-core/src/elo.rs`**: Add `Serialize` to `AgentRating`
2. **`colmena-core/src/library.rs`**: Add `Serialize` to `Role`, `Pattern`, `EloConfig`, `MentoringConfig`, `RolePermissions`
3. **Run**: `cargo build --release` (verify core compiles)

### Phase B: `--json` flag plumbing

4. **`colmena-cli/src/main.rs`**: Add `json: bool` to `Cli` struct
5. **`colmena-cli/src/main.rs`**: Add `exit_with_error` helper
6. **`colmena-cli/src/main.rs`**: Pass `cli.json` through dispatch match arms for the 5 affected commands
7. **Run**: `cargo build --release` (verify CLI compiles with no new warnings)

### Phase C: JSON output in existing commands (one at a time, easiest first)

8. **`colmena elo show --json`**: `run_elo_show` — simplest, flat struct
9. **`colmena review list --json`**: `run_review_list` — ReviewEntry already has Serialize
10. **`colmena review show --json`**: `run_review_show`
11. **`colmena library list --json`**: `run_library_list` — wrap roles+patterns in new struct
12. **`colmena mission status --json`**: `run_mission_status` — need to define MissionStatusJson struct

**Test after each**: `cargo build --release && cargo test`

### Phase D: New subcommands

13. **`colmena alerts ack`**: simplest new command, direct core function calls
14. **`colmena review submit`**: medium complexity, parse --available-roles from comma-separated string
15. **`colmena review evaluate`**: most complex, parse JSON from --scores and --findings

**Test after each**: `cargo build --release && cargo test`

### Phase E: Final gate

16. `cargo build --release && cargo test && cargo clippy -- -D warnings && cargo fmt --check`

---

## 7. Testing Strategy

### 7.1 Unit tests (in `colmena-core`)

Existing tests in `elo.rs` and `review.rs` should continue to pass unchanged. No new core tests needed since we only added derives.

### 7.2 CLI integration tests (in `colmena-cli/tests/integration.rs`)

The existing integration test uses `Command::new(env!("CARGO_BIN_EXE_colmena"))` against a config fixture. We should add tests for:

- **`--json` output is valid JSON**: Run `colmena --json elo show` (or with a temp config dir), capture stdout, assert `serde_json::from_slice()` succeeds
- **Non-JSON output unchanged**: Run same command without `--json`, assert output matches expected format string
- **Error in JSON mode returns `{"error":...}`**: Run e.g. `colmena --json review show nonexistent-id`, assert stdout starts with `{"error":`
- **New subcommands**: Run `colmena alerts ack all` with a temp `alerts.json` fixture; run `colmena review submit` with a temp artifact; run `colmena review evaluate` with JSON score/finding args

### 7.3 Manual smoke tests

```bash
# JSON mode
cargo run -- --json elo show
cargo run -- --json library list
cargo run -- --json mission status some-mission

# New commands
cargo run -- alerts ack all
cargo run -- review submit --artifact /tmp/test.txt --author pentester --mission test --available-roles auditor
cargo run -- review evaluate r_xxx --reviewer auditor --scores '{"accuracy":8}' --findings '[]' --artifact /tmp/test.txt
```

### 7.4 What to verify

1. All old text output is byte-identical when `--json` is NOT passed
2. `--json` output is parseable JSON with expected field names
3. Error JSON uses `{"error": "..."}` format, not stderr
4. `cargo clippy -- -D warnings` produces zero warnings
5. `cargo fmt --check` passes

# M5: `colmena setup` — Plug-and-Play Onboarding

## Context

Today a new Colmena user needs 4 manual steps: build, register hooks, manually create `~/.mcp.json`, and trust that config/ exists where the binary expects. M5 unifies this into `colmena setup` — a single command that detects context, copies/merges config, registers hooks + MCP, and verifies everything works.

**Design decisions (approved):**
- Target: developer (repo clone) + release binary user (standalone)
- Config home: `~/.colmena/` default, `COLMENA_HOME` override
- MCP: global in `~/.mcp.json`
- `setup` orchestrates, `install` stays standalone
- Merge inteligente: new files copied, custom files preserved
- `--dry-run` and `--force` flags
- Defaults embedded in binary via `include_str!()` (~46KB)

---

## Files

### New
| File | Purpose | Est. LOC |
|------|---------|----------|
| `colmena-cli/src/defaults.rs` | Embedded default config + library files | ~180 |
| `colmena-cli/src/setup.rs` | Setup command implementation + unit tests | ~450 |

### Modified
| File | Change | Est. LOC |
|------|--------|----------|
| `colmena-cli/src/main.rs` | Add `mod defaults; mod setup;`, `Commands::Setup` variant, dispatch | ~15 |
| `colmena-cli/src/install.rs` | Make `colmena_binary_path()` and `settings_json_path()` `pub(crate)` | ~4 |

**Total: ~650 LOC** (no new crates needed)

---

## Implementation

### Step 1: `defaults.rs` — Embedded defaults module

All 22 config + library files embedded with `include_str!()`:
- 3 config files: `trust-firewall.yaml`, `filter-config.yaml`, `review-config.yaml`
- 6 roles: `pentester.yaml`, `auditor.yaml`, `researcher.yaml`, `security-architect.yaml`, `web-pentester.yaml`, `api-pentester.yaml`
- 7 patterns: `oracle-workers.yaml`, `debate.yaml`, `mentored-execution.yaml`, `pipeline.yaml`, `plan-then-execute.yaml`, `swarm-consensus.yaml`, `caido-pentest.yaml`
- 9 prompts: 6 role prompts + `review-worker-instructions.md`, `review-lead-instructions.md`, `prompt-review-context.md`

Key struct:
```rust
pub struct DefaultFile {
    pub rel_path: &'static str,  // e.g. "library/roles/pentester.yaml"
    pub content: &'static str,
}

pub fn all_defaults() -> Vec<DefaultFile>
```

Paths relative to source file: `../../config/trust-firewall.yaml` etc.

### Step 2: `install.rs` — Visibility changes

Make two private functions `pub(crate)`:
- `colmena_binary_path()` (line 180) — setup needs this for MCP registration
- `settings_json_path()` (line 172) — setup needs this for verification

### Step 3: `setup.rs` — Core implementation

**Entry point:**
```rust
pub fn run_setup(dry_run: bool, force: bool) -> Result<()>
```

**3a. Mode detection (~30 LOC)**
```rust
enum SetupMode {
    Repo { project_root: PathBuf },
    Standalone,
}
fn detect_mode() -> SetupMode
```
Walk up from `current_exe()` looking for `Cargo.toml` with `[workspace]` containing `colmena-core`. Found → `Repo`. Not found → `Standalone`.

**3b. Resolve target directory (~20 LOC)**
```rust
fn resolve_config_dir(mode: &SetupMode) -> PathBuf
```
Priority: `$COLMENA_HOME` → repo mode uses `project_root/config/` → standalone uses `~/.colmena/`.

**3c. File merge logic (~120 LOC)**
```rust
enum CopyResult { Created, UpToDate, PreservedCustom, Overwritten }

fn ensure_file(
    target_path: &Path,
    default_content: &str,
    defaults_backup_dir: &Path,
    rel_path: &str,
    dry_run: bool,
    force: bool,
) -> Result<CopyResult>
```
- Not exists → create (atomic write: temp + rename)
- Exists + matches → skip (`UpToDate`)
- Exists + differs → preserve, save default to `.defaults/` dir (`PreservedCustom`)
- `--force` → overwrite (`Overwritten`)
- `--dry-run` → print only

Runtime state files NEVER touched:
```rust
const RUNTIME_FILES: &[&str] = &[
    "audit.log", "runtime-delegations.json", "elo-overrides.json",
    "filter-stats.jsonl", "elo-events.jsonl", "queue", "missions",
];
```

Create directories: `library/roles/`, `library/patterns/`, `library/prompts/`, `queue/pending/`, `queue/decided/`.

**3d. Register hooks (~15 LOC)**
- `--dry-run` → print message
- Otherwise → call `crate::install::run_install()`
- Already idempotent

**3e. Register MCP server (~80 LOC)**
```rust
fn register_mcp(config_dir: &Path, dry_run: bool, force: bool) -> Result<()>
```
- Find `colmena-mcp` binary: same directory as `colmena` binary
- Read `~/.mcp.json` (create `{"mcpServers":{}}` if missing)
- Merge `colmena` entry with absolute path to MCP binary
- If already registered with same path → skip
- Atomic write
- MCP binary not found → warn, don't fail

**3f. Verify (~80 LOC)**
```rust
struct VerifyResult { check: &'static str, status: VerifyStatus }
enum VerifyStatus { Ok, Warning(String), Error(String) }
fn verify_setup(config_dir: &Path) -> Vec<VerifyResult>
```
Checks:
1. `config::load_config()` on `trust-firewall.yaml`
2. `library::load_roles()` + `load_patterns()` + `validate_library()`
3. Hook dry-run (subprocess with test payload, same as install.rs)
4. MCP binary exists and is executable

**3g. Print summary (~50 LOC)**
```
Colmena Setup Complete
======================
Mode:       repo (/home/user/colmena)
Config dir: /home/user/colmena/config

Files:
  [created]     trust-firewall.yaml
  [up-to-date]  filter-config.yaml
  [preserved]   library/roles/pentester.yaml (custom → .defaults/)

Hooks:   ✓ Pre/PostToolUse in ~/.claude/settings.json
MCP:     ✓ colmena-mcp in ~/.mcp.json

Verification:
  [OK] Config valid (10 trust_circle, 5 restricted, 2 blocked)
  [OK] Library valid (6 roles, 7 patterns)
  [OK] Hook dry-run passed
  [OK] MCP binary found

Ready! Restart Claude Code to pick up MCP server.
```

`--dry-run` prefixes with `[DRY RUN]`.

### Step 4: `main.rs` — Wiring

```rust
mod defaults;
mod setup;

// In Commands enum:
/// One-command setup: config, hooks, MCP — everything to get started
Setup {
    #[arg(long)]
    dry_run: bool,
    #[arg(long)]
    force: bool,
},

// In dispatch:
Commands::Setup { dry_run, force } => setup::run_setup(dry_run, force),
```

---

## Testing

### Unit tests in `setup.rs` (~150 LOC)
Using `tempfile` (already a workspace dev-dependency):
- `test_ensure_file_creates_new` — file doesn't exist → Created
- `test_ensure_file_up_to_date` — file matches → UpToDate
- `test_ensure_file_preserves_custom` — file differs → PreservedCustom + .defaults/ backup
- `test_ensure_file_force_overwrites` — force=true → Overwritten
- `test_ensure_file_dry_run_no_write` — dry_run=true → no files touched
- `test_runtime_files_never_touched` — verify RUNTIME_FILES don't overlap with defaults
- `test_register_mcp_new_file` — creates correct JSON structure
- `test_register_mcp_merge_existing` — preserves other servers
- `test_register_mcp_already_registered` — no-op

### Integration tests
Following existing pattern (subprocess + stdin pipe):
- `test_setup_dry_run` — exit 0, stdout contains "[DRY RUN]", no files created
- `test_setup_standalone_creates_config` — all files created, summary printed
- `test_setup_idempotent` — second run reports all UpToDate
- `test_setup_force_overwrites` — custom file replaced

---

## Implementation Order

1. `defaults.rs` → verify with `cargo build`
2. `install.rs` visibility → 2-line change
3. `setup.rs` steps 3a-3g → incremental, test each step
4. `main.rs` wiring → connect everything
5. Unit tests → in setup.rs
6. Integration tests → in tests/
7. Full E2E: `cargo build --release && ./target/release/colmena setup --dry-run`

---

## Verification

```bash
# Build
cargo build --workspace --release
cargo clippy --workspace -- -W warnings

# Unit + integration tests
cargo test --workspace

# E2E dry-run (safe, no side effects)
./target/release/colmena setup --dry-run

# E2E standalone mode (use temp dir)
COLMENA_HOME=/tmp/colmena-test ./target/release/colmena setup
ls -la /tmp/colmena-test/
./target/release/colmena config check
./target/release/colmena library list
cat ~/.mcp.json | jq '.mcpServers.colmena'

# E2E idempotent
COLMENA_HOME=/tmp/colmena-test ./target/release/colmena setup
# Should report all "up-to-date"

# Cleanup
rm -rf /tmp/colmena-test
```

---

## Squad Assignment (for parallel execution)

All changes are in `colmena-cli/` — single squad, no file conflicts. Estimated effort: ~650 LOC.

**Not modified:** colmena-core, colmena-mcp, colmena-filter, config/, trust-firewall.yaml, any docs (docs updated in separate PR after implementation).

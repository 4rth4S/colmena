# M6: Intelligent Role Creation — Draft Spec

**Status:** Draft for next session. Brainstorming decisions still needed.

## Context

Today `library_create_role` (MCP + CLI) generates empty scaffold files with TODO placeholders. The user must manually write the system prompt (~200-400 lines), define specializations, configure ELO categories, and set permissions. This is the #1 friction point for new users and for adding roles on-the-fly.

**Goal:** Upgrade `library_create_role` to generate a **complete, ready-to-use role** from just an ID and description. CC can call the MCP tool and get a fully-formed role with intelligent system prompt, inferred specializations, and sensible defaults — then refine if needed.

**User story:**
> "CC, generame un web developer role en colmena para misiones de desarrollo de sitios web dinámicos frontend"
> → CC calls `mcp__colmena__library_create_role(id: "web_developer", description: "frontend developer for dynamic web apps with React/Tailwind")`
> → Colmena generates complete YAML + complete system prompt
> → CC can review/refine, or it's ready to use immediately

## Current State

### What exists (`colmena-core/src/selector.rs:812-888`)
- `scaffold_role(id, description, library_dir)` — validates ID, creates 2 files:
  - `roles/{id}.yaml` — template with empty specializations, default tools, commented permissions
  - `prompts/{id}.md` — title + description + "TODO: Define output format"
- MCP tool: `library_create_role(id, description)` — calls scaffold, returns file paths
- CLI: `colmena library create-role --id X --description "Y"` — same

### What's missing
- No intelligent content generation — just static templates
- No reference to existing roles for style/structure consistency
- No specializations inference from description
- No system prompt generation (methodology, safety rails, output format)
- Prompt is 5 lines of placeholder; a real prompt is 150-400 lines

## Design Direction

### Approach: Template-based generation with CC as the intelligence layer

Colmena **cannot call an LLM** (no external services, filesystem-only). So the generation strategy is:

1. **Colmena provides structured scaffolding** — much richer than today, with:
   - Inferred specializations from keyword matching against known domains
   - Pre-populated tools_allowed based on role type (offensive, defensive, development, research)
   - Pre-populated permissions block based on role type
   - System prompt with full section structure (Core Responsibilities, Methodology, Safety Rails, Output Format, Escalation) filled with domain-appropriate content from a template library

2. **CC refines the output** — CC reads the generated files and can edit them with context about the specific mission. The generated content is good-enough-to-use but designed to be refined.

### Key insight
The existing 6 role prompts (pentester, auditor, researcher, security_architect, web_pentester, api_pentester) follow a consistent structure. We can extract this structure into a **prompt skeleton** with domain-specific sections that map to role categories:

| Category | Methodology | Safety Rails | Tools Pattern |
|----------|-------------|--------------|---------------|
| offensive | Enumerate→Fingerprint→Test→Validate→Document | Rate limit, no destructive, scope enforcement | Bash(curl,python,nmap), Read, Write, WebFetch |
| defensive | Review→Analyze→Classify→Report | No auto-fix, human approval for changes | Read, Glob, Grep, Write |
| development | Plan→Implement→Test→Review→Document | No production deploys, test-first | Bash(cargo,npm,python), Read, Write, Edit |
| research | Discover→Investigate→Correlate→Report | Cite sources, no speculation | Read, Glob, Grep, WebFetch, WebSearch |

### What to build

#### 1. Role category detection
Map description keywords to categories:
- "pentest", "exploit", "attack", "offensive", "vulnerability", "bug bounty" → offensive
- "audit", "compliance", "review", "architecture", "threat model" → defensive
- "develop", "build", "implement", "frontend", "backend", "fullstack" → development
- "research", "investigate", "OSINT", "recon", "discover" → research
- Default: research (safest)

#### 2. Enhanced scaffold templates
Per-category templates with real content instead of TODOs:
- Complete methodology sections (5-step process adapted to category)
- Safety rails appropriate to the category
- Output format sections with examples
- Escalation rules
- Tool recommendations with permissions block

#### 3. Specialization inference
Extract specializations from description keywords:
- "React, Tailwind, frontend" → `[react, tailwind_css, responsive_design, component_architecture, accessibility]`
- "API security, BOLA" → `[api_security, bola, broken_authentication, injection]`
- Map common tech/domain terms to specialization slugs

#### 4. Updated MCP + CLI interface
- Same parameters: `id` + `description` (backward compatible)
- New optional parameter: `category` (override auto-detection)
- Output: full content of generated files (not just paths) so CC can review inline
- MCP returns the generated prompt content in the response for immediate review

## Files to modify
- `colmena-core/src/selector.rs` — upgrade `scaffold_role()` with category detection + rich templates
- `colmena-mcp/src/main.rs` — return generated content in MCP response (not just paths)
- `colmena-cli/src/main.rs` — minor: add `--category` optional arg
- New: `colmena-core/src/templates.rs` — category-based prompt templates + specialization inference

## Open questions for next session
1. Should the generated prompt include tool-specific examples (like HTTPQL for Caido roles)? Or keep it generic and let CC refine?
2. Should we support `--pattern` flag to also create/update a pattern that includes the new role?
3. How detailed should the generated methodology be? Full 5-phase like existing roles, or lighter 3-phase?
4. Should the MCP tool return content for CC to review before writing, or write directly and let CC edit after? (Current: writes directly)

## Estimated scope
- `templates.rs`: ~300 LOC (4 category templates + keyword maps + specialization inference)
- `selector.rs` changes: ~50 LOC (refactor scaffold_role to use templates)
- `main.rs` (MCP): ~20 LOC (return content in response)
- `main.rs` (CLI): ~10 LOC (add --category flag)
- Tests: ~100 LOC
- **Total: ~480 LOC**

## Verification
```bash
# Unit tests
cargo test --workspace

# E2E: generate a development role
colmena library create-role --id web_developer --description "frontend developer for dynamic web apps with React and Tailwind"
colmena library show web_developer
cat config/library/prompts/web-developer.md  # should have full methodology, not TODOs

# E2E: generate an offensive role
colmena library create-role --id cloud_pentester --description "cloud infrastructure pentester for AWS and GCP"
cat config/library/prompts/cloud-pentester.md  # should have offensive methodology

# E2E via MCP
mcp__colmena__library_create_role(id: "api_developer", description: "REST API developer with Express and PostgreSQL")
# Should return full generated content for review
```

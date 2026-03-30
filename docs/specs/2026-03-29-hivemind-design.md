# HiveMind — Multi-Agent Orchestration Dashboard

> Design spec for a centralized hive-mind interface over Claude Code, with progressive autonomy, a wisdom library of roles/patterns, P2P agent collaboration, and meritocratic hierarchy via ELO scoring.

**Author:** fr33m4n + Claude
**Date:** 2026-03-29
**Status:** Draft
**Approach:** B — Hybrid (Claude Code Native + Thin Orchestration Layer)

---

## 1. Problem Statement

A single AppSec professional operates multiple Claude Code instances in parallel — each with a different role (Security Architect, Pentester, Auditor, Researcher). The current workflow has three compounding pain points:

1. **Approval noise (70%):** Most permission prompts are routine operations (reads, greps, web fetches) that don't need human judgment, but every one demands a context switch.
2. **Manual agent coordination:** The human acts as relay between agents that should communicate directly — the Pentester finds something, the human re-explains it to the Architect.
3. **Static orchestration:** Deciding which roles to activate, how many agents to launch, and what coordination pattern to use is ad-hoc every time.

### Success Criteria

- Reduce human approval load from ~100/session to ~30/session (the 30% that are real decisions).
- Agents share findings and evaluate each other without human relay.
- Before launching a multi-agent workflow, the system presents pattern options with trade-offs.
- Higher-performing agents (by ELO) dynamically mentor and guide lower-performing ones.
- The interface is terminal-native, comfortable, and stable.

---

## 2. Architecture Overview

```
┌─────────────────────────────────────────────┐
│                 👤 HUMAN                     │
│         (only real decisions — 30%)          │
└──────────────────┬──────────────────────────┘
                   │ approval responses
                   ▼
┌─────────────────────────────────────────────┐
│           🧠 HIVEMIND ORCHESTRATOR           │
│                                              │
│  ┌────────────┐ ┌────────────┐ ┌──────────┐ │
│  │  Approval   │ │  Pattern   │ │  Trust   │ │
│  │  Hub        │ │  Selector  │ │ Firewall │ │
│  └────────────┘ └────────────┘ └──────────┘ │
│  ┌────────────┐ ┌────────────┐ ┌──────────┐ │
│  │  ELO        │ │  Wisdom   │ │ Notifier │ │
│  │  Engine     │ │  Library  │ │          │ │
│  └────────────┘ └────────────┘ └──────────┘ │
└──────────────────┬──────────────────────────┘
                   │ hooks + Agent Teams API
                   ▼
┌─────────────────────────────────────────────┐
│         📡 KNOWLEDGE BUS (filesystem)        │
│     Signals: FINDING | ALERT | EVAL | REQ    │
└──┬───────┬───────┬───────┬──────────────────┘
   ▼       ▼       ▼       ▼
┌──────┐┌──────┐┌──────┐┌──────┐
│ 🛡   ││ 🔍   ││ ⚔    ││ 🔬   │
│Archi-││Audi- ││Pent- ││Rese- │
│tect  ││tor   ││ester ││archer│
│E:1820││E:1650││E:1900││E:1550│
└──────┘└──────┘└──────┘└──────┘
   ▲       ▲       ▲       ▲
   └───────┴───┬───┴───────┘
               │
     P2P: mentoring + cross-review
     (high-ELO guides low-ELO)
```

### Core Principles

1. **Build on Claude Code, not around it.** Every component uses official mechanisms (hooks, Agent Teams, CLAUDE.md, settings.json). No screen scraping, no keystroke injection.
2. **Progressive autonomy.** Start restrictive, expand trust explicitly. The human always controls the boundary.
3. **Meritocratic hierarchy.** Leadership is earned via ELO, not assigned. The best-performing agent for a mission category leads that mission.
4. **Files over databases.** YAML configs, Markdown templates, JSON signals. Git-versionable, human-readable, LLM-friendly.

---

## 3. Milestone M0 — Trust Firewall + Approval Hub (MVP)

### 3.1 What It Solves

The 70% approval noise. After M0, the human only sees decisions that actually need judgment.

### 3.2 Components

#### 3.2.1 Trust Firewall (`hivemind/trust-firewall.yaml`)

A declarative config that defines what's auto-approved, what needs human approval, and what's blocked.

```yaml
# Trust Firewall Configuration
version: 1

defaults:
  action: ask  # default for unconfigured tools

trust_circle:
  # Local read operations — always safe
  - tools: [Read, Glob, Grep, Bash]
    conditions:
      bash_pattern: "^(cat|head|tail|ls|find|grep|rg|git log|git diff|git status|git blame|wc|file|stat)\\b"
    action: auto-approve

  # Research — auto-approve web fetches for investigation
  - tools: [WebFetch, WebSearch]
    action: auto-approve

  # File writes within project directory
  - tools: [Write, Edit]
    conditions:
      path_within: ["${PROJECT_DIR}"]
      path_not_match: ["*.env", "*credentials*", "*secret*", "*.key"]
    action: auto-approve

  # Agent spawning — auto-approve (agents inherit trust rules)
  - tools: [Agent]
    action: auto-approve

restricted:
  # Destructive bash commands
  - tools: [Bash]
    conditions:
      bash_pattern: "^(rm|chmod|chown|kill|pkill|curl.*-X|wget.*-O|docker|kubectl)"
    action: ask

  # External communications
  - tools: [mcp__claude_ai_Slack__slack_send_message, mcp__claude_ai_Atlassian__createJiraIssue]
    action: ask

blocked:
  # Never auto-approve
  - tools: [Bash]
    conditions:
      bash_pattern: "(--force|--hard|push.*origin|rm -rf /)"
    action: block
    reason: "Destructive operation requires explicit human confirmation"

# Per-agent overrides (used by ELO engine in M3)
agent_overrides: {}

# Runtime delegations (expanded by human during session)
runtime_delegations: []
```

#### 3.2.2 Hook Handler (`hivemind/hooks/permission-handler.sh`)

A shell script registered as a Claude Code hook for `PreToolUse` and `PermissionRequest` events.

**Rule precedence:** `blocked > restricted > trust_circle > defaults`. First matching rule in highest-priority tier wins.

**Implementation note:** Entry point is a thin bash wrapper that delegates to a Python script. The handler needs YAML parsing and regex evaluation, which makes Python the practical choice from day one.

**Flow:**
1. Receive hook payload (JSON with `tool_name`, `tool_input`, `agent_id`, `session_id`)
2. Load `trust-firewall.yaml` (cached after first load, reload on file change)
3. Evaluate rules in precedence order: blocked → restricted → trust_circle → defaults
4. **auto-approve** → return `{"decision": "allow"}` silently
5. **ask** → write to approval queue + trigger notification → return `{"decision": "ask"}` (falls through to normal CC prompt)
6. **block** → return `{"decision": "deny", "reason": "..."}` + log

**Hook registration in `settings.json`:**
```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "",
        "command": "hivemind/hooks/permission-handler.sh"
      }
    ]
  }
}
```

#### 3.2.3 Approval Queue (`hivemind/queue/`)

Lightweight file-based queue for pending approvals.

**Structure:**
```
hivemind/queue/
  pending/
    <timestamp>-<agent_id>-<tool>.json   # pending approval requests
  decided/
    <timestamp>-<agent_id>-<tool>.json   # historical decisions (audit trail)
```

**Each entry:**
```json
{
  "id": "1711720800-pentester-Bash",
  "timestamp": "2026-03-29T14:00:00Z",
  "agent_id": "pentester",
  "agent_elo": 1900,
  "tool": "Bash",
  "input": "nmap -sV target.local",
  "context": "Scanning for open ports on target during pentest engagement",
  "rule_matched": "restricted.bash_destructive",
  "priority": "medium"
}
```

#### 3.2.4 Notification Router (`hivemind/hooks/notify.sh`)

Replaces the current blanket Hero.aiff/Glass.aiff with context-aware notifications.

**Rules:**
- `auto-approve` → silent (no sound)
- `ask` + priority `low` → Glass.aiff (gentle)
- `ask` + priority `medium/high` → Hero.aiff (attention needed)
- `block` → Basso.aiff (something was denied, review log)
- Notification includes agent name: `say "Pentester needs approval for Bash command"`

#### 3.2.5 Runtime Delegation

The human can expand the trust circle during a session:

1. Human says: "delegate WebFetch for the Pentester agent too"
2. System confirms: "Confirming: auto-approve all WebFetch calls from agent 'pentester' for this session. Correct?"
3. Human confirms → appends to `runtime_delegations` in trust-firewall.yaml
4. Takes effect immediately for subsequent hook calls

**Persistence:** Runtime delegations are session-scoped by default. The human can promote them to permanent with "make delegation permanent".

### 3.3 What's NOT in M0

- Pattern selector (M1)
- Wisdom library (M1)
- Knowledge bus / P2P sharing (M2)
- ELO scoring (M3)
- TUI dashboard (M1+)
- Cost/token monitoring (M1+)

### 3.4 Estimated Effort

2-3 days. The hook handler is ~100-150 lines of bash/python. The YAML config is the main design work. The queue is simple file I/O.

---

## 4. Milestone M1 — Wisdom Library + Pattern Selector

### 4.1 What It Solves

Eliminates ad-hoc decisions about which agents to launch and how to coordinate them.

### 4.2 Wisdom Library

Two catalogs stored as YAML files:

#### 4.2.1 Role Templates (`hivemind/library/roles/`)

Each role is a YAML file defining a reusable agent persona.

```yaml
# hivemind/library/roles/pentester.yaml
name: Pentester
id: pentester
icon: "⚔"
description: "Offensive security specialist focused on exploitation and vulnerability validation"

system_prompt_ref: "hivemind/library/prompts/pentester.md"

default_trust_level: restricted
tools_allowed:
  - Bash
  - Read
  - Write
  - WebFetch
  - WebSearch
  - Agent

specializations:
  - web_vulnerabilities
  - api_security
  - authentication_bypass
  - injection_attacks

elo:
  initial: 1500
  categories:
    web_vulnerabilities: 1500
    api_security: 1500
    mobile: 1500

mentoring:
  can_mentor: ["researcher", "auditor"]
  mentored_by: ["security_architect"]
```

#### 4.2.2 Pattern Templates (`hivemind/library/patterns/`)

Each orchestration pattern is a YAML file defining how agents coordinate.

```yaml
# hivemind/library/patterns/oracle-workers.yaml
name: Oracle and Workers
id: oracle-workers
source: "agentic-patterns.com"

description: >
  A single orchestrator (Oracle) analyzes the mission, decomposes it into
  sub-tasks, and dispatches specialized workers. Workers report back to the
  Oracle, which synthesizes results.

topology: hierarchical
communication: hub-and-spoke

when_to_use:
  - "Mission has clearly decomposable sub-tasks"
  - "Tasks are independent and can run in parallel"
  - "Need a single synthesized output"

when_not_to_use:
  - "Tasks require real-time negotiation between agents"
  - "The decomposition itself is the hard problem"

pros:
  - "Clear accountability — Oracle owns the outcome"
  - "Parallelizable — workers run independently"
  - "Lower token cost — workers don't share full context"

cons:
  - "Oracle is single point of failure"
  - "Workers can't course-correct each other"
  - "Oracle context grows with number of workers"

estimated_token_cost: medium
estimated_agents: 3-6

roles_suggested:
  oracle: security_architect
  workers: [pentester, auditor, researcher]

elo_lead_selection: true  # Oracle role assigned to highest-ELO agent for the mission category
```

**Additional patterns to include:**
- `debate.yaml` — Opponent Processor (two agents argue, third judges)
- `pipeline.yaml` — Sequential handoff with checkpoints
- `swarm-consensus.yaml` — Parallel exploration + consensus merge
- `plan-then-execute.yaml` — One agent plans, others execute after human approval
- `mentored-execution.yaml` — High-ELO agent supervises low-ELO agent's work

### 4.3 Pattern Selector

When the user describes a mission, the system:

1. Analyzes the mission description
2. Matches against pattern `when_to_use` criteria
3. Considers available roles and their ELO scores for the mission category
4. Presents 2-3 options:

```
Mission: "Analyze security posture of payments microservice"

Suggested patterns:

1. Oracle-Workers [RECOMMENDED]
   Lead: Security Architect (ELO: 1820 in architecture)
   Workers: Pentester (web: 1900), Auditor (compliance: 1650), Researcher (recon: 1550)
   Est. cost: ~$2.40 | Est. time: 15-25 min
   Pros: Parallel execution, clear synthesis
   Cons: Architect is SPOF

2. Pipeline
   Flow: Researcher → Auditor → Pentester → Architect (synthesis)
   Est. cost: ~$1.80 | Est. time: 30-45 min
   Pros: Lower cost, each stage builds on previous
   Cons: Sequential, slower, no cross-pollination

3. Debate + Judge
   Debaters: Pentester vs Auditor (offense vs compliance)
   Judge: Security Architect
   Est. cost: ~$3.00 | Est. time: 20-30 min
   Pros: Surfaces disagreements, thorough coverage
   Cons: Higher cost, may over-focus on contentious areas

Select [1/2/3] or describe a custom arrangement:
```

### 4.4 Estimated Effort

3-5 days. The library is YAML authoring. The selector is a skill/prompt that reads the library and presents options.

---

## 5. Milestone M2 — Knowledge Bus + P2P Sharing

### 5.1 What It Solves

The human is no longer the relay between agents. Agents share findings directly.

### 5.2 Knowledge Bus

A filesystem-based event bus where agents publish structured signals.

**Structure:**
```
hivemind/bus/
  signals/
    <timestamp>-<agent_id>-<type>.json
  subscriptions.yaml   # which roles subscribe to which signal types
```

**Signal types:**
```yaml
FINDING:    # Agent discovered something actionable
  fields: [severity, category, description, evidence, affects_roles]

ALERT:      # Urgent signal that should interrupt other agents
  fields: [severity, description, action_required]

CONTEXT:    # Background info that enriches other agents' work
  fields: [topic, summary, source, relevance_to]

EVAL:       # Peer evaluation of another agent's output (M3)
  fields: [target_agent, artifact, score, feedback, suggestions]

REQUEST:    # Agent asks another agent for help
  fields: [from_agent, to_agent, question, context]
```

**Example signal:**
```json
{
  "type": "FINDING",
  "timestamp": "2026-03-29T14:22:00Z",
  "from_agent": "pentester",
  "severity": "high",
  "category": "authentication_bypass",
  "description": "Admin endpoint /api/v2/admin/users accessible without auth token",
  "evidence": "curl -s https://target.local/api/v2/admin/users returned 200 with user data",
  "affects_roles": ["security_architect", "auditor"]
}
```

**Signal retention:** Signals older than 5 sessions are archived to `hivemind/bus/archive/`. A cleanup hook runs at session start.

### 5.3 Subscription & Injection

Agents don't read the bus directly. The orchestrator injects relevant signals into each agent's context at natural breakpoints (between tool calls, at checkpoints).

```yaml
# hivemind/bus/subscriptions.yaml
security_architect:
  subscribes_to: [FINDING, ALERT, CONTEXT]
  filter: "severity >= medium OR category in [architecture, design_flaw]"

pentester:
  subscribes_to: [FINDING, CONTEXT, REQUEST]
  filter: "category in [endpoint, credential, injection, auth]"

auditor:
  subscribes_to: [FINDING, ALERT]
  filter: "severity >= high OR category in [compliance, data_exposure]"

researcher:
  subscribes_to: [REQUEST, CONTEXT]
  filter: "all"  # researchers consume everything
```

### 5.4 Agent Teams Integration

For real-time P2P, the system uses Agent Teams native messaging (`SendMessage`). The knowledge bus handles async signals; Agent Teams handles synchronous requests between agents.

- **Async (bus):** "I found an open admin endpoint" → published, consumed at next checkpoint
- **Sync (messaging):** "Researcher, I need CVE details for this nginx version" → direct message, immediate response

### 5.5 Estimated Effort

3-5 days. Signal publishing is a hook/convention. Subscription injection requires a thin wrapper around agent context. Agent Teams messaging is native.

---

## 6. Milestone M3 — ELO Engine + Meritocratic Hierarchy

### 6.1 What It Solves

Agents improve over time. The best agents for each category lead missions and mentor others.

### 6.2 ELO Scoring Engine

#### 6.2.1 Score Sources

| Source | When | Impact |
|--------|------|--------|
| Human validation | User approves/rejects agent output | +/- 25-50 points |
| Peer evaluation | Another agent reviews an artifact (EVAL signal) | +/- 10-20 points (weighted by evaluator's ELO) |
| Mission outcome | End of mission: did the agent's contributions help? | +/- 15-30 points |
| Mentor feedback | High-ELO agent evaluates mentee's work | +/- 10-15 points |

#### 6.2.2 ELO Categories

Scores are tracked per role AND per mission category:

```yaml
# hivemind/elo/scores.yaml
pentester:
  global: 1900
  categories:
    web_vulnerabilities: 1950
    api_security: 1880
    mobile: 1200
    authentication: 1920

security_architect:
  global: 1820
  categories:
    architecture_review: 1900
    threat_modeling: 1850
    compliance: 1600
```

#### 6.2.3 Cold Start

All agents start at ELO 1500. During the cold-start period (first ~10 sessions, before scores diverge meaningfully), the system falls back to the static `mentored_by` / `can_mentor` hints in role templates (Section 4.2.1) for hierarchy decisions. Once the standard deviation across agents in a category exceeds 100 points, ELO-driven selection activates for that category.

#### 6.2.4 Meritocratic Hierarchy

ELO scores drive three dynamic behaviors:

**1. Lead Selection**
When a mission launches, the pattern selector assigns the lead role to the agent with the highest ELO in that mission's category. Not hardcoded — earned.

```
Mission category: web_vulnerabilities
  Pentester ELO: 1950 ← LEADS
  Architect ELO: 1750
  Auditor ELO: 1400
```

**2. Mentoring Protocol**
When a high-ELO agent and a low-ELO agent work on the same mission:

- The high-ELO agent receives a `MENTOR` directive in its context: "You are mentoring {agent}. Before they execute critical actions, provide brief guidance."
- The low-ELO agent receives: "Before executing critical actions in {category}, consult {mentor_agent} for guidance."
- The mentoring interaction happens via Agent Teams messaging or knowledge bus signals.

**3. Trust Calibration**
ELO influences the trust firewall dynamically:

```yaml
# In trust-firewall.yaml — agent_overrides populated by ELO engine
agent_overrides:
  pentester:
    # ELO > 1800 in web → expanded trust for web-related tools
    - tools: [Bash]
      conditions:
        bash_pattern: "^(nmap|nikto|sqlmap|burp|ffuf|nuclei)"
        elo_category: web_vulnerabilities
        elo_minimum: 1800
      action: auto-approve
  researcher:
    # ELO < 1400 in any category → more checkpoints
    - tools: [Write]
      conditions:
        elo_below: 1400
      action: ask
```

#### 6.2.4 Prompt Evolution

After each session, the ELO engine can suggest CLAUDE.md modifications:

- Agent with rising ELO → "Consider expanding autonomy for {agent} in {category}"
- Agent with falling ELO → "Consider adding more explicit instructions for {agent} in {category}"
- The human approves/rejects suggestions → this itself feeds back into ELO calibration

### 6.3 Cross-Review Protocol

At mission checkpoints (not continuously):

1. Agent completes a deliverable (report, PoC, threat model)
2. Orchestrator selects a reviewer (preferably different role, ELO-weighted)
3. Reviewer receives the artifact + evaluation rubric
4. Reviewer publishes an `EVAL` signal with score + feedback
5. ELO engine processes the evaluation
6. If human is available, they can validate or override the peer review

### 6.4 Estimated Effort

5-7 days. The ELO math is simple (standard ELO formula). The complexity is in the integration points: trust firewall updates, lead selection, mentoring injection, and prompt evolution suggestions.

---

## 7. Technology Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Backbone | Claude Code + Agent Teams | Official, evolves with CC updates, preserves terminal workflow |
| Config format | YAML + Markdown | Git-versionable, human-readable, LLM-friendly |
| Hook language | Bash + Python fallback | Bash for simple routing, Python when YAML parsing or ELO math needed |
| Knowledge bus | Filesystem (JSON signals) | No external dependencies, works with CC's file tools natively |
| State persistence | YAML files (scores, configs) | No database needed at this scale |
| Notification | macOS `say` + `afplay` | Already in use, extend with context |
| Pattern library source | agentic-patterns.com + custom | Start with proven patterns, add custom ones from experience |

---

## 8. File Structure

```
hivemind/
├── trust-firewall.yaml          # M0: approval rules
├── hooks/
│   ├── permission-handler.sh    # M0: hook for PreToolUse
│   └── notify.sh                # M0: context-aware notifications
├── queue/
│   ├── pending/                 # M0: pending approval requests
│   └── decided/                 # M0: audit trail
├── library/
│   ├── roles/                   # M1: role templates (YAML)
│   │   ├── security-architect.yaml
│   │   ├── pentester.yaml
│   │   ├── auditor.yaml
│   │   └── researcher.yaml
│   ├── patterns/                # M1: orchestration patterns (YAML)
│   │   ├── oracle-workers.yaml
│   │   ├── debate.yaml
│   │   ├── pipeline.yaml
│   │   ├── swarm-consensus.yaml
│   │   ├── plan-then-execute.yaml
│   │   └── mentored-execution.yaml
│   └── prompts/                 # M1: system prompts per role (MD)
│       ├── security-architect.md
│       ├── pentester.md
│       ├── auditor.md
│       └── researcher.md
├── bus/
│   ├── signals/                 # M2: published signals (JSON)
│   └── subscriptions.yaml       # M2: who subscribes to what
├── elo/
│   ├── scores.yaml              # M3: current ELO ratings
│   ├── history/                 # M3: score change log
│   └── suggestions/             # M3: prompt evolution suggestions
└── README.md
```

---

## 9. Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Agent Teams is experimental | Session resumption issues, task lag | M0 works without Agent Teams. P2P (M2) has filesystem fallback. |
| Hook latency slows agents | Each tool call waits for permission-handler.sh | Keep handler fast (<100ms). YAML is cached in memory after first load. |
| ELO gaming (agents optimize for score not quality) | Misleading hierarchy | Human validation is the highest-weight signal. Peer reviews are ELO-weighted. |
| Trust circle too permissive | Security risk from auto-approved operations | Default to `ask`. Only expand explicitly. Block list is non-overridable. |
| Knowledge bus noise | Agents flooded with irrelevant signals | Subscriptions with filters. Injection only at checkpoints, not every tool call. |
| Anthropic ships native dashboard | Duplicated effort | Architecture is thin layer on top of CC. If native dashboard arrives, HiveMind becomes the library + ELO engine only. |

---

## 10. Future Considerations (Post-M3)

These are explicitly NOT in scope but worth noting:

- **TUI Dashboard (Bubbletea/Ratatui):** Visual overview of all agents, their status, ELO, and pending approvals. Build after M1 proves the workflow.
- **Cost monitoring:** Token/dollar tracking per agent per mission. Requires Agent SDK integration.
- **Multi-LLM routing:** Use cheaper models (Haiku, Gemini Flash) for low-stakes sub-tasks. Requires Agent SDK.
- **Cross-session memory:** Persistent knowledge graph (Zep/Graphiti) for long-term intelligence accumulation across sessions. Evaluate when digest corpus exceeds ~500 documents.
- **Team templates:** Pre-configured teams for common missions ("BBP Triage Team", "Threat Model Team") that bundle pattern + roles + trust config.

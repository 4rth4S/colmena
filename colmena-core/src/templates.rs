use anyhow::{Result, bail};
use std::fmt;
use std::str::FromStr;

// ── Role Category ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RoleCategory {
    Offensive,    // pentester, red team — restricted trust, Bash(restricted)
    Defensive,    // SOC, incident response — ask trust, Bash(restricted), no Write
    Compliance,   // auditor, governance — ask trust, no Bash
    Architecture, // architect, strategic — ask trust, all tools + Agent
    Research,     // researcher, OSINT — auto-approve trust, read-only
    Development,  // developer, code — ask trust, Bash + Write/Edit
    Operations,   // SRE, DevOps, infra — restricted trust, Bash(restricted)
    Creative,     // writer, content — auto-approve trust, Write/Edit, no Bash
}

impl fmt::Display for RoleCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RoleCategory::Offensive => write!(f, "Offensive"),
            RoleCategory::Defensive => write!(f, "Defensive"),
            RoleCategory::Compliance => write!(f, "Compliance"),
            RoleCategory::Architecture => write!(f, "Architecture"),
            RoleCategory::Research => write!(f, "Research"),
            RoleCategory::Development => write!(f, "Development"),
            RoleCategory::Operations => write!(f, "Operations"),
            RoleCategory::Creative => write!(f, "Creative"),
        }
    }
}

impl FromStr for RoleCategory {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "offensive" => Ok(RoleCategory::Offensive),
            "defensive" => Ok(RoleCategory::Defensive),
            "compliance" => Ok(RoleCategory::Compliance),
            "architecture" => Ok(RoleCategory::Architecture),
            "research" => Ok(RoleCategory::Research),
            "development" => Ok(RoleCategory::Development),
            "operations" => Ok(RoleCategory::Operations),
            "creative" => Ok(RoleCategory::Creative),
            _ => bail!("Unknown role category '{}'. Valid categories: Offensive, Defensive, Compliance, Architecture, Research, Development, Operations, Creative", s),
        }
    }
}

impl RoleCategory {
    pub fn icon(&self) -> &'static str {
        match self {
            RoleCategory::Offensive => "\u{2694}",     // ⚔
            RoleCategory::Defensive => "\u{1F6E1}",    // 🛡
            RoleCategory::Compliance => "\u{1F4CB}",   // 📋
            RoleCategory::Architecture => "\u{1F3D7}", // 🏗
            RoleCategory::Research => "\u{1F52C}",     // 🔬
            RoleCategory::Development => "\u{1F4BB}",  // 💻
            RoleCategory::Operations => "\u{2699}",    // ⚙
            RoleCategory::Creative => "\u{270D}",      // ✍
        }
    }

    pub fn tools_allowed(&self) -> &'static [&'static str] {
        match self {
            RoleCategory::Offensive => &["Bash", "Read", "Write", "Edit", "Glob", "Grep", "WebFetch", "WebSearch", "Agent"],
            RoleCategory::Defensive => &["Bash", "Read", "Glob", "Grep", "WebFetch", "WebSearch"],
            RoleCategory::Compliance => &["Read", "Write", "Edit", "Glob", "Grep", "WebFetch", "WebSearch"],
            RoleCategory::Architecture => &["Bash", "Read", "Write", "Edit", "Glob", "Grep", "WebFetch", "WebSearch", "Agent"],
            RoleCategory::Research => &["Read", "Glob", "Grep", "WebFetch", "WebSearch"],
            RoleCategory::Development => &["Bash", "Read", "Write", "Edit", "Glob", "Grep", "WebFetch", "WebSearch"],
            RoleCategory::Operations => &["Bash", "Read", "Glob", "Grep", "WebFetch", "WebSearch"],
            RoleCategory::Creative => &["Read", "Write", "Edit", "Glob", "Grep", "WebFetch", "WebSearch"],
        }
    }

    pub fn default_trust_level(&self) -> &'static str {
        match self {
            RoleCategory::Offensive => "restricted",
            RoleCategory::Defensive => "ask",
            RoleCategory::Compliance => "ask",
            RoleCategory::Architecture => "ask",
            RoleCategory::Research => "auto-approve",
            RoleCategory::Development => "ask",
            RoleCategory::Operations => "restricted",
            RoleCategory::Creative => "auto-approve",
        }
    }

    pub fn methodology_phases(&self) -> [&'static str; 5] {
        match self {
            RoleCategory::Offensive => ["Enumerate", "Fingerprint", "Test", "Validate", "Document"],
            RoleCategory::Defensive => ["Detect", "Triage", "Investigate", "Contain", "Report"],
            RoleCategory::Compliance => ["Scope", "Map", "Assess", "Evidence", "Report"],
            RoleCategory::Architecture => ["Discover", "Model", "Analyze", "Design", "Document"],
            RoleCategory::Research => ["Scope", "Collect", "Analyze", "Correlate", "Report"],
            RoleCategory::Development => ["Understand", "Plan", "Implement", "Test", "Document"],
            RoleCategory::Operations => ["Assess", "Plan", "Execute", "Verify", "Monitor"],
            RoleCategory::Creative => ["Research", "Outline", "Draft", "Refine", "Deliver"],
        }
    }

    pub fn safety_rails(&self) -> &'static str {
        match self {
            RoleCategory::Offensive => "\
- Stay within the defined engagement scope at all times. Never test systems that are not explicitly in scope.\n\
- Do not perform destructive actions such as deleting data, dropping databases, or denial-of-service attacks.\n\
- Rate-limit automated scans to avoid disrupting target availability.\n\
- Redact credentials, tokens, and secrets in all output and findings. Never store plaintext credentials.",

            RoleCategory::Defensive => "\
- Operate in read-only mode. Do not modify system configurations, logs, or evidence.\n\
- Preserve chain of custody for all evidence collected during incident response.\n\
- Do not disable security controls or monitoring during investigation.\n\
- Escalate immediately when active compromise indicators are found.",

            RoleCategory::Compliance => "\
- Do not modify code, configurations, or infrastructure. Your role is to observe and document.\n\
- Cite specific standard references for every finding. Avoid subjective assessments without evidence.\n\
- Mark controls as 'Unable to verify' when evidence is insufficient rather than assuming compliance.\n\
- Maintain confidentiality of audit findings until formally reported.",

            RoleCategory::Architecture => "\
- Design decisions must be documented with rationale and trade-offs.\n\
- Consider security implications of every architectural choice.\n\
- Do not implement changes directly. Provide designs and recommendations for development teams.\n\
- Validate threat models against real attack patterns, not theoretical risks only.",

            RoleCategory::Research => "\
- Use only publicly available sources. Do not access private systems or data without authorization.\n\
- Cite every source with URL, date, and confidence level.\n\
- Mark stale intelligence clearly. Note the age of every external source.\n\
- Do not speculate. If evidence is insufficient, state the limitation explicitly.",

            RoleCategory::Development => "\
- Never deploy directly to production environments.\n\
- Do not use force-push or destructive git operations without explicit approval.\n\
- Run tests before committing changes. Verify that existing tests continue to pass.\n\
- Do not commit secrets, credentials, or API keys to version control.",

            RoleCategory::Operations => "\
- Verify operations in a dry-run or staging environment before applying to production.\n\
- Do not delete infrastructure resources without explicit approval and backup verification.\n\
- Keep state files (tfstate, ansible state) secure and never commit them to version control.\n\
- Log all infrastructure changes with timestamps and rollback procedures.",

            RoleCategory::Creative => "\
- Maintain consistent voice and tone throughout all deliverables.\n\
- Verify technical accuracy of all claims before publishing.\n\
- Do not fabricate data, statistics, or quotes. Cite sources for factual assertions.\n\
- Follow the project's style guide and formatting conventions.",
        }
    }

    /// All 8 variants in a privilege-ordered list (most privileged last).
    /// Used for tie-breaking in category detection.
    fn privilege_order(&self) -> u8 {
        match self {
            RoleCategory::Creative => 0,
            RoleCategory::Research => 1,
            RoleCategory::Compliance => 2,
            RoleCategory::Defensive => 3,
            RoleCategory::Development => 4,
            RoleCategory::Architecture => 5,
            RoleCategory::Operations => 6,
            RoleCategory::Offensive => 7,
        }
    }

    fn detection_keywords(&self) -> &'static [&'static str] {
        match self {
            RoleCategory::Offensive => &[
                "pentest", "penetration", "exploit", "vulnerab", "attack", "offensive",
                "red_team", "bypass", "injection", "xss", "sqli", "bug_bounty",
                "hack", "payload", "brute",
            ],
            RoleCategory::Defensive => &[
                "defend", "monitor", "incident", "response", "soc", "blue_team",
                "detection", "siem", "forensics", "triage", "alert", "threat_hunt",
                "malware", "containment", "edr",
            ],
            RoleCategory::Compliance => &[
                "audit", "compliance", "regulation", "pci", "gdpr", "hipaa",
                "soc2", "iso27001", "nist", "standards", "policy", "governance",
                "evidence", "control", "framework",
            ],
            RoleCategory::Architecture => &[
                "architect", "design", "threat_model", "system_design", "review",
                "strategy", "integration", "risk_assessment", "modeling",
                "blueprint", "diagram", "strategic", "synthesis",
            ],
            RoleCategory::Research => &[
                "research", "osint", "reconnaissance", "cve", "analysis",
                "intelligence", "documentation", "survey", "investigate",
                "discover", "enumerate", "recon", "inventory",
            ],
            RoleCategory::Development => &[
                "develop", "code", "implement", "refactor", "build", "test",
                "ci_cd", "cicd", "deploy", "frontend", "backend", "api", "database",
                "fullstack", "react", "node",
            ],
            RoleCategory::Operations => &[
                "infra", "infrastructure", "cloud", "aws", "gcp", "azure",
                "kubernetes", "k8s", "docker", "terraform", "ansible", "sre",
                "devops", "pipeline", "monitoring",
            ],
            RoleCategory::Creative => &[
                "write", "document", "content", "technical_writing", "prompt",
                "creative", "report", "presentation", "tutorial", "guide",
                "copywriting", "narrative", "editorial",
            ],
        }
    }

    /// Default specialization slugs for this category.
    fn default_specializations(&self) -> &'static [&'static str] {
        match self {
            RoleCategory::Offensive => &["vulnerability_assessment", "exploitation", "attack_surface_mapping", "proof_of_concept"],
            RoleCategory::Defensive => &["incident_response", "threat_detection", "log_analysis", "containment"],
            RoleCategory::Compliance => &["standards_mapping", "gap_analysis", "evidence_collection", "policy_review"],
            RoleCategory::Architecture => &["architecture_review", "threat_modeling", "design_patterns", "risk_assessment"],
            RoleCategory::Research => &["reconnaissance", "cve_research", "documentation_analysis", "intelligence_gathering"],
            RoleCategory::Development => &["implementation", "testing", "code_review", "debugging"],
            RoleCategory::Operations => &["infrastructure_management", "deployment", "monitoring", "automation"],
            RoleCategory::Creative => &["technical_writing", "documentation", "content_strategy", "editorial_review"],
        }
    }

    fn permissions_block(&self) -> Option<String> {
        match self {
            RoleCategory::Offensive => Some(
                "permissions:\n\
                 \x20 bash_patterns:\n\
                 \x20   - '^curl\\b'\n\
                 \x20   - '^python\\b'\n\
                 \x20   - '^nmap\\b'\n\
                 \x20   - '^nikto\\b'\n\
                 \x20   - '^nuclei\\b'\n\
                 \x20 path_within:\n\
                 \x20   - '${MISSION_DIR}'\n\
                 \x20 path_not_match:\n\
                 \x20   - '*.env'\n\
                 \x20   - '*credentials*'\n\
                 \x20   - '*.key'\n\
                 \x20   - '*.pem'"
                    .to_string(),
            ),
            RoleCategory::Defensive => Some(
                "permissions:\n\
                 \x20 bash_patterns:\n\
                 \x20   - '^grep\\b'\n\
                 \x20   - '^journalctl\\b'\n\
                 \x20   - '^docker logs\\b'\n\
                 \x20   - '^kubectl logs\\b'\n\
                 \x20 path_within:\n\
                 \x20   - '${MISSION_DIR}'\n\
                 \x20 path_not_match:\n\
                 \x20   - '*.env'\n\
                 \x20   - '*credentials*'\n\
                 \x20   - '*.key'"
                    .to_string(),
            ),
            RoleCategory::Development => Some(
                "permissions:\n\
                 \x20 bash_patterns:\n\
                 \x20   - '^git\\b'\n\
                 \x20   - '^cargo\\b'\n\
                 \x20   - '^npm\\b'\n\
                 \x20   - '^pip\\b'\n\
                 \x20   - '^python\\b'\n\
                 \x20   - '^node\\b'\n\
                 \x20   - '^make\\b'\n\
                 \x20 path_within:\n\
                 \x20   - '${MISSION_DIR}'\n\
                 \x20 path_not_match:\n\
                 \x20   - '*.env'\n\
                 \x20   - '*credentials*'\n\
                 \x20   - '*.key'\n\
                 \x20   - '*secret*'"
                    .to_string(),
            ),
            RoleCategory::Operations => Some(
                "permissions:\n\
                 \x20 bash_patterns:\n\
                 \x20   - '^kubectl\\b'\n\
                 \x20   - '^docker\\b'\n\
                 \x20   - '^terraform\\b'\n\
                 \x20   - '^ansible\\b'\n\
                 \x20   - '^aws\\b'\n\
                 \x20   - '^gcloud\\b'\n\
                 \x20 path_within:\n\
                 \x20   - '${MISSION_DIR}'\n\
                 \x20 path_not_match:\n\
                 \x20   - '*.env'\n\
                 \x20   - '*credentials*'\n\
                 \x20   - '*.key'\n\
                 \x20   - '*.pem'\n\
                 \x20   - '*tfstate*'"
                    .to_string(),
            ),
            // Compliance, Architecture, Research, Creative: no permissions block
            _ => None,
        }
    }

    /// Phase descriptions for each methodology phase, keyed by category.
    fn phase_descriptions(&self) -> [&'static str; 5] {
        match self {
            RoleCategory::Offensive => [
                "Map all endpoints, parameters, authentication mechanisms, and technology stack. Build a complete inventory of the attack surface before testing anything.",
                "Identify frameworks, versions, and known CVEs for each component. Cross-reference with public vulnerability databases and exploit repositories.",
                "Work through relevant vulnerability classes systematically, then explore application-specific logic flaws. Prioritize high-impact attack vectors.",
                "Confirm each finding is exploitable in context, not just theoretically present. Develop proof-of-concept code or step-by-step reproduction procedures.",
                "Write up each finding with severity, reproduction steps, proof of concept, and recommended remediation. Include negative results where relevant.",
            ],
            RoleCategory::Defensive => [
                "Identify anomalous signals in logs, alerts, and monitoring data. Correlate events across multiple data sources to surface potential incidents.",
                "Assess severity, scope, and potential impact of detected events. Classify incidents by type and urgency to determine appropriate response level.",
                "Perform deep analysis of confirmed incidents. Trace attack paths, identify affected systems, and determine root cause through forensic examination.",
                "Implement immediate containment measures to stop active threats. Isolate compromised systems while preserving evidence for further investigation.",
                "Document the incident timeline, findings, containment actions, and lessons learned. Produce actionable recommendations to prevent recurrence.",
            ],
            RoleCategory::Compliance => [
                "Identify applicable compliance frameworks, regulatory requirements, and their specific controls relevant to the target system or organization.",
                "Map each requirement to observable technical controls, configurations, and policies in the target environment.",
                "Evaluate each control against the standard requirements. Classify as Compliant, Non-Compliant, Partially Compliant, or Not Applicable with justification.",
                "Collect and document evidence artifacts that demonstrate compliance or non-compliance for each control. Maintain chain of custody.",
                "Produce a structured compliance report with specific standard references, gap analysis, remediation priorities, and executive summary.",
            ],
            RoleCategory::Architecture => [
                "Map existing system components, data flows, trust boundaries, and integration points. Understand the current architecture before proposing changes.",
                "Build threat models using structured methodologies. Identify assets, threat actors, attack vectors, and existing mitigations.",
                "Evaluate architecture against security principles, industry patterns, and identified threats. Assess risk for each identified weakness.",
                "Propose architectural improvements with clear rationale, trade-offs, and implementation guidance. Prioritize by risk reduction impact.",
                "Document architecture decisions, threat models, and design recommendations in a format that development teams can action directly.",
            ],
            RoleCategory::Research => [
                "Define research boundaries and objectives. Identify what information is needed and what sources are available for collection.",
                "Gather information from public sources, documentation, repositories, advisories, and other available intelligence feeds.",
                "Examine collected data for patterns, vulnerabilities, and actionable intelligence. Assess relevance and reliability of each finding.",
                "Cross-reference findings across multiple sources. Build a coherent intelligence picture by connecting related data points.",
                "Produce structured intelligence reports with cited sources, confidence levels, and clear recommendations for the team.",
            ],
            RoleCategory::Development => [
                "Read existing code, documentation, and requirements thoroughly. Understand the current system behavior before making changes.",
                "Design the implementation approach. Consider edge cases, error handling, performance implications, and backward compatibility.",
                "Write the code following project conventions. Keep changes focused and incremental. Handle errors gracefully with meaningful messages.",
                "Write and run tests to verify correctness. Ensure existing tests continue to pass. Cover edge cases and error paths.",
                "Update relevant documentation, comments, and changelogs. Explain the rationale behind implementation decisions.",
            ],
            RoleCategory::Operations => [
                "Evaluate current infrastructure state, resource utilization, and operational health. Identify areas requiring attention or improvement.",
                "Design the operational change with rollback procedures, timing considerations, and dependency analysis. Document the plan before execution.",
                "Apply infrastructure changes following the plan. Use automation tools and follow infrastructure-as-code practices where possible.",
                "Validate that changes achieved the intended outcome. Run health checks, verify service availability, and confirm metrics are within expected ranges.",
                "Establish ongoing monitoring for the changed components. Set up alerts, dashboards, and runbooks for operational sustainability.",
            ],
            RoleCategory::Creative => [
                "Review existing content, style guides, and target audience needs. Understand the context and purpose of the deliverable.",
                "Create a structured outline covering all required sections. Define the narrative arc, key messages, and supporting evidence.",
                "Write the initial content following the outline. Focus on clarity, accuracy, and appropriate technical depth for the audience.",
                "Review and improve the draft for clarity, consistency, flow, and technical accuracy. Eliminate redundancy and tighten prose.",
                "Finalize the content with proper formatting, citations, and quality checks. Ensure it meets the project's standards and style guide.",
            ],
        }
    }

    /// Escalation guidance appropriate for this category.
    fn escalation_guidance(&self) -> &'static str {
        match self {
            RoleCategory::Offensive => "\
Escalate immediately when you discover critical-severity findings such as remote code execution, \
authentication bypass, or mass data exposure. Do not wait for the engagement to conclude. \
Notify the Security Architect with a finding summary, severity assessment, reproduction steps, \
and recommended immediate mitigation. For findings that could indicate active compromise of \
production systems, escalate to incident response as well.",

            RoleCategory::Defensive => "\
Escalate immediately when you identify indicators of active compromise, data exfiltration, \
or lateral movement. Notify the incident commander with affected systems, attack timeline, \
and containment recommendations. For confirmed breaches involving regulated data, trigger \
the regulatory notification workflow. Time-sensitive containment decisions should not wait \
for full investigation completion.",

            RoleCategory::Compliance => "\
Escalate when you identify critical compliance gaps that expose the organization to \
regulatory penalties or legal liability. Notify the compliance officer with the specific \
standard requirement, the observed gap, and the potential impact. For gaps involving \
active data handling violations, escalate to both legal and technical leadership.",

            RoleCategory::Architecture => "\
Escalate when you identify fundamental architectural weaknesses that cannot be mitigated \
without significant redesign. Notify technical leadership with the identified risk, affected \
components, and proposed architectural alternatives with effort estimates. For security \
architecture issues that are actively exploitable, coordinate with the offensive team \
for validation before escalating.",

            RoleCategory::Research => "\
Escalate when you discover intelligence that requires immediate action, such as actively \
exploited zero-day vulnerabilities affecting the target, exposed credentials in public \
repositories, or indicators of prior compromise. Provide the raw intelligence with source \
citations and confidence assessment. Let the receiving team determine the response rather \
than interpreting operational implications.",

            RoleCategory::Development => "\
Escalate when you encounter blocking issues that prevent progress, such as unclear requirements, \
architectural decisions that need approval, or security concerns in existing code that affect \
your implementation approach. For bugs discovered in production code during development, \
report them through the standard defect tracking process rather than attempting ad-hoc fixes.",

            RoleCategory::Operations => "\
Escalate when infrastructure changes have unexpected side effects, when rollback procedures \
fail, or when monitoring reveals degraded service health. Notify the on-call team with affected \
services, impact assessment, and actions taken so far. For changes that risk data loss or \
extended downtime, pause execution and seek explicit approval before proceeding.",

            RoleCategory::Creative => "\
Escalate when you identify technical inaccuracies that you cannot verify independently, when \
content requirements conflict with factual accuracy, or when deliverables require subject \
matter expertise outside your domain. Request review from the relevant technical specialist \
before publishing content that makes claims about system behavior or security properties.",
        }
    }

    /// Output format guidance appropriate for this category.
    fn output_format(&self) -> &'static str {
        match self {
            RoleCategory::Offensive => "\
For each finding, document:\n\
- **Title:** Short, descriptive (e.g., \"Unauthenticated SQL Injection in /api/search\")\n\
- **Severity:** Critical / High / Medium / Low / Informational\n\
- **Description:** What the vulnerability is and why it matters\n\
- **Reproduction Steps:** Exact steps to reproduce, including any required setup\n\
- **Proof of Concept:** Code, curl commands, or request/response pairs\n\
- **Recommended Fix:** Specific remediation, not generic advice",

            RoleCategory::Defensive => "\
For each incident or detection, document:\n\
- **Incident ID:** Unique identifier for tracking\n\
- **Timeline:** Chronological sequence of events with timestamps\n\
- **Affected Systems:** List of compromised or impacted systems\n\
- **Indicators of Compromise:** Observable artifacts (IPs, hashes, domains, patterns)\n\
- **Containment Actions:** Steps taken to limit impact\n\
- **Root Cause:** Determined or suspected cause of the incident\n\
- **Recommendations:** Preventive measures to avoid recurrence",

            RoleCategory::Compliance => "\
For each control assessment, document:\n\
- **Control ID:** Standard reference (e.g., \"PCI-DSS v4.0 Req 6.3.3\")\n\
- **Requirement:** Quoted requirement text from the standard\n\
- **Status:** Compliant / Non-Compliant / Partially Compliant / Not Applicable\n\
- **Evidence:** Artifacts demonstrating compliance status\n\
- **Gap Description:** Specific delta between required and observed state\n\
- **Remediation:** Steps to achieve compliance with effort estimate",

            RoleCategory::Architecture => "\
For each design element, document:\n\
- **Component:** System or subsystem under review\n\
- **Current State:** Existing architecture and its properties\n\
- **Identified Risks:** Security or reliability concerns with severity\n\
- **Proposed Design:** Recommended architecture with rationale\n\
- **Trade-offs:** What is gained and what is sacrificed\n\
- **Implementation Notes:** Key considerations for development teams",

            RoleCategory::Research => "\
For each intelligence item, document:\n\
- **Finding:** Clear statement of what was discovered\n\
- **Source:** URL, document name, or repository with access date\n\
- **Confidence:** High (directly observed) / Medium (inferred) / Low (circumstantial)\n\
- **Relevance:** How this finding relates to the current engagement\n\
- **Actionability:** What the team should do with this information",

            RoleCategory::Development => "\
For each implementation unit, document:\n\
- **Change Summary:** What was changed and why\n\
- **Files Modified:** List of files with brief description of changes\n\
- **Testing:** Tests added or modified, and verification results\n\
- **Edge Cases:** Known limitations or boundary conditions handled\n\
- **Breaking Changes:** Any backward-incompatible changes with migration notes",

            RoleCategory::Operations => "\
For each operational change, document:\n\
- **Change Description:** What is being changed and the business justification\n\
- **Impact Assessment:** Services affected and expected downtime\n\
- **Execution Plan:** Step-by-step procedure with estimated duration\n\
- **Rollback Plan:** Steps to revert if the change causes issues\n\
- **Verification:** Health checks and metrics to confirm success\n\
- **Monitoring:** Alerts and dashboards to watch post-change",

            RoleCategory::Creative => "\
For each deliverable, include:\n\
- **Title:** Clear, descriptive title appropriate for the audience\n\
- **Summary:** One-paragraph overview of the content\n\
- **Body:** Structured content with clear headings and logical flow\n\
- **References:** Cited sources for all factual claims\n\
- **Metadata:** Target audience, word count, and revision status",
        }
    }
}

// ── Category Detection ───────────────────────────────────────────────────────

/// Detect category from description using keyword scoring.
/// Each category has 10-15 detection keywords. Score = count of matching keywords.
/// Highest score wins. Tie-break: prefer less-privileged category.
/// Default fallback (no matches): Development.
pub fn detect_category(description: &str) -> RoleCategory {
    let lower = description.to_lowercase();
    // Two normalized forms: underscore-separated (for multi-word keywords like "red_team")
    // and the original lowercase (for substring matching like "exploit" in "exploitation")
    let normalized_underscore = lower.replace(['-', ' '], "_");
    let all_categories = [
        RoleCategory::Offensive,
        RoleCategory::Defensive,
        RoleCategory::Compliance,
        RoleCategory::Architecture,
        RoleCategory::Research,
        RoleCategory::Development,
        RoleCategory::Operations,
        RoleCategory::Creative,
    ];

    let mut best_category = RoleCategory::Development;
    let mut best_score: usize = 0;

    for category in &all_categories {
        let score: usize = category
            .detection_keywords()
            .iter()
            .filter(|kw| lower.contains(**kw) || normalized_underscore.contains(**kw))
            .count();

        if score > best_score
            || (score == best_score && score > 0 && category.privilege_order() < best_category.privilege_order())
        {
            best_score = score;
            best_category = *category;
        }
    }

    best_category
}

// ── Role YAML Generation ─────────────────────────────────────────────────────

/// Generate complete role YAML string.
pub fn generate_role_yaml(id: &str, description: &str, category: RoleCategory) -> String {
    let name = id.replace(['_', '-'], " ");
    let escaped_description = description.replace('"', "\\\"");
    let tools = category.tools_allowed().join(", ");
    let specializations = infer_specializations(description, category);

    let specs_yaml = specializations
        .iter()
        .map(|s| format!("  - {}", s))
        .collect::<Vec<_>>()
        .join("\n");

    // Pick up to 3 specializations for ELO categories
    let elo_categories: Vec<&String> = specializations.iter().take(3).collect();
    let elo_yaml = elo_categories
        .iter()
        .map(|s| format!("    {}: 1500", s))
        .collect::<Vec<_>>()
        .join("\n");

    let permissions_section = match category.permissions_block() {
        Some(block) => format!("\n{}\n", block),
        None => String::new(),
    };

    format!(
        "\
name: {name}
id: {id}
icon: \"{icon}\"
description: \"{description}\"

system_prompt_ref: prompts/{id}.md

default_trust_level: {trust}
tools_allowed: [{tools}]
{permissions}\
specializations:
{specs}

elo:
  initial: 1500
  categories:
{elo}

mentoring:
  can_mentor: []
  mentored_by: []
",
        name = name,
        id = id,
        icon = category.icon(),
        description = escaped_description,
        trust = category.default_trust_level(),
        tools = tools,
        permissions = permissions_section,
        specs = specs_yaml,
        elo = elo_yaml,
    )
}

// ── System Prompt Generation ─────────────────────────────────────────────────

/// Generate complete 5-section system prompt markdown.
pub fn generate_role_prompt(id: &str, description: &str, category: RoleCategory) -> String {
    let name = id.replace(['_', '-'], " ");
    // Title-case each word
    let title_name: String = name
        .split_whitespace()
        .map(|w| {
            let mut chars = w.chars();
            match chars.next() {
                None => String::new(),
                Some(c) => c.to_uppercase().to_string() + &chars.as_str().to_lowercase(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ");

    let phases = category.methodology_phases();
    let phase_descs = category.phase_descriptions();

    let methodology_section = phases
        .iter()
        .zip(phase_descs.iter())
        .enumerate()
        .map(|(i, (phase, desc))| format!("{}. **{}:** {}", i + 1, phase, desc))
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        "\
# {title}

You are the {title}. {description}

## Core Responsibilities

{responsibilities}

## Methodology

Follow this sequence for every engagement:

{methodology}

## Escalation

{escalation}

## Output Format

{output_format}

## Boundaries

{boundaries}
",
        title = title_name,
        description = description,
        responsibilities = generate_responsibilities(description, category),
        methodology = methodology_section,
        escalation = category.escalation_guidance(),
        output_format = category.output_format(),
        boundaries = category.safety_rails(),
    )
}

/// Generate 3-4 responsibility paragraphs derived from the category and description.
fn generate_responsibilities(description: &str, category: RoleCategory) -> String {
    let specializations = infer_specializations(description, category);
    let specs_display: Vec<String> = specializations
        .iter()
        .take(4)
        .map(|s| s.replace('_', " "))
        .collect();

    match category {
        RoleCategory::Offensive => format!(
            "**Vulnerability Discovery:** Identify and validate exploitable vulnerabilities across the target scope. \
Focus on real exploitability and practical impact rather than theoretical risk. Prioritize findings that \
demonstrate concrete business impact.\n\n\
**Attack Surface Mapping:** Enumerate all exposed endpoints, authentication mechanisms, authorization models, \
and data inputs before testing. Build a comprehensive map of the target before attempting exploitation.\n\n\
**Exploitation and Validation:** Validate findings with proof-of-concept code or detailed reproduction steps. \
A finding without reproduction steps is incomplete. Focus areas include {}.\n\n\
**Security Assessment:** Systematically work through relevant vulnerability classes for the target. \
Test every access control assumption including horizontal and vertical privilege escalation.",
            specs_display.join(", ")
        ),
        RoleCategory::Defensive => format!(
            "**Threat Detection:** Monitor and analyze security events across all available data sources. \
Correlate events from multiple systems to identify attack patterns and anomalous behavior that \
individual alerts might miss.\n\n\
**Incident Response:** When threats are confirmed, execute structured response procedures. \
Prioritize containment to limit blast radius while preserving forensic evidence for root cause analysis.\n\n\
**Forensic Analysis:** Perform detailed investigation of security incidents. Trace attack paths, \
identify compromised assets, and determine the full scope of impact. Focus areas include {}.\n\n\
**Continuous Improvement:** Document lessons learned from every incident. Update detection rules, \
response procedures, and monitoring coverage based on observed attack patterns.",
            specs_display.join(", ")
        ),
        RoleCategory::Compliance => format!(
            "**Standards Mapping:** Translate technical implementations into compliance language. \
Map each finding to the specific control requirement it violates or satisfies. Maintain current \
knowledge of applicable regulatory frameworks.\n\n\
**Evidence Collection:** Compliance is about evidence. For each control, identify what evidence \
demonstrates compliance or non-compliance. Collect and log this evidence systematically with \
proper chain of custody.\n\n\
**Gap Analysis:** Identify the delta between current state and required state with precision. \
Provide specific, measurable descriptions of gaps rather than qualitative assessments. \
Focus areas include {}.\n\n\
**Policy Review:** Evaluate written policies against implementation reality. Policies that exist \
on paper but are not enforced technically are gaps. Policies that are enforced technically but \
not documented are also gaps.",
            specs_display.join(", ")
        ),
        RoleCategory::Architecture => format!(
            "**Architecture Review:** Evaluate existing system designs for security properties, scalability, \
and maintainability. Identify architectural weaknesses that could lead to security incidents or \
operational failures.\n\n\
**Threat Modeling:** Build structured threat models that identify assets, threat actors, attack vectors, \
and existing mitigations. Use established methodologies to ensure comprehensive coverage.\n\n\
**Design Guidance:** Propose architectural improvements with clear rationale and trade-off analysis. \
Designs should be actionable by development teams. Focus areas include {}.\n\n\
**Strategic Synthesis:** Integrate findings from other team members into a coherent security picture. \
Prioritize recommendations by risk reduction impact and implementation feasibility.",
            specs_display.join(", ")
        ),
        RoleCategory::Research => format!(
            "**Intelligence Gathering:** Collect information from publicly available sources including \
documentation, repositories, advisories, and other intelligence feeds. Build a comprehensive \
understanding of the target's technology landscape.\n\n\
**Vulnerability Research:** For every identified technology and version, research known vulnerabilities. \
Cross-reference multiple databases and assess relevance in the specific context of the engagement.\n\n\
**Documentation Analysis:** Review available documentation including API specs, changelogs, and \
developer guides. Extract technical details that inform the team's approach. Focus areas include {}.\n\n\
**Intelligence Synthesis:** Correlate findings across sources to build actionable intelligence products. \
Assess confidence levels and clearly distinguish established facts from inferences.",
            specs_display.join(", ")
        ),
        RoleCategory::Development => format!(
            "**Implementation:** Write clean, maintainable code that follows project conventions. \
Handle errors gracefully and consider edge cases. Keep changes focused and incremental \
to facilitate review.\n\n\
**Testing:** Write tests that verify correctness across normal operation, edge cases, and error paths. \
Ensure existing tests continue to pass after changes. Aim for meaningful coverage rather than \
metric targets.\n\n\
**Code Quality:** Refactor code to improve readability, performance, and maintainability when \
appropriate. Follow established patterns in the codebase. Focus areas include {}.\n\n\
**Technical Documentation:** Document implementation decisions, API contracts, and non-obvious \
behavior. Keep documentation close to the code it describes and update it alongside code changes.",
            specs_display.join(", ")
        ),
        RoleCategory::Operations => format!(
            "**Infrastructure Management:** Maintain and improve infrastructure using automation and \
infrastructure-as-code practices. Ensure systems are reliable, secure, and cost-effective.\n\n\
**Deployment and Delivery:** Manage deployment pipelines and release processes. Ensure changes \
are applied safely with proper testing, approval gates, and rollback capabilities.\n\n\
**Monitoring and Observability:** Build and maintain monitoring systems that provide visibility \
into service health, performance, and reliability. Focus areas include {}.\n\n\
**Incident Response:** Respond to operational incidents with structured procedures. Diagnose root \
causes, restore service, and implement preventive measures to avoid recurrence.",
            specs_display.join(", ")
        ),
        RoleCategory::Creative => format!(
            "**Content Creation:** Produce clear, accurate, and well-structured content appropriate for \
the target audience. Balance technical depth with readability. Maintain consistent voice and \
tone throughout all deliverables.\n\n\
**Research and Accuracy:** Verify all factual claims before including them in content. Cite sources \
for technical assertions. Distinguish established facts from opinions or recommendations.\n\n\
**Structure and Flow:** Organize content with logical structure, clear headings, and smooth \
transitions between sections. Focus areas include {}.\n\n\
**Quality Assurance:** Review content for grammar, consistency, formatting, and technical accuracy \
before delivery. Ensure content meets the project's style guide and editorial standards.",
            specs_display.join(", ")
        ),
    }
}

// ── Specialization Inference ─────────────────────────────────────────────────

/// Infer specialization slugs from description.
/// Returns 3-8 slugs. Pads with category defaults if too few keyword matches.
pub fn infer_specializations(description: &str, category: RoleCategory) -> Vec<String> {
    let lower = description.to_lowercase();
    let normalized = lower.replace(['-', ' '], "_");

    // Keyword to specialization mapping per category
    let keyword_specs = specialization_keywords(category);

    let mut matched: Vec<String> = Vec::new();
    for (keyword, spec) in &keyword_specs {
        if normalized.contains(keyword) && !matched.contains(spec) {
            matched.push(spec.clone());
        }
    }

    // Pad with category defaults if too few matches
    let defaults = category.default_specializations();
    for default in defaults {
        if matched.len() >= 8 {
            break;
        }
        let s = default.to_string();
        if !matched.contains(&s) {
            matched.push(s);
        }
    }

    // Ensure at least 3
    while matched.len() < 3 {
        matched.push(format!("general_{}", category.to_string().to_lowercase()));
    }

    // Cap at 8
    matched.truncate(8);
    matched
}

/// Keyword-to-specialization mappings for each category.
fn specialization_keywords(category: RoleCategory) -> Vec<(&'static str, String)> {
    match category {
        RoleCategory::Offensive => vec![
            ("web", "web_vulnerabilities".into()),
            ("api", "api_security".into()),
            ("auth", "authentication_bypass".into()),
            ("injection", "injection_attacks".into()),
            ("endpoint", "endpoint_mapping".into()),
            ("privilege", "privilege_escalation".into()),
            ("mobile", "mobile_security".into()),
            ("cloud", "cloud_security".into()),
            ("network", "network_penetration".into()),
            ("exploit", "exploitation".into()),
            ("recon", "attack_surface_mapping".into()),
            ("payload", "payload_development".into()),
        ],
        RoleCategory::Defensive => vec![
            ("incident", "incident_response".into()),
            ("detect", "threat_detection".into()),
            ("monitor", "monitoring".into()),
            ("forensic", "forensics".into()),
            ("malware", "malware_analysis".into()),
            ("siem", "siem_management".into()),
            ("log", "log_analysis".into()),
            ("alert", "alert_triage".into()),
            ("threat", "threat_hunting".into()),
            ("contain", "containment".into()),
            ("edr", "endpoint_detection".into()),
        ],
        RoleCategory::Compliance => vec![
            ("pci", "pci_dss".into()),
            ("gdpr", "gdpr".into()),
            ("hipaa", "hipaa".into()),
            ("soc2", "soc2".into()),
            ("iso", "iso27001".into()),
            ("nist", "nist".into()),
            ("owasp", "owasp".into()),
            ("audit", "audit_management".into()),
            ("evidence", "evidence_collection".into()),
            ("policy", "policy_review".into()),
            ("gap", "gap_analysis".into()),
            ("risk", "risk_assessment".into()),
        ],
        RoleCategory::Architecture => vec![
            ("threat", "threat_modeling".into()),
            ("design", "design_patterns".into()),
            ("architect", "architecture_review".into()),
            ("risk", "risk_assessment".into()),
            ("compliance", "compliance".into()),
            ("cloud", "cloud_architecture".into()),
            ("micro", "microservices".into()),
            ("integrat", "integration_design".into()),
            ("security", "security_architecture".into()),
            ("data", "data_architecture".into()),
        ],
        RoleCategory::Research => vec![
            ("osint", "osint".into()),
            ("recon", "reconnaissance".into()),
            ("cve", "cve_research".into()),
            ("endpoint", "endpoint_mapping".into()),
            ("supply", "supply_chain".into()),
            ("document", "documentation_analysis".into()),
            ("intellig", "intelligence_gathering".into()),
            ("dns", "dns_enumeration".into()),
            ("fingerprint", "technology_fingerprinting".into()),
            ("certificate", "certificate_analysis".into()),
        ],
        RoleCategory::Development => vec![
            ("frontend", "frontend".into()),
            ("backend", "backend".into()),
            ("api", "api_development".into()),
            ("database", "database".into()),
            ("test", "testing".into()),
            ("ci", "ci_cd".into()),
            ("refactor", "refactoring".into()),
            ("react", "frontend".into()),
            ("node", "backend".into()),
            ("rust", "systems_programming".into()),
            ("python", "scripting".into()),
            ("security", "secure_development".into()),
        ],
        RoleCategory::Operations => vec![
            ("kubernetes", "kubernetes".into()),
            ("k8s", "kubernetes".into()),
            ("docker", "containerization".into()),
            ("terraform", "infrastructure_as_code".into()),
            ("ansible", "configuration_management".into()),
            ("aws", "aws".into()),
            ("gcp", "gcp".into()),
            ("azure", "azure".into()),
            ("monitor", "monitoring".into()),
            ("pipeline", "ci_cd_pipelines".into()),
            ("deploy", "deployment".into()),
            ("sre", "site_reliability".into()),
        ],
        RoleCategory::Creative => vec![
            ("technical", "technical_writing".into()),
            ("tutorial", "tutorials".into()),
            ("guide", "guides".into()),
            ("present", "presentations".into()),
            ("report", "report_writing".into()),
            ("document", "documentation".into()),
            ("content", "content_strategy".into()),
            ("blog", "blog_posts".into()),
            ("narrative", "narrative_design".into()),
            ("copy", "copywriting".into()),
        ],
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_category_offensive() {
        assert_eq!(
            detect_category("Penetration testing specialist for web app vulnerabilities and exploit development"),
            RoleCategory::Offensive
        );
        assert_eq!(
            detect_category("Red team operator focused on attack simulation and bypass techniques"),
            RoleCategory::Offensive
        );
    }

    #[test]
    fn test_detect_category_development() {
        assert_eq!(
            detect_category("Backend developer for building REST APIs with Node.js and database integration"),
            RoleCategory::Development
        );
        assert_eq!(
            detect_category("Fullstack developer to implement and refactor the frontend React components"),
            RoleCategory::Development
        );
    }

    #[test]
    fn test_detect_category_research() {
        assert_eq!(
            detect_category("OSINT researcher for reconnaissance and CVE analysis of target infrastructure"),
            RoleCategory::Research
        );
    }

    #[test]
    fn test_detect_category_ambiguous_prefers_less_privileged() {
        // "write" matches Creative, "document" matches both Creative and Research
        // With equal scores, less privileged (Creative=0) wins over Research(1)
        let cat = detect_category("write and document content");
        assert_eq!(cat, RoleCategory::Creative);
    }

    #[test]
    fn test_detect_category_empty_fallback() {
        assert_eq!(detect_category(""), RoleCategory::Development);
        assert_eq!(detect_category("some random unrelated text with no keywords"), RoleCategory::Development);
    }

    #[test]
    fn test_generate_role_yaml_has_required_fields() {
        let yaml = generate_role_yaml("test_scanner", "Automated security scanner", RoleCategory::Offensive);
        let value: serde_yml::Value = serde_yml::from_str(&yaml).expect("Generated YAML should be valid");

        assert_eq!(value["name"].as_str().unwrap(), "test scanner");
        assert_eq!(value["id"].as_str().unwrap(), "test_scanner");
        assert!(value["icon"].as_str().is_some());
        assert!(value["description"].as_str().is_some());
        assert!(value["system_prompt_ref"].as_str().is_some());
        assert_eq!(value["default_trust_level"].as_str().unwrap(), "restricted");
        assert!(value["tools_allowed"].as_sequence().is_some());
        assert!(value["specializations"].as_sequence().is_some());
        assert!(value["elo"]["initial"].as_u64().is_some());
        assert!(value["elo"]["categories"].as_mapping().is_some());
        assert!(value["mentoring"].as_mapping().is_some());
    }

    #[test]
    fn test_generate_role_yaml_no_permissions_for_research() {
        let yaml = generate_role_yaml("intel_analyst", "Research intelligence analyst", RoleCategory::Research);
        let value: serde_yml::Value = serde_yml::from_str(&yaml).expect("Generated YAML should be valid");
        assert!(value["permissions"].is_null(), "Research roles should not have a permissions block");
    }

    #[test]
    fn test_generate_role_yaml_has_permissions_for_development() {
        let yaml = generate_role_yaml("rust_dev", "Rust backend developer", RoleCategory::Development);
        let value: serde_yml::Value = serde_yml::from_str(&yaml).expect("Generated YAML should be valid");
        assert!(value["permissions"]["bash_patterns"].as_sequence().is_some(), "Development roles should have bash_patterns");
    }

    #[test]
    fn test_generate_role_prompt_has_5_sections() {
        let prompt = generate_role_prompt("test_role", "A test role for validation", RoleCategory::Development);
        assert!(prompt.contains("# Test Role"), "Should have title");
        assert!(prompt.contains("## Core Responsibilities"), "Should have Core Responsibilities section");
        assert!(prompt.contains("## Methodology"), "Should have Methodology section");
        assert!(prompt.contains("## Escalation"), "Should have Escalation section");
        assert!(prompt.contains("## Output Format"), "Should have Output Format section");
        assert!(prompt.contains("## Boundaries"), "Should have Boundaries section");
    }

    #[test]
    fn test_generate_role_prompt_no_todos_or_comments() {
        let categories = [
            RoleCategory::Offensive, RoleCategory::Defensive, RoleCategory::Compliance,
            RoleCategory::Architecture, RoleCategory::Research, RoleCategory::Development,
            RoleCategory::Operations, RoleCategory::Creative,
        ];
        for cat in &categories {
            let prompt = generate_role_prompt("test_role", "A test role", *cat);
            assert!(!prompt.contains("TODO"), "Prompt for {:?} should not contain TODO", cat);
            assert!(!prompt.contains("customize"), "Prompt for {:?} should not contain 'customize'", cat);
            assert!(!prompt.contains("<!--"), "Prompt for {:?} should not contain HTML comments", cat);
        }
    }

    #[test]
    fn test_infer_specializations_bounds() {
        // Minimal description — should still return 3-8
        let specs = infer_specializations("a role", RoleCategory::Development);
        assert!(specs.len() >= 3, "Should return at least 3 specializations, got {}", specs.len());
        assert!(specs.len() <= 8, "Should return at most 8 specializations, got {}", specs.len());

        // Rich description — should still cap at 8
        let specs = infer_specializations(
            "frontend backend api database test ci refactor react node rust python security deploy",
            RoleCategory::Development,
        );
        assert!(specs.len() <= 8, "Should return at most 8 specializations, got {}", specs.len());
        assert!(specs.len() >= 3, "Should return at least 3 specializations, got {}", specs.len());
    }

    #[test]
    fn test_category_display_and_from_str() {
        let categories = [
            RoleCategory::Offensive, RoleCategory::Defensive, RoleCategory::Compliance,
            RoleCategory::Architecture, RoleCategory::Research, RoleCategory::Development,
            RoleCategory::Operations, RoleCategory::Creative,
        ];
        for cat in &categories {
            let display = cat.to_string();
            let parsed: RoleCategory = display.parse().expect("Should roundtrip");
            assert_eq!(*cat, parsed);
        }
    }

    #[test]
    fn test_detect_category_defensive() {
        assert_eq!(
            detect_category("SOC analyst for incident response and threat detection with SIEM monitoring"),
            RoleCategory::Defensive
        );
    }

    #[test]
    fn test_detect_category_compliance() {
        assert_eq!(
            detect_category("PCI-DSS compliance auditor for standards mapping and governance"),
            RoleCategory::Compliance
        );
    }

    #[test]
    fn test_detect_category_operations() {
        assert_eq!(
            detect_category("SRE engineer managing Kubernetes infrastructure on AWS with Terraform"),
            RoleCategory::Operations
        );
    }

    #[test]
    fn test_detect_category_creative() {
        assert_eq!(
            detect_category("Technical writer creating tutorials, guides, and documentation content"),
            RoleCategory::Creative
        );
    }

    #[test]
    fn test_detect_category_architecture() {
        assert_eq!(
            detect_category("Security architect for threat modeling and system design review"),
            RoleCategory::Architecture
        );
    }

    #[test]
    fn test_all_categories_have_unique_icons() {
        let categories = [
            RoleCategory::Offensive, RoleCategory::Defensive, RoleCategory::Compliance,
            RoleCategory::Architecture, RoleCategory::Research, RoleCategory::Development,
            RoleCategory::Operations, RoleCategory::Creative,
        ];
        let icons: Vec<&str> = categories.iter().map(|c| c.icon()).collect();
        let unique: std::collections::HashSet<&&str> = icons.iter().collect();
        assert_eq!(icons.len(), unique.len(), "All categories should have unique icons");
    }

    #[test]
    fn test_all_categories_have_5_methodology_phases() {
        let categories = [
            RoleCategory::Offensive, RoleCategory::Defensive, RoleCategory::Compliance,
            RoleCategory::Architecture, RoleCategory::Research, RoleCategory::Development,
            RoleCategory::Operations, RoleCategory::Creative,
        ];
        for cat in &categories {
            let phases = cat.methodology_phases();
            assert_eq!(phases.len(), 5, "{:?} should have exactly 5 phases", cat);
        }
    }
}

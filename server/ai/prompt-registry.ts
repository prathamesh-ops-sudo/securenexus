import { logger } from "../logger";

const log = logger.child("prompt-registry");

export interface PromptTemplate {
  id: string;
  version: number;
  name: string;
  description: string;
  tier: "triage" | "narrative" | "correlation" | "health" | "general";
  systemPrompt: string;
  userTemplate: string;
  outputSchema?: Record<string, string>;
  maxTokens: number;
  temperature: number;
  deprecated?: boolean;
  deprecatedAt?: string;
  supersededBy?: string;
  createdAt: string;
  updatedAt: string;
  tags: string[];
}

interface PromptAuditEntry {
  promptId: string;
  version: number;
  action: "registered" | "updated" | "deprecated" | "invoked";
  timestamp: string;
  metadata?: Record<string, unknown>;
}

const registry = new Map<string, PromptTemplate>();
const versionHistory = new Map<string, PromptTemplate[]>();
const auditLog: PromptAuditEntry[] = [];
const MAX_AUDIT_ENTRIES = 2000;

function recordAudit(promptId: string, version: number, action: PromptAuditEntry["action"], metadata?: Record<string, unknown>): void {
  auditLog.push({ promptId, version, action, timestamp: new Date().toISOString(), metadata });
  if (auditLog.length > MAX_AUDIT_ENTRIES) auditLog.splice(0, auditLog.length - MAX_AUDIT_ENTRIES);
}

export function registerPrompt(template: PromptTemplate): void {
  const existing = registry.get(template.id);
  if (existing && existing.version >= template.version) {
    log.warn("Skipping prompt registration — same or newer version exists", { id: template.id, existing: existing.version, incoming: template.version });
    return;
  }

  registry.set(template.id, template);

  const history = versionHistory.get(template.id) || [];
  history.push({ ...template });
  versionHistory.set(template.id, history);

  recordAudit(template.id, template.version, existing ? "updated" : "registered");
  log.info("Prompt registered", { id: template.id, version: template.version, tier: template.tier });
}

export function getPrompt(id: string): PromptTemplate | undefined {
  return registry.get(id);
}

export function getPromptVersion(id: string, version: number): PromptTemplate | undefined {
  const history = versionHistory.get(id);
  if (!history) return undefined;
  return history.find((p) => p.version === version);
}

export function getAllPrompts(): PromptTemplate[] {
  return Array.from(registry.values());
}

export function getPromptsByTier(tier: PromptTemplate["tier"]): PromptTemplate[] {
  return Array.from(registry.values()).filter((p) => p.tier === tier);
}

export function deprecatePrompt(id: string, supersededBy?: string): boolean {
  const prompt = registry.get(id);
  if (!prompt) return false;
  prompt.deprecated = true;
  prompt.deprecatedAt = new Date().toISOString();
  if (supersededBy) prompt.supersededBy = supersededBy;
  recordAudit(id, prompt.version, "deprecated", { supersededBy });
  log.info("Prompt deprecated", { id, version: prompt.version, supersededBy });
  return true;
}

export function recordPromptInvocation(id: string, version: number, metadata?: Record<string, unknown>): void {
  recordAudit(id, version, "invoked", metadata);
}

export function getPromptAuditLog(promptId?: string, limit: number = 50): PromptAuditEntry[] {
  const filtered = promptId ? auditLog.filter((e) => e.promptId === promptId) : auditLog;
  return filtered.slice(-limit);
}

export function getPromptVersionHistory(id: string): PromptTemplate[] {
  return versionHistory.get(id) || [];
}

export function getPromptCatalogSummary(): {
  totalPrompts: number;
  byTier: Record<string, number>;
  deprecated: number;
  totalVersions: number;
  totalInvocations: number;
} {
  const byTier: Record<string, number> = {};
  let deprecated = 0;
  let totalVersions = 0;

  for (const prompt of Array.from(registry.values())) {
    byTier[prompt.tier] = (byTier[prompt.tier] || 0) + 1;
    if (prompt.deprecated) deprecated++;
  }

  for (const history of Array.from(versionHistory.values())) {
    totalVersions += history.length;
  }

  const totalInvocations = auditLog.filter((e) => e.action === "invoked").length;

  return {
    totalPrompts: registry.size,
    byTier,
    deprecated,
    totalVersions,
    totalInvocations,
  };
}

const CYBER_ENGINE_IDENTITY = `You are SecureNexus Cyber Analyst — a specialized cybersecurity instruct model purpose-built for Security Operations Center (SOC) analysis. You operate under strict analytical protocols derived from the following frameworks:

OPERATIONAL FRAMEWORKS:
- MITRE ATT&CK Enterprise Matrix v15 (14 Tactics, 201 Techniques, 424 Sub-techniques)
- NIST SP 800-61r2 Incident Response Lifecycle
- Lockheed Martin Cyber Kill Chain
- Diamond Model of Intrusion Analysis (Adversary, Infrastructure, Capability, Victim)
- OCSF (Open Cybersecurity Schema Framework)

ANALYSIS PROTOCOLS:
1. Evidence-Based Reasoning: Every assessment must cite observable indicators. Never speculate without labeling confidence levels.
2. Kill Chain Mapping: Map all findings to both MITRE ATT&CK and Cyber Kill Chain stages.
3. IOC Extraction: Extract all Indicators of Compromise (IPs, domains, file hashes, URLs, email addresses, registry keys, mutexes).
4. Confidence Scoring: Use calibrated confidence (0.0-1.0): >=0.9 confirmed, 0.7-0.89 high, 0.5-0.69 moderate, 0.3-0.49 low, <0.3 speculative.
5. False Positive Assessment: Always evaluate false positive probability with reasoning.
6. Severity Calibration: Map to CVSS-aligned severity (critical >=9.0, high 7.0-8.9, medium 4.0-6.9, low 0.1-3.9, informational 0.0).

OUTPUT REQUIREMENTS:
- Respond ONLY with valid JSON matching the requested schema
- No markdown formatting, no explanatory text outside the JSON
- All timestamps in ISO 8601 format
- All MITRE references use official technique IDs (e.g., T1059.001)
- All IOCs extracted and categorized by type`;

export function initializeDefaultPrompts(): void {
  const now = new Date().toISOString();

  registerPrompt({
    id: "correlation",
    version: 1,
    name: "Alert Correlation Engine",
    description: "Correlates security alerts into attack chains using MITRE ATT&CK, Kill Chain, and Diamond Model frameworks.",
    tier: "correlation",
    systemPrompt: `${CYBER_ENGINE_IDENTITY}

CORRELATION SPECIALIZATION:
You are executing Phase 2 (Detection & Analysis) of the NIST IR lifecycle.
Apply the following correlation heuristics in order of priority:
1. TEMPORAL: Alerts within 15-minute windows from related sources
2. TOPOLOGICAL: Shared source/destination IPs, hostnames, or user accounts
3. BEHAVIORAL: Sequential MITRE ATT&CK technique chains (e.g., T1566->T1059->T1053->T1048)
4. INDICATOR: Shared IOCs (file hashes, domains, IPs, URLs)
5. CAMPAIGN: TTP patterns matching known threat actor profiles
6. THREAT_INTEL: Cross-reference IOCs against provided threat intelligence enrichment and OSINT feed data to strengthen correlation confidence

Map each correlated group to:
- Lockheed Martin Kill Chain phases (Reconnaissance, Weaponization, Delivery, Exploitation, Installation, C2, Actions on Objectives)
- Diamond Model quadrants (Adversary, Infrastructure, Capability, Victim)
- MITRE ATT&CK Enterprise tactics and techniques`,
    userTemplate: `Correlate these {{alertCount}} security alerts. Identify attack chains, lateral movement patterns, and coordinated campaigns.

ALERT TELEMETRY:
{{alertTelemetry}}

Respond with this exact JSON structure:
{
  "correlatedGroups": [
    {
      "groupName": "descriptive attack chain name",
      "alertIds": ["id1", "id2"],
      "confidence": 0.85,
      "reasoning": "evidence-based explanation citing specific indicators",
      "suggestedIncidentTitle": "concise incident title",
      "severity": "critical|high|medium|low",
      "mitreTactics": ["Initial Access", "Execution"],
      "mitreTechniques": ["T1566.001", "T1059.001"],
      "killChainPhases": ["Delivery", "Exploitation"],
      "diamondModel": {
        "adversary": "threat actor profile or unknown",
        "infrastructure": ["malicious IPs/domains"],
        "capability": "attack capability description",
        "victim": ["affected hosts/users"]
      }
    }
  ],
  "uncorrelatedAlertIds": ["standalone alert ids"],
  "overallAssessment": "strategic threat assessment",
  "threatLandscape": "broader threat context and recommendations"
}`,
    outputSchema: {
      correlatedGroups: "array of correlation group objects",
      uncorrelatedAlertIds: "array of alert IDs not correlated",
      overallAssessment: "string",
      threatLandscape: "string",
    },
    maxTokens: 4096,
    temperature: 0.1,
    createdAt: now,
    updatedAt: now,
    tags: ["correlation", "mitre", "kill-chain", "diamond-model"],
  });

  registerPrompt({
    id: "narrative",
    version: 1,
    name: "Incident Narrative Generator",
    description: "Generates attacker-centric incident narratives with full MITRE mapping, IOC extraction, and citation-backed analysis.",
    tier: "narrative",
    systemPrompt: `${CYBER_ENGINE_IDENTITY}

NARRATIVE SPECIALIZATION:
You are executing Phase 2-3 (Detection/Analysis -> Containment) of the NIST IR lifecycle.
Generate an attacker-centric narrative that reconstructs the full intrusion timeline.
Apply the Lockheed Martin Cyber Kill Chain and Diamond Model to structure the narrative.

NARRATIVE REQUIREMENTS:
1. Reconstruct attacker actions in chronological order
2. Map each action to MITRE ATT&CK techniques
3. Identify the Kill Chain phase for each stage
4. Apply the Diamond Model to characterize the intrusion
5. Extract all IOCs with type classification (ip, domain, hash, url, email, registry, mutex)
6. Provide actionable containment and mitigation steps aligned with NIST SP 800-61r2
7. Assign a calibrated risk score (0-100) based on asset criticality, data sensitivity, and attack sophistication
8. CITATION REQUIREMENT: Every factual claim in the narrative MUST include an inline citation referencing the alert ID that provides the evidence. Use the format [Alert <alertId>] where alertId is the exact alert ID from the telemetry. For example: "Mimikatz credential dumping was detected on the domain controller [Alert abc123]."
9. Every paragraph in the narrative must cite at least one alert.
10. THREAT INTELLIGENCE: Incorporate provided threat intelligence enrichment and OSINT feed data into the narrative, citing which IOCs were confirmed malicious by external sources`,
    userTemplate: `Generate a comprehensive incident narrative for this security incident.

INCIDENT CONTEXT:
{{incidentContext}}

ASSOCIATED ALERT TELEMETRY ({{alertCount}} alerts):
{{alertTelemetry}}

Respond with this exact JSON structure:
{
  "narrative": "detailed multi-paragraph attacker-centric narrative with inline [Alert <id>] citations",
  "citedAlertIds": ["list of all alert IDs explicitly cited in the narrative"],
  "summary": "one-line executive summary",
  "attackTimeline": [
    {"timestamp": "ISO 8601", "description": "action description", "alertId": "source alert", "mitreTechnique": "T1xxx.xxx"}
  ],
  "attackerProfile": {
    "ttps": ["TTP descriptions"],
    "sophistication": "nation-state|advanced-persistent|organized-crime|intermediate|opportunistic",
    "likelyMotivation": "financial|espionage|hacktivism|destruction|unknown",
    "estimatedOrigin": "geographic/organizational origin assessment",
    "diamondModel": {
      "adversary": "threat actor characterization",
      "infrastructure": ["C2 servers, domains, IPs used"],
      "capability": "tooling and technique sophistication",
      "victim": ["targeted assets, users, systems"]
    }
  },
  "killChainAnalysis": [
    {"phase": "Kill Chain phase", "description": "what occurred in this phase", "evidence": ["supporting indicators"]}
  ],
  "mitigationSteps": ["NIST-aligned containment and recovery steps"],
  "iocs": [{"type": "ip|domain|hash|url|email|registry|mutex", "value": "indicator value", "context": "where/how observed"}],
  "riskScore": 85,
  "nistPhase": "Detection|Analysis|Containment|Eradication|Recovery"
}`,
    outputSchema: {
      narrative: "string with [Alert <id>] citations",
      citedAlertIds: "array of alert ID strings",
      summary: "string",
      attackTimeline: "array of timeline event objects",
      attackerProfile: "attacker characterization object",
      killChainAnalysis: "array of kill chain phase objects",
      mitigationSteps: "array of strings",
      iocs: "array of IOC objects",
      riskScore: "number 0-100",
      nistPhase: "string",
    },
    maxTokens: 6144,
    temperature: 0.1,
    createdAt: now,
    updatedAt: now,
    tags: ["narrative", "incident-response", "mitre", "kill-chain", "ioc-extraction"],
  });

  registerPrompt({
    id: "triage",
    version: 1,
    name: "Alert Triage Analyst",
    description: "Real-time alert triage with MITRE classification, false positive assessment, and actionable containment advice.",
    tier: "triage",
    systemPrompt: `${CYBER_ENGINE_IDENTITY}

TRIAGE SPECIALIZATION:
You are executing real-time alert triage as a Tier 2 SOC Analyst.
Apply the following triage protocol:
1. CLASSIFY: Map to MITRE ATT&CK tactic/technique and Kill Chain phase
2. ASSESS: Evaluate severity using CVSS-aligned scoring and environmental context
3. DETERMINE: Calculate false positive probability with evidence-based reasoning
4. PRIORITIZE: Assign priority (1=immediate, 2=urgent, 3=normal, 4=low, 5=informational)
5. RECOMMEND: Provide specific, actionable next steps for the analyst
6. ESCALATE: Determine if escalation to Tier 3 or incident commander is needed
7. CONTAIN: Provide immediate containment advice if threat is active
8. INTEL-AUGMENTED: Cross-reference alert IOCs against provided threat intelligence enrichment and OSINT feed matches to validate threat classification

TRIAGE DECISION MATRIX:
- P1 (Immediate): Active data exfiltration, ransomware execution, confirmed APT, critical asset compromise
- P2 (Urgent): Lateral movement detected, privilege escalation, C2 beacon, credential theft
- P3 (Normal): Suspicious behavior, policy violation, reconnaissance activity
- P4 (Low): Informational alerts, failed attacks, known benign anomalies
- P5 (Informational): Audit events, configuration changes, system health`,
    userTemplate: `Triage this security alert with full analytical assessment.

ALERT TELEMETRY:
{{alertTelemetry}}

Respond with this exact JSON structure:
{
  "severity": "critical|high|medium|low|informational",
  "priority": 1,
  "category": "MITRE-aligned category",
  "recommendedAction": "specific actionable next step for the analyst",
  "reasoning": "evidence-based triage reasoning citing specific indicators",
  "mitreTactic": "MITRE ATT&CK Tactic",
  "mitreTechnique": "T1xxx.xxx",
  "killChainPhase": "Kill Chain phase",
  "falsePositiveLikelihood": 0.15,
  "falsePositiveReasoning": "why this is or is not likely a false positive",
  "relatedIocs": [{"type": "ip|domain|hash|url", "value": "indicator value"}],
  "nistClassification": "NIST incident category",
  "escalationRequired": false,
  "containmentAdvice": "immediate containment steps if threat is active"
}`,
    outputSchema: {
      severity: "string enum",
      priority: "number 1-5",
      category: "string",
      recommendedAction: "string",
      reasoning: "string",
      mitreTactic: "string",
      mitreTechnique: "string T1xxx.xxx",
      killChainPhase: "string",
      falsePositiveLikelihood: "number 0-1",
      relatedIocs: "array of IOC objects",
      escalationRequired: "boolean",
      containmentAdvice: "string",
    },
    maxTokens: 2048,
    temperature: 0.05,
    createdAt: now,
    updatedAt: now,
    tags: ["triage", "classification", "mitre", "false-positive"],
  });

  registerPrompt({
    id: "health-check",
    version: 1,
    name: "Model Health Check",
    description: "Lightweight health probe to verify model endpoint availability.",
    tier: "health",
    systemPrompt: "You are a health check responder. Respond only with the exact JSON requested.",
    userTemplate: `Respond with exactly: {"status":"operational"}`,
    maxTokens: 50,
    temperature: 0.0,
    createdAt: now,
    updatedAt: now,
    tags: ["health", "diagnostic"],
  });

  log.info("Default prompts initialized", { count: registry.size });
}

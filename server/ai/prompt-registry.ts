import { pool } from "../db";
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
  isActive?: boolean;
}

interface PromptAuditEntry {
  promptId: string;
  version: number;
  action: "registered" | "updated" | "deprecated" | "invoked";
  timestamp: string;
  metadata?: Record<string, unknown>;
}

const TABLE_ENSURED = { done: false };

async function ensureTables(): Promise<void> {
  if (TABLE_ENSURED.done) return;
  await pool.query(`
    CREATE TABLE IF NOT EXISTS ai_prompts (
      id VARCHAR PRIMARY KEY,
      org_id VARCHAR,
      name VARCHAR NOT NULL,
      description TEXT NOT NULL DEFAULT '',
      tier VARCHAR NOT NULL DEFAULT 'general',
      system_prompt TEXT NOT NULL,
      user_template TEXT NOT NULL,
      output_schema JSONB,
      max_tokens INTEGER NOT NULL DEFAULT 2048,
      temperature DOUBLE PRECISION NOT NULL DEFAULT 0.1,
      version INTEGER NOT NULL DEFAULT 1,
      deprecated BOOLEAN NOT NULL DEFAULT false,
      deprecated_at TIMESTAMP,
      superseded_by VARCHAR,
      tags JSONB NOT NULL DEFAULT '[]',
      is_active BOOLEAN NOT NULL DEFAULT true,
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_ai_prompts_org ON ai_prompts (org_id)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_ai_prompts_tier ON ai_prompts (tier)`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS ai_prompt_versions (
      id SERIAL PRIMARY KEY,
      prompt_id VARCHAR NOT NULL,
      org_id VARCHAR,
      version INTEGER NOT NULL,
      name VARCHAR NOT NULL,
      description TEXT NOT NULL DEFAULT '',
      tier VARCHAR NOT NULL DEFAULT 'general',
      system_prompt TEXT NOT NULL,
      user_template TEXT NOT NULL,
      output_schema JSONB,
      max_tokens INTEGER NOT NULL DEFAULT 2048,
      temperature DOUBLE PRECISION NOT NULL DEFAULT 0.1,
      tags JSONB NOT NULL DEFAULT '[]',
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
  await pool.query(
    `CREATE UNIQUE INDEX IF NOT EXISTS idx_ai_prompt_versions_prompt_version ON ai_prompt_versions (prompt_id, version)`,
  );
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_ai_prompt_versions_prompt ON ai_prompt_versions (prompt_id)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_ai_prompt_versions_org ON ai_prompt_versions (org_id)`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS ai_prompt_audit_log (
      id SERIAL PRIMARY KEY,
      prompt_id VARCHAR NOT NULL,
      version INTEGER NOT NULL,
      action VARCHAR NOT NULL,
      metadata JSONB,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_ai_prompt_audit_prompt ON ai_prompt_audit_log (prompt_id)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_ai_prompt_audit_action ON ai_prompt_audit_log (action)`);

  TABLE_ENSURED.done = true;
}

function rowToTemplate(row: Record<string, unknown>): PromptTemplate {
  return {
    id: row.id as string,
    version: row.version as number,
    name: row.name as string,
    description: (row.description as string) || "",
    tier: (row.tier as PromptTemplate["tier"]) || "general",
    systemPrompt: row.system_prompt as string,
    userTemplate: row.user_template as string,
    outputSchema: row.output_schema as Record<string, string> | undefined,
    maxTokens: row.max_tokens as number,
    temperature: row.temperature as number,
    deprecated: (row.deprecated as boolean) || false,
    deprecatedAt: row.deprecated_at ? (row.deprecated_at as Date).toISOString() : undefined,
    supersededBy: row.superseded_by as string | undefined,
    createdAt: row.created_at ? (row.created_at as Date).toISOString() : new Date().toISOString(),
    updatedAt: row.updated_at ? (row.updated_at as Date).toISOString() : new Date().toISOString(),
    tags: (row.tags as string[]) || [],
    isActive: row.is_active as boolean,
  };
}

async function recordAudit(
  promptId: string,
  version: number,
  action: PromptAuditEntry["action"],
  metadata?: Record<string, unknown>,
): Promise<void> {
  await ensureTables();
  await pool.query(`INSERT INTO ai_prompt_audit_log (prompt_id, version, action, metadata) VALUES ($1, $2, $3, $4)`, [
    promptId,
    version,
    action,
    metadata ? JSON.stringify(metadata) : null,
  ]);
}

export async function registerPrompt(template: PromptTemplate): Promise<void> {
  await ensureTables();

  const existing = await pool.query(`SELECT id, version FROM ai_prompts WHERE id = $1`, [template.id]);

  if (existing.rows.length > 0 && existing.rows[0].version >= template.version) {
    log.warn("Skipping prompt registration \u2014 same or newer version exists", {
      id: template.id,
      existing: existing.rows[0].version,
      incoming: template.version,
    });
    return;
  }

  const action = existing.rows.length > 0 ? "updated" : "registered";

  await pool.query(
    `INSERT INTO ai_prompts (id, org_id, name, description, tier, system_prompt, user_template, output_schema, max_tokens, temperature, version, deprecated, deprecated_at, superseded_by, tags, is_active, created_at, updated_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, NOW(), NOW())
     ON CONFLICT (id) DO UPDATE SET
       name = EXCLUDED.name,
       description = EXCLUDED.description,
       tier = EXCLUDED.tier,
       system_prompt = EXCLUDED.system_prompt,
       user_template = EXCLUDED.user_template,
       output_schema = EXCLUDED.output_schema,
       max_tokens = EXCLUDED.max_tokens,
       temperature = EXCLUDED.temperature,
       version = EXCLUDED.version,
       deprecated = EXCLUDED.deprecated,
       deprecated_at = EXCLUDED.deprecated_at,
       superseded_by = EXCLUDED.superseded_by,
       is_active = EXCLUDED.is_active,
       tags = EXCLUDED.tags,
       updated_at = NOW()`,
    [
      template.id,
      null,
      template.name,
      template.description,
      template.tier,
      template.systemPrompt,
      template.userTemplate,
      template.outputSchema ? JSON.stringify(template.outputSchema) : null,
      template.maxTokens,
      template.temperature,
      template.version,
      template.deprecated || false,
      template.deprecatedAt || null,
      template.supersededBy || null,
      JSON.stringify(template.tags || []),
      true,
    ],
  );

  await pool.query(
    `INSERT INTO ai_prompt_versions (prompt_id, org_id, version, name, description, tier, system_prompt, user_template, output_schema, max_tokens, temperature, tags)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
     ON CONFLICT (prompt_id, version) DO NOTHING`,
    [
      template.id,
      null,
      template.version,
      template.name,
      template.description,
      template.tier,
      template.systemPrompt,
      template.userTemplate,
      template.outputSchema ? JSON.stringify(template.outputSchema) : null,
      template.maxTokens,
      template.temperature,
      JSON.stringify(template.tags || []),
    ],
  );

  await recordAudit(template.id, template.version, action);
  log.info("Prompt registered", { id: template.id, version: template.version, tier: template.tier });
}

export async function getPrompt(id: string): Promise<PromptTemplate | undefined> {
  await ensureTables();
  const result = await pool.query(`SELECT * FROM ai_prompts WHERE id = $1 AND is_active = true`, [id]);
  if (result.rows.length === 0) return undefined;
  return rowToTemplate(result.rows[0]);
}

export async function getPromptVersion(id: string, version: number): Promise<PromptTemplate | undefined> {
  await ensureTables();
  const result = await pool.query(
    `SELECT pv.*, p.deprecated, p.deprecated_at, p.superseded_by, p.is_active, p.updated_at
     FROM ai_prompt_versions pv
     JOIN ai_prompts p ON p.id = pv.prompt_id
     WHERE pv.prompt_id = $1 AND pv.version = $2`,
    [id, version],
  );
  if (result.rows.length === 0) return undefined;
  const row = result.rows[0];
  return {
    id: row.prompt_id as string,
    version: row.version as number,
    name: row.name as string,
    description: (row.description as string) || "",
    tier: (row.tier as PromptTemplate["tier"]) || "general",
    systemPrompt: row.system_prompt as string,
    userTemplate: row.user_template as string,
    outputSchema: row.output_schema as Record<string, string> | undefined,
    maxTokens: row.max_tokens as number,
    temperature: row.temperature as number,
    deprecated: (row.deprecated as boolean) || false,
    deprecatedAt: row.deprecated_at ? (row.deprecated_at as Date).toISOString() : undefined,
    supersededBy: row.superseded_by as string | undefined,
    createdAt: row.created_at ? (row.created_at as Date).toISOString() : new Date().toISOString(),
    updatedAt: row.updated_at ? (row.updated_at as Date).toISOString() : new Date().toISOString(),
    tags: (row.tags as string[]) || [],
  };
}

export async function getAllPrompts(): Promise<PromptTemplate[]> {
  await ensureTables();
  const result = await pool.query(`SELECT * FROM ai_prompts WHERE is_active = true ORDER BY tier, name`);
  return result.rows.map(rowToTemplate);
}

export async function getPromptsByTier(tier: PromptTemplate["tier"]): Promise<PromptTemplate[]> {
  await ensureTables();
  const result = await pool.query(`SELECT * FROM ai_prompts WHERE tier = $1 AND is_active = true ORDER BY name`, [
    tier,
  ]);
  return result.rows.map(rowToTemplate);
}

export async function deprecatePrompt(id: string, supersededBy?: string): Promise<boolean> {
  await ensureTables();
  const result = await pool.query(
    `UPDATE ai_prompts SET deprecated = true, deprecated_at = NOW(), superseded_by = $2, updated_at = NOW()
     WHERE id = $1 AND is_active = true
     RETURNING version`,
    [id, supersededBy || null],
  );
  if (result.rows.length === 0) return false;
  await recordAudit(id, result.rows[0].version as number, "deprecated", { supersededBy });
  log.info("Prompt deprecated", { id, version: result.rows[0].version, supersededBy });
  return true;
}

export async function deletePrompt(id: string): Promise<boolean> {
  await ensureTables();
  const result = await pool.query(
    `UPDATE ai_prompts SET is_active = false, updated_at = NOW() WHERE id = $1 AND is_active = true RETURNING version`,
    [id],
  );
  if (result.rows.length === 0) return false;
  log.info("Prompt soft-deleted", { id, version: result.rows[0].version });
  return true;
}

export async function recordPromptInvocation(
  id: string,
  version: number,
  metadata?: Record<string, unknown>,
): Promise<void> {
  await recordAudit(id, version, "invoked", metadata);
}

export async function getPromptAuditLog(promptId?: string, limit: number = 50): Promise<PromptAuditEntry[]> {
  await ensureTables();
  const safeLimit = Math.min(Math.max(limit, 1), 500);

  let result;
  if (promptId) {
    result = await pool.query(
      `SELECT prompt_id, version, action, metadata, created_at FROM ai_prompt_audit_log WHERE prompt_id = $1 ORDER BY created_at DESC LIMIT $2`,
      [promptId, safeLimit],
    );
  } else {
    result = await pool.query(
      `SELECT prompt_id, version, action, metadata, created_at FROM ai_prompt_audit_log ORDER BY created_at DESC LIMIT $1`,
      [safeLimit],
    );
  }

  return result.rows.map((row: Record<string, unknown>) => ({
    promptId: row.prompt_id as string,
    version: row.version as number,
    action: row.action as PromptAuditEntry["action"],
    timestamp: row.created_at ? (row.created_at as Date).toISOString() : new Date().toISOString(),
    metadata: row.metadata as Record<string, unknown> | undefined,
  }));
}

export async function getPromptVersionHistory(id: string): Promise<PromptTemplate[]> {
  await ensureTables();
  const result = await pool.query(
    `SELECT pv.*, p.deprecated, p.deprecated_at, p.superseded_by, p.is_active, p.updated_at
     FROM ai_prompt_versions pv
     JOIN ai_prompts p ON p.id = pv.prompt_id
     WHERE pv.prompt_id = $1
     ORDER BY pv.version DESC`,
    [id],
  );

  return result.rows.map((row: Record<string, unknown>) => ({
    id: row.prompt_id as string,
    version: row.version as number,
    name: row.name as string,
    description: (row.description as string) || "",
    tier: (row.tier as PromptTemplate["tier"]) || "general",
    systemPrompt: row.system_prompt as string,
    userTemplate: row.user_template as string,
    outputSchema: row.output_schema as Record<string, string> | undefined,
    maxTokens: row.max_tokens as number,
    temperature: row.temperature as number,
    deprecated: (row.deprecated as boolean) || false,
    deprecatedAt: row.deprecated_at ? (row.deprecated_at as Date).toISOString() : undefined,
    supersededBy: row.superseded_by as string | undefined,
    createdAt: row.created_at ? (row.created_at as Date).toISOString() : new Date().toISOString(),
    updatedAt: row.updated_at ? (row.updated_at as Date).toISOString() : new Date().toISOString(),
    tags: (row.tags as string[]) || [],
  }));
}

export async function getPromptCatalogSummary(): Promise<{
  totalPrompts: number;
  byTier: Record<string, number>;
  deprecated: number;
  totalVersions: number;
  totalInvocations: number;
}> {
  await ensureTables();

  const promptsResult = await pool.query(`SELECT tier, deprecated FROM ai_prompts WHERE is_active = true`);
  const byTier: Record<string, number> = {};
  let deprecated = 0;
  for (const row of promptsResult.rows) {
    const tier = row.tier as string;
    byTier[tier] = (byTier[tier] || 0) + 1;
    if (row.deprecated) deprecated++;
  }

  const versionsResult = await pool.query(`SELECT COUNT(*) as cnt FROM ai_prompt_versions`);
  const totalVersions = parseInt(String(versionsResult.rows[0].cnt), 10) || 0;

  const invocationsResult = await pool.query(
    `SELECT COUNT(*) as cnt FROM ai_prompt_audit_log WHERE action = 'invoked'`,
  );
  const totalInvocations = parseInt(String(invocationsResult.rows[0].cnt), 10) || 0;

  return {
    totalPrompts: promptsResult.rows.length,
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

export async function initializeDefaultPrompts(): Promise<void> {
  const now = new Date().toISOString();

  await registerPrompt({
    id: "correlation",
    version: 1,
    name: "Alert Correlation Engine",
    description:
      "Correlates security alerts into attack chains using MITRE ATT&CK, Kill Chain, and Diamond Model frameworks.",
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

  await registerPrompt({
    id: "narrative",
    version: 1,
    name: "Incident Narrative Generator",
    description:
      "Generates attacker-centric incident narratives with full MITRE mapping, IOC extraction, and citation-backed analysis.",
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

  await registerPrompt({
    id: "triage",
    version: 1,
    name: "Alert Triage Analyst",
    description:
      "Real-time alert triage with MITRE classification, false positive assessment, and actionable containment advice.",
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

  await registerPrompt({
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

  const count = await pool.query(`SELECT COUNT(*) as cnt FROM ai_prompts WHERE is_active = true`);
  log.info("Default prompts initialized", { count: parseInt(String(count.rows[0].cnt), 10) });
}

import { invokeModel } from "./model-gateway";
import { logger } from "../logger";
import { z } from "zod";

const log = logger.child("rule-generator");

const generatedRuleSchema = (ruleField: "sigmaYaml" | "yaraRule") =>
  z.object({
    name: z.string().min(1).max(256),
    description: z.string().max(4000),
    severity: z.enum(["low", "medium", "high", "critical"]),
    mitreTactic: z.string().max(128),
    mitreTechnique: z.string().regex(/^T\d{4}(\.\d{3})?$/),
    tags: z.array(z.string().max(128)).max(50),
    [ruleField]: z.string().max(20000),
    conditionTree: z.record(z.string(), z.unknown()),
    eventTypes: z.array(z.string().max(128)).max(50),
    falsePositiveNotes: z.string().max(4000),
    references: z.array(z.string().max(2000)).max(50),
  });

const ttpExtractionSchema = z.object({
  ttps: z
    .array(
      z.object({
        tactic: z.string().max(128),
        techniqueId: z.string().regex(/^T\d{4}(\.\d{3})?$/),
        techniqueName: z.string().max(256),
        description: z.string().max(4000),
        indicators: z.array(z.string().max(1000)).max(100),
        suggestedDetection: z.string().max(4000),
      }),
    )
    .max(100),
  summary: z.string().max(6000),
  threatActor: z.string().max(512),
  targetSectors: z.array(z.string().max(256)).max(50),
});

const SONNET_MODEL = "amazon.nova-pro-v1:0";

// ─── Prompts ──────────────────────────────────────────────────────────────────

const SIGMA_SYSTEM_PROMPT = `You are an expert detection engineer specializing in Sigma rules.
Given security context (incident data, threat intel, or log patterns), generate a valid Sigma-format detection rule.

Your output MUST be valid JSON with exactly these fields:
{
  "name": "Short descriptive rule name",
  "description": "What this rule detects and why it matters",
  "severity": "low|medium|high|critical",
  "mitreTactic": "MITRE ATT&CK tactic (e.g. initial_access, execution, persistence)",
  "mitreTechnique": "MITRE technique ID (e.g. T1059, T1566)",
  "tags": ["tag1", "tag2"],
  "sigmaYaml": "Full Sigma YAML rule as a string",
  "conditionTree": { "operator": "AND|OR", "conditions": [{"field": "...", "operator": "equals|contains|regex|gt|lt", "value": "..."}] },
  "eventTypes": ["process_start", "file_create", "network_connection", "registry_modify", "dns_query", "auth_event"],
  "falsePositiveNotes": "Known false positive scenarios",
  "references": ["https://..."]
}

Rules should be specific enough to minimize false positives while catching the described threat.
Always map to MITRE ATT&CK tactics and techniques when possible.
Use realistic field names: process.name, process.command_line, file.path, network.destination.ip, etc.`;

const YARA_SYSTEM_PROMPT = `You are an expert malware analyst specializing in YARA rules.
Given security context (malware samples, threat intel, or binary patterns), generate a valid YARA detection rule.

Your output MUST be valid JSON with exactly these fields:
{
  "name": "Short descriptive rule name",
  "description": "What this rule detects",
  "severity": "low|medium|high|critical",
  "mitreTactic": "MITRE ATT&CK tactic",
  "mitreTechnique": "MITRE technique ID",
  "tags": ["tag1", "tag2"],
  "yaraRule": "Full YARA rule as a string",
  "conditionTree": { "operator": "AND", "conditions": [{"field": "file.hash", "operator": "equals", "value": "..."}] },
  "eventTypes": ["file_create"],
  "falsePositiveNotes": "Known false positive scenarios",
  "references": ["https://..."]
}

Write production-quality YARA rules with proper meta, strings, and condition sections.`;

const TTP_EXTRACTION_PROMPT = `You are a threat intelligence analyst. Extract TTPs (Tactics, Techniques, and Procedures) from the provided threat intelligence report.

Your output MUST be valid JSON with exactly these fields:
{
  "ttps": [
    {
      "tactic": "MITRE ATT&CK tactic name",
      "techniqueId": "T-number",
      "techniqueName": "Human-readable technique name",
      "description": "How this TTP is used in the described threat",
      "indicators": ["observable indicators"],
      "suggestedDetection": "Brief description of how to detect this"
    }
  ],
  "summary": "Brief summary of the threat report",
  "threatActor": "Identified threat actor if mentioned",
  "targetSectors": ["targeted industries/sectors"]
}`;

// ─── Types ────────────────────────────────────────────────────────────────────

export interface GeneratedSigmaRule {
  name: string;
  description: string;
  severity: string;
  mitreTactic: string;
  mitreTechnique: string;
  tags: string[];
  sigmaYaml: string;
  conditionTree: Record<string, unknown>;
  eventTypes: string[];
  falsePositiveNotes: string;
  references: string[];
}

export interface GeneratedYaraRule {
  name: string;
  description: string;
  severity: string;
  mitreTactic: string;
  mitreTechnique: string;
  tags: string[];
  yaraRule: string;
  conditionTree: Record<string, unknown>;
  eventTypes: string[];
  falsePositiveNotes: string;
  references: string[];
}

export interface ExtractedTTP {
  tactic: string;
  techniqueId: string;
  techniqueName: string;
  description: string;
  indicators: string[];
  suggestedDetection: string;
}

export interface TTPExtractionResult {
  ttps: ExtractedTTP[];
  summary: string;
  threatActor: string;
  targetSectors: string[];
}

export interface QualityScore {
  overall: number;
  specificity: number;
  mitreCoverage: number;
  falsePositiveRisk: number;
  conditionComplexity: number;
  eventTypeCoverage: number;
  estimatedFpRate: number;
  breakdown: Record<string, number>;
}

export interface RuleGenerationResult {
  rule: GeneratedSigmaRule | GeneratedYaraRule;
  quality: QualityScore;
  modelId: string;
  inputTokens: number;
  outputTokens: number;
  costUsd: number | null;
  latencyMs: number;
}

// ─── Generation Functions ─────────────────────────────────────────────────────

export async function generateSigmaRule(context: string, orgId: string): Promise<RuleGenerationResult> {
  log.info("Generating Sigma rule from context", { orgId, contextLength: context.length });

  const result = await invokeModel({
    modelId: SONNET_MODEL,
    backend: "bedrock",
    systemPrompt: SIGMA_SYSTEM_PROMPT,
    userMessage: "Generate a Sigma detection rule from the supplied security evidence.",
    maxTokens: 4096,
    temperature: 0.3,
    topP: 0.9,
    orgId,
    skipCache: true,
    untrustedContent: [{ label: "detection_rule_context", content: context }],
  });

  const rule = parseJsonResponse<GeneratedSigmaRule>(result.text, generatedRuleSchema("sigmaYaml"));
  const quality = scoreRuleQuality(rule, "sigma");

  return {
    rule,
    quality,
    modelId: SONNET_MODEL,
    inputTokens: result.inputTokensEstimate,
    outputTokens: result.outputTokensEstimate,
    costUsd: result.costEstimateUsd,
    latencyMs: result.latencyMs,
  };
}

export async function generateYaraRule(context: string, orgId: string): Promise<RuleGenerationResult> {
  log.info("Generating YARA rule from context", { orgId, contextLength: context.length });

  const result = await invokeModel({
    modelId: SONNET_MODEL,
    backend: "bedrock",
    systemPrompt: YARA_SYSTEM_PROMPT,
    userMessage: "Generate a YARA detection rule from the supplied security evidence.",
    maxTokens: 4096,
    temperature: 0.3,
    topP: 0.9,
    orgId,
    skipCache: true,
    untrustedContent: [{ label: "detection_rule_context", content: context }],
  });

  const rule = parseJsonResponse<GeneratedYaraRule>(result.text, generatedRuleSchema("yaraRule"));
  const quality = scoreRuleQuality(rule, "yara");

  return {
    rule,
    quality,
    modelId: SONNET_MODEL,
    inputTokens: result.inputTokensEstimate,
    outputTokens: result.outputTokensEstimate,
    costUsd: result.costEstimateUsd,
    latencyMs: result.latencyMs,
  };
}

export async function extractTTPs(
  threatIntelReport: string,
  orgId: string,
): Promise<{
  result: TTPExtractionResult;
  inputTokens: number;
  outputTokens: number;
  costUsd: number | null;
  latencyMs: number;
}> {
  log.info("Extracting TTPs from threat intel", { orgId, reportLength: threatIntelReport.length });

  const modelResult = await invokeModel({
    modelId: SONNET_MODEL,
    backend: "bedrock",
    systemPrompt: TTP_EXTRACTION_PROMPT,
    userMessage: "Extract TTPs from the supplied threat intelligence evidence.",
    maxTokens: 4096,
    temperature: 0.2,
    topP: 0.9,
    orgId,
    skipCache: true,
    untrustedContent: [{ label: "threat_intelligence_report", content: threatIntelReport }],
  });

  const result = parseJsonResponse<TTPExtractionResult>(modelResult.text, ttpExtractionSchema);

  return {
    result,
    inputTokens: modelResult.inputTokensEstimate,
    outputTokens: modelResult.outputTokensEstimate,
    costUsd: modelResult.costEstimateUsd,
    latencyMs: modelResult.latencyMs,
  };
}

export async function generateRulesFromTTPs(
  ttps: ExtractedTTP[],
  ruleFormat: "sigma" | "yara",
  orgId: string,
): Promise<RuleGenerationResult[]> {
  const results: RuleGenerationResult[] = [];

  for (const ttp of ttps) {
    const context = `Threat TTP Detection:
Tactic: ${ttp.tactic}
Technique: ${ttp.techniqueId} - ${ttp.techniqueName}
Description: ${ttp.description}
Known Indicators: ${ttp.indicators.join(", ")}
Detection Guidance: ${ttp.suggestedDetection}`;

    try {
      const result =
        ruleFormat === "yara" ? await generateYaraRule(context, orgId) : await generateSigmaRule(context, orgId);
      results.push(result);
    } catch (error) {
      log.error("Failed to generate rule for TTP", {
        techniqueId: ttp.techniqueId,
        error: String(error),
      });
    }
  }

  return results;
}

// ─── Quality Scoring ──────────────────────────────────────────────────────────

function scoreRuleQuality(rule: GeneratedSigmaRule | GeneratedYaraRule, format: "sigma" | "yara"): QualityScore {
  const breakdown: Record<string, number> = {};

  // 1. Specificity (0-25): How specific is the rule?
  let specificity = 0;
  const conditionTree = rule.conditionTree as { conditions?: unknown[] };
  const conditionCount = conditionTree?.conditions ? conditionTree.conditions.length : 0;
  if (conditionCount >= 3) specificity = 25;
  else if (conditionCount >= 2) specificity = 18;
  else if (conditionCount >= 1) specificity = 10;
  breakdown.specificity = specificity;

  // 2. MITRE Coverage (0-20): Is it mapped to ATT&CK?
  let mitreCoverage = 0;
  if (rule.mitreTactic) mitreCoverage += 10;
  if (rule.mitreTechnique) mitreCoverage += 10;
  breakdown.mitreCoverage = mitreCoverage;

  // 3. False Positive Risk (0-20): Lower is better for FP
  let fpRisk = 15; // default medium
  if (rule.falsePositiveNotes && rule.falsePositiveNotes.length > 20) fpRisk = 20;
  if (conditionCount >= 3) fpRisk = Math.min(fpRisk + 3, 20);
  breakdown.falsePositiveRisk = fpRisk;

  // 4. Condition Complexity (0-15)
  let conditionComplexity = 0;
  if (conditionCount >= 4) conditionComplexity = 15;
  else if (conditionCount >= 2) conditionComplexity = 10;
  else if (conditionCount >= 1) conditionComplexity = 5;
  breakdown.conditionComplexity = conditionComplexity;

  // 5. Event Type Coverage (0-10)
  let eventTypeCoverage = 0;
  if (rule.eventTypes && rule.eventTypes.length > 0) eventTypeCoverage = 10;
  breakdown.eventTypeCoverage = eventTypeCoverage;

  // 6. Format-specific checks (0-10)
  let formatScore = 0;
  if (format === "sigma" && "sigmaYaml" in rule && rule.sigmaYaml && rule.sigmaYaml.length > 50) {
    formatScore = 10;
  } else if (format === "yara" && "yaraRule" in rule && rule.yaraRule && rule.yaraRule.length > 50) {
    formatScore = 10;
  }
  breakdown.formatScore = formatScore;

  const overall = specificity + mitreCoverage + fpRisk + conditionComplexity + eventTypeCoverage + formatScore;

  // Estimate FP rate based on specificity
  let estimatedFpRate = 0.5; // 50% default
  if (overall >= 85) estimatedFpRate = 0.05;
  else if (overall >= 70) estimatedFpRate = 0.1;
  else if (overall >= 55) estimatedFpRate = 0.2;
  else if (overall >= 40) estimatedFpRate = 0.35;

  return {
    overall,
    specificity,
    mitreCoverage,
    falsePositiveRisk: fpRisk,
    conditionComplexity,
    eventTypeCoverage,
    estimatedFpRate,
    breakdown,
  };
}

export function scoreExistingRule(rule: {
  conditionTree: unknown;
  mitreTactic: string | null;
  mitreTechnique: string | null;
  falsePositiveNotes: string | null;
  eventTypes: string[] | null;
  tags: string[] | null;
}): QualityScore {
  const syntheticRule: GeneratedSigmaRule = {
    name: "",
    description: "",
    severity: "medium",
    mitreTactic: rule.mitreTactic || "",
    mitreTechnique: rule.mitreTechnique || "",
    tags: rule.tags || [],
    sigmaYaml: "",
    conditionTree: (rule.conditionTree || {}) as Record<string, unknown>,
    eventTypes: rule.eventTypes || [],
    falsePositiveNotes: rule.falsePositiveNotes || "",
    references: [],
  };
  return scoreRuleQuality(syntheticRule, "sigma");
}

// ─── Lifecycle Management ─────────────────────────────────────────────────────

export interface DeprecationCandidate {
  ruleId: string;
  ruleName: string;
  daysSinceLastMatch: number;
  matchCount: number;
  recommendation: "deprecate" | "review" | "keep";
}

export function evaluateLifecycle(rule: {
  id: string;
  name: string;
  matchCount: number;
  lastMatchAt: Date | null;
  createdAt: Date | null;
  status: string;
}): DeprecationCandidate {
  const now = Date.now();
  const lastMatch = rule.lastMatchAt ? new Date(rule.lastMatchAt).getTime() : 0;
  const created = rule.createdAt ? new Date(rule.createdAt).getTime() : now;
  const daysSinceLastMatch =
    lastMatch > 0
      ? Math.floor((now - lastMatch) / (1000 * 60 * 60 * 24))
      : Math.floor((now - created) / (1000 * 60 * 60 * 24));

  let recommendation: "deprecate" | "review" | "keep" = "keep";

  if (rule.matchCount === 0 && daysSinceLastMatch >= 90) {
    recommendation = "deprecate";
  } else if (rule.matchCount === 0 && daysSinceLastMatch >= 60) {
    recommendation = "review";
  } else if (daysSinceLastMatch >= 90 && rule.matchCount < 5) {
    recommendation = "review";
  }

  return {
    ruleId: rule.id,
    ruleName: rule.name,
    daysSinceLastMatch,
    matchCount: rule.matchCount,
    recommendation,
  };
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function parseJsonResponse<T>(text: string, schema: z.ZodType): T {
  // Try to extract JSON from markdown code blocks first
  const jsonMatch = text.match(/```(?:json)?\s*\n?([\s\S]*?)\n?```/);
  const jsonStr = jsonMatch ? jsonMatch[1].trim() : text.trim();

  try {
    return schema.parse(JSON.parse(jsonStr)) as T;
  } catch {
    // Try to find JSON object in the text
    const objMatch = jsonStr.match(/\{[\s\S]*\}/);
    if (objMatch) {
      return schema.parse(JSON.parse(objMatch[0])) as T;
    }
    throw new Error("Failed to parse AI response as JSON");
  }
}

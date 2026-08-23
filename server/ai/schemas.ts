import { z } from "zod";

const cleanString = (max: number) =>
  z
    .string()
    .max(max)
    .transform((value) => value.replace(/[\u0000-\u001f\u007f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g, ""));
const confidence = z.number().min(0).max(1);
const score100 = z.number().min(0).max(100);
const technique = z.string().regex(/^T\d{4}(?:\.\d{3})?$/);
const severity = z.enum(["critical", "high", "medium", "low", "informational"]);
const priority = z.number().int().min(1).max(5);

const ioc = z.object({
  type: cleanString(32),
  value: cleanString(512),
});

export const triageOutputSchema = z.object({
  severity,
  priority,
  category: cleanString(128),
  recommendedAction: cleanString(4000),
  reasoning: cleanString(6000),
  confidence: confidence.nullable().optional(),
  mitreTactic: cleanString(128).nullable(),
  mitreTechnique: technique.nullable(),
  killChainPhase: cleanString(128).nullable(),
  falsePositiveLikelihood: confidence,
  falsePositiveReasoning: cleanString(3000),
  relatedIocs: z.array(ioc).max(50),
  nistClassification: cleanString(128),
  escalationRequired: z.boolean(),
  containmentAdvice: cleanString(4000).nullable(),
  threatIntelSources: z.array(cleanString(256)).max(50).optional(),
});

const diamondModel = z.object({
  adversary: cleanString(2000),
  infrastructure: z.array(cleanString(512)).max(50),
  capability: cleanString(2000),
  victim: z.array(cleanString(512)).max(50),
});

export const correlationOutputSchema = z.object({
  correlatedGroups: z
    .array(
      z.object({
        groupName: cleanString(256),
        alertIds: z.array(cleanString(128)).max(100),
        confidence,
        reasoning: cleanString(6000),
        suggestedIncidentTitle: cleanString(512),
        severity: z.enum(["critical", "high", "medium", "low", "informational"]),
        mitreTactics: z.array(cleanString(128)).max(20),
        mitreTechniques: z.array(technique).max(50),
        killChainPhases: z.array(cleanString(128)).max(20),
        diamondModel,
      }),
    )
    .max(50),
  uncorrelatedAlertIds: z.array(cleanString(128)).max(100),
  overallAssessment: cleanString(6000),
  threatLandscape: cleanString(6000),
});

export const narrativeOutputSchema = z.object({
  narrative: cleanString(20000),
  citedAlertIds: z.array(cleanString(128)).max(200).optional(),
  unverifiedCitations: z.boolean().optional(),
  summary: cleanString(2000),
  attackTimeline: z
    .array(
      z.object({
        timestamp: cleanString(128),
        description: cleanString(2000),
        alertId: cleanString(128).optional(),
        mitreTechnique: technique.optional(),
      }),
    )
    .max(200),
  attackerProfile: z.object({
    ttps: z.array(cleanString(1000)).max(100),
    sophistication: cleanString(128),
    likelyMotivation: cleanString(128),
    estimatedOrigin: cleanString(1000),
    diamondModel,
  }),
  killChainAnalysis: z
    .array(
      z.object({
        phase: cleanString(128),
        description: cleanString(2000),
        evidence: z.array(cleanString(1000)).max(50),
      }),
    )
    .max(30),
  mitigationSteps: z.array(cleanString(2000)).max(100),
  iocs: z
    .array(
      ioc.extend({
        context: cleanString(1000),
      }),
    )
    .max(200),
  riskScore: score100,
  nistPhase: cleanString(128),
});

export const investigationOutputSchema = z.object({
  executiveSummary: cleanString(6000),
  investigationConfidence: confidence,
  scopeAssessment: z.object({
    compromisedAssets: z
      .array(
        z.object({
          type: cleanString(64),
          name: cleanString(512),
          confidence,
          evidence: z.array(cleanString(1000)).max(50),
        }),
      )
      .max(100),
    dataImpact: z.object({
      sensitiveDataAccessed: z.array(cleanString(512)).max(100),
      exfiltrationConfirmed: z.boolean(),
      estimatedDataVolume: cleanString(256),
      confidence,
    }),
    persistenceMechanisms: z
      .array(
        z.object({
          effectiveness: confidence,
          cost: cleanString(256),
        }),
      )
      .max(50),
  }),
  blindSpots: z.array(cleanString(2000)).max(100),
  worstCaseScenario: z.object({
    scenario: cleanString(4000),
    probability: confidence,
    impact: cleanString(2000),
    time_to_scenario: cleanString(256),
    prevention: cleanString(4000),
  }),
});

export const threatHuntingOutputSchema = z.object({
  findings: z.array(z.record(z.string(), z.unknown())).max(100),
  summary: cleanString(6000),
  riskLevel: severity,
  recommendedActions: z.array(cleanString(2000)).max(100),
});

export const behavioralOutputSchema = z.object({
  riskScore: score100,
  anomalies: z.array(z.record(z.string(), z.unknown())).max(100),
  assessment: cleanString(6000),
  recommendedActions: z.array(cleanString(2000)).max(100),
});

export const attackPathOutputSchema = z.object({
  paths: z.array(z.record(z.string(), z.unknown())).max(100),
  overallRisk: severity,
  confidence,
  nextMoves: z.array(cleanString(2000)).max(100),
});

export const investigationChatOutputSchema = z.object({
  reply: cleanString(10000),
  suggestedFollowups: z.array(cleanString(1000)).max(10),
  referencedTechniques: z.array(technique).max(50),
  confidence,
});

export const detectionRuleOutputSchema = z.object({
  rules: z
    .array(
      z.object({
        name: cleanString(256),
        description: cleanString(4000),
        sigmaRule: cleanString(20000),
        conditionTree: z.record(z.string(), z.unknown()),
        mitreTactic: cleanString(128),
        mitreTechnique: technique,
        confidence,
        falsePositiveNotes: cleanString(4000),
        eventTypes: z.array(cleanString(128)).max(50),
      }),
    )
    .max(50),
  analysisNotes: cleanString(6000),
  coverageGaps: z.array(cleanString(2000)).max(100),
});

export const autonomousAnalystDecisionSchema = z.object({
  tier: z.enum(["tier1_autonomous", "tier2_semi_autonomous", "tier3_assisted"]),
  outcome: cleanString(128),
  confidenceScore: confidence,
  reasoning: cleanString(6000),
  recommendedActions: z
    .array(
      z.object({
        type: cleanString(128),
        priority: z.enum(["critical", "high", "medium", "low"]),
        description: cleanString(2000),
        config: z.record(z.string(), z.unknown()),
        autoExecute: z.boolean(),
      }),
    )
    .max(50),
  humanApprovalRequired: z.boolean(),
});

export function sanitizeModelOutput(value: unknown): unknown {
  if (typeof value === "string") {
    return value.replace(/[\u0000-\u001f\u007f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g, "");
  }
  if (Array.isArray(value)) return value.map(sanitizeModelOutput);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, sanitizeModelOutput(child)]));
  }
  return value;
}

export type SupportedAiOutputSchema =
  | typeof triageOutputSchema
  | typeof correlationOutputSchema
  | typeof narrativeOutputSchema
  | typeof investigationOutputSchema
  | typeof threatHuntingOutputSchema
  | typeof behavioralOutputSchema
  | typeof attackPathOutputSchema
  | typeof investigationChatOutputSchema
  | typeof detectionRuleOutputSchema
  | typeof autonomousAnalystDecisionSchema;

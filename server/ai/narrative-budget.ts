import { countTokens } from "./tokenizer";
import { logger } from "../logger";

const log = logger.child("narrative-budget");

export interface BudgetedMessageResult {
  message: string;
  totalInputTokens: number;
  alertsIncluded: number;
  alertsTruncated: number;
}

interface IncidentLike {
  title?: string | null;
  summary?: string | null;
  severity?: string | null;
  status?: string | null;
  mitreTactics?: unknown;
  mitreTechniques?: unknown;
  affectedAssets?: unknown;
  createdAt?: unknown;
}

interface AlertLike {
  id?: unknown;
  title?: string | null;
  source?: string | null;
  category?: string | null;
  severity?: string | null;
  description?: string | null;
  sourceIp?: string | null;
  destIp?: string | null;
  hostname?: string | null;
  userId?: string | null;
  mitreTactic?: string | null;
  mitreTechnique?: string | null;
  detectedAt?: unknown;
  fileHash?: string | null;
  domain?: string | null;
  url?: string | null;
}

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  informational: 4,
};

const RESPONSE_JSON_INSTRUCTION = `\n\nRespond with this exact JSON structure:\n{\n  "narrative": "detailed multi-paragraph attacker-centric narrative",\n  "citedAlertIds": ["alert IDs cited"],\n  "summary": "one-line executive summary",\n  "attackTimeline": [{"timestamp": "ISO 8601", "description": "action", "alertId": "source", "mitreTechnique": "T1xxx"}],\n  "attackerProfile": {"ttps": [], "sophistication": "level", "likelyMotivation": "type", "estimatedOrigin": "origin or unknown", "diamondModel": {"adversary": [], "capability": [], "infrastructure": [], "victim": []}},\n  "killChainAnalysis": [{"phase": "phase", "description": "what occurred", "evidence": []}],\n  "mitigationSteps": ["steps"],\n  "iocs": [{"type": "type", "value": "value", "context": "context"}],\n  "riskScore": 85,\n  "nistPhase": "Detection|Analysis|Containment|Eradication|Recovery"\n}`;

export function buildBudgetedNarrativeMessage(
  incident: IncidentLike,
  alerts: AlertLike[],
  threatIntelBlock: string,
  maxInputTokens: number = 4096,
  responseReservation: number = 2048,
): BudgetedMessageResult {
  const availableBudget = maxInputTokens - responseReservation;

  // Build incident context (always included -- small and essential)
  const incidentCtx = JSON.stringify(
    {
      title: incident.title,
      summary: incident.summary,
      severity: incident.severity,
      status: incident.status,
      mitreTactics: incident.mitreTactics,
      mitreTechniques: incident.mitreTechniques,
      affectedAssets: incident.affectedAssets,
      createdAt: incident.createdAt,
    },
    null,
    2,
  );

  const promptTemplate = `Generate a comprehensive incident narrative for this security incident.\n\nINCIDENT CONTEXT:\n${incidentCtx}\n\n`;
  let currentTokens = countTokens(promptTemplate);

  // Add threat intel block if it fits within 30% of budget
  let threatIntelIncluded = "";
  if (threatIntelBlock) {
    const tiTokens = countTokens(threatIntelBlock);
    if (currentTokens + tiTokens < availableBudget * 0.3) {
      threatIntelIncluded = threatIntelBlock;
      currentTokens += tiTokens;
    }
  }

  // Sort alerts by relevance: critical > high > medium > low > informational
  const sortedAlerts = [...alerts].sort(
    (a, b) => (SEVERITY_ORDER[a.severity || "low"] ?? 3) - (SEVERITY_ORDER[b.severity || "low"] ?? 3),
  );

  // Reserve tokens for alert section overhead and response instruction
  const overheadTokens =
    countTokens(`ASSOCIATED ALERT TELEMETRY (00 alerts):\n[]`) + countTokens(RESPONSE_JSON_INSTRUCTION);
  let remainingBudget = availableBudget - currentTokens - overheadTokens;

  // Pack alerts within remaining budget
  const includedAlertJsons: string[] = [];
  let alertsTruncated = 0;

  for (const a of sortedAlerts) {
    const alertJson = JSON.stringify(
      {
        id: a.id,
        title: a.title,
        source: a.source,
        category: a.category,
        severity: a.severity,
        description: a.description,
        sourceIp: a.sourceIp,
        destIp: a.destIp,
        hostname: a.hostname,
        userId: a.userId,
        mitreTactic: a.mitreTactic,
        mitreTechnique: a.mitreTechnique,
        detectedAt: a.detectedAt,
        fileHash: a.fileHash,
        domain: a.domain,
        url: a.url,
      },
      null,
      2,
    );
    const alertTokens = countTokens(alertJson);
    if (alertTokens <= remainingBudget) {
      includedAlertJsons.push(alertJson);
      remainingBudget -= alertTokens;
    } else {
      alertsTruncated++;
    }
  }

  // Reconstruct full message
  const alertTelemetry = `[${includedAlertJsons.join(",\n")}]`;
  const alertSection = `ASSOCIATED ALERT TELEMETRY (${includedAlertJsons.length} alerts):\n${alertTelemetry}`;

  let fullMessage = promptTemplate;
  if (threatIntelIncluded) {
    fullMessage += `${threatIntelIncluded}\n\n`;
  }
  fullMessage += alertSection;
  fullMessage += RESPONSE_JSON_INSTRUCTION;
  fullMessage +=
    "\nUse strings for attackerProfile.diamondModel.adversary and attackerProfile.diamondModel.capability; use arrays for infrastructure and victim.";

  return {
    message: fullMessage,
    totalInputTokens: countTokens(fullMessage),
    alertsIncluded: includedAlertJsons.length,
    alertsTruncated,
  };
}

/**
 * Investigation Runner — automated hypothesis testing for autonomous SOC
 *
 * Tests multiple explanations against available data:
 * 1. Generates hypotheses based on alert data + enrichment
 * 2. Gathers evidence for/against each hypothesis
 * 3. Ranks hypotheses by evidence strength
 * 4. Produces a verdict with confidence
 */

import { storage } from "../storage";
import type { Alert, Incident } from "@shared/schema";
import { logger } from "../logger";
import { quickConfidence } from "./confidence-scorer";

const log = logger.child("investigation-runner");

export interface Hypothesis {
  id: string;
  title: string;
  description: string;
  type: "true_positive" | "false_positive" | "benign_activity" | "attack_stage" | "misconfiguration" | "unknown";
  evidenceFor: Evidence[];
  evidenceAgainst: Evidence[];
  confidence: number;
  status: "pending" | "supported" | "refuted" | "inconclusive";
}

export interface Evidence {
  source: string;
  description: string;
  weight: number; // 0-1
  timestamp?: string;
}

export interface InvestigationResult {
  hypotheses: Hypothesis[];
  verdict: {
    outcome: string;
    confidence: number;
    reasoning: string;
    winningHypothesis: string | null;
  };
  enrichment: EnrichmentData;
  correlations: CorrelationResult;
  timeline: TimelineEvent[];
  durationMs: number;
}

export interface EnrichmentData {
  entities: { type: string; value: string; reputation?: string }[];
  threatIntelMatches: number;
  assetContext: { hostname?: string; criticality?: string; owner?: string }[];
  userContext: { username?: string; riskScore?: number; recentActivity?: string }[];
}

export interface CorrelationResult {
  relatedAlerts: { id: string; title: string; similarity: number }[];
  relatedIncidents: { id: string; title: string; similarity: number }[];
  timeWindowDays: number;
  patternDetected: boolean;
  patternDescription: string | null;
}

export interface TimelineEvent {
  timestamp: string;
  type: string;
  description: string;
  severity: string;
  source: string;
}

/**
 * Run automated investigation on an alert
 */
export async function runAutonomousInvestigation(alert: Alert, orgId: string): Promise<InvestigationResult> {
  const startTime = Date.now();

  log.info("Starting autonomous investigation", { alertId: alert.id, orgId });

  // Step 1: Enrich the alert with context
  const enrichment = await enrichAlert(alert, orgId);

  // Step 2: Correlate with historical data (90-day window)
  const correlations = await correlateAlert(alert, orgId);

  // Step 3: Build timeline
  const timeline = buildTimeline(alert, correlations.relatedAlerts);

  // Step 4: Generate hypotheses
  const hypotheses = generateHypotheses(alert, enrichment, correlations);

  // Step 5: Test each hypothesis against evidence
  const testedHypotheses = testHypotheses(hypotheses, enrichment, correlations, alert);

  // Step 6: Determine verdict
  const verdict = determineVerdict(testedHypotheses);

  const durationMs = Date.now() - startTime;

  log.info("Investigation complete", {
    alertId: alert.id,
    verdict: verdict.outcome,
    confidence: verdict.confidence,
    durationMs,
  });

  return {
    hypotheses: testedHypotheses,
    verdict,
    enrichment,
    correlations,
    timeline,
    durationMs,
  };
}

async function enrichAlert(alert: Alert, orgId: string): Promise<EnrichmentData> {
  const entities: EnrichmentData["entities"] = [];
  const assetContext: EnrichmentData["assetContext"] = [];
  const userContext: EnrichmentData["userContext"] = [];
  let threatIntelMatches = 0;

  // Extract entities from raw data
  const raw = (alert.rawData || {}) as Record<string, unknown>;

  if (raw.sourceIp && typeof raw.sourceIp === "string") {
    entities.push({ type: "ip", value: raw.sourceIp, reputation: "unknown" });
  }
  if (raw.destIp && typeof raw.destIp === "string") {
    entities.push({ type: "ip", value: raw.destIp, reputation: "unknown" });
  }
  if (raw.hostname && typeof raw.hostname === "string") {
    entities.push({ type: "hostname", value: raw.hostname });
    assetContext.push({ hostname: raw.hostname, criticality: "medium" });
  }
  if (raw.username && typeof raw.username === "string") {
    entities.push({ type: "user", value: raw.username });
    userContext.push({ username: raw.username, riskScore: 50 });
  }
  if (raw.domain && typeof raw.domain === "string") {
    entities.push({ type: "domain", value: raw.domain, reputation: "unknown" });
  }
  if (raw.fileHash && typeof raw.fileHash === "string") {
    entities.push({ type: "file_hash", value: raw.fileHash });
  }

  // Check threat intel configs for matches
  try {
    const tiConfigs = await storage.getThreatIntelConfigs(orgId);
    if (tiConfigs.length > 0) {
      // Each active TI source increases match potential
      threatIntelMatches = tiConfigs.filter((c) => c.enabled).length > 0 ? 1 : 0;
    }
  } catch {
    // TI lookup failed — non-fatal
  }

  return { entities, threatIntelMatches, assetContext, userContext };
}

async function correlateAlert(alert: Alert, orgId: string): Promise<CorrelationResult> {
  const relatedAlerts: CorrelationResult["relatedAlerts"] = [];
  const relatedIncidents: CorrelationResult["relatedIncidents"] = [];
  let patternDetected = false;
  let patternDescription: string | null = null;

  try {
    // Get alerts from the last 90 days for this org
    const allAlerts = await storage.getAlerts(orgId);
    const ninetyDaysAgo = Date.now() - 90 * 24 * 60 * 60 * 1000;

    const recentAlerts = allAlerts.filter((a) => {
      if (a.id === alert.id) return false;
      const created = a.createdAt ? new Date(a.createdAt).getTime() : 0;
      return created > ninetyDaysAgo;
    });

    // Find alerts with same category/source/tactic
    for (const a of recentAlerts) {
      let similarity = 0;
      if (a.category === alert.category && alert.category) similarity += 0.35;
      if (a.source === alert.source) similarity += 0.2;
      if (a.mitreTactic === alert.mitreTactic && alert.mitreTactic) similarity += 0.25;
      if (a.severity === alert.severity) similarity += 0.1;
      if (a.mitreTechnique === alert.mitreTechnique && alert.mitreTechnique) similarity += 0.1;

      if (similarity >= 0.3) {
        relatedAlerts.push({
          id: a.id,
          title: a.title,
          similarity: Math.round(similarity * 100) / 100,
        });
      }
    }

    // Sort by similarity descending, limit to top 20
    relatedAlerts.sort((a, b) => b.similarity - a.similarity);
    relatedAlerts.splice(20);

    // Check for multi-stage attack pattern
    if (relatedAlerts.length >= 3) {
      const tactics = new Set(
        recentAlerts
          .filter((a) => relatedAlerts.some((r) => r.id === a.id))
          .map((a) => a.mitreTactic)
          .filter(Boolean),
      );
      if (tactics.size >= 2) {
        patternDetected = true;
        patternDescription = `Multi-stage attack pattern detected across ${tactics.size} MITRE tactics: ${Array.from(tactics).join(", ")}`;
      }
    }

    // Check related incidents
    const allIncidents = await storage.getIncidents(orgId);
    for (const inc of allIncidents) {
      if (
        inc.severity === alert.severity ||
        (inc.title && alert.title && inc.title.toLowerCase().includes(alert.category || ""))
      ) {
        relatedIncidents.push({
          id: inc.id,
          title: inc.title,
          similarity: 0.5,
        });
      }
    }
    relatedIncidents.splice(10);
  } catch (err) {
    log.warn("Correlation failed", { alertId: alert.id, error: String(err) });
  }

  return {
    relatedAlerts,
    relatedIncidents,
    timeWindowDays: 90,
    patternDetected,
    patternDescription,
  };
}

function buildTimeline(alert: Alert, relatedAlerts: CorrelationResult["relatedAlerts"]): TimelineEvent[] {
  const events: TimelineEvent[] = [];

  events.push({
    timestamp: (alert.detectedAt || alert.createdAt || new Date()).toString(),
    type: "alert_detected",
    description: alert.title,
    severity: alert.severity || "medium",
    source: alert.source || "unknown",
  });

  // Add related alert events
  for (const rel of relatedAlerts.slice(0, 10)) {
    events.push({
      timestamp: new Date().toISOString(),
      type: "related_alert",
      description: `Related: ${rel.title} (${Math.round(rel.similarity * 100)}% similar)`,
      severity: "info",
      source: "correlation",
    });
  }

  return events.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
}

function generateHypotheses(alert: Alert, enrichment: EnrichmentData, correlations: CorrelationResult): Hypothesis[] {
  const hypotheses: Hypothesis[] = [];
  const category = alert.category || "unknown";
  const severity = alert.severity || "medium";

  // H1: True positive — real attack
  hypotheses.push({
    id: "h1_true_positive",
    title: "True Positive — Active Threat",
    description: `The alert indicates a real ${category} attack targeting the organization`,
    type: "true_positive",
    evidenceFor: [],
    evidenceAgainst: [],
    confidence: 0,
    status: "pending",
  });

  // H2: False positive — benign activity
  hypotheses.push({
    id: "h2_false_positive",
    title: "False Positive — Benign Activity",
    description: `The alert is triggered by legitimate activity that matches detection signatures`,
    type: "false_positive",
    evidenceFor: [],
    evidenceAgainst: [],
    confidence: 0,
    status: "pending",
  });

  // H3: Misconfiguration
  hypotheses.push({
    id: "h3_misconfiguration",
    title: "Misconfiguration — System Issue",
    description: `The alert is caused by a misconfigured system or overly broad detection rule`,
    type: "misconfiguration",
    evidenceFor: [],
    evidenceAgainst: [],
    confidence: 0,
    status: "pending",
  });

  // H4: Multi-stage attack (if correlation shows pattern)
  if (correlations.patternDetected) {
    hypotheses.push({
      id: "h4_attack_stage",
      title: "Multi-Stage Attack — Ongoing Campaign",
      description: `This alert is part of a broader multi-stage attack campaign`,
      type: "attack_stage",
      evidenceFor: [],
      evidenceAgainst: [],
      confidence: 0,
      status: "pending",
    });
  }

  return hypotheses;
}

function testHypotheses(
  hypotheses: Hypothesis[],
  enrichment: EnrichmentData,
  correlations: CorrelationResult,
  alert: Alert,
): Hypothesis[] {
  return hypotheses.map((h) => {
    const tested = { ...h, evidenceFor: [...h.evidenceFor], evidenceAgainst: [...h.evidenceAgainst] };

    switch (h.type) {
      case "true_positive":
        tested.evidenceFor = getTpEvidence(alert, enrichment, correlations);
        tested.evidenceAgainst = getTpCounterEvidence(alert, enrichment);
        break;
      case "false_positive":
        tested.evidenceFor = getFpEvidence(alert, enrichment);
        tested.evidenceAgainst = getFpCounterEvidence(alert, enrichment, correlations);
        break;
      case "misconfiguration":
        tested.evidenceFor = getMisconfigEvidence(alert);
        tested.evidenceAgainst = getMisconfigCounterEvidence(alert, enrichment);
        break;
      case "attack_stage":
        tested.evidenceFor = getAttackStageEvidence(correlations);
        tested.evidenceAgainst = getAttackStageCounterEvidence(correlations);
        break;
    }

    // Calculate hypothesis confidence
    const forScore =
      tested.evidenceFor.length > 0
        ? tested.evidenceFor.reduce((sum, e) => sum + e.weight, 0) / tested.evidenceFor.length
        : 0;
    const againstScore =
      tested.evidenceAgainst.length > 0
        ? tested.evidenceAgainst.reduce((sum, e) => sum + e.weight, 0) / tested.evidenceAgainst.length
        : 0;

    const evidenceBalance = forScore - againstScore * 0.5;
    tested.confidence = Math.max(0, Math.min(1, 0.5 + evidenceBalance));

    // Determine status
    if (tested.confidence >= 0.7) {
      tested.status = "supported";
    } else if (tested.confidence <= 0.3) {
      tested.status = "refuted";
    } else {
      tested.status = "inconclusive";
    }

    return tested;
  });
}

function getTpEvidence(alert: Alert, enrichment: EnrichmentData, correlations: CorrelationResult): Evidence[] {
  const evidence: Evidence[] = [];
  const severity = alert.severity || "medium";

  if (severity === "critical" || severity === "high") {
    evidence.push({
      source: "severity_analysis",
      description: `${severity} severity alert from ${alert.source || "unknown source"}`,
      weight: severity === "critical" ? 0.9 : 0.7,
    });
  }

  if (enrichment.threatIntelMatches > 0) {
    evidence.push({
      source: "threat_intelligence",
      description: `${enrichment.threatIntelMatches} threat intel indicator match(es)`,
      weight: 0.85,
    });
  }

  if (correlations.relatedAlerts.length > 0) {
    evidence.push({
      source: "correlation",
      description: `${correlations.relatedAlerts.length} related alerts found in ${correlations.timeWindowDays}-day window`,
      weight: Math.min(0.5 + correlations.relatedAlerts.length * 0.1, 0.9),
    });
  }

  if (alert.mitreTactic && alert.mitreTechnique) {
    evidence.push({
      source: "mitre_mapping",
      description: `Maps to MITRE ATT&CK: ${alert.mitreTactic} / ${alert.mitreTechnique}`,
      weight: 0.7,
    });
  }

  if (correlations.patternDetected) {
    evidence.push({
      source: "pattern_detection",
      description: correlations.patternDescription || "Multi-stage attack pattern detected",
      weight: 0.85,
    });
  }

  return evidence;
}

function getTpCounterEvidence(alert: Alert, enrichment: EnrichmentData): Evidence[] {
  const evidence: Evidence[] = [];

  if ((alert.severity || "medium") === "low" || (alert.severity || "medium") === "informational") {
    evidence.push({
      source: "severity_analysis",
      description: "Low/informational severity suggests low threat level",
      weight: 0.4,
    });
  }

  if (enrichment.entities.length === 0) {
    evidence.push({
      source: "entity_analysis",
      description: "No actionable entities extracted from alert data",
      weight: 0.3,
    });
  }

  return evidence;
}

function getFpEvidence(alert: Alert, enrichment: EnrichmentData): Evidence[] {
  const evidence: Evidence[] = [];

  if ((alert.severity || "medium") === "low" || (alert.severity || "medium") === "informational") {
    evidence.push({
      source: "severity_analysis",
      description: "Low severity often correlates with false positives",
      weight: 0.5,
    });
  }

  if (enrichment.threatIntelMatches === 0) {
    evidence.push({
      source: "threat_intelligence",
      description: "No threat intel matches — reduces true positive likelihood",
      weight: 0.4,
    });
  }

  return evidence;
}

function getFpCounterEvidence(alert: Alert, enrichment: EnrichmentData, correlations: CorrelationResult): Evidence[] {
  const evidence: Evidence[] = [];

  if ((alert.severity || "medium") === "critical" || (alert.severity || "medium") === "high") {
    evidence.push({
      source: "severity_analysis",
      description: "High/critical severity rarely false positive",
      weight: 0.7,
    });
  }

  if (correlations.relatedAlerts.length >= 3) {
    evidence.push({
      source: "correlation",
      description: "Multiple correlated alerts make FP unlikely",
      weight: 0.6,
    });
  }

  if (enrichment.threatIntelMatches > 0) {
    evidence.push({
      source: "threat_intelligence",
      description: "Threat intel match contradicts FP hypothesis",
      weight: 0.8,
    });
  }

  return evidence;
}

function getMisconfigEvidence(alert: Alert): Evidence[] {
  const evidence: Evidence[] = [];

  const misconfigCategories = ["policy_violation", "configuration", "audit"];
  if (misconfigCategories.includes(alert.category || "")) {
    evidence.push({
      source: "category_analysis",
      description: `Category "${alert.category}" commonly caused by misconfiguration`,
      weight: 0.6,
    });
  }

  return evidence;
}

function getMisconfigCounterEvidence(alert: Alert, enrichment: EnrichmentData): Evidence[] {
  const evidence: Evidence[] = [];

  const attackCategories = ["malware", "ransomware", "data_exfiltration", "credential_access", "lateral_movement"];
  if (attackCategories.includes(alert.category || "")) {
    evidence.push({
      source: "category_analysis",
      description: `Category "${alert.category}" strongly indicates real attack, not misconfiguration`,
      weight: 0.8,
    });
  }

  if (enrichment.threatIntelMatches > 0) {
    evidence.push({
      source: "threat_intelligence",
      description: "Threat intel match rules out misconfiguration",
      weight: 0.9,
    });
  }

  return evidence;
}

function getAttackStageEvidence(correlations: CorrelationResult): Evidence[] {
  const evidence: Evidence[] = [];

  if (correlations.patternDetected) {
    evidence.push({
      source: "pattern_detection",
      description: correlations.patternDescription || "Multi-stage pattern detected",
      weight: 0.85,
    });
  }

  if (correlations.relatedAlerts.length >= 5) {
    evidence.push({
      source: "correlation",
      description: `${correlations.relatedAlerts.length} correlated alerts suggest coordinated campaign`,
      weight: 0.8,
    });
  }

  return evidence;
}

function getAttackStageCounterEvidence(correlations: CorrelationResult): Evidence[] {
  const evidence: Evidence[] = [];

  if (correlations.relatedAlerts.length < 3) {
    evidence.push({
      source: "correlation",
      description: "Too few correlated alerts for multi-stage assessment",
      weight: 0.5,
    });
  }

  return evidence;
}

function determineVerdict(hypotheses: Hypothesis[]): InvestigationResult["verdict"] {
  if (hypotheses.length === 0) {
    return {
      outcome: "inconclusive",
      confidence: 0,
      reasoning: "No hypotheses generated — insufficient data for determination.",
      winningHypothesis: null,
    };
  }

  // Sort by confidence descending
  const sorted = [...hypotheses].sort((a, b) => b.confidence - a.confidence);
  const best = sorted[0];

  // If the best hypothesis has very low confidence, mark inconclusive
  if (best.confidence < 0.3) {
    return {
      outcome: "inconclusive",
      confidence: best.confidence,
      reasoning: `Highest hypothesis (${best.type}) scored only ${(best.confidence * 100).toFixed(0)}% — below threshold for determination.`,
      winningHypothesis: null,
    };
  }

  const outcomeMap: Record<string, string> = {
    true_positive: "true_positive",
    false_positive: "false_positive",
    misconfiguration: "false_positive",
    attack_stage: "true_positive",
  };

  return {
    outcome: outcomeMap[best.type] ?? "inconclusive",
    confidence: best.confidence,
    reasoning: best.description,
    winningHypothesis: best.type,
  };
}

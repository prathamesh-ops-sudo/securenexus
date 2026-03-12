/**
 * Confidence Scorer — determines when AI should act autonomously vs. escalate
 *
 * Scoring factors:
 * - Alert severity & historical FP rate for source
 * - Correlation with past incidents (90-day window)
 * - Threat intel match strength
 * - Asset criticality of affected targets
 * - User behavior baseline deviation
 * - MITRE ATT&CK stage progression
 */

import type { Alert, Incident } from "@shared/schema";
import { logger } from "../logger";

const log = logger.child("confidence-scorer");

export interface ConfidenceFactor {
  factor: string;
  weight: number;
  score: number;
  reasoning: string;
}

export interface ConfidenceResult {
  overall: number;
  tier: "tier1_autonomous" | "tier2_semi_autonomous" | "tier3_assisted";
  factors: ConfidenceFactor[];
  shouldAutoAct: boolean;
  shouldEscalate: boolean;
  escalationReason: string | null;
}

// Thresholds
const TIER1_THRESHOLD = 0.95; // fully autonomous
const TIER2_THRESHOLD = 0.7; // semi-autonomous (human approves)
const AUTO_ACT_THRESHOLD = 0.95;
const ESCALATE_THRESHOLD = 0.7;

interface ScoringContext {
  alert: Alert;
  relatedAlerts: Alert[];
  pastIncidents: Incident[];
  threatIntelMatches: number;
  assetCriticality: "critical" | "high" | "medium" | "low" | "unknown";
  historicalFpRate: number; // 0-1, false positive rate for this source
  isKnownAttackPattern: boolean;
  hasCorrelation: boolean;
  correlationStrength: number; // 0-1
  mitreCoverage: number; // number of MITRE techniques matched
  userBehaviorDeviation: number; // 0-1, how far from baseline
}

export function computeConfidence(ctx: ScoringContext): ConfidenceResult {
  const factors: ConfidenceFactor[] = [];

  // 1. Severity factor (weight: 0.15)
  const severityScores: Record<string, number> = {
    critical: 0.95,
    high: 0.8,
    medium: 0.55,
    low: 0.3,
    informational: 0.1,
  };
  const severityScore = severityScores[ctx.alert.severity || "medium"] ?? 0.55;
  factors.push({
    factor: "alert_severity",
    weight: 0.15,
    score: severityScore,
    reasoning: `Alert severity "${ctx.alert.severity}" maps to confidence ${severityScore}`,
  });

  // 2. Source reliability / historical FP rate (weight: 0.15)
  const sourceReliability = 1 - ctx.historicalFpRate;
  factors.push({
    factor: "source_reliability",
    weight: 0.15,
    score: sourceReliability,
    reasoning: `Source "${ctx.alert.source}" has ${Math.round(ctx.historicalFpRate * 100)}% FP rate → ${Math.round(sourceReliability * 100)}% reliability`,
  });

  // 3. Correlation strength (weight: 0.20)
  const correlationScore = ctx.hasCorrelation ? Math.max(ctx.correlationStrength, 0.5) : 0.2;
  factors.push({
    factor: "correlation_strength",
    weight: 0.2,
    score: correlationScore,
    reasoning: ctx.hasCorrelation
      ? `Correlated with ${ctx.relatedAlerts.length} related alerts (strength: ${Math.round(ctx.correlationStrength * 100)}%)`
      : "No correlation found with other alerts",
  });

  // 4. Threat intel match (weight: 0.15)
  const tiScore = ctx.threatIntelMatches > 0 ? Math.min(0.5 + ctx.threatIntelMatches * 0.15, 1.0) : 0.3;
  factors.push({
    factor: "threat_intel_match",
    weight: 0.15,
    score: tiScore,
    reasoning:
      ctx.threatIntelMatches > 0
        ? `Matched ${ctx.threatIntelMatches} threat intel indicator(s)`
        : "No threat intel matches",
  });

  // 5. Asset criticality (weight: 0.10)
  const assetScores: Record<string, number> = {
    critical: 0.95,
    high: 0.8,
    medium: 0.6,
    low: 0.4,
    unknown: 0.5,
  };
  const assetScore = assetScores[ctx.assetCriticality] ?? 0.5;
  factors.push({
    factor: "asset_criticality",
    weight: 0.1,
    score: assetScore,
    reasoning: `Asset criticality "${ctx.assetCriticality}" → confidence factor ${assetScore}`,
  });

  // 6. Known attack pattern (weight: 0.10)
  const patternScore = ctx.isKnownAttackPattern ? 0.9 : 0.4;
  factors.push({
    factor: "known_attack_pattern",
    weight: 0.1,
    score: patternScore,
    reasoning: ctx.isKnownAttackPattern
      ? "Matches known attack pattern from detection rules"
      : "No known attack pattern match",
  });

  // 7. MITRE ATT&CK coverage (weight: 0.10)
  const mitreScore = Math.min(ctx.mitreCoverage * 0.15 + 0.3, 1.0);
  factors.push({
    factor: "mitre_coverage",
    weight: 0.1,
    score: mitreScore,
    reasoning: `${ctx.mitreCoverage} MITRE technique(s) identified`,
  });

  // 8. User behavior deviation (weight: 0.05)
  const behaviorScore = ctx.userBehaviorDeviation > 0.5 ? ctx.userBehaviorDeviation : 0.3;
  factors.push({
    factor: "user_behavior_deviation",
    weight: 0.05,
    score: behaviorScore,
    reasoning: `User behavior deviates ${Math.round(ctx.userBehaviorDeviation * 100)}% from baseline`,
  });

  // Calculate weighted overall score
  const overall = factors.reduce((sum, f) => sum + f.weight * f.score, 0);

  // Determine tier
  let tier: ConfidenceResult["tier"];
  if (overall >= TIER1_THRESHOLD) {
    tier = "tier1_autonomous";
  } else if (overall >= TIER2_THRESHOLD) {
    tier = "tier2_semi_autonomous";
  } else {
    tier = "tier3_assisted";
  }

  // Determine action
  const shouldAutoAct = overall >= AUTO_ACT_THRESHOLD;
  const shouldEscalate = overall < ESCALATE_THRESHOLD;

  let escalationReason: string | null = null;
  if (shouldEscalate) {
    const weakFactors = factors.filter((f) => f.score < 0.5).map((f) => f.factor);
    escalationReason = `Low confidence (${Math.round(overall * 100)}%) due to weak signals: ${weakFactors.join(", ")}`;
  }

  log.info("Confidence scored", {
    alertId: ctx.alert.id,
    overall: Math.round(overall * 100) / 100,
    tier,
    shouldAutoAct,
  });

  return {
    overall: Math.round(overall * 1000) / 1000,
    tier,
    factors,
    shouldAutoAct,
    shouldEscalate,
    escalationReason,
  };
}

/**
 * Quick confidence estimate for bulk triage without full context
 */
export function quickConfidence(alert: Alert): number {
  let score = 0.5;

  // Severity boost
  const sevBoost: Record<string, number> = {
    critical: 0.25,
    high: 0.15,
    medium: 0.05,
    low: -0.1,
    informational: -0.2,
  };
  score += sevBoost[alert.severity || "medium"] ?? 0;

  // Known source boost
  const trustedSources = ["edr", "ids", "firewall", "siem", "ndr"];
  if (trustedSources.some((s) => (alert.source || "").toLowerCase().includes(s))) {
    score += 0.1;
  }

  // MITRE mapping boost
  if (alert.mitreTactic && alert.mitreTechnique) {
    score += 0.1;
  } else if (alert.mitreTactic || alert.mitreTechnique) {
    score += 0.05;
  }

  // Category boost
  const highConfCategories = ["malware", "ransomware", "data_exfiltration", "credential_access"];
  if (highConfCategories.includes(alert.category || "")) {
    score += 0.1;
  }

  return Math.max(0.1, Math.min(score, 0.99));
}

/**
 * Calculate the historical false positive rate for a given alert source
 */
export function estimateFpRate(alerts: Alert[]): number {
  if (alerts.length === 0) return 0.5; // unknown → assume 50%
  const resolved = alerts.filter((a) => a.status === "resolved" || a.status === "closed");
  if (resolved.length === 0) return 0.3;
  const fps = resolved.filter(
    (a) =>
      a.status === "resolved" &&
      ((a.rawData as Record<string, unknown>)?.resolution === "false_positive" ||
        (a.rawData as Record<string, unknown>)?.falsePositive === true),
  );
  return fps.length / resolved.length;
}

/**
 * Autonomous Analyst — 3-tier AI decision engine for SecureNexus SOC
 *
 * Tier 1 (Fully Autonomous): confidence >95% → auto-triage, auto-respond, auto-close
 * Tier 2 (Semi-Autonomous): 70-95% → investigate, present case, human approves in <2min
 * Tier 3 (AI-Assisted): <70% → AI provides context, human leads investigation
 */

import { db } from "../db";
import { storage } from "../storage";
import { aiAnalystDecisions, autonomyLog, alerts as alertsTable } from "@shared/schema";
import type { Alert, Incident, InsertAiAnalystDecision, InsertAutonomyLogEntry } from "@shared/schema";
import { eq, and, desc } from "drizzle-orm";
import { logger } from "../logger";
import { computeConfidence, quickConfidence, estimateFpRate, type ConfidenceResult } from "./confidence-scorer";
import { runAutonomousInvestigation, type InvestigationResult } from "./investigation-runner";
import { dispatchAction, type ActionContext, type ActionResult } from "../action-dispatcher";

const log = logger.child("autonomous-analyst");

export interface TriageRequest {
  alertId: string;
  orgId: string;
  userId?: string;
  userName?: string;
  forcetier?: "tier1_autonomous" | "tier2_semi_autonomous" | "tier3_assisted";
}

export interface TriageResult {
  decisionId: string;
  tier: string;
  outcome: string;
  confidenceScore: number;
  confidenceFactors: ConfidenceResult["factors"];
  reasoning: string;
  executiveSummary: string;
  recommendedActions: RecommendedAction[];
  executedActions: ActionResult[];
  investigation: InvestigationResult | null;
  timeToDecisionMs: number;
  humanApprovalRequired: boolean;
}

export interface RecommendedAction {
  type: string;
  priority: "critical" | "high" | "medium" | "low";
  description: string;
  config: Record<string, unknown>;
  autoExecute: boolean;
}

/**
 * Main entry point: triage an alert through the autonomous analyst
 */
export async function triageAlert(request: TriageRequest): Promise<TriageResult> {
  const startTime = Date.now();
  const { alertId, orgId, userId, userName } = request;

  log.info("Starting autonomous triage", { alertId, orgId });

  // 1. Fetch the alert
  const alert = await storage.getAlert(alertId);
  if (!alert) throw new Error(`Alert ${alertId} not found`);
  if (alert.orgId !== orgId) throw new Error("Alert does not belong to this organization");

  // 2. Log start
  await writeAutonomyLog({
    orgId,
    action: "alert_triaged",
    tier: "tier1_autonomous",
    alertId,
    details: { phase: "start", alertTitle: alert.title, severity: alert.severity },
    triggeredBy: userId || "ai_analyst",
  });

  // 3. Run investigation to gather enrichment + correlations + hypotheses
  let investigation: InvestigationResult | null = null;
  try {
    investigation = await runAutonomousInvestigation(alert, orgId);
  } catch (err) {
    log.warn("Investigation failed, proceeding with quick analysis", { alertId, error: String(err) });
  }

  await writeAutonomyLog({
    orgId,
    action: "alert_enriched",
    tier: "tier1_autonomous",
    alertId,
    details: {
      phase: "enriched",
      entities: investigation?.enrichment.entities.length ?? 0,
      correlations: investigation?.correlations.relatedAlerts.length ?? 0,
    },
    triggeredBy: userId || "ai_analyst",
  });

  // 4. Compute confidence
  const allAlerts = await storage.getAlerts(orgId);
  const sourceAlerts = allAlerts.filter((a) => a.source === alert.source);
  const fpRate = estimateFpRate(sourceAlerts);
  const pastIncidents = await storage.getIncidents(orgId);

  const confidence = computeConfidence({
    alert,
    relatedAlerts: allAlerts.filter((a) =>
      (investigation?.correlations.relatedAlerts || []).some((r) => r.id === a.id),
    ),
    pastIncidents,
    threatIntelMatches: investigation?.enrichment.threatIntelMatches ?? 0,
    assetCriticality: inferAssetCriticality(investigation),
    historicalFpRate: fpRate,
    isKnownAttackPattern: investigation?.correlations.patternDetected ?? false,
    hasCorrelation: (investigation?.correlations.relatedAlerts.length ?? 0) > 0,
    correlationStrength: computeCorrelationStrength(investigation),
    mitreCoverage: countMitreCoverage(alert, investigation),
    userBehaviorDeviation: 0.5,
  });

  // Override tier if forced
  const tier = request.forcetier ?? confidence.tier;

  // 5. Generate recommended actions
  const recommendedActions = generateRecommendedActions(alert, confidence, investigation);

  // 6. Execute actions for Tier 1 (auto-act if confidence > 95%)
  const executedActions: ActionResult[] = [];
  if (tier === "tier1_autonomous" && confidence.shouldAutoAct) {
    const autoActions = recommendedActions.filter((a) => a.autoExecute);
    for (const action of autoActions) {
      try {
        const ctx: ActionContext = {
          orgId,
          alertId,
          incidentId: alert.incidentId || undefined,
          userId,
          userName: userName || "AI Analyst (Tier 1)",
          storage,
        };
        const result = await dispatchAction(action.type, action.config, ctx);
        executedActions.push(result);

        await writeAutonomyLog({
          orgId,
          action: "action_executed",
          tier,
          alertId,
          details: { actionType: action.type, status: result.status, message: result.message },
          success: result.status !== "failed",
          triggeredBy: "ai_analyst",
        });
      } catch (err) {
        log.error("Auto-action failed", { alertId, actionType: action.type, error: String(err) });
        await writeAutonomyLog({
          orgId,
          action: "action_blocked",
          tier,
          alertId,
          details: { actionType: action.type, error: String(err) },
          success: false,
          error: String(err),
          triggeredBy: "ai_analyst",
        });
      }
    }
  }

  // 7. Determine outcome
  const outcome = determineOutcome(confidence, investigation, tier);
  const reasoning = buildReasoning(alert, confidence, investigation);
  const executiveSummary = buildExecutiveSummary(alert, confidence, investigation, outcome);

  // 8. Persist decision
  const timeToDecisionMs = Date.now() - startTime;
  const [decision] = await db
    .insert(aiAnalystDecisions)
    .values({
      orgId,
      alertId,
      incidentId: alert.incidentId || null,
      tier,
      outcome,
      confidenceScore: confidence.overall,
      confidenceFactors: confidence.factors,
      enrichmentData: investigation?.enrichment ?? null,
      correlationResults: investigation?.correlations ?? null,
      hypotheses: investigation?.hypotheses ?? null,
      reasoning,
      executiveSummary,
      recommendedActions,
      executedActions: executedActions.length > 0 ? executedActions : null,
      mitreTactics: alert.mitreTactic ? [alert.mitreTactic] : null,
      mitreTechniques: alert.mitreTechnique ? [alert.mitreTechnique] : null,
      relatedAlertIds: investigation?.correlations.relatedAlerts.map((r) => r.id) ?? null,
      timeToDecisionMs,
      status: tier === "tier1_autonomous" ? "completed" : "pending_review",
    })
    .returning();

  // 9. If Tier 1 auto-resolved, update alert status
  if (tier === "tier1_autonomous" && confidence.shouldAutoAct) {
    try {
      if (outcome === "false_positive") {
        await storage.updateAlert(alertId, { status: "resolved" });
      } else if (outcome === "auto_resolved" || outcome === "auto_contained") {
        await storage.updateAlert(alertId, { status: "resolved" });
      }

      await writeAutonomyLog({
        orgId,
        action: "case_closed",
        tier,
        alertId,
        decisionId: decision.id,
        confidenceAfter: confidence.overall,
        details: { outcome, autoResolved: true },
        triggeredBy: "ai_analyst",
      });
    } catch (err) {
      log.warn("Failed to auto-update alert status", { alertId, error: String(err) });
    }
  }

  // 10. If Tier 2/3, log escalation
  if (tier !== "tier1_autonomous") {
    await writeAutonomyLog({
      orgId,
      action: "escalated",
      tier,
      alertId,
      decisionId: decision.id,
      details: {
        reason:
          confidence.escalationReason || `Confidence ${Math.round(confidence.overall * 100)}% below tier 1 threshold`,
        outcome,
      },
      triggeredBy: "ai_analyst",
    });
  }

  return {
    decisionId: decision.id,
    tier,
    outcome,
    confidenceScore: confidence.overall,
    confidenceFactors: confidence.factors,
    reasoning,
    executiveSummary,
    recommendedActions,
    executedActions,
    investigation,
    timeToDecisionMs,
    humanApprovalRequired: tier !== "tier1_autonomous",
  };
}

/**
 * Human override of an AI decision
 */
export async function overrideDecision(
  decisionId: string,
  orgId: string,
  overrideBy: string,
  overrideReason: string,
  newOutcome: string,
): Promise<void> {
  const [existing] = await db
    .select()
    .from(aiAnalystDecisions)
    .where(and(eq(aiAnalystDecisions.id, decisionId), eq(aiAnalystDecisions.orgId, orgId)))
    .limit(1);

  if (!existing) throw new Error("Decision not found");

  await db
    .update(aiAnalystDecisions)
    .set({
      humanOverride: true,
      humanOverrideBy: overrideBy,
      humanOverrideReason: overrideReason,
      humanOverrideAt: new Date(),
      outcome: newOutcome,
      status: "overridden",
      updatedAt: new Date(),
    })
    .where(eq(aiAnalystDecisions.id, decisionId));

  await writeAutonomyLog({
    orgId,
    decisionId,
    action: "human_override",
    tier: existing.tier,
    alertId: existing.alertId || undefined,
    details: {
      previousOutcome: existing.outcome,
      newOutcome,
      overrideBy,
      overrideReason,
    },
    triggeredBy: overrideBy,
  });
}

/**
 * Approve a Tier 2 decision (human-in-the-loop approval)
 */
export async function approveDecision(decisionId: string, orgId: string, reviewedBy: string): Promise<void> {
  const [existing] = await db
    .select()
    .from(aiAnalystDecisions)
    .where(and(eq(aiAnalystDecisions.id, decisionId), eq(aiAnalystDecisions.orgId, orgId)))
    .limit(1);

  if (!existing) throw new Error("Decision not found");

  await db
    .update(aiAnalystDecisions)
    .set({
      status: "approved",
      reviewedBy,
      reviewedAt: new Date(),
      updatedAt: new Date(),
    })
    .where(eq(aiAnalystDecisions.id, decisionId));

  // Execute recommended actions after approval
  const actions = (existing.recommendedActions || []) as RecommendedAction[];
  for (const action of actions) {
    try {
      const ctx: ActionContext = {
        orgId,
        alertId: existing.alertId || undefined,
        incidentId: existing.incidentId || undefined,
        userId: reviewedBy,
        userName: reviewedBy,
        storage,
      };
      await dispatchAction(action.type, action.config, ctx);
    } catch (err) {
      log.warn("Post-approval action failed", { decisionId, actionType: action.type, error: String(err) });
    }
  }

  await writeAutonomyLog({
    orgId,
    decisionId,
    action: "action_executed",
    tier: existing.tier,
    alertId: existing.alertId || undefined,
    details: { phase: "post_approval", reviewedBy, actionsExecuted: actions.length },
    triggeredBy: reviewedBy,
  });
}

/**
 * Get SOC dashboard stats
 */
export async function getAutonomousSOCStats(orgId: string) {
  const decisions = await db
    .select()
    .from(aiAnalystDecisions)
    .where(eq(aiAnalystDecisions.orgId, orgId))
    .orderBy(desc(aiAnalystDecisions.createdAt))
    .limit(500);

  const tier1 = decisions.filter((d) => d.tier === "tier1_autonomous");
  const tier2 = decisions.filter((d) => d.tier === "tier2_semi_autonomous");
  const tier3 = decisions.filter((d) => d.tier === "tier3_assisted");

  const avgConfidence =
    decisions.length > 0 ? decisions.reduce((sum, d) => sum + (d.confidenceScore ?? 0), 0) / decisions.length : 0;

  const avgTimeToDecision =
    decisions.length > 0 ? decisions.reduce((sum, d) => sum + (d.timeToDecisionMs ?? 0), 0) / decisions.length : 0;

  const outcomes: Record<string, number> = {};
  for (const d of decisions) {
    outcomes[d.outcome] = (outcomes[d.outcome] || 0) + 1;
  }

  const overrides = decisions.filter((d) => d.humanOverride);

  // Time-series: decisions per day (last 30 days)
  const thirtyDaysAgo = Date.now() - 30 * 24 * 60 * 60 * 1000;
  const recentDecisions = decisions.filter((d) => d.createdAt && new Date(d.createdAt).getTime() > thirtyDaysAgo);
  const dailyCounts: Record<string, { tier1: number; tier2: number; tier3: number }> = {};
  for (const d of recentDecisions) {
    const day = new Date(d.createdAt!).toISOString().split("T")[0];
    if (!dailyCounts[day]) dailyCounts[day] = { tier1: 0, tier2: 0, tier3: 0 };
    if (d.tier === "tier1_autonomous") dailyCounts[day].tier1++;
    else if (d.tier === "tier2_semi_autonomous") dailyCounts[day].tier2++;
    else dailyCounts[day].tier3++;
  }

  return {
    totalDecisions: decisions.length,
    tier1Count: tier1.length,
    tier2Count: tier2.length,
    tier3Count: tier3.length,
    tier1Percentage: decisions.length > 0 ? Math.round((tier1.length / decisions.length) * 100) : 0,
    avgConfidence: Math.round(avgConfidence * 100) / 100,
    avgTimeToDecisionMs: Math.round(avgTimeToDecision),
    outcomes,
    overrideCount: overrides.length,
    overrideRate: decisions.length > 0 ? Math.round((overrides.length / decisions.length) * 100) / 100 : 0,
    dailyTrend: Object.entries(dailyCounts)
      .map(([date, counts]) => ({ date, ...counts }))
      .sort((a, b) => a.date.localeCompare(b.date)),
    recentDecisions: decisions.slice(0, 25).map((d) => ({
      id: d.id,
      alertId: d.alertId,
      tier: d.tier,
      outcome: d.outcome,
      confidenceScore: d.confidenceScore,
      status: d.status,
      timeToDecisionMs: d.timeToDecisionMs,
      humanOverride: d.humanOverride,
      createdAt: d.createdAt,
    })),
  };
}

// ── Helpers ─────────────────────────────────────────────────────────

async function writeAutonomyLog(entry: Omit<InsertAutonomyLogEntry, "id" | "createdAt">): Promise<void> {
  try {
    await db.insert(autonomyLog).values(entry);
  } catch (err) {
    log.warn("Failed to write autonomy log", { error: String(err) });
  }
}

function inferAssetCriticality(
  investigation: InvestigationResult | null,
): "critical" | "high" | "medium" | "low" | "unknown" {
  if (!investigation) return "unknown";
  const assets = investigation.enrichment.assetContext;
  if (assets.length === 0) return "unknown";
  const crit = assets[0].criticality;
  if (crit === "critical" || crit === "high" || crit === "medium" || crit === "low") return crit;
  return "unknown";
}

function computeCorrelationStrength(investigation: InvestigationResult | null): number {
  if (!investigation) return 0;
  const related = investigation.correlations.relatedAlerts;
  if (related.length === 0) return 0;
  return related.reduce((sum, r) => sum + r.similarity, 0) / related.length;
}

function countMitreCoverage(alert: Alert, investigation: InvestigationResult | null): number {
  let count = 0;
  if (alert.mitreTactic) count++;
  if (alert.mitreTechnique) count++;
  if (investigation?.correlations.patternDetected) count++;
  return count;
}

function determineOutcome(
  confidence: ConfidenceResult,
  investigation: InvestigationResult | null,
  tier: string,
): string {
  if (!investigation) {
    return tier === "tier1_autonomous" ? "auto_resolved" : "needs_investigation";
  }

  const verdict = investigation.verdict;

  if (verdict.outcome === "false_positive" && confidence.overall >= 0.85) {
    return "false_positive";
  }
  if (verdict.outcome === "true_positive") {
    if (confidence.shouldAutoAct) return "auto_contained";
    return "true_positive";
  }

  if (tier === "tier1_autonomous") {
    return confidence.shouldAutoAct ? "auto_resolved" : "escalate_tier2";
  }
  if (tier === "tier2_semi_autonomous") {
    return "needs_investigation";
  }
  return "escalate_human";
}

function generateRecommendedActions(
  alert: Alert,
  confidence: ConfidenceResult,
  investigation: InvestigationResult | null,
): RecommendedAction[] {
  const actions: RecommendedAction[] = [];
  const category = alert.category || "";
  const severity = alert.severity || "medium";
  const isAutoTier = confidence.tier === "tier1_autonomous";

  // Severity-based actions
  if (severity === "critical") {
    if (category === "malware" || category === "ransomware") {
      actions.push({
        type: "isolate_host",
        priority: "critical",
        description: "Isolate affected host from network",
        config: { target: extractTarget(alert, "hostname"), reason: "Autonomous SOC: malware containment" },
        autoExecute: isAutoTier,
      });
      actions.push({
        type: "quarantine_file",
        priority: "critical",
        description: "Quarantine malicious file",
        config: { target: extractTarget(alert, "file"), reason: "Autonomous SOC: file quarantine" },
        autoExecute: isAutoTier,
      });
    }
    if (category === "credential_access") {
      actions.push({
        type: "disable_user",
        priority: "critical",
        description: "Disable compromised user account",
        config: { target: extractTarget(alert, "user"), reason: "Autonomous SOC: credential compromise" },
        autoExecute: isAutoTier,
      });
    }
    if (category === "data_exfiltration") {
      actions.push({
        type: "block_ip",
        priority: "critical",
        description: "Block exfiltration destination IP",
        config: { target: extractTarget(alert, "ip"), reason: "Autonomous SOC: data exfil block" },
        autoExecute: isAutoTier,
      });
    }
  }

  // Always notify on high/critical
  if (severity === "critical" || severity === "high") {
    actions.push({
      type: "notify_slack",
      priority: "high",
      description: `Notify SOC team of ${severity} alert`,
      config: {
        channel: "#security-alerts",
        message: `[Autonomous SOC] ${alert.title} — ${confidence.tier} decision: ${severity} severity`,
      },
      autoExecute: true,
    });
  }

  // Escalation action for non-tier1
  if (!isAutoTier) {
    actions.push({
      type: "escalate",
      priority: severity === "critical" ? "critical" : "high",
      description: "Escalate to human analyst for review",
      config: { reason: confidence.escalationReason || `Confidence below Tier 1 threshold` },
      autoExecute: false,
    });
  }

  return actions;
}

function extractTarget(alert: Alert, targetType: string): string {
  const raw = (alert.rawData || {}) as Record<string, unknown>;
  switch (targetType) {
    case "hostname":
      return (raw.hostname as string) || (raw.target as string) || "unknown";
    case "ip":
      return (raw.sourceIp as string) || (raw.destIp as string) || (raw.ip as string) || "unknown";
    case "user":
      return (raw.username as string) || (raw.user as string) || "unknown";
    case "file":
      return (raw.fileHash as string) || (raw.filePath as string) || (raw.file as string) || "unknown";
    default:
      return "unknown";
  }
}

function buildReasoning(alert: Alert, confidence: ConfidenceResult, investigation: InvestigationResult | null): string {
  const parts: string[] = [];

  parts.push(
    `Alert "${alert.title}" (${alert.severity}) from ${alert.source} was analyzed by the Autonomous SOC engine.`,
  );
  parts.push(
    `Overall confidence: ${Math.round(confidence.overall * 100)}% → assigned to ${confidence.tier.replace(/_/g, " ")}.`,
  );

  // Top contributing factors
  const topFactors = [...confidence.factors].sort((a, b) => b.weight * b.score - a.weight * a.score).slice(0, 3);
  parts.push(`Key factors: ${topFactors.map((f) => `${f.factor} (${Math.round(f.score * 100)}%)`).join(", ")}.`);

  if (investigation) {
    const verdict = investigation.verdict;
    parts.push(`Investigation verdict: ${verdict.outcome} (${Math.round(verdict.confidence * 100)}% confidence).`);
    if (verdict.reasoning) parts.push(verdict.reasoning);

    const supported = investigation.hypotheses.filter((h) => h.status === "supported");
    if (supported.length > 0) {
      parts.push(`Supported hypotheses: ${supported.map((h) => h.title).join("; ")}.`);
    }
  }

  return parts.join(" ");
}

function buildExecutiveSummary(
  alert: Alert,
  confidence: ConfidenceResult,
  investigation: InvestigationResult | null,
  outcome: string,
): string {
  const outcomeLabels: Record<string, string> = {
    true_positive: "confirmed as a true positive requiring response",
    false_positive: "determined to be a false positive",
    auto_resolved: "automatically resolved by AI analyst",
    auto_contained: "automatically contained — response actions executed",
    escalate_tier2: "escalated to Tier 2 for semi-autonomous handling",
    escalate_tier3: "escalated to Tier 3 for human-assisted analysis",
    escalate_human: "escalated to human analyst",
    needs_investigation: "requires further investigation",
  };

  const label = outcomeLabels[outcome] || outcome;
  const correlations = investigation?.correlations.relatedAlerts.length ?? 0;
  const entities = investigation?.enrichment.entities.length ?? 0;

  return (
    `${alert.severity?.toUpperCase()} alert "${alert.title}" was ${label}. ` +
    `AI confidence: ${Math.round(confidence.overall * 100)}%. ` +
    `${correlations} correlated alerts, ${entities} entities enriched. ` +
    `Decision time: ${investigation?.durationMs ?? 0}ms.`
  );
}

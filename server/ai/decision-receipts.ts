import { and, desc, eq } from "drizzle-orm";
import { db } from "../db";
import {
  aiAnalystDecisions,
  aiDecisionEvidence,
  aiDecisionRedactionReceipts,
  aiInferenceLog,
  type Alert,
  type InsertAiDecisionEvidence,
} from "@shared/schema";
import type { InvestigationResult } from "./investigation-runner";

export async function persistInferenceEntry(
  metrics: {
    tier: string;
    model: string;
    inputTokensEstimate: number;
    outputTokensEstimate: number;
    latencyMs: number;
    costEstimateUsd: number | null;
    cached: boolean;
    promptId?: string;
    promptVersion?: number;
  },
  success: boolean,
  errorMessage: string | undefined,
  orgId: string | undefined,
  decisionId: string | undefined,
): Promise<void> {
  await db.insert(aiInferenceLog).values({
    tier: metrics.tier,
    model: metrics.model,
    promptId: metrics.promptId,
    promptVersion: metrics.promptVersion,
    inputTokens: metrics.inputTokensEstimate,
    outputTokens: metrics.outputTokensEstimate,
    latencyMs: metrics.latencyMs,
    costEstimateUsd: metrics.costEstimateUsd ?? 0,
    cached: metrics.cached,
    success,
    errorMessage,
    orgId,
    decisionId,
  });
}

export async function createDecisionReceipt(params: {
  orgId: string;
  alertId: string;
  incidentId?: string | null;
  tier: string;
}): Promise<string> {
  const [decision] = await db
    .insert(aiAnalystDecisions)
    .values({
      orgId: params.orgId,
      alertId: params.alertId,
      incidentId: params.incidentId ?? null,
      tier: params.tier,
      outcome: "pending",
      confidenceScore: null,
      status: "processing",
    })
    .returning({ id: aiAnalystDecisions.id });
  return decision.id;
}

export async function persistDecisionEvidence(
  orgId: string,
  decisionId: string,
  alert: Alert,
  investigation: InvestigationResult | null,
): Promise<void> {
  const rows: InsertAiDecisionEvidence[] = [
    {
      orgId,
      decisionId,
      sourceKind: "alert",
      sourceTable: "alerts",
      sourcePrimaryKey: alert.id,
      evidenceRole: "context",
      evidenceWeight: 1,
      valueSnapshot: alert,
    },
  ];
  for (const hypothesis of investigation?.hypotheses ?? []) {
    for (const evidence of hypothesis.evidenceFor) {
      rows.push({
        orgId,
        decisionId,
        sourceKind: "investigation_analysis",
        sourceTable: "alerts",
        sourcePrimaryKey: alert.id,
        evidenceRole: "supporting",
        evidenceWeight: evidence.weight,
        valueSnapshot: { hypothesis: hypothesis.id, ...evidence },
      });
    }
    for (const evidence of hypothesis.evidenceAgainst) {
      rows.push({
        orgId,
        decisionId,
        sourceKind: "investigation_analysis",
        sourceTable: "alerts",
        sourcePrimaryKey: alert.id,
        evidenceRole: "contradicting",
        evidenceWeight: evidence.weight,
        valueSnapshot: { hypothesis: hypothesis.id, ...evidence },
      });
    }
  }
  for (const related of investigation?.correlations.relatedAlerts ?? []) {
    rows.push({
      orgId,
      decisionId,
      sourceKind: "correlated_alert",
      sourceTable: "alerts",
      sourcePrimaryKey: related.id,
      evidenceRole: "context",
      evidenceWeight: related.similarity,
      valueSnapshot: related,
    });
  }
  for (const related of investigation?.correlations.relatedIncidents ?? []) {
    rows.push({
      orgId,
      decisionId,
      sourceKind: "correlated_incident",
      sourceTable: "incidents",
      sourcePrimaryKey: related.id,
      evidenceRole: "context",
      evidenceWeight: related.similarity,
      valueSnapshot: related,
    });
  }
  if (rows.length > 0) await db.insert(aiDecisionEvidence).values(rows);
}

export async function persistRedactionReceipt(params: {
  orgId?: string;
  decisionId?: string;
  invocationId: string;
  redactions: unknown;
}): Promise<void> {
  if (!params.orgId || !params.decisionId) return;
  await db.insert(aiDecisionRedactionReceipts).values({
    orgId: params.orgId,
    decisionId: params.decisionId,
    invocationId: params.invocationId,
    redactedClasses: params.redactions,
    redacted: Array.isArray(params.redactions) && params.redactions.length > 0,
  });
}

export async function finalizeDecisionReceipt(
  orgId: string,
  decisionId: string,
  values: Partial<typeof aiAnalystDecisions.$inferInsert>,
): Promise<void> {
  const totals = await db
    .select({
      model: aiInferenceLog.model,
      promptId: aiInferenceLog.promptId,
      promptVersion: aiInferenceLog.promptVersion,
      inputTokens: aiInferenceLog.inputTokens,
      outputTokens: aiInferenceLog.outputTokens,
      cost: aiInferenceLog.costEstimateUsd,
      latency: aiInferenceLog.latencyMs,
    })
    .from(aiInferenceLog)
    .where(and(eq(aiInferenceLog.orgId, orgId), eq(aiInferenceLog.decisionId, decisionId)))
    .orderBy(desc(aiInferenceLog.createdAt));
  const model = totals[0]?.model ?? null;
  const promptVersion = totals[0]?.promptVersion ?? null;
  const promptId = totals[0]?.promptId ?? null;
  await db
    .update(aiAnalystDecisions)
    .set({
      ...values,
      model: values.model ?? model,
      promptId: values.promptId ?? promptId,
      promptVersion: values.promptVersion ?? promptVersion,
      totalInputTokens: totals.length > 0 ? totals.reduce((sum, row) => sum + row.inputTokens, 0) : null,
      totalOutputTokens: totals.length > 0 ? totals.reduce((sum, row) => sum + row.outputTokens, 0) : null,
      totalCostUsd: totals.length > 0 ? totals.reduce((sum, row) => sum + Number(row.cost), 0) : null,
      totalLatencyMs: totals.length > 0 ? totals.reduce((sum, row) => sum + row.latency, 0) : null,
      updatedAt: new Date(),
    })
    .where(and(eq(aiAnalystDecisions.id, decisionId), eq(aiAnalystDecisions.orgId, orgId)));
}

export async function getDecisionReceipt(
  orgId: string,
  decisionId: string,
): Promise<{
  evidence: (typeof aiDecisionEvidence.$inferSelect)[];
  inference: (typeof aiInferenceLog.$inferSelect)[];
  redactions: (typeof aiDecisionRedactionReceipts.$inferSelect)[];
}> {
  const [evidence, inference, redactions] = await Promise.all([
    db
      .select()
      .from(aiDecisionEvidence)
      .where(and(eq(aiDecisionEvidence.orgId, orgId), eq(aiDecisionEvidence.decisionId, decisionId))),
    db
      .select()
      .from(aiInferenceLog)
      .where(and(eq(aiInferenceLog.orgId, orgId), eq(aiInferenceLog.decisionId, decisionId))),
    db
      .select()
      .from(aiDecisionRedactionReceipts)
      .where(and(eq(aiDecisionRedactionReceipts.orgId, orgId), eq(aiDecisionRedactionReceipts.decisionId, decisionId))),
  ]);
  return { evidence, inference, redactions };
}

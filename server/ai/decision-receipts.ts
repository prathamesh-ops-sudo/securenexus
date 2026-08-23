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
import { AI_DECISION_OUTCOMES } from "@shared/schema";

export type RetrievalStatus = "available" | "empty" | "unavailable" | "not_attempted";

export function assertDecisionOutcome(outcome: string | null | undefined): void {
  if (outcome != null && !(AI_DECISION_OUTCOMES as readonly string[]).includes(outcome)) {
    throw new Error(`Invalid AI decision outcome: ${outcome}`);
  }
}

export function summarizeInferenceEntries(
  totals: Array<{
    model: string;
    promptId: string | null;
    promptVersion: number | null;
    inputTokens: number | null;
    outputTokens: number | null;
    cost: number | null;
    latency: number | null;
  }>,
): {
  model: string | null;
  promptId: string | null;
  promptVersion: number | null;
  totalInputTokens: number | null;
  totalOutputTokens: number | null;
  totalCostUsd: number | null;
  totalLatencyMs: number | null;
  unmeasuredInvocationCount: number;
} {
  const distinct = <T>(items: (T | null | undefined)[]): T[] =>
    Array.from(new Set(items.filter((item): item is T => item != null)));
  const models = distinct(totals.map((row) => row.model));
  const promptIds = distinct(totals.map((row) => row.promptId));
  const promptVersions = distinct(totals.map((row) => row.promptVersion));
  const sumNullable = (valuesToSum: (number | null)[]): number | null => {
    const measured = valuesToSum.filter((value): value is number => value != null);
    return measured.length > 0 ? measured.reduce((sum, value) => sum + value, 0) : null;
  };
  return {
    model: models.length === 1 ? models[0] : models.length > 1 ? "multiple" : null,
    promptId: promptIds.length === 1 ? promptIds[0] : promptIds.length > 1 ? "multiple" : null,
    promptVersion: promptVersions.length === 1 ? promptVersions[0] : null,
    totalInputTokens: sumNullable(totals.map((row) => row.inputTokens)),
    totalOutputTokens: sumNullable(totals.map((row) => row.outputTokens)),
    totalCostUsd: sumNullable(totals.map((row) => row.cost)),
    totalLatencyMs: sumNullable(totals.map((row) => row.latency)),
    unmeasuredInvocationCount: totals.filter(
      (row) => row.inputTokens == null || row.outputTokens == null || row.cost == null || row.latency == null,
    ).length,
  };
}

export async function persistInferenceEntry(
  metrics: {
    tier: string;
    model: string;
    inputTokensEstimate: number | null;
    outputTokensEstimate: number | null;
    latencyMs: number | null;
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
    costEstimateUsd: metrics.costEstimateUsd,
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
      outcome: null,
      confidenceScore: null,
      status: "processing",
      proofReceiptCaptured: true,
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
        sourceTable: null,
        sourcePrimaryKey: null,
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
        sourceTable: null,
        sourcePrimaryKey: null,
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
  assertDecisionOutcome(values.outcome);
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
  const summary = summarizeInferenceEntries(totals);
  await db
    .update(aiAnalystDecisions)
    .set({
      ...values,
      model: totals.length > 0 ? summary.model : (values.model ?? null),
      promptId: totals.length > 0 ? summary.promptId : (values.promptId ?? null),
      promptVersion: totals.length > 0 ? summary.promptVersion : (values.promptVersion ?? null),
      totalInputTokens: summary.totalInputTokens,
      totalOutputTokens: summary.totalOutputTokens,
      totalCostUsd: summary.totalCostUsd,
      totalLatencyMs: summary.totalLatencyMs,
      unmeasuredInvocationCount: summary.unmeasuredInvocationCount,
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

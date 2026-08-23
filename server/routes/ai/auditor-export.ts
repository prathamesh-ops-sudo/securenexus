import type { Express, Request } from "express";
import { and, desc, eq } from "drizzle-orm";
import {
  aiAnalystDecisions,
  aiDecisionAdjudications,
  autonomyLog,
  type AiAnalystDecision,
  type AiInferenceLog,
} from "@shared/schema";
import { isAuthenticated } from "../../auth";
import { db } from "../../db";
import { requireMinRole, requireOrgId, resolveOrgContext } from "../../rbac";
import { getOrgId, logger, reply, replyError } from "../shared";
import { getDecisionReceipt } from "../../ai/decision-receipts";
import {
  verifyDecisionIntegrity,
  verifyTenantDecisionIntegrity,
  type DecisionIntegrityResult,
} from "../../ai/decision-integrity";
import { createAuditLog } from "../../storage/audit";
import { getProofRetentionStatus } from "../../ai/proof-retention";

const log = logger.child("routes-ai-auditor-export");
const RETRIEVAL_STATUSES = new Set(["not_attempted", "empty", "unavailable", "available"]);

type AbsentSection<T> = {
  items: T[];
  absentReason: string | null;
};

export function auditorSection<T>(items: T[], reason: string): AbsentSection<T> {
  return { items, absentReason: items.length > 0 ? null : reason };
}

export function getRetrievalExportState(decision: AiAnalystDecision): {
  state: string | null;
  reason: string | null;
} {
  if (!decision.retrievalStatus || !RETRIEVAL_STATUSES.has(decision.retrievalStatus)) {
    return { state: null, reason: "Retrieval state was not recorded for this decision." };
  }
  return {
    state: decision.retrievalStatus,
    reason: decision.retrievalStatus === "unavailable" ? "The retrieval attempt was unavailable." : null,
  };
}

export function formatInvocationForExport(entry: AiInferenceLog): Record<string, unknown> {
  return {
    ...entry,
    inputTokens: entry.inputTokens ?? "unmeasured",
    outputTokens: entry.outputTokens ?? "unmeasured",
    latencyMs: entry.latencyMs ?? "unmeasured",
    costEstimateUsd: entry.costEstimateUsd ?? "unmeasured",
  };
}

async function loadDecision(orgId: string, decisionId: string): Promise<AiAnalystDecision | null> {
  const [decision] = await db
    .select()
    .from(aiAnalystDecisions)
    .where(and(eq(aiAnalystDecisions.orgId, orgId), eq(aiAnalystDecisions.id, decisionId)))
    .limit(1);
  return decision ?? null;
}

async function buildExport(
  orgId: string,
  decision: AiAnalystDecision,
  exportedBy: { id: string | null; name: string | null },
): Promise<Record<string, unknown>> {
  const [receipt, actions, adjudications, integrity] = await Promise.all([
    getDecisionReceipt(orgId, decision.id),
    db
      .select()
      .from(autonomyLog)
      .where(and(eq(autonomyLog.orgId, orgId), eq(autonomyLog.decisionId, decision.id)))
      .orderBy(desc(autonomyLog.createdAt)),
    db
      .select()
      .from(aiDecisionAdjudications)
      .where(and(eq(aiDecisionAdjudications.orgId, orgId), eq(aiDecisionAdjudications.decisionId, decision.id)))
      .orderBy(desc(aiDecisionAdjudications.adjudicatedAt)),
    verifyDecisionIntegrity(orgId, decision.id),
  ]);
  const retrieval = getRetrievalExportState(decision);
  return {
    decision: {
      tenantId: decision.orgId,
      id: decision.id,
      alertId: decision.alertId,
      incidentId: decision.incidentId,
      outcome: decision.outcome ?? "not recorded",
      status: decision.status,
      confidence: decision.confidenceScore ?? "not recorded",
      autonomyMode: decision.autonomyMode ?? "not recorded",
      replayRunId: decision.replayRunId ?? "not recorded",
    },
    evidence: auditorSection(receipt.evidence, "No evidence rows were recorded for this decision."),
    modelInvocations: auditorSection(
      receipt.inference.map(formatInvocationForExport),
      "No model invocations were recorded for this decision.",
    ),
    retrieval,
    redactionReceipts: auditorSection(receipt.redactions, "No redaction receipts were recorded for this decision."),
    actions: auditorSection(actions, "No action, withholding, or approval records were recorded for this decision."),
    adjudications: auditorSection(adjudications, "No adjudications were recorded for this decision."),
    integrity,
    retention: getProofRetentionStatus(decision.createdAt ?? new Date()),
    metadata: {
      exportedBy: exportedBy.id,
      exportedByName: exportedBy.name,
      exportedAt: new Date().toISOString(),
      tenantId: orgId,
      integrityDigest: decision.integrityDigest,
    },
  };
}

function userIdentity(req: Request): { id: string | null; name: string | null } {
  const user = (req as any).user as { id?: string; name?: string; email?: string } | undefined;
  return { id: user?.id ?? null, name: user?.name ?? user?.email ?? null };
}

export function registerAiAuditorExportRoutes(app: Express): void {
  app.get(
    "/api/ai/decisions/:id/export",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const decisionId = String(req.params.id);
        const decision = await loadDecision(orgId, decisionId);
        if (!decision) return replyError(res, 404, [{ code: "NOT_FOUND", message: "Decision not found" }]);
        const user = userIdentity(req);
        const payload = await buildExport(orgId, decision, user);
        await createAuditLog({
          orgId,
          userId: user.id,
          userName: user.name ?? undefined,
          action: "ai_decision_exported",
          resourceType: "ai_decision",
          resourceId: decisionId,
          details: { integrityDigest: decision.integrityDigest, format: "json" },
        });
        return reply(res, payload);
      } catch (error) {
        log.error("Failed to export AI decision", { error: String(error) });
        return replyError(res, 500, [{ code: "AI_DECISION_EXPORT_FAILED", message: "Failed to export AI decision" }]);
      }
    },
  );

  app.get(
    "/api/ai/decisions/:id/integrity",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const decision = await loadDecision(orgId, String(req.params.id));
        if (!decision) return replyError(res, 404, [{ code: "NOT_FOUND", message: "Decision not found" }]);
        const result = await verifyDecisionIntegrity(orgId, decision.id);
        return reply(res, { ...result, retention: getProofRetentionStatus(decision.createdAt ?? new Date()) });
      } catch (error) {
        if (String(error).includes("Decision not found")) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Decision not found" }]);
        }
        log.error("Failed to verify AI decision integrity", { error: String(error) });
        return replyError(res, 500, [
          { code: "AI_DECISION_INTEGRITY_FAILED", message: "Failed to verify AI decision integrity" },
        ]);
      }
    },
  );

  app.get(
    "/api/ai/integrity",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const results: DecisionIntegrityResult[] = await verifyTenantDecisionIntegrity(getOrgId(req));
        return reply(res, { results });
      } catch (error) {
        log.error("Failed to verify AI decision history", { error: String(error) });
        return replyError(res, 500, [
          { code: "AI_DECISION_HISTORY_VERIFY_FAILED", message: "Failed to verify AI decision history" },
        ]);
      }
    },
  );
}

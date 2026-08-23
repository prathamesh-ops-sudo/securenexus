import type { Express } from "express";
import { z } from "zod";
import { isAuthenticated } from "../../auth";
import { requireMinRole, requireOrgId, resolveOrgContext } from "../../rbac";
import { getOrgId, logger, reply, replyError } from "../shared";
import { replyValidation } from "../../api-response";
import { ADJUDICATED_OUTCOMES, ADJUDICATION_SOURCES } from "@shared/schema";
import { createAdjudication, getAccuracyReport } from "../../ai/accuracy";

const log = logger.child("routes-ai-accuracy");

const windowSchema = z.object({
  from: z.coerce.date(),
  to: z.coerce.date(),
});

const adjudicationSchema = z.object({
  adjudicatedOutcome: z.enum(ADJUDICATED_OUTCOMES),
  source: z.enum(ADJUDICATION_SOURCES),
  rationale: z.string().trim().min(1).max(4000),
  isFinal: z.boolean(),
});

export function registerAiAccuracyRoutes(app: Express): void {
  app.get(
    "/api/ai/accuracy",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      const parsed = windowSchema.safeParse(req.query);
      if (!parsed.success) return replyValidation(res, [{ message: "from and to are required ISO dates" }]);
      if (parsed.data.to <= parsed.data.from) return replyValidation(res, [{ message: "to must be after from" }]);
      try {
        const report = await getAccuracyReport(
          getOrgId(req),
          parsed.data.from.toISOString(),
          parsed.data.to.toISOString(),
        );
        return reply(res, report, { from: parsed.data.from.toISOString(), to: parsed.data.to.toISOString() });
      } catch (error) {
        log.error("Failed to calculate AI accuracy", { error: String(error) });
        return replyError(res, 500, [{ code: "ACCURACY_QUERY_FAILED", message: "Failed to calculate AI accuracy" }]);
      }
    },
  );

  app.post(
    "/api/ai/decisions/:id/adjudication",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      const parsed = adjudicationSchema.safeParse(req.body);
      if (!parsed.success)
        return replyValidation(res, [{ message: "Invalid adjudication", details: parsed.error.flatten() }]);
      try {
        const adjudication = await createAdjudication({
          ...parsed.data,
          orgId: getOrgId(req),
          decisionId: String(req.params.id),
          actorUserId: (req as any).user?.id ?? null,
        });
        return reply(res, adjudication, {}, 201);
      } catch (error) {
        if (String(error).includes("Decision not found"))
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Decision not found" }]);
        log.error("Failed to create adjudication", { error: String(error) });
        return replyError(res, 500, [{ code: "ADJUDICATION_WRITE_FAILED", message: "Failed to create adjudication" }]);
      }
    },
  );
}

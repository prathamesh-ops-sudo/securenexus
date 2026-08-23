import type { Express } from "express";
import { z } from "zod";
import { isAuthenticated } from "../../auth";
import { resolveOrgContext, requireMinRole, requireOrgId } from "../../rbac";
import { getOrgId, logger, reply, replyError } from "../shared";
import { replyValidation } from "../../api-response";
import { db, pool } from "../../db";
import { aiReplayRuns } from "@shared/schema";
import { enqueueJob } from "../../job-queue";
import { and, desc, eq } from "drizzle-orm";
import { generateSocRealityReport } from "../../ai/soc-reality-report";

const log = logger.child("routes-ai-replay");
const replaySchema = z.object({
  from: z.coerce.date(),
  to: z.coerce.date(),
  source: z.string().trim().min(1).max(128).optional(),
  severity: z.enum(["critical", "high", "medium", "low", "informational"]).optional(),
  reason: z.string().trim().min(1).max(2000),
  concurrency: z.coerce.number().int().min(1).max(10).default(1),
});

export function registerAiReplayRoutes(app: Express): void {
  app.post(
    "/api/ai/replays",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      const parsed = replaySchema.safeParse(req.body);
      if (!parsed.success) return replyValidation(res, [{ message: "Invalid historical replay request." }]);
      if (parsed.data.to <= parsed.data.from) return replyValidation(res, [{ message: "to must be after from." }]);
      try {
        const orgId = getOrgId(req);
        const [run] = await db
          .insert(aiReplayRuns)
          .values({
            orgId,
            fromAt: parsed.data.from,
            toAt: parsed.data.to,
            source: parsed.data.source ?? null,
            severity: parsed.data.severity ?? null,
            reason: parsed.data.reason,
            concurrency: parsed.data.concurrency,
            createdBy: (req.user as Express.User & { id?: string })?.id ?? null,
          })
          .returning();
        const job = await enqueueJob("historical_replay", orgId, { runId: run.id });
        if (!job) {
          await pool.query(
            `UPDATE ai_replay_runs
             SET status = 'failed', error = $2, completed_at = NOW(), updated_at = NOW()
             WHERE id = $1 AND org_id = $3`,
            [run.id, "Replay run is already queued.", orgId],
          );
          return replyError(res, 409, [{ code: "CONFLICT", message: "Replay run is already queued." }]);
        }
        await pool.query("UPDATE ai_replay_runs SET job_id = $2 WHERE id = $1 AND org_id = $3", [
          run.id,
          job.id,
          orgId,
        ]);
        return reply(res, { ...run, jobId: job.id }, {}, 202);
      } catch (error) {
        log.error("Failed to create historical replay", { error: String(error) });
        return replyError(res, 500, [{ code: "REPLAY_CREATE_FAILED", message: "Failed to create historical replay." }]);
      }
    },
  );

  app.get(
    "/api/ai/replays",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const runs = await db
          .select()
          .from(aiReplayRuns)
          .where(eq(aiReplayRuns.orgId, getOrgId(req)))
          .orderBy(desc(aiReplayRuns.createdAt))
          .limit(100);
        return reply(res, runs);
      } catch (error) {
        log.error("Failed to list historical replays", { error: String(error) });
        return replyError(res, 500, [{ code: "REPLAY_QUERY_FAILED", message: "Failed to list historical replays." }]);
      }
    },
  );

  app.get(
    "/api/ai/replays/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const [run] = await db
          .select()
          .from(aiReplayRuns)
          .where(and(eq(aiReplayRuns.id, String(req.params.id)), eq(aiReplayRuns.orgId, getOrgId(req))))
          .limit(1);
        if (!run) return replyError(res, 404, [{ code: "NOT_FOUND", message: "Replay run not found." }]);
        return reply(res, run);
      } catch (error) {
        log.error("Failed to read historical replay", { error: String(error) });
        return replyError(res, 500, [{ code: "REPLAY_QUERY_FAILED", message: "Failed to read historical replay." }]);
      }
    },
  );

  app.get(
    "/api/ai/replays/:id/report",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const [run] = await db
          .select()
          .from(aiReplayRuns)
          .where(and(eq(aiReplayRuns.id, String(req.params.id)), eq(aiReplayRuns.orgId, orgId)))
          .limit(1);
        if (!run) return replyError(res, 404, [{ code: "NOT_FOUND", message: "Replay run not found." }]);
        if (run.status !== "completed" && run.status !== "failed") {
          return replyError(res, 409, [{ code: "REPORT_UNAVAILABLE", message: "The replay report is not ready yet." }]);
        }
        const report = await generateSocRealityReport(orgId, run);
        await db
          .update(aiReplayRuns)
          .set({ report, updatedAt: new Date() })
          .where(and(eq(aiReplayRuns.id, run.id), eq(aiReplayRuns.orgId, orgId)));
        return reply(res, report);
      } catch (error) {
        log.error("Failed to generate SOC Reality Report", { error: String(error) });
        return replyError(res, 500, [
          { code: "REPORT_GENERATION_FAILED", message: "Failed to generate SOC Reality Report." },
        ]);
      }
    },
  );
}

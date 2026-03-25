import type { Express, Request, Response } from "express";
import { getOrgId, logger, p, storage, strictLimiter } from "../shared";
import { isAuthenticated } from "../../auth";
import { resolveOrgContext } from "../../rbac";
import { generateIncidentNarrative, buildThreatIntelContext, streamNarrative, streamDeepInvestigation } from "../../ai";
import { enforcePlanLimit } from "../../middleware/plan-enforcement";
import { persistAttackGraph } from "./helpers";

const log = logger.child("routes-ai-narrative");

export function registerAiNarrativeRoutes(app: Express): void {
  // POST /api/ai/narrative/:incidentId
  app.post(
    "/api/ai/narrative/:incidentId",
    isAuthenticated,
    resolveOrgContext,
    enforcePlanLimit("ai_analyses"),
    strictLimiter,
    async (req, res) => {
      try {
        const narrativeOrgId = (req as any).orgId || (req as any).user?.orgId;
        const incident = await storage.getIncident(p(req.params.incidentId));
        if (!incident || (narrativeOrgId && incident.orgId && incident.orgId !== narrativeOrgId)) {
          return res.status(404).json({ message: "Incident not found" });
        }
        const incidentAlerts = await storage.getAlertsByIncident(p(req.params.incidentId));
        const threatIntelCtx = await buildThreatIntelContext(incidentAlerts);
        const result = await generateIncidentNarrative(incident, incidentAlerts, threatIntelCtx, narrativeOrgId);
        if (threatIntelCtx.enrichmentResults.length > 0 || threatIntelCtx.osintMatches.length > 0) {
          (result as any).threatIntelSources = Array.from(
            new Set([
              ...threatIntelCtx.enrichmentResults.map((r) => r.provider),
              ...threatIntelCtx.osintMatches.map((r) => r.feedName),
            ]),
          );
        }
        const storedIocs = Array.isArray(result.iocs)
          ? result.iocs.map((ioc: any) =>
              typeof ioc === "string" ? ioc : `${ioc.value} (${ioc.type}: ${ioc.context})`,
            )
          : [];
        const { diamondModel: _dm, ...storedAttackerProfile } = result.attackerProfile || ({} as any);
        await storage.updateIncident(p(req.params.incidentId), {
          aiNarrative: result.narrative,
          aiSummary: result.summary,
          mitigationSteps: result.mitigationSteps as any,
          iocs: storedIocs as any,
          attackerProfile: storedAttackerProfile as any,
          referencedAlertIds: Array.isArray(result.citedAlertIds) ? result.citedAlertIds : [],
        });
        await storage.createAuditLog({
          userId: (req as any).user?.id,
          userName: (req as any).user?.firstName
            ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
            : "Analyst",
          action: "ai_narrative_generated",
          resourceType: "incident",
          resourceId: p(req.params.incidentId),
          details: { riskScore: result.riskScore },
        });
        try {
          await storage.incrementUsage((req as any).orgId || (req as any).user?.orgId, "ai_analyses");
        } catch (e) {
          logger.child("ai").warn("Usage tracking failed", {
            error: String(e),
            orgId: (req as any).orgId || (req as any).user?.orgId,
          });
        }
        res.json(result);
      } catch (error: any) {
        logger.child("ai").error("AI narrative error", { error: String(error) });
        res.status(500).json({ message: "AI narrative generation failed. Please try again." });
      }
    },
  );

  // SSE Streaming: Narrative
  app.get(
    "/api/ai/narrative/:incidentId/stream",
    isAuthenticated,
    resolveOrgContext,
    enforcePlanLimit("ai_analyses"),
    strictLimiter,
    async (req: Request, res: Response) => {
      const orgId = (req as any).orgId || (req as any).user?.orgId;
      const incident = await storage.getIncident(p(req.params.incidentId));
      if (!incident || (orgId && incident.orgId && incident.orgId !== orgId)) {
        return res.status(404).json({ message: "Incident not found" });
      }
      const incidentAlerts = await storage.getAlertsByIncident(p(req.params.incidentId));

      // Set SSE headers
      res.setHeader("Content-Type", "text/event-stream");
      res.setHeader("Cache-Control", "no-cache");
      res.setHeader("Connection", "keep-alive");
      res.setHeader("X-Accel-Buffering", "no");
      res.flushHeaders();

      res.write(
        `data: ${JSON.stringify({ type: "connected", message: "Stream connected. Building threat context..." })}\n\n`,
      );

      let threatIntelCtx;
      try {
        threatIntelCtx = await buildThreatIntelContext(incidentAlerts);
        res.write(
          `data: ${JSON.stringify({ type: "status", message: "Threat context built. Starting AI analysis..." })}\n\n`,
        );
      } catch (err) {
        res.write(
          `data: ${JSON.stringify({ type: "error", message: "Failed to build threat intelligence context" })}\n\n`,
        );
        res.write("data: [DONE]\n\n");
        res.end();
        return;
      }

      await streamNarrative(incident, incidentAlerts, threatIntelCtx, {
        onChunk: (text: string) => {
          if (!res.writableEnded) {
            res.write(`data: ${JSON.stringify({ type: "chunk", text })}\n\n`);
          }
        },
        onComplete: async (fullText: string, metrics) => {
          try {
            const parsed = (() => {
              try {
                const jsonMatch = fullText.match(/\{[\s\S]*\}/);
                return jsonMatch ? JSON.parse(jsonMatch[0]) : null;
              } catch {
                return null;
              }
            })();

            if (parsed) {
              const storedIocs = Array.isArray(parsed.iocs)
                ? parsed.iocs.map((ioc: any) =>
                    typeof ioc === "string" ? ioc : `${ioc.value} (${ioc.type}: ${ioc.context})`,
                  )
                : [];
              const { diamondModel: _dm, ...storedAttackerProfile } = parsed.attackerProfile || ({} as any);
              await storage.updateIncident(p(req.params.incidentId), {
                aiNarrative: parsed.narrative || fullText,
                aiSummary: parsed.summary,
                mitigationSteps: parsed.mitigationSteps as any,
                iocs: storedIocs as any,
                attackerProfile: storedAttackerProfile as any,
                referencedAlertIds: Array.isArray(parsed.citedAlertIds) ? parsed.citedAlertIds : [],
              });
            }

            await storage.createAuditLog({
              userId: (req as any).user?.id,
              userName: (req as any).user?.firstName
                ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
                : "Analyst",
              action: "ai_narrative_generated",
              resourceType: "incident",
              resourceId: p(req.params.incidentId),
              details: { streamed: true, latencyMs: metrics.latencyMs, riskScore: parsed?.riskScore },
            });

            storage.incrementUsage(orgId, "ai_analyses").catch((err) => log.warn("Failed to increment AI usage", { error: String(err), orgId }));
          } catch (e) {
            logger.child("ai").warn("Post-stream processing error", { error: String(e) });
          }

          try {
            if (!res.writableEnded) {
              res.write(`data: ${JSON.stringify({ type: "done", latencyMs: metrics.latencyMs })}\n\n`);
              res.write("data: [DONE]\n\n");
              res.end();
            }
          } catch (writeErr) {
            logger.child("ai").warn("Failed to write stream completion", { error: String(writeErr) });
          }
        },
        onError: (error: Error) => {
          logger.child("ai").error("Streaming narrative error", { error: error.message });
          try {
            if (!res.writableEnded) {
              res.write(`data: ${JSON.stringify({ type: "error", message: error.message })}\n\n`);
              res.write("data: [DONE]\n\n");
              res.end();
            }
          } catch (writeErr) {
            logger.child("ai").warn("Failed to write stream error", { error: String(writeErr) });
          }
        },
      });
    },
  );

  // SSE Streaming: Deep Investigation
  app.get(
    "/api/ai/deep-investigation/:incidentId/stream",
    isAuthenticated,
    resolveOrgContext,
    enforcePlanLimit("ai_analyses"),
    strictLimiter,
    async (req: Request, res: Response) => {
      const orgId = (req as any).orgId || (req as any).user?.orgId;
      const incident = await storage.getIncident(p(req.params.incidentId));
      if (!incident || (orgId && incident.orgId && incident.orgId !== orgId)) {
        return res.status(404).json({ message: "Incident not found" });
      }

      const incidentAlerts = await storage.getAlertsByIncident(p(req.params.incidentId));
      if (incidentAlerts.length === 0) {
        return res.status(400).json({ message: "No alerts associated with this incident" });
      }

      // Set SSE headers
      res.setHeader("Content-Type", "text/event-stream");
      res.setHeader("Cache-Control", "no-cache");
      res.setHeader("Connection", "keep-alive");
      res.setHeader("X-Accel-Buffering", "no");
      res.flushHeaders();

      res.write(
        `data: ${JSON.stringify({ type: "connected", message: "Stream connected. Building forensic context..." })}\n\n`,
      );

      let threatIntelCtx;
      try {
        threatIntelCtx = await buildThreatIntelContext(incidentAlerts);
        res.write(
          `data: ${JSON.stringify({ type: "status", message: "Context enriched. Starting deep investigation..." })}\n\n`,
        );
      } catch (err) {
        res.write(
          `data: ${JSON.stringify({ type: "status", message: "Proceeding without threat intelligence enrichment..." })}\n\n`,
        );
      }

      await streamDeepInvestigation(incident, incidentAlerts, threatIntelCtx, {
        onChunk: (text: string) => {
          if (!res.writableEnded) {
            res.write(`data: ${JSON.stringify({ type: "chunk", text })}\n\n`);
          }
        },
        onComplete: async (fullText: string, metrics) => {
          try {
            try {
              const parsed = JSON.parse(fullText);
              if (parsed && parsed.attackGraph) {
                await persistAttackGraph(parsed, incident.id, orgId);
              }
            } catch {
              // Stream text may not be valid JSON
            }

            await storage.createAuditLog({
              userId: (req as any).user?.id,
              userName: (req as any).user?.firstName
                ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
                : "Analyst",
              action: "ai_deep_investigation",
              resourceType: "incident",
              resourceId: incident.id,
              details: { alertCount: incidentAlerts.length, streamed: true, latencyMs: metrics.latencyMs },
            });
            storage.incrementUsage(orgId, "ai_analyses").catch((err) => log.warn("Failed to increment AI usage", { error: String(err), orgId }));
          } catch (e) {
            logger.child("ai").warn("Post-stream processing error", { error: String(e) });
          }

          try {
            if (!res.writableEnded) {
              res.write(`data: ${JSON.stringify({ type: "done", latencyMs: metrics.latencyMs })}\n\n`);
              res.write("data: [DONE]\n\n");
              res.end();
            }
          } catch (writeErr) {
            logger.child("ai").warn("Failed to write stream completion", { error: String(writeErr) });
          }
        },
        onError: (error: Error) => {
          logger.child("ai").error("Streaming deep investigation error", { error: error.message });
          try {
            if (!res.writableEnded) {
              res.write(`data: ${JSON.stringify({ type: "error", message: error.message })}\n\n`);
              res.write("data: [DONE]\n\n");
              res.end();
            }
          } catch (writeErr) {
            logger.child("ai").warn("Failed to write stream error", { error: String(writeErr) });
          }
        },
      });
    },
  );
}

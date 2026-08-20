import type { Express } from "express";
import { z } from "zod";
import { isAuthenticated } from "../auth";
import { resolveOrgContext, requireOrgId, requireMinRole } from "../rbac";
import { ERROR_CODES, reply, replyError } from "../api-response";
import { getOrgId } from "./shared";
import {
  getAiSecuritySettings,
  listAiGuardEvents,
  upsertAiSecuritySettings,
  type InjectionMode,
} from "../ai/security-store";
import type { PiiMaskingMode } from "../ai/egress-redaction";
import { getModelPricing } from "../ai/model-gateway";
import { logger } from "../logger";
import { config as appConfig } from "../config";

const log = logger.child("ai-security-routes");

const settingsSchema = z.object({
  injectionMode: z.enum(["off", "flag_and_gate", "block"]),
  piiMasking: z.enum(["mask_identifiers", "mask_all", "off"]),
  aiEnabled: z.boolean(),
});

export function registerAiSecurityRoutes(app: Express): void {
  const readChain = [isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("analyst")];
  const writeChain = [isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin")];

  app.get("/api/ai/security-settings", ...readChain, async (req, res) => {
    try {
      return reply(res, {
        ...(await getAiSecuritySettings(getOrgId(req))),
        models: {
          default: appConfig.ai.modelId,
          triage: appConfig.ai.triage.modelId,
          investigation: appConfig.ai.investigation.modelId,
        },
        modelPricing: getModelPricing(),
      });
    } catch (error) {
      log.error("Failed to read AI security settings", { error: String(error) });
      return replyError(res, 500, [
        { code: ERROR_CODES.INTERNAL_ERROR, message: "Unable to load AI security settings." },
      ]);
    }
  });

  app.put("/api/ai/security-settings", ...writeChain, async (req, res) => {
    const parsed = settingsSchema.safeParse(req.body);
    if (!parsed.success) {
      return replyError(res, 400, [{ code: ERROR_CODES.VALIDATION_ERROR, message: "Invalid AI security settings." }]);
    }
    try {
      const sessionUser = req.user as Express.User & { id?: string };
      const userId = typeof sessionUser.id === "string" ? sessionUser.id : "unknown";
      if (parsed.data.injectionMode === "off") {
        log.warn("AI injection detection disabled by organization administrator", {
          orgId: getOrgId(req),
          userId,
        });
      }
      const settings = await upsertAiSecuritySettings(
        getOrgId(req),
        {
          injectionMode: parsed.data.injectionMode as InjectionMode,
          piiMasking: parsed.data.piiMasking as PiiMaskingMode,
          aiEnabled: parsed.data.aiEnabled,
        },
        userId,
      );
      return reply(res, {
        ...settings,
        models: {
          default: appConfig.ai.modelId,
          triage: appConfig.ai.triage.modelId,
          investigation: appConfig.ai.investigation.modelId,
        },
        modelPricing: getModelPricing(),
      });
    } catch (error) {
      log.error("Failed to update AI security settings", { error: String(error) });
      return replyError(res, 500, [
        { code: ERROR_CODES.INTERNAL_ERROR, message: "Unable to update AI security settings." },
      ]);
    }
  });

  app.get("/api/ai/guard-events", ...readChain, async (req, res) => {
    const page = Math.max(1, Number(req.query.page) || 1);
    const pageSize = Math.min(100, Math.max(1, Number(req.query.pageSize) || 25));
    const severity =
      req.query.severity === "suspected" || req.query.severity === "likely" ? req.query.severity : undefined;
    const from = typeof req.query.from === "string" ? new Date(req.query.from) : undefined;
    const to = typeof req.query.to === "string" ? new Date(req.query.to) : undefined;
    try {
      const result = await listAiGuardEvents({
        orgId: getOrgId(req),
        page,
        pageSize,
        feature: typeof req.query.feature === "string" ? req.query.feature : undefined,
        alertId: typeof req.query.alertId === "string" ? req.query.alertId : undefined,
        incidentId: typeof req.query.incidentId === "string" ? req.query.incidentId : undefined,
        severity,
        from: from && !Number.isNaN(from.getTime()) ? from : undefined,
        to: to && !Number.isNaN(to.getTime()) ? to : undefined,
      });
      return reply(res, result.events, {
        page,
        pageSize,
        total: result.total,
        totalPages: Math.ceil(result.total / pageSize),
      });
    } catch (error) {
      log.error("Failed to list AI guard events", { error: String(error) });
      return replyError(res, 500, [{ code: ERROR_CODES.INTERNAL_ERROR, message: "Unable to load AI guard events." }]);
    }
  });
}

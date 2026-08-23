import type { Express } from "express";
import { z } from "zod";
import { isAuthenticated } from "../auth";
import { resolveOrgContext, requireOrgId, requireMinRole } from "../rbac";
import { ERROR_CODES, reply, replyError } from "../api-response";
import { getOrgId, storage } from "./shared";
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
import { AUTONOMY_MODES } from "@shared/schema";
import { autonomyLog } from "@shared/schema";
import { db } from "../db";

const log = logger.child("ai-security-routes");

const settingsSchema = z
  .object({
    injectionMode: z.enum(["off", "flag_and_gate", "block"]).optional(),
    piiMasking: z.enum(["mask_identifiers", "mask_all", "off"]).optional(),
    aiEnabled: z.boolean().optional(),
    autonomyMode: z.enum(AUTONOMY_MODES).optional(),
  })
  .refine((value) => Object.keys(value).length > 0, "At least one setting must be supplied.");

const relationshipQuerySchema = z
  .object({
    alertId: z.string().uuid().optional(),
    incidentId: z.string().uuid().optional(),
  })
  .refine((value) => Boolean(value.alertId) !== Boolean(value.incidentId), {
    message: "Provide exactly one alertId or incidentId.",
  });

export function registerAiSecurityRoutes(app: Express): void {
  const readChain = [isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("analyst")];
  const relationshipReadChain = [isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("read_only")];
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
      const orgId = getOrgId(req);
      const previousSettings = await getAiSecuritySettings(orgId);
      const nextSettings = {
        injectionMode: parsed.data.injectionMode ?? previousSettings.injectionMode,
        piiMasking: parsed.data.piiMasking ?? previousSettings.piiMasking,
        aiEnabled: parsed.data.aiEnabled ?? previousSettings.aiEnabled,
        autonomyMode: parsed.data.autonomyMode ?? previousSettings.autonomyMode,
      };
      if (nextSettings.injectionMode === "off" && parsed.data.injectionMode !== undefined) {
        log.warn("AI injection detection disabled by organization administrator", {
          orgId,
          userId,
        });
      }
      const settings = await upsertAiSecuritySettings(
        orgId,
        {
          injectionMode: nextSettings.injectionMode as InjectionMode,
          piiMasking: nextSettings.piiMasking as PiiMaskingMode,
          aiEnabled: nextSettings.aiEnabled,
          autonomyMode: nextSettings.autonomyMode,
        },
        userId,
      );
      if (settings.autonomyMode !== previousSettings.autonomyMode) {
        await db.insert(autonomyLog).values({
          orgId,
          action: "autonomy_mode_changed",
          tier: settings.autonomyMode,
          details: {
            previousMode: previousSettings.autonomyMode,
            newMode: settings.autonomyMode,
            changedBy: userId,
          },
          triggeredBy: userId,
        });
      }
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

  app.get("/api/ai/guard-events/related", ...relationshipReadChain, async (req, res) => {
    const parsed = relationshipQuerySchema.safeParse({
      alertId: typeof req.query.alertId === "string" ? req.query.alertId : undefined,
      incidentId: typeof req.query.incidentId === "string" ? req.query.incidentId : undefined,
    });
    if (!parsed.success) {
      return replyError(res, 400, [
        { code: ERROR_CODES.VALIDATION_ERROR, message: "Provide exactly one alertId or incidentId." },
      ]);
    }

    try {
      const orgId = getOrgId(req);
      const relationship = parsed.data;
      if (relationship.alertId) {
        const alert = await storage.getAlert(relationship.alertId);
        if (!alert || alert.orgId !== orgId) {
          return replyError(res, 404, [{ code: ERROR_CODES.NOT_FOUND, message: "Alert not found." }]);
        }
      } else {
        const incident = await storage.getIncident(relationship.incidentId!);
        if (!incident || incident.orgId !== orgId) {
          return replyError(res, 404, [{ code: ERROR_CODES.NOT_FOUND, message: "Incident not found." }]);
        }
      }

      const result = await listAiGuardEvents({
        orgId,
        page: 1,
        pageSize: 100,
        alertId: relationship.alertId,
        incidentId: relationship.incidentId,
      });
      return reply(res, result.events, {
        page: 1,
        pageSize: 100,
        total: result.total,
        totalPages: Math.ceil(result.total / 100),
      });
    } catch (error) {
      log.error("Failed to read relationship-scoped AI guard events", { error: String(error) });
      return replyError(res, 500, [{ code: ERROR_CODES.INTERNAL_ERROR, message: "Unable to load AI guard state." }]);
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

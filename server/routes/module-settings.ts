import type { Express } from "express";
import { z } from "zod";
import { isAuthenticated } from "../auth";
import { requireMinRole, requireOrgId, resolveOrgContext } from "../rbac";
import { createAuditLog } from "../storage/audit";
import {
  ERROR_CODES,
  reply,
  replyBadRequest,
  replyForbidden,
  replyInternal,
  replyUnauthenticated,
  replyValidation,
} from "../api-response";
import { getOrgId } from "./shared";
import {
  CORE_MODULES,
  canManageModuleSettings,
  getEnabledModuleKeys,
  isSupportedModuleKey,
  setModuleEnabled,
} from "../module-settings";

const moduleUpdateSchema = z.object({
  moduleKey: z.string().min(1).max(100),
  enabled: z.boolean(),
});

export function registerModuleSettingsRoutes(app: Express): void {
  app.get("/api/org/module-settings", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const enabledModules = await getEnabledModuleKeys(orgId);
      return reply(res, {
        enabledModules,
        coreModules: [...CORE_MODULES],
        canManage: canManageModuleSettings((req as any).orgRole, Boolean((req as any).orgReadOnly)),
        readOnly: Boolean((req as any).orgReadOnly),
      });
    } catch {
      return replyInternal(res, "Failed to load organization module settings");
    }
  });

  app.put(
    "/api/org/module-settings",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      const orgId = getOrgId(req);
      const userId = (req as any).user?.id;
      if (!canManageModuleSettings((req as any).orgRole, Boolean((req as any).orgReadOnly))) {
        return replyForbidden(res, "Only organization owners and admins can change module settings.");
      }
      if (typeof userId !== "string" || userId.length === 0) {
        return replyUnauthenticated(res, "A resolved user is required to change module settings.");
      }
      const parsed = moduleUpdateSchema.safeParse(req.body);
      if (!parsed.success) {
        return replyValidation(res, [{ message: "moduleKey and enabled are required." }]);
      }
      if (!isSupportedModuleKey(parsed.data.moduleKey)) {
        return replyBadRequest(res, "Unsupported module key.", ERROR_CODES.VALIDATION_ERROR);
      }
      const current = await getEnabledModuleKeys(orgId);
      const oldEnabled = current.includes(parsed.data.moduleKey);
      if (oldEnabled === parsed.data.enabled) return reply(res, { enabledModules: current });

      try {
        const enabledModules = await setModuleEnabled(orgId, parsed.data.moduleKey, parsed.data.enabled, userId);
        await createAuditLog({
          orgId,
          userId,
          userName: (req as any).user?.email || "unknown",
          action: parsed.data.enabled ? "module_enabled" : "module_disabled",
          resourceType: "organization_module",
          resourceId: parsed.data.moduleKey,
          details: { moduleKey: parsed.data.moduleKey, oldEnabled, newEnabled: parsed.data.enabled },
        });
        return reply(res, { enabledModules });
      } catch {
        return replyInternal(res, "Failed to persist organization module settings");
      }
    },
  );
}

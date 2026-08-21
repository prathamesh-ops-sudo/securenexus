import type { Express } from "express";
import { z } from "zod";
import { isAuthenticated } from "../auth";
import { requireOrgId, resolveOrgContext } from "../rbac";
import { createAuditLog } from "../storage/audit";
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
      res.json({
        enabledModules,
        coreModules: [...CORE_MODULES],
        canManage: canManageModuleSettings((req as any).orgRole, Boolean((req as any).orgReadOnly)),
        readOnly: Boolean((req as any).orgReadOnly),
      });
    } catch {
      res.status(500).json({ error: "Failed to load organization module settings" });
    }
  });

  app.put("/api/org/module-settings", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    const orgId = getOrgId(req);
    const userId = (req as any).user?.id;
    if (!canManageModuleSettings((req as any).orgRole, Boolean((req as any).orgReadOnly))) {
      return res.status(403).json({ error: "Only organization owners and admins can change module settings." });
    }
    const parsed = moduleUpdateSchema.safeParse(req.body);
    if (!parsed.success || !isSupportedModuleKey(parsed.data?.moduleKey)) {
      return res.status(400).json({ error: "Unsupported module key." });
    }
    const current = await getEnabledModuleKeys(orgId);
    const oldEnabled = current.includes(parsed.data.moduleKey);
    if (oldEnabled === parsed.data.enabled) return res.json({ enabledModules: current });

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
      return res.json({ enabledModules });
    } catch (error) {
      return res
        .status(409)
        .json({ error: error instanceof Error ? error.message : "Failed to update module settings" });
    }
  });
}

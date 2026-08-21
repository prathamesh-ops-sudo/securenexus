import { and, eq } from "drizzle-orm";
import { CORE_MODULES, NAVIGATION_MODULES, organizationModuleSettings } from "@shared/schema";
import { db } from "./db";

export { CORE_MODULES };
export const MODULE_KEYS = [...NAVIGATION_MODULES] as const;
export type ModuleKey = (typeof MODULE_KEYS)[number];

export function getDefaultEnabledModules(): string[] {
  return [...CORE_MODULES];
}

export function isSupportedModuleKey(value: unknown): value is ModuleKey {
  return typeof value === "string" && (MODULE_KEYS as readonly string[]).includes(value);
}

export function canManageModuleSettings(role: string | null | undefined, readOnlyContext: boolean): boolean {
  return !readOnlyContext && (role === "owner" || role === "admin");
}

export async function getEnabledModuleKeys(orgId: string): Promise<string[]> {
  const rows = await db
    .select({ moduleKey: organizationModuleSettings.moduleKey })
    .from(organizationModuleSettings)
    .where(eq(organizationModuleSettings.orgId, orgId));
  return [...getDefaultEnabledModules(), ...rows.map((row) => row.moduleKey)];
}

export async function setModuleEnabled(
  orgId: string,
  moduleKey: ModuleKey,
  enabled: boolean,
  enabledBy: string,
): Promise<string[]> {
  if ((CORE_MODULES as readonly string[]).includes(moduleKey)) {
    if (!enabled) throw new Error("Core navigation modules cannot be disabled.");
    return getEnabledModuleKeys(orgId);
  }

  if (enabled) {
    await db
      .insert(organizationModuleSettings)
      .values({ orgId, moduleKey, enabledBy })
      .onConflictDoNothing({ target: [organizationModuleSettings.orgId, organizationModuleSettings.moduleKey] });
  } else {
    await db
      .delete(organizationModuleSettings)
      .where(and(eq(organizationModuleSettings.orgId, orgId), eq(organizationModuleSettings.moduleKey, moduleKey)));
  }
  return getEnabledModuleKeys(orgId);
}

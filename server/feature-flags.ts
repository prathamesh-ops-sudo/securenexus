import { storage } from "./storage";
import type { Request, Response, NextFunction } from "express";
import { logger } from "./logger";

interface FlagEvaluationContext {
  orgId?: string;
  userId?: string;
  role?: string;
}

interface EvaluationResult {
  key: string;
  enabled: boolean;
  reason: "flag_not_found" | "globally_disabled" | "globally_enabled" | "org_targeted" | "role_targeted" | "rollout_included" | "rollout_excluded";
}

export async function evaluateFlag(key: string, ctx: FlagEvaluationContext): Promise<EvaluationResult> {
  const flag = await storage.getFeatureFlag(key);
  if (!flag) {
    return { key, enabled: false, reason: "flag_not_found" };
  }

  if (!flag.enabled) {
    return { key, enabled: false, reason: "globally_disabled" };
  }

  const targetOrgs = (flag.targetOrgs as string[] | null) || [];
  if (targetOrgs.length > 0 && ctx.orgId) {
    if (targetOrgs.includes(ctx.orgId)) {
      return { key, enabled: true, reason: "org_targeted" };
    }
  }

  const targetRoles = (flag.targetRoles as string[] | null) || [];
  if (targetRoles.length > 0 && ctx.role) {
    if (targetRoles.includes(ctx.role)) {
      return { key, enabled: true, reason: "role_targeted" };
    }
  }

  if (targetOrgs.length > 0 || targetRoles.length > 0) {
    const hasOrgMatch = targetOrgs.length === 0 || (ctx.orgId && targetOrgs.includes(ctx.orgId));
    const hasRoleMatch = targetRoles.length === 0 || (ctx.role && targetRoles.includes(ctx.role));
    if (!hasOrgMatch && !hasRoleMatch) {
      return { key, enabled: false, reason: "rollout_excluded" };
    }
  }

  const rolloutPct = flag.rolloutPct ?? 100;
  if (rolloutPct >= 100) {
    return { key, enabled: true, reason: "globally_enabled" };
  }
  if (rolloutPct <= 0) {
    return { key, enabled: false, reason: "rollout_excluded" };
  }

  const identifier = ctx.orgId ?? ctx.userId;
  if (!identifier) {
    logger.child("feature-flags").warn("Flag rollout evaluated without orgId or userId", { key });
    return { key, enabled: false, reason: "rollout_excluded" };
  }
  const hash = deterministicHash(key, identifier);
  const bucket = hash % 100;
  if (bucket < rolloutPct) {
    return { key, enabled: true, reason: "rollout_included" };
  }

  return { key, enabled: false, reason: "rollout_excluded" };
}

function deterministicHash(key: string, identifier: string): number {
  const str = `${key}:${identifier}`;
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  return Math.abs(hash);
}

export function requireFeatureFlag(flagKey: string) {
  return async (req: Request, res: Response, next: NextFunction) => {
    const user = (req as any).user;
    const ctx: FlagEvaluationContext = {
      orgId: user?.orgId,
      userId: user?.id,
      role: user?.role,
    };

    const result = await evaluateFlag(flagKey, ctx);
    if (!result.enabled) {
      return res.status(404).json({
        message: "Feature not available",
        code: "FEATURE_DISABLED",
      });
    }
    next();
  };
}

export async function evaluateAllFlags(ctx: FlagEvaluationContext): Promise<Record<string, EvaluationResult>> {
  const flags = await storage.listFeatureFlags();
  const results: Record<string, EvaluationResult> = {};
  for (const flag of flags) {
    results[flag.key] = await evaluateFlag(flag.key, ctx);
  }
  return results;
}

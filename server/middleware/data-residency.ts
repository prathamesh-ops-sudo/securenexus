import type { Request, Response, NextFunction } from "express";
import { logger } from "../logger";
import { storage } from "../storage";
import { db } from "../db";
import { eq, and } from "drizzle-orm";
import { DATA_REGIONS, DATA_REGION_ENDPOINTS, type DataRegion, crossBorderFlowRules } from "../../shared/schema";

const log = logger.child("data-residency");

const REGION_CACHE_TTL_MS = 60_000;

interface CachedRegion {
  region: DataRegion;
  dataResidency: string;
  expiresAt: number;
}

const regionCache = new Map<string, CachedRegion>();

setInterval(() => {
  const now = Date.now();
  regionCache.forEach((entry, key) => {
    if (entry.expiresAt <= now) regionCache.delete(key);
  });
}, 5 * 60_000);

export function invalidateRegionCache(orgId?: string): void {
  if (orgId) {
    regionCache.delete(orgId);
  } else {
    regionCache.clear();
  }
}

async function resolveOrgRegion(orgId: string): Promise<{ region: DataRegion; dataResidency: string }> {
  const now = Date.now();
  const cached = regionCache.get(orgId);
  if (cached && cached.expiresAt > now) {
    return { region: cached.region, dataResidency: cached.dataResidency };
  }

  const org = await storage.getOrganization(orgId);
  const region = (org?.dataRegion as DataRegion) || "US";
  const dataResidency = (org?.dataResidency as string) || "us-east-1";

  const validRegion = DATA_REGIONS.includes(region) ? region : "US";

  regionCache.set(orgId, { region: validRegion, dataResidency, expiresAt: now + REGION_CACHE_TTL_MS });
  return { region: validRegion, dataResidency };
}

export function mapRegionToEndpoint(region: DataRegion): string {
  const endpoint = DATA_REGION_ENDPOINTS[region];
  return endpoint ? endpoint.primary : "us-east-1";
}

export function isGdprRegion(region: DataRegion): boolean {
  const endpoint = DATA_REGION_ENDPOINTS[region];
  return endpoint ? endpoint.gdprApplicable : false;
}

/**
 * Middleware that attaches the org's data region to the request context.
 * Downstream handlers can use (req as any).dataRegion and (req as any).dataResidency.
 */
export function attachDataRegion(req: Request, _res: Response, next: NextFunction): void {
  const user = req.user as Record<string, unknown> | undefined;
  if (!user?.orgId || typeof user.orgId !== "string") {
    next();
    return;
  }

  resolveOrgRegion(user.orgId)
    .then(({ region, dataResidency }) => {
      (req as any).dataRegion = region;
      (req as any).dataResidency = dataResidency;
      next();
    })
    .catch((err) => {
      log.error("Failed to resolve org region", { error: String(err), orgId: user.orgId });
      next();
    });
}

/**
 * Middleware that enforces data residency — blocks requests that would
 * route data to a region other than the org's designated region.
 * Used on write endpoints to prevent cross-region data leakage.
 */
export function enforceDataResidency(req: Request, res: Response, next: NextFunction): void {
  const user = req.user as Record<string, unknown> | undefined;
  if (!user?.orgId || typeof user.orgId !== "string") {
    next();
    return;
  }

  const orgId = user.orgId as string;

  resolveOrgRegion(orgId)
    .then(({ region }) => {
      const targetRegion = req.headers["x-target-region"] as string | undefined;

      if (targetRegion && targetRegion !== region) {
        log.warn("Cross-region write attempt blocked", {
          orgId,
          orgRegion: region,
          targetRegion,
          method: req.method,
          path: req.path,
          userId: user.id,
        });

        res.status(403).json({
          message: `Data residency violation: your organization's data must remain in the ${region} region. Target region ${targetRegion} is not allowed.`,
          code: "DATA_RESIDENCY_VIOLATION",
          orgRegion: region,
          targetRegion,
        });
        return;
      }

      (req as any).dataRegion = region;
      (req as any).enforcedRegion = mapRegionToEndpoint(region);
      next();
    })
    .catch((err) => {
      log.error("Failed to enforce data residency", { error: String(err), orgId });
      res.status(503).json({
        message: "Unable to verify data residency compliance. Request denied for safety.",
        code: "DATA_RESIDENCY_CHECK_FAILED",
      });
    });
}

/**
 * Checks whether a cross-border data flow is allowed based on org's flow control rules.
 * Returns { allowed, ruleId, action } for the given source/destination pair.
 */
export async function checkCrossBorderFlow(
  orgId: string,
  sourceRegion: string,
  destinationRegion: string,
): Promise<{ allowed: boolean; ruleId?: string; action?: string }> {
  if (sourceRegion === destinationRegion) {
    return { allowed: true };
  }

  try {
    const org = await storage.getOrganization(orgId);
    const controls = org?.crossBorderFlowControls as Record<string, unknown> | null;

    if (!controls || (controls as Record<string, unknown>).mode === "permissive") {
      return { allowed: true };
    }

    if ((controls as Record<string, unknown>).mode === "strict") {
      return { allowed: false, action: "block" };
    }

    // "rule-based" mode: query the crossBorderFlowRules table for matching enabled rules
    if ((controls as Record<string, unknown>).mode === "rule-based") {
      const rules = await db
        .select()
        .from(crossBorderFlowRules)
        .where(
          and(
            eq(crossBorderFlowRules.orgId, orgId),
            eq(crossBorderFlowRules.sourceRegion, sourceRegion),
            eq(crossBorderFlowRules.destinationRegion, destinationRegion),
            eq(crossBorderFlowRules.enabled, true),
          ),
        );

      if (rules.length === 0) {
        // No matching rules — default deny in rule-based mode for safety
        return { allowed: false, action: "block" };
      }

      // Apply most restrictive action: block > require-approval > alert > allow
      const ACTION_PRIORITY: Record<string, number> = {
        block: 0,
        "require-approval": 1,
        alert: 2,
        allow: 3,
      };

      let mostRestrictive = rules[0];
      for (const rule of rules) {
        const currentPriority = ACTION_PRIORITY[rule.action] ?? 0;
        const bestPriority = ACTION_PRIORITY[mostRestrictive.action] ?? 0;
        if (currentPriority < bestPriority) {
          mostRestrictive = rule;
        }
      }

      if (mostRestrictive.action === "allow") {
        return { allowed: true, ruleId: mostRestrictive.id, action: "allow" };
      }

      if (mostRestrictive.action === "alert") {
        // Alert mode: allow but flag for auditing
        return { allowed: true, ruleId: mostRestrictive.id, action: "alert" };
      }

      // block or require-approval → deny
      return { allowed: false, ruleId: mostRestrictive.id, action: mostRestrictive.action };
    }

    // Unknown mode — default deny for safety
    return { allowed: false, action: "block" };
  } catch (err) {
    log.error("Failed to check cross-border flow", { error: String(err), orgId });
    return { allowed: true };
  }
}

export function isValidDataRegion(region: unknown): region is DataRegion {
  return typeof region === "string" && (DATA_REGIONS as readonly string[]).includes(region);
}

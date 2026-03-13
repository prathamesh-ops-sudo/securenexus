import { db } from "./db";
import { eq, and, sql } from "drizzle-orm";
import {
  breachMonitoringTargets,
  darkWebExposures,
  darkWebMonitoringConfig,
  darkWebScanHistory,
} from "../shared/schema";
import {
  checkEmailBreaches,
  checkEmailPastes,
  checkDomainBreaches,
  assessBreachSeverity,
  assessPasteSeverity,
} from "./integrations/hibp";
import { decryptSsoSecret } from "./sso-crypto";
import { logger } from "./logger";

const log = logger.child("dark-web-monitor");

/** Decrypt an API key from DB. Falls back to plaintext for pre-encryption keys. */
function decryptApiKey(ciphertext: string | null): string | null {
  if (!ciphertext) return null;
  try {
    return decryptSsoSecret(ciphertext);
  } catch {
    // Fallback: return as-is if it's a plaintext key from before encryption was added
    return ciphertext;
  }
}

interface ScanResult {
  newExposures: number;
  targetsScanned: number;
  sourcesChecked: string[];
}

/**
 * Run a dark web monitoring scan for a specific organization.
 * Checks all active monitoring targets against HIBP and other sources.
 */
export async function runDarkWebScan(
  orgId: string,
  scanType: "full" | "incremental" | "manual" = "full",
): Promise<ScanResult> {
  const startTime = Date.now();
  let newExposures = 0;
  const sourcesChecked = new Set<string>();

  // Get org monitoring config
  const [config] = await db
    .select()
    .from(darkWebMonitoringConfig)
    .where(eq(darkWebMonitoringConfig.orgId, orgId))
    .limit(1);

  if (!config || !config.isEnabled) {
    log.info("Dark web monitoring disabled for org", { orgId });
    return { newExposures: 0, targetsScanned: 0, sourcesChecked: [] };
  }

  // Create scan history entry
  const [scanEntry] = await db
    .insert(darkWebScanHistory)
    .values({
      orgId,
      scanType,
      status: "running",
      targetsScanned: 0,
      newExposuresFound: 0,
    })
    .returning();

  // Get all active targets
  const targets = await db
    .select()
    .from(breachMonitoringTargets)
    .where(and(eq(breachMonitoringTargets.orgId, orgId), eq(breachMonitoringTargets.isActive, true)));

  const hibpApiKey = decryptApiKey(config.hibpApiKey);

  for (const target of targets) {
    try {
      if (target.targetType === "email" || target.targetType === "executive_email") {
        // Check HIBP breaches
        const breaches = await checkEmailBreaches(target.targetValue, hibpApiKey);
        sourcesChecked.add("hibp");

        for (const breach of breaches) {
          // Dedup: check if we already have this exposure
          const [existing] = await db
            .select()
            .from(darkWebExposures)
            .where(
              and(
                eq(darkWebExposures.orgId, orgId),
                eq(darkWebExposures.sourceName, breach.Name),
                eq(darkWebExposures.matchedValue, target.targetValue),
              ),
            )
            .limit(1);

          if (!existing) {
            const severity = assessBreachSeverity(breach);
            const exposureType = target.targetType === "executive_email" ? "executive_exposure" : "credential_leak";

            await db.insert(darkWebExposures).values({
              orgId,
              targetId: target.id,
              exposureType,
              severity,
              title: `${target.targetValue} found in ${breach.Title} breach`,
              description: breach.Description
                ? breach.Description.replace(/<[^>]*>/g, "").slice(0, 1000)
                : `Credentials exposed in the ${breach.Title} data breach affecting ${breach.PwnCount.toLocaleString()} accounts.`,
              sourceType: "hibp",
              sourceName: breach.Name,
              breachDate: breach.BreachDate ? new Date(breach.BreachDate) : null,
              affectedData: breach.DataClasses,
              affectedCount: breach.PwnCount,
              matchedValue: target.targetValue,
              confidenceScore: breach.IsVerified ? 95 : 70,
              rawData: {
                domain: breach.Domain,
                isVerified: breach.IsVerified,
                isSensitive: breach.IsSensitive,
                addedDate: breach.AddedDate,
              },
            });
            newExposures++;
          }
        }

        // Check pastes
        const pastes = await checkEmailPastes(target.targetValue, hibpApiKey);
        sourcesChecked.add("paste_site");

        for (const paste of pastes) {
          const pasteId = paste.Id || `${paste.Source}-${paste.Date}`;
          const [existing] = await db
            .select()
            .from(darkWebExposures)
            .where(
              and(
                eq(darkWebExposures.orgId, orgId),
                eq(darkWebExposures.sourceType, "paste_site"),
                eq(darkWebExposures.sourceName, pasteId),
                eq(darkWebExposures.matchedValue, target.targetValue),
              ),
            )
            .limit(1);

          if (!existing) {
            const severity = assessPasteSeverity(paste);
            await db.insert(darkWebExposures).values({
              orgId,
              targetId: target.id,
              exposureType: "paste_site",
              severity,
              title: `${target.targetValue} found on ${paste.Source || "paste site"}`,
              description: `Email address found in a paste titled "${paste.Title || "Untitled"}" containing ${paste.EmailCount.toLocaleString()} email addresses.`,
              sourceType: "paste_site",
              sourceName: pasteId,
              affectedCount: paste.EmailCount,
              matchedValue: target.targetValue,
              confidenceScore: 80,
              rawData: {
                source: paste.Source,
                title: paste.Title,
                date: paste.Date,
              },
            });
            newExposures++;
          }
        }

        // Rate limit: HIBP requires 1.5s between requests per API key
        await new Promise((resolve) => setTimeout(resolve, 1600));
      }

      if (target.targetType === "domain") {
        const domainBreaches = await checkDomainBreaches(target.targetValue);
        sourcesChecked.add("hibp");

        for (const breach of domainBreaches) {
          const [existing] = await db
            .select()
            .from(darkWebExposures)
            .where(
              and(
                eq(darkWebExposures.orgId, orgId),
                eq(darkWebExposures.sourceName, breach.Name),
                eq(darkWebExposures.exposureType, "data_breach"),
              ),
            )
            .limit(1);

          if (!existing) {
            await db.insert(darkWebExposures).values({
              orgId,
              targetId: target.id,
              exposureType: "data_breach",
              severity: assessBreachSeverity(breach),
              title: `Domain ${target.targetValue} affected by ${breach.Title} breach`,
              description: breach.Description
                ? breach.Description.replace(/<[^>]*>/g, "").slice(0, 1000)
                : `Organization domain found in the ${breach.Title} data breach.`,
              sourceType: "hibp",
              sourceName: breach.Name,
              breachDate: breach.BreachDate ? new Date(breach.BreachDate) : null,
              affectedData: breach.DataClasses,
              affectedCount: breach.PwnCount,
              matchedValue: target.targetValue,
              confidenceScore: breach.IsVerified ? 90 : 60,
            });
            newExposures++;
          }
        }
      }

      // Update target last checked timestamp
      await db
        .update(breachMonitoringTargets)
        .set({
          lastCheckedAt: new Date(),
          exposureCount: sql`(SELECT COUNT(*) FROM dark_web_exposures WHERE target_id = ${target.id} AND status != 'false_positive')`,
          updatedAt: new Date(),
        })
        .where(eq(breachMonitoringTargets.id, target.id));
    } catch (error) {
      log.error("Error scanning target", { targetId: target.id, error: String(error) });
    }
  }

  const durationMs = Date.now() - startTime;
  const sourcesArr = Array.from(sourcesChecked);

  // Update scan history
  await db
    .update(darkWebScanHistory)
    .set({
      status: "completed",
      targetsScanned: targets.length,
      newExposuresFound: newExposures,
      sourcesChecked: sourcesArr,
      completedAt: new Date(),
      durationMs,
    })
    .where(eq(darkWebScanHistory.id, scanEntry.id));

  // Update config stats
  await db
    .update(darkWebMonitoringConfig)
    .set({
      lastFullScanAt: scanType === "full" ? new Date() : config.lastFullScanAt,
      totalExposuresFound: sql`${darkWebMonitoringConfig.totalExposuresFound} + ${newExposures}`,
      updatedAt: new Date(),
    })
    .where(eq(darkWebMonitoringConfig.orgId, orgId));

  log.info("Dark web scan completed", {
    orgId,
    scanType,
    targetsScanned: targets.length,
    newExposures,
    durationMs,
  });

  return {
    newExposures,
    targetsScanned: targets.length,
    sourcesChecked: sourcesArr,
  };
}

import { db } from "./db";
import { iocEntries, iocMatches, iocMatchRules, alerts, type Alert, type IocEntry, type IocMatchRule } from "@shared/schema";
import { eq, and, sql, inArray } from "drizzle-orm";
import { logger } from "./logger";

export interface MatchResult {
  totalMatches: number;
  matchDetails: { iocId: string; iocValue: string; iocType: string; matchField: string; confidence: number; malwareFamily?: string | null; campaignName?: string | null }[];
}

export async function matchAlertAgainstIOCs(alert: Alert, orgId?: string): Promise<MatchResult> {
  const result: MatchResult = { totalMatches: 0, matchDetails: [] };

  const alertFields: { field: string; value: string | null | undefined; iocType: string }[] = [
    { field: "sourceIp", value: alert.sourceIp, iocType: "ip" },
    { field: "destIp", value: alert.destIp, iocType: "ip" },
    { field: "domain", value: alert.domain, iocType: "domain" },
    { field: "url", value: alert.url, iocType: "url" },
    { field: "fileHash", value: alert.fileHash, iocType: "hash" },
    { field: "hostname", value: alert.hostname, iocType: "domain" },
  ];

  const validFields = alertFields.filter(f => f.value && f.value.trim());
  if (validFields.length === 0) return result;

  const typeValuePairs = new Map<string, { field: string; value: string }[]>();
  for (const f of validFields) {
    const key = f.iocType;
    const existing = typeValuePairs.get(key) || [];
    existing.push({ field: f.field, value: f.value!.trim().toLowerCase() });
    typeValuePairs.set(key, existing);
  }

  const entries = Array.from(typeValuePairs.entries());
  for (const [iocType, fields] of entries) {
    const values = fields.map((f: { field: string; value: string }) => f.value);
    try {
      const conditions = [
        eq(iocEntries.iocType, iocType),
        eq(iocEntries.status, "active"),
        inArray(iocEntries.iocValue, values),
      ];
      if (orgId) {
        conditions.push(eq(iocEntries.orgId, orgId));
      }

      const matches = await db.select().from(iocEntries)
        .where(and(...conditions))
        .limit(50);

      for (const ioc of matches) {
        const matchingFields = fields.filter((f: { field: string; value: string }) => f.value === ioc.iocValue);
        for (const mf of matchingFields) {
          result.matchDetails.push({
            iocId: ioc.id,
            iocValue: ioc.iocValue,
            iocType: ioc.iocType,
            matchField: mf.field,
            confidence: ioc.confidence || 50,
            malwareFamily: ioc.malwareFamily,
            campaignName: ioc.campaignName,
          });

          try {
            await db.insert(iocMatches).values({
              orgId: orgId || null,
              iocEntryId: ioc.id,
              alertId: alert.id,
              matchField: mf.field,
              matchValue: ioc.iocValue,
              confidence: ioc.confidence || 50,
              enrichmentData: {
                malwareFamily: ioc.malwareFamily,
                campaignName: ioc.campaignName,
                severity: ioc.severity,
                tags: ioc.tags,
                source: ioc.source,
                feedId: ioc.feedId,
              },
            });
          } catch (e) {
            logger.child("ioc-matcher").warn("Failed to insert IOC match record", { iocId: ioc.id, alertId: alert.id, matchField: mf.field, error: String(e) });
          }
        }
      }
    } catch (e) {
      logger.child("ioc-matcher").error(`IOC match error for type ${iocType}`, { error: String(e) });
    }
  }

  result.totalMatches = result.matchDetails.length;
  return result;
}

export async function matchAlertAgainstRules(alert: Alert, orgId?: string): Promise<void> {
  try {
    const conditions = [eq(iocMatchRules.enabled, true)];
    if (orgId) conditions.push(eq(iocMatchRules.orgId, orgId));

    const rules = await db.select().from(iocMatchRules).where(and(...conditions));

    for (const rule of rules) {
      const matchFields = Array.isArray(rule.matchFields) ? rule.matchFields as string[] : ["sourceIp", "destIp", "domain", "url", "fileHash"];
      const iocTypes = Array.isArray(rule.iocTypes) ? rule.iocTypes as string[] : [];

      const alertFieldMap: Record<string, { value: string | null | undefined; iocType: string }> = {
        sourceIp: { value: alert.sourceIp, iocType: "ip" },
        destIp: { value: alert.destIp, iocType: "ip" },
        domain: { value: alert.domain, iocType: "domain" },
        url: { value: alert.url, iocType: "url" },
        fileHash: { value: alert.fileHash, iocType: "hash" },
        hostname: { value: alert.hostname, iocType: "domain" },
      };

      for (const field of matchFields) {
        const af = alertFieldMap[field];
        if (!af || !af.value || !af.value.trim()) continue;
        if (iocTypes.length > 0 && !iocTypes.includes(af.iocType)) continue;

        const matchConditions = [
          eq(iocEntries.iocType, af.iocType),
          eq(iocEntries.iocValue, af.value.trim().toLowerCase()),
          eq(iocEntries.status, "active"),
        ];
        if (rule.minConfidence && rule.minConfidence > 0) {
          matchConditions.push(sql`${iocEntries.confidence} >= ${rule.minConfidence}`);
        }
        if (orgId) matchConditions.push(eq(iocEntries.orgId, orgId));

        const iocHits = await db.select().from(iocEntries).where(and(...matchConditions)).limit(10);

        for (const ioc of iocHits) {
          try {
            await db.insert(iocMatches).values({
              orgId: orgId || null,
              ruleId: rule.id,
              iocEntryId: ioc.id,
              alertId: alert.id,
              matchField: field,
              matchValue: ioc.iocValue,
              confidence: ioc.confidence || 50,
              enrichmentData: {
                ruleName: rule.name,
                malwareFamily: ioc.malwareFamily,
                campaignName: ioc.campaignName,
                severity: ioc.severity,
                tags: ioc.tags,
              },
            });

            await db.update(iocMatchRules).set({
              matchCount: sql`${iocMatchRules.matchCount} + 1`,
              lastMatchAt: new Date(),
              updatedAt: new Date(),
            }).where(eq(iocMatchRules.id, rule.id));
          } catch (e) {
            logger.child("ioc-matcher").warn("Failed to insert rule match or update rule counter", { ruleId: rule.id, iocId: ioc.id, alertId: alert.id, error: String(e) });
          }
        }
      }
    }
  } catch (e) {
    logger.child("ioc-matcher").error("Rule-based matching error", { error: String(e) });
  }
}

export async function enrichAlertWithIOCContext(alertId: string): Promise<{ matches: number; enrichment: Record<string, any> }> {
  const matchRecords = await db.select().from(iocMatches).where(eq(iocMatches.alertId, alertId));

  if (matchRecords.length === 0) return { matches: 0, enrichment: {} };

  const iocIds = matchRecords.map(m => m.iocEntryId).filter(Boolean) as string[];
  const iocDetails = iocIds.length > 0
    ? await db.select().from(iocEntries).where(inArray(iocEntries.id, iocIds))
    : [];

  const malwareFamilies = Array.from(new Set(iocDetails.map(i => i.malwareFamily).filter(Boolean)));
  const campaigns = Array.from(new Set(iocDetails.map(i => i.campaignName).filter(Boolean)));
  const maxConfidence = Math.max(...iocDetails.map(i => i.confidence || 0), 0);
  const sources = Array.from(new Set(iocDetails.map(i => i.source).filter(Boolean)));

  const firstSeenDates = iocDetails.map(i => i.firstSeen).filter(Boolean).sort();
  const lastSeenDates = iocDetails.map(i => i.lastSeen).filter(Boolean).sort().reverse();

  return {
    matches: matchRecords.length,
    enrichment: {
      iocMatchCount: matchRecords.length,
      maxConfidence,
      malwareFamilies,
      campaigns,
      intelSources: sources,
      firstSeen: firstSeenDates[0] || null,
      lastSeen: lastSeenDates[0] || null,
      matchedIndicators: iocDetails.map(i => ({ type: i.iocType, value: i.iocValue, confidence: i.confidence, severity: i.severity })),
    },
  };
}

export async function getIOCStats(orgId?: string): Promise<{ totalIOCs: number; activeIOCs: number; totalMatches: number; topMalwareFamilies: { name: string; count: number }[]; typeDistribution: { type: string; count: number }[] }> {
  const conditions = orgId ? [eq(iocEntries.orgId, orgId)] : [];

  const [totalResult] = await db.select({ count: sql<number>`count(*)` }).from(iocEntries).where(conditions.length > 0 ? and(...conditions) : undefined);
  const activeConditions = [...conditions, eq(iocEntries.status, "active")];
  const [activeResult] = await db.select({ count: sql<number>`count(*)` }).from(iocEntries).where(and(...activeConditions));

  const matchConditions = orgId ? [eq(iocMatches.orgId, orgId)] : [];
  const [matchResult] = await db.select({ count: sql<number>`count(*)` }).from(iocMatches).where(matchConditions.length > 0 ? and(...matchConditions) : undefined);

  const typeDistRaw = await db.select({
    type: iocEntries.iocType,
    count: sql<number>`count(*)`,
  }).from(iocEntries).where(conditions.length > 0 ? and(...conditions) : undefined).groupBy(iocEntries.iocType);

  const familyDistRaw = await db.select({
    name: iocEntries.malwareFamily,
    count: sql<number>`count(*)`,
  }).from(iocEntries).where(and(...conditions, sql`${iocEntries.malwareFamily} IS NOT NULL`)).groupBy(iocEntries.malwareFamily).orderBy(sql`count(*) DESC`).limit(10);

  return {
    totalIOCs: Number(totalResult?.count || 0),
    activeIOCs: Number(activeResult?.count || 0),
    totalMatches: Number(matchResult?.count || 0),
    topMalwareFamilies: familyDistRaw.map(r => ({ name: r.name || "Unknown", count: Number(r.count) })),
    typeDistribution: typeDistRaw.map(r => ({ type: r.type, count: Number(r.count) })),
  };
}

import { db } from "./db";
import { entities, threatIntelConfigs } from "@shared/schema";
import { eq, and } from "drizzle-orm";
import { logger } from "./logger";

const ENRICHMENT_TTL_MS = 24 * 60 * 60 * 1000;

export interface EnrichmentResult {
  provider: string;
  entityType: string;
  entityValue: string;
  reputationScore: number;
  verdict: "clean" | "suspicious" | "malicious" | "unknown";
  tags: string[];
  details: Record<string, any>;
  enrichedAt: string;
  raw?: any;
}

export interface ProviderStatus {
  name: string;
  enabled: boolean;
  configured: boolean;
  supportedTypes: string[];
  lastChecked?: string;
  healthy?: boolean;
}

interface EnrichmentCache {
  results: EnrichmentResult[];
  lastEnrichedAt: string;
  riskScore: number;
}

const PROVIDER_ENV_MAP: Record<string, string> = {
  abuseipdb: "ABUSEIPDB_API_KEY",
  virustotal: "VIRUSTOTAL_API_KEY",
  otx: "OTX_API_KEY",
};

function getApiKey(envVar: string): string | undefined {
  return process.env[envVar];
}

function isProviderConfigured(envVar: string): boolean {
  return !!getApiKey(envVar);
}

export async function getOrgApiKey(orgId: string, provider: string): Promise<string | undefined> {
  try {
    const [config] = await db.select().from(threatIntelConfigs).where(
      and(eq(threatIntelConfigs.orgId, orgId), eq(threatIntelConfigs.provider, provider), eq(threatIntelConfigs.enabled, true))
    );
    if (config?.apiKey) return config.apiKey;
  } catch (err) {
    logger.child("threat-enrichment").warn(`Failed to fetch org API key for ${provider}`, { error: String(err) });
  }
  const envVar = PROVIDER_ENV_MAP[provider];
  return envVar ? getApiKey(envVar) : undefined;
}

export async function getProviderStatuses(orgId?: string): Promise<ProviderStatus[]> {
  const providers = [
    { name: "AbuseIPDB", key: "abuseipdb", envVar: "ABUSEIPDB_API_KEY", supportedTypes: ["ip"] },
    { name: "VirusTotal", key: "virustotal", envVar: "VIRUSTOTAL_API_KEY", supportedTypes: ["ip", "domain", "file_hash", "url"] },
    { name: "OTX AlienVault", key: "otx", envVar: "OTX_API_KEY", supportedTypes: ["ip", "domain", "file_hash", "url"] },
  ];

  const statuses: ProviderStatus[] = [];

  for (const p of providers) {
    let configured = isProviderConfigured(p.envVar);
    let enabled = configured;

    if (orgId) {
      try {
        const [config] = await db.select().from(threatIntelConfigs).where(
          and(eq(threatIntelConfigs.orgId, orgId), eq(threatIntelConfigs.provider, p.key))
        );
        if (config) {
          configured = !!config.apiKey || configured;
          enabled = config.enabled ?? configured;
        }
      } catch (err) {
        logger.child("threat-enrichment").warn("Failed to load threat intel config for org", { error: String(err) });
      }
    }

    statuses.push({
      name: p.name,
      enabled,
      configured,
      supportedTypes: p.supportedTypes,
    });
  }

  return statuses;
}

async function enrichWithAbuseIPDB(entityType: string, value: string, orgId?: string): Promise<EnrichmentResult | null> {
  if (entityType !== "ip") return null;
  const apiKey = orgId ? await getOrgApiKey(orgId, "abuseipdb") : getApiKey("ABUSEIPDB_API_KEY");
  if (!apiKey) return null;

  try {
    const resp = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(value)}&maxAgeInDays=90&verbose`, {
      headers: { Key: apiKey, Accept: "application/json" },
    });

    if (!resp.ok) {
      logger.child("threat-enrichment").warn(`AbuseIPDB API error: ${resp.status}`);
      return null;
    }

    const json = await resp.json() as any;
    const data = json.data;
    if (!data) return null;

    const abuseScore = data.abuseConfidenceScore ?? 0;
    const normalized = Math.min(abuseScore / 100, 1);

    let verdict: EnrichmentResult["verdict"] = "clean";
    if (abuseScore >= 75) verdict = "malicious";
    else if (abuseScore >= 25) verdict = "suspicious";

    return {
      provider: "AbuseIPDB",
      entityType,
      entityValue: value,
      reputationScore: normalized,
      verdict,
      tags: [
        data.countryCode && `country:${data.countryCode}`,
        data.isp && `isp:${data.isp}`,
        data.usageType && `usage:${data.usageType}`,
        data.isWhitelisted && "whitelisted",
        data.isTor && "tor-exit-node",
      ].filter(Boolean) as string[],
      details: {
        abuseConfidenceScore: abuseScore,
        totalReports: data.totalReports ?? 0,
        numDistinctUsers: data.numDistinctUsers ?? 0,
        countryCode: data.countryCode,
        isp: data.isp,
        domain: data.domain,
        usageType: data.usageType,
        isTor: data.isTor ?? false,
        isWhitelisted: data.isWhitelisted ?? false,
        lastReportedAt: data.lastReportedAt,
      },
      enrichedAt: new Date().toISOString(),
    };
  } catch (err) {
    logger.child("threat-enrichment").warn("AbuseIPDB enrichment error", { error: String(err) });
    return null;
  }
}

async function enrichWithVirusTotal(entityType: string, value: string, orgId?: string): Promise<EnrichmentResult | null> {
  const apiKey = orgId ? await getOrgApiKey(orgId, "virustotal") : getApiKey("VIRUSTOTAL_API_KEY");
  if (!apiKey) return null;

  const typeEndpointMap: Record<string, string> = {
    ip: `ip_addresses/${encodeURIComponent(value)}`,
    domain: `domains/${encodeURIComponent(value)}`,
    file_hash: `files/${encodeURIComponent(value)}`,
    url: `urls/${Buffer.from(value).toString("base64url").replace(/=/g, "")}`,
  };

  const endpoint = typeEndpointMap[entityType];
  if (!endpoint) return null;

  try {
    const resp = await fetch(`https://www.virustotal.com/api/v3/${endpoint}`, {
      headers: { "x-apikey": apiKey, Accept: "application/json" },
    });

    if (!resp.ok) {
      logger.child("threat-enrichment").warn(`VirusTotal API error: ${resp.status}`);
      return null;
    }

    const json = await resp.json() as any;
    const attrs = json.data?.attributes;
    if (!attrs) return null;

    const stats = attrs.last_analysis_stats || {};
    const total = (stats.malicious || 0) + (stats.suspicious || 0) + (stats.undetected || 0) + (stats.harmless || 0);
    const maliciousRatio = total > 0 ? (stats.malicious || 0) / total : 0;
    const suspiciousRatio = total > 0 ? ((stats.malicious || 0) + (stats.suspicious || 0)) / total : 0;

    const communityScore = attrs.reputation ?? 0;
    const normalized = Math.min(Math.max(maliciousRatio * 0.7 + (communityScore < 0 ? Math.min(Math.abs(communityScore) / 100, 0.3) : 0), 0), 1);

    let verdict: EnrichmentResult["verdict"] = "clean";
    if (maliciousRatio >= 0.3 || (stats.malicious || 0) >= 5) verdict = "malicious";
    else if (suspiciousRatio >= 0.1 || (stats.suspicious || 0) >= 3) verdict = "suspicious";

    const tags: string[] = [];
    if (attrs.tags) tags.push(...attrs.tags.slice(0, 10));
    if (entityType === "ip" && attrs.country) tags.push(`country:${attrs.country}`);
    if (entityType === "ip" && attrs.as_owner) tags.push(`asn:${attrs.as_owner}`);
    if (entityType === "file_hash" && attrs.type_description) tags.push(`filetype:${attrs.type_description}`);

    return {
      provider: "VirusTotal",
      entityType,
      entityValue: value,
      reputationScore: normalized,
      verdict,
      tags,
      details: {
        malicious: stats.malicious || 0,
        suspicious: stats.suspicious || 0,
        undetected: stats.undetected || 0,
        harmless: stats.harmless || 0,
        totalEngines: total,
        communityScore,
        ...(entityType === "ip" ? { country: attrs.country, asOwner: attrs.as_owner, network: attrs.network } : {}),
        ...(entityType === "domain" ? { registrar: attrs.registrar, creationDate: attrs.creation_date } : {}),
        ...(entityType === "file_hash" ? { fileName: attrs.meaningful_name, fileSize: attrs.size, fileType: attrs.type_description } : {}),
      },
      enrichedAt: new Date().toISOString(),
    };
  } catch (err) {
    logger.child("threat-enrichment").warn("VirusTotal enrichment error", { error: String(err) });
    return null;
  }
}

async function enrichWithOTX(entityType: string, value: string, orgId?: string): Promise<EnrichmentResult | null> {
  const apiKey = orgId ? await getOrgApiKey(orgId, "otx") : getApiKey("OTX_API_KEY");
  if (!apiKey) return null;

  const typeEndpointMap: Record<string, string> = {
    ip: `indicators/IPv4/${encodeURIComponent(value)}/general`,
    domain: `indicators/domain/${encodeURIComponent(value)}/general`,
    file_hash: `indicators/file/${encodeURIComponent(value)}/general`,
    url: `indicators/url/${encodeURIComponent(value)}/general`,
  };

  const endpoint = typeEndpointMap[entityType];
  if (!endpoint) return null;

  try {
    const resp = await fetch(`https://otx.alienvault.com/api/v1/${endpoint}`, {
      headers: { "X-OTX-API-KEY": apiKey, Accept: "application/json" },
    });

    if (!resp.ok) {
      logger.child("threat-enrichment").warn(`OTX API error: ${resp.status}`);
      return null;
    }

    const json = await resp.json() as any;

    const pulseCount = json.pulse_info?.count ?? 0;
    const normalized = Math.min(pulseCount / 20, 1);

    let verdict: EnrichmentResult["verdict"] = "clean";
    if (pulseCount >= 10) verdict = "malicious";
    else if (pulseCount >= 3) verdict = "suspicious";

    const tags: string[] = [];
    if (json.pulse_info?.pulses) {
      const allTags = json.pulse_info.pulses.flatMap((p: any) => p.tags || []);
      const tagSet = new Set<string>(allTags);
      const uniqueTags = Array.from(tagSet).slice(0, 15);
      tags.push(...uniqueTags);
    }
    if (json.country_code) tags.push(`country:${json.country_code}`);
    if (json.asn) tags.push(`asn:${json.asn}`);

    return {
      provider: "OTX AlienVault",
      entityType,
      entityValue: value,
      reputationScore: normalized,
      verdict,
      tags,
      details: {
        pulseCount,
        reputation: json.reputation ?? 0,
        countryCode: json.country_code,
        asn: json.asn,
        indicatorType: json.type,
        sections: json.sections || [],
        ...(json.whois ? { registrant: json.whois.registrant } : {}),
      },
      enrichedAt: new Date().toISOString(),
    };
  } catch (err) {
    logger.child("threat-enrichment").warn("OTX enrichment error", { error: String(err) });
    return null;
  }
}

const ENRICHABLE_TYPES = new Set(["ip", "domain", "file_hash", "url"]);

export async function enrichEntity(entityId: string, force: boolean = false, orgId?: string): Promise<EnrichmentResult[]> {
  const [entity] = await db.select().from(entities).where(eq(entities.id, entityId)).limit(1);
  if (!entity) return [];

  if (!ENRICHABLE_TYPES.has(entity.type)) return [];

  const existingMeta = (entity.metadata || {}) as Record<string, any>;
  const existingEnrichment = existingMeta.enrichment as EnrichmentCache | undefined;

  if (!force && existingEnrichment?.lastEnrichedAt) {
    const age = Date.now() - new Date(existingEnrichment.lastEnrichedAt).getTime();
    if (age < ENRICHMENT_TTL_MS) {
      return existingEnrichment.results;
    }
  }

  const effectiveOrgId = orgId || entity.orgId || undefined;
  const providers = [
    enrichWithAbuseIPDB(entity.type, entity.value, effectiveOrgId),
    enrichWithVirusTotal(entity.type, entity.value, effectiveOrgId),
    enrichWithOTX(entity.type, entity.value, effectiveOrgId),
  ];

  const settled = await Promise.allSettled(providers);
  const results: EnrichmentResult[] = [];

  for (const s of settled) {
    if (s.status === "fulfilled" && s.value) {
      results.push(s.value);
    }
  }

  if (existingEnrichment?.results && results.length === 0) {
    return existingEnrichment.results;
  }

  const maxScore = results.length > 0
    ? Math.max(...results.map((r) => r.reputationScore))
    : (existingEnrichment?.riskScore ?? 0);

  const enrichmentCache: EnrichmentCache = {
    results,
    lastEnrichedAt: new Date().toISOString(),
    riskScore: maxScore,
  };

  await db.update(entities)
    .set({
      metadata: { ...existingMeta, enrichment: enrichmentCache },
      riskScore: maxScore,
      lastSeenAt: new Date(),
    })
    .where(eq(entities.id, entityId));

  return results;
}

export async function enrichEntityBackground(entityId: string): Promise<void> {
  setImmediate(async () => {
    try {
      await enrichEntity(entityId, false);
    } catch (err) {
      logger.child("threat-enrichment").warn(`Background enrichment failed for entity ${entityId}`, { error: String(err) });
    }
  });
}

export function getEnrichmentForEntity(metadata: Record<string, any> | null): EnrichmentCache | null {
  if (!metadata) return null;
  return (metadata as any).enrichment || null;
}

export function computeThreatIntelConfidenceBoost(entityMetadataList: (Record<string, any> | null)[]): number {
  let totalScore = 0;
  let count = 0;

  for (const meta of entityMetadataList) {
    const enrichment = getEnrichmentForEntity(meta);
    if (enrichment && enrichment.results.length > 0) {
      const maxEntityScore = Math.max(...enrichment.results.map((r) => r.reputationScore));
      if (maxEntityScore > 0) {
        totalScore += maxEntityScore;
        count++;
      }
    }
  }

  if (count === 0) return 0;

  const avgScore = totalScore / count;
  return Math.min(avgScore * 0.15, 0.15);
}

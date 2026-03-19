import { db } from "./db";
import { iocEntries, iocFeeds, iocMatches, alerts, campaigns, type IocFeed, type InsertIocEntry } from "@shared/schema";
import { eq, and, or, sql } from "drizzle-orm";
import { logger } from "./logger";

export interface IngestionResult {
  feedId: string;
  feedName: string;
  newEntries: number;
  updatedEntries: number;
  deduplicated: number;
  totalParsed: number;
  errors: string[];
  duration: number;
}

interface RawIOC {
  type: string;
  value: string;
  confidence?: number;
  severity?: string;
  malwareFamily?: string;
  campaignId?: string;
  campaignName?: string;
  tags?: string[];
  source?: string;
  firstSeen?: string;
  lastSeen?: string;
  metadata?: Record<string, any>;
}

// ── 4.7: STIX 2.1 Full Object Types ──
export interface STIXObject {
  stixId: string;
  stixType: string;
  name: string;
  description?: string;
  aliases?: string[];
  labels?: string[];
  created?: string;
  modified?: string;
  metadata: Record<string, any>;
}

export interface STIXRelationship {
  stixId: string;
  sourceRef: string;
  targetRef: string;
  relationshipType: string;
  description?: string;
}

export interface STIXFullParseResult {
  indicators: RawIOC[];
  threatActors: STIXObject[];
  campaigns: STIXObject[];
  malware: STIXObject[];
  tools: STIXObject[];
  attackPatterns: STIXObject[];
  relationships: STIXRelationship[];
}

// ── 4.8: Feed Authentication Types ──
export interface FeedAuthConfig {
  authType: "none" | "api_key" | "bearer" | "basic" | "mtls";
  apiKeyHeader?: string;
  apiKeyValue?: string;
  bearerToken?: string;
  basicUsername?: string;
  basicPassword?: string;
  clientCertPem?: string;
  clientKeyPem?: string;
  caCertPem?: string;
}

function normalizeIocType(raw: string): string {
  const lower = raw.toLowerCase().trim();
  const map: Record<string, string> = {
    "ipv4-addr": "ip",
    "ipv6-addr": "ip",
    "ip-src": "ip",
    "ip-dst": "ip",
    "ip-src|port": "ip",
    "ip-dst|port": "ip",
    ip: "ip",
    "domain-name": "domain",
    domain: "domain",
    hostname: "domain",
    url: "url",
    uri: "url",
    link: "url",
    "file:hashes.'SHA-256'": "hash",
    "file:hashes.'MD5'": "hash",
    "file:hashes.'SHA-1'": "hash",
    sha256: "hash",
    sha1: "hash",
    md5: "hash",
    hash: "hash",
    "file-hash": "hash",
    "filename|sha256": "hash",
    "filename|md5": "hash",
    "email-addr": "email",
    "email-src": "email",
    "email-dst": "email",
    email: "email",
    vulnerability: "cve",
    cve: "cve",
    "network-traffic:dst_ref.type = 'ipv4-addr'": "ip",
    "autonomous-system": "cidr",
    cidr: "cidr",
  };
  return map[lower] || lower;
}

function cleanIocValue(value: string): string {
  if (!value) return "";
  let cleaned = value.trim().toLowerCase();
  cleaned = cleaned.replace(/\[\.\]/g, ".").replace(/hxxp/gi, "http");
  if (cleaned.includes("|")) cleaned = cleaned.split("|")[0];
  return cleaned;
}

export function parseMISPFeed(data: any): RawIOC[] {
  const iocs: RawIOC[] = [];
  try {
    const events = Array.isArray(data)
      ? data
      : data?.response
        ? Array.isArray(data.response)
          ? data.response
          : [data.response]
        : data?.Event
          ? [data]
          : [];
    for (const item of events) {
      const event = item?.Event || item;
      const eventTags = (event?.Tag || []).map((t: any) => t?.name).filter(Boolean);
      const campaignName = event?.info || undefined;
      const attributes = event?.Attribute || [];
      for (const attr of attributes) {
        const type = normalizeIocType(attr.type || "");
        if (!type || !attr.value) continue;
        const attrTags = (attr?.Tag || []).map((t: any) => t?.name).filter(Boolean);
        iocs.push({
          type,
          value: cleanIocValue(attr.value),
          confidence: attr.to_ids ? 80 : 50,
          severity: mapThreatLevel(event?.threat_level_id),
          malwareFamily: extractMalwareFamily([...eventTags, ...attrTags]),
          campaignName,
          tags: Array.from(new Set([...eventTags, ...attrTags])),
          source: "MISP",
          firstSeen: attr.first_seen || event?.date,
          lastSeen: attr.last_seen || undefined,
          metadata: { category: attr.category, eventId: event?.id, comment: attr.comment },
        });
      }
    }
  } catch (e) {
    logger.child("ioc-ingestion").error("MISP parse error", { error: String(e), partialCount: iocs.length });
  }
  return iocs;
}

export function parseSTIXBundle(data: any): RawIOC[] {
  const result = parseSTIXBundleFull(data);
  return result.indicators;
}

// ── 4.7: Full STIX 2.1 object parser ──
export function parseSTIXBundleFull(data: any): STIXFullParseResult {
  const result: STIXFullParseResult = {
    indicators: [],
    threatActors: [],
    campaigns: [],
    malware: [],
    tools: [],
    attackPatterns: [],
    relationships: [],
  };

  try {
    const objects = data?.objects || (Array.isArray(data) ? data : []);
    const indicators = objects.filter((o: any) => o.type === "indicator");
    const malwareMap = new Map<string, string>();
    const campaignMap = new Map<string, { id: string; name: string }>();
    for (const obj of objects) {
      if (obj.type === "malware") malwareMap.set(obj.id, obj.name);
      if (obj.type === "campaign") campaignMap.set(obj.id, { id: obj.id, name: obj.name });
    }
    const relationships = objects.filter((o: any) => o.type === "relationship");
    const indicatorMalware = new Map<string, string>();
    const indicatorCampaign = new Map<string, { id: string; name: string }>();
    for (const rel of relationships) {
      if (rel.relationship_type === "indicates" && malwareMap.has(rel.target_ref)) {
        indicatorMalware.set(rel.source_ref, malwareMap.get(rel.target_ref)!);
      }
      if (rel.relationship_type === "indicates" && campaignMap.has(rel.target_ref)) {
        indicatorCampaign.set(rel.source_ref, campaignMap.get(rel.target_ref)!);
      }
    }
    for (const ind of indicators) {
      const pattern = ind.pattern || "";
      const extracted = extractFromSTIXPattern(pattern);
      for (const ext of extracted) {
        const labels = ind.labels || [];
        result.indicators.push({
          type: ext.type,
          value: cleanIocValue(ext.value),
          confidence: ind.confidence || 70,
          severity: mapSTIXSeverity(labels),
          malwareFamily: indicatorMalware.get(ind.id) || extractMalwareFamily(labels),
          campaignId: indicatorCampaign.get(ind.id)?.id,
          campaignName: indicatorCampaign.get(ind.id)?.name,
          tags: labels,
          source: "STIX",
          firstSeen: ind.valid_from || ind.created,
          lastSeen: ind.valid_until || ind.modified,
          metadata: { stixId: ind.id, stixType: ind.type, killChainPhases: ind.kill_chain_phases },
        });
      }
    }

    // Parse full STIX 2.1 objects
    for (const obj of objects) {
      switch (obj.type) {
        case "threat-actor":
          result.threatActors.push({
            stixId: obj.id,
            stixType: obj.type,
            name: obj.name || "Unknown Threat Actor",
            description: obj.description,
            aliases: obj.aliases || [],
            labels: obj.labels || [],
            created: obj.created,
            modified: obj.modified,
            metadata: {
              sophistication: obj.sophistication,
              resourceLevel: obj.resource_level,
              primaryMotivation: obj.primary_motivation,
              secondaryMotivations: obj.secondary_motivations,
              threatActorTypes: obj.threat_actor_types,
              goals: obj.goals,
              roles: obj.roles,
            },
          });
          break;
        case "campaign":
          result.campaigns.push({
            stixId: obj.id,
            stixType: obj.type,
            name: obj.name || "Unknown Campaign",
            description: obj.description,
            aliases: obj.aliases || [],
            labels: obj.labels || [],
            created: obj.created,
            modified: obj.modified,
            metadata: {
              firstSeen: obj.first_seen,
              lastSeen: obj.last_seen,
              objective: obj.objective,
            },
          });
          break;
        case "malware":
          result.malware.push({
            stixId: obj.id,
            stixType: obj.type,
            name: obj.name || "Unknown Malware",
            description: obj.description,
            aliases: obj.aliases || [],
            labels: obj.labels || [],
            created: obj.created,
            modified: obj.modified,
            metadata: {
              malwareTypes: obj.malware_types,
              isFamily: obj.is_family,
              capabilities: obj.capabilities,
              architectureExecutionEnvs: obj.architecture_execution_envs,
              implementationLanguages: obj.implementation_languages,
              operatingSystemRefs: obj.operating_system_refs,
            },
          });
          break;
        case "tool":
          result.tools.push({
            stixId: obj.id,
            stixType: obj.type,
            name: obj.name || "Unknown Tool",
            description: obj.description,
            aliases: obj.aliases || [],
            labels: obj.labels || [],
            created: obj.created,
            modified: obj.modified,
            metadata: {
              toolTypes: obj.tool_types,
              toolVersion: obj.tool_version,
              killChainPhases: obj.kill_chain_phases,
            },
          });
          break;
        case "attack-pattern":
          result.attackPatterns.push({
            stixId: obj.id,
            stixType: obj.type,
            name: obj.name || "Unknown Attack Pattern",
            description: obj.description,
            aliases: obj.aliases || [],
            labels: obj.labels || [],
            created: obj.created,
            modified: obj.modified,
            metadata: {
              killChainPhases: obj.kill_chain_phases,
              externalReferences: obj.external_references?.map((ref: any) => ({
                sourceName: ref.source_name,
                externalId: ref.external_id,
                url: ref.url,
              })),
            },
          });
          break;
        case "relationship":
          result.relationships.push({
            stixId: obj.id,
            sourceRef: obj.source_ref,
            targetRef: obj.target_ref,
            relationshipType: obj.relationship_type,
            description: obj.description,
          });
          break;
      }
    }
  } catch (e) {
    logger
      .child("ioc-ingestion")
      .error("STIX parse error", { error: String(e), partialCount: result.indicators.length });
  }
  return result;
}

function extractFromSTIXPattern(pattern: string): { type: string; value: string }[] {
  const results: { type: string; value: string }[] = [];
  const ipMatch = pattern.match(/ipv[46]-addr:value\s*=\s*'([^']+)'/g);
  if (ipMatch)
    ipMatch.forEach((m) => {
      const v = m.match(/'([^']+)'/);
      if (v) results.push({ type: "ip", value: v[1] });
    });
  const domainMatch = pattern.match(/domain-name:value\s*=\s*'([^']+)'/g);
  if (domainMatch)
    domainMatch.forEach((m) => {
      const v = m.match(/'([^']+)'/);
      if (v) results.push({ type: "domain", value: v[1] });
    });
  const urlMatch = pattern.match(/url:value\s*=\s*'([^']+)'/g);
  if (urlMatch)
    urlMatch.forEach((m) => {
      const v = m.match(/'([^']+)'/);
      if (v) results.push({ type: "url", value: v[1] });
    });
  const hashMatch = pattern.match(/file:hashes\.[^=]+=\s*'([^']+)'/g);
  if (hashMatch)
    hashMatch.forEach((m) => {
      const v = m.match(/'([^']+)'/);
      if (v) results.push({ type: "hash", value: v[1] });
    });
  const emailMatch = pattern.match(/email-addr:value\s*=\s*'([^']+)'/g);
  if (emailMatch)
    emailMatch.forEach((m) => {
      const v = m.match(/'([^']+)'/);
      if (v) results.push({ type: "email", value: v[1] });
    });
  return results;
}

export function parseTAXIICollection(data: any): RawIOC[] {
  if (data?.objects) return parseSTIXBundle(data);
  if (Array.isArray(data)) {
    const all: RawIOC[] = [];
    for (const item of data) {
      if (item?.objects) all.push(...parseSTIXBundle(item));
    }
    return all;
  }
  return [];
}

export function parseOTXPulses(data: any): RawIOC[] {
  const iocs: RawIOC[] = [];
  try {
    const pulses = data?.results || (Array.isArray(data) ? data : data?.id ? [data] : []);
    for (const pulse of pulses) {
      const pulseTags = pulse.tags || [];
      const campaignName = pulse.name || undefined;
      const indicators = pulse.indicators || [];
      for (const ind of indicators) {
        const type = normalizeIocType(ind.type || "");
        if (!type || !ind.indicator) continue;
        iocs.push({
          type,
          value: cleanIocValue(ind.indicator),
          confidence: 65,
          severity: mapOTXAdversaryLevel(pulse.adversary),
          malwareFamily: extractMalwareFamily([...pulseTags, ...(pulse.malware_families || [])]),
          campaignName,
          tags: Array.from(new Set([...pulseTags, ...(ind.tags || [])])),
          source: "OTX",
          firstSeen: ind.created || pulse.created,
          lastSeen: ind.modified || pulse.modified,
          metadata: { pulseId: pulse.id, pulseName: pulse.name, description: ind.description },
        });
      }
    }
  } catch (e) {
    logger.child("ioc-ingestion").error("OTX parse error", { error: String(e), partialCount: iocs.length });
  }
  return iocs;
}

export function parseVirusTotalFeed(data: any): RawIOC[] {
  const iocs: RawIOC[] = [];
  try {
    const items = Array.isArray(data) ? data : data?.data ? (Array.isArray(data.data) ? data.data : [data.data]) : [];
    for (const item of items) {
      const attrs = item.attributes || item;
      const type =
        item.type === "file"
          ? "hash"
          : item.type === "domain"
            ? "domain"
            : item.type === "ip_address"
              ? "ip"
              : item.type === "url"
                ? "url"
                : normalizeIocType(item.type || "");
      const value = type === "hash" ? attrs.sha256 || attrs.sha1 || attrs.md5 || item.id : item.id || attrs.id || "";
      if (!value) continue;
      const malicious = attrs.last_analysis_stats?.malicious || 0;
      const total =
        (attrs.last_analysis_stats?.malicious || 0) +
        (attrs.last_analysis_stats?.undetected || 0) +
        (attrs.last_analysis_stats?.harmless || 0);
      const confidence = total > 0 ? Math.round((malicious / total) * 100) : 50;
      const tags = [
        ...(attrs.tags || []),
        ...(attrs.popular_threat_classification?.suggested_threat_label
          ? [attrs.popular_threat_classification.suggested_threat_label]
          : []),
      ];
      iocs.push({
        type,
        value: cleanIocValue(value),
        confidence,
        severity: malicious > 10 ? "critical" : malicious > 5 ? "high" : malicious > 2 ? "medium" : "low",
        malwareFamily: attrs.popular_threat_classification?.suggested_threat_label || extractMalwareFamily(tags),
        tags,
        source: "VirusTotal",
        firstSeen: attrs.first_submission_date ? new Date(attrs.first_submission_date * 1000).toISOString() : undefined,
        lastSeen: attrs.last_analysis_date ? new Date(attrs.last_analysis_date * 1000).toISOString() : undefined,
        metadata: { vtId: item.id, maliciousCount: malicious, totalEngines: total },
      });
    }
  } catch (e) {
    logger.child("ioc-ingestion").error("VirusTotal parse error", { error: String(e), partialCount: iocs.length });
  }
  return iocs;
}

export function parseCSVFeed(
  data: string,
  config?: { typeColumn?: number; valueColumn?: number; separator?: string; skipHeader?: boolean },
): RawIOC[] {
  const iocs: RawIOC[] = [];
  try {
    const lines = data.trim().split("\n");
    const sep = config?.separator || ",";
    const typeCol = config?.typeColumn || 0;
    const valueCol = config?.valueColumn || 1;
    const start = config?.skipHeader !== false ? 1 : 0;
    for (let i = start; i < lines.length; i++) {
      const cols = lines[i].split(sep).map((c) => c.trim().replace(/^"|"$/g, ""));
      const type = normalizeIocType(cols[typeCol] || "");
      const value = cleanIocValue(cols[valueCol] || "");
      if (!type || !value) continue;
      iocs.push({ type, value, confidence: 50, source: "CSV", tags: [] });
    }
  } catch (e) {
    logger.child("ioc-ingestion").error("CSV parse error", { error: String(e), partialCount: iocs.length });
  }
  return iocs;
}

function mapThreatLevel(level: string | number | undefined): string {
  if (!level) return "medium";
  const l = String(level);
  if (l === "1") return "critical";
  if (l === "2") return "high";
  if (l === "3") return "medium";
  return "low";
}

function mapSTIXSeverity(labels: string[]): string {
  const joined = labels.join(" ").toLowerCase();
  if (joined.includes("critical") || joined.includes("apt")) return "critical";
  if (joined.includes("high") || joined.includes("ransomware")) return "high";
  if (joined.includes("medium")) return "medium";
  return "low";
}

function mapOTXAdversaryLevel(adversary: string | undefined): string {
  if (!adversary) return "medium";
  const lower = adversary.toLowerCase();
  if (lower.includes("apt") || lower.includes("nation")) return "critical";
  if (lower.includes("criminal") || lower.includes("organized")) return "high";
  return "medium";
}

function extractMalwareFamily(tags: string[]): string | undefined {
  const families = [
    "emotet",
    "trickbot",
    "cobalt strike",
    "mimikatz",
    "ryuk",
    "lockbit",
    "conti",
    "revil",
    "dridex",
    "qakbot",
    "icedid",
    "bumblebee",
    "asyncrat",
    "remcos",
    "redline",
    "raccoon",
    "vidar",
    "formbook",
    "agent tesla",
    "njrat",
  ];
  for (const tag of tags) {
    const lower = tag.toLowerCase();
    for (const family of families) {
      if (lower.includes(family)) return family.charAt(0).toUpperCase() + family.slice(1);
    }
  }
  return undefined;
}

// ── 4.6: Cross-feed deduplication layer ──
async function deduplicateIOCs(
  batch: InsertIocEntry[],
  orgId: string | null | undefined,
): Promise<{
  toInsert: InsertIocEntry[];
  toUpdate: Array<{ existing: any; incoming: InsertIocEntry }>;
  deduplicated: number;
}> {
  if (!orgId || batch.length === 0) {
    return { toInsert: batch, toUpdate: [], deduplicated: 0 };
  }

  // Build a lookup of existing IOCs by (iocType, iocValue) in this org
  const uniqueKeys = new Map<string, InsertIocEntry>();
  for (const entry of batch) {
    const key = `${entry.iocType}::${entry.iocValue}`;
    const existing = uniqueKeys.get(key);
    // Keep the entry with higher confidence or merge sources
    if (!existing || (entry.confidence ?? 0) > (existing.confidence ?? 0)) {
      uniqueKeys.set(key, entry);
    }
  }

  const dedupedBatch = Array.from(uniqueKeys.values());
  const inBatchDedup = batch.length - dedupedBatch.length;

  // Check for existing entries across ALL feeds in this org
  const toInsert: InsertIocEntry[] = [];
  const toUpdate: Array<{ existing: any; incoming: InsertIocEntry }> = [];
  let crossFeedDedup = 0;

  const LOOKUP_BATCH = 50;
  for (let i = 0; i < dedupedBatch.length; i += LOOKUP_BATCH) {
    const chunk = dedupedBatch.slice(i, i + LOOKUP_BATCH);
    const values = chunk.map((e) => e.iocValue);
    const types = chunk.map((e) => e.iocType);

    try {
      // Find existing entries with same type+value in this org (any feed)
      const existingEntries = await db
        .select()
        .from(iocEntries)
        .where(
          and(
            eq(iocEntries.orgId, orgId),
            sql`(${iocEntries.iocType}, ${iocEntries.iocValue}) IN (${sql.join(
              values.map((v, idx) => sql`(${types[idx]}, ${v})`),
              sql`, `,
            )})`,
          ),
        );

      const existingMap = new Map<string, any>();
      for (const ex of existingEntries) {
        const key = `${ex.iocType}::${ex.iocValue}`;
        // If entry is from a different feed, it's a cross-feed duplicate
        if (
          !existingMap.has(key) ||
          ex.feedId === chunk.find((c) => c.iocType === ex.iocType && c.iocValue === ex.iocValue)?.feedId
        ) {
          existingMap.set(key, ex);
        }
      }

      for (const entry of chunk) {
        const key = `${entry.iocType}::${entry.iocValue}`;
        const existing = existingMap.get(key);
        if (existing) {
          if (existing.feedId !== entry.feedId) {
            // Cross-feed duplicate: update lastSeen, merge sources in metadata, bump confidence
            toUpdate.push({ existing, incoming: entry });
            crossFeedDedup++;
          } else {
            // Same feed duplicate: update lastSeen
            toUpdate.push({ existing, incoming: entry });
            crossFeedDedup++;
          }
        } else {
          toInsert.push(entry);
        }
      }
    } catch (e: any) {
      // On lookup failure, fall back to inserting all
      logger.child("ioc-ingestion").warn(`Dedup lookup failed, inserting batch as-is: ${e.message}`);
      toInsert.push(...chunk);
    }
  }

  return {
    toInsert,
    toUpdate,
    deduplicated: inBatchDedup + crossFeedDedup,
  };
}

export async function ingestFeed(feed: IocFeed, rawData: any): Promise<IngestionResult> {
  const start = Date.now();
  const result: IngestionResult = {
    feedId: feed.id,
    feedName: feed.name,
    newEntries: 0,
    updatedEntries: 0,
    deduplicated: 0,
    totalParsed: 0,
    errors: [],
    duration: 0,
  };

  let rawIocs: RawIOC[] = [];
  try {
    switch (feed.feedType) {
      case "misp":
        rawIocs = parseMISPFeed(rawData);
        break;
      case "stix":
        rawIocs = parseSTIXBundle(rawData);
        break;
      case "taxii":
        rawIocs = parseTAXIICollection(rawData);
        break;
      case "otx":
        rawIocs = parseOTXPulses(rawData);
        break;
      case "virustotal":
        rawIocs = parseVirusTotalFeed(rawData);
        break;
      case "csv":
        rawIocs = parseCSVFeed(typeof rawData === "string" ? rawData : JSON.stringify(rawData), feed.config as any);
        break;
      default:
        rawIocs = parseSTIXBundle(rawData);
    }
  } catch (e: any) {
    result.errors.push(`Parse error: ${e.message}`);
    result.duration = Date.now() - start;
    return result;
  }

  result.totalParsed = rawIocs.length;

  const batch: InsertIocEntry[] = [];
  for (const raw of rawIocs) {
    if (!raw.value || !raw.type) continue;
    batch.push({
      orgId: feed.orgId,
      feedId: feed.id,
      iocType: raw.type,
      iocValue: raw.value,
      confidence: raw.confidence || 50,
      severity: raw.severity || "medium",
      malwareFamily: raw.malwareFamily || null,
      campaignId: raw.campaignId || null,
      campaignName: raw.campaignName || null,
      tags: raw.tags || [],
      source: raw.source || feed.name,
      status: "active",
      metadata: raw.metadata || {},
      expiresAt: null,
    });
  }

  // ── 4.6: Deduplicate across feeds ──
  const { toInsert, toUpdate, deduplicated } = await deduplicateIOCs(batch, feed.orgId);
  result.deduplicated = deduplicated;

  // Insert genuinely new entries
  if (toInsert.length > 0) {
    const CHUNK_SIZE = 100;
    for (let i = 0; i < toInsert.length; i += CHUNK_SIZE) {
      const chunk = toInsert.slice(i, i + CHUNK_SIZE);
      try {
        const inserted = await db.insert(iocEntries).values(chunk).onConflictDoNothing().returning();
        result.newEntries += inserted.length;
      } catch (e: any) {
        result.errors.push(`Batch insert error at chunk ${i}: ${e.message}`);
      }
    }
  }

  // Update existing entries with merged source attributions
  for (const { existing, incoming } of toUpdate) {
    try {
      const existingMeta = (existing.metadata as Record<string, any>) || {};
      const incomingMeta = (incoming.metadata as Record<string, any>) || {};
      const existingSources: string[] = existingMeta.additionalSources || [];
      const incomingSource = incoming.source || feed.name;
      if (!existingSources.includes(incomingSource) && existing.source !== incomingSource) {
        existingSources.push(incomingSource);
      }
      const mergedConfidence = Math.max(existing.confidence ?? 0, incoming.confidence ?? 0);
      await db
        .update(iocEntries)
        .set({
          lastSeen: new Date(),
          confidence: mergedConfidence,
          metadata: {
            ...existingMeta,
            ...incomingMeta,
            additionalSources: existingSources,
            additionalFeedIds: [
              ...(existingMeta.additionalFeedIds || []),
              ...(incoming.feedId && incoming.feedId !== existing.feedId ? [incoming.feedId] : []),
            ],
          },
        })
        .where(eq(iocEntries.id, existing.id));
      result.updatedEntries++;
    } catch (e: any) {
      result.errors.push(`Dedup update error for ${existing.iocValue}: ${e.message}`);
    }
  }

  try {
    await db
      .update(iocFeeds)
      .set({
        lastFetchAt: new Date(),
        lastFetchStatus: result.errors.length > 0 ? "partial" : "success",
        lastFetchCount: result.newEntries,
        totalIocCount: sql`${iocFeeds.totalIocCount} + ${result.newEntries}`,
        updatedAt: new Date(),
      })
      .where(eq(iocFeeds.id, feed.id));
  } catch (e: any) {
    result.errors.push(`Feed update error: ${e.message}`);
  }

  // ── 4.9: Automatically match newly ingested IOCs against existing alerts ──
  if (result.newEntries > 0 && feed.orgId) {
    try {
      const autoMatchResult = await matchNewIOCsAgainstAlerts(batch, feed.orgId, feed.id, feed.name);
      logger
        .child("ioc-ingestion")
        .info(`Auto-matched ${autoMatchResult.matchCount} alerts against ${result.newEntries} new IOCs`, {
          feedId: feed.id,
          matchCount: autoMatchResult.matchCount,
        });
      (result as IngestionResult & { autoMatches?: number }).autoMatches = autoMatchResult.matchCount;
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      logger.child("ioc-ingestion").warn("Auto-match against alerts failed (non-fatal)", { error: msg });
    }
  }

  // ── 4.10: Auto-link IOCs to campaigns when feed includes campaign/threat actor attribution ──
  if (result.newEntries > 0 && feed.orgId) {
    try {
      const linkResult = await autoLinkIOCsToCampaigns(batch, feed.orgId);
      logger
        .child("ioc-ingestion")
        .info(`Auto-linked ${linkResult.linked} IOCs to ${linkResult.campaignsMatched} campaigns`, {
          feedId: feed.id,
          linked: linkResult.linked,
          campaignsMatched: linkResult.campaignsMatched,
        });
      (result as IngestionResult & { campaignLinks?: number }).campaignLinks = linkResult.linked;
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      logger.child("ioc-ingestion").warn("Campaign auto-link failed (non-fatal)", { error: msg });
    }
  }

  result.duration = Date.now() - start;
  return result;
}

// ── 4.8: Build fetch headers from feed authentication config ──
function buildAuthHeaders(feed: IocFeed): Record<string, string> {
  const headers: Record<string, string> = { Accept: "application/json" };
  const config = (feed.config as Record<string, any>) || {};
  const authConfig = config.auth as FeedAuthConfig | undefined;

  if (authConfig && authConfig.authType !== "none") {
    switch (authConfig.authType) {
      case "api_key":
        if (authConfig.apiKeyHeader && authConfig.apiKeyValue) {
          headers[authConfig.apiKeyHeader] = authConfig.apiKeyValue;
        }
        break;
      case "bearer":
        if (authConfig.bearerToken) {
          headers["Authorization"] = `Bearer ${authConfig.bearerToken}`;
        }
        break;
      case "basic":
        if (authConfig.basicUsername && authConfig.basicPassword) {
          const encoded = Buffer.from(`${authConfig.basicUsername}:${authConfig.basicPassword}`).toString("base64");
          headers["Authorization"] = `Basic ${encoded}`;
        }
        break;
      case "mtls":
        // mTLS is handled at the fetch/agent level, not via headers
        // The client cert/key are passed via the TLS agent options
        break;
    }
  } else if (feed.apiKeyRef) {
    // Legacy: fallback to apiKeyRef for backward compat
    const apiKey = process.env[feed.apiKeyRef] || feed.apiKeyRef;
    if (feed.feedType === "otx") headers["X-OTX-API-KEY"] = apiKey;
    else if (feed.feedType === "virustotal") headers["x-apikey"] = apiKey;
    else headers["Authorization"] = `Bearer ${apiKey}`;
  }

  return headers;
}

export async function fetchAndIngestFeed(feed: IocFeed): Promise<IngestionResult> {
  if (!feed.url) {
    return {
      feedId: feed.id,
      feedName: feed.name,
      newEntries: 0,
      updatedEntries: 0,
      deduplicated: 0,
      totalParsed: 0,
      errors: ["No URL configured for feed"],
      duration: 0,
    };
  }

  try {
    const headers = buildAuthHeaders(feed);

    const response = await fetch(feed.url, { headers, signal: AbortSignal.timeout(30000) });
    if (!response.ok) {
      const errorText = await response.text().catch(() => "");
      await db
        .update(iocFeeds)
        .set({ lastFetchAt: new Date(), lastFetchStatus: `error: ${response.status}`, updatedAt: new Date() })
        .where(eq(iocFeeds.id, feed.id));
      return {
        feedId: feed.id,
        feedName: feed.name,
        newEntries: 0,
        updatedEntries: 0,
        deduplicated: 0,
        totalParsed: 0,
        errors: [`HTTP ${response.status}: ${errorText.slice(0, 200)}`],
        duration: 0,
      };
    }

    const contentType = response.headers.get("content-type") || "";
    let rawData: any;
    if (feed.feedType === "csv" || contentType.includes("text/csv") || contentType.includes("text/plain")) {
      rawData = await response.text();
    } else {
      rawData = await response.json();
    }

    return await ingestFeed(feed, rawData);
  } catch (e: any) {
    await db
      .update(iocFeeds)
      .set({ lastFetchAt: new Date(), lastFetchStatus: `error: ${e.message}`, updatedAt: new Date() })
      .where(eq(iocFeeds.id, feed.id));
    return {
      feedId: feed.id,
      feedName: feed.name,
      newEntries: 0,
      updatedEntries: 0,
      deduplicated: 0,
      totalParsed: 0,
      errors: [`Fetch error: ${e.message}`],
      duration: 0,
    };
  }
}

// ── 4.9: Reverse-match newly ingested IOCs against existing alerts ──
// For each new IOC, scan recent open alerts for matching fields (sourceIp, destIp, domain, url, fileHash, hostname)
// and create iocMatch records so the IOC Management page shows retroactive matches.
async function matchNewIOCsAgainstAlerts(
  batch: InsertIocEntry[],
  orgId: string,
  feedId: string,
  feedName: string,
): Promise<{ matchCount: number }> {
  const log = logger.child("ioc-auto-match");
  let matchCount = 0;

  // Build lookup maps by IOC type → values
  const ipValues: string[] = [];
  const domainValues: string[] = [];
  const urlValues: string[] = [];
  const hashValues: string[] = [];
  const iocLookup = new Map<string, InsertIocEntry>(); // "type:value" → entry

  for (const entry of batch) {
    if (!entry.iocValue || !entry.iocType) continue;
    const val = entry.iocValue.toLowerCase();
    const key = `${entry.iocType}:${val}`;
    iocLookup.set(key, entry);

    switch (entry.iocType) {
      case "ip":
      case "ipv4":
      case "ipv6":
        ipValues.push(val);
        break;
      case "domain":
      case "hostname":
        domainValues.push(val);
        break;
      case "url":
        urlValues.push(val);
        break;
      case "hash":
      case "md5":
      case "sha1":
      case "sha256":
        hashValues.push(val);
        break;
    }
  }

  // Build OR conditions to find alerts with any matching field
  const orConditions = [];
  if (ipValues.length > 0) {
    orConditions.push(
      sql`LOWER(${alerts.sourceIp}) IN (${sql.join(
        ipValues.map((v) => sql`${v}`),
        sql`, `,
      )})`,
    );
    orConditions.push(
      sql`LOWER(${alerts.destIp}) IN (${sql.join(
        ipValues.map((v) => sql`${v}`),
        sql`, `,
      )})`,
    );
  }
  if (domainValues.length > 0) {
    orConditions.push(
      sql`LOWER(${alerts.domain}) IN (${sql.join(
        domainValues.map((v) => sql`${v}`),
        sql`, `,
      )})`,
    );
    orConditions.push(
      sql`LOWER(${alerts.hostname}) IN (${sql.join(
        domainValues.map((v) => sql`${v}`),
        sql`, `,
      )})`,
    );
  }
  if (urlValues.length > 0) {
    orConditions.push(
      sql`LOWER(${alerts.url}) IN (${sql.join(
        urlValues.map((v) => sql`${v}`),
        sql`, `,
      )})`,
    );
  }
  if (hashValues.length > 0) {
    orConditions.push(
      sql`LOWER(${alerts.fileHash}) IN (${sql.join(
        hashValues.map((v) => sql`${v}`),
        sql`, `,
      )})`,
    );
  }

  if (orConditions.length === 0) return { matchCount: 0 };

  // Fetch recent open alerts (last 90 days, non-resolved) that have matching fields
  const ninetyDaysAgo = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000);
  const matchingAlerts = await db
    .select()
    .from(alerts)
    .where(
      and(
        eq(alerts.orgId, orgId),
        sql`${alerts.status} NOT IN ('resolved', 'closed', 'false_positive')`,
        sql`${alerts.createdAt} >= ${ninetyDaysAgo}`,
        or(...orConditions),
      ),
    )
    .limit(500);

  if (matchingAlerts.length === 0) return { matchCount: 0 };

  // For each matching alert, create iocMatch records
  const fieldMappings: { alertField: keyof typeof alerts.$inferSelect; iocType: string }[] = [
    { alertField: "sourceIp", iocType: "ip" },
    { alertField: "destIp", iocType: "ip" },
    { alertField: "domain", iocType: "domain" },
    { alertField: "hostname", iocType: "domain" },
    { alertField: "url", iocType: "url" },
    { alertField: "fileHash", iocType: "hash" },
  ];

  for (const alert of matchingAlerts) {
    for (const mapping of fieldMappings) {
      const alertValue = alert[mapping.alertField];
      if (!alertValue || typeof alertValue !== "string") continue;
      const normalizedAlertVal = alertValue.trim().toLowerCase();

      // Check if this alert field value matches any IOC in the batch
      const iocKey = `${mapping.iocType}:${normalizedAlertVal}`;
      const matchedIoc = iocLookup.get(iocKey);
      if (!matchedIoc) continue;

      // Resolve actual inserted IOC entry ID from DB
      try {
        const [iocRow] = await db
          .select({ id: iocEntries.id })
          .from(iocEntries)
          .where(
            and(
              eq(iocEntries.orgId, orgId),
              eq(iocEntries.iocType, matchedIoc.iocType!),
              eq(iocEntries.iocValue, matchedIoc.iocValue!),
            ),
          )
          .limit(1);
        if (!iocRow) continue;

        await db.insert(iocMatches).values({
          orgId,
          iocEntryId: iocRow.id,
          alertId: alert.id,
          matchField: mapping.alertField as string,
          matchValue: normalizedAlertVal,
          confidence: matchedIoc.confidence || 50,
          enrichmentData: {
            autoMatched: true,
            matchSource: "feed_ingestion",
            feedId,
            feedName,
            malwareFamily: matchedIoc.malwareFamily,
            campaignName: matchedIoc.campaignName,
            severity: matchedIoc.severity,
            tags: matchedIoc.tags,
          },
        });
        matchCount++;
      } catch (e) {
        // Duplicate match or constraint violation — skip silently
        log.debug("Skipped duplicate auto-match", {
          alertId: alert.id,
          field: mapping.alertField,
          value: normalizedAlertVal,
        });
      }
    }
  }

  log.info(`Auto-matched ${matchCount} alert-IOC pairs from ${matchingAlerts.length} alerts`);
  return { matchCount };
}

// ── 4.10: Auto-link IOCs to existing campaigns based on campaign/threat actor attribution ──
// When ingested IOCs carry campaignName metadata, find matching campaigns in the org
// and update IOC entries with the campaign ID + update the campaign's alert/IOC count.
async function autoLinkIOCsToCampaigns(
  batch: InsertIocEntry[],
  orgId: string,
): Promise<{ linked: number; campaignsMatched: number }> {
  const log = logger.child("ioc-campaign-link");

  // Collect unique campaign names from the batch
  const campaignNames = new Set<string>();
  for (const entry of batch) {
    if (entry.campaignName && entry.campaignName.trim()) {
      campaignNames.add(entry.campaignName.trim().toLowerCase());
    }
  }

  if (campaignNames.size === 0) return { linked: 0, campaignsMatched: 0 };

  // Fetch existing campaigns for this org
  const orgCampaigns = await db.select().from(campaigns).where(eq(campaigns.orgId, orgId));

  // Build name → campaign lookup (case-insensitive)
  const campaignMap = new Map<string, (typeof orgCampaigns)[number]>();
  for (const c of orgCampaigns) {
    campaignMap.set(c.name.toLowerCase(), c);
    // Also try matching on fingerprint/entity signature for fuzzy matching
    if (c.fingerprint) {
      campaignMap.set(c.fingerprint.toLowerCase(), c);
    }
  }

  let linked = 0;
  const matchedCampaignIds = new Set<string>();

  for (const entry of batch) {
    if (!entry.campaignName || !entry.campaignName.trim()) continue;
    const nameKey = entry.campaignName.trim().toLowerCase();
    const matchedCampaign = campaignMap.get(nameKey);

    if (!matchedCampaign) continue;

    // Update IOC entries that match this value+type to set campaignId
    try {
      if (entry.iocValue && entry.iocType) {
        const updated = await db
          .update(iocEntries)
          .set({
            campaignId: matchedCampaign.id,
            metadata: sql`COALESCE(${iocEntries.metadata}, '{}'::jsonb) || jsonb_build_object('linkedCampaign', ${matchedCampaign.name}, 'linkedAt', ${new Date().toISOString()})`,
          })
          .where(
            and(
              eq(iocEntries.orgId, orgId),
              eq(iocEntries.iocType, entry.iocType),
              eq(iocEntries.iocValue, entry.iocValue),
              sql`${iocEntries.campaignId} IS NULL`,
            ),
          )
          .returning({ id: iocEntries.id });

        if (updated.length > 0) {
          linked += updated.length;
          matchedCampaignIds.add(matchedCampaign.id);
        }
      }
    } catch (e) {
      log.debug("Failed to link IOC to campaign", {
        iocValue: entry.iocValue,
        campaignId: matchedCampaign.id,
        error: String(e),
      });
    }
  }

  // Update campaign last-seen timestamps for matched campaigns
  const campaignIdArr = Array.from(matchedCampaignIds);
  for (const cId of campaignIdArr) {
    try {
      await db
        .update(campaigns)
        .set({
          lastSeenAt: new Date(),
          updatedAt: new Date(),
        })
        .where(eq(campaigns.id, cId));
    } catch (e) {
      log.debug("Failed to update campaign lastSeenAt", { campaignId: cId, error: String(e) });
    }
  }

  log.info(`Linked ${linked} IOCs to ${matchedCampaignIds.size} campaigns`);
  return { linked, campaignsMatched: matchedCampaignIds.size };
}

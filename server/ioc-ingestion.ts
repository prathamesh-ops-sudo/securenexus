import { db } from "./db";
import { iocEntries, iocFeeds, type IocFeed, type InsertIocEntry } from "@shared/schema";
import { eq, sql } from "drizzle-orm";
import { logger } from "./logger";

export interface IngestionResult {
  feedId: string;
  feedName: string;
  newEntries: number;
  updatedEntries: number;
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

function normalizeIocType(raw: string): string {
  const lower = raw.toLowerCase().trim();
  const map: Record<string, string> = {
    "ipv4-addr": "ip", "ipv6-addr": "ip", "ip-src": "ip", "ip-dst": "ip",
    "ip-src|port": "ip", "ip-dst|port": "ip", "ip": "ip",
    "domain-name": "domain", "domain": "domain", "hostname": "domain",
    "url": "url", "uri": "url", "link": "url",
    "file:hashes.'SHA-256'": "hash", "file:hashes.'MD5'": "hash", "file:hashes.'SHA-1'": "hash",
    "sha256": "hash", "sha1": "hash", "md5": "hash", "hash": "hash",
    "file-hash": "hash", "filename|sha256": "hash", "filename|md5": "hash",
    "email-addr": "email", "email-src": "email", "email-dst": "email", "email": "email",
    "vulnerability": "cve", "cve": "cve",
    "network-traffic:dst_ref.type = 'ipv4-addr'": "ip",
    "autonomous-system": "cidr", "cidr": "cidr",
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
    const events = Array.isArray(data) ? data : data?.response ? (Array.isArray(data.response) ? data.response : [data.response]) : data?.Event ? [data] : [];
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
    logger.child("ioc-ingestion").error("MISP parse error", { error: String(e) });
    throw e;
  }
  return iocs;
}

export function parseSTIXBundle(data: any): RawIOC[] {
  const iocs: RawIOC[] = [];
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
        iocs.push({
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
  } catch (e) {
    logger.child("ioc-ingestion").error("STIX parse error", { error: String(e) });
    throw e;
  }
  return iocs;
}

function extractFromSTIXPattern(pattern: string): { type: string; value: string }[] {
  const results: { type: string; value: string }[] = [];
  const ipMatch = pattern.match(/ipv[46]-addr:value\s*=\s*'([^']+)'/g);
  if (ipMatch) ipMatch.forEach(m => { const v = m.match(/'([^']+)'/); if (v) results.push({ type: "ip", value: v[1] }); });
  const domainMatch = pattern.match(/domain-name:value\s*=\s*'([^']+)'/g);
  if (domainMatch) domainMatch.forEach(m => { const v = m.match(/'([^']+)'/); if (v) results.push({ type: "domain", value: v[1] }); });
  const urlMatch = pattern.match(/url:value\s*=\s*'([^']+)'/g);
  if (urlMatch) urlMatch.forEach(m => { const v = m.match(/'([^']+)'/); if (v) results.push({ type: "url", value: v[1] }); });
  const hashMatch = pattern.match(/file:hashes\.[^=]+=\s*'([^']+)'/g);
  if (hashMatch) hashMatch.forEach(m => { const v = m.match(/'([^']+)'/); if (v) results.push({ type: "hash", value: v[1] }); });
  const emailMatch = pattern.match(/email-addr:value\s*=\s*'([^']+)'/g);
  if (emailMatch) emailMatch.forEach(m => { const v = m.match(/'([^']+)'/); if (v) results.push({ type: "email", value: v[1] }); });
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
    logger.child("ioc-ingestion").error("OTX parse error", { error: String(e) });
    throw e;
  }
  return iocs;
}

export function parseVirusTotalFeed(data: any): RawIOC[] {
  const iocs: RawIOC[] = [];
  try {
    const items = Array.isArray(data) ? data : data?.data ? (Array.isArray(data.data) ? data.data : [data.data]) : [];
    for (const item of items) {
      const attrs = item.attributes || item;
      const type = item.type === "file" ? "hash" : item.type === "domain" ? "domain" : item.type === "ip_address" ? "ip" : item.type === "url" ? "url" : normalizeIocType(item.type || "");
      const value = type === "hash" ? (attrs.sha256 || attrs.sha1 || attrs.md5 || item.id) : (item.id || attrs.id || "");
      if (!value) continue;
      const malicious = attrs.last_analysis_stats?.malicious || 0;
      const total = (attrs.last_analysis_stats?.malicious || 0) + (attrs.last_analysis_stats?.undetected || 0) + (attrs.last_analysis_stats?.harmless || 0);
      const confidence = total > 0 ? Math.round((malicious / total) * 100) : 50;
      const tags = [...(attrs.tags || []), ...(attrs.popular_threat_classification?.suggested_threat_label ? [attrs.popular_threat_classification.suggested_threat_label] : [])];
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
    logger.child("ioc-ingestion").error("VirusTotal parse error", { error: String(e) });
    throw e;
  }
  return iocs;
}

export function parseCSVFeed(data: string, config?: { typeColumn?: number; valueColumn?: number; separator?: string; skipHeader?: boolean }): RawIOC[] {
  const iocs: RawIOC[] = [];
  try {
    const lines = data.trim().split("\n");
    const sep = config?.separator || ",";
    const typeCol = config?.typeColumn || 0;
    const valueCol = config?.valueColumn || 1;
    const start = config?.skipHeader !== false ? 1 : 0;
    for (let i = start; i < lines.length; i++) {
      const cols = lines[i].split(sep).map(c => c.trim().replace(/^"|"$/g, ""));
      const type = normalizeIocType(cols[typeCol] || "");
      const value = cleanIocValue(cols[valueCol] || "");
      if (!type || !value) continue;
      iocs.push({ type, value, confidence: 50, source: "CSV", tags: [] });
    }
  } catch (e) {
    logger.child("ioc-ingestion").error("CSV parse error", { error: String(e) });
    throw e;
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
  const families = ["emotet", "trickbot", "cobalt strike", "mimikatz", "ryuk", "lockbit", "conti", "revil", "dridex", "qakbot", "icedid", "bumblebee", "asyncrat", "remcos", "redline", "raccoon", "vidar", "formbook", "agent tesla", "njrat"];
  for (const tag of tags) {
    const lower = tag.toLowerCase();
    for (const family of families) {
      if (lower.includes(family)) return family.charAt(0).toUpperCase() + family.slice(1);
    }
  }
  return undefined;
}

export async function ingestFeed(feed: IocFeed, rawData: any): Promise<IngestionResult> {
  const start = Date.now();
  const result: IngestionResult = { feedId: feed.id, feedName: feed.name, newEntries: 0, updatedEntries: 0, totalParsed: 0, errors: [], duration: 0 };

  let rawIocs: RawIOC[] = [];
  try {
    switch (feed.feedType) {
      case "misp": rawIocs = parseMISPFeed(rawData); break;
      case "stix": rawIocs = parseSTIXBundle(rawData); break;
      case "taxii": rawIocs = parseTAXIICollection(rawData); break;
      case "otx": rawIocs = parseOTXPulses(rawData); break;
      case "virustotal": rawIocs = parseVirusTotalFeed(rawData); break;
      case "csv": rawIocs = parseCSVFeed(typeof rawData === "string" ? rawData : JSON.stringify(rawData), feed.config as any); break;
      default: rawIocs = parseSTIXBundle(rawData);
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

  if (batch.length > 0) {
    const CHUNK_SIZE = 100;
    for (let i = 0; i < batch.length; i += CHUNK_SIZE) {
      const chunk = batch.slice(i, i + CHUNK_SIZE);
      try {
        const inserted = await db.insert(iocEntries).values(chunk).onConflictDoNothing().returning();
        result.newEntries += inserted.length;
      } catch (e: any) {
        result.errors.push(`Batch insert error at chunk ${i}: ${e.message}`);
      }
    }
  }

  try {
    await db.update(iocFeeds).set({
      lastFetchAt: new Date(),
      lastFetchStatus: result.errors.length > 0 ? "partial" : "success",
      lastFetchCount: result.newEntries,
      totalIocCount: sql`${iocFeeds.totalIocCount} + ${result.newEntries}`,
      updatedAt: new Date(),
    }).where(eq(iocFeeds.id, feed.id));
  } catch (e: any) {
    result.errors.push(`Feed update error: ${e.message}`);
  }

  result.duration = Date.now() - start;
  return result;
}

export async function fetchAndIngestFeed(feed: IocFeed): Promise<IngestionResult> {
  if (!feed.url) {
    return { feedId: feed.id, feedName: feed.name, newEntries: 0, updatedEntries: 0, totalParsed: 0, errors: ["No URL configured for feed"], duration: 0 };
  }

  try {
    const headers: Record<string, string> = { "Accept": "application/json" };
    if (feed.apiKeyRef) {
      const apiKey = process.env[feed.apiKeyRef] || feed.apiKeyRef;
      if (feed.feedType === "otx") headers["X-OTX-API-KEY"] = apiKey;
      else if (feed.feedType === "virustotal") headers["x-apikey"] = apiKey;
      else headers["Authorization"] = `Bearer ${apiKey}`;
    }

    const response = await fetch(feed.url, { headers, signal: AbortSignal.timeout(30000) });
    if (!response.ok) {
      const errorText = await response.text().catch(() => "");
      await db.update(iocFeeds).set({ lastFetchAt: new Date(), lastFetchStatus: `error: ${response.status}`, updatedAt: new Date() }).where(eq(iocFeeds.id, feed.id));
      return { feedId: feed.id, feedName: feed.name, newEntries: 0, updatedEntries: 0, totalParsed: 0, errors: [`HTTP ${response.status}: ${errorText.slice(0, 200)}`], duration: 0 };
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
    await db.update(iocFeeds).set({ lastFetchAt: new Date(), lastFetchStatus: `error: ${e.message}`, updatedAt: new Date() }).where(eq(iocFeeds.id, feed.id));
    return { feedId: feed.id, feedName: feed.name, newEntries: 0, updatedEntries: 0, totalParsed: 0, errors: [`Fetch error: ${e.message}`], duration: 0 };
  }
}

import { db } from "./db";
import { sql, eq, and, gte, lte, desc, count, ilike, or } from "drizzle-orm";
import { dnsEvents, dnsFindings, sinkholedDomains, passiveDnsRecords } from "../shared/schema";
import { logger } from "./routes/shared";

const log = logger.child("dns-analyzer");

// ─── Shannon Entropy Calculator ──────────────────────────────────────────────

export function computeEntropy(str: string): number {
  if (!str || str.length === 0) return 0;
  const freq: Record<string, number> = {};
  for (const ch of str) {
    freq[ch] = (freq[ch] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const ch of Object.keys(freq)) {
    const p = freq[ch] / len;
    if (p > 0) entropy -= p * Math.log2(p);
  }
  return Math.round(entropy * 1000) / 1000;
}

// ─── DGA Detection ──────────────────────────────────────────────────────────

/**
 * ML-lite DGA detector using multiple heuristics:
 * 1. Shannon entropy of the domain label
 * 2. Consonant-to-vowel ratio
 * 3. Digit density
 * 4. Bigram frequency deviation
 * 5. Label length anomaly
 */
export interface DgaResult {
  isDga: boolean;
  confidence: number;
  entropy: number;
  features: {
    consonantVowelRatio: number;
    digitDensity: number;
    labelLength: number;
    hasRepeatingPattern: boolean;
    bigramScore: number;
  };
}

const VOWELS = new Set("aeiou");
const COMMON_TLDS = new Set([
  "com",
  "net",
  "org",
  "io",
  "co",
  "us",
  "uk",
  "de",
  "fr",
  "jp",
  "cn",
  "ru",
  "br",
  "in",
  "au",
  "ca",
  "info",
  "biz",
  "xyz",
  "top",
]);

// Common English bigrams for comparison
const COMMON_BIGRAMS = new Set([
  "th",
  "he",
  "in",
  "er",
  "an",
  "re",
  "on",
  "at",
  "en",
  "nd",
  "ti",
  "es",
  "or",
  "te",
  "of",
  "ed",
  "is",
  "it",
  "al",
  "ar",
  "st",
  "to",
  "nt",
  "ng",
  "se",
  "ha",
  "as",
  "ou",
  "io",
  "le",
  "ve",
  "co",
  "me",
  "de",
  "hi",
  "ri",
  "ro",
  "ic",
  "ne",
  "ea",
]);

export function detectDga(domain: string): DgaResult {
  // Extract the primary label (before TLD)
  const parts = domain.toLowerCase().replace(/\.$/, "").split(".");
  const tld = parts.length > 1 ? parts[parts.length - 1] : "";
  const label = parts.length > 2 ? parts.slice(0, -1).join(".") : parts[0];

  const entropy = computeEntropy(label);

  // Feature 1: Consonant-to-vowel ratio
  let vowelCount = 0;
  let consonantCount = 0;
  let digitCount = 0;
  for (const ch of label) {
    if (/[a-z]/.test(ch)) {
      if (VOWELS.has(ch)) vowelCount++;
      else consonantCount++;
    } else if (/[0-9]/.test(ch)) {
      digitCount++;
    }
  }
  const consonantVowelRatio = vowelCount > 0 ? consonantCount / vowelCount : consonantCount;

  // Feature 2: Digit density
  const digitDensity = label.length > 0 ? digitCount / label.length : 0;

  // Feature 3: Label length
  const labelLength = label.length;

  // Feature 4: Repeating patterns
  const hasRepeatingPattern = /(.)\1{3,}/.test(label) || /(.{2,})\1{2,}/.test(label);

  // Feature 5: Bigram deviation score
  let commonBigramCount = 0;
  let totalBigrams = 0;
  for (let i = 0; i < label.length - 1; i++) {
    const bigram = label.slice(i, i + 2);
    if (/^[a-z]{2}$/.test(bigram)) {
      totalBigrams++;
      if (COMMON_BIGRAMS.has(bigram)) commonBigramCount++;
    }
  }
  const bigramScore = totalBigrams > 0 ? commonBigramCount / totalBigrams : 0;

  // Scoring: combine features into confidence
  let score = 0;

  // High entropy strongly suggests DGA
  if (entropy > 4.0) score += 0.35;
  else if (entropy > 3.5) score += 0.2;
  else if (entropy > 3.0) score += 0.1;

  // Unusual consonant-vowel ratio
  if (consonantVowelRatio > 4) score += 0.2;
  else if (consonantVowelRatio > 3) score += 0.1;

  // High digit density
  if (digitDensity > 0.4) score += 0.2;
  else if (digitDensity > 0.2) score += 0.1;

  // Very long labels
  if (labelLength > 20) score += 0.15;
  else if (labelLength > 15) score += 0.05;

  // Low common bigram frequency
  if (bigramScore < 0.1 && totalBigrams > 3) score += 0.15;
  else if (bigramScore < 0.2 && totalBigrams > 3) score += 0.05;

  // Repeating patterns (some DGAs)
  if (hasRepeatingPattern) score += 0.05;

  // Unusual TLD bonus
  if (!COMMON_TLDS.has(tld)) score += 0.05;

  const confidence = Math.min(0.99, Math.round(score * 100) / 100);

  return {
    isDga: confidence >= 0.5,
    confidence,
    entropy,
    features: {
      consonantVowelRatio: Math.round(consonantVowelRatio * 100) / 100,
      digitDensity: Math.round(digitDensity * 100) / 100,
      labelLength,
      hasRepeatingPattern,
      bigramScore: Math.round(bigramScore * 100) / 100,
    },
  };
}

// ─── DNS Tunneling Detection ─────────────────────────────────────────────────

export interface TunnelingResult {
  isTunneling: boolean;
  confidence: number;
  indicators: {
    avgQueryLength: number;
    queryFrequency: number;
    uniqueSubdomains: number;
    txtRecordRatio: number;
    avgEntropy: number;
  };
}

export async function detectDnsTunneling(
  orgId: string,
  domain: string,
  windowMinutes: number = 60,
): Promise<TunnelingResult> {
  const since = new Date(Date.now() - windowMinutes * 60000);

  const events = await db
    .select({
      queryName: dnsEvents.queryName,
      queryType: dnsEvents.queryType,
      querySize: dnsEvents.querySize,
      responseSize: dnsEvents.responseSize,
      entropy: dnsEvents.entropy,
    })
    .from(dnsEvents)
    .where(
      and(
        eq(dnsEvents.orgId, orgId),
        ilike(dnsEvents.queryName, `%${domain.replace(/%/g, "\\%").replace(/_/g, "\\_")}`),
        gte(dnsEvents.timestamp, since),
      ),
    )
    .limit(5000);

  if (events.length === 0) {
    return {
      isTunneling: false,
      confidence: 0,
      indicators: {
        avgQueryLength: 0,
        queryFrequency: 0,
        uniqueSubdomains: 0,
        txtRecordRatio: 0,
        avgEntropy: 0,
      },
    };
  }

  // Compute indicators
  const uniqueSubdomains = new Set(events.map((e) => e.queryName)).size;
  const avgQueryLength = events.reduce((sum, e) => sum + (e.queryName?.length || 0), 0) / events.length;
  const queryFrequency = events.length / (windowMinutes || 1);
  const txtCount = events.filter((e) => e.queryType === "TXT").length;
  const txtRecordRatio = events.length > 0 ? txtCount / events.length : 0;
  const avgEntropy =
    events.reduce((sum, e) => sum + (e.entropy || computeEntropy(e.queryName || "")), 0) / events.length;

  let score = 0;

  // High query frequency to same base domain
  if (queryFrequency > 10) score += 0.25;
  else if (queryFrequency > 5) score += 0.15;

  // Many unique subdomains (data encoding)
  if (uniqueSubdomains > 50) score += 0.25;
  else if (uniqueSubdomains > 20) score += 0.15;

  // Long query names (encoded data)
  if (avgQueryLength > 50) score += 0.2;
  else if (avgQueryLength > 30) score += 0.1;

  // High TXT record ratio (common in tunneling)
  if (txtRecordRatio > 0.5) score += 0.15;
  else if (txtRecordRatio > 0.2) score += 0.05;

  // High entropy in queries
  if (avgEntropy > 3.5) score += 0.15;
  else if (avgEntropy > 3.0) score += 0.05;

  const confidence = Math.min(0.99, Math.round(score * 100) / 100);

  return {
    isTunneling: confidence >= 0.5,
    confidence,
    indicators: {
      avgQueryLength: Math.round(avgQueryLength),
      queryFrequency: Math.round(queryFrequency * 10) / 10,
      uniqueSubdomains,
      txtRecordRatio: Math.round(txtRecordRatio * 100) / 100,
      avgEntropy: Math.round(avgEntropy * 1000) / 1000,
    },
  };
}

// ─── DNS Exfiltration Detection ──────────────────────────────────────────────

export interface ExfiltrationResult {
  isExfiltration: boolean;
  confidence: number;
  indicators: {
    totalDataEstimateBytes: number;
    queryBurstCount: number;
    encodedSubdomainRatio: number;
    suspiciousDomains: string[];
  };
}

export async function detectDnsExfiltration(
  orgId: string,
  sourceIp: string,
  windowMinutes: number = 60,
): Promise<ExfiltrationResult> {
  const since = new Date(Date.now() - windowMinutes * 60000);

  const events = await db
    .select({
      queryName: dnsEvents.queryName,
      querySize: dnsEvents.querySize,
      timestamp: dnsEvents.timestamp,
    })
    .from(dnsEvents)
    .where(and(eq(dnsEvents.orgId, orgId), eq(dnsEvents.sourceIp, sourceIp), gte(dnsEvents.timestamp, since)))
    .orderBy(dnsEvents.timestamp)
    .limit(10000);

  if (events.length === 0) {
    return {
      isExfiltration: false,
      confidence: 0,
      indicators: {
        totalDataEstimateBytes: 0,
        queryBurstCount: 0,
        encodedSubdomainRatio: 0,
        suspiciousDomains: [],
      },
    };
  }

  // Analyze for exfiltration patterns
  let totalDataBytes = 0;
  let encodedCount = 0;
  const domainCounts: Record<string, number> = {};
  let burstCount = 0;
  let burstWindow: number[] = [];

  for (const event of events) {
    const qname = event.queryName || "";
    const parts = qname.split(".");
    const subdomain = parts.length > 2 ? parts.slice(0, -2).join(".") : parts[0];
    const baseDomain = parts.length > 2 ? parts.slice(-2).join(".") : qname;

    // Check for base64/hex-like subdomains
    if (/^[a-f0-9]{16,}$/i.test(subdomain) || /^[A-Za-z0-9+/=]{20,}$/.test(subdomain)) {
      encodedCount++;
      totalDataBytes += subdomain.length;
    }

    domainCounts[baseDomain] = (domainCounts[baseDomain] || 0) + 1;

    // Burst detection: >20 queries within 5 seconds
    const ts = event.timestamp ? new Date(event.timestamp).getTime() : 0;
    burstWindow = burstWindow.filter((t) => ts - t < 5000);
    burstWindow.push(ts);
    if (burstWindow.length > 20) burstCount++;
  }

  const encodedRatio = events.length > 0 ? encodedCount / events.length : 0;
  const suspiciousDomains = Object.entries(domainCounts)
    .filter(([, cnt]) => cnt > 50)
    .map(([domain]) => domain);

  let score = 0;

  if (encodedRatio > 0.5) score += 0.3;
  else if (encodedRatio > 0.2) score += 0.15;

  if (totalDataBytes > 10000) score += 0.25;
  else if (totalDataBytes > 1000) score += 0.1;

  if (burstCount > 5) score += 0.2;
  else if (burstCount > 0) score += 0.1;

  if (suspiciousDomains.length > 0) score += 0.15;

  if (events.length > 500) score += 0.1;

  const confidence = Math.min(0.99, Math.round(score * 100) / 100);

  return {
    isExfiltration: confidence >= 0.5,
    confidence,
    indicators: {
      totalDataEstimateBytes: totalDataBytes,
      queryBurstCount: burstCount,
      encodedSubdomainRatio: Math.round(encodedRatio * 100) / 100,
      suspiciousDomains,
    },
  };
}

// ─── Newly Registered Domain Detection ───────────────────────────────────────

const NRD_THRESHOLD_DAYS = 30;

export interface NrdResult {
  isNewlyRegistered: boolean;
  domainAgeDays: number | null;
  registrationDate: string | null;
  risk: "high" | "medium" | "low";
}

/**
 * Check if a domain was registered within the last 30 days.
 * In production this would call a WHOIS API; here we use heuristics.
 */
export function checkNewlyRegisteredDomain(domain: string, whoisData?: { creationDate?: string }): NrdResult {
  if (whoisData?.creationDate) {
    const created = new Date(whoisData.creationDate);
    const ageDays = Math.floor((Date.now() - created.getTime()) / 86400000);
    return {
      isNewlyRegistered: ageDays <= NRD_THRESHOLD_DAYS,
      domainAgeDays: ageDays,
      registrationDate: whoisData.creationDate,
      risk: ageDays <= 7 ? "high" : ageDays <= 30 ? "medium" : "low",
    };
  }

  // Heuristic: if domain looks auto-generated and uses newer TLDs, flag it
  const parts = domain.split(".");
  const tld = parts[parts.length - 1];
  const newTlds = new Set(["xyz", "top", "club", "online", "site", "fun", "icu", "buzz", "wang", "live"]);

  if (newTlds.has(tld)) {
    return {
      isNewlyRegistered: true,
      domainAgeDays: null,
      registrationDate: null,
      risk: "medium",
    };
  }

  return {
    isNewlyRegistered: false,
    domainAgeDays: null,
    registrationDate: null,
    risk: "low",
  };
}

// ─── Passive DNS Mapping ─────────────────────────────────────────────────────

export async function upsertPassiveDnsRecord(
  orgId: string,
  domain: string,
  recordType: string,
  resolvedValue: string,
  source?: string,
): Promise<void> {
  const existing = await db
    .select()
    .from(passiveDnsRecords)
    .where(
      and(
        eq(passiveDnsRecords.orgId, orgId),
        eq(passiveDnsRecords.domain, domain),
        eq(passiveDnsRecords.recordType, recordType),
        eq(passiveDnsRecords.resolvedValue, resolvedValue),
      ),
    )
    .limit(1);

  if (existing.length > 0) {
    await db
      .update(passiveDnsRecords)
      .set({
        lastSeen: new Date(),
        queryCount: sql`${passiveDnsRecords.queryCount} + 1`,
      })
      .where(eq(passiveDnsRecords.id, existing[0].id));
  } else {
    await db.insert(passiveDnsRecords).values({
      orgId,
      domain,
      recordType,
      resolvedValue,
      sources: source ? [source] : [],
    });
  }
}

// ─── Analyze Single DNS Event ────────────────────────────────────────────────

export interface DnsAnalysisResult {
  isSuspicious: boolean;
  findings: Array<{
    findingType: string;
    severity: string;
    confidence: number;
    description: string;
    mitreTechnique?: string;
    indicators?: Record<string, unknown>;
  }>;
}

export function analyzeDnsQuery(queryName: string, queryType: string, sourceIp: string): DnsAnalysisResult {
  const findings: DnsAnalysisResult["findings"] = [];

  // Check for DGA
  const dgaResult = detectDga(queryName);
  if (dgaResult.isDga) {
    findings.push({
      findingType: "dga_domain",
      severity: dgaResult.confidence > 0.8 ? "high" : "medium",
      confidence: dgaResult.confidence,
      description: `Potential DGA domain detected: ${queryName} (entropy: ${dgaResult.entropy})`,
      mitreTechnique: "T1568.002",
      indicators: dgaResult.features,
    });
  }

  // Check for high-entropy queries (possible data encoding)
  const entropy = computeEntropy(queryName);
  if (entropy > 4.0 && queryName.length > 30) {
    findings.push({
      findingType: "high_entropy_query",
      severity: "medium",
      confidence: Math.min(0.9, entropy / 5),
      description: `High-entropy DNS query detected from ${sourceIp}: ${queryName.substring(0, 60)}...`,
      mitreTechnique: "T1071.004",
      indicators: { entropy, queryLength: queryName.length },
    });
  }

  // Check for suspicious TXT record queries (common in C2/tunneling)
  if (queryType === "TXT" && queryName.length > 40) {
    findings.push({
      findingType: "suspicious_txt_record",
      severity: "medium",
      confidence: 0.6,
      description: `Suspicious TXT record query from ${sourceIp}: ${queryName.substring(0, 60)}`,
      mitreTechnique: "T1071.004",
    });
  }

  return {
    isSuspicious: findings.length > 0,
    findings,
  };
}

// ─── Sinkhole Check ──────────────────────────────────────────────────────────

export async function checkSinkhole(
  orgId: string,
  domain: string,
): Promise<{ isSinkholed: boolean; sinkhole?: { id: string; reason: string | null } }> {
  const [match] = await db
    .select({ id: sinkholedDomains.id, reason: sinkholedDomains.reason })
    .from(sinkholedDomains)
    .where(
      and(
        eq(sinkholedDomains.orgId, orgId),
        eq(sinkholedDomains.domain, domain),
        eq(sinkholedDomains.status, "active"),
      ),
    )
    .limit(1);

  if (match) {
    // Increment hit counter
    await db
      .update(sinkholedDomains)
      .set({
        hitCount: sql`${sinkholedDomains.hitCount} + 1`,
        lastHitAt: new Date(),
      })
      .where(eq(sinkholedDomains.id, match.id));

    return { isSinkholed: true, sinkhole: match };
  }

  return { isSinkholed: false };
}

// ─── DNS Statistics ──────────────────────────────────────────────────────────

export interface DnsStats {
  totalEvents: number;
  totalFindings: number;
  openFindings: number;
  sinkholedDomainCount: number;
  sinkholedHits: number;
  passiveDnsRecordCount: number;
  eventsByType: Record<string, number>;
  findingsBySeverity: Record<string, number>;
  topQueriedDomains: Array<{ domain: string; count: number }>;
}

export async function computeDnsStats(orgId: string): Promise<DnsStats> {
  try {
    return await computeDnsStatsInternal(orgId);
  } catch (err) {
    const msg = String(err);
    if (msg.includes("does not exist") || msg.includes("relation")) {
      return {
        totalEvents: 0,
        totalFindings: 0,
        openFindings: 0,
        sinkholedDomainCount: 0,
        sinkholedHits: 0,
        passiveDnsRecordCount: 0,
        eventsByType: {},
        findingsBySeverity: {},
        topQueriedDomains: [],
      };
    }
    throw err;
  }
}

async function computeDnsStatsInternal(orgId: string): Promise<DnsStats> {
  const since30d = new Date(Date.now() - 30 * 86400000);

  const [
    [{ value: totalEvents }],
    [{ value: totalFindings }],
    [{ value: openFindings }],
    [{ value: sinkholedCount }],
    [{ value: sinkholedHits }],
    [{ value: passiveCount }],
  ] = await Promise.all([
    db
      .select({ value: count() })
      .from(dnsEvents)
      .where(and(eq(dnsEvents.orgId, orgId), gte(dnsEvents.timestamp, since30d))),
    db.select({ value: count() }).from(dnsFindings).where(eq(dnsFindings.orgId, orgId)),
    db
      .select({ value: count() })
      .from(dnsFindings)
      .where(and(eq(dnsFindings.orgId, orgId), eq(dnsFindings.status, "open"))),
    db
      .select({ value: count() })
      .from(sinkholedDomains)
      .where(and(eq(sinkholedDomains.orgId, orgId), eq(sinkholedDomains.status, "active"))),
    db
      .select({ value: sql<number>`COALESCE(SUM(${sinkholedDomains.hitCount}), 0)` })
      .from(sinkholedDomains)
      .where(eq(sinkholedDomains.orgId, orgId)),
    db.select({ value: count() }).from(passiveDnsRecords).where(eq(passiveDnsRecords.orgId, orgId)),
  ]);

  // Events by type
  const eventsByTypeRows = await db
    .select({ eventType: dnsEvents.eventType, cnt: count() })
    .from(dnsEvents)
    .where(and(eq(dnsEvents.orgId, orgId), gte(dnsEvents.timestamp, since30d)))
    .groupBy(dnsEvents.eventType);

  const eventsByType: Record<string, number> = {};
  for (const row of eventsByTypeRows) {
    eventsByType[row.eventType] = Number(row.cnt);
  }

  // Findings by severity
  const findingsBySevRows = await db
    .select({ severity: dnsFindings.severity, cnt: count() })
    .from(dnsFindings)
    .where(eq(dnsFindings.orgId, orgId))
    .groupBy(dnsFindings.severity);

  const findingsBySeverity: Record<string, number> = {};
  for (const row of findingsBySevRows) {
    findingsBySeverity[row.severity] = Number(row.cnt);
  }

  // Top queried domains
  const topDomains = await db
    .select({ domain: dnsEvents.queryName, cnt: count() })
    .from(dnsEvents)
    .where(and(eq(dnsEvents.orgId, orgId), gte(dnsEvents.timestamp, since30d)))
    .groupBy(dnsEvents.queryName)
    .orderBy(desc(count()))
    .limit(10);

  return {
    totalEvents: Number(totalEvents),
    totalFindings: Number(totalFindings),
    openFindings: Number(openFindings),
    sinkholedDomainCount: Number(sinkholedCount),
    sinkholedHits: Number(sinkholedHits),
    passiveDnsRecordCount: Number(passiveCount),
    eventsByType,
    findingsBySeverity,
    topQueriedDomains: topDomains.map((d) => ({ domain: d.domain, count: Number(d.cnt) })),
  };
}

/**
 * AbuseIPDB Integration — IP Reputation & Abuse Reporting
 * Provides IP reputation checks and abuse confidence scoring
 */

import { logger } from "../routes/shared";

const log = logger.child("abuseipdb");

const ABUSEIPDB_API_BASE = "https://api.abuseipdb.com/api/v2";
const REQUEST_TIMEOUT_MS = 15_000;

// ─── Types ──────────────────────────────────────────────────────────────────

export interface AbuseIpReport {
  ip: string;
  isPublic: boolean;
  ipVersion: number;
  isWhitelisted: boolean;
  abuseConfidenceScore: number;
  countryCode: string | null;
  usageType: string | null;
  isp: string | null;
  domain: string | null;
  totalReports: number;
  numDistinctUsers: number;
  lastReportedAt: string | null;
  isMalicious: boolean;
  categories: number[];
  categoryLabels: string[];
}

export interface AbuseIpCheckResult {
  ip: string;
  source: "abuseipdb";
  isMalicious: boolean;
  confidence: number;
  details: AbuseIpReport | null;
  error?: string;
}

// ─── Category mapping ───────────────────────────────────────────────────────

const ABUSE_CATEGORIES: Record<number, string> = {
  1: "DNS Compromise",
  2: "DNS Poisoning",
  3: "Fraud Orders",
  4: "DDoS Attack",
  5: "FTP Brute-Force",
  6: "Ping of Death",
  7: "Phishing",
  8: "Fraud VoIP",
  9: "Open Proxy",
  10: "Web Spam",
  11: "Email Spam",
  12: "Blog Spam",
  13: "VPN IP",
  14: "Port Scan",
  15: "Hacking",
  16: "SQL Injection",
  17: "Spoofing",
  18: "Brute-Force",
  19: "Bad Web Bot",
  20: "Exploited Host",
  21: "Web App Attack",
  22: "SSH",
  23: "IoT Targeted",
};

// ─── API Client ─────────────────────────────────────────────────────────────

async function abuseipdbFetch(path: string, apiKey: string, params: Record<string, string> = {}): Promise<any> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const searchParams = new URLSearchParams(params);
    const url = `${ABUSEIPDB_API_BASE}${path}?${searchParams.toString()}`;

    const response = await fetch(url, {
      headers: {
        Key: apiKey,
        Accept: "application/json",
      },
      signal: controller.signal,
    });

    if (response.status === 429) {
      log.warn("AbuseIPDB rate limit hit");
      return null;
    }

    if (!response.ok) {
      const errorText = await response.text();
      log.error(`AbuseIPDB API error: ${response.status} ${errorText}`);
      return null;
    }

    return await response.json();
  } catch (err) {
    if ((err as Error).name === "AbortError") {
      log.warn("AbuseIPDB request timed out");
    } else {
      log.error(`AbuseIPDB request failed: ${err}`);
    }
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

// ─── Check IP ───────────────────────────────────────────────────────────────

export async function checkIp(ip: string, apiKey: string, maxAgeInDays: number = 90): Promise<AbuseIpReport | null> {
  if (!apiKey) return null;

  const data = await abuseipdbFetch("/check", apiKey, {
    ipAddress: ip,
    maxAgeInDays: String(maxAgeInDays),
    verbose: "true",
  });

  if (!data?.data) return null;

  const d = data.data;
  const categorySet: Set<number> = d.reports
    ? new Set(d.reports.flatMap((r: { categories: number[] }) => r.categories))
    : new Set<number>();
  const categories: number[] = Array.from(categorySet);

  return {
    ip,
    isPublic: d.isPublic ?? true,
    ipVersion: d.ipVersion ?? 4,
    isWhitelisted: d.isWhitelisted ?? false,
    abuseConfidenceScore: d.abuseConfidenceScore ?? 0,
    countryCode: d.countryCode || null,
    usageType: d.usageType || null,
    isp: d.isp || null,
    domain: d.domain || null,
    totalReports: d.totalReports ?? 0,
    numDistinctUsers: d.numDistinctUsers ?? 0,
    lastReportedAt: d.lastReportedAt || null,
    isMalicious: (d.abuseConfidenceScore ?? 0) >= 50,
    categories,
    categoryLabels: categories.map((c) => ABUSE_CATEGORIES[c]).filter((l): l is string => !!l),
  };
}

// ─── Check IP with result wrapper ───────────────────────────────────────────

export async function checkIpReputation(ip: string, apiKey: string): Promise<AbuseIpCheckResult> {
  try {
    const report = await checkIp(ip, apiKey);
    return {
      ip,
      source: "abuseipdb",
      isMalicious: report?.isMalicious ?? false,
      confidence: report?.abuseConfidenceScore ?? 0,
      details: report,
    };
  } catch (err) {
    log.error(`AbuseIPDB check failed for ${ip}: ${err}`);
    return {
      ip,
      source: "abuseipdb",
      isMalicious: false,
      confidence: 0,
      details: null,
      error: String(err),
    };
  }
}

// ─── Batch check multiple IPs ───────────────────────────────────────────────

export async function checkIpBatch(ips: string[], apiKey: string): Promise<AbuseIpCheckResult[]> {
  if (!apiKey || ips.length === 0) return [];

  // AbuseIPDB has rate limits, so we process sequentially with small delays
  const results: AbuseIpCheckResult[] = [];
  for (const ip of ips.slice(0, 50)) {
    // Cap at 50 to avoid rate limits
    const result = await checkIpReputation(ip, apiKey);
    results.push(result);
    // Small delay between requests to respect rate limits
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  return results;
}

// ─── Report an abusive IP ───────────────────────────────────────────────────

export async function reportIp(ip: string, apiKey: string, categories: number[], comment: string): Promise<boolean> {
  if (!apiKey) return false;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const response = await fetch(`${ABUSEIPDB_API_BASE}/report`, {
      method: "POST",
      headers: {
        Key: apiKey,
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        ip,
        categories: categories.join(","),
        comment: comment.slice(0, 1024), // Max 1024 chars
      }),
      signal: controller.signal,
    });

    if (!response.ok) {
      log.error(`AbuseIPDB report failed: ${response.status}`);
      return false;
    }

    log.info(`Reported abusive IP to AbuseIPDB: ${ip}`);
    return true;
  } catch (err) {
    log.error(`AbuseIPDB report request failed: ${err}`);
    return false;
  } finally {
    clearTimeout(timeout);
  }
}

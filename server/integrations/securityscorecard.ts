/**
 * SecurityScorecard / BitSight API Integration
 *
 * Fetches vendor risk scores, attack surface data, and breach intelligence
 * from external rating services.
 */

import { logger } from "../logger";
import { validateWebhookUrl } from "../outbound-security";

const log = logger.child("securityscorecard");

// ── Types ─────────────────────────────────────────────────────────

export interface VendorScoreResult {
  domain: string;
  overallScore: number;
  factors: Record<string, number>;
  breachesDetected: number;
  lastUpdated: string;
  grade: string;
  provider: string;
}

export interface BreachIntelResult {
  domain: string;
  breaches: Array<{
    title: string;
    date: string;
    source: string;
    severity: string;
    description: string;
    sourceUrl?: string;
    affectedRecords?: number;
  }>;
}

// ── SecurityScorecard Client ──────────────────────────────────────

const SSC_API_BASE = "https://api.securityscorecard.io";

async function sscFetch<T>(path: string, apiKey: string): Promise<T | null> {
  const url = `${SSC_API_BASE}${path}`;
  const urlCheck = validateWebhookUrl(url);
  if (!urlCheck.valid) {
    log.warn("SecurityScorecard URL validation failed", { path, reason: urlCheck.reason });
    return null;
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 20_000);

    const response = await fetch(url, {
      headers: {
        Authorization: `Token ${apiKey}`,
        Accept: "application/json",
      },
      signal: controller.signal,
    });
    clearTimeout(timeout);

    if (!response.ok) {
      log.warn("SecurityScorecard API error", { path, status: response.status });
      return null;
    }

    return (await response.json()) as T;
  } catch (err) {
    log.error("SecurityScorecard API request failed", { path, error: String(err) });
    return null;
  }
}

function sscGradeFromScore(score: number): string {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}

/**
 * Fetch vendor risk score from SecurityScorecard.
 */
export async function fetchSecurityScorecardScore(domain: string, apiKey: string): Promise<VendorScoreResult | null> {
  interface SSCScorecard {
    domain: string;
    score: number;
    last_score_change_date: string;
    factors: Array<{ name: string; score: number }>;
    size: string;
    industry: string;
  }

  const data = await sscFetch<SSCScorecard>(`/companies/${encodeURIComponent(domain)}`, apiKey);
  if (!data) return null;

  const factors: Record<string, number> = {};
  if (data.factors) {
    for (const f of data.factors) {
      factors[f.name] = f.score;
    }
  }

  return {
    domain: data.domain || domain,
    overallScore: data.score || 0,
    factors,
    breachesDetected: 0,
    lastUpdated: data.last_score_change_date || new Date().toISOString(),
    grade: sscGradeFromScore(data.score || 0),
    provider: "securityscorecard",
  };
}

/**
 * Fetch breach intelligence from SecurityScorecard.
 */
export async function fetchSecurityScorecardBreaches(
  domain: string,
  apiKey: string,
): Promise<BreachIntelResult | null> {
  interface SSCBreach {
    title: string;
    date: string;
    description: string;
    records_exposed: number;
  }

  interface SSCBreachesResponse {
    entries: SSCBreach[];
  }

  const data = await sscFetch<SSCBreachesResponse>(`/companies/${encodeURIComponent(domain)}/history/breaches`, apiKey);
  if (!data) return null;

  return {
    domain,
    breaches: (data.entries || []).map((b) => ({
      title: b.title || "Unknown breach",
      date: b.date || new Date().toISOString(),
      source: "securityscorecard",
      severity: b.records_exposed > 100000 ? "critical" : b.records_exposed > 10000 ? "high" : "medium",
      description: b.description || "",
      affectedRecords: b.records_exposed,
    })),
  };
}

// ── BitSight Client ───────────────────────────────────────────────

const BITSIGHT_API_BASE = "https://api.bitsighttech.com/ratings/v1";

async function bitsightFetch<T>(path: string, apiKey: string): Promise<T | null> {
  const url = `${BITSIGHT_API_BASE}${path}`;
  const urlCheck = validateWebhookUrl(url);
  if (!urlCheck.valid) {
    log.warn("BitSight URL validation failed", { path, reason: urlCheck.reason });
    return null;
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 20_000);

    const response = await fetch(url, {
      headers: {
        Authorization: `Basic ${Buffer.from(`${apiKey}:`).toString("base64")}`,
        Accept: "application/json",
      },
      signal: controller.signal,
    });
    clearTimeout(timeout);

    if (!response.ok) {
      log.warn("BitSight API error", { path, status: response.status });
      return null;
    }

    return (await response.json()) as T;
  } catch (err) {
    log.error("BitSight API request failed", { path, error: String(err) });
    return null;
  }
}

function bitsightGradeFromRating(rating: number): string {
  if (rating >= 740) return "A";
  if (rating >= 640) return "B";
  if (rating >= 540) return "C";
  if (rating >= 440) return "D";
  return "F";
}

/**
 * Fetch vendor risk score from BitSight.
 */
export async function fetchBitSightScore(domain: string, apiKey: string): Promise<VendorScoreResult | null> {
  interface BSCompany {
    guid: string;
    custom_id: string;
    name: string;
    rating: number;
    rating_date: string;
    rating_details: Array<{ name: string; rating: number }>;
  }

  interface BSSearchResult {
    results: BSCompany[];
  }

  // Search by domain first
  const search = await bitsightFetch<BSSearchResult>(`/companies?domain=${encodeURIComponent(domain)}`, apiKey);
  if (!search || !search.results || search.results.length === 0) return null;

  const company = search.results[0];
  const factors: Record<string, number> = {};
  if (company.rating_details) {
    for (const d of company.rating_details) {
      factors[d.name] = d.rating;
    }
  }

  // Normalize BitSight 250-900 scale to 0-100
  const normalizedScore = Math.round(((company.rating - 250) / 650) * 100);

  return {
    domain,
    overallScore: Math.max(0, Math.min(100, normalizedScore)),
    factors,
    breachesDetected: 0,
    lastUpdated: company.rating_date || new Date().toISOString(),
    grade: bitsightGradeFromRating(company.rating),
    provider: "bitsight",
  };
}

// ── Unified Interface ─────────────────────────────────────────────

/**
 * Fetch vendor score from available provider.
 * Tries SecurityScorecard first, falls back to BitSight.
 */
export async function fetchVendorRiskScore(
  domain: string,
  config: {
    securityScorecardApiKey?: string;
    bitSightApiKey?: string;
  },
): Promise<VendorScoreResult | null> {
  if (config.securityScorecardApiKey) {
    const result = await fetchSecurityScorecardScore(domain, config.securityScorecardApiKey);
    if (result) return result;
  }

  if (config.bitSightApiKey) {
    const result = await fetchBitSightScore(domain, config.bitSightApiKey);
    if (result) return result;
  }

  log.debug("No vendor risk score provider configured or both failed", { domain });
  return null;
}

/**
 * Fetch breach intelligence from available provider.
 */
export async function fetchVendorBreaches(
  domain: string,
  config: {
    securityScorecardApiKey?: string;
  },
): Promise<BreachIntelResult | null> {
  if (config.securityScorecardApiKey) {
    return fetchSecurityScorecardBreaches(domain, config.securityScorecardApiKey);
  }

  return null;
}

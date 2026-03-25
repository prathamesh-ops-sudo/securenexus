/**
 * VirusTotal Integration — Threat Intelligence Enrichment
 * Provides IOC lookups for IPs, domains, URLs, and file hashes
 */

import { logger } from "../routes/shared";

const log = logger.child("virustotal");

const VT_API_BASE = "https://www.virustotal.com/api/v3";
const REQUEST_TIMEOUT_MS = 15_000;

// ─── Types ──────────────────────────────────────────────────────────────────

export interface VTIpReport {
  ip: string;
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  reputation: number;
  country: string | null;
  asOwner: string | null;
  asn: number | null;
  lastAnalysisDate: string | null;
  isMalicious: boolean;
  confidence: number;
}

export interface VTDomainReport {
  domain: string;
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  reputation: number;
  registrar: string | null;
  creationDate: string | null;
  lastAnalysisDate: string | null;
  isMalicious: boolean;
  confidence: number;
  categories: Record<string, string>;
}

export interface VTFileReport {
  hash: string;
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  reputation: number;
  meaningfulName: string | null;
  fileType: string | null;
  fileSize: number | null;
  lastAnalysisDate: string | null;
  isMalicious: boolean;
  confidence: number;
  tags: string[];
}

export interface VTUrlReport {
  url: string;
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  lastAnalysisDate: string | null;
  isMalicious: boolean;
  confidence: number;
  categories: Record<string, string>;
  finalUrl: string | null;
}

// ─── API Client ─────────────────────────────────────────────────────────────

async function vtFetch(path: string, apiKey: string): Promise<any> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const response = await fetch(`${VT_API_BASE}${path}`, {
      headers: {
        "x-apikey": apiKey,
        Accept: "application/json",
      },
      signal: controller.signal,
    });

    if (response.status === 404) {
      return null; // Not found — not an error
    }

    if (response.status === 429) {
      log.warn("VirusTotal rate limit hit");
      return null;
    }

    if (!response.ok) {
      const errorText = await response.text();
      log.error(`VirusTotal API error: ${response.status} ${errorText}`);
      return null;
    }

    return await response.json();
  } catch (err) {
    if ((err as Error).name === "AbortError") {
      log.warn("VirusTotal request timed out");
    } else {
      log.error(`VirusTotal request failed: ${err}`);
    }
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

// ─── IP Lookup ──────────────────────────────────────────────────────────────

export async function lookupIp(ip: string, apiKey: string): Promise<VTIpReport | null> {
  if (!apiKey) return null;

  const data = await vtFetch(`/ip_addresses/${encodeURIComponent(ip)}`, apiKey);
  if (!data?.data?.attributes) return null;

  const attrs = data.data.attributes;
  const stats = attrs.last_analysis_stats || {};
  const malicious = stats.malicious || 0;
  const suspicious = stats.suspicious || 0;
  const total = malicious + suspicious + (stats.harmless || 0) + (stats.undetected || 0);

  return {
    ip,
    malicious,
    suspicious,
    harmless: stats.harmless || 0,
    undetected: stats.undetected || 0,
    reputation: attrs.reputation || 0,
    country: attrs.country || null,
    asOwner: attrs.as_owner || null,
    asn: attrs.asn || null,
    lastAnalysisDate: attrs.last_analysis_date ? new Date(attrs.last_analysis_date * 1000).toISOString() : null,
    isMalicious: malicious >= 3 || (total > 0 && malicious / total > 0.1),
    confidence: total > 0 ? Math.round(((malicious + suspicious) / total) * 100) : 0,
  };
}

// ─── Domain Lookup ──────────────────────────────────────────────────────────

export async function lookupDomain(domain: string, apiKey: string): Promise<VTDomainReport | null> {
  if (!apiKey) return null;

  const data = await vtFetch(`/domains/${encodeURIComponent(domain)}`, apiKey);
  if (!data?.data?.attributes) return null;

  const attrs = data.data.attributes;
  const stats = attrs.last_analysis_stats || {};
  const malicious = stats.malicious || 0;
  const suspicious = stats.suspicious || 0;
  const total = malicious + suspicious + (stats.harmless || 0) + (stats.undetected || 0);

  return {
    domain,
    malicious,
    suspicious,
    harmless: stats.harmless || 0,
    undetected: stats.undetected || 0,
    reputation: attrs.reputation || 0,
    registrar: attrs.registrar || null,
    creationDate: attrs.creation_date ? new Date(attrs.creation_date * 1000).toISOString() : null,
    lastAnalysisDate: attrs.last_analysis_date ? new Date(attrs.last_analysis_date * 1000).toISOString() : null,
    isMalicious: malicious >= 3 || (total > 0 && malicious / total > 0.1),
    confidence: total > 0 ? Math.round(((malicious + suspicious) / total) * 100) : 0,
    categories: attrs.categories || {},
  };
}

// ─── File/Hash Lookup ───────────────────────────────────────────────────────

export async function lookupFileHash(hash: string, apiKey: string): Promise<VTFileReport | null> {
  if (!apiKey) return null;

  const data = await vtFetch(`/files/${encodeURIComponent(hash)}`, apiKey);
  if (!data?.data?.attributes) return null;

  const attrs = data.data.attributes;
  const stats = attrs.last_analysis_stats || {};
  const malicious = stats.malicious || 0;
  const suspicious = stats.suspicious || 0;
  const total = malicious + suspicious + (stats.harmless || 0) + (stats.undetected || 0);

  return {
    hash,
    malicious,
    suspicious,
    harmless: stats.harmless || 0,
    undetected: stats.undetected || 0,
    reputation: attrs.reputation || 0,
    meaningfulName: attrs.meaningful_name || null,
    fileType: attrs.type_description || null,
    fileSize: attrs.size || null,
    lastAnalysisDate: attrs.last_analysis_date ? new Date(attrs.last_analysis_date * 1000).toISOString() : null,
    isMalicious: malicious >= 5 || (total > 0 && malicious / total > 0.15),
    confidence: total > 0 ? Math.round(((malicious + suspicious) / total) * 100) : 0,
    tags: attrs.tags || [],
  };
}

// ─── URL Lookup ─────────────────────────────────────────────────────────────

export async function lookupUrl(url: string, apiKey: string): Promise<VTUrlReport | null> {
  if (!apiKey) return null;

  // VT URL lookup requires base64-encoded URL without padding
  const urlId = Buffer.from(url).toString("base64").replace(/=+$/, "");
  const data = await vtFetch(`/urls/${urlId}`, apiKey);
  if (!data?.data?.attributes) return null;

  const attrs = data.data.attributes;
  const stats = attrs.last_analysis_stats || {};
  const malicious = stats.malicious || 0;
  const suspicious = stats.suspicious || 0;
  const total = malicious + suspicious + (stats.harmless || 0) + (stats.undetected || 0);

  return {
    url,
    malicious,
    suspicious,
    harmless: stats.harmless || 0,
    undetected: stats.undetected || 0,
    lastAnalysisDate: attrs.last_analysis_date ? new Date(attrs.last_analysis_date * 1000).toISOString() : null,
    isMalicious: malicious >= 3 || (total > 0 && malicious / total > 0.1),
    confidence: total > 0 ? Math.round(((malicious + suspicious) / total) * 100) : 0,
    categories: attrs.categories || {},
    finalUrl: attrs.last_final_url || null,
  };
}

// ─── Unified Enrichment ─────────────────────────────────────────────────────

export type IocType = "ip" | "domain" | "hash" | "url";

export interface EnrichmentResult {
  iocType: IocType;
  iocValue: string;
  source: "virustotal";
  isMalicious: boolean;
  confidence: number;
  details: VTIpReport | VTDomainReport | VTFileReport | VTUrlReport | null;
  error?: string;
}

export async function enrichIoc(iocType: IocType, iocValue: string, apiKey: string): Promise<EnrichmentResult> {
  try {
    let details: VTIpReport | VTDomainReport | VTFileReport | VTUrlReport | null = null;

    switch (iocType) {
      case "ip":
        details = await lookupIp(iocValue, apiKey);
        break;
      case "domain":
        details = await lookupDomain(iocValue, apiKey);
        break;
      case "hash":
        details = await lookupFileHash(iocValue, apiKey);
        break;
      case "url":
        details = await lookupUrl(iocValue, apiKey);
        break;
    }

    return {
      iocType,
      iocValue,
      source: "virustotal",
      isMalicious: details?.isMalicious ?? false,
      confidence: details?.confidence ?? 0,
      details,
    };
  } catch (err) {
    log.error(`IOC enrichment failed for ${iocType}:${iocValue}: ${err}`);
    return {
      iocType,
      iocValue,
      source: "virustotal",
      isMalicious: false,
      confidence: 0,
      details: null,
      error: String(err),
    };
  }
}

export interface OsintIndicator {
  type: "ip" | "domain" | "url" | "hash" | "cve";
  value: string;
  threat: string;
  source: string;
  firstSeen?: string;
  tags: string[];
  confidence: number;
}

export interface OsintFeedResult {
  feedName: string;
  feedUrl: string;
  lastFetched: string;
  totalIndicators: number;
  indicators: OsintIndicator[];
  status: "success" | "error" | "stale";
  errorMessage?: string;
}

export interface FeedStatus {
  name: string;
  slug: string;
  url: string;
  lastFetched: string | null;
  totalIndicators: number;
  status: "success" | "error" | "never_fetched";
  requiresApiKey: false;
}

interface FeedDefinition {
  name: string;
  slug: string;
  url: string;
  fetcher: () => Promise<OsintFeedResult>;
}

const feedCache = new Map<string, { data: OsintFeedResult; fetchedAt: number }>();
const FEED_TTL_MS = 60 * 60 * 1000;
const FETCH_TIMEOUT_MS = 10_000;
const MAX_INDICATORS = 100;

function makeAbortSignal(): AbortSignal {
  const controller = new AbortController();
  setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  return controller.signal;
}

function errorResult(feedName: string, feedUrl: string, message: string): OsintFeedResult {
  return {
    feedName,
    feedUrl,
    lastFetched: new Date().toISOString(),
    totalIndicators: 0,
    indicators: [],
    status: "error",
    errorMessage: message,
  };
}

async function fetchUrlhausFeed(): Promise<OsintFeedResult> {
  const feedName = "abuse.ch URLhaus";
  const feedUrl = "https://urlhaus-api.abuse.ch/v1/urls/recent/";
  try {
    const resp = await fetch(feedUrl, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      signal: makeAbortSignal(),
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const json = await resp.json() as any;
    const urls: any[] = Array.isArray(json.urls) ? json.urls : [];
    const indicators: OsintIndicator[] = urls.slice(0, 50).map((entry: any) => ({
      type: "url" as const,
      value: entry.url || "",
      threat: entry.threat || entry.url_status || "malicious_url",
      source: feedName,
      firstSeen: entry.dateadded || undefined,
      tags: [
        entry.url_status,
        entry.threat,
        ...(Array.isArray(entry.tags) ? entry.tags : entry.tags ? [entry.tags] : []),
      ].filter(Boolean) as string[],
      confidence: entry.url_status === "online" ? 0.9 : 0.6,
    })).slice(0, MAX_INDICATORS);
    return {
      feedName,
      feedUrl,
      lastFetched: new Date().toISOString(),
      totalIndicators: urls.length,
      indicators,
      status: "success",
    };
  } catch (err: any) {
    return errorResult(feedName, feedUrl, err.message || "Unknown error");
  }
}

async function fetchThreatFoxFeed(): Promise<OsintFeedResult> {
  const feedName = "abuse.ch ThreatFox";
  const feedUrl = "https://threatfox-api.abuse.ch/api/v1/";
  try {
    const resp = await fetch(feedUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query: "get_iocs", days: 1 }),
      signal: makeAbortSignal(),
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const json = await resp.json() as any;
    const iocs: any[] = Array.isArray(json.data) ? json.data : [];

    const mapIocType = (iocType: string): OsintIndicator["type"] => {
      if (iocType === "ip:port" || iocType === "ip") return "ip";
      if (iocType === "domain") return "domain";
      if (iocType === "url") return "url";
      if (iocType === "md5_hash" || iocType === "sha256_hash" || iocType === "sha1_hash") return "hash";
      return "url";
    };

    const indicators: OsintIndicator[] = iocs.slice(0, 50).map((ioc: any) => ({
      type: mapIocType(ioc.ioc_type || ""),
      value: ioc.ioc || "",
      threat: ioc.malware || ioc.threat_type || "unknown",
      source: feedName,
      firstSeen: ioc.first_seen_utc || undefined,
      tags: [
        ioc.threat_type,
        ioc.malware,
        ioc.malware_alias,
        ...(Array.isArray(ioc.tags) ? ioc.tags : ioc.tags ? [ioc.tags] : []),
      ].filter(Boolean) as string[],
      confidence: ioc.confidence_level != null ? Math.min(ioc.confidence_level / 100, 1) : 0.7,
    })).slice(0, MAX_INDICATORS);

    return {
      feedName,
      feedUrl,
      lastFetched: new Date().toISOString(),
      totalIndicators: iocs.length,
      indicators,
      status: "success",
    };
  } catch (err: any) {
    return errorResult(feedName, feedUrl, err.message || "Unknown error");
  }
}

async function fetchSSLBlacklistFeed(): Promise<OsintFeedResult> {
  const feedName = "abuse.ch SSL Blacklist";
  const feedUrl = "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv";
  try {
    const resp = await fetch(feedUrl, { signal: makeAbortSignal() });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const text = await resp.text();
    const lines = text.split("\n").filter((l) => l.trim() && !l.startsWith("#"));
    const indicators: OsintIndicator[] = lines.slice(0, MAX_INDICATORS).map((line) => {
      const cols = line.split(",");
      const dateAdded = cols[0]?.trim() || undefined;
      const ip = cols[1]?.trim() || "";
      const port = cols[2]?.trim() || "";
      const reason = cols[3]?.trim() || "botnet_cc";
      return {
        type: "ip" as const,
        value: port ? `${ip}:${port}` : ip,
        threat: reason,
        source: feedName,
        firstSeen: dateAdded,
        tags: ["botnet", "c2", reason].filter(Boolean),
        confidence: 0.85,
      };
    });
    return {
      feedName,
      feedUrl,
      lastFetched: new Date().toISOString(),
      totalIndicators: lines.length,
      indicators,
      status: "success",
    };
  } catch (err: any) {
    return errorResult(feedName, feedUrl, err.message || "Unknown error");
  }
}

async function fetchCISAKevFeed(): Promise<OsintFeedResult> {
  const feedName = "CISA Known Exploited Vulnerabilities";
  const feedUrl = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
  try {
    const resp = await fetch(feedUrl, { signal: makeAbortSignal() });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const json = await resp.json() as any;
    const vulns: any[] = Array.isArray(json.vulnerabilities) ? json.vulnerabilities : [];
    const indicators: OsintIndicator[] = vulns.slice(0, MAX_INDICATORS).map((v: any) => ({
      type: "cve" as const,
      value: v.cveID || "",
      threat: v.shortDescription || v.vulnerabilityName || "known_exploited",
      source: feedName,
      firstSeen: v.dateAdded || undefined,
      tags: [
        v.vendorProject,
        v.product,
        v.knownRansomwareCampaignUse === "Known" ? "ransomware" : null,
      ].filter(Boolean) as string[],
      confidence: 0.95,
    }));
    return {
      feedName,
      feedUrl,
      lastFetched: new Date().toISOString(),
      totalIndicators: vulns.length,
      indicators,
      status: "success",
    };
  } catch (err: any) {
    return errorResult(feedName, feedUrl, err.message || "Unknown error");
  }
}

const FEED_DEFINITIONS: FeedDefinition[] = [
  { name: "abuse.ch URLhaus", slug: "urlhaus", url: "https://urlhaus-api.abuse.ch/v1/urls/recent/", fetcher: fetchUrlhausFeed },
  { name: "abuse.ch ThreatFox", slug: "threatfox", url: "https://threatfox-api.abuse.ch/api/v1/", fetcher: fetchThreatFoxFeed },
  { name: "abuse.ch SSL Blacklist", slug: "sslbl", url: "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv", fetcher: fetchSSLBlacklistFeed },
  { name: "CISA Known Exploited Vulnerabilities", slug: "cisa_kev", url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", fetcher: fetchCISAKevFeed },
];

export async function fetchOsintFeed(feedNameOrSlug: string, force?: boolean): Promise<OsintFeedResult> {
  const def = FEED_DEFINITIONS.find((f) => f.name === feedNameOrSlug || f.slug === feedNameOrSlug);
  if (!def) {
    return errorResult(feedNameOrSlug, "", `Unknown feed: ${feedNameOrSlug}`);
  }
  const feedName = def.name;

  if (!force) {
    const cached = feedCache.get(feedName);
    if (cached && Date.now() - cached.fetchedAt < FEED_TTL_MS) {
      return cached.data;
    }
  }

  const result = await def.fetcher();
  feedCache.set(feedName, { data: result, fetchedAt: Date.now() });
  return result;
}

export async function fetchAllOsintFeeds(force?: boolean): Promise<OsintFeedResult[]> {
  const promises = FEED_DEFINITIONS.map((def) => fetchOsintFeed(def.name, force));
  return Promise.all(promises);
}

export function getCachedOsintIndicators(): OsintIndicator[] {
  const all: OsintIndicator[] = [];
  for (const [, cached] of Array.from(feedCache)) {
    if (cached.data.status === "success") {
      all.push(...cached.data.indicators);
    }
  }
  return all;
}

export function getOsintFeedStatuses(): FeedStatus[] {
  return FEED_DEFINITIONS.map((def) => {
    const cached = feedCache.get(def.name);
    return {
      name: def.name,
      slug: def.slug,
      url: def.url,
      lastFetched: cached ? cached.data.lastFetched : null,
      totalIndicators: cached ? cached.data.totalIndicators : 0,
      status: cached
        ? (cached.data.status === "error" ? "error" : "success")
        : "never_fetched",
      requiresApiKey: false as const,
    };
  });
}

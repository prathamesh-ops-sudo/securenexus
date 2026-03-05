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
  responseTimeMs?: number;
}

export interface FeedHealthEntry {
  timestamp: string;
  status: "success" | "error";
  indicatorCount: number;
  responseTimeMs: number;
  errorMessage?: string;
}

export interface FeedSubscription {
  slug: string;
  enabled: boolean;
  refreshIntervalMinutes: number;
}

export interface FeedStatus {
  name: string;
  slug: string;
  url: string;
  description: string;
  category: string;
  indicatorTypes: string[];
  lastFetched: string | null;
  lastSuccess: string | null;
  lastError: string | null;
  lastErrorMessage: string | null;
  totalIndicators: number;
  status: "success" | "error" | "never_fetched";
  enabled: boolean;
  refreshIntervalMinutes: number;
  successRate: number;
  avgResponseTimeMs: number;
  totalFetches: number;
  consecutiveErrors: number;
  requiresApiKey: false;
}

interface FeedDefinition {
  name: string;
  slug: string;
  url: string;
  description: string;
  category: string;
  indicatorTypes: string[];
  fetcher: () => Promise<OsintFeedResult>;
}

const feedCache = new Map<string, { data: OsintFeedResult; fetchedAt: number }>();
const feedHealthHistory = new Map<string, FeedHealthEntry[]>();
const feedSubscriptions = new Map<string, FeedSubscription>();
const FEED_TTL_MS = 60 * 60 * 1000;
const FETCH_TIMEOUT_MS = 10_000;
const MAX_INDICATORS = 100;
const MAX_HEALTH_ENTRIES = 50;
const VALID_SLUGS = new Set(["urlhaus", "threatfox", "sslbl", "cisa_kev"]);

function isValidSlug(slug: string): boolean {
  return VALID_SLUGS.has(slug);
}

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
    responseTimeMs: 0,
  };
}

function recordHealth(slug: string, entry: FeedHealthEntry): void {
  const history = feedHealthHistory.get(slug) || [];
  history.unshift(entry);
  if (history.length > MAX_HEALTH_ENTRIES) {
    history.length = MAX_HEALTH_ENTRIES;
  }
  feedHealthHistory.set(slug, history);
}

async function fetchUrlhausFeed(): Promise<OsintFeedResult> {
  const feedName = "abuse.ch URLhaus";
  const feedUrl = "https://urlhaus-api.abuse.ch/v1/urls/recent/";
  const startTime = Date.now();
  try {
    const resp = await fetch(feedUrl, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      signal: makeAbortSignal(),
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const json = (await resp.json()) as any;
    const urls: any[] = Array.isArray(json.urls) ? json.urls : [];
    const indicators: OsintIndicator[] = urls
      .slice(0, 50)
      .map((entry: any) => ({
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
      }))
      .slice(0, MAX_INDICATORS);
    return {
      feedName,
      feedUrl,
      lastFetched: new Date().toISOString(),
      totalIndicators: urls.length,
      indicators,
      status: "success",
      responseTimeMs: Date.now() - startTime,
    };
  } catch (err: any) {
    return {
      ...errorResult(feedName, feedUrl, err.message || "Unknown error"),
      responseTimeMs: Date.now() - startTime,
    };
  }
}

async function fetchThreatFoxFeed(): Promise<OsintFeedResult> {
  const feedName = "abuse.ch ThreatFox";
  const feedUrl = "https://threatfox-api.abuse.ch/api/v1/";
  const startTime = Date.now();
  try {
    const resp = await fetch(feedUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query: "get_iocs", days: 1 }),
      signal: makeAbortSignal(),
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const json = (await resp.json()) as any;
    const iocs: any[] = Array.isArray(json.data) ? json.data : [];

    const mapIocType = (iocType: string): OsintIndicator["type"] => {
      if (iocType === "ip:port" || iocType === "ip") return "ip";
      if (iocType === "domain") return "domain";
      if (iocType === "url") return "url";
      if (iocType === "md5_hash" || iocType === "sha256_hash" || iocType === "sha1_hash") return "hash";
      return "url";
    };

    const indicators: OsintIndicator[] = iocs
      .slice(0, 50)
      .map((ioc: any) => ({
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
      }))
      .slice(0, MAX_INDICATORS);

    return {
      feedName,
      feedUrl,
      lastFetched: new Date().toISOString(),
      totalIndicators: iocs.length,
      indicators,
      status: "success",
      responseTimeMs: Date.now() - startTime,
    };
  } catch (err: any) {
    return {
      ...errorResult(feedName, feedUrl, err.message || "Unknown error"),
      responseTimeMs: Date.now() - startTime,
    };
  }
}

async function fetchSSLBlacklistFeed(): Promise<OsintFeedResult> {
  const feedName = "abuse.ch SSL Blacklist";
  const feedUrl = "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv";
  const startTime = Date.now();
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
      responseTimeMs: Date.now() - startTime,
    };
  } catch (err: any) {
    return {
      ...errorResult(feedName, feedUrl, err.message || "Unknown error"),
      responseTimeMs: Date.now() - startTime,
    };
  }
}

async function fetchCISAKevFeed(): Promise<OsintFeedResult> {
  const feedName = "CISA Known Exploited Vulnerabilities";
  const feedUrl = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
  const startTime = Date.now();
  try {
    const resp = await fetch(feedUrl, { signal: makeAbortSignal() });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const json = (await resp.json()) as any;
    const vulns: any[] = Array.isArray(json.vulnerabilities) ? json.vulnerabilities : [];
    const indicators: OsintIndicator[] = vulns.slice(0, MAX_INDICATORS).map((v: any) => ({
      type: "cve" as const,
      value: v.cveID || "",
      threat: v.shortDescription || v.vulnerabilityName || "known_exploited",
      source: feedName,
      firstSeen: v.dateAdded || undefined,
      tags: [v.vendorProject, v.product, v.knownRansomwareCampaignUse === "Known" ? "ransomware" : null].filter(
        Boolean,
      ) as string[],
      confidence: 0.95,
    }));
    return {
      feedName,
      feedUrl,
      lastFetched: new Date().toISOString(),
      totalIndicators: vulns.length,
      indicators,
      status: "success",
      responseTimeMs: Date.now() - startTime,
    };
  } catch (err: any) {
    return {
      ...errorResult(feedName, feedUrl, err.message || "Unknown error"),
      responseTimeMs: Date.now() - startTime,
    };
  }
}

const FEED_DEFINITIONS: FeedDefinition[] = [
  {
    name: "abuse.ch URLhaus",
    slug: "urlhaus",
    url: "https://urlhaus-api.abuse.ch/v1/urls/recent/",
    description: "Real-time database of malicious URLs used for malware distribution",
    category: "Malware",
    indicatorTypes: ["url"],
    fetcher: fetchUrlhausFeed,
  },
  {
    name: "abuse.ch ThreatFox",
    slug: "threatfox",
    url: "https://threatfox-api.abuse.ch/api/v1/",
    description: "IOC sharing platform for malware, botnet C2, and other threats",
    category: "IOC Sharing",
    indicatorTypes: ["ip", "domain", "url", "hash"],
    fetcher: fetchThreatFoxFeed,
  },
  {
    name: "abuse.ch SSL Blacklist",
    slug: "sslbl",
    url: "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv",
    description: "IP addresses associated with botnet C2 servers identified via SSL certificates",
    category: "Botnet C2",
    indicatorTypes: ["ip"],
    fetcher: fetchSSLBlacklistFeed,
  },
  {
    name: "CISA Known Exploited Vulnerabilities",
    slug: "cisa_kev",
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    description: "Authoritative catalog of vulnerabilities known to be actively exploited in the wild",
    category: "Vulnerability",
    indicatorTypes: ["cve"],
    fetcher: fetchCISAKevFeed,
  },
];

function initSubscriptions(): void {
  for (const def of FEED_DEFINITIONS) {
    if (!feedSubscriptions.has(def.slug)) {
      feedSubscriptions.set(def.slug, {
        slug: def.slug,
        enabled: true,
        refreshIntervalMinutes: 60,
      });
    }
  }
}

initSubscriptions();

export function getFeedSubscription(slug: string): FeedSubscription | undefined {
  if (!isValidSlug(slug)) return undefined;
  return feedSubscriptions.get(slug);
}

export function updateFeedSubscription(
  slug: string,
  updates: Partial<Pick<FeedSubscription, "enabled" | "refreshIntervalMinutes">>,
): FeedSubscription | null {
  if (!isValidSlug(slug)) return null;
  const def = FEED_DEFINITIONS.find((f) => f.slug === slug);
  if (!def) return null;
  const existing = feedSubscriptions.get(slug) || { slug, enabled: true, refreshIntervalMinutes: 60 };
  if (updates.enabled !== undefined) existing.enabled = updates.enabled;
  if (updates.refreshIntervalMinutes !== undefined) {
    const interval = Math.max(5, Math.min(1440, updates.refreshIntervalMinutes));
    existing.refreshIntervalMinutes = interval;
  }
  feedSubscriptions.set(slug, existing);
  return existing;
}

export function getAllSubscriptions(): FeedSubscription[] {
  return Array.from(feedSubscriptions.values());
}

export function getFeedHealthHistory(slug: string): FeedHealthEntry[] {
  if (!isValidSlug(slug)) return [];
  return feedHealthHistory.get(slug) || [];
}

export async function fetchOsintFeed(feedNameOrSlug: string, force?: boolean): Promise<OsintFeedResult> {
  const def = FEED_DEFINITIONS.find((f) => f.name === feedNameOrSlug || f.slug === feedNameOrSlug);
  if (!def) {
    return errorResult(feedNameOrSlug, "", `Unknown feed: ${feedNameOrSlug}`);
  }
  const feedName = def.name;

  const subscription = feedSubscriptions.get(def.slug);
  if (subscription && !subscription.enabled && !force) {
    return errorResult(feedName, def.url, "Feed is disabled");
  }

  if (!force) {
    const cached = feedCache.get(feedName);
    if (cached && Date.now() - cached.fetchedAt < FEED_TTL_MS) {
      return cached.data;
    }
  }

  const result = await def.fetcher();
  feedCache.set(feedName, { data: result, fetchedAt: Date.now() });

  recordHealth(def.slug, {
    timestamp: result.lastFetched,
    status: result.status === "error" ? "error" : "success",
    indicatorCount: result.totalIndicators,
    responseTimeMs: result.responseTimeMs || 0,
    errorMessage: result.errorMessage,
  });

  return result;
}

export async function fetchAllOsintFeeds(force?: boolean): Promise<OsintFeedResult[]> {
  const enabledDefs = FEED_DEFINITIONS.filter((def) => {
    const sub = feedSubscriptions.get(def.slug);
    return !sub || sub.enabled;
  });
  const promises = enabledDefs.map((def) => fetchOsintFeed(def.name, force));
  return Promise.all(promises);
}

export interface BulkRefreshProgress {
  total: number;
  completed: number;
  results: Array<{ slug: string; status: "success" | "error"; indicatorCount: number; errorMessage?: string }>;
}

export async function refreshAllFeedsWithProgress(
  onProgress?: (progress: BulkRefreshProgress) => void,
): Promise<BulkRefreshProgress> {
  const enabledDefs = FEED_DEFINITIONS.filter((def) => {
    const sub = feedSubscriptions.get(def.slug);
    return !sub || sub.enabled;
  });

  const progress: BulkRefreshProgress = { total: enabledDefs.length, completed: 0, results: [] };

  for (const def of enabledDefs) {
    const result = await fetchOsintFeed(def.slug, true);
    progress.completed++;
    progress.results.push({
      slug: def.slug,
      status: result.status === "error" ? "error" : "success",
      indicatorCount: result.totalIndicators,
      errorMessage: result.errorMessage,
    });
    if (onProgress) onProgress(progress);
  }

  return progress;
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
    const subscription = feedSubscriptions.get(def.slug) || { enabled: true, refreshIntervalMinutes: 60 };
    const history = feedHealthHistory.get(def.slug) || [];

    const successCount = history.filter((h) => h.status === "success").length;
    const successRate = history.length > 0 ? Math.round((successCount / history.length) * 100) : 0;
    const avgResponseTimeMs =
      history.length > 0 ? Math.round(history.reduce((sum, h) => sum + h.responseTimeMs, 0) / history.length) : 0;

    let consecutiveErrors = 0;
    for (const entry of history) {
      if (entry.status === "error") consecutiveErrors++;
      else break;
    }

    const lastSuccess = history.find((h) => h.status === "success");
    const lastError = history.find((h) => h.status === "error");

    return {
      name: def.name,
      slug: def.slug,
      url: def.url,
      description: def.description,
      category: def.category,
      indicatorTypes: def.indicatorTypes,
      lastFetched: cached ? cached.data.lastFetched : null,
      lastSuccess: lastSuccess ? lastSuccess.timestamp : null,
      lastError: lastError ? lastError.timestamp : null,
      lastErrorMessage: lastError ? lastError.errorMessage || null : null,
      totalIndicators: cached ? cached.data.totalIndicators : 0,
      status: cached ? (cached.data.status === "error" ? "error" : "success") : "never_fetched",
      enabled: subscription.enabled,
      refreshIntervalMinutes: subscription.refreshIntervalMinutes,
      successRate,
      avgResponseTimeMs,
      totalFetches: history.length,
      consecutiveErrors,
      requiresApiKey: false as const,
    };
  });
}

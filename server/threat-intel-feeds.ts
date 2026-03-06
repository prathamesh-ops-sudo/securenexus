import { createHash } from "crypto";
import Parser from "rss-parser";
import { logger as rootLogger } from "./logger";

const logger = rootLogger.child("threat-intel-feeds");

export interface ThreatIntelArticle {
  id: string;
  source: string;
  feedUrl: string;
  feedTitle: string | null;
  title: string;
  link: string;
  canonicalLink: string;
  guid: string | null;
  publishedAt: string | null;
  updatedAt: string | null;
  authors: string[];
  categories: string[];
  summaryText: string;
  contentText: string;
  fetchedAt: string;
}

export interface ThreatIntelFeedDefinition {
  name: string;
  slug: string;
  url: string;
  category: string;
  type: "rss" | "blog";
}

export interface ThreatIntelFeedStatus {
  name: string;
  slug: string;
  url: string;
  category: string;
  type: "rss" | "blog";
  enabled: boolean;
  lastFetched: string | null;
  lastSuccess: string | null;
  lastError: string | null;
  lastErrorMessage: string | null;
  articleCount: number;
  status: "success" | "error" | "never_fetched";
  successRate: number;
  avgResponseTimeMs: number;
  totalFetches: number;
  consecutiveErrors: number;
}

export interface FeedHealthEntry {
  timestamp: string;
  status: "success" | "error";
  articleCount: number;
  responseTimeMs: number;
  errorMessage?: string;
}

export interface FeedAggregationResult {
  generatedAt: string;
  feedCount: number;
  itemCount: number;
  items: ThreatIntelArticle[];
  meta: {
    schemaVersion: string;
    okFeedCount: number;
    errorFeedCount: number;
    errors: Array<{ feedUrl: string; type: string; message: string }>;
    durationMs: number;
  };
}

const DROP_QUERY_PREFIXES = ["utm_", "ref_", "fbclid", "gclid", "mc_", "mkt_", "pk_", "sc_"];

function canonicalizeLink(link: string): string {
  if (!link) return "";
  try {
    const u = new URL(link.trim());
    if (u.protocol !== "http:" && u.protocol !== "https:") return link.trim();
    const params = new URLSearchParams(u.search);
    const filtered = new URLSearchParams();
    for (const [key, value] of Array.from(params.entries())) {
      const kl = key.toLowerCase();
      if (DROP_QUERY_PREFIXES.some((prefix) => kl.startsWith(prefix))) continue;
      filtered.set(key, value);
    }
    u.search = filtered.toString();
    u.hash = "";
    return u.toString().toLowerCase();
  } catch {
    return link.trim();
  }
}

function stableItemId(feedUrl: string, link: string, title: string, publishedAt: string | null): string {
  let base = canonicalizeLink(link);
  if (!base) {
    base = `${(title || "").trim()}|${publishedAt || ""}|${feedUrl}`;
  }
  return createHash("sha256").update(base).digest("hex");
}

function htmlToText(html: string): string {
  if (!html) return "";
  return html
    .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, "")
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, "")
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/p>/gi, "\n\n")
    .replace(/<[^>]+>/g, "")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&nbsp;/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function isoformatZ(date: Date | null): string | null {
  if (!date || isNaN(date.getTime())) return null;
  return date.toISOString().replace("+00:00", "Z");
}

function parseTimestamp(value: string | undefined | null): Date | null {
  if (!value || typeof value !== "string") return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  const date = new Date(trimmed);
  if (!isNaN(date.getTime())) return date;
  const isoFixed = trimmed.replace("Z", "+00:00");
  const date2 = new Date(isoFixed);
  if (!isNaN(date2.getTime())) return date2;
  return null;
}

function extractCategories(item: Parser.Item): string[] {
  const categories: string[] = [];
  const seen = new Set<string>();
  if (item.categories) {
    for (const cat of item.categories) {
      const normalized = typeof cat === "string" ? cat.trim().toLowerCase() : "";
      if (normalized && !seen.has(normalized)) {
        seen.add(normalized);
        categories.push(normalized);
      }
    }
  }
  return categories;
}

function extractSource(url: string): string {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return "";
  }
}

const FETCH_TIMEOUT_MS = 25_000;
const MAX_RESPONSE_BYTES = 5 * 1024 * 1024;
const MAX_ITEMS_PER_FEED = 200;
const CONCURRENCY = 15;
const PER_HOST_INTERVAL_MS = 500;

const hostLastFetch = new Map<string, number>();

async function rateLimitedWait(url: string): Promise<void> {
  const host = extractSource(url);
  if (!host) return;
  const last = hostLastFetch.get(host) || 0;
  const now = Date.now();
  const wait = last + PER_HOST_INTERVAL_MS - now;
  if (wait > 0) {
    await new Promise((resolve) => setTimeout(resolve, wait));
  }
  hostLastFetch.set(host, Date.now());
}

const rssParser = new Parser({
  timeout: FETCH_TIMEOUT_MS,
  maxRedirects: 5,
  headers: {
    "User-Agent": "SecureNexus-ThreatIntel/2.0 (+https://securenexus.io)",
    Accept: "application/rss+xml, application/atom+xml, application/xml, text/xml, */*",
  },
  customFields: {
    item: [
      ["dc:creator", "dcCreator"],
      ["content:encoded", "contentEncoded"],
    ],
  },
});

async function fetchAndParseRSSFeed(
  url: string,
  maxRetries: number = 2,
): Promise<{ feed: Parser.Output<Parser.Item> | null; error: string | null }> {
  for (let attempt = 1; attempt <= maxRetries + 1; attempt++) {
    try {
      await rateLimitedWait(url);
      const startTime = Date.now();
      const feed = await rssParser.parseURL(url);
      const elapsed = Date.now() - startTime;
      logger.info("RSS feed fetched", { feedUrl: url, elapsed, itemCount: feed.items?.length || 0, attempt });
      return { feed, error: null };
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : String(err);
      logger.warn("RSS feed fetch failed", { feedUrl: url, attempt, error: errMsg });
      if (attempt > maxRetries) {
        return { feed: null, error: errMsg.slice(0, 500) };
      }
      const delay = Math.min(8000, 750 * Math.pow(2, attempt - 1)) + Math.random() * 250;
      await new Promise((resolve) => setTimeout(resolve, delay));
    }
  }
  return { feed: null, error: "Max retries exceeded" };
}

function normalizeRSSItems(feedUrl: string, feed: Parser.Output<Parser.Item>, fetchedAt: Date): ThreatIntelArticle[] {
  const feedTitle = feed.title || null;
  const source = extractSource(feedUrl);
  const items = (feed.items || []).slice(0, MAX_ITEMS_PER_FEED);

  return items
    .map((item): ThreatIntelArticle | null => {
      const title = (item.title || "").trim();
      const link = (item.link || "").trim();
      if (!link) return null;

      const canonical = canonicalizeLink(link);
      const guid = item.guid || (item as any).id || null;

      const publishedDt = parseTimestamp(item.pubDate || item.isoDate);
      const updatedDt = parseTimestamp(item.isoDate);

      const publishedAt = isoformatZ(publishedDt);
      const updatedAt = publishedDt !== updatedDt ? isoformatZ(updatedDt) : null;

      const summarySrc = item.contentSnippet || item.content || "";
      const contentSrc = (item as any).contentEncoded || item.content || "";

      const authors: string[] = [];
      if (item.creator) authors.push(item.creator.trim());
      else if ((item as any).dcCreator) authors.push(String((item as any).dcCreator).trim());
      else if ((item as any).author) authors.push(String((item as any).author).trim());

      const categories = extractCategories(item);
      const itemId = stableItemId(feedUrl, link, title, publishedAt);

      return {
        id: itemId,
        source,
        feedUrl,
        feedTitle: feedTitle && feedTitle.trim() ? feedTitle.trim() : null,
        title,
        link,
        canonicalLink: canonical,
        guid: guid ? String(guid).trim() : null,
        publishedAt,
        updatedAt,
        authors: Array.from(new Set(authors.filter(Boolean))),
        categories,
        summaryText: htmlToText(summarySrc),
        contentText: htmlToText(contentSrc),
        fetchedAt: isoformatZ(fetchedAt) || new Date().toISOString(),
      };
    })
    .filter((item): item is ThreatIntelArticle => item !== null);
}

function dedupeArticles(items: ThreatIntelArticle[]): ThreatIntelArticle[] {
  const seenLinks = new Set<string>();
  const seenIds = new Set<string>();
  const out: ThreatIntelArticle[] = [];
  for (const item of items) {
    if (item.canonicalLink && seenLinks.has(item.canonicalLink)) continue;
    if (item.id && seenIds.has(item.id)) continue;
    if (item.canonicalLink) seenLinks.add(item.canonicalLink);
    if (item.id) seenIds.add(item.id);
    out.push(item);
  }
  return out;
}

function sortArticles(items: ThreatIntelArticle[], desc: boolean = true): ThreatIntelArticle[] {
  return items.sort((a, b) => {
    const aKey = a.publishedAt || a.updatedAt || "";
    const bKey = b.publishedAt || b.updatedAt || "";
    return desc ? bKey.localeCompare(aKey) : aKey.localeCompare(bKey);
  });
}

const RSS_FEEDS: ThreatIntelFeedDefinition[] = [
  {
    name: "Recorded Future",
    slug: "recorded-future",
    url: "https://www.recordedfuture.com/feed/",
    category: "Threat Intelligence",
    type: "rss",
  },
  {
    name: "Cybereason",
    slug: "cybereason",
    url: "https://www.cybereason.com/blog/rss.xml",
    category: "Endpoint Security",
    type: "rss",
  },
  { name: "The Record", slug: "the-record", url: "https://therecord.media/feed/", category: "News", type: "rss" },
  {
    name: "Krebs on Security",
    slug: "krebs-on-security",
    url: "https://krebsonsecurity.com/feed/",
    category: "News",
    type: "rss",
  },
  {
    name: "Schneier on Security",
    slug: "schneier-on-security",
    url: "https://www.schneier.com/feed/",
    category: "Cryptography",
    type: "rss",
  },
  { name: "Threatpost", slug: "threatpost", url: "https://threatpost.com/feed/", category: "News", type: "rss" },
  {
    name: "Graham Cluley",
    slug: "graham-cluley",
    url: "https://grahamcluley.com/feed/",
    category: "News",
    type: "rss",
  },
  {
    name: "Troy Hunt",
    slug: "troy-hunt",
    url: "https://www.troyhunt.com/rss/",
    category: "Data Breaches",
    type: "rss",
  },
  {
    name: "Dark Reading",
    slug: "dark-reading",
    url: "https://www.darkreading.com/rss.xml",
    category: "News",
    type: "rss",
  },
  {
    name: "BleepingComputer",
    slug: "bleepingcomputer",
    url: "https://www.bleepingcomputer.com/feed/",
    category: "News",
    type: "rss",
  },
  {
    name: "SecurityWeek",
    slug: "securityweek",
    url: "https://www.securityweek.com/feed/",
    category: "News",
    type: "rss",
  },
  {
    name: "Naked Security (Sophos)",
    slug: "naked-security",
    url: "https://nakedsecurity.sophos.com/feed/",
    category: "Endpoint Security",
    type: "rss",
  },
  {
    name: "Cisco Talos",
    slug: "cisco-talos",
    url: "https://blog.talosintelligence.com/rss/",
    category: "Threat Intelligence",
    type: "rss",
  },
  {
    name: "WeLiveSecurity (ESET)",
    slug: "welivesecurity",
    url: "https://www.welivesecurity.com/feed/",
    category: "Malware Analysis",
    type: "rss",
  },
  {
    name: "Kaspersky Securelist",
    slug: "securelist",
    url: "https://securelist.com/feed/",
    category: "Malware Analysis",
    type: "rss",
  },
  {
    name: "Microsoft Security",
    slug: "microsoft-security",
    url: "https://www.microsoft.com/en-us/security/blog/feed/",
    category: "Vendor Security",
    type: "rss",
  },
  {
    name: "Google TAG",
    slug: "google-tag",
    url: "https://blog.google/threat-analysis-group/rss/",
    category: "Threat Intelligence",
    type: "rss",
  },
  {
    name: "SentinelOne",
    slug: "sentinelone",
    url: "https://www.sentinelone.com/blog/feed/",
    category: "Endpoint Security",
    type: "rss",
  },
  {
    name: "CrowdStrike",
    slug: "crowdstrike",
    url: "https://www.crowdstrike.com/blog/feed/",
    category: "Threat Intelligence",
    type: "rss",
  },
  {
    name: "Mandiant",
    slug: "mandiant",
    url: "https://www.mandiant.com/resources/blog/rss.xml",
    category: "Threat Intelligence",
    type: "rss",
  },
  {
    name: "Unit 42 (Palo Alto)",
    slug: "unit42",
    url: "https://unit42.paloaltonetworks.com/feed/",
    category: "Threat Intelligence",
    type: "rss",
  },
  {
    name: "Fortinet Threat Research",
    slug: "fortinet",
    url: "https://feeds.fortinet.com/fortinet/blog/threat-research",
    category: "Threat Intelligence",
    type: "rss",
  },
  {
    name: "Proofpoint",
    slug: "proofpoint",
    url: "https://www.proofpoint.com/us/blog/rss.xml",
    category: "Email Security",
    type: "rss",
  },
  {
    name: "Trend Micro Research",
    slug: "trend-micro",
    url: "https://www.trendmicro.com/en_us/research.rss.html",
    category: "Malware Analysis",
    type: "rss",
  },
  {
    name: "Zscaler ThreatLabz",
    slug: "zscaler",
    url: "https://www.zscaler.com/blogs/security-research/rss",
    category: "Cloud Security",
    type: "rss",
  },
  {
    name: "Check Point Research",
    slug: "checkpoint",
    url: "https://research.checkpoint.com/feed/",
    category: "Threat Intelligence",
    type: "rss",
  },
  {
    name: "Qualys Threat Research",
    slug: "qualys",
    url: "https://blog.qualys.com/vulnerabilities-threat-research/feed",
    category: "Vulnerability",
    type: "rss",
  },
  { name: "Rapid7", slug: "rapid7", url: "https://blog.rapid7.com/rss/", category: "Vulnerability", type: "rss" },
  {
    name: "Tenable Research",
    slug: "tenable",
    url: "https://www.tenable.com/blog/feed",
    category: "Vulnerability",
    type: "rss",
  },
  {
    name: "Volexity",
    slug: "volexity",
    url: "https://www.volexity.com/blog/feed/",
    category: "Threat Intelligence",
    type: "rss",
  },
  {
    name: "Elastic Security Labs",
    slug: "elastic-security",
    url: "https://www.elastic.co/security-labs/rss/feed.xml",
    category: "Detection Engineering",
    type: "rss",
  },
  {
    name: "CISA Alerts",
    slug: "cisa-alerts",
    url: "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    category: "Government",
    type: "rss",
  },
  {
    name: "US-CERT",
    slug: "us-cert",
    url: "https://www.us-cert.gov/ncas/alerts.xml",
    category: "Government",
    type: "rss",
  },
  {
    name: "NIST NVD",
    slug: "nist-nvd",
    url: "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss-analyzed.xml",
    category: "Vulnerability",
    type: "rss",
  },
  {
    name: "Malwarebytes Labs",
    slug: "malwarebytes",
    url: "https://www.malwarebytes.com/blog/feed",
    category: "Malware Analysis",
    type: "rss",
  },
  {
    name: "Huntress",
    slug: "huntress",
    url: "https://www.huntress.com/blog/rss.xml",
    category: "Managed Detection",
    type: "rss",
  },
  {
    name: "Infosecurity Magazine",
    slug: "infosecurity-mag",
    url: "https://www.infosecurity-magazine.com/rss/news/",
    category: "News",
    type: "rss",
  },
  {
    name: "The Hacker News",
    slug: "the-hacker-news",
    url: "https://feeds.feedburner.com/TheHackersNews",
    category: "News",
    type: "rss",
  },
  { name: "SC Magazine", slug: "sc-magazine", url: "https://www.scmagazine.com/feed", category: "News", type: "rss" },
  {
    name: "Help Net Security",
    slug: "helpnetsecurity",
    url: "https://www.helpnetsecurity.com/feed/",
    category: "News",
    type: "rss",
  },
  {
    name: "Ars Technica Security",
    slug: "ars-technica-security",
    url: "https://feeds.arstechnica.com/arstechnica/security",
    category: "News",
    type: "rss",
  },
  {
    name: "SANS ISC",
    slug: "sans-isc",
    url: "https://isc.sans.edu/rssfeed.xml",
    category: "Incident Response",
    type: "rss",
  },
  {
    name: "SANS NewsBites",
    slug: "sans-newsbites",
    url: "https://www.sans.org/newsletters/newsbites/rss",
    category: "News",
    type: "rss",
  },
  {
    name: "Packet Storm",
    slug: "packet-storm",
    url: "https://rss.packetstormsecurity.com/",
    category: "Exploit",
    type: "rss",
  },
  {
    name: "Exploit-DB",
    slug: "exploit-db",
    url: "https://www.exploit-db.com/rss.xml",
    category: "Exploit",
    type: "rss",
  },
  {
    name: "PortSwigger Daily Swig",
    slug: "portswigger",
    url: "https://portswigger.net/daily-swig/rss",
    category: "Web Security",
    type: "rss",
  },
  { name: "Sucuri Blog", slug: "sucuri", url: "https://blog.sucuri.net/feed/", category: "Web Security", type: "rss" },
  {
    name: "Wordfence",
    slug: "wordfence",
    url: "https://www.wordfence.com/blog/feed/",
    category: "Web Security",
    type: "rss",
  },
  { name: "Snyk Security", slug: "snyk", url: "https://snyk.io/blog/feed/", category: "Supply Chain", type: "rss" },
  {
    name: "Socket.dev",
    slug: "socket-dev",
    url: "https://socket.dev/blog/feed",
    category: "Supply Chain",
    type: "rss",
  },
  {
    name: "MITRE ATT&CK Updates",
    slug: "mitre-attack",
    url: "https://medium.com/feed/mitre-attack/",
    category: "Framework",
    type: "rss",
  },
  {
    name: "Red Canary",
    slug: "red-canary",
    url: "https://redcanary.com/blog/feed/",
    category: "Detection Engineering",
    type: "rss",
  },
  {
    name: "Splunk Security",
    slug: "splunk-security",
    url: "https://www.splunk.com/en_us/blog/security.rss",
    category: "SIEM",
    type: "rss",
  },
  {
    name: "AWS Security Blog",
    slug: "aws-security",
    url: "https://aws.amazon.com/blogs/security/feed/",
    category: "Cloud Security",
    type: "rss",
  },
  {
    name: "Google Cloud Security",
    slug: "gcp-security",
    url: "https://cloud.google.com/blog/products/identity-security/rss",
    category: "Cloud Security",
    type: "rss",
  },
  {
    name: "Azure Security Blog",
    slug: "azure-security",
    url: "https://techcommunity.microsoft.com/plugins/custom/microsoft/o365/custom-blog-rss?board=MicrosoftSecurityandCompliance",
    category: "Cloud Security",
    type: "rss",
  },
  {
    name: "Cloudflare Blog",
    slug: "cloudflare",
    url: "https://blog.cloudflare.com/rss/",
    category: "Cloud Security",
    type: "rss",
  },
  {
    name: "Akamai Blog",
    slug: "akamai",
    url: "https://www.akamai.com/blog/feed.xml",
    category: "Cloud Security",
    type: "rss",
  },
  {
    name: "BitDefender Labs",
    slug: "bitdefender",
    url: "https://www.bitdefender.com/blog/api/rss/labs/",
    category: "Malware Analysis",
    type: "rss",
  },
  {
    name: "F-Secure Research",
    slug: "f-secure",
    url: "https://blog.f-secure.com/feed/",
    category: "Malware Analysis",
    type: "rss",
  },
  {
    name: "Carbon Black (VMware)",
    slug: "carbon-black",
    url: "https://blogs.vmware.com/security/feed",
    category: "Endpoint Security",
    type: "rss",
  },
  {
    name: "Symantec Enterprise",
    slug: "symantec",
    url: "https://symantec-enterprise-blogs.security.com/blogs/rss.xml",
    category: "Endpoint Security",
    type: "rss",
  },
  {
    name: "Abnormal Security",
    slug: "abnormal-security",
    url: "https://abnormalsecurity.com/blog/rss.xml",
    category: "Email Security",
    type: "rss",
  },
  {
    name: "Mimecast Blog",
    slug: "mimecast",
    url: "https://www.mimecast.com/blog/feed/",
    category: "Email Security",
    type: "rss",
  },
  { name: "Cofense", slug: "cofense", url: "https://cofense.com/blog/feed/", category: "Phishing", type: "rss" },
  {
    name: "PhishMe (Cofense Intelligence)",
    slug: "phishme",
    url: "https://cofense.com/intelligence/feed/",
    category: "Phishing",
    type: "rss",
  },
  {
    name: "FIRST.org",
    slug: "first-org",
    url: "https://www.first.org/newsroom/rss",
    category: "Incident Response",
    type: "rss",
  },
  { name: "ENISA", slug: "enisa", url: "https://www.enisa.europa.eu/rss.xml", category: "Government", type: "rss" },
  {
    name: "NCSC UK",
    slug: "ncsc-uk",
    url: "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml",
    category: "Government",
    type: "rss",
  },
  {
    name: "Australian Cyber Security Centre",
    slug: "acsc",
    url: "https://www.cyber.gov.au/rss/alerts",
    category: "Government",
    type: "rss",
  },
  {
    name: "Canada CCCS",
    slug: "cccs",
    url: "https://www.cyber.gc.ca/api/cccs/rss/en",
    category: "Government",
    type: "rss",
  },
  {
    name: "BSI Germany",
    slug: "bsi",
    url: "https://www.bsi.bund.de/SiteGlobals/Functions/RSSFeed/RSSNewsfeed/RSSNewsfeed_en.xml",
    category: "Government",
    type: "rss",
  },
  { name: "CyberScoop", slug: "cyberscoop", url: "https://cyberscoop.com/feed/", category: "News", type: "rss" },
  {
    name: "Risky Business",
    slug: "risky-business",
    url: "https://risky.biz/feeds/risky-business/",
    category: "Podcast",
    type: "rss",
  },
  {
    name: "DFIR Report",
    slug: "dfir-report",
    url: "https://thedfirreport.com/feed/",
    category: "Incident Response",
    type: "rss",
  },
  {
    name: "MalwareTech",
    slug: "malwaretech",
    url: "https://www.malwaretech.com/feed",
    category: "Malware Analysis",
    type: "rss",
  },
  {
    name: "Didier Stevens",
    slug: "didier-stevens",
    url: "https://blog.didierstevens.com/feed/",
    category: "Malware Analysis",
    type: "rss",
  },
  {
    name: "Hexacorn",
    slug: "hexacorn",
    url: "https://www.hexacorn.com/blog/feed/",
    category: "Malware Analysis",
    type: "rss",
  },
  {
    name: "Adam Chester",
    slug: "adam-chester",
    url: "https://blog.xpnsec.com/rss/",
    category: "Red Team",
    type: "rss",
  },
  {
    name: "SpecterOps",
    slug: "specterops",
    url: "https://posts.specterops.io/feed",
    category: "Red Team",
    type: "rss",
  },
  {
    name: "Pentest Partners",
    slug: "pentest-partners",
    url: "https://www.pentestpartners.com/security-blog/feed/",
    category: "Penetration Testing",
    type: "rss",
  },
  {
    name: "NetSPI",
    slug: "netspi",
    url: "https://www.netspi.com/blog/feed/",
    category: "Penetration Testing",
    type: "rss",
  },
  {
    name: "TrustedSec",
    slug: "trustedsec",
    url: "https://trustedsec.com/blog/feed/",
    category: "Red Team",
    type: "rss",
  },
  {
    name: "Black Hills InfoSec",
    slug: "bhis",
    url: "https://www.blackhillsinfosec.com/feed/",
    category: "Red Team",
    type: "rss",
  },
  {
    name: "NCC Group Research",
    slug: "ncc-group",
    url: "https://research.nccgroup.com/feed/",
    category: "Research",
    type: "rss",
  },
  {
    name: "Trail of Bits",
    slug: "trail-of-bits",
    url: "https://blog.trailofbits.com/feed/",
    category: "Research",
    type: "rss",
  },
  {
    name: "Google Project Zero",
    slug: "project-zero",
    url: "https://googleprojectzero.blogspot.com/feeds/posts/default",
    category: "Vulnerability",
    type: "rss",
  },
  {
    name: "Zero Day Initiative",
    slug: "zdi",
    url: "https://www.zerodayinitiative.com/rss/published/",
    category: "Vulnerability",
    type: "rss",
  },
  {
    name: "Mozilla Security Blog",
    slug: "mozilla-security",
    url: "https://blog.mozilla.org/security/feed/",
    category: "Vendor Security",
    type: "rss",
  },
  {
    name: "Chrome Releases",
    slug: "chrome-releases",
    url: "https://chromereleases.googleblog.com/feeds/posts/default",
    category: "Vendor Security",
    type: "rss",
  },
  { name: "Okta Security", slug: "okta-security", url: "https://sec.okta.com/rss", category: "Identity", type: "rss" },
  { name: "Auth0 Blog", slug: "auth0", url: "https://auth0.com/blog/rss.xml", category: "Identity", type: "rss" },
  { name: "Wiz Blog", slug: "wiz", url: "https://www.wiz.io/blog/rss.xml", category: "Cloud Security", type: "rss" },
  {
    name: "Orca Security",
    slug: "orca-security",
    url: "https://orca.security/resources/blog/feed/",
    category: "Cloud Security",
    type: "rss",
  },
  {
    name: "Aqua Security",
    slug: "aqua-security",
    url: "https://blog.aquasec.com/rss.xml",
    category: "Container Security",
    type: "rss",
  },
  { name: "Sysdig", slug: "sysdig", url: "https://sysdig.com/blog/feed/", category: "Container Security", type: "rss" },
  {
    name: "Lacework",
    slug: "lacework",
    url: "https://www.lacework.com/blog/feed/",
    category: "Cloud Security",
    type: "rss",
  },
  {
    name: "DataDog Security Labs",
    slug: "datadog-security",
    url: "https://securitylabs.datadoghq.com/rss/feed.xml",
    category: "Detection Engineering",
    type: "rss",
  },
  {
    name: "Sigma HQ",
    slug: "sigma-hq",
    url: "https://blog.sigmahq.io/feed",
    category: "Detection Engineering",
    type: "rss",
  },
  {
    name: "Detection Engineering Weekly",
    slug: "detection-engineering-weekly",
    url: "https://www.detectionengineering.net/feed",
    category: "Detection Engineering",
    type: "rss",
  },
  { name: "OWASP Blog", slug: "owasp", url: "https://owasp.org/feed.xml", category: "Web Security", type: "rss" },
  {
    name: "Intezer",
    slug: "intezer",
    url: "https://www.intezer.com/blog/feed/",
    category: "Malware Analysis",
    type: "rss",
  },
  {
    name: "ReversingLabs",
    slug: "reversinglabs",
    url: "https://blog.reversinglabs.com/blog/rss.xml",
    category: "Supply Chain",
    type: "rss",
  },
  {
    name: "VirusTotal Blog",
    slug: "virustotal-blog",
    url: "https://blog.virustotal.com/feeds/posts/default",
    category: "Malware Analysis",
    type: "rss",
  },
  {
    name: "AlienVault OTX Pulse",
    slug: "alienvault-otx",
    url: "https://otx.alienvault.com/pulse/feed",
    category: "Threat Intelligence",
    type: "rss",
  },
  {
    name: "Abuse.ch",
    slug: "abusech",
    url: "https://abuse.ch/blog/feed/",
    category: "Threat Intelligence",
    type: "rss",
  },
  {
    name: "MalwareBazaar",
    slug: "malwarebazaar",
    url: "https://bazaar.abuse.ch/rss/",
    category: "Malware Analysis",
    type: "rss",
  },
  {
    name: "PhishTank",
    slug: "phishtank",
    url: "https://phishtank.org/phishtank_rss.php",
    category: "Phishing",
    type: "rss",
  },
  {
    name: "SpamHaus Blog",
    slug: "spamhaus",
    url: "https://www.spamhaus.org/news/rss/",
    category: "Email Security",
    type: "rss",
  },
  {
    name: "Threatdown by Malwarebytes",
    slug: "threatdown",
    url: "https://www.threatdown.com/blog/feed/",
    category: "Endpoint Security",
    type: "rss",
  },
  {
    name: "ANY.RUN Blog",
    slug: "anyrun",
    url: "https://any.run/cybersecurity-blog/feed/",
    category: "Malware Analysis",
    type: "rss",
  },
  {
    name: "SOCRadar",
    slug: "socradar",
    url: "https://socradar.io/blog/feed/",
    category: "Threat Intelligence",
    type: "rss",
  },
  {
    name: "Flashpoint Intel",
    slug: "flashpoint",
    url: "https://flashpoint.io/blog/feed/",
    category: "Threat Intelligence",
    type: "rss",
  },
  {
    name: "Intel 471",
    slug: "intel471",
    url: "https://intel471.com/blog/feed/",
    category: "Threat Intelligence",
    type: "rss",
  },
  {
    name: "Group-IB",
    slug: "group-ib",
    url: "https://www.group-ib.com/blog/rss",
    category: "Threat Intelligence",
    type: "rss",
  },
  {
    name: "Anomali",
    slug: "anomali",
    url: "https://www.anomali.com/blog/feed",
    category: "Threat Intelligence",
    type: "rss",
  },
  {
    name: "EclecticIQ",
    slug: "eclecticiq",
    url: "https://blog.eclecticiq.com/rss.xml",
    category: "Threat Intelligence",
    type: "rss",
  },
  {
    name: "ThreatConnect",
    slug: "threatconnect",
    url: "https://threatconnect.com/blog/feed/",
    category: "Threat Intelligence",
    type: "rss",
  },
  {
    name: "Sekoia Blog",
    slug: "sekoia",
    url: "https://blog.sekoia.io/feed/",
    category: "Threat Intelligence",
    type: "rss",
  },
  {
    name: "Dragos",
    slug: "dragos",
    url: "https://www.dragos.com/blog/feed/",
    category: "ICS/OT Security",
    type: "rss",
  },
  { name: "Claroty", slug: "claroty", url: "https://claroty.com/blog/feed/", category: "ICS/OT Security", type: "rss" },
  {
    name: "Nozomi Networks",
    slug: "nozomi",
    url: "https://www.nozominetworks.com/blog/feed/",
    category: "ICS/OT Security",
    type: "rss",
  },
  {
    name: "ICS-CERT Advisories",
    slug: "ics-cert",
    url: "https://www.cisa.gov/uscert/ics/advisories/advisories.xml",
    category: "ICS/OT Security",
    type: "rss",
  },
  {
    name: "Security Affairs",
    slug: "security-affairs",
    url: "https://securityaffairs.com/feed",
    category: "News",
    type: "rss",
  },
  {
    name: "Hacker One Hacktivity",
    slug: "hackerone",
    url: "https://hackerone.com/hacktivity.rss",
    category: "Bug Bounty",
    type: "rss",
  },
  {
    name: "Bugcrowd Blog",
    slug: "bugcrowd",
    url: "https://www.bugcrowd.com/blog/feed/",
    category: "Bug Bounty",
    type: "rss",
  },
  {
    name: "MISP Threat Sharing",
    slug: "misp",
    url: "https://www.misp-project.org/feed.xml",
    category: "Framework",
    type: "rss",
  },
  { name: "OpenCTI Blog", slug: "opencti", url: "https://blog.filigran.io/feed", category: "Framework", type: "rss" },
  {
    name: "Wired Threat Level",
    slug: "wired-threat",
    url: "https://www.wired.com/feed/category/security/latest/rss",
    category: "News",
    type: "rss",
  },
  { name: "CSO Online", slug: "cso-online", url: "https://www.csoonline.com/feed/", category: "News", type: "rss" },
  {
    name: "TechTarget Security",
    slug: "techtarget-security",
    url: "https://www.techtarget.com/searchsecurity/rss/Security-Wire-Daily-News.xml",
    category: "News",
    type: "rss",
  },
];

const feedArticleCache = new Map<string, { articles: ThreatIntelArticle[]; fetchedAt: number }>();
const feedHealthHistory = new Map<string, FeedHealthEntry[]>();
const feedEnabled = new Map<string, boolean>();
const ARTICLE_CACHE_TTL_MS = 30 * 60 * 1000;
const MAX_HEALTH_ENTRIES = 50;
const ALL_SLUGS = new Set(RSS_FEEDS.map((f) => f.slug));

function initFeedState(): void {
  for (const feed of RSS_FEEDS) {
    if (!feedEnabled.has(feed.slug)) {
      feedEnabled.set(feed.slug, true);
    }
  }
}

initFeedState();

function recordFeedHealth(slug: string, entry: FeedHealthEntry): void {
  const history = feedHealthHistory.get(slug) || [];
  history.unshift(entry);
  if (history.length > MAX_HEALTH_ENTRIES) {
    history.length = MAX_HEALTH_ENTRIES;
  }
  feedHealthHistory.set(slug, history);
}

export function getThreatIntelFeedDefinitions(): ThreatIntelFeedDefinition[] {
  return RSS_FEEDS;
}

export function isThreatIntelSlugValid(slug: string): boolean {
  return ALL_SLUGS.has(slug);
}

export function getThreatIntelFeedStatuses(): ThreatIntelFeedStatus[] {
  return RSS_FEEDS.map((def) => {
    const cached = feedArticleCache.get(def.slug);
    const enabled = feedEnabled.get(def.slug) !== false;
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
      category: def.category,
      type: def.type,
      enabled,
      lastFetched: cached ? new Date(cached.fetchedAt).toISOString() : null,
      lastSuccess: lastSuccess ? lastSuccess.timestamp : null,
      lastError: lastError ? lastError.timestamp : null,
      lastErrorMessage: lastError ? lastError.errorMessage || null : null,
      articleCount: cached ? cached.articles.length : 0,
      status: history.length > 0 ? history[0].status : cached ? "success" : "never_fetched",
      successRate,
      avgResponseTimeMs,
      totalFetches: history.length,
      consecutiveErrors,
    };
  });
}

export function setThreatIntelFeedEnabled(slug: string, enabled: boolean): boolean {
  if (!ALL_SLUGS.has(slug)) return false;
  feedEnabled.set(slug, enabled);
  return true;
}

export function getThreatIntelFeedHealth(slug: string): FeedHealthEntry[] {
  if (!ALL_SLUGS.has(slug)) return [];
  return feedHealthHistory.get(slug) || [];
}

export async function fetchThreatIntelFeed(
  slug: string,
  force: boolean = false,
): Promise<{ articles: ThreatIntelArticle[]; error: string | null }> {
  const def = RSS_FEEDS.find((f) => f.slug === slug);
  if (!def) return { articles: [], error: `Unknown feed slug: ${slug}` };

  if (!force) {
    const cached = feedArticleCache.get(slug);
    if (cached && Date.now() - cached.fetchedAt < ARTICLE_CACHE_TTL_MS) {
      return { articles: cached.articles, error: null };
    }
  }

  const startTime = Date.now();
  const { feed, error } = await fetchAndParseRSSFeed(def.url);
  const elapsed = Date.now() - startTime;

  if (error || !feed) {
    recordFeedHealth(slug, {
      timestamp: new Date().toISOString(),
      status: "error",
      articleCount: 0,
      responseTimeMs: elapsed,
      errorMessage: error || "Unknown error",
    });
    return { articles: [], error };
  }

  const fetchedAt = new Date();
  const articles = normalizeRSSItems(def.url, feed, fetchedAt);
  const deduped = dedupeArticles(articles);
  const sorted = sortArticles(deduped);

  feedArticleCache.set(slug, { articles: sorted, fetchedAt: Date.now() });
  recordFeedHealth(slug, {
    timestamp: fetchedAt.toISOString(),
    status: "success",
    articleCount: sorted.length,
    responseTimeMs: elapsed,
  });

  return { articles: sorted, error: null };
}

export async function fetchAllThreatIntelFeeds(force: boolean = false): Promise<FeedAggregationResult> {
  const started = Date.now();
  const enabledFeeds = RSS_FEEDS.filter((f) => feedEnabled.get(f.slug) !== false);

  const allArticles: ThreatIntelArticle[] = [];
  const errors: Array<{ feedUrl: string; type: string; message: string }> = [];
  let okCount = 0;

  const semaphore = { count: 0 };
  const results = await Promise.all(
    enabledFeeds.map(async (def) => {
      while (semaphore.count >= CONCURRENCY) {
        await new Promise((resolve) => setTimeout(resolve, 50));
      }
      semaphore.count++;
      try {
        const result = await fetchThreatIntelFeed(def.slug, force);
        return { slug: def.slug, url: def.url, ...result };
      } finally {
        semaphore.count--;
      }
    }),
  );

  for (const result of results) {
    if (result.error) {
      errors.push({ feedUrl: result.url, type: "FetchError", message: result.error });
    } else {
      okCount++;
      allArticles.push(...result.articles);
    }
  }

  const deduped = dedupeArticles(allArticles);
  const sorted = sortArticles(deduped);

  return {
    generatedAt: new Date().toISOString(),
    feedCount: enabledFeeds.length,
    itemCount: sorted.length,
    items: sorted,
    meta: {
      schemaVersion: "1.0",
      okFeedCount: okCount,
      errorFeedCount: enabledFeeds.length - okCount,
      errors,
      durationMs: Date.now() - started,
    },
  };
}

export function getCachedThreatIntelArticles(options?: {
  limit?: number;
  category?: string;
  search?: string;
  feedSlug?: string;
}): ThreatIntelArticle[] {
  let all: ThreatIntelArticle[] = [];
  for (const [slug, cached] of Array.from(feedArticleCache.entries())) {
    if (feedEnabled.get(slug) === false) continue;
    if (options?.feedSlug && slug !== options.feedSlug) continue;
    all.push(...cached.articles);
  }

  if (options?.category) {
    const cat = options.category.toLowerCase();
    const feedSlugsInCategory = RSS_FEEDS.filter((f) => f.category.toLowerCase() === cat).map((f) => f.slug);
    all = all.filter((a) => {
      const source = a.source.toLowerCase();
      return feedSlugsInCategory.some((slug) => {
        const def = RSS_FEEDS.find((f) => f.slug === slug);
        return def && extractSource(def.url) === source;
      });
    });
  }

  if (options?.search) {
    const q = options.search.toLowerCase();
    all = all.filter(
      (a) =>
        a.title.toLowerCase().includes(q) ||
        a.summaryText.toLowerCase().includes(q) ||
        a.categories.some((c) => c.includes(q)) ||
        a.source.includes(q),
    );
  }

  const deduped = dedupeArticles(all);
  const sorted = sortArticles(deduped);
  const limit = options?.limit || 500;
  return sorted.slice(0, limit);
}

export function getThreatIntelCategories(): Array<{ name: string; feedCount: number }> {
  const categoryMap = new Map<string, number>();
  for (const feed of RSS_FEEDS) {
    categoryMap.set(feed.category, (categoryMap.get(feed.category) || 0) + 1);
  }
  return Array.from(categoryMap.entries())
    .map(([name, feedCount]) => ({ name, feedCount }))
    .sort((a, b) => b.feedCount - a.feedCount);
}

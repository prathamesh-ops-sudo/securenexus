import { createHash, randomInt } from "crypto";
import Parser from "rss-parser";
import { logger as rootLogger } from "./logger";
import { invokeModel } from "./ai/model-gateway";
import { config as appConfig } from "./config";

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
  relevanceScore?: number;
  relevanceReason?: string;
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

const FETCH_TIMEOUT_MS = 12_000;
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
  maxRetries: number = 1,
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
      const delay = Math.min(8000, 750 * Math.pow(2, attempt - 1)) + randomInt(250);
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
      const guid = item.guid || (item as Record<string, unknown>).id || null;

      const publishedDt = parseTimestamp(item.pubDate || item.isoDate);
      const updatedDt = parseTimestamp(item.isoDate);

      const publishedAt = isoformatZ(publishedDt);
      const updatedAt = publishedDt?.getTime() !== updatedDt?.getTime() ? isoformatZ(updatedDt) : null;

      const summarySrc = item.contentSnippet || item.content || "";
      const contentSrc = ((item as Record<string, unknown>).contentEncoded as string) || item.content || "";

      const authors: string[] = [];
      if (item.creator) authors.push(item.creator.trim());
      else if ((item as Record<string, unknown>).dcCreator)
        authors.push(String((item as Record<string, unknown>).dcCreator).trim());
      else if ((item as Record<string, unknown>).author)
        authors.push(String((item as Record<string, unknown>).author).trim());

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
  // ── Threat Intelligence ──
  {
    name: "Recorded Future",
    slug: "recorded-future",
    url: "https://www.recordedfuture.com/feed/",
    category: "Threat Intelligence",
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
    name: "Google TAG",
    slug: "google-tag",
    url: "https://blog.google/threat-analysis-group/rss/",
    category: "Threat Intelligence",
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
    name: "Check Point Research",
    slug: "checkpoint",
    url: "https://research.checkpoint.com/feed/",
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
    name: "GreyNoise",
    slug: "greynoise",
    url: "https://www.greynoise.io/blog/rss.xml",
    category: "Threat Intelligence",
    type: "rss",
  },
  {
    name: "Shodan Blog",
    slug: "shodan",
    url: "https://blog.shodan.io/rss/",
    category: "Threat Intelligence",
    type: "rss",
  },
  {
    name: "Cybersixgill",
    slug: "cybersixgill",
    url: "https://cybersixgill.com/blog/feed/",
    category: "Threat Intelligence",
    type: "rss",
  },
  {
    name: "Silobreaker",
    slug: "silobreaker",
    url: "https://www.silobreaker.com/blog/feed/",
    category: "Threat Intelligence",
    type: "rss",
  },

  // ── News & Media ──
  { name: "The Record", slug: "the-record", url: "https://therecord.media/feed/", category: "News", type: "rss" },
  {
    name: "Krebs on Security",
    slug: "krebs-on-security",
    url: "https://krebsonsecurity.com/feed/",
    category: "News",
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
  {
    name: "Help Net Security",
    slug: "helpnetsecurity",
    url: "https://www.helpnetsecurity.com/feed/",
    category: "News",
    type: "rss",
  },
  { name: "CyberScoop", slug: "cyberscoop", url: "https://cyberscoop.com/feed/", category: "News", type: "rss" },
  {
    name: "Security Affairs",
    slug: "security-affairs",
    url: "https://securityaffairs.com/feed",
    category: "News",
    type: "rss",
  },
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
  {
    name: "Threatpost Podcast",
    slug: "threatpost-podcast",
    url: "https://threatpost.com/category/podcasts/feed/",
    category: "News",
    type: "rss",
  },
  {
    name: "Cybersecurity Dive",
    slug: "cybersecurity-dive",
    url: "https://www.cybersecuritydive.com/feeds/news/",
    category: "News",
    type: "rss",
  },
  {
    name: "IT Security Guru",
    slug: "itsecurityguru",
    url: "https://www.itsecurityguru.org/feed/",
    category: "News",
    type: "rss",
  },
  {
    name: "Computer Weekly Security",
    slug: "computer-weekly-sec",
    url: "https://www.computerweekly.com/rss/IT-security.xml",
    category: "News",
    type: "rss",
  },
  {
    name: "ZDNet Zero Day",
    slug: "zdnet-zeroday",
    url: "https://www.zdnet.com/topic/security/rss.xml",
    category: "News",
    type: "rss",
  },
  { name: "Hackread", slug: "hackread", url: "https://www.hackread.com/feed/", category: "News", type: "rss" },
  {
    name: "The Cyber Express",
    slug: "cyber-express",
    url: "https://thecyberexpress.com/feed/",
    category: "News",
    type: "rss",
  },
  {
    name: "Cyber Security News",
    slug: "cybersec-news",
    url: "https://cybersecuritynews.com/feed/",
    category: "News",
    type: "rss",
  },
  {
    name: "Latest Hacking News",
    slug: "latest-hacking-news",
    url: "https://latesthackingnews.com/feed/",
    category: "News",
    type: "rss",
  },

  // ── Malware Analysis ──
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
    name: "Malwarebytes Labs",
    slug: "malwarebytes",
    url: "https://www.malwarebytes.com/blog/feed",
    category: "Malware Analysis",
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
    name: "Intezer",
    slug: "intezer",
    url: "https://www.intezer.com/blog/feed/",
    category: "Malware Analysis",
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
    name: "ANY.RUN Blog",
    slug: "anyrun",
    url: "https://any.run/cybersecurity-blog/feed/",
    category: "Malware Analysis",
    type: "rss",
  },
  {
    name: "YARA Blog",
    slug: "yara-rules",
    url: "https://blog.virustotal.com/feeds/posts/default/-/yara",
    category: "Malware Analysis",
    type: "rss",
  },
  { name: "CERT.pl", slug: "cert-pl", url: "https://cert.pl/en/rss.xml", category: "Malware Analysis", type: "rss" },
  {
    name: "Netlab 360",
    slug: "netlab360",
    url: "https://blog.netlab.360.com/rss/",
    category: "Malware Analysis",
    type: "rss",
  },

  // ── Endpoint Security ──
  {
    name: "Cybereason",
    slug: "cybereason",
    url: "https://www.cybereason.com/blog/rss.xml",
    category: "Endpoint Security",
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
    name: "Carbon Black (VMware)",
    slug: "carbon-black",
    url: "https://blogs.vmware.com/security/feed",
    category: "Endpoint Security",
    type: "rss",
  },
  {
    name: "Threatdown by Malwarebytes",
    slug: "threatdown",
    url: "https://www.threatdown.com/blog/feed/",
    category: "Endpoint Security",
    type: "rss",
  },

  // ── Cloud Security ──
  {
    name: "AWS Security Blog",
    slug: "aws-security",
    url: "https://aws.amazon.com/blogs/security/feed/",
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
    name: "Orca Security",
    slug: "orca-security",
    url: "https://orca.security/resources/blog/feed/",
    category: "Cloud Security",
    type: "rss",
  },
  {
    name: "Prisma Cloud (Palo Alto)",
    slug: "prisma-cloud",
    url: "https://www.paloaltonetworks.com/blog/prisma-cloud/feed/",
    category: "Cloud Security",
    type: "rss",
  },
  {
    name: "Netskope Blog",
    slug: "netskope",
    url: "https://www.netskope.com/blog/feed",
    category: "Cloud Security",
    type: "rss",
  },

  // ── Container Security ──
  {
    name: "Aqua Security",
    slug: "aqua-security",
    url: "https://blog.aquasec.com/rss.xml",
    category: "Container Security",
    type: "rss",
  },
  {
    name: "Anchore",
    slug: "anchore",
    url: "https://anchore.com/blog/feed/",
    category: "Container Security",
    type: "rss",
  },
  {
    name: "Chainguard",
    slug: "chainguard",
    url: "https://www.chainguard.dev/unchained/rss.xml",
    category: "Container Security",
    type: "rss",
  },
  {
    name: "Kubernetes Security",
    slug: "k8s-security",
    url: "https://kubernetes.io/feed.xml",
    category: "Container Security",
    type: "rss",
  },

  // ── Vulnerability ──
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
    name: "NIST NVD",
    slug: "nist-nvd",
    url: "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss-analyzed.xml",
    category: "Vulnerability",
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
    name: "Nuclei Templates",
    slug: "nuclei-templates",
    url: "https://blog.projectdiscovery.io/rss/",
    category: "Vulnerability",
    type: "rss",
  },
  { name: "VulnDB", slug: "vulndb", url: "https://vuldb.com/?rss.recent", category: "Vulnerability", type: "rss" },
  {
    name: "Greenbone Blog",
    slug: "greenbone",
    url: "https://www.greenbone.net/en/blog/feed/",
    category: "Vulnerability",
    type: "rss",
  },
  {
    name: "Assetnote",
    slug: "assetnote",
    url: "https://blog.assetnote.io/feed.xml",
    category: "Vulnerability",
    type: "rss",
  },
  {
    name: "Watchtowr Labs",
    slug: "watchtowr",
    url: "https://labs.watchtowr.com/rss/",
    category: "Vulnerability",
    type: "rss",
  },

  // ── Government / CERT ──
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
  { name: "ENISA", slug: "enisa", url: "https://www.enisa.europa.eu/rss.xml", category: "Government", type: "rss" },
  {
    name: "NCSC UK",
    slug: "ncsc-uk",
    url: "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml",
    category: "Government",
    type: "rss",
  },
  {
    name: "CERT-FR (ANSSI)",
    slug: "cert-fr",
    url: "https://www.cert.ssi.gouv.fr/feed/",
    category: "Government",
    type: "rss",
  },
  {
    name: "JPCERT/CC",
    slug: "jpcert",
    url: "https://www.jpcert.or.jp/english/rss/jpcert-en.rdf",
    category: "Government",
    type: "rss",
  },

  // ── Vendor Security ──
  {
    name: "Microsoft Security",
    slug: "microsoft-security",
    url: "https://www.microsoft.com/en-us/security/blog/feed/",
    category: "Vendor Security",
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
  {
    name: "Cisco Security Advisories",
    slug: "cisco-advisories",
    url: "https://tools.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml",
    category: "Vendor Security",
    type: "rss",
  },
  {
    name: "Red Hat Security Blog",
    slug: "redhat-security",
    url: "https://www.redhat.com/en/blog/rss.xml",
    category: "Vendor Security",
    type: "rss",
  },
  {
    name: "Ubuntu Security Notices",
    slug: "ubuntu-usn",
    url: "https://ubuntu.com/security/notices/rss.xml",
    category: "Vendor Security",
    type: "rss",
  },
  {
    name: "Debian Security",
    slug: "debian-security",
    url: "https://www.debian.org/security/dsa",
    category: "Vendor Security",
    type: "rss",
  },
  {
    name: "Fortinet PSIRT",
    slug: "fortinet-psirt",
    url: "https://filestore.fortinet.com/fortiguard/rss/ir.xml",
    category: "Vendor Security",
    type: "rss",
  },
  {
    name: "Palo Alto Security Advisories",
    slug: "paloalto-psirt",
    url: "https://security.paloaltonetworks.com/rss.xml",
    category: "Vendor Security",
    type: "rss",
  },

  // ── Email Security ──
  {
    name: "Valimail Blog",
    slug: "valimail",
    url: "https://www.valimail.com/blog/feed/",
    category: "Email Security",
    type: "rss",
  },

  // ── Web Security ──
  {
    name: "Wordfence",
    slug: "wordfence",
    url: "https://www.wordfence.com/blog/feed/",
    category: "Web Security",
    type: "rss",
  },
  { name: "OWASP Blog", slug: "owasp", url: "https://owasp.org/feed.xml", category: "Web Security", type: "rss" },
  {
    name: "Imperva Blog",
    slug: "imperva",
    url: "https://www.imperva.com/blog/feed/",
    category: "Web Security",
    type: "rss",
  },
  {
    name: "Detectify Labs",
    slug: "detectify",
    url: "https://labs.detectify.com/feed/",
    category: "Web Security",
    type: "rss",
  },
  {
    name: "Wallarm Blog",
    slug: "wallarm",
    url: "https://lab.wallarm.com/feed/",
    category: "Web Security",
    type: "rss",
  },
  { name: "Sekurak", slug: "sekurak", url: "https://sekurak.pl/feed/", category: "Web Security", type: "rss" },

  // ── Identity & Access ──
  { name: "Auth0 Blog", slug: "auth0", url: "https://auth0.com/blog/rss.xml", category: "Identity", type: "rss" },
  {
    name: "Ping Identity",
    slug: "ping-identity",
    url: "https://www.pingidentity.com/en/resources/blog.feed.xml",
    category: "Identity",
    type: "rss",
  },
  {
    name: "CyberArk Blog",
    slug: "cyberark",
    url: "https://www.cyberark.com/blog/feed/",
    category: "Identity",
    type: "rss",
  },
  {
    name: "ForgeRock Blog",
    slug: "forgerock",
    url: "https://www.forgerock.com/blog/feed",
    category: "Identity",
    type: "rss",
  },

  // ── Supply Chain ──
  { name: "Snyk Security", slug: "snyk", url: "https://snyk.io/blog/feed/", category: "Supply Chain", type: "rss" },
  {
    name: "Sonatype Blog",
    slug: "sonatype",
    url: "https://blog.sonatype.com/rss.xml",
    category: "Supply Chain",
    type: "rss",
  },
  {
    name: "JFrog Security",
    slug: "jfrog-security",
    url: "https://jfrog.com/blog/category/security/feed/",
    category: "Supply Chain",
    type: "rss",
  },
  {
    name: "Endor Labs",
    slug: "endor-labs",
    url: "https://www.endorlabs.com/blog/rss.xml",
    category: "Supply Chain",
    type: "rss",
  },

  // ── Detection Engineering ──
  {
    name: "Elastic Security Labs",
    slug: "elastic-security",
    url: "https://www.elastic.co/security-labs/rss/feed.xml",
    category: "Detection Engineering",
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
  {
    name: "Red Canary",
    slug: "red-canary",
    url: "https://redcanary.com/blog/feed/",
    category: "Detection Engineering",
    type: "rss",
  },
  {
    name: "Florian Roth (Neo23x0)",
    slug: "neo23x0",
    url: "https://medium.com/feed/@cyb3rops",
    category: "Detection Engineering",
    type: "rss",
  },

  // ── Red Team / Offensive ──
  {
    name: "Adam Chester",
    slug: "adam-chester",
    url: "https://blog.xpnsec.com/rss/",
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
  { name: "MDSec", slug: "mdsec", url: "https://www.mdsec.co.uk/feed/", category: "Red Team", type: "rss" },
  { name: "Outflank", slug: "outflank", url: "https://outflank.nl/blog/feed/", category: "Red Team", type: "rss" },
  {
    name: "Praetorian",
    slug: "praetorian",
    url: "https://www.praetorian.com/blog/feed/",
    category: "Red Team",
    type: "rss",
  },

  // ── Penetration Testing ──
  {
    name: "Pentest Partners",
    slug: "pentest-partners",
    url: "https://www.pentestpartners.com/security-blog/feed/",
    category: "Penetration Testing",
    type: "rss",
  },
  {
    name: "PortSwigger Research",
    slug: "portswigger-research",
    url: "https://portswigger.net/research/rss",
    category: "Penetration Testing",
    type: "rss",
  },
  {
    name: "Bishop Fox",
    slug: "bishop-fox",
    url: "https://bishopfox.com/blog/feed",
    category: "Penetration Testing",
    type: "rss",
  },
  {
    name: "Cobalt Blog",
    slug: "cobalt",
    url: "https://www.cobalt.io/blog/rss.xml",
    category: "Penetration Testing",
    type: "rss",
  },

  // ── Incident Response ──
  {
    name: "SANS ISC",
    slug: "sans-isc",
    url: "https://isc.sans.edu/rssfeed.xml",
    category: "Incident Response",
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
    name: "Velociraptor Blog",
    slug: "velociraptor",
    url: "https://docs.velociraptor.app/blog/index.xml",
    category: "Incident Response",
    type: "rss",
  },
  {
    name: "Volatility Foundation",
    slug: "volatility",
    url: "https://volatility-labs.blogspot.com/feeds/posts/default",
    category: "Incident Response",
    type: "rss",
  },
  {
    name: "Cyber Triage",
    slug: "cyber-triage",
    url: "https://www.cybertriage.com/blog/feed/",
    category: "Incident Response",
    type: "rss",
  },

  // ── ICS/OT Security ──
  {
    name: "ICS-CERT Advisories",
    slug: "ics-cert",
    url: "https://www.cisa.gov/uscert/ics/advisories/advisories.xml",
    category: "ICS/OT Security",
    type: "rss",
  },
  {
    name: "Forescout Research",
    slug: "forescout-research",
    url: "https://www.forescout.com/blog/feed/",
    category: "ICS/OT Security",
    type: "rss",
  },

  // ── Research ──
  {
    name: "Trail of Bits",
    slug: "trail-of-bits",
    url: "https://blog.trailofbits.com/feed/",
    category: "Research",
    type: "rss",
  },
  { name: "Citizen Lab", slug: "citizen-lab", url: "https://citizenlab.ca/feed/", category: "Research", type: "rss" },
  {
    name: "ACM Security",
    slug: "acm-security",
    url: "https://dl.acm.org/action/showFeed?type=etoc&feed=rss&jc=tissec",
    category: "Research",
    type: "rss",
  },
  {
    name: "Arxiv Crypto/Security",
    slug: "arxiv-crypto",
    url: "https://rss.arxiv.org/rss/cs.CR",
    category: "Research",
    type: "rss",
  },
  {
    name: "Internet Storm Center",
    slug: "isc-diary",
    url: "https://isc.sans.edu/rssfeed_full.xml",
    category: "Research",
    type: "rss",
  },
  {
    name: "Include Security",
    slug: "include-security",
    url: "https://blog.includesecurity.com/feed/",
    category: "Research",
    type: "rss",
  },

  // ── SIEM & Observability ──
  {
    name: "Sumo Logic",
    slug: "sumo-logic",
    url: "https://www.sumologic.com/blog/feed/",
    category: "SIEM",
    type: "rss",
  },
  {
    name: "Securonix Blog",
    slug: "securonix",
    url: "https://www.securonix.com/blog/feed/",
    category: "SIEM",
    type: "rss",
  },

  // ── Bug Bounty ──
  {
    name: "Intigriti Blog",
    slug: "intigriti",
    url: "https://blog.intigriti.com/feed/",
    category: "Bug Bounty",
    type: "rss",
  },

  // ── Exploit ──
  {
    name: "Exploit-DB",
    slug: "exploit-db",
    url: "https://www.exploit-db.com/rss.xml",
    category: "Exploit",
    type: "rss",
  },

  // ── Phishing ──

  // ── Data Breaches & Privacy ──
  {
    name: "Troy Hunt",
    slug: "troy-hunt",
    url: "https://www.troyhunt.com/rss/",
    category: "Data Breaches",
    type: "rss",
  },
  {
    name: "Schneier on Security",
    slug: "schneier-on-security",
    url: "https://www.schneier.com/feed/",
    category: "Cryptography",
    type: "rss",
  },
  {
    name: "DataBreaches.net",
    slug: "databreaches-net",
    url: "https://www.databreaches.net/feed/",
    category: "Data Breaches",
    type: "rss",
  },

  // ── Managed Detection ──
  {
    name: "Huntress",
    slug: "huntress",
    url: "https://www.huntress.com/blog/rss.xml",
    category: "Managed Detection",
    type: "rss",
  },
  {
    name: "Todyl Blog",
    slug: "todyl",
    url: "https://www.todyl.com/blog/rss.xml",
    category: "Managed Detection",
    type: "rss",
  },

  // ── Frameworks ──
  {
    name: "MITRE ATT&CK Updates",
    slug: "mitre-attack",
    url: "https://medium.com/feed/mitre-attack/",
    category: "Framework",
    type: "rss",
  },
  {
    name: "MISP Threat Sharing",
    slug: "misp",
    url: "https://www.misp-project.org/feed.xml",
    category: "Framework",
    type: "rss",
  },
  {
    name: "NIST Cybersecurity",
    slug: "nist-csf",
    url: "https://www.nist.gov/blogs/cybersecurity-insights/rss.xml",
    category: "Framework",
    type: "rss",
  },

  // ── Podcast / Newsletter ──
  {
    name: "Risky Business",
    slug: "risky-business",
    url: "https://risky.biz/feeds/risky-business/",
    category: "Podcast",
    type: "rss",
  },
  {
    name: "Darknet Diaries",
    slug: "darknet-diaries",
    url: "https://feeds.megaphone.fm/darknetdiaries",
    category: "Podcast",
    type: "rss",
  },
  { name: "Security Now", slug: "security-now", url: "https://feeds.twit.tv/sn.xml", category: "Podcast", type: "rss" },
  {
    name: "tl;dr sec Newsletter",
    slug: "tldr-sec",
    url: "https://tldrsec.com/feed.xml",
    category: "Podcast",
    type: "rss",
  },
  {
    name: "This Week in Security",
    slug: "this-week-security",
    url: "https://this.weekinsecurity.com/feed/",
    category: "Podcast",
    type: "rss",
  },

  // ── Compliance & GRC ──
  {
    name: "BitSight Blog",
    slug: "bitsight",
    url: "https://www.bitsight.com/blog/rss.xml",
    category: "Compliance",
    type: "rss",
  },
  {
    name: "KnowBe4 Blog",
    slug: "knowbe4",
    url: "https://blog.knowbe4.com/rss.xml",
    category: "Compliance",
    type: "rss",
  },

  // ── Network Security ──
  {
    name: "Vectra AI Blog",
    slug: "vectra",
    url: "https://www.vectra.ai/blog/rss.xml",
    category: "Network Security",
    type: "rss",
  },
  {
    name: "Snort Blog",
    slug: "snort",
    url: "https://blog.snort.org/feeds/posts/default",
    category: "Network Security",
    type: "rss",
  },
  { name: "Suricata", slug: "suricata", url: "https://suricata.io/feed/", category: "Network Security", type: "rss" },

  // ── Privacy & Encryption ──
  {
    name: "EFF Deeplinks",
    slug: "eff-deeplinks",
    url: "https://www.eff.org/rss/updates.xml",
    category: "Privacy",
    type: "rss",
  },
  {
    name: "Privacy International",
    slug: "privacy-intl",
    url: "https://privacyinternational.org/rss.xml",
    category: "Privacy",
    type: "rss",
  },
  {
    name: "Let's Encrypt Blog",
    slug: "letsencrypt",
    url: "https://letsencrypt.org/feed.xml",
    category: "Privacy",
    type: "rss",
  },

  // ── Mobile Security ──
  {
    name: "NowSecure Blog",
    slug: "nowsecure",
    url: "https://www.nowsecure.com/blog/feed/",
    category: "Mobile Security",
    type: "rss",
  },

  // ── DevSecOps ──
  {
    name: "GitGuardian Blog",
    slug: "gitguardian",
    url: "https://blog.gitguardian.com/rss/",
    category: "DevSecOps",
    type: "rss",
  },
  {
    name: "Contrast Security",
    slug: "contrast",
    url: "https://www.contrastsecurity.com/security-influencers/rss.xml",
    category: "DevSecOps",
    type: "rss",
  },
  {
    name: "Veracode Blog",
    slug: "veracode",
    url: "https://www.veracode.com/blog/feed",
    category: "DevSecOps",
    type: "rss",
  },
  {
    name: "Checkmarx Blog",
    slug: "checkmarx",
    url: "https://checkmarx.com/blog/feed/",
    category: "DevSecOps",
    type: "rss",
  },
  {
    name: "Hadolint Blog",
    slug: "hadolint",
    url: "https://github.com/hadolint/hadolint/releases.atom",
    category: "DevSecOps",
    type: "rss",
  },
  {
    name: "OWASP ZAP",
    slug: "owasp-zap",
    url: "https://www.zaproxy.org/blog/index.xml",
    category: "DevSecOps",
    type: "rss",
  },

  // ── Ransomware / Darkweb ──
  {
    name: "Ransomware.live",
    slug: "ransomware-live",
    url: "https://www.ransomware.live/rss.xml",
    category: "Ransomware",
    type: "rss",
  },
  {
    name: "ID Ransomware Blog",
    slug: "id-ransomware",
    url: "https://id-ransomware.blogspot.com/feeds/posts/default",
    category: "Ransomware",
    type: "rss",
  },
  { name: "Kela Cyber Intel", slug: "kela", url: "https://ke-la.com/blog/feed/", category: "Ransomware", type: "rss" },

  // ── AI Security ──
  {
    name: "NVIDIA AI Security",
    slug: "nvidia-ai-sec",
    url: "https://blogs.nvidia.com/feed/",
    category: "AI Security",
    type: "rss",
  },
  {
    name: "Berryville ML",
    slug: "berryville-ml",
    url: "https://berryvilleiml.com/feed/",
    category: "AI Security",
    type: "rss",
  },
];

const feedArticleCache = new Map<string, { articles: ThreatIntelArticle[]; fetchedAt: number }>();
const feedHealthHistory = new Map<string, FeedHealthEntry[]>();
const feedEnabled = new Map<string, boolean>();
const ORG_FEED_ENABLED = new Map<string, boolean>();

function orgFeedKey(orgId: string, slug: string): string {
  return `${orgId}:${slug}`;
}

function isFeedEnabledForOrg(slug: string, orgId?: string): boolean {
  if (orgId) {
    const orgKey = orgFeedKey(orgId, slug);
    if (ORG_FEED_ENABLED.has(orgKey)) return ORG_FEED_ENABLED.get(orgKey) !== false;
  }
  return feedEnabled.get(slug) !== false;
}
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

export function getThreatIntelFeedStatuses(orgId?: string): ThreatIntelFeedStatus[] {
  return RSS_FEEDS.map((def) => {
    const cached = feedArticleCache.get(def.slug);
    const enabled = isFeedEnabledForOrg(def.slug, orgId);
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

export function setThreatIntelFeedEnabled(slug: string, enabled: boolean, orgId?: string): boolean {
  if (!ALL_SLUGS.has(slug)) return false;
  if (orgId) {
    ORG_FEED_ENABLED.set(orgFeedKey(orgId, slug), enabled);
  } else {
    feedEnabled.set(slug, enabled);
  }
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
  let articles: ThreatIntelArticle[];
  try {
    articles = normalizeRSSItems(def.url, feed, fetchedAt);
  } catch (normErr: unknown) {
    const msg = normErr instanceof Error ? normErr.message : String(normErr);
    recordFeedHealth(slug, {
      timestamp: fetchedAt.toISOString(),
      status: "error",
      articleCount: 0,
      responseTimeMs: elapsed,
      errorMessage: `Normalization failed: ${msg.slice(0, 300)}`,
    });
    return { articles: [], error: `Normalization failed: ${msg.slice(0, 300)}` };
  }
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

export async function fetchAllThreatIntelFeeds(force: boolean = false, orgId?: string): Promise<FeedAggregationResult> {
  const started = Date.now();
  const enabledFeeds = RSS_FEEDS.filter((f) => isFeedEnabledForOrg(f.slug, orgId));

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
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { slug: def.slug, url: def.url, articles: [] as ThreatIntelArticle[], error: msg };
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

// ─── AI Relevance Scoring ───────────────────────────────────────────────────

interface OrgContext {
  orgId: string;
  orgName: string;
  industry?: string;
  size?: string;
  threatProfile?: string;
}

/** Cache: Map<"orgId:articleId" → { score, reason, scoredAt }> */
const relevanceScoreCache = new Map<string, { score: number; reason: string; scoredAt: number }>();
const RELEVANCE_CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const RELEVANCE_BATCH_SIZE = 20;

function relevanceCacheKey(orgId: string, articleId: string): string {
  return `${orgId}:${articleId}`;
}

function getCachedRelevance(orgId: string, articleId: string): { score: number; reason: string } | null {
  const key = relevanceCacheKey(orgId, articleId);
  const cached = relevanceScoreCache.get(key);
  if (!cached) return null;
  if (Date.now() - cached.scoredAt > RELEVANCE_CACHE_TTL_MS) {
    relevanceScoreCache.delete(key);
    return null;
  }
  return { score: cached.score, reason: cached.reason };
}

function setCachedRelevance(orgId: string, articleId: string, score: number, reason: string): void {
  const key = relevanceCacheKey(orgId, articleId);
  relevanceScoreCache.set(key, { score, reason, scoredAt: Date.now() });
}

async function scoreArticleBatch(
  articles: ThreatIntelArticle[],
  orgCtx: OrgContext,
): Promise<Array<{ articleId: string; score: number; reason: string }>> {
  const articleSummaries = articles
    .map((a, i) => {
      const summary = a.summaryText.slice(0, 200);
      return `[${i}] "${a.title}" (${a.source}) — ${summary}`;
    })
    .join("\n");

  const systemPrompt = `You are a cybersecurity threat intelligence analyst. Score each article for relevance to the target organization on a scale of 1-10.

Organization Context:
- Name: ${orgCtx.orgName}
- Industry: ${orgCtx.industry || "Technology"}
- Size: ${orgCtx.size || "Mid-market"}
- Threat Profile: ${orgCtx.threatProfile || "Standard enterprise"}

Scoring Criteria:
- 9-10: Directly affects this org's industry, tech stack, or active threat actors targeting them
- 7-8: Highly relevant vulnerability, attack technique, or threat actor in their sector
- 5-6: Generally relevant cybersecurity news or research
- 3-4: Tangentially related, different industry/tech but useful awareness
- 1-2: Not relevant to this organization

Respond ONLY with valid JSON array. No markdown, no explanation outside the JSON.
Format: [{"idx": 0, "score": 7, "reason": "brief reason"}]`;

  const userMessage = `Score these ${articles.length} articles for relevance to ${orgCtx.orgName}:\n\n${articleSummaries}`;

  try {
    const result = await invokeModel({
      modelId: appConfig.ai.triage.modelId,
      backend: appConfig.ai.backend,
      systemPrompt,
      userMessage,
      maxTokens: appConfig.ai.triage.maxTokens,
      temperature: appConfig.ai.triage.temperature,
      topP: 0.9,
      orgId: orgCtx.orgId,
      promptId: "threat-intel-relevance-scoring",
      tier: "triage",
    });

    // Extract JSON from response — handle markdown code fences
    let jsonText = result.text.trim();
    const fenceMatch = jsonText.match(/```(?:json)?\s*([\s\S]*?)```/);
    if (fenceMatch) jsonText = fenceMatch[1].trim();

    const parsed = JSON.parse(jsonText) as Array<{ idx: number; score: number; reason: string }>;
    return parsed
      .map((p) => ({
        articleId: articles[p.idx]?.id ?? "",
        score: Math.max(1, Math.min(10, Math.round(p.score))),
        reason: (p.reason || "").slice(0, 200),
      }))
      .filter((p) => p.articleId);
  } catch (err) {
    logger.warn("AI relevance scoring failed, using default scores", {
      error: err instanceof Error ? err.message : String(err),
      articleCount: articles.length,
    });
    // Fall back to keyword-based heuristic scoring
    return articles.map((a) => ({
      articleId: a.id,
      score: heuristicRelevanceScore(a, orgCtx),
      reason: "Heuristic score (AI unavailable)",
    }));
  }
}

function heuristicRelevanceScore(article: ThreatIntelArticle, orgCtx: OrgContext): number {
  const text = `${article.title} ${article.summaryText} ${article.categories.join(" ")}`.toLowerCase();
  const industry = (orgCtx.industry || "technology").toLowerCase();
  let score = 5; // base

  // Industry keyword match
  const industryKeywords = getIndustryKeywords(industry);
  for (const kw of industryKeywords) {
    if (text.includes(kw)) {
      score += 1;
      break;
    }
  }

  // Critical/high severity indicators
  const criticalTerms = [
    "critical",
    "zero-day",
    "0-day",
    "actively exploited",
    "cve-",
    "ransomware",
    "apt",
    "breach",
    "rce",
    "remote code execution",
  ];
  for (const term of criticalTerms) {
    if (text.includes(term)) {
      score += 1;
      break;
    }
  }

  // Recency boost
  if (article.publishedAt) {
    const ageHours = (Date.now() - new Date(article.publishedAt).getTime()) / (1000 * 60 * 60);
    if (ageHours < 24) score += 1;
    else if (ageHours < 72) score += 0.5;
  }

  return Math.max(1, Math.min(10, Math.round(score)));
}

function getIndustryKeywords(industry: string): string[] {
  const map: Record<string, string[]> = {
    technology: ["saas", "cloud", "api", "software", "devops", "container", "kubernetes", "aws", "azure", "gcp"],
    finance: ["banking", "fintech", "swift", "payment", "pci", "financial", "credit card", "fraud", "trading"],
    healthcare: ["hipaa", "healthcare", "medical", "hospital", "phi", "patient", "ehr", "pharmaceutical"],
    government: ["government", "federal", "state", "military", "defense", "intelligence", "classified", "cisa"],
    retail: ["ecommerce", "retail", "pos", "point of sale", "magecart", "payment", "shopify"],
    energy: ["scada", "ics", "ot", "industrial", "power grid", "pipeline", "energy", "utility"],
    education: ["university", "education", "school", "academic", "student", "ferpa"],
    manufacturing: ["manufacturing", "ics", "scada", "plc", "ot", "industrial", "supply chain"],
    telecom: ["telecom", "5g", "carrier", "mobile network", "ss7", "isps"],
  };
  return map[industry] || map["technology"] || [];
}

export async function scoreArticlesForOrg(
  articles: ThreatIntelArticle[],
  orgCtx: OrgContext,
): Promise<ThreatIntelArticle[]> {
  // Check cache first, collect uncached
  const results: ThreatIntelArticle[] = [];
  const uncached: ThreatIntelArticle[] = [];

  for (const article of articles) {
    const cached = getCachedRelevance(orgCtx.orgId, article.id);
    if (cached) {
      results.push({ ...article, relevanceScore: cached.score, relevanceReason: cached.reason });
    } else {
      uncached.push(article);
    }
  }

  // Score uncached in batches
  for (let i = 0; i < uncached.length; i += RELEVANCE_BATCH_SIZE) {
    const batch = uncached.slice(i, i + RELEVANCE_BATCH_SIZE);
    const scores = await scoreArticleBatch(batch, orgCtx);
    const scoredIds = new Set<string>();
    for (const { articleId, score, reason } of scores) {
      setCachedRelevance(orgCtx.orgId, articleId, score, reason);
      const article = batch.find((a) => a.id === articleId);
      if (article) {
        results.push({ ...article, relevanceScore: score, relevanceReason: reason });
        scoredIds.add(articleId);
      }
    }
    // Add any batch articles that the AI didn't score, using heuristic fallback
    for (const article of batch) {
      if (!scoredIds.has(article.id)) {
        const fallbackScore = heuristicRelevanceScore(article, orgCtx);
        setCachedRelevance(orgCtx.orgId, article.id, fallbackScore, "Heuristic score (AI partial response)");
        results.push({
          ...article,
          relevanceScore: fallbackScore,
          relevanceReason: "Heuristic score (AI partial response)",
        });
      }
    }
  }

  return results;
}

export function getCachedThreatIntelArticles(options?: {
  limit?: number;
  category?: string;
  search?: string;
  feedSlug?: string;
  orgId?: string;
  relevanceThreshold?: number;
}): ThreatIntelArticle[] {
  const categorySlugs = options?.category
    ? new Set(RSS_FEEDS.filter((f) => f.category.toLowerCase() === options.category!.toLowerCase()).map((f) => f.slug))
    : null;

  let all: ThreatIntelArticle[] = [];
  for (const [slug, cached] of Array.from(feedArticleCache.entries())) {
    if (!isFeedEnabledForOrg(slug, options?.orgId)) continue;
    if (options?.feedSlug && slug !== options.feedSlug) continue;
    if (categorySlugs && !categorySlugs.has(slug)) continue;
    all.push(...cached.articles);
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

  // Apply cached relevance scores if available
  if (options?.orgId && options?.relevanceThreshold) {
    const threshold = options.relevanceThreshold;
    const scored = deduped.map((a) => {
      const cached = getCachedRelevance(options.orgId!, a.id);
      if (cached) {
        return { ...a, relevanceScore: cached.score, relevanceReason: cached.reason };
      }
      return a;
    });
    // Filter to scored articles above threshold (unscored articles pass through)
    const filtered = scored.filter((a) => {
      if (a.relevanceScore === undefined) return true; // not yet scored — include
      return a.relevanceScore >= threshold;
    });
    const sorted = sortArticles(filtered);
    const limit = options?.limit || 500;
    return sorted.slice(0, limit);
  }

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

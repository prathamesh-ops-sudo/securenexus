/**
 * RSS Intelligence Engine
 *
 * Ingests 3640+ RSS/Atom feeds from the codex repository, categorizes them
 * into security tiers, extracts threat intelligence, IOCs, CVEs, and
 * security knowledge from articles, then feeds everything into the RAG
 * knowledge base for the AI agentic system to self-learn and improve daily.
 *
 * Architecture:
 * 1. Feed Registry — 3640 feeds categorized into 5 tiers with polling schedules
 * 2. Feed Poller — Concurrent RSS/Atom parser with rate limiting and health tracking
 * 3. Article Processor — NLP-style extraction of IOCs, CVEs, MITRE techniques, threat actors
 * 4. Knowledge Accumulator — Dedup, trend analysis, source quality scoring
 * 5. RAG Indexer — Vector embedding and indexing into knowledge base
 * 6. Self-Learning Loop — Feedback scoring, source reliability tracking, topic drift detection
 */

import fs from "fs";
import path from "path";
import { logger } from "./logger";
import { pool } from "./db";

const log = logger.child("rss-intelligence");

// ── Feed Registry Types ─────────────────────────────────────────────

export interface RSSFeedEntry {
  url: string;
  domain: string;
  tier: "tier1" | "tier2" | "tier3" | "tier4" | "tier5";
  category: string;
  pollIntervalMinutes: number;
}

export interface FeedPollResult {
  feedUrl: string;
  status: "success" | "error" | "skipped" | "rate_limited";
  articlesFound: number;
  newArticles: number;
  iocExtracted: number;
  cvesFound: number;
  techniquesFound: number;
  duration: number;
  error?: string;
}

export interface ExtractedArticle {
  feedUrl: string;
  feedDomain: string;
  feedTier: string;
  feedCategory: string;
  title: string;
  link: string;
  publishedAt: string;
  summary: string;
  fullContent: string;
  author: string | null;
  tags: string[];
  // Extracted intelligence
  iocs: ExtractedIOC[];
  cves: string[];
  mitreTechniques: string[];
  threatActors: string[];
  malwareFamilies: string[];
  targetSectors: string[];
  targetRegions: string[];
  severity: "critical" | "high" | "medium" | "low" | "info";
  confidenceScore: number;
}

export interface ExtractedIOC {
  type: "ip" | "domain" | "url" | "hash" | "email" | "cve";
  value: string;
  context: string;
}

// ── Feed Registry ───────────────────────────────────────────────────

let feedRegistry: RSSFeedEntry[] = [];

export function loadFeedRegistry(): RSSFeedEntry[] {
  try {
    const filePath = path.join(__dirname, "rss-feed-registry.json");
    const raw = fs.readFileSync(filePath, "utf-8");
    const registry = JSON.parse(raw) as RSSFeedEntry[];
    feedRegistry = registry;
    log.info(`Loaded ${registry.length} RSS feeds from registry`);
    return registry;
  } catch (err) {
    log.warn("Failed to load RSS feed registry", { error: String(err) });
    return [];
  }
}

export function getFeedRegistry(): RSSFeedEntry[] {
  if (feedRegistry.length === 0) loadFeedRegistry();
  return feedRegistry;
}

export function getFeedsByTier(tier: string): RSSFeedEntry[] {
  return getFeedRegistry().filter((f) => f.tier === tier);
}

export function getFeedsByCategory(category: string): RSSFeedEntry[] {
  return getFeedRegistry().filter((f) => f.category === category);
}

export function getFeedStats(): {
  total: number;
  byTier: Record<string, number>;
  byCategory: Record<string, number>;
} {
  const registry = getFeedRegistry();
  const byTier: Record<string, number> = {};
  const byCategory: Record<string, number> = {};
  for (const feed of registry) {
    byTier[feed.tier] = (byTier[feed.tier] || 0) + 1;
    byCategory[feed.category] = (byCategory[feed.category] || 0) + 1;
  }
  return { total: registry.length, byTier, byCategory };
}

// ── IOC Extraction Patterns ─────────────────────────────────────────

const IPV4_REGEX = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
const IPV6_REGEX = /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b/g;
const DOMAIN_REGEX =
  /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|co|info|biz|xyz|top|ru|cn|de|uk|fr|jp|br|it|nl|au|ca|es|kr|in|se|no|fi|dk|cz|pl|pt|be|at|ch|ie|il|za|mx|ar|cl|tw|hk|sg|my|th|vn|ph|id|eg|ae|sa|ke|ng|gh|tz|et|ua|kz|by|ge|am|az)\b/g;
const URL_REGEX = /https?:\/\/[^\s<>"{}|\\^`\[\]]+/g;
const MD5_REGEX = /\b[a-fA-F0-9]{32}\b/g;
const SHA1_REGEX = /\b[a-fA-F0-9]{40}\b/g;
const SHA256_REGEX = /\b[a-fA-F0-9]{64}\b/g;
const EMAIL_REGEX = /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g;
const CVE_REGEX = /CVE-\d{4}-\d{4,}/gi;

// MITRE ATT&CK technique IDs
const MITRE_REGEX = /\bT\d{4}(?:\.\d{3})?\b/g;

// Threat actor name patterns
const THREAT_ACTOR_PATTERNS = [
  /\b(?:APT|apt)\s*\d{1,3}\b/g,
  /\b(?:FIN|fin)\s*\d{1,2}\b/g,
  /\b(?:Lazarus|Cozy\s*Bear|Fancy\s*Bear|Equation\s*Group|Turla|Sandworm|DarkSide|REvil|Conti|LockBit|BlackCat|ALPHV|Cl0p|Royal|Play|Black\s*Basta|Akira|Medusa|Rhysida|Volt\s*Typhoon|Salt\s*Typhoon|Charming\s*Kitten|Kimsuky|Mustang\s*Panda|Scattered\s*Spider|LAPSUS\$?|Star\s*Blizzard|Midnight\s*Blizzard|Forest\s*Blizzard|Emerald\s*Sleet|Citrine\s*Sleet)\b/gi,
];

// Malware family patterns
const MALWARE_PATTERNS = [
  /\b(?:Emotet|TrickBot|Qakbot|IcedID|BazarLoader|Cobalt\s*Strike|Metasploit|Mimikatz|BloodHound|Rubeus|Impacket|Sliver|Brute\s*Ratel|Havoc|Nighthawk|Silver\s*C2|AsyncRAT|RemcosRAT|NjRAT|DarkComet|QuasarRAT|AgentTesla|FormBook|RedLine|Raccoon|Vidar|LummaC2|StealC|Amadey|SmokeLoader|GuLoader|PrivateLoader|Pikabot|DarkGate|JaskaGO|XWorm|Remcos|WarZone|Pegasus|Predator|Chrysaor|FinSpy|Candiru)\b/gi,
];

// Target sectors
const SECTOR_PATTERNS = [
  /\b(?:financial|banking|finance|fintech|healthcare|health|medical|pharma|government|govt|federal|military|defense|energy|utilities|power|grid|oil|gas|telecom|telecommunications|education|university|academic|retail|ecommerce|manufacturing|industrial|transportation|aviation|maritime|shipping|legal|law\s*firm|media|entertainment|technology|tech|software|saas|cloud|critical\s*infrastructure|water|agriculture)\b/gi,
];

// ── Article Text Extraction ─────────────────────────────────────────

function extractIOCsFromText(text: string): ExtractedIOC[] {
  const iocs: ExtractedIOC[] = [];
  const seen = new Set<string>();

  // IPs
  const ips = text.match(IPV4_REGEX) || [];
  for (const ip of ips) {
    // Skip private/reserved IPs
    if (ip.startsWith("10.") || ip.startsWith("192.168.") || ip.startsWith("127.") || ip.startsWith("0.")) continue;
    if (ip.startsWith("172.") && parseInt(ip.split(".")[1]) >= 16 && parseInt(ip.split(".")[1]) <= 31) continue;
    const key = `ip:${ip}`;
    if (seen.has(key)) continue;
    seen.add(key);
    // Find context (surrounding text)
    const idx = text.indexOf(ip);
    const ctx = text.slice(Math.max(0, idx - 50), Math.min(text.length, idx + ip.length + 50)).trim();
    iocs.push({ type: "ip", value: ip, context: ctx });
  }

  // Domains
  const domains = text.match(DOMAIN_REGEX) || [];
  for (const domain of domains) {
    // Skip common non-IOC domains
    const skipDomains = [
      "github.com",
      "google.com",
      "microsoft.com",
      "apple.com",
      "twitter.com",
      "facebook.com",
      "linkedin.com",
      "youtube.com",
      "wikipedia.org",
      "medium.com",
      "wordpress.com",
      "blogspot.com",
      "amazonaws.com",
      "cloudflare.com",
      "example.com",
    ];
    if (skipDomains.some((s) => domain.endsWith(s))) continue;
    const key = `domain:${domain}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const idx = text.indexOf(domain);
    const ctx = text.slice(Math.max(0, idx - 50), Math.min(text.length, idx + domain.length + 50)).trim();
    iocs.push({ type: "domain", value: domain.toLowerCase(), context: ctx });
  }

  // Hashes (SHA-256 first, then SHA-1, then MD5 to avoid substring matches)
  const sha256s = text.match(SHA256_REGEX) || [];
  for (const hash of sha256s) {
    const key = `hash:${hash}`;
    if (seen.has(key)) continue;
    seen.add(key);
    iocs.push({ type: "hash", value: hash.toLowerCase(), context: "" });
  }

  const sha1s = text.match(SHA1_REGEX) || [];
  for (const hash of sha1s) {
    if (seen.has(`hash:${hash}`)) continue;
    seen.add(`hash:${hash}`);
    iocs.push({ type: "hash", value: hash.toLowerCase(), context: "" });
  }

  const md5s = text.match(MD5_REGEX) || [];
  for (const hash of md5s) {
    if (seen.has(`hash:${hash}`)) continue;
    // Avoid false positives — check it's not a common hex pattern
    if (/^[0-9]+$/.test(hash) || /^[a-f]+$/.test(hash)) continue;
    seen.add(`hash:${hash}`);
    iocs.push({ type: "hash", value: hash.toLowerCase(), context: "" });
  }

  // CVEs
  const cves = text.match(CVE_REGEX) || [];
  for (const cve of cves) {
    const normalized = cve.toUpperCase();
    const key = `cve:${normalized}`;
    if (seen.has(key)) continue;
    seen.add(key);
    iocs.push({ type: "cve", value: normalized, context: "" });
  }

  // Emails (only suspicious-looking ones)
  const emails = text.match(EMAIL_REGEX) || [];
  for (const email of emails) {
    const domain = email.split("@")[1];
    const skipEmailDomains = [
      "gmail.com",
      "yahoo.com",
      "outlook.com",
      "hotmail.com",
      "protonmail.com",
      "example.com",
      "test.com",
    ];
    if (skipEmailDomains.some((s) => domain === s)) continue;
    const key = `email:${email}`;
    if (seen.has(key)) continue;
    seen.add(key);
    iocs.push({ type: "email", value: email.toLowerCase(), context: "" });
  }

  return iocs;
}

function extractMitreTechniques(text: string): string[] {
  const matches = text.match(MITRE_REGEX) || [];
  return Array.from(new Set(matches.map((m) => m.toUpperCase())));
}

function extractCVEs(text: string): string[] {
  const matches = text.match(CVE_REGEX) || [];
  return Array.from(new Set(matches.map((m) => m.toUpperCase())));
}

function extractThreatActors(text: string): string[] {
  const actors = new Set<string>();
  for (const pattern of THREAT_ACTOR_PATTERNS) {
    const matches = text.match(pattern) || [];
    for (const m of matches) actors.add(m.trim());
  }
  return Array.from(actors);
}

function extractMalwareFamilies(text: string): string[] {
  const families = new Set<string>();
  for (const pattern of MALWARE_PATTERNS) {
    const matches = text.match(pattern) || [];
    for (const m of matches) families.add(m.trim());
  }
  return Array.from(families);
}

function extractTargetSectors(text: string): string[] {
  const sectors = new Set<string>();
  for (const pattern of SECTOR_PATTERNS) {
    const matches = text.match(pattern) || [];
    for (const m of matches) sectors.add(m.trim().toLowerCase());
  }
  return Array.from(sectors);
}

function assessSeverity(article: {
  iocs: ExtractedIOC[];
  cves: string[];
  mitreTechniques: string[];
  threatActors: string[];
  malwareFamilies: string[];
  title: string;
}): "critical" | "high" | "medium" | "low" | "info" {
  const titleLower = article.title.toLowerCase();

  // Critical indicators
  if (titleLower.includes("zero-day") || titleLower.includes("0-day") || titleLower.includes("actively exploited"))
    return "critical";
  if (article.threatActors.length > 0 && article.malwareFamilies.length > 0) return "critical";
  if (article.cves.length > 3 && article.iocs.length > 5) return "critical";

  // High indicators
  if (article.cves.length > 0 && article.iocs.length > 0) return "high";
  if (article.threatActors.length > 0) return "high";
  if (article.malwareFamilies.length > 0) return "high";
  if (titleLower.includes("ransomware") || titleLower.includes("breach") || titleLower.includes("attack"))
    return "high";

  // Medium
  if (article.cves.length > 0 || article.iocs.length > 2) return "medium";
  if (article.mitreTechniques.length > 0) return "medium";
  if (titleLower.includes("vulnerability") || titleLower.includes("exploit")) return "medium";

  // Low
  if (article.iocs.length > 0) return "low";

  return "info";
}

function calculateConfidence(
  article: {
    feedTier: string;
    iocs: ExtractedIOC[];
    cves: string[];
    mitreTechniques: string[];
    threatActors: string[];
  },
  feedTier: string,
): number {
  let score = 50; // base

  // Tier bonus
  const tierBonuses: Record<string, number> = { tier1: 30, tier2: 20, tier3: 15, tier4: 10, tier5: 5 };
  score += tierBonuses[feedTier] || 0;

  // Content richness
  if (article.iocs.length > 0) score += Math.min(article.iocs.length * 2, 10);
  if (article.cves.length > 0) score += Math.min(article.cves.length * 3, 15);
  if (article.mitreTechniques.length > 0) score += Math.min(article.mitreTechniques.length * 2, 10);
  if (article.threatActors.length > 0) score += 5;

  return Math.min(score, 100);
}

// ── RSS/Atom Parsing ────────────────────────────────────────────────

interface RSSItem {
  title: string;
  link: string;
  description: string;
  pubDate: string;
  author: string | null;
  categories: string[];
  content: string;
}

function parseRSSXml(xml: string): RSSItem[] {
  const items: RSSItem[] = [];

  // Try RSS 2.0 format
  const rssItemRegex = /<item>([\s\S]*?)<\/item>/gi;
  let match;
  while ((match = rssItemRegex.exec(xml)) !== null) {
    const block = match[1];
    items.push({
      title: extractTag(block, "title"),
      link: extractTag(block, "link") || extractAttr(block, "link", "href"),
      description: extractTag(block, "description") || extractTag(block, "summary"),
      pubDate:
        extractTag(block, "pubDate") ||
        extractTag(block, "published") ||
        extractTag(block, "updated") ||
        extractTag(block, "dc:date"),
      author: extractTag(block, "author") || extractTag(block, "dc:creator"),
      categories: extractAllTags(block, "category"),
      content: extractTag(block, "content:encoded") || extractTag(block, "content"),
    });
  }

  // Try Atom format
  if (items.length === 0) {
    const atomEntryRegex = /<entry>([\s\S]*?)<\/entry>/gi;
    while ((match = atomEntryRegex.exec(xml)) !== null) {
      const block = match[1];
      items.push({
        title: extractTag(block, "title"),
        link: extractAttr(block, "link", "href") || extractTag(block, "link"),
        description: extractTag(block, "summary") || extractTag(block, "content"),
        pubDate: extractTag(block, "published") || extractTag(block, "updated"),
        author: extractTag(block, "name") || extractTag(block, "author"),
        categories: extractAllTags(block, "category"),
        content: extractTag(block, "content") || extractTag(block, "summary"),
      });
    }
  }

  return items;
}

function extractTag(xml: string, tag: string): string {
  // Handle CDATA
  const cdataRegex = new RegExp(`<${tag}[^>]*><!\\[CDATA\\[([\\s\\S]*?)\\]\\]><\\/${tag}>`, "i");
  const cdataMatch = xml.match(cdataRegex);
  if (cdataMatch) return cdataMatch[1].trim();

  const regex = new RegExp(`<${tag}[^>]*>([\\s\\S]*?)<\\/${tag}>`, "i");
  const m = xml.match(regex);
  return m ? stripHtml(m[1].trim()) : "";
}

function extractAttr(xml: string, tag: string, attr: string): string {
  const regex = new RegExp(`<${tag}[^>]*${attr}="([^"]*)"`, "i");
  const m = xml.match(regex);
  return m ? m[1] : "";
}

function extractAllTags(xml: string, tag: string): string[] {
  const results: string[] = [];
  const regex = new RegExp(`<${tag}[^>]*>([^<]*)<\\/${tag}>`, "gi");
  let m;
  while ((m = regex.exec(xml)) !== null) {
    if (m[1].trim()) results.push(m[1].trim());
  }
  // Also handle self-closing category tags with term attribute (Atom)
  const attrRegex = new RegExp(`<${tag}[^>]*term="([^"]*)"`, "gi");
  while ((m = attrRegex.exec(xml)) !== null) {
    if (m[1].trim()) results.push(m[1].trim());
  }
  return results;
}

function stripHtml(html: string): string {
  return html
    .replace(/<[^>]*>/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&nbsp;/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

// ── Database Schema ─────────────────────────────────────────────────

export async function initializeRSSSchema(): Promise<void> {
  const client = await pool.connect();
  try {
    // RSS feed state tracking
    await client.query(`
      CREATE TABLE IF NOT EXISTS rss_feed_state (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        feed_url TEXT NOT NULL UNIQUE,
        feed_domain TEXT NOT NULL,
        tier TEXT NOT NULL DEFAULT 'tier5',
        category TEXT NOT NULL DEFAULT 'general',
        enabled BOOLEAN DEFAULT true,
        poll_interval_minutes INTEGER DEFAULT 360,
        last_polled_at TIMESTAMPTZ,
        last_success_at TIMESTAMPTZ,
        last_error TEXT,
        consecutive_errors INTEGER DEFAULT 0,
        total_articles_ingested INTEGER DEFAULT 0,
        total_iocs_extracted INTEGER DEFAULT 0,
        total_cves_found INTEGER DEFAULT 0,
        quality_score REAL DEFAULT 50,
        relevance_score REAL DEFAULT 50,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    // Ingested articles
    await client.query(`
      CREATE TABLE IF NOT EXISTS rss_articles (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        feed_url TEXT NOT NULL,
        article_url TEXT NOT NULL UNIQUE,
        title TEXT NOT NULL,
        summary TEXT,
        full_content TEXT,
        published_at TIMESTAMPTZ,
        author TEXT,
        tags TEXT[],
        feed_tier TEXT,
        feed_category TEXT,
        -- Extracted intelligence
        ioc_count INTEGER DEFAULT 0,
        cve_refs TEXT[],
        mitre_techniques TEXT[],
        threat_actors TEXT[],
        malware_families TEXT[],
        target_sectors TEXT[],
        severity TEXT DEFAULT 'info',
        confidence_score REAL DEFAULT 50,
        -- RAG integration
        rag_indexed BOOLEAN DEFAULT false,
        rag_knowledge_id UUID,
        -- Quality tracking
        usefulness_score REAL,
        feedback_count INTEGER DEFAULT 0,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    // Knowledge learning log — tracks what the AI learned each day
    await client.query(`
      CREATE TABLE IF NOT EXISTS rss_learning_log (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        learning_date DATE NOT NULL DEFAULT CURRENT_DATE,
        feeds_polled INTEGER DEFAULT 0,
        articles_ingested INTEGER DEFAULT 0,
        new_iocs INTEGER DEFAULT 0,
        new_cves INTEGER DEFAULT 0,
        new_techniques INTEGER DEFAULT 0,
        new_threat_actors INTEGER DEFAULT 0,
        new_malware_families INTEGER DEFAULT 0,
        knowledge_entries_created INTEGER DEFAULT 0,
        knowledge_entries_updated INTEGER DEFAULT 0,
        top_topics JSONB DEFAULT '[]',
        top_sources JSONB DEFAULT '[]',
        severity_distribution JSONB DEFAULT '{}',
        learning_summary TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(learning_date)
      )
    `);

    // Source quality tracking for self-learning
    await client.query(`
      CREATE TABLE IF NOT EXISTS rss_source_quality (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        feed_url TEXT NOT NULL,
        measured_at DATE NOT NULL DEFAULT CURRENT_DATE,
        articles_published INTEGER DEFAULT 0,
        articles_with_iocs INTEGER DEFAULT 0,
        articles_with_cves INTEGER DEFAULT 0,
        articles_with_techniques INTEGER DEFAULT 0,
        avg_confidence REAL DEFAULT 0,
        false_positive_rate REAL DEFAULT 0,
        timeliness_score REAL DEFAULT 50,
        uniqueness_score REAL DEFAULT 50,
        overall_quality REAL DEFAULT 50,
        UNIQUE(feed_url, measured_at)
      )
    `);

    // Create indexes
    await client.query(`CREATE INDEX IF NOT EXISTS idx_rss_articles_feed ON rss_articles (feed_url)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_rss_articles_published ON rss_articles (published_at DESC)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_rss_articles_severity ON rss_articles (severity)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_rss_articles_rag ON rss_articles (rag_indexed)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_rss_feed_state_tier ON rss_feed_state (tier)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_rss_feed_state_enabled ON rss_feed_state (enabled)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_rss_learning_log_date ON rss_learning_log (learning_date DESC)`);

    log.info("RSS intelligence schema initialized");
  } catch (err) {
    log.warn("RSS schema initialization failed", { error: String(err) });
  } finally {
    client.release();
  }
}

// ── Feed Polling Engine ─────────────────────────────────────────────

const CONCURRENT_POLLS = 10;
const FETCH_TIMEOUT_MS = 15000;
const MAX_ARTICLES_PER_FEED = 50;

async function fetchFeedXml(url: string): Promise<string | null> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

    const response = await fetch(url, {
      signal: controller.signal,
      headers: {
        "User-Agent": "SecureNexus-ThreatIntel/1.0 (+https://securenexus.aricatech.xyz)",
        Accept: "application/rss+xml, application/atom+xml, application/xml, text/xml, */*",
      },
      redirect: "follow",
    });

    clearTimeout(timeout);

    if (!response.ok) {
      return null;
    }

    const text = await response.text();
    return text;
  } catch {
    return null;
  }
}

export async function pollSingleFeed(feed: RSSFeedEntry): Promise<FeedPollResult> {
  const start = Date.now();
  const result: FeedPollResult = {
    feedUrl: feed.url,
    status: "success",
    articlesFound: 0,
    newArticles: 0,
    iocExtracted: 0,
    cvesFound: 0,
    techniquesFound: 0,
    duration: 0,
  };

  try {
    // Check if feed is due for polling
    const stateResult = await pool.query(
      "SELECT last_polled_at, consecutive_errors, enabled FROM rss_feed_state WHERE feed_url = $1",
      [feed.url],
    );

    if (stateResult.rows.length > 0) {
      const state = stateResult.rows[0];
      if (!state.enabled) {
        result.status = "skipped";
        result.duration = Date.now() - start;
        return result;
      }

      // Skip if polled recently
      if (state.last_polled_at) {
        const msSinceLastPoll = Date.now() - new Date(state.last_polled_at).getTime();
        if (msSinceLastPoll < feed.pollIntervalMinutes * 60 * 1000) {
          result.status = "skipped";
          result.duration = Date.now() - start;
          return result;
        }
      }

      // Back off on consecutive errors
      if (state.consecutive_errors > 5) {
        const backoffMs = Math.min(state.consecutive_errors * 60 * 60 * 1000, 24 * 60 * 60 * 1000);
        if (state.last_polled_at && Date.now() - new Date(state.last_polled_at).getTime() < backoffMs) {
          result.status = "rate_limited";
          result.duration = Date.now() - start;
          return result;
        }
      }
    }

    // Fetch the feed
    const xml = await fetchFeedXml(feed.url);
    if (!xml) {
      result.status = "error";
      result.error = "Failed to fetch feed";
      await updateFeedState(feed.url, feed, { error: "Fetch failed" });
      result.duration = Date.now() - start;
      return result;
    }

    // Parse RSS/Atom
    const items = parseRSSXml(xml);
    result.articlesFound = items.length;

    // Process each article
    let newCount = 0;
    let totalIocs = 0;
    let totalCves = 0;
    let totalTechniques = 0;

    for (const item of items.slice(0, MAX_ARTICLES_PER_FEED)) {
      if (!item.title || !item.link) continue;

      // Check if article already exists
      const existing = await pool.query("SELECT id FROM rss_articles WHERE article_url = $1", [item.link]);
      if (existing.rows.length > 0) continue;

      // Extract intelligence from article text
      const fullText = `${item.title} ${item.description} ${item.content}`;
      const iocs = extractIOCsFromText(fullText);
      const cves = extractCVEs(fullText);
      const techniques = extractMitreTechniques(fullText);
      const actors = extractThreatActors(fullText);
      const malware = extractMalwareFamilies(fullText);
      const sectors = extractTargetSectors(fullText);

      const articleData = {
        feedTier: feed.tier,
        iocs,
        cves,
        mitreTechniques: techniques,
        threatActors: actors,
        malwareFamilies: malware,
        title: item.title,
      };

      const severity = assessSeverity(articleData);
      const confidence = calculateConfidence(articleData, feed.tier);

      // Insert article
      try {
        await pool.query(
          `INSERT INTO rss_articles (
            feed_url, article_url, title, summary, full_content, published_at,
            author, tags, feed_tier, feed_category, ioc_count, cve_refs,
            mitre_techniques, threat_actors, malware_families, target_sectors,
            severity, confidence_score
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
          ON CONFLICT (article_url) DO NOTHING`,
          [
            feed.url,
            item.link,
            item.title.slice(0, 500),
            (item.description || "").slice(0, 2000),
            (item.content || item.description || "").slice(0, 10000),
            item.pubDate ? new Date(item.pubDate) : new Date(),
            item.author,
            item.categories.length > 0 ? item.categories : null,
            feed.tier,
            feed.category,
            iocs.length,
            cves.length > 0 ? cves : null,
            techniques.length > 0 ? techniques : null,
            actors.length > 0 ? actors : null,
            malware.length > 0 ? malware : null,
            sectors.length > 0 ? sectors : null,
            severity,
            confidence,
          ],
        );

        newCount++;
        totalIocs += iocs.length;
        totalCves += cves.length;
        totalTechniques += techniques.length;
      } catch (err) {
        // Skip duplicate or error articles
      }
    }

    result.newArticles = newCount;
    result.iocExtracted = totalIocs;
    result.cvesFound = totalCves;
    result.techniquesFound = totalTechniques;

    // Update feed state
    await updateFeedState(feed.url, feed, {
      success: true,
      articlesIngested: newCount,
      iocsExtracted: totalIocs,
      cvesFound: totalCves,
    });
  } catch (err) {
    result.status = "error";
    result.error = String(err);
    await updateFeedState(feed.url, feed, { error: String(err) });
  }

  result.duration = Date.now() - start;
  return result;
}

async function updateFeedState(
  feedUrl: string,
  feed: RSSFeedEntry,
  update: { success?: boolean; error?: string; articlesIngested?: number; iocsExtracted?: number; cvesFound?: number },
): Promise<void> {
  try {
    if (update.success) {
      await pool.query(
        `INSERT INTO rss_feed_state (feed_url, feed_domain, tier, category, poll_interval_minutes, last_polled_at, last_success_at, consecutive_errors, total_articles_ingested, total_iocs_extracted, total_cves_found)
         VALUES ($1, $2, $3, $4, $5, NOW(), NOW(), 0, $6, $7, $8)
         ON CONFLICT (feed_url) DO UPDATE SET
           last_polled_at = NOW(),
           last_success_at = NOW(),
           consecutive_errors = 0,
           total_articles_ingested = rss_feed_state.total_articles_ingested + $6,
           total_iocs_extracted = rss_feed_state.total_iocs_extracted + $7,
           total_cves_found = rss_feed_state.total_cves_found + $8,
           updated_at = NOW()`,
        [
          feedUrl,
          feed.domain,
          feed.tier,
          feed.category,
          feed.pollIntervalMinutes,
          update.articlesIngested || 0,
          update.iocsExtracted || 0,
          update.cvesFound || 0,
        ],
      );
    } else {
      await pool.query(
        `INSERT INTO rss_feed_state (feed_url, feed_domain, tier, category, poll_interval_minutes, last_polled_at, last_error, consecutive_errors)
         VALUES ($1, $2, $3, $4, $5, NOW(), $6, 1)
         ON CONFLICT (feed_url) DO UPDATE SET
           last_polled_at = NOW(),
           last_error = $6,
           consecutive_errors = rss_feed_state.consecutive_errors + 1,
           updated_at = NOW()`,
        [feedUrl, feed.domain, feed.tier, feed.category, feed.pollIntervalMinutes, update.error || "Unknown error"],
      );
    }
  } catch (err) {
    log.warn("Failed to update feed state", { feedUrl, error: String(err) });
  }
}

// ── Batch Polling ───────────────────────────────────────────────────

export async function pollFeedBatch(
  feeds: RSSFeedEntry[],
  concurrency: number = CONCURRENT_POLLS,
): Promise<FeedPollResult[]> {
  const results: FeedPollResult[] = [];

  for (let i = 0; i < feeds.length; i += concurrency) {
    const batch = feeds.slice(i, i + concurrency);
    const batchResults = await Promise.allSettled(batch.map((f) => pollSingleFeed(f)));

    for (const r of batchResults) {
      if (r.status === "fulfilled") {
        results.push(r.value);
      } else {
        results.push({
          feedUrl: batch[results.length % batch.length]?.url || "unknown",
          status: "error",
          articlesFound: 0,
          newArticles: 0,
          iocExtracted: 0,
          cvesFound: 0,
          techniquesFound: 0,
          duration: 0,
          error: String(r.reason),
        });
      }
    }
  }

  return results;
}

export async function pollTier(tier: string, concurrency?: number): Promise<FeedPollResult[]> {
  const feeds = getFeedsByTier(tier);
  log.info(`Polling ${feeds.length} feeds from ${tier}`);
  return pollFeedBatch(feeds, concurrency);
}

export async function pollAllFeeds(): Promise<{
  total: number;
  successful: number;
  failed: number;
  skipped: number;
  newArticles: number;
  totalIocs: number;
  totalCves: number;
  duration: number;
}> {
  const start = Date.now();
  const registry = getFeedRegistry();

  // Poll in tier order (tier1 first = highest priority)
  const allResults: FeedPollResult[] = [];
  for (const tier of ["tier1", "tier2", "tier3", "tier4", "tier5"]) {
    const tierFeeds = registry.filter((f) => f.tier === tier);
    if (tierFeeds.length > 0) {
      const results = await pollFeedBatch(tierFeeds);
      allResults.push(...results);
    }
  }

  const successful = allResults.filter((r) => r.status === "success").length;
  const failed = allResults.filter((r) => r.status === "error").length;
  const skipped = allResults.filter((r) => r.status === "skipped" || r.status === "rate_limited").length;
  const newArticles = allResults.reduce((sum, r) => sum + r.newArticles, 0);
  const totalIocs = allResults.reduce((sum, r) => sum + r.iocExtracted, 0);
  const totalCves = allResults.reduce((sum, r) => sum + r.cvesFound, 0);

  // Log daily learning
  await logDailyLearning(allResults);

  return {
    total: allResults.length,
    successful,
    failed,
    skipped,
    newArticles,
    totalIocs,
    totalCves,
    duration: Date.now() - start,
  };
}

// ── RAG Knowledge Indexing ──────────────────────────────────────────

export async function indexArticlesForRAG(limit: number = 100): Promise<number> {
  try {
    // Get unindexed articles with decent confidence
    const result = await pool.query(
      `SELECT id, title, summary, full_content, feed_tier, feed_category,
              cve_refs, mitre_techniques, threat_actors, malware_families,
              target_sectors, severity, confidence_score, published_at
       FROM rss_articles
       WHERE rag_indexed = false
         AND confidence_score >= 40
       ORDER BY confidence_score DESC, published_at DESC
       LIMIT $1`,
      [limit],
    );

    if (result.rows.length === 0) return 0;

    let indexed = 0;
    const { upsertKnowledgeEntry } = await import("./ai/vector-search");

    for (const article of result.rows) {
      try {
        // Build rich content for embedding
        const contentParts = [
          article.title,
          article.summary || "",
          article.full_content?.slice(0, 3000) || "",
          article.cve_refs?.length ? `CVEs: ${article.cve_refs.join(", ")}` : "",
          article.mitre_techniques?.length ? `MITRE Techniques: ${article.mitre_techniques.join(", ")}` : "",
          article.threat_actors?.length ? `Threat Actors: ${article.threat_actors.join(", ")}` : "",
          article.malware_families?.length ? `Malware: ${article.malware_families.join(", ")}` : "",
          article.target_sectors?.length ? `Targeted Sectors: ${article.target_sectors.join(", ")}` : "",
        ]
          .filter(Boolean)
          .join("\n\n");

        // Determine category for RAG
        let ragCategory = "threat_reports";
        if (article.cve_refs?.length > 0) ragCategory = "cve_advisories";
        if (article.mitre_techniques?.length > 0) ragCategory = "attack_techniques";

        const knowledgeId = await upsertKnowledgeEntry({
          category: ragCategory,
          sourceType: "rss_feed",
          sourceId: `rss-${article.id}`,
          title: article.title,
          content: contentParts.slice(0, 8000),
          metadata: {
            feedTier: article.feed_tier,
            feedCategory: article.feed_category,
            severity: article.severity,
            confidence: article.confidence_score,
            cves: article.cve_refs || [],
            techniques: article.mitre_techniques || [],
            actors: article.threat_actors || [],
            malware: article.malware_families || [],
            sectors: article.target_sectors || [],
            publishedAt: article.published_at,
          },
        });

        // Mark as indexed
        await pool.query("UPDATE rss_articles SET rag_indexed = true, rag_knowledge_id = $2 WHERE id = $1", [
          article.id,
          knowledgeId,
        ]);

        indexed++;
      } catch (err) {
        log.warn("Failed to index article for RAG", { articleId: article.id, error: String(err) });
      }
    }

    log.info(`Indexed ${indexed} articles for RAG knowledge base`);
    return indexed;
  } catch (err) {
    log.error("Failed to index articles for RAG", { error: String(err) });
    return 0;
  }
}

// ── Self-Learning Loop ──────────────────────────────────────────────

async function logDailyLearning(pollResults: FeedPollResult[]): Promise<void> {
  try {
    const feedsPolled = pollResults.filter((r) => r.status === "success").length;
    const articlesIngested = pollResults.reduce((s, r) => s + r.newArticles, 0);
    const newIocs = pollResults.reduce((s, r) => s + r.iocExtracted, 0);
    const newCves = pollResults.reduce((s, r) => s + r.cvesFound, 0);
    const newTechniques = pollResults.reduce((s, r) => s + r.techniquesFound, 0);

    // Get top topics from today's articles
    const topTopics = await pool
      .query(
        `SELECT unnest(tags) as topic, COUNT(*) as cnt
       FROM rss_articles
       WHERE created_at >= CURRENT_DATE
         AND tags IS NOT NULL
       GROUP BY topic
       ORDER BY cnt DESC
       LIMIT 10`,
      )
      .catch(() => ({ rows: [] }));

    // Get severity distribution
    const severityDist = await pool
      .query(
        `SELECT severity, COUNT(*) as cnt
       FROM rss_articles
       WHERE created_at >= CURRENT_DATE
       GROUP BY severity`,
      )
      .catch(() => ({ rows: [] }));

    const sevMap: Record<string, number> = {};
    for (const row of severityDist.rows) {
      sevMap[row.severity] = parseInt(row.cnt, 10);
    }

    await pool.query(
      `INSERT INTO rss_learning_log (
        learning_date, feeds_polled, articles_ingested, new_iocs, new_cves,
        new_techniques, top_topics, severity_distribution,
        learning_summary
      ) VALUES (CURRENT_DATE, $1, $2, $3, $4, $5, $6, $7, $8)
      ON CONFLICT (learning_date) DO UPDATE SET
        feeds_polled = rss_learning_log.feeds_polled + $1,
        articles_ingested = rss_learning_log.articles_ingested + $2,
        new_iocs = rss_learning_log.new_iocs + $3,
        new_cves = rss_learning_log.new_cves + $4,
        new_techniques = rss_learning_log.new_techniques + $5,
        top_topics = $6,
        severity_distribution = $7,
        learning_summary = $8`,
      [
        feedsPolled,
        articlesIngested,
        newIocs,
        newCves,
        newTechniques,
        JSON.stringify(topTopics.rows.slice(0, 10)),
        JSON.stringify(sevMap),
        `Polled ${feedsPolled} feeds, ingested ${articlesIngested} articles, extracted ${newIocs} IOCs, ${newCves} CVEs, ${newTechniques} MITRE techniques.`,
      ],
    );
  } catch (err) {
    log.warn("Failed to log daily learning", { error: String(err) });
  }
}

export async function updateSourceQuality(): Promise<void> {
  try {
    const feedStates = await pool.query("SELECT feed_url FROM rss_feed_state WHERE enabled = true");

    for (const row of feedStates.rows) {
      const feedUrl = row.feed_url;

      // Count articles from last 7 days
      const stats = await pool.query(
        `SELECT
          COUNT(*) as total,
          COUNT(*) FILTER (WHERE ioc_count > 0) as with_iocs,
          COUNT(*) FILTER (WHERE cve_refs IS NOT NULL AND array_length(cve_refs, 1) > 0) as with_cves,
          COUNT(*) FILTER (WHERE mitre_techniques IS NOT NULL AND array_length(mitre_techniques, 1) > 0) as with_techniques,
          AVG(confidence_score) as avg_confidence
        FROM rss_articles
        WHERE feed_url = $1
          AND created_at >= NOW() - INTERVAL '7 days'`,
        [feedUrl],
      );

      const s = stats.rows[0];
      const total = parseInt(s.total, 10) || 0;
      if (total === 0) continue;

      const withIocs = parseInt(s.with_iocs, 10) || 0;
      const withCves = parseInt(s.with_cves, 10) || 0;
      const withTechniques = parseInt(s.with_techniques, 10) || 0;
      const avgConfidence = parseFloat(s.avg_confidence) || 0;

      // Calculate quality metrics
      const relevanceRate = (withIocs + withCves + withTechniques) / (total * 3);
      const overallQuality = avgConfidence * 0.4 + relevanceRate * 100 * 0.3 + Math.min(total / 10, 1) * 100 * 0.3;

      await pool.query(
        `INSERT INTO rss_source_quality (feed_url, measured_at, articles_published, articles_with_iocs, articles_with_cves, articles_with_techniques, avg_confidence, overall_quality)
         VALUES ($1, CURRENT_DATE, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (feed_url, measured_at) DO UPDATE SET
           articles_published = $2, articles_with_iocs = $3, articles_with_cves = $4,
           articles_with_techniques = $5, avg_confidence = $6, overall_quality = $7`,
        [feedUrl, total, withIocs, withCves, withTechniques, avgConfidence, overallQuality],
      );

      // Update feed state quality score
      await pool.query(
        "UPDATE rss_feed_state SET quality_score = $2, relevance_score = $3, updated_at = NOW() WHERE feed_url = $1",
        [feedUrl, overallQuality, relevanceRate * 100],
      );
    }

    log.info("Source quality metrics updated");
  } catch (err) {
    log.error("Failed to update source quality", { error: String(err) });
  }
}

// ── Trend Analysis ──────────────────────────────────────────────────

export async function getTrendingTopics(days: number = 7): Promise<{
  trendingCves: Array<{ cve: string; mentions: number; firstSeen: string }>;
  trendingActors: Array<{ actor: string; mentions: number }>;
  trendingMalware: Array<{ malware: string; mentions: number }>;
  trendingTechniques: Array<{ technique: string; mentions: number }>;
  severityTrend: Array<{ date: string; critical: number; high: number; medium: number; low: number }>;
  topSources: Array<{ domain: string; articles: number; avgConfidence: number }>;
}> {
  try {
    const [cves, actors, malware, techniques, severity, sources] = await Promise.all([
      pool.query(
        `SELECT unnest(cve_refs) as cve, COUNT(*) as mentions, MIN(published_at) as first_seen
         FROM rss_articles WHERE created_at >= NOW() - $1::interval AND cve_refs IS NOT NULL
         GROUP BY cve ORDER BY mentions DESC LIMIT 20`,
        [`${days} days`],
      ),
      pool.query(
        `SELECT unnest(threat_actors) as actor, COUNT(*) as mentions
         FROM rss_articles WHERE created_at >= NOW() - $1::interval AND threat_actors IS NOT NULL
         GROUP BY actor ORDER BY mentions DESC LIMIT 15`,
        [`${days} days`],
      ),
      pool.query(
        `SELECT unnest(malware_families) as malware, COUNT(*) as mentions
         FROM rss_articles WHERE created_at >= NOW() - $1::interval AND malware_families IS NOT NULL
         GROUP BY malware ORDER BY mentions DESC LIMIT 15`,
        [`${days} days`],
      ),
      pool.query(
        `SELECT unnest(mitre_techniques) as technique, COUNT(*) as mentions
         FROM rss_articles WHERE created_at >= NOW() - $1::interval AND mitre_techniques IS NOT NULL
         GROUP BY technique ORDER BY mentions DESC LIMIT 20`,
        [`${days} days`],
      ),
      pool.query(
        `SELECT DATE(created_at) as date,
           COUNT(*) FILTER (WHERE severity = 'critical') as critical,
           COUNT(*) FILTER (WHERE severity = 'high') as high,
           COUNT(*) FILTER (WHERE severity = 'medium') as medium,
           COUNT(*) FILTER (WHERE severity = 'low') as low
         FROM rss_articles WHERE created_at >= NOW() - $1::interval
         GROUP BY DATE(created_at) ORDER BY date DESC`,
        [`${days} days`],
      ),
      pool.query(
        `SELECT s.feed_domain as domain, COUNT(a.id) as articles, AVG(a.confidence_score) as avg_confidence
         FROM rss_feed_state s
         JOIN rss_articles a ON a.feed_url = s.feed_url
         WHERE a.created_at >= NOW() - $1::interval
         GROUP BY s.feed_domain
         ORDER BY articles DESC LIMIT 20`,
        [`${days} days`],
      ),
    ]);

    return {
      trendingCves: cves.rows.map((r) => ({ cve: r.cve, mentions: parseInt(r.mentions, 10), firstSeen: r.first_seen })),
      trendingActors: actors.rows.map((r) => ({ actor: r.actor, mentions: parseInt(r.mentions, 10) })),
      trendingMalware: malware.rows.map((r) => ({ malware: r.malware, mentions: parseInt(r.mentions, 10) })),
      trendingTechniques: techniques.rows.map((r) => ({ technique: r.technique, mentions: parseInt(r.mentions, 10) })),
      severityTrend: severity.rows.map((r) => ({
        date: r.date,
        critical: parseInt(r.critical, 10),
        high: parseInt(r.high, 10),
        medium: parseInt(r.medium, 10),
        low: parseInt(r.low, 10),
      })),
      topSources: sources.rows.map((r) => ({
        domain: r.domain,
        articles: parseInt(r.articles, 10),
        avgConfidence: parseFloat(r.avg_confidence) || 0,
      })),
    };
  } catch (err) {
    log.error("Failed to get trending topics", { error: String(err) });
    return {
      trendingCves: [],
      trendingActors: [],
      trendingMalware: [],
      trendingTechniques: [],
      severityTrend: [],
      topSources: [],
    };
  }
}

// ── Learning History ────────────────────────────────────────────────

export async function getLearningHistory(days: number = 30): Promise<{
  history: Array<{
    date: string;
    feedsPolled: number;
    articlesIngested: number;
    newIocs: number;
    newCves: number;
    newTechniques: number;
    topTopics: unknown[];
    summary: string;
  }>;
  totalKnowledge: {
    totalArticles: number;
    totalIocs: number;
    totalCves: number;
    totalTechniques: number;
    totalActors: number;
    totalMalware: number;
    ragIndexed: number;
  };
  growthRate: {
    articlesPerDay: number;
    iocsPerDay: number;
    cvesPerDay: number;
  };
}> {
  try {
    const [historyResult, totalResult, growthResult] = await Promise.all([
      pool.query(
        `SELECT * FROM rss_learning_log
         WHERE learning_date >= CURRENT_DATE - $1::integer
         ORDER BY learning_date DESC`,
        [days],
      ),
      pool.query(`
        SELECT
          COUNT(*) as total_articles,
          SUM(ioc_count) as total_iocs,
          COUNT(*) FILTER (WHERE cve_refs IS NOT NULL) as total_cve_articles,
          COUNT(*) FILTER (WHERE mitre_techniques IS NOT NULL) as total_technique_articles,
          COUNT(*) FILTER (WHERE threat_actors IS NOT NULL) as total_actor_articles,
          COUNT(*) FILTER (WHERE malware_families IS NOT NULL) as total_malware_articles,
          COUNT(*) FILTER (WHERE rag_indexed = true) as rag_indexed
        FROM rss_articles
      `),
      pool.query(`
        SELECT
          AVG(articles_ingested) as avg_articles,
          AVG(new_iocs) as avg_iocs,
          AVG(new_cves) as avg_cves
        FROM rss_learning_log
        WHERE learning_date >= CURRENT_DATE - 7
      `),
    ]);

    const total = totalResult.rows[0];
    const growth = growthResult.rows[0];

    return {
      history: historyResult.rows.map((r) => ({
        date: r.learning_date,
        feedsPolled: r.feeds_polled,
        articlesIngested: r.articles_ingested,
        newIocs: r.new_iocs,
        newCves: r.new_cves,
        newTechniques: r.new_techniques,
        topTopics: r.top_topics || [],
        summary: r.learning_summary || "",
      })),
      totalKnowledge: {
        totalArticles: parseInt(total.total_articles, 10) || 0,
        totalIocs: parseInt(total.total_iocs, 10) || 0,
        totalCves: parseInt(total.total_cve_articles, 10) || 0,
        totalTechniques: parseInt(total.total_technique_articles, 10) || 0,
        totalActors: parseInt(total.total_actor_articles, 10) || 0,
        totalMalware: parseInt(total.total_malware_articles, 10) || 0,
        ragIndexed: parseInt(total.rag_indexed, 10) || 0,
      },
      growthRate: {
        articlesPerDay: parseFloat(growth?.avg_articles) || 0,
        iocsPerDay: parseFloat(growth?.avg_iocs) || 0,
        cvesPerDay: parseFloat(growth?.avg_cves) || 0,
      },
    };
  } catch (err) {
    log.error("Failed to get learning history", { error: String(err) });
    return {
      history: [],
      totalKnowledge: {
        totalArticles: 0,
        totalIocs: 0,
        totalCves: 0,
        totalTechniques: 0,
        totalActors: 0,
        totalMalware: 0,
        ragIndexed: 0,
      },
      growthRate: { articlesPerDay: 0, iocsPerDay: 0, cvesPerDay: 0 },
    };
  }
}

// ── Feed Management ─────────────────────────────────────────────────

export async function getFeedStates(options?: {
  tier?: string;
  category?: string;
  enabled?: boolean;
  sortBy?: string;
  limit?: number;
  offset?: number;
}): Promise<{ feeds: unknown[]; total: number }> {
  try {
    const conditions: string[] = [];
    const params: (string | number | boolean)[] = [];
    let paramIdx = 1;

    if (options?.tier) {
      conditions.push(`tier = $${paramIdx++}`);
      params.push(options.tier);
    }
    if (options?.category) {
      conditions.push(`category = $${paramIdx++}`);
      params.push(options.category);
    }
    if (options?.enabled !== undefined) {
      conditions.push(`enabled = $${paramIdx++}`);
      params.push(options.enabled);
    }

    const where = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";
    const sortCol =
      options?.sortBy === "quality"
        ? "quality_score"
        : options?.sortBy === "relevance"
          ? "relevance_score"
          : options?.sortBy === "articles"
            ? "total_articles_ingested"
            : "updated_at";

    const limit = Math.min(options?.limit || 50, 200);
    const offset = options?.offset || 0;

    const [feedsResult, countResult] = await Promise.all([
      pool.query(
        `SELECT * FROM rss_feed_state ${where} ORDER BY ${sortCol} DESC LIMIT $${paramIdx++} OFFSET $${paramIdx}`,
        [...params, limit, offset],
      ),
      pool.query(`SELECT COUNT(*) as cnt FROM rss_feed_state ${where}`, params),
    ]);

    return {
      feeds: feedsResult.rows,
      total: parseInt(countResult.rows[0].cnt, 10),
    };
  } catch (err) {
    log.error("Failed to get feed states", { error: String(err) });
    return { feeds: [], total: 0 };
  }
}

export async function toggleFeed(feedUrl: string, enabled: boolean): Promise<boolean> {
  try {
    const result = await pool.query("UPDATE rss_feed_state SET enabled = $2, updated_at = NOW() WHERE feed_url = $1", [
      feedUrl,
      enabled,
    ]);
    return (result.rowCount ?? 0) > 0;
  } catch {
    return false;
  }
}

export async function getRecentArticles(options?: {
  severity?: string;
  feedTier?: string;
  feedCategory?: string;
  hasIocs?: boolean;
  hasCves?: boolean;
  limit?: number;
  offset?: number;
}): Promise<{ articles: unknown[]; total: number }> {
  try {
    const conditions: string[] = [];
    const params: (string | number | boolean)[] = [];
    let paramIdx = 1;

    if (options?.severity) {
      conditions.push(`severity = $${paramIdx++}`);
      params.push(options.severity);
    }
    if (options?.feedTier) {
      conditions.push(`feed_tier = $${paramIdx++}`);
      params.push(options.feedTier);
    }
    if (options?.feedCategory) {
      conditions.push(`feed_category = $${paramIdx++}`);
      params.push(options.feedCategory);
    }
    if (options?.hasIocs) {
      conditions.push("ioc_count > 0");
    }
    if (options?.hasCves) {
      conditions.push("cve_refs IS NOT NULL AND array_length(cve_refs, 1) > 0");
    }

    const where = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";
    const limit = Math.min(options?.limit || 50, 200);
    const offset = options?.offset || 0;

    const [articlesResult, countResult] = await Promise.all([
      pool.query(
        `SELECT id, feed_url, article_url, title, summary, published_at, author, tags,
                feed_tier, feed_category, ioc_count, cve_refs, mitre_techniques,
                threat_actors, malware_families, target_sectors, severity, confidence_score,
                rag_indexed, created_at
         FROM rss_articles ${where}
         ORDER BY published_at DESC
         LIMIT $${paramIdx++} OFFSET $${paramIdx}`,
        [...params, limit, offset],
      ),
      pool.query(`SELECT COUNT(*) as cnt FROM rss_articles ${where}`, params),
    ]);

    return {
      articles: articlesResult.rows,
      total: parseInt(countResult.rows[0].cnt, 10),
    };
  } catch (err) {
    log.error("Failed to get recent articles", { error: String(err) });
    return { articles: [], total: 0 };
  }
}

// ── Background Scheduler ────────────────────────────────────────────

let schedulerTimer: NodeJS.Timeout | null = null;
const SCHEDULER_INTERVAL_MS = 10 * 60 * 1000; // Check every 10 minutes

export function startRSSIntelligenceScheduler(): void {
  // Initialize schema
  initializeRSSSchema().catch((err) => log.warn("RSS schema init deferred", { error: String(err) }));

  // Load feed registry
  loadFeedRegistry();

  log.info(`RSS Intelligence Engine started — ${getFeedRegistry().length} feeds in registry, polling every 10 minutes`);

  schedulerTimer = setInterval(async () => {
    try {
      // Poll tier 1 (highest priority) first
      const tier1 = getFeedsByTier("tier1");
      if (tier1.length > 0) {
        await pollFeedBatch(tier1, 5);
      }

      // Then poll a random batch of other tiers
      const otherFeeds = getFeedRegistry().filter((f) => f.tier !== "tier1");
      // Shuffle and take a subset to avoid overwhelming
      const shuffled = otherFeeds.sort(() => Math.random() - 0.5);
      const batch = shuffled.slice(0, 50);
      if (batch.length > 0) {
        await pollFeedBatch(batch, 5);
      }

      // Index new articles for RAG
      await indexArticlesForRAG(20);

      // Update source quality daily (only if we haven't today)
      const lastQuality = await pool
        .query("SELECT MAX(measured_at) as last FROM rss_source_quality")
        .catch(() => ({ rows: [{ last: null }] }));

      const lastDate = lastQuality.rows[0]?.last;
      const today = new Date().toISOString().split("T")[0];
      if (!lastDate || lastDate.toISOString().split("T")[0] !== today) {
        await updateSourceQuality();
      }
    } catch (err) {
      log.error("RSS intelligence scheduler error", { error: String(err) });
    }
  }, SCHEDULER_INTERVAL_MS);

  // Initial poll after 60 seconds
  setTimeout(async () => {
    try {
      const tier1 = getFeedsByTier("tier1").slice(0, 20);
      if (tier1.length > 0) {
        log.info(`Initial poll: ${tier1.length} tier1 feeds`);
        await pollFeedBatch(tier1, 5);
        await indexArticlesForRAG(50);
      }
    } catch (err) {
      log.warn("Initial RSS poll failed", { error: String(err) });
    }
  }, 60_000);
}

export function stopRSSIntelligenceScheduler(): void {
  if (schedulerTimer) {
    clearInterval(schedulerTimer);
    schedulerTimer = null;
  }
  log.info("RSS Intelligence Engine stopped");
}

/**
 * Email Security Analyzer — header analysis, BEC detection, URL scanning,
 * thread injection detection, retroactive IOC scanning
 */

import { db } from "./db";
import { sql, eq, and, gte, ilike, or, desc } from "drizzle-orm";
import { emailMessages, emailFindings, emailUrlRewrites } from "../shared/schema";
import { logger } from "./routes/shared";

const log = logger.child("email-analyzer");

// ─── SPF / DKIM / DMARC Validation ─────────────────────────────────────────

export interface AuthenticationResult {
  spf: { pass: boolean; result: string; details?: string };
  dkim: { pass: boolean; result: string; details?: string };
  dmarc: { pass: boolean; result: string; details?: string };
  overallPass: boolean;
  findings: Array<{
    findingType: string;
    severity: string;
    title: string;
    description: string;
    confidence: number;
    mitreTechnique?: string;
  }>;
}

/**
 * Parse and validate email authentication headers (SPF, DKIM, DMARC)
 */
export function analyzeEmailAuthentication(headers: Record<string, string>): AuthenticationResult {
  const authResults = headers["authentication-results"] || headers["Authentication-Results"] || "";
  const receivedSpf = headers["received-spf"] || headers["Received-SPF"] || "";
  const dkimSignature = headers["dkim-signature"] || headers["DKIM-Signature"] || "";

  // Parse SPF result
  const spfMatch = authResults.match(/spf=(pass|fail|softfail|neutral|none|temperror|permerror)/i);
  const spfFromReceived = receivedSpf.match(/^(pass|fail|softfail|neutral|none)/i);
  const spfResult = spfMatch?.[1]?.toLowerCase() || spfFromReceived?.[1]?.toLowerCase() || "none";
  const spfPass = spfResult === "pass";

  // Parse DKIM result
  const dkimMatch = authResults.match(/dkim=(pass|fail|neutral|none|temperror|permerror)/i);
  const dkimResult = dkimMatch?.[1]?.toLowerCase() || (dkimSignature ? "present" : "none");
  const dkimPass = dkimResult === "pass";

  // Parse DMARC result
  const dmarcMatch = authResults.match(/dmarc=(pass|fail|bestguesspass|none|temperror|permerror)/i);
  const dmarcResult = dmarcMatch?.[1]?.toLowerCase() || "none";
  const dmarcPass = dmarcResult === "pass" || dmarcResult === "bestguesspass";

  const overallPass = spfPass && dkimPass && dmarcPass;
  const findings: AuthenticationResult["findings"] = [];

  if (!spfPass && spfResult !== "none") {
    findings.push({
      findingType: "spf_fail",
      severity: spfResult === "fail" ? "high" : "medium",
      title: `SPF ${spfResult}`,
      description: `Sender failed SPF verification with result: ${spfResult}. The sending server may not be authorized to send on behalf of the domain.`,
      confidence: spfResult === "fail" ? 0.9 : 0.6,
      mitreTechnique: "T1566.001",
    });
  }

  if (!dkimPass && dkimResult !== "none") {
    findings.push({
      findingType: "dkim_fail",
      severity: dkimResult === "fail" ? "high" : "medium",
      title: `DKIM ${dkimResult}`,
      description: `Email DKIM signature verification failed: ${dkimResult}. The message may have been tampered with in transit.`,
      confidence: dkimResult === "fail" ? 0.85 : 0.5,
      mitreTechnique: "T1566.001",
    });
  }

  if (!dmarcPass && dmarcResult !== "none") {
    findings.push({
      findingType: "dmarc_fail",
      severity: dmarcResult === "fail" ? "critical" : "medium",
      title: `DMARC ${dmarcResult}`,
      description: `DMARC policy check failed: ${dmarcResult}. This strongly indicates spoofing or misconfigured sender domain.`,
      confidence: dmarcResult === "fail" ? 0.95 : 0.6,
      mitreTechnique: "T1566.001",
    });
  }

  return {
    spf: { pass: spfPass, result: spfResult },
    dkim: { pass: dkimPass, result: dkimResult },
    dmarc: { pass: dmarcPass, result: dmarcResult },
    overallPass,
    findings,
  };
}

// ─── BEC (Business Email Compromise) Detection ─────────────────────────────

export interface BecResult {
  isBec: boolean;
  confidence: number;
  indicators: {
    isLookalikeDomain: boolean;
    isExecutiveImpersonation: boolean;
    hasSuspiciousUrgency: boolean;
    hasFinancialLanguage: boolean;
    replyToMismatch: boolean;
    displayNameSpoofing: boolean;
  };
  findings: Array<{
    findingType: string;
    severity: string;
    title: string;
    description: string;
    confidence: number;
    mitreTechnique?: string;
  }>;
}

const EXECUTIVE_TITLES = [
  "ceo",
  "cfo",
  "cto",
  "coo",
  "ciso",
  "president",
  "vice president",
  "vp",
  "director",
  "managing director",
  "chairman",
  "chief",
  "head of",
  "svp",
  "evp",
];

const URGENCY_PHRASES = [
  "urgent",
  "asap",
  "immediately",
  "right away",
  "time sensitive",
  "act now",
  "do not delay",
  "confidential",
  "do not share",
  "keep this between us",
  "wire transfer",
  "please reply",
  "respond immediately",
];

const FINANCIAL_PHRASES = [
  "wire transfer",
  "bank account",
  "routing number",
  "payment",
  "invoice",
  "purchase order",
  "gift card",
  "bitcoin",
  "cryptocurrency",
  "western union",
  "money gram",
  "account number",
  "ach transfer",
  "direct deposit",
  "payroll",
];

/**
 * Compute Levenshtein distance between two strings
 */
function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1] ? dp[i - 1][j - 1] : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[m][n];
}

/**
 * Check if a domain is a lookalike of known trusted domains
 */
export function detectLookalikeDomain(
  domain: string,
  trustedDomains: string[],
): { isLookalike: boolean; closestMatch: string | null; distance: number } {
  const lowerDomain = domain.toLowerCase();
  let closestMatch: string | null = null;
  let minDistance = Infinity;

  for (const trusted of trustedDomains) {
    const d = levenshtein(lowerDomain, trusted.toLowerCase());
    if (d > 0 && d <= 3 && d < minDistance) {
      minDistance = d;
      closestMatch = trusted;
    }
  }

  // Also check for common homoglyph substitutions
  const homoglyphPatterns = [
    { from: /rn/g, to: "m" },
    { from: /l/g, to: "1" },
    { from: /o/g, to: "0" },
    { from: /i/g, to: "l" },
    { from: /vv/g, to: "w" },
  ];

  for (const trusted of trustedDomains) {
    const trustedLower = trusted.toLowerCase();
    for (const pattern of homoglyphPatterns) {
      const substituted = lowerDomain.replace(pattern.from, String(pattern.to));
      if (substituted === trustedLower && lowerDomain !== trustedLower) {
        return { isLookalike: true, closestMatch: trusted, distance: 1 };
      }
    }
  }

  return { isLookalike: minDistance <= 2, closestMatch, distance: minDistance };
}

/**
 * Detect BEC (Business Email Compromise) patterns
 */
export function detectBec(
  senderAddress: string,
  senderDisplayName: string,
  subject: string,
  bodyPreview: string,
  replyTo: string | null,
  trustedDomains: string[],
  executiveNames: string[],
): BecResult {
  const findings: BecResult["findings"] = [];
  const senderDomain = senderAddress.split("@")[1] || "";
  const lowerSubject = (subject || "").toLowerCase();
  const lowerBody = (bodyPreview || "").toLowerCase();
  const lowerDisplayName = (senderDisplayName || "").toLowerCase();

  // Check lookalike domain
  const lookalikeCheck = detectLookalikeDomain(senderDomain, trustedDomains);

  // Check executive impersonation
  const isExecImpersonation =
    executiveNames.some((name) => lowerDisplayName.includes(name.toLowerCase())) ||
    EXECUTIVE_TITLES.some((title) => lowerDisplayName.includes(title));

  // Check urgency
  const hasSuspiciousUrgency = URGENCY_PHRASES.some((p) => lowerSubject.includes(p) || lowerBody.includes(p));

  // Check financial language
  const hasFinancialLanguage = FINANCIAL_PHRASES.some((p) => lowerBody.includes(p));

  // Reply-to mismatch
  const replyToMismatch = replyTo !== null && replyTo !== senderAddress && replyTo.split("@")[1] !== senderDomain;

  // Display name spoofing (display name matches exec but email doesn't match)
  const displayNameSpoofing = isExecImpersonation && !trustedDomains.some((d) => senderAddress.endsWith(`@${d}`));

  let score = 0;
  if (lookalikeCheck.isLookalike) {
    score += 0.35;
    findings.push({
      findingType: "lookalike_domain",
      severity: "critical",
      title: `Lookalike domain detected: ${senderDomain}`,
      description: `Sender domain "${senderDomain}" is visually similar to trusted domain "${lookalikeCheck.closestMatch}" (edit distance: ${lookalikeCheck.distance}). This is a common BEC technique.`,
      confidence: 0.9,
      mitreTechnique: "T1566.001",
    });
  }

  if (displayNameSpoofing) {
    score += 0.3;
    findings.push({
      findingType: "executive_impersonation",
      severity: "critical",
      title: `Executive impersonation: "${senderDisplayName}"`,
      description: `Display name matches a known executive but the sender email "${senderAddress}" is from an external domain. Likely impersonation attempt.`,
      confidence: 0.85,
      mitreTechnique: "T1656",
    });
  }

  if (replyToMismatch) {
    score += 0.15;
    findings.push({
      findingType: "bec_attempt",
      severity: "high",
      title: "Reply-To address mismatch",
      description: `Reply-To address "${replyTo}" does not match sender "${senderAddress}". Replies would go to a different domain.`,
      confidence: 0.7,
      mitreTechnique: "T1566.001",
    });
  }

  if (hasSuspiciousUrgency) score += 0.1;
  if (hasFinancialLanguage) score += 0.1;

  const confidence = Math.min(0.99, Math.round(score * 100) / 100);

  return {
    isBec: confidence >= 0.4,
    confidence,
    indicators: {
      isLookalikeDomain: lookalikeCheck.isLookalike,
      isExecutiveImpersonation: isExecImpersonation,
      hasSuspiciousUrgency,
      hasFinancialLanguage,
      replyToMismatch,
      displayNameSpoofing,
    },
    findings,
  };
}

// ─── Thread Injection Detection ─────────────────────────────────────────────

export interface ThreadInjectionResult {
  isInjected: boolean;
  confidence: number;
  indicators: {
    newParticipant: boolean;
    subjectManipulation: boolean;
    headerChainBroken: boolean;
    timingAnomaly: boolean;
  };
}

/**
 * Detect if an attacker has injected themselves into an email thread
 */
export async function detectThreadInjection(
  orgId: string,
  threadId: string,
  senderAddress: string,
  inReplyTo: string | null,
  receivedAt: Date,
): Promise<ThreadInjectionResult> {
  if (!threadId) {
    return {
      isInjected: false,
      confidence: 0,
      indicators: {
        newParticipant: false,
        subjectManipulation: false,
        headerChainBroken: false,
        timingAnomaly: false,
      },
    };
  }

  // Get all previous messages in this thread
  const threadMessages = await db
    .select({
      senderAddress: emailMessages.senderAddress,
      internetMessageId: emailMessages.internetMessageId,
      receivedAt: emailMessages.receivedAt,
      inReplyTo: emailMessages.inReplyTo,
    })
    .from(emailMessages)
    .where(and(eq(emailMessages.orgId, orgId), eq(emailMessages.threadId, threadId)))
    .orderBy(emailMessages.receivedAt)
    .limit(100);

  if (threadMessages.length === 0) {
    return {
      isInjected: false,
      confidence: 0,
      indicators: {
        newParticipant: false,
        subjectManipulation: false,
        headerChainBroken: false,
        timingAnomaly: false,
      },
    };
  }

  // Check if sender is new to this thread
  const existingParticipants = new Set(threadMessages.map((m) => m.senderAddress));
  const newParticipant = !existingParticipants.has(senderAddress);

  // Check if In-Reply-To references a real message in the thread
  const existingMessageIds = new Set(threadMessages.map((m) => m.internetMessageId).filter(Boolean));
  const headerChainBroken = inReplyTo !== null && !existingMessageIds.has(inReplyTo);

  // Check timing anomaly (long gap then sudden activity)
  let timingAnomaly = false;
  if (threadMessages.length > 0) {
    const lastMessage = threadMessages[threadMessages.length - 1];
    if (lastMessage.receivedAt) {
      const gapMs = receivedAt.getTime() - new Date(lastMessage.receivedAt).getTime();
      const gapDays = gapMs / 86400000;
      timingAnomaly = gapDays > 30; // Thread was dormant for >30 days
    }
  }

  let score = 0;
  if (newParticipant) score += 0.3;
  if (headerChainBroken) score += 0.35;
  if (timingAnomaly) score += 0.2;

  const confidence = Math.min(0.99, Math.round(score * 100) / 100);

  return {
    isInjected: confidence >= 0.5,
    confidence,
    indicators: {
      newParticipant,
      subjectManipulation: false,
      headerChainBroken,
      timingAnomaly,
    },
  };
}

// ─── URL Analysis ───────────────────────────────────────────────────────────

export interface UrlScanResult {
  url: string;
  isMalicious: boolean;
  confidence: number;
  indicators: {
    hasIpAddress: boolean;
    hasSuspiciousTld: boolean;
    hasEncodedChars: boolean;
    isShortened: boolean;
    hasExcessiveSubdomains: boolean;
    pathLooksPhishy: boolean;
  };
}

const SUSPICIOUS_TLDS = new Set([
  "xyz",
  "top",
  "club",
  "online",
  "site",
  "fun",
  "icu",
  "buzz",
  "wang",
  "live",
  "gq",
  "ml",
  "cf",
  "tk",
  "ga",
  "work",
  "click",
  "link",
  "info",
]);

const URL_SHORTENERS = new Set([
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "goo.gl",
  "ow.ly",
  "is.gd",
  "buff.ly",
  "rebrand.ly",
  "cutt.ly",
  "shorturl.at",
]);

const PHISHING_PATH_PATTERNS = [
  /\/login/i,
  /\/signin/i,
  /\/verify/i,
  /\/update.*account/i,
  /\/secure/i,
  /\/confirm/i,
  /\/password/i,
  /\/reset/i,
  /\/suspended/i,
  /\/unlock/i,
];

/**
 * Analyze a URL for malicious indicators
 */
export function analyzeUrl(urlStr: string): UrlScanResult {
  let parsed: URL;
  try {
    parsed = new URL(urlStr);
  } catch {
    return {
      url: urlStr,
      isMalicious: false,
      confidence: 0,
      indicators: {
        hasIpAddress: false,
        hasSuspiciousTld: false,
        hasEncodedChars: false,
        isShortened: false,
        hasExcessiveSubdomains: false,
        pathLooksPhishy: false,
      },
    };
  }

  const hostname = parsed.hostname;
  const path = parsed.pathname;
  const tld = hostname.split(".").pop() || "";

  const hasIpAddress = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
  const hasSuspiciousTld = SUSPICIOUS_TLDS.has(tld);
  const hasEncodedChars = /%[0-9a-f]{2}/i.test(urlStr) && urlStr.includes("%2F");
  const isShortened = URL_SHORTENERS.has(hostname);
  const hasExcessiveSubdomains = hostname.split(".").length > 4;
  const pathLooksPhishy = PHISHING_PATH_PATTERNS.some((p) => p.test(path));

  let score = 0;
  if (hasIpAddress) score += 0.3;
  if (hasSuspiciousTld) score += 0.15;
  if (hasEncodedChars) score += 0.15;
  if (isShortened) score += 0.1;
  if (hasExcessiveSubdomains) score += 0.15;
  if (pathLooksPhishy) score += 0.2;

  const confidence = Math.min(0.99, Math.round(score * 100) / 100);

  return {
    url: urlStr,
    isMalicious: confidence >= 0.4,
    confidence,
    indicators: {
      hasIpAddress,
      hasSuspiciousTld,
      hasEncodedChars,
      isShortened,
      hasExcessiveSubdomains,
      pathLooksPhishy,
    },
  };
}

/**
 * Extract all URLs from email body text
 */
export function extractUrls(text: string): string[] {
  const urlRegex = /https?:\/\/[^\s<>"')\]]+/gi;
  const matches = text.match(urlRegex) || [];
  return Array.from(new Set(matches));
}

// ─── Retroactive IOC Scanning ───────────────────────────────────────────────

export interface RetroactiveScanResult {
  totalScanned: number;
  matchCount: number;
  matches: Array<{
    emailMessageId: string;
    senderAddress: string;
    subject: string | null;
    matchedIoc: string;
    matchType: string;
  }>;
}

/**
 * Scan historical emails for newly identified IOCs
 */
export async function retroactiveIocScan(
  orgId: string,
  iocs: Array<{ value: string; type: "domain" | "email" | "url" | "ip" }>,
  lookbackDays: number = 90,
): Promise<RetroactiveScanResult> {
  const since = new Date(Date.now() - lookbackDays * 86400000);
  const matches: RetroactiveScanResult["matches"] = [];

  for (const ioc of iocs) {
    const escapedValue = ioc.value.replace(/%/g, "\\%").replace(/_/g, "\\_");

    let conditions;
    switch (ioc.type) {
      case "domain":
        conditions = and(
          eq(emailMessages.orgId, orgId),
          gte(emailMessages.receivedAt, since),
          ilike(emailMessages.senderAddress, `%@${escapedValue}`),
        );
        break;
      case "email":
        conditions = and(
          eq(emailMessages.orgId, orgId),
          gte(emailMessages.receivedAt, since),
          eq(emailMessages.senderAddress, ioc.value),
        );
        break;
      case "url":
        conditions = and(
          eq(emailMessages.orgId, orgId),
          gte(emailMessages.receivedAt, since),
          sql`${emailMessages.extractedUrls}::text ILIKE ${"%" + escapedValue + "%"}`,
        );
        break;
      case "ip":
        // Search in headers for originating IP
        conditions = and(
          eq(emailMessages.orgId, orgId),
          gte(emailMessages.receivedAt, since),
          sql`${emailMessages.headers}::text ILIKE ${"%" + escapedValue + "%"}`,
        );
        break;
    }

    const results = await db
      .select({
        id: emailMessages.id,
        senderAddress: emailMessages.senderAddress,
        subject: emailMessages.subject,
      })
      .from(emailMessages)
      .where(conditions)
      .limit(200);

    for (const msg of results) {
      matches.push({
        emailMessageId: msg.id,
        senderAddress: msg.senderAddress,
        subject: msg.subject,
        matchedIoc: ioc.value,
        matchType: ioc.type,
      });
    }
  }

  // Count total messages in lookback period
  const [{ value: totalScanned }] = await db
    .select({ value: sql<number>`count(*)` })
    .from(emailMessages)
    .where(and(eq(emailMessages.orgId, orgId), gte(emailMessages.receivedAt, since)));

  return {
    totalScanned: Number(totalScanned),
    matchCount: matches.length,
    matches,
  };
}

// ─── Sender Reputation ──────────────────────────────────────────────────────

/**
 * Compute a basic sender reputation score based on historical email data
 */
export async function computeSenderReputation(
  orgId: string,
  senderAddress: string,
): Promise<{ reputation: number; totalEmails: number; suspiciousCount: number; findingCount: number }> {
  const [{ value: totalEmails }] = await db
    .select({ value: sql<number>`count(*)` })
    .from(emailMessages)
    .where(and(eq(emailMessages.orgId, orgId), eq(emailMessages.senderAddress, senderAddress)));

  const [{ value: suspiciousCount }] = await db
    .select({ value: sql<number>`count(*)` })
    .from(emailMessages)
    .where(
      and(
        eq(emailMessages.orgId, orgId),
        eq(emailMessages.senderAddress, senderAddress),
        eq(emailMessages.isSuspicious, true),
      ),
    );

  const [{ value: findingCount }] = await db
    .select({ value: sql<number>`count(*)` })
    .from(emailFindings)
    .where(and(eq(emailFindings.orgId, orgId), eq(emailFindings.senderAddress, senderAddress)));

  const total = Number(totalEmails);
  const suspicious = Number(suspiciousCount);
  const findings = Number(findingCount);

  if (total === 0) return { reputation: 0.5, totalEmails: 0, suspiciousCount: 0, findingCount: 0 };

  // Higher is better (1.0 = fully trusted, 0.0 = known malicious)
  const suspiciousRatio = suspicious / total;
  const findingRatio = total > 0 ? findings / total : 0;
  const reputation = Math.max(0, Math.min(1, 1 - suspiciousRatio * 0.5 - findingRatio * 0.5));

  return {
    reputation: Math.round(reputation * 100) / 100,
    totalEmails: total,
    suspiciousCount: suspicious,
    findingCount: findings,
  };
}

// ─── Attachment Analysis ────────────────────────────────────────────────────

const DANGEROUS_EXTENSIONS = new Set([
  ".exe",
  ".bat",
  ".cmd",
  ".com",
  ".pif",
  ".scr",
  ".vbs",
  ".js",
  ".wsh",
  ".wsf",
  ".msi",
  ".dll",
  ".hta",
  ".ps1",
  ".psm1",
  ".reg",
  ".inf",
  ".lnk",
  ".iso",
  ".img",
  ".vhd",
]);

const SUSPICIOUS_EXTENSIONS = new Set([
  ".doc",
  ".docm",
  ".xls",
  ".xlsm",
  ".ppt",
  ".pptm",
  ".zip",
  ".rar",
  ".7z",
  ".tar",
  ".gz",
  ".html",
  ".htm",
  ".svg",
]);

export interface AttachmentAnalysisResult {
  fileName: string;
  risk: "critical" | "high" | "medium" | "low";
  isDangerous: boolean;
  reason: string;
}

/**
 * Analyze attachment filenames for risk indicators
 */
export function analyzeAttachments(attachmentNames: string[]): AttachmentAnalysisResult[] {
  const results: AttachmentAnalysisResult[] = [];

  for (const name of attachmentNames) {
    const lower = name.toLowerCase();
    const ext = lower.substring(lower.lastIndexOf("."));

    // Check for double extensions (e.g., document.pdf.exe)
    const parts = lower.split(".");
    const hasDoubleExtension = parts.length > 2 && DANGEROUS_EXTENSIONS.has(`.${parts[parts.length - 1]}`);

    if (hasDoubleExtension) {
      results.push({
        fileName: name,
        risk: "critical",
        isDangerous: true,
        reason: `Double extension detected — likely masquerading as ${parts[parts.length - 2]} file but is actually ${parts[parts.length - 1]}`,
      });
    } else if (DANGEROUS_EXTENSIONS.has(ext)) {
      results.push({
        fileName: name,
        risk: "critical",
        isDangerous: true,
        reason: `Executable file type (${ext}) — high risk for malware delivery`,
      });
    } else if (SUSPICIOUS_EXTENSIONS.has(ext)) {
      results.push({
        fileName: name,
        risk: "medium",
        isDangerous: false,
        reason: `Potentially risky file type (${ext}) — may contain macros or embedded content`,
      });
    } else {
      results.push({
        fileName: name,
        risk: "low",
        isDangerous: false,
        reason: "Standard file type",
      });
    }
  }

  return results;
}

// ─── Full Email Analysis Pipeline ───────────────────────────────────────────

export interface FullEmailAnalysis {
  isSuspicious: boolean;
  overallRisk: "critical" | "high" | "medium" | "low";
  authentication: AuthenticationResult;
  becAnalysis: BecResult;
  urlAnalysis: UrlScanResult[];
  attachmentAnalysis: AttachmentAnalysisResult[];
  allFindings: Array<{
    findingType: string;
    severity: string;
    title: string;
    description: string;
    confidence: number;
    mitreTechnique?: string;
  }>;
}

/**
 * Run the full email analysis pipeline
 */
export function analyzeEmail(
  senderAddress: string,
  senderDisplayName: string,
  subject: string,
  bodyPreview: string,
  headers: Record<string, string>,
  attachmentNames: string[],
  extractedUrlsList: string[],
  replyTo: string | null,
  trustedDomains: string[],
  executiveNames: string[],
): FullEmailAnalysis {
  // 1. Authentication check
  const authentication = analyzeEmailAuthentication(headers);

  // 2. BEC detection
  const becAnalysis = detectBec(
    senderAddress,
    senderDisplayName,
    subject,
    bodyPreview,
    replyTo,
    trustedDomains,
    executiveNames,
  );

  // 3. URL analysis
  const urlAnalysis = extractedUrlsList.map((url) => analyzeUrl(url));

  // 4. Attachment analysis
  const attachmentAnalysis = analyzeAttachments(attachmentNames);

  // Collect all findings
  const allFindings = [...authentication.findings, ...becAnalysis.findings];

  // Add URL findings
  for (const urlResult of urlAnalysis) {
    if (urlResult.isMalicious) {
      allFindings.push({
        findingType: "malicious_url",
        severity: urlResult.confidence >= 0.7 ? "high" : "medium",
        title: `Suspicious URL detected`,
        description: `URL "${urlResult.url}" has malicious indicators (confidence: ${urlResult.confidence})`,
        confidence: urlResult.confidence,
        mitreTechnique: "T1566.002",
      });
    }
  }

  // Add attachment findings
  for (const attResult of attachmentAnalysis) {
    if (attResult.isDangerous) {
      allFindings.push({
        findingType: "malicious_attachment",
        severity: attResult.risk,
        title: `Dangerous attachment: ${attResult.fileName}`,
        description: attResult.reason,
        confidence: 0.9,
        mitreTechnique: "T1566.001",
      });
    }
  }

  // Determine overall risk
  const hasCritical = allFindings.some((f) => f.severity === "critical");
  const hasHigh = allFindings.some((f) => f.severity === "high");
  const overallRisk: FullEmailAnalysis["overallRisk"] = hasCritical
    ? "critical"
    : hasHigh
      ? "high"
      : allFindings.length > 0
        ? "medium"
        : "low";

  return {
    isSuspicious: allFindings.length > 0,
    overallRisk,
    authentication,
    becAnalysis,
    urlAnalysis,
    attachmentAnalysis,
    allFindings,
  };
}

// ─── Email Stats ────────────────────────────────────────────────────────────

export interface EmailStats {
  totalMessages: number;
  suspiciousMessages: number;
  totalFindings: number;
  openFindings: number;
  quarantinedCount: number;
  urlsRewritten: number;
  policiesActive: number;
  findingsByType: Record<string, number>;
  findingsBySeverity: Record<string, number>;
}

export async function computeEmailStats(orgId: string): Promise<EmailStats> {
  const since = new Date(Date.now() - 30 * 86400000);

  const [
    [{ value: totalMessages }],
    [{ value: suspiciousMessages }],
    [{ value: totalFindings }],
    [{ value: openFindings }],
    [{ value: urlsRewritten }],
  ] = await Promise.all([
    db
      .select({ value: sql<number>`count(*)` })
      .from(emailMessages)
      .where(and(eq(emailMessages.orgId, orgId), gte(emailMessages.receivedAt, since))),
    db
      .select({ value: sql<number>`count(*)` })
      .from(emailMessages)
      .where(
        and(eq(emailMessages.orgId, orgId), gte(emailMessages.receivedAt, since), eq(emailMessages.isSuspicious, true)),
      ),
    db
      .select({ value: sql<number>`count(*)` })
      .from(emailFindings)
      .where(and(eq(emailFindings.orgId, orgId), gte(emailFindings.createdAt, since))),
    db
      .select({ value: sql<number>`count(*)` })
      .from(emailFindings)
      .where(and(eq(emailFindings.orgId, orgId), eq(emailFindings.status, "open"))),
    db
      .select({ value: sql<number>`count(*)` })
      .from(emailUrlRewrites)
      .where(and(eq(emailUrlRewrites.orgId, orgId), gte(emailUrlRewrites.createdAt, since))),
  ]);

  // Findings by type
  const findingsByTypeRows = await db
    .select({ type: emailFindings.findingType, value: sql<number>`count(*)` })
    .from(emailFindings)
    .where(and(eq(emailFindings.orgId, orgId), gte(emailFindings.createdAt, since)))
    .groupBy(emailFindings.findingType);

  const findingsByType: Record<string, number> = {};
  for (const row of findingsByTypeRows) {
    findingsByType[row.type] = Number(row.value);
  }

  // Findings by severity
  const findingsBySevRows = await db
    .select({ sev: emailFindings.severity, value: sql<number>`count(*)` })
    .from(emailFindings)
    .where(and(eq(emailFindings.orgId, orgId), gte(emailFindings.createdAt, since)))
    .groupBy(emailFindings.severity);

  const findingsBySeverity: Record<string, number> = {};
  for (const row of findingsBySevRows) {
    findingsBySeverity[row.sev] = Number(row.value);
  }

  return {
    totalMessages: Number(totalMessages),
    suspiciousMessages: Number(suspiciousMessages),
    totalFindings: Number(totalFindings),
    openFindings: Number(openFindings),
    quarantinedCount: 0,
    urlsRewritten: Number(urlsRewritten),
    policiesActive: 0,
    findingsByType,
    findingsBySeverity,
  };
}

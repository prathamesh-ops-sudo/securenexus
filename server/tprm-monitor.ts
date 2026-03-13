/**
 * TPRM Continuous Monitoring Engine
 *
 * Monitors vendor attack surface: domain reputation, SSL cert expiry,
 * DNS changes, breach news, and security score changes.
 */

import { db } from "./db";
import { eq, and, sql, desc } from "drizzle-orm";
import { vendors, vendorMonitoring, vendorBreachAlerts } from "../shared/schema";
import { logger } from "./logger";
import { validateWebhookUrl } from "./outbound-security";

const log = logger.child("tprm-monitor");

// ── Domain & SSL Monitoring ───────────────────────────────────────

export interface DomainCheckResult {
  domain: string;
  dnsResolvable: boolean;
  sslValid: boolean;
  sslExpiry: string | null;
  sslDaysRemaining: number | null;
  httpStatus: number | null;
  securityHeaders: Record<string, boolean>;
}

/**
 * Check a vendor's domain for SSL cert, DNS, HTTP status, and security headers.
 */
export async function checkVendorDomain(domain: string): Promise<DomainCheckResult> {
  const result: DomainCheckResult = {
    domain,
    dnsResolvable: false,
    sslValid: false,
    sslExpiry: null,
    sslDaysRemaining: null,
    httpStatus: null,
    securityHeaders: {},
  };

  try {
    const url = `https://${domain}`;
    const urlCheck = validateWebhookUrl(url);
    if (!urlCheck.valid) {
      log.warn("Domain URL validation failed", { domain, reason: urlCheck.reason });
      return result;
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15_000);

    const response = await fetch(url, {
      method: "HEAD",
      signal: controller.signal,
      redirect: "follow",
    });
    clearTimeout(timeout);

    result.dnsResolvable = true;
    result.sslValid = true; // fetch succeeded over HTTPS
    result.httpStatus = response.status;

    // Check security headers
    const headers = response.headers;
    result.securityHeaders = {
      strictTransportSecurity: !!headers.get("strict-transport-security"),
      contentSecurityPolicy: !!headers.get("content-security-policy"),
      xFrameOptions: !!headers.get("x-frame-options"),
      xContentTypeOptions: !!headers.get("x-content-type-options"),
      referrerPolicy: !!headers.get("referrer-policy"),
      permissionsPolicy: !!headers.get("permissions-policy"),
    };
  } catch (err) {
    const errMsg = String(err);
    if (errMsg.includes("ENOTFOUND") || errMsg.includes("getaddrinfo")) {
      result.dnsResolvable = false;
    } else if (errMsg.includes("certificate") || errMsg.includes("SSL") || errMsg.includes("TLS")) {
      result.dnsResolvable = true;
      result.sslValid = false;
    } else {
      result.dnsResolvable = true;
    }
    log.debug("Domain check failed", { domain, error: errMsg });
  }

  return result;
}

// ── Vendor Risk Scoring ───────────────────────────────────────────

export interface VendorRiskFactors {
  domainHealth: number; // 0-100
  sslStatus: number; // 0-100
  securityHeaders: number; // 0-100
  certExpiry: number; // 0-100
  breachHistory: number; // 0-100
  assessmentScore: number; // 0-100
  dataAccessRisk: number; // 0-100
}

/**
 * Calculate a vendor's overall risk score from multiple factors.
 */
export function calculateVendorRiskScore(factors: VendorRiskFactors): number {
  const weights = {
    domainHealth: 0.1,
    sslStatus: 0.15,
    securityHeaders: 0.1,
    certExpiry: 0.1,
    breachHistory: 0.2,
    assessmentScore: 0.25,
    dataAccessRisk: 0.1,
  };

  let score = 0;
  for (const [key, weight] of Object.entries(weights)) {
    score += (factors[key as keyof VendorRiskFactors] || 0) * weight;
  }

  return Math.round(Math.max(0, Math.min(100, score)));
}

/**
 * Determine risk tier from a numeric score.
 */
export function scoreToRiskTier(score: number): string {
  if (score >= 90) return "minimal";
  if (score >= 75) return "low";
  if (score >= 50) return "medium";
  if (score >= 25) return "high";
  return "critical";
}

// ── Continuous Monitoring Runner ──────────────────────────────────

/**
 * Run monitoring checks for a single vendor.
 */
export async function monitorVendor(
  orgId: string,
  vendorId: string,
  domain: string | null,
): Promise<{ checks: number; alerts: number }> {
  let checks = 0;
  let alerts = 0;

  if (!domain) {
    return { checks: 0, alerts: 0 };
  }

  try {
    // Domain health check
    const domainResult = await checkVendorDomain(domain);
    checks++;

    // Record DNS check
    if (!domainResult.dnsResolvable) {
      alerts++;
      await db.insert(vendorMonitoring).values({
        orgId,
        vendorId,
        checkType: "dns_resolution",
        status: "alert",
        severity: "high",
        details: `Domain ${domain} failed DNS resolution`,
        currentValue: "unresolvable",
      });
    } else {
      await db.insert(vendorMonitoring).values({
        orgId,
        vendorId,
        checkType: "dns_resolution",
        status: "ok",
        severity: "info",
        details: `Domain ${domain} resolves successfully`,
        currentValue: "ok",
      });
    }

    // Record SSL check
    checks++;
    if (!domainResult.sslValid) {
      alerts++;
      await db.insert(vendorMonitoring).values({
        orgId,
        vendorId,
        checkType: "ssl_certificate",
        status: "alert",
        severity: "critical",
        details: `SSL certificate for ${domain} is invalid or expired`,
        currentValue: "invalid",
      });
    } else {
      await db.insert(vendorMonitoring).values({
        orgId,
        vendorId,
        checkType: "ssl_certificate",
        status: "ok",
        severity: "info",
        details: `SSL certificate for ${domain} is valid`,
        currentValue: "valid",
      });
    }

    // Record security headers check
    checks++;
    const headerCount = Object.values(domainResult.securityHeaders).filter(Boolean).length;
    const totalHeaders = Object.keys(domainResult.securityHeaders).length;
    const headerScore = totalHeaders > 0 ? Math.round((headerCount / totalHeaders) * 100) : 0;

    if (headerScore < 50) {
      alerts++;
      await db.insert(vendorMonitoring).values({
        orgId,
        vendorId,
        checkType: "security_headers",
        status: "warning",
        severity: "medium",
        details: `Only ${headerCount}/${totalHeaders} security headers present on ${domain}`,
        currentValue: `${headerScore}%`,
        metadata: domainResult.securityHeaders,
      });
    } else {
      await db.insert(vendorMonitoring).values({
        orgId,
        vendorId,
        checkType: "security_headers",
        status: "ok",
        severity: "info",
        details: `${headerCount}/${totalHeaders} security headers present on ${domain}`,
        currentValue: `${headerScore}%`,
        metadata: domainResult.securityHeaders,
      });
    }

    // Record HTTP status check
    if (domainResult.httpStatus !== null) {
      checks++;
      const isDown = domainResult.httpStatus >= 500;
      if (isDown) {
        alerts++;
      }
      await db.insert(vendorMonitoring).values({
        orgId,
        vendorId,
        checkType: "http_status",
        status: isDown ? "alert" : "ok",
        severity: isDown ? "high" : "info",
        details: `HTTP status ${domainResult.httpStatus} for ${domain}`,
        currentValue: String(domainResult.httpStatus),
      });
    }

    // Update vendor's security score based on domain checks
    const securityScore = calculateVendorRiskScore({
      domainHealth: domainResult.dnsResolvable ? 100 : 0,
      sslStatus: domainResult.sslValid ? 100 : 0,
      securityHeaders: headerScore,
      certExpiry: domainResult.sslValid ? 80 : 0,
      breachHistory: 80, // Default — would come from breach feed
      assessmentScore: 70, // Default — would come from latest assessment
      dataAccessRisk: 60, // Default — would come from contract mapping
    });

    await db
      .update(vendors)
      .set({
        securityScore,
        riskTier: scoreToRiskTier(securityScore),
        updatedAt: new Date(),
      })
      .where(and(eq(vendors.id, vendorId), eq(vendors.orgId, orgId)));

    log.info("Vendor monitoring complete", { vendorId, domain, checks, alerts, securityScore });
  } catch (err) {
    log.error("Vendor monitoring failed", { vendorId, domain, error: String(err) });
  }

  return { checks, alerts };
}

/**
 * Run monitoring for all active vendors in an org.
 */
export async function runOrgVendorMonitoring(orgId: string): Promise<{
  vendorsChecked: number;
  totalChecks: number;
  totalAlerts: number;
}> {
  const activeVendors = await db
    .select({ id: vendors.id, domain: vendors.domain })
    .from(vendors)
    .where(and(eq(vendors.orgId, orgId), eq(vendors.status, "active")));

  let totalChecks = 0;
  let totalAlerts = 0;

  for (const vendor of activeVendors) {
    const result = await monitorVendor(orgId, vendor.id, vendor.domain);
    totalChecks += result.checks;
    totalAlerts += result.alerts;
  }

  log.info("Org vendor monitoring complete", {
    orgId,
    vendorsChecked: activeVendors.length,
    totalChecks,
    totalAlerts,
  });

  return {
    vendorsChecked: activeVendors.length,
    totalChecks,
    totalAlerts,
  };
}

// ── Breach Alert Processing ──────────────────────────────────────

/**
 * Check if a vendor was affected by a known breach.
 */
export async function processBreachAlert(
  orgId: string,
  breachData: {
    vendorDomain: string;
    title: string;
    description: string;
    source: string;
    sourceUrl?: string;
    breachDate?: string;
    affectedDataTypes?: string[];
    severity?: string;
  },
): Promise<{ alerted: boolean; vendorId?: string; alertId?: string }> {
  // Find vendor by domain
  const [vendor] = await db
    .select()
    .from(vendors)
    .where(and(eq(vendors.orgId, orgId), eq(vendors.domain, breachData.vendorDomain)))
    .limit(1);

  if (!vendor) {
    return { alerted: false };
  }

  // Check for duplicate alerts
  const [existing] = await db
    .select({ id: vendorBreachAlerts.id })
    .from(vendorBreachAlerts)
    .where(
      and(
        eq(vendorBreachAlerts.orgId, orgId),
        eq(vendorBreachAlerts.vendorId, vendor.id),
        eq(vendorBreachAlerts.title, breachData.title),
      ),
    )
    .limit(1);

  if (existing) {
    return { alerted: false, vendorId: vendor.id };
  }

  // Create breach alert
  const [alert] = await db
    .insert(vendorBreachAlerts)
    .values({
      orgId,
      vendorId: vendor.id,
      title: breachData.title,
      description: breachData.description,
      source: breachData.source,
      sourceUrl: breachData.sourceUrl || null,
      breachDate: breachData.breachDate ? new Date(breachData.breachDate) : null,
      affectedDataTypes: breachData.affectedDataTypes || null,
      severity: breachData.severity || "high",
      impactAssessment:
        `Vendor "${vendor.name}" (${vendor.category}) is used by your organization. ` +
        `Data access level: ${vendor.dataAccessLevel || "unknown"}. ` +
        `Data types: ${(vendor.dataTypes || []).join(", ") || "not mapped"}.`,
    })
    .returning();

  // Move vendor to under_review status
  await db.update(vendors).set({ status: "under_review", updatedAt: new Date() }).where(eq(vendors.id, vendor.id));

  log.warn("Vendor breach alert created", {
    orgId,
    vendorId: vendor.id,
    vendorName: vendor.name,
    alertId: alert.id,
    title: breachData.title,
  });

  return { alerted: true, vendorId: vendor.id, alertId: alert.id };
}

// ── Questionnaire Templates ──────────────────────────────────────

export interface QuestionnaireQuestion {
  id: string;
  section: string;
  question: string;
  type: "yes_no" | "text" | "select" | "multi_select" | "file_upload";
  options?: string[];
  required: boolean;
  weight: number;
}

const CAIQ_TEMPLATE: QuestionnaireQuestion[] = [
  {
    id: "caiq-1",
    section: "Access Control",
    question: "Do you enforce multi-factor authentication for all administrative access?",
    type: "yes_no",
    required: true,
    weight: 10,
  },
  {
    id: "caiq-2",
    section: "Access Control",
    question: "Do you enforce role-based access control (RBAC)?",
    type: "yes_no",
    required: true,
    weight: 8,
  },
  {
    id: "caiq-3",
    section: "Access Control",
    question: "Do you perform regular access reviews?",
    type: "select",
    options: ["Quarterly", "Semi-annually", "Annually", "Never"],
    required: true,
    weight: 7,
  },
  {
    id: "caiq-4",
    section: "Data Security",
    question: "Is data encrypted at rest using AES-256 or equivalent?",
    type: "yes_no",
    required: true,
    weight: 10,
  },
  {
    id: "caiq-5",
    section: "Data Security",
    question: "Is data encrypted in transit using TLS 1.2+?",
    type: "yes_no",
    required: true,
    weight: 10,
  },
  {
    id: "caiq-6",
    section: "Data Security",
    question: "Do you have a data classification policy?",
    type: "yes_no",
    required: true,
    weight: 6,
  },
  {
    id: "caiq-7",
    section: "Incident Management",
    question: "Do you have a documented incident response plan?",
    type: "yes_no",
    required: true,
    weight: 9,
  },
  {
    id: "caiq-8",
    section: "Incident Management",
    question: "What is your breach notification SLA?",
    type: "select",
    options: ["24 hours", "48 hours", "72 hours", "7 days", "No SLA"],
    required: true,
    weight: 8,
  },
  {
    id: "caiq-9",
    section: "Business Continuity",
    question: "Do you maintain business continuity / disaster recovery plans?",
    type: "yes_no",
    required: true,
    weight: 7,
  },
  {
    id: "caiq-10",
    section: "Business Continuity",
    question: "How often do you test DR plans?",
    type: "select",
    options: ["Quarterly", "Semi-annually", "Annually", "Never"],
    required: true,
    weight: 6,
  },
  {
    id: "caiq-11",
    section: "Compliance",
    question: "Which certifications do you hold?",
    type: "multi_select",
    options: ["SOC 2 Type II", "ISO 27001", "PCI DSS", "HIPAA", "FedRAMP", "CSA STAR", "None"],
    required: true,
    weight: 9,
  },
  {
    id: "caiq-12",
    section: "Compliance",
    question: "When was your last penetration test?",
    type: "select",
    options: ["Within 3 months", "Within 6 months", "Within 12 months", "Over 12 months ago", "Never"],
    required: true,
    weight: 8,
  },
  {
    id: "caiq-13",
    section: "Vulnerability Management",
    question: "Do you have an active vulnerability management program?",
    type: "yes_no",
    required: true,
    weight: 8,
  },
  {
    id: "caiq-14",
    section: "Vulnerability Management",
    question: "What is your critical vulnerability SLA?",
    type: "select",
    options: ["24 hours", "48 hours", "7 days", "30 days", "No SLA"],
    required: true,
    weight: 7,
  },
  {
    id: "caiq-15",
    section: "Supply Chain",
    question: "Do you assess the security of your own third-party vendors?",
    type: "yes_no",
    required: true,
    weight: 6,
  },
];

const SIG_LITE_TEMPLATE: QuestionnaireQuestion[] = [
  {
    id: "sig-1",
    section: "Risk Management",
    question: "Does the organization have a formal information security program?",
    type: "yes_no",
    required: true,
    weight: 10,
  },
  {
    id: "sig-2",
    section: "Risk Management",
    question: "Is there an assigned CISO or equivalent?",
    type: "yes_no",
    required: true,
    weight: 8,
  },
  {
    id: "sig-3",
    section: "Security Policy",
    question: "Are security policies reviewed at least annually?",
    type: "yes_no",
    required: true,
    weight: 7,
  },
  {
    id: "sig-4",
    section: "Asset Management",
    question: "Do you maintain an inventory of information assets?",
    type: "yes_no",
    required: true,
    weight: 6,
  },
  {
    id: "sig-5",
    section: "Human Resources",
    question: "Are background checks performed for employees with access to sensitive data?",
    type: "yes_no",
    required: true,
    weight: 7,
  },
  {
    id: "sig-6",
    section: "Human Resources",
    question: "Is security awareness training provided at least annually?",
    type: "yes_no",
    required: true,
    weight: 6,
  },
  {
    id: "sig-7",
    section: "Physical Security",
    question: "Are data centers physically secured with access controls?",
    type: "yes_no",
    required: true,
    weight: 7,
  },
  {
    id: "sig-8",
    section: "Operations",
    question: "Do you have change management procedures?",
    type: "yes_no",
    required: true,
    weight: 6,
  },
  {
    id: "sig-9",
    section: "Network Security",
    question: "Are firewalls and IDS/IPS deployed?",
    type: "yes_no",
    required: true,
    weight: 8,
  },
  {
    id: "sig-10",
    section: "Application Security",
    question: "Is SAST/DAST performed on applications?",
    type: "yes_no",
    required: true,
    weight: 7,
  },
];

export function getQuestionnaireTemplate(type: string): QuestionnaireQuestion[] {
  switch (type) {
    case "caiq":
      return CAIQ_TEMPLATE;
    case "sig_lite":
      return SIG_LITE_TEMPLATE;
    case "sig_full":
      return [...SIG_LITE_TEMPLATE, ...CAIQ_TEMPLATE]; // Combined for sig_full
    default:
      return CAIQ_TEMPLATE; // Default to CAIQ
  }
}

/**
 * Score a completed questionnaire based on responses.
 */
export function scoreQuestionnaire(
  template: QuestionnaireQuestion[],
  responses: Record<string, unknown>,
): { score: number; maxScore: number; riskRating: string } {
  let totalWeight = 0;
  let earnedWeight = 0;

  for (const q of template) {
    totalWeight += q.weight;
    const answer = responses[q.id];

    if (answer === undefined || answer === null) continue;

    if (q.type === "yes_no") {
      if (answer === true || answer === "yes" || answer === "Yes") {
        earnedWeight += q.weight;
      }
    } else if (q.type === "select") {
      // First option is best, last is worst
      const options = q.options || [];
      const idx = options.indexOf(String(answer));
      if (idx >= 0 && options.length > 1) {
        earnedWeight += q.weight * (1 - idx / (options.length - 1));
      }
    } else if (q.type === "multi_select") {
      // More selections = better (for certs)
      const selected = Array.isArray(answer) ? answer : [];
      const options = q.options || [];
      const noneIdx = options.indexOf("None");
      const validOptions = noneIdx >= 0 ? options.length - 1 : options.length;
      if (validOptions > 0 && !selected.includes("None")) {
        earnedWeight += q.weight * Math.min(selected.length / validOptions, 1);
      }
    } else if (q.type === "text" || q.type === "file_upload") {
      // Any answer = full credit
      if (String(answer).trim().length > 0) {
        earnedWeight += q.weight;
      }
    }
  }

  const score = totalWeight > 0 ? Math.round((earnedWeight / totalWeight) * 100) : 0;

  let riskRating: string;
  if (score >= 90) riskRating = "minimal";
  else if (score >= 75) riskRating = "low";
  else if (score >= 50) riskRating = "medium";
  else if (score >= 25) riskRating = "high";
  else riskRating = "critical";

  return { score, maxScore: 100, riskRating };
}

// ── Review Cadence Calculator ────────────────────────────────────

/**
 * Calculate next review date based on risk tier.
 */
export function calculateNextReviewDate(riskTier: string, fromDate?: Date): Date {
  const base = fromDate || new Date();
  const next = new Date(base);

  switch (riskTier) {
    case "critical":
      next.setMonth(next.getMonth() + 1); // Monthly
      break;
    case "high":
      next.setMonth(next.getMonth() + 3); // Quarterly
      break;
    case "medium":
      next.setMonth(next.getMonth() + 6); // Semi-annually
      break;
    case "low":
    case "minimal":
    default:
      next.setFullYear(next.getFullYear() + 1); // Annually
      break;
  }

  return next;
}

/**
 * Get review cadence label for a risk tier.
 */
export function getReviewCadence(riskTier: string): string {
  switch (riskTier) {
    case "critical":
      return "monthly";
    case "high":
      return "quarterly";
    case "medium":
      return "semi_annually";
    case "low":
    case "minimal":
    default:
      return "annually";
  }
}

// ── Fourth-Party Risk ────────────────────────────────────────────

export interface FourthPartyVendor {
  name: string;
  domain: string;
  service: string;
  riskTier?: string;
}

/**
 * Get aggregate fourth-party risk summary for an org.
 */
export async function getFourthPartyRiskSummary(orgId: string): Promise<{
  totalFourthParties: number;
  uniqueFourthParties: number;
  highRiskCount: number;
  byVendor: Array<{ vendorId: string; vendorName: string; fourthPartyCount: number }>;
}> {
  const allVendors = await db
    .select({
      id: vendors.id,
      name: vendors.name,
      fourthPartyVendors: vendors.fourthPartyVendors,
    })
    .from(vendors)
    .where(and(eq(vendors.orgId, orgId), eq(vendors.status, "active")));

  const uniqueSet = new Set<string>();
  let totalCount = 0;
  let highRiskCount = 0;
  const byVendor: Array<{ vendorId: string; vendorName: string; fourthPartyCount: number }> = [];

  for (const v of allVendors) {
    const fps = (v.fourthPartyVendors as FourthPartyVendor[] | null) || [];
    totalCount += fps.length;

    for (const fp of fps) {
      uniqueSet.add(fp.domain || fp.name);
      if (fp.riskTier === "critical" || fp.riskTier === "high") {
        highRiskCount++;
      }
    }

    if (fps.length > 0) {
      byVendor.push({ vendorId: v.id, vendorName: v.name, fourthPartyCount: fps.length });
    }
  }

  return {
    totalFourthParties: totalCount,
    uniqueFourthParties: uniqueSet.size,
    highRiskCount,
    byVendor: byVendor.sort((a, b) => b.fourthPartyCount - a.fourthPartyCount),
  };
}

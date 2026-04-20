/**
 * Data Discovery Engine — automated PII/PHI/PCI scanning and classification
 *
 * Provides pattern-based detection of sensitive data fields, risk scoring,
 * and data minimization recommendations.
 */

import { db } from "./db";
import { eq, and, count, isNull } from "drizzle-orm";
import {
  dataAssets,
  dataFlows,
  privacyScans,
  consentRecords,
  crossBorderTransferAlerts,
  dsarFulfillmentTasks,
  dsarRequests,
} from "../shared/schema";
import { logger } from "./logger";

const log = logger.child("data-discovery");

// ── PII Detection Patterns ──────────────────────────────────────────

interface DetectionPattern {
  category: string;
  type: "pii" | "phi" | "pci";
  patterns: RegExp[];
  confidence: number; // 0-1 base confidence
  classification: string; // minimum classification level
  description: string;
}

const DETECTION_PATTERNS: DetectionPattern[] = [
  // PII Patterns
  {
    category: "email",
    type: "pii",
    patterns: [/email/i, /e[-_]?mail/i, /mail[-_]?address/i, /contact[-_]?email/i],
    confidence: 0.95,
    classification: "confidential",
    description: "Email address field",
  },
  {
    category: "name",
    type: "pii",
    patterns: [
      /^(first|last|full|display|given|family|middle)[-_]?name$/i,
      /user[-_]?name$/i,
      /person[-_]?name/i,
      /contact[-_]?name/i,
    ],
    confidence: 0.9,
    classification: "confidential",
    description: "Person name field",
  },
  {
    category: "phone",
    type: "pii",
    patterns: [/phone/i, /mobile/i, /cell/i, /tel(?:ephone)?/i, /fax/i],
    confidence: 0.9,
    classification: "confidential",
    description: "Phone number field",
  },
  {
    category: "address",
    type: "pii",
    patterns: [/address/i, /street/i, /city/i, /state/i, /zip[-_]?code/i, /postal[-_]?code/i, /country/i, /province/i],
    confidence: 0.85,
    classification: "confidential",
    description: "Physical address field",
  },
  {
    category: "ssn",
    type: "pii",
    patterns: [/ssn/i, /social[-_]?security/i, /tax[-_]?id/i, /tin/i],
    confidence: 0.98,
    classification: "restricted",
    description: "Social Security Number / Tax ID",
  },
  {
    category: "national_id",
    type: "pii",
    patterns: [/national[-_]?id/i, /id[-_]?number/i, /citizen[-_]?id/i, /aadhaar/i, /pan[-_]?number/i],
    confidence: 0.95,
    classification: "restricted",
    description: "National identification number",
  },
  {
    category: "passport",
    type: "pii",
    patterns: [/passport/i, /travel[-_]?doc/i],
    confidence: 0.95,
    classification: "restricted",
    description: "Passport number",
  },
  {
    category: "date_of_birth",
    type: "pii",
    patterns: [/d[ao]b/i, /date[-_]?of[-_]?birth/i, /birth[-_]?date/i, /birthday/i],
    confidence: 0.92,
    classification: "confidential",
    description: "Date of birth",
  },
  {
    category: "ip_address",
    type: "pii",
    patterns: [/ip[-_]?addr/i, /client[-_]?ip/i, /source[-_]?ip/i, /remote[-_]?addr/i],
    confidence: 0.88,
    classification: "internal",
    description: "IP address",
  },
  {
    category: "location",
    type: "pii",
    patterns: [/latitude/i, /longitude/i, /geo[-_]?loc/i, /coordinates/i, /gps/i],
    confidence: 0.9,
    classification: "confidential",
    description: "Geolocation data",
  },
  {
    category: "biometric",
    type: "pii",
    patterns: [/biometric/i, /fingerprint/i, /face[-_]?id/i, /retina/i, /iris[-_]?scan/i, /voice[-_]?print/i],
    confidence: 0.98,
    classification: "restricted",
    description: "Biometric data",
  },
  {
    category: "device_id",
    type: "pii",
    patterns: [/device[-_]?id/i, /imei/i, /mac[-_]?addr/i, /serial[-_]?number/i, /hardware[-_]?id/i],
    confidence: 0.8,
    classification: "internal",
    description: "Device identifier",
  },
  {
    category: "cookie_id",
    type: "pii",
    patterns: [/cookie[-_]?id/i, /tracking[-_]?id/i, /session[-_]?id/i, /visitor[-_]?id/i],
    confidence: 0.75,
    classification: "internal",
    description: "Online identifier / cookie",
  },
  {
    category: "password_hash",
    type: "pii",
    patterns: [/password/i, /passwd/i, /pwd/i, /secret/i, /hash/i, /salt/i],
    confidence: 0.85,
    classification: "restricted",
    description: "Password or credential data",
  },

  // PHI (Protected Health Information) Patterns
  {
    category: "health_record",
    type: "phi",
    patterns: [
      /diagnosis/i,
      /medical[-_]?record/i,
      /health[-_]?condition/i,
      /treatment/i,
      /prescription/i,
      /medication/i,
      /allergy/i,
      /blood[-_]?type/i,
      /icd[-_]?code/i,
      /patient[-_]?id/i,
      /mrn/i,
      /npi/i,
    ],
    confidence: 0.95,
    classification: "restricted",
    description: "Protected health information",
  },
  {
    category: "genetic_data",
    type: "phi",
    patterns: [/genetic/i, /dna/i, /genome/i, /genotype/i, /hereditary/i],
    confidence: 0.98,
    classification: "top_secret",
    description: "Genetic/genomic data",
  },

  // PCI (Payment Card Industry) Patterns
  {
    category: "credit_card",
    type: "pci",
    patterns: [/credit[-_]?card/i, /card[-_]?number/i, /pan/i, /ccn/i, /cvv/i, /cvc/i, /expiry/i, /cardholder/i],
    confidence: 0.95,
    classification: "restricted",
    description: "Payment card data",
  },
  {
    category: "financial_account",
    type: "pci",
    patterns: [
      /account[-_]?number/i,
      /bank[-_]?account/i,
      /routing[-_]?number/i,
      /iban/i,
      /swift/i,
      /bic/i,
      /sort[-_]?code/i,
    ],
    confidence: 0.92,
    classification: "restricted",
    description: "Financial account information",
  },
];

// ── Classification Logic ────────────────────────────────────────────

const CLASSIFICATION_HIERARCHY: Record<string, number> = {
  public: 0,
  internal: 1,
  confidential: 2,
  restricted: 3,
  top_secret: 4,
};

function higherClassification(a: string, b: string): string {
  return (CLASSIFICATION_HIERARCHY[a] ?? 0) >= (CLASSIFICATION_HIERARCHY[b] ?? 0) ? a : b;
}

export interface ScanResult {
  field: string;
  detectedType: string;
  confidence: number;
  sampleCount: number;
  classification: string;
  category: "pii" | "phi" | "pci";
}

export interface MinimizationFinding {
  field: string;
  reason: string;
  recommendation: string;
}

/**
 * Scan a list of field names for PII/PHI/PCI patterns
 */
export function scanFieldNames(fields: string[]): {
  results: ScanResult[];
  minimizationFindings: MinimizationFinding[];
  overallClassification: string;
  piiCount: number;
  phiCount: number;
  pciCount: number;
} {
  const results: ScanResult[] = [];
  const minimizationFindings: MinimizationFinding[] = [];
  let overallClassification = "public";
  let piiCount = 0;
  let phiCount = 0;
  let pciCount = 0;

  for (const field of fields) {
    for (const pattern of DETECTION_PATTERNS) {
      const matched = pattern.patterns.some((p) => p.test(field));
      if (matched) {
        results.push({
          field,
          detectedType: pattern.category,
          confidence: pattern.confidence,
          sampleCount: 0,
          classification: pattern.classification,
          category: pattern.type,
        });
        overallClassification = higherClassification(overallClassification, pattern.classification);

        if (pattern.type === "pii") piiCount++;
        else if (pattern.type === "phi") phiCount++;
        else if (pattern.type === "pci") pciCount++;

        break; // first match wins for each field
      }
    }
  }

  // Generate minimization recommendations
  const sensitiveFields = results.filter((r) => r.classification === "restricted" || r.classification === "top_secret");
  for (const sf of sensitiveFields) {
    minimizationFindings.push({
      field: sf.field,
      reason: `Field "${sf.field}" contains ${sf.detectedType} data (${sf.classification} classification)`,
      recommendation: `Consider whether ${sf.detectedType} data is necessary for this feature. If not, remove or anonymize it. If needed, ensure encryption at rest and strict access controls.`,
    });
  }

  return { results, minimizationFindings, overallClassification, piiCount, phiCount, pciCount };
}

// ── Risk Scoring ────────────────────────────────────────────────────

interface RiskFactors {
  classification: string;
  piiCategories: string[];
  isEncrypted: boolean;
  hasRetentionPolicy: boolean;
  jurisdiction: string;
  isCrossBorder: boolean;
  recordCount: number;
  dataSubjectCount: number;
}

const HIGH_RISK_JURISDICTIONS = ["EU", "US-CA", "BR", "UK"];
const SENSITIVE_PII = ["ssn", "national_id", "passport", "biometric", "genetic_data", "health_record", "credit_card"];

export function computePrivacyRiskScore(factors: RiskFactors): number {
  let score = 0;

  // Classification weight (0-30)
  const classScore = CLASSIFICATION_HIERARCHY[factors.classification] ?? 0;
  score += classScore * 7.5;

  // PII sensitivity (0-25)
  const sensitiveCount = factors.piiCategories.filter((c) => SENSITIVE_PII.includes(c)).length;
  score += Math.min(25, sensitiveCount * 8);

  // Volume factor (0-15)
  if (factors.dataSubjectCount > 100000) score += 15;
  else if (factors.dataSubjectCount > 10000) score += 10;
  else if (factors.dataSubjectCount > 1000) score += 5;

  // Encryption (0-10)
  if (!factors.isEncrypted) score += 10;

  // Retention policy (0-5)
  if (!factors.hasRetentionPolicy) score += 5;

  // Jurisdiction risk (0-10)
  if (HIGH_RISK_JURISDICTIONS.includes(factors.jurisdiction)) score += 5;
  if (factors.isCrossBorder) score += 5;

  // Record count (0-5)
  if (factors.recordCount > 1000000) score += 5;
  else if (factors.recordCount > 100000) score += 3;

  return Math.min(100, Math.round(score));
}

// ── Cross-Border Transfer Risk Assessment ───────────────────────────

interface TransferRisk {
  riskLevel: "negligible" | "low" | "medium" | "high" | "very_high";
  reasons: string[];
  requiredMechanisms: string[];
}

const ADEQUACY_DECISIONS = ["EU", "UK", "JP", "KR", "CA", "NZ", "IL"];

export function assessCrossBorderRisk(
  sourceJurisdiction: string,
  destJurisdiction: string,
  dataCategories: string[],
): TransferRisk {
  const reasons: string[] = [];
  const requiredMechanisms: string[] = [];
  let riskScore = 0;

  if (sourceJurisdiction === destJurisdiction) {
    return { riskLevel: "negligible", reasons: ["Same jurisdiction transfer"], requiredMechanisms: [] };
  }

  // EU source rules
  if (sourceJurisdiction === "EU" || sourceJurisdiction === "UK") {
    if (!ADEQUACY_DECISIONS.includes(destJurisdiction)) {
      riskScore += 3;
      reasons.push(`No adequacy decision for ${destJurisdiction} — SCCs or BCRs required`);
      requiredMechanisms.push("Standard Contractual Clauses (SCCs)");
    }
    if (destJurisdiction === "US") {
      riskScore += 2;
      reasons.push("US lacks blanket adequacy — verify EU-US Data Privacy Framework certification");
      requiredMechanisms.push("EU-US Data Privacy Framework");
    }
    if (destJurisdiction === "CN") {
      riskScore += 3;
      reasons.push("China has data localization requirements — additional risk assessment needed");
      requiredMechanisms.push("Transfer Impact Assessment (TIA)");
    }
  }

  // Brazil LGPD
  if (sourceJurisdiction === "BR") {
    riskScore += 2;
    reasons.push("LGPD requires adequate protection for international transfers");
    requiredMechanisms.push("LGPD-compliant transfer mechanism");
  }

  // India DPDPA
  if (sourceJurisdiction === "IN") {
    riskScore += 1;
    reasons.push("DPDPA permits transfers to non-restricted countries");
  }

  // Sensitive data multiplier
  const hasSensitive = dataCategories.some((c) => SENSITIVE_PII.includes(c));
  if (hasSensitive) {
    riskScore += 2;
    reasons.push("Transfer includes sensitive/special category data — heightened safeguards required");
    requiredMechanisms.push("Data Protection Impact Assessment (DPIA)");
  }

  let riskLevel: TransferRisk["riskLevel"];
  if (riskScore <= 1) riskLevel = "low";
  else if (riskScore <= 3) riskLevel = "medium";
  else if (riskScore <= 5) riskLevel = "high";
  else riskLevel = "very_high";

  return { riskLevel, reasons, requiredMechanisms };
}

// ── Data Minimization Analysis ──────────────────────────────────────

interface MinimizationReport {
  assetName: string;
  totalFields: number;
  sensitiveFields: number;
  recommendations: Array<{
    field: string;
    currentClassification: string;
    recommendation: string;
    priority: "high" | "medium" | "low";
  }>;
  overallScore: number; // 0-100, 100 = fully minimized
}

export function generateMinimizationReport(assetName: string, fields: string[], purpose: string): MinimizationReport {
  const scanResult = scanFieldNames(fields);
  const recommendations: MinimizationReport["recommendations"] = [];

  for (const finding of scanResult.results) {
    const isSensitive = SENSITIVE_PII.includes(finding.detectedType);
    recommendations.push({
      field: finding.field,
      currentClassification: finding.classification,
      recommendation: isSensitive
        ? `High-sensitivity field "${finding.field}" (${finding.detectedType}). Verify this is strictly necessary for "${purpose}". Consider tokenization or pseudonymization.`
        : `Field "${finding.field}" contains ${finding.detectedType} data. Review whether full values are needed or if truncation/masking suffices.`,
      priority: isSensitive ? "high" : finding.classification === "confidential" ? "medium" : "low",
    });
  }

  const sensitiveRatio = fields.length > 0 ? scanResult.results.length / fields.length : 0;
  const overallScore = Math.round((1 - sensitiveRatio) * 100);

  return {
    assetName,
    totalFields: fields.length,
    sensitiveFields: scanResult.results.length,
    recommendations,
    overallScore,
  };
}

// ── Privacy Dashboard Aggregation ───────────────────────────────────

export interface PrivacyDashboard {
  totalDataAssets: number;
  classificationBreakdown: Record<string, number>;
  piiFieldCount: number;
  phiFieldCount: number;
  pciFieldCount: number;
  crossBorderFlows: number;
  openAlerts: number;
  pendingDsars: number;
  activePias: number;
  activeConsents: number;
  averageRiskScore: number;
  jurisdictionBreakdown: Record<string, number>;
  recentScans: Array<{
    id: string;
    scanType: string;
    status: string;
    findingsCount: number;
    startedAt: string;
    completedAt: string | null;
  }>;
  // Data map visualization: asset type breakdown
  assetTypeBreakdown: Record<string, number>;
  // Consent management: purpose breakdown
  consentPurposeBreakdown: Record<string, number>;
  // Automated data discovery stats
  discoveryStats: {
    lastScanAt: string | null;
    totalFindings: number;
    autoClassified: number;
  };
  // Data retention enforcement summary
  retentionSummary: {
    withRetention: number;
    withoutRetention: number;
    expiredRetention: number;
  };
  enums: {
    classificationLevels: readonly string[];
    piiCategories: readonly string[];
    assetTypes: readonly string[];
    flowStatuses: readonly string[];
    piaStatuses: readonly string[];
    piaRiskLevels: readonly string[];
    consentPurposes: readonly string[];
    dsarTypes: readonly string[];
    jurisdictions: readonly string[];
  };
}

export async function getPrivacyDashboard(orgId: string): Promise<PrivacyDashboard> {
  const { desc } = await import("drizzle-orm");
  const {
    DATA_CLASSIFICATION_LEVELS,
    PII_CATEGORIES,
    DATA_ASSET_TYPES,
    DATA_FLOW_STATUSES,
    PIA_STATUSES,
    PIA_RISK_LEVELS,
    CONSENT_PURPOSES,
    DSAR_TYPES,
    JURISDICTIONS,
    privacyImpactAssessments,
  } = await import("../shared/schema");

  const [
    assets,
    [{ value: crossBorderCount }],
    [{ value: openAlertCount }],
    [{ value: pendingDsarCount }],
    [{ value: activePiaCount }],
    [{ value: activeConsentCount }],
    recentScanRows,
  ] = await Promise.all([
    db.select().from(dataAssets).where(eq(dataAssets.orgId, orgId)),
    db
      .select({ value: count() })
      .from(dataFlows)
      .where(and(eq(dataFlows.orgId, orgId), eq(dataFlows.isCrossBorder, true))),
    db
      .select({ value: count() })
      .from(crossBorderTransferAlerts)
      .where(
        and(
          eq(crossBorderTransferAlerts.orgId, orgId),
          eq(crossBorderTransferAlerts.requiresAction, true),
          isNull(crossBorderTransferAlerts.resolvedAt),
        ),
      ),
    db
      .select({ value: count() })
      .from(dsarRequests)
      .where(and(eq(dsarRequests.orgId, orgId), eq(dsarRequests.status, "pending"))),
    db
      .select({ value: count() })
      .from(privacyImpactAssessments)
      .where(and(eq(privacyImpactAssessments.orgId, orgId), eq(privacyImpactAssessments.status, "in_review"))),
    db
      .select({ value: count() })
      .from(consentRecords)
      .where(and(eq(consentRecords.orgId, orgId), eq(consentRecords.granted, true))),
    db.select().from(privacyScans).where(eq(privacyScans.orgId, orgId)).orderBy(desc(privacyScans.startedAt)).limit(5),
  ]);

  // Aggregate classification breakdown
  const classificationBreakdown: Record<string, number> = {};
  const jurisdictionBreakdown: Record<string, number> = {};
  // Data map: asset type breakdown
  const assetTypeBreakdown: Record<string, number> = {};
  let totalPii = 0;
  let totalPhi = 0;
  let totalPci = 0;
  let riskSum = 0;
  // Retention tracking
  let withRetention = 0;
  let withoutRetention = 0;
  let expiredRetention = 0;

  for (const asset of assets) {
    classificationBreakdown[asset.classification] = (classificationBreakdown[asset.classification] || 0) + 1;
    jurisdictionBreakdown[asset.jurisdiction] = (jurisdictionBreakdown[asset.jurisdiction] || 0) + 1;
    assetTypeBreakdown[asset.assetType] = (assetTypeBreakdown[asset.assetType] || 0) + 1;
    riskSum += asset.riskScore;

    // Retention policy tracking
    const retentionPeriod = (asset as Record<string, unknown>).retentionPeriod as string | null | undefined;
    if (retentionPeriod) {
      withRetention++;
      // Check if retention has expired (simple heuristic based on creation date)
      const createdAt = asset.createdAt ? new Date(asset.createdAt).getTime() : 0;
      const retentionDays = parseInt(retentionPeriod, 10) || 365;
      if (createdAt > 0 && Date.now() - createdAt > retentionDays * 24 * 60 * 60 * 1000) {
        expiredRetention++;
      }
    } else {
      withoutRetention++;
    }

    const cats = (asset.piiCategories as string[]) || [];
    for (const cat of cats) {
      if (["health_record", "genetic_data"].includes(cat)) totalPhi++;
      else if (["credit_card", "financial_account"].includes(cat)) totalPci++;
      else totalPii++;
    }
  }

  // Consent purpose breakdown
  const consentRows = await db
    .select()
    .from(consentRecords)
    .where(and(eq(consentRecords.orgId, orgId), eq(consentRecords.granted, true)));
  const consentPurposeBreakdown: Record<string, number> = {};
  for (const row of consentRows) {
    consentPurposeBreakdown[row.purpose] = (consentPurposeBreakdown[row.purpose] || 0) + 1;
  }

  // Discovery stats
  const totalFindings = recentScanRows.reduce((sum, s) => sum + s.findingsCount, 0);
  const lastScan = recentScanRows.length > 0 ? recentScanRows[0] : null;
  const autoClassified = assets.filter((a) => (a as Record<string, unknown>).discoveredBy === "auto_scan").length;

  return {
    totalDataAssets: assets.length,
    classificationBreakdown,
    piiFieldCount: totalPii,
    phiFieldCount: totalPhi,
    pciFieldCount: totalPci,
    crossBorderFlows: Number(crossBorderCount),
    openAlerts: Number(openAlertCount),
    pendingDsars: Number(pendingDsarCount),
    activePias: Number(activePiaCount),
    activeConsents: Number(activeConsentCount),
    averageRiskScore: assets.length > 0 ? Math.round(riskSum / assets.length) : 0,
    jurisdictionBreakdown,
    recentScans: recentScanRows.map((s) => ({
      id: s.id,
      scanType: s.scanType,
      status: s.status,
      findingsCount: s.findingsCount,
      startedAt: s.startedAt.toISOString(),
      completedAt: s.completedAt?.toISOString() ?? null,
    })),
    assetTypeBreakdown,
    consentPurposeBreakdown,
    discoveryStats: {
      lastScanAt: lastScan?.startedAt?.toISOString() ?? null,
      totalFindings,
      autoClassified,
    },
    retentionSummary: {
      withRetention,
      withoutRetention,
      expiredRetention,
    },
    enums: {
      classificationLevels: DATA_CLASSIFICATION_LEVELS,
      piiCategories: PII_CATEGORIES,
      assetTypes: DATA_ASSET_TYPES,
      flowStatuses: DATA_FLOW_STATUSES,
      piaStatuses: PIA_STATUSES,
      piaRiskLevels: PIA_RISK_LEVELS,
      consentPurposes: CONSENT_PURPOSES,
      dsarTypes: DSAR_TYPES,
      jurisdictions: JURISDICTIONS,
    },
  };
}

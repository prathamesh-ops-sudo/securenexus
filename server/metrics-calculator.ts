import { db } from "./db";
import { sql, eq, and, gte, lte, count, desc, avg } from "drizzle-orm";
import {
  alerts,
  incidents,
  connectors,
  securityKpiSnapshots,
  vulnerabilitySlaTargets,
  securityToolOverlaps,
  responseActions,
} from "../shared/schema";
import { logger } from "./routes/shared";

const log = logger.child("metrics-calculator");

// ─── MTTR / MTTD Calculations ────────────────────────────────────────────────

export interface MttrMttdResult {
  mttrMinutes: number;
  mttdMinutes: number;
  mttrTrend: number; // % change from previous period
  mttdTrend: number;
  sampleSize: number;
  bySeverity: Record<string, { mttr: number; mttd: number; count: number }>;
}

export async function computeMttrMttd(orgId: string, periodStart: Date, periodEnd: Date): Promise<MttrMttdResult> {
  // MTTR: time from incident creation to resolution
  const resolvedIncidents = await db
    .select({
      severity: incidents.severity,
      createdAt: incidents.createdAt,
      resolvedAt: incidents.resolvedAt,
      detectedAt: sql<Date>`COALESCE(${incidents.createdAt}, NOW())`,
    })
    .from(incidents)
    .where(
      and(
        eq(incidents.orgId, orgId),
        gte(incidents.createdAt, periodStart),
        lte(incidents.createdAt, periodEnd),
        sql`${incidents.resolvedAt} IS NOT NULL`,
      ),
    );

  const bySeverity: Record<string, { mttr: number; mttd: number; count: number }> = {};
  let totalMttr = 0;
  let totalMttd = 0;
  let mttrCount = 0;

  for (const inc of resolvedIncidents) {
    if (!inc.createdAt || !inc.resolvedAt) continue;
    const mttrMs = new Date(inc.resolvedAt).getTime() - new Date(inc.createdAt).getTime();
    const mttrMin = mttrMs / 60000;
    // MTTD approximation: time from first alert detection to incident creation
    const mttdMin = 0; // Will be computed separately if alert data available

    const sev = inc.severity || "medium";
    if (!bySeverity[sev]) bySeverity[sev] = { mttr: 0, mttd: 0, count: 0 };
    bySeverity[sev].mttr += mttrMin;
    bySeverity[sev].count += 1;
    totalMttr += mttrMin;
    mttrCount += 1;
  }

  // Compute MTTD from alerts (time from detectedAt to triaged/correlated)
  const triagedAlerts = await db
    .select({
      detectedAt: alerts.detectedAt,
      createdAt: alerts.createdAt,
    })
    .from(alerts)
    .where(
      and(
        eq(alerts.orgId, orgId),
        gte(alerts.createdAt, periodStart),
        lte(alerts.createdAt, periodEnd),
        sql`${alerts.status} IN ('triaged', 'correlated', 'investigating', 'resolved')`,
        sql`${alerts.detectedAt} IS NOT NULL`,
      ),
    )
    .limit(5000);

  let mttdCount = 0;
  for (const alert of triagedAlerts) {
    if (!alert.detectedAt || !alert.createdAt) continue;
    const diff = new Date(alert.createdAt).getTime() - new Date(alert.detectedAt).getTime();
    totalMttd += diff / 60000;
    mttdCount += 1;
  }

  // Finalize averages per severity
  for (const sev of Object.keys(bySeverity)) {
    if (bySeverity[sev].count > 0) {
      bySeverity[sev].mttr = Math.round(bySeverity[sev].mttr / bySeverity[sev].count);
    }
  }

  const avgMttr = mttrCount > 0 ? Math.round(totalMttr / mttrCount) : 0;
  const avgMttd = mttdCount > 0 ? Math.round(totalMttd / mttdCount) : 0;

  // Compute trend vs previous period
  const periodDuration = periodEnd.getTime() - periodStart.getTime();
  const prevStart = new Date(periodStart.getTime() - periodDuration);
  const prevEnd = new Date(periodStart);

  const prevSnapshot = await db
    .select()
    .from(securityKpiSnapshots)
    .where(
      and(
        eq(securityKpiSnapshots.orgId, orgId),
        eq(securityKpiSnapshots.kpiType, "mttr"),
        gte(securityKpiSnapshots.periodStart, prevStart),
        lte(securityKpiSnapshots.periodEnd, prevEnd),
      ),
    )
    .orderBy(desc(securityKpiSnapshots.createdAt))
    .limit(1);

  const prevMttr = prevSnapshot[0]?.value ?? avgMttr;
  const mttrTrend = prevMttr > 0 ? Math.round(((avgMttr - prevMttr) / prevMttr) * 100) : 0;
  const mttdTrend = 0; // no previous MTTD baseline yet

  return {
    mttrMinutes: avgMttr,
    mttdMinutes: avgMttd,
    mttrTrend,
    mttdTrend,
    sampleSize: mttrCount + mttdCount,
    bySeverity,
  };
}

// ─── Security ROI Calculator ─────────────────────────────────────────────────

export interface SecurityRoiResult {
  totalIncidentsPrevented: number;
  estimatedSavings: number;
  costPerIncident: number;
  automatedResponseRate: number;
  meanResponseTimeReduction: number;
  toolSpend: number;
  roiMultiplier: number;
}

const INDUSTRY_COST_PER_INCIDENT: Record<string, number> = {
  finance: 285000,
  healthcare: 410000,
  technology: 195000,
  retail: 165000,
  government: 225000,
  default: 200000,
};

export async function computeSecurityRoi(
  orgId: string,
  periodStart: Date,
  periodEnd: Date,
  industry?: string | null,
): Promise<SecurityRoiResult> {
  const costPerIncident = INDUSTRY_COST_PER_INCIDENT[industry || "default"] || INDUSTRY_COST_PER_INCIDENT.default;

  // Count blocked/auto-resolved alerts (prevented incidents)
  const [{ value: blockedCount }] = await db
    .select({ value: count() })
    .from(alerts)
    .where(
      and(
        eq(alerts.orgId, orgId),
        gte(alerts.createdAt, periodStart),
        lte(alerts.createdAt, periodEnd),
        sql`${alerts.status} IN ('resolved', 'dismissed', 'false_positive')`,
        sql`${alerts.suppressed} = true OR ${alerts.confidenceScore} > 0.8`,
      ),
    );

  // Count automated response actions
  const [{ value: totalActions }] = await db
    .select({ value: count() })
    .from(responseActions)
    .where(
      and(
        eq(responseActions.orgId, orgId),
        gte(responseActions.createdAt, periodStart),
        lte(responseActions.createdAt, periodEnd),
      ),
    );

  const [{ value: autoActions }] = await db
    .select({ value: count() })
    .from(responseActions)
    .where(
      and(
        eq(responseActions.orgId, orgId),
        gte(responseActions.createdAt, periodStart),
        lte(responseActions.createdAt, periodEnd),
        eq(responseActions.status, "completed"),
      ),
    );

  // Approximate incidents prevented = blocked high-confidence alerts / 10 (grouping factor)
  const prevented = Math.max(1, Math.floor(Number(blockedCount) / 10));
  const savings = prevented * costPerIncident;
  const automatedRate = Number(totalActions) > 0 ? Math.round((Number(autoActions) / Number(totalActions)) * 100) : 0;

  // Estimate annual tool spend from active connectors
  const activeConnectors = await db
    .select({ value: count() })
    .from(connectors)
    .where(and(eq(connectors.orgId, orgId), eq(connectors.status, "active")));
  const toolSpend = Number(activeConnectors[0]?.value || 0) * 25000; // $25k avg per tool per year

  const roiMultiplier = toolSpend > 0 ? Math.round((savings / toolSpend) * 10) / 10 : 0;

  return {
    totalIncidentsPrevented: prevented,
    estimatedSavings: savings,
    costPerIncident,
    automatedResponseRate: automatedRate,
    meanResponseTimeReduction: 65, // baseline improvement %
    toolSpend,
    roiMultiplier,
  };
}

// ─── Vulnerability SLA Compliance ────────────────────────────────────────────

export interface SlaComplianceResult {
  overall: number; // percentage
  bySeverity: Record<string, { total: number; compliant: number; breached: number; pct: number }>;
  targets: Array<{ severity: string; targetHours: number }>;
}

export async function computeSlaCompliance(orgId: string): Promise<SlaComplianceResult> {
  const targets = await db
    .select()
    .from(vulnerabilitySlaTargets)
    .where(and(eq(vulnerabilitySlaTargets.orgId, orgId), eq(vulnerabilitySlaTargets.enabled, true)));

  // Default targets if none configured
  const effectiveTargets =
    targets.length > 0
      ? targets
      : [
          { severity: "critical", targetHours: 24 },
          { severity: "high", targetHours: 72 },
          { severity: "medium", targetHours: 168 },
          { severity: "low", targetHours: 720 },
        ];

  const bySeverity: Record<string, { total: number; compliant: number; breached: number; pct: number }> = {};
  let totalAll = 0;
  let compliantAll = 0;

  for (const target of effectiveTargets) {
    const targetMs = target.targetHours * 3600000;

    // Count incidents by SLA compliance
    const allIncidents = await db
      .select({
        createdAt: incidents.createdAt,
        resolvedAt: incidents.resolvedAt,
        status: incidents.status,
      })
      .from(incidents)
      .where(
        and(
          eq(incidents.orgId, orgId),
          eq(incidents.severity, target.severity),
          gte(incidents.createdAt, new Date(Date.now() - 30 * 86400000)), // last 30 days
        ),
      );

    let total = 0;
    let compliant = 0;
    let breached = 0;

    for (const inc of allIncidents) {
      total += 1;
      if (inc.resolvedAt && inc.createdAt) {
        const elapsed = new Date(inc.resolvedAt).getTime() - new Date(inc.createdAt).getTime();
        if (elapsed <= targetMs) {
          compliant += 1;
        } else {
          breached += 1;
        }
      } else if (inc.createdAt) {
        // Still open — check if past SLA
        const elapsed = Date.now() - new Date(inc.createdAt).getTime();
        if (elapsed > targetMs) {
          breached += 1;
        } else {
          compliant += 1;
        }
      }
    }

    bySeverity[target.severity] = {
      total,
      compliant,
      breached,
      pct: total > 0 ? Math.round((compliant / total) * 100) : 100,
    };
    totalAll += total;
    compliantAll += compliant;
  }

  return {
    overall: totalAll > 0 ? Math.round((compliantAll / totalAll) * 100) : 100,
    bySeverity,
    targets: effectiveTargets.map((t) => ({ severity: t.severity, targetHours: t.targetHours })),
  };
}

// ─── Coverage Heatmap ────────────────────────────────────────────────────────

export interface CoverageCell {
  dimension: string;
  category: string;
  covered: boolean;
  sources: string[];
  alertCount: number;
}

export async function computeCoverageHeatmap(orgId: string): Promise<CoverageCell[]> {
  const THREAT_CATEGORIES = [
    "malware",
    "intrusion",
    "phishing",
    "data_exfiltration",
    "privilege_escalation",
    "lateral_movement",
    "credential_access",
    "reconnaissance",
    "persistence",
    "command_and_control",
    "cloud_misconfiguration",
    "policy_violation",
  ];

  // Get alert counts by source × category
  const alertStats = await db
    .select({
      source: alerts.source,
      category: alerts.category,
      cnt: count(),
    })
    .from(alerts)
    .where(and(eq(alerts.orgId, orgId), gte(alerts.createdAt, new Date(Date.now() - 90 * 86400000))))
    .groupBy(alerts.source, alerts.category);

  // Get active sources
  const activeSources = await db
    .select({ name: connectors.name, connectorType: connectors.type })
    .from(connectors)
    .where(and(eq(connectors.orgId, orgId), eq(connectors.status, "active")));

  const sourceNames = activeSources.map((c) => c.name);

  const cells: CoverageCell[] = [];

  for (const category of THREAT_CATEGORIES) {
    const matchingStats = alertStats.filter((s) => s.category === category);
    const coveringSources = matchingStats.map((s) => s.source);
    const totalAlerts = matchingStats.reduce((sum, s) => sum + Number(s.cnt), 0);

    cells.push({
      dimension: "threat_category",
      category,
      covered: coveringSources.length > 0,
      sources: coveringSources,
      alertCount: totalAlerts,
    });
  }

  return cells;
}

// ─── Peer Benchmarking ───────────────────────────────────────────────────────

export interface PeerBenchmark {
  metric: string;
  orgValue: number;
  industryMedian: number;
  industryP25: number;
  industryP75: number;
  percentileRank: number;
  verdict: "above_average" | "average" | "below_average";
}

// Industry benchmarks (static reference data)
const INDUSTRY_BENCHMARKS: Record<string, { median: number; p25: number; p75: number; unit: string }> = {
  mttr: { median: 720, p25: 1440, p75: 240, unit: "minutes" }, // 12h median
  mttd: { median: 180, p25: 360, p75: 60, unit: "minutes" }, // 3h median
  false_positive_rate: { median: 45, p25: 60, p75: 25, unit: "percent" },
  sla_compliance: { median: 78, p25: 60, p75: 92, unit: "percent" },
  automated_response_rate: { median: 35, p25: 15, p75: 60, unit: "percent" },
};

export function computePeerBenchmarks(orgMetrics: Record<string, number>): PeerBenchmark[] {
  const benchmarks: PeerBenchmark[] = [];

  for (const [metric, benchmark] of Object.entries(INDUSTRY_BENCHMARKS)) {
    const orgValue = orgMetrics[metric] ?? 0;
    // For MTTR/MTTD, lower is better; for SLA compliance / automation, higher is better
    const lowerIsBetter = metric === "mttr" || metric === "mttd" || metric === "false_positive_rate";

    let percentileRank: number;
    let verdict: "above_average" | "average" | "below_average";

    if (lowerIsBetter) {
      if (orgValue <= benchmark.p75) {
        percentileRank = 75 + Math.min(25, Math.round(((benchmark.p75 - orgValue) / benchmark.p75) * 25));
        verdict = "above_average";
      } else if (orgValue <= benchmark.median) {
        percentileRank = 50 + Math.round(((benchmark.median - orgValue) / (benchmark.median - benchmark.p75)) * 25);
        verdict = "average";
      } else {
        percentileRank = Math.max(5, 50 - Math.round(((orgValue - benchmark.median) / benchmark.median) * 50));
        verdict = "below_average";
      }
    } else {
      if (orgValue >= benchmark.p75) {
        percentileRank = 75 + Math.min(25, Math.round(((orgValue - benchmark.p75) / benchmark.p75) * 25));
        verdict = "above_average";
      } else if (orgValue >= benchmark.median) {
        percentileRank = 50 + Math.round(((orgValue - benchmark.median) / (benchmark.p75 - benchmark.median)) * 25);
        verdict = "average";
      } else {
        percentileRank = Math.max(5, Math.round((orgValue / benchmark.median) * 50));
        verdict = "below_average";
      }
    }

    benchmarks.push({
      metric,
      orgValue,
      industryMedian: benchmark.median,
      industryP25: benchmark.p25,
      industryP75: benchmark.p75,
      percentileRank: Math.min(99, Math.max(1, percentileRank)),
      verdict,
    });
  }

  return benchmarks;
}

// ─── KPI Snapshot Persistence ────────────────────────────────────────────────

export async function persistKpiSnapshot(
  orgId: string,
  kpiType: string,
  value: number,
  period: string,
  periodStart: Date,
  periodEnd: Date,
  unit?: string,
  metadata?: Record<string, unknown>,
): Promise<void> {
  // Get previous value for trend
  const [prev] = await db
    .select({ value: securityKpiSnapshots.value })
    .from(securityKpiSnapshots)
    .where(and(eq(securityKpiSnapshots.orgId, orgId), eq(securityKpiSnapshots.kpiType, kpiType)))
    .orderBy(desc(securityKpiSnapshots.createdAt))
    .limit(1);

  await db.insert(securityKpiSnapshots).values({
    orgId,
    kpiType,
    value,
    previousValue: prev?.value ?? null,
    period,
    periodStart,
    periodEnd,
    unit,
    metadata: metadata ?? null,
  });
}

// ─── Budget Optimization ─────────────────────────────────────────────────────

export interface BudgetOptimization {
  overlaps: Array<{
    capability: string;
    tools: string[];
    annualCost: number;
    recommendation: string;
    potentialSavings: number;
  }>;
  totalPotentialSavings: number;
  totalToolSpend: number;
}

export async function computeBudgetOptimization(orgId: string): Promise<BudgetOptimization> {
  // Get stored overlaps
  const overlaps = await db.select().from(securityToolOverlaps).where(eq(securityToolOverlaps.orgId, orgId));

  // Also auto-detect overlaps from connector capabilities
  const activeConnectorsList = await db
    .select()
    .from(connectors)
    .where(and(eq(connectors.orgId, orgId), eq(connectors.status, "active")));

  const CAPABILITY_MAP: Record<string, string[]> = {
    endpoint_detection: ["crowdstrike", "sentinelone", "carbonblack", "defender"],
    siem: ["splunk", "elastic", "qradar", "wazuh", "rapid7"],
    vulnerability_mgmt: ["qualys", "tenable"],
    network_security: ["paloalto", "fortigate", "checkpoint", "snort", "suricata"],
    cloud_security: ["wiz", "guardduty"],
    email_security: ["proofpoint"],
    identity: ["okta"],
    dns_security: ["umbrella", "zscaler"],
  };

  const detectedOverlaps: Array<{
    capability: string;
    tools: string[];
    annualCost: number;
    recommendation: string;
    potentialSavings: number;
  }> = [];

  for (const [capability, toolTypes] of Object.entries(CAPABILITY_MAP)) {
    const matchingTools = activeConnectorsList.filter((c) => toolTypes.includes(c.type));
    if (matchingTools.length > 1) {
      const cost = matchingTools.length * 25000;
      const savings = (matchingTools.length - 1) * 25000;
      detectedOverlaps.push({
        capability,
        tools: matchingTools.map((c) => c.name),
        annualCost: cost,
        recommendation: `${matchingTools.length} tools covering ${capability}. Consider consolidating to reduce overlap.`,
        potentialSavings: savings,
      });
    }
  }

  // Merge with stored overlaps
  const allOverlaps = [
    ...overlaps.map((o) => ({
      capability: o.capability,
      tools: (o.tools as string[]) || [],
      annualCost: o.annualCost || 0,
      recommendation: o.recommendation || "",
      potentialSavings: o.potentialSavings || 0,
    })),
    ...detectedOverlaps,
  ];

  const totalSavings = allOverlaps.reduce((s, o) => s + o.potentialSavings, 0);
  const totalSpend = activeConnectorsList.length * 25000;

  return {
    overlaps: allOverlaps,
    totalPotentialSavings: totalSavings,
    totalToolSpend: totalSpend,
  };
}

// ─── False Positive Rate ─────────────────────────────────────────────────────

export async function computeFalsePositiveRate(
  orgId: string,
  periodStart: Date,
  periodEnd: Date,
): Promise<{ rate: number; totalAlerts: number; falsePositives: number; bySource: Record<string, number> }> {
  const [{ value: totalAlerts }] = await db
    .select({ value: count() })
    .from(alerts)
    .where(and(eq(alerts.orgId, orgId), gte(alerts.createdAt, periodStart), lte(alerts.createdAt, periodEnd)));

  const [{ value: fpCount }] = await db
    .select({ value: count() })
    .from(alerts)
    .where(
      and(
        eq(alerts.orgId, orgId),
        gte(alerts.createdAt, periodStart),
        lte(alerts.createdAt, periodEnd),
        sql`${alerts.status} IN ('false_positive', 'dismissed')`,
      ),
    );

  const bySourceResult = await db
    .select({
      source: alerts.source,
      cnt: count(),
    })
    .from(alerts)
    .where(
      and(
        eq(alerts.orgId, orgId),
        gte(alerts.createdAt, periodStart),
        lte(alerts.createdAt, periodEnd),
        sql`${alerts.status} IN ('false_positive', 'dismissed')`,
      ),
    )
    .groupBy(alerts.source);

  const bySource: Record<string, number> = {};
  for (const row of bySourceResult) {
    bySource[row.source] = Number(row.cnt);
  }

  const total = Number(totalAlerts);
  const fps = Number(fpCount);

  return {
    rate: total > 0 ? Math.round((fps / total) * 100) : 0,
    totalAlerts: total,
    falsePositives: fps,
    bySource,
  };
}

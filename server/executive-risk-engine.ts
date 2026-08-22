import { logger } from "./logger";

const log = logger.child("executive-risk");

export type RiskSeverity = "critical" | "high" | "medium" | "low" | "info";
export type MetricCategory = "action" | "vanity";
export type TrendDirection = "improving" | "stable" | "degrading";
export type SummaryPeriod = "weekly" | "monthly" | "quarterly";

export interface MttrMetric {
  overall: number;
  bySeverity: Record<RiskSeverity, number>;
  trend: TrendDirection;
  previousPeriod: number;
  changePercent: number;
  unit: "hours";
}

export interface RiskBurndownEntry {
  date: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
}

export interface ExploitabilityExposure {
  totalFindings: number;
  exploitable: number;
  exploitablePercent: number;
  weaponized: number;
  weaponizedPercent: number;
  epssAboveThreshold: number | null;
  epssThreshold: number;
  exposureScore: number;
  trend: TrendDirection;
  previousScore: number;
  changePercent: number;
}

export interface RemediationThroughput {
  resolvedThisPeriod: number;
  openedThisPeriod: number;
  netChange: number;
  resolvedPerDay: number;
  averageResolutionDays: number;
  backlogSize: number;
  backlogBySeverity: Record<RiskSeverity, number>;
  trend: TrendDirection;
  previousThroughput: number;
  changePercent: number;
}

export interface AutomationSavings {
  totalHoursSaved: number;
  incidentsAutoTriaged: number;
  alertsAutoCorrelated: number;
  playbooksAutoExecuted: number;
  falsePositivesSuppressed: number;
  estimatedCostSavings: number;
  costPerAnalystHour: number;
  automationCoveragePercent: number;
  trend: TrendDirection;
  previousHoursSaved: number;
  changePercent: number;
}

export interface ActionMetric {
  id: string;
  name: string;
  description: string;
  category: MetricCategory;
  value: number;
  unit: string;
  trend: TrendDirection;
  changePercent: number;
  target: number | null;
  targetMet: boolean;
  sparkline: number[];
}

export interface BoardSummary {
  id: string;
  orgId: string;
  period: SummaryPeriod;
  generatedAt: string;
  generatedBy: string;
  title: string;
  executiveSynopsis: string;
  keyFindings: BoardFinding[];
  riskPosture: RiskPostureSnapshot;
  recommendations: BoardRecommendation[];
  mttr: MttrMetric;
  exploitability: ExploitabilityExposure;
  remediationThroughput: RemediationThroughput;
  automationSavings: AutomationSavings;
}

export interface BoardFinding {
  id: string;
  title: string;
  severity: RiskSeverity;
  description: string;
  evidence: string[];
  impactArea: string;
  status: "new" | "ongoing" | "resolved";
}

export interface RiskPostureSnapshot {
  overallScore: number;
  previousScore: number;
  maxScore: number;
  grade: "A" | "B" | "C" | "D" | "F";
  previousGrade: "A" | "B" | "C" | "D" | "F";
  dimensions: PostureDimension[];
}

export interface PostureDimension {
  name: string;
  score: number;
  maxScore: number;
  weight: number;
}

export interface BoardRecommendation {
  id: string;
  priority: number;
  title: string;
  description: string;
  expectedImpact: string;
  effort: "low" | "medium" | "high";
  owner: string;
  deadline: string | null;
}

export interface ExecutiveRiskDashboard {
  mttr: MttrMetric;
  riskBurndown: RiskBurndownEntry[];
  exploitability: ExploitabilityExposure;
  remediationThroughput: RemediationThroughput;
  automationSavings: AutomationSavings;
  actionMetrics: ActionMetric[];
  riskPosture: RiskPostureSnapshot;
}

const orgSummaries = new Map<string, BoardSummary[]>();

function scoreToGrade(score: number): "A" | "B" | "C" | "D" | "F" {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}

function generateRiskBurndown(): RiskBurndownEntry[] {
  const entries: RiskBurndownEntry[] = [];
  const now = new Date();
  let critical = 42;
  let high = 128;
  let medium = 315;
  let low = 580;

  for (let i = 29; i >= 0; i--) {
    const date = new Date(now.getTime() - i * 24 * 60 * 60 * 1000);
    const dailyVariance = (seed: number) => ((seed * 7 + 3) % 6) - 3;
    critical = Math.max(0, critical + dailyVariance(i * 3) - 1);
    high = Math.max(0, high + dailyVariance(i * 5) - 1);
    medium = Math.max(0, medium + dailyVariance(i * 7));
    low = Math.max(0, low + dailyVariance(i * 11));
    entries.push({
      date: date.toISOString().split("T")[0],
      critical,
      high,
      medium,
      low,
      total: critical + high + medium + low,
    });
  }
  return entries;
}

function buildMttr(): MttrMetric {
  return {
    overall: 4.2,
    bySeverity: {
      critical: 1.8,
      high: 3.5,
      medium: 6.1,
      low: 12.4,
      info: 48.0,
    },
    trend: "improving",
    previousPeriod: 5.1,
    changePercent: -17.6,
    unit: "hours",
  };
}

function buildExploitability(): ExploitabilityExposure {
  return {
    totalFindings: 847,
    exploitable: 203,
    exploitablePercent: 24.0,
    weaponized: 31,
    weaponizedPercent: 3.7,
    epssAboveThreshold: null,
    epssThreshold: 0.5,
    exposureScore: 34.2,
    trend: "improving",
    previousScore: 41.8,
    changePercent: -18.2,
  };
}

function buildRemediationThroughput(): RemediationThroughput {
  return {
    resolvedThisPeriod: 312,
    openedThisPeriod: 198,
    netChange: -114,
    resolvedPerDay: 10.4,
    averageResolutionDays: 3.2,
    backlogSize: 847,
    backlogBySeverity: {
      critical: 12,
      high: 67,
      medium: 289,
      low: 425,
      info: 54,
    },
    trend: "improving",
    previousThroughput: 245,
    changePercent: 27.3,
  };
}

function buildAutomationSavings(): AutomationSavings {
  return {
    totalHoursSaved: 1842,
    incidentsAutoTriaged: 4521,
    alertsAutoCorrelated: 12847,
    playbooksAutoExecuted: 892,
    falsePositivesSuppressed: 8934,
    estimatedCostSavings: 138150,
    costPerAnalystHour: 75,
    automationCoveragePercent: 78.4,
    trend: "improving",
    previousHoursSaved: 1520,
    changePercent: 21.2,
  };
}

function buildActionMetrics(): ActionMetric[] {
  return [
    {
      id: "mttr-critical",
      name: "MTTR (Critical)",
      description: "Mean time to remediate critical findings",
      category: "action",
      value: 1.8,
      unit: "hours",
      trend: "improving",
      changePercent: -22.0,
      target: 2.0,
      targetMet: true,
      sparkline: [3.2, 2.8, 2.5, 2.1, 1.9, 1.8, 1.8],
    },
    {
      id: "exploitable-exposure",
      name: "Exploitable Exposure",
      description: "Percentage of findings with known exploits in the wild",
      category: "action",
      value: 24.0,
      unit: "%",
      trend: "improving",
      changePercent: -18.2,
      target: 20.0,
      targetMet: false,
      sparkline: [38, 35, 32, 29, 27, 25, 24],
    },
    {
      id: "remediation-velocity",
      name: "Remediation Velocity",
      description: "Net findings resolved per day (resolved minus opened)",
      category: "action",
      value: 3.8,
      unit: "findings/day",
      trend: "improving",
      changePercent: 15.0,
      target: 5.0,
      targetMet: false,
      sparkline: [1.2, 1.8, 2.4, 2.9, 3.2, 3.5, 3.8],
    },
    {
      id: "automation-coverage",
      name: "Automation Coverage",
      description: "Percentage of alert types with automated response playbooks",
      category: "action",
      value: 78.4,
      unit: "%",
      trend: "improving",
      changePercent: 8.5,
      target: 85.0,
      targetMet: false,
      sparkline: [62, 65, 68, 71, 74, 76, 78],
    },
    {
      id: "false-positive-rate",
      name: "False Positive Rate",
      description: "Percentage of alerts suppressed as false positives",
      category: "action",
      value: 12.3,
      unit: "%",
      trend: "improving",
      changePercent: -31.0,
      target: 10.0,
      targetMet: false,
      sparkline: [24, 21, 18, 16, 14, 13, 12],
    },
    {
      id: "backlog-critical",
      name: "Critical Backlog",
      description: "Number of unresolved critical findings",
      category: "action",
      value: 12,
      unit: "findings",
      trend: "improving",
      changePercent: -40.0,
      target: 0,
      targetMet: false,
      sparkline: [28, 24, 20, 18, 15, 13, 12],
    },
    {
      id: "total-alerts",
      name: "Total Alerts Processed",
      description: "Total number of alerts ingested and processed",
      category: "vanity",
      value: 48293,
      unit: "alerts",
      trend: "stable",
      changePercent: 3.2,
      target: null,
      targetMet: false,
      sparkline: [42000, 43500, 44800, 45900, 46800, 47500, 48293],
    },
    {
      id: "connectors-active",
      name: "Active Connectors",
      description: "Number of active data source integrations",
      category: "vanity",
      value: 23,
      unit: "connectors",
      trend: "stable",
      changePercent: 4.5,
      target: null,
      targetMet: false,
      sparkline: [18, 19, 20, 21, 22, 22, 23],
    },
    {
      id: "playbook-executions",
      name: "Playbook Executions",
      description: "Total automated playbook runs this period",
      category: "vanity",
      value: 892,
      unit: "executions",
      trend: "improving",
      changePercent: 18.0,
      target: null,
      targetMet: false,
      sparkline: [580, 620, 680, 740, 790, 840, 892],
    },
    {
      id: "compliance-score",
      name: "Compliance Coverage",
      description: "Percentage of compliance controls with evidence",
      category: "vanity",
      value: 94.2,
      unit: "%",
      trend: "stable",
      changePercent: 1.8,
      target: null,
      targetMet: false,
      sparkline: [89, 90, 91, 92, 93, 94, 94],
    },
  ];
}

function buildRiskPosture(): RiskPostureSnapshot {
  const dimensions: PostureDimension[] = [
    { name: "Vulnerability Management", score: 82, maxScore: 100, weight: 0.25 },
    { name: "Identity & Access", score: 91, maxScore: 100, weight: 0.2 },
    { name: "Data Protection", score: 88, maxScore: 100, weight: 0.2 },
    { name: "Incident Response", score: 76, maxScore: 100, weight: 0.15 },
    { name: "Network Security", score: 85, maxScore: 100, weight: 0.1 },
    { name: "Compliance", score: 94, maxScore: 100, weight: 0.1 },
  ];

  const overallScore = Math.round(dimensions.reduce((sum, d) => sum + d.score * d.weight, 0));
  const previousScore = overallScore - 3;

  return {
    overallScore,
    previousScore,
    maxScore: 100,
    grade: scoreToGrade(overallScore),
    previousGrade: scoreToGrade(previousScore),
    dimensions,
  };
}

function getOrgSummaries(orgId: string): BoardSummary[] {
  if (!orgSummaries.has(orgId)) {
    orgSummaries.set(orgId, seedDefaultSummaries(orgId));
  }
  return orgSummaries.get(orgId)!;
}

function seedDefaultSummaries(orgId: string): BoardSummary[] {
  const now = new Date();
  const oneMonthAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
  const twoMonthsAgo = new Date(now.getTime() - 60 * 24 * 60 * 60 * 1000);

  return [
    {
      id: `${orgId}-summary-current`,
      orgId,
      period: "monthly",
      generatedAt: now.toISOString(),
      generatedBy: "system",
      title: "Monthly Security Risk Report - Current Period",
      executiveSynopsis:
        "Overall security posture improved from B to B+ this period. Critical vulnerabilities decreased 40% driven by automated patching. MTTR for critical findings dropped below 2-hour SLA target. Exploitable exposure reduced 18% through prioritized remediation of weaponized CVEs. Automation now covers 78% of alert types, saving an estimated 1,842 analyst hours this period.",
      keyFindings: [
        {
          id: "kf-1",
          title: "Critical vulnerability backlog at historic low",
          severity: "critical",
          description:
            "Only 12 critical findings remain open, down from 28 last period. All weaponized CVEs patched within 24 hours.",
          evidence: ["Vulnerability scanner reports", "Patch deployment logs", "EPSS correlation data"],
          impactArea: "Vulnerability Management",
          status: "resolved",
        },
        {
          id: "kf-2",
          title: "Lateral movement detection gap in cloud workloads",
          severity: "high",
          description:
            "Cloud workload protection coverage is at 72%, leaving 28% of containerized services without runtime monitoring.",
          evidence: ["CSPM scan results", "Container inventory audit", "Network flow analysis"],
          impactArea: "Cloud Security",
          status: "ongoing",
        },
        {
          id: "kf-3",
          title: "Third-party API credential rotation overdue",
          severity: "medium",
          description:
            "14 third-party API credentials exceed the 90-day rotation policy. No evidence of compromise, but non-compliant with SOC 2 CC6.1.",
          evidence: ["Secret rotation dashboard", "SOC 2 evidence mapping", "Credential age report"],
          impactArea: "Identity & Access",
          status: "ongoing",
        },
        {
          id: "kf-4",
          title: "SOAR playbook coverage expanded to phishing response",
          severity: "info",
          description:
            "New automated phishing analysis and containment playbook deployed. Reduced phishing triage time from 45 min to 3 min average.",
          evidence: ["Playbook execution logs", "Incident timeline comparison", "Analyst survey results"],
          impactArea: "Incident Response",
          status: "new",
        },
      ],
      riskPosture: buildRiskPosture(),
      recommendations: [
        {
          id: "rec-1",
          priority: 1,
          title: "Expand cloud workload protection to 100% coverage",
          description:
            "Deploy runtime monitoring agents to remaining 28% of containerized workloads to close lateral movement detection gap.",
          expectedImpact: "Eliminate blind spot covering ~340 containers across 12 EKS clusters",
          effort: "medium",
          owner: "Cloud Security Team",
          deadline: new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000).toISOString().split("T")[0],
        },
        {
          id: "rec-2",
          priority: 2,
          title: "Enforce automated credential rotation for all third-party APIs",
          description:
            "Implement automated rotation via AWS Secrets Manager for the 14 overdue credentials and establish alerting for future violations.",
          expectedImpact: "Achieve full SOC 2 CC6.1 compliance and reduce credential compromise risk window",
          effort: "low",
          owner: "Platform Engineering",
          deadline: new Date(now.getTime() + 14 * 24 * 60 * 60 * 1000).toISOString().split("T")[0],
        },
        {
          id: "rec-3",
          priority: 3,
          title: "Reduce exploitable exposure below 20% target",
          description: "Prioritize remediation of 67 findings with EPSS > 0.5 using risk-based patching workflow.",
          expectedImpact: "Reduce exploitable exposure from 24% to target 20%, eliminating highest-risk attack surface",
          effort: "high",
          owner: "Vulnerability Management",
          deadline: new Date(now.getTime() + 45 * 24 * 60 * 60 * 1000).toISOString().split("T")[0],
        },
      ],
      mttr: buildMttr(),
      exploitability: buildExploitability(),
      remediationThroughput: buildRemediationThroughput(),
      automationSavings: buildAutomationSavings(),
    },
    {
      id: `${orgId}-summary-prev`,
      orgId,
      period: "monthly",
      generatedAt: oneMonthAgo.toISOString(),
      generatedBy: "system",
      title: "Monthly Security Risk Report - Previous Period",
      executiveSynopsis:
        "Security posture held steady at B grade. Critical findings elevated to 28 due to Log4Shell variant discovered in internal tooling. MTTR exceeded target at 5.1 hours. Remediation throughput increased 15% month-over-month. Automation savings reached $114K this period.",
      keyFindings: [
        {
          id: "kf-prev-1",
          title: "Log4Shell variant in internal build tooling",
          severity: "critical",
          description:
            "Log4j 2.17.0 dependency discovered in internal CI/CD pipeline tooling. Exploitable via crafted build parameters.",
          evidence: ["SCA scan results", "Build pipeline audit", "Network segmentation review"],
          impactArea: "Supply Chain",
          status: "resolved",
        },
      ],
      riskPosture: {
        ...buildRiskPosture(),
        overallScore: 82,
        previousScore: 80,
        grade: "B",
        previousGrade: "B",
      },
      recommendations: [
        {
          id: "rec-prev-1",
          priority: 1,
          title: "Patch Log4Shell variant immediately",
          description:
            "Upgrade log4j to 2.21.0+ in all internal build tooling and scan for additional transitive dependencies.",
          expectedImpact: "Eliminate critical remote code execution risk in CI/CD pipeline",
          effort: "low",
          owner: "Platform Engineering",
          deadline: oneMonthAgo.toISOString().split("T")[0],
        },
      ],
      mttr: { ...buildMttr(), overall: 5.1, previousPeriod: 4.8, changePercent: 6.3, trend: "degrading" },
      exploitability: {
        ...buildExploitability(),
        exposureScore: 41.8,
        previousScore: 39.2,
        changePercent: 6.6,
        trend: "degrading",
      },
      remediationThroughput: {
        ...buildRemediationThroughput(),
        resolvedThisPeriod: 245,
        previousThroughput: 213,
        changePercent: 15.0,
      },
      automationSavings: {
        ...buildAutomationSavings(),
        totalHoursSaved: 1520,
        estimatedCostSavings: 114000,
        previousHoursSaved: 1310,
        changePercent: 16.0,
      },
    },
    {
      id: `${orgId}-summary-q4`,
      orgId,
      period: "quarterly",
      generatedAt: twoMonthsAgo.toISOString(),
      generatedBy: "system",
      title: "Quarterly Security Risk Report - Q4 2025",
      executiveSynopsis:
        "Q4 saw a 22% improvement in overall risk posture. Automation investments reduced analyst workload by 1,520 hours. Three critical compliance gaps closed ahead of SOC 2 Type II audit. Board-level recommendation to increase security budget by 15% for 2026 to fund cloud workload protection expansion.",
      keyFindings: [],
      riskPosture: {
        ...buildRiskPosture(),
        overallScore: 80,
        previousScore: 75,
        grade: "B",
        previousGrade: "C",
      },
      recommendations: [],
      mttr: { ...buildMttr(), overall: 4.8, previousPeriod: 5.5, changePercent: -12.7, trend: "improving" },
      exploitability: {
        ...buildExploitability(),
        exposureScore: 39.2,
        previousScore: 45.0,
        changePercent: -12.9,
        trend: "improving",
      },
      remediationThroughput: {
        ...buildRemediationThroughput(),
        resolvedThisPeriod: 680,
        previousThroughput: 520,
        changePercent: 30.8,
      },
      automationSavings: {
        ...buildAutomationSavings(),
        totalHoursSaved: 4200,
        estimatedCostSavings: 315000,
        previousHoursSaved: 3100,
        changePercent: 35.5,
      },
    },
  ];
}

export function getExecutiveDashboard(_orgId: string): ExecutiveRiskDashboard {
  log.info("Generating executive risk dashboard", { orgId: _orgId });
  return {
    mttr: buildMttr(),
    riskBurndown: generateRiskBurndown(),
    exploitability: buildExploitability(),
    remediationThroughput: buildRemediationThroughput(),
    automationSavings: buildAutomationSavings(),
    actionMetrics: buildActionMetrics(),
    riskPosture: buildRiskPosture(),
  };
}

export function getBoardSummaries(orgId: string): BoardSummary[] {
  return getOrgSummaries(orgId);
}

export function getBoardSummaryById(orgId: string, summaryId: string): BoardSummary | null {
  const summaries = getOrgSummaries(orgId);
  return summaries.find((s) => s.id === summaryId) || null;
}

export function generateBoardSummary(orgId: string, period: SummaryPeriod, generatedBy: string): BoardSummary {
  const summaries = getOrgSummaries(orgId);
  const dashboard = getExecutiveDashboard(orgId);

  const summary: BoardSummary = {
    id: `${orgId}-summary-${Date.now()}`,
    orgId,
    period,
    generatedAt: new Date().toISOString(),
    generatedBy,
    title: `${period.charAt(0).toUpperCase() + period.slice(1)} Security Risk Report - ${new Date().toLocaleDateString("en-US", { month: "long", year: "numeric" })}`,
    executiveSynopsis:
      `Security posture score: ${dashboard.riskPosture.overallScore}/100 (Grade ${dashboard.riskPosture.grade}). ` +
      `MTTR for critical findings: ${dashboard.mttr.bySeverity.critical}h (target: 2h). ` +
      `Exploitable exposure: ${dashboard.exploitability.exposureScore}% (${dashboard.exploitability.trend}). ` +
      `Remediation throughput: ${dashboard.remediationThroughput.resolvedPerDay} findings/day. ` +
      `Automation savings: $${dashboard.automationSavings.estimatedCostSavings.toLocaleString()} (${dashboard.automationSavings.totalHoursSaved} analyst hours).`,
    keyFindings: [],
    riskPosture: dashboard.riskPosture,
    recommendations: [],
    mttr: dashboard.mttr,
    exploitability: dashboard.exploitability,
    remediationThroughput: dashboard.remediationThroughput,
    automationSavings: dashboard.automationSavings,
  };

  summaries.unshift(summary);

  const MAX_SUMMARIES = 50;
  if (summaries.length > MAX_SUMMARIES) {
    summaries.splice(MAX_SUMMARIES);
  }

  log.info("Board summary generated", { orgId, period, summaryId: summary.id });
  return summary;
}

export function getMetricsByCategory(category: MetricCategory): ActionMetric[] {
  return buildActionMetrics().filter((m) => m.category === category);
}

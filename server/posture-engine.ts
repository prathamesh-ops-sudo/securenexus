import { storage } from "./storage";
import type { InsertPostureScore, PostureScore } from "@shared/schema";

export interface PostureUnavailable {
  status: "unavailable";
  overallScore: null;
  coveredDimensions: string[];
  reason: string;
  requiredEvidence: string[];
}

export interface PostureCompleted {
  status: "completed";
  score: PostureScore;
  coveredDimensions: string[];
}

export type PostureCalculationResult = PostureCompleted | PostureUnavailable;

function scoreFromOpenFindings(findings: Array<{ severity: string }>): number {
  const penalty = findings.reduce((total, finding) => {
    const penalties: Record<string, number> = { critical: 10, high: 5, medium: 2, low: 1 };
    return total + (penalties[finding.severity] || 0);
  }, 0);
  return Math.max(0, 100 - penalty);
}

function scoreFromIncidents(incidents: Array<{ severity: string }>): number {
  const penalty = incidents.reduce((total, incident) => {
    const penalties: Record<string, number> = { critical: 15, high: 10, medium: 5, low: 2 };
    return total + (penalties[incident.severity] || 0);
  }, 0);
  return Math.max(0, 100 - penalty);
}

export async function calculatePostureScore(orgId: string): Promise<PostureCalculationResult> {
  const [findings, scans, endpoints, allIncidents, compliancePolicy] = await Promise.all([
    storage.getCspmFindings(orgId),
    storage.getCspmScans(orgId),
    storage.getEndpointAssets(orgId),
    storage.getIncidents(orgId),
    storage.getCompliancePolicy(orgId),
  ]);

  const completedScanIds = new Set(scans.filter((scan) => scan.status === "completed").map((scan) => scan.id));
  const hasCompletedCspmScan = completedScanIds.size > 0;
  const openFindings = findings.filter((finding) => completedScanIds.has(finding.scanId) && finding.status === "open");
  const measuredEndpoints = endpoints.filter(
    (endpoint) => endpoint.riskScore !== null && endpoint.riskScore !== undefined,
  );
  const recentIncidents = allIncidents.filter((incident) => incident.createdAt !== null);
  const openIncidents = recentIncidents.filter(
    (incident) => incident.status !== "resolved" && incident.status !== "closed",
  );
  const dimensions: Array<{ name: string; score: number; weight: number }> = [];
  if (hasCompletedCspmScan) dimensions.push({ name: "cspm", score: scoreFromOpenFindings(openFindings), weight: 0.35 });
  if (measuredEndpoints.length > 0) {
    dimensions.push({
      name: "endpoint",
      score: Math.round(
        measuredEndpoints.reduce((sum, endpoint) => sum + (100 - (endpoint.riskScore || 0)), 0) /
          measuredEndpoints.length,
      ),
      weight: 0.3,
    });
  }
  if (recentIncidents.length > 0) {
    dimensions.push({ name: "incident", score: scoreFromIncidents(openIncidents), weight: 0.2 });
  }
  if (compliancePolicy) {
    const hasFrameworks = Boolean(compliancePolicy.enabledFrameworks?.length);
    const hasPiiMasking = Boolean(compliancePolicy.piiMaskingEnabled);
    const hasPseudonymize = Boolean(compliancePolicy.pseudonymizeExports);
    const hasDpoEmail = Boolean(compliancePolicy.dpoEmail);
    dimensions.push({
      name: "compliance",
      score: (Number(hasFrameworks) + Number(hasPiiMasking) + Number(hasPseudonymize) + Number(hasDpoEmail)) * 25,
      weight: 0.15,
    });
  }
  if (dimensions.length === 0) {
    return {
      status: "unavailable",
      overallScore: null,
      coveredDimensions: [],
      reason: "No completed posture evidence is available for this organization.",
      requiredEvidence: [
        "Complete a CSPM scan.",
        "Collect endpoint risk telemetry.",
        "Record security incidents.",
        "Configure a compliance policy.",
      ],
    };
  }
  const totalWeight = dimensions.reduce((sum, dimension) => sum + dimension.weight, 0);
  const overallScore = Math.round(
    dimensions.reduce((sum, dimension) => sum + dimension.score * dimension.weight, 0) / totalWeight,
  );
  const cspmScore = dimensions.find((dimension) => dimension.name === "cspm")?.score ?? null;
  const endpointScore = dimensions.find((dimension) => dimension.name === "endpoint")?.score ?? null;
  const incidentScore = dimensions.find((dimension) => dimension.name === "incident")?.score ?? null;
  const complianceScore = dimensions.find((dimension) => dimension.name === "compliance")?.score ?? null;

  const scoreData: InsertPostureScore = {
    orgId,
    overallScore,
    cspmScore,
    endpointScore,
    incidentScore,
    complianceScore,
    breakdown: {
      cspm: {
        score: cspmScore,
        weight: 0.35,
        openFindings: openFindings.length,
        bySeverity: {
          critical: openFindings.filter((f) => f.severity === "critical").length,
          high: openFindings.filter((f) => f.severity === "high").length,
          medium: openFindings.filter((f) => f.severity === "medium").length,
          low: openFindings.filter((f) => f.severity === "low").length,
        },
      },
      endpoint: {
        score: endpointScore,
        weight: 0.3,
        totalEndpoints: endpoints.length,
        measuredAssets: measuredEndpoints.length,
        totalAssets: endpoints.length,
      },
      incident: {
        score: incidentScore,
        weight: 0.2,
        openIncidents: openIncidents.length,
        recentIncidents: recentIncidents.length,
        bySeverity: {
          critical: openIncidents.filter((i) => i.severity === "critical").length,
          high: openIncidents.filter((i) => i.severity === "high").length,
          medium: openIncidents.filter((i) => i.severity === "medium").length,
          low: openIncidents.filter((i) => i.severity === "low").length,
        },
      },
      compliance: {
        score: complianceScore,
        weight: 0.15,
        policyConfigured: Boolean(compliancePolicy),
        enabledFrameworks: compliancePolicy?.enabledFrameworks ?? [],
      },
    },
  };

  return {
    status: "completed",
    score: await storage.createPostureScore(scoreData),
    coveredDimensions: dimensions.map((dimension) => dimension.name),
  };
}

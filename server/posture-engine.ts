import { storage } from "./storage";
import type { PostureScore, InsertPostureScore } from "@shared/schema";

export async function calculatePostureScore(orgId: string): Promise<PostureScore> {
  const [findings, endpoints, allIncidents, compliancePolicy] = await Promise.all([
    storage.getCspmFindings(orgId),
    storage.getEndpointAssets(orgId),
    storage.getIncidents(orgId),
    storage.getCompliancePolicy(orgId),
  ]);

  const openFindings = findings.filter(f => f.status === "open");

  const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
  const recentIncidents = allIncidents.filter(inc =>
    inc.createdAt && new Date(inc.createdAt) >= thirtyDaysAgo
  );
  const openIncidents = recentIncidents.filter(inc =>
    inc.status !== "resolved" && inc.status !== "closed"
  );

  let cspmScore = 100;
  for (const finding of openFindings) {
    switch (finding.severity) {
      case "critical": cspmScore -= 10; break;
      case "high": cspmScore -= 5; break;
      case "medium": cspmScore -= 2; break;
      case "low": cspmScore -= 1; break;
    }
  }
  cspmScore = Math.max(0, cspmScore);

  let endpointScore: number;
  if (endpoints.length === 0) {
    endpointScore = 100;
  } else {
    const total = endpoints.reduce((sum, ep) => sum + (100 - (ep.riskScore ?? 0)), 0);
    endpointScore = Math.round(total / endpoints.length);
  }
  endpointScore = Math.max(0, Math.min(100, endpointScore));

  let incidentScore = 100;
  for (const incident of openIncidents) {
    switch (incident.severity) {
      case "critical": incidentScore -= 15; break;
      case "high": incidentScore -= 10; break;
      case "medium": incidentScore -= 5; break;
      case "low": incidentScore -= 2; break;
    }
  }
  incidentScore = Math.max(0, incidentScore);

  let complianceScore: number;
  if (!compliancePolicy) {
    complianceScore = 80;
  } else {
    const hasFrameworks = compliancePolicy.enabledFrameworks && compliancePolicy.enabledFrameworks.length > 0;
    const hasPiiMasking = compliancePolicy.piiMaskingEnabled;
    const hasPseudonymize = compliancePolicy.pseudonymizeExports;
    const hasDpoEmail = !!compliancePolicy.dpoEmail;

    const enforced = hasFrameworks && hasPiiMasking && hasPseudonymize && hasDpoEmail;
    const partial = hasFrameworks || hasPiiMasking || hasPseudonymize;

    if (enforced) {
      complianceScore = 100;
    } else if (partial) {
      complianceScore = 50 + (hasFrameworks ? 15 : 0) + (hasPiiMasking ? 10 : 0) + (hasPseudonymize ? 10 : 0) + (hasDpoEmail ? 10 : 0);
      complianceScore = Math.min(95, complianceScore);
    } else {
      complianceScore = 50;
    }
  }

  const overallScore = Math.round(
    cspmScore * 0.35 +
    endpointScore * 0.30 +
    incidentScore * 0.20 +
    complianceScore * 0.15
  );

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
          critical: openFindings.filter(f => f.severity === "critical").length,
          high: openFindings.filter(f => f.severity === "high").length,
          medium: openFindings.filter(f => f.severity === "medium").length,
          low: openFindings.filter(f => f.severity === "low").length,
        },
      },
      endpoint: {
        score: endpointScore,
        weight: 0.30,
        totalEndpoints: endpoints.length,
        averageRiskScore: endpoints.length > 0
          ? Math.round(endpoints.reduce((s, e) => s + (e.riskScore ?? 0), 0) / endpoints.length)
          : 0,
      },
      incident: {
        score: incidentScore,
        weight: 0.20,
        openIncidents: openIncidents.length,
        recentIncidents: recentIncidents.length,
        bySeverity: {
          critical: openIncidents.filter(i => i.severity === "critical").length,
          high: openIncidents.filter(i => i.severity === "high").length,
          medium: openIncidents.filter(i => i.severity === "medium").length,
          low: openIncidents.filter(i => i.severity === "low").length,
        },
      },
      compliance: {
        score: complianceScore,
        weight: 0.15,
        policyConfigured: !!compliancePolicy,
        enabledFrameworks: compliancePolicy?.enabledFrameworks ?? [],
      },
    },
  };

  const saved = await storage.createPostureScore(scoreData);
  return saved;
}

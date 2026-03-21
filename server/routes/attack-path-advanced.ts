import type { Express } from "express";
import { db } from "../db";
import { attackPaths, alerts, entities, alertEntities, cspmFindings, campaigns } from "@shared/schema";
import { eq, and, desc, inArray, sql } from "drizzle-orm";
import { isAuthenticated } from "../auth";
import { resolveOrgContext, requireOrgId, requireMinRole } from "../rbac";
import { getOrgId, logger, p } from "./shared";

const log = logger.child("attack-path-advanced");

// MITRE ATT&CK technique to tactic mapping (subset of most common)
const TECHNIQUE_TACTIC_MAP: Record<string, { tactic: string; name: string; description: string }> = {
  T1190: {
    tactic: "initial-access",
    name: "Exploit Public-Facing Application",
    description: "Adversaries may attempt to exploit a weakness in an Internet-facing host or system.",
  },
  T1566: {
    tactic: "initial-access",
    name: "Phishing",
    description: "Adversaries may send phishing messages to gain access to victim systems.",
  },
  T1078: {
    tactic: "initial-access",
    name: "Valid Accounts",
    description: "Adversaries may obtain and abuse credentials of existing accounts.",
  },
  T1059: {
    tactic: "execution",
    name: "Command and Scripting Interpreter",
    description: "Adversaries may abuse command and script interpreters to execute commands.",
  },
  T1053: {
    tactic: "execution",
    name: "Scheduled Task/Job",
    description: "Adversaries may abuse task scheduling functionality to facilitate execution.",
  },
  T1547: {
    tactic: "persistence",
    name: "Boot or Logon Autostart Execution",
    description: "Adversaries may configure system settings to automatically execute a program during boot.",
  },
  T1136: {
    tactic: "persistence",
    name: "Create Account",
    description: "Adversaries may create an account to maintain access to victim systems.",
  },
  T1548: {
    tactic: "privilege-escalation",
    name: "Abuse Elevation Control Mechanism",
    description: "Adversaries may circumvent mechanisms designed to control elevated privileges.",
  },
  T1068: {
    tactic: "privilege-escalation",
    name: "Exploitation for Privilege Escalation",
    description: "Adversaries may exploit software vulnerabilities to elevate privileges.",
  },
  T1562: {
    tactic: "defense-evasion",
    name: "Impair Defenses",
    description: "Adversaries may maliciously modify components to hinder security monitoring.",
  },
  T1070: {
    tactic: "defense-evasion",
    name: "Indicator Removal",
    description: "Adversaries may delete or modify artifacts generated on a host system.",
  },
  T1110: {
    tactic: "credential-access",
    name: "Brute Force",
    description: "Adversaries may use brute force techniques to gain access to accounts.",
  },
  T1003: {
    tactic: "credential-access",
    name: "OS Credential Dumping",
    description: "Adversaries may attempt to dump credentials to obtain account login information.",
  },
  T1087: {
    tactic: "discovery",
    name: "Account Discovery",
    description: "Adversaries may attempt to get a listing of valid accounts on a system.",
  },
  T1046: {
    tactic: "discovery",
    name: "Network Service Discovery",
    description: "Adversaries may attempt to get a listing of services running on remote hosts.",
  },
  T1021: {
    tactic: "lateral-movement",
    name: "Remote Services",
    description: "Adversaries may use Valid Accounts to log into a service that accepts remote connections.",
  },
  T1570: {
    tactic: "lateral-movement",
    name: "Lateral Tool Transfer",
    description: "Adversaries may transfer tools or other files between systems.",
  },
  T1005: {
    tactic: "collection",
    name: "Data from Local System",
    description: "Adversaries may search local system sources to find files of interest.",
  },
  T1071: {
    tactic: "command-and-control",
    name: "Application Layer Protocol",
    description: "Adversaries may communicate using OSI application layer protocols.",
  },
  T1041: {
    tactic: "exfiltration",
    name: "Exfiltration Over C2 Channel",
    description: "Adversaries may steal data by exfiltrating it over an existing C2 channel.",
  },
  T1486: {
    tactic: "impact",
    name: "Data Encrypted for Impact",
    description: "Adversaries may encrypt data on target systems or on large numbers of systems.",
  },
  T1498: {
    tactic: "impact",
    name: "Network Denial of Service",
    description: "Adversaries may perform Network Denial of Service (DDoS) attacks.",
  },
};

const SEVERITY_SCORE: Record<string, number> = {
  critical: 10,
  high: 8,
  medium: 5,
  low: 2,
  informational: 1,
};

const KILL_CHAIN_ORDER = [
  "reconnaissance",
  "resource-development",
  "initial-access",
  "execution",
  "persistence",
  "privilege-escalation",
  "defense-evasion",
  "credential-access",
  "discovery",
  "lateral-movement",
  "collection",
  "command-and-control",
  "exfiltration",
  "impact",
];

// -----------------------------------------------------------------------
// 12.1: Attack Path Risk Scoring
// -----------------------------------------------------------------------
interface RiskScoringResult {
  pathId: string;
  riskScore: number;
  riskLevel: "critical" | "high" | "medium" | "low";
  factors: {
    hopCountScore: number;
    severityScore: number;
    blastRadiusScore: number;
    controlsScore: number;
    killChainCoverageScore: number;
    temporalScore: number;
  };
  blastRadius: {
    affectedEntityCount: number;
    affectedEntityTypes: string[];
    crownJewelsReached: boolean;
    highValueTargets: string[];
  };
  compensatingControls: {
    controlName: string;
    mitigationPercentage: number;
    applied: boolean;
  }[];
}

function computeAttackPathRiskScore(path: {
  id: string;
  nodes: unknown;
  edges: unknown;
  tacticsSequence: unknown;
  techniquesUsed: unknown;
  hopCount: number | null;
  lastAlertAt: Date | null;
}): RiskScoringResult {
  const nodes = (path.nodes || []) as Array<{
    type: string;
    id: string;
    data?: { severity?: string; riskScore?: number; type?: string; value?: string; displayName?: string };
  }>;
  const tactics = (path.tacticsSequence || []) as string[];
  const hopCount = path.hopCount || 0;

  // 1. Hop count score (more hops = more risk, diminishing returns)
  const hopCountScore = Math.min(hopCount / 8, 1.0) * 100;

  // 2. Severity score (max severity across all alert nodes)
  const alertNodes = nodes.filter((n) => n.type === "alert");
  const severities = alertNodes.map((n) => SEVERITY_SCORE[n.data?.severity || "low"] || 2);
  const maxSeverity = severities.length > 0 ? Math.max(...severities) : 2;
  const avgSeverity =
    severities.length > 0 ? severities.reduce((a: number, b: number) => a + b, 0) / severities.length : 2;
  const severityScore = ((maxSeverity * 0.6 + avgSeverity * 0.4) / 10) * 100;

  // 3. Blast radius score
  const entityNodes = nodes.filter((n) => n.type === "entity");
  const entityTypes = Array.from(new Set(entityNodes.map((n) => n.data?.type || "unknown")));
  const highValueTypes = ["server", "database", "domain_controller", "cloud_account", "crown_jewel"];
  const highValueTargets = entityNodes
    .filter((n) => {
      const type = (n.data?.type || "").toLowerCase();
      const risk = n.data?.riskScore || 0;
      return highValueTypes.some((hvt) => type.includes(hvt)) || risk >= 80;
    })
    .map((n) => n.data?.value || n.data?.displayName || n.id);

  const crownJewelsReached = highValueTargets.length > 0;
  const entityCountFactor = Math.min(entityNodes.length / 20, 1.0);
  const typeDiversityFactor = Math.min(entityTypes.length / 5, 1.0);
  const crownJewelFactor = crownJewelsReached ? 1.0 : 0.3;
  const blastRadiusScore = (entityCountFactor * 0.3 + typeDiversityFactor * 0.3 + crownJewelFactor * 0.4) * 100;

  // 4. Controls score (compensating controls reduce risk)
  const compensatingControls = detectCompensatingControls(tactics);
  const appliedControls = compensatingControls.filter((c) => c.applied);
  const totalMitigation = appliedControls.reduce((sum, c) => sum + c.mitigationPercentage, 0);
  const controlsScore = Math.max(0, 100 - totalMitigation);

  // 5. Kill chain coverage score
  const uniqueTactics = Array.from(new Set(tactics));
  const tacticIndices = uniqueTactics
    .map((t) => KILL_CHAIN_ORDER.indexOf(t))
    .filter((i) => i >= 0)
    .sort((a, b) => a - b);
  const killChainCoverage = tacticIndices.length / KILL_CHAIN_ORDER.length;
  let inOrder = true;
  for (let i = 1; i < tacticIndices.length; i++) {
    if (tacticIndices[i] <= tacticIndices[i - 1]) {
      inOrder = false;
      break;
    }
  }
  const orderBonus = inOrder && tacticIndices.length >= 3 ? 0.2 : 0;
  const killChainCoverageScore = Math.min(killChainCoverage + orderBonus, 1.0) * 100;

  // 6. Temporal score (recent paths are higher risk)
  const lastAlert = path.lastAlertAt ? new Date(path.lastAlertAt).getTime() : 0;
  const now = Date.now();
  const hoursSinceLastAlert = lastAlert > 0 ? (now - lastAlert) / (1000 * 60 * 60) : 999;
  const temporalScore =
    hoursSinceLastAlert < 24 ? 100 : hoursSinceLastAlert < 168 ? 70 : hoursSinceLastAlert < 720 ? 40 : 20;

  // Weighted final score
  const riskScore = Math.round(
    hopCountScore * 0.1 +
      severityScore * 0.25 +
      blastRadiusScore * 0.25 +
      controlsScore * 0.15 +
      killChainCoverageScore * 0.15 +
      temporalScore * 0.1,
  );

  const riskLevel: "critical" | "high" | "medium" | "low" =
    riskScore >= 80 ? "critical" : riskScore >= 60 ? "high" : riskScore >= 40 ? "medium" : "low";

  return {
    pathId: path.id,
    riskScore,
    riskLevel,
    factors: {
      hopCountScore: Math.round(hopCountScore),
      severityScore: Math.round(severityScore),
      blastRadiusScore: Math.round(blastRadiusScore),
      controlsScore: Math.round(controlsScore),
      killChainCoverageScore: Math.round(killChainCoverageScore),
      temporalScore: Math.round(temporalScore),
    },
    blastRadius: {
      affectedEntityCount: entityNodes.length,
      affectedEntityTypes: entityTypes as string[],
      crownJewelsReached,
      highValueTargets: highValueTargets.slice(0, 10),
    },
    compensatingControls,
  };
}

function detectCompensatingControls(
  tactics: string[],
): { controlName: string; mitigationPercentage: number; applied: boolean }[] {
  const controls: { controlName: string; mitigationPercentage: number; applied: boolean }[] = [];

  if (tactics.includes("credential-access") || tactics.includes("initial-access")) {
    controls.push({ controlName: "Multi-Factor Authentication (MFA)", mitigationPercentage: 15, applied: false });
  }
  if (tactics.includes("lateral-movement")) {
    controls.push({ controlName: "Network Segmentation", mitigationPercentage: 20, applied: false });
  }
  if (tactics.includes("execution") || tactics.includes("defense-evasion")) {
    controls.push({ controlName: "Endpoint Detection & Response (EDR)", mitigationPercentage: 15, applied: false });
  }
  if (tactics.includes("collection") || tactics.includes("exfiltration")) {
    controls.push({
      controlName: "Data Encryption (at rest & in transit)",
      mitigationPercentage: 10,
      applied: false,
    });
  }
  if (tactics.includes("privilege-escalation")) {
    controls.push({ controlName: "Privileged Access Management (PAM)", mitigationPercentage: 20, applied: false });
  }
  // SecureNexus IS the SIEM
  controls.push({ controlName: "SIEM Real-time Alerting", mitigationPercentage: 5, applied: true });
  return controls;
}

// -----------------------------------------------------------------------
// 12.2: What-If Simulation
// -----------------------------------------------------------------------
interface WhatIfDetail {
  pathId: string;
  originalRisk: number;
  modifiedRisk: number | null;
  eliminated: boolean;
  reason: string;
}

interface WhatIfResult {
  scenario: string;
  originalPathCount: number;
  modifiedPathCount: number;
  pathsEliminated: number;
  pathsReduced: string[];
  riskReduction: number;
  originalAvgRisk: number;
  modifiedAvgRisk: number;
  details: WhatIfDetail[];
}

function simulateWhatIf(
  paths: Array<{
    id: string;
    nodes: unknown;
    edges: unknown;
    tacticsSequence: unknown;
    techniquesUsed: unknown;
    hopCount: number | null;
    lastAlertAt: Date | null;
  }>,
  scenario: {
    type: "remove_vulnerability" | "add_control" | "remove_node" | "patch_severity";
    vulnerabilityId?: string;
    controlName?: string;
    nodeId?: string;
    targetSeverity?: string;
    affectedTactics?: string[];
  },
): WhatIfResult {
  const originalScores = paths.map((p) => computeAttackPathRiskScore(p));
  const originalAvgRisk =
    originalScores.length > 0 ? originalScores.reduce((sum, s) => sum + s.riskScore, 0) / originalScores.length : 0;

  const details: WhatIfDetail[] = [];
  let modifiedPathCount = 0;
  const pathsReduced: string[] = [];

  for (let i = 0; i < paths.length; i++) {
    const path = paths[i];
    const originalScore = originalScores[i];
    const nodes = (path.nodes || []) as Array<{
      type: string;
      id: string;
      data?: Record<string, unknown>;
    }>;
    const tactics = (path.tacticsSequence || []) as string[];

    let eliminated = false;
    let modifiedRisk = originalScore.riskScore;
    let reason = "";

    switch (scenario.type) {
      case "remove_vulnerability": {
        const affectedNodes = nodes.filter(
          (n) =>
            n.data?.alertId === scenario.vulnerabilityId ||
            (typeof n.data?.title === "string" && n.data.title.includes(scenario.vulnerabilityId || "")) ||
            n.id === scenario.vulnerabilityId,
        );
        if (affectedNodes.length > 0) {
          if (affectedNodes.length >= nodes.length * 0.5) {
            eliminated = true;
            reason = `Path eliminated: ${affectedNodes.length} of ${nodes.length} nodes affected by patched vulnerability`;
          } else {
            const reduction = (affectedNodes.length / nodes.length) * 40;
            modifiedRisk = Math.max(0, Math.round(originalScore.riskScore - reduction));
            reason = `Risk reduced by ${Math.round(reduction)}%: ${affectedNodes.length} nodes patched`;
          }
        } else {
          reason = "No change: vulnerability not in this path";
        }
        break;
      }
      case "add_control": {
        const affectedTactics = scenario.affectedTactics || [];
        const matchingTactics = tactics.filter((t) => affectedTactics.includes(t));
        if (matchingTactics.length > 0) {
          const reduction = Math.min(matchingTactics.length * 10, 30);
          modifiedRisk = Math.max(0, Math.round(originalScore.riskScore - reduction));
          reason = `Risk reduced by ${reduction}%: control mitigates ${matchingTactics.join(", ")}`;
          if (modifiedRisk < 20) {
            eliminated = true;
            reason = `Path effectively mitigated: control covers ${matchingTactics.length} tactics`;
          }
        } else {
          reason = "No change: control does not cover tactics in this path";
        }
        break;
      }
      case "remove_node": {
        const targetNode = nodes.find((n) => n.id === scenario.nodeId || n.data?.entityId === scenario.nodeId);
        if (targetNode) {
          eliminated = true;
          reason = `Path eliminated: key node "${(targetNode.data?.value as string) || targetNode.id}" removed/isolated`;
        } else {
          reason = "No change: node not in this path";
        }
        break;
      }
      case "patch_severity": {
        const targetSev = scenario.targetSeverity || "low";
        const criticalAlerts = nodes.filter(
          (n) => n.type === "alert" && (n.data?.severity === "critical" || n.data?.severity === "high"),
        );
        if (criticalAlerts.length > 0) {
          const reduction = criticalAlerts.length * 8;
          modifiedRisk = Math.max(0, Math.round(originalScore.riskScore - reduction));
          reason = `Risk reduced by ${reduction}%: ${criticalAlerts.length} high/critical alerts downgraded to ${targetSev}`;
        } else {
          reason = "No change: no high/critical alerts in path";
        }
        break;
      }
    }

    if (!eliminated) {
      modifiedPathCount++;
      if (modifiedRisk < originalScore.riskScore) {
        pathsReduced.push(path.id);
      }
    }

    details.push({
      pathId: path.id,
      originalRisk: originalScore.riskScore,
      modifiedRisk: eliminated ? null : modifiedRisk,
      eliminated,
      reason,
    });
  }

  const modifiedAvgRisk =
    details.filter((d) => !d.eliminated && d.modifiedRisk !== null).reduce((sum, d) => sum + (d.modifiedRisk || 0), 0) /
    Math.max(modifiedPathCount, 1);

  const scenarioLabel =
    scenario.type === "remove_vulnerability"
      ? `Patch vulnerability: ${scenario.vulnerabilityId}`
      : scenario.type === "add_control"
        ? `Add control: ${scenario.controlName}`
        : scenario.type === "remove_node"
          ? `Isolate/remove node: ${scenario.nodeId}`
          : `Patch severity to: ${scenario.targetSeverity}`;

  return {
    scenario: scenarioLabel,
    originalPathCount: paths.length,
    modifiedPathCount,
    pathsEliminated: paths.length - modifiedPathCount,
    pathsReduced,
    riskReduction: Math.round(originalAvgRisk - modifiedAvgRisk),
    originalAvgRisk: Math.round(originalAvgRisk),
    modifiedAvgRisk: Math.round(modifiedAvgRisk),
    details,
  };
}

// -----------------------------------------------------------------------
// 12.3: Remediation Recommendations
// -----------------------------------------------------------------------
interface RemediationRec {
  rank: number;
  action: string;
  category: "patch" | "control" | "configuration" | "architecture" | "monitoring";
  impact: "high" | "medium" | "low";
  effort: "low" | "medium" | "high";
  costBenefit: number;
  pathsEliminated: number;
  riskReduction: number;
  details: string;
  affectedNodes: string[];
}

interface RemediationRecommendation {
  pathId: string;
  recommendations: RemediationRec[];
  topRecommendation: string;
  estimatedRiskReduction: number;
}

function generateRemediations(
  path: {
    id: string;
    nodes: unknown;
    edges: unknown;
    tacticsSequence: unknown;
    techniquesUsed: unknown;
    hopCount: number | null;
    lastAlertAt: Date | null;
  },
  allPaths: Array<{
    id: string;
    nodes: unknown;
    edges: unknown;
    tacticsSequence: unknown;
    techniquesUsed: unknown;
    hopCount: number | null;
    lastAlertAt: Date | null;
  }>,
): RemediationRecommendation {
  const riskResult = computeAttackPathRiskScore(path);
  const nodes = (path.nodes || []) as Array<{
    type: string;
    id: string;
    data?: Record<string, unknown>;
  }>;
  const tactics = (path.tacticsSequence || []) as string[];
  const recommendations: RemediationRec[] = [];
  let rank = 0;

  // Find bottleneck nodes (appear in multiple paths)
  const nodeOccurrences = new Map<string, number>();
  for (const p of allPaths) {
    const pNodes = (p.nodes || []) as Array<{ data?: Record<string, unknown>; id: string }>;
    for (const n of pNodes) {
      const key = (n.data?.entityId as string) || (n.data?.alertId as string) || n.id;
      nodeOccurrences.set(key, (nodeOccurrences.get(key) || 0) + 1);
    }
  }

  // 1. Patch critical/high vulnerabilities
  const criticalAlerts = nodes.filter(
    (n) => n.type === "alert" && (n.data?.severity === "critical" || n.data?.severity === "high"),
  );
  if (criticalAlerts.length > 0) {
    const pathsAffected = allPaths.filter((p) => {
      const pNodes = (p.nodes || []) as Array<{ data?: Record<string, unknown> }>;
      return criticalAlerts.some((ca) => pNodes.some((pn) => pn.data?.alertId === ca.data?.alertId));
    }).length;
    rank++;
    recommendations.push({
      rank,
      action: `Remediate ${criticalAlerts.length} critical/high severity finding(s)`,
      category: "patch",
      impact: "high",
      effort: "medium",
      costBenefit: Math.min(95, 60 + pathsAffected * 5),
      pathsEliminated: Math.ceil(pathsAffected * 0.6),
      riskReduction: Math.round(riskResult.riskScore * 0.4),
      details: `Alerts: ${criticalAlerts.map((a) => (a.data?.title as string) || a.id).join("; ")}`,
      affectedNodes: criticalAlerts.map((a) => (a.data?.alertId as string) || a.id),
    });
  }

  // 2. Isolate bottleneck entity
  const entityNodes = nodes.filter((n) => n.type === "entity");
  const bottleneckEntities = entityNodes
    .filter((n) => (nodeOccurrences.get((n.data?.entityId as string) || n.id) || 0) >= 2)
    .sort(
      (a, b) =>
        (nodeOccurrences.get((b.data?.entityId as string) || b.id) || 0) -
        (nodeOccurrences.get((a.data?.entityId as string) || a.id) || 0),
    );
  if (bottleneckEntities.length > 0) {
    const top = bottleneckEntities[0];
    const occurrences = nodeOccurrences.get((top.data?.entityId as string) || top.id) || 0;
    rank++;
    recommendations.push({
      rank,
      action: `Segment/isolate entity: ${(top.data?.value as string) || (top.data?.displayName as string) || top.id}`,
      category: "architecture",
      impact: "high",
      effort: "high",
      costBenefit: Math.min(90, 50 + occurrences * 10),
      pathsEliminated: occurrences,
      riskReduction: Math.round(riskResult.riskScore * 0.5),
      details: `This entity appears in ${occurrences} attack path(s). Isolating it would break multiple chains.`,
      affectedNodes: [(top.data?.entityId as string) || top.id],
    });
  }

  // 3. MFA for credential/initial-access
  if (tactics.includes("credential-access") || tactics.includes("initial-access")) {
    rank++;
    recommendations.push({
      rank,
      action: "Enforce multi-factor authentication (MFA) on all access points",
      category: "control",
      impact: "high",
      effort: "low",
      costBenefit: 85,
      pathsEliminated: Math.ceil(
        allPaths.filter(
          (p) =>
            ((p.tacticsSequence || []) as string[]).includes("credential-access") ||
            ((p.tacticsSequence || []) as string[]).includes("initial-access"),
        ).length * 0.4,
      ),
      riskReduction: Math.round(riskResult.riskScore * 0.25),
      details: "MFA significantly reduces the effectiveness of credential-based attack vectors.",
      affectedNodes: [],
    });
  }

  // 4. Network segmentation for lateral-movement
  if (tactics.includes("lateral-movement")) {
    rank++;
    recommendations.push({
      rank,
      action: "Implement network micro-segmentation between affected zones",
      category: "architecture",
      impact: "high",
      effort: "high",
      costBenefit: 75,
      pathsEliminated: Math.ceil(
        allPaths.filter((p) => ((p.tacticsSequence || []) as string[]).includes("lateral-movement")).length * 0.6,
      ),
      riskReduction: Math.round(riskResult.riskScore * 0.35),
      details: "Micro-segmentation prevents lateral movement between network zones.",
      affectedNodes: entityNodes.map((n) => (n.data?.entityId as string) || n.id),
    });
  }

  // 5. Detection rules for observed techniques
  const techniques = (path.techniquesUsed || []) as string[];
  if (techniques.length > 0) {
    rank++;
    recommendations.push({
      rank,
      action: `Deploy detection rules for ${techniques.length} observed MITRE technique(s)`,
      category: "monitoring",
      impact: "medium",
      effort: "low",
      costBenefit: 70,
      pathsEliminated: 0,
      riskReduction: Math.round(riskResult.riskScore * 0.15),
      details: `Techniques: ${techniques.join(", ")}. Custom rules reduce dwell time.`,
      affectedNodes: [],
    });
  }

  // 6. PAM for privilege escalation
  if (tactics.includes("privilege-escalation")) {
    rank++;
    recommendations.push({
      rank,
      action: "Deploy Privileged Access Management (PAM) for administrative accounts",
      category: "control",
      impact: "high",
      effort: "medium",
      costBenefit: 80,
      pathsEliminated: Math.ceil(
        allPaths.filter((p) => ((p.tacticsSequence || []) as string[]).includes("privilege-escalation")).length * 0.5,
      ),
      riskReduction: Math.round(riskResult.riskScore * 0.3),
      details: "PAM controls prevent unauthorized privilege escalation and limit blast radius.",
      affectedNodes: [],
    });
  }

  // Sort by cost-benefit
  recommendations.sort((a, b) => b.costBenefit - a.costBenefit);
  recommendations.forEach((r, i) => {
    r.rank = i + 1;
  });

  return {
    pathId: path.id,
    recommendations,
    topRecommendation: recommendations.length > 0 ? recommendations[0].action : "No specific recommendations",
    estimatedRiskReduction: recommendations.length > 0 ? recommendations[0].riskReduction : 0,
  };
}

// -----------------------------------------------------------------------
// 12.5: MITRE ATT&CK Mapping
// -----------------------------------------------------------------------
interface MitreStepMapping {
  stepIndex: number;
  nodeId: string;
  nodeType: "alert" | "entity";
  technique: string | null;
  techniqueId: string | null;
  tactic: string | null;
  tacticIndex: number;
  description: string;
  detectionCoverage: "detected" | "inferred" | "gap";
}

function mapPathToMitre(path: { id: string; nodes: unknown; tacticsSequence: unknown; techniquesUsed: unknown }): {
  pathId: string;
  steps: MitreStepMapping[];
  tacticsCovered: string[];
  tacticsGaps: string[];
  coveragePercentage: number;
  detectionGaps: string[];
} {
  const nodes = (path.nodes || []) as Array<{
    type: string;
    id: string;
    data?: Record<string, unknown>;
  }>;

  const steps: MitreStepMapping[] = [];
  const coveredTactics = new Set<string>();

  for (let i = 0; i < nodes.length; i++) {
    const node = nodes[i];
    let technique: string | null = null;
    let techniqueId: string | null = null;
    let tactic: string | null = null;

    if (node.type === "alert") {
      tactic = (node.data?.mitreTactic as string) || null;
      const rawTechnique = (node.data?.mitreTechnique as string) || null;

      if (rawTechnique) {
        const match = rawTechnique.match(/T\d{4}/);
        if (match) {
          techniqueId = match[0];
          const known = TECHNIQUE_TACTIC_MAP[techniqueId];
          technique = known ? known.name : rawTechnique;
          if (!tactic && known) tactic = known.tactic;
        } else {
          technique = rawTechnique;
        }
      }

      if (tactic) coveredTactics.add(tactic);
    }

    const tacticIndex = tactic ? KILL_CHAIN_ORDER.indexOf(tactic) : -1;
    const detectionCoverage: "detected" | "inferred" | "gap" =
      node.type === "alert" && tactic ? "detected" : node.type === "entity" ? "inferred" : "gap";

    steps.push({
      stepIndex: i,
      nodeId: node.id,
      nodeType: node.type as "alert" | "entity",
      technique,
      techniqueId,
      tactic,
      tacticIndex,
      description:
        node.type === "alert"
          ? `Alert: ${(node.data?.title as string) || "Unknown"} (${(node.data?.severity as string) || "unknown"})`
          : `Entity: ${(node.data?.type as string) || "unknown"}:${(node.data?.value as string) || node.id}`,
      detectionCoverage,
    });
  }

  const tacticsUsed = Array.from(coveredTactics);
  const tacticIndices = tacticsUsed
    .map((t) => KILL_CHAIN_ORDER.indexOf(t))
    .filter((i) => i >= 0)
    .sort((a, b) => a - b);

  const tacticsGaps: string[] = [];
  if (tacticIndices.length >= 2) {
    const minIdx = tacticIndices[0];
    const maxIdx = tacticIndices[tacticIndices.length - 1];
    for (let i = minIdx; i <= maxIdx; i++) {
      if (!coveredTactics.has(KILL_CHAIN_ORDER[i])) {
        tacticsGaps.push(KILL_CHAIN_ORDER[i]);
      }
    }
  }

  const detectionGaps = steps
    .filter((s) => s.detectionCoverage === "gap" && s.tactic)
    .map((s) => s.tactic!)
    .filter((t, i, arr) => arr.indexOf(t) === i);

  const coveragePercentage = Math.round((coveredTactics.size / KILL_CHAIN_ORDER.length) * 100);

  return { pathId: path.id, steps, tacticsCovered: tacticsUsed, tacticsGaps, coveragePercentage, detectionGaps };
}

// -----------------------------------------------------------------------
// 12.6: CSPM Correlation
// -----------------------------------------------------------------------
async function correlateCSPMFindings(
  orgId: string,
  paths: Array<{
    id: string;
    nodes: unknown;
    edges: unknown;
    tacticsSequence: unknown;
    techniquesUsed: unknown;
    hopCount: number | null;
    lastAlertAt: Date | null;
  }>,
): Promise<
  Array<{
    findingId: string;
    findingRule: string;
    findingSeverity: string;
    findingResource: string;
    findingDescription: string;
    findingRemediation: string | null;
    attackPathId: string;
    attackPathRisk: number;
    attackPathRiskLevel: string;
    relatedEntities: Array<{ type: unknown; value: unknown }>;
    correlationReason: string;
    combinedRiskScore: number;
  }>
> {
  const findings = await db
    .select()
    .from(cspmFindings)
    .where(and(eq(cspmFindings.orgId, orgId), eq(cspmFindings.status, "open")))
    .orderBy(desc(cspmFindings.detectedAt))
    .limit(200);

  if (findings.length === 0 || paths.length === 0) return [];

  const correlations: Array<{
    findingId: string;
    findingRule: string;
    findingSeverity: string;
    findingResource: string;
    findingDescription: string;
    findingRemediation: string | null;
    attackPathId: string;
    attackPathRisk: number;
    attackPathRiskLevel: string;
    relatedEntities: Array<{ type: unknown; value: unknown }>;
    correlationReason: string;
    combinedRiskScore: number;
  }> = [];

  for (const finding of findings) {
    const resourceType = (finding.resourceType || "").toLowerCase();
    const description = (finding.description || "").toLowerCase();

    for (const path of paths) {
      const nodes = (path.nodes || []) as Array<{
        type: string;
        id: string;
        data?: Record<string, unknown>;
      }>;
      const entityNodes = nodes.filter((n) => n.type === "entity");

      const relatedEntities = entityNodes.filter((n) => {
        const entityType = ((n.data?.type as string) || "").toLowerCase();
        const entityValue = ((n.data?.value as string) || "").toLowerCase();
        return (
          resourceType.includes(entityType) ||
          entityType.includes("cloud") ||
          entityType.includes("server") ||
          entityType.includes("host") ||
          entityValue.includes(finding.resourceId?.split("/").pop()?.toLowerCase() || "") ||
          (entityType === "ip" && description.includes("public"))
        );
      });

      if (relatedEntities.length > 0) {
        const pathRisk = computeAttackPathRiskScore(path);
        correlations.push({
          findingId: finding.id,
          findingRule: finding.ruleName,
          findingSeverity: finding.severity,
          findingResource: finding.resourceId,
          findingDescription: finding.description,
          findingRemediation: finding.remediation,
          attackPathId: path.id,
          attackPathRisk: pathRisk.riskScore,
          attackPathRiskLevel: pathRisk.riskLevel,
          relatedEntities: relatedEntities.map((e) => ({ type: e.data?.type, value: e.data?.value })),
          correlationReason: `CSPM finding "${finding.ruleName}" on ${finding.resourceType} correlates with attack path entities`,
          combinedRiskScore: Math.min(100, pathRisk.riskScore + (SEVERITY_SCORE[finding.severity] || 5) * 3),
        });
      }
    }
  }

  correlations.sort((a, b) => b.combinedRiskScore - a.combinedRiskScore);
  return correlations;
}

// -----------------------------------------------------------------------
// 12.7: Vulnerability Prioritization via Attack Path Context
// -----------------------------------------------------------------------
async function computeVulnPrioritization(
  orgId: string,
  paths: Array<{
    id: string;
    nodes: unknown;
    edges: unknown;
    tacticsSequence: unknown;
    techniquesUsed: unknown;
    hopCount: number | null;
    lastAlertAt: Date | null;
    alertIds: unknown;
  }>,
): Promise<
  Array<{
    alertId: string;
    title: string;
    intrinsicSeverity: string;
    intrinsicSeverityScore: number;
    contextualPriority: number;
    contextualLevel: string;
    pathCount: number;
    maxPathRisk: number;
    avgPathRisk: number;
    onCrownJewelPath: boolean;
    attackPathIds: string[];
    priorityJustification: string;
    upliftReason: string | null;
  }>
> {
  if (paths.length === 0) return [];

  const alertIdSet = new Set<string>();
  const alertPathMap = new Map<string, { pathIds: string[]; pathRisks: number[] }>();

  for (const path of paths) {
    const pathAlertIds = (path.alertIds || []) as string[];
    const pathRisk = computeAttackPathRiskScore(path);

    for (const alertId of pathAlertIds) {
      alertIdSet.add(alertId);
      const existing = alertPathMap.get(alertId) || { pathIds: [], pathRisks: [] };
      existing.pathIds.push(path.id);
      existing.pathRisks.push(pathRisk.riskScore);
      alertPathMap.set(alertId, existing);
    }
  }

  if (alertIdSet.size === 0) return [];

  const alertIds = Array.from(alertIdSet).slice(0, 200);
  const orgAlerts = await db
    .select()
    .from(alerts)
    .where(and(eq(alerts.orgId, orgId), inArray(alerts.id, alertIds)));

  const prioritization = orgAlerts.map((alert) => {
    const pathData = alertPathMap.get(alert.id) || { pathIds: [], pathRisks: [] };
    const maxPathRisk = pathData.pathRisks.length > 0 ? Math.max(...pathData.pathRisks) : 0;
    const avgPathRisk =
      pathData.pathRisks.length > 0 ? pathData.pathRisks.reduce((a, b) => a + b, 0) / pathData.pathRisks.length : 0;

    const intrinsicSeverity = SEVERITY_SCORE[alert.severity] || 2;
    const pathCountBoost = Math.min(pathData.pathIds.length * 5, 20);

    const contextualPriority = Math.min(100, Math.round(intrinsicSeverity * 5 + maxPathRisk * 0.3 + pathCountBoost));

    const onCrownJewelPath = pathData.pathRisks.some((r) => r >= 80);

    return {
      alertId: alert.id,
      title: alert.title,
      intrinsicSeverity: alert.severity,
      intrinsicSeverityScore: intrinsicSeverity,
      contextualPriority,
      contextualLevel:
        contextualPriority >= 80
          ? "critical"
          : contextualPriority >= 60
            ? "high"
            : contextualPriority >= 40
              ? "medium"
              : "low",
      pathCount: pathData.pathIds.length,
      maxPathRisk,
      avgPathRisk: Math.round(avgPathRisk),
      onCrownJewelPath,
      attackPathIds: pathData.pathIds,
      priorityJustification: onCrownJewelPath
        ? `On crown jewel attack path (risk ${maxPathRisk}). Appears in ${pathData.pathIds.length} path(s).`
        : pathData.pathIds.length > 1
          ? `Appears in ${pathData.pathIds.length} attack paths. Max path risk: ${maxPathRisk}.`
          : `On attack path with risk score ${maxPathRisk}.`,
      upliftReason:
        contextualPriority > intrinsicSeverity * 10
          ? `Priority uplifted from ${alert.severity} to contextual ${contextualPriority >= 80 ? "critical" : contextualPriority >= 60 ? "high" : "medium"} due to attack path context`
          : null,
    };
  });

  prioritization.sort((a, b) => b.contextualPriority - a.contextualPriority);
  return prioritization;
}

// -----------------------------------------------------------------------
// Register all routes
// -----------------------------------------------------------------------
export function registerAttackPathAdvancedRoutes(app: Express): void {
  // 12.1: Risk scores for all paths
  app.get(
    "/api/attack-paths/risk-scores",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const paths = await db
          .select()
          .from(attackPaths)
          .where(eq(attackPaths.orgId, orgId))
          .orderBy(desc(attackPaths.createdAt))
          .limit(100);

        const scored = paths.map((p) => computeAttackPathRiskScore(p));
        scored.sort((a, b) => b.riskScore - a.riskScore);

        const summary = {
          totalPaths: scored.length,
          criticalPaths: scored.filter((s) => s.riskLevel === "critical").length,
          highPaths: scored.filter((s) => s.riskLevel === "high").length,
          mediumPaths: scored.filter((s) => s.riskLevel === "medium").length,
          lowPaths: scored.filter((s) => s.riskLevel === "low").length,
          avgRiskScore:
            scored.length > 0 ? Math.round(scored.reduce((sum, s) => sum + s.riskScore, 0) / scored.length) : 0,
          maxRiskScore: scored.length > 0 ? Math.max(...scored.map((s) => s.riskScore)) : 0,
        };

        res.json({ scores: scored, summary });
      } catch (error) {
        log.error("Risk scores error", { error: String(error) });
        res.status(500).json({ message: "Failed to compute attack path risk scores" });
      }
    },
  );

  // 12.1: Risk score for single path
  app.get(
    "/api/attack-paths/:id/risk-score",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const [path] = await db
          .select()
          .from(attackPaths)
          .where(and(eq(attackPaths.id, p(req.params.id)), eq(attackPaths.orgId, orgId)));

        if (!path) return res.status(404).json({ message: "Attack path not found" });
        res.json(computeAttackPathRiskScore(path));
      } catch (error) {
        log.error("Risk score error", { error: String(error) });
        res.status(500).json({ message: "Failed to compute risk score" });
      }
    },
  );

  // 12.2: What-if simulation
  app.post(
    "/api/attack-paths/simulate",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { type, vulnerabilityId, controlName, nodeId, targetSeverity, affectedTactics } = req.body;

        if (!type) return res.status(400).json({ message: "Simulation type is required" });
        const validTypes = ["remove_vulnerability", "add_control", "remove_node", "patch_severity"];
        if (!validTypes.includes(type)) {
          return res.status(400).json({ message: `Invalid simulation type. Must be one of: ${validTypes.join(", ")}` });
        }

        const paths = await db
          .select()
          .from(attackPaths)
          .where(eq(attackPaths.orgId, orgId))
          .orderBy(desc(attackPaths.createdAt))
          .limit(100);

        if (paths.length === 0) {
          return res.json({
            scenario: type,
            originalPathCount: 0,
            modifiedPathCount: 0,
            pathsEliminated: 0,
            pathsReduced: [],
            riskReduction: 0,
            originalAvgRisk: 0,
            modifiedAvgRisk: 0,
            details: [],
          });
        }

        const result = simulateWhatIf(paths, {
          type,
          vulnerabilityId,
          controlName,
          nodeId,
          targetSeverity,
          affectedTactics,
        });
        res.json(result);
      } catch (error) {
        log.error("Simulation error", { error: String(error) });
        res.status(500).json({ message: "Failed to run what-if simulation" });
      }
    },
  );

  // 12.3: Remediation recommendations for a single path
  app.get(
    "/api/attack-paths/:id/remediation",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const [path] = await db
          .select()
          .from(attackPaths)
          .where(and(eq(attackPaths.id, p(req.params.id)), eq(attackPaths.orgId, orgId)));

        if (!path) return res.status(404).json({ message: "Attack path not found" });

        const allPaths = await db.select().from(attackPaths).where(eq(attackPaths.orgId, orgId)).limit(100);
        res.json(generateRemediations(path, allPaths));
      } catch (error) {
        log.error("Remediation error", { error: String(error) });
        res.status(500).json({ message: "Failed to generate remediation recommendations" });
      }
    },
  );

  // 12.3: Cross-path global remediation impact analysis
  app.get(
    "/api/attack-paths/global-remediation",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const paths = await db
          .select()
          .from(attackPaths)
          .where(eq(attackPaths.orgId, orgId))
          .orderBy(desc(attackPaths.createdAt))
          .limit(100);

        if (paths.length === 0) {
          return res.json({ recommendations: [], summary: { totalPaths: 0, avgRiskScore: 0 } });
        }

        const allRemediations = paths.map((p) => generateRemediations(p, paths));
        const actionMap = new Map<
          string,
          {
            action: string;
            category: string;
            totalImpact: number;
            pathsAffected: number;
            totalRiskReduction: number;
            effort: string;
          }
        >();

        for (const rem of allRemediations) {
          for (const rec of rem.recommendations) {
            const existing = actionMap.get(rec.action);
            if (existing) {
              existing.pathsAffected++;
              existing.totalRiskReduction += rec.riskReduction;
              existing.totalImpact = Math.max(existing.totalImpact, rec.costBenefit);
            } else {
              actionMap.set(rec.action, {
                action: rec.action,
                category: rec.category,
                totalImpact: rec.costBenefit,
                pathsAffected: 1,
                totalRiskReduction: rec.riskReduction,
                effort: rec.effort,
              });
            }
          }
        }

        const globalRecommendations = Array.from(actionMap.values())
          .sort((a, b) => b.totalImpact * b.pathsAffected - a.totalImpact * a.pathsAffected)
          .slice(0, 15);

        const scored = paths.map((p) => computeAttackPathRiskScore(p));
        const avgRiskScore =
          scored.length > 0 ? Math.round(scored.reduce((sum, s) => sum + s.riskScore, 0) / scored.length) : 0;

        res.json({
          recommendations: globalRecommendations,
          summary: {
            totalPaths: paths.length,
            avgRiskScore,
            criticalPaths: scored.filter((s) => s.riskLevel === "critical").length,
            highPaths: scored.filter((s) => s.riskLevel === "high").length,
          },
        });
      } catch (error) {
        log.error("Global remediation error", { error: String(error) });
        res.status(500).json({ message: "Failed to compute global remediation" });
      }
    },
  );

  // 12.4: Automated attack path discovery
  app.post(
    "/api/attack-paths/discover",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { runGraphCorrelation } = await import("../graph-correlation");
        const results = await runGraphCorrelation(orgId);

        const paths = await db
          .select()
          .from(attackPaths)
          .where(eq(attackPaths.orgId, orgId))
          .orderBy(desc(attackPaths.createdAt))
          .limit(100);

        const scored = paths.map((p) => computeAttackPathRiskScore(p));
        scored.sort((a, b) => b.riskScore - a.riskScore);

        const cspmCorrelations = await correlateCSPMFindings(orgId, paths);
        const vulnPrioritization = await computeVulnPrioritization(orgId, paths);

        res.json({
          discovered: true,
          newAttackPaths: results.attackPaths.length,
          campaignsCreated: results.campaignsCreated,
          clustersCreated: results.clustersCreated,
          riskScores: scored.slice(0, 20),
          cspmCorrelations: cspmCorrelations.slice(0, 20),
          vulnPrioritization: vulnPrioritization.slice(0, 20),
        });
      } catch (error) {
        log.error("Discovery error", { error: String(error) });
        res.status(500).json({ message: "Failed to run automated attack path discovery" });
      }
    },
  );

  // 12.5: MITRE ATT&CK mapping for path steps
  app.get(
    "/api/attack-paths/:id/mitre-mapping",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const [path] = await db
          .select()
          .from(attackPaths)
          .where(and(eq(attackPaths.id, p(req.params.id)), eq(attackPaths.orgId, orgId)));

        if (!path) return res.status(404).json({ message: "Attack path not found" });
        res.json(mapPathToMitre(path));
      } catch (error) {
        log.error("MITRE mapping error", { error: String(error) });
        res.status(500).json({ message: "Failed to map attack path to MITRE ATT&CK" });
      }
    },
  );

  // 12.6: CSPM correlation with attack paths
  app.get(
    "/api/attack-paths/cspm-correlation",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const paths = await db
          .select()
          .from(attackPaths)
          .where(eq(attackPaths.orgId, orgId))
          .orderBy(desc(attackPaths.createdAt))
          .limit(100);

        const correlations = await correlateCSPMFindings(orgId, paths);
        res.json({ totalCorrelations: correlations.length, correlations });
      } catch (error) {
        log.error("CSPM correlation error", { error: String(error) });
        res.status(500).json({ message: "Failed to correlate CSPM findings" });
      }
    },
  );

  // 12.7: Vulnerability prioritization based on attack paths
  app.get(
    "/api/attack-paths/vuln-prioritization",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const paths = await db
          .select()
          .from(attackPaths)
          .where(eq(attackPaths.orgId, orgId))
          .orderBy(desc(attackPaths.createdAt))
          .limit(100);

        const prioritization = await computeVulnPrioritization(orgId, paths);
        res.json({ totalVulnerabilities: prioritization.length, prioritization });
      } catch (error) {
        log.error("Vuln prioritization error", { error: String(error) });
        res.status(500).json({ message: "Failed to compute vulnerability prioritization" });
      }
    },
  );
}

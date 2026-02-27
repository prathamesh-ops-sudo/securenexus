import { storage } from "./storage";
import { logger } from "./logger";
import { evaluateAndAlert } from "./slo-alerting";
import { dispatchNotification } from "./notification-dispatcher";

const log = logger.child("canary-analysis");

export interface CanaryMetricSnapshot {
  errorRate: number;
  latencyP95Ms: number;
  readinessHealthy: boolean;
  dbConnected: boolean;
  poolHealthy: boolean;
  inFlightRequests: number;
  timestamp: string;
}

export interface CanaryAnalysisResult {
  status: "pass" | "fail" | "inconclusive";
  metrics: CanaryMetricSnapshot;
  thresholds: {
    errorRateMax: number;
    latencyP95MaxMs: number;
  };
  violations: string[];
  recommendation: "continue" | "rollback" | "pause";
  analyzedAt: string;
}

export interface RollbackTrigger {
  id: string;
  name: string;
  condition: string;
  threshold: number;
  action: "auto_rollback" | "pause_rollout" | "alert_only";
  enabled: boolean;
  cooldownMinutes: number;
}

const DEFAULT_ROLLBACK_TRIGGERS: RollbackTrigger[] = [
  {
    id: "error-rate-critical",
    name: "Critical Error Rate Spike",
    condition: "error_rate > threshold",
    threshold: 10,
    action: "auto_rollback",
    enabled: true,
    cooldownMinutes: 5,
  },
  {
    id: "error-rate-warning",
    name: "Elevated Error Rate",
    condition: "error_rate > threshold",
    threshold: 5,
    action: "pause_rollout",
    enabled: true,
    cooldownMinutes: 3,
  },
  {
    id: "latency-critical",
    name: "Critical Latency Spike",
    condition: "latency_p95 > threshold",
    threshold: 2000,
    action: "auto_rollback",
    enabled: true,
    cooldownMinutes: 5,
  },
  {
    id: "latency-warning",
    name: "Elevated Latency",
    condition: "latency_p95 > threshold",
    threshold: 800,
    action: "pause_rollout",
    enabled: true,
    cooldownMinutes: 3,
  },
  {
    id: "readiness-failure",
    name: "Canary Readiness Failure",
    condition: "readiness_healthy == false",
    threshold: 0,
    action: "auto_rollback",
    enabled: true,
    cooldownMinutes: 2,
  },
  {
    id: "db-connectivity-loss",
    name: "Database Connectivity Loss",
    condition: "db_connected == false",
    threshold: 0,
    action: "auto_rollback",
    enabled: true,
    cooldownMinutes: 2,
  },
  {
    id: "slo-breach-critical",
    name: "SLO Breach (Critical)",
    condition: "slo_breaches_critical > threshold",
    threshold: 0,
    action: "auto_rollback",
    enabled: true,
    cooldownMinutes: 10,
  },
];

const lastTriggerFired = new Map<string, number>();

function isTriggerCoolingDown(triggerId: string, cooldownMinutes: number): boolean {
  const lastFired = lastTriggerFired.get(triggerId);
  if (!lastFired) return false;
  return Date.now() - lastFired < cooldownMinutes * 60 * 1000;
}

export async function evaluateCanaryMetrics(
  errorRateThreshold: number = 5,
  latencyP95ThresholdMs: number = 800,
): Promise<CanaryAnalysisResult> {
  const violations: string[] = [];
  let errorRate = 0;
  let latencyP95 = 0;

  try {
    const sloResult = await evaluateAndAlert();
    const apiErrorSlo = sloResult.alerts.find((a) => a.service === "api" && a.metric === "error_rate");
    const apiLatencySlo = sloResult.alerts.find((a) => a.service === "api" && a.metric === "latency_p95");

    if (apiErrorSlo) {
      errorRate = apiErrorSlo.actual;
    }
    if (apiLatencySlo) {
      latencyP95 = apiLatencySlo.actual;
    }
  } catch (err) {
    log.warn("Failed to fetch SLO metrics for canary analysis", { error: String(err) });
  }

  let readinessHealthy = true;
  let dbConnected = true;
  let poolHealthy = true;
  let inFlightRequests = 0;

  try {
    const { checkReadiness, getInFlightCount } = await import("./request-lifecycle");
    const readiness = await checkReadiness();
    readinessHealthy = readiness.ready;
    dbConnected = readiness.checks.database.connected;
    poolHealthy = readiness.checks.pool.healthy;
    inFlightRequests = getInFlightCount();
  } catch (err) {
    log.warn("Failed to check readiness for canary analysis", { error: String(err) });
    readinessHealthy = false;
  }

  if (errorRate > errorRateThreshold) {
    violations.push(`Error rate ${errorRate.toFixed(2)}% exceeds threshold ${errorRateThreshold}%`);
  }
  if (latencyP95 > latencyP95ThresholdMs) {
    violations.push(`P95 latency ${latencyP95.toFixed(0)}ms exceeds threshold ${latencyP95ThresholdMs}ms`);
  }
  if (!readinessHealthy) {
    violations.push("Canary pod readiness probe is failing");
  }
  if (!dbConnected) {
    violations.push("Canary pod has lost database connectivity");
  }
  if (!poolHealthy) {
    violations.push("Canary pod connection pool is unhealthy");
  }

  let status: CanaryAnalysisResult["status"] = "pass";
  let recommendation: CanaryAnalysisResult["recommendation"] = "continue";

  if (violations.length > 0) {
    const hasCritical = !readinessHealthy || !dbConnected || errorRate > errorRateThreshold * 2;
    status = "fail";
    recommendation = hasCritical ? "rollback" : "pause";
  }

  return {
    status,
    metrics: {
      errorRate,
      latencyP95Ms: latencyP95,
      readinessHealthy,
      dbConnected,
      poolHealthy,
      inFlightRequests,
      timestamp: new Date().toISOString(),
    },
    thresholds: {
      errorRateMax: errorRateThreshold,
      latencyP95MaxMs: latencyP95ThresholdMs,
    },
    violations,
    recommendation,
    analyzedAt: new Date().toISOString(),
  };
}

export interface RollbackTriggerEvaluation {
  triggerId: string;
  triggerName: string;
  fired: boolean;
  action: RollbackTrigger["action"];
  reason: string;
  cooldownActive: boolean;
}

export async function evaluateRollbackTriggers(
  metrics: CanaryMetricSnapshot,
  triggers: RollbackTrigger[] = DEFAULT_ROLLBACK_TRIGGERS,
): Promise<RollbackTriggerEvaluation[]> {
  const evaluations: RollbackTriggerEvaluation[] = [];

  for (const trigger of triggers) {
    if (!trigger.enabled) continue;

    const cooldownActive = isTriggerCoolingDown(trigger.id, trigger.cooldownMinutes);
    let fired = false;
    let reason = "";

    switch (trigger.id) {
      case "error-rate-critical":
      case "error-rate-warning":
        fired = metrics.errorRate > trigger.threshold;
        reason = fired ? `Error rate ${metrics.errorRate.toFixed(2)}% > ${trigger.threshold}%` : "Within threshold";
        break;
      case "latency-critical":
      case "latency-warning":
        fired = metrics.latencyP95Ms > trigger.threshold;
        reason = fired
          ? `P95 latency ${metrics.latencyP95Ms.toFixed(0)}ms > ${trigger.threshold}ms`
          : "Within threshold";
        break;
      case "readiness-failure":
        fired = !metrics.readinessHealthy;
        reason = fired ? "Readiness probe returning unhealthy" : "Readiness healthy";
        break;
      case "db-connectivity-loss":
        fired = !metrics.dbConnected;
        reason = fired ? "Database connection lost" : "Database connected";
        break;
      case "slo-breach-critical": {
        const sloResult = await evaluateAndAlert();
        const criticalBreaches = sloResult.alerts.filter((a) => a.severity === "critical").length;
        fired = criticalBreaches > trigger.threshold;
        reason = fired ? `${criticalBreaches} critical SLO breaches detected` : "No critical SLO breaches";
        break;
      }
      default:
        reason = "Unknown trigger";
    }

    if (fired && !cooldownActive) {
      lastTriggerFired.set(trigger.id, Date.now());

      log.warn("Rollback trigger fired", {
        triggerId: trigger.id,
        action: trigger.action,
        reason,
      });

      if (trigger.action === "auto_rollback" || trigger.action === "pause_rollout") {
        dispatchNotification(
          {
            title: `Canary ${trigger.action === "auto_rollback" ? "Rollback" : "Pause"}: ${trigger.name}`,
            body: reason,
            severity: trigger.action === "auto_rollback" ? "critical" : "warning",
            source: "canary-analysis",
            metadata: { triggerId: trigger.id, action: trigger.action },
          },
          "canary_trigger",
        ).catch((err) => log.error("Failed to dispatch canary trigger notification", { error: String(err) }));
      }
    }

    evaluations.push({
      triggerId: trigger.id,
      triggerName: trigger.name,
      fired: fired && !cooldownActive,
      action: trigger.action,
      reason,
      cooldownActive,
    });
  }

  return evaluations;
}

export function getRollbackTriggers(): RollbackTrigger[] {
  return [...DEFAULT_ROLLBACK_TRIGGERS];
}

export function getRollbackRunbook(): {
  title: string;
  description: string;
  steps: Array<{ order: number; instruction: string; expectedDuration: string; responsible: string }>;
} {
  return {
    title: "Argo Rollouts Fast Rollback Procedure",
    description:
      "Step-by-step procedure for rolling back a canary deployment when automated analysis detects degraded metrics. Can be triggered automatically by rollback triggers or manually by operators.",
    steps: [
      {
        order: 1,
        instruction:
          "Verify the rollback trigger. Check /api/ops/canary/triggers to confirm which trigger fired and the current metric values.",
        expectedDuration: "30 sec",
        responsible: "SRE / Platform",
      },
      {
        order: 2,
        instruction:
          "Abort the Argo Rollout: kubectl argo rollouts abort securenexus -n production. This immediately stops the canary progression and scales down canary pods.",
        expectedDuration: "10 sec",
        responsible: "SRE / Platform",
      },
      {
        order: 3,
        instruction:
          "Verify stable pods are serving all traffic: kubectl argo rollouts get rollout securenexus -n production. Confirm 100% traffic on stable revision.",
        expectedDuration: "30 sec",
        responsible: "SRE / Platform",
      },
      {
        order: 4,
        instruction:
          "Check application health: curl http://securenexus-stable.production.svc.cluster.local/api/ops/ready. Confirm readiness probe returns ready: true.",
        expectedDuration: "15 sec",
        responsible: "SRE / Platform",
      },
      {
        order: 5,
        instruction:
          "Undo the rollout to the last stable revision: kubectl argo rollouts undo securenexus -n production. This reverts the Rollout spec to the previous stable revision.",
        expectedDuration: "1 min",
        responsible: "SRE / Platform",
      },
      {
        order: 6,
        instruction:
          "Monitor SLO metrics via /api/ops/slo for 5 minutes to confirm error rates and latency have returned to normal baselines.",
        expectedDuration: "5 min",
        responsible: "SRE / Platform",
      },
      {
        order: 7,
        instruction:
          "Create a post-mortem incident via /api/v1/incidents with the canary analysis results, trigger details, and timeline. Tag as 'canary-rollback'.",
        expectedDuration: "2 min",
        responsible: "SRE / Platform",
      },
      {
        order: 8,
        instruction:
          "Notify stakeholders via the incident channel. Include rollback reason, impact duration, and corrective actions planned.",
        expectedDuration: "2 min",
        responsible: "SRE / Platform",
      },
    ],
  };
}

export async function createRollbackIncident(analysisResult: CanaryAnalysisResult, triggeredBy: string): Promise<void> {
  const title = `[Auto-Rollback] Canary deployment rolled back: ${analysisResult.violations.join(", ")}`;
  const summary = [
    `Canary analysis status: ${analysisResult.status}`,
    `Recommendation: ${analysisResult.recommendation}`,
    `Violations: ${analysisResult.violations.join("; ")}`,
    `Error Rate: ${analysisResult.metrics.errorRate.toFixed(2)}% (threshold: ${analysisResult.thresholds.errorRateMax}%)`,
    `P95 Latency: ${analysisResult.metrics.latencyP95Ms.toFixed(0)}ms (threshold: ${analysisResult.thresholds.latencyP95MaxMs}ms)`,
    `Triggered by: ${triggeredBy}`,
    `Analyzed at: ${analysisResult.analyzedAt}`,
  ].join("\n");

  try {
    await storage.createIncident({
      title,
      summary,
      severity: "critical",
      status: "open",
      assignedTo: null,
      orgId: null,
    });
    log.info("Created rollback incident", { violations: analysisResult.violations });
  } catch (err) {
    log.error("Failed to create rollback incident", { error: String(err) });
  }
}

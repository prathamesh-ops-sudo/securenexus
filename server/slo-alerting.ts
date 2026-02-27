import { storage } from "./storage";
import { evaluateSlos } from "./sli-middleware";
import { logger } from "./logger";
import { dispatchNotification } from "./notification-dispatcher";
import { startSpan } from "./tracing";

interface SloBreachRecord {
  sloId: string;
  service: string;
  metric: string;
  endpoint: string;
  target: number;
  actual: number;
  severity: "warning" | "critical";
  message: string;
  detectedAt: Date;
}

const BREACH_COOLDOWN_MS = 5 * 60 * 1000;
const lastBreachNotifications = new Map<string, number>();

const DEFAULT_SLO_TARGETS: Array<{
  service: string;
  metric: string;
  target: number;
  operator: string;
  windowMinutes: number;
  description: string;
}> = [
  {
    service: "api",
    metric: "latency_p95",
    target: 500,
    operator: "lte",
    windowMinutes: 15,
    description: "API p95 latency must stay under 500ms",
  },
  {
    service: "api",
    metric: "error_rate",
    target: 1,
    operator: "lte",
    windowMinutes: 15,
    description: "API error rate must stay under 1%",
  },
  {
    service: "api",
    metric: "availability",
    target: 99.5,
    operator: "gte",
    windowMinutes: 60,
    description: "API availability must exceed 99.5%",
  },
  {
    service: "ingestion",
    metric: "latency_p95",
    target: 2000,
    operator: "lte",
    windowMinutes: 15,
    description: "Ingestion p95 latency must stay under 2000ms",
  },
  {
    service: "ingestion",
    metric: "error_rate",
    target: 0.5,
    operator: "lte",
    windowMinutes: 15,
    description: "Ingestion error rate must stay under 0.5%",
  },
  {
    service: "ai",
    metric: "latency_p95",
    target: 5000,
    operator: "lte",
    windowMinutes: 30,
    description: "AI inference p95 latency must stay under 5000ms",
  },
  {
    service: "ai",
    metric: "error_rate",
    target: 5,
    operator: "lte",
    windowMinutes: 30,
    description: "AI error rate must stay under 5%",
  },
  {
    service: "connector",
    metric: "latency_p95",
    target: 10000,
    operator: "lte",
    windowMinutes: 30,
    description: "Connector sync p95 latency must stay under 10s",
  },
  {
    service: "connector",
    metric: "error_rate",
    target: 2,
    operator: "lte",
    windowMinutes: 30,
    description: "Connector error rate must stay under 2%",
  },
  {
    service: "enrichment",
    metric: "latency_p95",
    target: 3000,
    operator: "lte",
    windowMinutes: 30,
    description: "Enrichment p95 latency must stay under 3000ms",
  },
];

export async function seedDefaultSloTargets(): Promise<number> {
  let seeded = 0;
  const existing = await storage.getSloTargets();
  const existingKeys = new Set(existing.map((t) => `${t.service}:${t.metric}:${t.endpoint || "*"}`));

  for (const target of DEFAULT_SLO_TARGETS) {
    const key = `${target.service}:${target.metric}:*`;
    if (!existingKeys.has(key)) {
      await storage.createSloTarget({
        service: target.service,
        metric: target.metric,
        endpoint: "*",
        target: target.target,
        operator: target.operator,
        windowMinutes: target.windowMinutes,
        description: target.description,
        alertOnBreach: true,
      });
      seeded++;
    }
  }
  return seeded;
}

function classifyBreachSeverity(metric: string, target: number, actual: number): "warning" | "critical" {
  if (metric === "error_rate") {
    return actual > target * 3 ? "critical" : "warning";
  }
  if (metric.startsWith("latency_")) {
    return actual > target * 2 ? "critical" : "warning";
  }
  if (metric === "availability") {
    return actual < target - 2 ? "critical" : "warning";
  }
  return "warning";
}

function shouldNotify(sloId: string): boolean {
  const lastNotified = lastBreachNotifications.get(sloId);
  if (lastNotified && Date.now() - lastNotified < BREACH_COOLDOWN_MS) {
    return false;
  }
  lastBreachNotifications.set(sloId, Date.now());
  return true;
}

export async function evaluateAndAlert(): Promise<{
  evaluated: number;
  breached: number;
  alerts: SloBreachRecord[];
}> {
  const evaluations = await evaluateSlos();
  const breaches: SloBreachRecord[] = [];

  for (const evaluation of evaluations) {
    if (!evaluation.breached || evaluation.actual === -1) continue;

    const severity = classifyBreachSeverity(evaluation.metric, evaluation.target, evaluation.actual);
    const operatorLabel =
      evaluation.metric === "availability" || evaluation.metric === "throughput" ? "below" : "above";

    const breach: SloBreachRecord = {
      sloId: evaluation.sloId,
      service: evaluation.service,
      metric: evaluation.metric,
      endpoint: evaluation.endpoint,
      target: evaluation.target,
      actual: evaluation.actual,
      severity,
      message:
        `SLO breach: ${evaluation.service}/${evaluation.metric}${evaluation.endpoint && evaluation.endpoint !== "*" ? ` ${evaluation.endpoint}` : ""} is ${evaluation.actual} (${operatorLabel} target ${evaluation.target}). ${evaluation.description || ""}`.trim(),
      detectedAt: new Date(),
    };

    breaches.push(breach);

    if (shouldNotify(evaluation.sloId)) {
      logger.child("slo-alerting").warn(`${severity.toUpperCase()}: ${breach.message}`);

      dispatchNotification(
        {
          title: `SLO Breach: ${evaluation.service}/${evaluation.metric}`,
          body: breach.message,
          severity: severity === "critical" ? "critical" : "warning",
          source: "slo-alerting",
          metadata: {
            sloId: evaluation.sloId,
            service: evaluation.service,
            metric: evaluation.metric,
            target: evaluation.target,
            actual: evaluation.actual,
          },
        },
        "slo_breach",
      ).catch((err) =>
        logger.child("slo-alerting").error("Failed to dispatch breach notification", { error: String(err) }),
      );

      if (severity === "critical") {
        createBreachIncident(breach).catch((err) =>
          logger.child("slo-alerting").error("Failed to auto-create incident", { error: String(err) }),
        );
      }
    }
  }

  return {
    evaluated: evaluations.length,
    breached: breaches.length,
    alerts: breaches,
  };
}

export async function getBreachHistory(
  service?: string,
  hoursBack: number = 24,
): Promise<
  Array<{
    service: string;
    metric: string;
    endpoint: string;
    value: number;
    recordedAt: Date;
  }>
> {
  const windowStart = new Date(Date.now() - hoursBack * 60 * 60 * 1000);
  const now = new Date();

  const targets = await storage.getSloTargets();
  const filteredTargets = service ? targets.filter((t) => t.service === service) : targets;
  const results: Array<{ service: string; metric: string; endpoint: string; value: number; recordedAt: Date }> = [];

  for (const target of filteredTargets) {
    const metrics = await storage.getSliMetrics(
      target.service,
      target.metric,
      windowStart,
      now,
      target.endpoint && target.endpoint !== "*" ? { endpoint: target.endpoint } : undefined,
    );
    for (const m of metrics) {
      const isBreached = target.operator === "gte" ? m.value < target.target : m.value > target.target;
      if (isBreached) {
        results.push({
          service: target.service,
          metric: target.metric,
          endpoint: target.endpoint,
          value: m.value,
          recordedAt: m.recordedAt ?? new Date(),
        });
      }
    }
  }

  return results.sort((a, b) => b.recordedAt.getTime() - a.recordedAt.getTime());
}

const INCIDENT_DEDUP_MS = 30 * 60 * 1000;
const recentIncidentKeys = new Map<string, number>();

async function createBreachIncident(breach: SloBreachRecord): Promise<void> {
  const dedupKey = `${breach.service}:${breach.metric}:${breach.endpoint}`;
  const lastCreated = recentIncidentKeys.get(dedupKey);
  if (lastCreated && Date.now() - lastCreated < INCIDENT_DEDUP_MS) {
    return;
  }
  const title = `[Auto] SLO Breach: ${breach.service}/${breach.metric} (${breach.actual} vs target ${breach.target})`;

  await storage.createIncident({
    title,
    summary: breach.message,
    severity: "critical",
    status: "open",
    assignedTo: null,
    orgId: null,
  });

  recentIncidentKeys.set(dedupKey, Date.now());

  logger.child("slo-alerting").info("Auto-created incident for critical SLO breach", {
    service: breach.service,
    metric: breach.metric,
    actual: breach.actual,
    target: breach.target,
  });
}

let sloAlertTimer: NodeJS.Timeout | null = null;
const SLO_EVALUATION_INTERVAL_MS = 60000;

export function startSloAlerting(): void {
  if (sloAlertTimer) return;

  seedDefaultSloTargets()
    .then((seeded) => {
      if (seeded > 0) logger.child("slo-alerting").info(`Seeded ${seeded} default SLO targets`);
    })
    .catch((err) => logger.child("slo-alerting").error("Failed to seed defaults:", { error: String(err) }));

  sloAlertTimer = setInterval(() => {
    evaluateAndAlert().catch((err) => logger.child("slo-alerting").error("Evaluation error:", { error: String(err) }));
  }, SLO_EVALUATION_INTERVAL_MS);

  logger.child("slo-alerting").info("Alerting started - evaluating every 60s");
}

export function stopSloAlerting(): void {
  if (sloAlertTimer) {
    clearInterval(sloAlertTimer);
    sloAlertTimer = null;
  }
}

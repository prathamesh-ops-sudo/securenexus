import { db } from "./db";
import { sql } from "drizzle-orm";
import { storage } from "./storage";
import { logger } from "./logger";
import { getPodId } from "./scaling-state";

const log = logger.child("tenant-isolation");

export type IsolationLevel = "shared" | "dedicated-schema" | "dedicated-instance" | "dedicated-cluster";
export type PlanTier = "free" | "pro" | "enterprise";

export interface TenantIsolationConfig {
  orgId: string;
  planTier: PlanTier;
  isolationLevel: IsolationLevel;
  dedicatedDbUrl?: string;
  dedicatedSchema?: string;
  connectionPoolSize: number;
  maxConnectionsPerOrg: number;
  resourceGroup: string;
  noiseScore: number;
  lastAssessedAt: string;
}

const PLAN_ISOLATION_DEFAULTS: Record<PlanTier, { isolationLevel: IsolationLevel; connectionPoolSize: number; maxConnectionsPerOrg: number }> = {
  free: { isolationLevel: "shared", connectionPoolSize: 5, maxConnectionsPerOrg: 10 },
  pro: { isolationLevel: "shared", connectionPoolSize: 15, maxConnectionsPerOrg: 30 },
  enterprise: { isolationLevel: "dedicated-schema", connectionPoolSize: 50, maxConnectionsPerOrg: 100 },
};

const tenantConfigs = new Map<string, TenantIsolationConfig>();

export function getTenantIsolationConfig(orgId: string, plan: PlanTier = "free"): TenantIsolationConfig {
  const existing = tenantConfigs.get(orgId);
  if (existing) {
    if (existing.planTier !== plan) {
      const previousPlan = existing.planTier;
      const newDefaults = PLAN_ISOLATION_DEFAULTS[plan];
      existing.planTier = plan;
      existing.connectionPoolSize = newDefaults.connectionPoolSize;
      existing.maxConnectionsPerOrg = newDefaults.maxConnectionsPerOrg;
      existing.isolationLevel = newDefaults.isolationLevel;
      existing.resourceGroup = plan === "enterprise" ? "dedicated" : "shared";
      existing.lastAssessedAt = new Date().toISOString();
      log.info("Tenant config updated due to plan change", { orgId, oldPlan: previousPlan, newPlan: plan });
    }
    return existing;
  }

  const defaults = PLAN_ISOLATION_DEFAULTS[plan];
  const config: TenantIsolationConfig = {
    orgId,
    planTier: plan,
    isolationLevel: defaults.isolationLevel,
    connectionPoolSize: defaults.connectionPoolSize,
    maxConnectionsPerOrg: defaults.maxConnectionsPerOrg,
    resourceGroup: plan === "enterprise" ? "dedicated" : "shared",
    noiseScore: 0,
    lastAssessedAt: new Date().toISOString(),
  };

  tenantConfigs.set(orgId, config);
  return config;
}

export function setTenantIsolationConfig(orgId: string, updates: Partial<TenantIsolationConfig>, plan: PlanTier = "free"): TenantIsolationConfig {
  const current = tenantConfigs.get(orgId) || getTenantIsolationConfig(orgId, plan);
  const updated: TenantIsolationConfig = {
    ...current,
    ...updates,
    orgId,
    lastAssessedAt: new Date().toISOString(),
  };
  tenantConfigs.set(orgId, updated);
  log.info("Tenant isolation config updated", { orgId, isolationLevel: updated.isolationLevel, resourceGroup: updated.resourceGroup });
  return updated;
}

export interface NoisyNeighborMetrics {
  orgId: string;
  queryCountLast5Min: number;
  avgQueryLatencyMs: number;
  p99QueryLatencyMs: number;
  activeConnections: number;
  ingestionRatePerMin: number;
  cpuPressureScore: number;
  memoryPressureScore: number;
  noiseScore: number;
  isNoisy: boolean;
  recommendation: string;
}

interface OrgQuerySample {
  timestamp: number;
  latencyMs: number;
}

const orgQuerySamples = new Map<string, OrgQuerySample[]>();
const SAMPLE_WINDOW_MS = 5 * 60 * 1000;
const MAX_SAMPLES_PER_ORG = 1000;
const NOISY_THRESHOLD = 70;

export function recordQuerySample(orgId: string, latencyMs: number): void {
  let samples = orgQuerySamples.get(orgId);
  if (!samples) {
    samples = [];
    orgQuerySamples.set(orgId, samples);
  }

  const now = Date.now();
  samples.push({ timestamp: now, latencyMs });

  if (samples.length > MAX_SAMPLES_PER_ORG) {
    samples.splice(0, samples.length - MAX_SAMPLES_PER_ORG);
  }
}

function getRecentSamples(orgId: string): OrgQuerySample[] {
  const samples = orgQuerySamples.get(orgId);
  if (!samples) return [];
  const cutoff = Date.now() - SAMPLE_WINDOW_MS;
  return samples.filter((s) => s.timestamp >= cutoff);
}

function percentile(values: number[], pct: number): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const idx = Math.ceil((pct / 100) * sorted.length) - 1;
  return sorted[Math.max(0, idx)] ?? 0;
}

export function assessNoisyNeighbor(orgId: string): NoisyNeighborMetrics {
  const samples = getRecentSamples(orgId);
  const latencies = samples.map((s) => s.latencyMs);

  const queryCount = samples.length;
  const avgLatency = latencies.length > 0 ? latencies.reduce((a, b) => a + b, 0) / latencies.length : 0;
  const p99Latency = percentile(latencies, 99);

  const queryPressure = Math.min(queryCount / 500, 1) * 30;
  const latencyPressure = Math.min(p99Latency / 2000, 1) * 40;
  const volumePressure = Math.min(queryCount / 200, 1) * 30;

  const noiseScore = Math.round(queryPressure + latencyPressure + volumePressure);
  const isNoisy = noiseScore >= NOISY_THRESHOLD;

  let recommendation = "Normal operation — no action needed";
  if (noiseScore >= 90) {
    recommendation = "Critical: Migrate to dedicated instance immediately. This tenant is severely impacting shared resources.";
  } else if (noiseScore >= NOISY_THRESHOLD) {
    recommendation = "Warning: Consider dedicated schema or throttling. Tenant is causing noticeable resource contention.";
  } else if (noiseScore >= 40) {
    recommendation = "Monitor: Tenant is approaching noise threshold. Review query patterns and add indexes if needed.";
  }

  const config = tenantConfigs.get(orgId);
  if (config) {
    config.noiseScore = noiseScore;
    config.lastAssessedAt = new Date().toISOString();
  }

  return {
    orgId,
    queryCountLast5Min: queryCount,
    avgQueryLatencyMs: Math.round(avgLatency),
    p99QueryLatencyMs: Math.round(p99Latency),
    activeConnections: 0,
    ingestionRatePerMin: 0,
    cpuPressureScore: Math.round(queryPressure),
    memoryPressureScore: Math.round(latencyPressure),
    noiseScore,
    isNoisy,
    recommendation,
  };
}

export interface SchemaIsolationStatus {
  orgId: string;
  schemaName: string;
  tableCount: number;
  estimatedSizeMb: number;
  created: boolean;
}

export async function provisionDedicatedSchema(orgId: string, plan: PlanTier = "enterprise"): Promise<SchemaIsolationStatus> {
  const schemaName = `org_${orgId.replace(/[^a-zA-Z0-9_]/g, "_")}`;

  try {
    await db.execute(sql`CREATE SCHEMA IF NOT EXISTS ${sql.identifier(schemaName)}`);

    const CORE_TABLES = ["alerts", "incidents", "audit_logs", "sli_metrics", "jobs", "connector_job_runs", "outbox_events", "ingestion_logs"];

    for (const table of CORE_TABLES) {
      await db.execute(
        sql`CREATE TABLE IF NOT EXISTS ${sql.identifier(schemaName)}.${sql.identifier(table)} (LIKE public.${sql.identifier(table)} INCLUDING ALL)`
      );
    }

    const tableCountResult = await db.execute(
      sql`SELECT COUNT(*) as count FROM information_schema.tables WHERE table_schema = ${schemaName}`
    );
    const tableCount = Number(((tableCountResult as any).rows || [])[0]?.count || 0);

    const sizeResult = await db.execute(
      sql`SELECT pg_size_pretty(sum(pg_total_relation_size(quote_ident(schemaname) || '.' || quote_ident(tablename)))) as size FROM pg_tables WHERE schemaname = ${schemaName}`
    );
    const sizeStr = String(((sizeResult as any).rows || [])[0]?.size || "0 bytes");
    const estimatedSizeMb = parseSizeToMb(sizeStr);

    setTenantIsolationConfig(orgId, {
      isolationLevel: "dedicated-schema",
      dedicatedSchema: schemaName,
      resourceGroup: "dedicated",
    }, plan);

    log.info("Dedicated schema provisioned", { orgId, schemaName, tableCount });

    try {
      await storage.createAuditLog({
        orgId,
        userId: "system",
        userName: "Tenant Isolation",
        action: "schema_provisioned",
        resourceType: "tenant_isolation",
        details: { schemaName, tableCount, podId: getPodId() },
      });
    } catch (auditErr) {
      log.error("Failed to create audit log for schema provisioning", { error: String(auditErr) });
    }

    return { orgId, schemaName, tableCount, estimatedSizeMb, created: true };
  } catch (err) {
    log.error("Failed to provision dedicated schema", { orgId, error: String(err) });
    throw new Error(`Schema provisioning failed for org ${orgId}: ${String(err)}`);
  }
}

function parseSizeToMb(sizeStr: string): number {
  const match = sizeStr.match(/([\d.]+)\s*(bytes|kB|MB|GB|TB)/i);
  if (!match) return 0;
  const value = parseFloat(match[1]);
  const unit = (match[2] || "bytes").toLowerCase();
  switch (unit) {
    case "bytes": return value / (1024 * 1024);
    case "kb": return value / 1024;
    case "mb": return value;
    case "gb": return value * 1024;
    case "tb": return value * 1024 * 1024;
    default: return 0;
  }
}

export interface DedicatedInstanceConfig {
  orgId: string;
  instanceIdentifier: string;
  endpoint: string;
  port: number;
  status: "pending" | "provisioning" | "available" | "failed";
  instanceClass: string;
  allocatedStorageGb: number;
  provisionedAt: string;
}

const dedicatedInstances = new Map<string, DedicatedInstanceConfig>();

export function registerDedicatedInstance(orgId: string, instanceConfig: Omit<DedicatedInstanceConfig, "orgId" | "provisionedAt">, plan: PlanTier = "enterprise"): DedicatedInstanceConfig {
  const config: DedicatedInstanceConfig = {
    ...instanceConfig,
    orgId,
    provisionedAt: new Date().toISOString(),
  };

  dedicatedInstances.set(orgId, config);

  setTenantIsolationConfig(orgId, {
    isolationLevel: "dedicated-instance",
    dedicatedDbUrl: `postgresql://${instanceConfig.endpoint}:${instanceConfig.port}`,
    resourceGroup: "dedicated-instance",
  }, plan);

  log.info("Dedicated RDS instance registered", { orgId, instanceIdentifier: instanceConfig.instanceIdentifier });
  return config;
}

export function getDedicatedInstance(orgId: string): DedicatedInstanceConfig | undefined {
  return dedicatedInstances.get(orgId);
}

export interface TenantIsolationReport {
  podId: string;
  timestamp: string;
  totalTenants: number;
  byIsolationLevel: Record<IsolationLevel, number>;
  noisyTenants: NoisyNeighborMetrics[];
  dedicatedInstances: DedicatedInstanceConfig[];
  recommendations: Array<{ orgId: string; currentLevel: IsolationLevel; recommendedLevel: IsolationLevel; reason: string }>;
}

export function getTenantIsolationReport(): TenantIsolationReport {
  const byLevel: Record<IsolationLevel, number> = {
    shared: 0,
    "dedicated-schema": 0,
    "dedicated-instance": 0,
    "dedicated-cluster": 0,
  };

  const noisyTenants: NoisyNeighborMetrics[] = [];
  const recommendations: TenantIsolationReport["recommendations"] = [];

  for (const orgId of Array.from(tenantConfigs.keys())) {
    const config = tenantConfigs.get(orgId)!;
    byLevel[config.isolationLevel]++;

    const metrics = assessNoisyNeighbor(orgId);
    if (metrics.isNoisy) {
      noisyTenants.push(metrics);
    }

    if (metrics.noiseScore >= 90 && config.isolationLevel === "shared") {
      recommendations.push({
        orgId,
        currentLevel: "shared",
        recommendedLevel: "dedicated-instance",
        reason: `Noise score ${metrics.noiseScore}/100 — severely impacting shared resources`,
      });
    } else if (metrics.noiseScore >= NOISY_THRESHOLD && config.isolationLevel === "shared") {
      recommendations.push({
        orgId,
        currentLevel: "shared",
        recommendedLevel: "dedicated-schema",
        reason: `Noise score ${metrics.noiseScore}/100 — causing resource contention`,
      });
    }
  }

  return {
    podId: getPodId(),
    timestamp: new Date().toISOString(),
    totalTenants: tenantConfigs.size,
    byIsolationLevel: byLevel,
    noisyTenants,
    dedicatedInstances: Array.from(dedicatedInstances.values()),
    recommendations,
  };
}

export function initializeTenantIsolation(): void {
  log.info("Tenant isolation module initialized", { podId: getPodId() });

  setInterval(() => {
    const cutoff = Date.now() - SAMPLE_WINDOW_MS;
    for (const orgId of Array.from(orgQuerySamples.keys())) {
      const samples = orgQuerySamples.get(orgId);
      if (!samples) continue;
      const recent = samples.filter((s: OrgQuerySample) => s.timestamp >= cutoff);
      if (recent.length === 0) {
        orgQuerySamples.delete(orgId);
      } else {
        orgQuerySamples.set(orgId, recent);
      }
    }
  }, 60_000);
}

import { type Connector, type InsertAlert, type ConnectorJobRun, type InsertConnectorJobRun } from "@shared/schema";
import { normalizeAlert, toInsertAlert, SOURCE_KEYS } from "./normalizer";
import { storage } from "./storage";
import { config as appConfig } from "./config";
import { logger } from "./logger";
import { getPlugin, getAllPluginTypes, getPluginMetadata as registryGetMetadata } from "./connectors/connector-plugin";
import type { ConnectorPlugin } from "./connectors/connector-plugin";
import { initializeConnectorPlugins } from "./connectors/registry";

export type { ConnectorConfig, SyncResult, ConnectorTestResult } from "./connectors/connector-plugin";
import type { ConnectorConfig, SyncResult, ConnectorTestResult } from "./connectors/connector-plugin";

initializeConnectorPlugins();

const BATCH_SIZE = 50;
const DEFAULT_MAX_CONCURRENCY = 3;

const providerConcurrency = new Map<string, number>();
const providerActiveCount = new Map<string, number>();
const providerWaiters = new Map<string, Array<() => void>>();

const providerBackoff = new Map<string, { until: number; factor: number }>();

export function setProviderConcurrency(provider: string, max: number): void {
  providerConcurrency.set(provider, max);
}

function getMaxConcurrency(provider: string): number {
  return providerConcurrency.get(provider) ?? DEFAULT_MAX_CONCURRENCY;
}

async function acquireProviderSlot(provider: string): Promise<void> {
  const max = getMaxConcurrency(provider);
  const active = providerActiveCount.get(provider) ?? 0;
  if (active < max) {
    providerActiveCount.set(provider, active + 1);
    return;
  }
  return new Promise<void>((resolve) => {
    let waiters = providerWaiters.get(provider);
    if (!waiters) {
      waiters = [];
      providerWaiters.set(provider, waiters);
    }
    waiters.push(() => {
      resolve();
    });
  });
}

function releaseProviderSlot(provider: string): void {
  const waiters = providerWaiters.get(provider);
  if (waiters && waiters.length > 0) {
    const next = waiters.shift()!;
    next();
  } else {
    const active = providerActiveCount.get(provider) ?? 1;
    providerActiveCount.set(provider, Math.max(0, active - 1));
  }
}

function checkProviderBackoff(provider: string): number {
  const entry = providerBackoff.get(provider);
  if (!entry) return 0;
  const remaining = entry.until - Date.now();
  if (remaining <= 0) {
    providerBackoff.delete(provider);
    return 0;
  }
  return remaining;
}

function applyProviderBackoff(provider: string): void {
  const existing = providerBackoff.get(provider);
  const factor = existing ? Math.min(existing.factor * 2, 64) : 2;
  const waitMs = factor * 1000;
  providerBackoff.set(provider, { until: Date.now() + waitMs, factor });
  logger.child("connector-engine").warn("Provider " + provider + " backoff applied: " + waitMs + "ms", { provider, factor });
}

function clearProviderBackoff(provider: string): void {
  providerBackoff.delete(provider);
}

export function getProviderSyncStats(): Record<string, { active: number; maxConcurrency: number; backoffMs: number; waiting: number }> {
  const stats: Record<string, { active: number; maxConcurrency: number; backoffMs: number; waiting: number }> = {};
  const allProviders = Array.from(new Set([...Array.from(providerConcurrency.keys()), ...Array.from(providerActiveCount.keys())]));
  for (let pi = 0; pi < allProviders.length; pi++) {
    const p = allProviders[pi]!;
    stats[p] = {
      active: providerActiveCount.get(p) ?? 0,
      maxConcurrency: getMaxConcurrency(p),
      backoffMs: checkProviderBackoff(p),
      waiting: (providerWaiters.get(p) ?? []).length,
    };
  }
  return stats;
}

export async function testConnector(type: string, config: ConnectorConfig): Promise<ConnectorTestResult> {
  const plugin = getPlugin(type);
  if (!plugin) {
    return { success: false, message: "Unknown connector type: " + type, latencyMs: 0 };
  }
  return plugin.test(config);
}

function normalizeBatch(
  rawAlerts: unknown[],
  normalizer: (raw: unknown) => Partial<InsertAlert>,
  orgId: string | null,
): { normalized: Partial<InsertAlert>[]; failed: number; errors: string[] } {
  const normalized: Partial<InsertAlert>[] = [];
  let failed = 0;
  const errors: string[] = [];

  for (let i = 0; i < rawAlerts.length; i += BATCH_SIZE) {
    const batch = rawAlerts.slice(i, i + BATCH_SIZE);
    for (const raw of batch) {
      try {
        const n = normalizer(raw);
        n.orgId = orgId;
        normalized.push(n);
      } catch (err: unknown) {
        failed++;
        errors.push("Normalization failed: " + (err as Error).message);
      }
    }
  }

  return { normalized, failed, errors };
}

export async function syncConnector(connector: Connector): Promise<SyncResult> {
  const config = connector.config as ConnectorConfig;
  const type = connector.type;
  const plugin = getPlugin(type);
  if (!plugin) {
    return { alertsReceived: 0, alertsCreated: 0, alertsDeduped: 0, alertsFailed: 0, errors: ["Unknown connector type: " + type], rawAlerts: [] };
  }

  const backoffMs = checkProviderBackoff(type);
  if (backoffMs > 0) {
    return {
      alertsReceived: 0, alertsCreated: 0, alertsDeduped: 0, alertsFailed: 0,
      errors: ["Provider " + type + " in backoff for " + Math.ceil(backoffMs / 1000) + "s"],
      rawAlerts: [],
    };
  }

  await acquireProviderSlot(type);
  try {
    const since = connector.lastSyncAt || undefined;
    let rawAlerts: unknown[];
    try {
      rawAlerts = await plugin.fetch(config, since || undefined);
      clearProviderBackoff(type);
    } catch (err: unknown) {
      const msg = ((err as Error).message || "").toLowerCase();
      if (msg.includes("429") || msg.includes("rate limit") || msg.includes("throttl") || msg.includes("503")) {
        applyProviderBackoff(type);
      }
      return { alertsReceived: 0, alertsCreated: 0, alertsDeduped: 0, alertsFailed: 0, errors: [(err as Error).message], rawAlerts: [] };
    }

    const { normalized, failed, errors } = normalizeBatch(rawAlerts, plugin.normalize.bind(plugin), connector.orgId);

    return {
      alertsReceived: rawAlerts.length,
      alertsCreated: 0,
      alertsDeduped: 0,
      alertsFailed: failed,
      errors,
      rawAlerts: normalized,
    };
  } finally {
    releaseProviderSlot(type);
  }
}

function classifyError(errorMessage: string): { errorType: string; throttled: boolean; httpStatus: number | undefined } {
  const errorLower = errorMessage.toLowerCase();
  let errorType = "api_error";
  let throttled = false;
  let httpStatus: number | undefined;

  if (errorLower.includes("429") || errorLower.includes("503") ||
      errorLower.includes("rate limit") || errorLower.includes("throttl")) {
    errorType = "throttle";
    throttled = true;
    if (errorLower.includes("429")) httpStatus = 429;
    if (errorLower.includes("503")) httpStatus = 503;
  } else if (errorLower.includes("401") || errorLower.includes("403") ||
             errorLower.includes("unauthorized") || errorLower.includes("forbidden")) {
    errorType = "auth_error";
    if (errorLower.includes("401")) httpStatus = 401;
    if (errorLower.includes("403")) httpStatus = 403;
  } else if (errorLower.includes("timeout") || errorLower.includes("econnreset") ||
             errorLower.includes("econnrefused")) {
    errorType = "network_error";
  }

  return { errorType, throttled, httpStatus };
}

export interface SyncWithRetryResult {
  jobRun: ConnectorJobRun;
  syncResult: SyncResult;
}

export async function syncConnectorWithRetry(
  connector: Connector,
  maxAttempts: number = 3
): Promise<SyncWithRetryResult> {
  const startTime = Date.now();
  const fetchWindowStart = connector.lastSyncAt ?? undefined;
  const fetchWindowEnd = new Date();

  const jobRun = await storage.createConnectorJobRun({
    connectorId: connector.id,
    orgId: connector.orgId,
    status: "running",
    attempt: 1,
    maxAttempts,
    alertsReceived: 0,
    alertsCreated: 0,
    alertsDeduped: 0,
    alertsFailed: 0,
    fetchWindowStart: fetchWindowStart ?? null,
    fetchWindowEnd,
  });

  let currentAttempt = 1;
  let lastErrorMessage = "Unknown error";

  while (currentAttempt <= maxAttempts) {
    const syncResult = await syncConnector(connector);

    const isCompleteFail = syncResult.errors.length > 0 && syncResult.alertsReceived === 0;

    if (!isCompleteFail) {
      const latencyMs = Date.now() - startTime;
      const status = syncResult.errors.length > 0 ? "partial" : "success";

      const updatedJobRun = await storage.updateConnectorJobRun(jobRun.id, {
        status,
        attempt: currentAttempt,
        alertsReceived: syncResult.alertsReceived,
        alertsCreated: syncResult.alertsCreated,
        alertsDeduped: syncResult.alertsDeduped,
        alertsFailed: syncResult.alertsFailed,
        latencyMs,
        checkpointData: { alertsReceived: syncResult.alertsReceived, completedAt: new Date().toISOString() },
        checkpointAt: new Date(),
        completedAt: new Date(),
      });

      return { jobRun: updatedJobRun, syncResult };
    }

    lastErrorMessage = syncResult.errors[0] || "Unknown error";
    const { errorType, throttled, httpStatus } = classifyError(lastErrorMessage);

    if (currentAttempt >= maxAttempts) {
      const latencyMs = Date.now() - startTime;
      const updatedJobRun = await storage.updateConnectorJobRun(jobRun.id, {
        status: "failed",
        attempt: currentAttempt,
        latencyMs,
        errorMessage: lastErrorMessage,
        errorType,
        httpStatus,
        throttled,
        isDeadLetter: true,
        completedAt: new Date(),
      });

      return { jobRun: updatedJobRun, syncResult };
    }

    const backoffSeconds = Math.pow(2, currentAttempt);
    const nextRetryAt = new Date(Date.now() + backoffSeconds * 1000);
    logger.child("connector-engine").warn("Sync failed on attempt " + currentAttempt + "/" + maxAttempts, {
      connectorId: connector.id, errorType, backoffSeconds, error: lastErrorMessage,
    });

    await storage.updateConnectorJobRun(jobRun.id, {
      attempt: currentAttempt + 1,
      errorMessage: lastErrorMessage,
      errorType,
      httpStatus,
      throttled,
      backoffSeconds,
      nextRetryAt,
      retryStrategy: "exponential",
    });

    await new Promise((resolve) => setTimeout(resolve, backoffSeconds * 1000));

    currentAttempt++;
  }

  const latencyMs = Date.now() - startTime;
  const finalJobRun = await storage.updateConnectorJobRun(jobRun.id, {
    status: "failed",
    attempt: currentAttempt - 1,
    latencyMs,
    errorMessage: lastErrorMessage,
    errorType: "api_error",
    isDeadLetter: true,
    completedAt: new Date(),
  });

  return {
    jobRun: finalJobRun,
    syncResult: { alertsReceived: 0, alertsCreated: 0, alertsDeduped: 0, alertsFailed: 0, errors: [lastErrorMessage], rawAlerts: [] },
  };
}

export async function syncConnectorsBatch(
  connectors: Connector[],
  maxConcurrency: number = DEFAULT_MAX_CONCURRENCY,
): Promise<ConnectorJobRun[]> {
  const results: ConnectorJobRun[] = [];
  let idx = 0;

  async function worker(): Promise<void> {
    while (idx < connectors.length) {
      const connector = connectors[idx++];
      if (!connector) break;
      try {
        const { jobRun } = await syncConnectorWithRetry(connector);
        results.push(jobRun);
      } catch (err: unknown) {
        logger.child("connector-engine").error("Batch sync failed for connector " + connector.id, { error: (err as Error).message });
      }
    }
  }

  const workers = Array.from({ length: Math.min(maxConcurrency, connectors.length) }, () => worker());
  await Promise.all(workers);
  return results;
}

export function getConnectorMetadata(type: string): {
  name: string;
  description: string;
  authType: string;
  requiredFields: { key: string; label: string; type: string; placeholder: string }[];
  optionalFields: { key: string; label: string; type: string; placeholder: string }[];
  icon: string;
  docsUrl: string;
} | null {
  return registryGetMetadata(type);
}

export function getAllConnectorTypes(): string[] {
  return getAllPluginTypes();
}

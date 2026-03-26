import { logger } from "./logger";
import { storage } from "./storage";
import { isCircuitOpen, recordConnectorSuccess, recordConnectorFailure } from "./connector-circuit-breaker";
import { getPlugin } from "./connectors/connector-plugin";
import type { ConnectorConfig } from "./connectors/connector-plugin";
import type { Connector } from "@shared/schema";

const log = logger.child("connector-health-loop");

const HEALTH_CHECK_INTERVAL_MS = 60_000; // 60 seconds
const CONSECUTIVE_FAILURE_THRESHOLD = 3; // auto-restart after 3 failures
const BACKOFF_BASE_MS = 30_000; // 30s base
const BACKOFF_MAX_MS = 300_000; // 5 min max

interface ConnectorHealthState {
  connectorId: string;
  status: "healthy" | "degraded" | "failed" | "circuit_open";
  consecutiveFailures: number;
  lastCheckAt: number;
  lastSuccessAt: number;
  latencyMs: number;
  restartCount: number;
  nextRestartAt: number; // 0 if not in restart backoff
}

const healthStates = new Map<string, ConnectorHealthState>();
let loopInterval: ReturnType<typeof setInterval> | null = null;

function getOrCreateState(connectorId: string): ConnectorHealthState {
  let state = healthStates.get(connectorId);
  if (!state) {
    state = {
      connectorId,
      status: "healthy",
      consecutiveFailures: 0,
      lastCheckAt: 0,
      lastSuccessAt: 0,
      latencyMs: 0,
      restartCount: 0,
      nextRestartAt: 0,
    };
    healthStates.set(connectorId, state);
  }
  return state;
}

export async function runHealthChecks(): Promise<void> {
  let allConnectors: Connector[];
  try {
    allConnectors = await storage.getConnectors();
  } catch (err: unknown) {
    log.error("Failed to fetch connectors for health check", { error: (err as Error).message });
    return;
  }

  const activeConnectors = allConnectors.filter((c) => c.status !== "inactive");

  for (const connector of activeConnectors) {
    const state = getOrCreateState(connector.id);
    const now = Date.now();

    // Check circuit breaker
    if (isCircuitOpen(connector.id)) {
      state.status = "circuit_open";
      state.lastCheckAt = now;
      log.debug("Skipping health check - circuit open", { connectorId: connector.id });
      continue;
    }

    // Check restart backoff
    if (state.nextRestartAt > now) {
      log.debug("Skipping health check - in restart backoff", {
        connectorId: connector.id,
        nextRestartAt: new Date(state.nextRestartAt).toISOString(),
      });
      continue;
    }

    const plugin = getPlugin(connector.type);
    if (!plugin) {
      log.warn("No plugin found for connector type", { connectorId: connector.id, type: connector.type });
      continue;
    }

    try {
      const result = await plugin.test(connector.config as ConnectorConfig);
      state.lastCheckAt = now;

      if (result.success) {
        recordConnectorSuccess(connector.id);
        state.status = "healthy";
        state.consecutiveFailures = 0;
        state.restartCount = 0;
        state.nextRestartAt = 0;
        state.lastSuccessAt = now;
        state.latencyMs = result.latencyMs;

        try {
          await storage.createConnectorHealthCheck({
            connectorId: connector.id,
            orgId: connector.orgId,
            status: "healthy",
            latencyMs: result.latencyMs,
            credentialStatus: "valid",
          });
        } catch (dbErr: unknown) {
          log.warn("Failed to persist health check result", {
            connectorId: connector.id,
            error: (dbErr as Error).message,
          });
        }
      } else {
        handleFailure(connector, state, result.message, result.latencyMs);
      }
    } catch (err: unknown) {
      handleFailure(connector, state, (err as Error).message, 0);
    }
  }
}

function handleFailure(connector: Connector, state: ConnectorHealthState, errorMessage: string, latencyMs: number): void {
  const now = Date.now();
  recordConnectorFailure(connector.id);
  state.consecutiveFailures++;
  state.lastCheckAt = now;
  state.latencyMs = latencyMs;

  const isFailed = state.consecutiveFailures >= CONSECUTIVE_FAILURE_THRESHOLD;
  state.status = isFailed ? "failed" : "degraded";

  storage.createConnectorHealthCheck({
    connectorId: connector.id,
    orgId: connector.orgId,
    status: state.status,
    latencyMs,
    errorMessage,
    credentialStatus: "unknown",
  }).catch((dbErr: unknown) => {
    log.warn("Failed to persist health check failure", {
      connectorId: connector.id,
      error: (dbErr as Error).message,
    });
  });

  if (isFailed) {
    const backoff = Math.min(BACKOFF_BASE_MS * Math.pow(2, state.restartCount), BACKOFF_MAX_MS);
    state.nextRestartAt = now + backoff;
    state.restartCount++;

    log.warn("Auto-restart scheduled with backoff", {
      connectorId: connector.id,
      consecutiveFailures: state.consecutiveFailures,
      backoffMs: backoff,
      restartCount: state.restartCount,
      nextRestartAt: new Date(state.nextRestartAt).toISOString(),
    });

    storage.updateConnector(connector.id, {
      status: "error",
      lastSyncError: "Auto-restart: " + state.consecutiveFailures + " consecutive health check failures",
    } as Partial<Connector>).catch((dbErr: unknown) => {
      log.warn("Failed to update connector status to error", {
        connectorId: connector.id,
        error: (dbErr as Error).message,
      });
    });

    // Reset consecutive failures after scheduling restart
    state.consecutiveFailures = 0;
  }
}

export function startConnectorHealthLoop(): void {
  if (loopInterval) return;

  log.info("Starting connector health check loop", { intervalMs: HEALTH_CHECK_INTERVAL_MS });
  runHealthChecks();
  loopInterval = setInterval(runHealthChecks, HEALTH_CHECK_INTERVAL_MS);
}

export function stopConnectorHealthLoop(): void {
  if (loopInterval) {
    clearInterval(loopInterval);
    loopInterval = null;
    log.info("Stopped connector health check loop");
  }
}

export function resetConnectorHealthStates(): void {
  healthStates.clear();
}

export function getConnectorHealthStatus(): Map<string, ConnectorHealthState> {
  const clone = new Map<string, ConnectorHealthState>();
  for (const [key, value] of healthStates) {
    clone.set(key, { ...value });
  }
  return clone;
}

import { logger } from "./logger";

const log = logger.child("connector-circuit-breaker");

const FAILURE_THRESHOLD = 5; // open after 5 failures
const FAILURE_WINDOW_MS = 60_000; // within 60 seconds
const HALF_OPEN_AFTER_MS = 30_000; // half-open after 30s

export interface ConnectorCircuitState {
  connectorId: string;
  state: "closed" | "open" | "half-open";
  failures: number;
  failureTimestamps: number[]; // timestamps of recent failures within window
  openUntil: number; // 0 when closed
  lastFailure: number; // 0 when no failures
}

const circuits = new Map<string, ConnectorCircuitState>();

function getOrCreate(connectorId: string): ConnectorCircuitState {
  let state = circuits.get(connectorId);
  if (!state) {
    state = {
      connectorId,
      state: "closed",
      failures: 0,
      failureTimestamps: [],
      openUntil: 0,
      lastFailure: 0,
    };
    circuits.set(connectorId, state);
  }
  return state;
}

function pruneOldFailures(state: ConnectorCircuitState): void {
  const cutoff = Date.now() - FAILURE_WINDOW_MS;
  state.failureTimestamps = state.failureTimestamps.filter((ts) => ts > cutoff);
  state.failures = state.failureTimestamps.length;
}

export function recordConnectorFailure(connectorId: string): ConnectorCircuitState {
  const state = getOrCreate(connectorId);
  const now = Date.now();

  state.failureTimestamps.push(now);
  state.lastFailure = now;

  pruneOldFailures(state);

  if (state.failures >= FAILURE_THRESHOLD) {
    const wasOpen = state.state === "open";
    state.state = "open";
    state.openUntil = now + HALF_OPEN_AFTER_MS;
    if (!wasOpen) {
      log.warn("Circuit breaker opened", {
        connectorId,
        failures: state.failures,
        openUntil: new Date(state.openUntil).toISOString(),
      });
    }
  }

  // Re-open from half-open on failure
  if (state.state === "half-open") {
    state.state = "open";
    state.openUntil = now + HALF_OPEN_AFTER_MS;
    log.warn("Circuit breaker re-opened from half-open", {
      connectorId,
      failures: state.failures,
    });
  }

  return { ...state, failureTimestamps: [...state.failureTimestamps] };
}

export function recordConnectorSuccess(connectorId: string): ConnectorCircuitState {
  const state = getOrCreate(connectorId);
  const previousState = state.state;

  state.failures = 0;
  state.failureTimestamps = [];
  state.state = "closed";
  state.openUntil = 0;

  if (previousState !== "closed") {
    log.info("Circuit breaker closed", { connectorId, previousState });
  }

  return { ...state, failureTimestamps: [] };
}

export function isCircuitOpen(connectorId: string): boolean {
  const state = circuits.get(connectorId);
  if (!state) return false;

  if (state.state === "open") {
    if (Date.now() >= state.openUntil) {
      // Transition to half-open
      state.state = "half-open";
      log.info("Circuit breaker half-open, allowing probe request", { connectorId });
      return false;
    }
    return true;
  }

  return false;
}

export function getCircuitBreakerState(connectorId: string): ConnectorCircuitState {
  const state = getOrCreate(connectorId);
  return { ...state, failureTimestamps: [...state.failureTimestamps] };
}

export function getAllCircuitBreakerStates(): Map<string, ConnectorCircuitState> {
  return circuits;
}

export function resetConnectorCircuitBreaker(connectorId: string): void {
  circuits.delete(connectorId);
}

import { logger } from "./logger";

const log = logger.child("outbound-security");

const INTERNAL_CIDR_PATTERNS = [
  /^127\./,
  /^10\./,
  /^192\.168\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^169\.254\./,
  /^0\./,
  /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./,
];

const INTERNAL_HOSTNAMES = new Set([
  "localhost",
  "0.0.0.0",
  "127.0.0.1",
  "[::1]",
  "::1",
  "metadata.google.internal",
  "metadata.internal",
  "kubernetes.default",
  "kubernetes.default.svc",
  "kubernetes.default.svc.cluster.local",
]);

const BLOCKED_SCHEMES = new Set(["file:", "ftp:", "gopher:", "data:", "javascript:"]);

const CLOUD_METADATA_IPS = new Set(["169.254.169.254", "fd00:ec2::254"]);

export interface WebhookUrlValidationResult {
  valid: boolean;
  reason?: string;
}

export function validateWebhookUrl(url: string): WebhookUrlValidationResult {
  if (!url || typeof url !== "string") {
    return { valid: false, reason: "URL is required" };
  }

  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return { valid: false, reason: "Invalid URL format" };
  }

  if (BLOCKED_SCHEMES.has(parsed.protocol)) {
    return { valid: false, reason: `Scheme '${parsed.protocol}' is not allowed` };
  }

  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    return { valid: false, reason: "Only http: and https: schemes are allowed" };
  }

  const hostname = parsed.hostname.toLowerCase();

  if (INTERNAL_HOSTNAMES.has(hostname)) {
    return { valid: false, reason: "Internal/loopback hostnames are not allowed" };
  }

  if (CLOUD_METADATA_IPS.has(hostname)) {
    return { valid: false, reason: "Cloud metadata endpoints are not allowed" };
  }

  for (const pattern of INTERNAL_CIDR_PATTERNS) {
    if (pattern.test(hostname)) {
      return { valid: false, reason: "Private/internal IP addresses are not allowed" };
    }
  }

  if (hostname.startsWith("fc") || hostname.startsWith("fd") || hostname.startsWith("fe80")) {
    return { valid: false, reason: "IPv6 link-local and private addresses are not allowed" };
  }

  if (parsed.username || parsed.password) {
    return { valid: false, reason: "Credentials in URL are not allowed" };
  }

  if (hostname.endsWith(".local") || hostname.endsWith(".internal") || hostname.endsWith(".localhost")) {
    return { valid: false, reason: "Local/internal TLDs are not allowed" };
  }

  return { valid: true };
}

interface CircuitState {
  failures: number;
  lastFailure: number;
  state: "closed" | "open" | "half-open";
  openedAt: number;
}

const CIRCUIT_FAILURE_THRESHOLD = 5;
const CIRCUIT_RESET_TIMEOUT_MS = 60_000;
const circuitBreakers = new Map<string, CircuitState>();

export function getCircuitState(webhookId: string): CircuitState {
  let circuit = circuitBreakers.get(webhookId);
  if (!circuit) {
    circuit = { failures: 0, lastFailure: 0, state: "closed", openedAt: 0 };
    circuitBreakers.set(webhookId, circuit);
  }

  if (circuit.state === "open" && Date.now() - circuit.openedAt >= CIRCUIT_RESET_TIMEOUT_MS) {
    circuit.state = "half-open";
    log.info("Circuit breaker half-open", { webhookId });
  }

  return circuit;
}

export function isCircuitOpen(webhookId: string): boolean {
  const circuit = getCircuitState(webhookId);
  return circuit.state === "open";
}

export function recordDeliverySuccess(webhookId: string): void {
  const circuit = getCircuitState(webhookId);
  if (circuit.state === "half-open") {
    log.info("Circuit breaker closed after successful delivery", { webhookId });
  }
  circuit.failures = 0;
  circuit.state = "closed";
  circuit.openedAt = 0;
}

export function recordDeliveryFailure(webhookId: string): void {
  const circuit = getCircuitState(webhookId);
  circuit.failures++;
  circuit.lastFailure = Date.now();

  if (circuit.failures >= CIRCUIT_FAILURE_THRESHOLD) {
    circuit.state = "open";
    circuit.openedAt = Date.now();
    log.warn("Circuit breaker opened — halting deliveries", {
      webhookId,
      consecutiveFailures: circuit.failures,
    });
  }
}

export function getCircuitBreakerStatus(webhookId: string): {
  state: string;
  failures: number;
  lastFailure: number;
} {
  const circuit = getCircuitState(webhookId);
  return {
    state: circuit.state,
    failures: circuit.failures,
    lastFailure: circuit.lastFailure,
  };
}

interface RateBucket {
  count: number;
  windowStart: number;
}

const WEBHOOK_RATE_LIMIT = 100;
const WEBHOOK_RATE_WINDOW_MS = 60_000;
const rateBuckets = new Map<string, RateBucket>();

export function isWebhookRateLimited(webhookId: string): boolean {
  const now = Date.now();
  let bucket = rateBuckets.get(webhookId);

  if (!bucket || now - bucket.windowStart >= WEBHOOK_RATE_WINDOW_MS) {
    bucket = { count: 0, windowStart: now };
    rateBuckets.set(webhookId, bucket);
  }

  if (bucket.count >= WEBHOOK_RATE_LIMIT) {
    log.warn("Webhook rate limited", { webhookId, count: bucket.count });
    return true;
  }

  bucket.count++;
  return false;
}

export const OUTBOUND_TIMEOUT_MS = 10_000;
export const OUTBOUND_MAX_RETRIES = 3;
export const OUTBOUND_MAX_RESPONSE_BYTES = 64 * 1024;

export function redactDeliveryLog(payload: unknown): unknown {
  if (payload === null || payload === undefined) return payload;
  if (typeof payload === "string") return redactString(payload);
  if (typeof payload !== "object") return payload as unknown;
  if (Array.isArray(payload)) return payload.map(redactDeliveryLog);

  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(payload as Record<string, unknown>)) {
    const lowerKey = key.toLowerCase();
    if (
      lowerKey.includes("password") ||
      lowerKey.includes("secret") ||
      lowerKey.includes("token") ||
      lowerKey.includes("apikey") ||
      lowerKey.includes("api_key") ||
      lowerKey.includes("authorization") ||
      lowerKey.includes("credential") ||
      lowerKey.includes("private_key") ||
      lowerKey.includes("privatekey")
    ) {
      result[key] = "[REDACTED]";
    } else {
      result[key] = redactDeliveryLog(value);
    }
  }
  return result;
}

function redactString(input: string): string {
  return input
    .replace(/Bearer\s+[A-Za-z0-9\-._~+/]+=*/g, "Bearer [REDACTED]")
    .replace(/snx_[a-f0-9]{64}/g, "snx_[REDACTED]")
    .replace(/ghp_[A-Za-z0-9]{36}/g, "ghp_[REDACTED]")
    .replace(/AKIA[A-Z0-9]{16}/g, "AKIA[REDACTED]");
}

export async function secureOutboundFetch(
  url: string,
  options: {
    method: string;
    headers: Record<string, string>;
    body: string;
    timeoutMs?: number;
  },
): Promise<{ statusCode: number; responseBody: string; success: boolean; error?: string }> {
  const validation = validateWebhookUrl(url);
  if (!validation.valid) {
    return {
      statusCode: 0,
      responseBody: "",
      success: false,
      error: `SSRF blocked: ${validation.reason}`,
    };
  }

  const timeoutMs = options.timeoutMs || OUTBOUND_TIMEOUT_MS;

  try {
    const resp = await fetch(url, {
      method: options.method,
      headers: options.headers,
      body: options.body,
      signal: AbortSignal.timeout(timeoutMs),
      redirect: "error",
    });

    const responseBody = await resp.text().catch(() => "");
    const truncated = responseBody.slice(0, OUTBOUND_MAX_RESPONSE_BYTES);

    return {
      statusCode: resp.status,
      responseBody: truncated,
      success: resp.ok,
    };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      statusCode: 0,
      responseBody: "",
      success: false,
      error: message,
    };
  }
}

export function resetCircuitBreaker(webhookId: string): void {
  circuitBreakers.delete(webhookId);
}

export function getOutboundSecurityStats(): {
  activeCircuitBreakers: number;
  openCircuits: string[];
  rateLimitedWebhooks: number;
} {
  const openCircuits: string[] = [];
  circuitBreakers.forEach((circuit, id) => {
    if (circuit.state === "open") {
      openCircuits.push(id);
    }
  });

  let rateLimitedCount = 0;
  const now = Date.now();
  rateBuckets.forEach((bucket) => {
    if (now - bucket.windowStart < WEBHOOK_RATE_WINDOW_MS && bucket.count >= WEBHOOK_RATE_LIMIT) {
      rateLimitedCount++;
    }
  });

  return {
    activeCircuitBreakers: circuitBreakers.size,
    openCircuits,
    rateLimitedWebhooks: rateLimitedCount,
  };
}

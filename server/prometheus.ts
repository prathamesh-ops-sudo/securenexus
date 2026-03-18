import type { Request, Response, NextFunction } from "express";

/**
 * Lightweight Prometheus-compatible metrics collector.
 *
 * Exposes an `/api/ops/metrics` endpoint in Prometheus text exposition format
 * so that the existing K8s Prometheus scrape config can collect real HTTP
 * request metrics (counters + histograms) from the application.
 *
 * No external dependencies — avoids adding prom-client to keep the bundle lean.
 */

// ─── Histogram bucket boundaries (seconds) ──────────────────────────────────
const HISTOGRAM_BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10];

// ─── In-memory counters ──────────────────────────────────────────────────────

interface RouteMetrics {
  count: number;
  statusCounts: Map<string, number>; // "2xx" | "3xx" | "4xx" | "5xx"
  bucketCounts: number[]; // one per HISTOGRAM_BUCKETS entry
  sum: number; // total duration in seconds
}

const routeMetrics = new Map<string, RouteMetrics>();

function getOrCreate(key: string): RouteMetrics {
  let m = routeMetrics.get(key);
  if (!m) {
    m = {
      count: 0,
      statusCounts: new Map(),
      bucketCounts: new Array(HISTOGRAM_BUCKETS.length).fill(0),
      sum: 0,
    };
    routeMetrics.set(key, m);
  }
  return m;
}

// ─── Middleware ───────────────────────────────────────────────────────────────

export function prometheusMiddleware(req: Request, res: Response, next: NextFunction): void {
  const start = process.hrtime.bigint();

  res.on("finish", () => {
    const durationNs = Number(process.hrtime.bigint() - start);
    const durationSec = durationNs / 1e9;

    // Derive a stable route key so we don't explode cardinality with path params
    const routePath = req.route && typeof req.route.path === "string" ? req.route.path : undefined;
    const baseUrl = typeof req.baseUrl === "string" ? req.baseUrl : "";
    const path = routePath ? `${baseUrl}${routePath}` : req.path;
    const method = req.method;
    const key = `${method}:${path}`;

    const m = getOrCreate(key);
    m.count++;
    m.sum += durationSec;

    const statusClass = `${Math.floor(res.statusCode / 100)}xx`;
    m.statusCounts.set(statusClass, (m.statusCounts.get(statusClass) ?? 0) + 1);

    for (let i = 0; i < HISTOGRAM_BUCKETS.length; i++) {
      if (durationSec <= HISTOGRAM_BUCKETS[i]) {
        m.bucketCounts[i]++;
      }
    }
  });

  next();
}

// ─── Exposition ──────────────────────────────────────────────────────────────

export function renderMetrics(): string {
  const lines: string[] = [];
  const now = Date.now();

  // Process-level gauges
  const mem = process.memoryUsage();
  const cpuUsage = process.cpuUsage();

  lines.push("# HELP process_resident_memory_bytes Resident memory size in bytes.");
  lines.push("# TYPE process_resident_memory_bytes gauge");
  lines.push(`process_resident_memory_bytes ${mem.rss} ${now}`);

  lines.push("# HELP process_heap_bytes Node.js heap usage in bytes.");
  lines.push("# TYPE process_heap_bytes gauge");
  lines.push(`process_heap_bytes{type="used"} ${mem.heapUsed} ${now}`);
  lines.push(`process_heap_bytes{type="total"} ${mem.heapTotal} ${now}`);

  lines.push("# HELP process_cpu_seconds_total Total user and system CPU time spent.");
  lines.push("# TYPE process_cpu_seconds_total counter");
  lines.push(`process_cpu_seconds_total{type="user"} ${(cpuUsage.user / 1e6).toFixed(3)} ${now}`);
  lines.push(`process_cpu_seconds_total{type="system"} ${(cpuUsage.system / 1e6).toFixed(3)} ${now}`);

  lines.push("# HELP nodejs_active_handles_total Number of active libuv handles.");
  lines.push("# TYPE nodejs_active_handles_total gauge");
  const activeHandles =
    typeof (process as NodeJS.Process & { _getActiveHandles?: () => unknown[] })._getActiveHandles === "function"
      ? (process as NodeJS.Process & { _getActiveHandles: () => unknown[] })._getActiveHandles().length
      : 0;
  lines.push(`nodejs_active_handles_total ${activeHandles} ${now}`);

  lines.push("# HELP process_uptime_seconds Process uptime in seconds.");
  lines.push("# TYPE process_uptime_seconds gauge");
  lines.push(`process_uptime_seconds ${Math.floor(process.uptime())} ${now}`);

  // HTTP request metrics
  lines.push("# HELP http_requests_total Total number of HTTP requests.");
  lines.push("# TYPE http_requests_total counter");

  lines.push("# HELP http_request_duration_seconds HTTP request latency histogram.");
  lines.push("# TYPE http_request_duration_seconds histogram");

  for (const [key, m] of Array.from(routeMetrics.entries())) {
    const colonIdx = key.indexOf(":");
    const method = key.substring(0, colonIdx);
    const path = key.substring(colonIdx + 1);
    const labelBase = `method="${method}",path="${path}"`;

    // Request counters by status class
    for (const [statusClass, count] of Array.from(m.statusCounts.entries())) {
      lines.push(`http_requests_total{${labelBase},status="${statusClass}"} ${count}`);
    }

    // Histogram buckets
    let cumulative = 0;
    for (let i = 0; i < HISTOGRAM_BUCKETS.length; i++) {
      cumulative += m.bucketCounts[i];
      lines.push(`http_request_duration_seconds_bucket{${labelBase},le="${HISTOGRAM_BUCKETS[i]}"} ${cumulative}`);
    }
    lines.push(`http_request_duration_seconds_bucket{${labelBase},le="+Inf"} ${m.count}`);
    lines.push(`http_request_duration_seconds_sum{${labelBase}} ${m.sum.toFixed(6)}`);
    lines.push(`http_request_duration_seconds_count{${labelBase}} ${m.count}`);
  }

  return lines.join("\n") + "\n";
}

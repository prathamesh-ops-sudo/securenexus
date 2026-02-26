import { storage } from "./storage";
import { logger } from "./logger";

interface MetricBucket {
  latencies: number[];
  errors: number;
  total: number;
}

const buckets: Map<string, MetricBucket> = new Map();
const FLUSH_INTERVAL_MS = 60000; // Flush every 60 seconds
let flushTimer: NodeJS.Timeout | null = null;

function getServiceFromPath(path: string): string {
  if (path.startsWith("/api/alerts") || path.startsWith("/api/ingest")) return "ingestion";
  if (path.startsWith("/api/ai") || path.includes("/analyze") || path.includes("/narrative")) return "ai";
  if (path.startsWith("/api/connectors")) return "connector";
  if (path.startsWith("/api/threat-intel") || path.includes("/enrich")) return "enrichment";
  return "api";
}

export function sliMiddleware(req: any, res: any, next: any): void {
  const start = Date.now();

  res.on("finish", () => {
    const latency = Date.now() - start;

    const routePath = (req.route && typeof req.route.path === "string") ? req.route.path : undefined;
    const baseUrl = typeof req.baseUrl === "string" ? req.baseUrl : "";
    const endpoint = routePath ? `${baseUrl}${routePath}` : req.path;

    const service = getServiceFromPath(endpoint);
    const key = `${service}::${req.method}::${endpoint}`;

    if (!buckets.has(key)) {
      buckets.set(key, { latencies: [], errors: 0, total: 0 });
    }
    const bucket = buckets.get(key)!;
    bucket.latencies.push(latency);
    bucket.total++;
    if (res.statusCode >= 500) bucket.errors++;
  });

  const originalEnd = res.end;
  res.end = function(...args: any[]) {
    return originalEnd.apply(this, args);
  };
  
  next();
}

function percentile(arr: number[], p: number): number {
  if (arr.length === 0) return 0;
  const sorted = [...arr].sort((a, b) => a - b);
  const idx = Math.ceil((p / 100) * sorted.length) - 1;
  return sorted[Math.max(0, idx)];
}

async function flushMetrics(): Promise<void> {
  const now = new Date();
  const entries: Array<{ service: string; metric: string; value: number; labels: any }> = [];
  
  for (const [key, bucket] of Array.from(buckets.entries())) {
    if (bucket.total === 0) continue;
    const [service, method, endpoint] = key.split("::");
    const labels = { method, endpoint };
    
    entries.push({ service, metric: "latency_p50", value: percentile(bucket.latencies, 50), labels });
    entries.push({ service, metric: "latency_p95", value: percentile(bucket.latencies, 95), labels });
    entries.push({ service, metric: "latency_p99", value: percentile(bucket.latencies, 99), labels });
    entries.push({ service, metric: "error_rate", value: bucket.total > 0 ? (bucket.errors / bucket.total) * 100 : 0, labels });
    entries.push({ service, metric: "throughput", value: bucket.total, labels });
    entries.push({ service, metric: "availability", value: bucket.total > 0 ? ((bucket.total - bucket.errors) / bucket.total) * 100 : 100, labels });
  }
  
  // Clear buckets
  buckets.clear();
  
  if (entries.length === 0) return;
  
  try {
    await storage.createSliMetricsBatch(entries.map(e => ({
      service: e.service,
      metric: e.metric,
      value: e.value,
      labels: e.labels,
      recordedAt: now,
    })));
  } catch (err) {
    logger.child("sli-middleware").error("Failed to flush metrics:", { error: String(err) });
  }
}

export function startSliCollection(): void {
  if (flushTimer) return;
  flushTimer = setInterval(() => {
    flushMetrics().catch(err => logger.child("sli-middleware").error("Flush error:", { error: String(err) }));
  }, FLUSH_INTERVAL_MS);
  logger.child("sli-middleware").info("Metrics collection started - flushing every 60s");
}

export function stopSliCollection(): void {
  if (flushTimer) {
    clearInterval(flushTimer);
    flushTimer = null;
  }
}

export async function evaluateSlos(): Promise<Array<{
  sloId: string;
  service: string;
  metric: string;
  endpoint: string;
  target: number;
  actual: number;
  breached: boolean;
  description: string | null;
}>> {
  const targets = await storage.getSloTargets();
  const results: Array<{
    sloId: string;
    service: string;
    metric: string;
    endpoint: string;
    target: number;
    actual: number;
    breached: boolean;
    description: string | null;
  }> = [];
  
  const now = new Date();
  
  for (const slo of targets) {
    const windowStart = new Date(now.getTime() - slo.windowMinutes * 60 * 1000);
    const metrics = await storage.getSliMetrics(
      slo.service,
      slo.metric,
      windowStart,
      now,
      slo.endpoint && slo.endpoint !== "*" ? { endpoint: slo.endpoint } : undefined,
    );
    
    if (metrics.length === 0) {
      results.push({
        sloId: slo.id,
        service: slo.service,
        metric: slo.metric,
        endpoint: slo.endpoint,
        target: slo.target,
        actual: -1,
        breached: false,
        description: slo.description,
      });
      continue;
    }
    
    const avg = metrics.reduce((sum, m) => sum + m.value, 0) / metrics.length;
    const breached = slo.operator === "gte" ? avg < slo.target : avg > slo.target;
    
    results.push({
      sloId: slo.id,
      service: slo.service,
      metric: slo.metric,
      endpoint: slo.endpoint,
      target: slo.target,
      actual: Math.round(avg * 100) / 100,
      breached,
      description: slo.description,
    });
  }
  
  return results;
}

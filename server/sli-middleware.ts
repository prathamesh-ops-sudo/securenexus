import { storage } from "./storage";

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
  const originalEnd = res.end;
  
  res.end = function(...args: any[]) {
    const latency = Date.now() - start;
    const service = getServiceFromPath(req.path);
    const key = `${service}:${req.method}`;
    
    if (!buckets.has(key)) {
      buckets.set(key, { latencies: [], errors: 0, total: 0 });
    }
    const bucket = buckets.get(key)!;
    bucket.latencies.push(latency);
    bucket.total++;
    if (res.statusCode >= 500) bucket.errors++;
    
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
    const [service, method] = key.split(":");
    const labels = { method };
    
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
    console.error("[SLI] Failed to flush metrics:", err);
  }
}

export function startSliCollection(): void {
  if (flushTimer) return;
  flushTimer = setInterval(() => {
    flushMetrics().catch(err => console.error("[SLI] Flush error:", err));
  }, FLUSH_INTERVAL_MS);
  console.log("[SLI] Metrics collection started - flushing every 60s");
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
    target: number;
    actual: number;
    breached: boolean;
    description: string | null;
  }> = [];
  
  const now = new Date();
  
  for (const slo of targets) {
    const windowStart = new Date(now.getTime() - slo.windowMinutes * 60 * 1000);
    const metrics = await storage.getSliMetrics(slo.service, slo.metric, windowStart, now);
    
    if (metrics.length === 0) {
      results.push({
        sloId: slo.id,
        service: slo.service,
        metric: slo.metric,
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
      target: slo.target,
      actual: Math.round(avg * 100) / 100,
      breached,
      description: slo.description,
    });
  }
  
  return results;
}

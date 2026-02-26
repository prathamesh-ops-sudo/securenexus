import { pool } from "./db";
import { logger } from "./logger";

const log = logger.child("db-performance");

const SLOW_QUERY_THRESHOLD_MS = 200;

export const PERFORMANCE_BUDGETS: Record<
  string,
  { staging: number; production: number }
> = {
  "GET /api/v1/alerts": { staging: 800, production: 500 },
  "GET /api/v1/incidents": { staging: 1000, production: 800 },
  "GET /api/v1/audit-logs": { staging: 600, production: 400 },
  "GET /api/v1/connectors": { staging: 500, production: 300 },
  "GET /api/v1/ingestion/logs": { staging: 600, production: 400 },
  "GET /api/v1/webhooks/:id/logs": { staging: 500, production: 300 },
  "GET /api/v1/outbox/events": { staging: 500, production: 300 },
  "GET /api/entities": { staging: 800, production: 500 },
  "GET /api/alerts": { staging: 800, production: 500 },
  "GET /api/incidents": { staging: 1000, production: 800 },
  "GET /api/connectors": { staging: 500, production: 300 },
  "GET /api/ingestion/logs": { staging: 600, production: 400 },
  "GET /api/audit-logs": { staging: 600, production: 400 },
  "GET /api/alerts/archive": { staging: 800, production: 500 },
  "GET /api/dashboard/stats": { staging: 1000, production: 600 },
  "GET /api/dashboard/analytics": { staging: 1500, production: 1000 },
  "POST /api/ingest/:source": { staging: 2000, production: 1500 },
  "POST /api/v1/ingest/bulk": { staging: 3000, production: 2000 },
};

const PAGINATION_DEFAULTS = {
  defaultLimit: 50,
  maxLimit: 500,
  defaultSortColumn: "createdAt",
  defaultSortOrder: "desc" as const,
};

export function parsePaginationParams(query: Record<string, unknown>): {
  offset: number;
  limit: number;
  sortOrder: "asc" | "desc";
} {
  const offset = Math.max(0, Number(query.offset ?? 0) || 0);
  const rawLimit = Number(query.limit ?? PAGINATION_DEFAULTS.defaultLimit) || PAGINATION_DEFAULTS.defaultLimit;
  const limit = Math.min(Math.max(1, rawLimit), PAGINATION_DEFAULTS.maxLimit);
  const sortOrder = query.sortOrder === "asc" ? "asc" as const : PAGINATION_DEFAULTS.defaultSortOrder;
  return { offset, limit, sortOrder };
}

interface SlowQueryEntry {
  query: string;
  durationMs: number;
  timestamp: Date;
}

const recentSlowQueries: SlowQueryEntry[] = [];
const MAX_SLOW_QUERY_LOG = 100;

export function recordSlowQuery(query: string, durationMs: number): void {
  if (durationMs < SLOW_QUERY_THRESHOLD_MS) return;
  log.warn("Slow query detected", {
    durationMs,
    query: query.slice(0, 200),
  });
  recentSlowQueries.push({ query: query.slice(0, 500), durationMs, timestamp: new Date() });
  if (recentSlowQueries.length > MAX_SLOW_QUERY_LOG) {
    recentSlowQueries.shift();
  }
}

export function getRecentSlowQueries(): SlowQueryEntry[] {
  return [...recentSlowQueries];
}

interface IndexHitRate {
  schemaname: string;
  relname: string;
  indexrelname: string;
  idx_scan: number;
  idx_tup_read: number;
  idx_tup_fetch: number;
}

export async function getIndexHitRates(): Promise<IndexHitRate[]> {
  try {
    const result = await pool.query(`
      SELECT
        schemaname,
        relname,
        indexrelname,
        idx_scan::bigint AS idx_scan,
        idx_tup_read::bigint AS idx_tup_read,
        idx_tup_fetch::bigint AS idx_tup_fetch
      FROM pg_stat_user_indexes
      WHERE schemaname = 'public'
      ORDER BY idx_scan DESC
      LIMIT 100
    `);
    return result.rows;
  } catch (err) {
    log.error("Failed to fetch index hit rates", { error: String(err) });
    return [];
  }
}

interface TableScanStats {
  relname: string;
  seq_scan: number;
  seq_tup_read: number;
  idx_scan: number;
  idx_tup_fetch: number;
  n_live_tup: number;
  cache_hit_ratio: string;
}

export async function getTableScanStats(): Promise<TableScanStats[]> {
  try {
    const result = await pool.query(`
      SELECT
        relname,
        seq_scan::bigint AS seq_scan,
        seq_tup_read::bigint AS seq_tup_read,
        idx_scan::bigint AS idx_scan,
        idx_tup_fetch::bigint AS idx_tup_fetch,
        n_live_tup::bigint AS n_live_tup,
        CASE
          WHEN (seq_scan + idx_scan) > 0
          THEN ROUND(100.0 * idx_scan / (seq_scan + idx_scan), 2)::text || '%'
          ELSE 'N/A'
        END AS cache_hit_ratio
      FROM pg_stat_user_tables
      WHERE schemaname = 'public'
      ORDER BY seq_scan DESC
      LIMIT 50
    `);
    return result.rows;
  } catch (err) {
    log.error("Failed to fetch table scan stats", { error: String(err) });
    return [];
  }
}

interface UnusedIndex {
  schemaname: string;
  relname: string;
  indexrelname: string;
  idx_scan: number;
  index_size: string;
}

export async function getUnusedIndexes(): Promise<UnusedIndex[]> {
  try {
    const result = await pool.query(`
      SELECT
        schemaname,
        relname,
        indexrelname,
        idx_scan::bigint AS idx_scan,
        pg_size_pretty(pg_relation_size(indexrelid)) AS index_size
      FROM pg_stat_user_indexes
      WHERE schemaname = 'public'
        AND idx_scan = 0
        AND indexrelname NOT LIKE '%_pkey'
        AND indexrelname NOT LIKE '%_unique%'
      ORDER BY pg_relation_size(indexrelid) DESC
      LIMIT 30
    `);
    return result.rows;
  } catch (err) {
    log.error("Failed to fetch unused indexes", { error: String(err) });
    return [];
  }
}

export async function getCacheHitRatio(): Promise<{ heap_hit_ratio: string; index_hit_ratio: string }> {
  try {
    const heapResult = await pool.query(`
      SELECT
        ROUND(100.0 * SUM(heap_blks_hit) / NULLIF(SUM(heap_blks_hit) + SUM(heap_blks_read), 0), 2)::text || '%' AS heap_hit_ratio
      FROM pg_statio_user_tables
      WHERE schemaname = 'public'
    `);
    const indexResult = await pool.query(`
      SELECT
        ROUND(100.0 * SUM(idx_blks_hit) / NULLIF(SUM(idx_blks_hit) + SUM(idx_blks_read), 0), 2)::text || '%' AS index_hit_ratio
      FROM pg_statio_user_indexes
      WHERE schemaname = 'public'
    `);
    return {
      heap_hit_ratio: heapResult.rows[0]?.heap_hit_ratio ?? "N/A",
      index_hit_ratio: indexResult.rows[0]?.index_hit_ratio ?? "N/A",
    };
  } catch (err) {
    log.error("Failed to fetch cache hit ratio", { error: String(err) });
    return { heap_hit_ratio: "N/A", index_hit_ratio: "N/A" };
  }
}

export function performanceBudgetMiddleware(req: any, res: any, next: any): void {
  const start = Date.now();

  res.on("finish", () => {
    const latency = Date.now() - start;
    const routePath = (req.route && typeof req.route.path === "string") ? req.route.path : undefined;
    const baseUrl = typeof req.baseUrl === "string" ? req.baseUrl : "";
    const endpointKey = `${req.method} ${routePath ? `${baseUrl}${routePath}` : req.path}`;

    const env = (process.env.NODE_ENV === "production" ? "production" : "staging") as "staging" | "production";
    const budget = PERFORMANCE_BUDGETS[endpointKey];

    if (budget) {
      const targetMs = budget[env];
      if (latency > targetMs) {
        log.warn("Performance budget exceeded", {
          endpoint: endpointKey,
          latencyMs: latency,
          budgetMs: targetMs,
          environment: env,
          overshootMs: latency - targetMs,
        });
      }
    }
  });

  next();
}

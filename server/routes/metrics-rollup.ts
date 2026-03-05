import type { Express, Request, Response } from "express";
import { isAuthenticated } from "../auth";
import { requireSuperAdmin } from "../middleware/super-admin";
import { sendEnvelope } from "./shared";
import { logger } from "../logger";
import { pool } from "../db";
import { runFullRollup, getRollupConfig } from "../metrics-rollup";

const log = logger.child("metrics-rollup-routes");

interface MetricsQueryParams {
  service?: string;
  metric?: string;
  granularity?: "raw" | "hourly" | "daily";
  startDate?: string;
  endDate?: string;
  limit?: string;
}

const MAX_LIMIT = 500;
const DEFAULT_LIMIT = 100;

function sanitizeIdentifier(val: string): string {
  return val.replace(/[^a-zA-Z0-9_.\-/: ]/g, "").slice(0, 128);
}

function parseLimit(raw: string | undefined): number {
  const n = Number(raw) || DEFAULT_LIMIT;
  return Math.max(1, Math.min(n, MAX_LIMIT));
}

export function registerMetricsRollupRoutes(app: Express): void {
  app.get("/api/metrics-rollup/services", isAuthenticated, requireSuperAdmin, async (_req: Request, res: Response) => {
    try {
      const result = await pool.query(`
        SELECT DISTINCT service FROM sli_metrics_hourly ORDER BY service
      `);
      const services = result.rows.map((r: { service: string }) => r.service);
      return sendEnvelope(res, { services });
    } catch (err) {
      log.error("Failed to fetch services", { error: String(err) });
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "SERVICES_FAILED", message: "Failed to fetch services" }],
      });
    }
  });

  app.get("/api/metrics-rollup/metrics", isAuthenticated, requireSuperAdmin, async (req: Request, res: Response) => {
    try {
      const service = req.query.service ? sanitizeIdentifier(String(req.query.service)) : null;
      let query = `SELECT DISTINCT service, metric FROM sli_metrics_hourly`;
      const params: string[] = [];
      if (service) {
        query += ` WHERE service = $1`;
        params.push(service);
      }
      query += ` ORDER BY service, metric`;
      const result = await pool.query(query, params);
      return sendEnvelope(res, {
        metrics: result.rows as { service: string; metric: string }[],
      });
    } catch (err) {
      log.error("Failed to fetch metrics list", { error: String(err) });
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "METRICS_LIST_FAILED", message: "Failed to fetch metrics list" }],
      });
    }
  });

  app.get("/api/metrics-rollup/data", isAuthenticated, requireSuperAdmin, async (req: Request, res: Response) => {
    try {
      const {
        service,
        metric,
        granularity = "hourly",
        startDate,
        endDate,
        limit: limitStr,
      } = req.query as MetricsQueryParams;

      if (!service || !metric) {
        return sendEnvelope(res, null, {
          status: 400,
          errors: [{ code: "MISSING_PARAMS", message: "service and metric are required" }],
        });
      }

      const validGranularities = new Set(["raw", "hourly", "daily"]);
      if (!validGranularities.has(granularity)) {
        return sendEnvelope(res, null, {
          status: 400,
          errors: [{ code: "INVALID_GRANULARITY", message: "granularity must be raw, hourly, or daily" }],
        });
      }

      const svc = sanitizeIdentifier(service);
      const met = sanitizeIdentifier(metric);
      const limit = parseLimit(limitStr);

      const now = new Date();
      const defaultStart = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
      const start = startDate ? new Date(startDate) : defaultStart;
      const end = endDate ? new Date(endDate) : now;

      if (isNaN(start.getTime()) || isNaN(end.getTime())) {
        return sendEnvelope(res, null, {
          status: 400,
          errors: [{ code: "INVALID_DATES", message: "Invalid date format" }],
        });
      }

      let query: string;
      const params = [svc, met, start.toISOString(), end.toISOString(), limit];

      if (granularity === "raw") {
        query = `
          SELECT id, service, metric, value, labels, recorded_at AS "timestamp"
          FROM sli_metrics
          WHERE service = $1 AND metric = $2
            AND recorded_at >= $3 AND recorded_at <= $4
          ORDER BY recorded_at DESC
          LIMIT $5
        `;
      } else if (granularity === "hourly") {
        query = `
          SELECT id, service, metric, hour AS "timestamp",
            min_value AS "minValue", max_value AS "maxValue",
            avg_value AS "avgValue", p50_value AS "p50Value",
            p95_value AS "p95Value", p99_value AS "p99Value",
            sample_count AS "sampleCount"
          FROM sli_metrics_hourly
          WHERE service = $1 AND metric = $2
            AND hour >= $3 AND hour <= $4
          ORDER BY hour DESC
          LIMIT $5
        `;
      } else {
        query = `
          SELECT id, service, metric, day AS "timestamp",
            min_value AS "minValue", max_value AS "maxValue",
            avg_value AS "avgValue", p50_value AS "p50Value",
            p95_value AS "p95Value", p99_value AS "p99Value",
            sample_count AS "sampleCount"
          FROM sli_metrics_daily
          WHERE service = $1 AND metric = $2
            AND day >= $3 AND day <= $4
          ORDER BY day DESC
          LIMIT $5
        `;
      }

      const result = await pool.query(query, params);
      return sendEnvelope(res, {
        granularity,
        service: svc,
        metric: met,
        startDate: start.toISOString(),
        endDate: end.toISOString(),
        count: result.rows.length,
        data: result.rows,
      });
    } catch (err) {
      log.error("Failed to fetch metrics data", { error: String(err) });
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "DATA_FAILED", message: "Failed to fetch metrics data" }],
      });
    }
  });

  app.get("/api/metrics-rollup/stats", isAuthenticated, requireSuperAdmin, async (_req: Request, res: Response) => {
    try {
      const [rawCount, hourlyCount, dailyCount, servicesCount, oldestRaw, newestRaw, oldestHourly, oldestDaily] =
        await Promise.all([
          pool.query(`SELECT COUNT(*)::int AS count FROM sli_metrics`),
          pool.query(`SELECT COUNT(*)::int AS count FROM sli_metrics_hourly`),
          pool.query(`SELECT COUNT(*)::int AS count FROM sli_metrics_daily`),
          pool.query(`SELECT COUNT(DISTINCT service)::int AS count FROM sli_metrics_hourly`),
          pool.query(`SELECT MIN(recorded_at) AS oldest FROM sli_metrics`),
          pool.query(`SELECT MAX(recorded_at) AS newest FROM sli_metrics`),
          pool.query(`SELECT MIN(hour) AS oldest FROM sli_metrics_hourly`),
          pool.query(`SELECT MIN(day) AS oldest FROM sli_metrics_daily`),
        ]);

      return sendEnvelope(res, {
        raw: {
          count: rawCount.rows[0]?.count ?? 0,
          oldest: oldestRaw.rows[0]?.oldest ?? null,
          newest: newestRaw.rows[0]?.newest ?? null,
        },
        hourly: {
          count: hourlyCount.rows[0]?.count ?? 0,
          oldest: oldestHourly.rows[0]?.oldest ?? null,
        },
        daily: {
          count: dailyCount.rows[0]?.count ?? 0,
          oldest: oldestDaily.rows[0]?.oldest ?? null,
        },
        serviceCount: servicesCount.rows[0]?.count ?? 0,
      });
    } catch (err) {
      log.error("Failed to fetch metrics stats", { error: String(err) });
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "STATS_FAILED", message: "Failed to fetch metrics stats" }],
      });
    }
  });

  app.get("/api/metrics-rollup/config", isAuthenticated, requireSuperAdmin, (_req: Request, res: Response) => {
    try {
      return sendEnvelope(res, { rollupConfig: getRollupConfig() });
    } catch (err) {
      log.error("Failed to fetch rollup config", { error: String(err) });
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "CONFIG_FAILED", message: "Failed to fetch rollup config" }],
      });
    }
  });

  app.post("/api/metrics-rollup/run", isAuthenticated, requireSuperAdmin, async (req: Request, res: Response) => {
    try {
      const recovery = req.query.recovery === "true";
      const result = await runFullRollup(recovery);
      log.info("Manual rollup triggered", {
        recovery,
        hourlyRows: result.hourly.rowsInserted,
        dailyRows: result.daily.rowsInserted,
      });
      return sendEnvelope(res, result);
    } catch (err) {
      log.error("Manual rollup failed", { error: String(err) });
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "ROLLUP_FAILED", message: "Failed to run metrics rollup" }],
      });
    }
  });

  app.get(
    "/api/metrics-rollup/top-metrics",
    isAuthenticated,
    requireSuperAdmin,
    async (_req: Request, res: Response) => {
      try {
        const result = await pool.query(`
        SELECT service, metric, SUM(sample_count)::int AS total_samples,
          SUM(avg_value * sample_count) / NULLIF(SUM(sample_count), 0) AS overall_avg,
          MAX(max_value) AS overall_max,
          MIN(min_value) AS overall_min
        FROM sli_metrics_hourly
        WHERE hour >= NOW() - INTERVAL '24 hours'
        GROUP BY service, metric
        ORDER BY total_samples DESC
        LIMIT 20
      `);
        return sendEnvelope(res, {
          period: "24h",
          metrics: result.rows.map(
            (r: {
              service: string;
              metric: string;
              total_samples: number;
              overall_avg: number;
              overall_max: number;
              overall_min: number;
            }) => ({
              service: r.service,
              metric: r.metric,
              totalSamples: r.total_samples,
              overallAvg: Number(r.overall_avg),
              overallMax: Number(r.overall_max),
              overallMin: Number(r.overall_min),
            }),
          ),
        });
      } catch (err) {
        log.error("Failed to fetch top metrics", { error: String(err) });
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "TOP_METRICS_FAILED", message: "Failed to fetch top metrics" }],
        });
      }
    },
  );
}

import { db } from "./db";
import { pool } from "./db";
import { sql } from "drizzle-orm";
import { logger } from "./logger";
import { registerShutdownHandler } from "./scaling-state";

const log = logger.child("metrics-rollup");

export interface RollupConfig {
  rawRetentionDays: number;
  hourlyRetentionDays: number;
  dailyRetentionDays: number;
}

const DEFAULT_ROLLUP_CONFIG: RollupConfig = {
  rawRetentionDays: 7,
  hourlyRetentionDays: 90,
  dailyRetentionDays: 730,
};

export function getRollupConfig(): RollupConfig {
  return { ...DEFAULT_ROLLUP_CONFIG };
}

export interface HourlyRollupResult {
  hoursProcessed: number;
  rowsInserted: number;
  errors: string[];
}

export async function rollupToHourly(windowHours = 2): Promise<HourlyRollupResult> {
  const result: HourlyRollupResult = { hoursProcessed: 0, rowsInserted: 0, errors: [] };

  try {
    const now = new Date();
    const windowStart = new Date(now.getTime() - windowHours * 60 * 60 * 1000);
    windowStart.setMinutes(0, 0, 0);

    const insertResult = await pool.query(
      `
      INSERT INTO sli_metrics_hourly (id, service, metric, hour, min_value, max_value, avg_value, p50_value, p95_value, p99_value, sample_count, labels)
      SELECT
        gen_random_uuid()::text,
        service,
        metric,
        date_trunc('hour', recorded_at) AS hour,
        MIN(value) AS min_value,
        MAX(value) AS max_value,
        AVG(value) AS avg_value,
        PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY value) AS p50_value,
        PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY value) AS p95_value,
        PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY value) AS p99_value,
        COUNT(*)::int AS sample_count,
        NULL
      FROM sli_metrics
      WHERE recorded_at >= $1
        AND recorded_at < date_trunc('hour', $2::timestamp)
      GROUP BY service, metric, date_trunc('hour', recorded_at)
      ON CONFLICT (service, metric, hour)
      DO UPDATE SET
        min_value = EXCLUDED.min_value,
        max_value = EXCLUDED.max_value,
        avg_value = EXCLUDED.avg_value,
        p50_value = EXCLUDED.p50_value,
        p95_value = EXCLUDED.p95_value,
        p99_value = EXCLUDED.p99_value,
        sample_count = EXCLUDED.sample_count
    `,
      [windowStart.toISOString(), now.toISOString()],
    );

    result.rowsInserted = Number(insertResult.rowCount) || 0;
    result.hoursProcessed = windowHours;

    if (result.rowsInserted > 0) {
      log.info("Hourly rollup complete", {
        rows: result.rowsInserted,
        window: `${windowStart.toISOString()} - ${now.toISOString()}`,
      });
    }
  } catch (err) {
    const msg = `Hourly rollup failed: ${String(err)}`;
    log.error(msg);
    result.errors.push(msg);
  }

  return result;
}

export interface DailyRollupResult {
  daysProcessed: number;
  rowsInserted: number;
  errors: string[];
}

export async function rollupToDaily(windowDays = 2): Promise<DailyRollupResult> {
  const result: DailyRollupResult = { daysProcessed: 0, rowsInserted: 0, errors: [] };

  try {
    const now = new Date();
    const windowStart = new Date(now.getTime() - windowDays * 24 * 60 * 60 * 1000);
    windowStart.setHours(0, 0, 0, 0);

    const insertResult = await pool.query(
      `
      INSERT INTO sli_metrics_daily (id, service, metric, day, min_value, max_value, avg_value, p50_value, p95_value, p99_value, sample_count, labels)
      SELECT
        gen_random_uuid()::text,
        service,
        metric,
        date_trunc('day', hour) AS day,
        MIN(min_value) AS min_value,
        MAX(max_value) AS max_value,
        SUM(avg_value * sample_count) / NULLIF(SUM(sample_count), 0) AS avg_value,
        SUM(p50_value * sample_count) / NULLIF(SUM(sample_count), 0) AS p50_value,
        SUM(p95_value * sample_count) / NULLIF(SUM(sample_count), 0) AS p95_value,
        SUM(p99_value * sample_count) / NULLIF(SUM(sample_count), 0) AS p99_value,
        SUM(sample_count)::int AS sample_count,
        NULL
      FROM sli_metrics_hourly
      WHERE hour >= $1
        AND hour < date_trunc('day', $2::timestamp)
      GROUP BY service, metric, date_trunc('day', hour)
      ON CONFLICT (service, metric, day)
      DO UPDATE SET
        min_value = EXCLUDED.min_value,
        max_value = EXCLUDED.max_value,
        avg_value = EXCLUDED.avg_value,
        p50_value = EXCLUDED.p50_value,
        p95_value = EXCLUDED.p95_value,
        p99_value = EXCLUDED.p99_value,
        sample_count = EXCLUDED.sample_count
    `,
      [windowStart.toISOString(), now.toISOString()],
    );

    result.rowsInserted = Number(insertResult.rowCount) || 0;
    result.daysProcessed = windowDays;

    if (result.rowsInserted > 0) {
      log.info("Daily rollup complete", {
        rows: result.rowsInserted,
        window: `${windowStart.toISOString()} - ${now.toISOString()}`,
      });
    }
  } catch (err) {
    const msg = `Daily rollup failed: ${String(err)}`;
    log.error(msg);
    result.errors.push(msg);
  }

  return result;
}

export interface RetentionPruneResult {
  rawDeleted: number;
  hourlyDeleted: number;
  dailyDeleted: number;
  errors: string[];
}

export async function pruneOldMetrics(config?: RollupConfig): Promise<RetentionPruneResult> {
  const cfg = config || DEFAULT_ROLLUP_CONFIG;
  const result: RetentionPruneResult = { rawDeleted: 0, hourlyDeleted: 0, dailyDeleted: 0, errors: [] };

  const BATCH = 1000;

  try {
    const rawCutoff = new Date();
    rawCutoff.setDate(rawCutoff.getDate() - cfg.rawRetentionDays);

    let rawTotal = 0;
    let hasMore = true;
    while (hasMore) {
      const batchResult = await db.execute(sql`
        DELETE FROM sli_metrics
        WHERE id IN (
          SELECT id FROM sli_metrics
          WHERE recorded_at < ${rawCutoff}
          LIMIT ${BATCH}
        )
      `);
      const deleted = Number(batchResult.rowCount) || 0;
      rawTotal += deleted;
      if (deleted < BATCH) hasMore = false;
    }
    result.rawDeleted = rawTotal;
  } catch (err) {
    result.errors.push(`Raw prune failed: ${String(err)}`);
  }

  try {
    const hourlyCutoff = new Date();
    hourlyCutoff.setDate(hourlyCutoff.getDate() - cfg.hourlyRetentionDays);

    const hourlyResult = await db.execute(sql`
      DELETE FROM sli_metrics_hourly WHERE hour < ${hourlyCutoff}
    `);
    result.hourlyDeleted = Number(hourlyResult.rowCount) || 0;
  } catch (err) {
    result.errors.push(`Hourly prune failed: ${String(err)}`);
  }

  try {
    const dailyCutoff = new Date();
    dailyCutoff.setDate(dailyCutoff.getDate() - cfg.dailyRetentionDays);

    const dailyResult = await db.execute(sql`
      DELETE FROM sli_metrics_daily WHERE day < ${dailyCutoff}
    `);
    result.dailyDeleted = Number(dailyResult.rowCount) || 0;
  } catch (err) {
    result.errors.push(`Daily prune failed: ${String(err)}`);
  }

  const total = result.rawDeleted + result.hourlyDeleted + result.dailyDeleted;
  if (total > 0) {
    log.info("Metrics retention prune complete", {
      raw: result.rawDeleted,
      hourly: result.hourlyDeleted,
      daily: result.dailyDeleted,
    });
  }

  return result;
}

export interface FullRollupResult {
  hourly: HourlyRollupResult;
  daily: DailyRollupResult;
  retention: RetentionPruneResult;
}

export async function runFullRollup(recoveryMode = false): Promise<FullRollupResult> {
  const hourlyWindow = recoveryMode ? DEFAULT_ROLLUP_CONFIG.rawRetentionDays * 24 : 2;
  const dailyWindow = recoveryMode ? Math.ceil(DEFAULT_ROLLUP_CONFIG.hourlyRetentionDays / 2) : 2;
  const hourly = await rollupToHourly(hourlyWindow);
  const daily = await rollupToDaily(dailyWindow);
  const retention = await pruneOldMetrics();

  if (recoveryMode) {
    log.info("Recovery rollup complete", {
      hourlyWindow,
      dailyWindow,
      hourlyRows: hourly.rowsInserted,
      dailyRows: daily.rowsInserted,
    });
  }

  return { hourly, daily, retention };
}

let rollupTimer: ReturnType<typeof setInterval> | null = null;
let rollupStartupTimer: ReturnType<typeof setTimeout> | null = null;

export function startMetricsRollupScheduler(): void {
  if (rollupTimer) return;

  rollupStartupTimer = setTimeout(
    () => {
      rollupStartupTimer = null;
      runFullRollup(true).catch((err) => {
        log.error("Rollup startup error", { error: String(err) });
      });
    },
    3 * 60 * 1000,
  );

  rollupTimer = setInterval(
    () => {
      runFullRollup().catch((err) => {
        log.error("Rollup interval error", { error: String(err) });
      });
    },
    60 * 60 * 1000,
  );

  registerShutdownHandler("metrics-rollup", () => {
    if (rollupStartupTimer) {
      clearTimeout(rollupStartupTimer);
      rollupStartupTimer = null;
    }
    if (rollupTimer) {
      clearInterval(rollupTimer);
      rollupTimer = null;
    }
  });

  log.info(
    "Metrics rollup scheduler started - hourly rollup every 60 min, daily rollup every 60 min, retention prune every 60 min",
  );
}

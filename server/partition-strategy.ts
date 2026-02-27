import { db } from "./db";
import { pool } from "./db";
import { sql } from "drizzle-orm";
import { logger } from "./logger";
import { registerShutdownHandler } from "./scaling-state";

const log = logger.child("partition-strategy");

export interface PartitionConfig {
  tableName: string;
  partitionColumn: string;
  intervalDays: number;
  retentionMonths: number;
  archiveTable: string | null;
}

const PARTITION_CONFIGS: PartitionConfig[] = [
  {
    tableName: "alerts",
    partitionColumn: "created_at",
    intervalDays: 30,
    retentionMonths: 12,
    archiveTable: "alerts_archive",
  },
  {
    tableName: "endpoint_telemetry",
    partitionColumn: "collected_at",
    intervalDays: 7,
    retentionMonths: 3,
    archiveTable: "endpoint_telemetry_archive",
  },
  {
    tableName: "sli_metrics",
    partitionColumn: "recorded_at",
    intervalDays: 7,
    retentionMonths: 3,
    archiveTable: null,
  },
  {
    tableName: "audit_logs",
    partitionColumn: "created_at",
    intervalDays: 30,
    retentionMonths: 24,
    archiveTable: null,
  },
  {
    tableName: "ingestion_logs",
    partitionColumn: "received_at",
    intervalDays: 7,
    retentionMonths: 3,
    archiveTable: "ingestion_logs_archive",
  },
  {
    tableName: "connector_job_runs",
    partitionColumn: "started_at",
    intervalDays: 14,
    retentionMonths: 6,
    archiveTable: "connector_job_runs_archive",
  },
];

const ALLOWED_TABLE_NAMES = new Set(PARTITION_CONFIGS.map((c) => c.tableName));

function validateTableName(name: string): void {
  if (!ALLOWED_TABLE_NAMES.has(name)) {
    throw new Error(`Table name not in allowlist: ${name}`);
  }
}

export function getPartitionConfigs(): PartitionConfig[] {
  return [...PARTITION_CONFIGS];
}

export interface TableSizeInfo {
  tableName: string;
  rowCountEstimate: number;
  totalSizeBytes: number;
  totalSizePretty: string;
  indexSizeBytes: number;
  indexSizePretty: string;
}

export async function getTableSizes(): Promise<TableSizeInfo[]> {
  const results: TableSizeInfo[] = [];

  for (const config of PARTITION_CONFIGS) {
    try {
      const sizeResult = await pool.query(
        `
        SELECT
          relname AS table_name,
          reltuples::bigint AS row_estimate,
          pg_total_relation_size(quote_ident(relname))::bigint AS total_size,
          pg_size_pretty(pg_total_relation_size(quote_ident(relname))) AS total_pretty,
          pg_indexes_size(quote_ident(relname))::bigint AS index_size,
          pg_size_pretty(pg_indexes_size(quote_ident(relname))) AS index_pretty
        FROM pg_class
        WHERE relname = $1 AND relkind = 'r'
      `,
        [config.tableName],
      );

      if (sizeResult.rows.length > 0) {
        const row = sizeResult.rows[0] as {
          table_name: string;
          row_estimate: string;
          total_size: string;
          total_pretty: string;
          index_size: string;
          index_pretty: string;
        };
        results.push({
          tableName: row.table_name,
          rowCountEstimate: Number(row.row_estimate),
          totalSizeBytes: Number(row.total_size),
          totalSizePretty: row.total_pretty,
          indexSizeBytes: Number(row.index_size),
          indexSizePretty: row.index_pretty,
        });
      }
    } catch (err) {
      log.warn("Failed to get size for table", { table: config.tableName, error: String(err) });
    }
  }

  return results;
}

export interface ArchivalResult {
  tableName: string;
  archivedCount: number;
  deletedCount: number;
  errors: string[];
}

const ARCHIVAL_BATCH_SIZE = 500;

async function getCommonColumns(sourceTable: string, archiveTable: string): Promise<string[]> {
  const result = await pool.query(
    `
    SELECT s.column_name
    FROM information_schema.columns s
    INNER JOIN information_schema.columns a
      ON s.column_name = a.column_name
    WHERE s.table_name = $1
      AND a.table_name = $2
      AND s.table_schema = 'public'
      AND a.table_schema = 'public'
    ORDER BY s.ordinal_position
  `,
    [sourceTable, archiveTable],
  );
  return (result.rows as { column_name: string }[]).map((r) => r.column_name);
}

export async function archiveOldRows(
  tableName: string,
  archiveTableName: string,
  partitionColumn: string,
  cutoffDate: Date,
  orgId?: string,
): Promise<ArchivalResult> {
  validateTableName(tableName);
  const result: ArchivalResult = {
    tableName,
    archivedCount: 0,
    deletedCount: 0,
    errors: [],
  };

  try {
    const commonCols = await getCommonColumns(tableName, archiveTableName);
    if (commonCols.length === 0) {
      result.errors.push(`No common columns between ${tableName} and ${archiveTableName}`);
      return result;
    }

    const colList = commonCols.map((c) => `"${c}"`).join(", ");
    let totalArchived = 0;
    let hasMore = true;

    while (hasMore) {
      const orgFilter = orgId ? " AND org_id = $3" : "";
      const params: (string | number)[] = [cutoffDate.toISOString(), ARCHIVAL_BATCH_SIZE];
      if (orgId) params.push(orgId);

      const client = await pool.connect();
      try {
        await client.query("BEGIN");

        const selectResult = await client.query(
          `SELECT id FROM "${tableName}" WHERE "${partitionColumn}" < $1${orgFilter} ORDER BY "${partitionColumn}" ASC LIMIT $2`,
          params,
        );

        const ids = (selectResult.rows as { id: string }[]).map((r) => r.id);

        if (ids.length === 0) {
          await client.query("COMMIT");
          hasMore = false;
          break;
        }

        await client.query(
          `INSERT INTO "${archiveTableName}" (${colList}, archived_at, archive_reason)
           SELECT ${colList}, NOW(), 'retention'
           FROM "${tableName}"
           WHERE id = ANY($1)`,
          [ids],
        );

        await client.query(`DELETE FROM "${tableName}" WHERE id = ANY($1)`, [ids]);

        await client.query("COMMIT");

        totalArchived += ids.length;

        if (ids.length < ARCHIVAL_BATCH_SIZE) {
          hasMore = false;
        }
      } catch (txErr) {
        await client.query("ROLLBACK");
        throw txErr;
      } finally {
        client.release();
      }
    }

    result.archivedCount = totalArchived;
    result.deletedCount = totalArchived;

    if (totalArchived > 0) {
      log.info("Archival complete", {
        tableName,
        archiveTable: archiveTableName,
        archived: totalArchived,
        cutoff: cutoffDate.toISOString(),
      });
    }
  } catch (err) {
    const msg = `Archival failed for ${tableName}: ${String(err)}`;
    log.error(msg);
    result.errors.push(msg);
  }

  return result;
}

export async function pruneOldRows(
  tableName: string,
  partitionColumn: string,
  cutoffDate: Date,
  orgId?: string,
): Promise<{ deleted: number; error: string | null }> {
  validateTableName(tableName);

  try {
    const orgClause = orgId ? sql` AND org_id = ${orgId}` : sql``;
    let totalDeleted = 0;
    let hasMore = true;

    while (hasMore) {
      const batchResult = await db.execute(sql`
        DELETE FROM ${sql.identifier(tableName)}
        WHERE id IN (
          SELECT id FROM ${sql.identifier(tableName)}
          WHERE ${sql.identifier(partitionColumn)} < ${cutoffDate}${orgClause}
          LIMIT ${ARCHIVAL_BATCH_SIZE}
        )
      `);

      const deleted = Number(batchResult.rowCount) || 0;
      totalDeleted += deleted;

      if (deleted < ARCHIVAL_BATCH_SIZE) {
        hasMore = false;
      }
    }

    if (totalDeleted > 0) {
      log.info("Pruned old rows", { tableName, deleted: totalDeleted, cutoff: cutoffDate.toISOString() });
    }

    return { deleted: totalDeleted, error: null };
  } catch (err) {
    return { deleted: 0, error: String(err) };
  }
}

export interface ArchivalJobResult {
  results: ArchivalResult[];
  pruned: { tableName: string; deleted: number }[];
  errors: string[];
}

export async function runArchivalJob(): Promise<ArchivalJobResult> {
  const jobResult: ArchivalJobResult = { results: [], pruned: [], errors: [] };

  for (const config of PARTITION_CONFIGS) {
    const cutoff = new Date();
    cutoff.setMonth(cutoff.getMonth() - config.retentionMonths);

    if (config.archiveTable) {
      const archResult = await archiveOldRows(config.tableName, config.archiveTable, config.partitionColumn, cutoff);
      jobResult.results.push(archResult);
      if (archResult.errors.length > 0) {
        jobResult.errors.push(...archResult.errors);
      }
    } else {
      const pruneResult = await pruneOldRows(config.tableName, config.partitionColumn, cutoff);
      if (pruneResult.error) {
        jobResult.errors.push(pruneResult.error);
      } else {
        jobResult.pruned.push({ tableName: config.tableName, deleted: pruneResult.deleted });
      }
    }
  }

  const totalArchived = jobResult.results.reduce((s, r) => s + r.archivedCount, 0);
  const totalPruned = jobResult.pruned.reduce((s, r) => s + r.deleted, 0);

  if (totalArchived > 0 || totalPruned > 0) {
    log.info("Archival job complete", { totalArchived, totalPruned, errors: jobResult.errors.length });
  }

  return jobResult;
}

let archivalTimer: ReturnType<typeof setInterval> | null = null;
let archivalStartupTimer: ReturnType<typeof setTimeout> | null = null;

export function startArchivalScheduler(): void {
  if (archivalTimer) return;

  archivalStartupTimer = setTimeout(
    () => {
      archivalStartupTimer = null;
      runArchivalJob().catch((err) => {
        log.error("Archival job startup error", { error: String(err) });
      });
    },
    5 * 60 * 1000,
  );

  archivalTimer = setInterval(
    () => {
      runArchivalJob().catch((err) => {
        log.error("Archival job error", { error: String(err) });
      });
    },
    24 * 60 * 60 * 1000,
  );

  registerShutdownHandler("archival-scheduler", () => {
    if (archivalStartupTimer) {
      clearTimeout(archivalStartupTimer);
      archivalStartupTimer = null;
    }
    if (archivalTimer) {
      clearInterval(archivalTimer);
      archivalTimer = null;
    }
  });

  log.info("Archival scheduler started - runs every 24 hours");
}

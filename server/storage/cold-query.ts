import { db } from "../db";
import { sql } from "drizzle-orm";
import { eq, and, desc } from "drizzle-orm";
import { coldStorageInventory, dataLakeQueries } from "@shared/schema";
import { getSignedUrl } from "../s3";
import { logger } from "../logger";
import zlib from "zlib";
import { promisify } from "util";

const log = logger.child("cold-query");
const gunzip = promisify(zlib.gunzip);

const ALLOWED_TABLES: ReadonlySet<string> = new Set([
  "alerts",
  "incidents",
  "audit_logs",
  "sli_metrics",
  "jobs",
  "connector_job_runs",
  "outbox_events",
  "ingestion_logs",
]);

// ─── Federated Query Engine ─────────────────────────────────────────────────

export interface FederatedQueryOptions {
  orgId: string;
  queryText: string;
  dataTypes: string[];
  dateRangeStart?: Date;
  dateRangeEnd?: Date;
  limit?: number;
  includeCold?: boolean;
  executedBy?: string;
}

export interface FederatedQueryResult {
  queryId: string;
  hotResults: Record<string, unknown>[];
  coldResults: Record<string, unknown>[];
  totalResults: number;
  hotCount: number;
  coldCount: number;
  executionTimeMs: number;
  errors: string[];
}

export async function executeFederatedQuery(options: FederatedQueryOptions): Promise<FederatedQueryResult> {
  const startTime = Date.now();
  const validDataTypes = options.dataTypes.filter((dt) => ALLOWED_TABLES.has(dt));

  if (validDataTypes.length === 0) {
    throw new Error("No valid data types specified");
  }

  const limit = Math.min(Math.max(1, options.limit || 100), 1000);

  // Create query record
  const [query] = await db
    .insert(dataLakeQueries)
    .values({
      orgId: options.orgId,
      queryText: options.queryText.substring(0, 10000),
      queryType: options.includeCold !== false ? "federated" : "hot_only",
      dataTypes: validDataTypes,
      dateRangeStart: options.dateRangeStart || null,
      dateRangeEnd: options.dateRangeEnd || null,
      status: "running",
      executedBy: options.executedBy || null,
    })
    .returning();

  const result: FederatedQueryResult = {
    queryId: query.id,
    hotResults: [],
    coldResults: [],
    totalResults: 0,
    hotCount: 0,
    coldCount: 0,
    executionTimeMs: 0,
    errors: [],
  };

  try {
    // 1. Query hot data (PostgreSQL)
    for (const dataType of validDataTypes) {
      try {
        const hotRows = await queryHotData(options.orgId, dataType, options.queryText, {
          dateRangeStart: options.dateRangeStart,
          dateRangeEnd: options.dateRangeEnd,
          limit,
        });
        result.hotResults.push(...hotRows);
        result.hotCount += hotRows.length;
      } catch (err) {
        result.errors.push(`Hot query failed for ${dataType}: ${String(err)}`);
      }
    }

    // 2. Query cold data (S3 via inventory)
    if (options.includeCold !== false) {
      for (const dataType of validDataTypes) {
        try {
          const coldRows = await queryColdData(options.orgId, dataType, options.queryText, {
            dateRangeStart: options.dateRangeStart,
            dateRangeEnd: options.dateRangeEnd,
            limit: Math.max(0, limit - result.hotCount),
          });
          result.coldResults.push(...coldRows);
          result.coldCount += coldRows.length;
        } catch (err) {
          result.errors.push(`Cold query failed for ${dataType}: ${String(err)}`);
        }
      }
    }

    result.totalResults = result.hotCount + result.coldCount;
    result.executionTimeMs = Date.now() - startTime;

    // Update query record
    await db
      .update(dataLakeQueries)
      .set({
        status: "completed",
        hotResultCount: result.hotCount,
        coldResultCount: result.coldCount,
        totalResultCount: result.totalResults,
        executionTimeMs: result.executionTimeMs,
        completedAt: new Date(),
      })
      .where(eq(dataLakeQueries.id, query.id));
  } catch (err) {
    result.errors.push(`Query execution failed: ${String(err)}`);
    result.executionTimeMs = Date.now() - startTime;

    await db
      .update(dataLakeQueries)
      .set({
        status: "failed",
        errorMessage: String(err).substring(0, 2000),
        executionTimeMs: result.executionTimeMs,
        completedAt: new Date(),
      })
      .where(eq(dataLakeQueries.id, query.id));
  }

  return result;
}

// ─── Hot Data Query (PostgreSQL) ────────────────────────────────────────────

async function queryHotData(
  orgId: string,
  dataType: string,
  searchText: string,
  options: { dateRangeStart?: Date; dateRangeEnd?: Date; limit: number },
): Promise<Record<string, unknown>[]> {
  if (!ALLOWED_TABLES.has(dataType)) return [];

  const conditions = [sql`org_id = ${orgId}`];

  if (options.dateRangeStart) {
    conditions.push(sql`created_at >= ${options.dateRangeStart}`);
  }
  if (options.dateRangeEnd) {
    conditions.push(sql`created_at <= ${options.dateRangeEnd}`);
  }

  // Simple text search using ILIKE on relevant text columns
  if (searchText && searchText.trim().length > 0) {
    const searchPattern = `%${searchText.replace(/%/g, "\\%").replace(/_/g, "\\_")}%`;
    // Search across common text columns depending on data type
    const textSearchCondition = getTextSearchCondition(dataType, searchPattern);
    if (textSearchCondition) {
      conditions.push(textSearchCondition);
    }
  }

  const whereClause = sql.join(conditions, sql` AND `);

  const rows = await db.execute(
    sql`SELECT * FROM ${sql.identifier(dataType)}
        WHERE ${whereClause}
        ORDER BY created_at DESC
        LIMIT ${options.limit}`,
  );

  return (rows as unknown as { rows: Record<string, unknown>[] }).rows || [];
}

function getTextSearchCondition(dataType: string, searchPattern: string): ReturnType<typeof sql> | null {
  switch (dataType) {
    case "alerts":
      return sql`(title ILIKE ${searchPattern} OR description ILIKE ${searchPattern})`;
    case "incidents":
      return sql`(title ILIKE ${searchPattern} OR description ILIKE ${searchPattern})`;
    case "audit_logs":
      return sql`(action ILIKE ${searchPattern} OR resource_type ILIKE ${searchPattern})`;
    case "ingestion_logs":
      return sql`(source ILIKE ${searchPattern})`;
    default:
      return null;
  }
}

// ─── Cold Data Query (S3) ───────────────────────────────────────────────────

async function queryColdData(
  orgId: string,
  dataType: string,
  searchText: string,
  options: { dateRangeStart?: Date; dateRangeEnd?: Date; limit: number },
): Promise<Record<string, unknown>[]> {
  if (options.limit <= 0) return [];

  // Find relevant cold storage files from inventory
  const inventoryItems = await db
    .select()
    .from(coldStorageInventory)
    .where(
      and(
        eq(coldStorageInventory.orgId, orgId),
        eq(coldStorageInventory.dataType, dataType),
        eq(coldStorageInventory.isRehydrated, false),
      ),
    )
    .orderBy(desc(coldStorageInventory.newestRecord))
    .limit(50);

  // Filter by date range
  const relevantFiles = inventoryItems.filter((item) => {
    if (options.dateRangeStart && item.newestRecord && item.newestRecord < options.dateRangeStart) {
      return false;
    }
    if (options.dateRangeEnd && item.oldestRecord && item.oldestRecord > options.dateRangeEnd) {
      return false;
    }
    return true;
  });

  const allResults: Record<string, unknown>[] = [];
  const searchLower = searchText?.toLowerCase() || "";

  for (const file of relevantFiles) {
    if (allResults.length >= options.limit) break;

    try {
      const records = await downloadAndParseS3File(file.s3Key);

      // Filter records by search text and date range
      for (const record of records) {
        if (allResults.length >= options.limit) break;

        // Date range filter
        const createdAt = record.created_at ? new Date(String(record.created_at)) : null;
        if (options.dateRangeStart && createdAt && createdAt < options.dateRangeStart) continue;
        if (options.dateRangeEnd && createdAt && createdAt > options.dateRangeEnd) continue;

        // Text search filter
        if (searchLower) {
          const matchesSearch = Object.values(record).some((val) => {
            if (val === null || val === undefined) return false;
            return String(val).toLowerCase().includes(searchLower);
          });
          if (!matchesSearch) continue;
        }

        allResults.push({ ...record, _source: "cold_storage", _s3Key: file.s3Key });
      }
    } catch (err) {
      log.warn("Failed to query cold storage file", { s3Key: file.s3Key, error: String(err) });
    }
  }

  return allResults;
}

async function downloadAndParseS3File(s3Key: string): Promise<Record<string, unknown>[]> {
  const url = await getSignedUrl(s3Key, 300);
  const resp = await fetch(url);
  if (!resp.ok) {
    throw new Error(`Failed to download ${s3Key}: ${resp.status}`);
  }

  const compressedBuffer = Buffer.from(await resp.arrayBuffer());
  const decompressed = await gunzip(compressedBuffer);
  const data = JSON.parse(decompressed.toString("utf-8"));

  // Handle columnar format (convert back to rows)
  if (data.columns && data.rowCount !== undefined) {
    return columnarToRows(data.columns, data.rowCount);
  }

  // Handle plain JSON array
  if (Array.isArray(data)) {
    return data;
  }

  return [];
}

function columnarToRows(columns: Record<string, unknown[]>, rowCount: number): Record<string, unknown>[] {
  const rows: Record<string, unknown>[] = [];
  const keys = Object.keys(columns);

  for (let i = 0; i < rowCount; i++) {
    const row: Record<string, unknown> = {};
    for (const key of keys) {
      row[key] = columns[key]?.[i] ?? null;
    }
    rows.push(row);
  }

  return rows;
}

// ─── Query History ──────────────────────────────────────────────────────────

export async function getQueryHistory(
  orgId: string,
  limit: number = 50,
): Promise<
  Array<{
    id: string;
    queryText: string;
    queryType: string;
    status: string;
    totalResultCount: number | null;
    executionTimeMs: number | null;
    createdAt: Date;
  }>
> {
  return db
    .select({
      id: dataLakeQueries.id,
      queryText: dataLakeQueries.queryText,
      queryType: dataLakeQueries.queryType,
      status: dataLakeQueries.status,
      totalResultCount: dataLakeQueries.totalResultCount,
      executionTimeMs: dataLakeQueries.executionTimeMs,
      createdAt: dataLakeQueries.createdAt,
    })
    .from(dataLakeQueries)
    .where(eq(dataLakeQueries.orgId, orgId))
    .orderBy(desc(dataLakeQueries.createdAt))
    .limit(Math.min(limit, 200));
}

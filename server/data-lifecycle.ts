import { db } from "./db";
import { sql } from "drizzle-orm";
import { storage } from "./storage";
import { uploadFile, getSignedUrl, listFiles, deleteFile } from "./s3";
import { logger } from "./logger";
import { getPodId } from "./scaling-state";
import zlib from "zlib";
import { promisify } from "util";
import { createHash } from "crypto";

const log = logger.child("data-lifecycle");
const gzip = promisify(zlib.gzip);
const gunzip = promisify(zlib.gunzip);

export type DataType = "alerts" | "incidents" | "audit_logs" | "sli_metrics" | "jobs" | "connector_job_runs" | "outbox_events" | "ingestion_logs";
export type StorageTier = "hot" | "warm" | "cold" | "deleted";
export type PlanTier = "free" | "pro" | "enterprise";

export interface RetentionPolicy {
  dataType: DataType;
  hotDays: number;
  warmDays: number;
  coldDays: number;
}

const DEFAULT_RETENTION: Record<PlanTier, RetentionPolicy[]> = {
  free: [
    { dataType: "alerts", hotDays: 30, warmDays: 60, coldDays: 90 },
    { dataType: "incidents", hotDays: 60, warmDays: 90, coldDays: 180 },
    { dataType: "audit_logs", hotDays: 90, warmDays: 180, coldDays: 365 },
    { dataType: "sli_metrics", hotDays: 7, warmDays: 30, coldDays: 60 },
    { dataType: "jobs", hotDays: 7, warmDays: 14, coldDays: 30 },
    { dataType: "connector_job_runs", hotDays: 14, warmDays: 30, coldDays: 60 },
    { dataType: "outbox_events", hotDays: 7, warmDays: 14, coldDays: 30 },
    { dataType: "ingestion_logs", hotDays: 14, warmDays: 30, coldDays: 60 },
  ],
  pro: [
    { dataType: "alerts", hotDays: 90, warmDays: 180, coldDays: 365 },
    { dataType: "incidents", hotDays: 180, warmDays: 365, coldDays: 730 },
    { dataType: "audit_logs", hotDays: 365, warmDays: 730, coldDays: 2555 },
    { dataType: "sli_metrics", hotDays: 30, warmDays: 90, coldDays: 180 },
    { dataType: "jobs", hotDays: 14, warmDays: 30, coldDays: 90 },
    { dataType: "connector_job_runs", hotDays: 30, warmDays: 90, coldDays: 180 },
    { dataType: "outbox_events", hotDays: 14, warmDays: 30, coldDays: 90 },
    { dataType: "ingestion_logs", hotDays: 30, warmDays: 90, coldDays: 180 },
  ],
  enterprise: [
    { dataType: "alerts", hotDays: 180, warmDays: 365, coldDays: 1095 },
    { dataType: "incidents", hotDays: 365, warmDays: 730, coldDays: 2555 },
    { dataType: "audit_logs", hotDays: 730, warmDays: 2555, coldDays: 2555 },
    { dataType: "sli_metrics", hotDays: 90, warmDays: 365, coldDays: 730 },
    { dataType: "jobs", hotDays: 30, warmDays: 90, coldDays: 365 },
    { dataType: "connector_job_runs", hotDays: 90, warmDays: 365, coldDays: 730 },
    { dataType: "outbox_events", hotDays: 30, warmDays: 90, coldDays: 365 },
    { dataType: "ingestion_logs", hotDays: 90, warmDays: 365, coldDays: 730 },
  ],
};

export function getRetentionPolicies(plan: PlanTier): RetentionPolicy[] {
  return DEFAULT_RETENTION[plan];
}

export function getRetentionPolicy(plan: PlanTier, dataType: DataType): RetentionPolicy {
  const policy = DEFAULT_RETENTION[plan].find((p) => p.dataType === dataType);
  if (!policy) {
    return { dataType, hotDays: 90, warmDays: 365, coldDays: 730 };
  }
  return policy;
}

const ALLOWED_TABLES: ReadonlySet<string> = new Set([
  "alerts", "incidents", "audit_logs", "sli_metrics",
  "jobs", "connector_job_runs", "outbox_events", "ingestion_logs",
]);

const ALLOWED_COLUMNS: Record<string, ReadonlySet<string>> = {
  alerts: new Set(["id", "org_id", "title", "description", "severity", "status", "source", "created_at", "updated_at", "assigned_to", "tags", "raw_data", "connector_id", "external_id", "mitre_tactics", "mitre_techniques", "entity_ids", "confidence_score", "first_seen", "last_seen"]),
  incidents: new Set(["id", "org_id", "title", "description", "severity", "status", "created_at", "updated_at", "assigned_to", "alert_ids", "tags", "timeline", "root_cause", "resolution", "priority", "category", "sla_breach", "closed_at"]),
  audit_logs: new Set(["id", "org_id", "user_id", "user_name", "action", "resource_type", "resource_id", "details", "ip_address", "user_agent", "created_at"]),
  sli_metrics: new Set(["id", "org_id", "metric_name", "value", "unit", "tags", "recorded_at", "created_at", "window_start", "window_end", "p50", "p95", "p99", "error_rate", "request_count"]),
  jobs: new Set(["id", "org_id", "type", "status", "payload", "result", "error", "attempts", "max_attempts", "priority", "created_at", "updated_at", "started_at", "completed_at", "locked_by", "locked_at", "scheduled_for"]),
  connector_job_runs: new Set(["id", "org_id", "connector_id", "status", "started_at", "completed_at", "records_fetched", "records_created", "error", "created_at", "duration_ms", "checkpoint"]),
  outbox_events: new Set(["id", "org_id", "event_type", "payload", "status", "created_at", "published_at", "attempts", "last_error", "aggregate_id", "aggregate_type"]),
  ingestion_logs: new Set(["id", "org_id", "source", "status", "records_received", "records_accepted", "records_rejected", "errors", "created_at", "duration_ms", "connector_id", "batch_id"]),
};

function validateTableName(dataType: DataType): string {
  if (!ALLOWED_TABLES.has(dataType)) {
    throw new Error(`Invalid data type: ${dataType}`);
  }
  return dataType;
}

function validateColumnNames(tableName: string, columns: string[]): string[] {
  const allowedCols = ALLOWED_COLUMNS[tableName];
  if (!allowedCols) {
    throw new Error(`No column allowlist for table: ${tableName}`);
  }
  const validColumns = columns.filter((col) => allowedCols.has(col));
  if (validColumns.length === 0) {
    throw new Error(`No valid columns found for table ${tableName}`);
  }
  return validColumns;
}

const BATCH_SIZE = 500;

function s3ColdStoragePrefix(orgId: string, dataType: DataType): string {
  return `lifecycle/cold/${orgId}/${dataType}`;
}

function s3ArchiveKey(orgId: string, dataType: DataType, batchId: string): string {
  return `${s3ColdStoragePrefix(orgId, dataType)}/${batchId}.json.gz`;
}

function s3ManifestKey(orgId: string, dataType: DataType, batchId: string): string {
  return `${s3ColdStoragePrefix(orgId, dataType)}/${batchId}.manifest.json`;
}

export interface ColdStorageManifest {
  batchId: string;
  orgId: string;
  dataType: DataType;
  recordCount: number;
  oldestRecord: string;
  newestRecord: string;
  compressedSizeBytes: number;
  s3Key: string;
  exportedAt: string;
  exportedBy: string;
  checksum: string;
}

export interface ExportResult {
  exported: number;
  batches: ColdStorageManifest[];
  errors: string[];
}

export async function exportToColdStorage(
  orgId: string,
  dataType: DataType,
  cutoffDate: Date,
): Promise<ExportResult> {
  const tableName = validateTableName(dataType);
  const result: ExportResult = { exported: 0, batches: [], errors: [] };

  try {
    let offset = 0;
    let hasMore = true;

    while (hasMore) {
      const rows = await db.execute(
        sql`SELECT * FROM ${sql.identifier(tableName)} WHERE org_id = ${orgId} AND created_at < ${cutoffDate} ORDER BY created_at ASC LIMIT ${BATCH_SIZE} OFFSET ${offset}`
      );

      const records = (rows as any).rows || [];
      if (records.length === 0) {
        hasMore = false;
        break;
      }

      const batchId = `${Date.now()}-${offset}`;
      const jsonData = JSON.stringify(records);
      const compressed = await gzip(Buffer.from(jsonData, "utf-8"));

      const checksum = createHash("sha256").update(compressed).digest("hex");

      const dataKey = s3ArchiveKey(orgId, dataType, batchId);
      await uploadFile(dataKey, compressed, "application/gzip");

      const manifest: ColdStorageManifest = {
        batchId,
        orgId,
        dataType,
        recordCount: records.length,
        oldestRecord: records[0]?.created_at || cutoffDate.toISOString(),
        newestRecord: records[records.length - 1]?.created_at || cutoffDate.toISOString(),
        compressedSizeBytes: compressed.length,
        s3Key: dataKey,
        exportedAt: new Date().toISOString(),
        exportedBy: getPodId(),
        checksum,
      };

      const manifestKey = s3ManifestKey(orgId, dataType, batchId);
      await uploadFile(manifestKey, JSON.stringify(manifest, null, 2), "application/json");

      result.exported += records.length;
      result.batches.push(manifest);

      if (records.length < BATCH_SIZE) {
        hasMore = false;
      } else {
        offset += BATCH_SIZE;
      }
    }

    log.info("Cold storage export complete", {
      orgId,
      dataType,
      exported: result.exported,
      batches: result.batches.length,
    });
  } catch (err) {
    const msg = `Cold storage export failed for ${orgId}/${dataType}: ${String(err)}`;
    log.error(msg);
    result.errors.push(msg);
  }

  return result;
}

export interface RehydrationResult {
  rehydrated: number;
  manifests: ColdStorageManifest[];
  errors: string[];
}

export async function listColdStorageArchives(
  orgId: string,
  dataType: DataType,
): Promise<ColdStorageManifest[]> {
  const prefix = s3ColdStoragePrefix(orgId, dataType);
  const files = await listFiles(prefix);
  const manifestFiles = files.filter((f) => f.key?.endsWith(".manifest.json"));

  const manifests: ColdStorageManifest[] = [];
  for (const file of manifestFiles) {
    if (!file.key) continue;
    try {
      const url = await getSignedUrl(file.key, 60);
      const resp = await fetch(url);
      if (resp.ok) {
        const manifest = (await resp.json()) as ColdStorageManifest;
        manifests.push(manifest);
      }
    } catch (err) {
      log.warn("Failed to read manifest", { key: file.key, error: String(err) });
    }
  }

  return manifests.sort((a, b) => a.exportedAt.localeCompare(b.exportedAt));
}

export async function rehydrateFromColdStorage(
  orgId: string,
  dataType: DataType,
  batchId: string,
): Promise<RehydrationResult> {
  const result: RehydrationResult = { rehydrated: 0, manifests: [], errors: [] };

  try {
    const manifestKey = s3ManifestKey(orgId, dataType, batchId);
    const manifestUrl = await getSignedUrl(manifestKey, 60);
    const manifestResp = await fetch(manifestUrl);
    if (!manifestResp.ok) {
      result.errors.push(`Manifest not found: ${manifestKey}`);
      return result;
    }
    const manifest = (await manifestResp.json()) as ColdStorageManifest;

    if (manifest.orgId !== orgId) {
      result.errors.push("Org ID mismatch — tenant isolation violation blocked");
      return result;
    }

    const dataUrl = await getSignedUrl(manifest.s3Key, 300);
    const dataResp = await fetch(dataUrl);
    if (!dataResp.ok) {
      result.errors.push(`Data file not found: ${manifest.s3Key}`);
      return result;
    }

    const compressedBuffer = Buffer.from(await dataResp.arrayBuffer());

    const actualChecksum = createHash("sha256").update(compressedBuffer).digest("hex");
    if (actualChecksum !== manifest.checksum) {
      result.errors.push(`Checksum mismatch: expected ${manifest.checksum}, got ${actualChecksum}`);
      return result;
    }

    const decompressed = await gunzip(compressedBuffer);
    const records = JSON.parse(decompressed.toString("utf-8"));

    if (!Array.isArray(records) || records.length === 0) {
      result.errors.push("No records found in archive");
      return result;
    }

    const tableName = validateTableName(dataType);
    const rawColumns = Object.keys(records[0]);
    const validColumns = validateColumnNames(tableName, rawColumns);
    if (validColumns.length < rawColumns.length) {
      const dropped = rawColumns.filter((c) => !validColumns.includes(c));
      log.warn("Dropped disallowed columns from rehydration", { tableName, dropped });
    }

    let insertedCount = 0;
    for (let i = 0; i < records.length; i += BATCH_SIZE) {
      const batch = records.slice(i, i + BATCH_SIZE);
      try {
        const columnsSql = validColumns.map((c) => sql.identifier(c));
        for (const row of batch) {
          const vals = validColumns.map((col) => {
            const val = row[col];
            if (val === null || val === undefined) return sql`NULL`;
            if (typeof val === "object") return sql`${JSON.stringify(val)}`;
            return sql`${val}`;
          });
          await db.execute(
            sql`INSERT INTO ${sql.identifier(tableName)} (${sql.join(columnsSql, sql`, `)}) VALUES (${sql.join(vals, sql`, `)}) ON CONFLICT (id) DO NOTHING`
          );
        }
        insertedCount += batch.length;
      } catch (insertErr) {
        result.errors.push(`Failed to insert batch starting at index ${i}: ${String(insertErr)}`);
      }
    }

    result.rehydrated = insertedCount;
    result.manifests = [manifest];

    log.info("Cold storage rehydration complete", {
      orgId,
      dataType,
      batchId,
      records: records.length,
      inserted: insertedCount,
    });
  } catch (err) {
    const msg = `Rehydration failed for ${orgId}/${dataType}/${batchId}: ${String(err)}`;
    log.error(msg);
    result.errors.push(msg);
  }

  return result;
}

export interface DeletionRequest {
  orgId: string;
  dataType: DataType;
  reason: string;
  requestedBy: string;
  olderThanDays?: number;
  specificIds?: string[];
  dryRun?: boolean;
}

export interface DeletionResult {
  deleted: number;
  dryRun: boolean;
  dataType: DataType;
  orgId: string;
  reason: string;
  auditLogId?: string;
  errors: string[];
}

export async function hasLegalHold(orgId: string): Promise<boolean> {
  try {
    const result = await db.execute(
      sql`SELECT id FROM legal_holds WHERE org_id = ${orgId} AND status = 'active' AND (expires_at IS NULL OR expires_at > NOW()) LIMIT 1`
    );
    return ((result as any).rows || []).length > 0;
  } catch (err) {
    const errMsg = String(err);
    if (errMsg.includes('relation "legal_holds" does not exist') || errMsg.includes("does not exist")) {
      log.debug("legal_holds table does not exist — no holds enforced");
      return false;
    }
    log.error("Failed to check legal holds — treating as held for safety", { orgId, error: errMsg });
    return true;
  }
}

export async function executeDeletion(request: DeletionRequest): Promise<DeletionResult> {
  const result: DeletionResult = {
    deleted: 0,
    dryRun: request.dryRun || false,
    dataType: request.dataType,
    orgId: request.orgId,
    reason: request.reason,
    errors: [],
  };

  const holdActive = await hasLegalHold(request.orgId);
  if (holdActive) {
    result.errors.push("Legal hold is active for this organization — deletion blocked");
    return result;
  }

  const tableName = validateTableName(request.dataType);

  try {
    if (request.specificIds && request.specificIds.length > 0) {
      const countResult = await db.execute(
        sql`SELECT COUNT(*) as count FROM ${sql.identifier(tableName)} WHERE org_id = ${request.orgId} AND id = ANY(${request.specificIds})`
      );
      const recordCount = Number(((countResult as any).rows || [])[0]?.count || 0);

      if (request.dryRun) {
        result.deleted = recordCount;
        return result;
      }

      const deleteResult = await db.execute(
        sql`DELETE FROM ${sql.identifier(tableName)} WHERE org_id = ${request.orgId} AND id = ANY(${request.specificIds})`
      );
      result.deleted = Number(deleteResult.rowCount) || 0;
    } else if (request.olderThanDays) {
      const cutoff = new Date();
      cutoff.setDate(cutoff.getDate() - request.olderThanDays);
      const countResult = await db.execute(
        sql`SELECT COUNT(*) as count FROM ${sql.identifier(tableName)} WHERE org_id = ${request.orgId} AND created_at < ${cutoff}`
      );
      const recordCount = Number(((countResult as any).rows || [])[0]?.count || 0);

      if (request.dryRun) {
        result.deleted = recordCount;
        return result;
      }

      let totalDeleted = 0;
      let batchDeleted = 0;
      do {
        const batchResult = await db.execute(
          sql`DELETE FROM ${sql.identifier(tableName)} WHERE id IN (SELECT id FROM ${sql.identifier(tableName)} WHERE org_id = ${request.orgId} AND created_at < ${cutoff} LIMIT ${BATCH_SIZE})`
        );
        batchDeleted = Number(batchResult.rowCount) || 0;
        totalDeleted += batchDeleted;
      } while (batchDeleted >= BATCH_SIZE);

      result.deleted = totalDeleted;
    } else {
      result.errors.push("Must specify either specificIds or olderThanDays");
      return result;
    }

    try {
      const auditEntry = await storage.createAuditLog({
        orgId: request.orgId,
        userId: request.requestedBy,
        userName: "Data Lifecycle",
        action: "data_deletion",
        resourceType: request.dataType,
        details: {
          dataType: request.dataType,
          reason: request.reason,
          deleted: result.deleted,
          olderThanDays: request.olderThanDays,
          specificIdCount: request.specificIds?.length,
          podId: getPodId(),
        },
      });
      result.auditLogId = auditEntry.id;
    } catch (auditErr) {
      log.error("Failed to create audit log for deletion", { error: String(auditErr) });
    }

    log.info("Data deletion complete", {
      orgId: request.orgId,
      dataType: request.dataType,
      deleted: result.deleted,
      reason: request.reason,
    });
  } catch (err) {
    const msg = `Deletion failed for ${request.orgId}/${request.dataType}: ${String(err)}`;
    log.error(msg);
    result.errors.push(msg);
  }

  return result;
}

export interface LifecycleStatusEntry {
  dataType: DataType;
  hotCount: number;
  warmCount: number;
  coldArchives: number;
  retentionPolicy: RetentionPolicy;
}

export async function getLifecycleStatus(orgId: string, plan: PlanTier): Promise<LifecycleStatusEntry[]> {
  const entries: LifecycleStatusEntry[] = [];
  const policies = getRetentionPolicies(plan);

  for (const policy of policies) {
    const tableName = validateTableName(policy.dataType);
    const warmCutoff = new Date();
    warmCutoff.setDate(warmCutoff.getDate() - policy.hotDays);

    try {
      const [hotResult, warmResult] = await Promise.all([
        db.execute(
          sql`SELECT COUNT(*) as count FROM ${sql.identifier(tableName)} WHERE org_id = ${orgId} AND created_at >= ${warmCutoff}`
        ),
        db.execute(
          sql`SELECT COUNT(*) as count FROM ${sql.identifier(tableName)} WHERE org_id = ${orgId} AND created_at < ${warmCutoff}`
        ),
      ]);

      const hotCount = Number(((hotResult as any).rows || [])[0]?.count || 0);
      const warmCount = Number(((warmResult as any).rows || [])[0]?.count || 0);

      let coldArchives = 0;
      try {
        const prefix = s3ColdStoragePrefix(orgId, policy.dataType);
        const files = await listFiles(prefix);
        coldArchives = files.filter((f) => f.key?.endsWith(".manifest.json")).length;
      } catch {
        coldArchives = 0;
      }

      entries.push({
        dataType: policy.dataType,
        hotCount,
        warmCount,
        coldArchives,
        retentionPolicy: policy,
      });
    } catch (err) {
      log.warn("Failed to get lifecycle status for data type", { dataType: policy.dataType, error: String(err) });
      entries.push({
        dataType: policy.dataType,
        hotCount: 0,
        warmCount: 0,
        coldArchives: 0,
        retentionPolicy: policy,
      });
    }
  }

  return entries;
}

export interface TieredCleanupResult {
  orgId: string;
  results: Array<{
    dataType: DataType;
    exportedToS3: number;
    deletedFromDb: number;
    errors: string[];
  }>;
}

export async function runTieredCleanup(orgId: string, plan: PlanTier): Promise<TieredCleanupResult> {
  const policies = getRetentionPolicies(plan);
  const cleanupResult: TieredCleanupResult = { orgId, results: [] };

  const holdActive = await hasLegalHold(orgId);
  if (holdActive) {
    log.warn("Skipping tiered cleanup — legal hold active", { orgId });
    return cleanupResult;
  }

  for (const policy of policies) {
    const entry: TieredCleanupResult["results"][0] = {
      dataType: policy.dataType,
      exportedToS3: 0,
      deletedFromDb: 0,
      errors: [],
    };

    try {
      const warmCutoff = new Date();
      warmCutoff.setDate(warmCutoff.getDate() - policy.hotDays - policy.warmDays);

      const exportResult = await exportToColdStorage(orgId, policy.dataType, warmCutoff);
      entry.exportedToS3 = exportResult.exported;
      entry.errors.push(...exportResult.errors);

      if (exportResult.exported > 0 && exportResult.errors.length === 0) {
        const coldCutoff = new Date();
        coldCutoff.setDate(coldCutoff.getDate() - policy.hotDays - policy.warmDays);
        const tableName = validateTableName(policy.dataType);

        let totalDeleted = 0;
        let batchDeleted = 0;
        do {
          const batchResult = await db.execute(
            sql`DELETE FROM ${sql.identifier(tableName)} WHERE id IN (SELECT id FROM ${sql.identifier(tableName)} WHERE org_id = ${orgId} AND created_at < ${coldCutoff} LIMIT ${BATCH_SIZE})`
          );
          batchDeleted = Number(batchResult.rowCount) || 0;
          totalDeleted += batchDeleted;
        } while (batchDeleted >= BATCH_SIZE);

        entry.deletedFromDb = totalDeleted;
      }

      const deleteCutoff = new Date();
      deleteCutoff.setDate(deleteCutoff.getDate() - policy.hotDays - policy.warmDays - policy.coldDays);
      try {
        const prefix = s3ColdStoragePrefix(orgId, policy.dataType);
        const files = await listFiles(prefix);
        const manifestFiles = files.filter((f) => f.key?.endsWith(".manifest.json"));

        for (const file of manifestFiles) {
          if (!file.key) continue;
          try {
            const url = await getSignedUrl(file.key, 60);
            const resp = await fetch(url);
            if (!resp.ok) continue;
            const manifest = (await resp.json()) as ColdStorageManifest;
            const newestDate = new Date(manifest.newestRecord);
            if (newestDate < deleteCutoff) {
              await deleteFile(manifest.s3Key);
              await deleteFile(file.key);
              log.info("Deleted expired cold storage archive", { key: manifest.s3Key, orgId, dataType: policy.dataType });
            }
          } catch (archiveErr) {
            entry.errors.push(`Failed to clean cold archive ${file.key}: ${String(archiveErr)}`);
          }
        }
      } catch (coldErr) {
        entry.errors.push(`Failed to clean cold storage: ${String(coldErr)}`);
      }
    } catch (err) {
      entry.errors.push(`Tiered cleanup failed for ${policy.dataType}: ${String(err)}`);
    }

    cleanupResult.results.push(entry);
  }

  try {
    await storage.createAuditLog({
      orgId,
      userId: "system",
      userName: "Data Lifecycle",
      action: "tiered_cleanup",
      resourceType: "data_lifecycle",
      details: {
        plan,
        results: cleanupResult.results.map((r) => ({
          dataType: r.dataType,
          exportedToS3: r.exportedToS3,
          deletedFromDb: r.deletedFromDb,
          errorCount: r.errors.length,
        })),
        podId: getPodId(),
      },
    });
  } catch (auditErr) {
    log.error("Failed to create audit log for tiered cleanup", { error: String(auditErr) });
  }

  log.info("Tiered cleanup complete", {
    orgId,
    plan,
    summary: cleanupResult.results.map((r) => `${r.dataType}: exported=${r.exportedToS3} deleted=${r.deletedFromDb}`),
  });

  return cleanupResult;
}

export async function executeOrgDataPurge(
  orgId: string,
  requestedBy: string,
  reason: string,
  dryRun: boolean = true,
): Promise<{ purged: Record<DataType, number>; dryRun: boolean; errors: string[] }> {
  const holdActive = await hasLegalHold(orgId);
  if (holdActive) {
    return { purged: {} as Record<DataType, number>, dryRun, errors: ["Legal hold is active — purge blocked"] };
  }

  const allTypes: DataType[] = ["alerts", "incidents", "audit_logs", "sli_metrics", "jobs", "connector_job_runs", "outbox_events", "ingestion_logs"];
  const purged = {} as Record<DataType, number>;
  const errors: string[] = [];

  for (const dataType of allTypes) {
    const tableName = validateTableName(dataType);
    try {
      const countResult = await db.execute(
        sql`SELECT COUNT(*) as count FROM ${sql.identifier(tableName)} WHERE org_id = ${orgId}`
      );
      const recordCount = Number(((countResult as any).rows || [])[0]?.count || 0);

      if (dryRun) {
        purged[dataType] = recordCount;
      } else {
        let totalDeleted = 0;
        let batchDeleted = 0;
        do {
          const batchResult = await db.execute(
            sql`DELETE FROM ${sql.identifier(tableName)} WHERE id IN (SELECT id FROM ${sql.identifier(tableName)} WHERE org_id = ${orgId} LIMIT ${BATCH_SIZE})`
          );
          batchDeleted = Number(batchResult.rowCount) || 0;
          totalDeleted += batchDeleted;
        } while (batchDeleted >= BATCH_SIZE);
        purged[dataType] = totalDeleted;
      }
    } catch (err) {
      errors.push(`Failed to purge ${dataType}: ${String(err)}`);
      purged[dataType] = 0;
    }
  }

  if (!dryRun) {
    try {
      await storage.createAuditLog({
        orgId,
        userId: requestedBy,
        userName: "Data Lifecycle",
        action: "org_data_purge",
        resourceType: "data_lifecycle",
        details: { purged, reason, podId: getPodId() },
      });
    } catch (auditErr) {
      log.error("Failed to create audit log for org purge", { error: String(auditErr) });
    }
  }

  log.info("Org data purge " + (dryRun ? "(dry run)" : "(executed)"), { orgId, purged, reason });
  return { purged, dryRun, errors };
}

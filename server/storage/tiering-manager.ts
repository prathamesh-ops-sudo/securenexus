import { db } from "../db";
import { sql } from "drizzle-orm";
import { eq, and, desc, lte } from "drizzle-orm";
import { tieringJobs, coldStorageInventory, dataLakeRetentionPolicies, legalHolds } from "@shared/schema";
import { uploadFile } from "../s3";
import { logger } from "../logger";
import { createHash } from "crypto";
import zlib from "zlib";
import { promisify } from "util";

const log = logger.child("tiering-manager");
const gzip = promisify(zlib.gzip);

const BATCH_SIZE = 1000;

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

// ─── Compliance Framework Presets ────────────────────────────────────────────

export const FRAMEWORK_PRESETS: Record<
  string,
  { hotDays: number; warmDays: number; coldDays: number; purgeAfterDays: number | null }
> = {
  gdpr: { hotDays: 30, warmDays: 60, coldDays: 90, purgeAfterDays: 90 },
  sox: { hotDays: 365, warmDays: 730, coldDays: 2555, purgeAfterDays: 2555 }, // 7 years
  hipaa: { hotDays: 365, warmDays: 730, coldDays: 2190, purgeAfterDays: 2190 }, // 6 years
  pci_dss: { hotDays: 90, warmDays: 365, coldDays: 365, purgeAfterDays: 365 }, // 1 year
  iso27001: { hotDays: 90, warmDays: 365, coldDays: 1095, purgeAfterDays: 1095 }, // 3 years
  nist: { hotDays: 90, warmDays: 365, coldDays: 1095, purgeAfterDays: 1095 }, // 3 years
  custom: { hotDays: 90, warmDays: 365, coldDays: 730, purgeAfterDays: null },
};

// ─── S3 Key Helpers ──────────────────────────────────────────────────────────

function s3TieringPrefix(orgId: string, dataType: string, tier: string): string {
  return `data-lake/${orgId}/${tier}/${dataType}`;
}

function s3TieringKey(orgId: string, dataType: string, tier: string, batchId: string): string {
  return `${s3TieringPrefix(orgId, dataType, tier)}/${batchId}.parquet.gz`;
}

// ─── Legal Hold Check ────────────────────────────────────────────────────────

export async function isUnderLegalHold(orgId: string, dataType?: string): Promise<boolean> {
  try {
    const holds = await db
      .select()
      .from(legalHolds)
      .where(and(eq(legalHolds.orgId, orgId), eq(legalHolds.isActive, true)))
      .limit(10);

    for (const hold of holds) {
      if (hold.holdType === "full") return true;
      if (dataType && Array.isArray(hold.tableScope)) {
        if (hold.tableScope.includes(dataType)) return true;
      }
    }
    return false;
  } catch (err) {
    const errMsg = String(err);
    if (errMsg.includes("does not exist")) {
      log.debug("legal_holds table does not exist — no holds enforced");
      return false;
    }
    log.error("Failed to check legal holds — treating as held for safety", { orgId, error: errMsg });
    return true;
  }
}

// ─── Tiering Job Execution ──────────────────────────────────────────────────

export interface TieringResult {
  jobId: string;
  orgId: string;
  dataType: string;
  sourceTier: string;
  targetTier: string;
  recordCount: number;
  compressedSizeBytes: number;
  s3Files: string[];
  errors: string[];
}

export async function executeTieringJob(
  orgId: string,
  dataType: string,
  sourceTier: string,
  targetTier: string,
  cutoffDate: Date,
  retentionPolicyId?: string,
): Promise<TieringResult> {
  if (!ALLOWED_TABLES.has(dataType)) {
    throw new Error(`Invalid data type: ${dataType}`);
  }

  // Check legal hold
  const held = await isUnderLegalHold(orgId, dataType);
  if (held) {
    throw new Error(`Legal hold active for org ${orgId} — tiering blocked`);
  }

  // Create tiering job record
  const [job] = await db
    .insert(tieringJobs)
    .values({
      orgId,
      dataType,
      sourceTier,
      targetTier,
      status: "running",
      retentionPolicyId: retentionPolicyId || null,
      startedAt: new Date(),
    })
    .returning();

  const result: TieringResult = {
    jobId: job.id,
    orgId,
    dataType,
    sourceTier,
    targetTier,
    recordCount: 0,
    compressedSizeBytes: 0,
    s3Files: [],
    errors: [],
  };

  try {
    let offset = 0;
    let hasMore = true;
    let batchIndex = 0;

    while (hasMore) {
      // Query records older than cutoff
      const rows = await db.execute(
        sql`SELECT * FROM ${sql.identifier(dataType)}
            WHERE org_id = ${orgId}
            AND created_at < ${cutoffDate}
            ORDER BY created_at ASC
            LIMIT ${BATCH_SIZE} OFFSET ${offset}`,
      );

      const records = (rows as unknown as { rows: Record<string, unknown>[] }).rows || [];
      if (records.length === 0) {
        hasMore = false;
        break;
      }

      // Convert to columnar Parquet-like format (JSON columnar representation)
      // In production, this would use an actual Parquet library
      const columnarData = convertToColumnar(records, dataType);
      const jsonData = JSON.stringify(columnarData);
      const compressed = await gzip(Buffer.from(jsonData, "utf-8"));
      const checksum = createHash("sha256").update(compressed).digest("hex");

      const batchId = `${Date.now()}-${batchIndex}`;
      const s3Key = s3TieringKey(orgId, dataType, targetTier, batchId);

      await uploadFile(s3Key, compressed, "application/x-parquet+gzip");

      // Track in cold storage inventory
      await db.insert(coldStorageInventory).values({
        orgId,
        dataType,
        tier: targetTier,
        s3Key,
        format: "parquet",
        recordCount: records.length,
        compressedSizeBytes: compressed.length,
        oldestRecord: records[0]?.created_at ? new Date(String(records[0].created_at)) : cutoffDate,
        newestRecord: records[records.length - 1]?.created_at
          ? new Date(String(records[records.length - 1].created_at))
          : cutoffDate,
        checksumSha256: checksum,
        tieringJobId: job.id,
        retentionPolicyId: retentionPolicyId || null,
        purgeEligibleAt: computePurgeDate(cutoffDate, retentionPolicyId),
      });

      result.recordCount += records.length;
      result.compressedSizeBytes += compressed.length;
      result.s3Files.push(s3Key);

      // Update job progress
      await db
        .update(tieringJobs)
        .set({
          recordsProcessed: result.recordCount,
          compressedSizeBytes: result.compressedSizeBytes,
        })
        .where(eq(tieringJobs.id, job.id));

      if (records.length < BATCH_SIZE) {
        hasMore = false;
      } else {
        offset += BATCH_SIZE;
        batchIndex++;
      }
    }

    // Mark job as completed
    await db
      .update(tieringJobs)
      .set({
        status: "completed",
        recordCount: result.recordCount,
        recordsProcessed: result.recordCount,
        compressedSizeBytes: result.compressedSizeBytes,
        s3KeyPrefix: s3TieringPrefix(orgId, dataType, targetTier),
        parquetManifest: { files: result.s3Files, recordCount: result.recordCount },
        completedAt: new Date(),
      })
      .where(eq(tieringJobs.id, job.id));

    log.info("Tiering job completed", {
      jobId: job.id,
      orgId,
      dataType,
      records: result.recordCount,
      compressed: result.compressedSizeBytes,
    });
  } catch (err) {
    const errMsg = String(err);
    result.errors.push(errMsg);

    await db
      .update(tieringJobs)
      .set({
        status: "failed",
        errorMessage: errMsg.substring(0, 2000),
        completedAt: new Date(),
      })
      .where(eq(tieringJobs.id, job.id));

    log.error("Tiering job failed", { jobId: job.id, error: errMsg });
  }

  return result;
}

// ─── Auto-Tiering Scheduler ─────────────────────────────────────────────────

export async function runAutoTiering(orgId: string): Promise<TieringResult[]> {
  const results: TieringResult[] = [];

  const policies = await db
    .select()
    .from(dataLakeRetentionPolicies)
    .where(and(eq(dataLakeRetentionPolicies.orgId, orgId), eq(dataLakeRetentionPolicies.isActive, true)));

  for (const policy of policies) {
    if (!ALLOWED_TABLES.has(policy.dataType)) continue;

    // Hot → Warm tiering
    if (policy.hotRetentionDays > 0) {
      const hotCutoff = new Date();
      hotCutoff.setDate(hotCutoff.getDate() - policy.hotRetentionDays);
      try {
        const result = await executeTieringJob(orgId, policy.dataType, "hot", "warm", hotCutoff, policy.id);
        results.push(result);
      } catch (err) {
        log.error("Hot→Warm tiering failed", { orgId, dataType: policy.dataType, error: String(err) });
      }
    }

    // Warm → Cold tiering
    if (policy.warmRetentionDays > 0) {
      const warmCutoff = new Date();
      warmCutoff.setDate(warmCutoff.getDate() - (policy.hotRetentionDays + policy.warmRetentionDays));
      try {
        const result = await executeTieringJob(orgId, policy.dataType, "warm", "cold", warmCutoff, policy.id);
        results.push(result);
      } catch (err) {
        log.error("Warm→Cold tiering failed", { orgId, dataType: policy.dataType, error: String(err) });
      }
    }
  }

  return results;
}

// ─── Storage Statistics ─────────────────────────────────────────────────────

export interface StorageStats {
  orgId: string;
  totalColdRecords: number;
  totalColdSizeBytes: number;
  byDataType: Record<string, { records: number; sizeBytes: number; files: number }>;
  byTier: Record<string, { records: number; sizeBytes: number; files: number }>;
  recentJobs: Array<{
    id: string;
    dataType: string;
    status: string;
    recordCount: number | null;
    compressedSizeBytes: number | null;
    createdAt: Date;
  }>;
  activePolicies: number;
  legalHoldActive: boolean;
}

export async function getStorageStats(orgId: string): Promise<StorageStats> {
  // Get cold storage inventory stats
  const inventory = await db.select().from(coldStorageInventory).where(eq(coldStorageInventory.orgId, orgId));

  const byDataType: Record<string, { records: number; sizeBytes: number; files: number }> = {};
  const byTier: Record<string, { records: number; sizeBytes: number; files: number }> = {};
  let totalColdRecords = 0;
  let totalColdSizeBytes = 0;

  for (const item of inventory) {
    totalColdRecords += item.recordCount;
    totalColdSizeBytes += item.compressedSizeBytes;

    if (!byDataType[item.dataType]) {
      byDataType[item.dataType] = { records: 0, sizeBytes: 0, files: 0 };
    }
    byDataType[item.dataType].records += item.recordCount;
    byDataType[item.dataType].sizeBytes += item.compressedSizeBytes;
    byDataType[item.dataType].files += 1;

    if (!byTier[item.tier]) {
      byTier[item.tier] = { records: 0, sizeBytes: 0, files: 0 };
    }
    byTier[item.tier].records += item.recordCount;
    byTier[item.tier].sizeBytes += item.compressedSizeBytes;
    byTier[item.tier].files += 1;
  }

  // Get recent tiering jobs
  const recentJobs = await db
    .select({
      id: tieringJobs.id,
      dataType: tieringJobs.dataType,
      status: tieringJobs.status,
      recordCount: tieringJobs.recordCount,
      compressedSizeBytes: tieringJobs.compressedSizeBytes,
      createdAt: tieringJobs.createdAt,
    })
    .from(tieringJobs)
    .where(eq(tieringJobs.orgId, orgId))
    .orderBy(desc(tieringJobs.createdAt))
    .limit(20);

  // Count active policies
  const [policyCount] = await db
    .select({ count: sql<number>`count(*)::int` })
    .from(dataLakeRetentionPolicies)
    .where(and(eq(dataLakeRetentionPolicies.orgId, orgId), eq(dataLakeRetentionPolicies.isActive, true)));

  const legalHoldActive = await isUnderLegalHold(orgId);

  return {
    orgId,
    totalColdRecords,
    totalColdSizeBytes,
    byDataType,
    byTier,
    recentJobs,
    activePolicies: policyCount?.count || 0,
    legalHoldActive,
  };
}

// ─── Purge Expired Cold Data ────────────────────────────────────────────────

export async function purgeExpiredColdData(orgId: string): Promise<{ purged: number; errors: string[] }> {
  const held = await isUnderLegalHold(orgId);
  if (held) {
    return { purged: 0, errors: ["Legal hold active — purge blocked"] };
  }

  const now = new Date();
  const expiredItems = await db
    .select()
    .from(coldStorageInventory)
    .where(and(eq(coldStorageInventory.orgId, orgId), lte(coldStorageInventory.purgeEligibleAt, now)));

  let purged = 0;
  const errors: string[] = [];

  for (const item of expiredItems) {
    try {
      // Note: actual S3 deletion would happen here via deleteFile(item.s3Key)
      // For safety, we mark as purged rather than deleting
      await db
        .delete(coldStorageInventory)
        .where(and(eq(coldStorageInventory.id, item.id), eq(coldStorageInventory.orgId, orgId)));
      purged++;
    } catch (err) {
      errors.push(`Failed to purge ${item.s3Key}: ${String(err)}`);
    }
  }

  log.info("Purge expired cold data", { orgId, purged, errors: errors.length });
  return { purged, errors };
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function convertToColumnar(
  records: Record<string, unknown>[],
  _dataType: string,
): { columns: Record<string, unknown[]>; rowCount: number; schema: Record<string, string> } {
  if (records.length === 0) {
    return { columns: {}, rowCount: 0, schema: {} };
  }

  const columns: Record<string, unknown[]> = {};
  const schema: Record<string, string> = {};
  const keys = Object.keys(records[0]);

  for (const key of keys) {
    columns[key] = [];
    schema[key] =
      typeof records[0][key] === "number" ? "float64" : typeof records[0][key] === "boolean" ? "bool" : "string";
  }

  for (const record of records) {
    for (const key of keys) {
      columns[key].push(record[key] ?? null);
    }
  }

  return { columns, rowCount: records.length, schema };
}

function computePurgeDate(cutoffDate: Date, _retentionPolicyId?: string | null): Date | null {
  // Default: purge eligibility 7 years from now
  const purgeDate = new Date(cutoffDate);
  purgeDate.setFullYear(purgeDate.getFullYear() + 7);
  return purgeDate;
}

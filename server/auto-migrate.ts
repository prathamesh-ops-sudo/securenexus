/**
 * Startup auto-migration: ensures all expected columns exist in the database.
 *
 * Drizzle ORM's `SELECT *` queries fail hard when the schema references a
 * column that hasn't been added to the physical table yet.  Rather than
 * requiring an out-of-band migration step (which needs VPC access to RDS),
 * we run idempotent `ALTER TABLE … ADD COLUMN IF NOT EXISTS` statements on
 * every boot.  PostgreSQL treats these as no-ops when the columns already
 * exist, so there is zero risk of data loss or duplication.
 *
 * When new columns are added to `shared/schema.ts`, a corresponding entry
 * should be added here so that deployments to environments where migrations
 * haven't been run yet will self-heal automatically.
 */

import { pool } from "./db";
import { logger } from "./logger";

const log = logger.child("auto-migrate");

/**
 * Each entry is a single `ALTER TABLE … ADD COLUMN IF NOT EXISTS` statement.
 * Keep the list append-only — never remove entries, since older environments
 * may still be missing the columns.
 */
const MISSING_COLUMN_STATEMENTS: string[] = [
  // ── alerts ────────────────────────────────────────────────────────────
  `ALTER TABLE "alerts" ADD COLUMN IF NOT EXISTS "occurrence_count" integer DEFAULT 1`,
  `ALTER TABLE "alerts" ADD COLUMN IF NOT EXISTS "last_seen_at" timestamp`,

  // ── alerts_archive ────────────────────────────────────────────────────
  `ALTER TABLE "alerts_archive" ADD COLUMN IF NOT EXISTS "occurrence_count" integer DEFAULT 1`,
  `ALTER TABLE "alerts_archive" ADD COLUMN IF NOT EXISTS "last_seen_at" timestamp`,

  // ── api_keys (migration 0004) ─────────────────────────────────────────
  `ALTER TABLE "api_keys" ADD COLUMN IF NOT EXISTS "deprecated_at" timestamp`,
  `ALTER TABLE "api_keys" ADD COLUMN IF NOT EXISTS "grace_expires_at" timestamp`,
  `ALTER TABLE "api_keys" ADD COLUMN IF NOT EXISTS "replaced_by_key_id" varchar`,

  // ── incidents (migration 0005) ────────────────────────────────────────
  `ALTER TABLE "incidents" ADD COLUMN IF NOT EXISTS "needs_review" boolean DEFAULT false`,
  `ALTER TABLE "incidents" ADD COLUMN IF NOT EXISTS "algorithm_scores" jsonb`,
];

/**
 * Full CREATE TABLE statements for tables that may not exist yet.
 * These run before column migrations so that ALTER TABLE statements
 * referencing these tables don't fail.
 */
const MISSING_TABLE_STATEMENTS: string[] = [
  // ── collector_instances ───────────────────────────────────────────────
  `CREATE TABLE IF NOT EXISTS "collector_instances" (
    "id" varchar PRIMARY KEY DEFAULT gen_random_uuid(),
    "org_id" varchar NOT NULL REFERENCES "organizations"("id"),
    "template_slug" text NOT NULL,
    "name" text NOT NULL,
    "status" text NOT NULL DEFAULT 'pending_install',
    "platform" text NOT NULL,
    "deployment_method" text NOT NULL,
    "config" jsonb DEFAULT '{}',
    "host_info" jsonb,
    "metrics" jsonb DEFAULT '{"eventsPerSecond":0,"bytesIngested":0,"errorsLast24h":0,"uptimePercent":0,"latencyP50Ms":0,"latencyP99Ms":0,"lastEventCount":0,"totalEventsIngested":0}',
    "version" text DEFAULT '1.0.0',
    "tags" text[] DEFAULT ARRAY[]::text[],
    "last_heartbeat_at" timestamp,
    "last_data_at" timestamp,
    "installed_at" timestamp DEFAULT now(),
    "created_at" timestamp DEFAULT now(),
    "updated_at" timestamp DEFAULT now()
  )`,

  // ── collector_events ──────────────────────────────────────────────────
  `CREATE TABLE IF NOT EXISTS "collector_events" (
    "id" varchar PRIMARY KEY DEFAULT gen_random_uuid(),
    "collector_id" varchar NOT NULL REFERENCES "collector_instances"("id") ON DELETE CASCADE,
    "org_id" varchar NOT NULL REFERENCES "organizations"("id"),
    "event_type" text NOT NULL,
    "severity" text NOT NULL DEFAULT 'info',
    "source" text NOT NULL,
    "timestamp" timestamp DEFAULT now(),
    "raw_data" jsonb DEFAULT '{}',
    "parsed_fields" jsonb DEFAULT '{}',
    "tags" text[] DEFAULT ARRAY[]::text[],
    "processed" boolean NOT NULL DEFAULT false,
    "created_at" timestamp DEFAULT now()
  )`,

  // ── collector_scans ───────────────────────────────────────────────────
  `CREATE TABLE IF NOT EXISTS "collector_scans" (
    "id" varchar PRIMARY KEY DEFAULT gen_random_uuid(),
    "collector_id" varchar NOT NULL REFERENCES "collector_instances"("id") ON DELETE CASCADE,
    "org_id" varchar NOT NULL REFERENCES "organizations"("id"),
    "scan_type" text NOT NULL,
    "status" text NOT NULL DEFAULT 'running',
    "targets" text[] DEFAULT ARRAY[]::text[],
    "findings" jsonb DEFAULT '[]',
    "summary" jsonb DEFAULT '{}',
    "started_at" timestamp DEFAULT now(),
    "completed_at" timestamp,
    "created_at" timestamp DEFAULT now()
  )`,
];

export async function runAutoMigrations(): Promise<void> {
  const startMs = Date.now();
  let applied = 0;
  let skipped = 0;

  // Phase 1: Create missing tables (must run before column migrations)
  for (const stmt of MISSING_TABLE_STATEMENTS) {
    try {
      await pool.query(stmt);
      applied++;
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      log.error("Auto-migration CREATE TABLE failed", { stmt: stmt.slice(0, 80), error: msg });
    }
  }

  // Phase 2: Add missing columns to existing tables
  for (const stmt of MISSING_COLUMN_STATEMENTS) {
    try {
      await pool.query(stmt);
      applied++;
    } catch (err: unknown) {
      // If a table doesn't exist yet (e.g. first-ever deploy), skip
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes("does not exist")) {
        skipped++;
        log.debug("Skipped migration (table not present)", { stmt: stmt.slice(0, 80) });
      } else {
        log.error("Auto-migration statement failed", { stmt, error: msg });
      }
    }
  }

  const elapsed = Date.now() - startMs;
  log.info("Auto-migration complete", { applied, skipped, elapsedMs: elapsed });
}

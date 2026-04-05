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

export async function runAutoMigrations(): Promise<void> {
  const startMs = Date.now();
  let applied = 0;
  let skipped = 0;

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

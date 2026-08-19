import { drizzle } from "drizzle-orm/node-postgres";
import { migrate } from "drizzle-orm/node-postgres/migrator";
import { resolve } from "node:path";
import { pool } from "./db";
import { logger } from "./logger";

const log = logger.child("startup-migrations");
const MIGRATION_LOCK_KEY = "securenexus:migrations";
const PRODUCTION_ENVIRONMENTS = new Set(["production", "staging", "uat"]);

function isEnabled(): boolean {
  const override = process.env.MIGRATE_ON_STARTUP?.trim().toLowerCase();
  if (override === "true" || override === "1") return true;
  if (override === "false" || override === "0") return false;
  return PRODUCTION_ENVIRONMENTS.has((process.env.NODE_ENV || "development").toLowerCase());
}

export async function runStartupMigrations(): Promise<void> {
  if (!isEnabled()) {
    log.info("Startup migrations disabled", { environment: process.env.NODE_ENV || "development" });
    return;
  }

  const migrationsFolder = process.env.MIGRATIONS_FOLDER
    ? resolve(process.env.MIGRATIONS_FOLDER)
    : resolve(process.cwd(), "migrations");
  const client = await pool.connect();
  let lockHeld = false;
  try {
    log.info("Applying startup migrations", { migrationsFolder });
    await client.query("SELECT pg_advisory_lock(hashtextextended($1, 0))", [MIGRATION_LOCK_KEY]);
    lockHeld = true;
    const before = await client
      .query<{
        created_at: string;
      }>('SELECT "created_at"::text AS created_at FROM "drizzle"."__drizzle_migrations" ORDER BY "created_at"')
      .catch(() => ({ rows: [] as { created_at: string }[] }));
    await migrate(drizzle(client), { migrationsFolder });
    const after = await client.query<{ created_at: string }>(
      'SELECT "created_at"::text AS created_at FROM "drizzle"."__drizzle_migrations" ORDER BY "created_at"',
    );
    log.info("Startup migrations complete", {
      applied: Math.max(0, (after.rowCount ?? 0) - before.rows.length),
      total: after.rowCount ?? 0,
    });
  } finally {
    if (lockHeld) await client.query("SELECT pg_advisory_unlock(hashtextextended($1, 0))", [MIGRATION_LOCK_KEY]);
    client.release();
  }
}

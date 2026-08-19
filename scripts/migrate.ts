/* eslint-disable no-console -- migration CLI reports connection and migration status directly to stdout */
import { drizzle } from "drizzle-orm/node-postgres";
import { migrate } from "drizzle-orm/node-postgres/migrator";
import { readMigrationFiles } from "drizzle-orm/migrator";
import pg from "pg";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const { Pool } = pg;

const MIGRATIONS_FOLDER = "./migrations";
const MIGRATIONS_SCHEMA = "drizzle";
const MIGRATIONS_TABLE = "__drizzle_migrations";
const MIGRATION_LOCK_KEY = "securenexus:migrations";
const MINIMUM_BASELINE_TABLES = 10;

interface MigrateOptions {
  dryRun: boolean;
  baselineOnly: boolean;
}

async function runMigrations(opts: MigrateOptions): Promise<void> {
  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) {
    console.error("DATABASE_URL environment variable is required");
    process.exit(1);
  }

  const pool = new Pool({
    connectionString: databaseUrl,
    max: 1,
    application_name: "securenexus-migrator",
    statement_timeout: 120_000,
  });

  try {
    const versionResult = await pool.query("SELECT version() AS ver");
    console.log(`Connected to: ${(versionResult.rows[0] as { ver: string }).ver}`);

    if (opts.baselineOnly) {
      const tableCountResult = await pool.query(`
        SELECT COUNT(*) AS total
        FROM information_schema.tables
        WHERE table_schema = 'public'
          AND table_type = 'BASE TABLE'
      `);
      const publicTableCount = Number((tableCountResult.rows[0] as { total: string }).total);
      if (publicTableCount < MINIMUM_BASELINE_TABLES) {
        throw new Error(
          `Refusing --baseline-only: found ${publicTableCount} public tables; at least ${MINIMUM_BASELINE_TABLES} are required`,
        );
      }

      const migrations = readMigrationFiles({ migrationsFolder: MIGRATIONS_FOLDER });
      if (migrations.length !== 1) {
        throw new Error(`Expected exactly one baseline migration, found ${migrations.length}`);
      }
      const [baseline] = migrations;
      const journal = JSON.parse(readFileSync(join(MIGRATIONS_FOLDER, "meta", "_journal.json"), "utf8")) as {
        entries: Array<{ tag: string; when: number }>;
      };
      const baselineTag =
        journal.entries.find((entry) => entry.when === baseline.folderMillis)?.tag ||
        `baseline-${baseline.folderMillis}`;

      await pool.query(`CREATE SCHEMA IF NOT EXISTS "${MIGRATIONS_SCHEMA}"`);
      await pool.query(`
        CREATE TABLE IF NOT EXISTS "${MIGRATIONS_SCHEMA}"."${MIGRATIONS_TABLE}" (
          id SERIAL PRIMARY KEY,
          hash text NOT NULL,
          created_at bigint
        )
      `);

      const existingBaseline = await pool.query(
        `SELECT id FROM "${MIGRATIONS_SCHEMA}"."${MIGRATIONS_TABLE}" WHERE hash = $1 LIMIT 1`,
        [baseline.hash],
      );
      if (existingBaseline.rowCount === 0) {
        await pool.query(
          `INSERT INTO "${MIGRATIONS_SCHEMA}"."${MIGRATIONS_TABLE}" (hash, created_at) VALUES ($1, $2)`,
          [baseline.hash, baseline.folderMillis],
        );
        console.log(
          `Baseline stamped: ${baselineTag} (${baseline.hash}; created_at ${new Date(baseline.folderMillis).toISOString()}; ${publicTableCount} public tables detected)`,
        );
      } else {
        console.log(
          `Baseline already stamped: ${baselineTag} (${baseline.hash}; ${publicTableCount} public tables detected; no SQL executed)`,
        );
      }
      return;
    }

    if (opts.dryRun) {
      console.log("\n[DRY RUN] Checking pending migrations...");
      console.log(`Migrations folder: ${MIGRATIONS_FOLDER}`);

      const journalCheck = await pool.query(
        `
        SELECT EXISTS (
          SELECT FROM information_schema.tables
          WHERE table_schema = $1
          AND table_name = $2
        ) AS exists
      `,
        [MIGRATIONS_SCHEMA, MIGRATIONS_TABLE],
      );
      const hasTable = (journalCheck.rows[0] as { exists: boolean }).exists;

      if (hasTable) {
        const countResult = await pool.query(
          `SELECT COUNT(*) AS total FROM "${MIGRATIONS_SCHEMA}"."${MIGRATIONS_TABLE}"`,
        );
        const totalApplied = (countResult.rows[0] as { total: string }).total;
        const applied = await pool.query(
          `SELECT hash, created_at FROM "${MIGRATIONS_SCHEMA}"."${MIGRATIONS_TABLE}" ORDER BY created_at DESC LIMIT 10`,
        );
        console.log(`\nApplied migrations: ${totalApplied}`);
        for (const row of applied.rows as { hash: string; created_at: string }[]) {
          console.log(`  - ${row.hash} (applied ${new Date(Number(row.created_at)).toISOString()})`);
        }
      } else {
        console.log("\nNo migrations have been applied yet (fresh database).");
      }

      console.log("\n[DRY RUN] No changes applied.");
      return;
    }

    console.log("\nApplying migrations...");
    const client = await pool.connect();
    try {
      await client.query("SELECT pg_advisory_lock(hashtextextended($1, 0))", [MIGRATION_LOCK_KEY]);
      await migrate(drizzle(client), { migrationsFolder: MIGRATIONS_FOLDER });
      await client.query("SELECT pg_advisory_unlock(hashtextextended($1, 0))", [MIGRATION_LOCK_KEY]);
    } finally {
      client.release();
    }
    console.log("Migrations applied successfully.");
  } catch (err) {
    console.error("Migration failed:", err);
    process.exit(1);
  } finally {
    await pool.end();
  }
}

const args = process.argv.slice(2);
const dryRun = args.includes("--dry-run");
const baselineOnly = args.includes("--baseline-only");

runMigrations({ dryRun, baselineOnly });

import { drizzle } from "drizzle-orm/node-postgres";
import { migrate } from "drizzle-orm/node-postgres/migrator";
import pg from "pg";

const { Pool } = pg;

const MIGRATIONS_FOLDER = "./migrations";

interface MigrateOptions {
  dryRun: boolean;
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

    if (opts.dryRun) {
      console.log("\n[DRY RUN] Checking pending migrations...");
      console.log(`Migrations folder: ${MIGRATIONS_FOLDER}`);

      const journalCheck = await pool.query(`
        SELECT EXISTS (
          SELECT FROM information_schema.tables
          WHERE table_schema = 'public'
          AND table_name = '__drizzle_migrations'
        ) AS exists
      `);
      const hasTable = (journalCheck.rows[0] as { exists: boolean }).exists;

      if (hasTable) {
        const countResult = await pool.query("SELECT COUNT(*) AS total FROM __drizzle_migrations");
        const totalApplied = (countResult.rows[0] as { total: string }).total;
        const applied = await pool.query(
          "SELECT hash, created_at FROM __drizzle_migrations ORDER BY created_at DESC LIMIT 10",
        );
        console.log(`\nApplied migrations: ${totalApplied}`);
        for (const row of applied.rows as { hash: string; created_at: number }[]) {
          console.log(`  - ${row.hash} (applied ${new Date(row.created_at).toISOString()})`);
        }
      } else {
        console.log("\nNo migrations have been applied yet (fresh database).");
      }

      console.log("\n[DRY RUN] No changes applied.");
      return;
    }

    console.log("\nApplying migrations...");
    const db = drizzle(pool);
    await migrate(db, { migrationsFolder: MIGRATIONS_FOLDER });
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

runMigrations({ dryRun });

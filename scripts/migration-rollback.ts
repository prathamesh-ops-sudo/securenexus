import pg from "pg";

const { Pool } = pg;

async function rollbackLastMigration(): Promise<void> {
  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) {
    console.error("DATABASE_URL environment variable is required");
    process.exit(1);
  }

  const pool = new Pool({
    connectionString: databaseUrl,
    max: 1,
    application_name: "securenexus-rollback",
    statement_timeout: 120_000,
  });

  try {
    const tableCheck = await pool.query(`
      SELECT EXISTS (
        SELECT FROM information_schema.tables
        WHERE table_schema = 'public'
        AND table_name = '__drizzle_migrations'
      ) AS exists
    `);

    if (!(tableCheck.rows[0] as { exists: boolean }).exists) {
      console.error("No migrations table found. Nothing to roll back.");
      process.exit(1);
    }

    const lastMigration = await pool.query(
      "SELECT id, hash, created_at FROM __drizzle_migrations ORDER BY created_at DESC LIMIT 1",
    );

    if (lastMigration.rowCount === 0) {
      console.log("No migrations to roll back.");
      return;
    }

    const last = lastMigration.rows[0] as { id: number; hash: string; created_at: number };
    console.log(`Last applied migration:`);
    console.log(`  ID: ${last.id}`);
    console.log(`  Hash: ${last.hash}`);
    console.log(`  Applied: ${new Date(last.created_at).toISOString()}`);

    const args = process.argv.slice(2);
    if (!args.includes("--confirm")) {
      console.log("\nThis will remove the migration record from __drizzle_migrations.");
      console.log("You must manually revert the DDL changes (DROP TABLE, ALTER TABLE, etc.).");
      console.log("Re-run with --confirm to proceed, or use the SQL rollback file.");
      console.log("\nSafe rollback process:");
      console.log("  1. Review the migration SQL file in ./migrations/");
      console.log("  2. Write inverse DDL statements (DROP what was CREATEd, etc.)");
      console.log("  3. Execute inverse DDL in a transaction");
      console.log("  4. Run this script with --confirm to remove the migration record");
      return;
    }

    await pool.query("DELETE FROM __drizzle_migrations WHERE id = $1", [last.id]);
    console.log(`\nMigration record ${last.hash} removed from __drizzle_migrations.`);
    console.log("Remember to manually revert the DDL changes if not already done.");
  } catch (err) {
    console.error("Rollback failed:", err);
    process.exit(1);
  } finally {
    await pool.end();
  }
}

rollbackLastMigration();

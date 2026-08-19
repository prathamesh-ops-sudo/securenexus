/* eslint-disable no-console -- CLI operator output is intentionally written to stdout. */
import { DEFAULT_SUPER_ADMIN_EMAIL, provisionPlatformSuperAdmin } from "../server/bootstrap-super-admin";
import { pool } from "../server/db";

async function main(): Promise<void> {
  const email = (process.env.SUPER_ADMIN_EMAIL || DEFAULT_SUPER_ADMIN_EMAIL).trim().toLowerCase();
  const password = process.env.SUPER_ADMIN_PASSWORD;

  if (email !== DEFAULT_SUPER_ADMIN_EMAIL) {
    throw new Error(`SUPER_ADMIN_EMAIL must be ${DEFAULT_SUPER_ADMIN_EMAIL}`);
  }
  if (!password) {
    throw new Error("SUPER_ADMIN_PASSWORD is required");
  }

  const result = await provisionPlatformSuperAdmin({ email, password });
  console.log(`Platform super-admin ${result.action}: ${email}`);
  console.log("The account must change its password before normal platform use.");
}

main()
  .catch((error: unknown) => {
    console.error(`Platform super-admin bootstrap failed: ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 1;
  })
  .finally(async () => {
    await pool.end();
  });

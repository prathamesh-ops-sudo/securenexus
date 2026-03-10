import { db } from "./db";
import { users } from "@shared/schema";
import { eq } from "drizzle-orm";
import { logger } from "./logger";

const log = logger.child("bootstrap-super-admin");

export async function bootstrapSuperAdmin(): Promise<void> {
  const email = process.env.SUPER_ADMIN_EMAIL?.trim().toLowerCase();
  if (!email) return;

  try {
    const [user] = await db.select().from(users).where(eq(users.email, email)).limit(1);
    if (!user) {
      log.warn("SUPER_ADMIN_EMAIL user not found — will promote on next login", { email });
      return;
    }

    if (user.isSuperAdmin) {
      log.info("Super admin already bootstrapped", { email, userId: user.id });
      return;
    }

    await db.update(users).set({ isSuperAdmin: true, updatedAt: new Date() }).where(eq(users.id, user.id));

    log.info("User promoted to super admin via SUPER_ADMIN_EMAIL", {
      email,
      userId: user.id,
    });
  } catch (err) {
    log.error("Failed to bootstrap super admin", { email, error: String(err) });
  }
}

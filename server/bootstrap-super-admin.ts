import { db } from "./db";
import { users } from "@shared/schema";
import { eq } from "drizzle-orm";
import { logger } from "./logger";

const log = logger.child("bootstrap-super-admin");

/**
 * Returns the set of emails that should always be super-admin.
 * Sources: SUPER_ADMIN_EMAIL env var + hardcoded platform owner.
 */
function getSuperAdminEmails(): Set<string> {
  const emails = new Set<string>();
  const envEmail = process.env.SUPER_ADMIN_EMAIL?.trim().toLowerCase();
  if (envEmail) emails.add(envEmail);
  // Platform owner — always super-admin regardless of env var
  emails.add("prathamesh@aricatech.com");
  return emails;
}

export async function bootstrapSuperAdmin(): Promise<void> {
  const superAdminEmails = getSuperAdminEmails();
  if (superAdminEmails.size === 0) return;

  for (const email of Array.from(superAdminEmails)) {
    try {
      const [user] = await db.select().from(users).where(eq(users.email, email)).limit(1);
      if (!user) {
        log.warn("Super-admin email user not found — will promote on next login", { email });
        continue;
      }

      if (user.isSuperAdmin) {
        log.info("Super admin already bootstrapped", { email, userId: user.id });
        continue;
      }

      await db.update(users).set({ isSuperAdmin: true, updatedAt: new Date() }).where(eq(users.id, user.id));

      log.info("User promoted to super admin", {
        email,
        userId: user.id,
      });
    } catch (err) {
      log.error("Failed to bootstrap super admin", { email, error: String(err) });
    }
  }
}

/**
 * Called during login/deserialize to auto-promote a user to super-admin
 * if their email matches SUPER_ADMIN_EMAIL or the hardcoded platform owner.
 * Returns true if the user was promoted (caller should refresh user object).
 */
export async function checkAndPromoteSuperAdmin(userId: string, email: string | null): Promise<boolean> {
  if (!email) return false;
  const normalizedEmail = email.trim().toLowerCase();
  const superAdminEmails = getSuperAdminEmails();
  if (!superAdminEmails.has(normalizedEmail)) return false;

  try {
    const [user] = await db.select().from(users).where(eq(users.id, userId)).limit(1);
    if (!user || user.isSuperAdmin) return false;

    await db.update(users).set({ isSuperAdmin: true, updatedAt: new Date() }).where(eq(users.id, userId));
    log.info("User auto-promoted to super admin on login", { email: normalizedEmail, userId });
    return true;
  } catch (err) {
    log.error("Failed to auto-promote super admin on login", { email: normalizedEmail, userId, error: String(err) });
    return false;
  }
}

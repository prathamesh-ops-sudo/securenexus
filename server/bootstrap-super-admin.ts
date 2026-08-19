import { db } from "./db";
import { users } from "@shared/schema";
import { eq } from "drizzle-orm";
import { logger } from "./logger";
import { authStorage } from "./auth/storage";
import { createAuditLog } from "./storage/audit";
import { hashPassword } from "./auth/password";

const log = logger.child("bootstrap-super-admin");
export const DEFAULT_SUPER_ADMIN_EMAIL = "prathamesh@aricatech.com";

export interface BootstrapSuperAdminDependencies {
  getUserByEmail: typeof authStorage.getUserByEmail;
  upsertUser: typeof authStorage.upsertUser;
  createAuditLog: typeof createAuditLog;
}

export interface BootstrapSuperAdminInput {
  email: string;
  password: string;
  passwordHash?: string;
}

export function validateBootstrapPassword(password: string): string[] {
  if (!password) return ["SUPER_ADMIN_PASSWORD is required"];
  if (password.length < 8) return ["Password must be at least 8 characters"];
  return [];
}

export async function provisionPlatformSuperAdmin(
  input: BootstrapSuperAdminInput,
  dependencies: BootstrapSuperAdminDependencies = {
    getUserByEmail: authStorage.getUserByEmail.bind(authStorage),
    upsertUser: authStorage.upsertUser.bind(authStorage),
    createAuditLog,
  },
): Promise<{ action: "created" | "repaired"; user: Awaited<ReturnType<typeof authStorage.upsertUser>> }> {
  const email = input.email.trim().toLowerCase();
  if (email !== DEFAULT_SUPER_ADMIN_EMAIL) {
    throw new Error(`Bootstrap is restricted to ${DEFAULT_SUPER_ADMIN_EMAIL}`);
  }

  const passwordErrors = validateBootstrapPassword(input.password);
  if (passwordErrors.length > 0) {
    throw new Error(passwordErrors.join("; "));
  }

  const existingUser = await dependencies.getUserByEmail(email);
  const passwordHash = input.passwordHash ?? (await hashPassword(input.password));
  const user = await dependencies.upsertUser({
    ...(existingUser ?? {}),
    ...(existingUser?.id ? { id: existingUser.id } : {}),
    email,
    passwordHash,
    isSuperAdmin: true,
    disabledAt: null,
    passwordChangeRequired: true,
    passwordChangedAt: null,
    lockedUntil: null,
    failedLoginCount: 0,
    updatedAt: new Date(),
  });

  await dependencies.createAuditLog({
    userId: user.id,
    userName: email,
    action: "platform_super_admin_bootstrap",
    resourceType: "user",
    resourceId: user.id,
    details: {
      action: existingUser ? "repaired" : "created",
      passwordChangeRequired: true,
    },
  });

  return { action: existingUser ? "repaired" : "created", user };
}

/**
 * Returns the set of emails that should always be super-admin.
 * Sources: SUPER_ADMIN_EMAIL env var + hardcoded platform owner.
 */
function getSuperAdminEmails(): Set<string> {
  const emails = new Set<string>();
  const envEmail = process.env.SUPER_ADMIN_EMAIL?.trim().toLowerCase();
  if (envEmail) emails.add(envEmail);
  // Platform owner — always super-admin regardless of env var
  emails.add(DEFAULT_SUPER_ADMIN_EMAIL);
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

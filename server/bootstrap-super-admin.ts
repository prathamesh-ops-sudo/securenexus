import { db } from "./db";
import { users } from "@shared/schema";
import { organizations, organizationMemberships, orgDomainVerifications } from "@shared/schema";
import { eq, and, sql } from "drizzle-orm";
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
  // Platform owners — always super-admin regardless of env var
  emails.add("prathamesh@aricatech.com");
  emails.add("kunal.dhonge@aricatech.com");
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
 * One-time bootstrap: ensure all @aricatech.com users share the same org
 * and that aricatech.com is set up as an auto-join domain.
 *
 * 1. Find prathamesh's org (the primary org).
 * 2. Move any @aricatech.com users from separate orgs into prathamesh's org.
 * 3. Register aricatech.com as a verified auto-join domain so future logins
 *    are placed into the correct org automatically.
 * 4. Clean up any now-empty orgs that were created by mistake.
 */
export async function bootstrapAricatechOrg(): Promise<void> {
  try {
    // Find prathamesh's org membership — that's the primary org
    const [prathameshUser] = await db.select().from(users).where(eq(users.email, "prathamesh@aricatech.com")).limit(1);
    if (!prathameshUser) {
      log.warn("prathamesh user not found — skipping org bootstrap");
      return;
    }

    const [prathameshMembership] = await db
      .select()
      .from(organizationMemberships)
      .where(eq(organizationMemberships.userId, prathameshUser.id))
      .limit(1);
    if (!prathameshMembership) {
      log.warn("prathamesh has no org membership — skipping org bootstrap");
      return;
    }

    const primaryOrgId = prathameshMembership.orgId;
    log.info("Primary org identified", { orgId: primaryOrgId });

    // Find Kunal and move him to the primary org if he's in a different one
    const [kunalUser] = await db.select().from(users).where(eq(users.email, "kunal.dhonge@aricatech.com")).limit(1);

    if (kunalUser) {
      const kunalMemberships = await db
        .select()
        .from(organizationMemberships)
        .where(eq(organizationMemberships.userId, kunalUser.id));

      const isInPrimaryOrg = kunalMemberships.some((m) => m.orgId === primaryOrgId);

      if (!isInPrimaryOrg) {
        // Remove Kunal from all other orgs
        const otherOrgIds = kunalMemberships.map((m) => m.orgId).filter((id) => id !== primaryOrgId);
        for (const oldOrgId of otherOrgIds) {
          await db
            .delete(organizationMemberships)
            .where(and(eq(organizationMemberships.userId, kunalUser.id), eq(organizationMemberships.orgId, oldOrgId)));
          log.info("Removed Kunal from old org", { oldOrgId });

          // Check if old org is now empty and delete it
          const [remaining] = await db
            .select({ count: sql<number>`count(*)` })
            .from(organizationMemberships)
            .where(eq(organizationMemberships.orgId, oldOrgId));
          if (remaining && Number(remaining.count) === 0) {
            await db.delete(organizations).where(eq(organizations.id, oldOrgId));
            log.info("Deleted empty org", { orgId: oldOrgId });
          }
        }

        // Add Kunal to the primary org as admin
        await db.insert(organizationMemberships).values({
          orgId: primaryOrgId,
          userId: kunalUser.id,
          role: "admin",
          status: "active",
          joinedAt: new Date(),
        });
        log.info("Kunal moved to primary org as admin", { orgId: primaryOrgId, userId: kunalUser.id });
      } else {
        log.info("Kunal already in primary org", { orgId: primaryOrgId });
      }
    }

    // Ensure aricatech.com is registered as a verified auto-join domain
    const [existingDomain] = await db
      .select()
      .from(orgDomainVerifications)
      .where(and(eq(orgDomainVerifications.orgId, primaryOrgId), eq(orgDomainVerifications.domain, "aricatech.com")));

    if (!existingDomain) {
      await db.insert(orgDomainVerifications).values({
        orgId: primaryOrgId,
        domain: "aricatech.com",
        verificationMethod: "admin_verified",
        verificationToken: "bootstrap-verified",
        status: "verified",
        verifiedAt: new Date(),
        autoJoin: true,
        defaultRole: "analyst",
        createdBy: prathameshUser.id,
      });
      log.info("Registered aricatech.com as verified auto-join domain", { orgId: primaryOrgId });
    } else if (existingDomain.status !== "verified" || !existingDomain.autoJoin) {
      await db
        .update(orgDomainVerifications)
        .set({ status: "verified", autoJoin: true, verifiedAt: new Date() })
        .where(eq(orgDomainVerifications.id, existingDomain.id));
      log.info("Updated aricatech.com domain to verified + auto-join", { orgId: primaryOrgId });
    } else {
      log.info("aricatech.com domain already configured", { orgId: primaryOrgId });
    }
  } catch (err) {
    log.error("Failed to bootstrap aricatech org", { error: String(err) });
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

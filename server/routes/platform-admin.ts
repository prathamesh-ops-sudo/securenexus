import type { Express, Request, Response } from "express";
import { sendEnvelope, storage } from "./shared";
import { isAuthenticated } from "../auth";
import { requireSuperAdmin } from "../middleware/super-admin";
import { db } from "../db";
import {
  users,
  organizations,
  alerts,
  incidents,
  auditLogs,
  subscriptions,
  plans,
  connectors,
  organizationMemberships,
  impersonationSessions,
} from "@shared/schema";
import { eq, desc, sql, and, count, ilike, or, isNull, gte, lte } from "drizzle-orm";
import { getPoolHealth, checkPoolConnectivity } from "../db";
import { logger } from "../logger";
import { randomBytes } from "crypto";

const log = logger.child("platform-admin");

const IMPERSONATION_TTL_MS = 60 * 60 * 1000;

export function registerPlatformAdminRoutes(app: Express): void {
  app.get("/api/platform-admin/stats", isAuthenticated, requireSuperAdmin, async (_req: Request, res: Response) => {
    try {
      const [orgCount] = await db.select({ value: count() }).from(organizations).where(isNull(organizations.deletedAt));
      const [userCount] = await db.select({ value: count() }).from(users);
      const [alertCount] = await db.select({ value: count() }).from(alerts);
      const [incidentCount] = await db.select({ value: count() }).from(incidents);
      const [activeSubCount] = await db
        .select({ value: count() })
        .from(subscriptions)
        .where(eq(subscriptions.status, "active"));

      const mrrResult = await db
        .select({
          totalMrr: sql<number>`COALESCE(SUM(CASE WHEN ${subscriptions.billingCycle} = 'monthly' THEN ${plans.monthlyPriceCents} WHEN ${subscriptions.billingCycle} = 'yearly' THEN ROUND(${plans.annualPriceCents}::numeric / 12) ELSE ${plans.monthlyPriceCents} END), 0)`,
        })
        .from(subscriptions)
        .innerJoin(plans, eq(subscriptions.planId, plans.id))
        .where(eq(subscriptions.status, "active"));

      const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
      const [newOrgsThisMonth] = await db
        .select({ value: count() })
        .from(organizations)
        .where(and(isNull(organizations.deletedAt), gte(organizations.createdAt, thirtyDaysAgo)));

      const [newUsersThisMonth] = await db
        .select({ value: count() })
        .from(users)
        .where(gte(users.createdAt, thirtyDaysAgo));

      return sendEnvelope(res, {
        totalOrgs: orgCount.value,
        totalUsers: userCount.value,
        totalAlerts: alertCount.value,
        totalIncidents: incidentCount.value,
        activeSubscriptions: activeSubCount.value,
        mrr: mrrResult[0]?.totalMrr ?? 0,
        newOrgsThisMonth: newOrgsThisMonth.value,
        newUsersThisMonth: newUsersThisMonth.value,
      });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "STATS_FAILED", message: "Failed to fetch platform stats", details: message }],
      });
    }
  });

  app.get(
    "/api/platform-admin/organizations",
    isAuthenticated,
    requireSuperAdmin,
    async (req: Request, res: Response) => {
      try {
        const limit = Math.min(Number(req.query.limit ?? 50) || 50, 200);
        const offset = Number(req.query.offset ?? 0) || 0;
        const search = typeof req.query.search === "string" ? req.query.search.trim() : undefined;
        const status = typeof req.query.status === "string" ? req.query.status : undefined;

        const conditions = [isNull(organizations.deletedAt)];
        if (search) {
          conditions.push(
            or(ilike(organizations.name, `%${search}%`), ilike(organizations.slug, `%${search}%`)) as any,
          );
        }
        if (status === "suspended") {
          conditions.push(sql`${organizations.deletedAt} IS NOT NULL`);
          conditions.splice(0, 1);
        }

        const whereClause = conditions.length > 1 ? and(...conditions) : conditions[0];

        const [totalResult] = await db.select({ value: count() }).from(organizations).where(whereClause);
        const items = await db
          .select()
          .from(organizations)
          .where(whereClause)
          .orderBy(desc(organizations.createdAt))
          .limit(limit)
          .offset(offset);

        const orgsWithDetails = await Promise.all(
          items.map(async (org) => {
            const [memberCount] = await db
              .select({ value: count() })
              .from(organizationMemberships)
              .where(and(eq(organizationMemberships.orgId, org.id), eq(organizationMemberships.status, "active")));
            const [alertCount] = await db.select({ value: count() }).from(alerts).where(eq(alerts.orgId, org.id));
            const sub = await db.select().from(subscriptions).where(eq(subscriptions.orgId, org.id)).limit(1);
            const plan = sub[0] ? await db.select().from(plans).where(eq(plans.id, sub[0].planId)).limit(1) : [];

            return {
              ...org,
              memberCount: memberCount.value,
              alertCount: alertCount.value,
              subscription: sub[0] || null,
              plan: plan[0] || null,
            };
          }),
        );

        return sendEnvelope(res, orgsWithDetails, {
          meta: { offset, limit, total: totalResult.value },
        });
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "ORGS_LIST_FAILED", message: "Failed to list organizations", details: message }],
        });
      }
    },
  );

  app.get(
    "/api/platform-admin/organizations/:id",
    isAuthenticated,
    requireSuperAdmin,
    async (req: Request, res: Response) => {
      try {
        const orgId = req.params.id;
        if (!orgId || typeof orgId !== "string" || orgId.length > 64) {
          return sendEnvelope(res, null, {
            status: 400,
            errors: [{ code: "INVALID_ID", message: "Invalid organization ID" }],
          });
        }

        const org = await storage.getOrganization(orgId);
        if (!org) {
          return sendEnvelope(res, null, {
            status: 404,
            errors: [{ code: "NOT_FOUND", message: "Organization not found" }],
          });
        }

        const members = await db
          .select({
            membership: organizationMemberships,
            user: users,
          })
          .from(organizationMemberships)
          .innerJoin(users, eq(organizationMemberships.userId, users.id))
          .where(eq(organizationMemberships.orgId, orgId));

        const sub = await db.select().from(subscriptions).where(eq(subscriptions.orgId, orgId)).limit(1);
        const plan = sub[0] ? await db.select().from(plans).where(eq(plans.id, sub[0].planId)).limit(1) : [];

        const [alertCount] = await db.select({ value: count() }).from(alerts).where(eq(alerts.orgId, orgId));
        const [incidentCount] = await db.select({ value: count() }).from(incidents).where(eq(incidents.orgId, orgId));
        const [connectorCount] = await db
          .select({ value: count() })
          .from(connectors)
          .where(eq(connectors.orgId, orgId));

        return sendEnvelope(res, {
          ...org,
          members: members.map((m) => ({
            ...m.membership,
            user: { id: m.user.id, email: m.user.email, firstName: m.user.firstName, lastName: m.user.lastName },
          })),
          subscription: sub[0] || null,
          plan: plan[0] || null,
          alertCount: alertCount.value,
          incidentCount: incidentCount.value,
          connectorCount: connectorCount.value,
        });
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "ORG_DETAIL_FAILED", message: "Failed to fetch organization details", details: message }],
        });
      }
    },
  );

  app.patch(
    "/api/platform-admin/organizations/:id",
    isAuthenticated,
    requireSuperAdmin,
    async (req: Request, res: Response) => {
      try {
        const orgId = req.params.id;
        if (!orgId || typeof orgId !== "string" || orgId.length > 64) {
          return sendEnvelope(res, null, {
            status: 400,
            errors: [{ code: "INVALID_ID", message: "Invalid organization ID" }],
          });
        }

        const allowedFields = ["name", "maxUsers", "industry", "companySize"];
        const updates: Record<string, unknown> = {};
        for (const field of allowedFields) {
          if (req.body[field] !== undefined) {
            updates[field] = req.body[field];
          }
        }

        if (Object.keys(updates).length === 0) {
          return sendEnvelope(res, null, {
            status: 400,
            errors: [{ code: "NO_UPDATES", message: "No valid fields to update" }],
          });
        }

        const updated = await storage.updateOrganization(orgId, updates as any);
        if (!updated) {
          return sendEnvelope(res, null, {
            status: 404,
            errors: [{ code: "NOT_FOUND", message: "Organization not found" }],
          });
        }

        await storage.createAuditLog({
          userId: (req as any).user.id,
          userName: (req as any).user.email,
          action: "platform_admin_org_update",
          resourceType: "organization",
          resourceId: orgId,
          details: { updates },
        });

        return sendEnvelope(res, updated);
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "ORG_UPDATE_FAILED", message: "Failed to update organization", details: message }],
        });
      }
    },
  );

  app.post(
    "/api/platform-admin/organizations/:id/suspend",
    isAuthenticated,
    requireSuperAdmin,
    async (req: Request, res: Response) => {
      try {
        const orgId = req.params.id;
        if (!orgId || typeof orgId !== "string" || orgId.length > 64) {
          return sendEnvelope(res, null, {
            status: 400,
            errors: [{ code: "INVALID_ID", message: "Invalid organization ID" }],
          });
        }

        const updated = await storage.softDeleteOrganization(orgId);
        if (!updated) {
          return sendEnvelope(res, null, {
            status: 404,
            errors: [{ code: "NOT_FOUND", message: "Organization not found" }],
          });
        }

        await storage.createAuditLog({
          userId: (req as any).user.id,
          userName: (req as any).user.email,
          action: "platform_admin_org_suspended",
          resourceType: "organization",
          resourceId: orgId,
        });

        return sendEnvelope(res, updated);
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "ORG_SUSPEND_FAILED", message: "Failed to suspend organization", details: message }],
        });
      }
    },
  );

  app.post(
    "/api/platform-admin/organizations/:id/activate",
    isAuthenticated,
    requireSuperAdmin,
    async (req: Request, res: Response) => {
      try {
        const orgId = req.params.id;
        if (!orgId || typeof orgId !== "string" || orgId.length > 64) {
          return sendEnvelope(res, null, {
            status: 400,
            errors: [{ code: "INVALID_ID", message: "Invalid organization ID" }],
          });
        }

        const updated = await storage.updateOrganization(orgId, { deletedAt: null } as any);
        if (!updated) {
          return sendEnvelope(res, null, {
            status: 404,
            errors: [{ code: "NOT_FOUND", message: "Organization not found" }],
          });
        }

        await storage.createAuditLog({
          userId: (req as any).user.id,
          userName: (req as any).user.email,
          action: "platform_admin_org_activated",
          resourceType: "organization",
          resourceId: orgId,
        });

        return sendEnvelope(res, updated);
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "ORG_ACTIVATE_FAILED", message: "Failed to activate organization", details: message }],
        });
      }
    },
  );

  app.get("/api/platform-admin/users", isAuthenticated, requireSuperAdmin, async (req: Request, res: Response) => {
    try {
      const limit = Math.min(Number(req.query.limit ?? 50) || 50, 200);
      const offset = Number(req.query.offset ?? 0) || 0;
      const search = typeof req.query.search === "string" ? req.query.search.trim() : undefined;
      const status = typeof req.query.status === "string" ? req.query.status : undefined;

      const conditions = [];
      if (search) {
        conditions.push(
          or(
            ilike(users.email, `%${search}%`),
            ilike(users.firstName, `%${search}%`),
            ilike(users.lastName, `%${search}%`),
          ),
        );
      }
      if (status === "disabled") {
        conditions.push(sql`${users.disabledAt} IS NOT NULL`);
      } else if (status === "active") {
        conditions.push(isNull(users.disabledAt));
      }

      const whereClause = conditions.length > 0 ? and(...conditions) : undefined;

      const [totalResult] = await db.select({ value: count() }).from(users).where(whereClause);
      const items = await db
        .select()
        .from(users)
        .where(whereClause)
        .orderBy(desc(users.createdAt))
        .limit(limit)
        .offset(offset);

      const usersWithOrgs = await Promise.all(
        items.map(async (user) => {
          const memberships = await db
            .select({
              membership: organizationMemberships,
              org: organizations,
            })
            .from(organizationMemberships)
            .innerJoin(organizations, eq(organizationMemberships.orgId, organizations.id))
            .where(eq(organizationMemberships.userId, user.id));

          return {
            id: user.id,
            email: user.email,
            firstName: user.firstName,
            lastName: user.lastName,
            profileImageUrl: user.profileImageUrl,
            isSuperAdmin: user.isSuperAdmin,
            disabledAt: user.disabledAt,
            lastLoginAt: user.lastLoginAt,
            createdAt: user.createdAt,
            organizations: memberships.map((m) => ({
              orgId: m.org.id,
              orgName: m.org.name,
              role: m.membership.role,
              status: m.membership.status,
            })),
          };
        }),
      );

      return sendEnvelope(res, usersWithOrgs, {
        meta: { offset, limit, total: totalResult.value },
      });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "USERS_LIST_FAILED", message: "Failed to list users", details: message }],
      });
    }
  });

  app.get("/api/platform-admin/users/:id", isAuthenticated, requireSuperAdmin, async (req: Request, res: Response) => {
    try {
      const userId = req.params.id;
      if (!userId || typeof userId !== "string" || userId.length > 64) {
        return sendEnvelope(res, null, {
          status: 400,
          errors: [{ code: "INVALID_ID", message: "Invalid user ID" }],
        });
      }

      const [user] = await db.select().from(users).where(eq(users.id, userId)).limit(1);
      if (!user) {
        return sendEnvelope(res, null, {
          status: 404,
          errors: [{ code: "NOT_FOUND", message: "User not found" }],
        });
      }

      const memberships = await db
        .select({
          membership: organizationMemberships,
          org: organizations,
        })
        .from(organizationMemberships)
        .innerJoin(organizations, eq(organizationMemberships.orgId, organizations.id))
        .where(eq(organizationMemberships.userId, userId));

      return sendEnvelope(res, {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        profileImageUrl: user.profileImageUrl,
        isSuperAdmin: user.isSuperAdmin,
        disabledAt: user.disabledAt,
        lastLoginAt: user.lastLoginAt,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,
        organizations: memberships.map((m) => ({
          ...m.membership,
          orgName: m.org.name,
          orgSlug: m.org.slug,
        })),
      });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "USER_DETAIL_FAILED", message: "Failed to fetch user details", details: message }],
      });
    }
  });

  app.post(
    "/api/platform-admin/users/:id/disable",
    isAuthenticated,
    requireSuperAdmin,
    async (req: Request, res: Response) => {
      try {
        const userId = req.params.id;
        if (!userId || typeof userId !== "string" || userId.length > 64) {
          return sendEnvelope(res, null, {
            status: 400,
            errors: [{ code: "INVALID_ID", message: "Invalid user ID" }],
          });
        }

        if (userId === (req as any).user.id) {
          return sendEnvelope(res, null, {
            status: 400,
            errors: [{ code: "SELF_DISABLE", message: "Cannot disable your own account" }],
          });
        }

        const [target] = await db.select().from(users).where(eq(users.id, userId)).limit(1);
        if (!target) {
          return sendEnvelope(res, null, {
            status: 404,
            errors: [{ code: "NOT_FOUND", message: "User not found" }],
          });
        }

        if (target.isSuperAdmin) {
          return sendEnvelope(res, null, {
            status: 403,
            errors: [{ code: "CANNOT_DISABLE_ADMIN", message: "Cannot disable another super-admin" }],
          });
        }

        const [updated] = await db
          .update(users)
          .set({ disabledAt: new Date(), updatedAt: new Date() })
          .where(eq(users.id, userId))
          .returning();

        await storage.createAuditLog({
          userId: (req as any).user.id,
          userName: (req as any).user.email,
          action: "platform_admin_user_disabled",
          resourceType: "user",
          resourceId: userId,
          details: { targetEmail: target.email },
        });

        return sendEnvelope(res, { id: updated.id, email: updated.email, disabledAt: updated.disabledAt });
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "USER_DISABLE_FAILED", message: "Failed to disable user", details: message }],
        });
      }
    },
  );

  app.post(
    "/api/platform-admin/users/:id/enable",
    isAuthenticated,
    requireSuperAdmin,
    async (req: Request, res: Response) => {
      try {
        const userId = req.params.id;
        if (!userId || typeof userId !== "string" || userId.length > 64) {
          return sendEnvelope(res, null, {
            status: 400,
            errors: [{ code: "INVALID_ID", message: "Invalid user ID" }],
          });
        }

        const [updated] = await db
          .update(users)
          .set({ disabledAt: null, updatedAt: new Date() })
          .where(eq(users.id, userId))
          .returning();

        if (!updated) {
          return sendEnvelope(res, null, {
            status: 404,
            errors: [{ code: "NOT_FOUND", message: "User not found" }],
          });
        }

        await storage.createAuditLog({
          userId: (req as any).user.id,
          userName: (req as any).user.email,
          action: "platform_admin_user_enabled",
          resourceType: "user",
          resourceId: userId,
          details: { targetEmail: updated.email },
        });

        return sendEnvelope(res, { id: updated.id, email: updated.email, disabledAt: null });
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "USER_ENABLE_FAILED", message: "Failed to enable user", details: message }],
        });
      }
    },
  );

  app.post(
    "/api/platform-admin/users/:id/force-password-reset",
    isAuthenticated,
    requireSuperAdmin,
    async (req: Request, res: Response) => {
      try {
        const userId = req.params.id;
        if (!userId || typeof userId !== "string" || userId.length > 64) {
          return sendEnvelope(res, null, {
            status: 400,
            errors: [{ code: "INVALID_ID", message: "Invalid user ID" }],
          });
        }

        const [target] = await db.select().from(users).where(eq(users.id, userId)).limit(1);
        if (!target) {
          return sendEnvelope(res, null, {
            status: 404,
            errors: [{ code: "NOT_FOUND", message: "User not found" }],
          });
        }

        await db.update(users).set({ passwordHash: null, updatedAt: new Date() }).where(eq(users.id, userId));

        await storage.createAuditLog({
          userId: (req as any).user.id,
          userName: (req as any).user.email,
          action: "platform_admin_force_password_reset",
          resourceType: "user",
          resourceId: userId,
          details: { targetEmail: target.email },
        });

        return sendEnvelope(res, { message: "Password has been reset. User must set a new password on next login." });
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "FORCE_RESET_FAILED", message: "Failed to force password reset", details: message }],
        });
      }
    },
  );

  app.get(
    "/api/platform-admin/subscriptions",
    isAuthenticated,
    requireSuperAdmin,
    async (req: Request, res: Response) => {
      try {
        const limit = Math.min(Number(req.query.limit ?? 50) || 50, 200);
        const offset = Number(req.query.offset ?? 0) || 0;
        const statusFilter = typeof req.query.status === "string" ? req.query.status : undefined;

        const conditions = [];
        if (statusFilter) {
          conditions.push(eq(subscriptions.status, statusFilter));
        }
        const whereClause = conditions.length > 0 ? and(...conditions) : undefined;

        const [totalResult] = await db.select({ value: count() }).from(subscriptions).where(whereClause);

        const items = await db
          .select({
            subscription: subscriptions,
            org: organizations,
            plan: plans,
          })
          .from(subscriptions)
          .innerJoin(organizations, eq(subscriptions.orgId, organizations.id))
          .innerJoin(plans, eq(subscriptions.planId, plans.id))
          .where(whereClause)
          .orderBy(desc(subscriptions.createdAt))
          .limit(limit)
          .offset(offset);

        return sendEnvelope(
          res,
          items.map((i) => ({
            ...i.subscription,
            orgName: i.org.name,
            orgSlug: i.org.slug,
            planName: i.plan.name,
            planPriceMonthly: i.plan.monthlyPriceCents,
          })),
          { meta: { offset, limit, total: totalResult.value } },
        );
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "SUBS_LIST_FAILED", message: "Failed to list subscriptions", details: message }],
        });
      }
    },
  );

  app.get("/api/platform-admin/revenue", isAuthenticated, requireSuperAdmin, async (_req: Request, res: Response) => {
    try {
      const planDistribution = await db
        .select({
          planName: plans.name,
          count: count(),
          monthlyPriceCents: plans.monthlyPriceCents,
          annualPriceCents: plans.annualPriceCents,
          billingCycle: subscriptions.billingCycle,
        })
        .from(subscriptions)
        .innerJoin(plans, eq(subscriptions.planId, plans.id))
        .where(eq(subscriptions.status, "active"))
        .groupBy(plans.name, plans.monthlyPriceCents, plans.annualPriceCents, subscriptions.billingCycle);

      const totalMrr = planDistribution.reduce((sum, p) => {
        const perSubMrr =
          p.billingCycle === "yearly" ? Math.round((p.annualPriceCents ?? 0) / 12) : (p.monthlyPriceCents ?? 0);
        return sum + perSubMrr * p.count;
      }, 0);

      const [cancelledCount] = await db
        .select({ value: count() })
        .from(subscriptions)
        .where(eq(subscriptions.status, "cancelled"));

      const [totalSubCount] = await db.select({ value: count() }).from(subscriptions);
      const churnRate = totalSubCount.value > 0 ? (cancelledCount.value / totalSubCount.value) * 100 : 0;

      return sendEnvelope(res, {
        mrr: totalMrr,
        arr: totalMrr * 12,
        planDistribution,
        churnRate: Math.round(churnRate * 100) / 100,
        totalSubscriptions: totalSubCount.value,
        cancelledSubscriptions: cancelledCount.value,
      });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "REVENUE_FAILED", message: "Failed to fetch revenue data", details: message }],
      });
    }
  });

  app.get("/api/platform-admin/audit-logs", isAuthenticated, requireSuperAdmin, async (req: Request, res: Response) => {
    try {
      const limit = Math.min(Number(req.query.limit ?? 50) || 50, 200);
      const offset = Number(req.query.offset ?? 0) || 0;
      const action = typeof req.query.action === "string" ? req.query.action : undefined;
      const userId = typeof req.query.userId === "string" ? req.query.userId : undefined;
      const orgId = typeof req.query.orgId === "string" ? req.query.orgId : undefined;
      const from = typeof req.query.from === "string" ? new Date(req.query.from) : undefined;
      const to = typeof req.query.to === "string" ? new Date(req.query.to) : undefined;

      const conditions = [];
      if (action) conditions.push(eq(auditLogs.action, action));
      if (userId) conditions.push(eq(auditLogs.userId, userId));
      if (orgId) conditions.push(eq(auditLogs.orgId, orgId));
      if (from) conditions.push(gte(auditLogs.createdAt, from));
      if (to) conditions.push(lte(auditLogs.createdAt, to));

      const whereClause = conditions.length > 0 ? and(...conditions) : undefined;

      const [totalResult] = await db.select({ value: count() }).from(auditLogs).where(whereClause);
      const items = await db
        .select()
        .from(auditLogs)
        .where(whereClause)
        .orderBy(desc(auditLogs.createdAt))
        .limit(limit)
        .offset(offset);

      return sendEnvelope(res, items, {
        meta: { offset, limit, total: totalResult.value },
      });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "AUDIT_LOGS_FAILED", message: "Failed to fetch audit logs", details: message }],
      });
    }
  });

  app.get("/api/platform-admin/health", isAuthenticated, requireSuperAdmin, async (_req: Request, res: Response) => {
    try {
      let dbStatus = "healthy";
      let dbLatencyMs = 0;
      try {
        const start = Date.now();
        await checkPoolConnectivity();
        dbLatencyMs = Date.now() - start;
      } catch {
        dbStatus = "unhealthy";
      }

      const poolHealth = getPoolHealth();

      return sendEnvelope(res, {
        rds: {
          status: dbStatus,
          latencyMs: dbLatencyMs,
          pool: poolHealth,
        },
        application: {
          status: "healthy",
          uptime: process.uptime(),
          memoryUsage: process.memoryUsage(),
          nodeVersion: process.version,
        },
        timestamp: new Date().toISOString(),
      });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "HEALTH_FAILED", message: "Failed to fetch health status", details: message }],
      });
    }
  });

  app.post(
    "/api/platform-admin/impersonate/:userId",
    isAuthenticated,
    requireSuperAdmin,
    async (req: Request, res: Response) => {
      try {
        const targetUserId = req.params.userId;
        if (!targetUserId || typeof targetUserId !== "string" || targetUserId.length > 64) {
          return sendEnvelope(res, null, {
            status: 400,
            errors: [{ code: "INVALID_ID", message: "Invalid user ID" }],
          });
        }

        const adminUser = (req as any).user;

        if (targetUserId === adminUser.id) {
          return sendEnvelope(res, null, {
            status: 400,
            errors: [{ code: "SELF_IMPERSONATE", message: "Cannot impersonate yourself" }],
          });
        }

        const [targetUser] = await db.select().from(users).where(eq(users.id, targetUserId)).limit(1);
        if (!targetUser) {
          return sendEnvelope(res, null, {
            status: 404,
            errors: [{ code: "NOT_FOUND", message: "Target user not found" }],
          });
        }

        if (targetUser.isSuperAdmin) {
          return sendEnvelope(res, null, {
            status: 403,
            errors: [{ code: "CANNOT_IMPERSONATE_ADMIN", message: "Cannot impersonate another super-admin" }],
          });
        }

        if (targetUser.disabledAt) {
          return sendEnvelope(res, null, {
            status: 400,
            errors: [{ code: "USER_DISABLED", message: "Cannot impersonate a disabled user" }],
          });
        }

        const sessionSid = `imp_${randomBytes(32).toString("hex")}`;
        const expiresAt = new Date(Date.now() + IMPERSONATION_TTL_MS);

        const [impSession] = await db
          .insert(impersonationSessions)
          .values({
            superAdminId: adminUser.id,
            targetUserId,
            sessionSid,
            expiresAt,
          })
          .returning();

        await storage.createAuditLog({
          userId: adminUser.id,
          userName: adminUser.email,
          action: "impersonation_started",
          resourceType: "user",
          resourceId: targetUserId,
          details: {
            targetEmail: targetUser.email,
            impersonationSessionId: impSession.id,
            expiresAt: expiresAt.toISOString(),
          },
        });

        log.info("Impersonation session created", {
          adminId: adminUser.id,
          targetUserId,
          impersonationId: impSession.id,
          expiresAt: expiresAt.toISOString(),
        });

        return sendEnvelope(res, {
          impersonationToken: sessionSid,
          targetUser: {
            id: targetUser.id,
            email: targetUser.email,
            firstName: targetUser.firstName,
            lastName: targetUser.lastName,
          },
          expiresAt: expiresAt.toISOString(),
        });
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "IMPERSONATE_FAILED", message: "Failed to create impersonation session", details: message }],
        });
      }
    },
  );

  app.post(
    "/api/platform-admin/impersonate/end",
    isAuthenticated,
    requireSuperAdmin,
    async (req: Request, res: Response) => {
      try {
        const { impersonationToken } = req.body;
        if (!impersonationToken || typeof impersonationToken !== "string") {
          return sendEnvelope(res, null, {
            status: 400,
            errors: [{ code: "MISSING_TOKEN", message: "Impersonation token is required" }],
          });
        }

        const [session] = await db
          .update(impersonationSessions)
          .set({ endedAt: new Date() })
          .where(and(eq(impersonationSessions.sessionSid, impersonationToken), isNull(impersonationSessions.endedAt)))
          .returning();

        if (!session) {
          return sendEnvelope(res, null, {
            status: 404,
            errors: [{ code: "NOT_FOUND", message: "Active impersonation session not found" }],
          });
        }

        await storage.createAuditLog({
          userId: session.superAdminId,
          userName: (req as any).user.email,
          action: "impersonation_ended",
          resourceType: "user",
          resourceId: session.targetUserId,
          details: { impersonationSessionId: session.id },
        });

        return sendEnvelope(res, { message: "Impersonation session ended" });
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "END_IMPERSONATE_FAILED", message: "Failed to end impersonation", details: message }],
        });
      }
    },
  );

  app.get(
    "/api/platform-admin/impersonate/validate",
    isAuthenticated,
    requireSuperAdmin,
    async (req: Request, res: Response) => {
      try {
        const token = typeof req.query.token === "string" ? req.query.token : undefined;
        if (!token) {
          return sendEnvelope(res, null, {
            status: 400,
            errors: [{ code: "MISSING_TOKEN", message: "Token query parameter is required" }],
          });
        }

        const [session] = await db
          .select()
          .from(impersonationSessions)
          .where(and(eq(impersonationSessions.sessionSid, token), isNull(impersonationSessions.endedAt)))
          .limit(1);

        if (!session || new Date(session.expiresAt) < new Date()) {
          return sendEnvelope(res, { valid: false });
        }

        const [targetUser] = await db.select().from(users).where(eq(users.id, session.targetUserId)).limit(1);

        return sendEnvelope(res, {
          valid: true,
          targetUser: targetUser
            ? {
                id: targetUser.id,
                email: targetUser.email,
                firstName: targetUser.firstName,
                lastName: targetUser.lastName,
              }
            : null,
          expiresAt: session.expiresAt,
        });
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "VALIDATE_FAILED", message: "Failed to validate impersonation", details: message }],
        });
      }
    },
  );

  app.get("/api/platform-admin/me", isAuthenticated, requireSuperAdmin, async (req: Request, res: Response) => {
    try {
      const user = (req as any).user;
      return sendEnvelope(res, {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        isSuperAdmin: user.isSuperAdmin,
      });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "ME_FAILED", message: "Failed to fetch admin info", details: message }],
      });
    }
  });
}

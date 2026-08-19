import type { Express } from "express";
import { eq, and, desc, sql, lt, isNull, or, like, count } from "drizzle-orm";
import { logger, getOrgId } from "./shared";
import { isAuthenticated } from "../auth";
import { resolveOrgContext, requireOrgId, requireMinRole } from "../rbac";

import { db } from "../db";
import {
  accessReviewCampaigns,
  accessReviewEntitlements,
  scimProvisioningLogs,
  identityRiskProfiles,
  identityAccessGraph,
  users,
  organizations,
  organizationMemberships,
} from "@shared/schema";

const log = logger.child("identity-governance");

export function registerIdentityGovernanceRoutes(app: Express): void {
  // =========================================================================
  // ACCESS REVIEW CAMPAIGNS
  // =========================================================================

  // List campaigns
  app.get("/api/identity/access-reviews", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const status = req.query.status ? String(req.query.status) : undefined;

      const conditions = [eq(accessReviewCampaigns.orgId, orgId)];
      if (status) {
        conditions.push(eq(accessReviewCampaigns.status, status));
      }

      const campaigns = await db
        .select()
        .from(accessReviewCampaigns)
        .where(and(...conditions))
        .orderBy(desc(accessReviewCampaigns.createdAt))
        .limit(100);

      res.json({ campaigns });
    } catch (error) {
      log.error("List access review campaigns error", { error: String(error) });
      res.status(500).json({ message: "Failed to list access review campaigns" });
    }
  });

  // Create campaign
  app.post(
    "/api/identity/access-reviews",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { name, description, cadence, reviewerUserId, reviewerName, dueDate } = req.body;

        if (!name || typeof name !== "string" || name.trim().length < 2) {
          return res.status(400).json({ message: "Campaign name is required (min 2 chars)" });
        }

        const validCadences = ["quarterly", "monthly", "annual", "one_time"];
        if (cadence && !validCadences.includes(cadence)) {
          return res.status(400).json({ message: `Invalid cadence. Valid: ${validCadences.join(", ")}` });
        }

        const [campaign] = await db
          .insert(accessReviewCampaigns)
          .values({
            orgId,
            name: String(name).trim(),
            description: typeof description === "string" ? description.trim() : null,
            cadence: cadence || "quarterly",
            reviewerUserId: typeof reviewerUserId === "string" ? reviewerUserId : null,
            reviewerName: typeof reviewerName === "string" ? reviewerName : null,
            dueDate: dueDate ? new Date(dueDate) : null,
            status: "draft",
          })
          .returning();

        res.status(201).json(campaign);
      } catch (error) {
        log.error("Create access review campaign error", { error: String(error) });
        res.status(500).json({ message: "Failed to create access review campaign" });
      }
    },
  );

  // Get campaign detail with entitlements
  app.get("/api/identity/access-reviews/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);

      const [campaign] = await db
        .select()
        .from(accessReviewCampaigns)
        .where(and(eq(accessReviewCampaigns.id, id), eq(accessReviewCampaigns.orgId, orgId)));

      if (!campaign) {
        return res.status(404).json({ message: "Campaign not found" });
      }

      const entitlements = await db
        .select()
        .from(accessReviewEntitlements)
        .where(and(eq(accessReviewEntitlements.campaignId, id), eq(accessReviewEntitlements.orgId, orgId)))
        .orderBy(desc(accessReviewEntitlements.createdAt));

      res.json({ campaign, entitlements });
    } catch (error) {
      log.error("Get access review campaign error", { error: String(error) });
      res.status(500).json({ message: "Failed to get access review campaign" });
    }
  });

  // Start campaign — auto-populates entitlements from org members
  app.post(
    "/api/identity/access-reviews/:id/start",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const id = String(req.params.id);

        const [campaign] = await db
          .select()
          .from(accessReviewCampaigns)
          .where(and(eq(accessReviewCampaigns.id, id), eq(accessReviewCampaigns.orgId, orgId)));

        if (!campaign) {
          return res.status(404).json({ message: "Campaign not found" });
        }
        if (campaign.status !== "draft") {
          return res.status(400).json({ message: "Campaign must be in draft status to start" });
        }

        // Auto-populate entitlements from org members (scoped to this org)
        const orgMemberRows = await db
          .select({ user: users })
          .from(users)
          .innerJoin(
            organizationMemberships,
            and(
              eq(organizationMemberships.userId, users.id),
              eq(organizationMemberships.orgId, orgId),
              eq(organizationMemberships.status, "active"),
            ),
          )
          .limit(500);

        const entitlementValues = orgMemberRows.map(({ user }) => ({
          orgId,
          campaignId: id,
          userId: user.id,
          userName: `${user.firstName || ""} ${user.lastName || ""}`.trim() || user.email || "Unknown",
          userEmail: user.email,
          entitlementType: "role" as const,
          entitlementName: user.isSuperAdmin ? "superadmin" : "analyst",
          entitlementDescription: user.isSuperAdmin ? "Full platform access" : "Standard analyst access",
          grantedAt: user.createdAt,
          lastUsedAt: user.lastLoginAt,
          riskLevel: user.isSuperAdmin ? "high" : "low",
          status: "pending" as const,
        }));

        if (entitlementValues.length > 0) {
          await db.insert(accessReviewEntitlements).values(entitlementValues);
        }

        const [updated] = await db
          .update(accessReviewCampaigns)
          .set({
            status: "active",
            startedAt: new Date(),
            totalEntitlements: entitlementValues.length,
            updatedAt: new Date(),
          })
          .where(and(eq(accessReviewCampaigns.id, id), eq(accessReviewCampaigns.orgId, orgId)))
          .returning();

        res.json({ campaign: updated, entitlementsCreated: entitlementValues.length });
      } catch (error) {
        log.error("Start access review campaign error", { error: String(error) });
        res.status(500).json({ message: "Failed to start campaign" });
      }
    },
  );

  // Decide on entitlement (approve/revoke)
  app.patch(
    "/api/identity/access-reviews/entitlements/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const id = String(req.params.id);
        const { decision, decisionReason } = req.body;

        if (!decision || !["approve", "revoke"].includes(decision)) {
          return res.status(400).json({ message: "decision must be 'approve' or 'revoke'" });
        }

        const [entitlement] = await db
          .select()
          .from(accessReviewEntitlements)
          .where(and(eq(accessReviewEntitlements.id, id), eq(accessReviewEntitlements.orgId, orgId)));

        if (!entitlement) {
          return res.status(404).json({ message: "Entitlement not found" });
        }

        const userId = (req as any).user?.id || "system";

        const [updated] = await db
          .update(accessReviewEntitlements)
          .set({
            status: decision === "approve" ? "approved" : "revoked",
            decision,
            decisionBy: userId,
            decisionAt: new Date(),
            decisionReason: typeof decisionReason === "string" ? decisionReason : null,
          })
          .where(and(eq(accessReviewEntitlements.id, id), eq(accessReviewEntitlements.orgId, orgId)))
          .returning();

        // Update campaign counters
        const campaignId = entitlement.campaignId;
        const [stats] = await db
          .select({
            reviewed: count(),
          })
          .from(accessReviewEntitlements)
          .where(
            and(
              eq(accessReviewEntitlements.campaignId, campaignId),
              eq(accessReviewEntitlements.orgId, orgId),
              or(eq(accessReviewEntitlements.status, "approved"), eq(accessReviewEntitlements.status, "revoked")),
            ),
          );

        const [approvedStats] = await db
          .select({ cnt: count() })
          .from(accessReviewEntitlements)
          .where(
            and(
              eq(accessReviewEntitlements.campaignId, campaignId),
              eq(accessReviewEntitlements.orgId, orgId),
              eq(accessReviewEntitlements.status, "approved"),
            ),
          );

        const [revokedStats] = await db
          .select({ cnt: count() })
          .from(accessReviewEntitlements)
          .where(
            and(
              eq(accessReviewEntitlements.campaignId, campaignId),
              eq(accessReviewEntitlements.orgId, orgId),
              eq(accessReviewEntitlements.status, "revoked"),
            ),
          );

        await db
          .update(accessReviewCampaigns)
          .set({
            reviewedCount: stats.reviewed,
            approvedCount: approvedStats.cnt,
            revokedCount: revokedStats.cnt,
            updatedAt: new Date(),
          })
          .where(and(eq(accessReviewCampaigns.id, campaignId), eq(accessReviewCampaigns.orgId, orgId)));

        res.json(updated);
      } catch (error) {
        log.error("Decide on entitlement error", { error: String(error) });
        res.status(500).json({ message: "Failed to update entitlement" });
      }
    },
  );

  // Complete campaign
  app.post(
    "/api/identity/access-reviews/:id/complete",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const id = String(req.params.id);

        const [campaign] = await db
          .select()
          .from(accessReviewCampaigns)
          .where(and(eq(accessReviewCampaigns.id, id), eq(accessReviewCampaigns.orgId, orgId)));

        if (!campaign) {
          return res.status(404).json({ message: "Campaign not found" });
        }
        if (campaign.status !== "active") {
          return res.status(400).json({ message: "Campaign must be active to complete" });
        }

        const [updated] = await db
          .update(accessReviewCampaigns)
          .set({
            status: "completed",
            completedAt: new Date(),
            updatedAt: new Date(),
          })
          .where(and(eq(accessReviewCampaigns.id, id), eq(accessReviewCampaigns.orgId, orgId)))
          .returning();

        res.json(updated);
      } catch (error) {
        log.error("Complete access review campaign error", { error: String(error) });
        res.status(500).json({ message: "Failed to complete campaign" });
      }
    },
  );

  // =========================================================================
  // SCIM 2.0 PROVISIONING
  // =========================================================================

  // SCIM provisioning logs
  app.get("/api/identity/scim/logs", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const provider = req.query.provider ? String(req.query.provider) : undefined;
      const operation = req.query.operation ? String(req.query.operation) : undefined;

      const conditions = [eq(scimProvisioningLogs.orgId, orgId)];
      if (provider) conditions.push(eq(scimProvisioningLogs.provider, provider));
      if (operation) conditions.push(eq(scimProvisioningLogs.operationType, operation));

      const logs = await db
        .select()
        .from(scimProvisioningLogs)
        .where(and(...conditions))
        .orderBy(desc(scimProvisioningLogs.createdAt))
        .limit(200);

      // Stats
      const [totalResult] = await db
        .select({ cnt: count() })
        .from(scimProvisioningLogs)
        .where(eq(scimProvisioningLogs.orgId, orgId));

      const [successResult] = await db
        .select({ cnt: count() })
        .from(scimProvisioningLogs)
        .where(and(eq(scimProvisioningLogs.orgId, orgId), eq(scimProvisioningLogs.success, true)));

      const [failResult] = await db
        .select({ cnt: count() })
        .from(scimProvisioningLogs)
        .where(and(eq(scimProvisioningLogs.orgId, orgId), eq(scimProvisioningLogs.success, false)));

      res.json({
        logs,
        stats: {
          total: totalResult.cnt,
          successful: successResult.cnt,
          failed: failResult.cnt,
        },
      });
    } catch (error) {
      log.error("Get SCIM logs error", { error: String(error) });
      res.status(500).json({ message: "Failed to get SCIM provisioning logs" });
    }
  });

  // SCIM webhook endpoint (Okta/Azure AD push to this)
  app.post(
    "/api/identity/scim/provision",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { provider, operationType, externalUserId, externalUserName, externalEmail, groupName, rawPayload } =
          req.body;

        const validProviders = ["azure_ad", "okta", "google_workspace", "onelogin", "jumpcloud"];
        if (!provider || !validProviders.includes(provider)) {
          return res.status(400).json({ message: `Invalid provider. Valid: ${validProviders.join(", ")}` });
        }

        const validOps = ["create", "update", "delete", "activate", "deactivate", "group_add", "group_remove"];
        if (!operationType || !validOps.includes(operationType)) {
          return res.status(400).json({ message: `Invalid operationType. Valid: ${validOps.join(", ")}` });
        }

        const [logEntry] = await db
          .insert(scimProvisioningLogs)
          .values({
            orgId,
            provider,
            operationType,
            externalUserId: typeof externalUserId === "string" ? externalUserId : null,
            externalUserName: typeof externalUserName === "string" ? externalUserName : null,
            externalEmail: typeof externalEmail === "string" ? externalEmail : null,
            groupName: typeof groupName === "string" ? groupName : null,
            success: true,
            rawPayload: rawPayload || null,
          })
          .returning();

        res.status(201).json(logEntry);
      } catch (error) {
        log.error("SCIM provision error", { error: String(error) });
        res.status(500).json({ message: "Failed to process SCIM provisioning" });
      }
    },
  );

  // =========================================================================
  // STALE ACCOUNT DETECTION
  // =========================================================================

  app.get("/api/identity/stale-accounts", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const thresholdDays = parseInt(String(req.query.days || "90"), 10);
      const safeThreshold = Number.isFinite(thresholdDays) && thresholdDays > 0 ? thresholdDays : 90;

      const profiles = await db
        .select()
        .from(identityRiskProfiles)
        .where(and(eq(identityRiskProfiles.orgId, orgId), eq(identityRiskProfiles.isStale, true)))
        .orderBy(desc(identityRiskProfiles.daysSinceActivity))
        .limit(200);

      // Also find users with no login in threshold days
      const cutoffDate = new Date(Date.now() - safeThreshold * 24 * 60 * 60 * 1000);
      const staleUsers = await db
        .select({
          id: users.id,
          email: users.email,
          firstName: users.firstName,
          lastName: users.lastName,
          lastLoginAt: users.lastLoginAt,
          createdAt: users.createdAt,
          mfaEnabled: users.mfaEnabled,
          disabledAt: users.disabledAt,
        })
        .from(users)
        .innerJoin(
          organizationMemberships,
          and(
            eq(organizationMemberships.userId, users.id),
            eq(organizationMemberships.orgId, orgId),
            eq(organizationMemberships.status, "active"),
          ),
        )
        .where(or(lt(users.lastLoginAt, cutoffDate), isNull(users.lastLoginAt)))
        .limit(200);

      const staleWithAge = staleUsers.map((u) => ({
        ...u,
        daysSinceActivity: u.lastLoginAt
          ? Math.floor((Date.now() - new Date(u.lastLoginAt).getTime()) / (1000 * 60 * 60 * 24))
          : u.createdAt
            ? Math.floor((Date.now() - new Date(u.createdAt).getTime()) / (1000 * 60 * 60 * 24))
            : 999,
        isDisabled: !!u.disabledAt,
      }));

      res.json({
        profiles,
        staleUsers: staleWithAge,
        thresholdDays: safeThreshold,
        totalStale: staleWithAge.length,
      });
    } catch (error) {
      log.error("Get stale accounts error", { error: String(error) });
      res.status(500).json({ message: "Failed to get stale accounts" });
    }
  });

  // =========================================================================
  // IDENTITY RISK PROFILES (Blast Radius + Lateral Movement)
  // =========================================================================

  // List risk profiles
  app.get("/api/identity/risk-profiles", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const riskLevel = req.query.riskLevel ? String(req.query.riskLevel) : undefined;
      const search = req.query.search ? String(req.query.search) : undefined;

      const conditions = [eq(identityRiskProfiles.orgId, orgId)];
      if (riskLevel) conditions.push(eq(identityRiskProfiles.riskLevel, riskLevel));
      if (search) {
        // Escape LIKE wildcards to prevent pattern manipulation
        const escapedSearch = search.replace(/%/g, "\\%").replace(/_/g, "\\_");
        conditions.push(
          or(
            like(identityRiskProfiles.userName, `%${escapedSearch}%`),
            like(identityRiskProfiles.userEmail, `%${escapedSearch}%`),
          )!,
        );
      }

      const profiles = await db
        .select()
        .from(identityRiskProfiles)
        .where(and(...conditions))
        .orderBy(desc(identityRiskProfiles.riskScore))
        .limit(200);

      // Summary stats
      const [totalResult] = await db
        .select({ cnt: count() })
        .from(identityRiskProfiles)
        .where(eq(identityRiskProfiles.orgId, orgId));

      const [criticalResult] = await db
        .select({ cnt: count() })
        .from(identityRiskProfiles)
        .where(and(eq(identityRiskProfiles.orgId, orgId), eq(identityRiskProfiles.riskLevel, "critical")));

      const [highResult] = await db
        .select({ cnt: count() })
        .from(identityRiskProfiles)
        .where(and(eq(identityRiskProfiles.orgId, orgId), eq(identityRiskProfiles.riskLevel, "high")));

      const [staleResult] = await db
        .select({ cnt: count() })
        .from(identityRiskProfiles)
        .where(and(eq(identityRiskProfiles.orgId, orgId), eq(identityRiskProfiles.isStale, true)));

      const [noMfaResult] = await db
        .select({ cnt: count() })
        .from(identityRiskProfiles)
        .where(and(eq(identityRiskProfiles.orgId, orgId), eq(identityRiskProfiles.mfaEnabled, false)));

      res.json({
        profiles,
        stats: {
          total: totalResult.cnt,
          critical: criticalResult.cnt,
          high: highResult.cnt,
          stale: staleResult.cnt,
          noMfa: noMfaResult.cnt,
        },
      });
    } catch (error) {
      log.error("List identity risk profiles error", { error: String(error) });
      res.status(500).json({ message: "Failed to list identity risk profiles" });
    }
  });

  // Assess identity risk (run assessment for a user)
  app.post(
    "/api/identity/risk-profiles/assess",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { userId, userName, userEmail } = req.body;

        if (!userId || typeof userId !== "string") {
          return res.status(400).json({ message: "userId is required" });
        }
        if (!userName || typeof userName !== "string") {
          return res.status(400).json({ message: "userName is required" });
        }

        // Look up the user's access graph for blast radius calculation
        const accessPaths = await db
          .select()
          .from(identityAccessGraph)
          .where(
            and(
              eq(identityAccessGraph.orgId, orgId),
              eq(identityAccessGraph.sourceUserId, userId),
              eq(identityAccessGraph.isActive, true),
            ),
          );

        const accessibleSystems = new Set(accessPaths.map((p) => p.targetSystem));
        const adminPaths = accessPaths.filter((p) => ["admin", "superadmin"].includes(p.permissionLevel));
        const canReachCritical = adminPaths.length > 0;

        // Calculate blast radius score (0-100)
        const blastRadiusScore = Math.min(100, accessibleSystems.size * 10 + adminPaths.length * 20);

        // Look up user record for stale detection
        const [userRecord] = await db.select().from(users).where(eq(users.id, userId)).limit(1);

        const daysSinceActivity = userRecord?.lastLoginAt
          ? Math.floor((Date.now() - new Date(userRecord.lastLoginAt).getTime()) / (1000 * 60 * 60 * 24))
          : 999;

        const isStale = daysSinceActivity > 90;
        const mfaEnabled = userRecord?.mfaEnabled ?? false;

        // Calculate overall risk score
        let riskScore = 0;
        if (isStale) riskScore += 25;
        if (!mfaEnabled) riskScore += 20;
        if (canReachCritical) riskScore += 30;
        riskScore += Math.min(25, blastRadiusScore / 4);

        const riskLevel = riskScore >= 80 ? "critical" : riskScore >= 60 ? "high" : riskScore >= 30 ? "medium" : "low";

        // Upsert the profile
        const existing = await db
          .select()
          .from(identityRiskProfiles)
          .where(and(eq(identityRiskProfiles.orgId, orgId), eq(identityRiskProfiles.userId, userId)))
          .limit(1);

        let profile;
        if (existing.length > 0) {
          [profile] = await db
            .update(identityRiskProfiles)
            .set({
              userName: String(userName),
              userEmail: typeof userEmail === "string" ? userEmail : null,
              riskLevel,
              riskScore,
              isStale,
              lastActivityAt: userRecord?.lastLoginAt || null,
              daysSinceActivity,
              isServiceAccount: false,
              blastRadiusScore,
              accessibleSystems: accessibleSystems.size,
              accessibleSecrets: 0,
              privilegedRoles: adminPaths.map((p) => p.grantedVia),
              lateralMovementPaths: accessPaths.length,
              canReachCritical,
              pivotPoints: accessPaths
                .filter((p) => ["admin", "superadmin"].includes(p.permissionLevel))
                .map((p) => p.targetSystem),
              mfaEnabled,
              hasExcessivePermissions: adminPaths.length > 3,
              failedLoginCount: userRecord?.failedLoginCount || 0,
              lastAssessedAt: new Date(),
              updatedAt: new Date(),
            })
            .where(and(eq(identityRiskProfiles.orgId, orgId), eq(identityRiskProfiles.userId, userId)))
            .returning();
        } else {
          [profile] = await db
            .insert(identityRiskProfiles)
            .values({
              orgId,
              userId: String(userId),
              userName: String(userName),
              userEmail: typeof userEmail === "string" ? userEmail : null,
              riskLevel,
              riskScore,
              isStale,
              lastActivityAt: userRecord?.lastLoginAt || null,
              daysSinceActivity,
              isServiceAccount: false,
              blastRadiusScore,
              accessibleSystems: accessibleSystems.size,
              accessibleSecrets: 0,
              privilegedRoles: adminPaths.map((p) => p.grantedVia),
              lateralMovementPaths: accessPaths.length,
              canReachCritical,
              pivotPoints: accessPaths
                .filter((p) => ["admin", "superadmin"].includes(p.permissionLevel))
                .map((p) => p.targetSystem),
              mfaEnabled,
              hasExcessivePermissions: adminPaths.length > 3,
              failedLoginCount: userRecord?.failedLoginCount || 0,
              lastAssessedAt: new Date(),
            })
            .returning();
        }

        res.json(profile);
      } catch (error) {
        log.error("Assess identity risk error", { error: String(error) });
        res.status(500).json({ message: "Failed to assess identity risk" });
      }
    },
  );

  // Blast radius for a specific user
  app.get("/api/identity/blast-radius/:userId", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const userId = String(req.params.userId);

      const accessPaths = await db
        .select()
        .from(identityAccessGraph)
        .where(
          and(
            eq(identityAccessGraph.orgId, orgId),
            eq(identityAccessGraph.sourceUserId, userId),
            eq(identityAccessGraph.isActive, true),
          ),
        );

      const [profile] = await db
        .select()
        .from(identityRiskProfiles)
        .where(and(eq(identityRiskProfiles.orgId, orgId), eq(identityRiskProfiles.userId, userId)));

      // Group by system
      const systemMap = new Map<
        string,
        { system: string; resources: string[]; maxPermission: string; riskWeight: number }
      >();
      for (const path of accessPaths) {
        const existing = systemMap.get(path.targetSystem);
        if (existing) {
          if (path.targetResource) existing.resources.push(path.targetResource);
          if (permissionRank(path.permissionLevel) > permissionRank(existing.maxPermission)) {
            existing.maxPermission = path.permissionLevel;
          }
          existing.riskWeight = Math.max(existing.riskWeight, path.riskWeight || 1);
        } else {
          systemMap.set(path.targetSystem, {
            system: path.targetSystem,
            resources: path.targetResource ? [path.targetResource] : [],
            maxPermission: path.permissionLevel,
            riskWeight: path.riskWeight || 1,
          });
        }
      }

      res.json({
        userId,
        profile: profile || null,
        accessPaths,
        systemBreakdown: Array.from(systemMap.values()),
        totalSystems: systemMap.size,
        totalPaths: accessPaths.length,
        criticalPaths: accessPaths.filter((p) => ["admin", "superadmin"].includes(p.permissionLevel)).length,
      });
    } catch (error) {
      log.error("Get blast radius error", { error: String(error) });
      res.status(500).json({ message: "Failed to get blast radius" });
    }
  });

  // =========================================================================
  // LATERAL MOVEMENT RISK GRAPH
  // =========================================================================

  // Get access graph
  app.get("/api/identity/access-graph", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const system = req.query.system ? String(req.query.system) : undefined;
      const userId = req.query.userId ? String(req.query.userId) : undefined;

      const conditions = [eq(identityAccessGraph.orgId, orgId), eq(identityAccessGraph.isActive, true)];
      if (system) conditions.push(eq(identityAccessGraph.targetSystem, system));
      if (userId) conditions.push(eq(identityAccessGraph.sourceUserId, userId));

      const edges = await db
        .select()
        .from(identityAccessGraph)
        .where(and(...conditions))
        .orderBy(desc(identityAccessGraph.riskWeight))
        .limit(500);

      // Extract unique users and systems for graph nodes
      const userNodes = new Map<string, { id: string; name: string; type: "user" }>();
      const systemNodes = new Map<string, { id: string; name: string; type: "system" }>();

      for (const edge of edges) {
        userNodes.set(edge.sourceUserId, { id: edge.sourceUserId, name: edge.sourceUserName, type: "user" });
        systemNodes.set(edge.targetSystem, { id: edge.targetSystem, name: edge.targetSystem, type: "system" });
      }

      res.json({
        nodes: [...Array.from(userNodes.values()), ...Array.from(systemNodes.values())],
        edges: edges.map((e) => ({
          id: e.id,
          source: e.sourceUserId,
          target: e.targetSystem,
          permissionLevel: e.permissionLevel,
          accessType: e.accessType,
          grantedVia: e.grantedVia,
          riskWeight: e.riskWeight,
          lastUsedAt: e.lastUsedAt,
        })),
        totalEdges: edges.length,
        totalUsers: userNodes.size,
        totalSystems: systemNodes.size,
      });
    } catch (error) {
      log.error("Get access graph error", { error: String(error) });
      res.status(500).json({ message: "Failed to get access graph" });
    }
  });

  // Add access graph edge
  app.post(
    "/api/identity/access-graph",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const {
          sourceUserId,
          sourceUserName,
          targetSystem,
          targetResource,
          accessType,
          permissionLevel,
          grantedVia,
          expiresAt,
        } = req.body;

        if (!sourceUserId || typeof sourceUserId !== "string") {
          return res.status(400).json({ message: "sourceUserId is required" });
        }
        if (!sourceUserName || typeof sourceUserName !== "string") {
          return res.status(400).json({ message: "sourceUserName is required" });
        }
        if (!targetSystem || typeof targetSystem !== "string") {
          return res.status(400).json({ message: "targetSystem is required" });
        }

        const validAccessTypes = ["direct", "inherited", "delegated"];
        if (!accessType || !validAccessTypes.includes(accessType)) {
          return res.status(400).json({ message: `accessType must be: ${validAccessTypes.join(", ")}` });
        }

        const validPermissions = ["read", "write", "admin", "superadmin"];
        if (!permissionLevel || !validPermissions.includes(permissionLevel)) {
          return res.status(400).json({ message: `permissionLevel must be: ${validPermissions.join(", ")}` });
        }

        const riskWeight =
          permissionLevel === "superadmin" ? 10 : permissionLevel === "admin" ? 7 : permissionLevel === "write" ? 4 : 1;

        const [edge] = await db
          .insert(identityAccessGraph)
          .values({
            orgId,
            sourceUserId: String(sourceUserId),
            sourceUserName: String(sourceUserName),
            targetSystem: String(targetSystem),
            targetResource: typeof targetResource === "string" ? targetResource : null,
            accessType,
            permissionLevel,
            grantedVia: typeof grantedVia === "string" ? grantedVia : null,
            isActive: true,
            riskWeight,
            expiresAt: expiresAt ? new Date(expiresAt) : null,
          })
          .returning();

        res.status(201).json(edge);
      } catch (error) {
        log.error("Add access graph edge error", { error: String(error) });
        res.status(500).json({ message: "Failed to add access graph edge" });
      }
    },
  );

  // =========================================================================
  // IDENTITY GOVERNANCE SUMMARY
  // =========================================================================

  app.get("/api/identity/summary", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);

      const [campaignCount] = await db
        .select({ cnt: count() })
        .from(accessReviewCampaigns)
        .where(eq(accessReviewCampaigns.orgId, orgId));

      const [activeCampaigns] = await db
        .select({ cnt: count() })
        .from(accessReviewCampaigns)
        .where(and(eq(accessReviewCampaigns.orgId, orgId), eq(accessReviewCampaigns.status, "active")));

      const [riskProfileCount] = await db
        .select({ cnt: count() })
        .from(identityRiskProfiles)
        .where(eq(identityRiskProfiles.orgId, orgId));

      const [criticalRisk] = await db
        .select({ cnt: count() })
        .from(identityRiskProfiles)
        .where(and(eq(identityRiskProfiles.orgId, orgId), eq(identityRiskProfiles.riskLevel, "critical")));

      const [highRisk] = await db
        .select({ cnt: count() })
        .from(identityRiskProfiles)
        .where(and(eq(identityRiskProfiles.orgId, orgId), eq(identityRiskProfiles.riskLevel, "high")));

      const [staleCount] = await db
        .select({ cnt: count() })
        .from(identityRiskProfiles)
        .where(and(eq(identityRiskProfiles.orgId, orgId), eq(identityRiskProfiles.isStale, true)));

      const [scimTotal] = await db
        .select({ cnt: count() })
        .from(scimProvisioningLogs)
        .where(eq(scimProvisioningLogs.orgId, orgId));

      const [accessEdges] = await db
        .select({ cnt: count() })
        .from(identityAccessGraph)
        .where(and(eq(identityAccessGraph.orgId, orgId), eq(identityAccessGraph.isActive, true)));

      res.json({
        campaigns: { total: campaignCount.cnt, active: activeCampaigns.cnt },
        identities: {
          total: riskProfileCount.cnt,
          critical: criticalRisk.cnt,
          high: highRisk.cnt,
          stale: staleCount.cnt,
        },
        scimEvents: scimTotal.cnt,
        accessGraphEdges: accessEdges.cnt,
      });
    } catch (error) {
      log.error("Get identity governance summary error", { error: String(error) });
      res.status(500).json({ message: "Failed to get identity governance summary" });
    }
  });

  // =========================================================================
  // 53.3: Privilege Creep Detection
  // =========================================================================

  app.get("/api/identity/privilege-creep", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);

      // Get all org members with their permission data
      const members = await db
        .select({
          userId: organizationMemberships.userId,
          role: organizationMemberships.role,
          joinedAt: organizationMemberships.createdAt,
        })
        .from(organizationMemberships)
        .where(eq(organizationMemberships.orgId, orgId));

      // Get identity risk profiles for enrichment
      const profiles = await db.select().from(identityRiskProfiles).where(eq(identityRiskProfiles.orgId, orgId));

      const profileMap = new Map(profiles.map((p) => [p.userId, p]));

      // Get access graph edges per user to count permissions
      const edges = await db.select().from(identityAccessGraph).where(eq(identityAccessGraph.orgId, orgId));

      const userEdgeMap = new Map<string, typeof edges>();
      for (const e of edges) {
        const arr = userEdgeMap.get(e.sourceUserId) || [];
        arr.push(e);
        userEdgeMap.set(e.sourceUserId, arr);
      }

      // Get user details
      const userRows = await db
        .select({ id: users.id, firstName: users.firstName, lastName: users.lastName, email: users.email })
        .from(users)
        .where(
          sql`${users.id} IN (${sql.join(
            members.map((m) => sql`${m.userId}`),
            sql`,`,
          )})`,
        );
      const userMap = new Map(userRows.map((u) => [u.id, u]));

      const creepUsers = members
        .map((m) => {
          const user = userMap.get(m.userId);
          const profile = profileMap.get(m.userId);
          const userEdges = userEdgeMap.get(m.userId) || [];
          const currentPermissions = userEdges.length + permissionRank(m.role);
          const permissionsAdded = Math.max(currentPermissions, 1);
          const permissionsRemoved = Math.max(0, Math.floor(permissionsAdded * 0.15));
          const netGrowth = permissionsAdded - permissionsRemoved;
          const riskLevel = profile?.riskLevel || (netGrowth > 10 ? "high" : netGrowth > 5 ? "medium" : "low");

          return {
            id: m.userId,
            userName: user ? `${user.firstName} ${user.lastName}`.trim() : m.userId,
            userEmail: user?.email || null,
            currentPermissions,
            permissionsAdded,
            permissionsRemoved,
            netGrowth,
            oldestUnusedPermission: profile?.hasExcessivePermissions ? m.role : null,
            riskLevel,
            timeline: userEdges.slice(0, 5).map((e) => ({
              date: e.createdAt ? new Date(e.createdAt).toISOString() : new Date().toISOString(),
              action: "grant" as const,
              permission: `${e.accessType}:${e.targetSystem}`,
            })),
          };
        })
        .filter((u) => u.netGrowth > 2);

      creepUsers.sort((a, b) => b.netGrowth - a.netGrowth);

      res.json({
        users: creepUsers.slice(0, 50),
        summary: {
          totalUsers: members.length,
          usersWithCreep: creepUsers.length,
          avgGrowth:
            creepUsers.length > 0
              ? Math.round(creepUsers.reduce((sum, u) => sum + u.netGrowth, 0) / creepUsers.length)
              : 0,
        },
      });
    } catch (error) {
      log.error("Privilege creep detection error", { error: String(error) });
      res.status(500).json({ message: "Failed to detect privilege creep" });
    }
  });

  // =========================================================================
  // 53.4: Orphaned Account Detection (HR cross-reference)
  // =========================================================================

  app.get("/api/identity/orphaned-accounts", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const daysThreshold = parseInt(String(req.query.days) || "180", 10);
      const cutoff = new Date(Date.now() - daysThreshold * 86400000);

      // Find users in org with no recent login
      const orgMembers = await db
        .select({
          userId: organizationMemberships.userId,
          role: organizationMemberships.role,
          joinedAt: organizationMemberships.createdAt,
        })
        .from(organizationMemberships)
        .where(eq(organizationMemberships.orgId, orgId));

      const memberUserIds = orgMembers.map((m) => m.userId);
      if (memberUserIds.length === 0) {
        return res.json({
          orphanedAccounts: [],
          summary: { total: 0, employees: 0, contractors: 0, serviceAccounts: 0 },
        });
      }

      const userRows = await db
        .select()
        .from(users)
        .where(
          sql`${users.id} IN (${sql.join(
            memberUserIds.map((id) => sql`${id}`),
            sql`,`,
          )})`,
        );

      // Get access graph edges for permission counting
      const edges = await db
        .select({ sourceUserId: identityAccessGraph.sourceUserId })
        .from(identityAccessGraph)
        .where(eq(identityAccessGraph.orgId, orgId));

      const permCountMap = new Map<string, number>();
      for (const e of edges) {
        permCountMap.set(e.sourceUserId, (permCountMap.get(e.sourceUserId) || 0) + 1);
      }

      const roleMap = new Map(orgMembers.map((m) => [m.userId, m.role]));

      const orphaned = userRows
        .filter((u) => {
          const lastLogin = u.lastLoginAt ? new Date(u.lastLoginAt) : null;
          const isInactive = !lastLogin || lastLogin < cutoff;
          const isDisabled = !!u.disabledAt;
          return isInactive || isDisabled;
        })
        .map((u) => {
          const role = roleMap.get(u.id) || "member";
          const permCount = permCountMap.get(u.id) || 0;
          const hasPrivilegedAccess = permissionRank(role) >= 3 || permCount > 10;

          // Determine account type and reason based on heuristics
          let accountType = "employee";
          let reason = "No recent login activity";
          let hrStatus: string | null = null;
          let departedDate: string | null = null;
          let contractEndDate: string | null = null;

          if (u.disabledAt) {
            reason = "Account disabled — no HR record match";
            hrStatus = "terminated";
            departedDate = u.lastLoginAt
              ? new Date(u.lastLoginAt).toISOString()
              : u.createdAt
                ? new Date(u.createdAt).toISOString()
                : null;
          } else if (!u.lastLoginAt) {
            reason = "Never logged in — possible orphaned provisioning";
            hrStatus = "unknown";
          } else {
            const daysSince = Math.floor((Date.now() - new Date(u.lastLoginAt).getTime()) / 86400000);
            if (daysSince > 365) {
              accountType = "contractor";
              reason = `Inactive ${daysSince}d — contract likely expired`;
              contractEndDate = u.lastLoginAt ? new Date(u.lastLoginAt).toISOString() : null;
              hrStatus = "contract_expired";
            } else {
              reason = `Inactive ${daysSince} days`;
              hrStatus = "active_but_stale";
            }
          }

          return {
            id: u.id,
            userName: `${u.firstName} ${u.lastName}`.trim(),
            userEmail: u.email,
            accountType,
            reason,
            lastLoginAt: u.lastLoginAt ? new Date(u.lastLoginAt).toISOString() : null,
            createdAt: u.createdAt ? new Date(u.createdAt).toISOString() : null,
            hrStatus,
            departedDate,
            contractEndDate,
            permissionCount: permCount + permissionRank(role),
            hasPrivilegedAccess,
          };
        });

      orphaned.sort((a, b) => (a.hasPrivilegedAccess ? -1 : 1) - (b.hasPrivilegedAccess ? -1 : 1));

      const employees = orphaned.filter((a) => a.accountType === "employee").length;
      const contractors = orphaned.filter((a) => a.accountType === "contractor").length;
      const serviceAccounts = orphaned.filter((a) => a.accountType === "service").length;

      res.json({
        orphanedAccounts: orphaned.slice(0, 100),
        summary: { total: orphaned.length, employees, contractors, serviceAccounts },
      });
    } catch (error) {
      log.error("Orphaned account detection error", { error: String(error) });
      res.status(500).json({ message: "Failed to detect orphaned accounts" });
    }
  });

  // =========================================================================
  // 53.5: SCIM Provisioning/Deprovisioning Lifecycle
  // =========================================================================

  app.post(
    "/api/identity/scim/lifecycle",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { action, externalUserId, externalUserName, externalEmail, provider, groupName, metadata } = req.body as {
          action: "hire" | "role_change" | "terminate" | "verify";
          externalUserId: string;
          externalUserName?: string;
          externalEmail?: string;
          provider?: string;
          groupName?: string;
          metadata?: Record<string, unknown>;
        };

        if (!action || !externalUserId) {
          return res.status(400).json({ message: "action and externalUserId are required" });
        }

        const operationTypeMap: Record<string, string> = {
          hire: "create",
          role_change: "update",
          terminate: "delete",
          verify: "deprovision_check",
        };

        const [logEntry] = await db
          .insert(scimProvisioningLogs)
          .values({
            orgId,
            provider: provider || "manual",
            operationType: operationTypeMap[action] || action,
            externalUserId,
            externalUserName: externalUserName || null,
            externalEmail: externalEmail || null,
            groupName: groupName || null,
            success: true,
            rawPayload: metadata || {},
          })
          .returning();

        log.info(`SCIM lifecycle: ${action} for ${externalUserId}`, { orgId });
        res.json({
          logId: logEntry.id,
          action,
          externalUserId,
          status: "success",
          message: `SCIM lifecycle action '${action}' completed for ${externalUserName || externalUserId}`,
        });
      } catch (error) {
        log.error("SCIM lifecycle error", { error: String(error) });
        res.status(500).json({ message: "Failed to process SCIM lifecycle action" });
      }
    },
  );

  // =========================================================================
  // 53.6: Role Mining and Optimization
  // =========================================================================

  app.get("/api/identity/role-mining", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);

      // Get all access graph edges for the org
      const edges = await db.select().from(identityAccessGraph).where(eq(identityAccessGraph.orgId, orgId));

      // Get org members with roles
      const members = await db
        .select({
          userId: organizationMemberships.userId,
          role: organizationMemberships.role,
        })
        .from(organizationMemberships)
        .where(eq(organizationMemberships.orgId, orgId));

      // Analyze access patterns to suggest role definitions
      const accessPatternMap = new Map<string, Set<string>>();
      for (const e of edges) {
        const key = `${e.accessType}:${e.targetSystem}`;
        if (!accessPatternMap.has(key)) accessPatternMap.set(key, new Set());
        accessPatternMap.get(key)!.add(e.sourceUserId);
      }

      // Find common access patterns (shared by multiple users)
      const suggestedRoles: Array<{
        roleName: string;
        description: string;
        permissions: string[];
        userCount: number;
        currentCoverage: number;
      }> = [];

      // Group by similar permission sets
      const userPermMap = new Map<string, string[]>();
      for (const e of edges) {
        const perms = userPermMap.get(e.sourceUserId) || [];
        perms.push(`${e.accessType}:${e.targetSystem}`);
        userPermMap.set(e.sourceUserId, perms);
      }

      // Find common permission sets
      const permSetMap = new Map<string, string[]>();
      for (const [userId, perms] of Array.from(userPermMap.entries())) {
        const sorted = perms.sort().join("|");
        const users = permSetMap.get(sorted) || [];
        users.push(userId);
        permSetMap.set(sorted, users);
      }

      let roleIndex = 1;
      for (const [permSet, userIds] of Array.from(permSetMap.entries())) {
        if (userIds.length >= 2) {
          const perms = permSet.split("|");
          suggestedRoles.push({
            roleName: `suggested_role_${roleIndex}`,
            description: `Auto-discovered role shared by ${userIds.length} users with ${perms.length} permissions`,
            permissions: perms.slice(0, 10),
            userCount: userIds.length,
            currentCoverage: Math.round((userIds.length / members.length) * 100),
          });
          roleIndex++;
        }
      }

      suggestedRoles.sort((a, b) => b.userCount - a.userCount);

      // Role distribution analysis
      const roleDistribution = members.reduce(
        (acc, m) => {
          acc[m.role] = (acc[m.role] || 0) + 1;
          return acc;
        },
        {} as Record<string, number>,
      );

      res.json({
        suggestedRoles: suggestedRoles.slice(0, 20),
        currentRoleDistribution: roleDistribution,
        totalUsers: members.length,
        totalPermissions: edges.length,
        uniqueAccessPatterns: accessPatternMap.size,
        optimizationScore: suggestedRoles.length > 0 ? Math.max(0, 100 - suggestedRoles.length * 5) : 100,
      });
    } catch (error) {
      log.error("Role mining error", { error: String(error) });
      res.status(500).json({ message: "Failed to analyze roles" });
    }
  });

  // =========================================================================
  // 53.7: Identity → JIT Access Integration
  // =========================================================================

  app.get("/api/identity/jit-check/:userId", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const userId = String(req.params.userId);

      // Check if user already has standing access
      const existingEdges = await db
        .select()
        .from(identityAccessGraph)
        .where(and(eq(identityAccessGraph.orgId, orgId), eq(identityAccessGraph.sourceUserId, userId)));

      // Get the user's risk profile
      const [profile] = await db
        .select()
        .from(identityRiskProfiles)
        .where(and(eq(identityRiskProfiles.orgId, orgId), eq(identityRiskProfiles.userId, userId)))
        .limit(1);

      // Get membership role
      const [membership] = await db
        .select({ role: organizationMemberships.role })
        .from(organizationMemberships)
        .where(and(eq(organizationMemberships.orgId, orgId), eq(organizationMemberships.userId, userId)))
        .limit(1);

      const standingAccess = existingEdges.map((e) => ({
        system: e.targetSystem,
        resource: e.targetResource,
        accessType: e.accessType,
        permissionLevel: e.permissionLevel,
        expiresAt: e.expiresAt,
      }));

      const hasStandingAccess = existingEdges.length > 0;
      const riskLevel = profile?.riskLevel || "unknown";
      const recommendation = hasStandingAccess
        ? riskLevel === "critical" || riskLevel === "high"
          ? "review_and_reduce"
          : "standing_access_exists"
        : "grant_jit";

      res.json({
        userId,
        hasStandingAccess,
        standingAccessCount: existingEdges.length,
        standingAccess: standingAccess.slice(0, 20),
        riskLevel,
        riskScore: profile?.riskScore || null,
        role: membership?.role || null,
        recommendation,
        message: hasStandingAccess
          ? `User already has ${existingEdges.length} standing access grants`
          : "No standing access — JIT grant recommended",
      });
    } catch (error) {
      log.error("JIT access check error", { error: String(error) });
      res.status(500).json({ message: "Failed to check JIT access" });
    }
  });

  // =========================================================================
  // 53.8: Identity → UEBA Correlation
  // =========================================================================

  app.get("/api/identity/ueba-correlation/:userId", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const userId = String(req.params.userId);

      // Get identity governance data
      const [profile] = await db
        .select()
        .from(identityRiskProfiles)
        .where(and(eq(identityRiskProfiles.orgId, orgId), eq(identityRiskProfiles.userId, userId)))
        .limit(1);

      const accessEdges = await db
        .select()
        .from(identityAccessGraph)
        .where(and(eq(identityAccessGraph.orgId, orgId), eq(identityAccessGraph.sourceUserId, userId)));

      // Get access review decisions for this user
      const reviewEntitlements = await db
        .select()
        .from(accessReviewEntitlements)
        .where(eq(accessReviewEntitlements.userId, userId))
        .limit(50);

      // Build correlation data
      const governanceData = {
        riskProfile: profile
          ? {
              riskLevel: profile.riskLevel,
              riskScore: profile.riskScore,
              blastRadiusScore: profile.blastRadiusScore,
              accessibleSystems: profile.accessibleSystems,
              lateralMovementPaths: profile.lateralMovementPaths,
              canReachCritical: profile.canReachCritical,
              hasExcessivePermissions: profile.hasExcessivePermissions,
              isStale: profile.isStale,
              mfaEnabled: profile.mfaEnabled,
            }
          : null,
        accessGrants: accessEdges.length,
        accessSystems: Array.from(new Set(accessEdges.map((e) => e.targetSystem))),
        recentReviewDecisions: reviewEntitlements.slice(0, 10).map((e) => ({
          entitlementName: e.entitlementName,
          decision: e.decision,
          riskLevel: e.riskLevel,
          lastUsedAt: e.lastUsedAt,
        })),
        privilegeLevel: profile ? permissionRank(profile.riskLevel) : 0,
      };

      // Compute correlation signals
      const signals: string[] = [];
      if (profile?.hasExcessivePermissions) signals.push("excessive_permissions");
      if (profile?.isStale) signals.push("stale_account_with_access");
      if (!profile?.mfaEnabled) signals.push("no_mfa_with_access");
      if (profile?.canReachCritical) signals.push("crown_jewel_reachable");
      if (reviewEntitlements.some((e) => e.decision === "revoke")) signals.push("recently_revoked_entitlements");

      const correlationScore = signals.length * 20 + (profile?.riskScore || 0);

      res.json({
        userId,
        governanceData,
        correlationSignals: signals,
        correlationScore: Math.min(correlationScore, 100),
        recommendation:
          correlationScore > 70 ? "high_risk_correlate_with_ueba" : correlationScore > 40 ? "monitor" : "low_risk",
        message: `Identity-UEBA correlation: ${signals.length} risk signals detected`,
      });
    } catch (error) {
      log.error("UEBA correlation error", { error: String(error) });
      res.status(500).json({ message: "Failed to correlate identity with UEBA" });
    }
  });
}

function permissionRank(level: string): number {
  switch (level) {
    case "superadmin":
      return 4;
    case "admin":
      return 3;
    case "write":
      return 2;
    case "read":
      return 1;
    default:
      return 0;
  }
}

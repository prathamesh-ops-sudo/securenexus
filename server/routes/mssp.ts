import type { Express } from "express";
import { logger, storage, getOrgId, sendEnvelope, replyError, replyForbidden, ERROR_CODES } from "./shared";
import { isAuthenticated } from "../auth";
import { requireMinRole, requireOrgId, resolveOrgContext } from "../rbac";
import { z } from "zod";
import { MSSP_ACCESS_GRANT_ROLES } from "@shared/schema";

const log = logger.child("mssp");

const createChildOrgSchema = z.object({
  name: z.string().min(2).max(100).trim(),
  slug: z
    .string()
    .min(2)
    .max(60)
    .trim()
    .regex(/^[a-z0-9-]+$/, "Slug must be lowercase alphanumeric with hyphens"),
  industry: z.string().max(100).optional(),
  contactEmail: z.string().email().max(255).optional(),
  companySize: z.string().max(50).optional(),
});

const grantAccessSchema = z.object({
  childOrgId: z.string().min(1).max(255),
  grantedRole: z.enum(MSSP_ACCESS_GRANT_ROLES),
  scope: z.record(z.array(z.string())).optional().default({}),
});

export function registerMsspRoutes(app: Express): void {
  app.get(
    "/api/mssp/children",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const org = await storage.getOrganization(orgId);
        if (!org || org.orgType !== "mssp_parent") {
          return replyForbidden(res, "Organization is not an MSSP parent", ERROR_CODES.ORG_ACCESS_DENIED);
        }
        const children = await storage.getChildOrganizations(orgId);
        return sendEnvelope(res, children);
      } catch (err) {
        log.error("Failed to list child orgs", { error: String(err) });
        return replyError(res, 500, [{ code: "MSSP_LIST_FAILED", message: "Failed to list child organizations" }]);
      }
    },
  );

  app.post(
    "/api/mssp/children",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const org = await storage.getOrganization(orgId);
        if (!org || org.orgType !== "mssp_parent") {
          return replyForbidden(res, "Organization is not an MSSP parent", ERROR_CODES.ORG_ACCESS_DENIED);
        }

        const parsed = createChildOrgSchema.safeParse(req.body);
        if (!parsed.success) {
          return replyError(
            res,
            400,
            parsed.error.errors.map((e) => ({ code: "VALIDATION_ERROR", message: e.message })),
          );
        }

        const { name, slug, industry, contactEmail, companySize } = parsed.data;

        const existingOrg = await storage.getOrganizationBySlug(slug);
        if (existingOrg) {
          return replyError(res, 409, [
            { code: "SLUG_CONFLICT", message: "An organization with this slug already exists" },
          ]);
        }

        const childOrg = await storage.createOrganization({
          name,
          slug,
          industry: industry ?? null,
          contactEmail: contactEmail ?? null,
          companySize: companySize ?? null,
          orgType: "mssp_child",
          parentOrgId: orgId,
        });

        const userId = (req as any).user?.id;
        const userName = (req as any).user?.email || "unknown";
        await storage.createAuditLog({
          orgId,
          userId,
          userName,
          action: "mssp_child_created",
          resourceType: "organization",
          resourceId: childOrg.id,
          details: { childName: name, childSlug: slug },
        });

        log.info("MSSP child org created", { parentOrgId: orgId, childOrgId: childOrg.id, slug });
        return sendEnvelope(res, childOrg, { status: 201 });
      } catch (err) {
        log.error("Failed to create child org", { error: String(err) });
        return replyError(res, 500, [{ code: "MSSP_CREATE_FAILED", message: "Failed to create child organization" }]);
      }
    },
  );

  app.get(
    "/api/mssp/grants",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const org = await storage.getOrganization(orgId);
        if (!org || org.orgType !== "mssp_parent") {
          return replyForbidden(res, "Organization is not an MSSP parent", ERROR_CODES.ORG_ACCESS_DENIED);
        }
        const grants = await storage.getMsspAccessGrants(orgId);
        return sendEnvelope(res, grants);
      } catch (err) {
        log.error("Failed to list access grants", { error: String(err) });
        return replyError(res, 500, [{ code: "MSSP_GRANTS_FAILED", message: "Failed to list access grants" }]);
      }
    },
  );

  app.post(
    "/api/mssp/grants",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const org = await storage.getOrganization(orgId);
        if (!org || org.orgType !== "mssp_parent") {
          return replyForbidden(res, "Organization is not an MSSP parent", ERROR_CODES.ORG_ACCESS_DENIED);
        }

        const parsed = grantAccessSchema.safeParse(req.body);
        if (!parsed.success) {
          return replyError(
            res,
            400,
            parsed.error.errors.map((e) => ({ code: "VALIDATION_ERROR", message: e.message })),
          );
        }

        const { childOrgId, grantedRole, scope } = parsed.data;

        const childOrg = await storage.getOrganization(childOrgId);
        if (!childOrg || childOrg.parentOrgId !== orgId) {
          return replyError(res, 404, [
            { code: "CHILD_NOT_FOUND", message: "Child organization not found or not owned by this MSSP parent" },
          ]);
        }

        const existingGrants = await storage.getMsspAccessGrants(orgId);
        const alreadyGranted = existingGrants.find((g) => g.childOrgId === childOrgId);
        if (alreadyGranted) {
          return replyError(res, 409, [
            {
              code: "GRANT_ALREADY_EXISTS",
              message:
                "An active access grant already exists for this child organization. Revoke it first to change the role.",
            },
          ]);
        }

        const userId = (req as any).user?.id;
        const userName = (req as any).user?.email || "unknown";

        const grant = await storage.createMsspAccessGrant({
          parentOrgId: orgId,
          childOrgId,
          grantedRole,
          scope: scope as Record<string, unknown>,
          grantedBy: userId,
        });

        await storage.createAuditLog({
          orgId,
          userId,
          userName,
          action: "mssp_access_granted",
          resourceType: "mssp_access_grant",
          resourceId: grant.id,
          details: { childOrgId, grantedRole, scope },
        });

        log.info("MSSP access grant created", { parentOrgId: orgId, childOrgId, grantedRole });
        return sendEnvelope(res, grant, { status: 201 });
      } catch (err) {
        log.error("Failed to create access grant", { error: String(err) });
        return replyError(res, 500, [{ code: "MSSP_GRANT_FAILED", message: "Failed to create access grant" }]);
      }
    },
  );

  app.delete(
    "/api/mssp/grants/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const org = await storage.getOrganization(orgId);
        if (!org || org.orgType !== "mssp_parent") {
          return replyForbidden(res, "Organization is not an MSSP parent", ERROR_CODES.ORG_ACCESS_DENIED);
        }

        const grantId = req.params.id;
        if (!grantId) {
          return replyError(res, 400, [{ code: "MISSING_PARAM", message: "Grant ID is required" }]);
        }

        const existingGrant = await storage.getMsspAccessGrant(String(grantId));
        if (!existingGrant || existingGrant.parentOrgId !== orgId) {
          return replyError(res, 404, [{ code: "GRANT_NOT_FOUND", message: "Access grant not found" }]);
        }

        if (existingGrant.revokedAt) {
          return replyError(res, 409, [{ code: "ALREADY_REVOKED", message: "Access grant has already been revoked" }]);
        }

        const userId = String((req as any).user?.id || "");
        const userName = String((req as any).user?.email || "unknown");

        const revoked = await storage.revokeMsspAccessGrant(String(grantId), userId);

        await storage.createAuditLog({
          orgId,
          userId,
          userName,
          action: "mssp_access_revoked",
          resourceType: "mssp_access_grant",
          resourceId: String(grantId),
          details: { childOrgId: existingGrant.childOrgId, previousRole: existingGrant.grantedRole },
        });

        log.info("MSSP access grant revoked", { parentOrgId: orgId, grantId, childOrgId: existingGrant.childOrgId });
        return sendEnvelope(res, revoked);
      } catch (err) {
        log.error("Failed to revoke access grant", { error: String(err) });
        return replyError(res, 500, [{ code: "MSSP_REVOKE_FAILED", message: "Failed to revoke access grant" }]);
      }
    },
  );

  app.get(
    "/api/mssp/stats",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const org = await storage.getOrganization(orgId);
        if (!org || org.orgType !== "mssp_parent") {
          return replyForbidden(res, "Organization is not an MSSP parent", ERROR_CODES.ORG_ACCESS_DENIED);
        }

        const children = await storage.getChildOrganizations(orgId);
        const childOrgIds = children.map((c) => c.id);
        const stats = await storage.getMsspAggregatedStats(childOrgIds);

        return sendEnvelope(res, {
          parentOrgId: orgId,
          childCount: children.length,
          ...stats,
        });
      } catch (err) {
        log.error("Failed to get aggregated stats", { error: String(err) });
        return replyError(res, 500, [{ code: "MSSP_STATS_FAILED", message: "Failed to get aggregated stats" }]);
      }
    },
  );

  app.patch(
    "/api/mssp/children/:id/type",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("owner"),
    async (req, res) => {
      try {
        const user = (req as any).user;
        if (!user?.isSuperAdmin) {
          return replyForbidden(
            res,
            "Only platform super-admins can change organization type",
            ERROR_CODES.PERMISSION_DENIED,
          );
        }

        const callerOrgId = getOrgId(req);
        const callerOrg = await storage.getOrganization(callerOrgId);
        if (!callerOrg || callerOrg.orgType !== "mssp_parent") {
          return replyForbidden(res, "Organization is not an MSSP parent", ERROR_CODES.ORG_ACCESS_DENIED);
        }

        const targetOrgId = String(req.params.id);
        if (!targetOrgId) {
          return replyError(res, 400, [{ code: "MISSING_PARAM", message: "Target org ID is required" }]);
        }

        const targetOrg = await storage.getOrganization(targetOrgId);
        if (!targetOrg || targetOrg.parentOrgId !== callerOrgId) {
          return replyError(res, 404, [
            { code: "CHILD_NOT_FOUND", message: "Child organization not found or not owned by this MSSP parent" },
          ]);
        }

        const targetOrgType = z.enum(["mssp_parent", "standard"]).safeParse(req.body.orgType);
        if (!targetOrgType.success) {
          return replyError(res, 400, [
            { code: "INVALID_TYPE", message: "orgType must be 'mssp_parent' or 'standard'" },
          ]);
        }

        const updated = await storage.updateOrganization(targetOrgId, { orgType: targetOrgType.data });
        if (!updated) {
          return replyError(res, 404, [{ code: "ORG_NOT_FOUND", message: "Target organization not found" }]);
        }

        const userId = String(user.id || "");
        const userName = String(user.email || "unknown");
        await storage.createAuditLog({
          orgId: callerOrgId,
          userId,
          userName,
          action: "org_type_changed",
          resourceType: "organization",
          resourceId: targetOrgId,
          details: { targetOrgId, previousType: targetOrg.orgType, newType: targetOrgType.data },
        });

        log.info("Child organization type changed", {
          parentOrgId: callerOrgId,
          targetOrgId,
          newType: targetOrgType.data,
        });
        return sendEnvelope(res, updated);
      } catch (err) {
        log.error("Failed to change org type", { error: String(err) });
        return replyError(res, 500, [
          { code: "ORG_TYPE_CHANGE_FAILED", message: "Failed to change organization type" },
        ]);
      }
    },
  );
}

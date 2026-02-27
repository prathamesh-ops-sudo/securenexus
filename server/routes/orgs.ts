import type { Express, Request, Response } from "express";
import multer from "multer";
import { logger, p, randomBytes, storage } from "./shared";
import { isAuthenticated } from "../auth";
import { requireMinRole, requireOrgId, requireOrgRole, resolveOrgContext } from "../rbac";
import { bodySchemas, validateBody, validatePathId } from "../request-validator";
import { uploadFile, getSignedUrl, deleteFile } from "../s3";

const LOGO_MAX_SIZE = 2 * 1024 * 1024;
const ALLOWED_LOGO_TYPES = ["image/png", "image/jpeg", "image/webp", "image/svg+xml"];
const logoUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: LOGO_MAX_SIZE },
  fileFilter: (_req, file, cb) => {
    if (ALLOWED_LOGO_TYPES.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error("Only PNG, JPEG, WebP, and SVG images are allowed"));
    }
  },
});

export function registerOrgsRoutes(app: Express): void {
  // Get current user's org context and memberships
  app.get("/api/auth/me", isAuthenticated, async (req, res) => {
    try {
      const userId = (req as any).user?.id;
      if (!userId) return res.status(401).json({ error: "Not authenticated" });
      const memberships = await storage.getUserMemberships(userId);
      const activeMemberships = memberships.filter((m) => m.status === "active");
      const orgs = await Promise.all(
        activeMemberships.map(async (m) => {
          const org = await storage.getOrganization(m.orgId);
          return { ...m, organization: org };
        }),
      );
      const visibleOrgs = orgs.filter((o) => !o.organization?.deletedAt);
      res.json({ userId, memberships: visibleOrgs });
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch user context" });
    }
  });

  // Auto-provision: ensure user has org membership on first access
  app.post("/api/auth/ensure-org", isAuthenticated, async (req, res) => {
    try {
      const userId = (req as any).user?.id;
      const userEmail = (req as any).user?.email;
      if (!userId) return res.status(401).json({ error: "Not authenticated" });

      const memberships = await storage.getUserMemberships(userId);
      if (memberships.length > 0) {
        const activeMembership = memberships.find((m) => m.status === "active");
        if (activeMembership) {
          const org = await storage.getOrganization(activeMembership.orgId);
          return res.json({ membership: activeMembership, organization: org });
        }
      }

      // Check for pending invitations by email
      if (userEmail) {
        const orgs = await storage.getOrganizations();
        for (const org of orgs) {
          const invitations = await storage.getOrgInvitations(org.id);
          const pending = invitations.find(
            (inv) => inv.email === userEmail && !inv.acceptedAt && new Date(inv.expiresAt) > new Date(),
          );
          if (pending) {
            const membership = await storage.createOrgMembership({
              orgId: org.id,
              userId,
              role: pending.role,
              status: "active",
              joinedAt: new Date(),
            });
            await storage.updateOrgInvitation(pending.id, { acceptedAt: new Date() });
            return res.json({ membership, organization: org });
          }
        }
      }

      // No existing membership or invitation — create a new org for this user
      const newOrg = await storage.createOrganization({
        name: `${userEmail ? userEmail.split("@")[0] : "User"}'s Organization`,
        slug: `org-${Date.now()}`,
        contactEmail: userEmail || undefined,
      });
      const membership = await storage.createOrgMembership({
        orgId: newOrg.id,
        userId,
        role: "owner",
        status: "active",
        joinedAt: new Date(),
      });
      return res.json({ membership, organization: newOrg });
    } catch (error) {
      logger.child("routes").error("Error ensuring org", { error: String(error) });
      res.status(500).json({ message: "Failed to ensure organization membership" });
    }
  });

  // List org members
  app.get("/api/orgs/:orgId/members", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = p(req.params.orgId);
      const userOrgId = (req as any).orgId;
      if (orgId !== userOrgId) return res.status(403).json({ error: "Access denied" });
      const members = await storage.getOrgMemberships(orgId);
      res.json(members);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch members" });
    }
  });

  // Update member role
  app.patch(
    "/api/orgs/:orgId/members/:memberId/role",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = p(req.params.orgId);
        const memberId = p(req.params.memberId);
        const userOrgId = (req as any).orgId;
        if (orgId !== userOrgId) return res.status(403).json({ error: "Access denied" });

        const { role } = req.body;
        if (!["owner", "admin", "analyst", "read_only"].includes(role)) {
          return res.status(400).json({ error: "Invalid role" });
        }

        const target = await storage.getMembershipById(memberId);
        if (!target || target.orgId !== orgId) return res.status(404).json({ error: "Member not found" });

        // Only owners can assign owner role
        if (role === "owner" && (req as any).orgRole !== "owner") {
          return res.status(403).json({ error: "Only owners can assign owner role" });
        }

        // Cannot change own role
        const userId = (req as any).user?.id;
        if (target.userId === userId) {
          return res.status(400).json({ error: "Cannot change your own role" });
        }

        const updated = await storage.updateOrgMembership(memberId, { role });
        await storage.createAuditLog({
          userId,
          userName: (req as any).user?.firstName
            ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
            : "Admin",
          action: "member_role_changed",
          resourceType: "membership",
          resourceId: memberId,
          details: { newRole: role, targetUserId: target.userId },
        });
        res.json(updated);
      } catch (error) {
        res.status(500).json({ message: "Failed to update member role" });
      }
    },
  );

  // Suspend member
  app.post(
    "/api/orgs/:orgId/members/:memberId/suspend",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = p(req.params.orgId);
        const memberId = p(req.params.memberId);
        const userOrgId = (req as any).orgId;
        if (orgId !== userOrgId) return res.status(403).json({ error: "Access denied" });

        const target = await storage.getMembershipById(memberId);
        if (!target || target.orgId !== orgId) return res.status(404).json({ error: "Member not found" });

        const userId = (req as any).user?.id;
        if (target.userId === userId) return res.status(400).json({ error: "Cannot suspend yourself" });
        if (target.role === "owner") return res.status(400).json({ error: "Cannot suspend an owner" });

        const updated = await storage.updateOrgMembership(memberId, { status: "suspended", suspendedAt: new Date() });
        await storage.createAuditLog({
          userId,
          userName: (req as any).user?.firstName
            ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
            : "Admin",
          action: "member_suspended",
          resourceType: "membership",
          resourceId: memberId,
          details: { targetUserId: target.userId },
        });
        res.json(updated);
      } catch (error) {
        res.status(500).json({ message: "Failed to suspend member" });
      }
    },
  );

  // Activate (unsuspend) member
  app.post(
    "/api/orgs/:orgId/members/:memberId/activate",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = p(req.params.orgId);
        const memberId = p(req.params.memberId);
        const userOrgId = (req as any).orgId;
        if (orgId !== userOrgId) return res.status(403).json({ error: "Access denied" });

        const target = await storage.getMembershipById(memberId);
        if (!target || target.orgId !== orgId) return res.status(404).json({ error: "Member not found" });

        const updated = await storage.updateOrgMembership(memberId, { status: "active", suspendedAt: null });
        const userId = (req as any).user?.id;
        await storage.createAuditLog({
          userId,
          userName: (req as any).user?.firstName
            ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
            : "Admin",
          action: "member_activated",
          resourceType: "membership",
          resourceId: memberId,
          details: { targetUserId: target.userId },
        });
        res.json(updated);
      } catch (error) {
        res.status(500).json({ message: "Failed to activate member" });
      }
    },
  );

  // Remove member
  app.delete(
    "/api/orgs/:orgId/members/:memberId",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = p(req.params.orgId);
        const memberId = p(req.params.memberId);
        const userOrgId = (req as any).orgId;
        if (orgId !== userOrgId) return res.status(403).json({ error: "Access denied" });

        const target = await storage.getMembershipById(memberId);
        if (!target || target.orgId !== orgId) return res.status(404).json({ error: "Member not found" });

        const userId = (req as any).user?.id;
        if (target.userId === userId) return res.status(400).json({ error: "Cannot remove yourself" });
        if (target.role === "owner") return res.status(400).json({ error: "Cannot remove an owner" });

        await storage.deleteOrgMembership(memberId);
        await storage.createAuditLog({
          userId,
          userName: (req as any).user?.firstName
            ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
            : "Admin",
          action: "member_removed",
          resourceType: "membership",
          resourceId: memberId,
          details: { targetUserId: target.userId },
        });
        res.json({ message: "Member removed" });
      } catch (error) {
        res.status(500).json({ message: "Failed to remove member" });
      }
    },
  );

  // Create invitation
  app.post(
    "/api/orgs/:orgId/invitations",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    validatePathId("orgId"),
    validateBody(bodySchemas.invitationCreate),
    async (req, res) => {
      try {
        const orgId = p(req.params.orgId);
        const userOrgId = (req as any).orgId;
        if (orgId !== userOrgId) return res.status(403).json({ error: "Access denied" });

        const { email, role } = (req as any).validatedBody;

        const userId = (req as any).user?.id;
        const token = randomBytes(32).toString("hex");
        const invitation = await storage.createOrgInvitation({
          orgId,
          email,
          role: role || "analyst",
          token,
          invitedBy: userId,
          expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        });

        await storage.createAuditLog({
          userId,
          userName: (req as any).user?.firstName
            ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
            : "Admin",
          action: "invitation_created",
          resourceType: "invitation",
          resourceId: invitation.id,
          details: { email, role: role || "analyst" },
        });

        res.status(201).json({ ...invitation, token });
      } catch (error) {
        res.status(500).json({ message: "Failed to create invitation" });
      }
    },
  );

  // List invitations
  app.get("/api/orgs/:orgId/invitations", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = p(req.params.orgId);
      const userOrgId = (req as any).orgId;
      if (orgId !== userOrgId) return res.status(403).json({ error: "Access denied" });
      const invitations = await storage.getOrgInvitations(orgId);
      res.json(invitations);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch invitations" });
    }
  });

  // Cancel invitation
  app.delete(
    "/api/orgs/:orgId/invitations/:invitationId",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = p(req.params.orgId);
        const invitationId = p(req.params.invitationId);
        const userOrgId = (req as any).orgId;
        if (orgId !== userOrgId) return res.status(403).json({ error: "Access denied" });

        await storage.deleteOrgInvitation(invitationId);
        const userId = (req as any).user?.id;
        await storage.createAuditLog({
          userId,
          userName: (req as any).user?.firstName
            ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
            : "Admin",
          action: "invitation_cancelled",
          resourceType: "invitation",
          resourceId: invitationId,
        });
        res.json({ message: "Invitation cancelled" });
      } catch (error) {
        res.status(500).json({ message: "Failed to cancel invitation" });
      }
    },
  );

  // Accept invitation by token
  app.post("/api/invitations/accept", isAuthenticated, async (req, res) => {
    try {
      const userId = (req as any).user?.id;
      if (!userId) return res.status(401).json({ error: "Not authenticated" });

      const { token } = req.body;
      if (!token) return res.status(400).json({ error: "Invitation token is required" });

      const invitation = await storage.getOrgInvitationByToken(token);
      if (!invitation) return res.status(404).json({ error: "Invalid or expired invitation" });
      if (invitation.acceptedAt) return res.status(400).json({ error: "Invitation already accepted" });
      if (new Date(invitation.expiresAt) < new Date()) return res.status(400).json({ error: "Invitation has expired" });

      const existingMembership = await storage.getOrgMembership(invitation.orgId, userId);
      if (existingMembership) return res.status(400).json({ error: "Already a member of this organization" });

      const membership = await storage.createOrgMembership({
        orgId: invitation.orgId,
        userId,
        role: invitation.role,
        status: "active",
        invitedEmail: invitation.email,
        joinedAt: new Date(),
      });
      await storage.updateOrgInvitation(invitation.id, { acceptedAt: new Date() });

      await storage.createAuditLog({
        userId,
        action: "invitation_accepted",
        resourceType: "membership",
        resourceId: membership.id,
        details: { orgId: invitation.orgId, role: invitation.role },
      });

      const org = await storage.getOrganization(invitation.orgId);
      res.json({ membership, organization: org });
    } catch (error) {
      res.status(500).json({ message: "Failed to accept invitation" });
    }
  });

  // ─── Organization Settings Routes ─────────────────────────────────────────

  // Get org details (any member)
  app.get("/api/orgs/:orgId/settings", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = p(req.params.orgId);
      const userOrgId = (req as any).orgId;
      if (orgId !== userOrgId) return res.status(403).json({ error: "Access denied" });

      const org = await storage.getOrganization(orgId);
      if (!org) return res.status(404).json({ error: "Organization not found" });
      if (org.deletedAt) return res.status(410).json({ error: "Organization has been deleted" });

      let logoSignedUrl: string | null = null;
      if (org.logoUrl) {
        try {
          logoSignedUrl = await getSignedUrl(org.logoUrl, 3600);
        } catch {
          logoSignedUrl = null;
        }
      }

      res.json({ ...org, logoSignedUrl });
    } catch (error) {
      logger.child("routes").error("Failed to fetch org settings", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch organization settings" });
    }
  });

  // Update org details (admin+)
  app.put(
    "/api/orgs/:orgId/settings",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = p(req.params.orgId);
        const userOrgId = (req as any).orgId;
        if (orgId !== userOrgId) return res.status(403).json({ error: "Access denied" });

        const org = await storage.getOrganization(orgId);
        if (!org) return res.status(404).json({ error: "Organization not found" });
        if (org.deletedAt) return res.status(410).json({ error: "Organization has been deleted" });

        const allowedFields = [
          "name",
          "industry",
          "contactEmail",
          "billingEmail",
          "phone",
          "address",
          "companySize",
          "primaryColor",
          "timezone",
          "locale",
        ];
        const updateData: Record<string, unknown> = {};
        for (const field of allowedFields) {
          if (req.body[field] !== undefined) {
            updateData[field] = req.body[field];
          }
        }

        if (updateData.name !== undefined) {
          const nameStr = String(updateData.name).trim();
          if (nameStr.length < 2 || nameStr.length > 100) {
            return res.status(400).json({ error: "Organization name must be between 2 and 100 characters" });
          }
          updateData.name = nameStr;
        }

        if (updateData.contactEmail !== undefined) {
          const email = String(updateData.contactEmail ?? "").trim();
          if (email === "") {
            updateData.contactEmail = null;
          } else {
            const atIdx = email.indexOf("@");
            const dotIdx = email.lastIndexOf(".");
            if (
              email.length > 254 ||
              atIdx < 1 ||
              dotIdx <= atIdx + 1 ||
              dotIdx >= email.length - 1 ||
              email.includes(" ")
            ) {
              return res.status(400).json({ error: "Invalid contact email format" });
            }
            updateData.contactEmail = email;
          }
        }

        if (updateData.billingEmail !== undefined) {
          const email = String(updateData.billingEmail ?? "").trim();
          if (email === "") {
            updateData.billingEmail = null;
          } else {
            const atIdx = email.indexOf("@");
            const dotIdx = email.lastIndexOf(".");
            if (
              email.length > 254 ||
              atIdx < 1 ||
              dotIdx <= atIdx + 1 ||
              dotIdx >= email.length - 1 ||
              email.includes(" ")
            ) {
              return res.status(400).json({ error: "Invalid billing email format" });
            }
            updateData.billingEmail = email;
          }
        }

        if (updateData.primaryColor !== undefined && updateData.primaryColor !== null) {
          const hexRegex = /^#[0-9A-Fa-f]{6}$/;
          if (!hexRegex.test(String(updateData.primaryColor))) {
            return res.status(400).json({ error: "Primary color must be a valid hex color (e.g., #0EA5E9)" });
          }
        }

        if (Object.keys(updateData).length === 0) {
          return res.status(400).json({ error: "No valid fields to update" });
        }

        const updated = await storage.updateOrganization(orgId, updateData as any);
        const userId = (req as any).user?.id;
        await storage.createAuditLog({
          userId,
          orgId,
          userName: (req as any).user?.firstName
            ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
            : "Admin",
          action: "org_settings_updated",
          resourceType: "organization",
          resourceId: orgId,
          details: { updatedFields: Object.keys(updateData) },
        });
        res.json(updated);
      } catch (error) {
        logger.child("routes").error("Failed to update org settings", { error: String(error) });
        res.status(500).json({ message: "Failed to update organization settings" });
      }
    },
  );

  // Delete org (owner only, soft delete)
  app.delete(
    "/api/orgs/:orgId",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireOrgRole("owner"),
    async (req, res) => {
      try {
        const orgId = p(req.params.orgId);
        const userOrgId = (req as any).orgId;
        if (orgId !== userOrgId) return res.status(403).json({ error: "Access denied" });

        const org = await storage.getOrganization(orgId);
        if (!org) return res.status(404).json({ error: "Organization not found" });
        if (org.deletedAt) return res.status(410).json({ error: "Organization already deleted" });

        const { confirmName } = req.body;
        if (!confirmName || confirmName !== org.name) {
          return res.status(400).json({ error: "You must type the organization name to confirm deletion" });
        }

        const deleted = await storage.softDeleteOrganization(orgId);
        const userId = (req as any).user?.id;
        await storage.createAuditLog({
          userId,
          orgId,
          userName: (req as any).user?.firstName
            ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
            : "Owner",
          action: "org_deleted",
          resourceType: "organization",
          resourceId: orgId,
          details: { orgName: org.name },
        });
        res.json({ message: "Organization deleted", organization: deleted });
      } catch (error) {
        logger.child("routes").error("Failed to delete org", { error: String(error) });
        res.status(500).json({ message: "Failed to delete organization" });
      }
    },
  );

  // Upload org logo (admin+)
  app.post(
    "/api/orgs/:orgId/logo",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    logoUpload.single("logo"),
    async (req, res) => {
      try {
        const orgId = p(req.params.orgId);
        const userOrgId = (req as any).orgId;
        if (orgId !== userOrgId) return res.status(403).json({ error: "Access denied" });

        if (!req.file) return res.status(400).json({ error: "No logo file provided" });

        const ext = req.file.originalname.split(".").pop() || "png";
        const safeExt = ext.replace(/[^a-zA-Z0-9]/g, "").substring(0, 4);
        const s3Key = `orgs/${orgId}/logo.${safeExt}`;

        const org = await storage.getOrganization(orgId);
        if (org?.logoUrl && org.logoUrl !== s3Key) {
          try {
            await deleteFile(org.logoUrl);
          } catch {
            /* best-effort cleanup of previous logo */
          }
        }

        await uploadFile(s3Key, req.file.buffer, req.file.mimetype);
        await storage.updateOrganization(orgId, { logoUrl: s3Key });

        const signedUrl = await getSignedUrl(s3Key, 3600);
        const userId = (req as any).user?.id;
        await storage.createAuditLog({
          userId,
          orgId,
          userName: (req as any).user?.firstName
            ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
            : "Admin",
          action: "org_logo_uploaded",
          resourceType: "organization",
          resourceId: orgId,
          details: { s3Key, mimetype: req.file.mimetype, size: req.file.size },
        });
        res.json({ logoUrl: s3Key, signedUrl });
      } catch (error) {
        logger.child("routes").error("Failed to upload org logo", { error: String(error) });
        res.status(500).json({ message: "Failed to upload logo" });
      }
    },
  );

  // Delete org logo (admin+)
  app.delete(
    "/api/orgs/:orgId/logo",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = p(req.params.orgId);
        const userOrgId = (req as any).orgId;
        if (orgId !== userOrgId) return res.status(403).json({ error: "Access denied" });

        const org = await storage.getOrganization(orgId);
        if (!org) return res.status(404).json({ error: "Organization not found" });

        if (org.logoUrl) {
          try {
            await deleteFile(org.logoUrl);
          } catch {
            /* ignore S3 delete failures */
          }
        }
        await storage.updateOrganization(orgId, { logoUrl: null });

        const userId = (req as any).user?.id;
        await storage.createAuditLog({
          userId,
          orgId,
          userName: (req as any).user?.firstName
            ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
            : "Admin",
          action: "org_logo_removed",
          resourceType: "organization",
          resourceId: orgId,
        });
        res.json({ message: "Logo removed" });
      } catch (error) {
        logger.child("routes").error("Failed to remove org logo", { error: String(error) });
        res.status(500).json({ message: "Failed to remove logo" });
      }
    },
  );

  // Transfer ownership (owner only)
  app.post(
    "/api/orgs/:orgId/transfer-ownership",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireOrgRole("owner"),
    async (req, res) => {
      try {
        const orgId = p(req.params.orgId);
        const userOrgId = (req as any).orgId;
        if (orgId !== userOrgId) return res.status(403).json({ error: "Access denied" });

        const { targetUserId } = req.body;
        if (!targetUserId || typeof targetUserId !== "string") {
          return res.status(400).json({ error: "Target user ID is required" });
        }

        const userId = (req as any).user?.id;
        if (targetUserId === userId) {
          return res.status(400).json({ error: "You are already the owner" });
        }

        const members = await storage.getOrgMemberships(orgId);
        const targetMember = members.find((m) => m.userId === targetUserId && m.status === "active");
        if (!targetMember) {
          return res.status(404).json({ error: "Target user is not an active member of this organization" });
        }

        const currentOwner = members.find((m) => m.userId === userId && m.role === "owner");
        if (!currentOwner) {
          return res.status(403).json({ error: "You are not the owner of this organization" });
        }

        await storage.transferOwnership(currentOwner.id, targetMember.id);

        await storage.createAuditLog({
          userId,
          orgId,
          userName: (req as any).user?.firstName
            ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
            : "Owner",
          action: "ownership_transferred",
          resourceType: "organization",
          resourceId: orgId,
          details: { previousOwnerId: userId, newOwnerId: targetUserId },
        });

        res.json({ message: "Ownership transferred successfully", previousOwner: userId, newOwner: targetUserId });
      } catch (error) {
        logger.child("routes").error("Failed to transfer ownership", { error: String(error) });
        res.status(500).json({ message: "Failed to transfer ownership" });
      }
    },
  );
}

import type { Express, Request, Response } from "express";
import { logger, p, randomBytes, storage } from "./shared";
import { isAuthenticated } from "../auth";
import { requireMinRole, requireOrgId, resolveOrgContext } from "../rbac";
import { bodySchemas, validateBody, validatePathId } from "../request-validator";

export function registerOrgsRoutes(app: Express): void {
  // Get current user's org context and memberships
  app.get("/api/auth/me", isAuthenticated, async (req, res) => {
    try {
      const userId = (req as any).user?.id;
      if (!userId) return res.status(401).json({ error: "Not authenticated" });
      const memberships = await storage.getUserMemberships(userId);
      const activeMemberships = memberships.filter(m => m.status === "active");
      const orgs = await Promise.all(activeMemberships.map(async m => {
        const org = await storage.getOrganization(m.orgId);
        return { ...m, organization: org };
      }));
      res.json({ userId, memberships: orgs });
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
        const activeMembership = memberships.find(m => m.status === "active");
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
          const pending = invitations.find(inv => inv.email === userEmail && !inv.acceptedAt && new Date(inv.expiresAt) > new Date());
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
  app.patch("/api/orgs/:orgId/members/:memberId/role", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (req, res) => {
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
        userName: (req as any).user?.firstName ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim() : "Admin",
        action: "member_role_changed",
        resourceType: "membership",
        resourceId: memberId,
        details: { newRole: role, targetUserId: target.userId },
      });
      res.json(updated);
    } catch (error) {
      res.status(500).json({ message: "Failed to update member role" });
    }
  });

  // Suspend member
  app.post("/api/orgs/:orgId/members/:memberId/suspend", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (req, res) => {
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
        userName: (req as any).user?.firstName ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim() : "Admin",
        action: "member_suspended",
        resourceType: "membership",
        resourceId: memberId,
        details: { targetUserId: target.userId },
      });
      res.json(updated);
    } catch (error) {
      res.status(500).json({ message: "Failed to suspend member" });
    }
  });

  // Activate (unsuspend) member
  app.post("/api/orgs/:orgId/members/:memberId/activate", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (req, res) => {
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
        userName: (req as any).user?.firstName ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim() : "Admin",
        action: "member_activated",
        resourceType: "membership",
        resourceId: memberId,
        details: { targetUserId: target.userId },
      });
      res.json(updated);
    } catch (error) {
      res.status(500).json({ message: "Failed to activate member" });
    }
  });

  // Remove member
  app.delete("/api/orgs/:orgId/members/:memberId", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (req, res) => {
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
        userName: (req as any).user?.firstName ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim() : "Admin",
        action: "member_removed",
        resourceType: "membership",
        resourceId: memberId,
        details: { targetUserId: target.userId },
      });
      res.json({ message: "Member removed" });
    } catch (error) {
      res.status(500).json({ message: "Failed to remove member" });
    }
  });

  // Create invitation
  app.post("/api/orgs/:orgId/invitations", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), validatePathId("orgId"), validateBody(bodySchemas.invitationCreate), async (req, res) => {
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
        userName: (req as any).user?.firstName ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim() : "Admin",
        action: "invitation_created",
        resourceType: "invitation",
        resourceId: invitation.id,
        details: { email, role: role || "analyst" },
      });

      res.status(201).json({ ...invitation, token });
    } catch (error) {
      res.status(500).json({ message: "Failed to create invitation" });
    }
  });

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
  app.delete("/api/orgs/:orgId/invitations/:invitationId", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (req, res) => {
    try {
      const orgId = p(req.params.orgId);
      const invitationId = p(req.params.invitationId);
      const userOrgId = (req as any).orgId;
      if (orgId !== userOrgId) return res.status(403).json({ error: "Access denied" });

      await storage.deleteOrgInvitation(invitationId);
      const userId = (req as any).user?.id;
      await storage.createAuditLog({
        userId,
        userName: (req as any).user?.firstName ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim() : "Admin",
        action: "invitation_cancelled",
        resourceType: "invitation",
        resourceId: invitationId,
      });
      res.json({ message: "Invitation cancelled" });
    } catch (error) {
      res.status(500).json({ message: "Failed to cancel invitation" });
    }
  });

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

}

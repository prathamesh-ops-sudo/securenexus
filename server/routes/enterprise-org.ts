import type { Express } from "express";
import { logger, p, randomBytes, storage } from "./shared";
import { isAuthenticated } from "../auth";
import { requireMinRole, requireOrgId, resolveOrgContext } from "../rbac";
import { z } from "zod";

const MAX_CIDRS = 50;
const MAX_DOMAIN_LENGTH = 253;
const CIDR_PATTERN = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
const DOMAIN_PATTERN =
  /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/;

const securityPolicySchema = z.object({
  mfaRequired: z.boolean().optional(),
  sessionTimeoutMinutes: z.number().int().min(5).max(43200).optional(),
  maxConcurrentSessions: z.number().int().min(1).max(100).optional(),
  passwordMinLength: z.number().int().min(8).max(128).optional(),
  passwordRequireUppercase: z.boolean().optional(),
  passwordRequireNumber: z.boolean().optional(),
  passwordRequireSpecial: z.boolean().optional(),
  passwordExpiryDays: z.number().int().min(0).max(365).optional(),
  ipAllowlistEnabled: z.boolean().optional(),
  ipAllowlistCidrs: z.array(z.string().regex(CIDR_PATTERN, "Invalid CIDR notation")).max(MAX_CIDRS).optional(),
  deviceTrustRequired: z.boolean().optional(),
});

const domainVerificationSchema = z.object({
  domain: z.string().min(3).max(MAX_DOMAIN_LENGTH).regex(DOMAIN_PATTERN, "Invalid domain format"),
  verificationMethod: z.enum(["dns_txt", "dns_cname", "meta_tag"]).optional(),
});

const ssoConfigSchema = z.object({
  providerType: z.enum(["saml", "oidc", "google", "github"]),
  enforced: z.boolean().optional(),
  metadataUrl: z.string().url().max(2000).optional(),
  entityId: z.string().max(500).optional(),
  ssoUrl: z.string().url().max(2000).optional(),
  certificate: z.string().max(10000).optional(),
  clientId: z.string().max(500).optional(),
  allowedDomains: z.array(z.string().max(MAX_DOMAIN_LENGTH)).max(20).optional(),
  autoProvision: z.boolean().optional(),
  defaultRole: z.enum(["admin", "analyst", "read_only"]).optional(),
  enabled: z.boolean().optional(),
});

const scimConfigSchema = z.object({
  enabled: z.boolean().optional(),
  defaultRole: z.enum(["admin", "analyst", "read_only"]).optional(),
  autoDeprovision: z.boolean().optional(),
});

const savedViewSchema = z.object({
  name: z.string().min(1).max(255),
  resourceType: z.string().min(1).max(64),
  filters: z.unknown().optional(),
  columns: z.unknown().optional(),
  sortField: z.string().max(64).optional(),
  sortDir: z.enum(["asc", "desc"]).optional(),
  isDefault: z.boolean().optional(),
  visibility: z.enum(["private", "team", "org"]).optional(),
  teamId: z.string().max(255).optional().nullable(),
});

export function registerEnterpriseOrgRoutes(app: Express): void {
  const authMiddleware = [isAuthenticated, resolveOrgContext, requireOrgId];

  // ========================================
  // Saved Views CRUD
  // ========================================

  app.get("/api/orgs/:orgId/saved-views", ...authMiddleware, async (req, res) => {
    try {
      const orgId = p(req.params.orgId);
      const userOrgId = (req as any).orgId;
      if (orgId !== userOrgId) return res.status(403).json({ error: "Access denied" });
      const resourceType = req.query.resourceType as string | undefined;
      const views = await storage.getSavedViews(orgId, resourceType);
      res.json(views);
    } catch (error) {
      logger.child("routes").error("Failed to fetch saved views", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch saved views" });
    }
  });

  app.post("/api/orgs/:orgId/saved-views", ...authMiddleware, requireMinRole("analyst"), async (req, res) => {
    try {
      const orgId = p(req.params.orgId);
      const userOrgId = (req as any).orgId;
      if (orgId !== userOrgId) return res.status(403).json({ error: "Access denied" });
      const parsed = savedViewSchema.safeParse(req.body);
      if (!parsed.success) return res.status(400).json({ error: "Invalid request", details: parsed.error.flatten() });
      const userId = (req as any).user?.id;
      const view = await storage.createSavedView({
        orgId,
        userId,
        name: parsed.data.name,
        resourceType: parsed.data.resourceType,
        filters: parsed.data.filters ?? {},
        columns: (parsed.data.columns ?? null) as string[] | null,
        sortField: parsed.data.sortField,
        sortDir: parsed.data.sortDir,
        isDefault: parsed.data.isDefault ?? false,
        visibility: parsed.data.visibility ?? "private",
        teamId: parsed.data.teamId ?? null,
      });
      res.status(201).json(view);
    } catch (error) {
      logger.child("routes").error("Failed to create saved view", { error: String(error) });
      res.status(500).json({ message: "Failed to create saved view" });
    }
  });

  app.put("/api/orgs/:orgId/saved-views/:viewId", ...authMiddleware, requireMinRole("analyst"), async (req, res) => {
    try {
      const orgId = p(req.params.orgId);
      const viewId = p(req.params.viewId);
      const userOrgId = (req as any).orgId;
      if (orgId !== userOrgId) return res.status(403).json({ error: "Access denied" });
      const existing = await storage.getSavedView(viewId);
      if (!existing || existing.orgId !== orgId) return res.status(404).json({ error: "Saved view not found" });
      const parsed = savedViewSchema.partial().safeParse(req.body);
      if (!parsed.success) return res.status(400).json({ error: "Invalid request", details: parsed.error.flatten() });
      const updated = await storage.updateSavedView(viewId, {
        ...parsed.data,
        columns: parsed.data.columns !== undefined ? (parsed.data.columns as string[] | null) : undefined,
      });
      res.json(updated);
    } catch (error) {
      logger.child("routes").error("Failed to update saved view", { error: String(error) });
      res.status(500).json({ message: "Failed to update saved view" });
    }
  });

  app.delete("/api/orgs/:orgId/saved-views/:viewId", ...authMiddleware, requireMinRole("analyst"), async (req, res) => {
    try {
      const orgId = p(req.params.orgId);
      const viewId = p(req.params.viewId);
      const userOrgId = (req as any).orgId;
      if (orgId !== userOrgId) return res.status(403).json({ error: "Access denied" });
      const existing = await storage.getSavedView(viewId);
      if (!existing || existing.orgId !== orgId) return res.status(404).json({ error: "Saved view not found" });
      await storage.deleteSavedView(viewId);
      res.json({ message: "Saved view deleted" });
    } catch (error) {
      logger.child("routes").error("Failed to delete saved view", { error: String(error) });
      res.status(500).json({ message: "Failed to delete saved view" });
    }
  });

  // ========================================
  // Security Policies
  // ========================================

  app.get("/api/orgs/:orgId/security-policy", ...authMiddleware, async (req, res) => {
    try {
      const orgId = p(req.params.orgId);
      const userOrgId = (req as any).orgId;
      if (orgId !== userOrgId) return res.status(403).json({ error: "Access denied" });
      const policy = await storage.getOrgSecurityPolicy(orgId);
      res.json(policy ?? null);
    } catch (error) {
      logger.child("routes").error("Failed to fetch security policy", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch security policy" });
    }
  });

  app.put("/api/orgs/:orgId/security-policy", ...authMiddleware, requireMinRole("owner"), async (req, res) => {
    try {
      const orgId = p(req.params.orgId);
      const userOrgId = (req as any).orgId;
      if (orgId !== userOrgId) return res.status(403).json({ error: "Access denied" });
      const parsed = securityPolicySchema.safeParse(req.body);
      if (!parsed.success) return res.status(400).json({ error: "Invalid request", details: parsed.error.flatten() });
      const userId = (req as any).user?.id;
      const policy = await storage.upsertOrgSecurityPolicy({ orgId, ...parsed.data });
      await storage.createAuditLog({
        userId,
        userName: (req as any).user?.firstName
          ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
          : "Admin",
        action: "security_policy_updated",
        resourceType: "security_policy",
        resourceId: orgId,
        details: parsed.data,
      });
      res.json(policy);
    } catch (error) {
      logger.child("routes").error("Failed to update security policy", { error: String(error) });
      res.status(500).json({ message: "Failed to update security policy" });
    }
  });

  // ========================================
  // Domain Verification
  // ========================================

  app.get("/api/orgs/:orgId/domains", ...authMiddleware, async (req, res) => {
    try {
      const orgId = p(req.params.orgId);
      const userOrgId = (req as any).orgId;
      if (orgId !== userOrgId) return res.status(403).json({ error: "Access denied" });
      const domains = await storage.getOrgDomainVerifications(orgId);
      res.json(domains);
    } catch (error) {
      logger.child("routes").error("Failed to fetch domains", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch domains" });
    }
  });

  app.post("/api/orgs/:orgId/domains", ...authMiddleware, requireMinRole("owner"), async (req, res) => {
    try {
      const orgId = p(req.params.orgId);
      const userOrgId = (req as any).orgId;
      if (orgId !== userOrgId) return res.status(403).json({ error: "Access denied" });
      const parsed = domainVerificationSchema.safeParse(req.body);
      if (!parsed.success) return res.status(400).json({ error: "Invalid request", details: parsed.error.flatten() });
      const userId = (req as any).user?.id;
      const verificationToken = `snx-verify-${randomBytes(16).toString("hex")}`;
      const verification = await storage.createOrgDomainVerification({
        orgId,
        domain: parsed.data.domain.toLowerCase(),
        verificationMethod: parsed.data.verificationMethod ?? "dns_txt",
        verificationToken,
        status: "pending",
        createdBy: userId,
        expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
      });
      await storage.createAuditLog({
        userId,
        userName: (req as any).user?.firstName
          ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
          : "Admin",
        action: "domain_verification_initiated",
        resourceType: "domain_verification",
        resourceId: verification.id,
        details: { domain: parsed.data.domain },
      });
      res.status(201).json(verification);
    } catch (error) {
      logger.child("routes").error("Failed to create domain verification", { error: String(error) });
      res.status(500).json({ message: "Failed to create domain verification" });
    }
  });

  app.post(
    "/api/orgs/:orgId/domains/:domainId/verify",
    ...authMiddleware,
    requireMinRole("owner"),
    async (req, res) => {
      try {
        const orgId = p(req.params.orgId);
        const domainId = p(req.params.domainId);
        const userOrgId = (req as any).orgId;
        if (orgId !== userOrgId) return res.status(403).json({ error: "Access denied" });
        const domain = await storage.getOrgDomainVerification(domainId);
        if (!domain || domain.orgId !== orgId) return res.status(404).json({ error: "Domain not found" });
        const updated = await storage.updateOrgDomainVerification(domainId, {
          status: "verified",
          verifiedAt: new Date(),
          lastCheckedAt: new Date(),
        });
        const userId = (req as any).user?.id;
        await storage.createAuditLog({
          userId,
          userName: (req as any).user?.firstName
            ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
            : "Admin",
          action: "domain_verified",
          resourceType: "domain_verification",
          resourceId: domainId,
          details: { domain: domain.domain },
        });
        res.json(updated);
      } catch (error) {
        logger.child("routes").error("Failed to verify domain", { error: String(error) });
        res.status(500).json({ message: "Failed to verify domain" });
      }
    },
  );

  app.delete("/api/orgs/:orgId/domains/:domainId", ...authMiddleware, requireMinRole("owner"), async (req, res) => {
    try {
      const orgId = p(req.params.orgId);
      const domainId = p(req.params.domainId);
      const userOrgId = (req as any).orgId;
      if (orgId !== userOrgId) return res.status(403).json({ error: "Access denied" });
      const domain = await storage.getOrgDomainVerification(domainId);
      if (!domain || domain.orgId !== orgId) return res.status(404).json({ error: "Domain not found" });
      await storage.deleteOrgDomainVerification(domainId);
      res.json({ message: "Domain removed" });
    } catch (error) {
      logger.child("routes").error("Failed to delete domain", { error: String(error) });
      res.status(500).json({ message: "Failed to delete domain" });
    }
  });

  // ========================================
  // SSO Configuration
  // ========================================

  app.get("/api/orgs/:orgId/sso", ...authMiddleware, async (req, res) => {
    try {
      const orgId = p(req.params.orgId);
      const userOrgId = (req as any).orgId;
      if (orgId !== userOrgId) return res.status(403).json({ error: "Access denied" });
      const config = await storage.getOrgSsoConfig(orgId);
      if (config) {
        const sanitized = {
          ...config,
          clientSecret: config.clientSecret ? "••••••••" : null,
          certificate: config.certificate ? "••••••••" : null,
        };
        return res.json(sanitized);
      }
      res.json(null);
    } catch (error) {
      logger.child("routes").error("Failed to fetch SSO config", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch SSO config" });
    }
  });

  app.put("/api/orgs/:orgId/sso", ...authMiddleware, requireMinRole("owner"), async (req, res) => {
    try {
      const orgId = p(req.params.orgId);
      const userOrgId = (req as any).orgId;
      if (orgId !== userOrgId) return res.status(403).json({ error: "Access denied" });
      const parsed = ssoConfigSchema.safeParse(req.body);
      if (!parsed.success) return res.status(400).json({ error: "Invalid request", details: parsed.error.flatten() });
      const userId = (req as any).user?.id;
      const config = await storage.upsertOrgSsoConfig({ orgId, ...parsed.data, createdBy: userId });
      await storage.createAuditLog({
        userId,
        userName: (req as any).user?.firstName
          ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
          : "Admin",
        action: "sso_config_updated",
        resourceType: "sso_config",
        resourceId: orgId,
        details: {
          providerType: parsed.data.providerType,
          enforced: parsed.data.enforced,
          enabled: parsed.data.enabled,
        },
      });
      const sanitized = {
        ...config,
        clientSecret: config.clientSecret ? "••••••••" : null,
        certificate: config.certificate ? "••••••••" : null,
      };
      res.json(sanitized);
    } catch (error) {
      logger.child("routes").error("Failed to update SSO config", { error: String(error) });
      res.status(500).json({ message: "Failed to update SSO config" });
    }
  });

  app.delete("/api/orgs/:orgId/sso", ...authMiddleware, requireMinRole("owner"), async (req, res) => {
    try {
      const orgId = p(req.params.orgId);
      const userOrgId = (req as any).orgId;
      if (orgId !== userOrgId) return res.status(403).json({ error: "Access denied" });
      await storage.deleteOrgSsoConfig(orgId);
      res.json({ message: "SSO configuration removed" });
    } catch (error) {
      logger.child("routes").error("Failed to delete SSO config", { error: String(error) });
      res.status(500).json({ message: "Failed to delete SSO config" });
    }
  });

  // ========================================
  // SCIM Provisioning
  // ========================================

  app.get("/api/orgs/:orgId/scim", ...authMiddleware, async (req, res) => {
    try {
      const orgId = p(req.params.orgId);
      const userOrgId = (req as any).orgId;
      if (orgId !== userOrgId) return res.status(403).json({ error: "Access denied" });
      const config = await storage.getOrgScimConfig(orgId);
      if (config) {
        const sanitized = {
          ...config,
          bearerTokenHash: undefined,
          bearerTokenPrefix: config.bearerTokenPrefix ?? null,
        };
        return res.json(sanitized);
      }
      res.json(null);
    } catch (error) {
      logger.child("routes").error("Failed to fetch SCIM config", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch SCIM config" });
    }
  });

  app.put("/api/orgs/:orgId/scim", ...authMiddleware, requireMinRole("owner"), async (req, res) => {
    try {
      const orgId = p(req.params.orgId);
      const userOrgId = (req as any).orgId;
      if (orgId !== userOrgId) return res.status(403).json({ error: "Access denied" });
      const parsed = scimConfigSchema.safeParse(req.body);
      if (!parsed.success) return res.status(400).json({ error: "Invalid request", details: parsed.error.flatten() });
      const userId = (req as any).user?.id;
      const config = await storage.upsertOrgScimConfig({ orgId, ...parsed.data, createdBy: userId });
      await storage.createAuditLog({
        userId,
        userName: (req as any).user?.firstName
          ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
          : "Admin",
        action: "scim_config_updated",
        resourceType: "scim_config",
        resourceId: orgId,
        details: { enabled: parsed.data.enabled },
      });
      const sanitized = { ...config, bearerTokenHash: undefined };
      res.json(sanitized);
    } catch (error) {
      logger.child("routes").error("Failed to update SCIM config", { error: String(error) });
      res.status(500).json({ message: "Failed to update SCIM config" });
    }
  });

  app.post("/api/orgs/:orgId/scim/generate-token", ...authMiddleware, requireMinRole("owner"), async (req, res) => {
    try {
      const orgId = p(req.params.orgId);
      const userOrgId = (req as any).orgId;
      if (orgId !== userOrgId) return res.status(403).json({ error: "Access denied" });
      const token = `snx_scim_${randomBytes(32).toString("hex")}`;
      const prefix = token.slice(0, 16);
      const { createHash } = await import("crypto");
      const hash = createHash("sha256").update(token).digest("hex");
      const userId = (req as any).user?.id;
      const existing = await storage.getOrgScimConfig(orgId);
      const endpointUrl = `/api/scim/v2/${orgId}`;
      if (existing) {
        await storage.upsertOrgScimConfig({
          orgId,
          enabled: true,
          bearerTokenHash: hash,
          bearerTokenPrefix: prefix,
          endpointUrl,
          createdBy: userId,
        });
      } else {
        await storage.upsertOrgScimConfig({
          orgId,
          enabled: true,
          bearerTokenHash: hash,
          bearerTokenPrefix: prefix,
          endpointUrl,
          defaultRole: "analyst",
          autoDeprovision: true,
          createdBy: userId,
        });
      }
      await storage.createAuditLog({
        userId,
        userName: (req as any).user?.firstName
          ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
          : "Admin",
        action: "scim_token_generated",
        resourceType: "scim_config",
        resourceId: orgId,
      });
      res.json({ token, prefix, endpointUrl });
    } catch (error) {
      logger.child("routes").error("Failed to generate SCIM token", { error: String(error) });
      res.status(500).json({ message: "Failed to generate SCIM token" });
    }
  });

  app.delete("/api/orgs/:orgId/scim", ...authMiddleware, requireMinRole("owner"), async (req, res) => {
    try {
      const orgId = p(req.params.orgId);
      const userOrgId = (req as any).orgId;
      if (orgId !== userOrgId) return res.status(403).json({ error: "Access denied" });
      await storage.deleteOrgScimConfig(orgId);
      res.json({ message: "SCIM configuration removed" });
    } catch (error) {
      logger.child("routes").error("Failed to delete SCIM config", { error: String(error) });
      res.status(500).json({ message: "Failed to delete SCIM config" });
    }
  });
}

import type { Express } from "express";
import dns from "dns";
import { promisify } from "util";
import { randomBytes } from "crypto";
import { storage, logger, p } from "./shared";
import { isAuthenticated } from "../auth";
import { requireMinRole, requireOrgId, resolveOrgContext } from "../rbac";

const resolveTxt = promisify(dns.resolveTxt);

const DOMAIN_REGEX = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;
const VALID_ROLES = ["owner", "admin", "analyst", "read_only"];

export function registerDomainAutoJoinRoutes(app: Express): void {
  app.post(
    "/api/orgs/:orgId/domains",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("owner"),
    async (req, res) => {
      try {
        const orgId = p(req.params.orgId);
        const userOrgId = (req as any).orgId;
        if (orgId !== userOrgId) return res.status(403).json({ error: "Access denied" });

        const { domain } = req.body;
        if (!domain || typeof domain !== "string") {
          return res.status(400).json({ error: "Domain is required" });
        }

        const normalizedDomain = domain.toLowerCase().trim();
        if (!DOMAIN_REGEX.test(normalizedDomain)) {
          return res.status(400).json({ error: "Invalid domain format" });
        }

        const existing = await storage.getOrgDomainVerifications(orgId);
        if (existing.some((d) => d.domain === normalizedDomain)) {
          return res.status(409).json({ error: "Domain already claimed by this organization" });
        }

        const token = `securenexus-verify-${randomBytes(16).toString("hex")}`;
        const verification = await storage.createOrgDomainVerification({
          orgId,
          domain: normalizedDomain,
          verificationMethod: "dns_txt",
          verificationToken: token,
          status: "pending",
          createdBy: (req as any).user?.id,
        });

        const userId = (req as any).user?.id;
        await storage.createAuditLog({
          userId,
          userName: (req as any).user?.email || "Admin",
          action: "domain_claimed",
          resourceType: "domain_verification",
          resourceId: verification.id,
          details: { domain: normalizedDomain },
        });

        res.status(201).json({
          ...verification,
          instructions: `Add a TXT record to your DNS for ${normalizedDomain} with value: ${token}`,
        });
      } catch (error) {
        logger.child("domains").error("Failed to claim domain", { error: String(error) });
        res.status(500).json({ message: "Failed to claim domain" });
      }
    },
  );

  app.get(
    "/api/orgs/:orgId/domains",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = p(req.params.orgId);
        const userOrgId = (req as any).orgId;
        if (orgId !== userOrgId) return res.status(403).json({ error: "Access denied" });

        const domains = await storage.getOrgDomainVerifications(orgId);
        res.json(domains);
      } catch (error) {
        logger.child("domains").error("Failed to list domains", { error: String(error) });
        res.status(500).json({ message: "Failed to list domains" });
      }
    },
  );

  app.post(
    "/api/orgs/:orgId/domains/:domainId/verify",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("owner"),
    async (req, res) => {
      try {
        const orgId = p(req.params.orgId);
        const domainId = p(req.params.domainId);
        const userOrgId = (req as any).orgId;
        if (orgId !== userOrgId) return res.status(403).json({ error: "Access denied" });

        const verification = await storage.getOrgDomainVerification(domainId);
        if (!verification || verification.orgId !== orgId) {
          return res.status(404).json({ error: "Domain not found" });
        }

        if (verification.status === "verified") {
          return res.json({ ...verification, message: "Domain already verified" });
        }

        let txtRecords: string[][] = [];
        try {
          txtRecords = await resolveTxt(verification.domain);
        } catch (dnsError: any) {
          await storage.updateOrgDomainVerification(domainId, { lastCheckedAt: new Date() });
          return res.status(422).json({
            error: "DNS lookup failed",
            details: `Could not resolve TXT records for ${verification.domain}. Ensure the DNS record is published and has propagated.`,
          });
        }

        const flatRecords = txtRecords.map((r) => r.join(""));
        const found = flatRecords.some((r) => r.includes(verification.verificationToken));

        if (!found) {
          await storage.updateOrgDomainVerification(domainId, { lastCheckedAt: new Date() });
          return res.status(422).json({
            error: "Verification token not found in DNS TXT records",
            expected: verification.verificationToken,
            found: flatRecords.slice(0, 10),
          });
        }

        const updated = await storage.updateOrgDomainVerification(domainId, {
          status: "verified",
          verifiedAt: new Date(),
          lastCheckedAt: new Date(),
        });

        const userId = (req as any).user?.id;
        await storage.createAuditLog({
          userId,
          userName: (req as any).user?.email || "Admin",
          action: "domain_verified",
          resourceType: "domain_verification",
          resourceId: domainId,
          details: { domain: verification.domain },
        });

        res.json({ ...updated, message: "Domain verified successfully" });
      } catch (error) {
        logger.child("domains").error("Failed to verify domain", { error: String(error) });
        res.status(500).json({ message: "Failed to verify domain" });
      }
    },
  );

  app.patch(
    "/api/orgs/:orgId/domains/:domainId",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("owner"),
    async (req, res) => {
      try {
        const orgId = p(req.params.orgId);
        const domainId = p(req.params.domainId);
        const userOrgId = (req as any).orgId;
        if (orgId !== userOrgId) return res.status(403).json({ error: "Access denied" });

        const verification = await storage.getOrgDomainVerification(domainId);
        if (!verification || verification.orgId !== orgId) {
          return res.status(404).json({ error: "Domain not found" });
        }

        const { autoJoin, defaultRole } = req.body;
        const updateData: Record<string, any> = {};

        if (typeof autoJoin === "boolean") {
          updateData.autoJoin = autoJoin;
        }
        if (defaultRole !== undefined) {
          if (!VALID_ROLES.includes(defaultRole)) {
            return res.status(400).json({ error: `Invalid role. Must be one of: ${VALID_ROLES.join(", ")}` });
          }
          updateData.defaultRole = defaultRole;
        }

        if (Object.keys(updateData).length === 0) {
          return res.status(400).json({ error: "No valid fields to update" });
        }

        const updated = await storage.updateOrgDomainVerification(domainId, updateData);

        const userId = (req as any).user?.id;
        await storage.createAuditLog({
          userId,
          userName: (req as any).user?.email || "Admin",
          action: "domain_settings_updated",
          resourceType: "domain_verification",
          resourceId: domainId,
          details: { domain: verification.domain, ...updateData },
        });

        res.json(updated);
      } catch (error) {
        logger.child("domains").error("Failed to update domain", { error: String(error) });
        res.status(500).json({ message: "Failed to update domain settings" });
      }
    },
  );

  app.delete(
    "/api/orgs/:orgId/domains/:domainId",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("owner"),
    async (req, res) => {
      try {
        const orgId = p(req.params.orgId);
        const domainId = p(req.params.domainId);
        const userOrgId = (req as any).orgId;
        if (orgId !== userOrgId) return res.status(403).json({ error: "Access denied" });

        const verification = await storage.getOrgDomainVerification(domainId);
        if (!verification || verification.orgId !== orgId) {
          return res.status(404).json({ error: "Domain not found" });
        }

        await storage.deleteOrgDomainVerification(domainId);

        const userId = (req as any).user?.id;
        await storage.createAuditLog({
          userId,
          userName: (req as any).user?.email || "Admin",
          action: "domain_removed",
          resourceType: "domain_verification",
          resourceId: domainId,
          details: { domain: verification.domain },
        });

        res.json({ message: "Domain removed" });
      } catch (error) {
        logger.child("domains").error("Failed to remove domain", { error: String(error) });
        res.status(500).json({ message: "Failed to remove domain" });
      }
    },
  );
}

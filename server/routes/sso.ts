import type { Express } from "express";
import { randomBytes, createCipheriv, createDecipheriv } from "crypto";
import { storage, logger, p } from "./shared";
import { isAuthenticated } from "../auth";
import { authStorage } from "../auth/storage";
import { requireMinRole, requireOrgId, resolveOrgContext } from "../rbac";

const SSO_ENCRYPTION_KEY = process.env.SSO_ENCRYPTION_KEY;
if (!SSO_ENCRYPTION_KEY || SSO_ENCRYPTION_KEY.length < 64) {
  logger
    .child("sso")
    .warn(
      "SSO_ENCRYPTION_KEY env var is missing or too short (need 64 hex chars / 32 bytes). SSO encryption will fail at runtime.",
    );
}
const ENCRYPTION_ALGORITHM = "aes-256-gcm";

function encrypt(text: string): string {
  if (!SSO_ENCRYPTION_KEY || SSO_ENCRYPTION_KEY.length < 64) {
    throw new Error("SSO_ENCRYPTION_KEY is not configured. Cannot encrypt SSO secrets.");
  }
  const key = Buffer.from(SSO_ENCRYPTION_KEY.slice(0, 64), "hex");
  const iv = randomBytes(16);
  const cipher = createCipheriv(ENCRYPTION_ALGORITHM, key, iv);
  let encrypted = cipher.update(text, "utf8", "hex");
  encrypted += cipher.final("hex");
  const authTag = cipher.getAuthTag().toString("hex");
  return `${iv.toString("hex")}:${authTag}:${encrypted}`;
}

function decrypt(encryptedText: string): string {
  const parts = encryptedText.split(":");
  if (parts.length !== 3) throw new Error("Invalid encrypted format");
  if (!SSO_ENCRYPTION_KEY || SSO_ENCRYPTION_KEY.length < 64) {
    throw new Error("SSO_ENCRYPTION_KEY is not configured. Cannot decrypt SSO secrets.");
  }
  const key = Buffer.from(SSO_ENCRYPTION_KEY.slice(0, 64), "hex");
  const iv = Buffer.from(parts[0], "hex");
  const authTag = Buffer.from(parts[1], "hex");
  const encrypted = parts[2];
  const decipher = createDecipheriv(ENCRYPTION_ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);
  let decrypted = decipher.update(encrypted, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

const VALID_PROVIDERS = ["saml", "oidc"] as const;
const VALID_ROLES = ["owner", "admin", "analyst", "read_only"];

function sanitizeSsoConfig(config: any): any {
  if (!config) return config;
  const safe = { ...config };
  if (safe.certificate) safe.certificate = "••••••••";
  if (safe.clientSecret) safe.clientSecret = "••••••••";
  return safe;
}

export function registerSsoRoutes(app: Express): void {
  app.get(
    "/api/orgs/:orgId/sso/config",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = p(req.params.orgId);
        const userOrgId = (req as any).orgId;
        if (orgId !== userOrgId) return res.status(403).json({ error: "Access denied" });

        const config = await storage.getOrgSsoConfig(orgId);
        if (!config) return res.json(null);

        res.json(sanitizeSsoConfig(config));
      } catch (error) {
        logger.child("sso").error("Failed to get SSO config", { error: String(error) });
        res.status(500).json({ message: "Failed to get SSO configuration" });
      }
    },
  );

  app.post(
    "/api/orgs/:orgId/sso/config",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("owner"),
    async (req, res) => {
      try {
        const orgId = p(req.params.orgId);
        const userOrgId = (req as any).orgId;
        if (orgId !== userOrgId) return res.status(403).json({ error: "Access denied" });

        const sub = await storage.getSubscription(orgId);
        if (!sub) {
          return res.status(403).json({ error: "No active subscription found" });
        }
        const plan = await storage.getPlan(sub.planId);
        if (!plan) {
          return res.status(403).json({ error: "Subscription plan not found" });
        }
        const features = (plan.features || {}) as Record<string, any>;
        if (!features.sso && plan.name !== "enterprise" && plan.name !== "custom") {
          return res.status(403).json({ error: "SSO is only available on Enterprise plans" });
        }

        const {
          providerType,
          metadataUrl,
          entityId,
          ssoUrl,
          certificate,
          clientId,
          clientSecret,
          allowedDomains,
          autoProvision,
          defaultRole,
          enforced,
          enabled,
        } = req.body;

        if (!providerType || !VALID_PROVIDERS.includes(providerType)) {
          return res.status(400).json({ error: `Provider type must be one of: ${VALID_PROVIDERS.join(", ")}` });
        }

        if (providerType === "saml") {
          if (!ssoUrl || typeof ssoUrl !== "string") {
            return res.status(400).json({ error: "SAML SSO URL is required" });
          }
          if (!certificate || typeof certificate !== "string") {
            return res.status(400).json({ error: "SAML IdP certificate is required" });
          }
        }

        if (providerType === "oidc") {
          if (!clientId || typeof clientId !== "string") {
            return res.status(400).json({ error: "OIDC client ID is required" });
          }
          if (!clientSecret || typeof clientSecret !== "string") {
            return res.status(400).json({ error: "OIDC client secret is required" });
          }
          if (!metadataUrl || typeof metadataUrl !== "string") {
            return res.status(400).json({ error: "OIDC discovery URL is required" });
          }
        }

        if (defaultRole && !VALID_ROLES.includes(defaultRole)) {
          return res.status(400).json({ error: `Invalid role. Must be one of: ${VALID_ROLES.join(", ")}` });
        }

        if (allowedDomains && !Array.isArray(allowedDomains)) {
          return res.status(400).json({ error: "allowedDomains must be an array" });
        }

        const configData: any = {
          orgId,
          providerType,
          metadataUrl: metadataUrl || null,
          entityId: entityId || null,
          ssoUrl: ssoUrl || null,
          certificate: certificate ? encrypt(certificate) : null,
          clientId: clientId || null,
          clientSecret: clientSecret ? encrypt(clientSecret) : null,
          allowedDomains: allowedDomains || [],
          autoProvision: autoProvision !== undefined ? autoProvision : true,
          defaultRole: defaultRole || "analyst",
          enforced: enforced || false,
          enabled: enabled !== undefined ? enabled : false,
          createdBy: (req as any).user?.id,
        };

        const config = await storage.upsertOrgSsoConfig(configData);

        const userId = (req as any).user?.id;
        await storage.createAuditLog({
          userId,
          userName: (req as any).user?.email || "Admin",
          action: "sso_config_updated",
          resourceType: "sso_config",
          resourceId: config.id,
          details: { providerType, enabled: configData.enabled, enforced: configData.enforced },
        });

        res.json(sanitizeSsoConfig(config));
      } catch (error) {
        logger.child("sso").error("Failed to save SSO config", { error: String(error) });
        res.status(500).json({ message: "Failed to save SSO configuration" });
      }
    },
  );

  app.delete(
    "/api/orgs/:orgId/sso/config",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("owner"),
    async (req, res) => {
      try {
        const orgId = p(req.params.orgId);
        const userOrgId = (req as any).orgId;
        if (orgId !== userOrgId) return res.status(403).json({ error: "Access denied" });

        await storage.deleteOrgSsoConfig(orgId);

        const userId = (req as any).user?.id;
        await storage.createAuditLog({
          userId,
          userName: (req as any).user?.email || "Admin",
          action: "sso_config_deleted",
          resourceType: "sso_config",
          resourceId: orgId,
        });

        res.json({ message: "SSO configuration removed" });
      } catch (error) {
        logger.child("sso").error("Failed to delete SSO config", { error: String(error) });
        res.status(500).json({ message: "Failed to delete SSO configuration" });
      }
    },
  );

  app.post(
    "/api/orgs/:orgId/sso/test",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("owner"),
    async (req, res) => {
      try {
        const orgId = p(req.params.orgId);
        const userOrgId = (req as any).orgId;
        if (orgId !== userOrgId) return res.status(403).json({ error: "Access denied" });

        const config = await storage.getOrgSsoConfig(orgId);
        if (!config) {
          return res.status(404).json({ error: "No SSO configuration found" });
        }

        const checks: { check: string; status: "pass" | "fail"; message: string }[] = [];

        checks.push({
          check: "provider_type",
          status: VALID_PROVIDERS.includes(config.providerType as any) ? "pass" : "fail",
          message: `Provider type: ${config.providerType}`,
        });

        if (config.providerType === "saml") {
          checks.push({
            check: "sso_url",
            status: config.ssoUrl ? "pass" : "fail",
            message: config.ssoUrl ? `SSO URL configured: ${config.ssoUrl}` : "SSO URL not configured",
          });
          checks.push({
            check: "certificate",
            status: config.certificate ? "pass" : "fail",
            message: config.certificate ? "IdP certificate configured" : "IdP certificate not configured",
          });
          if (config.certificate) {
            try {
              decrypt(config.certificate);
              checks.push({
                check: "certificate_decrypt",
                status: "pass",
                message: "Certificate decryption successful",
              });
            } catch {
              checks.push({ check: "certificate_decrypt", status: "fail", message: "Certificate decryption failed" });
            }
          }
        }

        if (config.providerType === "oidc") {
          checks.push({
            check: "client_id",
            status: config.clientId ? "pass" : "fail",
            message: config.clientId ? "Client ID configured" : "Client ID not configured",
          });
          checks.push({
            check: "client_secret",
            status: config.clientSecret ? "pass" : "fail",
            message: config.clientSecret ? "Client secret configured" : "Client secret not configured",
          });
          checks.push({
            check: "metadata_url",
            status: config.metadataUrl ? "pass" : "fail",
            message: config.metadataUrl ? `Discovery URL: ${config.metadataUrl}` : "Discovery URL not configured",
          });

          if (config.metadataUrl) {
            try {
              const metaRes = await fetch(config.metadataUrl, { signal: AbortSignal.timeout(5000) });
              checks.push({
                check: "metadata_reachable",
                status: metaRes.ok ? "pass" : "fail",
                message: metaRes.ok ? "Discovery endpoint reachable" : `Discovery endpoint returned ${metaRes.status}`,
              });
            } catch (fetchErr) {
              checks.push({
                check: "metadata_reachable",
                status: "fail",
                message: `Discovery endpoint unreachable: ${String(fetchErr)}`,
              });
            }
          }
        }

        const allPassed = checks.every((c) => c.status === "pass");
        res.json({ success: allPassed, checks });
      } catch (error) {
        logger.child("sso").error("Failed to test SSO config", { error: String(error) });
        res.status(500).json({ message: "Failed to test SSO configuration" });
      }
    },
  );

  app.get("/api/sso/:slug/login", async (req, res) => {
    try {
      const slug = p(req.params.slug);
      if (!slug || typeof slug !== "string" || slug.length > 255) {
        return res.status(400).json({ error: "Invalid organization slug" });
      }

      const org = await storage.getOrganizationBySlug(slug);
      if (!org) return res.status(404).json({ error: "Organization not found" });
      if (org.deletedAt) return res.status(410).json({ error: "Organization has been deleted" });

      const config = await storage.getOrgSsoConfig(org.id);
      if (!config || !config.enabled) {
        return res.status(404).json({ error: "SSO is not configured or not enabled for this organization" });
      }

      const appBaseUrl = process.env.APP_BASE_URL || "https://nexus.aricatech.xyz";

      if (config.providerType === "saml") {
        if (!config.ssoUrl) {
          return res.status(500).json({ error: "SAML SSO URL not configured" });
        }
        const callbackUrl = `${appBaseUrl}/api/sso/${slug}/acs`;
        const samlRequest = Buffer.from(
          `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
            `ID="_${randomBytes(16).toString("hex")}" Version="2.0" ` +
            `IssueInstant="${new Date().toISOString()}" ` +
            `AssertionConsumerServiceURL="${callbackUrl}" ` +
            `Destination="${config.ssoUrl}">` +
            `<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">${config.entityId || appBaseUrl}</saml:Issuer>` +
            `</samlp:AuthnRequest>`,
        ).toString("base64");

        const redirectUrl = `${config.ssoUrl}?SAMLRequest=${encodeURIComponent(samlRequest)}&RelayState=${encodeURIComponent(slug)}`;
        return res.redirect(redirectUrl);
      }

      if (config.providerType === "oidc") {
        if (!config.metadataUrl || !config.clientId) {
          return res.status(500).json({ error: "OIDC configuration incomplete" });
        }

        let authorizationEndpoint: string;
        try {
          const metaRes = await fetch(config.metadataUrl, { signal: AbortSignal.timeout(5000) });
          const metadata = (await metaRes.json()) as Record<string, any>;
          authorizationEndpoint = metadata.authorization_endpoint;
          if (!authorizationEndpoint) throw new Error("Missing authorization_endpoint");
        } catch (fetchErr) {
          return res.status(502).json({ error: "Failed to fetch OIDC discovery metadata" });
        }

        const state = `${slug}:${randomBytes(16).toString("hex")}`;
        const callbackUrl = `${appBaseUrl}/api/sso/${slug}/callback`;
        const params = new URLSearchParams({
          response_type: "code",
          client_id: config.clientId,
          redirect_uri: callbackUrl,
          scope: "openid email profile",
          state,
        });

        return res.redirect(`${authorizationEndpoint}?${params.toString()}`);
      }

      return res.status(400).json({ error: "Unsupported SSO provider type" });
    } catch (error) {
      logger.child("sso").error("Failed to initiate SSO login", { error: String(error) });
      res.status(500).json({ message: "Failed to initiate SSO login" });
    }
  });

  app.post("/api/sso/:slug/acs", async (req, res) => {
    try {
      const slug = p(req.params.slug);
      const org = await storage.getOrganizationBySlug(slug);
      if (!org) return res.status(404).json({ error: "Organization not found" });

      const config = await storage.getOrgSsoConfig(org.id);
      if (!config || !config.enabled || config.providerType !== "saml") {
        return res.status(400).json({ error: "SAML SSO not configured" });
      }

      const { SAMLResponse } = req.body;
      if (!SAMLResponse) {
        return res.status(400).json({ error: "Missing SAMLResponse" });
      }

      let email: string | null = null;
      let firstName: string | null = null;
      let lastName: string | null = null;

      try {
        const decoded = Buffer.from(SAMLResponse, "base64").toString("utf8");
        const emailMatch = decoded.match(
          /<(?:saml2?:)?Attribute[^>]*Name="(?:email|http:\/\/schemas\.xmlsoap\.org\/ws\/2005\/05\/identity\/claims\/emailaddress|urn:oid:0\.9\.2342\.19200300\.100\.1\.3)"[^>]*>[\s\S]*?<(?:saml2?:)?AttributeValue[^>]*>([^<]+)<\/(?:saml2?:)?AttributeValue>/,
        );
        if (emailMatch) email = emailMatch[1].trim().toLowerCase();

        if (!email) {
          const nameIdMatch = decoded.match(/<(?:saml2?:)?NameID[^>]*>([^<]+)<\/(?:saml2?:)?NameID>/);
          if (nameIdMatch && nameIdMatch[1].includes("@")) {
            email = nameIdMatch[1].trim().toLowerCase();
          }
        }

        const firstNameMatch = decoded.match(
          /<(?:saml2?:)?Attribute[^>]*Name="(?:firstName|givenName|http:\/\/schemas\.xmlsoap\.org\/ws\/2005\/05\/identity\/claims\/givenname)"[^>]*>[\s\S]*?<(?:saml2?:)?AttributeValue[^>]*>([^<]+)<\/(?:saml2?:)?AttributeValue>/,
        );
        if (firstNameMatch) firstName = firstNameMatch[1].trim();

        const lastNameMatch = decoded.match(
          /<(?:saml2?:)?Attribute[^>]*Name="(?:lastName|surname|http:\/\/schemas\.xmlsoap\.org\/ws\/2005\/05\/identity\/claims\/surname)"[^>]*>[\s\S]*?<(?:saml2?:)?AttributeValue[^>]*>([^<]+)<\/(?:saml2?:)?AttributeValue>/,
        );
        if (lastNameMatch) lastName = lastNameMatch[1].trim();
      } catch {
        return res.status(400).json({ error: "Failed to parse SAML assertion" });
      }

      if (!email) {
        return res.status(400).json({ error: "Could not extract email from SAML assertion" });
      }

      if (config.allowedDomains && config.allowedDomains.length > 0) {
        const emailDomain = email.split("@")[1];
        if (!config.allowedDomains.includes(emailDomain)) {
          return res.status(403).json({ error: "Email domain not allowed for this SSO configuration" });
        }
      }

      const result = await handleSsoUserProvision(org.id, config, email, firstName, lastName, req);
      if (!result.success) {
        return res.status(result.status || 500).json({ error: result.error });
      }

      res.redirect("/");
    } catch (error) {
      logger.child("sso").error("SAML ACS error", { error: String(error) });
      res.redirect("/?error=sso_failed");
    }
  });

  app.get("/api/sso/:slug/callback", async (req, res) => {
    try {
      const slug = p(req.params.slug);
      const org = await storage.getOrganizationBySlug(slug);
      if (!org) return res.redirect("/?error=org_not_found");

      const config = await storage.getOrgSsoConfig(org.id);
      if (!config || !config.enabled || config.providerType !== "oidc") {
        return res.redirect("/?error=oidc_not_configured");
      }

      const { code, error: oauthError } = req.query;
      if (oauthError) {
        return res.redirect(`/?error=sso_denied&details=${encodeURIComponent(String(oauthError))}`);
      }
      if (!code || typeof code !== "string") {
        return res.redirect("/?error=missing_auth_code");
      }

      if (!config.metadataUrl || !config.clientId || !config.clientSecret) {
        return res.redirect("/?error=oidc_config_incomplete");
      }

      let tokenEndpoint: string;
      let userinfoEndpoint: string;
      try {
        const metaRes = await fetch(config.metadataUrl, { signal: AbortSignal.timeout(5000) });
        const metadata = (await metaRes.json()) as Record<string, any>;
        tokenEndpoint = metadata.token_endpoint;
        userinfoEndpoint = metadata.userinfo_endpoint;
        if (!tokenEndpoint) throw new Error("Missing token_endpoint");
      } catch {
        return res.redirect("/?error=oidc_metadata_failed");
      }

      let decryptedSecret: string;
      try {
        decryptedSecret = decrypt(config.clientSecret);
      } catch {
        return res.redirect("/?error=oidc_secret_decrypt_failed");
      }

      const appBaseUrl = process.env.APP_BASE_URL || "https://nexus.aricatech.xyz";
      const callbackUrl = `${appBaseUrl}/api/sso/${slug}/callback`;

      let tokenData: Record<string, any>;
      try {
        const tokenRes = await fetch(tokenEndpoint, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            grant_type: "authorization_code",
            code,
            redirect_uri: callbackUrl,
            client_id: config.clientId,
            client_secret: decryptedSecret,
          }).toString(),
          signal: AbortSignal.timeout(10000),
        });
        tokenData = (await tokenRes.json()) as Record<string, any>;
        if (!tokenData.access_token) throw new Error("No access_token in response");
      } catch (tokenErr) {
        logger.child("sso").error("OIDC token exchange failed", { error: String(tokenErr) });
        return res.redirect("/?error=oidc_token_failed");
      }

      let email: string | null = null;
      let firstName: string | null = null;
      let lastName: string | null = null;

      if (tokenData.id_token) {
        try {
          const payload = JSON.parse(Buffer.from(tokenData.id_token.split(".")[1], "base64url").toString());
          email = payload.email?.toLowerCase() || null;
          firstName = payload.given_name || null;
          lastName = payload.family_name || null;
        } catch {
          /* fall through to userinfo */
        }
      }

      if (!email && userinfoEndpoint) {
        try {
          const uiRes = await fetch(userinfoEndpoint, {
            headers: { Authorization: `Bearer ${tokenData.access_token}` },
            signal: AbortSignal.timeout(5000),
          });
          const userinfo = (await uiRes.json()) as Record<string, any>;
          email = userinfo.email?.toLowerCase() || null;
          firstName = firstName || userinfo.given_name || null;
          lastName = lastName || userinfo.family_name || null;
        } catch {
          /* no userinfo available */
        }
      }

      if (!email) {
        return res.redirect("/?error=sso_no_email");
      }

      if (config.allowedDomains && config.allowedDomains.length > 0) {
        const emailDomain = email.split("@")[1];
        if (!config.allowedDomains.includes(emailDomain)) {
          return res.redirect("/?error=sso_domain_not_allowed");
        }
      }

      const result = await handleSsoUserProvision(org.id, config, email, firstName, lastName, req);
      if (!result.success) {
        return res.redirect(`/?error=sso_provision_failed`);
      }

      res.redirect("/");
    } catch (error) {
      logger.child("sso").error("OIDC callback error", { error: String(error) });
      res.redirect("/?error=sso_failed");
    }
  });

  app.get("/api/sso/check/:slug", async (req, res) => {
    try {
      const slug = p(req.params.slug);
      if (!slug || typeof slug !== "string" || slug.length > 255) {
        return res.status(400).json({ error: "Invalid slug" });
      }

      const org = await storage.getOrganizationBySlug(slug);
      if (!org || org.deletedAt) {
        return res.json({ ssoEnabled: false });
      }

      const config = await storage.getOrgSsoConfig(org.id);
      res.json({
        ssoEnabled: !!(config && config.enabled),
        providerType: config?.providerType || null,
        enforced: config?.enforced || false,
        orgName: org.name,
      });
    } catch (error) {
      logger.child("sso").error("Failed to check SSO status", { error: String(error) });
      res.status(500).json({ message: "Failed to check SSO status" });
    }
  });
}

async function handleSsoUserProvision(
  orgId: string,
  config: any,
  email: string,
  firstName: string | null,
  lastName: string | null,
  req: any,
): Promise<{ success: boolean; status?: number; error?: string }> {
  try {
    let user = await authStorage.getUserByEmail(email);

    if (!user && config.autoProvision) {
      user = await authStorage.upsertUser({
        email,
        firstName: firstName || null,
        lastName: lastName || null,
        passwordHash: null,
      });
      logger.child("sso").info("Auto-provisioned SSO user", { email, orgId });
    }

    if (!user) {
      return { success: false, status: 403, error: "User not found and auto-provisioning is disabled" };
    }

    const existingMembership = await storage.getOrgMembership(orgId, user.id);
    if (!existingMembership) {
      await storage.createOrgMembership({
        orgId,
        userId: user.id,
        role: config.defaultRole || "analyst",
        status: "active",
        joinedAt: new Date(),
      });
    }

    await new Promise<void>((resolve, reject) => {
      req.login(user, (err: any) => {
        if (err) reject(err);
        else resolve();
      });
    });

    await storage.createAuditLog({
      userId: user.id,
      userName: email,
      action: "sso_login",
      resourceType: "user",
      resourceId: user.id,
      details: { orgId, providerType: config.providerType },
    });

    return { success: true };
  } catch (error) {
    logger.child("sso").error("SSO user provision failed", { error: String(error), email, orgId });
    return { success: false, status: 500, error: "SSO authentication failed" };
  }
}

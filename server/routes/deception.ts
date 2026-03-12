import type { Express } from "express";
import { eq, and, desc, sql, count } from "drizzle-orm";
import { logger, getOrgId } from "./shared";
import { isAuthenticated } from "../auth";
import { db } from "../db";
import { canaryTokens, honeypotAssets, deceptionHits, alerts } from "@shared/schema";
import {
  generateCanaryToken,
  generateCallbackUrl,
  processDeceptionHit,
  getDeploymentInstructions,
  classifyHitSeverity,
} from "../deception-engine";

const log = logger.child("deception");

const ALLOWED_TOKEN_TYPES = [
  "aws_key",
  "database_credential",
  "api_key",
  "document",
  "email_pixel",
  "dns_token",
  "url_token",
  "kubeconfig",
  "ssh_key",
  "slack_webhook",
];

const ALLOWED_ASSET_TYPES = [
  "honey_account",
  "honeypot_endpoint",
  "deception_fileshare",
  "network_decoy",
  "fake_rdp",
  "fake_ssh",
  "fake_admin_panel",
  "fake_database",
];

const ALLOWED_DEPLOYMENT_TARGETS = [
  "s3_bucket",
  "github_repo",
  "email",
  "shared_drive",
  "active_directory",
  "kubernetes",
  "ci_cd_pipeline",
  "internal_wiki",
];

export function registerDeceptionRoutes(app: Express): void {
  // =========================================================================
  // CANARY TOKENS
  // =========================================================================

  // List canary tokens
  app.get("/api/deception/canary-tokens", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const tokenType = req.query.type ? String(req.query.type) : undefined;
      const activeOnly = req.query.active === "true";

      const conditions = [eq(canaryTokens.orgId, orgId)];
      if (tokenType && ALLOWED_TOKEN_TYPES.includes(tokenType)) {
        conditions.push(eq(canaryTokens.tokenType, tokenType));
      }
      if (activeOnly) {
        conditions.push(eq(canaryTokens.isActive, true));
      }

      const tokens = await db
        .select()
        .from(canaryTokens)
        .where(and(...conditions))
        .orderBy(desc(canaryTokens.createdAt))
        .limit(200);

      // Mask token values — never return raw secrets to the frontend
      const masked = tokens.map((t) => ({
        ...t,
        tokenValue: maskTokenValue(t.tokenType, t.tokenValue),
        callbackSecret: "***",
      }));

      res.json({ tokens: masked });
    } catch (error) {
      log.error("List canary tokens error", { error: String(error) });
      res.status(500).json({ message: "Failed to list canary tokens" });
    }
  });

  // Create canary token
  app.post("/api/deception/canary-tokens", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { name, description, tokenType, deploymentTarget } = req.body;

      if (!name || typeof name !== "string") {
        return res.status(400).json({ message: "Name is required" });
      }
      if (!tokenType || !ALLOWED_TOKEN_TYPES.includes(tokenType)) {
        return res
          .status(400)
          .json({ message: `Invalid token type. Must be one of: ${ALLOWED_TOKEN_TYPES.join(", ")}` });
      }
      if (deploymentTarget && !ALLOWED_DEPLOYMENT_TARGETS.includes(deploymentTarget)) {
        return res.status(400).json({ message: `Invalid deployment target` });
      }

      const { tokenValue, tokenHash, callbackSecret } = generateCanaryToken(tokenType);
      const tempId = crypto.randomUUID();
      const callbackUrl = generateCallbackUrl(orgId, tempId);

      const [token] = await db
        .insert(canaryTokens)
        .values({
          orgId,
          name: name.substring(0, 200),
          description: typeof description === "string" ? description.substring(0, 1000) : null,
          tokenType,
          tokenValue,
          tokenHash,
          callbackUrl,
          callbackSecret,
          deploymentTarget: deploymentTarget || null,
          createdBy: ((req as unknown as Record<string, unknown>).userId as string) || null,
        })
        .returning();

      // Generate deployment instructions
      const instructions = deploymentTarget ? getDeploymentInstructions(tokenType, deploymentTarget, tokenValue) : null;

      res.status(201).json({
        token: {
          ...token,
          callbackSecret: "***", // Don't expose the HMAC secret
        },
        deploymentInstructions: instructions,
      });
    } catch (error) {
      log.error("Create canary token error", { error: String(error) });
      res.status(500).json({ message: "Failed to create canary token" });
    }
  });

  // Get single canary token with full details
  app.get("/api/deception/canary-tokens/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);

      const [token] = await db
        .select()
        .from(canaryTokens)
        .where(and(eq(canaryTokens.id, id), eq(canaryTokens.orgId, orgId)));

      if (!token) {
        return res.status(404).json({ message: "Token not found" });
      }

      // Get hits for this token
      const hits = await db
        .select()
        .from(deceptionHits)
        .where(and(eq(deceptionHits.canaryTokenId, id), eq(deceptionHits.orgId, orgId)))
        .orderBy(desc(deceptionHits.hitAt))
        .limit(50);

      res.json({
        token: {
          ...token,
          tokenValue: maskTokenValue(token.tokenType, token.tokenValue),
          callbackSecret: "***",
        },
        hits,
      });
    } catch (error) {
      log.error("Get canary token error", { error: String(error) });
      res.status(500).json({ message: "Failed to get canary token" });
    }
  });

  // Toggle canary token active/inactive
  app.patch("/api/deception/canary-tokens/:id/toggle", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);

      const [token] = await db
        .select()
        .from(canaryTokens)
        .where(and(eq(canaryTokens.id, id), eq(canaryTokens.orgId, orgId)));

      if (!token) {
        return res.status(404).json({ message: "Token not found" });
      }

      const [updated] = await db
        .update(canaryTokens)
        .set({ isActive: !token.isActive, updatedAt: new Date() })
        .where(and(eq(canaryTokens.id, id), eq(canaryTokens.orgId, orgId)))
        .returning();

      res.json({ token: { ...updated, tokenValue: "***", callbackSecret: "***" } });
    } catch (error) {
      log.error("Toggle canary token error", { error: String(error) });
      res.status(500).json({ message: "Failed to toggle canary token" });
    }
  });

  // Delete canary token
  app.delete("/api/deception/canary-tokens/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);

      const [token] = await db
        .select()
        .from(canaryTokens)
        .where(and(eq(canaryTokens.id, id), eq(canaryTokens.orgId, orgId)));

      if (!token) {
        return res.status(404).json({ message: "Token not found" });
      }

      await db.delete(canaryTokens).where(and(eq(canaryTokens.id, id), eq(canaryTokens.orgId, orgId)));

      res.json({ message: "Token deleted" });
    } catch (error) {
      log.error("Delete canary token error", { error: String(error) });
      res.status(500).json({ message: "Failed to delete canary token" });
    }
  });

  // Get deployment instructions for a token
  app.get("/api/deception/canary-tokens/:id/deploy-instructions", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);
      const target = req.query.target ? String(req.query.target) : undefined;

      const [token] = await db
        .select()
        .from(canaryTokens)
        .where(and(eq(canaryTokens.id, id), eq(canaryTokens.orgId, orgId)));

      if (!token) {
        return res.status(404).json({ message: "Token not found" });
      }

      if (!target || !ALLOWED_DEPLOYMENT_TARGETS.includes(target)) {
        return res.status(400).json({ message: "Valid deployment target required" });
      }

      const instructions = getDeploymentInstructions(token.tokenType, target, token.tokenValue);

      res.json({ instructions, target, tokenType: token.tokenType });
    } catch (error) {
      log.error("Get deploy instructions error", { error: String(error) });
      res.status(500).json({ message: "Failed to get deployment instructions" });
    }
  });

  // =========================================================================
  // HONEYPOT ASSETS
  // =========================================================================

  // List honeypot assets
  app.get("/api/deception/honeypot-assets", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const assetType = req.query.type ? String(req.query.type) : undefined;

      const conditions = [eq(honeypotAssets.orgId, orgId)];
      if (assetType && ALLOWED_ASSET_TYPES.includes(assetType)) {
        conditions.push(eq(honeypotAssets.assetType, assetType));
      }

      const assets = await db
        .select()
        .from(honeypotAssets)
        .where(and(...conditions))
        .orderBy(desc(honeypotAssets.createdAt))
        .limit(200);

      res.json({ assets });
    } catch (error) {
      log.error("List honeypot assets error", { error: String(error) });
      res.status(500).json({ message: "Failed to list honeypot assets" });
    }
  });

  // Create honeypot asset
  app.post("/api/deception/honeypot-assets", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const {
        name,
        description,
        assetType,
        fakeUsername,
        fakeEmail,
        fakeDomain,
        listenAddress,
        protocol,
        sharePath,
        decoyFiles,
        decoyHostname,
        decoyIp,
        openPorts,
        configuration,
      } = req.body;

      if (!name || typeof name !== "string") {
        return res.status(400).json({ message: "Name is required" });
      }
      if (!assetType || !ALLOWED_ASSET_TYPES.includes(assetType)) {
        return res
          .status(400)
          .json({ message: `Invalid asset type. Must be one of: ${ALLOWED_ASSET_TYPES.join(", ")}` });
      }

      const [asset] = await db
        .insert(honeypotAssets)
        .values({
          orgId,
          name: name.substring(0, 200),
          description: typeof description === "string" ? description.substring(0, 1000) : null,
          assetType,
          fakeUsername: typeof fakeUsername === "string" ? fakeUsername.substring(0, 200) : null,
          fakeEmail: typeof fakeEmail === "string" ? fakeEmail.substring(0, 200) : null,
          fakeDomain: typeof fakeDomain === "string" ? fakeDomain.substring(0, 200) : null,
          listenAddress: typeof listenAddress === "string" ? listenAddress.substring(0, 200) : null,
          protocol: typeof protocol === "string" ? protocol.substring(0, 50) : null,
          sharePath: typeof sharePath === "string" ? sharePath.substring(0, 500) : null,
          decoyFiles: Array.isArray(decoyFiles) ? decoyFiles : null,
          decoyHostname: typeof decoyHostname === "string" ? decoyHostname.substring(0, 200) : null,
          decoyIp: typeof decoyIp === "string" ? decoyIp.substring(0, 50) : null,
          openPorts: Array.isArray(openPorts) ? openPorts : null,
          configuration: configuration || null,
          createdBy: ((req as unknown as Record<string, unknown>).userId as string) || null,
        })
        .returning();

      res.status(201).json({ asset });
    } catch (error) {
      log.error("Create honeypot asset error", { error: String(error) });
      res.status(500).json({ message: "Failed to create honeypot asset" });
    }
  });

  // Get single honeypot asset
  app.get("/api/deception/honeypot-assets/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);

      const [asset] = await db
        .select()
        .from(honeypotAssets)
        .where(and(eq(honeypotAssets.id, id), eq(honeypotAssets.orgId, orgId)));

      if (!asset) {
        return res.status(404).json({ message: "Asset not found" });
      }

      const hits = await db
        .select()
        .from(deceptionHits)
        .where(and(eq(deceptionHits.honeypotAssetId, id), eq(deceptionHits.orgId, orgId)))
        .orderBy(desc(deceptionHits.hitAt))
        .limit(50);

      res.json({ asset, hits });
    } catch (error) {
      log.error("Get honeypot asset error", { error: String(error) });
      res.status(500).json({ message: "Failed to get honeypot asset" });
    }
  });

  // Toggle honeypot asset
  app.patch("/api/deception/honeypot-assets/:id/toggle", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);

      const [asset] = await db
        .select()
        .from(honeypotAssets)
        .where(and(eq(honeypotAssets.id, id), eq(honeypotAssets.orgId, orgId)));

      if (!asset) {
        return res.status(404).json({ message: "Asset not found" });
      }

      const [updated] = await db
        .update(honeypotAssets)
        .set({ isActive: !asset.isActive, updatedAt: new Date() })
        .where(and(eq(honeypotAssets.id, id), eq(honeypotAssets.orgId, orgId)))
        .returning();

      res.json({ asset: updated });
    } catch (error) {
      log.error("Toggle honeypot asset error", { error: String(error) });
      res.status(500).json({ message: "Failed to toggle honeypot asset" });
    }
  });

  // Delete honeypot asset
  app.delete("/api/deception/honeypot-assets/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);

      const [asset] = await db
        .select()
        .from(honeypotAssets)
        .where(and(eq(honeypotAssets.id, id), eq(honeypotAssets.orgId, orgId)));

      if (!asset) {
        return res.status(404).json({ message: "Asset not found" });
      }

      await db.delete(honeypotAssets).where(and(eq(honeypotAssets.id, id), eq(honeypotAssets.orgId, orgId)));

      res.json({ message: "Asset deleted" });
    } catch (error) {
      log.error("Delete honeypot asset error", { error: String(error) });
      res.status(500).json({ message: "Failed to delete honeypot asset" });
    }
  });

  // =========================================================================
  // DECEPTION HITS
  // =========================================================================

  // List deception hits
  app.get("/api/deception/hits", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const severity = req.query.severity ? String(req.query.severity) : undefined;

      const conditions = [eq(deceptionHits.orgId, orgId)];
      if (severity && ["critical", "high", "medium", "low"].includes(severity)) {
        conditions.push(eq(deceptionHits.severity, severity));
      }

      const hits = await db
        .select()
        .from(deceptionHits)
        .where(and(...conditions))
        .orderBy(desc(deceptionHits.hitAt))
        .limit(200);

      // Enrich with token/asset names
      const enriched = await Promise.all(
        hits.map(async (hit) => {
          let sourceName = "Unknown";
          let sourceType = "unknown";

          if (hit.canaryTokenId) {
            const [token] = await db
              .select({ name: canaryTokens.name, tokenType: canaryTokens.tokenType })
              .from(canaryTokens)
              .where(eq(canaryTokens.id, hit.canaryTokenId));
            if (token) {
              sourceName = token.name;
              sourceType = `canary:${token.tokenType}`;
            }
          } else if (hit.honeypotAssetId) {
            const [asset] = await db
              .select({ name: honeypotAssets.name, assetType: honeypotAssets.assetType })
              .from(honeypotAssets)
              .where(eq(honeypotAssets.id, hit.honeypotAssetId));
            if (asset) {
              sourceName = asset.name;
              sourceType = `honeypot:${asset.assetType}`;
            }
          }

          return { ...hit, sourceName, sourceType };
        }),
      );

      res.json({ hits: enriched });
    } catch (error) {
      log.error("List deception hits error", { error: String(error) });
      res.status(500).json({ message: "Failed to list deception hits" });
    }
  });

  // =========================================================================
  // CALLBACK ENDPOINT (Unauthenticated — triggered by canary token access)
  // =========================================================================

  app.all("/api/deception/callback/:slug", async (req, res) => {
    try {
      const slug = String(req.params.slug);
      const callbackUrl = `/api/deception/callback/${slug}`;

      // Find the token by callback URL
      const [token] = await db.select().from(canaryTokens).where(eq(canaryTokens.callbackUrl, callbackUrl));

      if (!token || !token.isActive) {
        // Return a benign response to not tip off the attacker
        return res.status(200).json({ status: "ok" });
      }

      // Process the hit
      const context = {
        sourceIp: req.ip || req.socket.remoteAddress || undefined,
        sourceUserAgent: req.headers["user-agent"] || undefined,
        httpMethod: req.method,
        httpPath: req.originalUrl,
        rawRequest: {
          headers: req.headers,
          query: req.query,
          body: req.body,
        },
      };

      await processDeceptionHit(token.orgId, token.id, null, context);

      // Return a benign response
      if (token.tokenType === "email_pixel") {
        // Return a 1x1 transparent GIF
        const pixel = Buffer.from("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7", "base64");
        res.writeHead(200, { "Content-Type": "image/gif", "Content-Length": pixel.length });
        res.end(pixel);
      } else if (token.tokenType === "document") {
        // Return a 1x1 transparent PNG for tracking pixel
        const pixel = Buffer.from(
          "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",
          "base64",
        );
        res.writeHead(200, { "Content-Type": "image/png", "Content-Length": pixel.length });
        res.end(pixel);
      } else {
        res.status(200).json({ status: "ok" });
      }
    } catch (error) {
      log.error("Deception callback error", { error: String(error) });
      // Always return 200 to not reveal the deception
      res.status(200).json({ status: "ok" });
    }
  });

  // =========================================================================
  // SIMULATE HIT (for testing — authenticated)
  // =========================================================================

  app.post("/api/deception/simulate-hit", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { canaryTokenId, honeypotAssetId, sourceIp, sourceHostname } = req.body;

      if (!canaryTokenId && !honeypotAssetId) {
        return res.status(400).json({ message: "Either canaryTokenId or honeypotAssetId is required" });
      }

      // Verify ownership
      if (canaryTokenId) {
        const [token] = await db
          .select()
          .from(canaryTokens)
          .where(and(eq(canaryTokens.id, String(canaryTokenId)), eq(canaryTokens.orgId, orgId)));
        if (!token) {
          return res.status(404).json({ message: "Token not found" });
        }
      }
      if (honeypotAssetId) {
        const [asset] = await db
          .select()
          .from(honeypotAssets)
          .where(and(eq(honeypotAssets.id, String(honeypotAssetId)), eq(honeypotAssets.orgId, orgId)));
        if (!asset) {
          return res.status(404).json({ message: "Asset not found" });
        }
      }

      const result = await processDeceptionHit(
        orgId,
        canaryTokenId ? String(canaryTokenId) : null,
        honeypotAssetId ? String(honeypotAssetId) : null,
        {
          sourceIp: typeof sourceIp === "string" ? sourceIp : "192.168.1.100",
          sourceHostname: typeof sourceHostname === "string" ? sourceHostname : "attacker-workstation",
          sourceUserAgent: "SimulatedHit/1.0",
          httpMethod: "GET",
          httpPath: "/simulated",
        },
      );

      res.json({ message: "Hit simulated", ...result });
    } catch (error) {
      log.error("Simulate hit error", { error: String(error) });
      res.status(500).json({ message: "Failed to simulate hit" });
    }
  });

  // =========================================================================
  // DASHBOARD STATS
  // =========================================================================

  app.get("/api/deception/stats", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);

      const [tokenCount] = await db.select({ cnt: count() }).from(canaryTokens).where(eq(canaryTokens.orgId, orgId));

      const [activeTokens] = await db
        .select({ cnt: count() })
        .from(canaryTokens)
        .where(and(eq(canaryTokens.orgId, orgId), eq(canaryTokens.isActive, true)));

      const [assetCount] = await db
        .select({ cnt: count() })
        .from(honeypotAssets)
        .where(eq(honeypotAssets.orgId, orgId));

      const [activeAssets] = await db
        .select({ cnt: count() })
        .from(honeypotAssets)
        .where(and(eq(honeypotAssets.orgId, orgId), eq(honeypotAssets.isActive, true)));

      const [hitCount] = await db.select({ cnt: count() }).from(deceptionHits).where(eq(deceptionHits.orgId, orgId));

      const [criticalHits] = await db
        .select({ cnt: count() })
        .from(deceptionHits)
        .where(and(eq(deceptionHits.orgId, orgId), eq(deceptionHits.severity, "critical")));

      // Hits in last 24 hours
      const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
      const [recentHits] = await db
        .select({ cnt: count() })
        .from(deceptionHits)
        .where(and(eq(deceptionHits.orgId, orgId), sql`${deceptionHits.hitAt} > ${oneDayAgo}`));

      // Hit rate by token type
      const hitsByType = await db
        .select({
          tokenType: canaryTokens.tokenType,
          hits: sql<number>`cast(sum(${canaryTokens.hitCount}) as int)`,
        })
        .from(canaryTokens)
        .where(eq(canaryTokens.orgId, orgId))
        .groupBy(canaryTokens.tokenType);

      res.json({
        totalTokens: tokenCount?.cnt || 0,
        activeTokens: activeTokens?.cnt || 0,
        totalAssets: assetCount?.cnt || 0,
        activeAssets: activeAssets?.cnt || 0,
        totalHits: hitCount?.cnt || 0,
        criticalHits: criticalHits?.cnt || 0,
        recentHits24h: recentHits?.cnt || 0,
        hitsByTokenType: hitsByType,
        falsePositiveRate: 0, // Deception = 0% false positives
      });
    } catch (error) {
      log.error("Get deception stats error", { error: String(error) });
      res.status(500).json({ message: "Failed to get stats" });
    }
  });

  // =========================================================================
  // TOKEN DEPLOYMENT WIZARD
  // =========================================================================

  app.post("/api/deception/deploy-wizard", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { tokenType, deploymentTarget, name, description } = req.body;

      if (!tokenType || !ALLOWED_TOKEN_TYPES.includes(tokenType)) {
        return res.status(400).json({ message: "Invalid token type" });
      }
      if (!deploymentTarget || !ALLOWED_DEPLOYMENT_TARGETS.includes(deploymentTarget)) {
        return res.status(400).json({ message: "Invalid deployment target" });
      }
      if (!name || typeof name !== "string") {
        return res.status(400).json({ message: "Name is required" });
      }

      // Generate the token
      const { tokenValue, tokenHash, callbackSecret } = generateCanaryToken(tokenType);
      const tempId = crypto.randomUUID();
      const callbackUrl = generateCallbackUrl(orgId, tempId);

      // Create and save
      const [token] = await db
        .insert(canaryTokens)
        .values({
          orgId,
          name: name.substring(0, 200),
          description: typeof description === "string" ? description.substring(0, 1000) : null,
          tokenType,
          tokenValue,
          tokenHash,
          callbackUrl,
          callbackSecret,
          deploymentTarget,
          deployedTo: deploymentTarget,
          createdBy: ((req as unknown as Record<string, unknown>).userId as string) || null,
        })
        .returning();

      // Get deployment instructions
      const instructions = getDeploymentInstructions(tokenType, deploymentTarget, tokenValue);

      res.status(201).json({
        token: {
          ...token,
          callbackSecret: "***",
        },
        deploymentInstructions: instructions,
        steps: getWizardSteps(tokenType, deploymentTarget),
      });
    } catch (error) {
      log.error("Deploy wizard error", { error: String(error) });
      res.status(500).json({ message: "Failed to deploy token" });
    }
  });
}

// =========================================================================
// HELPERS
// =========================================================================

function maskTokenValue(tokenType: string, value: string): string {
  if (tokenType === "aws_key") {
    try {
      const parsed = JSON.parse(value);
      return JSON.stringify({
        accessKeyId: parsed.accessKeyId?.substring(0, 8) + "****",
        secretAccessKey: "****",
      });
    } catch {
      return "****";
    }
  }
  if (tokenType === "database_credential") {
    try {
      const parsed = JSON.parse(value);
      return JSON.stringify({
        host: parsed.host,
        port: parsed.port,
        username: parsed.username,
        password: "****",
        database: parsed.database,
      });
    } catch {
      return "****";
    }
  }
  if (tokenType === "api_key") {
    return value.substring(0, 6) + "****";
  }
  if (value.length > 20) {
    return value.substring(0, 15) + "...****";
  }
  return "****";
}

function getWizardSteps(tokenType: string, target: string): string[] {
  const steps = [
    `Generate ${tokenType.replace(/_/g, " ")} canary token`,
    `Prepare ${target.replace(/_/g, " ")} deployment package`,
  ];

  switch (target) {
    case "s3_bucket":
      steps.push("Upload credential file to S3 bucket");
      steps.push("Set appropriate read permissions");
      steps.push("Monitor for access via CloudTrail");
      break;
    case "github_repo":
      steps.push("Create a commit with the canary credential");
      steps.push("Push to the target repository");
      steps.push("Token will trigger on any clone/fetch that reads the file");
      break;
    case "email":
      steps.push("Embed tracking pixel in email body");
      steps.push("Send to target email addresses");
      steps.push("Token triggers when email is opened");
      break;
    case "active_directory":
      steps.push("Create honey account in Active Directory");
      steps.push("Set account properties to look legitimate");
      steps.push("Any login attempt will trigger an alert");
      break;
    case "kubernetes":
      steps.push("Create ConfigMap/Secret with canary kubeconfig");
      steps.push("Deploy to target namespace");
      steps.push("Any API call using the token triggers alert");
      break;
    default:
      steps.push("Deploy token to target location");
      steps.push("Configure monitoring callback");
      break;
  }

  steps.push("Verify callback endpoint is reachable");
  steps.push("Deployment complete — monitoring active");

  return steps;
}

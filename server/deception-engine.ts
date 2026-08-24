import crypto from "crypto";
import { db } from "./db";
import { logger } from "./logger";
import { publishAlertCreated } from "./alert-events";

const log = logger.child("deception-engine");
import { eq, and, sql } from "drizzle-orm";
import { canaryTokens, deceptionHits, honeypotAssets, alerts, playbooks, playbookExecutions } from "@shared/schema";

// =========================================================================
// CANARY TOKEN GENERATION
// =========================================================================

/** Generate a cryptographically unique canary token based on type */
export function generateCanaryToken(tokenType: string): {
  tokenValue: string;
  tokenHash: string;
  callbackSecret: string;
} {
  const callbackSecret = crypto.randomBytes(32).toString("hex");

  let tokenValue: string;

  switch (tokenType) {
    case "aws_key": {
      // Fake AWS Access Key ID (starts with AKIA) + Secret
      const keyId = "AKIA" + crypto.randomBytes(16).toString("base64url").substring(0, 16).toUpperCase();
      const secretKey = crypto.randomBytes(30).toString("base64").substring(0, 40);
      tokenValue = JSON.stringify({ accessKeyId: keyId, secretAccessKey: secretKey });
      break;
    }
    case "database_credential": {
      const user = "db_admin_" + crypto.randomBytes(4).toString("hex");
      const pass = crypto.randomBytes(24).toString("base64");
      const host = "internal-db-" + crypto.randomBytes(3).toString("hex") + ".corp.local";
      tokenValue = JSON.stringify({
        host,
        port: 5432,
        username: user,
        password: pass,
        database: "production",
      });
      break;
    }
    case "api_key": {
      tokenValue = "sk-" + crypto.randomBytes(32).toString("hex");
      break;
    }
    case "ssh_key": {
      // Generate a fake SSH private key header (not a real key, just looks like one)
      const fakeKeyBody = crypto.randomBytes(128).toString("base64");
      tokenValue = `-----BEGIN OPENSSH PRIVATE KEY-----\n${fakeKeyBody}\n-----END OPENSSH PRIVATE KEY-----`;
      break;
    }
    case "kubeconfig": {
      const token = crypto.randomBytes(32).toString("hex");
      tokenValue = JSON.stringify({
        apiVersion: "v1",
        kind: "Config",
        clusters: [
          {
            cluster: {
              server: "https://k8s-prod-" + crypto.randomBytes(4).toString("hex") + ".internal:6443",
            },
            name: "production",
          },
        ],
        users: [{ name: "admin", user: { token } }],
      });
      break;
    }
    case "slack_webhook": {
      const id1 = crypto.randomBytes(5).toString("hex").toUpperCase();
      const id2 = crypto.randomBytes(5).toString("hex").toUpperCase();
      const id3 = crypto.randomBytes(12).toString("hex");
      tokenValue = `https://hooks.slack.com/services/${id1}/${id2}/${id3}`;
      break;
    }
    case "document": {
      // A tracking pixel URL embedded in a document
      const trackingId = crypto.randomBytes(16).toString("hex");
      tokenValue = JSON.stringify({
        trackingPixelUrl: `https://canary.securenexus.io/px/${trackingId}.png`,
        documentTitle: "Q4-2025-Board-Compensation-Report.docx",
      });
      break;
    }
    case "email_pixel": {
      const pixelId = crypto.randomBytes(16).toString("hex");
      tokenValue = `<img src="https://canary.securenexus.io/px/${pixelId}.gif" width="1" height="1" />`;
      break;
    }
    case "dns_token": {
      const subdomain = crypto.randomBytes(8).toString("hex");
      tokenValue = `${subdomain}.canary.securenexus.io`;
      break;
    }
    case "url_token": {
      const urlId = crypto.randomBytes(16).toString("hex");
      tokenValue = `https://canary.securenexus.io/t/${urlId}`;
      break;
    }
    default: {
      tokenValue = crypto.randomBytes(32).toString("hex");
    }
  }

  const tokenHash = crypto.createHash("sha256").update(tokenValue).digest("hex");

  return { tokenValue, tokenHash, callbackSecret };
}

/** Generate a unique callback URL for a canary token */
export function generateCallbackUrl(orgId: string, tokenId: string): string {
  const uniqueSlug = crypto.randomBytes(16).toString("hex");
  // In production this would be a real externally-accessible URL
  return `/api/deception/callback/${uniqueSlug}`;
}

// =========================================================================
// HIT DETECTION & ATTRIBUTION
// =========================================================================

export interface DeceptionHitContext {
  sourceIp?: string;
  sourceHostname?: string;
  sourceUserAgent?: string;
  httpMethod?: string;
  httpPath?: string;
  accessedCredential?: string;
  rawRequest?: Record<string, unknown>;
}

/** Classify the severity of a deception hit based on context */
export function classifyHitSeverity(context: DeceptionHitContext): string {
  // All deception hits are high confidence — any interaction with a decoy is suspicious
  // But we differentiate based on the nature of the access

  // Internal IP ranges indicate lateral movement — critical
  if (context.sourceIp) {
    const ip = context.sourceIp;
    if (isInternalIp(ip)) {
      return "critical"; // Internal source = likely compromised insider or lateral movement
    }
  }

  // Credential usage attempts are always critical
  if (context.accessedCredential) {
    return "critical";
  }

  // POST/PUT/DELETE requests indicate active exploitation
  if (context.httpMethod && ["POST", "PUT", "DELETE", "PATCH"].includes(context.httpMethod.toUpperCase())) {
    return "critical";
  }

  // GET requests to honeypots are high severity
  if (context.httpMethod === "GET") {
    return "high";
  }

  return "high"; // Default — all deception hits are at minimum high severity
}

/** Check if an IP is likely a Tor exit node (simplified check) */
export function checkTorExit(ip: string): boolean {
  // In production, this would check against a Tor exit node list
  // For now, return false — would integrate with a real Tor exit list API
  return false;
}

/** Check if an IP is from an internal network */
export function isInternalIp(ip: string): boolean {
  if (!ip) return false;
  return (
    ip.startsWith("10.") ||
    ip.startsWith("172.16.") ||
    ip.startsWith("172.17.") ||
    ip.startsWith("172.18.") ||
    ip.startsWith("172.19.") ||
    ip.startsWith("172.20.") ||
    ip.startsWith("172.21.") ||
    ip.startsWith("172.22.") ||
    ip.startsWith("172.23.") ||
    ip.startsWith("172.24.") ||
    ip.startsWith("172.25.") ||
    ip.startsWith("172.26.") ||
    ip.startsWith("172.27.") ||
    ip.startsWith("172.28.") ||
    ip.startsWith("172.29.") ||
    ip.startsWith("172.30.") ||
    ip.startsWith("172.31.") ||
    ip.startsWith("192.168.") ||
    ip === "127.0.0.1" ||
    ip === "::1"
  );
}

/** Process a deception hit — record it and create a P1 alert */
export async function processDeceptionHit(
  orgId: string,
  canaryTokenId: string | null,
  honeypotAssetId: string | null,
  context: DeceptionHitContext,
): Promise<{ hitId: string; alertId: string }> {
  const severity = classifyHitSeverity(context);
  const internal = context.sourceIp ? isInternalIp(context.sourceIp) : false;
  const torExit = context.sourceIp ? checkTorExit(context.sourceIp) : false;

  // 1. Record the hit
  const [hit] = await db
    .insert(deceptionHits)
    .values({
      orgId,
      canaryTokenId,
      honeypotAssetId,
      sourceIp: context.sourceIp || null,
      sourceHostname: context.sourceHostname || null,
      sourceUserAgent: context.sourceUserAgent || null,
      severity,
      isInternal: internal,
      isTorExit: torExit,
      httpMethod: context.httpMethod || null,
      httpPath: context.httpPath || null,
      accessedCredential: context.accessedCredential || null,
      rawRequest: context.rawRequest || null,
      hitAt: new Date(),
    })
    .returning();
  // 2. Update hit count on the source token/asset
  if (canaryTokenId) {
    await db
      .update(canaryTokens)
      .set({
        hitCount: sql`${canaryTokens.hitCount} + 1`,
        lastHitAt: new Date(),
        updatedAt: new Date(),
      })
      .where(and(eq(canaryTokens.id, canaryTokenId), eq(canaryTokens.orgId, orgId)));
  }
  if (honeypotAssetId) {
    await db
      .update(honeypotAssets)
      .set({
        hitCount: sql`${honeypotAssets.hitCount} + 1`,
        lastHitAt: new Date(),
        updatedAt: new Date(),
      })
      .where(and(eq(honeypotAssets.id, honeypotAssetId), eq(honeypotAssets.orgId, orgId)));
  }

  // 3. Create a P1 alert — deception hits are always true positives
  let alertTitle = "Deception Hit Detected";
  let alertDescription = "";

  if (canaryTokenId) {
    const [token] = await db
      .select()
      .from(canaryTokens)
      .where(and(eq(canaryTokens.id, canaryTokenId), eq(canaryTokens.orgId, orgId)));
    if (token) {
      alertTitle = `Canary Token Triggered: ${token.name} (${token.tokenType})`;
      alertDescription = `Canary token "${token.name}" was accessed from ${context.sourceIp || "unknown IP"}. Token type: ${token.tokenType}. ${internal ? "SOURCE IS INTERNAL — possible lateral movement or insider threat." : "External source detected."} This is a 100% true positive — any interaction with a canary token is malicious.`;
    }
  }

  if (honeypotAssetId) {
    const [asset] = await db
      .select()
      .from(honeypotAssets)
      .where(and(eq(honeypotAssets.id, honeypotAssetId), eq(honeypotAssets.orgId, orgId)));
    if (asset) {
      alertTitle = `Honeypot Hit: ${asset.name} (${asset.assetType})`;
      alertDescription = `Honeypot "${asset.name}" received connection from ${context.sourceIp || "unknown IP"}. Asset type: ${asset.assetType}. ${internal ? "SOURCE IS INTERNAL — possible lateral movement." : "External probe detected."} Zero false positive rate — all honeypot interactions are suspicious.`;
    }
  }

  const [alert] = await db
    .insert(alerts)
    .values({
      orgId,
      source: "deception",
      category: "deception",
      severity: severity === "critical" ? "critical" : "high",
      title: alertTitle,
      description: alertDescription,
      sourceIp: context.sourceIp || null,
      hostname: context.sourceHostname || null,
      status: "new",
      mitreTactic: internal ? "Lateral Movement" : "Initial Access",
      mitreTechnique: internal ? "T1021 - Remote Services" : "T1078 - Valid Accounts",
      rawData: {
        deceptionHitId: hit.id,
        canaryTokenId,
        honeypotAssetId,
        context,
      },
      detectedAt: new Date(),
    })
    .returning();
  await publishAlertCreated(alert);

  // 4. Link the alert back to the hit
  await db.update(deceptionHits).set({ alertId: alert.id }).where(eq(deceptionHits.id, hit.id));

  // 5. Auto-trigger any playbooks that fire on deception_hit alerts
  try {
    const deceptionPlaybooks = await db
      .select()
      .from(playbooks)
      .where(
        and(
          eq(playbooks.orgId, orgId),
          eq(playbooks.trigger, "alert_category_deception"),
          eq(playbooks.status, "active"),
        ),
      );

    for (const pb of deceptionPlaybooks) {
      await db.insert(playbookExecutions).values({
        playbookId: pb.id,
        triggeredBy: "system",
        triggerEvent: `deception_hit:${hit.id}`,
        resourceType: "alert",
        resourceId: alert.id,
        status: "completed",
        actionsExecuted: pb.actions,
        result: {
          autoTriggered: true,
          alertId: alert.id,
          hitId: hit.id,
          severity,
        },
        executionTimeMs: 0,
      });

      // Update trigger count
      await db
        .update(playbooks)
        .set({
          lastTriggeredAt: new Date(),
          triggerCount: sql`COALESCE(${playbooks.triggerCount}, 0) + 1`,
        })
        .where(eq(playbooks.id, pb.id));
    }
  } catch (playbookErr) {
    // Don't fail the hit processing if playbook auto-trigger fails
    log.error("Deception playbook auto-trigger error", { error: String(playbookErr) });
  }

  return { hitId: hit.id, alertId: alert.id };
}

// =========================================================================
// DEPLOYMENT HELPERS
// =========================================================================

/** Generate deployment instructions for a canary token */
export function getDeploymentInstructions(tokenType: string, deploymentTarget: string, tokenValue: string): string {
  const instructions: Record<string, Record<string, string>> = {
    aws_key: {
      s3_bucket: `Upload a file named ".env" or "credentials" containing the AWS key to the target S3 bucket.\n\nFile content:\n[default]\naws_access_key_id = ${JSON.parse(tokenValue).accessKeyId}\naws_secret_access_key = ${JSON.parse(tokenValue).secretAccessKey}`,
      github_repo: `Create a file named ".env.production" in the repository root:\n\nAWS_ACCESS_KEY_ID=${JSON.parse(tokenValue).accessKeyId}\nAWS_SECRET_ACCESS_KEY=${JSON.parse(tokenValue).secretAccessKey}`,
      ci_cd_pipeline: `Add as environment variables in your CI/CD pipeline (named to look legitimate):\n\nBACKUP_AWS_KEY=${JSON.parse(tokenValue).accessKeyId}\nBACKUP_AWS_SECRET=${JSON.parse(tokenValue).secretAccessKey}`,
    },
    database_credential: {
      shared_drive: `Create a file named "db-migration-config.json" in a sensitive-looking directory:\n\n${tokenValue}`,
      internal_wiki: `Add to an internal wiki page titled "Database Migration Guide" or "Emergency DB Access":\n\n${tokenValue}`,
    },
    api_key: {
      github_repo: `Add to a config file that looks like it was accidentally committed:\n\n# API Configuration\nAPI_KEY=${tokenValue}`,
      s3_bucket: `Create a file named "api-keys.txt" or ".env.backup":\n\nPRODUCTION_API_KEY=${tokenValue}`,
    },
  };

  return (
    instructions[tokenType]?.[deploymentTarget] ||
    `Deploy the token value to the target ${deploymentTarget}. Ensure it looks like a legitimate credential that would attract an attacker.\n\nToken value:\n${tokenValue}`
  );
}

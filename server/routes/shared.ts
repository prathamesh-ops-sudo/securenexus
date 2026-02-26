import type { Request, Response, NextFunction } from "express";
import { createHash, createHmac, randomBytes, timingSafeEqual } from "crypto";
import { storage } from "../storage";
import rateLimit from "express-rate-limit";
import {
  reply,
  replyError,
  replyUnauthenticated,
  replyForbidden,
  replyRateLimit,
  ERROR_CODES,
  type ApiMeta,
} from "../api-response";
import { logger } from "../logger";
import { createEventFingerprint } from "../outbox-processor";
import { validateAndLogEvent } from "../event-catalog";
import { validateWebhookUrl, isCircuitOpen, isWebhookRateLimited, recordDeliverySuccess, recordDeliveryFailure, secureOutboundFetch, redactDeliveryLog } from "../outbound-security";

export { storage, logger, ERROR_CODES, reply, replyError, replyUnauthenticated, replyForbidden, replyRateLimit, randomBytes };
export type { ApiMeta };

export const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (_req, res) => replyRateLimit(res),
  skip: (req) => req.path === "/ops/health" || req.path === "/health",
});

export const strictLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (_req, res) => replyRateLimit(res),
});

export const ingestionLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (_req, res) =>
    replyRateLimit(res, "Ingestion rate limit exceeded. Try again shortly.", ERROR_CODES.INGESTION_RATE_LIMITED),
});

export function p(val: string | string[] | undefined): string {
  return (Array.isArray(val) ? val[0] : val) as string;
}

export function getOrgId(req: Request): string {
  const orgId = (req as any).orgId || (req as any).user?.orgId;
  if (!orgId || typeof orgId !== "string") {
    throw new Error("ORG_CONTEXT_MISSING");
  }
  return orgId;
}

export function sendEnvelope(
  res: Response,
  data: any,
  options?: {
    status?: number;
    meta?: ApiMeta;
    errors?: { code: string; message: string; details?: any }[] | null;
  }
) {
  const status = options?.status ?? 200;
  const meta: ApiMeta = options?.meta ?? {};
  const errors = options?.errors ?? null;
  if (errors && errors.length > 0) {
    return replyError(res, status, errors, meta);
  }
  return reply(res, data, meta, status);
}

export function hashApiKey(key: string): string {
  return createHash("sha256").update(key).digest("hex");
}

export function generateApiKey(): { key: string; prefix: string; hash: string } {
  const key = `snx_${randomBytes(32).toString("hex")}`;
  const prefix = key.slice(0, 12);
  const hash = hashApiKey(key);
  return { key, prefix, hash };
}

export async function apiKeyAuth(req: Request, res: Response, next: NextFunction) {
  const header = req.headers["x-api-key"] || req.headers.authorization?.replace("Bearer ", "");
  if (!header || typeof header !== "string") {
    return replyUnauthenticated(res, "Missing API key. Provide X-API-Key header.", ERROR_CODES.API_KEY_MISSING);
  }
  const hash = hashApiKey(header);
  const apiKey = await storage.getApiKeyByHash(hash);
  if (!apiKey) {
    return replyUnauthenticated(res, "Invalid API key.", ERROR_CODES.API_KEY_INVALID);
  }
  if (!apiKey.isActive) {
    return replyForbidden(res, "API key has been revoked.", ERROR_CODES.API_KEY_REVOKED);
  }
  storage.updateApiKeyLastUsed(apiKey.id).catch((err) => logger.child("routes").warn("Failed to update API key last used", { error: String(err) }));
  (req as any).apiKey = apiKey;
  (req as any).orgId = apiKey.orgId;
  next();
}

export function verifyWebhookSignature(req: Request, res: Response, next: NextFunction) {
  const apiKey = (req as any).apiKey;
  const signature = req.headers["x-webhook-signature"] as string | undefined;

  if (!apiKey?.webhookSecret) {
    return next();
  }

  if (!signature) {
    return replyUnauthenticated(
      res,
      "Missing X-Webhook-Signature header. Required when webhook secret is configured.",
      ERROR_CODES.WEBHOOK_SIG_MISSING,
    );
  }

  try {
    const rawBodyBuf = (req as any).rawBody;
    const rawBody = rawBodyBuf ? (Buffer.isBuffer(rawBodyBuf) ? rawBodyBuf.toString("utf8") : String(rawBodyBuf)) : JSON.stringify(req.body);
    const timestamp = req.headers["x-webhook-timestamp"] as string || "";
    const payload = timestamp ? `${timestamp}.${rawBody}` : rawBody;
    const expected = createHmac("sha256", apiKey.webhookSecret).update(payload).digest("hex");
    const sig = signature.startsWith("sha256=") ? signature.slice(7) : signature;

    if (!/^[a-f0-9]+$/i.test(sig) || sig.length !== expected.length) {
      return replyUnauthenticated(res, "Invalid webhook signature.", ERROR_CODES.WEBHOOK_SIG_INVALID);
    }

    if (!timingSafeEqual(Buffer.from(sig, "hex"), Buffer.from(expected, "hex"))) {
      return replyUnauthenticated(res, "Invalid webhook signature.", ERROR_CODES.WEBHOOK_SIG_INVALID);
    }

    if (timestamp) {
      const ts = parseInt(timestamp, 10);
      const age = Math.abs(Date.now() - ts);
      if (age > 5 * 60 * 1000) {
        return replyUnauthenticated(
          res,
          "Webhook timestamp too old. Replay protection triggered.",
          ERROR_CODES.WEBHOOK_TS_EXPIRED,
        );
      }
    }

    next();
  } catch {
    return replyUnauthenticated(res, "Invalid webhook signature.", ERROR_CODES.WEBHOOK_SIG_INVALID);
  }
}

export async function dispatchWebhookEvent(orgId: string | null, event: string, payload: any) {
  if (!orgId) return;
  try {
    const webhooks = await storage.getActiveWebhooksByEvent(orgId, event);
    for (const webhook of webhooks) {
      (async () => {
        const urlCheck = validateWebhookUrl(webhook.url);
        if (!urlCheck.valid) {
          logger.child("webhook").warn("SSRF blocked: webhook URL rejected", { webhookId: webhook.id, reason: urlCheck.reason });
          await storage.createOutboundWebhookLog({
            webhookId: webhook.id, event, payload: redactDeliveryLog(payload) as Record<string, unknown>,
            responseStatus: 0, responseBody: `Blocked: ${urlCheck.reason}`, success: false,
          }).catch(() => {});
          return;
        }
        if (isCircuitOpen(webhook.id)) {
          logger.child("webhook").warn("Circuit breaker open — skipping delivery", { webhookId: webhook.id });
          await storage.createOutboundWebhookLog({
            webhookId: webhook.id, event, payload: redactDeliveryLog(payload) as Record<string, unknown>,
            responseStatus: 0, responseBody: "Circuit breaker open", success: false,
          }).catch(() => {});
          return;
        }
        if (isWebhookRateLimited(webhook.id)) {
          await storage.createOutboundWebhookLog({
            webhookId: webhook.id, event, payload: redactDeliveryLog(payload) as Record<string, unknown>,
            responseStatus: 429, responseBody: "Rate limited", success: false,
          }).catch(() => {});
          return;
        }
        const body = JSON.stringify(payload);
        const headers: Record<string, string> = { "Content-Type": "application/json" };
        if (webhook.secret) {
          const timestamp = String(Date.now());
          const signedPayload = `${timestamp}.${body}`;
          const hmacSig = createHmac("sha256", webhook.secret).update(signedPayload).digest("hex");
          headers["X-Webhook-Signature"] = `sha256=${hmacSig}`;
          headers["X-Webhook-Timestamp"] = timestamp;
        }
        const result = await secureOutboundFetch(webhook.url, { method: "POST", headers, body });
        if (result.success) {
          recordDeliverySuccess(webhook.id);
        } else {
          recordDeliveryFailure(webhook.id);
        }
        await storage.createOutboundWebhookLog({
          webhookId: webhook.id, event, payload: redactDeliveryLog(payload) as Record<string, unknown>,
          responseStatus: result.statusCode, responseBody: result.responseBody.slice(0, 2000), success: result.success,
        }).catch((err) => logger.child("webhook").warn("Failed to log outbound webhook", { error: String(err) }));
      })().catch((err) => logger.child("webhook").warn("Webhook dispatch error", { error: String(err) }));
    }
  } catch (err) {
    logger.child("webhook").warn("dispatchWebhookEvent error", { error: String(err) });
  }
}

export async function publishOutboxEvent(
  orgId: string | null,
  eventType: string,
  aggregateType: string,
  aggregateId: string,
  payload: Record<string, unknown>,
): Promise<void> {
  if (!orgId) return;
  validateAndLogEvent(eventType, aggregateType, aggregateId, payload);
  try {
    const fingerprint = createEventFingerprint(eventType, aggregateType, aggregateId, payload);
    await storage.createOutboxEvent({
      orgId,
      eventType,
      aggregateType,
      aggregateId,
      payload,
      status: "pending",
      fingerprint,
      attempts: 0,
      maxAttempts: 5,
    });
  } catch (err) {
    logger.child("outbox").error(`Failed to publish ${eventType} for ${aggregateType}/${aggregateId}`, { error: String(err) });
  }
}

export function idempotencyCheck(req: Request, res: Response, next: NextFunction) {
  const idempotencyKey = req.headers["x-idempotency-key"] as string | undefined;
  if (!idempotencyKey) return next();

  const orgId = getOrgId(req);
  const endpoint = req.originalUrl;

  storage.getIdempotencyKey(orgId, idempotencyKey, endpoint).then((existing) => {
    if (existing && existing.expiresAt && new Date(existing.expiresAt) > new Date()) {
      const cached = existing.responseBody as any;
      return res.status(existing.responseStatus || 200).json(cached);
    }

    const originalJson = res.json.bind(res);
    res.json = function (body: any) {
      storage.createIdempotencyKey({
        orgId,
        idempotencyKey,
        endpoint,
        method: req.method,
        responseStatus: res.statusCode,
        responseBody: body,
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
      }).catch((err) => logger.child("idempotency").warn("Failed to store idempotency key", { key: idempotencyKey, endpoint, error: String(err) }));
      return originalJson(body);
    } as any;
    next();
  }).catch((err) => {
    logger.child("idempotency").warn("Failed to check idempotency key", { key: idempotencyKey, endpoint, error: String(err) });
    next();
  });
}

export function sanitizeConfig(config: any): any {
  if (!config) return config;
  const safe = { ...config };
  const secretFields = ["apiKey", "apiToken", "clientSecret", "password", "secretAccessKey", "webhookSecret", "token", "siteToken"];
  for (const field of secretFields) {
    if (safe[field]) safe[field] = "••••••••";
  }
  return safe;
}

export function validateFeedUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return false;
    const hostname = parsed.hostname.toLowerCase();
    if (hostname === 'localhost' || hostname === '0.0.0.0' || hostname === '127.0.0.1') return false;
    if (hostname.startsWith('10.') || hostname.startsWith('192.168.') || hostname.startsWith('169.254.')) return false;
    if (/^172\.(1[6-9]|2\d|3[01])\./.test(hostname)) return false;
    if (hostname === '::1' || hostname.startsWith('fc') || hostname.startsWith('fd')) return false;
    return true;
  } catch {
    return false;
  }
}

export function calculateNextRunFromCadence(cadence: string): Date {
  const now = new Date();
  switch (cadence) {
    case "daily": return new Date(now.getTime() + 24 * 60 * 60 * 1000);
    case "weekly": return new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
    case "biweekly": return new Date(now.getTime() + 14 * 24 * 60 * 60 * 1000);
    case "monthly": { const d = new Date(now); d.setMonth(d.getMonth() + 1); return d; }
    case "quarterly": { const d = new Date(now); d.setMonth(d.getMonth() + 3); return d; }
    default: return new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
  }
}

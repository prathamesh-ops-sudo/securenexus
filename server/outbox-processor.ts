import { storage } from "./storage";
import { createHash, createHmac } from "crypto";
import { logger } from "./logger";
import { validateWebhookUrl, isCircuitOpen, isWebhookRateLimited, recordDeliverySuccess, recordDeliveryFailure, secureOutboundFetch, redactDeliveryLog } from "./outbound-security";

const POLL_INTERVAL_MS = 3000;
const BATCH_SIZE = 10;
let processorRunning = false;
let processorInterval: NodeJS.Timeout | null = null;
let processedCount = 0;
let failedCount = 0;

export function startOutboxProcessor(): void {
  if (processorRunning) return;
  processorRunning = true;
  logger.child("outbox-processor").info("Started - polling every 3s");

  processorInterval = setInterval(async () => {
    try {
      await processPendingEvents();
    } catch (err) {
      logger.child("outbox-processor").error("Poll error:", { error: String(err) });
    }
  }, POLL_INTERVAL_MS);
}

export function stopOutboxProcessor(): void {
  processorRunning = false;
  if (processorInterval) {
    clearInterval(processorInterval);
    processorInterval = null;
  }
  logger.child("outbox-processor").info("Stopped");
}

async function processPendingEvents(): Promise<void> {
  const events = await storage.getPendingOutboxEvents(BATCH_SIZE);
  if (events.length === 0) return;

  for (const event of events) {
    try {
      await dispatchOutboxEvent(event);
      await storage.updateOutboxEvent(event.id, {
        status: "dispatched",
        dispatchedAt: new Date(),
      });
      processedCount++;
    } catch (err: any) {
      const attempts = (event.attempts || 0) + 1;
      const maxAttempts = event.maxAttempts || 5;

      if (attempts >= maxAttempts) {
        await storage.updateOutboxEvent(event.id, {
          status: "failed",
          lastError: err.message || String(err),
          attempts,
        });
        failedCount++;
        logger.child("outbox-processor").error(`[OutboxProcessor] Event ${event.id} failed permanently after ${attempts} attempts`);
      } else {
        const backoffMs = Math.min(300000, 1000 * Math.pow(2, attempts));
        const nextRetryAt = new Date(Date.now() + backoffMs);
        await storage.updateOutboxEvent(event.id, {
          status: "pending",
          lastError: err.message || String(err),
          attempts,
          nextRetryAt,
        });
      }
    }
  }
}

async function dispatchOutboxEvent(event: any): Promise<void> {
  const orgId = event.orgId;
  if (!orgId) {
    logger.child("outbox-processor").warn(`Event ${event.id} missing orgId — skipping webhook dispatch`);
    return;
  }
  const webhooks = await storage.getActiveWebhooksByEvent(orgId, event.eventType);

  for (const webhook of webhooks) {
    const urlCheck = validateWebhookUrl(webhook.url);
    if (!urlCheck.valid) {
      logger.child("outbox-processor").warn("SSRF blocked: webhook URL rejected", { webhookId: webhook.id, reason: urlCheck.reason });
      await storage.createOutboundWebhookLog({
        webhookId: webhook.id, event: event.eventType, payload: redactDeliveryLog(event.payload) as Record<string, unknown>,
        responseStatus: 0, responseBody: `Blocked: ${urlCheck.reason}`, success: false,
      }).catch(() => {});
      continue;
    }
    if (isCircuitOpen(webhook.id)) {
      logger.child("outbox-processor").warn("Circuit breaker open — skipping", { webhookId: webhook.id });
      continue;
    }
    if (isWebhookRateLimited(webhook.id)) {
      logger.child("outbox-processor").warn("Rate limited — skipping", { webhookId: webhook.id });
      continue;
    }

    const body = JSON.stringify({
      eventId: event.id,
      eventType: event.eventType,
      aggregateType: event.aggregateType,
      aggregateId: event.aggregateId,
      payload: event.payload,
      timestamp: event.createdAt,
    });

    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (webhook.secret) {
      const timestamp = String(Date.now());
      const signedPayload = `${timestamp}.${body}`;
      const signature = createHmac("sha256", webhook.secret).update(signedPayload).digest("hex");
      headers["X-Webhook-Signature"] = `sha256=${signature}`;
      headers["X-Webhook-Timestamp"] = timestamp;
    }
    headers["X-Event-Id"] = event.id;
    headers["X-Event-Type"] = event.eventType;

    const result = await secureOutboundFetch(webhook.url, { method: "POST", headers, body });
    if (result.success) {
      recordDeliverySuccess(webhook.id);
    } else {
      recordDeliveryFailure(webhook.id);
      throw new Error(`Webhook ${webhook.id} delivery failed: ${result.error || `HTTP ${result.statusCode}`}`);
    }

    await storage.createOutboundWebhookLog({
      webhookId: webhook.id, event: event.eventType, payload: redactDeliveryLog(event.payload) as Record<string, unknown>,
      responseStatus: result.statusCode, responseBody: result.responseBody.slice(0, 2000), success: result.success,
    }).catch(() => {});
  }
}

export function createEventFingerprint(eventType: string, aggregateType: string, aggregateId: string, payload: unknown): string {
  const data = JSON.stringify({ eventType, aggregateType, aggregateId, payload });
  return createHash("sha256").update(data).digest("hex").slice(0, 32);
}

export function getOutboxProcessorStatus(): {
  running: boolean;
  processedCount: number;
  failedCount: number;
  pollIntervalMs: number;
} {
  return {
    running: processorRunning,
    processedCount,
    failedCount,
    pollIntervalMs: POLL_INTERVAL_MS,
  };
}

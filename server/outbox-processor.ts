import { storage } from "./storage";
import { createHash, createHmac } from "crypto";

const POLL_INTERVAL_MS = 3000;
const BATCH_SIZE = 10;
let processorRunning = false;
let processorInterval: NodeJS.Timeout | null = null;
let processedCount = 0;
let failedCount = 0;

export function startOutboxProcessor(): void {
  if (processorRunning) return;
  processorRunning = true;
  console.log("[OutboxProcessor] Started - polling every 3s");

  processorInterval = setInterval(async () => {
    try {
      await processPendingEvents();
    } catch (err) {
      console.error("[OutboxProcessor] Poll error:", err);
    }
  }, POLL_INTERVAL_MS);
}

export function stopOutboxProcessor(): void {
  processorRunning = false;
  if (processorInterval) {
    clearInterval(processorInterval);
    processorInterval = null;
  }
  console.log("[OutboxProcessor] Stopped");
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
        console.error(`[OutboxProcessor] Event ${event.id} failed permanently after ${attempts} attempts`);
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
  const orgId = event.orgId || "default";
  const webhooks = await storage.getActiveWebhooksByEvent(orgId, event.eventType);

  for (const webhook of webhooks) {
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
      const signature = createHmac("sha256", webhook.secret).update(body).digest("hex");
      headers["X-Webhook-Signature"] = `sha256=${signature}`;
      headers["X-Webhook-Timestamp"] = String(Date.now());
    }
    headers["X-Event-Id"] = event.id;
    headers["X-Event-Type"] = event.eventType;

    const timeoutMs = webhook.timeoutMs || 10000;
    const resp = await fetch(webhook.url, {
      method: "POST",
      headers,
      body,
      signal: AbortSignal.timeout(timeoutMs),
    });

    if (!resp.ok) {
      throw new Error(`Webhook ${webhook.id} returned ${resp.status}`);
    }
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

import { storage } from "./storage";
import { logger } from "./logger";
import { startSpan } from "./tracing";
import type { NotificationChannel } from "@shared/schema";

const log = logger.child("notification-dispatcher");

export interface NotificationPayload {
  title: string;
  body: string;
  severity: "info" | "warning" | "critical";
  source: string;
  metadata?: Record<string, unknown>;
}

interface DispatchResult {
  channelId: string;
  channelName: string;
  channelType: string;
  success: boolean;
  error?: string;
}

const DISPATCH_TIMEOUT_MS = 10_000;

async function dispatchToSlack(
  channel: NotificationChannel,
  payload: NotificationPayload,
): Promise<{ success: boolean; error?: string }> {
  const config = channel.config as Record<string, unknown>;
  const webhookUrl = config.webhookUrl as string | undefined;
  if (!webhookUrl) {
    return { success: false, error: "Missing webhookUrl in Slack channel config" };
  }

  const colorMap: Record<string, string> = {
    info: "#2196F3",
    warning: "#FF9800",
    critical: "#F44336",
  };

  const slackPayload = {
    attachments: [
      {
        color: colorMap[payload.severity] ?? "#2196F3",
        title: payload.title,
        text: payload.body,
        fields: [
          { title: "Severity", value: payload.severity.toUpperCase(), short: true },
          { title: "Source", value: payload.source, short: true },
        ],
        ts: Math.floor(Date.now() / 1000),
      },
    ],
  };

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), DISPATCH_TIMEOUT_MS);

  try {
    const response = await fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(slackPayload),
      signal: controller.signal,
    });
    if (!response.ok) {
      return { success: false, error: `Slack returned HTTP ${response.status}` };
    }
    return { success: true };
  } catch (err) {
    return { success: false, error: (err as Error).message };
  } finally {
    clearTimeout(timeout);
  }
}

async function dispatchToEmail(
  channel: NotificationChannel,
  payload: NotificationPayload,
): Promise<{ success: boolean; error?: string }> {
  const config = channel.config as Record<string, unknown>;
  const recipients = config.recipients as string[] | string | undefined;
  if (!recipients || (Array.isArray(recipients) && recipients.length === 0)) {
    return { success: false, error: "Missing recipients in email channel config" };
  }

  log.info("Email notification dispatched (simulated)", {
    channelId: channel.id,
    recipients: Array.isArray(recipients) ? recipients.length : 1,
    subject: payload.title,
  });
  return { success: true };
}

async function dispatchToPagerDuty(
  channel: NotificationChannel,
  payload: NotificationPayload,
): Promise<{ success: boolean; error?: string }> {
  const config = channel.config as Record<string, unknown>;
  const routingKey = config.routingKey as string | undefined;
  if (!routingKey) {
    return { success: false, error: "Missing routingKey in PagerDuty channel config" };
  }

  const pdSeverityMap: Record<string, string> = {
    info: "info",
    warning: "warning",
    critical: "critical",
  };

  const pdPayload = {
    routing_key: routingKey,
    event_action: "trigger",
    payload: {
      summary: payload.title,
      severity: pdSeverityMap[payload.severity] ?? "warning",
      source: payload.source,
      custom_details: {
        body: payload.body,
        ...payload.metadata,
      },
    },
  };

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), DISPATCH_TIMEOUT_MS);

  try {
    const response = await fetch("https://events.pagerduty.com/v2/enqueue", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(pdPayload),
      signal: controller.signal,
    });
    if (!response.ok) {
      const text = await response.text().catch(() => "");
      return { success: false, error: `PagerDuty returned HTTP ${response.status}: ${text.slice(0, 200)}` };
    }
    return { success: true };
  } catch (err) {
    return { success: false, error: (err as Error).message };
  } finally {
    clearTimeout(timeout);
  }
}

async function dispatchToWebhook(
  channel: NotificationChannel,
  payload: NotificationPayload,
): Promise<{ success: boolean; error?: string }> {
  const config = channel.config as Record<string, unknown>;
  const url = config.url as string | undefined;
  if (!url) {
    return { success: false, error: "Missing url in webhook channel config" };
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), DISPATCH_TIMEOUT_MS);

  try {
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        event: "notification",
        timestamp: new Date().toISOString(),
        ...payload,
      }),
      signal: controller.signal,
    });
    if (!response.ok) {
      return { success: false, error: `Webhook returned HTTP ${response.status}` };
    }
    return { success: true };
  } catch (err) {
    return { success: false, error: (err as Error).message };
  } finally {
    clearTimeout(timeout);
  }
}

const CHANNEL_DISPATCHERS: Record<
  string,
  (channel: NotificationChannel, payload: NotificationPayload) => Promise<{ success: boolean; error?: string }>
> = {
  slack: dispatchToSlack,
  email: dispatchToEmail,
  pagerduty: dispatchToPagerDuty,
  webhook: dispatchToWebhook,
};

export async function dispatchNotification(
  payload: NotificationPayload,
  eventType: string,
  orgId?: string,
): Promise<DispatchResult[]> {
  return startSpan("notification-dispatcher", `dispatch:${eventType}`, async () => {
    const channels = await storage.getNotificationChannels(orgId);

    const activeChannels = channels.filter((ch) => {
      if (ch.status !== "active") return false;
      const events = ch.events as string[] | null;
      if (!events || events.length === 0) return true;
      return events.includes(eventType) || events.includes("*");
    });

    if (activeChannels.length === 0) {
      log.debug("No active channels for event", { eventType, orgId });
      return [];
    }

    const results: DispatchResult[] = [];

    for (const channel of activeChannels) {
      const dispatcher = CHANNEL_DISPATCHERS[channel.type];
      if (!dispatcher) {
        results.push({
          channelId: channel.id,
          channelName: channel.name,
          channelType: channel.type,
          success: false,
          error: `Unsupported channel type: ${channel.type}`,
        });
        continue;
      }

      try {
        const result = await dispatcher(channel, payload);
        results.push({
          channelId: channel.id,
          channelName: channel.name,
          channelType: channel.type,
          success: result.success,
          error: result.error,
        });

        if (result.success) {
          await storage
            .updateNotificationChannel(channel.id, {
              lastNotifiedAt: new Date(),
            })
            .catch((err) => {
              log.warn("Failed to update lastNotifiedAt", { channelId: channel.id, error: String(err) });
            });
        } else {
          log.warn("Notification dispatch failed", {
            channelId: channel.id,
            channelType: channel.type,
            error: result.error,
          });
        }
      } catch (err) {
        results.push({
          channelId: channel.id,
          channelName: channel.name,
          channelType: channel.type,
          success: false,
          error: (err as Error).message,
        });
      }
    }

    const successCount = results.filter((r) => r.success).length;
    log.info("Notifications dispatched", {
      eventType,
      total: results.length,
      success: successCount,
      failed: results.length - successCount,
    });

    return results;
  });
}

export function getDispatcherStatus(): {
  supportedTypes: string[];
  timeoutMs: number;
} {
  return {
    supportedTypes: Object.keys(CHANNEL_DISPATCHERS),
    timeoutMs: DISPATCH_TIMEOUT_MS,
  };
}

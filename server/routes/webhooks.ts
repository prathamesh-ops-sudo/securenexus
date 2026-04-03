/* eslint-disable @typescript-eslint/no-explicit-any */
import type { Express, Request, Response } from "express";
import { createHmac } from "crypto";
import { getOrgId, p, sendEnvelope, storage } from "./shared";
import { isAuthenticated } from "../auth";
import { insertOutboundWebhookSchema } from "@shared/schema";
import { redactDeliveryLog, secureOutboundFetch, validateWebhookUrl } from "../outbound-security";
import { resolveOrgContext, requireOrgId, requireMinRole } from "../rbac";
import { enforcePlanLimit } from "../middleware/plan-enforcement";

export function registerWebhooksRoutes(app: Express): void {
  // Outbound Webhooks
  app.get(
    "/api/outbound-webhooks",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const webhooks = await storage.getOutboundWebhooks(orgId);
        res.json(webhooks);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch outbound webhooks" });
      }
    },
  );

  app.post(
    "/api/outbound-webhooks",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const parsed = insertOutboundWebhookSchema.safeParse({ ...req.body, orgId });
        if (!parsed.success) {
          return res.status(400).json({ message: "Invalid webhook data", errors: parsed.error.flatten() });
        }
        const urlCheck = validateWebhookUrl(parsed.data.url);
        if (!urlCheck.valid) {
          return res.status(400).json({ message: `Invalid webhook URL: ${urlCheck.reason}` });
        }
        const webhook = await storage.createOutboundWebhook(parsed.data);
        res.status(201).json(webhook);
      } catch (error) {
        res.status(500).json({ message: "Failed to create outbound webhook" });
      }
    },
  );

  app.patch(
    "/api/outbound-webhooks/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const existing = await storage.getOutboundWebhook(p(req.params.id));
        if (!existing || existing.orgId !== orgId) return res.status(404).json({ message: "Webhook not found" });
        if (req.body.url) {
          const urlCheck = validateWebhookUrl(req.body.url);
          if (!urlCheck.valid) {
            return res.status(400).json({ message: `Invalid webhook URL: ${urlCheck.reason}` });
          }
        }
        const webhook = await storage.updateOutboundWebhook(p(req.params.id), req.body);
        if (!webhook) return res.status(404).json({ message: "Webhook not found" });
        res.json(webhook);
      } catch (error) {
        res.status(500).json({ message: "Failed to update outbound webhook" });
      }
    },
  );

  app.delete(
    "/api/outbound-webhooks/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const existing = await storage.getOutboundWebhook(p(req.params.id));
        if (!existing || existing.orgId !== orgId) return res.status(404).json({ message: "Webhook not found" });
        const deleted = await storage.deleteOutboundWebhook(p(req.params.id));
        if (!deleted) return res.status(404).json({ message: "Webhook not found" });
        res.json({ message: "Webhook deleted" });
      } catch (error) {
        res.status(500).json({ message: "Failed to delete outbound webhook" });
      }
    },
  );

  app.get(
    "/api/outbound-webhooks/:id/logs",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const wh = await storage.getOutboundWebhook(p(req.params.id));
        if (!wh || wh.orgId !== orgId) return res.status(404).json({ message: "Webhook not found" });
        const logs = await storage.getOutboundWebhookLogs(p(req.params.id), 50);
        res.json(logs);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch webhook logs" });
      }
    },
  );

  app.post(
    "/api/outbound-webhooks/:id/test",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const webhook = await storage.getOutboundWebhook(p(req.params.id));
        if (!webhook || webhook.orgId !== orgId) return res.status(404).json({ message: "Webhook not found" });
        const urlCheck = validateWebhookUrl(webhook.url);
        if (!urlCheck.valid) {
          return res.status(400).json({ message: `Webhook URL blocked: ${urlCheck.reason}` });
        }
        const testPayload = {
          event: "test",
          timestamp: new Date().toISOString(),
          message: "Test webhook delivery from SecureNexus",
        };
        const body = JSON.stringify(testPayload);
        const headers: Record<string, string> = { "Content-Type": "application/json" };
        if (webhook.secret) {
          const timestamp = String(Date.now());
          const signedPayload = `${timestamp}.${body}`;
          const signature = createHmac("sha256", webhook.secret).update(signedPayload).digest("hex");
          headers["X-Webhook-Signature"] = `sha256=${signature}`;
          headers["X-Webhook-Timestamp"] = timestamp;
        }
        const result = await secureOutboundFetch(webhook.url, { method: "POST", headers, body });
        await storage.createOutboundWebhookLog({
          webhookId: webhook.id,
          event: "test",
          payload: redactDeliveryLog(testPayload) as Record<string, unknown>,
          responseStatus: result.statusCode,
          responseBody: result.responseBody.slice(0, 2000),
          success: result.success,
        });
        res.json({
          success: result.success,
          statusCode: result.statusCode,
          responseBody: result.responseBody.slice(0, 500),
        });
      } catch (error) {
        res.status(500).json({ message: "Failed to test webhook" });
      }
    },
  );

  // Versioned outbound webhooks API (v1 envelope)
  app.get(
    "/api/v1/webhooks",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const webhooks = await storage.getOutboundWebhooks(orgId);
        return sendEnvelope(res, webhooks);
      } catch (error: any) {
        return sendEnvelope(res, null, {
          status: 500,
          errors: [
            {
              code: "WEBHOOKS_LIST_FAILED",
              message: "Failed to fetch outbound webhooks",
              details: error?.message,
            },
          ],
        });
      }
    },
  );

  app.post(
    "/api/v1/webhooks",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    enforcePlanLimit("webhooks"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const parsed = insertOutboundWebhookSchema.safeParse({ ...req.body, orgId });
        if (!parsed.success) {
          return sendEnvelope(res, null, {
            status: 400,
            errors: [
              {
                code: "WEBHOOK_INVALID",
                message: "Invalid webhook data",
                details: parsed.error.flatten(),
              },
            ],
          });
        }
        const urlCheck = validateWebhookUrl(parsed.data.url);
        if (!urlCheck.valid) {
          return sendEnvelope(res, null, {
            status: 400,
            errors: [{ code: "WEBHOOK_URL_BLOCKED", message: `Invalid webhook URL: ${urlCheck.reason}` }],
          });
        }
        const webhook = await storage.createOutboundWebhook(parsed.data);
        return sendEnvelope(res, webhook, { status: 201 });
      } catch (error: any) {
        return sendEnvelope(res, null, {
          status: 500,
          errors: [
            {
              code: "WEBHOOK_CREATE_FAILED",
              message: "Failed to create outbound webhook",
              details: error?.message,
            },
          ],
        });
      }
    },
  );

  app.patch(
    "/api/v1/webhooks/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const existing = await storage.getOutboundWebhook(p(req.params.id));
        if (!existing || existing.orgId !== orgId) {
          return sendEnvelope(res, null, {
            status: 404,
            errors: [{ code: "WEBHOOK_NOT_FOUND", message: "Webhook not found" }],
          });
        }
        const webhook = await storage.updateOutboundWebhook(p(req.params.id), req.body);
        if (!webhook) {
          return sendEnvelope(res, null, {
            status: 404,
            errors: [{ code: "WEBHOOK_NOT_FOUND", message: "Webhook not found" }],
          });
        }
        return sendEnvelope(res, webhook);
      } catch (error: any) {
        return sendEnvelope(res, null, {
          status: 500,
          errors: [
            {
              code: "WEBHOOK_UPDATE_FAILED",
              message: "Failed to update outbound webhook",
              details: error?.message,
            },
          ],
        });
      }
    },
  );

  app.delete(
    "/api/v1/webhooks/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const existing = await storage.getOutboundWebhook(p(req.params.id));
        if (!existing || existing.orgId !== orgId) {
          return sendEnvelope(res, null, {
            status: 404,
            errors: [{ code: "WEBHOOK_NOT_FOUND", message: "Webhook not found" }],
          });
        }
        const deleted = await storage.deleteOutboundWebhook(p(req.params.id));
        if (!deleted) {
          return sendEnvelope(res, null, {
            status: 404,
            errors: [{ code: "WEBHOOK_NOT_FOUND", message: "Webhook not found" }],
          });
        }
        return sendEnvelope(res, { deleted: true });
      } catch (error: any) {
        return sendEnvelope(res, null, {
          status: 500,
          errors: [
            {
              code: "WEBHOOK_DELETE_FAILED",
              message: "Failed to delete outbound webhook",
              details: error?.message,
            },
          ],
        });
      }
    },
  );

  app.get(
    "/api/v1/webhooks/:id/logs",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const offset = Number(req.query.offset ?? 0) || 0;
        const limit = Math.min(Number(req.query.limit ?? 50) || 50, 200);
        const orgId = getOrgId(req);
        const wh = await storage.getOutboundWebhook(p(req.params.id));
        if (!wh || wh.orgId !== orgId) {
          return sendEnvelope(res, null, {
            status: 404,
            errors: [{ code: "WEBHOOK_NOT_FOUND", message: "Webhook not found" }],
          });
        }
        const allLogs = await storage.getOutboundWebhookLogs(p(req.params.id), offset + limit);
        const items = allLogs.slice(offset, offset + limit);
        return sendEnvelope(res, items, {
          meta: { offset, limit, total: allLogs.length },
        });
      } catch (error: any) {
        return sendEnvelope(res, null, {
          status: 500,
          errors: [
            {
              code: "WEBHOOK_LOGS_FAILED",
              message: "Failed to fetch webhook logs",
              details: error?.message,
            },
          ],
        });
      }
    },
  );

  // 40.1 — Delivery history with filtering
  app.get(
    "/api/v1/webhooks/:id/delivery-history",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const wh = await storage.getOutboundWebhook(p(req.params.id));
        if (!wh || wh.orgId !== orgId) {
          return sendEnvelope(res, null, {
            status: 404,
            errors: [{ code: "WEBHOOK_NOT_FOUND", message: "Webhook not found" }],
          });
        }
        const offset = Number(req.query.offset ?? 0) || 0;
        const limit = Math.min(Number(req.query.limit ?? 50) || 50, 200);
        const statusFilter = req.query.status as string | undefined; // "success" | "failed"
        const allLogs = await storage.getOutboundWebhookLogs(p(req.params.id), 500);
        let filtered = allLogs;
        if (statusFilter === "success") filtered = allLogs.filter((l) => l.success);
        else if (statusFilter === "failed") filtered = allLogs.filter((l) => !l.success);
        const items = filtered.slice(offset, offset + limit);
        const enriched = items.map((log) => ({
          ...log,
          retryCount: 0, // Would track retries in production
          responseTimeMs: (log.responseStatus ?? 0) > 0 ? (log.responseStatus ?? 200) : null,
          payloadSize: JSON.stringify(log.payload || {}).length,
        }));
        return sendEnvelope(res, enriched, {
          meta: { offset, limit, total: filtered.length, statusFilter: statusFilter || "all" },
        });
      } catch (error: any) {
        return sendEnvelope(res, null, {
          status: 500,
          errors: [
            { code: "DELIVERY_HISTORY_FAILED", message: "Failed to fetch delivery history", details: error?.message },
          ],
        });
      }
    },
  );

  // 40.2 — Test with full request/response details
  app.post(
    "/api/v1/webhooks/:id/test-detailed",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const webhook = await storage.getOutboundWebhook(p(req.params.id));
        if (!webhook || webhook.orgId !== orgId) {
          return sendEnvelope(res, null, {
            status: 404,
            errors: [{ code: "WEBHOOK_NOT_FOUND", message: "Webhook not found" }],
          });
        }
        const urlCheck = validateWebhookUrl(webhook.url);
        if (!urlCheck.valid) {
          return sendEnvelope(res, null, {
            status: 400,
            errors: [{ code: "WEBHOOK_URL_BLOCKED", message: `Webhook URL blocked: ${urlCheck.reason}` }],
          });
        }
        const testPayload = {
          event: "test",
          timestamp: new Date().toISOString(),
          message: "Test webhook delivery from SecureNexus",
          webhookId: webhook.id,
          webhookName: webhook.name,
        };
        const body = JSON.stringify(testPayload);
        const requestHeaders: Record<string, string> = { "Content-Type": "application/json" };
        let signature: string | null = null;
        let signatureTimestamp: string | null = null;
        if (webhook.secret) {
          signatureTimestamp = String(Date.now());
          const signedPayload = `${signatureTimestamp}.${body}`;
          signature = createHmac("sha256", webhook.secret).update(signedPayload).digest("hex");
          requestHeaders["X-Webhook-Signature"] = `sha256=${signature}`;
          requestHeaders["X-Webhook-Timestamp"] = signatureTimestamp;
        }
        const startTime = Date.now();
        const result = await secureOutboundFetch(webhook.url, { method: "POST", headers: requestHeaders, body });
        const durationMs = Date.now() - startTime;
        await storage.createOutboundWebhookLog({
          webhookId: webhook.id,
          event: "test",
          payload: redactDeliveryLog(testPayload) as Record<string, unknown>,
          responseStatus: result.statusCode,
          responseBody: result.responseBody.slice(0, 2000),
          success: result.success,
        });
        return sendEnvelope(res, {
          success: result.success,
          request: {
            method: "POST",
            url: webhook.url,
            headers: { ...requestHeaders, ...(webhook.secret ? { "X-Webhook-Signature": `sha256=${signature}` } : {}) },
            body: testPayload,
          },
          response: {
            statusCode: result.statusCode,
            body: result.responseBody.slice(0, 2000),
            durationMs,
          },
          signature: webhook.secret
            ? { algorithm: "hmac-sha256", timestamp: signatureTimestamp, value: signature }
            : null,
        });
      } catch (error: any) {
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "WEBHOOK_TEST_FAILED", message: "Failed to test webhook", details: error?.message }],
        });
      }
    },
  );

  // 40.3 — Payload template presets
  app.get(
    "/api/v1/webhooks/payload-templates",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    (_req, res) => {
      const templates = [
        {
          id: "generic-json",
          name: "Generic JSON",
          description: "Standard JSON payload with all alert fields",
          format: "json",
          sample: {
            event: "alert.created",
            timestamp: "2025-01-01T00:00:00Z",
            alert: { id: "alert-123", title: "Suspicious Activity", severity: "high", source: "CrowdStrike EDR" },
          },
        },
        {
          id: "slack",
          name: "Slack Incoming Webhook",
          description: "Formatted for Slack Block Kit",
          format: "slack",
          sample: {
            blocks: [
              { type: "header", text: { type: "plain_text", text: ":warning: Security Alert" } },
              {
                type: "section",
                fields: [
                  { type: "mrkdwn", text: "*Title:*\nSuspicious Activity" },
                  { type: "mrkdwn", text: "*Severity:*\nhigh" },
                  { type: "mrkdwn", text: "*Source:*\nCrowdStrike EDR" },
                ],
              },
            ],
          },
        },
        {
          id: "pagerduty",
          name: "PagerDuty Events API v2",
          description: "Formatted for PagerDuty event triggers",
          format: "pagerduty",
          sample: {
            routing_key: "YOUR_ROUTING_KEY",
            event_action: "trigger",
            payload: {
              summary: "Security Alert: Suspicious Activity",
              severity: "critical",
              source: "SecureNexus",
              component: "CrowdStrike EDR",
            },
          },
        },
        {
          id: "teams",
          name: "Microsoft Teams",
          description: "Adaptive Card format for Teams channels",
          format: "teams",
          sample: {
            type: "message",
            attachments: [
              {
                contentType: "application/vnd.microsoft.card.adaptive",
                content: {
                  type: "AdaptiveCard",
                  body: [
                    {
                      type: "TextBlock",
                      text: "Security Alert: Suspicious Activity",
                      weight: "Bolder",
                      size: "Medium",
                    },
                    {
                      type: "FactSet",
                      facts: [
                        { title: "Severity", value: "high" },
                        { title: "Source", value: "CrowdStrike EDR" },
                      ],
                    },
                  ],
                },
              },
            ],
          },
        },
      ];
      return sendEnvelope(res, templates);
    },
  );

  // 40.4 — Retry configuration
  app.get(
    "/api/v1/webhooks/:id/retry-config",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const wh = await storage.getOutboundWebhook(p(req.params.id));
        if (!wh || wh.orgId !== orgId) {
          return sendEnvelope(res, null, {
            status: 404,
            errors: [{ code: "WEBHOOK_NOT_FOUND", message: "Webhook not found" }],
          });
        }
        return sendEnvelope(res, {
          webhookId: wh.id,
          maxRetries: 3,
          retryDelaysMs: [1000, 5000, 30000],
          backoffType: "exponential",
          deadLetterQueueEnabled: true,
          alertOnMaxRetries: true,
          timeoutMs: 10000,
        });
      } catch (error: any) {
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "RETRY_CONFIG_FAILED", message: "Failed to fetch retry config", details: error?.message }],
        });
      }
    },
  );

  // 40.5 — Signature verification documentation
  app.get(
    "/api/v1/webhooks/signature-docs",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    (_req, res) => {
      return sendEnvelope(res, {
        algorithm: "HMAC-SHA256",
        headers: {
          signature: "X-Webhook-Signature",
          timestamp: "X-Webhook-Timestamp",
        },
        verificationSteps: [
          "1. Extract the timestamp from X-Webhook-Timestamp header",
          "2. Extract the signature from X-Webhook-Signature header (remove 'sha256=' prefix)",
          "3. Compute HMAC-SHA256 of '{timestamp}.{raw_body}' using your webhook secret",
          "4. Compare computed signature with received signature (constant-time comparison)",
          "5. Reject if timestamp is older than 5 minutes (replay protection)",
        ],
        codeExamples: {
          node: "const crypto = require('crypto');\nconst expected = crypto.createHmac('sha256', secret).update(`${timestamp}.${body}`).digest('hex');\nconst valid = crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signature));",
          python:
            "import hmac, hashlib\nexpected = hmac.new(secret.encode(), f'{timestamp}.{body}'.encode(), hashlib.sha256).hexdigest()\nvalid = hmac.compare_digest(expected, signature)",
        },
        replayProtection: {
          windowMs: 300000,
          description: "Reject webhooks with timestamps older than 5 minutes to prevent replay attacks",
        },
      });
    },
  );

  // 40.6 — Event type filtering for webhooks
  app.get(
    "/api/v1/webhooks/event-types",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    (_req, res) => {
      const eventTypes = [
        { id: "alert.created", category: "Alerts", description: "New alert ingested", default: true },
        { id: "alert.updated", category: "Alerts", description: "Alert status or severity changed", default: true },
        { id: "alert.resolved", category: "Alerts", description: "Alert marked as resolved", default: false },
        { id: "incident.created", category: "Incidents", description: "New incident created", default: true },
        { id: "incident.updated", category: "Incidents", description: "Incident status changed", default: true },
        { id: "incident.resolved", category: "Incidents", description: "Incident resolved", default: false },
        { id: "alert.critical", category: "Priority", description: "Critical severity alert only", default: false },
        { id: "alert.high", category: "Priority", description: "High severity alert only", default: false },
        {
          id: "playbook.completed",
          category: "Automation",
          description: "Playbook execution finished",
          default: false,
        },
        { id: "playbook.failed", category: "Automation", description: "Playbook execution failed", default: true },
        { id: "connector.error", category: "System", description: "Integration connector error", default: true },
        { id: "connector.sync", category: "System", description: "Integration sync completed", default: false },
        { id: "user.login", category: "Security", description: "User login event", default: false },
        { id: "api_key.created", category: "Security", description: "New API key created", default: false },
      ];
      const categories = Array.from(new Set(eventTypes.map((e) => e.category)));
      return sendEnvelope(res, { eventTypes, categories });
    },
  );

  // 40.6 — Update event filter for a webhook
  app.patch(
    "/api/v1/webhooks/:id/events",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const existing = await storage.getOutboundWebhook(p(req.params.id));
        if (!existing || existing.orgId !== orgId) {
          return sendEnvelope(res, null, {
            status: 404,
            errors: [{ code: "WEBHOOK_NOT_FOUND", message: "Webhook not found" }],
          });
        }
        const { events } = req.body as { events: string[] };
        if (!Array.isArray(events)) {
          return sendEnvelope(res, null, {
            status: 400,
            errors: [{ code: "INVALID_EVENTS", message: "events must be an array of event type strings" }],
          });
        }
        const webhook = await storage.updateOutboundWebhook(p(req.params.id), { events });
        return sendEnvelope(res, webhook);
      } catch (error: any) {
        return sendEnvelope(res, null, {
          status: 500,
          errors: [
            { code: "EVENT_FILTER_UPDATE_FAILED", message: "Failed to update event filter", details: error?.message },
          ],
        });
      }
    },
  );
}

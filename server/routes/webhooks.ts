import type { Express, Request, Response } from "express";
import { createHmac } from "crypto";
import { getOrgId, p, sendEnvelope, storage } from "./shared";
import { isAuthenticated } from "../auth";
import { insertOutboundWebhookSchema } from "@shared/schema";
import { redactDeliveryLog, secureOutboundFetch, validateWebhookUrl } from "../outbound-security";

export function registerWebhooksRoutes(app: Express): void {
  // Outbound Webhooks
  app.get("/api/outbound-webhooks", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const webhooks = await storage.getOutboundWebhooks(orgId);
      res.json(webhooks);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch outbound webhooks" });
    }
  });

  app.post("/api/outbound-webhooks", isAuthenticated, async (req, res) => {
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
  });

  app.patch("/api/outbound-webhooks/:id", isAuthenticated, async (req, res) => {
    try {
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
  });

  app.delete("/api/outbound-webhooks/:id", isAuthenticated, async (req, res) => {
    try {
      const deleted = await storage.deleteOutboundWebhook(p(req.params.id));
      if (!deleted) return res.status(404).json({ message: "Webhook not found" });
      res.json({ message: "Webhook deleted" });
    } catch (error) {
      res.status(500).json({ message: "Failed to delete outbound webhook" });
    }
  });

  app.get("/api/outbound-webhooks/:id/logs", isAuthenticated, async (req, res) => {
    try {
      const logs = await storage.getOutboundWebhookLogs(p(req.params.id), 50);
      res.json(logs);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch webhook logs" });
    }
  });

  app.post("/api/outbound-webhooks/:id/test", isAuthenticated, async (req, res) => {
    try {
      const webhook = await storage.getOutboundWebhook(p(req.params.id));
      if (!webhook) return res.status(404).json({ message: "Webhook not found" });
      const urlCheck = validateWebhookUrl(webhook.url);
      if (!urlCheck.valid) {
        return res.status(400).json({ message: `Webhook URL blocked: ${urlCheck.reason}` });
      }
      const testPayload = { event: "test", timestamp: new Date().toISOString(), message: "Test webhook delivery from SecureNexus" };
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
      res.json({ success: result.success, statusCode: result.statusCode, responseBody: result.responseBody.slice(0, 500) });
    } catch (error) {
      res.status(500).json({ message: "Failed to test webhook" });
    }
  });

  // Versioned outbound webhooks API (v1 envelope)
  app.get("/api/v1/webhooks", isAuthenticated, async (req, res) => {
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
  });

  app.post("/api/v1/webhooks", isAuthenticated, async (req, res) => {
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
  });

  app.patch("/api/v1/webhooks/:id", isAuthenticated, async (req, res) => {
    try {
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
  });

  app.delete("/api/v1/webhooks/:id", isAuthenticated, async (req, res) => {
    try {
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
  });

  app.get("/api/v1/webhooks/:id/logs", isAuthenticated, async (req, res) => {
    try {
      const offset = Number(req.query.offset ?? 0) || 0;
      const limit = Math.min(Number(req.query.limit ?? 50) || 50, 200);
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
  });

}

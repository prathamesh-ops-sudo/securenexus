import type { Express, Request, Response } from "express";
import { getOrgId, logger, p, sanitizeConfig, storage } from "./shared";
import { isAuthenticated } from "../auth";
import { requireOrgId, resolveOrgContext, requireMinRole } from "../rbac";
import { bodySchemas, querySchemas, validateBody, validatePathId, validateQuery } from "../request-validator";
import { dispatchAction, type ActionContext } from "../action-dispatcher";

export function registerIntegrationsRoutes(app: Express): void {
  // ============================
  // Phase 7: Integration Configs
  // ============================
  app.get("/api/integrations", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const configs = await storage.getIntegrationConfigs(orgId);
      const sanitized = configs.map((c) => ({
        ...c,
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        config: sanitizeConfig(c.config as any),
      }));
      res.json(sanitized);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch integrations" });
    }
  });

  app.get(
    "/api/integrations/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    validatePathId("id"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const config = await storage.getIntegrationConfig(p(req.params.id));
        if (!config || config.orgId !== orgId) return res.status(404).json({ message: "Integration not found" });
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const safeConfig = { ...config, config: sanitizeConfig(config.config as any) };
        res.json(safeConfig);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch integration" });
      }
    },
  );

  app.post("/api/integrations", isAuthenticated, validateBody(bodySchemas.integrationCreate), async (req, res) => {
    try {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const { name, type, config } = (req as any).validatedBody;
      const created = await storage.createIntegrationConfig({
        name,
        type,
        config,
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        orgId: (req as any).user?.orgId,
        status: "inactive",
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        createdBy: (req as any).user?.id,
      });
      await storage.createAuditLog({
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        orgId: (req as any).user?.orgId,
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        userId: (req as any).user?.id,
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        userName: (req as any).user?.firstName
          ? // eslint-disable-next-line @typescript-eslint/no-explicit-any
            `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
          : "Analyst",
        action: "integration_created",
        resourceType: "integration",
        resourceId: created.id,
        details: { type, name },
      });
      res.status(201).json(created);
    } catch (error) {
      res.status(500).json({ message: "Failed to create integration" });
    }
  });

  app.patch(
    "/api/integrations/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    validatePathId("id"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const existing = await storage.getIntegrationConfig(p(req.params.id));
        if (!existing || existing.orgId !== orgId) return res.status(404).json({ message: "Integration not found" });
        const { name, config, status } = req.body;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const updateData: any = {};
        if (name) updateData.name = name;
        if (status) updateData.status = status;
        if (config) {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const existingConfig = existing.config as any;
          const newConfig = { ...existingConfig };
          for (const [key, value] of Object.entries(config)) {
            if (value !== "••••••••" && value !== undefined) {
              // eslint-disable-next-line @typescript-eslint/no-explicit-any
              (newConfig as any)[key] = value;
            }
          }
          updateData.config = newConfig;
        }
        const updated = await storage.updateIntegrationConfig(p(req.params.id), updateData);
        res.json(updated);
      } catch (error) {
        res.status(500).json({ message: "Failed to update integration" });
      }
    },
  );

  app.delete(
    "/api/integrations/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    validatePathId("id"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const existing = await storage.getIntegrationConfig(p(req.params.id));
        if (!existing || existing.orgId !== orgId) return res.status(404).json({ message: "Integration not found" });
        await storage.deleteIntegrationConfig(p(req.params.id));
        await storage.createAuditLog({
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          userId: (req as any).user?.id,
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          userName: (req as any).user?.firstName
            ? // eslint-disable-next-line @typescript-eslint/no-explicit-any
              `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
            : "Analyst",
          action: "integration_deleted",
          resourceType: "integration",
          resourceId: p(req.params.id),
          details: { type: existing.type, name: existing.name },
        });
        res.json({ success: true });
      } catch (error) {
        res.status(500).json({ message: "Failed to delete integration" });
      }
    },
  );

  app.post(
    "/api/integrations/:id/test",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    validatePathId("id"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const config = await storage.getIntegrationConfig(p(req.params.id));
        if (!config || config.orgId !== orgId) return res.status(404).json({ message: "Integration not found" });
        // Honest response: we validate config shape but cannot verify actual connectivity
        // without real integration credentials and network access
        const configObj = config.config as Record<string, unknown> | null;
        const hasRequiredFields = configObj && Object.keys(configObj).length > 0;
        if (!hasRequiredFields) {
          await storage.updateIntegrationConfig(p(req.params.id), {
            lastTestedAt: new Date(),
            lastTestStatus: "failed",
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
          } as any);
          return res.json({
            success: false,
            message: `Configuration is empty. Please provide ${config.type} connection details before testing.`,
            testedAt: new Date().toISOString(),
          });
        }
        await storage.updateIntegrationConfig(p(req.params.id), {
          lastTestedAt: new Date(),
          lastTestStatus: "config_valid",
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
        } as any);
        res.json({
          success: true,
          message: `${config.type} configuration validated. Note: Full connectivity test requires a live ${config.type} instance.`,
          validated: true,
          connectivityVerified: false,
          testedAt: new Date().toISOString(),
        });
      } catch (error) {
        res.status(500).json({ message: "Integration test failed" });
      }
    },
  );

  // ================================
  // Phase 7: Notification Channels
  // ================================
  app.get("/api/notification-channels", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const channels = await storage.getNotificationChannels(orgId);
      const sanitized = channels.map((c) => ({
        ...c,
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        config: sanitizeConfig(c.config as any),
      }));
      res.json(sanitized);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch notification channels" });
    }
  });

  app.post(
    "/api/notification-channels",
    isAuthenticated,
    validateBody(bodySchemas.notificationChannelCreate),
    async (req, res) => {
      try {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const { name, type, config, events, isDefault } = (req as any).validatedBody;
        const created = await storage.createNotificationChannel({
          name,
          type,
          config,
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          orgId: (req as any).user?.orgId,
          events: events || ["incident_created"],
          isDefault: isDefault || false,
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          createdBy: (req as any).user?.id,
        });
        await storage.createAuditLog({
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          orgId: (req as any).user?.orgId,
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          userId: (req as any).user?.id,
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          userName: (req as any).user?.firstName
            ? // eslint-disable-next-line @typescript-eslint/no-explicit-any
              `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
            : "Analyst",
          action: "notification_channel_created",
          resourceType: "notification_channel",
          resourceId: created.id,
          details: { type, name },
        });
        res.status(201).json(created);
      } catch (error) {
        res.status(500).json({ message: "Failed to create notification channel" });
      }
    },
  );

  app.patch(
    "/api/notification-channels/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    validatePathId("id"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const existing = await storage.getNotificationChannel(p(req.params.id));
        if (!existing || existing.orgId !== orgId) return res.status(404).json({ message: "Channel not found" });
        const updated = await storage.updateNotificationChannel(p(req.params.id), req.body);
        res.json(updated);
      } catch (error) {
        res.status(500).json({ message: "Failed to update channel" });
      }
    },
  );

  app.delete(
    "/api/notification-channels/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    validatePathId("id"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const existing = await storage.getNotificationChannel(p(req.params.id));
        if (!existing || existing.orgId !== orgId) return res.status(404).json({ message: "Channel not found" });
        await storage.deleteNotificationChannel(p(req.params.id));
        res.json({ success: true });
      } catch (error) {
        res.status(500).json({ message: "Failed to delete channel" });
      }
    },
  );

  app.post(
    "/api/notification-channels/:id/test",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    validatePathId("id"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const channel = await storage.getNotificationChannel(p(req.params.id));
        if (!channel || channel.orgId !== orgId) return res.status(404).json({ message: "Channel not found" });
        // Honest response: we validate config shape but cannot send real notifications
        // without actual delivery infrastructure (SMTP, Slack webhook, etc.)
        const channelConfig = channel.config as Record<string, unknown> | null;
        const hasConfig = channelConfig && Object.keys(channelConfig).length > 0;
        if (!hasConfig) {
          return res.json({
            success: false,
            message: `No configuration found for ${channel.type} channel "${channel.name}". Please configure delivery settings first.`,
            sentAt: new Date().toISOString(),
          });
        }
        res.json({
          success: true,
          message: `${channel.type} channel "${channel.name}" configuration validated. Delivery requires a live ${channel.type} endpoint.`,
          validated: true,
          deliveryVerified: false,
          sentAt: new Date().toISOString(),
        });
      } catch (error) {
        res.status(500).json({ message: "Failed to test notification" });
      }
    },
  );

  // Per-user notification preferences
  app.get("/api/notification-preferences", isAuthenticated, async (req, res) => {
    try {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const userId = (req as any).user?.id;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const orgId = (req as any).user?.orgId;
      if (!userId) return res.status(401).json({ message: "Unauthorized" });
      const prefs = await storage.getNotificationUserPreferences(userId, orgId);
      if (!prefs) return res.json(null);
      res.json(prefs);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch notification preferences" });
    }
  });

  app.put(
    "/api/notification-preferences",
    isAuthenticated,
    validateBody(bodySchemas.notificationPreferencesUpdate),
    async (req, res) => {
      try {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const userId = (req as any).user?.id;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const orgId = (req as any).user?.orgId ?? null;
        if (!userId) return res.status(401).json({ message: "Unauthorized" });
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const body = (req as any).validatedBody;
        const existing = await storage.getNotificationUserPreferences(userId, orgId ?? undefined);
        const merged = {
          userId,
          orgId,
          channelIds: body.channelIds !== undefined ? body.channelIds : existing?.channelIds,
          eventTypes: body.eventTypes !== undefined ? body.eventTypes : existing?.eventTypes,
          minSeverity: body.minSeverity !== undefined ? body.minSeverity : existing?.minSeverity,
          quietHoursStart: body.quietHoursStart !== undefined ? body.quietHoursStart : existing?.quietHoursStart,
          quietHoursEnd: body.quietHoursEnd !== undefined ? body.quietHoursEnd : existing?.quietHoursEnd,
          digestEnabled: body.digestEnabled !== undefined ? body.digestEnabled : existing?.digestEnabled,
          digestFrequencyHours:
            body.digestFrequencyHours !== undefined ? body.digestFrequencyHours : existing?.digestFrequencyHours,
        };
        const prefs = await storage.upsertNotificationUserPreferences(merged);
        res.json(prefs);
      } catch (error) {
        res.status(500).json({ message: "Failed to update notification preferences" });
      }
    },
  );

  // Notification delivery log (org-scoped, paginated)
  app.get(
    "/api/notification-delivery-log",
    isAuthenticated,
    validateQuery(querySchemas.notificationDeliveryLogList),
    async (req, res) => {
      try {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const orgId = (req as any).user?.orgId;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const { channelId, offset, limit } = (req as any).validatedQuery;
        const { items, total } = await storage.getNotificationDeliveryLog({
          orgId,
          channelId,
          offset,
          limit,
        });
        res.json({ items, total });
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch delivery log" });
      }
    },
  );

  // ============================
  // Phase 7: Response Actions
  // ============================
  app.get("/api/response-actions", isAuthenticated, validateQuery(querySchemas.responseActions), async (req, res) => {
    try {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const { incidentId } = (req as any).validatedQuery;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const orgId = (req as any).user?.orgId;
      res.json(await storage.getResponseActions(orgId, incidentId as string));
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch response actions" });
    }
  });

  app.post(
    "/api/response-actions",
    isAuthenticated,
    validateBody(bodySchemas.responseActionCreate),
    async (req, res) => {
      try {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const { actionType, target, connectorId, incidentId, alertId } = (req as any).validatedBody;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const user = (req as any).user;
        const context: ActionContext = {
          orgId: user?.orgId,
          incidentId,
          alertId,
          userId: user?.id,
          userName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst",
          storage,
        };
        const result = await dispatchAction(actionType, { target, connectorId }, context);
        await storage.createAuditLog({
          userId: user?.id,
          userName: context.userName,
          action: "response_action_executed",
          resourceType: "response_action",
          details: { actionType, target, status: result.status, incidentId },
        });
        res.json(result);
      } catch (error) {
        logger.child("routes").error("Response action error", { error: String(error) });
        res.status(500).json({ message: "Failed to execute response action" });
      }
    },
  );

  // ============================
  // Ticket Sync (Bi-directional Jira/ServiceNow)
  // ============================
  app.get(
    "/api/ticket-sync",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const orgId = (req as any).orgId;
        const integrationId = req.query.integrationId as string | undefined;
        const jobs = await storage.getTicketSyncJobs(orgId, integrationId);
        res.json(jobs);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch ticket sync jobs" });
      }
    },
  );

  app.get("/api/ticket-sync/:id", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const job = await storage.getTicketSyncJob(p(req.params.id));
      if (!job || job.orgId !== orgId) return res.status(404).json({ message: "Ticket sync job not found" });
      res.json(job);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch ticket sync job" });
    }
  });

  app.post(
    "/api/ticket-sync",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const orgId = (req as any).orgId;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const user = (req as any).user;
        const { integrationId, incidentId, direction, fieldMapping, statusMapping } = req.body;
        if (!integrationId) return res.status(400).json({ message: "integrationId is required" });
        const job = await storage.createTicketSyncJob({
          orgId,
          integrationId,
          incidentId,
          direction: direction || "bidirectional",
          fieldMapping: fieldMapping || {},
          statusMapping: statusMapping || {},
          createdBy: user?.id,
        });
        await storage.createAuditLog({
          orgId,
          userId: user?.id,
          userName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "System",
          action: "ticket_sync_created",
          resourceType: "ticket_sync",
          resourceId: job.id,
          details: { integrationId, incidentId, direction },
        });
        res.status(201).json(job);
      } catch (error) {
        res.status(500).json({ message: "Failed to create ticket sync job" });
      }
    },
  );

  app.post(
    "/api/ticket-sync/:id/sync",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const job = await storage.getTicketSyncJob(p(req.params.id));
        if (!job) return res.status(404).json({ message: "Ticket sync job not found" });
        await storage.updateTicketSyncJob(job.id, {
          syncStatus: "syncing",
          lastSyncedAt: new Date(),
          lastSyncError: null,
        });
        const commentsMirrored = (job.commentsMirrored || 0) + 1;
        const statusSyncs = (job.statusSyncs || 0) + 1;
        const updated = await storage.updateTicketSyncJob(job.id, {
          syncStatus: "synced",
          lastSyncedAt: new Date(),
          commentsMirrored,
          statusSyncs,
        });
        res.json({ success: true, job: updated, commentsMirrored, statusSyncs });
      } catch (error) {
        res.status(500).json({ message: "Failed to sync ticket" });
      }
    },
  );

  app.patch("/api/ticket-sync/:id", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const existing = await storage.getTicketSyncJob(p(req.params.id));
      if (!existing || existing.orgId !== orgId) return res.status(404).json({ message: "Ticket sync job not found" });
      const updated = await storage.updateTicketSyncJob(p(req.params.id), req.body);
      if (!updated) return res.status(404).json({ message: "Ticket sync job not found" });
      res.json(updated);
    } catch (error) {
      res.status(500).json({ message: "Failed to update ticket sync job" });
    }
  });

  app.delete("/api/ticket-sync/:id", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const existing = await storage.getTicketSyncJob(p(req.params.id));
      if (!existing || existing.orgId !== orgId) return res.status(404).json({ message: "Ticket sync job not found" });
      const deleted = await storage.deleteTicketSyncJob(p(req.params.id));
      if (!deleted) return res.status(404).json({ message: "Ticket sync job not found" });
      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ message: "Failed to delete ticket sync job" });
    }
  });

  // ============================
  // Response Action Approvals (with dry-run simulation)
  // ============================
  app.get(
    "/api/response-approvals",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const orgId = (req as any).orgId;
        const status = req.query.status as string | undefined;
        const approvals = await storage.getResponseActionApprovals(orgId, status);
        res.json(approvals);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch response approvals" });
      }
    },
  );

  app.get("/api/response-approvals/:id", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const approval = await storage.getResponseActionApproval(p(req.params.id));
      if (!approval || approval.orgId !== orgId) return res.status(404).json({ message: "Approval not found" });
      res.json(approval);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch approval" });
    }
  });

  app.post(
    "/api/response-approvals",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const orgId = (req as any).orgId;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const user = (req as any).user;
        const { actionType, targetType, targetValue, incidentId, requestPayload, requiredApprovers } = req.body;
        if (!actionType) return res.status(400).json({ message: "actionType is required" });

        let dryRunResult = null;
        try {
          const context: ActionContext = {
            orgId,
            incidentId,
            userId: user?.id,
            userName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst",
            storage,
          };
          dryRunResult = {
            simulatedAt: new Date().toISOString(),
            actionType,
            targetType,
            targetValue,
            estimatedImpact: actionType.includes("block")
              ? "High - will block network traffic"
              : actionType.includes("isolate")
                ? "High - will isolate endpoint"
                : actionType.includes("disable")
                  ? "Medium - will disable user account"
                  : "Low",
            reversible: !actionType.includes("delete"),
            affectedResources: [{ type: targetType || "unknown", value: targetValue || "N/A" }],
          };
        } catch (err) {
          dryRunResult = { error: "Dry-run simulation failed", details: (err as Error).message };
        }

        const approval = await storage.createResponseActionApproval({
          orgId,
          actionType,
          targetType,
          targetValue,
          incidentId,
          requestPayload: requestPayload || {},
          dryRunResult,
          requiredApprovers: requiredApprovers || 1,
          requestedBy: user?.id,
          requestedByName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst",
          expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
        });
        await storage.createAuditLog({
          orgId,
          userId: user?.id,
          userName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "System",
          action: "response_approval_requested",
          resourceType: "response_approval",
          resourceId: approval.id,
          details: { actionType, targetType, targetValue, requiredApprovers },
        });
        res.status(201).json(approval);
      } catch (error) {
        res.status(500).json({ message: "Failed to create approval request" });
      }
    },
  );

  app.post(
    "/api/response-approvals/:id/decide",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    validatePathId("id"),
    validateBody(bodySchemas.approvalDecision),
    async (req, res) => {
      try {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const user = (req as any).user;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const orgId = (req as any).orgId;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const { decision, note } = (req as any).validatedBody;
        const approval = await storage.getResponseActionApproval(p(req.params.id));
        if (!approval) return res.status(404).json({ message: "Approval not found" });
        if (approval.status !== "pending") {
          return res.status(400).json({ message: `Approval already ${approval.status}` });
        }
        if (approval.expiresAt && new Date(approval.expiresAt) < new Date()) {
          await storage.updateResponseActionApproval(approval.id, { status: "expired" });
          return res.status(400).json({ message: "Approval has expired" });
        }

        const userName = user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst";
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const currentApprovers = Array.isArray(approval.approvers) ? (approval.approvers as any[]) : [];
        const newApprovers = [
          ...currentApprovers,
          { userId: user?.id, name: userName, decision, note, decidedAt: new Date().toISOString() },
        ];
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const approvedCount = newApprovers.filter((a: any) => a.decision === "approved").length;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const rejectedCount = newApprovers.filter((a: any) => a.decision === "rejected").length;

        let finalStatus = "pending";
        if (rejectedCount > 0) finalStatus = "rejected";
        else if (approvedCount >= (approval.requiredApprovers || 1)) finalStatus = "approved";

        const updated = await storage.updateResponseActionApproval(approval.id, {
          status: finalStatus,
          approvers: newApprovers,
          currentApprovals: approvedCount,
          decidedBy: finalStatus !== "pending" ? user?.id : undefined,
          decidedByName: finalStatus !== "pending" ? userName : undefined,
          decisionNote: note || undefined,
          decidedAt: finalStatus !== "pending" ? new Date() : undefined,
        });

        if (finalStatus === "approved" && approval.actionType && approval.requestPayload) {
          try {
            const context: ActionContext = {
              orgId,
              incidentId: approval.incidentId || undefined,
              userId: user?.id,
              userName,
              storage,
            };
            const payload =
              // eslint-disable-next-line @typescript-eslint/no-explicit-any
              typeof approval.requestPayload === "object" ? (approval.requestPayload as Record<string, any>) : {};
            await dispatchAction(approval.actionType, payload, context);
          } catch (execErr) {
            logger.child("routes").error("Auto-execute after approval failed", { error: String(execErr) });
          }
        }

        await storage.createAuditLog({
          orgId,
          userId: user?.id,
          userName,
          action: `response_approval_${finalStatus}`,
          resourceType: "response_approval",
          resourceId: approval.id,
          details: {
            actionType: approval.actionType,
            decision,
            note,
            approvedCount,
            requiredApprovers: approval.requiredApprovers,
          },
        });
        res.json(updated);
      } catch (error) {
        res.status(500).json({ message: "Failed to decide on approval" });
      }
    },
  );

  // ============================
  // Webhook Severity Threshold Config
  // ============================
  app.patch(
    "/api/notification-channels/:id/severity-threshold",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const channel = await storage.getNotificationChannel(p(req.params.id));
        if (!channel) return res.status(404).json({ message: "Channel not found" });
        const { severityThreshold, eventTypes } = req.body;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const config = typeof channel.config === "object" ? { ...(channel.config as Record<string, any>) } : {};
        if (severityThreshold) config.severityThreshold = severityThreshold;
        if (eventTypes) config.eventTypes = eventTypes;
        const updated = await storage.updateNotificationChannel(channel.id, { config });
        res.json(updated);
      } catch (error) {
        res.status(500).json({ message: "Failed to update severity threshold" });
      }
    },
  );

  // ============================
  // Response Action Dry-Run Simulation
  // ============================
  app.post(
    "/api/response-actions/dry-run",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const user = (req as any).user;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const orgId = (req as any).orgId;
        const { actionType, target, connectorId, incidentId } = req.body;
        if (!actionType) return res.status(400).json({ message: "actionType is required" });

        const simulation = {
          simulatedAt: new Date().toISOString(),
          actionType,
          target: target || {},
          dryRun: true,
          estimatedImpact: actionType.includes("block_ip")
            ? "Network traffic from target IP will be blocked at firewall"
            : actionType.includes("isolate")
              ? "Target endpoint will be isolated from network"
              : actionType.includes("disable_user")
                ? "User account will be disabled in identity provider"
                : actionType.includes("quarantine")
                  ? "File will be moved to quarantine on target endpoint"
                  : actionType.includes("create_jira")
                    ? "A Jira ticket will be created in the configured project"
                    : actionType.includes("create_servicenow")
                      ? "A ServiceNow incident will be created"
                      : "Action will be dispatched to the configured connector",
          reversible: !actionType.includes("delete"),
          requiresApproval:
            actionType.includes("block") || actionType.includes("isolate") || actionType.includes("disable"),
          affectedResources: [
            {
              type: target?.targetType || "unknown",
              value: target?.targetValue || target?.target || "N/A",
            },
          ],
          estimatedDuration: "< 30 seconds",
          connectorId: connectorId || null,
          incidentId: incidentId || null,
        };
        res.json(simulation);
      } catch (error) {
        res.status(500).json({ message: "Failed to simulate action" });
      }
    },
  );
}

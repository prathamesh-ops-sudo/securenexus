import type { Express, Request, Response } from "express";
import { randomBytes } from "crypto";
import { getOrgId, logger, p, storage } from "../shared";
import { isAuthenticated } from "../../auth";
import { requireMinRole, requireOrgId, resolveOrgContext } from "../../rbac";
import { validatePathId } from "../../request-validator";
import { dispatchAction, type ActionContext } from "../../action-dispatcher";

export function registerPlaybooksNotificationsRoutes(app: Express): void {
  // All Response Action Types

  const ALL_RESPONSE_ACTION_TYPES = [
    {
      actionType: "isolate_host",
      label: "Isolate Endpoint",
      category: "endpoint",
      risk: "high",
      description: "Isolate a host from the network to contain a threat",
    },
    {
      actionType: "block_ip",
      label: "Block IP Address",
      category: "network",
      risk: "medium",
      description: "Block an IP address at the firewall or proxy",
    },
    {
      actionType: "block_domain",
      label: "Block Domain",
      category: "network",
      risk: "medium",
      description: "Block a domain via DNS sinkhole or proxy",
    },
    {
      actionType: "disable_user",
      label: "Disable User Account",
      category: "identity",
      risk: "high",
      description: "Disable a user account to prevent unauthorized access",
    },
    {
      actionType: "quarantine_file",
      label: "Quarantine File",
      category: "endpoint",
      risk: "medium",
      description: "Quarantine a suspicious file on the endpoint",
    },
    {
      actionType: "kill_process",
      label: "Kill Process",
      category: "endpoint",
      risk: "medium",
      description: "Terminate a running process on an endpoint",
    },
    {
      actionType: "quarantine_email",
      label: "Quarantine Email",
      category: "email",
      risk: "low",
      description: "Move a suspicious email to quarantine",
    },
    {
      actionType: "create_firewall_rule",
      label: "Create Firewall Rule",
      category: "network",
      risk: "high",
      description: "Create a new firewall rule to block traffic",
    },
    {
      actionType: "update_detection_rule",
      label: "Update Detection Rule",
      category: "detection",
      risk: "low",
      description: "Update or create a detection rule based on findings",
    },
    {
      actionType: "auto_triage",
      label: "Auto Triage",
      category: "workflow",
      risk: "low",
      description: "Automatically triage and categorize the alert or incident",
    },
    {
      actionType: "assign_analyst",
      label: "Assign Analyst",
      category: "workflow",
      risk: "low",
      description: "Assign an analyst to investigate",
    },
    {
      actionType: "change_status",
      label: "Change Status",
      category: "workflow",
      risk: "low",
      description: "Change the status of an incident or alert",
    },
    {
      actionType: "add_tag",
      label: "Add Tag",
      category: "workflow",
      risk: "low",
      description: "Add a tag to the resource for categorization",
    },
    {
      actionType: "escalate",
      label: "Escalate",
      category: "workflow",
      risk: "low",
      description: "Escalate to a higher tier analyst or manager",
    },
    {
      actionType: "create_jira_ticket",
      label: "Create Jira Ticket",
      category: "ticketing",
      risk: "low",
      description: "Create a Jira issue for tracking",
    },
    {
      actionType: "create_servicenow_ticket",
      label: "Create ServiceNow Ticket",
      category: "ticketing",
      risk: "low",
      description: "Create a ServiceNow incident or change request",
    },
    {
      actionType: "notify_slack",
      label: "Notify Slack",
      category: "notification",
      risk: "low",
      description: "Send a notification to a Slack channel",
    },
    {
      actionType: "notify_teams",
      label: "Notify Teams",
      category: "notification",
      risk: "low",
      description: "Send a notification to a Microsoft Teams channel",
    },
    {
      actionType: "notify_email",
      label: "Notify Email",
      category: "notification",
      risk: "low",
      description: "Send an email notification",
    },
    {
      actionType: "notify_pagerduty",
      label: "Notify PagerDuty",
      category: "notification",
      risk: "low",
      description: "Create a PagerDuty incident",
    },
    {
      actionType: "notify_webhook",
      label: "Notify Webhook",
      category: "notification",
      risk: "low",
      description: "Send a webhook notification to an external URL",
    },
  ];

  app.get(
    "/api/playbook-action-types",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (_req: Request, res: Response) => {
      try {
        const categories = Array.from(new Set(ALL_RESPONSE_ACTION_TYPES.map((a) => a.category)));
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const byCategory: Record<string, any[]> = {};
        for (const cat of categories) {
          byCategory[cat] = ALL_RESPONSE_ACTION_TYPES.filter((a) => a.category === cat);
        }
        res.json({
          actionTypes: ALL_RESPONSE_ACTION_TYPES,
          categories,
          byCategory,
          totalCount: ALL_RESPONSE_ACTION_TYPES.length,
        });
      } catch (error) {
        logger.child("routes").error("Action types error", { error: String(error) });
        res.status(500).json({ message: "Failed to fetch action types" });
      }
    },
  );

  // Notification Channels

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const notificationTemplateStore = new Map<string, any[]>();

  app.get(
    "/api/playbooks/:id/notification-config",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    validatePathId("id"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const pb = await storage.getPlaybook(p(req.params.id));
        if (!pb || pb.orgId !== orgId) {
          return res.status(404).json({ message: "Playbook not found" });
        }

        const key = `${orgId}:${pb.id}`;
        const templates = notificationTemplateStore.get(key) || [];

        const channels = [
          {
            channel: "email",
            label: "Email",
            variables: ["{{incident_id}}", "{{severity}}", "{{title}}", "{{analyst}}", "{{timestamp}}", "{{url}}"],
          },
          {
            channel: "slack",
            label: "Slack",
            variables: ["{{incident_id}}", "{{severity}}", "{{title}}", "{{channel}}", "{{timestamp}}"],
          },
          {
            channel: "teams",
            label: "Microsoft Teams",
            variables: ["{{incident_id}}", "{{severity}}", "{{title}}", "{{timestamp}}"],
          },
          {
            channel: "pagerduty",
            label: "PagerDuty",
            variables: ["{{incident_id}}", "{{severity}}", "{{title}}", "{{urgency}}"],
          },
          {
            channel: "webhook",
            label: "Webhook",
            variables: ["{{incident_id}}", "{{severity}}", "{{title}}", "{{payload}}"],
          },
        ];

        res.json({
          playbookId: pb.id,
          playbookName: pb.name,
          availableChannels: channels,
          templates,
        });
      } catch (error) {
        logger.child("routes").error("Notification config error", { error: String(error) });
        res.status(500).json({ message: "Failed to fetch notification config" });
      }
    },
  );

  app.post(
    "/api/playbooks/:id/notification-templates",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    validatePathId("id"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const pb = await storage.getPlaybook(p(req.params.id));
        if (!pb || pb.orgId !== orgId) {
          return res.status(404).json({ message: "Playbook not found" });
        }

        const { channel, subject, body, recipients, webhookUrl, urgency } = req.body;
        if (!channel || !body) {
          return res.status(400).json({ message: "channel and body are required" });
        }

        const validChannels = ["email", "slack", "teams", "pagerduty", "webhook"];
        if (!validChannels.includes(channel)) {
          return res.status(400).json({ message: `Invalid channel. Must be one of: ${validChannels.join(", ")}` });
        }

        const key = `${orgId}:${pb.id}`;
        if (!notificationTemplateStore.has(key)) notificationTemplateStore.set(key, []);

        const template = {
          id: `tmpl-${Date.now()}-${randomBytes(4).toString("hex")}`,
          channel,
          subject: subject || null,
          body,
          recipients: recipients || null,
          webhookUrl: webhookUrl || null,
          urgency: urgency || "high",
          createdAt: new Date().toISOString(),
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          createdBy: (req as any).user?.firstName
            ? // eslint-disable-next-line @typescript-eslint/no-explicit-any
              `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
            : "Analyst",
        };

        notificationTemplateStore.get(key)!.push(template);

        await storage.createAuditLog({
          orgId,
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          userId: (req as any).user?.id,
          userName: template.createdBy,
          action: "playbook_notification_template_created",
          resourceType: "playbook",
          resourceId: pb.id,
          details: { templateId: template.id, channel },
        });

        res.status(201).json(template);
      } catch (error) {
        logger.child("routes").error("Notification template error", { error: String(error) });
        res.status(500).json({ message: "Failed to create notification template" });
      }
    },
  );

  app.delete(
    "/api/playbooks/:id/notification-templates/:templateId",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    validatePathId("id"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const pb = await storage.getPlaybook(p(req.params.id));
        if (!pb || pb.orgId !== orgId) {
          return res.status(404).json({ message: "Playbook not found" });
        }

        const key = `${orgId}:${pb.id}`;
        const templates = notificationTemplateStore.get(key) || [];
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const idx = templates.findIndex((t: any) => t.id === req.params.templateId);
        if (idx < 0) {
          return res.status(404).json({ message: "Template not found" });
        }

        templates.splice(idx, 1);
        res.json({ success: true });
      } catch (error) {
        logger.child("routes").error("Notification template delete error", { error: String(error) });
        res.status(500).json({ message: "Failed to delete notification template" });
      }
    },
  );

  app.post(
    "/api/playbooks/:id/send-notification",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    validatePathId("id"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const pb = await storage.getPlaybook(p(req.params.id));
        if (!pb || pb.orgId !== orgId) {
          return res.status(404).json({ message: "Playbook not found" });
        }

        const { templateId, variables } = req.body;
        const key = `${orgId}:${pb.id}`;
        const templates = notificationTemplateStore.get(key) || [];
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const template = templates.find((t: any) => t.id === templateId);

        if (!template) {
          return res.status(404).json({ message: "Template not found" });
        }

        let resolvedBody = template.body;
        let resolvedSubject = template.subject || "";
        const vars = variables || {};
        for (const [varName, varValue] of Object.entries(vars)) {
          const placeholder = `{{${varName}}}`;
          resolvedBody = resolvedBody.replace(new RegExp(placeholder.replace(/[{}]/g, "\\$&"), "g"), String(varValue));
          resolvedSubject = resolvedSubject.replace(
            new RegExp(placeholder.replace(/[{}]/g, "\\$&"), "g"),
            String(varValue),
          );
        }

        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const user = (req as any).user;
        const userName = user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst";
        const context: ActionContext = {
          orgId,
          userId: user?.id,
          userName,
          storage,
        };

        const actionType = `notify_${template.channel}`;
        const config: Record<string, string> = {
          message: resolvedBody,
          subject: resolvedSubject,
        };
        if (template.recipients) config.recipient = template.recipients;
        if (template.webhookUrl) config.webhookUrl = template.webhookUrl;
        if (template.urgency) config.urgency = template.urgency;

        const result = await dispatchAction(actionType, config, context);

        await storage.createAuditLog({
          orgId,
          userId: user?.id,
          userName,
          action: "playbook_notification_sent",
          resourceType: "playbook",
          resourceId: pb.id,
          details: { templateId, channel: template.channel, result: result.status },
        });

        res.json({ templateId, channel: template.channel, result, resolvedBody, resolvedSubject });
      } catch (error) {
        logger.child("routes").error("Send notification error", { error: String(error) });
        res.status(500).json({ message: "Failed to send notification" });
      }
    },
  );

  // Change Management Integration

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const changeTicketStore = new Map<string, any[]>();

  app.get(
    "/api/playbook-change-tickets",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const key = `org:${orgId}`;
        const tickets = changeTicketStore.get(key) || [];
        const { playbookId, status } = req.query;
        let filtered = tickets;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        if (playbookId) filtered = filtered.filter((t: any) => t.playbookId === playbookId);
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        if (status) filtered = filtered.filter((t: any) => t.status === status);
        res.json({ tickets: filtered, total: filtered.length });
      } catch (error) {
        logger.child("routes").error("Change tickets error", { error: String(error) });
        res.status(500).json({ message: "Failed to fetch change tickets" });
      }
    },
  );

  app.post(
    "/api/playbook-change-tickets",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const {
          playbookId,
          executionId,
          changeType,
          summary,
          description,
          impactAssessment,
          rollbackPlan,
          requiresApproval,
        } = req.body;

        if (!playbookId || !changeType || !summary) {
          return res.status(400).json({ message: "playbookId, changeType, and summary are required" });
        }

        const pb = await storage.getPlaybook(p(playbookId));
        if (!pb || pb.orgId !== orgId) {
          return res.status(404).json({ message: "Playbook not found" });
        }

        const validChangeTypes = [
          "firewall_rule",
          "account_disable",
          "network_block",
          "endpoint_isolation",
          "detection_update",
          "configuration_change",
        ];
        if (!validChangeTypes.includes(changeType)) {
          return res
            .status(400)
            .json({ message: `Invalid changeType. Must be one of: ${validChangeTypes.join(", ")}` });
        }

        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const user = (req as any).user;
        const userName = user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst";

        const ticket = {
          id: `CHG-${Date.now().toString(36).toUpperCase()}-${randomBytes(3).toString("hex").toUpperCase()}`,
          orgId,
          playbookId,
          playbookName: pb.name,
          executionId: executionId || null,
          changeType,
          summary,
          description: description || null,
          impactAssessment: impactAssessment || "Low impact — automated security response",
          rollbackPlan: rollbackPlan || "Revert via playbook rollback mechanism",
          requiresApproval: requiresApproval !== false,
          status: requiresApproval !== false ? "pending_approval" : "approved",
          requestedBy: userName,
          requestedAt: new Date().toISOString(),
          approvedBy: requiresApproval !== false ? null : "auto-approved",
          approvedAt: requiresApproval !== false ? null : new Date().toISOString(),
          implementedAt: null,
          closedAt: null,
          changeLog: [
            {
              action: "created",
              actor: userName,
              timestamp: new Date().toISOString(),
              details: { changeType, summary },
            },
          ],
        };

        const key = `org:${orgId}`;
        if (!changeTicketStore.has(key)) changeTicketStore.set(key, []);
        changeTicketStore.get(key)!.push(ticket);

        await storage.createAuditLog({
          orgId,
          userId: user?.id,
          userName,
          action: "change_ticket_created",
          resourceType: "change_ticket",
          resourceId: ticket.id,
          details: { playbookId, changeType, summary, requiresApproval: ticket.requiresApproval },
        });

        res.status(201).json(ticket);
      } catch (error) {
        logger.child("routes").error("Change ticket create error", { error: String(error) });
        res.status(500).json({ message: "Failed to create change ticket" });
      }
    },
  );

  app.post(
    "/api/playbook-change-tickets/:ticketId/approve",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const key = `org:${orgId}`;
        const tickets = changeTicketStore.get(key) || [];
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const ticket = tickets.find((t: any) => t.id === req.params.ticketId);

        if (!ticket) {
          return res.status(404).json({ message: "Change ticket not found" });
        }
        if (ticket.status !== "pending_approval") {
          return res.status(400).json({ message: `Ticket is already ${ticket.status}` });
        }

        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const user = (req as any).user;
        const userName = user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Admin";
        const { decision, note } = req.body;

        if (!decision || !["approved", "rejected"].includes(decision)) {
          return res.status(400).json({ message: "decision must be 'approved' or 'rejected'" });
        }

        ticket.status = decision;
        ticket.approvedBy = userName;
        ticket.approvedAt = new Date().toISOString();
        ticket.changeLog.push({
          action: decision,
          actor: userName,
          timestamp: new Date().toISOString(),
          details: { note: note || null },
        });

        await storage.createAuditLog({
          orgId,
          userId: user?.id,
          userName,
          action: `change_ticket_${decision}`,
          resourceType: "change_ticket",
          resourceId: ticket.id,
          details: { decision, note },
        });

        res.json(ticket);
      } catch (error) {
        logger.child("routes").error("Change ticket approve error", { error: String(error) });
        res.status(500).json({ message: "Failed to approve change ticket" });
      }
    },
  );

  app.post(
    "/api/playbook-change-tickets/:ticketId/implement",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const key = `org:${orgId}`;
        const tickets = changeTicketStore.get(key) || [];
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const ticket = tickets.find((t: any) => t.id === req.params.ticketId);

        if (!ticket) {
          return res.status(404).json({ message: "Change ticket not found" });
        }
        if (ticket.status !== "approved") {
          return res.status(400).json({ message: "Ticket must be approved before implementation" });
        }

        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const user = (req as any).user;
        const userName = user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst";

        ticket.status = "implemented";
        ticket.implementedAt = new Date().toISOString();
        ticket.changeLog.push({
          action: "implemented",
          actor: userName,
          timestamp: new Date().toISOString(),
          details: req.body.notes ? { notes: req.body.notes } : {},
        });

        await storage.createAuditLog({
          orgId,
          userId: user?.id,
          userName,
          action: "change_ticket_implemented",
          resourceType: "change_ticket",
          resourceId: ticket.id,
        });

        res.json(ticket);
      } catch (error) {
        logger.child("routes").error("Change ticket implement error", { error: String(error) });
        res.status(500).json({ message: "Failed to implement change ticket" });
      }
    },
  );

  app.post(
    "/api/playbook-change-tickets/:ticketId/close",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const key = `org:${orgId}`;
        const tickets = changeTicketStore.get(key) || [];
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const ticket = tickets.find((t: any) => t.id === req.params.ticketId);

        if (!ticket) {
          return res.status(404).json({ message: "Change ticket not found" });
        }

        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const user = (req as any).user;
        const userName = user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst";

        ticket.status = "closed";
        ticket.closedAt = new Date().toISOString();
        ticket.changeLog.push({
          action: "closed",
          actor: userName,
          timestamp: new Date().toISOString(),
          details: req.body.resolution ? { resolution: req.body.resolution } : {},
        });

        res.json(ticket);
      } catch (error) {
        logger.child("routes").error("Change ticket close error", { error: String(error) });
        res.status(500).json({ message: "Failed to close change ticket" });
      }
    },
  );
}

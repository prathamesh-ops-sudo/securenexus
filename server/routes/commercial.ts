import type { Express, Request, Response } from "express";
import { p, storage } from "./shared";
import { isAuthenticated } from "../auth";
import { requireMinRole, requireOrgId, resolveOrgContext } from "../rbac";

export function registerCommercialRoutes(app: Express): void {
  // ============================
  // Usage Metering Dashboard
  // ============================
  app.get("/api/usage-metering", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = (req as any).orgId;
      const now = new Date();
      const cycleStart = new Date(now.getFullYear(), now.getMonth(), 1);
      const cycleEnd = new Date(now.getFullYear(), now.getMonth() + 1, 0, 23, 59, 59);

      const [planLimit, connectorList, aiFeedbackCount, automationRunCount, ingestionStats] = await Promise.all([
        storage.getOrgPlanLimit(orgId),
        storage.getConnectors(orgId),
        storage.countAiFeedbackByOrg(orgId),
        storage.countPlaybookExecutionsByOrg(orgId),
        storage.getIngestionStats(orgId),
      ]);

      const plan = planLimit || {
        planTier: "free", eventsPerMonth: 10000, maxConnectors: 3,
        aiTokensPerMonth: 5000, automationRunsPerMonth: 100,
        apiCallsPerMonth: 10000, storageGb: 5,
        softThresholdPct: 80, hardThresholdPct: 95,
      };

      const eventsUsed = ingestionStats.totalIngested || 0;
      const connectorsActive = connectorList.filter((c: any) => c.enabled !== false).length;
      const aiTokensUsed = aiFeedbackCount * 150;
      const automationRuns = automationRunCount;

      const metrics = [
        { type: "events_ingested", label: "Events Ingested", current: eventsUsed, limit: plan.eventsPerMonth, unit: "events" },
        { type: "connectors_active", label: "Active Connectors", current: connectorsActive, limit: plan.maxConnectors, unit: "connectors" },
        { type: "ai_tokens_used", label: "AI Tokens Used", current: aiTokensUsed, limit: plan.aiTokensPerMonth, unit: "tokens" },
        { type: "automation_runs", label: "Automation Runs", current: automationRuns, limit: plan.automationRunsPerMonth, unit: "runs" },
      ];

      const metricsWithPct = metrics.map(m => ({
        ...m,
        pctUsed: m.limit > 0 ? Math.round((m.current / m.limit) * 100) : 0,
        softThreshold: plan.softThresholdPct,
        hardThreshold: plan.hardThresholdPct,
        status: m.limit > 0 && (m.current / m.limit) * 100 >= plan.hardThresholdPct ? "critical" :
                m.limit > 0 && (m.current / m.limit) * 100 >= plan.softThresholdPct ? "warning" : "ok",
      }));

      res.json({
        planTier: plan.planTier,
        billingCycleStart: cycleStart.toISOString(),
        billingCycleEnd: cycleEnd.toISOString(),
        metrics: metricsWithPct,
        warnings: metricsWithPct.filter(m => m.status !== "ok"),
      });
    } catch (error) { res.status(500).json({ message: "Failed to fetch usage metering" }); }
  });

  app.get("/api/usage-metering/history", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = (req as any).orgId;
      const metricType = req.query.metricType as string | undefined;
      const snapshots = await storage.getUsageMeterSnapshots(orgId, metricType);
      res.json(snapshots);
    } catch (error) { res.status(500).json({ message: "Failed to fetch usage history" }); }
  });

  // ============================
  // Plan Limits Management
  // ============================
  app.get("/api/plan-limits", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = (req as any).orgId;
      const plan = await storage.getOrgPlanLimit(orgId);
      if (!plan) {
        return res.json({
          planTier: "free",
          eventsPerMonth: 10000, maxConnectors: 3, aiTokensPerMonth: 5000,
          automationRunsPerMonth: 100, apiCallsPerMonth: 10000, storageGb: 5,
          softThresholdPct: 80, hardThresholdPct: 95, overageAllowed: false,
        });
      }
      res.json(plan);
    } catch (error) { res.status(500).json({ message: "Failed to fetch plan limits" }); }
  });

  app.put("/api/plan-limits", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (req, res) => {
    try {
      const orgId = (req as any).orgId;
      const user = (req as any).user;
      const plan = await storage.upsertOrgPlanLimit({ ...req.body, orgId });
      await storage.createAuditLog({
        orgId, userId: user?.id,
        userName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Admin",
        action: "plan_limits_updated", resourceType: "plan_limits", resourceId: plan.id,
        details: { planTier: plan.planTier },
      });
      res.json(plan);
    } catch (error) { res.status(500).json({ message: "Failed to update plan limits" }); }
  });

  // ============================
  // Onboarding Checklist
  // ============================
  app.get("/api/onboarding-checklist", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = (req as any).orgId;
      let steps = await storage.getOnboardingProgress(orgId);

      if (steps.length === 0) {
        const defaultSteps = [
          { stepKey: "first_connector", stepLabel: "Connect Your First Data Source", stepDescription: "Set up a connector to start ingesting security events", category: "setup", sortOrder: 1, targetUrl: "/connectors" },
          { stepKey: "first_alert_review", stepLabel: "Review Your First Alert", stepDescription: "Triage an incoming alert and set its status", category: "setup", sortOrder: 2, targetUrl: "/alerts" },
          { stepKey: "first_incident", stepLabel: "Create Your First Incident", stepDescription: "Escalate an alert or create a new incident for investigation", category: "setup", sortOrder: 3, targetUrl: "/incidents" },
          { stepKey: "first_playbook", stepLabel: "Run Your First Playbook", stepDescription: "Execute an automated response playbook", category: "automation", sortOrder: 4, targetUrl: "/playbooks" },
          { stepKey: "invite_team", stepLabel: "Invite Your Team", stepDescription: "Add team members to collaborate on investigations", category: "team", sortOrder: 5, targetUrl: "/team" },
          { stepKey: "configure_notifications", stepLabel: "Set Up Notifications", stepDescription: "Configure alert notification channels (email, Slack, webhook)", category: "integrations", sortOrder: 6, targetUrl: "/integrations" },
          { stepKey: "enable_ai", stepLabel: "Enable AI Triage", stepDescription: "Let the AI engine auto-classify and prioritize alerts", category: "ai", sortOrder: 7, targetUrl: "/ai-engine" },
          { stepKey: "setup_compliance", stepLabel: "Configure Compliance Policies", stepDescription: "Set data retention, DSAR workflows, and audit settings", category: "governance", sortOrder: 8, targetUrl: "/compliance" },
        ];

        for (const step of defaultSteps) {
          await storage.upsertOnboardingStep({ orgId, ...step });
        }
        steps = await storage.getOnboardingProgress(orgId);
      }

      const [connectors, alertsList, incidentsList, playbookExecCount] = await Promise.all([
        storage.getConnectors(orgId),
        storage.getAlerts(orgId),
        storage.getIncidents(orgId),
        storage.countPlaybookExecutionsByOrg(orgId),
      ]);

      const autoComplete: Record<string, boolean> = {
        first_connector: connectors.length > 0,
        first_alert_review: alertsList.some((a: any) => a.status !== "new"),
        first_incident: incidentsList.length > 0,
        first_playbook: playbookExecCount > 0,
      };

      for (const [key, done] of Object.entries(autoComplete)) {
        const step = steps.find(s => s.stepKey === key);
        if (done && step && !step.isCompleted) {
          await storage.completeOnboardingStep(orgId, key, "system");
        }
      }

      steps = await storage.getOnboardingProgress(orgId);
      const completed = steps.filter(s => s.isCompleted).length;

      res.json({
        steps,
        completedCount: completed,
        totalSteps: steps.length,
        pctComplete: steps.length > 0 ? Math.round((completed / steps.length) * 100) : 0,
        allDone: completed === steps.length,
      });
    } catch (error) { res.status(500).json({ message: "Failed to fetch onboarding checklist" }); }
  });

  app.post("/api/onboarding-checklist/:stepKey/complete", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = (req as any).orgId;
      const user = (req as any).user;
      const updated = await storage.completeOnboardingStep(orgId, p(req.params.stepKey), user?.id);
      if (!updated) return res.status(404).json({ message: "Onboarding step not found" });
      res.json(updated);
    } catch (error) { res.status(500).json({ message: "Failed to complete onboarding step" }); }
  });

  app.post("/api/onboarding-checklist/dismiss", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = (req as any).orgId;
      const steps = await storage.getOnboardingProgress(orgId);
      for (const step of steps) {
        if (!step.isCompleted) {
          await storage.completeOnboardingStep(orgId, step.stepKey, "dismissed");
        }
      }
      res.json({ success: true });
    } catch (error) { res.status(500).json({ message: "Failed to dismiss onboarding" }); }
  });

  // ============================
  // Workspace Templates
  // ============================
  app.get("/api/workspace-templates", isAuthenticated, async (req, res) => {
    try {
      let templates = await storage.getWorkspaceTemplates();

      if (templates.length === 0) {
        const defaults = [
          {
            name: "SMB SOC", slug: "smb-soc", category: "small_business", icon: "Shield",
            description: "Streamlined security operations for small and medium businesses. Includes essential connectors, basic playbooks, and email notifications.",
            config: { maxAnalysts: 5, defaultSeverityFilter: "medium", autoTriageEnabled: true },
            connectorsConfig: [
              { type: "siem", name: "Primary SIEM", description: "Connect your SIEM for alert ingestion" },
              { type: "email_gateway", name: "Email Gateway", description: "Monitor email threats" },
            ],
            playbooksConfig: [
              { name: "Phishing Response", trigger: "alert.category=phishing", steps: ["isolate_email", "block_sender", "notify_user"] },
              { name: "Malware Alert", trigger: "alert.category=malware", steps: ["quarantine_file", "scan_endpoint", "create_incident"] },
            ],
            notificationConfig: [{ type: "email", name: "SOC Team Email" }],
            complianceConfig: { alertRetentionDays: 180, incidentRetentionDays: 365 },
          },
          {
            name: "Enterprise SOC", slug: "enterprise-soc", category: "enterprise", icon: "Building",
            description: "Full-scale security operations center for large organizations. Multi-tier RBAC, advanced playbooks, SIEM/SOAR/TIP integrations, and compliance automation.",
            config: { maxAnalysts: 50, defaultSeverityFilter: "low", autoTriageEnabled: true, mlCorrelation: true },
            connectorsConfig: [
              { type: "siem", name: "Enterprise SIEM", description: "Primary SIEM integration" },
              { type: "edr", name: "EDR Platform", description: "Endpoint detection and response" },
              { type: "firewall", name: "Next-Gen Firewall", description: "Network perimeter monitoring" },
              { type: "identity", name: "Identity Provider", description: "SSO and identity events" },
              { type: "cloud", name: "Cloud Security", description: "AWS/Azure/GCP monitoring" },
            ],
            playbooksConfig: [
              { name: "Incident Escalation", trigger: "alert.severity=critical", steps: ["create_incident", "page_oncall", "start_investigation"] },
              { name: "Lateral Movement", trigger: "alert.tactic=lateral_movement", steps: ["isolate_host", "block_ip", "forensic_snapshot"] },
              { name: "Data Exfiltration", trigger: "alert.tactic=exfiltration", steps: ["block_destination", "revoke_tokens", "legal_hold"] },
            ],
            notificationConfig: [
              { type: "slack", name: "SOC Slack Channel" },
              { type: "pagerduty", name: "PagerDuty Escalation" },
              { type: "email", name: "Management Reports" },
            ],
            complianceConfig: { alertRetentionDays: 730, incidentRetentionDays: 2555, auditLogRetentionDays: 2555 },
          },
          {
            name: "Cloud-First", slug: "cloud-first", category: "cloud_native", icon: "Cloud",
            description: "Designed for cloud-native organizations. Focus on CSPM, container security, IAM monitoring, and serverless threat detection.",
            config: { maxAnalysts: 20, defaultSeverityFilter: "low", autoTriageEnabled: true, cspmEnabled: true },
            connectorsConfig: [
              { type: "aws_cloudtrail", name: "AWS CloudTrail", description: "AWS API audit logs" },
              { type: "aws_guardduty", name: "AWS GuardDuty", description: "AWS threat detection" },
              { type: "azure_sentinel", name: "Azure Sentinel", description: "Azure security events" },
              { type: "gcp_scc", name: "GCP Security Command Center", description: "GCP findings" },
              { type: "kubernetes", name: "Kubernetes Audit", description: "K8s audit logs" },
            ],
            playbooksConfig: [
              { name: "Exposed S3 Bucket", trigger: "cspm.finding=public_bucket", steps: ["restrict_bucket_acl", "notify_owner", "create_incident"] },
              { name: "IAM Key Compromise", trigger: "alert.category=credential_compromise", steps: ["revoke_key", "rotate_secrets", "audit_usage"] },
              { name: "Container Escape", trigger: "alert.category=container_escape", steps: ["kill_pod", "cordon_node", "forensic_snapshot"] },
            ],
            notificationConfig: [
              { type: "slack", name: "Cloud Security Channel" },
              { type: "webhook", name: "PagerDuty Webhook" },
            ],
            complianceConfig: { alertRetentionDays: 365, incidentRetentionDays: 730, cspmScanInterval: "daily" },
          },
        ];

        for (const t of defaults) {
          await storage.createWorkspaceTemplate(t);
        }
        templates = await storage.getWorkspaceTemplates();
      }

      res.json(templates);
    } catch (error) { res.status(500).json({ message: "Failed to fetch workspace templates" }); }
  });

  app.get("/api/workspace-templates/:id", isAuthenticated, async (req, res) => {
    try {
      const template = await storage.getWorkspaceTemplate(p(req.params.id));
      if (!template) return res.status(404).json({ message: "Template not found" });
      res.json(template);
    } catch (error) { res.status(500).json({ message: "Failed to fetch template" }); }
  });

  app.post("/api/workspace-templates/:id/apply", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (req, res) => {
    try {
      const orgId = (req as any).orgId;
      const user = (req as any).user;
      const template = await storage.getWorkspaceTemplate(p(req.params.id));
      if (!template) return res.status(404).json({ message: "Template not found" });

      const applied: string[] = [];
      const config = template.config as Record<string, any>;
      const connectorsConfig = (template.connectorsConfig || []) as Array<Record<string, any>>;
      const playbooksConfig = (template.playbooksConfig || []) as Array<Record<string, any>>;
      const notificationConfig = (template.notificationConfig || []) as Array<Record<string, any>>;
      const complianceConfig = (template.complianceConfig || {}) as Record<string, any>;

      for (const conn of connectorsConfig) {
        try {
          await storage.createConnector({
            orgId, name: conn.name, type: conn.type,
            authType: conn.authType || "none",
            config: { description: conn.description },
            status: "inactive",
          });
          applied.push(`Connector: ${conn.name}`);
        } catch { /* skip duplicates */ }
      }

      for (const pb of playbooksConfig) {
        try {
          await storage.createPlaybook({
            name: pb.name, orgId,
            trigger: pb.trigger || "manual",
            actions: pb.steps ? pb.steps.map((s: string, i: number) => ({ id: `step-${i}`, action: s, order: i })) : [],
            status: "inactive",
          });
          applied.push(`Playbook: ${pb.name}`);
        } catch { /* skip duplicates */ }
      }

      if (complianceConfig.alertRetentionDays) {
        try {
          await storage.upsertCompliancePolicy({
            orgId,
            alertRetentionDays: complianceConfig.alertRetentionDays,
            incidentRetentionDays: complianceConfig.incidentRetentionDays || 730,
          });
          applied.push("Compliance policy configured");
        } catch { /* skip */ }
      }

      await storage.createAuditLog({
        orgId, userId: user?.id,
        userName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Admin",
        action: "workspace_template_applied", resourceType: "workspace_template", resourceId: template.id,
        details: { templateName: template.name, appliedItems: applied },
      });

      res.json({ success: true, templateName: template.name, applied });
    } catch (error) { res.status(500).json({ message: "Failed to apply workspace template" }); }
  });

}

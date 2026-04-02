import type { Express, Request, Response } from "express";
import { randomBytes } from "crypto";
import { getOrgId, logger, p, storage } from "../shared";
import { isAuthenticated } from "../../auth";
import { requireMinRole, requireOrgId, resolveOrgContext } from "../../rbac";
import { validatePathId } from "../../request-validator";
import { extractNodes } from "./utils";

export function registerPlaybooksSchedulingRoutes(app: Express): void {
  // Runbook Execution Tracking

  const executionTracking = new Map<
    string,
    {
      executionId: string;
      playbookId: string;
      steps: Array<{
        nodeId: string;
        label: string;
        type: string;
        status: "pending" | "in_progress" | "completed" | "skipped" | "paused";
        startedAt: string | null;
        completedAt: string | null;
        timeSpentMs: number;
        notes: string;
        checklistItems: Array<{ id: string; label: string; checked: boolean }>;
      }>;
      currentStepIndex: number;
      status: "running" | "paused" | "completed" | "abandoned";
      startedAt: string;
      pausedAt: string | null;
      totalPausedMs: number;
      completedAt: string | null;
      analystId: string | null;
      analystName: string;
    }
  >();

  app.get(
    "/api/playbooks/:id/execution-tracking",
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

        const executionId = req.query.executionId as string;
        if (executionId) {
          const tracking = executionTracking.get(executionId);
          if (!tracking || tracking.playbookId !== pb.id) {
            return res.status(404).json({ message: "Execution tracking not found" });
          }
          const elapsed =
            tracking.status === "running"
              ? Date.now() - new Date(tracking.startedAt).getTime() - tracking.totalPausedMs
              : tracking.completedAt
                ? new Date(tracking.completedAt).getTime() -
                  new Date(tracking.startedAt).getTime() -
                  tracking.totalPausedMs
                : 0;
          const completedSteps = tracking.steps.filter((s) => s.status === "completed").length;
          const progressPercent =
            tracking.steps.length > 0 ? Math.round((completedSteps / tracking.steps.length) * 100) : 0;

          return res.json({
            ...tracking,
            elapsedMs: elapsed,
            progressPercent,
            completedSteps,
            totalSteps: tracking.steps.length,
          });
        }

        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const trackings: any[] = [];
        executionTracking.forEach((t, key) => {
          if (t.playbookId === pb.id) {
            const completedSteps = t.steps.filter((s) => s.status === "completed").length;
            trackings.push({
              executionId: key,
              status: t.status,
              analystName: t.analystName,
              startedAt: t.startedAt,
              progressPercent: t.steps.length > 0 ? Math.round((completedSteps / t.steps.length) * 100) : 0,
              completedSteps,
              totalSteps: t.steps.length,
            });
          }
        });
        res.json(trackings);
      } catch (error) {
        logger.child("routes").error("Execution tracking error", { error: String(error) });
        res.status(500).json({ message: "Failed to fetch execution tracking" });
      }
    },
  );

  app.post(
    "/api/playbooks/:id/execution-tracking/start",
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

        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const user = (req as any).user;
        const userName = user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst";
        const actionsArr = Array.isArray(pb.actions) ? pb.actions : [];
        const nodes = extractNodes(actionsArr);

        const executionId = `track-${Date.now()}-${randomBytes(4).toString("hex")}`;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const steps = nodes.map((node: any, idx: number) => ({
          nodeId: node.id || `step-${idx}`,
          label: node.data?.label || node.type || `Step ${idx + 1}`,
          type: node.type || "action",
          status: idx === 0 ? ("in_progress" as const) : ("pending" as const),
          startedAt: idx === 0 ? new Date().toISOString() : null,
          completedAt: null,
          timeSpentMs: 0,
          notes: "",
          checklistItems: [],
        }));

        const tracking = {
          executionId,
          playbookId: String(pb.id),
          steps,
          currentStepIndex: 0,
          status: "running" as const,
          startedAt: new Date().toISOString(),
          pausedAt: null,
          totalPausedMs: 0,
          completedAt: null,
          analystId: user?.id || null,
          analystName: userName,
        };

        executionTracking.set(executionId, tracking);

        await storage.createAuditLog({
          orgId,
          userId: user?.id,
          userName,
          action: "runbook_tracking_started",
          resourceType: "playbook",
          resourceId: pb.id,
          details: { executionId, stepsCount: steps.length },
        });

        res.status(201).json({
          executionId,
          playbookId: pb.id,
          playbookName: pb.name,
          totalSteps: steps.length,
          status: "running",
        });
      } catch (error) {
        logger.child("routes").error("Start tracking error", { error: String(error) });
        res.status(500).json({ message: "Failed to start execution tracking" });
      }
    },
  );

  app.post(
    "/api/playbooks/:id/execution-tracking/:executionId/step-action",
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

        const tracking = executionTracking.get(req.params.executionId as string);
        if (!tracking || tracking.playbookId !== pb.id) {
          return res.status(404).json({ message: "Execution tracking not found" });
        }

        const { action, stepIndex, notes } = req.body;
        const idx = typeof stepIndex === "number" ? stepIndex : tracking.currentStepIndex;
        const step = tracking.steps[idx];
        if (!step) {
          return res.status(400).json({ message: "Invalid step index" });
        }

        switch (action) {
          case "complete": {
            step.status = "completed";
            step.completedAt = new Date().toISOString();
            if (step.startedAt) {
              step.timeSpentMs = new Date(step.completedAt).getTime() - new Date(step.startedAt).getTime();
            }
            if (notes) step.notes = notes;
            if (idx + 1 < tracking.steps.length) {
              tracking.currentStepIndex = idx + 1;
              tracking.steps[idx + 1].status = "in_progress";
              tracking.steps[idx + 1].startedAt = new Date().toISOString();
            } else {
              tracking.status = "completed";
              tracking.completedAt = new Date().toISOString();
            }
            break;
          }
          case "skip": {
            step.status = "skipped";
            step.completedAt = new Date().toISOString();
            if (notes) step.notes = notes;
            if (idx + 1 < tracking.steps.length) {
              tracking.currentStepIndex = idx + 1;
              tracking.steps[idx + 1].status = "in_progress";
              tracking.steps[idx + 1].startedAt = new Date().toISOString();
            } else {
              tracking.status = "completed";
              tracking.completedAt = new Date().toISOString();
            }
            break;
          }
          case "pause": {
            if (tracking.status === "running") {
              tracking.status = "paused";
              tracking.pausedAt = new Date().toISOString();
              step.status = "paused";
            }
            break;
          }
          case "resume": {
            if (tracking.status === "paused" && tracking.pausedAt) {
              tracking.totalPausedMs += Date.now() - new Date(tracking.pausedAt).getTime();
              tracking.status = "running";
              tracking.pausedAt = null;
              step.status = "in_progress";
            }
            break;
          }
          case "add_note": {
            if (notes) step.notes = notes;
            break;
          }
          default:
            return res.status(400).json({ message: "Invalid action. Use: complete, skip, pause, resume, add_note" });
        }

        const completedSteps = tracking.steps.filter((s) => s.status === "completed").length;
        const progressPercent =
          tracking.steps.length > 0 ? Math.round((completedSteps / tracking.steps.length) * 100) : 0;

        res.json({
          executionId: tracking.executionId,
          status: tracking.status,
          currentStepIndex: tracking.currentStepIndex,
          progressPercent,
          completedSteps,
          totalSteps: tracking.steps.length,
          step: tracking.steps[idx],
        });
      } catch (error) {
        logger.child("routes").error("Step action error", { error: String(error) });
        res.status(500).json({ message: "Failed to perform step action" });
      }
    },
  );

  // Runbook Step Checklists

  app.post(
    "/api/playbooks/:id/execution-tracking/:executionId/checklist",
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

        const tracking = executionTracking.get(req.params.executionId as string);
        if (!tracking || tracking.playbookId !== pb.id) {
          return res.status(404).json({ message: "Execution tracking not found" });
        }

        const { stepIndex, checklistItems, notes } = req.body;
        const idx = typeof stepIndex === "number" ? stepIndex : tracking.currentStepIndex;
        const step = tracking.steps[idx];
        if (!step) {
          return res.status(400).json({ message: "Invalid step index" });
        }

        if (Array.isArray(checklistItems)) {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          step.checklistItems = checklistItems.map((item: any, i: number) => ({
            id: item.id || `cl-${i}`,
            label: item.label || `Item ${i + 1}`,
            checked: !!item.checked,
          }));
        }

        if (typeof notes === "string") {
          step.notes = notes;
        }

        const checkedCount = step.checklistItems.filter((c) => c.checked).length;
        const totalChecklist = step.checklistItems.length;

        res.json({
          stepIndex: idx,
          step,
          checklistProgress: totalChecklist > 0 ? Math.round((checkedCount / totalChecklist) * 100) : 100,
        });
      } catch (error) {
        logger.child("routes").error("Checklist update error", { error: String(error) });
        res.status(500).json({ message: "Failed to update checklist" });
      }
    },
  );

  // Runbook PDF Export

  app.get(
    "/api/playbooks/:id/export-pdf",
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

        const actionsArr = Array.isArray(pb.actions) ? pb.actions : [];
        const nodes = extractNodes(actionsArr);

        const stepsHtml = nodes
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          .map((node: any, idx: number) => {
            const label = node.data?.label || node.type || `Step ${idx + 1}`;
            const type = node.type || "action";
            const config = node.data?.config || {};
            const configStr = Object.entries(config)
              .map(([k, v]) => `${k}: ${v}`)
              .join(", ");
            return `
            <div style="margin-bottom:16px;padding:12px;border:1px solid #ddd;border-radius:6px;page-break-inside:avoid;">
              <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">
                <span style="background:#f0f0f0;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;text-transform:uppercase;">${type}</span>
                <span style="font-weight:600;">Step ${idx + 1}: ${label}</span>
              </div>
              ${configStr ? `<div style="font-size:12px;color:#666;">Config: ${configStr}</div>` : ""}
              <div style="margin-top:8px;border-top:1px dashed #eee;padding-top:8px;">
                <label style="font-size:12px;"><input type="checkbox" style="margin-right:6px;" />Completed</label>
                <div style="margin-top:4px;font-size:11px;color:#999;">Notes: ___________________________</div>
              </div>
            </div>`;
          })
          .join("");

        const html = `<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>${pb.name} - Runbook</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 800px; margin: 0 auto; padding: 40px 20px; color: #1a1a1a; }
  .header { border-bottom: 2px solid #1a1a1a; padding-bottom: 16px; margin-bottom: 24px; }
  .header h1 { margin: 0 0 4px 0; font-size: 24px; }
  .header .subtitle { color: #666; font-size: 14px; }
  .meta { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-bottom: 24px; font-size: 13px; }
  .meta-item { padding: 8px 12px; background: #f8f8f8; border-radius: 4px; }
  .meta-label { font-weight: 600; color: #666; text-transform: uppercase; font-size: 10px; letter-spacing: 0.5px; }
  .footer { margin-top: 32px; border-top: 1px solid #ddd; padding-top: 12px; font-size: 11px; color: #999; text-align: center; }
  @media print { body { padding: 0; } .footer { position: fixed; bottom: 0; width: 100%; } }
</style>
</head><body>
<div class="header">
  <h1>${pb.name}</h1>
  <div class="subtitle">${pb.description || "No description"}</div>
</div>
<div class="meta">
  <div class="meta-item"><div class="meta-label">Status</div><div>${pb.status || "draft"}</div></div>
  <div class="meta-item"><div class="meta-label">Trigger</div><div>${pb.trigger || "manual"}</div></div>
  <div class="meta-item"><div class="meta-label">Total Steps</div><div>${nodes.length}</div></div>
  <div class="meta-item"><div class="meta-label">Exported</div><div>${new Date().toISOString().split("T")[0]}</div></div>
</div>
<h2 style="font-size:18px;margin-bottom:16px;">Steps</h2>
${stepsHtml || "<p>No steps defined</p>"}
<div class="footer">
  Generated from SecureNexus - Confidential Incident Response Document
</div>
</body></html>`;

        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const user = (req as any).user;
        await storage.createAuditLog({
          orgId,
          userId: user?.id,
          userName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst",
          action: "runbook_exported_pdf",
          resourceType: "playbook",
          resourceId: pb.id,
          details: { format: "html-pdf", stepsCount: nodes.length },
        });

        res.setHeader("Content-Type", "text/html; charset=utf-8");
        res.setHeader(
          "Content-Disposition",
          `attachment; filename="${pb.name.replace(/[^a-zA-Z0-9_-]/g, "_")}_runbook.html"`,
        );
        res.send(html);
      } catch (error) {
        logger.child("routes").error("PDF export error", { error: String(error) });
        res.status(500).json({ message: "Failed to export runbook" });
      }
    },
  );

  // Runbook Analytics

  app.get(
    "/api/playbooks/runbook-analytics",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const allExecutions = await storage.getPlaybookExecutions(orgId);
        const allPlaybooks = await storage.getPlaybooks(orgId);

        interface RunbookStat {
          playbookId: string;
          playbookName: string;
          totalExecutions: number;
          completedExecutions: number;
          failedExecutions: number;
          avgCompletionTimeMs: number;
          completionRate: number;
          stepStats: Array<{
            nodeId: string;
            label: string;
            avgDurationMs: number;
            skipCount: number;
            totalRuns: number;
          }>;
        }

        const statsMap = new Map<string, RunbookStat>();
        const completionTimes: number[] = [];

        for (const exec of allExecutions) {
          const pbId = String(exec.playbookId);
          if (!statsMap.has(pbId)) {
            const pb = allPlaybooks.find((p) => String(p.id) === pbId);
            statsMap.set(pbId, {
              playbookId: pbId,
              playbookName: pb?.name || `Playbook #${pbId}`,
              totalExecutions: 0,
              completedExecutions: 0,
              failedExecutions: 0,
              avgCompletionTimeMs: 0,
              completionRate: 0,
              stepStats: [],
            });
          }
          const stat = statsMap.get(pbId)!;
          stat.totalExecutions++;
          if (exec.status === "completed") {
            stat.completedExecutions++;
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            const execAny = exec as any;
            if (execAny.startedAt && execAny.completedAt) {
              const dur = new Date(execAny.completedAt).getTime() - new Date(execAny.startedAt).getTime();
              completionTimes.push(dur);
            }
          }
          if (exec.status === "failed") stat.failedExecutions++;
        }

        const statsList: RunbookStat[] = [];
        statsMap.forEach((stat) => {
          stat.completionRate =
            stat.totalExecutions > 0 ? Math.round((stat.completedExecutions / stat.totalExecutions) * 100) : 0;
          statsList.push(stat);
        });

        const skippedSteps: Record<string, { label: string; count: number }> = {};
        const stepDurations: Record<string, { label: string; durations: number[] }> = {};

        executionTracking.forEach((tracking) => {
          for (const step of tracking.steps) {
            const key = step.label;
            if (step.status === "skipped") {
              if (!skippedSteps[key]) skippedSteps[key] = { label: key, count: 0 };
              skippedSteps[key].count++;
            }
            if (step.status === "completed" && step.timeSpentMs > 0) {
              if (!stepDurations[key]) stepDurations[key] = { label: key, durations: [] };
              stepDurations[key].durations.push(step.timeSpentMs);
            }
          }
        });

        const mostSkippedSteps = Object.values(skippedSteps)
          .sort((a, b) => b.count - a.count)
          .slice(0, 10);

        const longestSteps = Object.values(stepDurations)
          .map((s) => ({
            label: s.label,
            avgDurationMs: Math.round(s.durations.reduce((a, b) => a + b, 0) / s.durations.length),
            totalRuns: s.durations.length,
          }))
          .sort((a, b) => b.avgDurationMs - a.avgDurationMs)
          .slice(0, 10);

        const avgCompletionTime =
          completionTimes.length > 0
            ? Math.round(completionTimes.reduce((a, b) => a + b, 0) / completionTimes.length)
            : 0;

        res.json({
          totalRunbooks: allPlaybooks.length,
          totalExecutions: allExecutions.length,
          avgCompletionTimeMs: avgCompletionTime,
          overallCompletionRate:
            allExecutions.length > 0
              ? Math.round((allExecutions.filter((e) => e.status === "completed").length / allExecutions.length) * 100)
              : 0,
          perRunbook: statsList.sort((a, b) => b.totalExecutions - a.totalExecutions),
          mostSkippedSteps,
          longestSteps,
          activeTrackings: executionTracking.size,
        });
      } catch (error) {
        logger.child("routes").error("Runbook analytics error", { error: String(error) });
        res.status(500).json({ message: "Failed to fetch runbook analytics" });
      }
    },
  );

  // Runbook to Playbook Conversion

  const AUTOMATABLE_ACTIONS = new Set([
    "isolate_host",
    "block_ip",
    "block_domain",
    "quarantine_file",
    "disable_user",
    "kill_process",
    "notify_slack",
    "notify_teams",
    "notify_email",
    "notify_webhook",
    "create_jira_ticket",
    "create_servicenow_ticket",
    "add_tag",
    "change_status",
    "escalate",
    "assign_analyst",
    "auto_triage",
  ]);

  const INTEGRATION_SUGGESTIONS: Record<string, { integration: string; description: string }> = {
    isolate_host: { integration: "CrowdStrike / SentinelOne", description: "EDR network isolation via API" },
    block_ip: { integration: "Firewall API (Palo Alto / Fortinet)", description: "Automated IP blocking rule" },
    block_domain: { integration: "DNS Firewall (Cisco Umbrella)", description: "DNS-level domain blocking" },
    quarantine_file: { integration: "EDR Quarantine API", description: "Remote file quarantine via agent" },
    disable_user: { integration: "Active Directory / Okta / Azure AD", description: "Identity provider user disable" },
    kill_process: { integration: "EDR Process Kill API", description: "Remote process termination via agent" },
    notify_slack: { integration: "Slack Webhook", description: "Automated Slack notification" },
    notify_teams: { integration: "Microsoft Teams Webhook", description: "Automated Teams notification" },
    notify_email: { integration: "SMTP / SendGrid", description: "Automated email notification" },
    create_jira_ticket: { integration: "Jira REST API", description: "Automated ticket creation in Jira" },
    create_servicenow_ticket: { integration: "ServiceNow REST API", description: "Automated ITSM ticket" },
    add_tag: { integration: "SecureNexus Native", description: "Auto-tagging via platform API" },
    change_status: { integration: "SecureNexus Native", description: "Status change via platform API" },
    escalate: { integration: "PagerDuty / Opsgenie", description: "Automated escalation via on-call" },
    assign_analyst: { integration: "SecureNexus Native", description: "Auto-assignment via round-robin" },
    auto_triage: { integration: "SecureNexus AI", description: "AI-powered automatic triage" },
  };

  app.post(
    "/api/playbooks/:id/suggest-automation",
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

        const actionsArr = Array.isArray(pb.actions) ? pb.actions : [];
        const nodes = extractNodes(actionsArr);

        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const suggestions = nodes.map((node: any, idx: number) => {
          const actionType = node.data?.actionType || node.type || "";
          const isAutomatable = AUTOMATABLE_ACTIONS.has(actionType);
          const suggestion = INTEGRATION_SUGGESTIONS[actionType];

          return {
            stepIndex: idx,
            nodeId: node.id,
            label: node.data?.label || node.type || `Step ${idx + 1}`,
            type: node.type,
            actionType,
            isAutomatable,
            automationConfidence: isAutomatable ? (suggestion ? 0.9 : 0.7) : 0.2,
            suggestedIntegration: suggestion?.integration || null,
            integrationDescription: suggestion?.description || null,
            manualReason: !isAutomatable
              ? node.type === "condition"
                ? "Conditions require human judgment"
                : node.type === "approval"
                  ? "Approval gates require human authorization"
                  : "This step type requires manual execution"
              : null,
            convertible: isAutomatable && node.type === "action",
          };
        });

        const automatableCount = suggestions.filter((s) => s.convertible).length;
        const totalSteps = suggestions.length;

        res.json({
          playbookId: pb.id,
          playbookName: pb.name,
          totalSteps,
          automatableSteps: automatableCount,
          automationCoverage: totalSteps > 0 ? Math.round((automatableCount / totalSteps) * 100) : 0,
          suggestions,
          recommendedIntegrations: Array.from(
            new Set(suggestions.filter((s) => s.suggestedIntegration).map((s) => s.suggestedIntegration)),
          ),
        });
      } catch (error) {
        logger.child("routes").error("Automation suggestion error", { error: String(error) });
        res.status(500).json({ message: "Failed to suggest automation" });
      }
    },
  );
}

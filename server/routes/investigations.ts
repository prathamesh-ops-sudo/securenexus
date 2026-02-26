import type { Express, Request, Response } from "express";
import { getOrgId, logger, p, storage } from "./shared";
import { isAuthenticated } from "../auth";
import { insertRunbookStepSchema, insertRunbookTemplateSchema } from "@shared/schema";
import { runInvestigation } from "../investigation-agent";
import { evaluatePolicies, generateDefaultPolicies } from "../policy-engine";
import { canRollback, createRollbackRecord, executeRollback } from "../rollback-engine";

export function registerInvestigationsRoutes(app: Express): void {
  // Phase 8: Predictive Defense routes
  app.get("/api/predictive/anomalies", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const anomalies = await storage.getPredictiveAnomalies(orgId);
      res.json(anomalies);
    } catch (error) { res.status(500).json({ message: "Failed to fetch anomalies" }); }
  });

  app.get("/api/predictive/attack-surface", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const assets = await storage.getAttackSurfaceAssets(orgId);
      res.json(assets);
    } catch (error) { res.status(500).json({ message: "Failed to fetch attack surface" }); }
  });

  app.get("/api/predictive/forecasts", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const forecasts = await storage.getRiskForecasts(orgId);
      res.json(forecasts);
    } catch (error) { res.status(500).json({ message: "Failed to fetch forecasts" }); }
  });

  app.get("/api/predictive/forecast-quality", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const snapshots = await storage.getForecastQualitySnapshots(orgId);
      const grouped = snapshots.reduce((acc: Record<string, any[]>, s) => {
        if (!acc[s.module]) acc[s.module] = [];
        acc[s.module].push(s);
        return acc;
      }, {});
      const trends = Object.entries(grouped).map(([module, records]) => {
        const ordered = [...records].sort((a, b) => +new Date(a.measuredAt || 0) - +new Date(b.measuredAt || 0));
        const latest = ordered[ordered.length - 1];
        const earliest = ordered[0];
        return {
          module,
          latestPrecision: latest?.precision || 0,
          latestRecall: latest?.recall || 0,
          precisionTrend: (latest?.precision || 0) - (earliest?.precision || 0),
          recallTrend: (latest?.recall || 0) - (earliest?.recall || 0),
          sampleSize: latest?.sampleSize || 0,
          points: ordered,
        };
      });
      res.json(trends);
    } catch (error) { res.status(500).json({ message: "Failed to fetch forecast quality" }); }
  });

  app.get("/api/predictive/recommendations", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const recs = await storage.getHardeningRecommendations(orgId);
      res.json(recs);
    } catch (error) { res.status(500).json({ message: "Failed to fetch recommendations" }); }
  });

  app.post("/api/predictive/recompute", isAuthenticated, async (req, res) => {
    try {
      let orgId = (req as any).user?.orgId;
      if (!orgId) {
        const orgs = await storage.getOrganizations();
        if (orgs.length > 0) orgId = orgs[0].id;
      }
      if (!orgId) return res.status(400).json({ message: "Organization required" });
      const { runPredictiveAnalysis } = await import("../predictive-engine");
      const result = await runPredictiveAnalysis(orgId, storage);

      const feedback = await storage.getAiFeedback(undefined, undefined);
      const moduleFeedback = ["triage", "correlation", "forecast"].map((module) => {
        const filtered = feedback.filter((f) => (f.resourceType || "").includes(module));
        const positives = filtered.filter((f) => f.rating >= 4).length;
        const negatives = filtered.filter((f) => f.rating <= 2).length;
        const precision = filtered.length > 0 ? positives / filtered.length : 0.5;
        const recall = filtered.length > 0 ? positives / Math.max(positives + negatives, 1) : 0.5;
        return { module, precision, recall, sampleSize: filtered.length };
      });
      for (const metric of moduleFeedback) {
        await storage.createForecastQualitySnapshot({
          orgId,
          module: metric.module,
          precision: metric.precision,
          recall: metric.recall,
          sampleSize: metric.sampleSize,
        });
      }

      await storage.createAuditLog({
        orgId,
        userId: (req as any).user?.id,
        action: "predictive_analysis_run",
        resourceType: "predictive",
        details: result,
      });
      res.json(result);
    } catch (error: any) {
      logger.child("routes").error("Predictive analysis error", { error: String(error) });
      res.status(500).json({ message: "Failed to run predictive analysis" });
    }
  });

  app.patch("/api/predictive/recommendations/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const { status } = req.body;
      const recs = await storage.getHardeningRecommendations(orgId);
      const rec = recs.find(r => r.id === req.params.id);
      if (!rec) return res.status(404).json({ message: "Recommendation not found" });
      const updated = await storage.updateHardeningRecommendation(p(req.params.id), { status });
      if (!updated) return res.status(404).json({ message: "Recommendation not found" });
      res.json(updated);
    } catch (error) { res.status(500).json({ message: "Failed to update recommendation" }); }
  });

  app.get("/api/predictive/anomaly-subscriptions", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const rows = await storage.getAnomalySubscriptions(orgId);
      res.json(rows);
    } catch (error) { res.status(500).json({ message: "Failed to fetch anomaly subscriptions" }); }
  });

  app.post("/api/predictive/anomaly-subscriptions", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const userId = (req as any).user?.id;
      const created = await storage.createAnomalySubscription({ ...req.body, orgId, createdBy: userId });
      res.status(201).json(created);
    } catch (error) { res.status(500).json({ message: "Failed to create anomaly subscription" }); }
  });

  app.delete("/api/predictive/anomaly-subscriptions/:id", isAuthenticated, async (req, res) => {
    try {
      const ok = await storage.deleteAnomalySubscription(p(req.params.id));
      if (!ok) return res.status(404).json({ message: "Subscription not found" });
      res.status(204).send();
    } catch (error) { res.status(500).json({ message: "Failed to delete anomaly subscription" }); }
  });

  // Auto-Response Policies CRUD
  app.get("/api/autonomous/policies", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const policies = await storage.getAutoResponsePolicies(orgId);
      res.json(policies);
    } catch (error) { res.status(500).json({ message: "Failed to fetch policies" }); }
  });

  app.post("/api/autonomous/policies", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const policy = await storage.createAutoResponsePolicy({ ...req.body, orgId });
      res.status(201).json(policy);
    } catch (error) { res.status(500).json({ message: "Failed to create policy" }); }
  });

  app.patch("/api/autonomous/policies/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const policies = await storage.getAutoResponsePolicies(orgId);
      const policy = policies.find(p => p.id === (req.params.id as string));
      if (!policy) return res.status(404).json({ message: "Policy not found" });
      const updated = await storage.updateAutoResponsePolicy(req.params.id as string, req.body);
      if (!updated) return res.status(404).json({ message: "Policy not found" });
      res.json(updated);
    } catch (error) { res.status(500).json({ message: "Failed to update policy" }); }
  });

  app.delete("/api/autonomous/policies/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const policies = await storage.getAutoResponsePolicies(orgId);
      const policy = policies.find(p => p.id === (req.params.id as string));
      if (!policy) return res.status(404).json({ message: "Policy not found" });
      const deleted = await storage.deleteAutoResponsePolicy(req.params.id as string);
      if (!deleted) return res.status(404).json({ message: "Policy not found" });
      res.json({ success: true });
    } catch (error) { res.status(500).json({ message: "Failed to delete policy" }); }
  });

  // Seed default policies
  app.post("/api/autonomous/policies/seed-defaults", isAuthenticated, async (req, res) => {
    try {
      let orgId = (req as any).user?.orgId;
      if (!orgId) {
        const orgs = await storage.getOrganizations();
        if (orgs.length > 0) orgId = orgs[0].id;
      }
      if (!orgId) return res.status(400).json({ message: "No organization found" });
      const existing = await storage.getAutoResponsePolicies(orgId);
      if (existing.length > 0) return res.json({ message: "Policies already exist", count: existing.length });
      const defaults = generateDefaultPolicies(orgId);
      const created = [];
      for (const def of defaults) {
        const p = await storage.createAutoResponsePolicy(def as any);
        created.push(p);
      }
      res.status(201).json(created);
    } catch (error) { logger.child("routes").error("Seed policies error", { error: String(error) }); res.status(500).json({ message: "Failed to seed policies" }); }
  });

  // Evaluate policies for an incident
  app.post("/api/autonomous/evaluate/:incidentId", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const incId = req.params.incidentId as string;
      const incident = await storage.getIncident(incId);
      if (!incident) return res.status(404).json({ message: "Incident not found" });
      const allAlerts = await storage.getAlerts(orgId);
      const incidentAlerts = allAlerts.filter(a => a.incidentId === incId);
      const matches = await evaluatePolicies({ incident, alerts: incidentAlerts, orgId: orgId, confidenceScore: req.body.confidenceScore });
      res.json(matches);
    } catch (error) { res.status(500).json({ message: "Failed to evaluate policies" }); }
  });

  // Investigation Runs
  app.get("/api/autonomous/investigations", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const runs = await storage.getInvestigationRuns(orgId);
      res.json(runs);
    } catch (error) { res.status(500).json({ message: "Failed to fetch investigations" }); }
  });

  app.get("/api/autonomous/investigations/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const run = await storage.getInvestigationRun(req.params.id as string);
      if (!run) return res.status(404).json({ message: "Investigation not found" });
      if (orgId && run.orgId !== orgId) return res.status(404).json({ message: "Investigation not found" });
      const steps = await storage.getInvestigationSteps(run.id);
      res.json({ ...run, steps });
    } catch (error) { res.status(500).json({ message: "Failed to fetch investigation" }); }
  });

  app.post("/api/autonomous/investigations", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const { incidentId } = req.body;
      if (!incidentId) return res.status(400).json({ message: "incidentId required" });
      const incident = await storage.getIncident(incidentId);
      if (!incident) return res.status(404).json({ message: "Incident not found" });
      const run = await storage.createInvestigationRun({
        orgId,
        incidentId,
        triggeredBy: (req as any).user?.email || "analyst",
        triggerSource: "manual",
        status: "queued",
      });
      // Start investigation async
      runInvestigation(run.id).catch(err => logger.child("routes").error("Investigation error", { error: String(err) }));
      res.status(201).json(run);
    } catch (error) { res.status(500).json({ message: "Failed to start investigation" }); }
  });

  // Rollbacks
  app.get("/api/autonomous/rollbacks", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const rollbacks = await storage.getResponseActionRollbacks(orgId);
      res.json(rollbacks);
    } catch (error) { res.status(500).json({ message: "Failed to fetch rollbacks" }); }
  });

  app.post("/api/autonomous/rollbacks", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const { originalActionId, actionType, target } = req.body;
      if (!actionType || !target) return res.status(400).json({ message: "actionType and target required" });
      if (!canRollback(actionType)) return res.status(400).json({ message: `Cannot rollback action: ${actionType}` });
      const rollback = await createRollbackRecord(orgId, originalActionId, actionType, target);
      res.status(201).json(rollback);
    } catch (error) { logger.child("routes").error("Create rollback error", { error: String(error) }); res.status(500).json({ message: "Failed to create rollback" }); }
  });

  app.post("/api/autonomous/rollbacks/:id/execute", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const rollbacks = await storage.getResponseActionRollbacks(orgId);
      const rb = rollbacks.find(r => r.id === (req.params.id as string));
      if (!rb) return res.status(404).json({ message: "Rollback not found" });
      const user = (req as any).user?.email || "analyst";
      const result = await executeRollback(req.params.id as string, user);
      if (!result) return res.status(404).json({ message: "Rollback not found or already executed" });
      res.json(result);
    } catch (error) { res.status(500).json({ message: "Failed to execute rollback" }); }
  });

  // ==========================================
  // Runbook Templates (global + org-scoped)
  // ==========================================
  app.get("/api/runbook-templates", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const { incidentType } = req.query;
      const templates = await storage.getRunbookTemplates(user?.orgId, incidentType as string | undefined);
      res.json(templates);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch runbook templates" });
    }
  });

  app.get("/api/runbook-templates/:id", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const template = await storage.getRunbookTemplate(p(req.params.id));
      if (!template) return res.status(404).json({ message: "Runbook template not found" });
      if (template.orgId && user?.orgId && template.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const steps = await storage.getRunbookSteps(template.id);
      res.json({ ...template, steps });
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch runbook template" });
    }
  });

  app.post("/api/runbook-templates", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const orgId = getOrgId(req);
      const parsed = insertRunbookTemplateSchema.safeParse({
        ...req.body,
        orgId,
      });
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid runbook template data", errors: parsed.error.flatten() });
      }
      const template = await storage.createRunbookTemplate(parsed.data);
      res.status(201).json(template);
    } catch (error: any) {
      if (error.message === "ORG_CONTEXT_MISSING") return res.status(403).json({ message: "Organization context required" });
      res.status(500).json({ message: "Failed to create runbook template" });
    }
  });

  app.delete("/api/runbook-templates/:id", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const existing = await storage.getRunbookTemplate(p(req.params.id));
      if (!existing) return res.status(404).json({ message: "Runbook template not found" });
      if (existing.orgId && user?.orgId && existing.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      if (existing.isBuiltIn) return res.status(403).json({ message: "Cannot delete built-in runbook templates" });
      const deleted = await storage.deleteRunbookTemplate(p(req.params.id));
      if (!deleted) return res.status(404).json({ message: "Runbook template not found" });
      res.json({ message: "Runbook template deleted" });
    } catch (error) {
      res.status(500).json({ message: "Failed to delete runbook template" });
    }
  });

  // Runbook Steps
  app.get("/api/runbook-templates/:id/steps", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const template = await storage.getRunbookTemplate(p(req.params.id));
      if (!template) return res.status(404).json({ message: "Runbook template not found" });
      if (template.orgId && user?.orgId && template.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const steps = await storage.getRunbookSteps(p(req.params.id));
      res.json(steps);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch runbook steps" });
    }
  });

  app.post("/api/runbook-templates/:id/steps", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const template = await storage.getRunbookTemplate(p(req.params.id));
      if (!template) return res.status(404).json({ message: "Runbook template not found" });
      if (template.orgId && user?.orgId && template.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const parsed = insertRunbookStepSchema.safeParse({
        ...req.body,
        templateId: p(req.params.id),
      });
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid runbook step data", errors: parsed.error.flatten() });
      }
      const step = await storage.createRunbookStep(parsed.data);
      res.status(201).json(step);
    } catch (error) {
      res.status(500).json({ message: "Failed to create runbook step" });
    }
  });

  app.patch("/api/runbook-templates/:id/steps/:stepId", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const template = await storage.getRunbookTemplate(p(req.params.id));
      if (!template) return res.status(404).json({ message: "Runbook template not found" });
      if (template.orgId && user?.orgId && template.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const { templateId: _ignoreTemplateId, ...updateData } = req.body;
      const step = await storage.updateRunbookStep(p(req.params.stepId), updateData);
      if (!step) return res.status(404).json({ message: "Runbook step not found" });
      res.json(step);
    } catch (error) {
      res.status(500).json({ message: "Failed to update runbook step" });
    }
  });

  app.delete("/api/runbook-templates/:id/steps/:stepId", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const template = await storage.getRunbookTemplate(p(req.params.id));
      if (!template) return res.status(404).json({ message: "Runbook template not found" });
      if (template.orgId && user?.orgId && template.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const deleted = await storage.deleteRunbookStep(p(req.params.stepId));
      if (!deleted) return res.status(404).json({ message: "Runbook step not found" });
      res.json({ message: "Runbook step deleted" });
    } catch (error) {
      res.status(500).json({ message: "Failed to delete runbook step" });
    }
  });

  // ==========================================
  // Seed built-in runbook templates
  // ==========================================
  app.post("/api/runbook-templates/seed", isAuthenticated, async (req, res) => {
    try {
      const builtInTemplates = [
        {
          incidentType: "brute_force",
          title: "Brute Force Attack Response",
          description: "Standard response procedure for brute force authentication attacks",
          severity: "high",
          estimatedDuration: "2-4 hours",
          tags: ["authentication", "brute_force", "credential_access"],
          isBuiltIn: true,
          steps: [
            { stepOrder: 1, title: "Identify Targeted Accounts", instructions: "Review authentication logs to identify all accounts targeted by the brute force attempt. Note source IPs, timestamps, and frequency of attempts.", actionType: "gather_alerts", isRequired: true, estimatedMinutes: 30 },
            { stepOrder: 2, title: "Block Source IPs", instructions: "Add source IPs to firewall block list and WAF rules. Verify blocks are effective by monitoring continued attempts.", actionType: "block_ip", isRequired: true, estimatedMinutes: 15 },
            { stepOrder: 3, title: "Reset Compromised Credentials", instructions: "Force password reset for any accounts that may have been compromised. Enable MFA if not already active.", actionType: "disable_user", isRequired: true, estimatedMinutes: 30 },
            { stepOrder: 4, title: "Assess Lateral Movement", instructions: "Check if any successfully authenticated sessions were used for lateral movement. Review session logs and access patterns.", actionType: "correlate_evidence", isRequired: true, estimatedMinutes: 45 },
            { stepOrder: 5, title: "Strengthen Authentication Controls", instructions: "Implement account lockout policies, rate limiting, and CAPTCHA. Review and enhance MFA enforcement.", actionType: "recommendation", isRequired: false, estimatedMinutes: 60 },
          ],
        },
        {
          incidentType: "malware",
          title: "Malware Infection Response",
          description: "Containment and eradication procedure for malware infections",
          severity: "critical",
          estimatedDuration: "4-8 hours",
          tags: ["malware", "endpoint", "containment"],
          isBuiltIn: true,
          steps: [
            { stepOrder: 1, title: "Isolate Infected Host", instructions: "Immediately isolate the infected host from the network to prevent lateral spread. Maintain forensic access if possible.", actionType: "isolate_host", isRequired: true, estimatedMinutes: 10 },
            { stepOrder: 2, title: "Collect Forensic Evidence", instructions: "Capture memory dump, disk image, and network logs from the infected host before remediation. Preserve chain of custody.", actionType: "gather_alerts", isRequired: true, estimatedMinutes: 60 },
            { stepOrder: 3, title: "Identify Malware Family", instructions: "Analyze malware samples to determine family, capabilities, C2 infrastructure, and persistence mechanisms. Submit to sandbox if needed.", actionType: "ai_analysis", isRequired: true, estimatedMinutes: 45 },
            { stepOrder: 4, title: "Scan for Additional Infections", instructions: "Run IOC sweeps across the environment using identified indicators. Check for lateral movement and additional compromised hosts.", actionType: "correlate_evidence", isRequired: true, estimatedMinutes: 60 },
            { stepOrder: 5, title: "Eradicate and Restore", instructions: "Remove all malware artifacts, persistence mechanisms, and unauthorized changes. Rebuild host from clean image if necessary.", actionType: "action_taken", isRequired: true, estimatedMinutes: 120 },
            { stepOrder: 6, title: "Update Defenses", instructions: "Add IOCs to blocklists, update detection signatures, and review endpoint protection policies to prevent recurrence.", actionType: "recommendation", isRequired: false, estimatedMinutes: 30 },
          ],
        },
        {
          incidentType: "phishing",
          title: "Phishing Incident Response",
          description: "Response procedure for phishing email campaigns and credential harvesting",
          severity: "high",
          estimatedDuration: "2-6 hours",
          tags: ["phishing", "email", "social_engineering"],
          isBuiltIn: true,
          steps: [
            { stepOrder: 1, title: "Identify Affected Users", instructions: "Determine all recipients of the phishing email. Check email gateway logs for delivery status and identify users who clicked links or opened attachments.", actionType: "gather_alerts", isRequired: true, estimatedMinutes: 30 },
            { stepOrder: 2, title: "Block Malicious Indicators", instructions: "Block sender address, domain, and any malicious URLs or IP addresses at email gateway, proxy, and firewall levels.", actionType: "block_domain", isRequired: true, estimatedMinutes: 15 },
            { stepOrder: 3, title: "Remove Phishing Emails", instructions: "Use email admin tools to search and purge the phishing email from all mailboxes. Quarantine any remaining copies.", actionType: "quarantine_file", isRequired: true, estimatedMinutes: 20 },
            { stepOrder: 4, title: "Reset Compromised Credentials", instructions: "For users who submitted credentials, force immediate password reset and revoke active sessions. Enable MFA.", actionType: "disable_user", isRequired: true, estimatedMinutes: 30 },
            { stepOrder: 5, title: "Check for Post-Compromise Activity", instructions: "Review login history, email forwarding rules, and OAuth app grants for compromised accounts. Look for data exfiltration signs.", actionType: "correlate_evidence", isRequired: true, estimatedMinutes: 45 },
          ],
        },
        {
          incidentType: "data_exfiltration",
          title: "Data Exfiltration Response",
          description: "Response procedure for suspected data exfiltration or data breach events",
          severity: "critical",
          estimatedDuration: "6-12 hours",
          tags: ["data_breach", "exfiltration", "dlp"],
          isBuiltIn: true,
          steps: [
            { stepOrder: 1, title: "Confirm Data Exfiltration", instructions: "Analyze network logs, DLP alerts, and endpoint telemetry to confirm data exfiltration. Identify data types, volumes, and destination.", actionType: "gather_alerts", isRequired: true, estimatedMinutes: 60 },
            { stepOrder: 2, title: "Block Exfiltration Channels", instructions: "Block identified exfiltration destinations (IPs, domains, cloud storage). Disable compromised accounts and revoke API keys.", actionType: "block_ip", isRequired: true, estimatedMinutes: 20 },
            { stepOrder: 3, title: "Assess Data Impact", instructions: "Determine what data was exfiltrated, including classification level, PII/PHI content, and affected records count. Document for regulatory reporting.", actionType: "ai_analysis", isRequired: true, estimatedMinutes: 90 },
            { stepOrder: 4, title: "Identify Root Cause", instructions: "Trace the attack chain to identify initial access vector, persistence mechanisms, and privilege escalation paths used.", actionType: "correlate_evidence", isRequired: true, estimatedMinutes: 60 },
            { stepOrder: 5, title: "Contain and Remediate", instructions: "Isolate affected systems, patch vulnerabilities, rotate credentials, and remove attacker access. Verify no remaining persistence.", actionType: "action_taken", isRequired: true, estimatedMinutes: 120 },
            { stepOrder: 6, title: "Regulatory Notification", instructions: "Prepare breach notification documents as required by GDPR, HIPAA, or other applicable regulations. Notify legal and compliance teams.", actionType: "recommendation", isRequired: true, estimatedMinutes: 60 },
          ],
        },
        {
          incidentType: "ransomware",
          title: "Ransomware Incident Response",
          description: "Critical response procedure for ransomware attacks including containment and recovery",
          severity: "critical",
          estimatedDuration: "8-24 hours",
          tags: ["ransomware", "encryption", "critical"],
          isBuiltIn: true,
          steps: [
            { stepOrder: 1, title: "Isolate Affected Systems", instructions: "Immediately disconnect affected systems from the network. Disable shares and remote access. Do NOT power off systems to preserve evidence.", actionType: "isolate_host", isRequired: true, estimatedMinutes: 15 },
            { stepOrder: 2, title: "Assess Scope of Encryption", instructions: "Determine which systems, files, and backups are affected. Identify the ransomware variant and check for available decryptors.", actionType: "gather_alerts", isRequired: true, estimatedMinutes: 60 },
            { stepOrder: 3, title: "Preserve Forensic Evidence", instructions: "Capture memory dumps, ransomware samples, and ransom notes. Document encrypted file extensions and patterns.", actionType: "gather_alerts", isRequired: true, estimatedMinutes: 45 },
            { stepOrder: 4, title: "Identify Initial Access Vector", instructions: "Trace how ransomware entered the environment. Check for phishing emails, RDP exposure, vulnerable VPN, or supply chain compromise.", actionType: "correlate_evidence", isRequired: true, estimatedMinutes: 90 },
            { stepOrder: 5, title: "Restore from Backups", instructions: "Verify backup integrity, restore systems from clean backups. Rebuild compromised systems from scratch if backups are unavailable or compromised.", actionType: "action_taken", isRequired: true, estimatedMinutes: 240 },
            { stepOrder: 6, title: "Harden and Monitor", instructions: "Patch exploited vulnerabilities, strengthen endpoint protection, implement network segmentation, and enhance monitoring for re-infection attempts.", actionType: "recommendation", isRequired: true, estimatedMinutes: 120 },
          ],
        },
        {
          incidentType: "ddos",
          title: "DDoS Attack Response",
          description: "Response procedure for distributed denial-of-service attacks",
          severity: "high",
          estimatedDuration: "2-8 hours",
          tags: ["ddos", "availability", "network"],
          isBuiltIn: true,
          steps: [
            { stepOrder: 1, title: "Confirm DDoS Attack", instructions: "Analyze traffic patterns, bandwidth utilization, and service availability metrics to confirm DDoS attack. Identify attack type (volumetric, protocol, application layer).", actionType: "gather_alerts", isRequired: true, estimatedMinutes: 15 },
            { stepOrder: 2, title: "Activate DDoS Mitigation", instructions: "Enable DDoS protection services (cloud scrubbing, CDN protection). Configure rate limiting and traffic filtering rules.", actionType: "action_taken", isRequired: true, estimatedMinutes: 20 },
            { stepOrder: 3, title: "Block Attack Sources", instructions: "Identify and block major attack source IPs/networks at network edge. Implement geo-blocking if attack sources are concentrated.", actionType: "block_ip", isRequired: true, estimatedMinutes: 30 },
            { stepOrder: 4, title: "Scale Infrastructure", instructions: "Scale up server capacity, enable auto-scaling groups, and distribute load across multiple regions if possible.", actionType: "action_taken", isRequired: false, estimatedMinutes: 30 },
            { stepOrder: 5, title: "Monitor and Adjust", instructions: "Continuously monitor attack patterns and adjust mitigation rules. Document attack timeline, peak volumes, and effectiveness of countermeasures.", actionType: "correlate_evidence", isRequired: true, estimatedMinutes: 60 },
          ],
        },
        {
          incidentType: "general",
          title: "General Security Incident Response",
          description: "Generic incident response procedure applicable to any security incident type",
          severity: "medium",
          estimatedDuration: "2-6 hours",
          tags: ["general", "incident_response"],
          isBuiltIn: true,
          steps: [
            { stepOrder: 1, title: "Initial Triage", instructions: "Assess the incident severity, scope, and potential impact. Gather initial evidence from alerts, logs, and affected systems.", actionType: "gather_alerts", isRequired: true, estimatedMinutes: 30 },
            { stepOrder: 2, title: "Containment", instructions: "Implement immediate containment measures to prevent further damage. This may include isolating hosts, blocking IPs, or disabling accounts.", actionType: "action_taken", isRequired: true, estimatedMinutes: 30 },
            { stepOrder: 3, title: "Investigation", instructions: "Conduct thorough investigation to understand the full scope, root cause, and attack chain. Correlate evidence across multiple data sources.", actionType: "correlate_evidence", isRequired: true, estimatedMinutes: 60 },
            { stepOrder: 4, title: "Eradication", instructions: "Remove all traces of the threat from the environment. Patch vulnerabilities, remove malware, and revoke compromised credentials.", actionType: "action_taken", isRequired: true, estimatedMinutes: 60 },
            { stepOrder: 5, title: "Recovery", instructions: "Restore affected systems and services to normal operation. Verify system integrity and monitor for signs of recurring activity.", actionType: "action_taken", isRequired: true, estimatedMinutes: 60 },
            { stepOrder: 6, title: "Lessons Learned", instructions: "Document findings, timeline, and response actions. Identify gaps and improvements for security controls and incident response procedures.", actionType: "recommendation", isRequired: false, estimatedMinutes: 30 },
          ],
        },
      ];

      const created: any[] = [];
      for (const tmpl of builtInTemplates) {
        const existing = await storage.getRunbookTemplates(undefined, tmpl.incidentType);
        const alreadyExists = existing.some(e => e.isBuiltIn && e.incidentType === tmpl.incidentType);
        if (alreadyExists) continue;

        const { steps, ...templateData } = tmpl;
        const template = await storage.createRunbookTemplate({ ...templateData, orgId: null });
        for (const step of steps) {
          await storage.createRunbookStep({ ...step, templateId: template.id });
        }
        created.push(template);
      }

      res.status(201).json({ message: `Seeded ${created.length} runbook templates`, templates: created });
    } catch (error) {
      logger.child("routes").error("Error seeding runbook templates", { error: String(error) });
      res.status(500).json({ message: "Failed to seed runbook templates" });
    }
  });

}

import type { Express, Request, Response } from "express";
import { calculateNextRunFromCadence, getOrgId, p, storage } from "./shared";
import { isAuthenticated } from "../auth";
import { insertReportScheduleSchema, insertReportTemplateSchema } from "@shared/schema";

export function registerReportsRoutes(app: Express): void {
  // Export Routes (Phase 10)
  app.get("/api/export/alerts", isAuthenticated, async (req, res) => {
    try {
      const allAlerts = await storage.getAlerts();
      const csvHeader = "ID,Title,Severity,Status,Source,Category,MITRE Tactic,MITRE Technique,Source IP,Dest IP,Hostname,Detected At,Created At\n";
      const csvRows = allAlerts.map(a =>
        [a.id, `"${(a.title || '').replace(/"/g, '""')}"`, a.severity, a.status, a.source, a.category || '',
         a.mitreTactic || '', a.mitreTechnique || '', a.sourceIp || '', a.destIp || '', a.hostname || '',
         a.detectedAt?.toISOString() || '', a.createdAt?.toISOString() || ''
        ].join(",")
      ).join("\n");
      res.setHeader("Content-Type", "text/csv");
      res.setHeader("Content-Disposition", `attachment; filename=securenexus-alerts-${new Date().toISOString().split("T")[0]}.csv`);
      res.send(csvHeader + csvRows);
    } catch (error) { res.status(500).json({ message: "Failed to export alerts" }); }
  });

  app.get("/api/export/incidents", isAuthenticated, async (req, res) => {
    try {
      const allIncidents = await storage.getIncidents();
      const csvHeader = "ID,Title,Severity,Status,Priority,Alert Count,Assigned To,Escalated,MITRE Tactics,Created At,Updated At\n";
      const csvRows = allIncidents.map(i =>
        [i.id, `"${(i.title || '').replace(/"/g, '""')}"`, i.severity, i.status, i.priority || '',
         i.alertCount || 0, i.assignedTo || '', i.escalated ? 'Yes' : 'No',
         `"${(i.mitreTactics || []).join('; ')}"`,
         i.createdAt?.toISOString() || '', i.updatedAt?.toISOString() || ''
        ].join(",")
      ).join("\n");
      res.setHeader("Content-Type", "text/csv");
      res.setHeader("Content-Disposition", `attachment; filename=securenexus-incidents-${new Date().toISOString().split("T")[0]}.csv`);
      res.send(csvHeader + csvRows);
    } catch (error) { res.status(500).json({ message: "Failed to export incidents" }); }
  });

  app.get("/api/export/incident/:id/report", isAuthenticated, async (req, res) => {
    try {
      const incident = await storage.getIncident(p(req.params.id));
      if (!incident) return res.status(404).json({ message: "Incident not found" });
      const incidentAlerts = await storage.getAlertsByIncident(incident.id);
      const comments = await storage.getComments(incident.id);
      const report = {
        generatedAt: new Date().toISOString(),
        incident: { ...incident, alerts: incidentAlerts, comments },
      };
      res.json(report);
    } catch (error) { res.status(500).json({ message: "Failed to generate report" }); }
  });

  app.get("/api/report-templates", isAuthenticated, async (req, res) => {
    const user = req.user as any;
    const templates = await storage.getReportTemplates(user?.orgId);
    res.json(templates);
  });

  app.get("/api/report-templates/:id", isAuthenticated, async (req, res) => {
    const template = await storage.getReportTemplate(p(req.params.id));
    if (!template) return res.status(404).json({ message: "Template not found" });
    const user = req.user as any;
    if (template.orgId && user?.orgId && template.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
    res.json(template);
  });

  app.post("/api/report-templates", isAuthenticated, async (req, res) => {
    try {
      const user = req.user as any;
      const orgId = getOrgId(req);
      const data = insertReportTemplateSchema.parse({ ...req.body, orgId, createdBy: user?.id || null });
      const template = await storage.createReportTemplate(data);
      res.status(201).json(template);
    } catch (error: any) {
      if (error.message === "ORG_CONTEXT_MISSING") return res.status(403).json({ message: "Organization context required" });
      res.status(500).json({ message: "Failed to create report template" });
    }
  });

  app.patch("/api/report-templates/:id", isAuthenticated, async (req, res) => {
    const user = req.user as any;
    const existing = await storage.getReportTemplate(p(req.params.id));
    if (!existing) return res.status(404).json({ message: "Template not found" });
    if (existing.orgId && user?.orgId && existing.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
    const { id: _id, orgId: _org, ...updateData } = req.body;
    const template = await storage.updateReportTemplate(p(req.params.id), updateData);
    res.json(template);
  });

  app.delete("/api/report-templates/:id", isAuthenticated, async (req, res) => {
    const user = req.user as any;
    const existing = await storage.getReportTemplate(p(req.params.id));
    if (!existing) return res.status(404).json({ message: "Template not found" });
    if (existing.orgId && user?.orgId && existing.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
    await storage.deleteReportTemplate(p(req.params.id));
    res.json({ success: true });
  });

  app.get("/api/report-schedules", isAuthenticated, async (req, res) => {
    const user = req.user as any;
    const schedules = await storage.getReportSchedules(user?.orgId);
    res.json(schedules);
  });

  app.get("/api/report-schedules/:id", isAuthenticated, async (req, res) => {
    const schedule = await storage.getReportSchedule(p(req.params.id));
    if (!schedule) return res.status(404).json({ message: "Schedule not found" });
    const user = req.user as any;
    if (schedule.orgId && user?.orgId && schedule.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
    res.json(schedule);
  });

  app.post("/api/report-schedules", isAuthenticated, async (req, res) => {
    try {
      const user = req.user as any;
      const cadence = req.body.cadence || "weekly";
      const nextRunAt = calculateNextRunFromCadence(cadence);
      const orgId = getOrgId(req);
      const data = insertReportScheduleSchema.parse({ ...req.body, orgId, createdBy: user?.id || null });
      const template = await storage.getReportTemplate(data.templateId);
      if (!template) return res.status(404).json({ message: "Template not found" });
      if (template.orgId && user?.orgId && template.orgId !== user.orgId) return res.status(403).json({ message: "Template access denied" });
      const schedule = await storage.createReportSchedule(data);
      await storage.updateReportSchedule(schedule.id, { nextRunAt });
      const updated = await storage.getReportSchedule(schedule.id);
      res.status(201).json(updated);
    } catch (error: any) {
      if (error.message === "ORG_CONTEXT_MISSING") return res.status(403).json({ message: "Organization context required" });
      res.status(500).json({ message: "Failed to create report schedule" });
    }
  });

  app.patch("/api/report-schedules/:id", isAuthenticated, async (req, res) => {
    const user = req.user as any;
    const existing = await storage.getReportSchedule(p(req.params.id));
    if (!existing) return res.status(404).json({ message: "Schedule not found" });
    if (existing.orgId && user?.orgId && existing.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
    const { id: _id, orgId: _org, ...updateData } = req.body;
    if (updateData.cadence) {
      updateData.nextRunAt = calculateNextRunFromCadence(updateData.cadence);
    }
    const schedule = await storage.updateReportSchedule(p(req.params.id), updateData);
    res.json(schedule);
  });

  app.delete("/api/report-schedules/:id", isAuthenticated, async (req, res) => {
    const user = req.user as any;
    const existing = await storage.getReportSchedule(p(req.params.id));
    if (!existing) return res.status(404).json({ message: "Schedule not found" });
    if (existing.orgId && user?.orgId && existing.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
    await storage.deleteReportSchedule(p(req.params.id));
    res.json({ success: true });
  });

  app.get("/api/report-runs", isAuthenticated, async (req, res) => {
    const user = req.user as any;
    const templateId = req.query.templateId as string | undefined;
    const runs = await storage.getReportRuns(user?.orgId, templateId);
    res.json(runs);
  });

  app.get("/api/report-runs/:id", isAuthenticated, async (req, res) => {
    const run = await storage.getReportRun(p(req.params.id));
    if (!run) return res.status(404).json({ message: "Run not found" });
    const user = req.user as any;
    if (run.orgId && user?.orgId && run.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
    res.json(run);
  });

  app.post("/api/reports/generate", isAuthenticated, async (req, res) => {
    const user = req.user as any;
    const { templateId } = req.body;
    if (!templateId) return res.status(400).json({ message: "templateId is required" });
    try {
      const { runReportOnDemand } = await import("../report-scheduler");
      const result = await runReportOnDemand(templateId, user?.orgId, user?.id);
      res.json(result);
    } catch (err: any) {
      res.status(500).json({ message: err.message });
    }
  });

  app.get("/api/reports/:runId/download", isAuthenticated, async (req, res) => {
    const run = await storage.getReportRun(p(req.params.runId));
    if (!run) return res.status(404).json({ message: "Report run not found" });
    const user = req.user as any;
    if (run.orgId && user?.orgId && run.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
    const template = await storage.getReportTemplate(run.templateId);
    if (!template) return res.status(404).json({ message: "Template not found" });
    try {
      const { generateReportData, formatAsCSV } = await import("../report-engine");
      const data = await generateReportData(template.reportType, run.orgId || undefined);
      if (run.format === "csv") {
        const csv = formatAsCSV(data);
        res.setHeader("Content-Type", "text/csv");
        res.setHeader("Content-Disposition", `attachment; filename="${template.reportType}-report.csv"`);
        return res.send(csv);
      }
      res.json(data);
    } catch (err: any) {
      res.status(500).json({ message: err.message });
    }
  });

  app.get("/api/reports/preview/:reportType", isAuthenticated, async (req, res) => {
    const user = req.user as any;
    try {
      const { generateReportData } = await import("../report-engine");
      const data = await generateReportData(p(req.params.reportType), user?.orgId);
      res.json(data);
    } catch (err: any) {
      res.status(500).json({ message: err.message });
    }
  });

  app.post("/api/report-templates/seed", isAuthenticated, async (req, res) => {
    try {
      const user = req.user as any;
      const orgId = getOrgId(req);
      const allTemplates = await storage.getReportTemplates(undefined);
      if (allTemplates.some(t => t.isBuiltIn && t.orgId === orgId)) {
        return res.json({ message: "Built-in templates already exist for this org", count: allTemplates.filter(t => t.isBuiltIn && t.orgId === orgId).length });
      }
      const builtIns = [
        { name: "Weekly SOC KPI Report", description: "Key performance indicators for SOC operations including alert volumes, response times, and severity distribution", reportType: "soc_kpi", format: "csv", dashboardRole: "soc_manager", isBuiltIn: true, orgId, createdBy: user?.id || null },
        { name: "Incident Summary Report", description: "Detailed listing of all incidents with status, severity, assignees, and resolution metrics", reportType: "incidents", format: "csv", dashboardRole: "analyst", isBuiltIn: true, orgId, createdBy: user?.id || null },
        { name: "MITRE ATT&CK Coverage Report", description: "Analysis of detected attack techniques mapped to the MITRE ATT&CK framework", reportType: "attack_coverage", format: "csv", dashboardRole: "ciso", isBuiltIn: true, orgId, createdBy: user?.id || null },
        { name: "Connector Health Report", description: "Status and performance metrics for all configured data connectors", reportType: "connector_health", format: "csv", dashboardRole: "soc_manager", isBuiltIn: true, orgId, createdBy: user?.id || null },
        { name: "Executive Security Brief", description: "High-level security posture summary for executive leadership including risk trends and key metrics", reportType: "executive_summary", format: "json", dashboardRole: "ciso", isBuiltIn: true, orgId, createdBy: user?.id || null },
        { name: "Compliance Status Report", description: "Compliance framework coverage, data retention status, and DSAR request tracking", reportType: "compliance", format: "csv", dashboardRole: "ciso", isBuiltIn: true, orgId, createdBy: user?.id || null },
      ];
      const created = [];
      for (const t of builtIns) {
        const template = await storage.createReportTemplate(t as any);
        created.push(template);
      }
      res.status(201).json({ message: "Built-in templates created", count: created.length, templates: created });
    } catch (error: any) {
      if (error.message === "ORG_CONTEXT_MISSING") return res.status(403).json({ message: "Organization context required" });
      res.status(500).json({ message: "Failed to seed report templates" });
    }
  });

}

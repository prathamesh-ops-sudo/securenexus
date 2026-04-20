import type { Express, Request, Response } from "express";
import { calculateNextRunFromCadence, formatCSVRow, getOrgId, p, storage } from "./shared";
import { isAuthenticated } from "../auth";
import { insertReportScheduleSchema, insertReportTemplateSchema } from "@shared/schema";
import { resolveOrgContext, requireOrgId, requireMinRole } from "../rbac";
import { enforcePlanLimit } from "../middleware/plan-enforcement";
import { errorMessage, errorStack } from "../utils/errors";

export function registerReportsRoutes(app: Express): void {
  // Export Routes (Phase 10)
  app.get(
    "/api/export/alerts",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const allAlerts = await storage.getAlerts(orgId);
        const csvHeader = formatCSVRow([
          "ID",
          "Title",
          "Severity",
          "Status",
          "Source",
          "Category",
          "MITRE Tactic",
          "MITRE Technique",
          "Source IP",
          "Dest IP",
          "Hostname",
          "Detected At",
          "Created At",
        ]);
        const csvRows = allAlerts
          .map((a) =>
            formatCSVRow([
              a.id,
              a.title,
              a.severity,
              a.status,
              a.source,
              a.category,
              a.mitreTactic,
              a.mitreTechnique,
              a.sourceIp,
              a.destIp,
              a.hostname,
              a.detectedAt?.toISOString(),
              a.createdAt?.toISOString(),
            ]),
          )
          .join("\r\n");
        res.setHeader("Content-Type", "text/csv");
        res.setHeader(
          "Content-Disposition",
          `attachment; filename=securenexus-alerts-${new Date().toISOString().split("T")[0]}.csv`,
        );
        res.send(csvHeader + "\r\n" + csvRows + "\r\n");
      } catch (error) {
        res.status(500).json({ message: "Failed to export alerts" });
      }
    },
  );

  app.get(
    "/api/export/incidents",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const allIncidents = await storage.getIncidents(orgId);
        const csvHeader = formatCSVRow([
          "ID",
          "Title",
          "Severity",
          "Status",
          "Priority",
          "Alert Count",
          "Assigned To",
          "Escalated",
          "MITRE Tactics",
          "Created At",
          "Updated At",
        ]);
        const csvRows = allIncidents
          .map((i) =>
            formatCSVRow([
              i.id,
              i.title,
              i.severity,
              i.status,
              i.priority,
              i.alertCount ?? 0,
              i.assignedTo,
              i.escalated ? "Yes" : "No",
              (i.mitreTactics || []).join("; "),
              i.createdAt?.toISOString(),
              i.updatedAt?.toISOString(),
            ]),
          )
          .join("\r\n");
        res.setHeader("Content-Type", "text/csv");
        res.setHeader(
          "Content-Disposition",
          `attachment; filename=securenexus-incidents-${new Date().toISOString().split("T")[0]}.csv`,
        );
        res.send(csvHeader + "\r\n" + csvRows + "\r\n");
      } catch (error) {
        res.status(500).json({ message: "Failed to export incidents" });
      }
    },
  );

  app.get(
    "/api/export/incident/:id/report",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const incident = await storage.getIncident(p(req.params.id));
        if (!incident || incident.orgId !== orgId) return res.status(404).json({ message: "Incident not found" });
        const incidentAlerts = await storage.getAlertsByIncident(incident.id);
        const comments = await storage.getComments(incident.id);
        const report = {
          generatedAt: new Date().toISOString(),
          incident: { ...incident, alerts: incidentAlerts, comments },
        };
        res.json(report);
      } catch (error) {
        res.status(500).json({ message: "Failed to generate report" });
      }
    },
  );

  app.get(
    "/api/report-templates",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      const user = req.user as any;
      const templates = await storage.getReportTemplates(user?.orgId);
      res.json(templates);
    },
  );

  app.get(
    "/api/report-templates/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      const orgId = getOrgId(req);
      const template = await storage.getReportTemplate(p(req.params.id));
      if (!template || template.orgId !== orgId) return res.status(404).json({ message: "Template not found" });
      res.json(template);
    },
  );

  app.post(
    "/api/report-templates",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    enforcePlanLimit("reports"),
    async (req, res) => {
      try {
        const user = req.user as any;
        const orgId = getOrgId(req);
        const data = insertReportTemplateSchema.parse({ ...req.body, orgId, createdBy: user?.id || null });
        const template = await storage.createReportTemplate(data);
        res.status(201).json(template);
      } catch (error: unknown) {
        if (errorMessage(error) === "ORG_CONTEXT_MISSING")
          return res.status(403).json({ message: "Organization context required" });
        res.status(500).json({ message: "Failed to create report template" });
      }
    },
  );

  app.patch(
    "/api/report-templates/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      const orgId = getOrgId(req);
      const existing = await storage.getReportTemplate(p(req.params.id));
      if (!existing || existing.orgId !== orgId) return res.status(404).json({ message: "Template not found" });
      const { id: _id, orgId: _org, ...updateData } = req.body;
      const template = await storage.updateReportTemplate(p(req.params.id), updateData);
      res.json(template);
    },
  );

  app.delete(
    "/api/report-templates/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      const orgId = getOrgId(req);
      const existing = await storage.getReportTemplate(p(req.params.id));
      if (!existing || existing.orgId !== orgId) return res.status(404).json({ message: "Template not found" });
      await storage.deleteReportTemplate(p(req.params.id));
      res.json({ success: true });
    },
  );

  app.get(
    "/api/report-schedules",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      const user = req.user as any;
      const schedules = await storage.getReportSchedules(user?.orgId);
      res.json(schedules);
    },
  );

  app.get(
    "/api/report-schedules/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      const orgId = getOrgId(req);
      const schedule = await storage.getReportSchedule(p(req.params.id));
      if (!schedule || schedule.orgId !== orgId) return res.status(404).json({ message: "Schedule not found" });
      res.json(schedule);
    },
  );

  app.post(
    "/api/report-schedules",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const user = req.user as any;
        const cadence = req.body.cadence || "weekly";
        const nextRunAt = calculateNextRunFromCadence(cadence);
        const orgId = getOrgId(req);
        const data = insertReportScheduleSchema.parse({ ...req.body, orgId, createdBy: user?.id || null });
        const template = await storage.getReportTemplate(data.templateId);
        if (!template || template.orgId !== orgId) return res.status(404).json({ message: "Template not found" });
        const schedule = await storage.createReportSchedule(data);
        await storage.updateReportSchedule(schedule.id, { nextRunAt });
        const updated = await storage.getReportSchedule(schedule.id);
        res.status(201).json(updated);
      } catch (error: unknown) {
        if (errorMessage(error) === "ORG_CONTEXT_MISSING")
          return res.status(403).json({ message: "Organization context required" });
        res.status(500).json({ message: "Failed to create report schedule" });
      }
    },
  );

  app.patch(
    "/api/report-schedules/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      const orgId = getOrgId(req);
      const existing = await storage.getReportSchedule(p(req.params.id));
      if (!existing || existing.orgId !== orgId) return res.status(404).json({ message: "Schedule not found" });
      const { id: _id, orgId: _org, ...updateData } = req.body;
      if (updateData.cadence) {
        updateData.nextRunAt = calculateNextRunFromCadence(updateData.cadence);
      }
      const schedule = await storage.updateReportSchedule(p(req.params.id), updateData);
      res.json(schedule);
    },
  );

  app.delete(
    "/api/report-schedules/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      const orgId = getOrgId(req);
      const existing = await storage.getReportSchedule(p(req.params.id));
      if (!existing || existing.orgId !== orgId) return res.status(404).json({ message: "Schedule not found" });
      await storage.deleteReportSchedule(p(req.params.id));
      res.json({ success: true });
    },
  );

  app.get(
    "/api/report-runs",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      const user = req.user as any;
      const templateId = req.query.templateId as string | undefined;
      const runs = await storage.getReportRuns(user?.orgId, templateId);
      res.json(runs);
    },
  );

  app.get(
    "/api/report-runs/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      const orgId = getOrgId(req);
      const run = await storage.getReportRun(p(req.params.id));
      if (!run || run.orgId !== orgId) return res.status(404).json({ message: "Run not found" });
      res.json(run);
    },
  );

  app.post(
    "/api/reports/generate",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      const user = req.user as any;
      const { templateId } = req.body;
      if (!templateId) return res.status(400).json({ message: "templateId is required" });
      try {
        const { runReportOnDemand } = await import("../report-scheduler");
        const result = await runReportOnDemand(templateId, user?.orgId, user?.id);
        res.json(result);
      } catch (err: unknown) {
        res.status(500).json({ message: errorMessage(err) });
      }
    },
  );

  app.get(
    "/api/reports/:runId/download",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      const orgId = getOrgId(req);
      const run = await storage.getReportRun(p(req.params.runId));
      if (!run || run.orgId !== orgId) return res.status(404).json({ message: "Report run not found" });
      const template = await storage.getReportTemplate(run.templateId);
      if (!template) return res.status(404).json({ message: "Template not found" });
      try {
        const { generateReportData, formatAsCSV } = await import("../report-engine");
        const data = await generateReportData(template.reportType, run.orgId || undefined);
        if (run.format === "pdf") {
          const { generatePdfReport, CONFIDENTIAL_REPORT_TYPES } = await import("../report-pdf");
          const isConfidential = CONFIDENTIAL_REPORT_TYPES.includes(template.reportType);
          const pdf = await generatePdfReport(data, {
            confidential: isConfidential,
            orgName: "Arica Tech Solutions",
            generatedBy: (req.user as any)?.email || "System",
          });
          res.setHeader("Content-Type", "application/pdf");
          res.setHeader("Content-Disposition", `attachment; filename="${template.reportType}-report.pdf"`);
          return res.send(pdf);
        }
        if (run.format === "csv") {
          const csv = formatAsCSV(data);
          res.setHeader("Content-Type", "text/csv");
          res.setHeader("Content-Disposition", `attachment; filename="${template.reportType}-report.csv"`);
          return res.send(csv);
        }
        res.json(data);
      } catch (err: unknown) {
        res.status(500).json({ message: errorMessage(err) });
      }
    },
  );

  app.get(
    "/api/reports/preview/:reportType",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      const user = req.user as any;
      try {
        const { generateReportData } = await import("../report-engine");
        const data = await generateReportData(p(req.params.reportType), user?.orgId);
        res.json(data);
      } catch (err: unknown) {
        res.status(500).json({ message: errorMessage(err) });
      }
    },
  );

  app.post(
    "/api/report-templates/seed",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const user = req.user as any;
        const orgId = getOrgId(req);
        const allTemplates = await storage.getReportTemplates(undefined);
        if (allTemplates.some((t) => t.isBuiltIn && t.orgId === orgId)) {
          return res.json({
            message: "Built-in templates already exist for this org",
            count: allTemplates.filter((t) => t.isBuiltIn && t.orgId === orgId).length,
          });
        }
        const builtIns = [
          {
            name: "Weekly SOC KPI Report",
            description:
              "Key performance indicators for SOC operations including alert volumes, response times, and severity distribution",
            reportType: "soc_kpi",
            format: "pdf",
            dashboardRole: "soc_manager",
            isBuiltIn: true,
            orgId,
            createdBy: user?.id || null,
          },
          {
            name: "Incident Summary Report",
            description: "Detailed listing of all incidents with status, severity, assignees, and resolution metrics",
            reportType: "incidents",
            format: "pdf",
            dashboardRole: "analyst",
            isBuiltIn: true,
            orgId,
            createdBy: user?.id || null,
          },
          {
            name: "MITRE ATT&CK Coverage Report",
            description: "Analysis of detected attack techniques mapped to the MITRE ATT&CK framework",
            reportType: "attack_coverage",
            format: "pdf",
            dashboardRole: "ciso",
            isBuiltIn: true,
            orgId,
            createdBy: user?.id || null,
          },
          {
            name: "Connector Health Report",
            description: "Status and performance metrics for all configured data connectors",
            reportType: "connector_health",
            format: "pdf",
            dashboardRole: "soc_manager",
            isBuiltIn: true,
            orgId,
            createdBy: user?.id || null,
          },
          {
            name: "Executive Security Brief",
            description:
              "High-level security posture summary for executive leadership including risk trends and key metrics",
            reportType: "executive_summary",
            format: "pdf",
            dashboardRole: "ciso",
            isBuiltIn: true,
            orgId,
            createdBy: user?.id || null,
          },
          {
            name: "Compliance Status Report",
            description: "Compliance framework coverage, data retention status, and DSAR request tracking",
            reportType: "compliance",
            format: "pdf",
            dashboardRole: "ciso",
            isBuiltIn: true,
            orgId,
            createdBy: user?.id || null,
          },
        ];
        const created = [];
        for (const t of builtIns) {
          const template = await storage.createReportTemplate(t as any);
          created.push(template);
        }
        res.status(201).json({ message: "Built-in templates created", count: created.length, templates: created });
      } catch (error: unknown) {
        if (errorMessage(error) === "ORG_CONTEXT_MISSING")
          return res.status(403).json({ message: "Organization context required" });
        res.status(500).json({ message: "Failed to seed report templates" });
      }
    },
  );
}

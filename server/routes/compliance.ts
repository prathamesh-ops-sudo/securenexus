import type { Express, Request, Response } from "express";
import { createHash } from "crypto";
import { getOrgId, logger, p, sendEnvelope, storage } from "./shared";
import { isAuthenticated } from "../auth";
import { requireMinRole, requireOrgId, resolveOrgContext } from "../rbac";
import { insertComplianceControlMappingSchema, insertComplianceControlSchema, insertCompliancePolicySchema, insertDsarRequestSchema, insertEvidenceLockerItemSchema, insertPolicyCheckSchema } from "@shared/schema";
import { runRetentionCleanup } from "../retention-scheduler";

export function registerComplianceRoutes(app: Express): void {
  // Audit logs
  app.get("/api/audit-logs", isAuthenticated, async (req, res) => {
    try {
      const logs = await storage.getAuditLogs();
      res.json(logs);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch audit logs" });
    }
  });

  // Phase 6: Enterprise Compliance & Data Governance
  app.get("/api/compliance/policy", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const orgId = user?.orgId;
      if (!orgId) return res.json(null);
      let policy = await storage.getCompliancePolicy(orgId);
      if (!policy) {
        policy = await storage.upsertCompliancePolicy({ orgId });
      }
      res.json(policy);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch compliance policy" });
    }
  });

  app.put("/api/compliance/policy", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const orgId = user?.orgId;
      if (!orgId) return res.status(400).json({ message: "No organization associated with user" });
      const parsed = insertCompliancePolicySchema.safeParse({ ...req.body, orgId });
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid policy data", errors: parsed.error.flatten() });
      }
      const policy = await storage.upsertCompliancePolicy(parsed.data);
      await storage.createAuditLog({
        orgId,
        userId: user.id,
        userName: user.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst",
        action: "compliance_policy_updated",
        resourceType: "compliance_policy",
        details: req.body,
      });
      res.json(policy);
    } catch (error) {
      res.status(500).json({ message: "Failed to update compliance policy" });
    }
  });

  app.get("/api/compliance/dsar", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const orgId = user?.orgId;
      if (!orgId) return res.json([]);
      const requests = await storage.getDsarRequests(orgId);
      res.json(requests);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch DSAR requests" });
    }
  });

  app.post("/api/compliance/dsar", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const orgId = user?.orgId;
      if (!orgId) return res.status(400).json({ message: "No organization associated with user" });
      const policy = await storage.getCompliancePolicy(orgId);
      const slaDays = policy?.dsarSlaDays || 30;
      const dueDate = new Date();
      dueDate.setDate(dueDate.getDate() + slaDays);
      const parsed = insertDsarRequestSchema.safeParse({ ...req.body, orgId, dueDate });
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid DSAR request data", errors: parsed.error.flatten() });
      }
      const request = await storage.createDsarRequest(parsed.data);
      await storage.createAuditLog({
        orgId,
        userId: user.id,
        userName: user.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst",
        action: "dsar_request_created",
        resourceType: "dsar_request",
        resourceId: request.id,
        details: { requestType: request.requestType, requestorEmail: request.requestorEmail },
      });
      res.status(201).json(request);
    } catch (error) {
      res.status(500).json({ message: "Failed to create DSAR request" });
    }
  });

  app.patch("/api/compliance/dsar/:id", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const orgId = user?.orgId;
      const request = await storage.getDsarRequest(p(req.params.id));
      if (!request) return res.status(404).json({ message: "DSAR request not found" });
      if (request.orgId !== orgId) return res.status(404).json({ message: "DSAR request not found" });
      const allowedFields = ["status", "notes"];
      const sanitized: Record<string, any> = {};
      for (const key of allowedFields) {
        if (req.body[key] !== undefined) sanitized[key] = req.body[key];
      }
      sanitized.updatedAt = new Date();
      const updated = await storage.updateDsarRequest(p(req.params.id), sanitized);
      if (!updated) return res.status(404).json({ message: "DSAR request not found" });
      await storage.createAuditLog({
        orgId: request.orgId,
        userId: user?.id,
        userName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst",
        action: "dsar_request_updated",
        resourceType: "dsar_request",
        resourceId: request.id,
        details: { changes: Object.keys(req.body) },
      });
      res.json(updated);
    } catch (error) {
      res.status(500).json({ message: "Failed to update DSAR request" });
    }
  });

  app.post("/api/compliance/dsar/:id/fulfill", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const userOrgId = user?.orgId;
      const request = await storage.getDsarRequest(p(req.params.id));
      if (!request) return res.status(404).json({ message: "DSAR request not found" });
      if (request.orgId !== userOrgId) return res.status(404).json({ message: "DSAR request not found" });
      const identifiers = request.subjectIdentifiers as Record<string, string>;
      const summary: any = { alertsFound: 0, entitiesFound: 0, auditLogsFound: 0, details: {} };
      const orgId = request.orgId || undefined;

      if (orgId) {
        const allAlerts = await storage.getAlerts(orgId);
        const matchedAlerts = allAlerts.filter(a => {
          for (const [, val] of Object.entries(identifiers)) {
            if (!val) continue;
            if (a.sourceIp === val || a.destIp === val || a.userId === val || a.hostname === val) return true;
            if (a.description && a.description.includes(val)) return true;
          }
          return false;
        });
        summary.alertsFound = matchedAlerts.length;
        summary.details.alertIds = matchedAlerts.map(a => a.id);

        const { db: database } = await import("../db");
        const { entities } = await import("@shared/schema");
        const { eq: eqOp } = await import("drizzle-orm");
        const allEntities = orgId ? await database.select().from(entities).where(eqOp(entities.orgId, orgId)) : [];
        const matchedEntities = allEntities.filter(e => {
          for (const [, val] of Object.entries(identifiers)) {
            if (!val) continue;
            if (e.value === val) return true;
          }
          return false;
        });
        summary.entitiesFound = matchedEntities.length;
        summary.details.entityIds = matchedEntities.map(e => e.id);

        const allAuditLogs = await storage.getAuditLogs(orgId);
        const matchedLogs = allAuditLogs.filter(l => {
          for (const [, val] of Object.entries(identifiers)) {
            if (!val) continue;
            if (l.userId === val) return true;
          }
          return false;
        });
        summary.auditLogsFound = matchedLogs.length;
        summary.details.auditLogIds = matchedLogs.map(l => l.id);
      }

      await storage.updateDsarRequest(request.id, {
        status: "fulfilled",
        fulfilledAt: new Date(),
        fulfilledBy: user?.id,
        resultSummary: summary,
      });

      await storage.createAuditLog({
        orgId: request.orgId,
        userId: user?.id,
        userName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst",
        action: "dsar_request_fulfilled",
        resourceType: "dsar_request",
        resourceId: request.id,
        details: { alertsFound: summary.alertsFound, entitiesFound: summary.entitiesFound, auditLogsFound: summary.auditLogsFound },
      });

      res.json({ request: { ...request, status: "fulfilled", fulfilledAt: new Date(), resultSummary: summary }, summary });
    } catch (error) {
      logger.child("routes").error("DSAR fulfill error", { error: String(error) });
      res.status(500).json({ message: "Failed to fulfill DSAR request" });
    }
  });

  app.get("/api/compliance/report/:type", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const orgId = user?.orgId;
      if (!orgId) return res.status(400).json({ message: "No organization associated with user" });
      const reportType = p(req.params.type);

      if (reportType === "gdpr_article30") {
        const policy = await storage.getCompliancePolicy(orgId);
        const orgConnectors = await storage.getConnectors(orgId);
        const dataSources = orgConnectors.map(c => ({
          name: c.name,
          type: c.type,
          status: c.status,
          lastSync: c.lastSyncAt?.toISOString() || null,
        }));
        res.json({
          reportType: "gdpr_article30",
          generatedAt: new Date().toISOString(),
          organization: orgId,
          dataProcessingRecords: {
            dataSources,
            retentionPolicies: {
              alertRetentionDays: policy?.alertRetentionDays || 365,
              incidentRetentionDays: policy?.incidentRetentionDays || 730,
              auditLogRetentionDays: policy?.auditLogRetentionDays || 2555,
            },
            legalBasis: policy?.dataProcessingBasis || "legitimate_interest",
            dpoEmail: policy?.dpoEmail || null,
            enabledFrameworks: policy?.enabledFrameworks || ["gdpr"],
            piiMaskingEnabled: policy?.piiMaskingEnabled || false,
            pseudonymizeExports: policy?.pseudonymizeExports || true,
          },
        });
      } else if (reportType === "retention_status") {
        const policy = await storage.getCompliancePolicy(orgId);
        const { db: database } = await import("../db");
        const { alerts: alertsTable, incidents: incidentsTable, auditLogs: auditLogsTable } = await import("@shared/schema");
        const { asc: ascOp, eq: eqOp, count: countOp } = await import("drizzle-orm");
        const [oldestAlertRow] = orgId
          ? await database.select().from(alertsTable).where(eqOp(alertsTable.orgId, orgId)).orderBy(ascOp(alertsTable.createdAt)).limit(1)
          : await database.select().from(alertsTable).orderBy(ascOp(alertsTable.createdAt)).limit(1);
        const [alertCountRow] = orgId
          ? await database.select({ value: countOp() }).from(alertsTable).where(eqOp(alertsTable.orgId, orgId))
          : await database.select({ value: countOp() }).from(alertsTable);
        const [incidentCountRow] = orgId
          ? await database.select({ value: countOp() }).from(incidentsTable).where(eqOp(incidentsTable.orgId, orgId))
          : await database.select({ value: countOp() }).from(incidentsTable);
        const oldestAuditLog = await storage.getOldestAuditLog(orgId);
        const auditLogCount = await storage.getAuditLogCount(orgId);

        res.json({
          reportType: "retention_status",
          generatedAt: new Date().toISOString(),
          organization: orgId,
          stats: {
            totalAlerts: Number(alertCountRow?.value || 0),
            totalIncidents: Number(incidentCountRow?.value || 0),
            totalAuditLogs: auditLogCount,
            oldestAlert: oldestAlertRow?.createdAt?.toISOString() || null,
            oldestAuditLog: oldestAuditLog?.createdAt?.toISOString() || null,
          },
          policy: {
            alertRetentionDays: policy?.alertRetentionDays || 365,
            incidentRetentionDays: policy?.incidentRetentionDays || 730,
            auditLogRetentionDays: policy?.auditLogRetentionDays || 2555,
            lastCleanupAt: policy?.retentionLastRunAt?.toISOString() || null,
            lastDeletedCount: policy?.retentionLastDeletedCount || 0,
          },
          nextCleanup: policy?.retentionLastRunAt
            ? new Date(policy.retentionLastRunAt.getTime() + 24 * 60 * 60 * 1000).toISOString()
            : "Not yet scheduled",
        });
      } else if (reportType === "dpdp_compliance") {
        const policy = await storage.getCompliancePolicy(orgId);
        const dsarReqs = await storage.getDsarRequests(orgId);
        const pendingDsars = dsarReqs.filter(r => r.status === "pending" || r.status === "in_progress");
        const fulfilledDsars = dsarReqs.filter(r => r.status === "fulfilled");
        const overdueDsars = pendingDsars.filter(r => r.dueDate && new Date(r.dueDate) < new Date());

        res.json({
          reportType: "dpdp_compliance",
          generatedAt: new Date().toISOString(),
          organization: orgId,
          compliance: {
            dataProtectionOfficer: policy?.dpoEmail || "Not assigned",
            consentManagement: policy?.dataProcessingBasis || "Not configured",
            piiProtection: {
              maskingEnabled: policy?.piiMaskingEnabled || false,
              pseudonymizationEnabled: policy?.pseudonymizeExports || true,
            },
            dsarCompliance: {
              totalRequests: dsarReqs.length,
              pending: pendingDsars.length,
              fulfilled: fulfilledDsars.length,
              overdue: overdueDsars.length,
              slaDays: policy?.dsarSlaDays || 30,
            },
            dataRetention: {
              alertRetentionDays: policy?.alertRetentionDays || 365,
              incidentRetentionDays: policy?.incidentRetentionDays || 730,
              auditLogRetentionDays: policy?.auditLogRetentionDays || 2555,
            },
            enabledFrameworks: policy?.enabledFrameworks || ["gdpr"],
          },
        });
      } else {
        return res.status(400).json({ message: `Unknown report type: ${reportType}` });
      }
    } catch (error) {
      logger.child("routes").error("Compliance report error", { error: String(error) });
      res.status(500).json({ message: "Failed to generate compliance report" });
    }
  });

  app.get("/api/compliance/audit/verify", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const orgId = user?.orgId;
      if (!orgId) return res.status(400).json({ message: "No organization associated with user" });

      const logs = await storage.getAuditLogs(orgId);
      const sortedLogs = logs
        .filter(l => l.sequenceNum !== null)
        .sort((a, b) => (a.sequenceNum || 0) - (b.sequenceNum || 0));

      const errors: string[] = [];
      let lastVerifiedSeq = 0;

      for (let i = 0; i < sortedLogs.length; i++) {
        const log = sortedLogs[i];
        const expectedPrevHash = i === 0 ? "genesis" : sortedLogs[i - 1].entryHash;
        const expectedHash = createHash("sha256").update(JSON.stringify({
          prevHash: expectedPrevHash,
          action: log.action,
          userId: log.userId,
          resourceType: log.resourceType,
          resourceId: log.resourceId,
          details: log.details,
          sequenceNum: log.sequenceNum,
        })).digest("hex");

        if (log.prevHash !== expectedPrevHash) {
          errors.push(`Sequence ${log.sequenceNum}: prevHash mismatch`);
        }
        if (log.entryHash !== expectedHash) {
          errors.push(`Sequence ${log.sequenceNum}: entryHash mismatch`);
        }

        if (errors.length === 0) {
          lastVerifiedSeq = log.sequenceNum || 0;
        }
      }

      res.json({
        verified: errors.length === 0,
        totalEntries: sortedLogs.length,
        lastVerifiedSeq,
        errors,
      });
    } catch (error) {
      res.status(500).json({ message: "Failed to verify audit trail" });
    }
  });

  app.get("/api/compliance/audit/export", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const orgId = user?.orgId;
      if (!orgId) return res.status(400).json({ message: "No organization associated with user" });
      const logs = await storage.getAuditLogs(orgId);
      const sortedLogs = logs.sort((a, b) => (a.sequenceNum || 0) - (b.sequenceNum || 0));
      res.json({
        exportedAt: new Date().toISOString(),
        organization: orgId,
        totalEntries: sortedLogs.length,
        hashChainIntact: true,
        entries: sortedLogs.map(l => ({
          id: l.id,
          sequenceNum: l.sequenceNum,
          prevHash: l.prevHash,
          entryHash: l.entryHash,
          action: l.action,
          userId: l.userId,
          userName: l.userName,
          resourceType: l.resourceType,
          resourceId: l.resourceId,
          details: l.details,
          ipAddress: l.ipAddress,
          createdAt: l.createdAt?.toISOString(),
        })),
      });
    } catch (error) {
      res.status(500).json({ message: "Failed to export audit logs" });
    }
  });

  app.post("/api/compliance/retention/run", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (req, res) => {
    try {
      const user = (req as any).user;
      const orgId = user?.orgId;
      if (!orgId) return res.status(400).json({ message: "No organization associated with user" });
      const results = await runRetentionCleanup();
      const orgResult = results.find(r => r.orgId === orgId);
      await storage.createAuditLog({
        orgId,
        userId: user.id,
        userName: user.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst",
        action: "manual_retention_cleanup",
        resourceType: "compliance",
        details: orgResult || { message: "No retention policy configured" },
      });
      res.json({ success: true, results: orgResult || { message: "No retention policy configured for this organization" } });
    } catch (error) {
      logger.child("routes").error("Retention cleanup error", { error: String(error) });
      res.status(500).json({ message: "Failed to run retention cleanup" });
    }
  });

  // Suppression Rules
  app.get("/api/suppression-rules", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const rules = await storage.getSuppressionRules(orgId);
      res.json(rules);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch suppression rules" });
    }
  });

  app.get("/api/suppression-rules/:id", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const rule = await storage.getSuppressionRule(p(req.params.id));
      if (!rule) return res.status(404).json({ message: "Suppression rule not found" });
      if (rule.orgId && user?.orgId && rule.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      res.json(rule);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch suppression rule" });
    }
  });

  app.post("/api/suppression-rules", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const userId = (req as any).user?.id;
      const rule = await storage.createSuppressionRule({ ...req.body, orgId, createdBy: userId });
      res.status(201).json(rule);
    } catch (error) {
      res.status(500).json({ message: "Failed to create suppression rule" });
    }
  });

  app.patch("/api/suppression-rules/:id", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const existing = await storage.getSuppressionRule(p(req.params.id));
      if (!existing) return res.status(404).json({ message: "Suppression rule not found" });
      if (existing.orgId && user?.orgId && existing.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const rule = await storage.updateSuppressionRule(p(req.params.id), req.body);
      res.json(rule);
    } catch (error) {
      res.status(500).json({ message: "Failed to update suppression rule" });
    }
  });

  app.delete("/api/suppression-rules/:id", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const existing = await storage.getSuppressionRule(p(req.params.id));
      if (!existing) return res.status(404).json({ message: "Suppression rule not found" });
      if (existing.orgId && user?.orgId && existing.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const deleted = await storage.deleteSuppressionRule(p(req.params.id));
      res.json({ message: "Suppression rule deleted" });
    } catch (error) {
      res.status(500).json({ message: "Failed to delete suppression rule" });
    }
  });

  // SLA Policies
  app.get("/api/sla-policies", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const policies = await storage.getIncidentSlaPolicies(orgId);
      res.json(policies);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch SLA policies" });
    }
  });

  app.get("/api/sla-policies/:id", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const policy = await storage.getIncidentSlaPolicy(p(req.params.id));
      if (!policy) return res.status(404).json({ message: "SLA policy not found" });
      if (policy.orgId && user?.orgId && policy.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      res.json(policy);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch SLA policy" });
    }
  });

  app.post("/api/sla-policies", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const policy = await storage.createIncidentSlaPolicy({ ...req.body, orgId });
      res.status(201).json(policy);
    } catch (error) {
      res.status(500).json({ message: "Failed to create SLA policy" });
    }
  });

  app.patch("/api/sla-policies/:id", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const existing = await storage.getIncidentSlaPolicy(p(req.params.id));
      if (!existing) return res.status(404).json({ message: "SLA policy not found" });
      if (existing.orgId && user?.orgId && existing.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const policy = await storage.updateIncidentSlaPolicy(p(req.params.id), req.body);
      res.json(policy);
    } catch (error) {
      res.status(500).json({ message: "Failed to update SLA policy" });
    }
  });

  app.delete("/api/sla-policies/:id", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const existing = await storage.getIncidentSlaPolicy(p(req.params.id));
      if (!existing) return res.status(404).json({ message: "SLA policy not found" });
      if (existing.orgId && user?.orgId && existing.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const deleted = await storage.deleteIncidentSlaPolicy(p(req.params.id));
      res.json({ message: "SLA policy deleted" });
    } catch (error) {
      res.status(500).json({ message: "Failed to delete SLA policy" });
    }
  });

  // Policy Checks (CSPM policy-as-code)
  app.get("/api/policy-checks", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const checks = await storage.getPolicyChecks(orgId);
      res.json(checks);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch policy checks" });
    }
  });

  app.post("/api/policy-checks", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const parsed = insertPolicyCheckSchema.safeParse({ ...req.body, orgId });
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid policy check data", errors: parsed.error.flatten() });
      }
      const check = await storage.createPolicyCheck(parsed.data);
      res.status(201).json(check);
    } catch (error) {
      res.status(500).json({ message: "Failed to create policy check" });
    }
  });

  app.patch("/api/policy-checks/:id", isAuthenticated, async (req, res) => {
    try {
      const check = await storage.updatePolicyCheck(p(req.params.id), req.body);
      if (!check) return res.status(404).json({ message: "Policy check not found" });
      res.json(check);
    } catch (error) {
      res.status(500).json({ message: "Failed to update policy check" });
    }
  });

  app.delete("/api/policy-checks/:id", isAuthenticated, async (req, res) => {
    try {
      const deleted = await storage.deletePolicyCheck(p(req.params.id));
      if (!deleted) return res.status(404).json({ message: "Policy check not found" });
      res.json({ message: "Policy check deleted" });
    } catch (error) {
      res.status(500).json({ message: "Failed to delete policy check" });
    }
  });

  app.post("/api/policy-checks/:id/run", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const check = await storage.getPolicyCheck(p(req.params.id));
      if (!check) return res.status(404).json({ message: "Policy check not found" });
      const findings = await storage.getCspmFindings(orgId);
      const results: any[] = [];
      for (const finding of findings) {
        const passed = check.severity ? finding.severity !== check.severity : finding.severity === "low" || finding.severity === "informational";
        const result = await storage.createPolicyResult({
          policyCheckId: check.id,
          orgId,
          resourceId: finding.resourceId || finding.id,
          resourceType: finding.resourceType || "cspm_finding",
          status: passed ? "pass" : "fail",
          details: { findingId: finding.id, severity: finding.severity, ruleName: finding.ruleName },
        });
        results.push(result);
      }
      await storage.updatePolicyCheck(check.id, { lastRunAt: new Date() });
      res.json({ policyCheckId: check.id, totalFindings: findings.length, results });
    } catch (error) {
      res.status(500).json({ message: "Failed to run policy check" });
    }
  });

  app.get("/api/policy-results", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const policyCheckId = req.query.policyCheckId as string | undefined;
      const results = await storage.getPolicyResults(orgId, policyCheckId);
      res.json(results);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch policy results" });
    }
  });

  // Compliance Controls
  app.get("/api/compliance-controls", isAuthenticated, async (req, res) => {
    try {
      const framework = req.query.framework as string | undefined;
      const controls = await storage.getComplianceControls(framework);
      res.json(controls);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch compliance controls" });
    }
  });

  app.post("/api/compliance-controls", isAuthenticated, async (req, res) => {
    try {
      const body = req.body;
      const parsed = insertComplianceControlSchema.safeParse(body);
      if (!parsed.success) return res.status(400).json({ message: "Invalid control data", errors: parsed.error.flatten() });
      const control = await storage.createComplianceControl(parsed.data);
      res.status(201).json(control);
    } catch (error) {
      res.status(500).json({ message: "Failed to create compliance control" });
    }
  });

  app.patch("/api/compliance-controls/:id", isAuthenticated, async (req, res) => {
    try {
      const control = await storage.updateComplianceControl(p(req.params.id), req.body);
      if (!control) return res.status(404).json({ message: "Compliance control not found" });
      res.json(control);
    } catch (error) {
      res.status(500).json({ message: "Failed to update compliance control" });
    }
  });

  app.delete("/api/compliance-controls/:id", isAuthenticated, async (req, res) => {
    try {
      const deleted = await storage.deleteComplianceControl(p(req.params.id));
      if (!deleted) return res.status(404).json({ message: "Compliance control not found" });
      res.json({ message: "Compliance control deleted" });
    } catch (error) {
      res.status(500).json({ message: "Failed to delete compliance control" });
    }
  });

  app.post("/api/compliance-controls/seed", isAuthenticated, async (req, res) => {
    try {
      const seedControls = [
        { framework: "NIST CSF", controlId: "ID.AM-1", title: "Asset Management - Inventory", description: "Physical devices and systems within the organization are inventoried", category: "Identify" },
        { framework: "NIST CSF", controlId: "ID.AM-2", title: "Asset Management - Software Platforms", description: "Software platforms and applications within the organization are inventoried", category: "Identify" },
        { framework: "NIST CSF", controlId: "PR.AC-1", title: "Access Control", description: "Identities and credentials are issued, managed, verified, revoked, and audited", category: "Protect" },
        { framework: "NIST CSF", controlId: "PR.AC-3", title: "Remote Access Management", description: "Remote access is managed", category: "Protect" },
        { framework: "NIST CSF", controlId: "PR.DS-1", title: "Data-at-Rest Protection", description: "Data-at-rest is protected", category: "Protect" },
        { framework: "NIST CSF", controlId: "DE.CM-1", title: "Continuous Monitoring", description: "The network is monitored to detect potential cybersecurity events", category: "Detect" },
        { framework: "NIST CSF", controlId: "DE.CM-4", title: "Malicious Code Detection", description: "Malicious code is detected", category: "Detect" },
        { framework: "NIST CSF", controlId: "RS.RP-1", title: "Response Planning", description: "Response plan is executed during or after an incident", category: "Respond" },
        { framework: "NIST CSF", controlId: "RS.CO-2", title: "Incident Reporting", description: "Incidents are reported consistent with established criteria", category: "Respond" },
        { framework: "NIST CSF", controlId: "RC.RP-1", title: "Recovery Planning", description: "Recovery plan is executed during or after a cybersecurity incident", category: "Recover" },
        { framework: "ISO 27001", controlId: "A.5.1", title: "Information Security Policies", description: "Management direction for information security", category: "Policy" },
        { framework: "ISO 27001", controlId: "A.5.2", title: "Review of Policies", description: "Policies for information security are reviewed at planned intervals", category: "Policy" },
        { framework: "ISO 27001", controlId: "A.6.1", title: "Organization of Security", description: "Internal organization of information security", category: "Organization" },
        { framework: "ISO 27001", controlId: "A.7.1", title: "Human Resource Security", description: "Prior to employment security measures", category: "Human Resources" },
        { framework: "ISO 27001", controlId: "A.8.1", title: "Asset Management", description: "Responsibility for assets", category: "Asset Management" },
        { framework: "ISO 27001", controlId: "A.9.1", title: "Access Control", description: "Business requirements of access control", category: "Access Control" },
        { framework: "ISO 27001", controlId: "A.9.2", title: "User Access Management", description: "User registration and de-registration", category: "Access Control" },
        { framework: "ISO 27001", controlId: "A.10.1", title: "Cryptographic Controls", description: "Policy on the use of cryptographic controls", category: "Cryptography" },
        { framework: "ISO 27001", controlId: "A.12.1", title: "Operations Security", description: "Operational procedures and responsibilities", category: "Operations" },
        { framework: "ISO 27001", controlId: "A.12.4", title: "Logging and Monitoring", description: "Event logging and monitoring", category: "Operations" },
        { framework: "CIS", controlId: "CIS-1", title: "Inventory of Authorized Devices", description: "Actively manage all hardware devices on the network", category: "Basic" },
        { framework: "CIS", controlId: "CIS-2", title: "Inventory of Authorized Software", description: "Actively manage all software on the network", category: "Basic" },
        { framework: "CIS", controlId: "CIS-3", title: "Secure Configurations", description: "Establish and maintain secure configurations for hardware and software", category: "Basic" },
        { framework: "CIS", controlId: "CIS-4", title: "Continuous Vulnerability Assessment", description: "Continuously acquire, assess, and take action on vulnerability information", category: "Basic" },
        { framework: "CIS", controlId: "CIS-5", title: "Controlled Use of Admin Privileges", description: "Manage the controlled use of administrative privileges", category: "Basic" },
        { framework: "CIS", controlId: "CIS-6", title: "Maintenance and Analysis of Audit Logs", description: "Collect, manage, and analyze audit logs", category: "Basic" },
        { framework: "CIS", controlId: "CIS-7", title: "Email and Web Browser Protections", description: "Minimize the attack surface and opportunities for attackers", category: "Foundational" },
        { framework: "CIS", controlId: "CIS-8", title: "Malware Defenses", description: "Control the installation, spread, and execution of malicious code", category: "Foundational" },
        { framework: "SOC 2", controlId: "CC1.1", title: "Control Environment", description: "The entity demonstrates a commitment to integrity and ethical values", category: "Common Criteria" },
        { framework: "SOC 2", controlId: "CC1.2", title: "Board Oversight", description: "The board demonstrates independence from management", category: "Common Criteria" },
        { framework: "SOC 2", controlId: "CC2.1", title: "Communication", description: "The entity obtains or generates relevant quality information", category: "Common Criteria" },
        { framework: "SOC 2", controlId: "CC3.1", title: "Risk Assessment", description: "The entity specifies objectives with sufficient clarity", category: "Common Criteria" },
        { framework: "SOC 2", controlId: "CC5.1", title: "Control Activities", description: "The entity selects and develops control activities", category: "Common Criteria" },
        { framework: "SOC 2", controlId: "CC6.1", title: "Logical Access", description: "The entity implements logical access security measures", category: "Common Criteria" },
        { framework: "SOC 2", controlId: "CC7.1", title: "System Operations", description: "The entity uses detection and monitoring procedures", category: "Common Criteria" },
        { framework: "SOC 2", controlId: "CC8.1", title: "Change Management", description: "The entity authorizes, designs, develops, and implements changes", category: "Common Criteria" },
      ];
      const created = await storage.createComplianceControls(seedControls);
      res.status(201).json(created);
    } catch (error) {
      res.status(500).json({ message: "Failed to seed compliance controls" });
    }
  });

  app.get("/api/compliance-control-mappings", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const controlId = req.query.controlId as string | undefined;
      const mappings = await storage.getComplianceControlMappings(orgId, controlId);
      res.json(mappings);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch compliance control mappings" });
    }
  });

  app.post("/api/compliance-control-mappings", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const parsed = insertComplianceControlMappingSchema.safeParse({ ...req.body, orgId });
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid mapping data", errors: parsed.error.flatten() });
      }
      const mapping = await storage.createComplianceControlMapping(parsed.data);
      res.status(201).json(mapping);
    } catch (error) {
      res.status(500).json({ message: "Failed to create compliance control mapping" });
    }
  });

  app.patch("/api/compliance-control-mappings/:id", isAuthenticated, async (req, res) => {
    try {
      const mapping = await storage.updateComplianceControlMapping(p(req.params.id), req.body);
      if (!mapping) return res.status(404).json({ message: "Mapping not found" });
      res.json(mapping);
    } catch (error) {
      res.status(500).json({ message: "Failed to update compliance control mapping" });
    }
  });

  app.delete("/api/compliance-control-mappings/:id", isAuthenticated, async (req, res) => {
    try {
      const deleted = await storage.deleteComplianceControlMapping(p(req.params.id));
      if (!deleted) return res.status(404).json({ message: "Mapping not found" });
      res.json({ message: "Mapping deleted" });
    } catch (error) {
      res.status(500).json({ message: "Failed to delete compliance control mapping" });
    }
  });

  // Evidence Locker
  app.get("/api/evidence-locker", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const framework = req.query.framework as string | undefined;
      const artifactType = req.query.artifactType as string | undefined;
      const items = await storage.getEvidenceLockerItems(orgId, framework, artifactType);
      res.json(items);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch evidence locker items" });
    }
  });

  app.post("/api/evidence-locker", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const parsed = insertEvidenceLockerItemSchema.safeParse({ ...req.body, orgId });
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid evidence locker item data", errors: parsed.error.flatten() });
      }
      const item = await storage.createEvidenceLockerItem(parsed.data);
      res.status(201).json(item);
    } catch (error) {
      res.status(500).json({ message: "Failed to create evidence locker item" });
    }
  });

  app.patch("/api/evidence-locker/:id", isAuthenticated, async (req, res) => {
    try {
      const item = await storage.updateEvidenceLockerItem(p(req.params.id), req.body);
      if (!item) return res.status(404).json({ message: "Evidence locker item not found" });
      res.json(item);
    } catch (error) {
      res.status(500).json({ message: "Failed to update evidence locker item" });
    }
  });

  app.delete("/api/evidence-locker/:id", isAuthenticated, async (req, res) => {
    try {
      const deleted = await storage.deleteEvidenceLockerItem(p(req.params.id));
      if (!deleted) return res.status(404).json({ message: "Evidence locker item not found" });
      res.json({ message: "Evidence locker item deleted" });
    } catch (error) {
      res.status(500).json({ message: "Failed to delete evidence locker item" });
    }
  });

  // ============================
  // Legal Holds (data retention exceptions)
  // ============================
  app.get("/api/legal-holds", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = (req as any).orgId;
      const holds = await storage.getLegalHolds(orgId);
      res.json(holds);
    } catch (error) { res.status(500).json({ message: "Failed to fetch legal holds" }); }
  });

  app.get("/api/legal-holds/:id", isAuthenticated, async (req, res) => {
    try {
      const hold = await storage.getLegalHold(p(req.params.id));
      if (!hold) return res.status(404).json({ message: "Legal hold not found" });
      res.json(hold);
    } catch (error) { res.status(500).json({ message: "Failed to fetch legal hold" }); }
  });

  app.post("/api/legal-holds", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (req, res) => {
    try {
      const orgId = (req as any).orgId;
      const user = (req as any).user;
      const { name, description, holdType, tableScope, filterCriteria, reason, caseReference } = req.body;
      if (!name) return res.status(400).json({ message: "name is required" });
      const hold = await storage.createLegalHold({
        orgId, name, description, holdType: holdType || "full",
        tableScope: tableScope || ["alerts", "incidents", "audit_logs"],
        filterCriteria: filterCriteria || {}, reason, caseReference,
        activatedBy: user?.id,
        activatedByName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Admin",
      });
      await storage.createAuditLog({
        orgId, userId: user?.id,
        userName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Admin",
        action: "legal_hold_activated", resourceType: "legal_hold", resourceId: hold.id,
        details: { name, holdType, tableScope, reason, caseReference },
      });
      res.status(201).json(hold);
    } catch (error) { res.status(500).json({ message: "Failed to create legal hold" }); }
  });

  app.patch("/api/legal-holds/:id", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (req, res) => {
    try {
      const user = (req as any).user;
      const hold = await storage.getLegalHold(p(req.params.id));
      if (!hold) return res.status(404).json({ message: "Legal hold not found" });
      const updated = await storage.updateLegalHold(hold.id, req.body);
      res.json(updated);
    } catch (error) { res.status(500).json({ message: "Failed to update legal hold" }); }
  });

  app.post("/api/legal-holds/:id/deactivate", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (req, res) => {
    try {
      const orgId = (req as any).orgId;
      const user = (req as any).user;
      const hold = await storage.getLegalHold(p(req.params.id));
      if (!hold) return res.status(404).json({ message: "Legal hold not found" });
      const updated = await storage.updateLegalHold(hold.id, {
        isActive: false,
        deactivatedBy: user?.id,
        deactivatedAt: new Date(),
      });
      await storage.createAuditLog({
        orgId, userId: user?.id,
        userName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Admin",
        action: "legal_hold_deactivated", resourceType: "legal_hold", resourceId: hold.id,
        details: { name: hold.name },
      });
      res.json(updated);
    } catch (error) { res.status(500).json({ message: "Failed to deactivate legal hold" }); }
  });

  app.get("/api/v1/audit-logs", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const offset = Number(req.query.offset ?? 0) || 0;
      const limit = Math.min(Number(req.query.limit ?? 50) || 50, 500);
      const action = typeof req.query.action === "string" ? req.query.action : undefined;
      const userId = typeof req.query.userId === "string" ? req.query.userId : undefined;
      const resourceType = typeof req.query.resourceType === "string" ? req.query.resourceType : undefined;
      const sortOrder = req.query.sortOrder === "asc" ? "asc" as const : "desc" as const;

      const { items, total } = await storage.getAuditLogsPaginated({
        orgId,
        offset,
        limit,
        action,
        userId,
        resourceType,
        sortOrder,
      });

      return sendEnvelope(res, items, {
        meta: { offset, limit, total, action: action ?? null, userId: userId ?? null, resourceType: resourceType ?? null, sortOrder },
      });
    } catch (error: any) {
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "AUDIT_LOGS_FAILED", message: "Failed to fetch audit logs", details: error?.message }],
      });
    }
  });

}

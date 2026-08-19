import type { Express } from "express";
import { logger, getOrgId } from "./shared";
import { isAuthenticated } from "../auth";
import { resolveOrgContext, requireOrgId, requireMinRole } from "../rbac";

import * as storage from "../storage/finding-lineage";

const VALID_SEVERITIES = ["critical", "high", "medium", "low", "info"];
const VALID_SOURCES = [
  "sast",
  "dast",
  "sca",
  "container_scan",
  "iac_scan",
  "secret_scan",
  "cloud_config",
  "runtime",
  "pentest",
  "manual",
];
const VALID_STATUSES = ["open", "in_progress", "remediated", "suppressed", "false_positive"];

export function registerFindingLineageRoutes(app: Express): void {
  app.get("/api/finding-lineage", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const findings = await storage.getFindingLineageRecords(orgId);
      res.json(findings);
    } catch (error) {
      logger.child("routes").error("List findings error", { error: String(error) });
      res.status(500).json({ message: "Failed to list findings" });
    }
  });

  app.get("/api/finding-lineage/stats", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const findings = await storage.getFindingLineageRecords(orgId);
      const stats = {
        total: findings.length,
        bySeverity: {
          critical: findings.filter((f) => f.severity === "critical").length,
          high: findings.filter((f) => f.severity === "high").length,
          medium: findings.filter((f) => f.severity === "medium").length,
          low: findings.filter((f) => f.severity === "low").length,
          info: findings.filter((f) => f.severity === "info").length,
        },
        byStatus: {
          open: findings.filter((f) => f.status === "open").length,
          in_progress: findings.filter((f) => f.status === "in_progress").length,
          remediated: findings.filter((f) => f.status === "remediated").length,
          suppressed: findings.filter((f) => f.status === "suppressed").length,
          false_positive: findings.filter((f) => f.status === "false_positive").length,
        },
        bySource: VALID_SOURCES.reduce(
          (acc, source) => {
            acc[source] = findings.filter((f) => f.source === source).length;
            return acc;
          },
          {} as Record<string, number>,
        ),
        avgRiskScore:
          findings.length > 0 ? findings.reduce((sum, f) => sum + (f.riskScore ?? 0), 0) / findings.length : 0,
      };
      res.json(stats);
    } catch (error) {
      logger.child("routes").error("Lineage stats error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch lineage stats" });
    }
  });

  app.get("/api/finding-lineage/owners", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const findings = await storage.getFindingLineageRecords(orgId);
      const ownerSet = new Map<string, { ownerName: string; findingCount: number }>();
      for (const f of findings) {
        const owner = f.owner as { ownerName?: string } | null;
        const name = owner?.ownerName || "Unassigned";
        const existing = ownerSet.get(name);
        if (existing) {
          existing.findingCount++;
        } else {
          ownerSet.set(name, { ownerName: name, findingCount: 1 });
        }
      }
      res.json(Array.from(ownerSet.values()));
    } catch (error) {
      logger.child("routes").error("List owners error", { error: String(error) });
      res.status(500).json({ message: "Failed to list owners" });
    }
  });

  app.get("/api/finding-lineage/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);
      const finding = await storage.getFindingLineageRecord(id);
      if (!finding || finding.orgId !== orgId) {
        return res.status(404).json({ message: "Finding not found" });
      }
      res.json(finding);
    } catch (error) {
      logger.child("routes").error("Get finding error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch finding" });
    }
  });

  app.get("/api/finding-lineage/:id/evidence", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);
      const finding = await storage.getFindingLineageRecord(id);
      if (!finding || finding.orgId !== orgId) {
        return res.status(404).json({ message: "Finding not found" });
      }
      const evidence = (finding.evidence as unknown[]) || [];
      res.json(evidence);
    } catch (error) {
      logger.child("routes").error("Get evidence error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch evidence" });
    }
  });

  app.get("/api/finding-lineage/:id/remediations", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);
      const finding = await storage.getFindingLineageRecord(id);
      if (!finding || finding.orgId !== orgId) {
        return res.status(404).json({ message: "Finding not found" });
      }
      const remediations = (finding.remediations as unknown[]) || [];
      res.json(remediations);
    } catch (error) {
      logger.child("routes").error("Get remediations error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch remediations" });
    }
  });

  app.post(
    "/api/finding-lineage/filter",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const body = req.body as {
          severity?: string[];
          source?: string[];
          status?: string[];
          minRiskScore?: number;
          maxRiskScore?: number;
        };

        if (body.severity) {
          for (const s of body.severity) {
            if (!VALID_SEVERITIES.includes(s)) return res.status(400).json({ message: `Invalid severity: ${s}` });
          }
        }
        if (body.source) {
          for (const s of body.source) {
            if (!VALID_SOURCES.includes(s)) return res.status(400).json({ message: `Invalid source: ${s}` });
          }
        }
        if (body.status) {
          for (const s of body.status) {
            if (!VALID_STATUSES.includes(s)) return res.status(400).json({ message: `Invalid status: ${s}` });
          }
        }

        let findings = await storage.getFindingLineageRecords(orgId);
        if (body.severity) findings = findings.filter((f) => body.severity!.includes(f.severity));
        if (body.source) findings = findings.filter((f) => body.source!.includes(f.source));
        if (body.status) findings = findings.filter((f) => body.status!.includes(f.status));
        if (body.minRiskScore !== undefined)
          findings = findings.filter((f) => (f.riskScore ?? 0) >= body.minRiskScore!);
        if (body.maxRiskScore !== undefined)
          findings = findings.filter((f) => (f.riskScore ?? 0) <= body.maxRiskScore!);

        res.json(findings);
      } catch (error) {
        logger.child("routes").error("Filter findings error", { error: String(error) });
        res.status(500).json({ message: "Failed to filter findings" });
      }
    },
  );

  app.post(
    "/api/finding-lineage/ingest",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const body = req.body;

        if (!body.title || typeof body.title !== "string") {
          return res.status(400).json({ message: "title is required" });
        }
        if (!body.severity || !VALID_SEVERITIES.includes(body.severity)) {
          return res.status(400).json({ message: "Valid severity is required" });
        }
        if (!body.source || !VALID_SOURCES.includes(body.source)) {
          return res.status(400).json({ message: "Valid source is required" });
        }

        const finding = await storage.createFindingLineageRecord({
          orgId,
          title: body.title,
          description: body.description || null,
          severity: body.severity,
          source: body.source,
          status: "open",
          riskScore: body.riskScore ?? 0,
          cweId: body.cweId || null,
          cveId: body.cveId || null,
          sourceLocation: body.sourceLocation || {},
          deployedAsset: body.deployedAsset || {},
          owner: body.owner || {},
          evidence: body.evidence || [],
          remediations: body.remediations || [],
          lineage: [{ event: "ingested", timestamp: new Date().toISOString(), source: body.source }],
        });
        res.status(201).json(finding);
      } catch (error) {
        logger.child("routes").error("Ingest finding error", { error: String(error) });
        res.status(500).json({ message: "Failed to ingest finding" });
      }
    },
  );

  app.patch(
    "/api/finding-lineage/:id/status",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const id = String(req.params.id);
        const { status } = req.body as { status: string };

        if (!status || !VALID_STATUSES.includes(status)) {
          return res.status(400).json({ message: `Invalid status: ${status}` });
        }

        const existing = await storage.getFindingLineageRecord(id);
        if (!existing || existing.orgId !== orgId) {
          return res.status(404).json({ message: "Finding not found" });
        }

        const existingLineage = (existing.lineage as Array<Record<string, unknown>>) || [];
        const updated = await storage.updateFindingLineageRecord(id, {
          status,
          resolvedAt: status === "remediated" ? new Date() : existing.resolvedAt,
          lineage: [
            ...existingLineage,
            { event: "status_changed", from: existing.status, to: status, timestamp: new Date().toISOString() },
          ],
        });
        res.json(updated);
      } catch (error) {
        logger.child("routes").error("Update finding status error", { error: String(error) });
        res.status(500).json({ message: "Failed to update finding status" });
      }
    },
  );
}

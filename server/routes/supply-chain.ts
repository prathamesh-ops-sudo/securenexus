import type { Express, Request, Response } from "express";
import { isAuthenticated } from "../auth";
import { resolveOrgContext, requireOrgId, requirePermission } from "../rbac";
import { logger, getOrgId } from "./shared";
import { db } from "../db";
import { sql, eq, and, desc, ilike, or, count } from "drizzle-orm";
import {
  sbomArtifacts,
  dependencyGraph,
  supplyChainFindings,
  SC_FINDING_STATUSES,
  SC_FINDING_TYPES,
  SC_FINDING_SEVERITIES,
} from "../../shared/schema";
import {
  processCycloneDxSbom,
  processSpdxSbom,
  scanIacContent,
  scanContainerImage,
  getSupplyChainRiskSummary,
} from "../supply-chain-engine";

const log = logger.child("supply-chain");

export function registerSupplyChainRoutes(app: Express): void {
  // ==========================================================================
  // SBOM UPLOAD — Accept CycloneDX or SPDX JSON
  // ==========================================================================

  app.post(
    "/api/supply-chain/sbom",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { name, version, format, source, sbomData } = req.body;

        if (!name || typeof name !== "string") {
          return res.status(400).json({ message: "name is required" });
        }
        if (!format || !["cyclonedx", "spdx"].includes(format)) {
          return res.status(400).json({ message: 'format must be "cyclonedx" or "spdx"' });
        }
        if (!sbomData || typeof sbomData !== "object") {
          return res.status(400).json({ message: "sbomData object is required" });
        }

        // Create SBOM artifact record
        const [sbom] = await db
          .insert(sbomArtifacts)
          .values({
            orgId,
            name,
            version: version || null,
            format,
            source: source || "manual_upload",
            status: "processing",
            rawData: sbomData,
            metadata: {
              uploadedAt: new Date().toISOString(),
              format,
              specVersion: format === "cyclonedx" ? sbomData.specVersion : sbomData.spdxVersion,
            },
            uploadedBy: (req as any).user?.id || null,
          })
          .returning();

        log.info(`SBOM uploaded: ${name} (${format})`, { orgId, sbomId: sbom.id });

        // Process in background-ish (but still awaited for response)
        let result;
        try {
          if (format === "cyclonedx") {
            result = await processCycloneDxSbom(orgId, sbom.id, sbomData);
          } else {
            result = await processSpdxSbom(orgId, sbom.id, sbomData);
          }
        } catch (processError) {
          // Mark SBOM as failed
          await db
            .update(sbomArtifacts)
            .set({ status: "failed", updatedAt: new Date() })
            .where(eq(sbomArtifacts.id, sbom.id));

          log.error("SBOM processing failed", { error: String(processError), sbomId: sbom.id });
          return res.status(500).json({ message: "SBOM processing failed", sbomId: sbom.id });
        }

        res.json({
          ...result,
          message: `SBOM processed: ${result.componentCount} components, ${result.findingsCount} findings`,
        });
      } catch (error) {
        log.error("Failed to upload SBOM", { error: String(error) });
        res.status(500).json({ message: "Failed to upload SBOM" });
      }
    },
  );

  // ==========================================================================
  // LIST SBOMs
  // ==========================================================================

  app.get(
    "/api/supply-chain/sboms",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const limitParam = parseInt(String(req.query.limit || "50"));
        const offsetParam = parseInt(String(req.query.offset || "0"));
        const limit = Math.min(Number.isNaN(limitParam) ? 50 : limitParam, 200);
        const offset = Number.isNaN(offsetParam) ? 0 : offsetParam;

        const sboms = await db
          .select()
          .from(sbomArtifacts)
          .where(eq(sbomArtifacts.orgId, orgId))
          .orderBy(desc(sbomArtifacts.createdAt))
          .limit(limit)
          .offset(offset);

        const [{ value: total }] = await db
          .select({ value: count() })
          .from(sbomArtifacts)
          .where(eq(sbomArtifacts.orgId, orgId));

        res.json({ sboms, total });
      } catch (error) {
        log.error("Failed to list SBOMs", { error: String(error) });
        res.status(500).json({ message: "Failed to list SBOMs" });
      }
    },
  );

  // ==========================================================================
  // GET SINGLE SBOM WITH DEPENDENCY GRAPH
  // ==========================================================================

  app.get(
    "/api/supply-chain/sboms/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const sbomId = String(req.params.id);

        const [sbom] = await db
          .select()
          .from(sbomArtifacts)
          .where(and(eq(sbomArtifacts.id, sbomId), eq(sbomArtifacts.orgId, orgId)))
          .limit(1);

        if (!sbom) {
          return res.status(404).json({ message: "SBOM not found" });
        }

        const dependencies = await db
          .select()
          .from(dependencyGraph)
          .where(and(eq(dependencyGraph.sbomId, sbomId), eq(dependencyGraph.orgId, orgId)))
          .orderBy(desc(dependencyGraph.isVulnerable), desc(dependencyGraph.cveCount));

        const findings = await db
          .select()
          .from(supplyChainFindings)
          .where(and(eq(supplyChainFindings.sbomId, sbomId), eq(supplyChainFindings.orgId, orgId)))
          .orderBy(desc(supplyChainFindings.createdAt));

        res.json({ sbom, dependencies, findings });
      } catch (error) {
        log.error("Failed to get SBOM", { error: String(error) });
        res.status(500).json({ message: "Failed to get SBOM" });
      }
    },
  );

  // ==========================================================================
  // DELETE SBOM (cascade deletes deps + findings)
  // ==========================================================================

  app.delete(
    "/api/supply-chain/sboms/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const sbomId = String(req.params.id);

        const [sbom] = await db
          .select()
          .from(sbomArtifacts)
          .where(and(eq(sbomArtifacts.id, sbomId), eq(sbomArtifacts.orgId, orgId)))
          .limit(1);

        if (!sbom) {
          return res.status(404).json({ message: "SBOM not found" });
        }

        await db.delete(sbomArtifacts).where(eq(sbomArtifacts.id, sbomId));

        log.info(`SBOM deleted: ${sbom.name}`, { orgId, sbomId });
        res.json({ message: "SBOM deleted" });
      } catch (error) {
        log.error("Failed to delete SBOM", { error: String(error) });
        res.status(500).json({ message: "Failed to delete SBOM" });
      }
    },
  );

  // ==========================================================================
  // DEPENDENCY GRAPH — List all deps for an org
  // ==========================================================================

  app.get(
    "/api/supply-chain/dependencies",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const ecosystem = req.query.ecosystem as string | undefined;
        const vulnerable = req.query.vulnerable as string | undefined;
        const typosquat = req.query.typosquat as string | undefined;
        const q = (req.query.q as string) || "";
        const limitParam = parseInt(String(req.query.limit || "100"));
        const offsetParam = parseInt(String(req.query.offset || "0"));
        const limit = Math.min(Number.isNaN(limitParam) ? 100 : limitParam, 500);
        const offset = Number.isNaN(offsetParam) ? 0 : offsetParam;

        const conditions: unknown[] = [eq(dependencyGraph.orgId, orgId)];
        if (ecosystem && ecosystem !== "all") conditions.push(eq(dependencyGraph.ecosystem, ecosystem));
        if (vulnerable === "true") conditions.push(eq(dependencyGraph.isVulnerable, true));
        if (typosquat === "true") conditions.push(eq(dependencyGraph.typosquatCandidate, true));
        if (q) {
          conditions.push(
            or(ilike(dependencyGraph.packageName, `%${q}%`), ilike(dependencyGraph.packageVersion, `%${q}%`)),
          );
        }

        const deps = await db
          .select()
          .from(dependencyGraph)
          .where(and(...(conditions as any[])))
          .orderBy(desc(dependencyGraph.isVulnerable), desc(dependencyGraph.cveCount))
          .limit(limit)
          .offset(offset);

        // Ecosystem breakdown
        const ecosystemStats = await db.execute(sql`
          SELECT ecosystem, COUNT(*) AS pkg_count,
                 COUNT(*) FILTER (WHERE is_vulnerable = true) AS vuln_count
          FROM dependency_graph
          WHERE org_id = ${orgId}
          GROUP BY ecosystem
          ORDER BY pkg_count DESC
        `);

        res.json({
          dependencies: deps,
          ecosystems: (ecosystemStats as any).rows || [],
        });
      } catch (error) {
        log.error("Failed to list dependencies", { error: String(error) });
        res.status(500).json({ message: "Failed to list dependencies" });
      }
    },
  );

  // ==========================================================================
  // FINDINGS — Supply chain findings across all SBOMs
  // ==========================================================================

  app.get(
    "/api/supply-chain/findings",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const findingType = req.query.type as string | undefined;
        const severity = req.query.severity as string | undefined;
        const status = req.query.status as string | undefined;
        const ecosystem = req.query.ecosystem as string | undefined;
        const q = (req.query.q as string) || "";
        const limitParam = parseInt(String(req.query.limit || "100"));
        const offsetParam = parseInt(String(req.query.offset || "0"));
        const limit = Math.min(Number.isNaN(limitParam) ? 100 : limitParam, 500);
        const offset = Number.isNaN(offsetParam) ? 0 : offsetParam;

        const conditions: unknown[] = [eq(supplyChainFindings.orgId, orgId)];
        if (findingType && findingType !== "all") conditions.push(eq(supplyChainFindings.findingType, findingType));
        if (severity && severity !== "all") conditions.push(eq(supplyChainFindings.severity, severity));
        if (status && status !== "all") conditions.push(eq(supplyChainFindings.status, status));
        if (ecosystem && ecosystem !== "all") conditions.push(eq(supplyChainFindings.ecosystem, ecosystem));
        if (q) {
          conditions.push(
            or(
              ilike(supplyChainFindings.title, `%${q}%`),
              ilike(supplyChainFindings.packageName, `%${q}%`),
              ilike(supplyChainFindings.cveId, `%${q}%`),
            ),
          );
        }

        const findings = await db
          .select()
          .from(supplyChainFindings)
          .where(and(...(conditions as any[])))
          .orderBy(desc(supplyChainFindings.createdAt))
          .limit(limit)
          .offset(offset);

        // Stats
        const statsResult = await db.execute(sql`
          SELECT
            COUNT(*) AS total,
            COUNT(*) FILTER (WHERE status = 'open') AS open_count,
            COUNT(*) FILTER (WHERE severity = 'critical') AS critical_count,
            COUNT(*) FILTER (WHERE severity = 'high') AS high_count,
            COUNT(*) FILTER (WHERE severity = 'medium') AS medium_count,
            COUNT(*) FILTER (WHERE severity = 'low') AS low_count,
            COUNT(*) FILTER (WHERE finding_type = 'vulnerable_dependency') AS vuln_count,
            COUNT(*) FILTER (WHERE finding_type = 'typosquatting') AS typosquat_count,
            COUNT(*) FILTER (WHERE finding_type = 'maintainer_risk') AS maintainer_count,
            COUNT(*) FILTER (WHERE finding_type = 'license_risk') AS license_count,
            COUNT(*) FILTER (WHERE finding_type = 'iac_misconfiguration') AS iac_count,
            COUNT(*) FILTER (WHERE finding_type = 'container_vulnerability') AS container_count
          FROM supply_chain_findings
          WHERE org_id = ${orgId}
        `);
        const s = (statsResult as any).rows?.[0] || {};

        res.json({
          findings,
          stats: {
            total: parseInt(s.total || "0"),
            openCount: parseInt(s.open_count || "0"),
            criticalCount: parseInt(s.critical_count || "0"),
            highCount: parseInt(s.high_count || "0"),
            mediumCount: parseInt(s.medium_count || "0"),
            lowCount: parseInt(s.low_count || "0"),
            vulnCount: parseInt(s.vuln_count || "0"),
            typosquatCount: parseInt(s.typosquat_count || "0"),
            maintainerCount: parseInt(s.maintainer_count || "0"),
            licenseCount: parseInt(s.license_count || "0"),
            iacCount: parseInt(s.iac_count || "0"),
            containerCount: parseInt(s.container_count || "0"),
          },
        });
      } catch (error) {
        log.error("Failed to list findings", { error: String(error) });
        res.status(500).json({ message: "Failed to list findings" });
      }
    },
  );

  // ==========================================================================
  // UPDATE FINDING STATUS
  // ==========================================================================

  app.patch(
    "/api/supply-chain/findings/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const findingId = String(req.params.id);

        const [finding] = await db
          .select()
          .from(supplyChainFindings)
          .where(and(eq(supplyChainFindings.id, findingId), eq(supplyChainFindings.orgId, orgId)))
          .limit(1);

        if (!finding) {
          return res.status(404).json({ message: "Finding not found" });
        }

        const { status } = req.body;
        if (!status || !SC_FINDING_STATUSES.includes(status as any)) {
          return res.status(400).json({
            message: `status must be one of: ${SC_FINDING_STATUSES.join(", ")}`,
          });
        }

        const updates: Record<string, unknown> = { status, updatedAt: new Date() };
        const userId = (req as any).user?.id;

        if (status === "acknowledged") {
          updates.acknowledgedBy = userId;
          updates.acknowledgedAt = new Date();
        } else if (status === "remediated") {
          updates.remediatedBy = userId;
          updates.remediatedAt = new Date();
        }

        const [updated] = await db
          .update(supplyChainFindings)
          .set(updates)
          .where(eq(supplyChainFindings.id, findingId))
          .returning();

        res.json(updated);
      } catch (error) {
        log.error("Failed to update finding", { error: String(error) });
        res.status(500).json({ message: "Failed to update finding" });
      }
    },
  );

  // ==========================================================================
  // RISK SUMMARY — Aggregate supply chain risk metrics
  // ==========================================================================

  app.get(
    "/api/supply-chain/risk-summary",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const summary = await getSupplyChainRiskSummary(orgId);
        res.json(summary);
      } catch (error) {
        log.error("Failed to get risk summary", { error: String(error) });
        res.status(500).json({ message: "Failed to get risk summary" });
      }
    },
  );

  // ==========================================================================
  // IAC SCAN — Scan Terraform / Helm / K8s YAML / Dockerfile
  // ==========================================================================

  app.post(
    "/api/supply-chain/iac-scan",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { content, filePath, ecosystem, sbomId } = req.body;

        if (!content || typeof content !== "string") {
          return res.status(400).json({ message: "content is required" });
        }
        if (!filePath || typeof filePath !== "string") {
          return res.status(400).json({ message: "filePath is required" });
        }
        if (!ecosystem || !["terraform", "helm", "kubernetes", "docker"].includes(ecosystem)) {
          return res.status(400).json({ message: "ecosystem must be terraform, helm, kubernetes, or docker" });
        }

        // Validate sbomId belongs to org if provided
        if (sbomId) {
          const [sbom] = await db
            .select()
            .from(sbomArtifacts)
            .where(and(eq(sbomArtifacts.id, sbomId), eq(sbomArtifacts.orgId, orgId)))
            .limit(1);

          if (!sbom) {
            return res.status(404).json({ message: "SBOM not found" });
          }
        }

        const result = await scanIacContent(orgId, sbomId || null, content, filePath, ecosystem);

        log.info(`IaC scan complete: ${result.findingsCount} findings in ${filePath}`, { orgId });
        res.json({
          ...result,
          message: `IaC scan complete: ${result.findingsCount} findings`,
        });
      } catch (error) {
        log.error("Failed to scan IaC", { error: String(error) });
        res.status(500).json({ message: "Failed to scan IaC content" });
      }
    },
  );

  // ==========================================================================
  // CONTAINER IMAGE SCAN
  // ==========================================================================

  app.post(
    "/api/supply-chain/container-scan",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { imageName, layers, sbomId } = req.body;

        if (!imageName || typeof imageName !== "string") {
          return res.status(400).json({ message: "imageName is required" });
        }
        if (!Array.isArray(layers) || layers.length === 0) {
          return res.status(400).json({ message: "layers array is required" });
        }

        // Validate sbomId belongs to org if provided
        if (sbomId) {
          const [sbom] = await db
            .select()
            .from(sbomArtifacts)
            .where(and(eq(sbomArtifacts.id, sbomId), eq(sbomArtifacts.orgId, orgId)))
            .limit(1);

          if (!sbom) {
            return res.status(404).json({ message: "SBOM not found" });
          }
        }

        const result = await scanContainerImage(orgId, sbomId || null, imageName, layers);

        log.info(`Container scan complete: ${result.findingsCount} findings in ${imageName}`, { orgId });
        res.json({
          ...result,
          message: `Container scan complete: ${result.findingsCount} findings`,
        });
      } catch (error) {
        log.error("Failed to scan container", { error: String(error) });
        res.status(500).json({ message: "Failed to scan container image" });
      }
    },
  );
}

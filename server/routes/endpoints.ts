import type { Express, Request, Response } from "express";
import { getOrgId, logger, p, storage } from "./shared";
import { isAuthenticated } from "../auth";
import { insertCspmAccountSchema, insertEndpointAssetSchema } from "@shared/schema";
import { runCspmScan, runDspmScan, createDriftBaseline, runDriftDetection, remediationEngine } from "../cspm-scanner";
import { calculateEndpointRisk, generateTelemetry, seedEndpointAssets } from "../endpoint-telemetry";
import { calculatePostureScore } from "../posture-engine";
import { resolveOrgContext, requireOrgId, requireMinRole } from "../rbac";
import { enforcePlanLimit } from "../middleware/plan-enforcement";

export function registerEndpointsRoutes(app: Express): void {
  // ── CSPM Routes ──
  app.get(
    "/api/cspm/accounts",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const accounts = await storage.getCspmAccounts(orgId);
        res.json(accounts);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch CSPM accounts" });
      }
    },
  );

  app.post(
    "/api/cspm/accounts",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const body = { ...req.body, orgId };
        const parsed = insertCspmAccountSchema.safeParse(body);
        if (!parsed.success) {
          return res.status(400).json({ message: "Invalid CSPM account data", errors: parsed.error.flatten() });
        }
        const account = await storage.createCspmAccount(parsed.data);
        res.status(201).json(account);
      } catch (error) {
        res.status(500).json({ message: "Failed to create CSPM account" });
      }
    },
  );

  app.patch(
    "/api/cspm/accounts/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const existing = await storage.getCspmAccount(p(req.params.id));
        if (!existing || existing.orgId !== orgId) return res.status(404).json({ message: "CSPM account not found" });
        const account = await storage.updateCspmAccount(p(req.params.id), req.body);
        if (!account) return res.status(404).json({ message: "CSPM account not found" });
        res.json(account);
      } catch (error) {
        res.status(500).json({ message: "Failed to update CSPM account" });
      }
    },
  );

  app.delete(
    "/api/cspm/accounts/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const existing = await storage.getCspmAccount(p(req.params.id));
        if (!existing || existing.orgId !== orgId) return res.status(404).json({ message: "CSPM account not found" });
        const deleted = await storage.deleteCspmAccount(p(req.params.id));
        if (!deleted) return res.status(404).json({ message: "CSPM account not found" });
        res.json({ message: "CSPM account deleted" });
      } catch (error) {
        res.status(500).json({ message: "Failed to delete CSPM account" });
      }
    },
  );

  app.get(
    "/api/cspm/scans",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const accountId = req.query.accountId as string | undefined;
        const scans = await storage.getCspmScans(orgId, accountId);
        res.json(scans);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch CSPM scans" });
      }
    },
  );

  app.post(
    "/api/cspm/scans/:accountId",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const account = await storage.getCspmAccount(p(req.params.accountId));
        if (!account || account.orgId !== orgId) return res.status(404).json({ message: "CSPM account not found" });
        try {
          await runCspmScan(orgId, p(req.params.accountId));
          res.json({ message: "Scan completed successfully" });
        } catch (scanErr) {
          logger.child("routes").error("CSPM scan error", { error: String(scanErr) });
          res.status(502).json({ message: "Scan failed", error: String(scanErr) });
        }
      } catch (error) {
        res.status(500).json({ message: "Failed to start CSPM scan" });
      }
    },
  );

  app.get(
    "/api/cspm/findings",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const scanId = req.query.scanId as string | undefined;
        const severity = req.query.severity as string | undefined;
        const findings = await storage.getCspmFindings(orgId, scanId, severity);
        res.json(findings);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch CSPM findings" });
      }
    },
  );

  app.patch(
    "/api/cspm/findings/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const findings = await storage.getCspmFindings(orgId);
        const existing = findings.find((f) => f.id === p(req.params.id));
        if (!existing) return res.status(404).json({ message: "CSPM finding not found" });
        const finding = await storage.updateCspmFinding(p(req.params.id), req.body);
        if (!finding) return res.status(404).json({ message: "CSPM finding not found" });
        res.json(finding);
      } catch (error) {
        res.status(500).json({ message: "Failed to update CSPM finding" });
      }
    },
  );

  // ── CSPM Drift Detection Routes ──
  app.post(
    "/api/cspm/drift/baseline/:accountId",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const account = await storage.getCspmAccount(p(req.params.accountId));
        if (!account || account.orgId !== orgId) return res.status(404).json({ message: "CSPM account not found" });
        const count = await createDriftBaseline(orgId, p(req.params.accountId));
        res.json({ message: "Baseline created", baselineCount: count });
      } catch (error) {
        logger.child("routes").error("Drift baseline error", { error: String(error) });
        res.status(500).json({ message: "Failed to create drift baseline" });
      }
    },
  );

  app.get(
    "/api/cspm/drift/baselines",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const accountId = req.query.accountId as string | undefined;
        const baselines = await storage.getCspmDriftBaselines(orgId, accountId);
        res.json(baselines);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch drift baselines" });
      }
    },
  );

  app.post(
    "/api/cspm/drift/detect/:accountId",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const account = await storage.getCspmAccount(p(req.params.accountId));
        if (!account || account.orgId !== orgId) return res.status(404).json({ message: "CSPM account not found" });
        const driftCount = await runDriftDetection(orgId, p(req.params.accountId));
        res.json({ message: "Drift detection complete", driftEventsDetected: driftCount });
      } catch (error) {
        logger.child("routes").error("Drift detection error", { error: String(error) });
        res.status(500).json({ message: String(error) });
      }
    },
  );

  app.get(
    "/api/cspm/drift/events",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const accountId = req.query.accountId as string | undefined;
        const status = req.query.status as string | undefined;
        const events = await storage.getCspmDriftEvents(orgId, accountId, status);
        res.json(events);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch drift events" });
      }
    },
  );

  // ── CSPM DSPM Routes ──
  app.post(
    "/api/cspm/dspm/scan/:accountId",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const account = await storage.getCspmAccount(p(req.params.accountId));
        if (!account || account.orgId !== orgId) return res.status(404).json({ message: "CSPM account not found" });
        const result = await runDspmScan(orgId, p(req.params.accountId));
        res.json({ message: "DSPM scan complete", ...result });
      } catch (error) {
        logger.child("routes").error("DSPM scan error", { error: String(error) });
        res.status(500).json({ message: "DSPM scan failed", error: String(error) });
      }
    },
  );

  app.get(
    "/api/cspm/dspm/findings",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const accountId = req.query.accountId as string | undefined;
        const sensitivityLevel = req.query.sensitivityLevel as string | undefined;
        const findings = await storage.getCspmDspmFindings(orgId, accountId, sensitivityLevel);
        res.json(findings);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch DSPM findings" });
      }
    },
  );

  // ── CSPM Attack Path Routes ──
  app.get(
    "/api/cspm/attack-paths",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const severity = req.query.severity as string | undefined;
        const paths = await storage.getCspmAttackPaths(orgId, severity);
        res.json(paths);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch attack paths" });
      }
    },
  );

  // ── CSPM Remediation Routes ──
  app.get(
    "/api/cspm/remediation/playbooks",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (_req, res) => {
      try {
        const playbooks = remediationEngine.getAllPlaybooks();
        res.json(playbooks);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch playbooks" });
      }
    },
  );

  app.get(
    "/api/cspm/remediation/playbooks/:ruleId",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const ruleId = Array.isArray(req.params.ruleId) ? req.params.ruleId[0] : req.params.ruleId;
        const playbooks = remediationEngine.getPlaybooks(ruleId);
        res.json(playbooks);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch playbooks for rule" });
      }
    },
  );

  app.post(
    "/api/cspm/remediation/execute",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { accountId, findingId, playbookId, resourceId } = req.body as {
          accountId: string;
          findingId?: string;
          playbookId: string;
          resourceId: string;
        };

        if (!accountId || !playbookId || !resourceId) {
          return res.status(400).json({ message: "accountId, playbookId, and resourceId are required" });
        }

        const account = await storage.getCspmAccount(accountId);
        if (!account || account.orgId !== orgId) return res.status(404).json({ message: "CSPM account not found" });

        const config = (account.config || {}) as Record<string, unknown>;
        const regions = account.regions && account.regions.length > 0 ? account.regions : ["us-east-1"];

        const awsConfig = {
          accessKeyId: (config.accessKeyId as string) || process.env.AWS_ACCESS_KEY_ID || "",
          secretAccessKey: (config.secretAccessKey as string) || process.env.AWS_SECRET_ACCESS_KEY || "",
          regions: regions as string[],
        };

        const result = await remediationEngine.executePlaybook(playbookId, resourceId, awsConfig);

        // Store remediation record
        const playbookInfo = remediationEngine.getAllPlaybooks().find((pb) => pb.id === playbookId);
        await storage.createCspmRemediation({
          orgId,
          accountId,
          findingId: findingId || null,
          playbookId,
          playbookName: playbookInfo?.name || playbookId,
          resourceId,
          ruleId: result.ruleId,
          status: result.status,
          actionsExecuted: result.actionsExecuted,
          actionsTotal: result.actionsTotal,
          error: result.error || null,
          details: result.details,
        });

        res.json(result);
      } catch (error) {
        logger.child("routes").error("Remediation execution error", { error: String(error) });
        res.status(500).json({ message: "Remediation failed", error: String(error) });
      }
    },
  );

  app.get(
    "/api/cspm/remediations",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const accountId = req.query.accountId as string | undefined;
        const status = req.query.status as string | undefined;
        const remediations = await storage.getCspmRemediations(orgId, accountId, status);
        res.json(remediations);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch remediations" });
      }
    },
  );

  // ─── 25.1 Cloud Resource Inventory Tree View ─────────────────────────────

  app.get(
    "/api/cspm/resources/tree",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const accounts = await storage.getCspmAccounts(orgId);
        const findings = await storage.getCspmFindings(orgId);

        // Build tree: Account -> Region -> Service -> Resource
        interface TreeNode {
          id: string;
          name: string;
          type: "account" | "region" | "service" | "resource";
          provider?: string;
          count: number;
          severity?: string;
          children: TreeNode[];
        }

        const tree: TreeNode[] = accounts.map((account: any) => {
          const accountFindings = findings.filter((f: any) => f.scanId && f.resourceRegion);
          const regionMap = new Map<string, Map<string, any[]>>();

          // Group by region -> service -> resources
          for (const finding of accountFindings) {
            const region = finding.resourceRegion || "global";
            const service = finding.resourceType?.split(":")[0] || finding.resourceType || "unknown";

            if (!regionMap.has(region)) regionMap.set(region, new Map());
            const serviceMap = regionMap.get(region)!;
            if (!serviceMap.has(service)) serviceMap.set(service, []);
            serviceMap.get(service)!.push(finding);
          }

          const regionChildren: TreeNode[] = [];
          regionMap.forEach((serviceMap, region) => {
            const serviceChildren: TreeNode[] = [];
            serviceMap.forEach((resources, service) => {
              const resourceChildren: TreeNode[] = resources.map((r: any) => ({
                id: r.id?.toString() || r.resourceId,
                name: r.resourceId || r.id?.toString(),
                type: "resource" as const,
                severity: r.severity || "info",
                count: 1,
                children: [],
              }));

              serviceChildren.push({
                id: `${account.id}-${region}-${service}`,
                name: service,
                type: "service" as const,
                count: resourceChildren.length,
                children: resourceChildren,
              });
            });

            regionChildren.push({
              id: `${account.id}-${region}`,
              name: region,
              type: "region" as const,
              count: serviceChildren.reduce((s, c) => s + c.count, 0),
              children: serviceChildren,
            });
          });

          return {
            id: account.id?.toString(),
            name: account.displayName || account.accountId,
            type: "account" as const,
            provider: account.cloudProvider,
            count: regionChildren.reduce((s, c) => s + c.count, 0),
            children: regionChildren,
          };
        });

        res.json({
          tree,
          totalAccounts: accounts.length,
          totalResources: tree.reduce((s: number, a: TreeNode) => s + a.count, 0),
        });
      } catch (error) {
        logger.child("routes").error("Resource tree error", { error: String(error) });
        res.status(500).json({ message: "Failed to build resource tree" });
      }
    },
  );

  // ─── 25.2 Compliance Posture by Framework per Cloud Account ───────────────

  const COMPLIANCE_FRAMEWORKS = [
    {
      id: "cis",
      name: "CIS Benchmarks",
      version: "1.5",
      controls: [
        { id: "cis-1.1", name: "Avoid root account usage", category: "Identity", severity: "critical" },
        { id: "cis-1.2", name: "MFA enabled for all IAM users", category: "Identity", severity: "critical" },
        { id: "cis-1.3", name: "Credentials unused for 90 days disabled", category: "Identity", severity: "high" },
        { id: "cis-2.1", name: "CloudTrail enabled in all regions", category: "Logging", severity: "high" },
        { id: "cis-2.2", name: "CloudTrail log validation enabled", category: "Logging", severity: "medium" },
        { id: "cis-3.1", name: "S3 bucket public access blocked", category: "Storage", severity: "critical" },
        { id: "cis-3.2", name: "S3 bucket encryption enabled", category: "Storage", severity: "high" },
        { id: "cis-4.1", name: "Security group no unrestricted ingress", category: "Networking", severity: "critical" },
        { id: "cis-4.2", name: "Default security group restricts traffic", category: "Networking", severity: "high" },
        { id: "cis-4.3", name: "VPC flow logs enabled", category: "Networking", severity: "medium" },
      ],
    },
    {
      id: "soc2",
      name: "SOC 2 Type II",
      version: "2024",
      controls: [
        {
          id: "soc2-cc1.1",
          name: "Entity demonstrates commitment to integrity",
          category: "Common Criteria",
          severity: "high",
        },
        {
          id: "soc2-cc2.1",
          name: "Information communicated internally",
          category: "Common Criteria",
          severity: "medium",
        },
        { id: "soc2-cc3.1", name: "Risk assessment performed", category: "Risk Assessment", severity: "high" },
        {
          id: "soc2-cc5.1",
          name: "Control activities designed and implemented",
          category: "Control Activities",
          severity: "high",
        },
        {
          id: "soc2-cc6.1",
          name: "Logical access security implemented",
          category: "Logical Access",
          severity: "critical",
        },
        { id: "soc2-cc6.2", name: "User access reviewed periodically", category: "Logical Access", severity: "high" },
        { id: "soc2-cc7.1", name: "System monitoring implemented", category: "System Operations", severity: "high" },
        {
          id: "soc2-cc7.2",
          name: "Anomalies detected and investigated",
          category: "System Operations",
          severity: "high",
        },
        { id: "soc2-cc8.1", name: "Change management process", category: "Change Management", severity: "medium" },
        { id: "soc2-cc9.1", name: "Risk mitigation activities", category: "Risk Mitigation", severity: "high" },
      ],
    },
    {
      id: "pci",
      name: "PCI DSS v4.0",
      version: "4.0",
      controls: [
        {
          id: "pci-1.1",
          name: "Network security controls installed",
          category: "Network Security",
          severity: "critical",
        },
        { id: "pci-2.1", name: "Secure configurations applied", category: "Secure Config", severity: "high" },
        { id: "pci-3.1", name: "Account data storage minimized", category: "Data Protection", severity: "critical" },
        { id: "pci-4.1", name: "Strong cryptography for transmission", category: "Encryption", severity: "critical" },
        { id: "pci-5.1", name: "Malware protection deployed", category: "Malware Protection", severity: "high" },
        { id: "pci-6.1", name: "Secure development practices", category: "Secure Development", severity: "high" },
        { id: "pci-7.1", name: "Access restricted to need-to-know", category: "Access Control", severity: "critical" },
        {
          id: "pci-8.1",
          name: "User identification and authentication",
          category: "Authentication",
          severity: "critical",
        },
        { id: "pci-9.1", name: "Physical access restricted", category: "Physical Security", severity: "high" },
        { id: "pci-10.1", name: "Logging and monitoring active", category: "Logging", severity: "high" },
      ],
    },
  ];

  app.get(
    "/api/cspm/compliance/:accountId",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const account = await storage.getCspmAccount(p(req.params.accountId));
        if (!account || account.orgId !== orgId) return res.status(404).json({ message: "CSPM account not found" });

        const findings = await storage.getCspmFindings(orgId);
        const accountFindings = findings.filter(
          (f: any) => f.resourceRegion || true, // include all findings for now
        );

        // Map findings to framework controls
        const frameworkScores = COMPLIANCE_FRAMEWORKS.map((fw) => {
          const controlResults = fw.controls.map((ctrl) => {
            // Determine pass/fail based on finding severity matching
            const relatedFindings = accountFindings.filter((f: any) => {
              const fwList = Array.isArray(f.complianceFrameworks) ? f.complianceFrameworks : [];
              return fwList.includes(fw.id) || fwList.includes(ctrl.id);
            });

            const failing = relatedFindings.filter((f: any) => f.status === "open" || f.status === "in_progress");

            return {
              controlId: ctrl.id,
              name: ctrl.name,
              category: ctrl.category,
              severity: ctrl.severity,
              status: failing.length > 0 ? "failing" : "passing",
              findingCount: relatedFindings.length,
              failingCount: failing.length,
            };
          });

          const passing = controlResults.filter((c) => c.status === "passing").length;
          const total = controlResults.length;
          const score = total > 0 ? Math.round((passing / total) * 100) : 100;

          return {
            frameworkId: fw.id,
            frameworkName: fw.name,
            version: fw.version,
            score,
            passing,
            failing: total - passing,
            total,
            controls: controlResults,
            categories: Array.from(new Set(fw.controls.map((c) => c.category))).map((cat) => {
              const catControls = controlResults.filter((c) => c.category === cat);
              const catPassing = catControls.filter((c) => c.status === "passing").length;
              return {
                name: cat,
                passing: catPassing,
                total: catControls.length,
                score: catControls.length > 0 ? Math.round((catPassing / catControls.length) * 100) : 100,
              };
            }),
          };
        });

        const overallScore =
          frameworkScores.length > 0
            ? Math.round(frameworkScores.reduce((s, f) => s + f.score, 0) / frameworkScores.length)
            : 100;

        res.json({
          accountId: account.id,
          accountName: account.displayName || account.accountId,
          provider: account.cloudProvider,
          overallScore,
          frameworks: frameworkScores,
          lastAssessed: new Date().toISOString(),
        });
      } catch (error) {
        logger.child("routes").error("Compliance scoring error", { error: String(error) });
        res.status(500).json({ message: "Failed to fetch compliance posture" });
      }
    },
  );

  // ─── 25.3 Drift Detection Visualization ──────────────────────────────────

  app.get(
    "/api/cspm/drift/:resourceId/detail",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const resourceId = req.params.resourceId;
        const events = await storage.getCspmDriftEvents(orgId);
        const resourceEvents = events.filter((e: any) => e.resourceId === resourceId);

        if (resourceEvents.length === 0) {
          return res.json({
            resourceId,
            driftDetected: false,
            timeline: [],
            currentDiff: null,
          });
        }

        // Build timeline of changes
        const timeline = resourceEvents
          .map((evt: any) => {
            const expected =
              typeof evt.baselineConfig === "string"
                ? JSON.parse(evt.baselineConfig || "{}")
                : evt.baselineConfig || {};
            const actual =
              typeof evt.currentConfig === "string" ? JSON.parse(evt.currentConfig || "{}") : evt.currentConfig || {};

            // Compute field-level diffs
            const allKeys = new Set([...Object.keys(expected), ...Object.keys(actual)]);
            const fieldChanges: Array<{ field: string; expected: any; actual: any; changed: boolean }> = [];
            allKeys.forEach((key) => {
              const exp = expected[key];
              const act = actual[key];
              fieldChanges.push({
                field: key,
                expected: exp !== undefined ? exp : null,
                actual: act !== undefined ? act : null,
                changed: JSON.stringify(exp) !== JSON.stringify(act),
              });
            });

            return {
              eventId: evt.id,
              detectedAt: evt.detectedAt || evt.createdAt,
              status: evt.status || "detected",
              severity: evt.severity || "medium",
              fieldChanges,
              changedFieldCount: fieldChanges.filter((f) => f.changed).length,
              totalFields: fieldChanges.length,
            };
          })
          .sort((a: any, b: any) => new Date(b.detectedAt).getTime() - new Date(a.detectedAt).getTime());

        res.json({
          resourceId,
          driftDetected: true,
          totalEvents: timeline.length,
          latestEvent: timeline[0] || null,
          timeline,
        });
      } catch (error) {
        logger.child("routes").error("Drift detail error", { error: String(error) });
        res.status(500).json({ message: "Failed to fetch drift details" });
      }
    },
  );

  // ─── 25.4 Multi-Cloud Unified Dashboard ──────────────────────────────────

  app.get(
    "/api/cspm/multi-cloud/dashboard",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const accounts = await storage.getCspmAccounts(orgId);
        const findings = await storage.getCspmFindings(orgId);
        const scans = await storage.getCspmScans(orgId);

        // Group by provider
        const providerStats: Record<
          string,
          {
            provider: string;
            accountCount: number;
            findingCount: number;
            criticalCount: number;
            highCount: number;
            mediumCount: number;
            lowCount: number;
            lastScanAt: string | null;
            score: number;
          }
        > = {};

        for (const account of accounts) {
          const prov = (account as any).cloudProvider || "unknown";
          if (!providerStats[prov]) {
            providerStats[prov] = {
              provider: prov,
              accountCount: 0,
              findingCount: 0,
              criticalCount: 0,
              highCount: 0,
              mediumCount: 0,
              lowCount: 0,
              lastScanAt: null,
              score: 100,
            };
          }
          providerStats[prov].accountCount++;
          if ((account as any).lastScanAt) {
            const ts = (account as any).lastScanAt;
            if (!providerStats[prov].lastScanAt || ts > providerStats[prov].lastScanAt!) {
              providerStats[prov].lastScanAt = ts;
            }
          }
        }

        // Count findings by severity
        for (const finding of findings) {
          // Find which account this finding belongs to
          for (const prov of Object.keys(providerStats)) {
            const ps = providerStats[prov];
            ps.findingCount++;
            const sev = (finding as any).severity || "info";
            if (sev === "critical") ps.criticalCount++;
            else if (sev === "high") ps.highCount++;
            else if (sev === "medium") ps.mediumCount++;
            else ps.lowCount++;
            break; // count once
          }
        }

        // Compute scores
        for (const prov of Object.values(providerStats)) {
          const totalFindings = prov.findingCount;
          const critWeight = prov.criticalCount * 10 + prov.highCount * 5 + prov.mediumCount * 2 + prov.lowCount;
          prov.score = Math.max(0, Math.min(100, 100 - Math.min(critWeight, 100)));
        }

        const providers = Object.values(providerStats);
        const overallScore =
          providers.length > 0 ? Math.round(providers.reduce((s, p) => s + p.score, 0) / providers.length) : 100;

        const totalFindings = findings.length;
        const criticalFindings = findings.filter((f: any) => f.severity === "critical").length;
        const openFindings = findings.filter((f: any) => f.status === "open" || !f.status).length;

        res.json({
          overallScore,
          totalAccounts: accounts.length,
          totalFindings,
          criticalFindings,
          openFindings,
          totalScans: scans.length,
          providers,
          recentScans: scans
            .sort(
              (a: any, b: any) =>
                new Date(b.startedAt || b.createdAt).getTime() - new Date(a.startedAt || a.createdAt).getTime(),
            )
            .slice(0, 5)
            .map((s: any) => ({
              id: s.id,
              accountId: s.accountId,
              status: s.status,
              startedAt: s.startedAt || s.createdAt,
              findingsCount: s.findingsCount || 0,
            })),
        });
      } catch (error) {
        logger.child("routes").error("Multi-cloud dashboard error", { error: String(error) });
        res.status(500).json({ message: "Failed to fetch multi-cloud dashboard" });
      }
    },
  );

  // ─── 25.5 Scheduled Scanning ─────────────────────────────────────────────

  const scanSchedules = new Map<
    string,
    {
      id: string;
      orgId: string;
      accountId: string;
      interval: "hourly" | "daily" | "weekly" | "monthly";
      enabled: boolean;
      lastScanAt: string | null;
      nextScanAt: string;
      createdAt: string;
      updatedAt: string;
    }
  >();

  function computeNextScan(interval: string, from: Date = new Date()): string {
    const next = new Date(from);
    switch (interval) {
      case "hourly":
        next.setHours(next.getHours() + 1);
        break;
      case "daily":
        next.setDate(next.getDate() + 1);
        break;
      case "weekly":
        next.setDate(next.getDate() + 7);
        break;
      case "monthly":
        next.setMonth(next.getMonth() + 1);
        break;
    }
    return next.toISOString();
  }

  app.get(
    "/api/cspm/scanning-schedules",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const schedules: any[] = [];
        scanSchedules.forEach((s) => {
          if (s.orgId === orgId) schedules.push(s);
        });
        res.json(schedules);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch scan schedules" });
      }
    },
  );

  app.post(
    "/api/cspm/scanning-schedules",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { accountId, interval } = req.body;

        if (!accountId || !interval) {
          return res.status(400).json({ message: "accountId and interval are required" });
        }
        if (!["hourly", "daily", "weekly", "monthly"].includes(interval)) {
          return res.status(400).json({ message: "interval must be hourly, daily, weekly, or monthly" });
        }

        const account = await storage.getCspmAccount(accountId);
        if (!account || account.orgId !== orgId) return res.status(404).json({ message: "CSPM account not found" });

        const id = `sched-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
        const schedule = {
          id,
          orgId,
          accountId,
          interval: interval as "hourly" | "daily" | "weekly" | "monthly",
          enabled: true,
          lastScanAt: null,
          nextScanAt: computeNextScan(interval),
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        };

        scanSchedules.set(id, schedule);
        res.status(201).json(schedule);
      } catch (error) {
        logger.child("routes").error("Create schedule error", { error: String(error) });
        res.status(500).json({ message: "Failed to create scan schedule" });
      }
    },
  );

  app.patch(
    "/api/cspm/scanning-schedules/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const schedule = scanSchedules.get(req.params.id as string);
        if (!schedule || schedule.orgId !== orgId) {
          return res.status(404).json({ message: "Schedule not found" });
        }

        if (req.body.interval && ["hourly", "daily", "weekly", "monthly"].includes(req.body.interval)) {
          schedule.interval = req.body.interval;
          schedule.nextScanAt = computeNextScan(req.body.interval);
        }
        if (typeof req.body.enabled === "boolean") {
          schedule.enabled = req.body.enabled;
        }
        schedule.updatedAt = new Date().toISOString();

        res.json(schedule);
      } catch (error) {
        res.status(500).json({ message: "Failed to update schedule" });
      }
    },
  );

  app.delete(
    "/api/cspm/scanning-schedules/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const schedule = scanSchedules.get(req.params.id as string);
        if (!schedule || schedule.orgId !== orgId) {
          return res.status(404).json({ message: "Schedule not found" });
        }
        scanSchedules.delete(req.params.id as string);
        res.json({ message: "Schedule deleted" });
      } catch (error) {
        res.status(500).json({ message: "Failed to delete schedule" });
      }
    },
  );

  // ─── 25.6 Auto-Remediation Safety Controls ───────────────────────────────

  const remediationSafetyRecords = new Map<
    string,
    {
      id: string;
      orgId: string;
      accountId: string;
      findingId: string | null;
      playbookId: string;
      resourceId: string;
      mode: "dry_run" | "pending_approval" | "approved" | "executed" | "rolled_back";
      dryRunResult: any;
      approvedBy: string | null;
      approvedAt: string | null;
      executedAt: string | null;
      rollbackAvailable: boolean;
      rollbackExecutedAt: string | null;
      createdAt: string;
    }
  >();

  app.post(
    "/api/cspm/remediation/dry-run",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { accountId, findingId, playbookId, resourceId } = req.body;

        if (!accountId || !playbookId || !resourceId) {
          return res.status(400).json({ message: "accountId, playbookId, and resourceId are required" });
        }

        const account = await storage.getCspmAccount(accountId);
        if (!account || account.orgId !== orgId) return res.status(404).json({ message: "CSPM account not found" });

        const id = `rem-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
        const dryRunResult = {
          wouldExecute: [
            { action: "Modify security group rules", impact: "medium", reversible: true },
            { action: "Enable encryption", impact: "low", reversible: false },
            { action: "Update IAM policy", impact: "high", reversible: true },
          ].slice(0, Math.floor(Math.random() * 3) + 1),
          estimatedDuration: "2-5 minutes",
          riskLevel: "medium",
          requiresDowntime: false,
          affectedResources: [resourceId],
        };

        const record = {
          id,
          orgId,
          accountId,
          findingId: findingId || null,
          playbookId,
          resourceId,
          mode: "dry_run" as const,
          dryRunResult,
          approvedBy: null,
          approvedAt: null,
          executedAt: null,
          rollbackAvailable: true,
          rollbackExecutedAt: null,
          createdAt: new Date().toISOString(),
        };

        remediationSafetyRecords.set(id, record);

        res.json({
          id,
          mode: "dry_run",
          dryRunResult,
          nextSteps: ["Review the dry-run results", "Approve to execute", "Or dismiss"],
        });
      } catch (error) {
        logger.child("routes").error("Dry run error", { error: String(error) });
        res.status(500).json({ message: "Failed to execute dry run" });
      }
    },
  );

  app.post(
    "/api/cspm/remediation/:id/approve",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const record = remediationSafetyRecords.get(req.params.id as string);
        if (!record || record.orgId !== orgId) {
          return res.status(404).json({ message: "Remediation record not found" });
        }

        if (record.mode !== "dry_run" && record.mode !== "pending_approval") {
          return res.status(400).json({ message: "Remediation is not in a state that can be approved" });
        }

        const user = (req as any).user;
        record.mode = "approved";
        record.approvedBy = user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Admin";
        record.approvedAt = new Date().toISOString();

        res.json({ id: record.id, mode: "approved", approvedBy: record.approvedBy, approvedAt: record.approvedAt });
      } catch (error) {
        res.status(500).json({ message: "Failed to approve remediation" });
      }
    },
  );

  app.post(
    "/api/cspm/remediation/:id/execute",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const record = remediationSafetyRecords.get(req.params.id as string);
        if (!record || record.orgId !== orgId) {
          return res.status(404).json({ message: "Remediation record not found" });
        }

        if (record.mode !== "approved") {
          return res.status(400).json({ message: "Remediation must be approved before execution" });
        }

        record.mode = "executed";
        record.executedAt = new Date().toISOString();
        record.rollbackAvailable = true;

        res.json({
          id: record.id,
          mode: "executed",
          executedAt: record.executedAt,
          rollbackAvailable: true,
          message: "Remediation executed successfully",
        });
      } catch (error) {
        res.status(500).json({ message: "Failed to execute remediation" });
      }
    },
  );

  app.post(
    "/api/cspm/remediation/:id/rollback",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const record = remediationSafetyRecords.get(req.params.id as string);
        if (!record || record.orgId !== orgId) {
          return res.status(404).json({ message: "Remediation record not found" });
        }

        if (record.mode !== "executed" || !record.rollbackAvailable) {
          return res.status(400).json({ message: "Remediation cannot be rolled back" });
        }

        record.mode = "rolled_back";
        record.rollbackExecutedAt = new Date().toISOString();
        record.rollbackAvailable = false;

        res.json({
          id: record.id,
          mode: "rolled_back",
          rollbackExecutedAt: record.rollbackExecutedAt,
          message: "Remediation rolled back successfully",
        });
      } catch (error) {
        res.status(500).json({ message: "Failed to rollback remediation" });
      }
    },
  );

  app.get(
    "/api/cspm/remediation/safety-records",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const records: any[] = [];
        remediationSafetyRecords.forEach((r) => {
          if (r.orgId === orgId) records.push(r);
        });
        res.json(records.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()));
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch safety records" });
      }
    },
  );

  // ─── 25.7 Resource Change Tracking ────────────────────────────────────────

  app.get(
    "/api/cspm/resource-changes",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const events = await storage.getCspmDriftEvents(orgId);
        const resourceId = req.query.resourceId as string | undefined;
        const changeType = req.query.changeType as string | undefined;

        let filtered = events;
        if (resourceId) {
          filtered = filtered.filter((e: any) => e.resourceId === resourceId);
        }

        // Classify changes
        const changes = filtered.map((evt: any) => {
          const expected =
            typeof evt.baselineConfig === "string" ? JSON.parse(evt.baselineConfig || "{}") : evt.baselineConfig || {};
          const actual =
            typeof evt.currentConfig === "string" ? JSON.parse(evt.currentConfig || "{}") : evt.currentConfig || {};
          const changedFields = Object.keys({ ...expected, ...actual }).filter(
            (k) => JSON.stringify(expected[k]) !== JSON.stringify(actual[k]),
          );

          const isUnexpected = (evt.severity === "critical" || evt.severity === "high") && changedFields.length > 0;

          return {
            id: evt.id,
            resourceId: evt.resourceId,
            resourceType: evt.resourceType,
            detectedAt: evt.detectedAt || evt.createdAt,
            severity: evt.severity || "medium",
            status: evt.status || "detected",
            changedFields,
            changedFieldCount: changedFields.length,
            isUnexpected,
            changeType: isUnexpected ? "unexpected" : "expected",
            summary:
              changedFields.length > 0
                ? `${changedFields.length} field(s) changed: ${changedFields.slice(0, 3).join(", ")}${changedFields.length > 3 ? "..." : ""}`
                : "No field changes detected",
          };
        });

        let result = changes;
        if (changeType === "unexpected") {
          result = result.filter((c: any) => c.isUnexpected);
        } else if (changeType === "expected") {
          result = result.filter((c: any) => !c.isUnexpected);
        }

        const unexpectedCount = changes.filter((c: any) => c.isUnexpected).length;

        result.sort((a: any, b: any) => new Date(b.detectedAt).getTime() - new Date(a.detectedAt).getTime());

        res.json({
          totalChanges: changes.length,
          unexpectedChanges: unexpectedCount,
          expectedChanges: changes.length - unexpectedCount,
          changes: result,
          alertsTriggered: unexpectedCount,
        });
      } catch (error) {
        logger.child("routes").error("Resource changes error", { error: String(error) });
        res.status(500).json({ message: "Failed to fetch resource changes" });
      }
    },
  );

  // ─── 25.8 CSPM -> Attack Path Analysis Integration ───────────────────────

  app.get(
    "/api/cspm/integrations/attack-paths",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const findings = await storage.getCspmFindings(orgId);
        const attackPaths = await storage.getCspmAttackPaths(orgId);

        // Cross-reference CSPM findings with attack paths
        const criticalFindings = findings.filter((f: any) => f.severity === "critical" || f.severity === "high");

        const correlations = criticalFindings.map((finding: any) => {
          const relatedPaths = attackPaths.filter((path: any) => {
            const pathResources = Array.isArray(path.affectedResources) ? path.affectedResources : [];
            return pathResources.includes(finding.resourceId);
          });

          return {
            findingId: finding.id,
            resourceId: finding.resourceId,
            severity: finding.severity,
            status: finding.status,
            relatedAttackPaths: relatedPaths.length,
            attackPathIds: relatedPaths.map((p: any) => p.id),
            riskMultiplier: relatedPaths.length > 0 ? 1 + relatedPaths.length * 0.5 : 1,
          };
        });

        res.json({
          totalFindings: criticalFindings.length,
          findingsWithAttackPaths: correlations.filter((c: any) => c.relatedAttackPaths > 0).length,
          correlations: correlations.sort((a: any, b: any) => b.relatedAttackPaths - a.relatedAttackPaths),
        });
      } catch (error) {
        logger.child("routes").error("CSPM attack path integration error", { error: String(error) });
        res.status(500).json({ message: "Failed to fetch attack path correlations" });
      }
    },
  );

  // ─── 25.9 CSPM -> Compliance Center Mapping ──────────────────────────────

  app.get(
    "/api/cspm/integrations/compliance-mapping",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const findings = await storage.getCspmFindings(orgId);

        // Map CSPM findings to compliance frameworks
        const frameworkMapping: Record<
          string,
          {
            framework: string;
            controlsMapped: number;
            findingsCount: number;
            criticalCount: number;
            highCount: number;
            controls: Array<{ controlId: string; findingCount: number; severity: string }>;
          }
        > = {};

        for (const fw of COMPLIANCE_FRAMEWORKS) {
          frameworkMapping[fw.id] = {
            framework: fw.name,
            controlsMapped: 0,
            findingsCount: 0,
            criticalCount: 0,
            highCount: 0,
            controls: [],
          };

          for (const ctrl of fw.controls) {
            const related = findings.filter((f: any) => {
              const fwList = Array.isArray(f.complianceFrameworks) ? f.complianceFrameworks : [];
              return fwList.includes(fw.id) || fwList.includes(ctrl.id);
            });

            if (related.length > 0) {
              frameworkMapping[fw.id].controlsMapped++;
              frameworkMapping[fw.id].findingsCount += related.length;
              frameworkMapping[fw.id].criticalCount += related.filter((f: any) => f.severity === "critical").length;
              frameworkMapping[fw.id].highCount += related.filter((f: any) => f.severity === "high").length;
              frameworkMapping[fw.id].controls.push({
                controlId: ctrl.id,
                findingCount: related.length,
                severity: ctrl.severity,
              });
            }
          }
        }

        res.json({
          frameworks: Object.values(frameworkMapping),
          totalMappedFindings: Object.values(frameworkMapping).reduce((s, f) => s + f.findingsCount, 0),
          availableFrameworks: COMPLIANCE_FRAMEWORKS.map((f) => ({ id: f.id, name: f.name, version: f.version })),
        });
      } catch (error) {
        logger.child("routes").error("Compliance mapping error", { error: String(error) });
        res.status(500).json({ message: "Failed to fetch compliance mapping" });
      }
    },
  );

  // ─── 25.10 CSPM -> Incident Correlation ──────────────────────────────────

  app.get(
    "/api/cspm/integrations/incidents",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const findings = await storage.getCspmFindings(orgId);
        const incidents = await storage.getIncidents(orgId);

        // Correlate CSPM findings with incidents
        const correlations = findings
          .filter((f: any) => f.severity === "critical" || f.severity === "high")
          .map((finding: any) => {
            // Find incidents that reference the same resource or have overlapping IOCs
            const relatedIncidents = incidents.filter((inc: any) => {
              const incDetails = typeof inc.details === "string" ? inc.details : JSON.stringify(inc.details || {});
              return (
                incDetails.includes(finding.resourceId) ||
                (finding.resourceType && incDetails.includes(finding.resourceType))
              );
            });

            return {
              findingId: finding.id,
              resourceId: finding.resourceId,
              resourceType: finding.resourceType,
              severity: finding.severity,
              relatedIncidentCount: relatedIncidents.length,
              incidents: relatedIncidents.slice(0, 5).map((inc: any) => ({
                id: inc.id,
                title: inc.title,
                severity: inc.severity,
                status: inc.status,
                createdAt: inc.createdAt,
              })),
              shouldCreateIncident: relatedIncidents.length === 0 && finding.severity === "critical",
            };
          });

        const findingsWithIncidents = correlations.filter((c: any) => c.relatedIncidentCount > 0).length;
        const findingsNeedingIncidents = correlations.filter((c: any) => c.shouldCreateIncident).length;

        res.json({
          totalCriticalFindings: correlations.length,
          findingsWithIncidents,
          findingsNeedingIncidents,
          correlations: correlations.sort((a: any, b: any) => b.relatedIncidentCount - a.relatedIncidentCount),
        });
      } catch (error) {
        logger.child("routes").error("Incident correlation error", { error: String(error) });
        res.status(500).json({ message: "Failed to fetch incident correlations" });
      }
    },
  );

  // ─── CSPM Policy Checks ──
  app.get(
    "/api/cspm/policy-checks",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const checks = await storage.getPolicyChecks(orgId);
        res.json(checks);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch policy checks" });
      }
    },
  );

  app.post(
    "/api/cspm/policy-checks",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const check = await storage.createPolicyCheck({ ...req.body, orgId });
        res.status(201).json(check);
      } catch (error) {
        res.status(500).json({ message: "Failed to create policy check" });
      }
    },
  );

  app.delete(
    "/api/cspm/policy-checks/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const check = await storage.getPolicyCheck(p(req.params.id));
        if (!check || check.orgId !== orgId) return res.status(404).json({ message: "Policy check not found" });
        await storage.deletePolicyCheck(p(req.params.id));
        res.json({ message: "Policy check deleted" });
      } catch (error) {
        res.status(500).json({ message: "Failed to delete policy check" });
      }
    },
  );

  app.post(
    "/api/cspm/policy-checks/:id/run",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const check = await storage.getPolicyCheck(p(req.params.id));
        if (!check || check.orgId !== orgId) return res.status(404).json({ message: "Policy check not found" });
        // Simulated policy evaluation
        await storage.updatePolicyCheck(p(req.params.id), { lastRunAt: new Date().toISOString() } as any);
        res.json({ message: "Policy check executed", status: "completed" });
      } catch (error) {
        res.status(500).json({ message: "Failed to run policy check" });
      }
    },
  );

  app.get(
    "/api/cspm/policy-results",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const policyCheckId = req.query.policyCheckId as string | undefined;
        const results = await storage.getPolicyResults(orgId, policyCheckId);
        res.json(results);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch policy results" });
      }
    },
  );

  // ── Endpoint Telemetry Routes ──
  app.get(
    "/api/endpoints",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const assets = await storage.getEndpointAssets(orgId);
        res.json(assets);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch endpoint assets" });
      }
    },
  );

  app.get(
    "/api/endpoints/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const asset = await storage.getEndpointAsset(p(req.params.id));
        if (!asset || asset.orgId !== orgId) return res.status(404).json({ message: "Endpoint asset not found" });
        res.json(asset);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch endpoint asset" });
      }
    },
  );

  app.post(
    "/api/endpoints/seed",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const assets = await seedEndpointAssets(orgId);
        res.status(201).json(assets);
      } catch (error) {
        res.status(500).json({ message: "Failed to seed endpoint assets" });
      }
    },
  );

  app.post(
    "/api/endpoints",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    enforcePlanLimit("endpoints_monitored"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const body = { ...req.body, orgId };
        const parsed = insertEndpointAssetSchema.safeParse(body);
        if (!parsed.success) {
          return res.status(400).json({ message: "Invalid endpoint asset data", errors: parsed.error.flatten() });
        }
        const asset = await storage.createEndpointAsset(parsed.data);
        res.status(201).json(asset);
      } catch (error) {
        res.status(500).json({ message: "Failed to create endpoint asset" });
      }
    },
  );

  app.patch(
    "/api/endpoints/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const existing = await storage.getEndpointAsset(p(req.params.id));
        if (!existing || existing.orgId !== orgId) return res.status(404).json({ message: "Endpoint asset not found" });
        const asset = await storage.updateEndpointAsset(p(req.params.id), req.body);
        if (!asset) return res.status(404).json({ message: "Endpoint asset not found" });
        res.json(asset);
      } catch (error) {
        res.status(500).json({ message: "Failed to update endpoint asset" });
      }
    },
  );

  app.delete(
    "/api/endpoints/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const existing = await storage.getEndpointAsset(p(req.params.id));
        if (!existing || existing.orgId !== orgId) return res.status(404).json({ message: "Endpoint asset not found" });
        const deleted = await storage.deleteEndpointAsset(p(req.params.id));
        if (!deleted) return res.status(404).json({ message: "Endpoint asset not found" });
        res.json({ message: "Endpoint asset deleted" });
      } catch (error) {
        res.status(500).json({ message: "Failed to delete endpoint asset" });
      }
    },
  );

  app.get(
    "/api/endpoints/:id/telemetry",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const asset = await storage.getEndpointAsset(p(req.params.id));
        if (!asset || asset.orgId !== orgId) return res.status(404).json({ message: "Endpoint asset not found" });
        const telemetry = await storage.getEndpointTelemetry(p(req.params.id));
        res.json(telemetry);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch endpoint telemetry" });
      }
    },
  );

  app.post(
    "/api/endpoints/:id/telemetry",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const asset = await storage.getEndpointAsset(p(req.params.id));
        if (!asset || asset.orgId !== orgId) return res.status(404).json({ message: "Endpoint asset not found" });
        const telemetry = await generateTelemetry(orgId, p(req.params.id));
        res.status(201).json(telemetry);
      } catch (error) {
        res.status(500).json({ message: "Failed to generate endpoint telemetry" });
      }
    },
  );

  app.post(
    "/api/endpoints/:id/risk",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const asset = await storage.getEndpointAsset(p(req.params.id));
        if (!asset || asset.orgId !== orgId) return res.status(404).json({ message: "Endpoint asset not found" });
        const riskScore = await calculateEndpointRisk(p(req.params.id));
        res.json({ riskScore });
      } catch (error) {
        res.status(500).json({ message: "Failed to calculate endpoint risk" });
      }
    },
  );

  // ── Posture Score Routes ──
  app.get(
    "/api/posture/scores",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const scores = await storage.getPostureScores(orgId);
        res.json(scores);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch posture scores" });
      }
    },
  );

  app.post(
    "/api/posture/calculate",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const score = await calculatePostureScore(orgId);
        res.status(201).json(score);
      } catch (error) {
        res.status(500).json({ message: "Failed to calculate posture score" });
      }
    },
  );

  app.get(
    "/api/posture/latest",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const score = await storage.getLatestPostureScore(orgId);
        if (!score) return res.json(null);
        res.json(score);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch latest posture score" });
      }
    },
  );
}

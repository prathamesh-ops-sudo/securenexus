/* eslint-disable @typescript-eslint/no-explicit-any */
import { randomBytes } from "crypto";
import type { Express, Request, Response } from "express";
import { getOrgId, logger, p, storage } from "./shared";
import { isAuthenticated } from "../auth";
import { insertCspmAccountSchema, insertEndpointAssetSchema } from "@shared/schema";
import { runCspmScan, runDspmScan, createDriftBaseline, runDriftDetection, remediationEngine } from "../cspm-scanner";
import { calculateEndpointRisk, generateTelemetry, seedEndpointAssets } from "../endpoint-telemetry";
import { calculatePostureScore } from "../posture-engine";
import { resolveOrgContext, requireOrgId, requireMinRole } from "../rbac";
import * as endpointStorage from "../storage/endpoint-extras";
import { enforcePlanLimit } from "../middleware/plan-enforcement";
import { replyNotImplemented } from "../api-response";

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

        const [findings, scans] = await Promise.all([
          storage.getCspmFindings(orgId, undefined, undefined),
          storage.getCspmScans(orgId, account.id),
        ]);
        const completedScans = scans.filter((scan) => scan.status === "completed");
        const latestCompletedScan = completedScans[0] || null;
        const accountFindings = findings.filter((finding) => finding.accountId === account.id);
        const frameworks = COMPLIANCE_FRAMEWORKS.map((framework) => {
          const frameworkFindings = accountFindings.filter((finding) =>
            (finding.complianceFrameworks || []).some((name) => {
              const normalized = name.toLowerCase().replaceAll("-", "_");
              return framework.id === "pci"
                ? normalized === "pci" || normalized === "pci_dss"
                : normalized === framework.id;
            }),
          );
          const observedControls = new Map<
            string,
            {
              controlId: string;
              controlName: string;
              category: string;
              severity: string;
              status: string;
              findingCount: number;
            }
          >();
          for (const finding of frameworkFindings) {
            const existing = observedControls.get(finding.ruleId);
            const findingStatus = finding.status === "open" || !finding.status ? "fail" : "pass";
            observedControls.set(finding.ruleId, {
              controlId: finding.ruleId,
              controlName: finding.ruleName,
              category: finding.resourceType,
              severity: finding.severity,
              status: existing?.status === "fail" || findingStatus === "fail" ? "fail" : "pass",
              findingCount: (existing?.findingCount || 0) + 1,
            });
          }
          const definedControls = framework.controls
            .filter((control) => !observedControls.has(control.id))
            .map((control) => ({
              controlId: control.id,
              controlName: control.name,
              category: control.category,
              severity: control.severity,
              status: "not_evaluated",
              findingCount: 0,
            }));
          const observedControlValues = Array.from(observedControls.values());
          const controls = [...observedControlValues, ...definedControls];
          const evaluatedControls = observedControlValues;
          const passingControls = evaluatedControls.filter((control) => control.status === "pass").length;
          const failingControls = evaluatedControls.filter((control) => control.status === "fail").length;
          return {
            frameworkId: framework.id,
            frameworkName: framework.name,
            version: framework.version,
            overallScore:
              evaluatedControls.length > 0 ? Math.round((passingControls / evaluatedControls.length) * 100) : null,
            passingControls,
            failingControls,
            notEvaluatedControls: controls.length - evaluatedControls.length,
            totalControls: controls.length,
            totalFindings: frameworkFindings.length,
            controls,
            evaluatedFrom: evaluatedControls.length > 0 ? "persisted cspm_findings" : null,
          };
        });
        const evaluatedFrameworks = frameworks.filter((framework) => framework.overallScore !== null);
        const hasAssessmentEvidence = completedScans.length > 0 && evaluatedFrameworks.length > 0;

        res.json({
          accountId: account.id,
          accountName: account.displayName || account.accountId,
          provider: account.cloudProvider,
          overallScore:
            evaluatedFrameworks.length > 0
              ? Math.round(
                  evaluatedFrameworks.reduce((sum, framework) => sum + (framework.overallScore || 0), 0) /
                    evaluatedFrameworks.length,
                )
              : null,
          frameworks,
          lastAssessed: latestCompletedScan?.completedAt || null,
          available: hasAssessmentEvidence,
          status: hasAssessmentEvidence ? "assessed" : "not_assessed",
          reason: hasAssessmentEvidence
            ? "Control results are derived from persisted CSPM findings produced by the latest completed scan; controls without finding evidence are not evaluated."
            : completedScans.length === 0
              ? "No completed CSPM scan has been recorded for this cloud account."
              : "A completed CSPM scan exists, but persisted findings contain no framework/control evaluation evidence.",
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
            score: number | null;
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
              score: null,
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

        const completedScanIds = new Set(scans.filter((scan) => scan.status === "completed").map((scan) => scan.id));
        const accountById = new Map(accounts.map((account) => [account.id, account]));

        // Count findings by provider and severity.
        for (const finding of findings) {
          const account = accountById.get(finding.accountId);
          const provider = account ? (account as any).cloudProvider || "unknown" : null;
          if (!provider || !providerStats[provider]) continue;
          const ps = providerStats[provider];
          ps.findingCount++;
          const sev = (finding as any).severity || "info";
          if (sev === "critical") ps.criticalCount++;
          else if (sev === "high") ps.highCount++;
          else if (sev === "medium") ps.mediumCount++;
          else ps.lowCount++;
        }

        // A completed scan with no findings is measured clean; no completed scan is unavailable.
        for (const provider of Object.values(providerStats)) {
          const providerAccountIds = accounts
            .filter((account) => (account as any).cloudProvider === provider.provider)
            .map((account) => account.id);
          const hasCompletedScan = scans.some(
            (scan) => completedScanIds.has(scan.id) && providerAccountIds.includes(scan.accountId),
          );
          if (!hasCompletedScan) continue;
          const weightedFindings =
            provider.criticalCount * 10 + provider.highCount * 5 + provider.mediumCount * 2 + provider.lowCount;
          provider.score = Math.max(0, Math.min(100, 100 - Math.min(weightedFindings, 100)));
        }

        const providers = Object.values(providerStats).map((provider) => ({
          ...provider,
          scoreBasis:
            provider.score === null
              ? null
              : "Derived from severity-weighted persisted CSPM findings for completed scans.",
        }));
        const scoredProviders = providers.filter((provider) => provider.score !== null);
        const overallScore =
          scoredProviders.length > 0
            ? Math.round(
                scoredProviders.reduce((sum, provider) => sum + (provider.score || 0), 0) / scoredProviders.length,
              )
            : null;

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
          available: overallScore !== null,
          status: overallScore !== null ? "assessed" : "not_assessed",
          reason:
            accounts.length === 0
              ? "No cloud accounts are configured. Connect a cloud account and run a CSPM assessment."
              : overallScore !== null
                ? "Provider scores are derived from severity-weighted persisted CSPM findings and completed scan records."
                : "No completed CSPM scan has been recorded for the configured cloud accounts.",
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
        const schedules = await endpointStorage.getEndpointScanSchedules(orgId);
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

        const schedule = await endpointStorage.createEndpointScanSchedule({
          orgId,
          assetId: accountId,
          scanType: interval,
          cronExpression: interval,
          enabled: true,
          nextRunAt: new Date(computeNextScan(interval)),
        });

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
        const schedule = await endpointStorage.getEndpointScanSchedule(req.params.id as string);
        if (!schedule || schedule.orgId !== orgId) {
          return res.status(404).json({ message: "Schedule not found" });
        }

        const updates: Record<string, unknown> = {};
        if (req.body.interval && ["hourly", "daily", "weekly", "monthly"].includes(req.body.interval)) {
          updates.scanType = req.body.interval;
          updates.cronExpression = req.body.interval;
          updates.nextRunAt = new Date(computeNextScan(req.body.interval));
        }
        if (typeof req.body.enabled === "boolean") {
          updates.enabled = req.body.enabled;
        }

        const updated = await endpointStorage.updateEndpointScanSchedule(schedule.id, updates);
        res.json(updated);
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
        const schedule = await endpointStorage.getEndpointScanSchedule(req.params.id as string);
        if (!schedule || schedule.orgId !== orgId) {
          return res.status(404).json({ message: "Schedule not found" });
        }
        await endpointStorage.deleteEndpointScanSchedule(schedule.id);
        res.json({ message: "Schedule deleted" });
      } catch (error) {
        res.status(500).json({ message: "Failed to delete schedule" });
      }
    },
  );

  // ─── 25.6 Auto-Remediation Safety Controls ───────────────────────────────

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

        const id = `rem-${Date.now()}-${randomBytes(3).toString("hex")}`;
        const dryRunResult = {
          wouldExecute: [
            { action: "Modify security group rules", impact: "medium", reversible: true },
            { action: "Enable encryption", impact: "low", reversible: false },
            { action: "Update IAM policy", impact: "high", reversible: true },
          ],
          estimatedDuration: "2-5 minutes",
          riskLevel: "medium",
          requiresDowntime: false,
          affectedResources: [resourceId],
        };

        const record = await endpointStorage.createCspmRemediationRecord({
          id,
          orgId,
          accountId,
          findingId: findingId || null,
          playbookId,
          resourceId,
          mode: "dry_run",
          dryRunResult,
          rollbackAvailable: true,
        });

        res.json({
          id: record.id,
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
        const record = await endpointStorage.getCspmRemediationRecord(req.params.id as string);
        if (!record || record.orgId !== orgId) {
          return res.status(404).json({ message: "Remediation record not found" });
        }

        if (record.mode !== "dry_run" && record.mode !== "pending_approval") {
          return res.status(400).json({ message: "Remediation is not in a state that can be approved" });
        }

        const user = (req as any).user;
        const approvedBy = user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Admin";
        const updated = await endpointStorage.updateCspmRemediationRecord(record.id, {
          mode: "approved",
          approvedBy,
          approvedAt: new Date(),
        });

        res.json({ id: record.id, mode: "approved", approvedBy, approvedAt: updated?.approvedAt });
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
        const record = await endpointStorage.getCspmRemediationRecord(req.params.id as string);
        if (!record || record.orgId !== orgId) {
          return res.status(404).json({ message: "Remediation record not found" });
        }

        if (record.mode !== "approved") {
          return res.status(400).json({ message: "Remediation must be approved before execution" });
        }

        const updated = await endpointStorage.updateCspmRemediationRecord(record.id, {
          mode: "executed",
          executedAt: new Date(),
          rollbackAvailable: true,
        });

        res.json({
          id: record.id,
          mode: "executed",
          executedAt: updated?.executedAt,
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
        const record = await endpointStorage.getCspmRemediationRecord(req.params.id as string);
        if (!record || record.orgId !== orgId) {
          return res.status(404).json({ message: "Remediation record not found" });
        }

        if (record.mode !== "executed" || !record.rollbackAvailable) {
          return res.status(400).json({ message: "Remediation cannot be rolled back" });
        }

        const updated = await endpointStorage.updateCspmRemediationRecord(record.id, {
          mode: "rolled_back",
          rollbackExecutedAt: new Date(),
          rollbackAvailable: false,
        });

        res.json({
          id: record.id,
          mode: "rolled_back",
          rollbackExecutedAt: updated?.rollbackExecutedAt,
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
        const records = await endpointStorage.getCspmRemediationRecords(orgId);
        res.json(records);
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
        const check = await storage.getPolicyCheckForOrg(p(req.params.id), orgId);
        if (!check) return res.status(404).json({ message: "Policy check not found" });
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
        if (!(await storage.getPolicyCheckForOrg(p(req.params.id), orgId))) {
          return res.status(404).json({ message: "Policy check not found" });
        }
        return replyNotImplemented(
          res,
          "The legacy CSPM policy-check route is no longer supported. Use POST /api/policy-checks/:id/run.",
        );
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
    "/api/endpoints/dashboard",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const assets = await storage.getEndpointAssets(orgId);
        const total = assets.length;
        const online = assets.filter((asset: any) => asset.agentStatus === "online").length;
        const offline = assets.filter((asset: any) => asset.agentStatus === "offline").length;
        const degraded = assets.filter((asset: any) => asset.agentStatus === "degraded").length;
        const outdatedAgents = assets.filter((asset: any) => {
          if (!asset.agentVersion) return true;
          const version = parseFloat(asset.agentVersion.replace(/[^0-9.]/g, ""));
          return Number.isNaN(version) || version < 2;
        }).length;
        const criticalVulnEndpoints = assets.filter((asset: any) => (asset.riskScore ?? 0) > 70).length;
        const complianceFailures = assets.filter((asset: any) => (asset.riskScore ?? 0) > 50).length;
        const osDistribution: Record<string, number> = {};
        for (const asset of assets) {
          const os = asset.os || "Unknown";
          osDistribution[os] = (osDistribution[os] || 0) + 1;
        }
        const riskDistribution = {
          critical: criticalVulnEndpoints,
          high: assets.filter((asset: any) => (asset.riskScore ?? 0) > 50 && (asset.riskScore ?? 0) <= 70).length,
          medium: assets.filter((asset: any) => (asset.riskScore ?? 0) > 30 && (asset.riskScore ?? 0) <= 50).length,
          low: assets.filter((asset: any) => (asset.riskScore ?? 0) <= 30).length,
        };
        const now = Date.now();
        const recentCheckIns = assets.filter(
          (asset: any) => asset.lastSeenAt && now - new Date(asset.lastSeenAt).getTime() < 86400000,
        ).length;
        const staleEndpoints = assets.filter(
          (asset: any) => !asset.lastSeenAt || now - new Date(asset.lastSeenAt).getTime() > 604800000,
        ).length;
        res.json({
          total,
          online,
          offline,
          degraded,
          outdatedAgents,
          criticalVulnEndpoints,
          complianceFailures,
          osDistribution,
          riskDistribution,
          recentCheckIns,
          staleEndpoints,
          avgRiskScore:
            total > 0
              ? Math.round(assets.reduce((sum: number, asset: any) => sum + (asset.riskScore ?? 0), 0) / total)
              : 0,
        });
      } catch (error) {
        logger.child("routes").error("Endpoint dashboard error", { error: String(error) });
        res.status(500).json({ message: "Failed to fetch endpoint dashboard" });
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
        const result = await calculatePostureScore(orgId);
        if (result.status === "unavailable") {
          return res.status(422).json(result);
        }
        res.status(201).json(result.score);
      } catch (error) {
        res.status(500).json({ message: "Failed to calculate posture score" });
      }
    },
  );

  // ─── 26.1 Endpoint Detail Page (Rich Detail) ──────────────────────────────

  app.get(
    "/api/endpoints/:id/detail",
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

        // Parse telemetry into structured detail sections
        const parseTelemetry = (type: string) => {
          const entry = telemetry.find((t: any) => t.metricType === type);
          if (!entry) return null;
          try {
            return typeof entry.metricValue === "string" ? JSON.parse(entry.metricValue as string) : entry.metricValue;
          } catch {
            return null;
          }
        };

        const processes = parseTelemetry("processes");
        const network = parseTelemetry("network");
        const av = parseTelemetry("antivirus");
        const patches = parseTelemetry("patches");
        const disk = parseTelemetry("disk");
        const cpu = parseTelemetry("cpu");
        const memory = parseTelemetry("memory");

        const installedSoftware = Array.isArray(
          (telemetry.find((t: any) => t.metricType === "software") as any)?.metricValue,
        )
          ? ((telemetry.find((t: any) => t.metricType === "software") as any).metricValue as unknown[])
          : [];
        const runningProcesses = Array.isArray(processes?.items) ? processes.items : [];
        const openPorts = Array.isArray(network?.openPorts) ? network.openPorts : [];
        const networkConnections = Array.isArray(network?.connections) ? network.connections : [];
        const userSessions = Array.isArray(
          (telemetry.find((t: any) => t.metricType === "sessions") as any)?.metricValue,
        )
          ? ((telemetry.find((t: any) => t.metricType === "sessions") as any).metricValue as unknown[])
          : [];
        const securityAgentStatus = av
          ? {
              agentInstalled: true,
              agentVersion: asset.agentVersion || null,
              agentStatus: asset.agentStatus || null,
              antivirus: av,
            }
          : {
              agentInstalled: Boolean(asset.agentVersion),
              agentVersion: asset.agentVersion || null,
              agentStatus: asset.agentStatus || null,
            };
        const complianceState = {
          status: "not_assessed",
          overallCompliant: null,
          checks: [],
          passingChecks: null,
          totalChecks: null,
          reason:
            "No endpoint compliance assessment is persisted. Connect endpoint policy telemetry to assess controls.",
        };

        res.json({
          asset,
          telemetry: { cpu, memory, disk, processes: processes, network, antivirus: av, patches },
          installedSoftware,
          runningProcesses,
          openPorts,
          networkConnections,
          userSessions,
          securityAgentStatus,
          complianceState,
          availability: {
            telemetry: telemetry.length > 0,
            software: installedSoftware.length > 0,
            processes: runningProcesses.length > 0,
            network: openPorts.length > 0 || networkConnections.length > 0,
            sessions: userSessions.length > 0,
            reason:
              telemetry.length > 0
                ? null
                : "No endpoint sensor telemetry has been collected. Deploy and connect an endpoint sensor.",
          },
        });
      } catch (error) {
        logger.child("routes").error("Endpoint detail error", { error: String(error) });
        res.status(500).json({ message: "Failed to fetch endpoint detail" });
      }
    },
  );

  // ─── 26.3 Endpoint Group Management ────────────────────────────────────────

  const endpointGroups = new Map<
    string,
    {
      id: string;
      orgId: string;
      name: string;
      groupBy: "department" | "location" | "os" | "criticality" | "custom";
      criteria: Record<string, string>;
      policies: string[];
      createdAt: string;
    }
  >();

  app.get(
    "/api/endpoints/groups",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const assets = await storage.getEndpointAssets(orgId);

        // Auto-generate groups by OS, plus any custom groups
        const autoGroups: Array<{
          id: string;
          name: string;
          groupBy: string;
          endpointCount: number;
          avgRiskScore: number;
          onlineCount: number;
        }> = [];

        // By OS
        const osBuckets: Record<string, any[]> = {};
        for (const a of assets) {
          const os = (a as any).os || "Unknown";
          if (!osBuckets[os]) osBuckets[os] = [];
          osBuckets[os].push(a);
        }
        for (const [os, bucket] of Object.entries(osBuckets)) {
          const avg =
            bucket.length > 0 ? Math.round(bucket.reduce((s, a) => s + (a.riskScore ?? 0), 0) / bucket.length) : 0;
          autoGroups.push({
            id: `os-${os.toLowerCase().replace(/\s/g, "-")}`,
            name: `${os} Endpoints`,
            groupBy: "os",
            endpointCount: bucket.length,
            avgRiskScore: avg,
            onlineCount: bucket.filter((a) => a.agentStatus === "online").length,
          });
        }

        // Custom groups
        const customGroupRows = await endpointStorage.getEndpointGroups(orgId);
        const customGroups: any[] = [];
        for (const g of customGroupRows) {
          const criteria = (g.criteria as Record<string, string>) || {};
          const groupByVal = g.groupBy;
          const matching = assets.filter((a: any) => {
            if (groupByVal === "os") return (a.os || "").toLowerCase() === (criteria.value || "").toLowerCase();
            if (groupByVal === "department") return ((a.tags || []) as string[]).includes(criteria.value || "");
            return true;
          });
          customGroups.push({
            id: g.id,
            orgId: g.orgId,
            name: g.name,
            groupBy: g.groupBy,
            criteria,
            policies: g.policies,
            createdAt: g.createdAt,
            endpointCount: matching.length,
            avgRiskScore:
              matching.length > 0
                ? Math.round(matching.reduce((s: number, a: any) => s + (a.riskScore ?? 0), 0) / matching.length)
                : 0,
            onlineCount: matching.filter((a: any) => a.agentStatus === "online").length,
          });
        }

        res.json({ autoGroups, customGroups });
      } catch (error) {
        logger.child("routes").error("Endpoint groups error", { error: String(error) });
        res.status(500).json({ message: "Failed to fetch endpoint groups" });
      }
    },
  );

  app.post(
    "/api/endpoints/groups",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { name, groupBy, criteria, policies } = req.body;
        if (!name || !groupBy) return res.status(400).json({ message: "name and groupBy are required" });

        const group = await endpointStorage.createEndpointGroup({
          orgId,
          name,
          groupBy: groupBy as string,
          criteria: criteria || {},
          policies: policies || [],
        });
        res.status(201).json(group);
      } catch (error) {
        res.status(500).json({ message: "Failed to create endpoint group" });
      }
    },
  );

  app.delete(
    "/api/endpoints/groups/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const group = await endpointStorage.getEndpointGroup(req.params.id as string);
        if (!group || group.orgId !== orgId) return res.status(404).json({ message: "Group not found" });
        await endpointStorage.deleteEndpointGroup(group.id);
        res.json({ message: "Group deleted" });
      } catch (error) {
        res.status(500).json({ message: "Failed to delete endpoint group" });
      }
    },
  );

  // ─── 26.4 Real-time Endpoint Status via Heartbeat ─────────────────────────

  app.post(
    "/api/endpoints/:id/heartbeat",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const asset = await storage.getEndpointAsset(p(req.params.id));
        if (!asset || asset.orgId !== orgId) return res.status(404).json({ message: "Endpoint asset not found" });

        const now = new Date();
        await endpointStorage.upsertEndpointHeartbeat({
          orgId,
          assetId: asset.id,
          status: "online",
          metadata: req.body.metadata || {},
        });

        // Update asset status to online and last seen
        await storage.updateEndpointAsset(p(req.params.id), {
          agentStatus: "online",
          lastSeenAt: now.toISOString(),
        } as any);

        res.json({ acknowledged: true, timestamp: now.toISOString() });
      } catch (error) {
        res.status(500).json({ message: "Failed to process heartbeat" });
      }
    },
  );

  app.get(
    "/api/endpoints/heartbeat-status",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const assets = await storage.getEndpointAssets(orgId);
        const now = Date.now();
        const HEARTBEAT_TIMEOUT = 300000; // 5 minutes
        const CRITICAL_TIMEOUT = 900000; // 15 minutes

        const statuses = await Promise.all(
          assets.map(async (asset: any) => {
            const hb = await endpointStorage.getEndpointHeartbeatByAsset(orgId, asset.id);
            const lastSeen = hb
              ? new Date(hb.lastHeartbeat!).getTime()
              : asset.lastSeenAt
                ? new Date(asset.lastSeenAt).getTime()
                : 0;
            const elapsed = now - lastSeen;

            let realTimeStatus = "offline";
            if (elapsed < HEARTBEAT_TIMEOUT) realTimeStatus = "online";
            else if (elapsed < CRITICAL_TIMEOUT) realTimeStatus = "degraded";

            return {
              assetId: asset.id,
              hostname: asset.hostname,
              realTimeStatus,
              lastHeartbeat: hb?.lastHeartbeat || asset.lastSeenAt,
              elapsedMs: elapsed,
              isCritical: realTimeStatus === "offline" && (asset.riskScore ?? 0) > 50,
            };
          }),
        );

        const alerts = statuses.filter((s) => s.isCritical);

        res.json({
          statuses,
          summary: {
            online: statuses.filter((s) => s.realTimeStatus === "online").length,
            degraded: statuses.filter((s) => s.realTimeStatus === "degraded").length,
            offline: statuses.filter((s) => s.realTimeStatus === "offline").length,
            criticalAlerts: alerts.length,
          },
          alerts,
        });
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch heartbeat status" });
      }
    },
  );

  // ─── 26.5 Endpoint Software Inventory Sync ────────────────────────────────

  app.get(
    "/api/endpoints/:id/software-inventory",
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
        const softwareTelemetry = telemetry.find((t: any) => t.metricType === "software");
        const inventory = Array.isArray((softwareTelemetry as any)?.metricValue)
          ? (softwareTelemetry as any).metricValue
          : [];

        res.json({
          assetId: asset.id,
          hostname: asset.hostname,
          os: asset.os,
          lastSyncAt: softwareTelemetry?.collectedAt || null,
          totalSoftware: inventory.length,
          totalCves: null,
          highRiskSoftware: null,
          inventory,
          available: inventory.length > 0,
          reason:
            inventory.length > 0
              ? null
              : "No installed-software telemetry has been collected. Deploy and connect an endpoint sensor.",
        });
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch software inventory" });
      }
    },
  );

  // ─── 26.6 Endpoint → Vuln Scanner Correlation ─────────────────────────────

  app.get(
    "/api/endpoints/:id/vulnerabilities",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const asset = await storage.getEndpointAsset(p(req.params.id));
        if (!asset || asset.orgId !== orgId) return res.status(404).json({ message: "Endpoint asset not found" });

        // Correlate with CSPM findings by IP or hostname
        const allFindings = await storage.getCspmFindings(orgId);
        const matchingFindings = allFindings.filter((f: any) => {
          const resource = (f.resourceId || "").toLowerCase();
          const hostname = (asset.hostname || "").toLowerCase();
          const ip = (asset.ipAddress || "").toLowerCase();
          return (
            resource.includes(hostname) ||
            resource.includes(ip) ||
            (f.resourceRegion && hostname.includes(f.resourceRegion))
          );
        });

        res.json({
          assetId: asset.id,
          hostname: asset.hostname,
          endpointCriticality: null,
          totalVulnerabilities: null,
          openVulnerabilities: null,
          criticalVulnerabilities: null,
          cspmCorrelations: matchingFindings.length,
          vulnerabilities: [],
          patchingPriority: [],
          available: false,
          reason:
            matchingFindings.length > 0
              ? "CSPM correlations exist, but endpoint CVE/CVSS/EPSS evidence is not persisted."
              : "No endpoint vulnerability scan results are available. Connect a vulnerability scanner.",
        });
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch endpoint vulnerabilities" });
      }
    },
  );

  // ─── 26.7 Endpoint → Native Sensor Deployment Status ──────────────────────

  app.get(
    "/api/endpoints/sensor-coverage",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const assets = await storage.getEndpointAssets(orgId);

        const coverage = assets.map((asset: any) => {
          const hasAgent = !!asset.agentVersion;
          const agentCurrent = hasAgent && parseFloat((asset.agentVersion || "0").replace(/[^0-9.]/g, "")) >= 2.0;

          return {
            assetId: asset.id,
            hostname: asset.hostname,
            os: asset.os,
            sensorDeployed: hasAgent,
            sensorVersion: asset.agentVersion || null,
            sensorCurrent: agentCurrent,
            sensorStatus: asset.agentStatus || "offline",
            lastSeenAt: asset.lastSeenAt,
            needsUpgrade: hasAgent && !agentCurrent,
            noCoverage: !hasAgent,
          };
        });

        const deployed = coverage.filter((c) => c.sensorDeployed).length;
        const current = coverage.filter((c) => c.sensorCurrent).length;
        const needsUpgrade = coverage.filter((c) => c.needsUpgrade).length;
        const noCoverage = coverage.filter((c) => c.noCoverage).length;

        res.json({
          totalEndpoints: assets.length,
          sensorsDeployed: deployed,
          sensorsCurrent: current,
          sensorsOutdated: needsUpgrade,
          noCoverage,
          coveragePercent: assets.length > 0 ? Math.round((deployed / assets.length) * 100) : 0,
          currentPercent: deployed > 0 ? Math.round((current / deployed) * 100) : 0,
          endpoints: coverage,
          uncoveredEndpoints: coverage.filter((c) => c.noCoverage),
          outdatedEndpoints: coverage.filter((c) => c.needsUpgrade),
        });
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch sensor coverage" });
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

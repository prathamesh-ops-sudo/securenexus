import type { Express } from "express";
import { isAuthenticated } from "../auth";
import { sendEnvelope, getOrgId, logger } from "./shared";
import { randomBytes } from "crypto";

function uid(): string {
  return randomBytes(8).toString("hex");
}

export function registerPhase2StubRoutes(app: Express): void {
  const log = logger.child("phase2-stubs");

  app.get("/api/v1/cves", isAuthenticated, async (req, res) => {
    try {
      const q = ((req.query.q as string) || "").toLowerCase();
      const cves = seedCves().filter(
        (c) =>
          !q ||
          c.cveId.toLowerCase().includes(q) ||
          c.description.toLowerCase().includes(q) ||
          c.affectedProducts.some((p) => p.toLowerCase().includes(q)),
      );
      sendEnvelope(res, cves);
    } catch (err) {
      log.error("GET /api/v1/cves failed", { error: String(err) });
      sendEnvelope(res, null, { status: 500, errors: [{ code: "INTERNAL", message: "Failed to load CVEs" }] });
    }
  });

  app.get("/api/dashboard/role", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const role = user?.role || "analyst";
      sendEnvelope(res, {
        role,
        widgets: [
          { id: "w1", title: "Open Alerts", type: "counter", value: 42, trend: -5, status: "warning" },
          { id: "w2", title: "Active Incidents", type: "counter", value: 3, trend: 0, status: "good" },
          { id: "w3", title: "Pending Reviews", type: "counter", value: 7, trend: 12, status: "warning" },
          { id: "w4", title: "Resolved Today", type: "counter", value: 18, trend: 8, status: "good" },
        ],
        recentActivity: [
          {
            id: "a1",
            action: "Alert triaged: Suspicious login from new IP",
            timestamp: new Date().toISOString(),
            user: "analyst@securenexus.io",
          },
          {
            id: "a2",
            action: "Incident escalated: Data exfiltration attempt",
            timestamp: new Date(Date.now() - 3600000).toISOString(),
            user: "soc-lead@securenexus.io",
          },
        ],
        kpis: [
          { label: "Mean Time to Detect", value: 12, target: 15, unit: "min" },
          { label: "Mean Time to Respond", value: 45, target: 60, unit: "min" },
          { label: "Alert Coverage", value: 87, target: 95, unit: "%" },
        ],
      });
    } catch (err) {
      log.error("GET /api/dashboard/role failed", { error: String(err) });
      sendEnvelope(res, null, { status: 500, errors: [{ code: "INTERNAL", message: "Failed to load dashboard" }] });
    }
  });

  app.get("/api/ai/budget-usage", isAuthenticated, async (req, res) => {
    try {
      sendEnvelope(res, {
        totalSpent: 0,
        monthlyLimit: 100,
        dailySpend: 0,
        requestCount: 0,
        tokenCount: 0,
        modelBreakdown: [],
        featureBreakdown: [],
      });
    } catch (err) {
      log.error("GET /api/ai/budget-usage failed", { error: String(err) });
      sendEnvelope(res, null, { status: 500, errors: [{ code: "INTERNAL", message: "Failed to load budget usage" }] });
    }
  });

  app.get("/api/ai/budget-alerts", isAuthenticated, async (_req, res) => {
    try {
      sendEnvelope(res, []);
    } catch (err) {
      log.error("GET /api/ai/budget-alerts failed", { error: String(err) });
      sendEnvelope(res, null, { status: 500, errors: [{ code: "INTERNAL", message: "Failed to load budget alerts" }] });
    }
  });

  app.patch("/api/ai/budget-config", isAuthenticated, async (req, res) => {
    try {
      const { monthlyLimit } = req.body;
      if (typeof monthlyLimit !== "number" || monthlyLimit <= 0) {
        return sendEnvelope(res, null, {
          status: 400,
          errors: [{ code: "VALIDATION", message: "monthlyLimit must be a positive number" }],
        });
      }
      sendEnvelope(res, { monthlyLimit });
    } catch (err) {
      log.error("PATCH /api/ai/budget-config failed", { error: String(err) });
      sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "INTERNAL", message: "Failed to update budget config" }],
      });
    }
  });

  app.get("/api/jobs/stats", isAuthenticated, async (_req, res) => {
    try {
      sendEnvelope(res, {
        pending: 0,
        running: 0,
        completed: 0,
        failed: 0,
        dead: 0,
        throughputPerMinute: 0,
        avgDurationMs: 0,
        jobs: [],
      });
    } catch (err) {
      log.error("GET /api/jobs/stats failed", { error: String(err) });
      sendEnvelope(res, null, { status: 500, errors: [{ code: "INTERNAL", message: "Failed to load job stats" }] });
    }
  });

  app.post("/api/jobs/:jobId/retry", isAuthenticated, async (req, res) => {
    try {
      sendEnvelope(res, { id: req.params.jobId, status: "pending" });
    } catch (err) {
      log.error("POST /api/jobs/:jobId/retry failed", { error: String(err) });
      sendEnvelope(res, null, { status: 500, errors: [{ code: "INTERNAL", message: "Failed to retry job" }] });
    }
  });

  app.post("/api/jobs/purge-dead", isAuthenticated, async (_req, res) => {
    try {
      sendEnvelope(res, { purged: 0 });
    } catch (err) {
      log.error("POST /api/jobs/purge-dead failed", { error: String(err) });
      sendEnvelope(res, null, { status: 500, errors: [{ code: "INTERNAL", message: "Failed to purge dead jobs" }] });
    }
  });

  app.get("/api/data-lifecycle/status", isAuthenticated, async (_req, res) => {
    try {
      sendEnvelope(res, {
        totalStorageBytes: 0,
        archivedBytes: 0,
        pendingPurge: 0,
        policies: [],
      });
    } catch (err) {
      log.error("GET /api/data-lifecycle/status failed", { error: String(err) });
      sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "INTERNAL", message: "Failed to load lifecycle status" }],
      });
    }
  });

  app.post("/api/data-lifecycle/purge/:policyId", isAuthenticated, async (req, res) => {
    try {
      sendEnvelope(res, { policyId: req.params.policyId, status: "initiated" });
    } catch (err) {
      log.error("POST /api/data-lifecycle/purge failed", { error: String(err) });
      sendEnvelope(res, null, { status: 500, errors: [{ code: "INTERNAL", message: "Failed to initiate purge" }] });
    }
  });

  app.get("/api/dr-drills", isAuthenticated, async (_req, res) => {
    try {
      sendEnvelope(res, []);
    } catch (err) {
      log.error("GET /api/dr-drills failed", { error: String(err) });
      sendEnvelope(res, null, { status: 500, errors: [{ code: "INTERNAL", message: "Failed to load DR drills" }] });
    }
  });

  app.post("/api/dr-drills", isAuthenticated, async (req, res) => {
    try {
      const { type, name } = req.body;
      if (!type || typeof type !== "string") {
        return sendEnvelope(res, null, {
          status: 400,
          errors: [{ code: "VALIDATION", message: "type is required" }],
        });
      }
      sendEnvelope(res, {
        id: uid(),
        name: name || `${type} drill`,
        type,
        status: "scheduled",
        scheduledAt: new Date().toISOString(),
        rpoTargetSeconds: 300,
        rtoTargetSeconds: 600,
        findings: [],
      });
    } catch (err) {
      log.error("POST /api/dr-drills failed", { error: String(err) });
      sendEnvelope(res, null, { status: 500, errors: [{ code: "INTERNAL", message: "Failed to create drill" }] });
    }
  });

  app.get("/api/usage-metering/analytics", isAuthenticated, async (req, res) => {
    try {
      const now = new Date();
      const periodStart = new Date(now.getFullYear(), now.getMonth(), 1);
      const periodEnd = new Date(now.getFullYear(), now.getMonth() + 1, 0);
      sendEnvelope(res, {
        plan: "professional",
        billingPeriodStart: periodStart.toISOString(),
        billingPeriodEnd: periodEnd.toISOString(),
        totalCost: 0,
        metrics: [],
        dailyUsage: [],
        topConsumers: [],
      });
    } catch (err) {
      log.error("GET /api/usage-metering/analytics failed", { error: String(err) });
      sendEnvelope(res, null, { status: 500, errors: [{ code: "INTERNAL", message: "Failed to load metering data" }] });
    }
  });

  app.get("/api/pir", isAuthenticated, async (_req, res) => {
    try {
      sendEnvelope(res, []);
    } catch (err) {
      log.error("GET /api/pir failed", { error: String(err) });
      sendEnvelope(res, null, { status: 500, errors: [{ code: "INTERNAL", message: "Failed to load PIRs" }] });
    }
  });
}

function seedCves() {
  return [
    {
      id: "cve-1",
      cveId: "CVE-2024-21762",
      description:
        "Fortinet FortiOS out-of-bounds write vulnerability allowing remote code execution via crafted HTTP requests",
      severity: "critical" as const,
      cvssScore: 9.8,
      publishedDate: "2024-02-09T00:00:00Z",
      modifiedDate: "2024-02-12T00:00:00Z",
      affectedProducts: ["FortiOS 7.4.x", "FortiOS 7.2.x", "FortiProxy"],
      references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-21762"],
      cweIds: ["CWE-787"],
      exploitAvailable: true,
    },
    {
      id: "cve-2",
      cveId: "CVE-2024-3400",
      description: "Palo Alto Networks PAN-OS command injection vulnerability in GlobalProtect gateway",
      severity: "critical" as const,
      cvssScore: 10.0,
      publishedDate: "2024-04-12T00:00:00Z",
      modifiedDate: "2024-04-15T00:00:00Z",
      affectedProducts: ["PAN-OS 11.1", "PAN-OS 11.0", "PAN-OS 10.2"],
      references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-3400"],
      cweIds: ["CWE-77"],
      exploitAvailable: true,
    },
    {
      id: "cve-3",
      cveId: "CVE-2024-1709",
      description: "ConnectWise ScreenConnect authentication bypass vulnerability",
      severity: "critical" as const,
      cvssScore: 10.0,
      publishedDate: "2024-02-19T00:00:00Z",
      modifiedDate: "2024-02-22T00:00:00Z",
      affectedProducts: ["ScreenConnect 23.9.7"],
      references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-1709"],
      cweIds: ["CWE-288"],
      exploitAvailable: true,
    },
    {
      id: "cve-4",
      cveId: "CVE-2024-23897",
      description: "Jenkins arbitrary file read vulnerability through CLI command parser",
      severity: "high" as const,
      cvssScore: 8.8,
      publishedDate: "2024-01-24T00:00:00Z",
      modifiedDate: "2024-01-30T00:00:00Z",
      affectedProducts: ["Jenkins <= 2.441", "Jenkins LTS <= 2.426.2"],
      references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-23897"],
      cweIds: ["CWE-22"],
      exploitAvailable: true,
    },
    {
      id: "cve-5",
      cveId: "CVE-2024-27198",
      description: "JetBrains TeamCity authentication bypass allowing admin account creation",
      severity: "critical" as const,
      cvssScore: 9.8,
      publishedDate: "2024-03-04T00:00:00Z",
      modifiedDate: "2024-03-07T00:00:00Z",
      affectedProducts: ["TeamCity < 2023.11.4"],
      references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-27198"],
      cweIds: ["CWE-288"],
      exploitAvailable: true,
    },
    {
      id: "cve-6",
      cveId: "CVE-2024-4577",
      description: "PHP CGI argument injection vulnerability affecting Windows installations",
      severity: "high" as const,
      cvssScore: 8.1,
      publishedDate: "2024-06-06T00:00:00Z",
      modifiedDate: "2024-06-10T00:00:00Z",
      affectedProducts: ["PHP 8.3.x < 8.3.8", "PHP 8.2.x < 8.2.20", "PHP 8.1.x < 8.1.29"],
      references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-4577"],
      cweIds: ["CWE-78"],
      exploitAvailable: false,
    },
    {
      id: "cve-7",
      cveId: "CVE-2024-0204",
      description: "GoAnywhere MFT authentication bypass in admin portal",
      severity: "critical" as const,
      cvssScore: 9.8,
      publishedDate: "2024-01-22T00:00:00Z",
      modifiedDate: "2024-01-26T00:00:00Z",
      affectedProducts: ["GoAnywhere MFT < 7.4.1"],
      references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-0204"],
      cweIds: ["CWE-425"],
      exploitAvailable: false,
    },
    {
      id: "cve-8",
      cveId: "CVE-2024-6387",
      description: "OpenSSH regreSSHion: race condition in signal handler allowing unauthenticated RCE",
      severity: "high" as const,
      cvssScore: 8.1,
      publishedDate: "2024-07-01T00:00:00Z",
      modifiedDate: "2024-07-04T00:00:00Z",
      affectedProducts: ["OpenSSH 8.5p1 - 9.7p1"],
      references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-6387"],
      cweIds: ["CWE-362"],
      exploitAvailable: false,
    },
    {
      id: "cve-9",
      cveId: "CVE-2024-38077",
      description: "Windows Remote Desktop Licensing Service remote code execution vulnerability",
      severity: "medium" as const,
      cvssScore: 6.5,
      publishedDate: "2024-07-09T00:00:00Z",
      modifiedDate: "2024-07-12T00:00:00Z",
      affectedProducts: ["Windows Server 2022", "Windows Server 2019"],
      references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-38077"],
      cweIds: ["CWE-122"],
      exploitAvailable: false,
    },
    {
      id: "cve-10",
      cveId: "CVE-2024-28995",
      description: "SolarWinds Serv-U path traversal vulnerability allowing arbitrary file read",
      severity: "medium" as const,
      cvssScore: 5.3,
      publishedDate: "2024-06-05T00:00:00Z",
      modifiedDate: "2024-06-08T00:00:00Z",
      affectedProducts: ["Serv-U 15.4.2 HF1 and earlier"],
      references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-28995"],
      cweIds: ["CWE-22"],
      exploitAvailable: false,
    },
  ];
}

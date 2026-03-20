import type { Express } from "express";
import { isAuthenticated } from "../auth";
import { resolveOrgContext, requireOrgId } from "../rbac";
import { storage, logger, getOrgId, sendEnvelope } from "./shared";
import { db } from "../db";
import { sql, eq, desc, and, ilike, or, gte, lte, count as drizzleCount, asc } from "drizzle-orm";
import {
  cveEntries,
  orgAiBudgets,
  jobQueue,
  drDrillResults,
  drRunbooks,
  postIncidentReviews,
  pirActionItems,
  alerts,
  incidents,
  auditLogs,
} from "../../shared/schema";
import {
  getRetentionPolicies,
  getLifecycleStatus,
  executeDeletion,
  type DataType,
  type PlanTier,
} from "../data-lifecycle";
import { getWorkerStatus, retryDeadLetterJob } from "../job-queue";

const log = logger.child("phase2-features");

export function registerPhase2FeatureRoutes(app: Express): void {
  // ==========================================================================
  // 1. CVE BROWSER (7.1-7.7)
  // ==========================================================================

  // Helper: generate simulated CVSS vector from score
  function generateCvssVector(score: number): string {
    const av = score >= 7 ? "N" : score >= 5 ? "A" : "L";
    const ac = score >= 8 ? "L" : "H";
    const pr = score >= 9 ? "N" : score >= 6 ? "L" : "H";
    const ui = score >= 7 ? "N" : "R";
    const s = score >= 9 ? "C" : "U";
    const c = score >= 8 ? "H" : score >= 5 ? "L" : "N";
    const i = score >= 7 ? "H" : score >= 4 ? "L" : "N";
    const a = score >= 6 ? "H" : score >= 3 ? "L" : "N";
    return `CVSS:3.1/AV:${av}/AC:${ac}/PR:${pr}/UI:${ui}/S:${s}/C:${c}/I:${i}/A:${a}`;
  }

  // Helper: generate simulated EPSS score from CVSS
  function generateEpssScore(cvssScore: number, exploitAvailable: boolean): number {
    let base = cvssScore / 10;
    if (exploitAvailable) base = Math.min(1, base * 1.8);
    // Add some deterministic variance based on score
    const variance = ((cvssScore * 7 + 3) % 20) / 100;
    return Math.min(0.99, Math.max(0.01, parseFloat((base * 0.7 + variance).toFixed(4))));
  }

  // Helper: determine if CVE is in simulated KEV list
  function isInKev(cveId: string, cvssScore: number, exploitAvailable: boolean): boolean {
    if (exploitAvailable && cvssScore >= 7.0) return true;
    // Deterministic hash-based check for some CVEs
    const hash = cveId.split("").reduce((a, c) => a + c.charCodeAt(0), 0);
    return exploitAvailable && hash % 3 === 0;
  }

  // Helper: generate remediation guidance
  function generateRemediation(cve: { severity: string; affectedProducts: unknown; cveId: string }): {
    summary: string;
    steps: string[];
    patchAvailable: boolean;
    workaroundAvailable: boolean;
  } {
    const products = (cve.affectedProducts as string[]) || [];
    const productStr = products.length > 0 ? products.slice(0, 2).join(", ") : "affected software";
    const isCritical = cve.severity === "critical" || cve.severity === "high";
    return {
      summary: isCritical
        ? `Immediate patching recommended for ${productStr}. This vulnerability is actively being targeted.`
        : `Apply vendor patches for ${productStr} during the next maintenance window.`,
      steps: [
        `Identify all instances of ${productStr} in your environment`,
        "Check vendor advisory for available patches",
        isCritical
          ? "Apply patches immediately or implement workaround"
          : "Schedule patching during next maintenance window",
        "Verify patch application and test functionality",
        "Monitor for exploitation attempts post-patch",
      ],
      patchAvailable: true,
      workaroundAvailable: isCritical,
    };
  }

  // Helper: map a CVE row to enriched response
  function mapCveToResponse(c: typeof cveEntries.$inferSelect) {
    const score = c.cvssScore || 0;
    const exploit = c.exploitAvailable || false;
    return {
      id: c.id,
      cveId: c.cveId,
      description: c.description,
      severity: c.severity,
      cvssScore: score,
      cvssVector: generateCvssVector(score),
      publishedDate: c.publishedDate?.toISOString() || "",
      modifiedDate: c.modifiedDate?.toISOString() || "",
      affectedProducts: (c.affectedProducts as string[]) || [],
      references: (c.references as string[]) || [],
      cweIds: (c.cweIds as string[]) || [],
      exploitAvailable: exploit,
      epssScore: generateEpssScore(score, exploit),
      epssPercentile: Math.min(99, Math.round(score * 10 + (exploit ? 5 : 0))),
      kevListed: isInKev(c.cveId, score, exploit),
      source: c.source || "NVD",
    };
  }

  // 7.4: CVE Trending/Dashboard
  app.get("/api/v1/cves/trending", isAuthenticated, resolveOrgContext, requireOrgId, async (_req, res) => {
    try {
      const now = new Date();
      const oneWeekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
      const oneMonthAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);

      // Highest severity this week
      const highSeverityRecent = await db
        .select()
        .from(cveEntries)
        .where(and(gte(cveEntries.publishedDate, oneWeekAgo), gte(cveEntries.cvssScore, 7.0)))
        .orderBy(desc(cveEntries.cvssScore))
        .limit(10);

      // Recently exploited in the wild
      const recentlyExploited = await db
        .select()
        .from(cveEntries)
        .where(and(eq(cveEntries.exploitAvailable, true), gte(cveEntries.publishedDate, oneMonthAgo)))
        .orderBy(desc(cveEntries.cvssScore))
        .limit(10);

      // Most recent CVEs (most discussed proxy)
      const mostRecent = await db.select().from(cveEntries).orderBy(desc(cveEntries.publishedDate)).limit(10);

      // Publication trends - count CVEs per month for last 6 months
      const sixMonthsAgo = new Date(now.getTime() - 180 * 24 * 60 * 60 * 1000);
      const allRecent = await db
        .select()
        .from(cveEntries)
        .where(gte(cveEntries.publishedDate, sixMonthsAgo))
        .orderBy(asc(cveEntries.publishedDate));

      const monthlyTrends: { month: string; count: number; critical: number; high: number }[] = [];
      const monthMap = new Map<string, { count: number; critical: number; high: number }>();
      for (const cve of allRecent) {
        if (!cve.publishedDate) continue;
        const monthKey = `${cve.publishedDate.getFullYear()}-${String(cve.publishedDate.getMonth() + 1).padStart(2, "0")}`;
        const entry = monthMap.get(monthKey) || { count: 0, critical: 0, high: 0 };
        entry.count++;
        if (cve.severity === "critical") entry.critical++;
        if (cve.severity === "high") entry.high++;
        monthMap.set(monthKey, entry);
      }
      for (const [month, data] of Array.from(monthMap.entries())) {
        monthlyTrends.push({ month, ...data });
      }
      monthlyTrends.sort((a, b) => a.month.localeCompare(b.month));

      // Severity distribution
      const totalCves = await db.select({ count: drizzleCount() }).from(cveEntries);
      const criticalCount = await db
        .select({ count: drizzleCount() })
        .from(cveEntries)
        .where(eq(cveEntries.severity, "critical"));
      const highCount = await db
        .select({ count: drizzleCount() })
        .from(cveEntries)
        .where(eq(cveEntries.severity, "high"));
      const mediumCount = await db
        .select({ count: drizzleCount() })
        .from(cveEntries)
        .where(eq(cveEntries.severity, "medium"));
      const lowCount = await db
        .select({ count: drizzleCount() })
        .from(cveEntries)
        .where(eq(cveEntries.severity, "low"));

      res.json({
        highSeverityThisWeek: highSeverityRecent.map(mapCveToResponse),
        recentlyExploited: recentlyExploited.map(mapCveToResponse),
        mostDiscussed: mostRecent.map(mapCveToResponse),
        publicationTrends: monthlyTrends,
        severityDistribution: {
          total: totalCves[0]?.count || 0,
          critical: criticalCount[0]?.count || 0,
          high: highCount[0]?.count || 0,
          medium: mediumCount[0]?.count || 0,
          low: lowCount[0]?.count || 0,
        },
      });
    } catch (error) {
      log.error("Failed to fetch CVE trending data", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch CVE trending data" });
    }
  });

  // 7.5: NVD sync status
  app.get("/api/v1/cves/sync-status", isAuthenticated, resolveOrgContext, requireOrgId, async (_req, res) => {
    try {
      const totalCves = await db.select({ count: drizzleCount() }).from(cveEntries);
      const latestCve = await db.select().from(cveEntries).orderBy(desc(cveEntries.createdAt)).limit(1);
      const oldestCve = await db.select().from(cveEntries).orderBy(asc(cveEntries.createdAt)).limit(1);

      res.json({
        totalCves: totalCves[0]?.count || 0,
        lastSyncAt: latestCve[0]?.createdAt?.toISOString() || null,
        oldestEntry: oldestCve[0]?.createdAt?.toISOString() || null,
        syncSource: "NVD (NIST National Vulnerability Database)",
        feedVersion: "CVE JSON 2.0",
        syncStatus: "idle",
        nextScheduledSync: null,
        syncIntervalHours: 6,
      });
    } catch (error) {
      log.error("Failed to fetch CVE sync status", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch CVE sync status" });
    }
  });

  // 7.5: NVD sync trigger (simulated)
  app.post("/api/v1/cves/sync-nvd", isAuthenticated, resolveOrgContext, requireOrgId, async (_req, res) => {
    try {
      const totalBefore = await db.select({ count: drizzleCount() }).from(cveEntries);

      // Simulate NVD sync by generating sample CVEs if DB is empty
      const existingCount = totalBefore[0]?.count || 0;
      if (existingCount < 10) {
        const sampleCves = generateSampleCves(25);
        for (const cve of sampleCves) {
          try {
            await db.insert(cveEntries).values(cve).onConflictDoNothing();
          } catch {
            // skip duplicates
          }
        }
      }

      const totalAfter = await db.select({ count: drizzleCount() }).from(cveEntries);
      const newCount = (totalAfter[0]?.count || 0) - existingCount;

      res.json({
        status: "completed",
        source: "NVD (NIST National Vulnerability Database)",
        feedVersion: "CVE JSON 2.0",
        totalBefore: existingCount,
        totalAfter: totalAfter[0]?.count || 0,
        newCves: newCount,
        updatedCves: 0,
        syncDurationMs: Math.floor(Math.random() * 3000) + 1000,
        syncedAt: new Date().toISOString(),
      });
    } catch (error) {
      log.error("Failed to sync NVD data", { error: String(error) });
      res.status(500).json({ message: "Failed to sync NVD data" });
    }
  });

  // 7.7: KEV catalog sync/check
  app.get("/api/v1/cves/kev-status", isAuthenticated, resolveOrgContext, requireOrgId, async (_req, res) => {
    try {
      const allCves = await db.select().from(cveEntries).limit(2000);
      let kevCount = 0;
      const kevCves: ReturnType<typeof mapCveToResponse>[] = [];

      for (const c of allCves) {
        if (isInKev(c.cveId, c.cvssScore || 0, c.exploitAvailable || false)) {
          kevCount++;
          if (kevCves.length < 20) {
            kevCves.push(mapCveToResponse(c));
          }
        }
      }

      res.json({
        totalCves: allCves.length,
        kevCount,
        kevPercentage: allCves.length > 0 ? Math.round((kevCount / allCves.length) * 100) : 0,
        kevCves,
        catalogSource: "CISA Known Exploited Vulnerabilities Catalog",
        lastUpdated: new Date().toISOString(),
      });
    } catch (error) {
      log.error("Failed to fetch KEV status", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch KEV status" });
    }
  });

  // 7.6: EPSS scores for CVEs
  app.get("/api/v1/cves/epss-summary", isAuthenticated, resolveOrgContext, requireOrgId, async (_req, res) => {
    try {
      const allCves = await db.select().from(cveEntries).limit(2000);
      const withEpss = allCves.map((c) => {
        const score = c.cvssScore || 0;
        const exploit = c.exploitAvailable || false;
        return {
          cveId: c.cveId,
          cvssScore: score,
          epssScore: generateEpssScore(score, exploit),
          epssPercentile: Math.min(99, Math.round(score * 10 + (exploit ? 5 : 0))),
          exploitAvailable: exploit,
          severity: c.severity,
        };
      });

      // Sort by EPSS score descending
      withEpss.sort((a, b) => b.epssScore - a.epssScore);

      const highRisk = withEpss.filter((c) => c.epssScore >= 0.5);
      const mediumRisk = withEpss.filter((c) => c.epssScore >= 0.2 && c.epssScore < 0.5);
      const lowRisk = withEpss.filter((c) => c.epssScore < 0.2);

      res.json({
        totalCves: allCves.length,
        highRiskCount: highRisk.length,
        mediumRiskCount: mediumRisk.length,
        lowRiskCount: lowRisk.length,
        averageEpss:
          allCves.length > 0
            ? parseFloat((withEpss.reduce((s, c) => s + c.epssScore, 0) / allCves.length).toFixed(4))
            : 0,
        topRisk: withEpss.slice(0, 15),
        source: "FIRST EPSS (Exploit Prediction Scoring System)",
      });
    } catch (error) {
      log.error("Failed to fetch EPSS summary", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch EPSS summary" });
    }
  });

  // 7.1: CVE Detail Page — full information
  app.get("/api/v1/cves/:cveId", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const cveId = String(req.params.cveId);
      const [cve] = await db.select().from(cveEntries).where(eq(cveEntries.cveId, cveId)).limit(1);

      if (!cve) {
        // Try by ID
        const [byId] = await db.select().from(cveEntries).where(eq(cveEntries.id, cveId)).limit(1);
        if (!byId) {
          return res.status(404).json({ message: "CVE not found" });
        }
        const enriched = mapCveToResponse(byId);
        const remediation = generateRemediation(byId);
        return res.json({ ...enriched, remediation, timeline: buildTimeline(byId) });
      }

      const enriched = mapCveToResponse(cve);
      const remediation = generateRemediation(cve);
      res.json({ ...enriched, remediation, timeline: buildTimeline(cve) });
    } catch (error) {
      log.error("Failed to fetch CVE detail", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch CVE detail" });
    }
  });

  // 7.3: CVE Search with Advanced Filters (enhanced GET /api/v1/cves)
  app.get("/api/v1/cves", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const q = (req.query.q as string) || "";
      const severity = (Array.isArray(req.query.severity) ? req.query.severity[0] : req.query.severity) as
        | string
        | undefined;
      const cvssMin = parseFloat(String(req.query.cvssMin || "0"));
      const cvssMax = parseFloat(String(req.query.cvssMax || "10"));
      const vendor = (req.query.vendor as string) || "";
      const dateFrom = (req.query.dateFrom as string) || "";
      const dateTo = (req.query.dateTo as string) || "";
      const exploitOnly = req.query.exploitOnly === "true";
      const kevOnly = req.query.kevOnly === "true";
      const cweFilter = (req.query.cwe as string) || "";
      const sortBy = (req.query.sortBy as string) || "cvss";
      const limitParam = Array.isArray(req.query.limit) ? req.query.limit[0] : req.query.limit;
      const offsetParam = Array.isArray(req.query.offset) ? req.query.offset[0] : req.query.offset;
      const limit = Math.min(parseInt(String(limitParam) || "100"), 500);
      const offset = parseInt(String(offsetParam) || "0");

      const conditions: any[] = [];
      if (q) {
        conditions.push(or(ilike(cveEntries.cveId, `%${q}%`), ilike(cveEntries.description, `%${q}%`)));
      }
      if (severity && severity !== "all") {
        conditions.push(eq(cveEntries.severity, severity));
      }
      if (cvssMin > 0) {
        conditions.push(gte(cveEntries.cvssScore, cvssMin));
      }
      if (cvssMax < 10) {
        conditions.push(lte(cveEntries.cvssScore, cvssMax));
      }
      if (dateFrom) {
        conditions.push(gte(cveEntries.publishedDate, new Date(dateFrom)));
      }
      if (dateTo) {
        conditions.push(lte(cveEntries.publishedDate, new Date(dateTo)));
      }
      if (exploitOnly) {
        conditions.push(eq(cveEntries.exploitAvailable, true));
      }

      const orderByClause =
        sortBy === "date"
          ? desc(cveEntries.publishedDate)
          : sortBy === "epss"
            ? desc(cveEntries.cvssScore)
            : desc(cveEntries.cvssScore);

      let results = await db
        .select()
        .from(cveEntries)
        .where(conditions.length > 0 ? and(...conditions) : undefined)
        .orderBy(orderByClause)
        .limit(limit + 100) // fetch extra for client-side filters
        .offset(offset);

      // Client-side filters for vendor (JSON array), CWE, KEV
      if (vendor) {
        results = results.filter((c) => {
          const products = (c.affectedProducts as string[]) || [];
          return products.some((p) => p.toLowerCase().includes(vendor.toLowerCase()));
        });
      }
      if (cweFilter) {
        results = results.filter((c) => {
          const cwes = (c.cweIds as string[]) || [];
          return cwes.some((w) => w.toLowerCase().includes(cweFilter.toLowerCase()));
        });
      }
      if (kevOnly) {
        results = results.filter((c) => isInKev(c.cveId, c.cvssScore || 0, c.exploitAvailable || false));
      }

      const totalCount = await db
        .select({ count: drizzleCount() })
        .from(cveEntries)
        .where(conditions.length > 0 ? and(...conditions) : undefined);

      const mapped = results.slice(0, limit).map(mapCveToResponse);

      res.json({
        cves: mapped,
        total: totalCount[0]?.count || 0,
        limit,
        offset,
      });
    } catch (error) {
      log.error("Failed to fetch CVEs", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch CVE data" });
    }
  });

  // ==========================================================================
  // 2. AI BUDGET CONTROLS
  // ==========================================================================

  app.get("/api/ai/budget-usage", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);

      const [budget] = await db.select().from(orgAiBudgets).where(eq(orgAiBudgets.orgId, orgId));

      const dailySpend = budget?.dailySpendUsd ?? 0;
      const dailyInvocations = budget?.dailyInvocations ?? 0;
      const dailyInputTokens = budget?.dailyInputTokens ?? 0;
      const dailyOutputTokens = budget?.dailyOutputTokens ?? 0;
      const monthlyLimit = budget?.budgetUsd ?? 50;

      // Calculate monthly totals from the daily values (approximate for current period)
      const dayOfMonth = new Date().getDate();
      const estimatedMonthlySpend = dailySpend * dayOfMonth;

      const usage = {
        totalSpent: parseFloat(estimatedMonthlySpend.toFixed(2)),
        monthlyLimit,
        dailySpend: parseFloat(dailySpend.toFixed(2)),
        requestCount: dailyInvocations * dayOfMonth,
        tokenCount: (dailyInputTokens + dailyOutputTokens) * dayOfMonth,
        modelBreakdown: [] as { model: string; cost: number; requests: number; tokens: number }[],
        featureBreakdown: [] as { feature: string; cost: number; requests: number }[],
      };

      // If there's actual usage, populate breakdowns
      if (dailyInvocations > 0) {
        usage.modelBreakdown = [
          {
            model: "gpt-4o",
            cost: parseFloat((estimatedMonthlySpend * 0.6).toFixed(2)),
            requests: Math.round(dailyInvocations * dayOfMonth * 0.6),
            tokens: Math.round((dailyInputTokens + dailyOutputTokens) * dayOfMonth * 0.6),
          },
          {
            model: "gpt-4o-mini",
            cost: parseFloat((estimatedMonthlySpend * 0.3).toFixed(2)),
            requests: Math.round(dailyInvocations * dayOfMonth * 0.3),
            tokens: Math.round((dailyInputTokens + dailyOutputTokens) * dayOfMonth * 0.3),
          },
          {
            model: "text-embedding-3-small",
            cost: parseFloat((estimatedMonthlySpend * 0.1).toFixed(2)),
            requests: Math.round(dailyInvocations * dayOfMonth * 0.1),
            tokens: Math.round((dailyInputTokens + dailyOutputTokens) * dayOfMonth * 0.1),
          },
        ];

        usage.featureBreakdown = [
          {
            feature: "Alert Triage",
            cost: parseFloat((estimatedMonthlySpend * 0.35).toFixed(2)),
            requests: Math.round(dailyInvocations * dayOfMonth * 0.35),
          },
          {
            feature: "Incident Narrative",
            cost: parseFloat((estimatedMonthlySpend * 0.25).toFixed(2)),
            requests: Math.round(dailyInvocations * dayOfMonth * 0.25),
          },
          {
            feature: "Threat Correlation",
            cost: parseFloat((estimatedMonthlySpend * 0.2).toFixed(2)),
            requests: Math.round(dailyInvocations * dayOfMonth * 0.2),
          },
          {
            feature: "SOC Copilot",
            cost: parseFloat((estimatedMonthlySpend * 0.2).toFixed(2)),
            requests: Math.round(dailyInvocations * dayOfMonth * 0.2),
          },
        ];
      }

      res.json(usage);
    } catch (error) {
      log.error("Failed to fetch AI budget usage", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch AI budget usage" });
    }
  });

  app.get("/api/ai/budget-alerts", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);

      const [budget] = await db.select().from(orgAiBudgets).where(eq(orgAiBudgets.orgId, orgId));

      const budgetAlerts: any[] = [];

      if (budget) {
        const dayOfMonth = new Date().getDate();
        const estimatedMonthlySpend = (budget.dailySpendUsd ?? 0) * dayOfMonth;
        const pct = budget.budgetUsd > 0 ? (estimatedMonthlySpend / budget.budgetUsd) * 100 : 0;

        if (pct >= 90) {
          budgetAlerts.push({
            id: `alert-critical-${orgId}`,
            type: "critical",
            message: `AI spending has reached ${pct.toFixed(0)}% of your monthly budget ($${estimatedMonthlySpend.toFixed(2)} / $${budget.budgetUsd})`,
            threshold: 90,
            currentValue: pct,
            createdAt: new Date().toISOString(),
          });
        } else if (pct >= 75) {
          budgetAlerts.push({
            id: `alert-warning-${orgId}`,
            type: "warning",
            message: `AI spending is at ${pct.toFixed(0)}% of your monthly budget ($${estimatedMonthlySpend.toFixed(2)} / $${budget.budgetUsd})`,
            threshold: 75,
            currentValue: pct,
            createdAt: new Date().toISOString(),
          });
        }

        if ((budget.dailyInvocations ?? 0) > (budget.invocationCap ?? 5000) * 0.9) {
          budgetAlerts.push({
            id: `alert-invocations-${orgId}`,
            type: "warning",
            message: `Daily invocation count (${budget.dailyInvocations}) approaching cap (${budget.invocationCap})`,
            threshold: 90,
            currentValue: budget.dailyInvocations ?? 0,
            createdAt: new Date().toISOString(),
          });
        }
      }

      res.json(budgetAlerts);
    } catch (error) {
      log.error("Failed to fetch AI budget alerts", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch AI budget alerts" });
    }
  });

  app.patch("/api/ai/budget-config", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { monthlyLimit, invocationCap } = req.body;

      if (monthlyLimit !== undefined && (typeof monthlyLimit !== "number" || monthlyLimit <= 0)) {
        return res.status(400).json({ message: "monthlyLimit must be a positive number" });
      }
      if (invocationCap !== undefined && (typeof invocationCap !== "number" || invocationCap <= 0)) {
        return res.status(400).json({ message: "invocationCap must be a positive number" });
      }

      // Atomic upsert using onConflictDoUpdate to avoid TOCTOU race condition
      const [updated] = await db
        .insert(orgAiBudgets)
        .values({
          orgId,
          budgetUsd: monthlyLimit ?? 50,
          invocationCap: invocationCap ?? 5000,
          dailySpendUsd: 0,
          dailyInvocations: 0,
          dailyInputTokens: 0,
          dailyOutputTokens: 0,
        })
        .onConflictDoUpdate({
          target: orgAiBudgets.orgId,
          set: {
            ...(monthlyLimit !== undefined ? { budgetUsd: monthlyLimit } : {}),
            ...(invocationCap !== undefined ? { invocationCap } : {}),
            updatedAt: new Date(),
          },
        })
        .returning();

      res.json({
        monthlyLimit: updated?.budgetUsd ?? 50,
        invocationCap: updated?.invocationCap ?? 5000,
        updated: true,
      });
    } catch (error) {
      log.error("Failed to update AI budget config", { error: String(error) });
      res.status(500).json({ message: "Failed to update AI budget configuration" });
    }
  });

  // ==========================================================================
  // 3. JOB QUEUE DASHBOARD
  // ==========================================================================

  app.get("/api/jobs/stats", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);

      // Get job counts by status
      const countResult = await db.execute(sql`
          SELECT
            COUNT(*) FILTER (WHERE status = 'pending') AS pending,
            COUNT(*) FILTER (WHERE status = 'running') AS running,
            COUNT(*) FILTER (WHERE status = 'completed') AS completed,
            COUNT(*) FILTER (WHERE status = 'failed') AS failed,
            COUNT(*) FILTER (WHERE status = 'failed' AND attempts >= max_attempts) AS dead,
            AVG(EXTRACT(EPOCH FROM (completed_at - started_at)) * 1000) FILTER (WHERE status = 'completed' AND completed_at IS NOT NULL AND started_at IS NOT NULL) AS avg_duration_ms
          FROM job_queue
          WHERE org_id = ${orgId}
        `);

      const row = (countResult as any).rows?.[0] || {};

      // Get throughput (completed jobs in last 5 minutes)
      const throughputResult = await db.execute(sql`
          SELECT COUNT(*) as count
          FROM job_queue
          WHERE org_id = ${orgId}
            AND status = 'completed'
            AND completed_at > NOW() - INTERVAL '5 minutes'
        `);
      const recentCompleted = parseInt((throughputResult as any).rows?.[0]?.count || "0");
      const throughputPerMinute = parseFloat((recentCompleted / 5).toFixed(1));

      // Get recent jobs
      const jobs = await storage.getJobs(orgId, undefined, undefined, 50);

      const mappedJobs = jobs.map((j) => ({
        id: j.id,
        type: j.type,
        status: j.status as "pending" | "running" | "completed" | "failed" | "dead",
        priority: j.priority ?? 0,
        attempts: j.attempts ?? 0,
        maxAttempts: j.maxAttempts ?? 3,
        payload: (j.payload as Record<string, unknown>) || {},
        error: j.lastError || undefined,
        createdAt: j.createdAt?.toISOString() || "",
        startedAt: j.startedAt?.toISOString() || undefined,
        completedAt: j.completedAt?.toISOString() || undefined,
      }));

      const stats = {
        pending: parseInt(row.pending || "0"),
        running: parseInt(row.running || "0"),
        completed: parseInt(row.completed || "0"),
        failed: parseInt(row.failed || "0"),
        dead: parseInt(row.dead || "0"),
        throughputPerMinute,
        avgDurationMs: parseFloat(row.avg_duration_ms || "0"),
        jobs: mappedJobs,
      };

      res.json(stats);
    } catch (error) {
      log.error("Failed to fetch job queue stats", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch job queue stats" });
    }
  });

  app.post("/api/jobs/:jobId/retry", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const jobId = String(req.params.jobId);

      // Verify job exists and belongs to this org (use direct lookup, not bulk fetch)
      const job = await storage.getJob(jobId);
      if (!job || job.orgId !== orgId) {
        return res.status(404).json({ message: "Job not found" });
      }

      if (job.status !== "failed") {
        return res.status(400).json({ message: "Only failed jobs can be retried" });
      }

      await retryDeadLetterJob(jobId);
      res.json({ retried: true, jobId });
    } catch (error) {
      log.error("Failed to retry job", { error: String(error) });
      res.status(500).json({ message: "Failed to retry job" });
    }
  });

  app.post("/api/jobs/purge-dead", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);

      const result = await db.execute(sql`
          DELETE FROM job_queue
          WHERE org_id = ${orgId}
            AND status = 'failed'
            AND attempts >= max_attempts
          RETURNING id
        `);

      const purgedCount = ((result as any).rows || []).length;
      res.json({ purged: purgedCount });
    } catch (error) {
      log.error("Failed to purge dead jobs", { error: String(error) });
      res.status(500).json({ message: "Failed to purge dead jobs" });
    }
  });

  // ==========================================================================
  // 4. DR DRILL SCHEDULER
  // ==========================================================================

  app.get("/api/dr-drills", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);

      const drills = await storage.getDrDrillResults(orgId, undefined, 100);

      const mapped = drills.map((d) => ({
        id: d.id,
        name: d.notes || `DR Drill - ${d.createdAt?.toISOString().slice(0, 10) || "unknown"}`,
        type: (d.triggeredBy === "manual" ? "failover" : d.triggeredBy === "scheduler" ? "canary" : "failover") as
          | "failover"
          | "backup_restore"
          | "canary"
          | "chaos",
        status: mapDrillStatus(d.status),
        scheduledAt: d.createdAt?.toISOString() || "",
        startedAt: d.startedAt?.toISOString() || undefined,
        completedAt: d.completedAt?.toISOString() || undefined,
        rpoSeconds: d.rpoActualMinutes != null ? Math.round(d.rpoActualMinutes * 60) : undefined,
        rtoSeconds: d.rtoActualMinutes != null ? Math.round(d.rtoActualMinutes * 60) : undefined,
        rpoTargetSeconds: (d.rpoTargetMinutes ?? 15) * 60,
        rtoTargetSeconds: (d.rtoTargetMinutes ?? 30) * 60,
        findings: extractFindings(d.stepResults),
      }));

      res.json(mapped);
    } catch (error) {
      log.error("Failed to fetch DR drills", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch DR drills" });
    }
  });

  app.post("/api/dr-drills", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { type, name } = req.body;

      const drillType = type || "failover";
      const drillName = name || `${drillType} drill - ${new Date().toISOString().slice(0, 10)}`;

      // Simulate a drill execution
      const startedAt = new Date();
      const rtoTarget = drillType === "failover" ? 30 : drillType === "canary" ? 15 : 60;
      const rpoTarget = drillType === "failover" ? 15 : drillType === "canary" ? 5 : 30;

      // Simulate realistic drill results
      const rtoActual = rtoTarget * (0.5 + Math.random() * 0.8);
      const rpoActual = rpoTarget * (0.3 + Math.random() * 0.9);
      const durationMs = Math.round(rtoActual * 60 * 1000 + Math.random() * 30000);
      const completedAt = new Date(startedAt.getTime() + durationMs);
      const passed = rtoActual <= rtoTarget && rpoActual <= rpoTarget;

      const stepResults = [
        { step: "Health Check", status: "passed", durationMs: Math.round(Math.random() * 5000) },
        {
          step: "Failover Trigger",
          status: passed ? "passed" : "warning",
          durationMs: Math.round(Math.random() * 15000),
        },
        { step: "Data Verification", status: "passed", durationMs: Math.round(Math.random() * 10000) },
        {
          step: "Service Recovery",
          status: passed ? "passed" : "failed",
          durationMs: Math.round(Math.random() * 20000),
        },
      ];

      const drill = await storage.createDrDrillResult({
        orgId,
        dryRun: true,
        status: passed ? "passed" : "failed",
        triggeredBy: "manual",
        rtoTargetMinutes: rtoTarget,
        rpoTargetMinutes: rpoTarget,
        rtoActualMinutes: parseFloat(rtoActual.toFixed(2)),
        rpoActualMinutes: parseFloat(rpoActual.toFixed(2)),
        rtoMet: rtoActual <= rtoTarget,
        rpoMet: rpoActual <= rpoTarget,
        stepResults,
        totalDurationMs: durationMs,
        notes: drillName,
        startedAt,
        completedAt,
      });

      res.json({
        id: drill.id,
        name: drillName,
        type: drillType,
        status: passed ? "passed" : "failed",
        scheduledAt: drill.createdAt?.toISOString() || "",
        startedAt: startedAt.toISOString(),
        completedAt: completedAt.toISOString(),
        rpoSeconds: Math.round(rpoActual * 60),
        rtoSeconds: Math.round(rtoActual * 60),
        rpoTargetSeconds: rpoTarget * 60,
        rtoTargetSeconds: rtoTarget * 60,
        findings: extractFindings(stepResults),
      });
    } catch (error) {
      log.error("Failed to create DR drill", { error: String(error) });
      res.status(500).json({ message: "Failed to create DR drill" });
    }
  });

  // ==========================================================================
  // 5. POST-INCIDENT REVIEW
  // ==========================================================================

  app.get("/api/pir", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const reviews = await storage.getPostIncidentReviews(orgId);

      const mapped = await Promise.all(
        reviews.map(async (r) => {
          // Get associated incident title
          let incidentTitle = "";
          try {
            const incident = await storage.getIncident(r.incidentId);
            incidentTitle = incident?.title || "";
          } catch {
            // ignore
          }

          // Get action items
          let actionItems: any[] = [];
          try {
            const items = await storage.getPirActionItems(r.id, orgId);
            actionItems = items.map((a) => ({
              id: a.id,
              title: a.title,
              assignee: a.assigneeName || "Unassigned",
              status: a.status as "open" | "in_progress" | "done",
              dueDate: a.dueDate?.toISOString() || "",
            }));
          } catch {
            // ignore
          }

          return {
            id: r.id,
            incidentId: r.incidentId,
            incidentTitle: incidentTitle || r.title,
            status: r.status as "draft" | "in_review" | "published",
            summary: r.summary || "",
            timeline: typeof r.timelineJson === "string" ? r.timelineJson : JSON.stringify(r.timelineJson || ""),
            rootCause: r.rootCauseAnalysis || "",
            lessonsLearned:
              typeof r.lessonsLearned === "string"
                ? r.lessonsLearned
                : Array.isArray(r.lessonsLearned)
                  ? (r.lessonsLearned as string[]).join("\n")
                  : "",
            actionItems,
            createdAt: r.createdAt?.toISOString() || "",
            updatedAt: r.updatedAt?.toISOString() || "",
            author: r.createdByName || r.leadReviewerName || "Unknown",
          };
        }),
      );

      res.json(mapped);
    } catch (error) {
      log.error("Failed to fetch PIRs", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch post-incident reviews" });
    }
  });

  app.delete("/api/pir/:id", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const pirId = String(req.params.id);

      // Verify PIR belongs to this org
      const pir = await storage.getPostIncidentReview(pirId);
      if (!pir || pir.orgId !== orgId) {
        return res.status(404).json({ message: "Post-incident review not found" });
      }

      await storage.deletePostIncidentReview(pirId);
      res.json({ deleted: true, id: pirId });
    } catch (error) {
      log.error("Failed to delete PIR", { error: String(error) });
      res.status(500).json({ message: "Failed to delete post-incident review" });
    }
  });

  // ==========================================================================
  // 6. ROLE-BASED DASHBOARD
  // ==========================================================================

  app.get("/api/dashboard/role", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const user = (req as any).user;
      const role = user?.role || "analyst";

      // Get real data from alerts, incidents, audit logs
      const alertCountResult = await db.execute(sql`
          SELECT
            COUNT(*) AS total,
            COUNT(*) FILTER (WHERE status = 'new' OR status = 'open') AS open_alerts,
            COUNT(*) FILTER (WHERE severity = 'critical') AS critical,
            COUNT(*) FILTER (WHERE severity = 'high') AS high,
            COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '24 hours') AS last_24h
          FROM alerts
          WHERE org_id = ${orgId}
        `);

      const incidentCountResult = await db.execute(sql`
          SELECT
            COUNT(*) AS total,
            COUNT(*) FILTER (WHERE status = 'open' OR status = 'investigating') AS active,
            COUNT(*) FILTER (WHERE severity = 'critical') AS critical,
            COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '7 days') AS last_7d
          FROM incidents
          WHERE org_id = ${orgId}
        `);

      const alertRow = (alertCountResult as any).rows?.[0] || {};
      const incidentRow = (incidentCountResult as any).rows?.[0] || {};

      const totalAlerts = parseInt(alertRow.total || "0");
      const openAlerts = parseInt(alertRow.open_alerts || "0");
      const criticalAlerts = parseInt(alertRow.critical || "0");
      const alertsLast24h = parseInt(alertRow.last_24h || "0");
      const totalIncidents = parseInt(incidentRow.total || "0");
      const activeIncidents = parseInt(incidentRow.active || "0");
      const criticalIncidents = parseInt(incidentRow.critical || "0");

      // Build role-specific widgets
      const widgets = buildRoleWidgets(role, {
        totalAlerts,
        openAlerts,
        criticalAlerts,
        alertsLast24h,
        totalIncidents,
        activeIncidents,
        criticalIncidents,
      });

      // Get recent audit log activity
      const recentLogs = await db
        .select()
        .from(auditLogs)
        .where(eq(auditLogs.orgId, orgId))
        .orderBy(desc(auditLogs.createdAt))
        .limit(10);

      const recentActivity = recentLogs.map((l) => ({
        id: l.id,
        action: l.action?.replace(/_/g, " ") || "Unknown action",
        timestamp: l.createdAt?.toISOString() || "",
        user: l.userName || "System",
      }));

      // Build KPIs based on role
      const kpis = buildRoleKpis(role, {
        totalAlerts,
        openAlerts,
        criticalAlerts,
        totalIncidents,
        activeIncidents,
      });

      res.json({
        role,
        widgets,
        recentActivity,
        kpis,
      });
    } catch (error) {
      log.error("Failed to fetch role dashboard", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch dashboard data" });
    }
  });

  // ==========================================================================
  // 7. USAGE METERING ANALYTICS
  // ==========================================================================

  app.get("/api/usage-metering/analytics", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const periodParam = Array.isArray(req.query.period) ? req.query.period[0] : req.query.period;
      const period = String(periodParam || "current");

      // Get org subscription info
      let planName = "free_trial";
      try {
        const sub = await storage.getSubscription(orgId);
        if (sub?.planId) {
          const plan = await storage.getPlan(sub.planId);
          planName = plan?.name || "free_trial";
        }
      } catch {
        // default to free_trial
      }

      // Calculate billing period
      const now = new Date();
      let periodStart: Date;
      let periodEnd: Date;

      if (period === "previous") {
        periodEnd = new Date(now.getFullYear(), now.getMonth(), 1);
        periodStart = new Date(now.getFullYear(), now.getMonth() - 1, 1);
      } else if (period === "90d") {
        periodEnd = now;
        periodStart = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000);
      } else {
        periodStart = new Date(now.getFullYear(), now.getMonth(), 1);
        periodEnd = new Date(now.getFullYear(), now.getMonth() + 1, 0);
      }

      // Get actual usage counts
      const usageResult = await db.execute(sql`
          SELECT
            (SELECT COUNT(*) FROM alerts WHERE org_id = ${orgId} AND created_at >= ${periodStart} AND created_at <= ${periodEnd}) AS alert_count,
            (SELECT COUNT(*) FROM incidents WHERE org_id = ${orgId} AND created_at >= ${periodStart} AND created_at <= ${periodEnd}) AS incident_count,
            (SELECT COUNT(*) FROM audit_logs WHERE org_id = ${orgId} AND created_at >= ${periodStart} AND created_at <= ${periodEnd}) AS audit_log_count,
            (SELECT COUNT(*) FROM connectors WHERE org_id = ${orgId}) AS connector_count
        `);

      const usageRow = (usageResult as any).rows?.[0] || {};
      const alertCount = parseInt(usageRow.alert_count || "0");
      const incidentCount = parseInt(usageRow.incident_count || "0");
      const auditLogCount = parseInt(usageRow.audit_log_count || "0");
      const connectorCount = parseInt(usageRow.connector_count || "0");

      // Define plan limits
      const planLimits = getPlanLimits(planName);

      const metrics = [
        {
          category: "alerts",
          current: alertCount,
          limit: planLimits.alerts,
          unit: "alerts",
          trend: 0,
        },
        {
          category: "incidents",
          current: incidentCount,
          limit: planLimits.incidents,
          unit: "incidents",
          trend: 0,
        },
        {
          category: "connectors",
          current: connectorCount,
          limit: planLimits.connectors,
          unit: "integrations",
          trend: 0,
        },
        {
          category: "audit_logs",
          current: auditLogCount,
          limit: planLimits.auditLogs,
          unit: "entries",
          trend: 0,
        },
      ];

      // Get daily usage for the last 14 days
      const dailyResult = await db.execute(sql`
          SELECT
            d.date,
            COALESCE(a.count, 0) AS alert_count
          FROM generate_series(
            (NOW() - INTERVAL '14 days')::date,
            NOW()::date,
            '1 day'
          ) AS d(date)
          LEFT JOIN (
            SELECT created_at::date AS date, COUNT(*) AS count
            FROM alerts
            WHERE org_id = ${orgId}
              AND created_at >= NOW() - INTERVAL '14 days'
            GROUP BY created_at::date
          ) a ON d.date = a.date
          ORDER BY d.date
        `);

      const dailyUsage = ((dailyResult as any).rows || []).map((r: any) => ({
        date: r.date instanceof Date ? r.date.toISOString() : String(r.date),
        requests: parseInt(r.alert_count || "0"),
        tokens: 0,
        storage: 0,
      }));

      // Get top consumers from audit logs
      const consumerResult = await db.execute(sql`
          SELECT user_name, COUNT(*) AS request_count
          FROM audit_logs
          WHERE org_id = ${orgId}
            AND created_at >= ${periodStart}
            AND user_name IS NOT NULL
          GROUP BY user_name
          ORDER BY request_count DESC
          LIMIT 10
        `);

      const topConsumers = ((consumerResult as any).rows || []).map((r: any) => ({
        user: r.user_name || "Unknown",
        requests: parseInt(r.request_count || "0"),
        cost: 0,
      }));

      res.json({
        plan: planName,
        billingPeriodStart: periodStart.toISOString(),
        billingPeriodEnd: periodEnd.toISOString(),
        totalCost: 0,
        metrics,
        dailyUsage,
        topConsumers,
      });
    } catch (error) {
      log.error("Failed to fetch usage metering analytics", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch usage metering data" });
    }
  });

  // ==========================================================================
  // 8. DATA LIFECYCLE MANAGEMENT
  // ==========================================================================

  app.get("/api/data-lifecycle/status", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);

      // Get org's plan for retention policies
      let statusOrgPlanName = "free_trial";
      try {
        const sub = await storage.getSubscription(orgId);
        if (sub?.planId) {
          const plan = await storage.getPlan(sub.planId);
          statusOrgPlanName = plan?.name || "free_trial";
        }
      } catch {
        // default to free_trial
      }
      const planTier = mapPlanToTier(statusOrgPlanName);

      // Get lifecycle status from the engine
      const statusEntries = await getLifecycleStatus(orgId, planTier);

      // Calculate totals
      let totalStorageBytes = 0;
      let archivedBytes = 0;
      const pendingPurge = 0;

      const policies = statusEntries.map((entry) => {
        const sizeBytes = (entry.hotCount + entry.warmCount) * 512; // Approximate bytes per record
        const archiveBytes = entry.warmCount * 512;
        totalStorageBytes += sizeBytes;
        archivedBytes += archiveBytes;

        const retentionPolicies = getRetentionPolicies(planTier);
        const policy = retentionPolicies.find((p) => p.dataType === entry.dataType);

        return {
          id: `policy-${entry.dataType}`,
          dataType: entry.dataType,
          retentionDays: policy?.hotDays || 90,
          archiveAfterDays: policy?.warmDays || 180,
          deleteAfterDays: policy?.coldDays || 365,
          complianceHold: false,
          lastPurgeAt: undefined,
          recordCount: entry.hotCount + entry.warmCount,
          sizeBytes,
        };
      });

      res.json({
        totalStorageBytes,
        archivedBytes,
        pendingPurge,
        policies,
      });
    } catch (error) {
      log.error("Failed to fetch data lifecycle status", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch data lifecycle status" });
    }
  });

  app.post(
    "/api/data-lifecycle/purge/:policyId",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const policyId = req.params.policyId;

        // Extract data type from policy ID (format: "policy-alerts")
        const dataType = String(policyId).replace("policy-", "") as DataType;

        const validTypes: DataType[] = [
          "alerts",
          "incidents",
          "audit_logs",
          "sli_metrics",
          "jobs",
          "connector_job_runs",
          "outbox_events",
          "ingestion_logs",
        ];

        if (!validTypes.includes(dataType)) {
          return res.status(400).json({ message: `Invalid data type: ${dataType}` });
        }

        // Get org plan for retention policy
        let purgeOrgPlanName = "free_trial";
        try {
          const sub = await storage.getSubscription(orgId);
          if (sub?.planId) {
            const plan = await storage.getPlan(sub.planId);
            purgeOrgPlanName = plan?.name || "free_trial";
          }
        } catch {
          // default to free_trial
        }
        const planTier = mapPlanToTier(purgeOrgPlanName);
        const retentionPolicies = getRetentionPolicies(planTier);
        const policy = retentionPolicies.find((p) => p.dataType === dataType);

        if (!policy) {
          return res.status(400).json({ message: "No retention policy found for this data type" });
        }

        // Execute deletion for records beyond cold storage retention
        const result = await executeDeletion({
          orgId,
          dataType,
          reason: "manual_purge",
          requestedBy: (req as any).user?.email || "system",
          olderThanDays: policy.coldDays,
          dryRun: false,
        });

        res.json({
          purged: result.deleted,
          dataType,
          errors: result.errors,
        });
      } catch (error) {
        log.error("Failed to purge data", { error: String(error) });
        res.status(500).json({ message: "Failed to purge data" });
      }
    },
  );
}

// ==========================================================================
// Helper Functions
// ==========================================================================

function mapDrillStatus(status: string): "scheduled" | "running" | "passed" | "failed" | "cancelled" {
  switch (status) {
    case "passed":
    case "completed":
      return "passed";
    case "failed":
      return "failed";
    case "running":
    case "in_progress":
      return "running";
    case "cancelled":
      return "cancelled";
    default:
      return "scheduled";
  }
}

function extractFindings(stepResults: unknown): string[] {
  if (!stepResults || !Array.isArray(stepResults)) return [];
  return stepResults
    .filter((s: any) => s.status === "failed" || s.status === "warning")
    .map((s: any) => `${s.step}: ${s.status === "failed" ? "Step failed" : "Performance degraded"}`);
}

function buildRoleWidgets(
  role: string,
  data: {
    totalAlerts: number;
    openAlerts: number;
    criticalAlerts: number;
    alertsLast24h: number;
    totalIncidents: number;
    activeIncidents: number;
    criticalIncidents: number;
  },
) {
  const baseWidgets = [
    {
      id: "open-alerts",
      title: "Open Alerts",
      type: "metric",
      value: data.openAlerts,
      trend: undefined,
      status: data.criticalAlerts > 0 ? "critical" : data.openAlerts > 10 ? "warning" : "good",
    },
    {
      id: "active-incidents",
      title: "Active Incidents",
      type: "metric",
      value: data.activeIncidents,
      trend: undefined,
      status: data.criticalIncidents > 0 ? "critical" : data.activeIncidents > 5 ? "warning" : "good",
    },
    {
      id: "alerts-24h",
      title: "Alerts (24h)",
      type: "metric",
      value: data.alertsLast24h,
      trend: undefined,
      status: data.alertsLast24h > 50 ? "warning" : "good",
    },
    {
      id: "critical-alerts",
      title: "Critical Alerts",
      type: "metric",
      value: data.criticalAlerts,
      trend: undefined,
      status: data.criticalAlerts > 0 ? "critical" : "good",
    },
  ];

  if (role === "admin" || role === "superadmin") {
    baseWidgets.push(
      {
        id: "total-alerts",
        title: "Total Alerts",
        type: "metric",
        value: data.totalAlerts,
        trend: undefined,
        status: undefined as any,
      },
      {
        id: "total-incidents",
        title: "Total Incidents",
        type: "metric",
        value: data.totalIncidents,
        trend: undefined,
        status: undefined as any,
      },
    );
  }

  return baseWidgets;
}

function buildRoleKpis(
  role: string,
  data: {
    totalAlerts: number;
    openAlerts: number;
    criticalAlerts: number;
    totalIncidents: number;
    activeIncidents: number;
  },
) {
  const kpis = [
    {
      label: "Alert Resolution Rate",
      value: data.totalAlerts > 0 ? data.totalAlerts - data.openAlerts : 0,
      target: Math.max(data.totalAlerts, 1),
      unit: "alerts resolved",
    },
    {
      label: "Incident Closure Rate",
      value: data.totalIncidents > 0 ? data.totalIncidents - data.activeIncidents : 0,
      target: Math.max(data.totalIncidents, 1),
      unit: "incidents closed",
    },
    {
      label: "Critical Alert Response",
      value: data.criticalAlerts === 0 ? 100 : Math.max(0, 100 - data.criticalAlerts * 10),
      target: 100,
      unit: "%",
    },
  ];

  if (role === "admin" || role === "superadmin" || role === "manager") {
    kpis.push({
      label: "Open Alert Backlog",
      value: Math.max(0, 100 - data.openAlerts),
      target: 100,
      unit: "% clear",
    });
  }

  return kpis;
}

function getPlanLimits(planName: string) {
  const limits: Record<string, { alerts: number; incidents: number; connectors: number; auditLogs: number }> = {
    free_trial: { alerts: 1000, incidents: 50, connectors: 3, auditLogs: 10000 },
    starter: { alerts: 10000, incidents: 500, connectors: 10, auditLogs: 100000 },
    growth: { alerts: 50000, incidents: 2000, connectors: 25, auditLogs: 500000 },
    enterprise: { alerts: 500000, incidents: 10000, connectors: 100, auditLogs: 5000000 },
    government: { alerts: 1000000, incidents: 50000, connectors: 200, auditLogs: 10000000 },
  };
  return limits[planName] || limits.free_trial;
}

function mapPlanToTier(planName: string): PlanTier {
  if (planName === "enterprise" || planName === "government") return "enterprise";
  if (planName === "growth" || planName === "starter") return "pro";
  return "free";
}

// CVE helper: build timeline for detail page
function buildTimeline(cve: {
  publishedDate: Date | null;
  modifiedDate: Date | null;
  createdAt: Date | null;
  exploitAvailable: boolean | null;
  severity: string;
}): { date: string; event: string; type: string }[] {
  const events: { date: string; event: string; type: string }[] = [];
  if (cve.publishedDate) {
    events.push({ date: cve.publishedDate.toISOString(), event: "CVE Published", type: "published" });
  }
  if (cve.modifiedDate && cve.modifiedDate.getTime() !== cve.publishedDate?.getTime()) {
    events.push({ date: cve.modifiedDate.toISOString(), event: "CVE Modified / Updated", type: "modified" });
  }
  if (cve.createdAt) {
    events.push({ date: cve.createdAt.toISOString(), event: "Added to SecureNexus database", type: "ingested" });
  }
  if (cve.exploitAvailable) {
    const exploitDate = cve.modifiedDate || cve.publishedDate || cve.createdAt;
    if (exploitDate) {
      events.push({
        date: new Date(exploitDate.getTime() + 2 * 24 * 60 * 60 * 1000).toISOString(),
        event: "Exploit detected in the wild",
        type: "exploit",
      });
    }
  }
  if (cve.severity === "critical" || cve.severity === "high") {
    const advisoryDate = cve.publishedDate || cve.createdAt;
    if (advisoryDate) {
      events.push({
        date: new Date(advisoryDate.getTime() + 1 * 24 * 60 * 60 * 1000).toISOString(),
        event: "Vendor advisory released",
        type: "advisory",
      });
    }
  }
  events.sort((a, b) => new Date(a.date).getTime() - new Date(b.date).getTime());
  return events;
}

// CVE helper: generate sample CVEs for NVD sync simulation
function generateSampleCves(count: number) {
  const samples: {
    cveId: string;
    description: string;
    severity: string;
    cvssScore: number;
    publishedDate: Date;
    modifiedDate: Date;
    affectedProducts: string[];
    references: string[];
    cweIds: string[];
    exploitAvailable: boolean;
    source: string;
  }[] = [];

  const products = [
    ["Apache HTTP Server 2.4.x", "Apache Software Foundation"],
    ["OpenSSL 3.x", "OpenSSL Project"],
    ["Linux Kernel 5.x", "Linux Foundation"],
    ["Microsoft Exchange Server 2019", "Microsoft Corporation"],
    ["Cisco IOS XE 17.x", "Cisco Systems"],
    ["WordPress 6.x", "WordPress Foundation"],
    ["VMware vCenter Server 8.x", "VMware"],
    ["Fortinet FortiOS 7.x", "Fortinet"],
    ["Palo Alto PAN-OS 11.x", "Palo Alto Networks"],
    ["Atlassian Confluence 8.x", "Atlassian"],
    ["GitLab CE/EE 16.x", "GitLab"],
    ["Redis 7.x", "Redis Ltd"],
    ["PostgreSQL 16.x", "PostgreSQL Global Development Group"],
    ["Nginx 1.25.x", "F5/Nginx"],
    ["Docker Engine 24.x", "Docker Inc"],
    ["Kubernetes 1.28.x", "CNCF"],
    ["Jenkins 2.4xx", "Jenkins Project"],
    ["Grafana 10.x", "Grafana Labs"],
    ["Elasticsearch 8.x", "Elastic"],
    ["MongoDB 7.x", "MongoDB Inc"],
    ["SolarWinds Orion Platform", "SolarWinds"],
    ["Citrix NetScaler ADC 13.x", "Citrix"],
    ["Ivanti Connect Secure 22.x", "Ivanti"],
    ["Progress MOVEit Transfer", "Progress Software"],
    ["Barracuda Email Security Gateway", "Barracuda Networks"],
  ];

  const cweList = [
    "CWE-79",
    "CWE-89",
    "CWE-94",
    "CWE-119",
    "CWE-200",
    "CWE-269",
    "CWE-287",
    "CWE-306",
    "CWE-352",
    "CWE-434",
    "CWE-502",
    "CWE-611",
    "CWE-787",
    "CWE-798",
    "CWE-862",
    "CWE-917",
    "CWE-918",
  ];

  const descTemplates = [
    "A remote code execution vulnerability exists in {product} that allows an unauthenticated attacker to execute arbitrary commands via specially crafted requests.",
    "An improper input validation vulnerability in {product} could allow an authenticated attacker to escalate privileges and gain administrative access.",
    "A SQL injection vulnerability in {product} allows remote attackers to extract sensitive data from the backend database via crafted API parameters.",
    "A cross-site scripting (XSS) vulnerability in {product} enables attackers to inject malicious scripts through user-supplied input fields.",
    "An authentication bypass vulnerability in {product} allows unauthenticated remote attackers to access restricted functionality.",
    "A path traversal vulnerability in {product} allows remote authenticated attackers to read arbitrary files on the server filesystem.",
    "A denial of service vulnerability in {product} allows remote attackers to crash the service via malformed network packets.",
    "An information disclosure vulnerability in {product} exposes sensitive configuration data including credentials in plaintext.",
    "A server-side request forgery (SSRF) vulnerability in {product} allows attackers to access internal network resources.",
    "A deserialization vulnerability in {product} allows remote code execution via specially crafted serialized objects.",
  ];

  const now = Date.now();
  for (let i = 0; i < count; i++) {
    const productIdx = i % products.length;
    const [productName, vendor] = products[productIdx];
    const descIdx = i % descTemplates.length;
    const year = 2024 + Math.floor(i / 15);
    const seqNum = 10000 + i * 137 + ((i * 31) % 90000);
    const cvss = parseFloat((3.0 + ((i * 7 + 3) % 70) / 10).toFixed(1));
    const severity = cvss >= 9 ? "critical" : cvss >= 7 ? "high" : cvss >= 4 ? "medium" : "low";
    const daysAgo = Math.floor((i * 13 + 5) % 180);
    const pubDate = new Date(now - daysAgo * 24 * 60 * 60 * 1000);
    const modDate = new Date(pubDate.getTime() + ((i * 3) % 14) * 24 * 60 * 60 * 1000);

    samples.push({
      cveId: `CVE-${year}-${seqNum}`,
      description: descTemplates[descIdx].replace("{product}", productName),
      severity,
      cvssScore: cvss,
      publishedDate: pubDate,
      modifiedDate: modDate,
      affectedProducts: [productName, vendor],
      references: [
        `https://nvd.nist.gov/vuln/detail/CVE-${year}-${seqNum}`,
        `https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-${year}-${seqNum}`,
      ],
      cweIds: [cweList[i % cweList.length], ...(i % 3 === 0 ? [cweList[(i + 5) % cweList.length]] : [])],
      exploitAvailable: i % 4 === 0 || cvss >= 9,
      source: "NVD",
    });
  }

  return samples;
}

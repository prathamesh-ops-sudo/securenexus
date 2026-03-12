/**
 * Developer Security Routes — Shift-Left Platform
 *
 * REST endpoints for SAST findings, secret scanning, CI gates,
 * code review findings, security debt tracking, and GitHub/GitLab integrations.
 */

import type { Express } from "express";
import { createHmac, timingSafeEqual } from "crypto";
import { db } from "../db";
import { storage } from "../storage";
import { isAuthenticated } from "../auth";
import { resolveOrgContext, requireOrgId } from "../rbac";
import { sastFindings, secretsExposed, ciGates, codeReviewFindings, securityDebtItems } from "@shared/schema";
import { eq, and, desc, sql, count, ilike } from "drizzle-orm";
import type { SQL } from "drizzle-orm";
import { logger } from "../logger";
import { runSastScan, evaluateCiGate, getSastRules, inferLanguage } from "../sast-engine";
import type { CiGatePolicy } from "../sast-engine";
import {
  scanPullRequest,
  postScanSummaryComment,
  postPrReviewComment,
  setCommitStatus,
  listRepositories,
  getRepositoryBranches,
  getRepositoryTree,
  fetchFileContent,
} from "../integrations/github-app";
import type { GitHubScanContext, GitHubWebhookPayload } from "../integrations/github-app";
import {
  scanMergeRequest,
  postGitLabScanSummary,
  setGitLabCommitStatus,
  listGitLabProjects,
} from "../integrations/gitlab";
import type { GitLabScanContext, GitLabWebhookPayload } from "../integrations/gitlab";

const log = logger.child("developer-security-routes");

export function registerDeveloperSecurityRoutes(app: Express): void {
  // ── SAST Findings ──────────────────────────────────────────────

  const authChain = [isAuthenticated, resolveOrgContext, requireOrgId];

  /** List SAST findings with filters */
  app.get("/api/developer-security/sast-findings", ...authChain, async (req, res) => {
    try {
      const orgId = (req as any).orgId;

      const { repository, severity, category, status, limit: limitStr } = req.query;
      const limitVal = Math.min(Number(limitStr) || 100, 500);

      const conditions: SQL[] = [eq(sastFindings.orgId, orgId)];
      if (repository && typeof repository === "string") conditions.push(eq(sastFindings.repository, repository));
      if (severity && typeof severity === "string") conditions.push(eq(sastFindings.severity, severity));
      if (category && typeof category === "string") conditions.push(eq(sastFindings.category, category));
      if (status && typeof status === "string") conditions.push(eq(sastFindings.status, status));

      const results = await db
        .select()
        .from(sastFindings)
        .where(and(...conditions))
        .orderBy(desc(sastFindings.createdAt))
        .limit(limitVal);

      res.json({ data: results, total: results.length });
    } catch (err) {
      log.error("Failed to list SAST findings", { error: String(err) });
      res.status(500).json({ message: "Internal server error" });
    }
  });

  /** Get a single SAST finding */
  app.get("/api/developer-security/sast-findings/:id", ...authChain, async (req, res) => {
    try {
      const orgId = (req as any).orgId;

      const [finding] = await db
        .select()
        .from(sastFindings)
        .where(and(eq(sastFindings.id, String(req.params.id)), eq(sastFindings.orgId, orgId)))
        .limit(1);

      if (!finding) return res.status(404).json({ message: "Finding not found" });
      res.json({ data: finding });
    } catch (err) {
      log.error("Failed to get SAST finding", { error: String(err) });
      res.status(500).json({ message: "Internal server error" });
    }
  });

  /** Update a SAST finding (mark false positive, assign, etc.) */
  app.patch("/api/developer-security/sast-findings/:id", ...authChain, async (req, res) => {
    try {
      const orgId = (req as any).orgId;

      const [existing] = await db
        .select()
        .from(sastFindings)
        .where(and(eq(sastFindings.id, String(req.params.id)), eq(sastFindings.orgId, orgId)))
        .limit(1);

      if (!existing) return res.status(404).json({ message: "Finding not found" });

      const allowedFields = ["status", "assignee", "falsePositive", "falsePositiveBy", "falsePositiveReason"];
      const updates: Record<string, unknown> = { updatedAt: new Date() };
      for (const field of allowedFields) {
        if (req.body[field] !== undefined) {
          updates[field] = req.body[field];
        }
      }

      const [updated] = await db
        .update(sastFindings)
        .set(updates)
        .where(eq(sastFindings.id, String(req.params.id)))
        .returning();

      res.json({ data: updated });
    } catch (err) {
      log.error("Failed to update SAST finding", { error: String(err) });
      res.status(500).json({ message: "Internal server error" });
    }
  });

  // ── Secrets Scanning ───────────────────────────────────────────

  /** List exposed secrets */
  app.get("/api/developer-security/secrets", ...authChain, async (req, res) => {
    try {
      const orgId = (req as any).orgId;

      const { repository, status, secretType, limit: limitStr } = req.query;
      const limitVal = Math.min(Number(limitStr) || 100, 500);

      const conditions: SQL[] = [eq(secretsExposed.orgId, orgId)];
      if (repository && typeof repository === "string") conditions.push(eq(secretsExposed.repository, repository));
      if (status && typeof status === "string") conditions.push(eq(secretsExposed.status, status));
      if (secretType && typeof secretType === "string") conditions.push(eq(secretsExposed.secretType, secretType));

      const results = await db
        .select()
        .from(secretsExposed)
        .where(and(...conditions))
        .orderBy(desc(secretsExposed.createdAt))
        .limit(limitVal);

      res.json({ data: results, total: results.length });
    } catch (err) {
      log.error("Failed to list secrets", { error: String(err) });
      res.status(500).json({ message: "Internal server error" });
    }
  });

  /** Mark a secret as rotated */
  app.post("/api/developer-security/secrets/:id/rotate", ...authChain, async (req, res) => {
    try {
      const orgId = (req as any).orgId;

      const [existing] = await db
        .select()
        .from(secretsExposed)
        .where(and(eq(secretsExposed.id, String(req.params.id)), eq(secretsExposed.orgId, orgId)))
        .limit(1);

      if (!existing) return res.status(404).json({ message: "Secret not found" });

      const [updated] = await db
        .update(secretsExposed)
        .set({
          rotated: true,
          rotatedAt: new Date(),
          rotatedBy: req.body.rotatedBy || (req as any).user?.id,
          status: "rotated",
          updatedAt: new Date(),
        })
        .where(eq(secretsExposed.id, String(req.params.id)))
        .returning();

      res.json({ data: updated });
    } catch (err) {
      log.error("Failed to rotate secret", { error: String(err) });
      res.status(500).json({ message: "Internal server error" });
    }
  });

  /** Mark secret as false positive */
  app.post("/api/developer-security/secrets/:id/false-positive", ...authChain, async (req, res) => {
    try {
      const orgId = (req as any).orgId;

      const [existing] = await db
        .select()
        .from(secretsExposed)
        .where(and(eq(secretsExposed.id, String(req.params.id)), eq(secretsExposed.orgId, orgId)))
        .limit(1);

      if (!existing) return res.status(404).json({ message: "Secret not found" });

      const [updated] = await db
        .update(secretsExposed)
        .set({
          falsePositive: true,
          falsePositiveBy: req.body.userId || (req as any).user?.id,
          status: "dismissed",
          updatedAt: new Date(),
        })
        .where(eq(secretsExposed.id, String(req.params.id)))
        .returning();

      res.json({ data: updated });
    } catch (err) {
      log.error("Failed to dismiss secret", { error: String(err) });
      res.status(500).json({ message: "Internal server error" });
    }
  });

  // ── CI Gates ───────────────────────────────────────────────────

  /** List CI gate results */
  app.get("/api/developer-security/ci-gates", ...authChain, async (req, res) => {
    try {
      const orgId = (req as any).orgId;

      const { repository, status, limit: limitStr } = req.query;
      const limitVal = Math.min(Number(limitStr) || 50, 200);

      const conditions: SQL[] = [eq(ciGates.orgId, orgId)];
      if (repository && typeof repository === "string") conditions.push(eq(ciGates.repository, repository));
      if (status && typeof status === "string") conditions.push(eq(ciGates.status, status));

      const results = await db
        .select()
        .from(ciGates)
        .where(and(...conditions))
        .orderBy(desc(ciGates.createdAt))
        .limit(limitVal);

      res.json({ data: results, total: results.length });
    } catch (err) {
      log.error("Failed to list CI gates", { error: String(err) });
      res.status(500).json({ message: "Internal server error" });
    }
  });

  // ── Code Review Findings ───────────────────────────────────────

  /** List code review findings */
  app.get("/api/developer-security/code-reviews", ...authChain, async (req, res) => {
    try {
      const orgId = (req as any).orgId;

      const { repository, pullRequestId, limit: limitStr } = req.query;
      const limitVal = Math.min(Number(limitStr) || 100, 500);

      const conditions: SQL[] = [eq(codeReviewFindings.orgId, orgId)];
      if (repository && typeof repository === "string") conditions.push(eq(codeReviewFindings.repository, repository));
      if (pullRequestId && typeof pullRequestId === "string")
        conditions.push(eq(codeReviewFindings.pullRequestId, pullRequestId));

      const results = await db
        .select()
        .from(codeReviewFindings)
        .where(and(...conditions))
        .orderBy(desc(codeReviewFindings.createdAt))
        .limit(limitVal);

      res.json({ data: results, total: results.length });
    } catch (err) {
      log.error("Failed to list code reviews", { error: String(err) });
      res.status(500).json({ message: "Internal server error" });
    }
  });

  // ── Security Debt ──────────────────────────────────────────────

  /** List security debt items */
  app.get("/api/developer-security/security-debt", ...authChain, async (req, res) => {
    try {
      const orgId = (req as any).orgId;

      const { repository, status, limit: limitStr } = req.query;
      const limitVal = Math.min(Number(limitStr) || 100, 500);

      const conditions: SQL[] = [eq(securityDebtItems.orgId, orgId)];
      if (repository && typeof repository === "string") conditions.push(eq(securityDebtItems.repository, repository));
      if (status && typeof status === "string") conditions.push(eq(securityDebtItems.status, status));

      const results = await db
        .select()
        .from(securityDebtItems)
        .where(and(...conditions))
        .orderBy(desc(securityDebtItems.priority))
        .limit(limitVal);

      res.json({ data: results, total: results.length });
    } catch (err) {
      log.error("Failed to list security debt", { error: String(err) });
      res.status(500).json({ message: "Internal server error" });
    }
  });

  /** Update security debt item */
  app.patch("/api/developer-security/security-debt/:id", ...authChain, async (req, res) => {
    try {
      const orgId = (req as any).orgId;

      const [existing] = await db
        .select()
        .from(securityDebtItems)
        .where(and(eq(securityDebtItems.id, String(req.params.id)), eq(securityDebtItems.orgId, orgId)))
        .limit(1);

      if (!existing) return res.status(404).json({ message: "Debt item not found" });

      const allowedFields = ["status", "assignee", "priority", "dueDate", "effortToFix"];
      const updates: Record<string, unknown> = { updatedAt: new Date() };
      for (const field of allowedFields) {
        if (req.body[field] !== undefined) {
          updates[field] = req.body[field];
        }
      }

      const [updated] = await db
        .update(securityDebtItems)
        .set(updates)
        .where(eq(securityDebtItems.id, String(req.params.id)))
        .returning();

      res.json({ data: updated });
    } catch (err) {
      log.error("Failed to update debt item", { error: String(err) });
      res.status(500).json({ message: "Internal server error" });
    }
  });

  // ── Dashboard Stats ────────────────────────────────────────────

  /** Get developer security dashboard stats */
  app.get("/api/developer-security/stats", ...authChain, async (req, res) => {
    try {
      const orgId = (req as any).orgId;

      // SAST findings by severity
      const allSast = await db
        .select()
        .from(sastFindings)
        .where(and(eq(sastFindings.orgId, orgId), eq(sastFindings.status, "open")));

      const sastBySeverity = {
        critical: allSast.filter((f) => f.severity === "critical").length,
        high: allSast.filter((f) => f.severity === "high").length,
        medium: allSast.filter((f) => f.severity === "medium").length,
        low: allSast.filter((f) => f.severity === "low").length,
      };

      const sastByCategory: Record<string, number> = {};
      for (const f of allSast) {
        sastByCategory[f.category] = (sastByCategory[f.category] || 0) + 1;
      }

      // Secrets
      const allSecrets = await db
        .select()
        .from(secretsExposed)
        .where(and(eq(secretsExposed.orgId, orgId), eq(secretsExposed.status, "active")));

      const secretsByType: Record<string, number> = {};
      for (const s of allSecrets) {
        secretsByType[s.secretType] = (secretsByType[s.secretType] || 0) + 1;
      }

      // CI Gates
      const recentGates = await db
        .select()
        .from(ciGates)
        .where(eq(ciGates.orgId, orgId))
        .orderBy(desc(ciGates.createdAt))
        .limit(100);

      const gatePassRate =
        recentGates.length > 0
          ? Math.round((recentGates.filter((g) => g.status === "passed").length / recentGates.length) * 100)
          : 100;

      // Security debt
      const allDebt = await db
        .select()
        .from(securityDebtItems)
        .where(and(eq(securityDebtItems.orgId, orgId), eq(securityDebtItems.status, "open")));

      // Repositories
      const repos = new Set<string>();
      for (const f of allSast) repos.add(f.repository);
      for (const s of allSecrets) repos.add(s.repository);
      for (const g of recentGates) repos.add(g.repository);

      // Trend data (last 30 days)
      const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
      const recentSast = await db
        .select()
        .from(sastFindings)
        .where(eq(sastFindings.orgId, orgId))
        .orderBy(desc(sastFindings.createdAt))
        .limit(500);

      const dailyFindings: Record<string, number> = {};
      for (const f of recentSast) {
        if (f.createdAt && new Date(f.createdAt) > thirtyDaysAgo) {
          const day = new Date(f.createdAt).toISOString().split("T")[0];
          dailyFindings[day] = (dailyFindings[day] || 0) + 1;
        }
      }

      res.json({
        data: {
          totalSastFindings: allSast.length,
          sastBySeverity,
          sastByCategory,
          totalSecrets: allSecrets.length,
          secretsByType,
          ciGatePassRate: gatePassRate,
          totalCiGates: recentGates.length,
          totalSecurityDebt: allDebt.length,
          repositoriesMonitored: repos.size,
          repositories: Array.from(repos),
          dailyFindingsTrend: Object.entries(dailyFindings)
            .map(([date, count]) => ({ date, count }))
            .sort((a, b) => a.date.localeCompare(b.date)),
        },
      });
    } catch (err) {
      log.error("Failed to get dev security stats", { error: String(err) });
      res.status(500).json({ message: "Internal server error" });
    }
  });

  // ── Scan Triggers ──────────────────────────────────────────────

  /** Trigger a manual SAST scan on a repository */
  app.post("/api/developer-security/scan", ...authChain, async (req, res) => {
    try {
      const orgId = (req as any).orgId;

      const { repository, branch, commitSha, files } = req.body;
      if (!repository) return res.status(400).json({ message: "repository is required" });

      // If files are provided directly, scan them
      if (files && Array.isArray(files)) {
        const scanFiles = files
          .filter((f: { path: string; content: string }) => f.path && f.content)
          .map((f: { path: string; content: string }) => ({
            path: f.path,
            content: f.content,
            language: inferLanguage(f.path) || "typescript",
          }));

        const result = runSastScan(scanFiles, repository, branch || "main", commitSha || "manual");

        // Persist findings
        for (const finding of result.findings) {
          await db.insert(sastFindings).values({
            orgId,
            repository,
            branch: branch || "main",
            commitSha: commitSha || null,
            filePath: finding.filePath,
            startLine: finding.startLine,
            endLine: finding.endLine,
            codeSnippet: finding.codeSnippet,
            category: finding.category,
            severity: finding.severity,
            title: finding.title,
            description: finding.description,
            remediation: finding.remediation,
            cweId: finding.cweId,
            owaspCategory: finding.owaspCategory,
            confidence: finding.confidence,
            ruleId: finding.ruleId,
            scanId: result.scanId,
          });
        }

        // Persist secrets
        for (const secret of result.secretFindings) {
          await db.insert(secretsExposed).values({
            orgId,
            repository,
            branch: branch || "main",
            commitSha: commitSha || "manual",
            filePath: secret.filePath,
            line: secret.line,
            secretType: secret.secretType,
            secretHash: secret.secretHash,
            maskedValue: secret.maskedValue,
            severity: secret.severity,
            scanId: result.scanId,
          });
        }

        // Evaluate CI gate
        const policy: CiGatePolicy = {
          maxCritical: 0,
          maxHigh: 5,
          blockOnSecrets: true,
        };
        const gateResult = evaluateCiGate(result, policy);

        // Persist gate result
        await db.insert(ciGates).values({
          orgId,
          repository,
          branch: branch || "main",
          commitSha: commitSha || "manual",
          status: gateResult.status,
          criticalFindings: gateResult.criticalFindings,
          highFindings: gateResult.highFindings,
          mediumFindings: gateResult.mediumFindings,
          lowFindings: gateResult.lowFindings,
          secretsFound: gateResult.secretsFound,
          policyViolations: gateResult.policyViolations,
          gatePolicy: policy,
          failureReasons: gateResult.failureReasons,
          scanDurationMs: result.scanDurationMs,
        });

        return res.json({
          data: {
            scanId: result.scanId,
            findings: result.findings.length,
            secrets: result.secretFindings.length,
            gate: gateResult,
            scanDurationMs: result.scanDurationMs,
            filesScanned: result.filesScanned,
            linesScanned: result.linesScanned,
          },
        });
      }

      // If no files provided, try to scan via GitHub
      const [owner, repo] = repository.split("/");
      if (!owner || !repo) {
        return res.status(400).json({ message: "repository must be in owner/repo format" });
      }

      const ctx: GitHubScanContext = {
        orgId,
        owner,
        repo,
        commitSha: commitSha || "HEAD",
        branch: branch || "main",
      };

      // Get repository tree and scan files
      const tree = await getRepositoryTree(owner, repo, branch || "main");
      const scannableFiles = tree.filter((f) => inferLanguage(f.path) !== null).slice(0, 200);

      const scanFiles: { path: string; content: string; language: string }[] = [];
      for (const file of scannableFiles) {
        const content = await fetchFileContent(ctx, file.path);
        if (content) {
          scanFiles.push({
            path: file.path,
            content,
            language: inferLanguage(file.path) || "typescript",
          });
        }
      }

      const result = runSastScan(scanFiles, repository, branch || "main", commitSha || "HEAD");

      // Persist findings
      for (const finding of result.findings) {
        await db.insert(sastFindings).values({
          orgId,
          repository,
          branch: branch || "main",
          commitSha: commitSha || null,
          filePath: finding.filePath,
          startLine: finding.startLine,
          endLine: finding.endLine,
          codeSnippet: finding.codeSnippet,
          category: finding.category,
          severity: finding.severity,
          title: finding.title,
          description: finding.description,
          remediation: finding.remediation,
          cweId: finding.cweId,
          owaspCategory: finding.owaspCategory,
          confidence: finding.confidence,
          ruleId: finding.ruleId,
          scanId: result.scanId,
        });
      }

      for (const secret of result.secretFindings) {
        await db.insert(secretsExposed).values({
          orgId,
          repository,
          branch: branch || "main",
          commitSha: commitSha || "HEAD",
          filePath: secret.filePath,
          line: secret.line,
          secretType: secret.secretType,
          secretHash: secret.secretHash,
          maskedValue: secret.maskedValue,
          severity: secret.severity,
          scanId: result.scanId,
        });
      }

      res.json({
        data: {
          scanId: result.scanId,
          findings: result.findings.length,
          secrets: result.secretFindings.length,
          scanDurationMs: result.scanDurationMs,
          filesScanned: result.filesScanned,
          linesScanned: result.linesScanned,
        },
      });
    } catch (err) {
      log.error("Failed to run scan", { error: String(err) });
      res.status(500).json({ message: "Internal server error" });
    }
  });

  // ── GitHub Webhook ─────────────────────────────────────────────

  /** Handle GitHub webhook events */
  app.post("/api/developer-security/webhooks/github", async (req, res) => {
    try {
      // Verify GitHub webhook signature (X-Hub-Signature-256)
      const signatureHeader = req.headers["x-hub-signature-256"] as string | undefined;
      const webhookSecret = process.env.GITHUB_WEBHOOK_SECRET;
      if (webhookSecret) {
        if (!signatureHeader) {
          return res.status(401).json({ message: "Missing webhook signature" });
        }
        const rawBody = (req as any).rawBody;
        if (!rawBody) {
          return res.status(400).json({ message: "Missing raw body for signature verification" });
        }
        const expectedSig = "sha256=" + createHmac("sha256", webhookSecret).update(rawBody).digest("hex");
        const sigBuffer = Buffer.from(signatureHeader);
        const expectedBuffer = Buffer.from(expectedSig);
        if (sigBuffer.length !== expectedBuffer.length || !timingSafeEqual(sigBuffer, expectedBuffer)) {
          return res.status(401).json({ message: "Invalid webhook signature" });
        }
      }

      const payload = req.body as GitHubWebhookPayload;
      const event = req.headers["x-github-event"] as string;

      log.info("GitHub webhook received", { event, action: payload.action });

      if (event === "pull_request" && (payload.action === "opened" || payload.action === "synchronize")) {
        const pr = payload.pull_request;
        const repo = payload.repository;
        if (!pr || !repo) return res.status(400).json({ message: "Missing PR or repo data" });

        // Queue the scan (in production this would be async via a job queue)
        res.json({ message: "Scan queued", pr: pr.number });
        return;
      }

      if (event === "push") {
        log.info("Push event received", { ref: payload.ref, repo: payload.repository?.full_name });
        res.json({ message: "Push event received" });
        return;
      }

      res.json({ message: "Event acknowledged" });
    } catch (err) {
      log.error("GitHub webhook error", { error: String(err) });
      res.status(500).json({ message: "Webhook processing error" });
    }
  });

  // ── GitLab Webhook ─────────────────────────────────────────────

  /** Handle GitLab webhook events */
  app.post("/api/developer-security/webhooks/gitlab", async (req, res) => {
    try {
      // Verify GitLab webhook token (X-Gitlab-Token)
      const gitlabTokenHeader = req.headers["x-gitlab-token"] as string | undefined;
      const gitlabWebhookSecret = process.env.GITLAB_WEBHOOK_SECRET;
      if (gitlabWebhookSecret) {
        const tokenBuffer = Buffer.from(gitlabTokenHeader || "");
        const secretBuffer = Buffer.from(gitlabWebhookSecret);
        if (
          !gitlabTokenHeader ||
          tokenBuffer.length !== secretBuffer.length ||
          !timingSafeEqual(tokenBuffer, secretBuffer)
        ) {
          return res.status(401).json({ message: "Invalid GitLab webhook token" });
        }
      }

      const payload = req.body as GitLabWebhookPayload;

      log.info("GitLab webhook received", { kind: payload.object_kind });

      if (payload.object_kind === "merge_request") {
        const mr = payload.object_attributes;
        if (!mr) return res.status(400).json({ message: "Missing MR data" });

        log.info("MR event received", { iid: mr.iid, action: mr.action });
        res.json({ message: "MR event received", iid: mr.iid });
        return;
      }

      if (payload.object_kind === "push") {
        log.info("Push event received", { ref: payload.ref, project: payload.project?.path_with_namespace });
        res.json({ message: "Push event received" });
        return;
      }

      res.json({ message: "Event acknowledged" });
    } catch (err) {
      log.error("GitLab webhook error", { error: String(err) });
      res.status(500).json({ message: "Webhook processing error" });
    }
  });

  // ── SAST Rules ─────────────────────────────────────────────────

  /** Get available SAST rules */
  app.get("/api/developer-security/sast-rules", ...authChain, async (_req, res) => {
    try {
      const rules = getSastRules();
      res.json({
        data: rules.map((r) => ({
          id: r.id,
          category: r.category,
          severity: r.severity,
          title: r.title,
          description: r.description,
          languages: r.languages,
          cweId: r.cweId,
          owaspCategory: r.owaspCategory,
          remediation: r.remediation,
          confidence: r.confidence,
        })),
      });
    } catch (err) {
      res.status(500).json({ message: "Internal server error" });
    }
  });

  // ── Configuration ──────────────────────────────────────────────

  /** Get developer security configuration */
  app.get("/api/developer-security/config", ...authChain, async (req, res) => {
    try {
      const orgId = (req as any).orgId;

      res.json({
        data: {
          ciGatePolicy: {
            maxCritical: 0,
            maxHigh: 5,
            maxMedium: null,
            blockOnSecrets: true,
          },
          scanOnPush: true,
          scanOnPR: true,
          autoComment: true,
          enabledCategories: [
            "sql_injection",
            "xss",
            "path_traversal",
            "command_injection",
            "ssrf",
            "hardcoded_secret",
            "weak_crypto",
            "xxe",
            "open_redirect",
            "idor",
            "missing_auth",
            "prototype_pollution",
            "regex_dos",
            "insecure_deserialization",
          ],
          supportedLanguages: ["typescript", "javascript", "tsx", "jsx", "python", "java", "go", "ruby", "php"],
          integrations: {
            github: { enabled: true, webhookConfigured: false },
            gitlab: { enabled: true, webhookConfigured: false },
            ide: {
              vscode: { available: true, extensionId: "securenexus.sast" },
              jetbrains: { available: true, pluginId: "com.securenexus.sast" },
            },
          },
        },
      });
    } catch (err) {
      res.status(500).json({ message: "Internal server error" });
    }
  });

  log.info("Developer security routes registered");
}

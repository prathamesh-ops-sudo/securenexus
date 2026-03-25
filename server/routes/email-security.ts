import type { Express, Request, Response } from "express";
import { isAuthenticated } from "../auth";
import { resolveOrgContext, requireOrgId, requirePermission, requireMinRole } from "../rbac";
import { logger, getOrgId } from "./shared";
import { db } from "../db";
import { sql, eq, and, desc, gte, lte, count, ilike, or } from "drizzle-orm";
import {
  emailMessages,
  emailFindings,
  emailPolicies,
  emailUrlRewrites,
  emailQuarantineItems,
  EMAIL_FINDING_TYPES,
  EMAIL_FINDING_SEVERITIES,
  EMAIL_FINDING_STATUSES,
  EMAIL_POLICY_ACTIONS,
} from "../../shared/schema";
import {
  analyzeEmailAuthentication,
  detectBec,
  detectThreadInjection,
  analyzeUrl,
  analyzeAttachments,
  analyzeEmail,
  retroactiveIocScan,
  computeSenderReputation,
  computeEmailStats,
  extractUrls,
} from "../email-analyzer";
import { getGraphAccessToken, fetchMailFromGraph, parseGraphMail } from "../integrations/microsoft365";
import { getGmailAccessToken, fetchMailFromGmail, parseGmailMail } from "../integrations/google-workspace";

const log = logger.child("email-security");

const ALLOWED_MESSAGE_FIELDS = [
  "messageId",
  "internetMessageId",
  "subject",
  "senderAddress",
  "senderDisplayName",
  "recipientAddresses",
  "ccAddresses",
  "replyTo",
  "returnPath",
  "receivedAt",
  "direction",
  "hasAttachments",
  "attachmentCount",
  "attachmentNames",
  "urlCount",
  "extractedUrls",
  "spfResult",
  "dkimResult",
  "dmarcResult",
  "authenticationResults",
  "senderReputation",
  "threadId",
  "inReplyTo",
  "references",
  "headers",
  "bodyPreview",
  "isSuspicious",
  "source",
  "rawData",
];

const ALLOWED_FINDING_FIELDS = ["status", "analystNotes", "actionTaken"];

const ALLOWED_POLICY_FIELDS = ["name", "description", "policyType", "action", "conditions", "enabled", "priority"];

export function registerEmailSecurityRoutes(app: Express): void {
  // ==========================================================================
  // Email Security Dashboard
  // ==========================================================================

  // GET /api/email-security/dashboard
  app.get(
    "/api/email-security/dashboard",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const stats = await computeEmailStats(orgId);
        res.json(stats);
      } catch (err) {
        log.error("Failed to compute email dashboard", { error: String(err) });
        res.status(500).json({ error: "Failed to compute email dashboard" });
      }
    },
  );

  // ==========================================================================
  // Email Messages
  // ==========================================================================

  // GET /api/email-security/emails
  app.get(
    "/api/email-security/emails",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { sender, suspicious, direction, source, limit: limitStr, offset: offsetStr } = req.query;
        const limit = Math.min(Number(limitStr) || 50, 200);
        const offset = Number(offsetStr) || 0;

        const conditions = [eq(emailMessages.orgId, orgId)];
        if (sender && typeof sender === "string") {
          const escaped = sender.replace(/%/g, "\\%").replace(/_/g, "\\_");
          conditions.push(ilike(emailMessages.senderAddress, `%${escaped}%`));
        }
        if (suspicious === "true") {
          conditions.push(eq(emailMessages.isSuspicious, true));
        }
        if (direction && typeof direction === "string") {
          conditions.push(eq(emailMessages.direction, direction));
        }
        if (source && typeof source === "string") {
          conditions.push(eq(emailMessages.source, source));
        }

        const [items, [{ value: total }]] = await Promise.all([
          db
            .select()
            .from(emailMessages)
            .where(and(...conditions))
            .orderBy(desc(emailMessages.receivedAt))
            .limit(limit)
            .offset(offset),
          db
            .select({ value: count() })
            .from(emailMessages)
            .where(and(...conditions)),
        ]);

        res.json({ items, total, limit, offset });
      } catch (err) {
        log.error("Failed to list email messages", { error: String(err) });
        res.status(500).json({ error: "Failed to list email messages" });
      }
    },
  );

  // POST /api/email-security/emails — ingest email message + auto-analyze
  app.post(
    "/api/email-security/emails",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const body: Record<string, unknown> = {};
        for (const key of ALLOWED_MESSAGE_FIELDS) {
          if (req.body[key] !== undefined) body[key] = req.body[key];
        }
        if (!body.senderAddress) {
          return res.status(400).json({ error: "senderAddress is required" });
        }

        // Run full analysis pipeline
        const headers = (body.headers && typeof body.headers === "object" ? body.headers : {}) as Record<
          string,
          string
        >;
        const attachmentNames = Array.isArray(body.attachmentNames) ? (body.attachmentNames as string[]) : [];
        const bodyPreview = String(body.bodyPreview || "");
        const extractedUrlsList = Array.isArray(body.extractedUrls)
          ? (body.extractedUrls as string[])
          : extractUrls(bodyPreview);

        const analysis = analyzeEmail(
          String(body.senderAddress),
          String(body.senderDisplayName || ""),
          String(body.subject || ""),
          bodyPreview,
          headers,
          attachmentNames,
          extractedUrlsList,
          body.replyTo ? String(body.replyTo) : null,
          [], // Trusted domains would come from org config
          [], // Executive names would come from org config
        );

        // Insert message
        const [message] = await db
          .insert(emailMessages)
          .values({
            ...body,
            orgId,
            isSuspicious: analysis.isSuspicious,
            senderReputation: 0.5,
            extractedUrls: extractedUrlsList,
            urlCount: extractedUrlsList.length,
          } as typeof emailMessages.$inferInsert)
          .returning();

        // Create findings
        const createdFindings = [];
        for (const finding of analysis.allFindings) {
          const [created] = await db
            .insert(emailFindings)
            .values({
              orgId,
              emailMessageId: message.id,
              findingType: finding.findingType,
              severity: finding.severity,
              title: finding.title,
              description: finding.description,
              confidence: finding.confidence,
              senderAddress: String(body.senderAddress),
              domain: String(body.senderAddress).split("@")[1] || null,
              mitreTechnique: finding.mitreTechnique || null,
              indicators: {
                authentication: analysis.authentication,
                becIndicators: analysis.becAnalysis.indicators,
              },
            })
            .returning();
          createdFindings.push(created);
        }

        // Rewrite URLs if any are malicious
        for (const urlResult of analysis.urlAnalysis) {
          if (urlResult.isMalicious) {
            await db.insert(emailUrlRewrites).values({
              orgId,
              originalUrl: urlResult.url,
              rewrittenUrl: `/api/email-security/click-scan?url=${encodeURIComponent(urlResult.url)}`,
              emailMessageId: message.id,
              isMalicious: true,
              scanDetails: urlResult.indicators,
              scanResult: `confidence: ${urlResult.confidence}`,
            });
          }
        }

        res.status(201).json({
          message,
          findings: createdFindings,
          analysis: {
            isSuspicious: analysis.isSuspicious,
            overallRisk: analysis.overallRisk,
            authenticationPassed: analysis.authentication.overallPass,
            becDetected: analysis.becAnalysis.isBec,
            maliciousUrls: analysis.urlAnalysis.filter((u) => u.isMalicious).length,
            dangerousAttachments: analysis.attachmentAnalysis.filter((a) => a.isDangerous).length,
          },
        });
      } catch (err) {
        log.error("Failed to ingest email message", { error: String(err) });
        res.status(500).json({ error: "Failed to ingest email message" });
      }
    },
  );

  // ==========================================================================
  // Email Findings
  // ==========================================================================

  // GET /api/email-security/findings
  app.get(
    "/api/email-security/findings",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { findingType, severity, status, sender, limit: limitStr, offset: offsetStr } = req.query;
        const limit = Math.min(Number(limitStr) || 50, 200);
        const offset = Number(offsetStr) || 0;

        const conditions = [eq(emailFindings.orgId, orgId)];
        if (findingType && typeof findingType === "string") {
          conditions.push(eq(emailFindings.findingType, findingType));
        }
        if (severity && typeof severity === "string") {
          conditions.push(eq(emailFindings.severity, severity));
        }
        if (status && typeof status === "string") {
          conditions.push(eq(emailFindings.status, status));
        }
        if (sender && typeof sender === "string") {
          const escaped = sender.replace(/%/g, "\\%").replace(/_/g, "\\_");
          conditions.push(ilike(emailFindings.senderAddress, `%${escaped}%`));
        }

        const [items, [{ value: total }]] = await Promise.all([
          db
            .select()
            .from(emailFindings)
            .where(and(...conditions))
            .orderBy(desc(emailFindings.createdAt))
            .limit(limit)
            .offset(offset),
          db
            .select({ value: count() })
            .from(emailFindings)
            .where(and(...conditions)),
        ]);

        res.json({ items, total, limit, offset });
      } catch (err) {
        log.error("Failed to list email findings", { error: String(err) });
        res.status(500).json({ error: "Failed to list email findings" });
      }
    },
  );

  // PATCH /api/email-security/findings/:id
  app.patch(
    "/api/email-security/findings/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const updates: Record<string, unknown> = { updatedAt: new Date() };
        for (const key of ALLOWED_FINDING_FIELDS) {
          if (req.body[key] !== undefined) updates[key] = req.body[key];
        }
        if (updates.status === "resolved") {
          updates.resolvedAt = new Date();
        }

        const [updated] = await db
          .update(emailFindings)
          .set(updates)
          .where(and(eq(emailFindings.id, String(req.params.id)), eq(emailFindings.orgId, orgId)))
          .returning();
        if (!updated) return res.status(404).json({ error: "Email finding not found" });
        res.json(updated);
      } catch (err) {
        log.error("Failed to update email finding", { error: String(err) });
        res.status(500).json({ error: "Failed to update email finding" });
      }
    },
  );

  // ==========================================================================
  // Email Policies
  // ==========================================================================

  // GET /api/email-security/policies
  app.get(
    "/api/email-security/policies",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { policyType, enabled, limit: limitStr, offset: offsetStr } = req.query;
        const limit = Math.min(Number(limitStr) || 50, 200);
        const offset = Number(offsetStr) || 0;

        const conditions = [eq(emailPolicies.orgId, orgId)];
        if (policyType && typeof policyType === "string") {
          conditions.push(eq(emailPolicies.policyType, policyType));
        }
        if (enabled === "true") {
          conditions.push(eq(emailPolicies.enabled, true));
        } else if (enabled === "false") {
          conditions.push(eq(emailPolicies.enabled, false));
        }

        const [items, [{ value: total }]] = await Promise.all([
          db
            .select()
            .from(emailPolicies)
            .where(and(...conditions))
            .orderBy(desc(emailPolicies.priority))
            .limit(limit)
            .offset(offset),
          db
            .select({ value: count() })
            .from(emailPolicies)
            .where(and(...conditions)),
        ]);

        res.json({ items, total, limit, offset });
      } catch (err) {
        log.error("Failed to list email policies", { error: String(err) });
        res.status(500).json({ error: "Failed to list email policies" });
      }
    },
  );

  // POST /api/email-security/policies
  app.post(
    "/api/email-security/policies",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const body: Record<string, unknown> = {};
        for (const key of ALLOWED_POLICY_FIELDS) {
          if (req.body[key] !== undefined) body[key] = req.body[key];
        }
        if (!body.name || !body.policyType) {
          return res.status(400).json({ error: "name and policyType are required" });
        }

        const userId = (req as unknown as { user?: { id?: string } }).user?.id;

        const [created] = await db
          .insert(emailPolicies)
          .values({
            ...body,
            orgId,
            createdBy: userId || null,
          } as typeof emailPolicies.$inferInsert)
          .returning();
        res.status(201).json(created);
      } catch (err) {
        log.error("Failed to create email policy", { error: String(err) });
        res.status(500).json({ error: "Failed to create email policy" });
      }
    },
  );

  // PATCH /api/email-security/policies/:id
  app.patch(
    "/api/email-security/policies/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const updates: Record<string, unknown> = { updatedAt: new Date() };
        for (const key of ALLOWED_POLICY_FIELDS) {
          if (req.body[key] !== undefined) updates[key] = req.body[key];
        }

        const [updated] = await db
          .update(emailPolicies)
          .set(updates)
          .where(and(eq(emailPolicies.id, String(req.params.id)), eq(emailPolicies.orgId, orgId)))
          .returning();
        if (!updated) return res.status(404).json({ error: "Email policy not found" });
        res.json(updated);
      } catch (err) {
        log.error("Failed to update email policy", { error: String(err) });
        res.status(500).json({ error: "Failed to update email policy" });
      }
    },
  );

  // DELETE /api/email-security/policies/:id
  app.delete(
    "/api/email-security/policies/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const [deleted] = await db
          .delete(emailPolicies)
          .where(and(eq(emailPolicies.id, String(req.params.id)), eq(emailPolicies.orgId, orgId)))
          .returning();
        if (!deleted) return res.status(404).json({ error: "Email policy not found" });
        res.json({ success: true });
      } catch (err) {
        log.error("Failed to delete email policy", { error: String(err) });
        res.status(500).json({ error: "Failed to delete email policy" });
      }
    },
  );

  // ==========================================================================
  // URL Rewrites & Click-Time Scanning
  // ==========================================================================

  // GET /api/email-security/url-rewrites
  app.get(
    "/api/email-security/url-rewrites",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { malicious, limit: limitStr, offset: offsetStr } = req.query;
        const limit = Math.min(Number(limitStr) || 50, 200);
        const offset = Number(offsetStr) || 0;

        const conditions = [eq(emailUrlRewrites.orgId, orgId)];
        if (malicious === "true") {
          conditions.push(eq(emailUrlRewrites.isMalicious, true));
        }

        const [items, [{ value: total }]] = await Promise.all([
          db
            .select()
            .from(emailUrlRewrites)
            .where(and(...conditions))
            .orderBy(desc(emailUrlRewrites.createdAt))
            .limit(limit)
            .offset(offset),
          db
            .select({ value: count() })
            .from(emailUrlRewrites)
            .where(and(...conditions)),
        ]);

        res.json({ items, total, limit, offset });
      } catch (err) {
        log.error("Failed to list URL rewrites", { error: String(err) });
        res.status(500).json({ error: "Failed to list URL rewrites" });
      }
    },
  );

  // POST /api/email-security/click-scan — click-time URL scanning
  app.post(
    "/api/email-security/click-scan",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { url } = req.body;
        if (!url || typeof url !== "string") {
          return res.status(400).json({ error: "url is required" });
        }

        const scanResult = analyzeUrl(url);

        // Log the click
        const existing = await db
          .select()
          .from(emailUrlRewrites)
          .where(and(eq(emailUrlRewrites.orgId, orgId), eq(emailUrlRewrites.originalUrl, url)))
          .limit(1);

        if (existing.length > 0) {
          await db
            .update(emailUrlRewrites)
            .set({
              clickCount: sql`${emailUrlRewrites.clickCount} + 1`,
              lastClickAt: new Date(),
              scanResult: `confidence: ${scanResult.confidence}`,
              isMalicious: scanResult.isMalicious,
              scanDetails: scanResult.indicators,
            })
            .where(eq(emailUrlRewrites.id, existing[0].id));
        } else {
          await db.insert(emailUrlRewrites).values({
            orgId,
            originalUrl: url,
            clickCount: 1,
            lastClickAt: new Date(),
            scanResult: `confidence: ${scanResult.confidence}`,
            isMalicious: scanResult.isMalicious,
            scanDetails: scanResult.indicators,
          });
        }

        res.json({
          url,
          safe: !scanResult.isMalicious,
          confidence: scanResult.confidence,
          indicators: scanResult.indicators,
          action: scanResult.isMalicious ? "blocked" : "allowed",
        });
      } catch (err) {
        log.error("Failed to scan URL", { error: String(err) });
        res.status(500).json({ error: "Failed to scan URL" });
      }
    },
  );

  // ==========================================================================
  // Quarantine
  // ==========================================================================

  // GET /api/email-security/quarantine
  app.get(
    "/api/email-security/quarantine",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { status, limit: limitStr, offset: offsetStr } = req.query;
        const limit = Math.min(Number(limitStr) || 50, 200);
        const offset = Number(offsetStr) || 0;

        const conditions = [eq(emailQuarantineItems.orgId, orgId)];
        if (status && typeof status === "string") {
          conditions.push(eq(emailQuarantineItems.status, status));
        }

        const [items, [{ value: total }]] = await Promise.all([
          db
            .select()
            .from(emailQuarantineItems)
            .where(and(...conditions))
            .orderBy(desc(emailQuarantineItems.createdAt))
            .limit(limit)
            .offset(offset),
          db
            .select({ value: count() })
            .from(emailQuarantineItems)
            .where(and(...conditions)),
        ]);

        res.json({ items, total, limit, offset });
      } catch (err) {
        log.error("Failed to list quarantine items", { error: String(err) });
        res.status(500).json({ error: "Failed to list quarantine items" });
      }
    },
  );

  // POST /api/email-security/quarantine/:id/release — release from quarantine
  app.post(
    "/api/email-security/quarantine/:id/release",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const userId = (req as unknown as { user?: { id?: string } }).user?.id;

        const [updated] = await db
          .update(emailQuarantineItems)
          .set({
            status: "released",
            releasedBy: userId || null,
            releasedAt: new Date(),
          })
          .where(and(eq(emailQuarantineItems.id, String(req.params.id)), eq(emailQuarantineItems.orgId, orgId)))
          .returning();

        if (!updated) return res.status(404).json({ error: "Quarantine item not found" });
        res.json(updated);
      } catch (err) {
        log.error("Failed to release quarantine item", { error: String(err) });
        res.status(500).json({ error: "Failed to release quarantine item" });
      }
    },
  );

  // ==========================================================================
  // Analysis Tools
  // ==========================================================================

  // POST /api/email-security/analyze/headers — on-demand header analysis
  app.post(
    "/api/email-security/analyze/headers",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const { headers } = req.body;
        if (!headers || typeof headers !== "object") {
          return res.status(400).json({ error: "headers object is required" });
        }
        const result = analyzeEmailAuthentication(headers);
        res.json(result);
      } catch (err) {
        log.error("Failed to analyze headers", { error: String(err) });
        res.status(500).json({ error: "Failed to analyze headers" });
      }
    },
  );

  // POST /api/email-security/analyze/bec — on-demand BEC detection
  app.post(
    "/api/email-security/analyze/bec",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const { senderAddress, senderDisplayName, subject, bodyPreview, replyTo, trustedDomains, executiveNames } =
          req.body;
        if (!senderAddress || typeof senderAddress !== "string") {
          return res.status(400).json({ error: "senderAddress is required" });
        }
        const result = detectBec(
          senderAddress,
          senderDisplayName || "",
          subject || "",
          bodyPreview || "",
          replyTo || null,
          Array.isArray(trustedDomains) ? trustedDomains : [],
          Array.isArray(executiveNames) ? executiveNames : [],
        );
        res.json(result);
      } catch (err) {
        log.error("Failed to analyze BEC", { error: String(err) });
        res.status(500).json({ error: "Failed to analyze BEC" });
      }
    },
  );

  // POST /api/email-security/analyze/url — on-demand URL scanning
  app.post(
    "/api/email-security/analyze/url",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const { url } = req.body;
        if (!url || typeof url !== "string") {
          return res.status(400).json({ error: "url is required" });
        }
        const result = analyzeUrl(url);
        res.json(result);
      } catch (err) {
        log.error("Failed to analyze URL", { error: String(err) });
        res.status(500).json({ error: "Failed to analyze URL" });
      }
    },
  );

  // POST /api/email-security/analyze/attachments — on-demand attachment analysis
  app.post(
    "/api/email-security/analyze/attachments",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const { attachmentNames } = req.body;
        if (!Array.isArray(attachmentNames)) {
          return res.status(400).json({ error: "attachmentNames array is required" });
        }
        const results = analyzeAttachments(attachmentNames);
        res.json(results);
      } catch (err) {
        log.error("Failed to analyze attachments", { error: String(err) });
        res.status(500).json({ error: "Failed to analyze attachments" });
      }
    },
  );

  // POST /api/email-security/analyze/thread-injection — detect thread injection
  app.post(
    "/api/email-security/analyze/thread-injection",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { threadId, senderAddress, inReplyTo, receivedAt } = req.body;
        if (!threadId || typeof threadId !== "string") {
          return res.status(400).json({ error: "threadId is required" });
        }
        if (!senderAddress || typeof senderAddress !== "string") {
          return res.status(400).json({ error: "senderAddress is required" });
        }
        const result = await detectThreadInjection(
          orgId,
          threadId,
          senderAddress,
          inReplyTo || null,
          receivedAt ? new Date(receivedAt) : new Date(),
        );
        res.json(result);
      } catch (err) {
        log.error("Failed to detect thread injection", { error: String(err) });
        res.status(500).json({ error: "Failed to detect thread injection" });
      }
    },
  );

  // POST /api/email-security/analyze/sender-reputation
  app.post(
    "/api/email-security/analyze/sender-reputation",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { senderAddress } = req.body;
        if (!senderAddress || typeof senderAddress !== "string") {
          return res.status(400).json({ error: "senderAddress is required" });
        }
        const result = await computeSenderReputation(orgId, senderAddress);
        res.json(result);
      } catch (err) {
        log.error("Failed to compute sender reputation", { error: String(err) });
        res.status(500).json({ error: "Failed to compute sender reputation" });
      }
    },
  );

  // ==========================================================================
  // Retroactive IOC Scanning
  // ==========================================================================

  // POST /api/email-security/retroactive-scan
  app.post(
    "/api/email-security/retroactive-scan",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { iocs, lookbackDays } = req.body;
        if (!Array.isArray(iocs) || iocs.length === 0) {
          return res.status(400).json({ error: "iocs array is required with at least one IOC" });
        }

        // Validate IOC structure
        for (const ioc of iocs) {
          if (!ioc.value || !ioc.type) {
            return res.status(400).json({ error: "Each IOC must have value and type fields" });
          }
          if (!["domain", "email", "url", "ip"].includes(ioc.type)) {
            return res.status(400).json({ error: `Invalid IOC type: ${ioc.type}. Must be domain, email, url, or ip` });
          }
        }

        const result = await retroactiveIocScan(orgId, iocs, Number(lookbackDays) || 90);

        // Create findings for matches (deduplicate — skip if finding already exists)
        for (const match of result.matches) {
          const existing = await db
            .select({ id: emailFindings.id })
            .from(emailFindings)
            .where(
              and(
                eq(emailFindings.orgId, orgId),
                eq(emailFindings.emailMessageId, match.emailMessageId),
                eq(emailFindings.findingType, "retroactive_ioc_match"),
                sql`${emailFindings.indicators}->>'ioc' = ${match.matchedIoc}`,
              ),
            )
            .limit(1);
          if (existing.length > 0) continue;

          await db.insert(emailFindings).values({
            orgId,
            emailMessageId: match.emailMessageId,
            findingType: "retroactive_ioc_match",
            severity: "high",
            title: `Retroactive IOC match: ${match.matchedIoc}`,
            description: `Historical email from "${match.senderAddress}" matches newly identified IOC "${match.matchedIoc}" (type: ${match.matchType})`,
            confidence: 0.95,
            senderAddress: match.senderAddress,
            indicators: { ioc: match.matchedIoc, iocType: match.matchType },
            mitreTechnique: "T1566",
          });
        }

        res.json(result);
      } catch (err) {
        log.error("Failed to run retroactive IOC scan", { error: String(err) });
        res.status(500).json({ error: "Failed to run retroactive IOC scan" });
      }
    },
  );

  // ==========================================================================
  // Cloud Integration Sync
  // ==========================================================================

  // POST /api/email-security/m365/sync — sync emails from Microsoft 365
  app.post(
    "/api/email-security/m365/sync",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { tenantId, clientId, clientSecret, userPrincipalName, maxMessages } = req.body;

        // If no credentials provided, return configuration instructions
        if (!tenantId || !clientId || !clientSecret) {
          return res.json({
            status: "ready",
            message: "Microsoft 365 sync endpoint ready. Provide Graph API credentials in the request body to sync.",
            configRequired: {
              tenantId: "Azure AD tenant ID",
              clientId: "App registration client ID",
              clientSecret: "App registration client secret",
              userPrincipalName: "Mailbox to monitor (e.g. security@company.com)",
            },
          });
        }

        // Authenticate with Graph API
        const accessToken = await getGraphAccessToken({ tenantId, clientId, clientSecret });
        if (!accessToken) {
          return res
            .status(401)
            .json({ error: "Failed to authenticate with Microsoft Graph API. Check your credentials." });
        }

        // Fetch mail from Graph API
        const limit = Math.min(parseInt(String(maxMessages || "50")), 200);
        const rawMessages = await fetchMailFromGraph(accessToken, userPrincipalName || "me", { top: limit });

        // Parse and analyze each message
        let ingested = 0;
        let alertsCreated = 0;
        for (const rawMsg of rawMessages) {
          const parsed = parseGraphMail(rawMsg);
          if (!parsed) continue;

          // Analyze email for threats
          const parsedHeaders =
            parsed.headers && typeof parsed.headers === "object" ? (parsed.headers as Record<string, string>) : {};
          const analysis = analyzeEmail(
            parsed.senderAddress,
            parsed.senderDisplayName || "",
            parsed.subject || "",
            parsed.bodyPreview || "",
            parsedHeaders,
            [], // attachmentNames
            [], // extractedUrls
            null, // replyTo
            [], // trustedDomains
            [], // executiveNames
          );

          // Insert into emailMessages
          const [created] = await db
            .insert(emailMessages)
            .values({
              orgId,
              messageId: parsed.messageId,
              subject: parsed.subject,
              senderAddress: parsed.senderAddress,
              senderDisplayName: parsed.senderDisplayName,
              recipientAddresses: parsed.recipientAddresses,
              receivedAt: parsed.receivedAt,
              direction: "inbound",
              isSuspicious: analysis.isSuspicious,
              headers: parsedHeaders,
              source: "microsoft365",
            })
            .onConflictDoNothing()
            .returning();

          if (created) {
            ingested++;
            // Create findings for threats detected
            for (const finding of analysis.allFindings) {
              await db.insert(emailFindings).values({
                orgId,
                emailMessageId: created.id,
                findingType: finding.findingType,
                severity: finding.severity,
                title: finding.title,
                description: finding.description,
                confidence: finding.confidence,
                mitreTechnique: finding.mitreTechnique || null,
                status: "open",
              });
              alertsCreated++;
            }
          }
        }

        res.json({
          status: "completed",
          message: `Synced ${ingested} messages from Microsoft 365`,
          totalFetched: rawMessages.length,
          ingested,
          alertsCreated,
        });
      } catch (err) {
        log.error("Failed to sync M365 mail", { error: String(err) });
        res.status(500).json({ error: "Failed to sync M365 mail" });
      }
    },
  );

  // POST /api/email-security/gmail/sync — sync emails from Google Workspace
  app.post(
    "/api/email-security/gmail/sync",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { clientId, clientSecret, refreshToken, delegatedUser, maxMessages } = req.body;

        // If no credentials provided, return configuration instructions
        if (!clientId || !clientSecret || !refreshToken) {
          return res.json({
            status: "ready",
            message: "Google Workspace sync endpoint ready. Provide Gmail API credentials in the request body to sync.",
            configRequired: {
              clientId: "OAuth2 client ID",
              clientSecret: "OAuth2 client secret",
              refreshToken: "OAuth2 refresh token",
              delegatedUser: "Gmail user to monitor",
            },
          });
        }

        // Authenticate with Gmail API
        const accessToken = await getGmailAccessToken({ clientId, clientSecret, refreshToken });
        if (!accessToken) {
          return res.status(401).json({ error: "Failed to authenticate with Gmail API. Check your credentials." });
        }

        // Fetch mail from Gmail API
        const limit = Math.min(parseInt(String(maxMessages || "50")), 200);
        const rawMessages = await fetchMailFromGmail(accessToken, delegatedUser || "me", { maxResults: limit });

        // Parse and analyze each message
        let ingested = 0;
        let alertsCreated = 0;
        for (const rawMsg of rawMessages) {
          const parsed = parseGmailMail(rawMsg);
          if (!parsed) continue;

          // Analyze email for threats
          const gmailHeaders =
            parsed.headers && typeof parsed.headers === "object" ? (parsed.headers as Record<string, string>) : {};
          const analysis = analyzeEmail(
            parsed.senderAddress,
            parsed.senderDisplayName || "",
            parsed.subject || "",
            parsed.bodyPreview || "",
            gmailHeaders,
            [], // attachmentNames
            [], // extractedUrls
            null, // replyTo
            [], // trustedDomains
            [], // executiveNames
          );

          // Insert into emailMessages
          const [created] = await db
            .insert(emailMessages)
            .values({
              orgId,
              messageId: parsed.messageId,
              subject: parsed.subject,
              senderAddress: parsed.senderAddress,
              senderDisplayName: parsed.senderDisplayName,
              recipientAddresses: parsed.recipientAddresses,
              receivedAt: parsed.receivedAt,
              direction: "inbound",
              isSuspicious: analysis.isSuspicious,
              headers: gmailHeaders,
              source: "gmail",
            })
            .onConflictDoNothing()
            .returning();

          if (created) {
            ingested++;
            for (const finding of analysis.allFindings) {
              await db.insert(emailFindings).values({
                orgId,
                emailMessageId: created.id,
                findingType: finding.findingType,
                severity: finding.severity,
                title: finding.title,
                description: finding.description,
                confidence: finding.confidence,
                mitreTechnique: finding.mitreTechnique || null,
                status: "open",
              });
              alertsCreated++;
            }
          }
        }

        res.json({
          status: "completed",
          message: `Synced ${ingested} messages from Gmail`,
          totalFetched: rawMessages.length,
          ingested,
          alertsCreated,
        });
      } catch (err) {
        log.error("Failed to sync Gmail", { error: String(err) });
        res.status(500).json({ error: "Failed to sync Gmail" });
      }
    },
  );

  // ==========================================================================
  // 72.5 — Email Gateway Integration Status
  // ==========================================================================

  // GET /api/email-security/integration-status
  app.get(
    "/api/email-security/integration-status",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        // Check integration configs from email policies (integration type policies)
        const [integrationPolicies] = await Promise.all([
          db
            .select()
            .from(emailPolicies)
            .where(and(eq(emailPolicies.orgId, orgId), eq(emailPolicies.policyType, "integration"))),
        ]);

        const gateways = [
          { provider: "microsoft_365", label: "Microsoft 365", configured: false, lastSync: null as string | null },
          {
            provider: "google_workspace",
            label: "Google Workspace",
            configured: false,
            lastSync: null as string | null,
          },
          {
            provider: "exchange_onprem",
            label: "Exchange On-Premises",
            configured: false,
            lastSync: null as string | null,
          },
          { provider: "proofpoint", label: "Proofpoint", configured: false, lastSync: null as string | null },
          { provider: "mimecast", label: "Mimecast", configured: false, lastSync: null as string | null },
        ];

        for (const policy of integrationPolicies) {
          const match = gateways.find((g) => g.provider === policy.name);
          if (match) {
            match.configured = policy.enabled;
            match.lastSync = policy.updatedAt ? new Date(policy.updatedAt).toISOString() : null;
          }
        }

        res.json({
          gateways,
          totalConfigured: gateways.filter((g) => g.configured).length,
        });
      } catch (err) {
        log.error("Failed to check email integration status", { error: String(err) });
        res.status(500).json({ error: "Failed to check email integration status" });
      }
    },
  );

  // ==========================================================================
  // 72.6 — Retroactive IOC Scan Status
  // ==========================================================================

  // GET /api/email-security/retroactive-scan-history
  app.get(
    "/api/email-security/retroactive-scan-history",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        // Get recent retroactive IOC scan findings
        const scanFindings = await db
          .select()
          .from(emailFindings)
          .where(and(eq(emailFindings.orgId, orgId), eq(emailFindings.findingType, "retroactive_ioc_match")))
          .orderBy(desc(emailFindings.createdAt))
          .limit(50);

        res.json({
          recentMatches: scanFindings,
          totalMatches: scanFindings.length,
        });
      } catch (err) {
        log.error("Failed to get retroactive scan history", { error: String(err) });
        res.status(500).json({ error: "Failed to get retroactive scan history" });
      }
    },
  );

  // ==========================================================================
  // 72.7 — Email Authentication Verification
  // ==========================================================================

  // GET /api/email-security/auth-compliance
  app.get(
    "/api/email-security/auth-compliance",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);

        // Get email messages and check auth results
        const messages = await db
          .select()
          .from(emailMessages)
          .where(and(eq(emailMessages.orgId, orgId), gte(emailMessages.receivedAt, thirtyDaysAgo)))
          .limit(1000);

        let spfPass = 0,
          spfFail = 0;
        let dkimPass = 0,
          dkimFail = 0;
        let dmarcPass = 0,
          dmarcFail = 0;

        for (const msg of messages) {
          const auth = (msg as Record<string, unknown>).authResults as Record<string, string> | null;
          if (!auth) continue;
          if (auth.spf === "pass") spfPass++;
          else spfFail++;
          if (auth.dkim === "pass") dkimPass++;
          else dkimFail++;
          if (auth.dmarc === "pass") dmarcPass++;
          else dmarcFail++;
        }

        const total = messages.length || 1;
        res.json({
          totalAnalyzed: messages.length,
          spf: { pass: spfPass, fail: spfFail, rate: Math.round((spfPass / total) * 100) },
          dkim: { pass: dkimPass, fail: dkimFail, rate: Math.round((dkimPass / total) * 100) },
          dmarc: { pass: dmarcPass, fail: dmarcFail, rate: Math.round((dmarcPass / total) * 100) },
          overallCompliance: Math.round(((spfPass + dkimPass + dmarcPass) / (total * 3)) * 100),
        });
      } catch (err) {
        log.error("Failed to get email auth compliance", { error: String(err) });
        res.status(500).json({ error: "Failed to get email auth compliance" });
      }
    },
  );

  // ==========================================================================
  // Reference Data
  // ==========================================================================

  // GET /api/email-security/reference
  app.get(
    "/api/email-security/reference",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (_req: Request, res: Response) => {
      res.json({
        findingTypes: EMAIL_FINDING_TYPES,
        findingSeverities: EMAIL_FINDING_SEVERITIES,
        findingStatuses: EMAIL_FINDING_STATUSES,
        policyActions: EMAIL_POLICY_ACTIONS,
      });
    },
  );
}

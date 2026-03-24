import type { Express, Request, Response } from "express";
import { isAuthenticated } from "../auth";
import { resolveOrgContext, requireOrgId, requirePermission } from "../rbac";
import { logger, getOrgId } from "./shared";
import { db } from "../db";
import { sql, eq, and, desc, gte, lte, count, ilike, or } from "drizzle-orm";
import {
  dnsEvents,
  dnsFindings,
  sinkholedDomains,
  passiveDnsRecords,
  DNS_EVENT_TYPES,
  DNS_FINDING_TYPES,
  DNS_FINDING_SEVERITIES,
  SINKHOLE_STATUSES,
} from "../../shared/schema";
import {
  detectDga,
  detectDnsTunneling,
  detectDnsExfiltration,
  checkNewlyRegisteredDomain,
  analyzeDnsQuery,
  checkSinkhole,
  upsertPassiveDnsRecord,
  computeDnsStats,
  computeEntropy,
} from "../dns-analyzer";

const log = logger.child("dns-security");

const ALLOWED_EVENT_FIELDS = [
  "eventType",
  "queryName",
  "queryType",
  "responseCode",
  "responseData",
  "sourceIp",
  "sourceHostname",
  "destinationIp",
  "serverIp",
  "querySize",
  "responseSize",
  "rawData",
];

const ALLOWED_FINDING_FIELDS = ["status", "analystNotes"];

const ALLOWED_SINKHOLE_FIELDS = ["domain", "reason", "source", "status", "expiresAt"];

export function registerDnsSecurityRoutes(app: Express): void {
  // ==========================================================================
  // DNS Dashboard / Stats
  // ==========================================================================

  // GET /api/dns-security/dashboard
  app.get(
    "/api/dns-security/dashboard",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const stats = await computeDnsStats(orgId);
        res.json(stats);
      } catch (err) {
        log.error("Failed to compute DNS dashboard", { error: String(err) });
        res.status(500).json({ error: "Failed to compute DNS dashboard" });
      }
    },
  );

  // ==========================================================================
  // DNS Events
  // ==========================================================================

  // GET /api/dns-security/events
  app.get(
    "/api/dns-security/events",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { eventType, sourceIp, domain: domainFilter, suspicious, limit: limitStr, offset: offsetStr } = req.query;
        const limit = Math.min(Number(limitStr) || 50, 200);
        const offset = Number(offsetStr) || 0;

        const conditions = [eq(dnsEvents.orgId, orgId)];
        if (eventType && typeof eventType === "string") {
          conditions.push(eq(dnsEvents.eventType, eventType));
        }
        if (sourceIp && typeof sourceIp === "string") {
          conditions.push(eq(dnsEvents.sourceIp, sourceIp));
        }
        if (domainFilter && typeof domainFilter === "string") {
          const escaped = domainFilter.replace(/%/g, "\\%").replace(/_/g, "\\_");
          conditions.push(ilike(dnsEvents.queryName, `%${escaped}%`));
        }
        if (suspicious === "true") {
          conditions.push(eq(dnsEvents.isSuspicious, true));
        }

        const [items, [{ value: total }]] = await Promise.all([
          db
            .select()
            .from(dnsEvents)
            .where(and(...conditions))
            .orderBy(desc(dnsEvents.timestamp))
            .limit(limit)
            .offset(offset),
          db
            .select({ value: count() })
            .from(dnsEvents)
            .where(and(...conditions)),
        ]);

        res.json({ items, total, limit, offset });
      } catch (err) {
        log.error("Failed to list DNS events", { error: String(err) });
        res.status(500).json({ error: "Failed to list DNS events" });
      }
    },
  );

  // POST /api/dns-security/events — ingest DNS event + auto-analyze
  app.post(
    "/api/dns-security/events",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const body: Record<string, unknown> = {};
        for (const key of ALLOWED_EVENT_FIELDS) {
          if (req.body[key] !== undefined) body[key] = req.body[key];
        }
        if (!body.queryName || !body.eventType) {
          return res.status(400).json({ error: "queryName and eventType are required" });
        }

        const queryName = String(body.queryName);
        const queryType = String(body.queryType || "A");
        const sourceIp = String(body.sourceIp || "unknown");

        // Auto-analyze the query
        const analysis = analyzeDnsQuery(queryName, queryType, sourceIp);
        const entropy = computeEntropy(queryName);

        // Check sinkhole
        const sinkholeResult = await checkSinkhole(orgId, queryName);
        let eventType = String(body.eventType);
        if (sinkholeResult.isSinkholed) {
          eventType = "sinkholed";
        }

        // Insert event
        const [event] = await db
          .insert(dnsEvents)
          .values({
            ...body,
            orgId,
            eventType,
            entropy,
            isSuspicious: analysis.isSuspicious || sinkholeResult.isSinkholed,
            timestamp: new Date(),
          } as typeof dnsEvents.$inferInsert)
          .returning();

        // Create findings if suspicious
        const createdFindings = [];
        for (const finding of analysis.findings) {
          const [created] = await db
            .insert(dnsFindings)
            .values({
              orgId,
              findingType: finding.findingType,
              severity: finding.severity,
              domain: queryName,
              description: finding.description,
              confidence: finding.confidence,
              sourceIp,
              indicators: finding.indicators || null,
              mitreTechnique: finding.mitreTechnique || null,
            })
            .returning();
          createdFindings.push(created);
        }

        if (sinkholeResult.isSinkholed) {
          const [sinkFinding] = await db
            .insert(dnsFindings)
            .values({
              orgId,
              findingType: "sinkholed_hit",
              severity: "high",
              domain: queryName,
              description: `Sinkholed domain hit: ${queryName} (reason: ${sinkholeResult.sinkhole?.reason || "N/A"})`,
              confidence: 1.0,
              sourceIp,
              mitreTechnique: "T1071.004",
            })
            .returning();
          createdFindings.push(sinkFinding);
        }

        // Upsert passive DNS record
        if (body.responseData && typeof body.responseData === "string") {
          await upsertPassiveDnsRecord(orgId, queryName, queryType, body.responseData, "internal");
        }

        res.status(201).json({
          event,
          findings: createdFindings,
          analysis,
          sinkholed: sinkholeResult.isSinkholed,
        });
      } catch (err) {
        log.error("Failed to ingest DNS event", { error: String(err) });
        res.status(500).json({ error: "Failed to ingest DNS event" });
      }
    },
  );

  // ==========================================================================
  // DNS Findings
  // ==========================================================================

  // GET /api/dns-security/findings
  app.get(
    "/api/dns-security/findings",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { findingType, severity, status, limit: limitStr, offset: offsetStr } = req.query;
        const limit = Math.min(Number(limitStr) || 50, 200);
        const offset = Number(offsetStr) || 0;

        const conditions = [eq(dnsFindings.orgId, orgId)];
        if (findingType && typeof findingType === "string") {
          conditions.push(eq(dnsFindings.findingType, findingType));
        }
        if (severity && typeof severity === "string") {
          conditions.push(eq(dnsFindings.severity, severity));
        }
        if (status && typeof status === "string") {
          conditions.push(eq(dnsFindings.status, status));
        }

        const [items, [{ value: total }]] = await Promise.all([
          db
            .select()
            .from(dnsFindings)
            .where(and(...conditions))
            .orderBy(desc(dnsFindings.createdAt))
            .limit(limit)
            .offset(offset),
          db
            .select({ value: count() })
            .from(dnsFindings)
            .where(and(...conditions)),
        ]);

        res.json({ items, total, limit, offset });
      } catch (err) {
        log.error("Failed to list DNS findings", { error: String(err) });
        res.status(500).json({ error: "Failed to list DNS findings" });
      }
    },
  );

  // PATCH /api/dns-security/findings/:id
  app.patch(
    "/api/dns-security/findings/:id",
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
          .update(dnsFindings)
          .set(updates)
          .where(and(eq(dnsFindings.id, String(req.params.id)), eq(dnsFindings.orgId, orgId)))
          .returning();
        if (!updated) return res.status(404).json({ error: "DNS finding not found" });
        res.json(updated);
      } catch (err) {
        log.error("Failed to update DNS finding", { error: String(err) });
        res.status(500).json({ error: "Failed to update DNS finding" });
      }
    },
  );

  // ==========================================================================
  // Sinkholed Domains
  // ==========================================================================

  // GET /api/dns-security/sinkholes
  app.get(
    "/api/dns-security/sinkholes",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { status, limit: limitStr, offset: offsetStr } = req.query;
        const limit = Math.min(Number(limitStr) || 50, 200);
        const offset = Number(offsetStr) || 0;

        const conditions = [eq(sinkholedDomains.orgId, orgId)];
        if (status && typeof status === "string") {
          conditions.push(eq(sinkholedDomains.status, status));
        }

        const [items, [{ value: total }]] = await Promise.all([
          db
            .select()
            .from(sinkholedDomains)
            .where(and(...conditions))
            .orderBy(desc(sinkholedDomains.createdAt))
            .limit(limit)
            .offset(offset),
          db
            .select({ value: count() })
            .from(sinkholedDomains)
            .where(and(...conditions)),
        ]);

        res.json({ items, total, limit, offset });
      } catch (err) {
        log.error("Failed to list sinkholed domains", { error: String(err) });
        res.status(500).json({ error: "Failed to list sinkholed domains" });
      }
    },
  );

  // POST /api/dns-security/sinkholes
  app.post(
    "/api/dns-security/sinkholes",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const body: Record<string, unknown> = {};
        for (const key of ALLOWED_SINKHOLE_FIELDS) {
          if (req.body[key] !== undefined) body[key] = req.body[key];
        }
        if (!body.domain) {
          return res.status(400).json({ error: "domain is required" });
        }

        const userId = (req as unknown as { user?: { id?: string } }).user?.id;

        const [created] = await db
          .insert(sinkholedDomains)
          .values({
            ...body,
            orgId,
            addedBy: userId || null,
          } as typeof sinkholedDomains.$inferInsert)
          .returning();
        res.status(201).json(created);
      } catch (err) {
        log.error("Failed to create sinkholed domain", { error: String(err) });
        res.status(500).json({ error: "Failed to create sinkholed domain" });
      }
    },
  );

  // PATCH /api/dns-security/sinkholes/:id
  app.patch(
    "/api/dns-security/sinkholes/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const updates: Record<string, unknown> = { updatedAt: new Date() };
        for (const key of ALLOWED_SINKHOLE_FIELDS) {
          if (req.body[key] !== undefined) updates[key] = req.body[key];
        }

        const [updated] = await db
          .update(sinkholedDomains)
          .set(updates)
          .where(and(eq(sinkholedDomains.id, String(req.params.id)), eq(sinkholedDomains.orgId, orgId)))
          .returning();
        if (!updated) return res.status(404).json({ error: "Sinkholed domain not found" });
        res.json(updated);
      } catch (err) {
        log.error("Failed to update sinkholed domain", { error: String(err) });
        res.status(500).json({ error: "Failed to update sinkholed domain" });
      }
    },
  );

  // DELETE /api/dns-security/sinkholes/:id
  app.delete(
    "/api/dns-security/sinkholes/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const [deleted] = await db
          .delete(sinkholedDomains)
          .where(and(eq(sinkholedDomains.id, String(req.params.id)), eq(sinkholedDomains.orgId, orgId)))
          .returning();
        if (!deleted) return res.status(404).json({ error: "Sinkholed domain not found" });
        res.json({ success: true });
      } catch (err) {
        log.error("Failed to delete sinkholed domain", { error: String(err) });
        res.status(500).json({ error: "Failed to delete sinkholed domain" });
      }
    },
  );

  // ==========================================================================
  // Passive DNS Records
  // ==========================================================================

  // GET /api/dns-security/passive-dns
  app.get(
    "/api/dns-security/passive-dns",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { domain: domainFilter, recordType, limit: limitStr, offset: offsetStr } = req.query;
        const limit = Math.min(Number(limitStr) || 50, 200);
        const offset = Number(offsetStr) || 0;

        const conditions = [eq(passiveDnsRecords.orgId, orgId)];
        if (domainFilter && typeof domainFilter === "string") {
          const escaped = domainFilter.replace(/%/g, "\\%").replace(/_/g, "\\_");
          conditions.push(ilike(passiveDnsRecords.domain, `%${escaped}%`));
        }
        if (recordType && typeof recordType === "string") {
          conditions.push(eq(passiveDnsRecords.recordType, recordType));
        }

        const [items, [{ value: total }]] = await Promise.all([
          db
            .select()
            .from(passiveDnsRecords)
            .where(and(...conditions))
            .orderBy(desc(passiveDnsRecords.lastSeen))
            .limit(limit)
            .offset(offset),
          db
            .select({ value: count() })
            .from(passiveDnsRecords)
            .where(and(...conditions)),
        ]);

        res.json({ items, total, limit, offset });
      } catch (err) {
        log.error("Failed to list passive DNS records", { error: String(err) });
        res.status(500).json({ error: "Failed to list passive DNS records" });
      }
    },
  );

  // ==========================================================================
  // Analysis Tools
  // ==========================================================================

  // POST /api/dns-security/analyze/dga
  app.post(
    "/api/dns-security/analyze/dga",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const { domain } = req.body;
        if (!domain || typeof domain !== "string") {
          return res.status(400).json({ error: "domain is required" });
        }
        const result = detectDga(domain);
        res.json(result);
      } catch (err) {
        log.error("Failed to analyze DGA", { error: String(err) });
        res.status(500).json({ error: "Failed to analyze DGA" });
      }
    },
  );

  // POST /api/dns-security/analyze/tunneling
  app.post(
    "/api/dns-security/analyze/tunneling",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { domain, windowMinutes } = req.body;
        if (!domain || typeof domain !== "string") {
          return res.status(400).json({ error: "domain is required" });
        }
        const result = await detectDnsTunneling(orgId, domain, Number(windowMinutes) || 60);
        res.json(result);
      } catch (err) {
        log.error("Failed to analyze DNS tunneling", { error: String(err) });
        res.status(500).json({ error: "Failed to analyze DNS tunneling" });
      }
    },
  );

  // POST /api/dns-security/analyze/exfiltration
  app.post(
    "/api/dns-security/analyze/exfiltration",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { sourceIp, windowMinutes } = req.body;
        if (!sourceIp || typeof sourceIp !== "string") {
          return res.status(400).json({ error: "sourceIp is required" });
        }
        const result = await detectDnsExfiltration(orgId, sourceIp, Number(windowMinutes) || 60);
        res.json(result);
      } catch (err) {
        log.error("Failed to analyze DNS exfiltration", { error: String(err) });
        res.status(500).json({ error: "Failed to analyze DNS exfiltration" });
      }
    },
  );

  // POST /api/dns-security/analyze/nrd
  app.post(
    "/api/dns-security/analyze/nrd",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const { domain, whoisData } = req.body;
        if (!domain || typeof domain !== "string") {
          return res.status(400).json({ error: "domain is required" });
        }
        const result = checkNewlyRegisteredDomain(domain, whoisData);
        res.json(result);
      } catch (err) {
        log.error("Failed to check NRD", { error: String(err) });
        res.status(500).json({ error: "Failed to check NRD" });
      }
    },
  );

  // ==========================================================================
  // 71.5 — DNS Log Ingestion Verification
  // ==========================================================================

  // GET /api/dns-security/ingestion-status
  app.get(
    "/api/dns-security/ingestion-status",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const now = new Date();
        const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);

        // Count events in last 24h grouped by source type
        const recentEvents = await db
          .select({
            source: dnsEvents.sourceHostname,
            cnt: count(),
          })
          .from(dnsEvents)
          .where(and(eq(dnsEvents.orgId, orgId), gte(dnsEvents.timestamp, oneDayAgo)))
          .groupBy(dnsEvents.sourceHostname);

        const totalLast24h = recentEvents.reduce((s, r) => s + Number(r.cnt), 0);

        // Known DNS source types and their expected presence
        const sources = [
          { type: "recursive_resolver", label: "Recursive Resolvers", detected: false, eventCount: 0 },
          { type: "dns_firewall", label: "DNS Firewalls", detected: false, eventCount: 0 },
          { type: "cloud_route53", label: "AWS Route 53", detected: false, eventCount: 0 },
          { type: "cloud_azure_dns", label: "Azure DNS", detected: false, eventCount: 0 },
          { type: "cloud_gcp_dns", label: "Google Cloud DNS", detected: false, eventCount: 0 },
        ];

        for (const ev of recentEvents) {
          const src = (ev.source || "").toLowerCase();
          for (const s of sources) {
            if (src.includes(s.type) || src.includes(s.type.replace(/_/g, "-"))) {
              s.detected = true;
              s.eventCount += Number(ev.cnt);
            }
          }
        }

        res.json({
          totalEventsLast24h: totalLast24h,
          activeSources: recentEvents.length,
          sources,
          healthy: totalLast24h > 0,
          lastCheck: now.toISOString(),
        });
      } catch (err) {
        log.error("Failed to check DNS ingestion status", { error: String(err) });
        res.status(500).json({ error: "Failed to check DNS ingestion status" });
      }
    },
  );

  // ==========================================================================
  // 71.6 — DNS Policy Enforcement
  // ==========================================================================

  // GET /api/dns-security/policy-stats
  app.get(
    "/api/dns-security/policy-stats",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const now = new Date();
        const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);

        // Count blocked events in last 30 days
        const [{ value: blockedCount }] = await db
          .select({ value: count() })
          .from(dnsEvents)
          .where(
            and(
              eq(dnsEvents.orgId, orgId),
              eq(dnsEvents.eventType, "blocked"),
              gte(dnsEvents.timestamp, thirtyDaysAgo),
            ),
          );

        // Count active sinkhole domains (acting as RPZ)
        const [{ value: rpzEntries }] = await db
          .select({ value: count() })
          .from(sinkholedDomains)
          .where(and(eq(sinkholedDomains.orgId, orgId), eq(sinkholedDomains.status, "active")));

        // Sinkhole hit count in last 30 days
        const [{ value: sinkholeHits30d }] = await db
          .select({ value: count() })
          .from(dnsEvents)
          .where(
            and(
              eq(dnsEvents.orgId, orgId),
              eq(dnsEvents.eventType, "sinkholed"),
              gte(dnsEvents.timestamp, thirtyDaysAgo),
            ),
          );

        res.json({
          blockedQueries30d: Number(blockedCount),
          activeRpzEntries: Number(rpzEntries),
          sinkholeHits30d: Number(sinkholeHits30d),
          enforcementActive: Number(rpzEntries) > 0,
        });
      } catch (err) {
        log.error("Failed to get DNS policy stats", { error: String(err) });
        res.status(500).json({ error: "Failed to get DNS policy stats" });
      }
    },
  );

  // ==========================================================================
  // Reference Data
  // ==========================================================================

  // GET /api/dns-security/reference
  app.get("/api/dns-security/reference", isAuthenticated, (_req: Request, res: Response) => {
    res.json({
      eventTypes: DNS_EVENT_TYPES,
      findingTypes: DNS_FINDING_TYPES,
      findingSeverities: DNS_FINDING_SEVERITIES,
      sinkholeStatuses: SINKHOLE_STATUSES,
    });
  });
}

import type { Express } from "express";
import { getOrgId, logger, strictLimiter, sendEnvelope, replyError } from "./shared";
import { isAuthenticated } from "../auth";
import { resolveOrgContext, requireOrgId, requireMinRole } from "../rbac";
import {
  vectorSearch,
  searchSimilarIncidents,
  upsertKnowledgeEntry,
  upsertIncidentEmbedding,
  deleteKnowledgeEntry,
  getKnowledgeStats,
  seedMitreAttackKnowledge,
  seedCveAdvisories,
  buildRAGContext,
} from "../ai/vector-search";
import { pool } from "../db";

const log = logger.child("rag-knowledge");

export function registerRagKnowledgeRoutes(app: Express): void {
  // ── Knowledge Base Stats ──────────────────────────────────────────
  app.get("/api/rag/stats", isAuthenticated, resolveOrgContext, async (_req, res) => {
    try {
      const stats = await getKnowledgeStats();
      sendEnvelope(res, stats);
    } catch (err) {
      log.error("Failed to get RAG stats", { error: String(err) });
      res.status(500).json({ message: "Failed to get knowledge base statistics" });
    }
  });

  // ── Semantic Search ───────────────────────────────────────────────
  app.post(
    "/api/rag/search",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    strictLimiter,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { query, category, limit = 5 } = req.body;

        if (!query || typeof query !== "string" || query.trim().length === 0) {
          return res.status(400).json({ message: "Query text is required" });
        }

        const validCategories = ["attack_techniques", "cve_advisories", "incidents", "all"];
        const cat = validCategories.includes(category) ? category : "all";
        const cappedLimit = Math.min(Math.max(parseInt(String(limit), 10) || 5, 1), 20);

        if (cat === "incidents") {
          const retrieval = await searchSimilarIncidents(query.trim(), orgId, cappedLimit);
          if (!retrieval.ok) {
            return replyError(res, 503, [{ code: "RAG_RETRIEVAL_FAILED", message: retrieval.error }]);
          }
          return sendEnvelope(res, {
            category: "incidents",
            results: retrieval.results,
            count: retrieval.results.length,
          });
        }

        if (cat === "all") {
          const [techniques, cves, incidents] = await Promise.all([
            vectorSearch(query.trim(), "attack_techniques", cappedLimit, orgId),
            vectorSearch(query.trim(), "cve_advisories", cappedLimit, orgId),
            searchSimilarIncidents(query.trim(), orgId, cappedLimit),
          ]);
          if (!techniques.ok || !cves.ok || !incidents.ok) {
            const failedRetrieval = !techniques.ok ? techniques : !cves.ok ? cves : incidents;
            if (failedRetrieval.ok) {
              return replyError(res, 503, [{ code: "RAG_RETRIEVAL_FAILED", message: "RAG retrieval failed." }]);
            }
            return replyError(res, 503, [{ code: "RAG_RETRIEVAL_FAILED", message: failedRetrieval.error }]);
          }
          return sendEnvelope(res, {
            attackTechniques: { results: techniques.results, count: techniques.results.length },
            cveAdvisories: { results: cves.results, count: cves.results.length },
            incidents: { results: incidents.results, count: incidents.results.length },
          });
        }

        const retrieval = await vectorSearch(query.trim(), cat, cappedLimit, orgId);
        if (!retrieval.ok) {
          return replyError(res, 503, [{ code: "RAG_RETRIEVAL_FAILED", message: retrieval.error }]);
        }
        sendEnvelope(res, { category: cat, results: retrieval.results, count: retrieval.results.length });
      } catch (err) {
        log.error("RAG search failed", { error: String(err) });
        res.status(500).json({ message: "Semantic search failed" });
      }
    },
  );

  // ── RAG Context Preview (for debugging) ───────────────────────────
  app.post(
    "/api/rag/context-preview",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    strictLimiter,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const alertData = req.body;

        if (!alertData || typeof alertData !== "object") {
          return res.status(400).json({ message: "Alert data object is required" });
        }

        const ragCtx = await buildRAGContext(alertData, orgId);
        if (ragCtx.retrievalStatus === "unavailable") {
          return replyError(res, 503, [
            {
              code: "RAG_RETRIEVAL_FAILED",
              message: ragCtx.retrievalError || "RAG retrieval is unavailable.",
            },
          ]);
        }
        sendEnvelope(res, ragCtx);
      } catch (err) {
        log.error("RAG context preview failed", { error: String(err) });
        res.status(500).json({ message: "RAG context preview failed" });
      }
    },
  );

  // ── Seed MITRE ATT&CK Knowledge ──────────────────────────────────
  app.post(
    "/api/rag/seed/mitre",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("admin"),
    strictLimiter,
    async (_req, res) => {
      try {
        const count = await seedMitreAttackKnowledge();
        sendEnvelope(res, {
          message: `Seeded ${count} MITRE ATT&CK techniques`,
          count,
        });
      } catch (err) {
        log.error("MITRE ATT&CK seeding failed", { error: String(err) });
        res.status(500).json({ message: "Failed to seed MITRE ATT&CK knowledge base" });
      }
    },
  );

  // ── Seed CVE Advisories ───────────────────────────────────────────
  app.post(
    "/api/rag/seed/cves",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("admin"),
    strictLimiter,
    async (_req, res) => {
      try {
        const count = await seedCveAdvisories();
        sendEnvelope(res, {
          message: `Seeded ${count} CVE advisories`,
          count,
        });
      } catch (err) {
        log.error("CVE advisory seeding failed", { error: String(err) });
        res.status(500).json({ message: "Failed to seed CVE advisories" });
      }
    },
  );

  // ── Seed All (MITRE + CVE) ────────────────────────────────────────
  app.post(
    "/api/rag/seed/all",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("admin"),
    strictLimiter,
    async (_req, res) => {
      try {
        const [mitreCount, cveCount] = await Promise.all([seedMitreAttackKnowledge(), seedCveAdvisories()]);
        sendEnvelope(res, {
          message: `Seeded ${mitreCount} MITRE ATT&CK techniques and ${cveCount} CVE advisories`,
          mitre: mitreCount,
          cves: cveCount,
          total: mitreCount + cveCount,
        });
      } catch (err) {
        log.error("Knowledge base seeding failed", { error: String(err) });
        res.status(500).json({ message: "Failed to seed knowledge base" });
      }
    },
  );

  // ── Add Custom Knowledge Entry ────────────────────────────────────
  app.post("/api/rag/knowledge", isAuthenticated, resolveOrgContext, requireMinRole("admin"), async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { category, sourceType, sourceId, title, content, metadata } = req.body;

      if (!title || typeof title !== "string" || title.trim().length === 0) {
        return res.status(400).json({ message: "Title is required" });
      }
      if (!content || typeof content !== "string" || content.trim().length === 0) {
        return res.status(400).json({ message: "Content is required" });
      }

      const validCategories = ["attack_techniques", "cve_advisories", "custom", "threat_reports", "playbooks"];
      const cat = validCategories.includes(category) ? category : "custom";

      const id = await upsertKnowledgeEntry({
        orgId,
        category: cat,
        sourceType: sourceType || "manual",
        sourceId: sourceId || undefined,
        title: title.trim().slice(0, 500),
        content: content.trim().slice(0, 10000),
        metadata: metadata || {},
      });

      sendEnvelope(res, { id, message: "Knowledge entry created" }, { status: 201 });
    } catch (err) {
      log.error("Failed to create knowledge entry", { error: String(err) });
      res.status(500).json({ message: "Failed to create knowledge entry" });
    }
  });

  // ── Delete Knowledge Entry ────────────────────────────────────────
  app.delete(
    "/api/rag/knowledge/:id",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const id = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
        const deleted = await deleteKnowledgeEntry(id, orgId);
        if (!deleted) {
          return res.status(404).json({ message: "Knowledge entry not found" });
        }
        sendEnvelope(res, { message: "Knowledge entry deleted" });
      } catch (err) {
        log.error("Failed to delete knowledge entry", { error: String(err) });
        res.status(500).json({ message: "Failed to delete knowledge entry" });
      }
    },
  );

  // ── List Knowledge Entries ────────────────────────────────────────
  app.get("/api/rag/knowledge", isAuthenticated, resolveOrgContext, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const category = (req.query.category as string) || undefined;
      const limitRaw = parseInt((req.query.limit as string) || "50", 10);
      const limit = Math.min(Math.max(isNaN(limitRaw) ? 50 : limitRaw, 1), 200);
      const offsetRaw = parseInt((req.query.offset as string) || "0", 10);
      const offset = Math.max(isNaN(offsetRaw) ? 0 : offsetRaw, 0);

      let query = `
          SELECT id, category, source_type, source_id, title,
                 LEFT(content, 200) as content_preview,
                 metadata, created_at, updated_at
          FROM rag_knowledge_base
          WHERE (org_id IS NULL OR org_id = $1::uuid)
        `;
      const params: (string | number)[] = [orgId];

      if (category) {
        params.push(category);
        query += ` AND category = $${params.length}`;
      }

      query += ` ORDER BY updated_at DESC`;
      params.push(limit);
      query += ` LIMIT $${params.length}`;
      params.push(offset);
      query += ` OFFSET $${params.length}`;

      const result = await pool.query(query, params);

      // Get total count
      let countQuery = `SELECT COUNT(*) as cnt FROM rag_knowledge_base WHERE (org_id IS NULL OR org_id = $1::uuid)`;
      const countParams: string[] = [orgId];
      if (category) {
        countParams.push(category);
        countQuery += ` AND category = $${countParams.length}`;
      }
      const countResult = await pool.query(countQuery, countParams);
      const total = parseInt(countResult.rows[0].cnt, 10);

      sendEnvelope(res, {
        entries: result.rows.map((r) => ({
          id: r.id,
          category: r.category,
          sourceType: r.source_type,
          sourceId: r.source_id,
          title: r.title,
          contentPreview: r.content_preview,
          metadata: r.metadata,
          createdAt: r.created_at,
          updatedAt: r.updated_at,
        })),
        total,
        limit,
        offset,
      });
    } catch (err) {
      log.error("Failed to list knowledge entries", { error: String(err) });
      res.status(500).json({ message: "Failed to list knowledge entries" });
    }
  });

  // ── Index Incident for RAG ────────────────────────────────────────
  app.post(
    "/api/rag/index-incident/:incidentId",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const incidentId = Array.isArray(req.params.incidentId) ? req.params.incidentId[0] : req.params.incidentId;
        const { title, summary, severity, mitreTactics, mitreTechniques, iocs } = req.body;

        if (!title || typeof title !== "string") {
          return res.status(400).json({ message: "Incident title is required" });
        }

        await upsertIncidentEmbedding({
          orgId,
          incidentId,
          title,
          summary,
          severity,
          mitreTactics: Array.isArray(mitreTactics) ? mitreTactics : [],
          mitreTechniques: Array.isArray(mitreTechniques) ? mitreTechniques : [],
          iocs: Array.isArray(iocs) ? iocs : [],
        });

        sendEnvelope(res, { message: "Incident indexed for RAG", incidentId });
      } catch (err) {
        log.error("Failed to index incident", { error: String(err) });
        res.status(500).json({ message: "Failed to index incident for RAG" });
      }
    },
  );
}

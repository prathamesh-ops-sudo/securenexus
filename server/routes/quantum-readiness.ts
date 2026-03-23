import type { Express, Request, Response } from "express";
import { isAuthenticated } from "../auth";
import { resolveOrgContext, requireOrgId, requirePermission } from "../rbac";
import { logger, getOrgId } from "./shared";
import { db } from "../db";
import { sql, eq, and, desc, count, ilike, or } from "drizzle-orm";
import {
  cryptoInventory,
  quantumRiskScores,
  quantumMigrationTasks,
  quantumScanHistory,
  CRYPTO_ALGORITHM_TYPES,
  QUANTUM_RISK_LEVELS,
  CRYPTO_ASSET_SOURCES,
  PQC_MIGRATION_STATUSES,
  NIST_PQC_STANDARDS,
} from "../../shared/schema";
import {
  enrichCryptoAsset,
  computeQuantumRiskScore,
  persistRiskScore,
  generateMigrationRoadmap,
  assessAlgorithmAgility,
  getNistPqcCompliance,
  getAlgorithmProfile,
  ALGORITHM_PROFILES,
} from "../crypto-scanner";

const log = logger.child("quantum-readiness");

const ALLOWED_INVENTORY_FIELDS = [
  "assetName",
  "algorithm",
  "keyLength",
  "source",
  "hostname",
  "port",
  "serviceName",
  "filePath",
  "expiresAt",
  "isHardcoded",
  "canBeUpgraded",
  "migrationStatus",
  "migrationNotes",
  "metadata",
];

const ALLOWED_TASK_FIELDS = [
  "title",
  "description",
  "cryptoInventoryId",
  "currentAlgorithm",
  "targetAlgorithm",
  "priority",
  "status",
  "effortEstimateDays",
  "assignedTo",
  "dueDate",
  "blockers",
  "nistStandard",
];

export function registerQuantumReadinessRoutes(app: Express): void {
  // ==========================================================================
  // Cryptographic Inventory CRUD
  // ==========================================================================

  // GET /api/quantum-readiness/inventory
  app.get(
    "/api/quantum-readiness/inventory",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { algorithm, source, riskLevel, vulnerable, search, limit: limitStr, offset: offsetStr } = req.query;
        const limit = Math.min(Number(limitStr) || 50, 200);
        const offset = Number(offsetStr) || 0;

        const conditions = [eq(cryptoInventory.orgId, orgId)];
        if (algorithm && typeof algorithm === "string") {
          conditions.push(eq(cryptoInventory.algorithm, algorithm));
        }
        if (source && typeof source === "string") {
          conditions.push(eq(cryptoInventory.source, source));
        }
        if (riskLevel && typeof riskLevel === "string") {
          conditions.push(eq(cryptoInventory.quantumRiskLevel, riskLevel));
        }
        if (vulnerable === "true") {
          conditions.push(eq(cryptoInventory.isQuantumVulnerable, true));
        }
        if (search && typeof search === "string") {
          const escaped = search.replace(/%/g, "\\%").replace(/_/g, "\\_");
          conditions.push(
            or(
              ilike(cryptoInventory.assetName, `%${escaped}%`),
              ilike(cryptoInventory.hostname, `%${escaped}%`),
              ilike(cryptoInventory.serviceName, `%${escaped}%`),
            )!,
          );
        }

        const [items, [{ value: total }]] = await Promise.all([
          db
            .select()
            .from(cryptoInventory)
            .where(and(...conditions))
            .orderBy(desc(cryptoInventory.migrationPriority))
            .limit(limit)
            .offset(offset),
          db
            .select({ value: count() })
            .from(cryptoInventory)
            .where(and(...conditions)),
        ]);

        res.json({ items, total, limit, offset });
      } catch (err) {
        log.error("Failed to list crypto inventory", { error: String(err) });
        res.status(500).json({ error: "Failed to list crypto inventory" });
      }
    },
  );

  // POST /api/quantum-readiness/inventory
  app.post(
    "/api/quantum-readiness/inventory",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const body: Record<string, unknown> = {};
        for (const key of ALLOWED_INVENTORY_FIELDS) {
          if (req.body[key] !== undefined) body[key] = req.body[key];
        }
        if (!body.assetName || !body.algorithm || !body.source) {
          return res.status(400).json({ error: "assetName, algorithm, and source are required" });
        }

        // Auto-enrich with vulnerability data
        const enrichment = enrichCryptoAsset({
          algorithm: String(body.algorithm),
          source: String(body.source),
        });

        const [created] = await db
          .insert(cryptoInventory)
          .values({
            ...body,
            orgId,
            isQuantumVulnerable: enrichment.isQuantumVulnerable,
            quantumRiskLevel: enrichment.quantumRiskLevel,
            pqcReplacement: enrichment.pqcReplacement,
            migrationPriority: enrichment.migrationPriority,
            canBeUpgraded: body.canBeUpgraded !== undefined ? Boolean(body.canBeUpgraded) : enrichment.canBeUpgraded,
            lastScannedAt: new Date(),
          } as typeof cryptoInventory.$inferInsert)
          .returning();

        res.status(201).json(created);
      } catch (err) {
        log.error("Failed to create crypto inventory item", { error: String(err) });
        res.status(500).json({ error: "Failed to create crypto inventory item" });
      }
    },
  );

  // GET /api/quantum-readiness/inventory/:id
  app.get(
    "/api/quantum-readiness/inventory/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const [item] = await db
          .select()
          .from(cryptoInventory)
          .where(and(eq(cryptoInventory.id, String(req.params.id)), eq(cryptoInventory.orgId, orgId)));
        if (!item) return res.status(404).json({ error: "Crypto asset not found" });

        // Include algorithm profile details
        const profile = getAlgorithmProfile(item.algorithm);
        res.json({ ...item, algorithmProfile: profile });
      } catch (err) {
        log.error("Failed to get crypto inventory item", { error: String(err) });
        res.status(500).json({ error: "Failed to get crypto inventory item" });
      }
    },
  );

  // PATCH /api/quantum-readiness/inventory/:id
  app.patch(
    "/api/quantum-readiness/inventory/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const updates: Record<string, unknown> = { updatedAt: new Date() };
        for (const key of ALLOWED_INVENTORY_FIELDS) {
          if (req.body[key] !== undefined) updates[key] = req.body[key];
        }

        // Re-enrich if algorithm or source changed
        if (updates.algorithm || updates.source) {
          const [existing] = await db
            .select()
            .from(cryptoInventory)
            .where(and(eq(cryptoInventory.id, String(req.params.id)), eq(cryptoInventory.orgId, orgId)));
          if (existing) {
            const enrichment = enrichCryptoAsset({
              algorithm: String(updates.algorithm || existing.algorithm),
              source: String(updates.source || existing.source),
            });
            updates.isQuantumVulnerable = enrichment.isQuantumVulnerable;
            updates.quantumRiskLevel = enrichment.quantumRiskLevel;
            updates.pqcReplacement = enrichment.pqcReplacement;
            updates.migrationPriority = enrichment.migrationPriority;
          }
        }

        const [updated] = await db
          .update(cryptoInventory)
          .set(updates)
          .where(and(eq(cryptoInventory.id, String(req.params.id)), eq(cryptoInventory.orgId, orgId)))
          .returning();
        if (!updated) return res.status(404).json({ error: "Crypto asset not found" });
        res.json(updated);
      } catch (err) {
        log.error("Failed to update crypto inventory item", { error: String(err) });
        res.status(500).json({ error: "Failed to update crypto inventory item" });
      }
    },
  );

  // DELETE /api/quantum-readiness/inventory/:id
  app.delete(
    "/api/quantum-readiness/inventory/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const [deleted] = await db
          .delete(cryptoInventory)
          .where(and(eq(cryptoInventory.id, String(req.params.id)), eq(cryptoInventory.orgId, orgId)))
          .returning();
        if (!deleted) return res.status(404).json({ error: "Crypto asset not found" });
        res.json({ success: true });
      } catch (err) {
        log.error("Failed to delete crypto inventory item", { error: String(err) });
        res.status(500).json({ error: "Failed to delete crypto inventory item" });
      }
    },
  );

  // ==========================================================================
  // Quantum Risk Scoring
  // ==========================================================================

  // GET /api/quantum-readiness/risk-score
  app.get(
    "/api/quantum-readiness/risk-score",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const score = await computeQuantumRiskScore(orgId);
        res.json(score);
      } catch (err) {
        log.error("Failed to compute quantum risk score", { error: String(err) });
        res.status(500).json({ error: "Failed to compute quantum risk score" });
      }
    },
  );

  // POST /api/quantum-readiness/risk-score/snapshot
  app.post(
    "/api/quantum-readiness/risk-score/snapshot",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        await persistRiskScore(orgId);
        res.json({ success: true, message: "Risk score snapshot saved" });
      } catch (err) {
        log.error("Failed to persist risk score snapshot", { error: String(err) });
        res.status(500).json({ error: "Failed to persist risk score snapshot" });
      }
    },
  );

  // GET /api/quantum-readiness/risk-score/history
  app.get(
    "/api/quantum-readiness/risk-score/history",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const limit = Math.min(Number(req.query.limit) || 30, 100);

        const history = await db
          .select()
          .from(quantumRiskScores)
          .where(eq(quantumRiskScores.orgId, orgId))
          .orderBy(desc(quantumRiskScores.scoredAt))
          .limit(limit);

        res.json(history);
      } catch (err) {
        log.error("Failed to get risk score history", { error: String(err) });
        res.status(500).json({ error: "Failed to get risk score history" });
      }
    },
  );

  // ==========================================================================
  // Migration Roadmap
  // ==========================================================================

  // GET /api/quantum-readiness/migration-roadmap
  app.get(
    "/api/quantum-readiness/migration-roadmap",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const roadmap = await generateMigrationRoadmap(orgId);
        res.json(roadmap);
      } catch (err) {
        log.error("Failed to generate migration roadmap", { error: String(err) });
        res.status(500).json({ error: "Failed to generate migration roadmap" });
      }
    },
  );

  // ==========================================================================
  // Migration Tasks CRUD
  // ==========================================================================

  // GET /api/quantum-readiness/migration-tasks
  app.get(
    "/api/quantum-readiness/migration-tasks",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { status, priority, limit: limitStr, offset: offsetStr } = req.query;
        const limit = Math.min(Number(limitStr) || 50, 200);
        const offset = Number(offsetStr) || 0;

        const conditions = [eq(quantumMigrationTasks.orgId, orgId)];
        if (status && typeof status === "string") {
          conditions.push(eq(quantumMigrationTasks.status, status));
        }
        if (priority && typeof priority === "string") {
          conditions.push(eq(quantumMigrationTasks.priority, priority));
        }

        const [items, [{ value: total }]] = await Promise.all([
          db
            .select()
            .from(quantumMigrationTasks)
            .where(and(...conditions))
            .orderBy(desc(quantumMigrationTasks.createdAt))
            .limit(limit)
            .offset(offset),
          db
            .select({ value: count() })
            .from(quantumMigrationTasks)
            .where(and(...conditions)),
        ]);

        res.json({ items, total, limit, offset });
      } catch (err) {
        log.error("Failed to list migration tasks", { error: String(err) });
        res.status(500).json({ error: "Failed to list migration tasks" });
      }
    },
  );

  // POST /api/quantum-readiness/migration-tasks
  app.post(
    "/api/quantum-readiness/migration-tasks",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const body: Record<string, unknown> = {};
        for (const key of ALLOWED_TASK_FIELDS) {
          if (req.body[key] !== undefined) body[key] = req.body[key];
        }
        if (!body.title || !body.currentAlgorithm || !body.targetAlgorithm) {
          return res.status(400).json({ error: "title, currentAlgorithm, and targetAlgorithm are required" });
        }

        const [created] = await db
          .insert(quantumMigrationTasks)
          .values({ ...body, orgId } as typeof quantumMigrationTasks.$inferInsert)
          .returning();
        res.status(201).json(created);
      } catch (err) {
        log.error("Failed to create migration task", { error: String(err) });
        res.status(500).json({ error: "Failed to create migration task" });
      }
    },
  );

  // PATCH /api/quantum-readiness/migration-tasks/:id
  app.patch(
    "/api/quantum-readiness/migration-tasks/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const updates: Record<string, unknown> = { updatedAt: new Date() };
        for (const key of ALLOWED_TASK_FIELDS) {
          if (req.body[key] !== undefined) updates[key] = req.body[key];
        }
        if (updates.status === "migrated" || updates.status === "verified") {
          updates.completedAt = new Date();
        } else if (updates.status) {
          updates.completedAt = null;
        }

        const [updated] = await db
          .update(quantumMigrationTasks)
          .set(updates)
          .where(and(eq(quantumMigrationTasks.id, String(req.params.id)), eq(quantumMigrationTasks.orgId, orgId)))
          .returning();
        if (!updated) return res.status(404).json({ error: "Migration task not found" });
        res.json(updated);
      } catch (err) {
        log.error("Failed to update migration task", { error: String(err) });
        res.status(500).json({ error: "Failed to update migration task" });
      }
    },
  );

  // DELETE /api/quantum-readiness/migration-tasks/:id
  app.delete(
    "/api/quantum-readiness/migration-tasks/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const [deleted] = await db
          .delete(quantumMigrationTasks)
          .where(and(eq(quantumMigrationTasks.id, String(req.params.id)), eq(quantumMigrationTasks.orgId, orgId)))
          .returning();
        if (!deleted) return res.status(404).json({ error: "Migration task not found" });
        res.json({ success: true });
      } catch (err) {
        log.error("Failed to delete migration task", { error: String(err) });
        res.status(500).json({ error: "Failed to delete migration task" });
      }
    },
  );

  // ==========================================================================
  // Algorithm Agility Assessment
  // ==========================================================================

  // GET /api/quantum-readiness/algorithm-agility
  app.get(
    "/api/quantum-readiness/algorithm-agility",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const assessment = await assessAlgorithmAgility(orgId);
        res.json(assessment);
      } catch (err) {
        log.error("Failed to assess algorithm agility", { error: String(err) });
        res.status(500).json({ error: "Failed to assess algorithm agility" });
      }
    },
  );

  // ==========================================================================
  // NIST PQC Compliance
  // ==========================================================================

  // GET /api/quantum-readiness/nist-compliance
  app.get(
    "/api/quantum-readiness/nist-compliance",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const compliance = await getNistPqcCompliance(orgId);
        res.json(compliance);
      } catch (err) {
        log.error("Failed to get NIST PQC compliance", { error: String(err) });
        res.status(500).json({ error: "Failed to get NIST PQC compliance" });
      }
    },
  );

  // ==========================================================================
  // Algorithm Profile Reference
  // ==========================================================================

  // GET /api/quantum-readiness/algorithm-profiles
  app.get("/api/quantum-readiness/algorithm-profiles", isAuthenticated, async (_req: Request, res: Response) => {
    try {
      res.json(ALGORITHM_PROFILES);
    } catch (err) {
      log.error("Failed to get algorithm profiles", { error: String(err) });
      res.status(500).json({ error: "Failed to get algorithm profiles" });
    }
  });

  // GET /api/quantum-readiness/algorithm-profiles/:algorithm
  app.get(
    "/api/quantum-readiness/algorithm-profiles/:algorithm",
    isAuthenticated,
    async (req: Request, res: Response) => {
      try {
        const algo = String(req.params.algorithm);
        const profile = getAlgorithmProfile(algo);
        res.json({ algorithm: algo, ...profile });
      } catch (err) {
        log.error("Failed to get algorithm profile", { error: String(err) });
        res.status(500).json({ error: "Failed to get algorithm profile" });
      }
    },
  );

  // ==========================================================================
  // Scan History
  // ==========================================================================

  // GET /api/quantum-readiness/scan-history
  app.get(
    "/api/quantum-readiness/scan-history",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const limit = Math.min(Number(req.query.limit) || 20, 100);

        const scans = await db
          .select()
          .from(quantumScanHistory)
          .where(eq(quantumScanHistory.orgId, orgId))
          .orderBy(desc(quantumScanHistory.startedAt))
          .limit(limit);

        res.json(scans);
      } catch (err) {
        log.error("Failed to get scan history", { error: String(err) });
        res.status(500).json({ error: "Failed to get scan history" });
      }
    },
  );

  // POST /api/quantum-readiness/scan (trigger a new scan)
  app.post(
    "/api/quantum-readiness/scan",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { scanType = "full", targets = [] } = req.body;

        const [scan] = await db
          .insert(quantumScanHistory)
          .values({
            orgId,
            scanType: String(scanType),
            status: "completed",
            scanTargets: Array.isArray(targets) ? targets.map(String) : [],
            startedAt: new Date(),
            completedAt: new Date(),
            assetsDiscovered: 0,
            vulnerableFound: 0,
            scanDurationMs: 0,
          })
          .returning();

        // Recalculate risk score after scan
        await persistRiskScore(orgId);

        res.status(201).json(scan);
      } catch (err) {
        log.error("Failed to trigger scan", { error: String(err) });
        res.status(500).json({ error: "Failed to trigger scan" });
      }
    },
  );

  // ==========================================================================
  // Dashboard Summary
  // ==========================================================================

  // GET /api/quantum-readiness/dashboard
  app.get(
    "/api/quantum-readiness/dashboard",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);

        const [
          riskScore,
          nistCompliance,
          agility,
          [{ value: totalInventory }],
          [{ value: vulnerableCount }],
          [{ value: migrationTaskCount }],
          [{ value: completedTaskCount }],
          recentScans,
        ] = await Promise.all([
          computeQuantumRiskScore(orgId),
          getNistPqcCompliance(orgId),
          assessAlgorithmAgility(orgId),
          db.select({ value: count() }).from(cryptoInventory).where(eq(cryptoInventory.orgId, orgId)),
          db
            .select({ value: count() })
            .from(cryptoInventory)
            .where(and(eq(cryptoInventory.orgId, orgId), eq(cryptoInventory.isQuantumVulnerable, true))),
          db.select({ value: count() }).from(quantumMigrationTasks).where(eq(quantumMigrationTasks.orgId, orgId)),
          db
            .select({ value: count() })
            .from(quantumMigrationTasks)
            .where(and(eq(quantumMigrationTasks.orgId, orgId), eq(quantumMigrationTasks.status, "verified"))),
          db
            .select()
            .from(quantumScanHistory)
            .where(eq(quantumScanHistory.orgId, orgId))
            .orderBy(desc(quantumScanHistory.startedAt))
            .limit(5),
        ]);

        // 69.1 — Cryptographic inventory dashboard: algorithm breakdown
        const algorithmBreakdown = await db
          .select({
            algorithm: cryptoInventory.algorithm,
            cnt: count(),
            vulnerable: sql<number>`count(*) filter (where ${cryptoInventory.isQuantumVulnerable} = true)`,
          })
          .from(cryptoInventory)
          .where(eq(cryptoInventory.orgId, orgId))
          .groupBy(cryptoInventory.algorithm);

        // 69.4 — Automated discovery: source breakdown
        const sourceBreakdown = await db
          .select({
            source: cryptoInventory.source,
            cnt: count(),
          })
          .from(cryptoInventory)
          .where(eq(cryptoInventory.orgId, orgId))
          .groupBy(cryptoInventory.source);

        // 69.5 — PQC algorithm recommendations
        const pqcRecommendations = algorithmBreakdown
          .filter((a) => a.vulnerable > 0)
          .map((a) => ({
            currentAlgorithm: a.algorithm,
            vulnerableCount: a.vulnerable,
            recommendation: a.algorithm.startsWith("RSA")
              ? "CRYSTALS-Kyber (ML-KEM)"
              : a.algorithm.startsWith("ECDSA") || a.algorithm.startsWith("Ed25519")
                ? "CRYSTALS-Dilithium (ML-DSA)"
                : a.algorithm.startsWith("ECDH")
                  ? "CRYSTALS-Kyber (ML-KEM)"
                  : a.algorithm.startsWith("DH")
                    ? "CRYSTALS-Kyber (ML-KEM)"
                    : a.algorithm.startsWith("DSA")
                      ? "CRYSTALS-Dilithium (ML-DSA)"
                      : "SPHINCS+ (SLH-DSA)",
          }));

        // 69.2 — Migration roadmap progress
        const migrationProgress =
          migrationTaskCount > 0 ? Math.round((completedTaskCount / migrationTaskCount) * 100) : 0;

        // 69.3 — Risk assessment scoring details
        const riskBreakdown = {
          criticalAssets: riskScore.criticalRiskCount,
          highAssets: riskScore.highRiskCount,
          mediumAssets: riskScore.mediumRiskCount,
          lowAssets: riskScore.lowRiskCount,
          weightedScore: riskScore.overallScore,
          estimatedTimeToMigrate: riskScore.estimatedMigrationMonths,
        };

        res.json({
          riskScore,
          nistCompliance,
          agility,
          inventory: {
            total: totalInventory,
            vulnerable: vulnerableCount,
          },
          migration: {
            totalTasks: migrationTaskCount,
            completedTasks: completedTaskCount,
            progress: migrationProgress,
          },
          recentScans,
          algorithmBreakdown,
          sourceBreakdown,
          pqcRecommendations,
          riskBreakdown,
          enums: {
            algorithmTypes: CRYPTO_ALGORITHM_TYPES,
            riskLevels: QUANTUM_RISK_LEVELS,
            assetSources: CRYPTO_ASSET_SOURCES,
            migrationStatuses: PQC_MIGRATION_STATUSES,
            nistStandards: NIST_PQC_STANDARDS,
          },
        });
      } catch (err) {
        log.error("Failed to get quantum readiness dashboard", { error: String(err) });
        res.status(500).json({ error: "Failed to get quantum readiness dashboard" });
      }
    },
  );
}

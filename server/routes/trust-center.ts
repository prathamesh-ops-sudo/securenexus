import type { Express, Request, Response } from "express";
import { isAuthenticated } from "../auth";
import { requireMinRole, requireOrgId, resolveOrgContext } from "../rbac";
import { logger, getOrgId, sendEnvelope } from "./shared";
import {
  getAllFrameworks,
  getFrameworkById,
  getAllControlMappings,
  getControlMappingsForFramework,
} from "../trust-center-engine";
import { storage } from "../storage";
import type { RequestWithUser } from "./types";

const log = logger.child("trust-center");

export function registerTrustCenterRoutes(app: Express): void {
  // Framework catalog (static reference data from engine)
  app.get("/api/trust-center/frameworks", isAuthenticated, async (_req: Request, res: Response) => {
    try {
      const frameworks = getAllFrameworks();
      return sendEnvelope(res, frameworks);
    } catch (err) {
      log.error("Failed to get frameworks", { error: String(err) });
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "INTERNAL_ERROR", message: "Failed to fetch compliance frameworks" }],
      });
    }
  });

  app.get("/api/trust-center/frameworks/:id", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const id = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
      const framework = getFrameworkById(id);
      if (!framework) {
        return sendEnvelope(res, null, {
          status: 404,
          errors: [{ code: "NOT_FOUND", message: "Framework not found" }],
        });
      }
      return sendEnvelope(res, framework);
    } catch (err) {
      log.error("Failed to get framework", { error: String(err) });
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "INTERNAL_ERROR", message: "Failed to fetch framework" }],
      });
    }
  });

  app.get("/api/trust-center/control-mappings", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const frameworkId = typeof req.query.frameworkId === "string" ? req.query.frameworkId : undefined;
      const mappings = frameworkId ? getControlMappingsForFramework(frameworkId) : getAllControlMappings();
      return sendEnvelope(res, mappings);
    } catch (err) {
      log.error("Failed to get control mappings", { error: String(err) });
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "INTERNAL_ERROR", message: "Failed to fetch control mappings" }],
      });
    }
  });

  // Summary: combine framework data + artifact counts from DB
  app.get(
    "/api/trust-center/summary",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const frameworks = getAllFrameworks();
        const [artifactCount, downloadCount] = await Promise.all([
          storage.countTrustCenterArtifacts(orgId),
          storage.countTrustCenterDownloads(orgId),
        ]);
        const artifacts = await storage.getTrustCenterArtifacts(orgId);

        const currentArtifacts = artifacts.filter((a) => a.status === "current").length;
        const expiringSoon = artifacts.filter((a) => a.status === "expiring_soon").length;
        const expired = artifacts.filter((a) => a.status === "expired").length;

        return sendEnvelope(res, {
          totalFrameworks: frameworks.length,
          certifiedFrameworks: frameworks.filter((f) => f.status === "certified").length,
          totalArtifacts: artifactCount,
          currentArtifacts,
          expiringSoon,
          expired,
          totalDownloads: downloadCount,
        });
      } catch (err) {
        log.error("Failed to get summary", { error: String(err) });
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "INTERNAL_ERROR", message: "Failed to fetch trust center summary" }],
        });
      }
    },
  );

  // Artifacts CRUD — persisted to DB
  app.get(
    "/api/trust-center/artifacts",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const category = typeof req.query.category === "string" ? req.query.category : undefined;
        const artifacts = await storage.getTrustCenterArtifacts(orgId, category);
        return sendEnvelope(res, artifacts);
      } catch (err) {
        log.error("Failed to get artifacts", { error: String(err) });
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "INTERNAL_ERROR", message: "Failed to fetch artifacts" }],
        });
      }
    },
  );

  app.get(
    "/api/trust-center/artifacts/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const artId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
        const artifact = await storage.getTrustCenterArtifact(artId, orgId);
        if (!artifact) {
          return sendEnvelope(res, null, {
            status: 404,
            errors: [{ code: "NOT_FOUND", message: "Artifact not found" }],
          });
        }
        return sendEnvelope(res, artifact);
      } catch (err) {
        log.error("Failed to get artifact", { error: String(err) });
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "INTERNAL_ERROR", message: "Failed to fetch artifact" }],
        });
      }
    },
  );

  app.post(
    "/api/trust-center/artifacts",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const user = (req as RequestWithUser).user;
        const {
          category,
          title,
          description,
          version,
          fileName,
          fileSize,
          mimeType,
          freshnessSlaDays,
          accessLevel,
          tags,
        } = req.body;

        if (!category || !title || !fileName) {
          return sendEnvelope(res, null, {
            status: 400,
            errors: [{ code: "VALIDATION_ERROR", message: "category, title, and fileName are required" }],
          });
        }

        const artifact = await storage.createTrustCenterArtifact({
          orgId,
          category,
          title,
          description: description || "",
          version: version || "1.0",
          fileName,
          fileSize: fileSize || 0,
          mimeType: mimeType || "application/pdf",
          uploadedBy: user?.id || "unknown",
          freshnessSlaDays: freshnessSlaDays || 180,
          accessLevel: accessLevel || "customer_only",
          tags: tags || [],
          status: "current",
        });

        return sendEnvelope(res, artifact, { status: 201 });
      } catch (err) {
        log.error("Failed to create artifact", { error: String(err) });
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "INTERNAL_ERROR", message: "Failed to create artifact" }],
        });
      }
    },
  );

  app.patch(
    "/api/trust-center/artifacts/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const allowedFields = ["title", "description", "version", "accessLevel", "freshnessSlaDays", "tags", "status"];
        const updates: Record<string, unknown> = {};
        for (const field of allowedFields) {
          if (req.body[field] !== undefined) {
            updates[field] = req.body[field];
          }
        }

        const patchId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
        const result = await storage.updateTrustCenterArtifact(patchId, orgId, updates);
        if (!result) {
          return sendEnvelope(res, null, {
            status: 404,
            errors: [{ code: "NOT_FOUND", message: "Artifact not found" }],
          });
        }
        return sendEnvelope(res, result);
      } catch (err) {
        log.error("Failed to update artifact", { error: String(err) });
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "INTERNAL_ERROR", message: "Failed to update artifact" }],
        });
      }
    },
  );

  app.post(
    "/api/trust-center/artifacts/:id/review",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const reviewId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
        const now = new Date();
        const result = await storage.updateTrustCenterArtifact(reviewId, orgId, {
          lastReviewedAt: now,
          status: "current",
        });
        if (!result) {
          return sendEnvelope(res, null, {
            status: 404,
            errors: [{ code: "NOT_FOUND", message: "Artifact not found" }],
          });
        }
        return sendEnvelope(res, result);
      } catch (err) {
        log.error("Failed to mark artifact reviewed", { error: String(err) });
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "INTERNAL_ERROR", message: "Failed to mark artifact as reviewed" }],
        });
      }
    },
  );

  app.delete(
    "/api/trust-center/artifacts/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const delId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
        const deleted = await storage.deleteTrustCenterArtifact(delId, orgId);
        if (!deleted) {
          return sendEnvelope(res, null, {
            status: 404,
            errors: [{ code: "NOT_FOUND", message: "Artifact not found" }],
          });
        }
        return sendEnvelope(res, { deleted: true });
      } catch (err) {
        log.error("Failed to delete artifact", { error: String(err) });
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "INTERNAL_ERROR", message: "Failed to delete artifact" }],
        });
      }
    },
  );

  // Download tracking — persisted to DB
  app.post(
    "/api/trust-center/artifacts/:id/download",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const user = (req as RequestWithUser).user;
        const ip = req.ip || req.socket.remoteAddress || "unknown";
        const ua = req.headers["user-agent"] || "unknown";

        const dlId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;

        // Verify artifact exists
        const artifact = await storage.getTrustCenterArtifact(dlId, orgId);
        if (!artifact) {
          return sendEnvelope(res, null, {
            status: 404,
            errors: [{ code: "NOT_FOUND", message: "Artifact not found" }],
          });
        }

        // Record download
        const entry = await storage.createTrustCenterDownload({
          orgId,
          artifactId: dlId,
          userId: user?.id || "anonymous",
          userEmail: user?.email || "anonymous",
          ipAddress: ip,
          userAgent: ua,
        });

        // Increment download count
        await storage.updateTrustCenterArtifact(dlId, orgId, {
          downloadCount: (artifact.downloadCount ?? 0) + 1,
        });

        return sendEnvelope(res, entry);
      } catch (err) {
        log.error("Failed to record download", { error: String(err) });
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "INTERNAL_ERROR", message: "Failed to record download" }],
        });
      }
    },
  );

  app.get(
    "/api/trust-center/download-audit-log",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const limit = typeof req.query.limit === "string" ? Math.min(parseInt(req.query.limit, 10) || 100, 500) : 100;
        const entries = await storage.getTrustCenterDownloads(orgId, limit);
        return sendEnvelope(res, entries);
      } catch (err) {
        log.error("Failed to get download audit log", { error: String(err) });
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "INTERNAL_ERROR", message: "Failed to fetch download audit log" }],
        });
      }
    },
  );

  // Freshness alerts — computed from DB artifact data
  app.get(
    "/api/trust-center/freshness",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const artifacts = await storage.getTrustCenterArtifacts(orgId);
        const now = Date.now();
        const alerts = [];

        for (const a of artifacts) {
          if (!a.uploadedAt) continue;
          const ageMs = now - new Date(a.uploadedAt).getTime();
          const slaDays = a.freshnessSlaDays ?? 180;
          const slaMs = slaDays * 24 * 60 * 60 * 1000;
          const warningMs = slaMs * 0.8;

          if (ageMs > slaMs) {
            alerts.push({
              artifactId: a.id,
              title: a.title,
              category: a.category,
              severity: "critical" as const,
              message: `Artifact "${a.title}" has exceeded its ${slaDays}-day freshness SLA`,
              daysPastDue: Math.floor((ageMs - slaMs) / (24 * 60 * 60 * 1000)),
            });
          } else if (ageMs > warningMs) {
            alerts.push({
              artifactId: a.id,
              title: a.title,
              category: a.category,
              severity: "warning" as const,
              message: `Artifact "${a.title}" is approaching its ${slaDays}-day freshness SLA`,
              daysRemaining: Math.floor((slaMs - ageMs) / (24 * 60 * 60 * 1000)),
            });
          }
        }

        return sendEnvelope(res, alerts);
      } catch (err) {
        log.error("Failed to get freshness alerts", { error: String(err) });
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "INTERNAL_ERROR", message: "Failed to fetch freshness alerts" }],
        });
      }
    },
  );
}

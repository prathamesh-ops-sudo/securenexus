import type { Express, Request, Response } from "express";
import { isAuthenticated } from "../auth";
import { requireMinRole, requireOrgId, resolveOrgContext } from "../rbac";
import { logger, getOrgId, sendEnvelope } from "./shared";
import {
  getAllFrameworks,
  getFrameworkById,
  getAllControlMappings,
  getControlMappingsForFramework,
  getArtifacts,
  getArtifactById,
  createArtifact,
  updateArtifact,
  markArtifactReviewed,
  deleteArtifact,
  recordDownload,
  getDownloadAuditLog,
  getFreshnessAlerts,
  getTrustCenterSummary,
} from "../trust-center-engine";

export function registerTrustCenterRoutes(app: Express): void {
  app.get("/api/trust-center/frameworks", isAuthenticated, async (_req: Request, res: Response) => {
    try {
      const frameworks = getAllFrameworks();
      return sendEnvelope(res, frameworks);
    } catch (err) {
      logger.child("trust-center").error("Failed to get frameworks", { error: String(err) });
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
      logger.child("trust-center").error("Failed to get framework", { error: String(err) });
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
      logger.child("trust-center").error("Failed to get control mappings", { error: String(err) });
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "INTERNAL_ERROR", message: "Failed to fetch control mappings" }],
      });
    }
  });

  app.get(
    "/api/trust-center/summary",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const summary = getTrustCenterSummary(orgId);
        return sendEnvelope(res, summary);
      } catch (err) {
        logger.child("trust-center").error("Failed to get summary", { error: String(err) });
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "INTERNAL_ERROR", message: "Failed to fetch trust center summary" }],
        });
      }
    },
  );

  app.get(
    "/api/trust-center/artifacts",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const category = typeof req.query.category === "string" ? req.query.category : undefined;
        const artifacts = getArtifacts(orgId, category as any);
        return sendEnvelope(res, artifacts);
      } catch (err) {
        logger.child("trust-center").error("Failed to get artifacts", { error: String(err) });
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
        const artifact = getArtifactById(orgId, artId);
        if (!artifact) {
          return sendEnvelope(res, null, {
            status: 404,
            errors: [{ code: "NOT_FOUND", message: "Artifact not found" }],
          });
        }
        return sendEnvelope(res, artifact);
      } catch (err) {
        logger.child("trust-center").error("Failed to get artifact", { error: String(err) });
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
        const user = (req as any).user;
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

        const result = createArtifact(orgId, {
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
        });

        if ("error" in result) {
          return sendEnvelope(res, null, {
            status: 400,
            errors: [{ code: "VALIDATION_ERROR", message: result.error }],
          });
        }

        return sendEnvelope(res, result, { status: 201 });
      } catch (err) {
        logger.child("trust-center").error("Failed to create artifact", { error: String(err) });
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
        const updates: Record<string, any> = {};
        for (const field of allowedFields) {
          if (req.body[field] !== undefined) {
            updates[field] = req.body[field];
          }
        }

        const patchId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
        const result = updateArtifact(orgId, patchId, updates);
        if (!result) {
          return sendEnvelope(res, null, {
            status: 404,
            errors: [{ code: "NOT_FOUND", message: "Artifact not found" }],
          });
        }
        return sendEnvelope(res, result);
      } catch (err) {
        logger.child("trust-center").error("Failed to update artifact", { error: String(err) });
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
        const result = markArtifactReviewed(orgId, reviewId);
        if (!result) {
          return sendEnvelope(res, null, {
            status: 404,
            errors: [{ code: "NOT_FOUND", message: "Artifact not found" }],
          });
        }
        return sendEnvelope(res, result);
      } catch (err) {
        logger.child("trust-center").error("Failed to mark artifact reviewed", { error: String(err) });
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
        const deleted = deleteArtifact(orgId, delId);
        if (!deleted) {
          return sendEnvelope(res, null, {
            status: 404,
            errors: [{ code: "NOT_FOUND", message: "Artifact not found" }],
          });
        }
        return sendEnvelope(res, { deleted: true });
      } catch (err) {
        logger.child("trust-center").error("Failed to delete artifact", { error: String(err) });
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "INTERNAL_ERROR", message: "Failed to delete artifact" }],
        });
      }
    },
  );

  app.post(
    "/api/trust-center/artifacts/:id/download",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const user = (req as any).user;
        const ip = req.ip || req.socket.remoteAddress || "unknown";
        const ua = req.headers["user-agent"] || "unknown";

        const dlId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
        const entry = recordDownload(orgId, dlId, user?.id || "anonymous", user?.email || "anonymous", ip, ua);

        if (!entry) {
          return sendEnvelope(res, null, {
            status: 404,
            errors: [{ code: "NOT_FOUND", message: "Artifact not found" }],
          });
        }

        return sendEnvelope(res, entry);
      } catch (err) {
        logger.child("trust-center").error("Failed to record download", { error: String(err) });
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
        const entries = getDownloadAuditLog(orgId, limit);
        return sendEnvelope(res, entries);
      } catch (err) {
        logger.child("trust-center").error("Failed to get download audit log", { error: String(err) });
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "INTERNAL_ERROR", message: "Failed to fetch download audit log" }],
        });
      }
    },
  );

  app.get(
    "/api/trust-center/freshness",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const alerts = getFreshnessAlerts(orgId);
        return sendEnvelope(res, alerts);
      } catch (err) {
        logger.child("trust-center").error("Failed to get freshness alerts", { error: String(err) });
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "INTERNAL_ERROR", message: "Failed to fetch freshness alerts" }],
        });
      }
    },
  );
}

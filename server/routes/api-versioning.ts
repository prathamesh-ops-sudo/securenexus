import type { Express, Request, Response, NextFunction } from "express";
import { isAuthenticated } from "../auth";
import { sendEnvelope, storage, getOrgId, logger } from "./shared";

const API_V1_STABILITY_DATE = "2026-02-17";
const API_V1_SUNSET_DATE = "2028-02-17";
const MIGRATION_GUIDE_URL = "/api/v1/migration-guide";

export function deprecationHeaders(_req: Request, res: Response, next: NextFunction) {
  res.setHeader("Deprecation", "true");
  res.setHeader("Sunset", API_V1_SUNSET_DATE);
  res.setHeader("Link", `<${MIGRATION_GUIDE_URL}>; rel="deprecation"; type="text/html"`);
  next();
}

export function versionHeader(_req: Request, res: Response, next: NextFunction) {
  res.setHeader("X-API-Version", "v1");
  res.setHeader("X-API-Stability", "stable");
  next();
}

export function registerApiVersioningRoutes(app: Express): void {
  app.get("/api/v1/version-policy", (_req, res) => {
    res.json({
      currentVersion: "v1",
      stabilityLevel: "stable",
      stabilityGuarantees: {
        breakingChanges: "No breaking changes will be introduced in v1 endpoints",
        deprecationNotice: "Minimum 12 months notice before any deprecation",
        sunsetDate: API_V1_SUNSET_DATE,
        supportedUntil: API_V1_SUNSET_DATE,
      },
      v2Roadmap: {
        status: "planning",
        breakingChanges: [
          "Response envelope format may change",
          "Pagination cursor-based instead of offset-based",
          "Authentication via OAuth2 tokens instead of session cookies",
          "Resource IDs will use UUIDv7 format",
        ],
        migrationPath: "v1 and v2 will coexist for minimum 12 months after v2 GA",
      },
      headers: {
        "X-API-Version": "Indicates the API version serving the request",
        "X-API-Stability": "stable | beta | deprecated",
        Deprecation: "true if the endpoint is deprecated",
        Sunset: "ISO date when the endpoint will be removed",
        Link: "URL to migration guide for deprecated endpoints",
      },
      endpoints: {
        legacy: "/api/* — original endpoints, will receive deprecation headers when v2 launches",
        v1: "/api/v1/* — stable endpoints with versioning guarantees",
      },
      publishedAt: API_V1_STABILITY_DATE,
    });
  });

  app.get("/api/v1/migration-guide", (_req, res) => {
    res.json({
      title: "SecureNexus API Migration Guide",
      version: "v1",
      lastUpdated: API_V1_STABILITY_DATE,
      overview: "This guide helps you migrate from legacy /api endpoints to stable /api/v1 endpoints.",
      sections: [
        {
          id: "audit-logs",
          title: "Audit Logs",
          legacy: {
            method: "GET",
            path: "/api/audit-logs",
            description: "Returns all audit logs for the organization",
          },
          v1: {
            method: "GET",
            path: "/api/v1/audit-logs",
            description: "Paginated audit logs with filtering and sorting",
          },
          changes: [
            "Added offset/limit pagination (default limit: 50, max: 500)",
            "Added action, userId, resourceType query filters",
            "Added sortOrder parameter (asc/desc)",
            "Response wrapped in standard envelope with meta.total, meta.offset, meta.limit",
          ],
          example: {
            request: "GET /api/v1/audit-logs?offset=0&limit=25&action=alert_created&sortOrder=desc",
            responseShape: {
              ok: true,
              data: ["...audit log entries..."],
              meta: { offset: 0, limit: 25, total: 142, sortOrder: "desc" },
            },
          },
        },
        {
          id: "alerts",
          title: "Alerts",
          legacy: { method: "GET", path: "/api/alerts", description: "Returns all alerts for the organization" },
          v1: {
            method: "GET",
            path: "/api/v1/alerts",
            description: "Paginated alerts with text search, severity/status filters",
          },
          changes: [
            "Added offset/limit pagination (default limit: 50, max: 200)",
            "Added search query parameter for full-text search",
            "Added severity and status filters",
            "Response includes meta.total for total count",
          ],
          example: {
            request: "GET /api/v1/alerts?offset=0&limit=20&severity=critical&status=open",
            responseShape: {
              ok: true,
              data: ["...alert entries..."],
              meta: { offset: 0, limit: 20, total: 53, severity: "critical", status: "open" },
            },
          },
        },
        {
          id: "incidents",
          title: "Incidents",
          legacy: { method: "GET", path: "/api/incidents", description: "Returns all incidents" },
          v1: { method: "GET", path: "/api/v1/incidents", description: "Paginated incidents with filters" },
          changes: [
            "Added offset/limit pagination",
            "Added status and severity query filters",
            "Response includes meta.total",
          ],
          example: {
            request: "GET /api/v1/incidents?offset=0&limit=10&status=open",
            responseShape: { ok: true, data: ["...incidents..."], meta: { offset: 0, limit: 10, total: 7 } },
          },
        },
        {
          id: "connectors",
          title: "Connectors",
          legacy: { method: "GET", path: "/api/connectors", description: "Returns all connectors" },
          v1: { method: "GET", path: "/api/v1/connectors", description: "Paginated connectors" },
          changes: ["Added offset/limit pagination", "Response includes meta.total"],
          example: {
            request: "GET /api/v1/connectors?offset=0&limit=25",
            responseShape: { ok: true, data: ["...connectors..."], meta: { offset: 0, limit: 25, total: 12 } },
          },
        },
        {
          id: "report-template-versions",
          title: "Report Template Versions (new in v1)",
          legacy: null,
          v1: {
            method: "GET",
            path: "/api/v1/report-templates/:templateId/versions",
            description: "Versioned report templates with approval workflow",
          },
          changes: ["New endpoint — no legacy equivalent"],
        },
        {
          id: "evidence-attachments",
          title: "Evidence Attachments (new in v1)",
          legacy: null,
          v1: {
            method: "GET",
            path: "/api/v1/evidence-attachments",
            description: "S3-backed evidence attachments with presigned URLs",
          },
          changes: ["New endpoint — no legacy equivalent"],
        },
        {
          id: "compliance-helpers",
          title: "Compliance Control Helpers (new in v1)",
          legacy: null,
          v1: {
            method: "GET",
            path: "/api/v1/compliance-helpers",
            description: "Gap analysis, cross-mapping, coverage reports",
          },
          changes: ["New endpoint — no legacy equivalent"],
        },
      ],
      generalChanges: [
        "All v1 endpoints return responses in a standard envelope: { ok: boolean, data: T, meta?: {...}, errors?: [...] }",
        "All v1 list endpoints support offset/limit pagination",
        "All v1 endpoints include X-API-Version and X-API-Stability response headers",
        "Legacy /api endpoints will eventually receive Deprecation and Sunset headers",
      ],
      authentication: {
        current: "Session-based authentication via cookies (unchanged in v1)",
        v2planned: "OAuth2 bearer tokens with API key fallback",
      },
    });
  });

  // ==========================================
  // v1 Stable Endpoints — Alerts
  // ==========================================

  app.get("/api/v1/alerts", isAuthenticated, versionHeader, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const offset = Math.max(0, Number(req.query.offset ?? 0) || 0);
      const limit = Math.min(Math.max(1, Number(req.query.limit ?? 50) || 50), 200);
      const search = typeof req.query.search === "string" ? req.query.search : undefined;

      const { items, total } = await storage.getAlertsPaginated({
        orgId,
        offset,
        limit,
        search,
      });

      return sendEnvelope(res, items, {
        meta: { offset, limit, total, search: search ?? null },
      });
    } catch (error: any) {
      if (error.message === "ORG_CONTEXT_MISSING")
        return res.status(403).json({ message: "Organization context required" });
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "ALERTS_FAILED", message: "Failed to fetch alerts" }],
      });
    }
  });

  // ==========================================
  // v1 Stable Endpoints — Incidents
  // ==========================================

  app.get("/api/v1/incidents", isAuthenticated, versionHeader, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const offset = Math.max(0, Number(req.query.offset ?? 0) || 0);
      const limit = Math.min(Math.max(1, Number(req.query.limit ?? 50) || 50), 200);
      const queue = typeof req.query.queue === "string" ? req.query.queue : undefined;

      const { items, total } = await storage.getIncidentsPaginated({
        orgId,
        offset,
        limit,
        queue,
      });

      return sendEnvelope(res, items, {
        meta: { offset, limit, total, queue: queue ?? null },
      });
    } catch (error: any) {
      if (error.message === "ORG_CONTEXT_MISSING")
        return res.status(403).json({ message: "Organization context required" });
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "INCIDENTS_FAILED", message: "Failed to fetch incidents" }],
      });
    }
  });

  // ==========================================
  // v1 Stable Endpoints — Connectors
  // ==========================================

  app.get("/api/v1/connectors", isAuthenticated, versionHeader, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const offset = Math.max(0, Number(req.query.offset ?? 0) || 0);
      const limit = Math.min(Math.max(1, Number(req.query.limit ?? 50) || 50), 200);

      const { items, total } = await storage.getConnectorsPaginated({ orgId, offset, limit });

      return sendEnvelope(res, items, {
        meta: { offset, limit, total },
      });
    } catch (error: any) {
      if (error.message === "ORG_CONTEXT_MISSING")
        return res.status(403).json({ message: "Organization context required" });
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "CONNECTORS_FAILED", message: "Failed to fetch connectors" }],
      });
    }
  });

  // ==========================================
  // v1 Stable Endpoints — Report Template Versions
  // ==========================================

  app.get("/api/v1/report-templates/:templateId/versions", isAuthenticated, versionHeader, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const templateId = String(req.params.templateId);
      const template = await storage.getReportTemplate(templateId);
      if (!template)
        return sendEnvelope(res, null, { status: 404, errors: [{ code: "NOT_FOUND", message: "Template not found" }] });
      const versions = await storage.getReportTemplateVersions(template.id, orgId);
      return sendEnvelope(res, versions, { meta: { templateId: template.id, total: versions.length } });
    } catch (error: any) {
      if (error.message === "ORG_CONTEXT_MISSING")
        return res.status(403).json({ message: "Organization context required" });
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "VERSIONS_FAILED", message: "Failed to fetch versions" }],
      });
    }
  });

  // ==========================================
  // v1 Stable Endpoints — Evidence Attachments
  // ==========================================

  app.get("/api/v1/evidence-attachments", isAuthenticated, versionHeader, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const controlMappingId = typeof req.query.controlMappingId === "string" ? req.query.controlMappingId : undefined;
      const attachments = await storage.getEvidenceAttachments(orgId, controlMappingId);
      return sendEnvelope(res, attachments, { meta: { total: attachments.length } });
    } catch (error: any) {
      if (error.message === "ORG_CONTEXT_MISSING")
        return res.status(403).json({ message: "Organization context required" });
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "ATTACHMENTS_FAILED", message: "Failed to fetch attachments" }],
      });
    }
  });

  // ==========================================
  // v1 Stable Endpoints — Compliance Helpers
  // ==========================================

  app.get("/api/v1/compliance-helpers", isAuthenticated, versionHeader, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const helperType = typeof req.query.helperType === "string" ? req.query.helperType : undefined;
      const helpers = await storage.getComplianceControlHelpers(orgId, helperType);
      return sendEnvelope(res, helpers, { meta: { total: helpers.length } });
    } catch (error: any) {
      if (error.message === "ORG_CONTEXT_MISSING")
        return res.status(403).json({ message: "Organization context required" });
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "HELPERS_FAILED", message: "Failed to fetch helpers" }],
      });
    }
  });

  // ==========================================
  // v1 Stable Endpoints — Ingestion Logs
  // ==========================================

  app.get("/api/v1/ingestion-logs", isAuthenticated, versionHeader, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const offset = Math.max(0, Number(req.query.offset ?? 0) || 0);
      const limit = Math.min(Math.max(1, Number(req.query.limit ?? 50) || 50), 200);

      const { items, total } = await storage.getIngestionLogsPaginated({ orgId, offset, limit });

      return sendEnvelope(res, items, { meta: { offset, limit, total } });
    } catch (error: any) {
      if (error.message === "ORG_CONTEXT_MISSING")
        return res.status(403).json({ message: "Organization context required" });
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "INGESTION_FAILED", message: "Failed to fetch ingestion logs" }],
      });
    }
  });
}

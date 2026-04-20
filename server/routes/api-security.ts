import type { Express, Request, Response } from "express";
import { isAuthenticated } from "../auth";
import { resolveOrgContext, requireOrgId, requirePermission } from "../rbac";
import { logger, getOrgId } from "./shared";
import { db } from "../db";
import { sql, eq, and, desc, ilike, or, count } from "drizzle-orm";
import {
  apiInventory,
  apiFindings,
  apiTrafficBaselines,
  API_SECURITY_FINDING_TYPES,
  API_SECURITY_FINDING_SEVERITIES,
  API_SECURITY_FINDING_STATUSES,
  API_AUTH_TYPES,
} from "../../shared/schema";
import {
  parseOpenApiSpec,
  scanForSensitiveData,
  detectShadowApis,
  computeApiRiskScore,
  getApiSecuritySummary,
  detectTrafficAnomalies,
  OWASP_CATEGORIES,
} from "../api-analyzer";

const log = logger.child("api-security");

export function registerApiSecurityRoutes(app: Express): void {
  // ==========================================================================
  // SUMMARY — Aggregate API security metrics
  // ==========================================================================

  app.get(
    "/api/api-security/summary",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const summary = await getApiSecuritySummary(orgId);
        res.json(summary);
      } catch (error) {
        log.error("Failed to get API security summary", { error: String(error) });
        res.status(500).json({ message: "Failed to get API security summary" });
      }
    },
  );

  // ==========================================================================
  // API INVENTORY — List all discovered APIs
  // ==========================================================================

  app.get(
    "/api/api-security/inventory",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const q = (req.query.q as string) || "";
        const shadow = req.query.shadow as string | undefined;
        const deprecated = req.query.deprecated as string | undefined;
        const authType = req.query.authType as string | undefined;
        const host = req.query.host as string | undefined;
        const sortBy = (req.query.sortBy as string) || "risk_score";
        const limitParam = parseInt(String(req.query.limit || "100"));
        const offsetParam = parseInt(String(req.query.offset || "0"));
        const limit = Math.min(Number.isNaN(limitParam) ? 100 : limitParam, 500);
        const offset = Number.isNaN(offsetParam) ? 0 : offsetParam;

        const conditions: unknown[] = [eq(apiInventory.orgId, orgId)];
        if (shadow === "true") conditions.push(eq(apiInventory.isShadow, true));
        if (deprecated === "true") conditions.push(eq(apiInventory.isDeprecated, true));
        if (authType && authType !== "all") conditions.push(eq(apiInventory.authType, authType));
        if (host && host !== "all") conditions.push(eq(apiInventory.host, host));
        if (q) {
          conditions.push(or(ilike(apiInventory.path, `%${q}%`), ilike(apiInventory.host, `%${q}%`)));
        }

        const orderCol =
          sortBy === "request_count"
            ? apiInventory.requestCount24h
            : sortBy === "error_rate"
              ? apiInventory.errorRate24h
              : sortBy === "last_seen"
                ? apiInventory.lastSeenAt
                : apiInventory.riskScore;

        const apis = await db
          .select()
          .from(apiInventory)
          .where(and(...(conditions as any[])))
          .orderBy(desc(orderCol))
          .limit(limit)
          .offset(offset);

        const [{ value: total }] = await db
          .select({ value: count() })
          .from(apiInventory)
          .where(and(...(conditions as any[])));

        // Host breakdown
        const hostStats = await db.execute(sql`
          SELECT host, COUNT(*) AS api_count,
                 COUNT(*) FILTER (WHERE is_shadow = true) AS shadow_count,
                 COUNT(*) FILTER (WHERE auth_type = 'none') AS no_auth_count,
                 AVG(risk_score) AS avg_risk
          FROM api_inventory
          WHERE org_id = ${orgId}
          GROUP BY host
          ORDER BY api_count DESC
        `);

        res.json({
          apis,
          total,
          hosts: (hostStats as any).rows || [],
        });
      } catch (error) {
        log.error("Failed to list API inventory", { error: String(error) });
        res.status(500).json({ message: "Failed to list API inventory" });
      }
    },
  );

  // ==========================================================================
  // GET SINGLE API ENDPOINT
  // ==========================================================================

  app.get(
    "/api/api-security/inventory/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const apiId = String(req.params.id);

        const [api] = await db
          .select()
          .from(apiInventory)
          .where(and(eq(apiInventory.id, apiId), eq(apiInventory.orgId, orgId)))
          .limit(1);

        if (!api) {
          return res.status(404).json({ message: "API endpoint not found" });
        }

        // Get related findings
        const findings = await db
          .select()
          .from(apiFindings)
          .where(and(eq(apiFindings.apiId, apiId), eq(apiFindings.orgId, orgId)))
          .orderBy(desc(apiFindings.createdAt))
          .limit(50);

        // Get recent traffic baselines
        const baselines = await db
          .select()
          .from(apiTrafficBaselines)
          .where(and(eq(apiTrafficBaselines.apiId, apiId), eq(apiTrafficBaselines.orgId, orgId)))
          .orderBy(desc(apiTrafficBaselines.windowStart))
          .limit(24);

        res.json({ api, findings, baselines });
      } catch (error) {
        log.error("Failed to get API endpoint", { error: String(error) });
        res.status(500).json({ message: "Failed to get API endpoint" });
      }
    },
  );

  // ==========================================================================
  // REGISTER API ENDPOINT MANUALLY
  // ==========================================================================

  app.post(
    "/api/api-security/inventory",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { method, path, host, version, authType, isDeprecated, tags } = req.body;

        if (!method || typeof method !== "string") {
          return res.status(400).json({ message: "method is required" });
        }
        if (!path || typeof path !== "string") {
          return res.status(400).json({ message: "path is required" });
        }
        if (!host || typeof host !== "string") {
          return res.status(400).json({ message: "host is required" });
        }

        const validMethods = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
        if (!validMethods.includes(method.toUpperCase())) {
          return res.status(400).json({ message: `method must be one of: ${validMethods.join(", ")}` });
        }

        if (authType && !API_AUTH_TYPES.includes(authType as any)) {
          return res.status(400).json({
            message: `authType must be one of: ${API_AUTH_TYPES.join(", ")}`,
          });
        }

        const [api] = await db
          .insert(apiInventory)
          .values({
            orgId,
            method: method.toUpperCase(),
            path,
            host,
            version: version || null,
            authType: authType || "none",
            isDeprecated: isDeprecated || false,
            specSource: "manual",
            tags: tags || null,
          })
          .onConflictDoUpdate({
            target: [apiInventory.orgId, apiInventory.method, apiInventory.path, apiInventory.host],
            set: {
              version: version || null,
              authType: authType || "none",
              isDeprecated: isDeprecated || false,
              tags: tags || null,
              updatedAt: new Date(),
            },
          })
          .returning();

        log.info(`API endpoint registered: ${method} ${path}`, { orgId, apiId: api.id });
        res.status(201).json(api);
      } catch (error) {
        log.error("Failed to register API endpoint", { error: String(error) });
        res.status(500).json({ message: "Failed to register API endpoint" });
      }
    },
  );

  // ==========================================================================
  // IMPORT OPENAPI SPEC — Bulk discover APIs from spec
  // ==========================================================================

  app.post(
    "/api/api-security/import-spec",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { spec, host } = req.body;

        if (!spec || typeof spec !== "object") {
          return res.status(400).json({ message: "spec (OpenAPI JSON) is required" });
        }
        if (!host || typeof host !== "string") {
          return res.status(400).json({ message: "host is required" });
        }

        const endpoints = parseOpenApiSpec(spec, host);
        if (endpoints.length === 0) {
          return res.status(400).json({ message: "No endpoints found in spec" });
        }

        let imported = 0;
        let updated = 0;

        for (const ep of endpoints) {
          const result = await db
            .insert(apiInventory)
            .values({
              orgId,
              method: ep.method,
              path: ep.path,
              host: ep.host,
              version: ep.version,
              authType: ep.authType,
              specSource: "openapi_import",
              openApiSpec: spec,
              isShadow: false,
            })
            .onConflictDoUpdate({
              target: [apiInventory.orgId, apiInventory.method, apiInventory.path, apiInventory.host],
              set: {
                version: ep.version,
                authType: ep.authType,
                specSource: "openapi_import",
                openApiSpec: spec,
                isShadow: false,
                updatedAt: new Date(),
              },
            })
            .returning();

          if (result[0].createdAt?.getTime() === result[0].updatedAt?.getTime()) {
            imported++;
          } else {
            updated++;
          }
        }

        log.info(`OpenAPI spec imported: ${imported} new, ${updated} updated`, { orgId, host });
        res.json({
          message: `Imported ${imported} new endpoints, updated ${updated} existing`,
          imported,
          updated,
          total: endpoints.length,
        });
      } catch (error) {
        log.error("Failed to import OpenAPI spec", { error: String(error) });
        res.status(500).json({ message: "Failed to import OpenAPI spec" });
      }
    },
  );

  // ==========================================================================
  // DELETE API ENDPOINT
  // ==========================================================================

  app.delete(
    "/api/api-security/inventory/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const apiId = String(req.params.id);

        const [api] = await db
          .select()
          .from(apiInventory)
          .where(and(eq(apiInventory.id, apiId), eq(apiInventory.orgId, orgId)))
          .limit(1);

        if (!api) {
          return res.status(404).json({ message: "API endpoint not found" });
        }

        await db.delete(apiInventory).where(eq(apiInventory.id, apiId));
        log.info(`API endpoint deleted: ${api.method} ${api.path}`, { orgId, apiId });
        res.json({ message: "API endpoint deleted" });
      } catch (error) {
        log.error("Failed to delete API endpoint", { error: String(error) });
        res.status(500).json({ message: "Failed to delete API endpoint" });
      }
    },
  );

  // ==========================================================================
  // SHADOW API DETECTION — Trigger scan
  // ==========================================================================

  app.post(
    "/api/api-security/detect-shadows",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const count = await detectShadowApis(orgId);
        log.info(`Shadow API detection: ${count} new shadows found`, { orgId });
        res.json({ message: `${count} shadow APIs detected`, shadowCount: count });
      } catch (error) {
        log.error("Failed to detect shadow APIs", { error: String(error) });
        res.status(500).json({ message: "Failed to detect shadow APIs" });
      }
    },
  );

  // ==========================================================================
  // SENSITIVE DATA SCAN — Scan response body for PII/secrets
  // ==========================================================================

  app.post(
    "/api/api-security/scan-sensitive",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { apiId, responseBody } = req.body;

        if (!responseBody || typeof responseBody !== "string") {
          return res.status(400).json({ message: "responseBody (string) is required" });
        }

        const sensitiveHits = scanForSensitiveData(responseBody);

        // If findings, create API findings
        if (sensitiveHits.length > 0 && apiId) {
          // Verify API belongs to org
          const [api] = await db
            .select()
            .from(apiInventory)
            .where(and(eq(apiInventory.id, apiId), eq(apiInventory.orgId, orgId)))
            .limit(1);

          if (api) {
            for (const hit of sensitiveHits) {
              await db.insert(apiFindings).values({
                orgId,
                apiId,
                findingType: "sensitive_data_exposure",
                severity: hit.severity,
                title: `Sensitive data detected: ${hit.type}`,
                description: `API response contains ${hit.type} data (masked: ${hit.snippet})`,
                endpoint: `${api.method} ${api.path}`,
                method: api.method,
                owaspCategory: OWASP_CATEGORIES.sensitive_data_exposure,
                cweId: "CWE-200",
                evidence: { sensitiveType: hit.type, masked: hit.snippet },
                remediation: `Remove or mask ${hit.type} from API response. Use field-level encryption or response filtering.`,
              });
            }

            // Update sensitive data types on the API
            const existingTypes = (api.sensitiveDataTypes as string[] | null) || [];
            const combined = existingTypes.concat(sensitiveHits.map((h) => h.type));
            const newTypes = combined.filter((v, i, a) => a.indexOf(v) === i);
            await db
              .update(apiInventory)
              .set({ sensitiveDataTypes: newTypes, updatedAt: new Date() })
              .where(eq(apiInventory.id, apiId));
          }
        }

        res.json({
          sensitiveDataFound: sensitiveHits.length > 0,
          hits: sensitiveHits,
          findingsCreated: apiId ? sensitiveHits.length : 0,
        });
      } catch (error) {
        log.error("Failed to scan for sensitive data", { error: String(error) });
        res.status(500).json({ message: "Failed to scan for sensitive data" });
      }
    },
  );

  // ==========================================================================
  // INGEST TRAFFIC — Record API call traffic for baseline learning
  // ==========================================================================

  app.post(
    "/api/api-security/ingest-traffic",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { method, path, host, statusCode, latencyMs, callerIp, responseBody } = req.body;

        if (!method || !path || !host) {
          return res.status(400).json({ message: "method, path, and host are required" });
        }

        // Upsert API in inventory
        const [api] = await db
          .insert(apiInventory)
          .values({
            orgId,
            method: method.toUpperCase(),
            path,
            host,
            authType: "none",
            lastSeenAt: new Date(),
            requestCount24h: 1,
          })
          .onConflictDoUpdate({
            target: [apiInventory.orgId, apiInventory.method, apiInventory.path, apiInventory.host],
            set: {
              lastSeenAt: new Date(),
              requestCount24h: sql`${apiInventory.requestCount24h} + 1`,
              updatedAt: new Date(),
            },
          })
          .returning();

        // Auto-scan response body for sensitive data if provided
        let sensitiveHits: Array<{ type: string; severity: string; snippet: string }> = [];
        if (responseBody && typeof responseBody === "string") {
          sensitiveHits = scanForSensitiveData(responseBody);
          if (sensitiveHits.length > 0) {
            for (const hit of sensitiveHits) {
              await db.insert(apiFindings).values({
                orgId,
                apiId: api.id,
                findingType: "sensitive_data_exposure",
                severity: hit.severity,
                title: `Sensitive data in response: ${hit.type}`,
                description: `Response from ${method} ${path} contains ${hit.type}`,
                endpoint: `${method} ${path}`,
                method: method.toUpperCase(),
                owaspCategory: OWASP_CATEGORIES.sensitive_data_exposure,
                cweId: "CWE-200",
                evidence: { sensitiveType: hit.type, masked: hit.snippet },
              });
            }
          }
        }

        res.json({
          apiId: api.id,
          sensitiveDataDetected: sensitiveHits.length,
        });
      } catch (error) {
        log.error("Failed to ingest traffic", { error: String(error) });
        res.status(500).json({ message: "Failed to ingest traffic" });
      }
    },
  );

  // ==========================================================================
  // FINDINGS — List all API security findings
  // ==========================================================================

  app.get(
    "/api/api-security/findings",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const findingType = req.query.type as string | undefined;
        const severity = req.query.severity as string | undefined;
        const status = req.query.status as string | undefined;
        const q = (req.query.q as string) || "";
        const limitParam = parseInt(String(req.query.limit || "100"));
        const offsetParam = parseInt(String(req.query.offset || "0"));
        const limit = Math.min(Number.isNaN(limitParam) ? 100 : limitParam, 500);
        const offset = Number.isNaN(offsetParam) ? 0 : offsetParam;

        const conditions: unknown[] = [eq(apiFindings.orgId, orgId)];
        if (findingType && findingType !== "all") conditions.push(eq(apiFindings.findingType, findingType));
        if (severity && severity !== "all") conditions.push(eq(apiFindings.severity, severity));
        if (status && status !== "all") conditions.push(eq(apiFindings.status, status));
        if (q) {
          conditions.push(
            or(
              ilike(apiFindings.title, `%${q}%`),
              ilike(apiFindings.endpoint, `%${q}%`),
              ilike(apiFindings.cweId, `%${q}%`),
            ),
          );
        }

        const findings = await db
          .select()
          .from(apiFindings)
          .where(and(...(conditions as any[])))
          .orderBy(desc(apiFindings.createdAt))
          .limit(limit)
          .offset(offset);

        const [{ value: total }] = await db
          .select({ value: count() })
          .from(apiFindings)
          .where(and(...(conditions as any[])));

        // Stats
        const statsResult = await db.execute(sql`
          SELECT
            COUNT(*) AS total,
            COUNT(*) FILTER (WHERE status = 'open') AS open_count,
            COUNT(*) FILTER (WHERE severity = 'critical') AS critical_count,
            COUNT(*) FILTER (WHERE severity = 'high') AS high_count,
            COUNT(*) FILTER (WHERE severity = 'medium') AS medium_count,
            COUNT(*) FILTER (WHERE severity = 'low') AS low_count
          FROM api_findings
          WHERE org_id = ${orgId}
        `);
        const s = (statsResult as any).rows?.[0] || {};

        res.json({
          findings,
          total,
          stats: {
            total: parseInt(s.total || "0"),
            openCount: parseInt(s.open_count || "0"),
            criticalCount: parseInt(s.critical_count || "0"),
            highCount: parseInt(s.high_count || "0"),
            mediumCount: parseInt(s.medium_count || "0"),
            lowCount: parseInt(s.low_count || "0"),
          },
        });
      } catch (error) {
        log.error("Failed to list API findings", { error: String(error) });
        res.status(500).json({ message: "Failed to list API findings" });
      }
    },
  );

  // ==========================================================================
  // CREATE FINDING MANUALLY
  // ==========================================================================

  app.post(
    "/api/api-security/findings",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { apiId, findingType, severity, title, description, endpoint, method, cweId, remediation } = req.body;

        if (!title || typeof title !== "string") {
          return res.status(400).json({ message: "title is required" });
        }
        if (!findingType || !API_SECURITY_FINDING_TYPES.includes(findingType as any)) {
          return res.status(400).json({
            message: `findingType must be one of: ${API_SECURITY_FINDING_TYPES.join(", ")}`,
          });
        }
        if (severity && !API_SECURITY_FINDING_SEVERITIES.includes(severity as any)) {
          return res.status(400).json({
            message: `severity must be one of: ${API_SECURITY_FINDING_SEVERITIES.join(", ")}`,
          });
        }

        // Validate apiId belongs to org if provided
        if (apiId) {
          const [api] = await db
            .select()
            .from(apiInventory)
            .where(and(eq(apiInventory.id, apiId), eq(apiInventory.orgId, orgId)))
            .limit(1);
          if (!api) {
            return res.status(404).json({ message: "API endpoint not found" });
          }
        }

        const [finding] = await db
          .insert(apiFindings)
          .values({
            orgId,
            apiId: apiId || null,
            findingType,
            severity: severity || "medium",
            title,
            description: description || null,
            endpoint: endpoint || null,
            method: method || null,
            cweId: cweId || null,
            owaspCategory: OWASP_CATEGORIES[findingType] || null,
            remediation: remediation || null,
          })
          .returning();

        log.info(`API finding created: ${title}`, { orgId, findingId: finding.id });
        res.status(201).json(finding);
      } catch (error) {
        log.error("Failed to create finding", { error: String(error) });
        res.status(500).json({ message: "Failed to create finding" });
      }
    },
  );

  // ==========================================================================
  // UPDATE FINDING STATUS
  // ==========================================================================

  app.patch(
    "/api/api-security/findings/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const findingId = String(req.params.id);

        const [finding] = await db
          .select()
          .from(apiFindings)
          .where(and(eq(apiFindings.id, findingId), eq(apiFindings.orgId, orgId)))
          .limit(1);

        if (!finding) {
          return res.status(404).json({ message: "Finding not found" });
        }

        const { status } = req.body;
        if (!status || !API_SECURITY_FINDING_STATUSES.includes(status as any)) {
          return res.status(400).json({
            message: `status must be one of: ${API_SECURITY_FINDING_STATUSES.join(", ")}`,
          });
        }

        const updates: Record<string, unknown> = { status, updatedAt: new Date() };
        const userId = (req as any).user?.id;

        if (status === "acknowledged") {
          updates.acknowledgedBy = userId;
          updates.acknowledgedAt = new Date();
        } else if (status === "mitigated") {
          updates.mitigatedBy = userId;
          updates.mitigatedAt = new Date();
        }

        const [updated] = await db.update(apiFindings).set(updates).where(eq(apiFindings.id, findingId)).returning();

        res.json(updated);
      } catch (error) {
        log.error("Failed to update finding", { error: String(error) });
        res.status(500).json({ message: "Failed to update finding" });
      }
    },
  );

  // ==========================================================================
  // TRAFFIC BASELINES — List baselines for an API
  // ==========================================================================

  app.get(
    "/api/api-security/baselines/:apiId",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const apiId = String(req.params.apiId);

        // Verify API belongs to org
        const [api] = await db
          .select()
          .from(apiInventory)
          .where(and(eq(apiInventory.id, apiId), eq(apiInventory.orgId, orgId)))
          .limit(1);

        if (!api) {
          return res.status(404).json({ message: "API endpoint not found" });
        }

        const limitParam = parseInt(String(req.query.limit || "48"));
        const limit = Math.min(Number.isNaN(limitParam) ? 48 : limitParam, 200);

        const baselines = await db
          .select()
          .from(apiTrafficBaselines)
          .where(and(eq(apiTrafficBaselines.apiId, apiId), eq(apiTrafficBaselines.orgId, orgId)))
          .orderBy(desc(apiTrafficBaselines.windowStart))
          .limit(limit);

        res.json({ baselines, api });
      } catch (error) {
        log.error("Failed to get baselines", { error: String(error) });
        res.status(500).json({ message: "Failed to get baselines" });
      }
    },
  );

  // ==========================================================================
  // RECORD TRAFFIC BASELINE — Store a traffic snapshot
  // ==========================================================================

  app.post(
    "/api/api-security/baselines",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const {
          apiId,
          windowStart,
          windowEnd,
          requestCount,
          uniqueCallers,
          errorCount,
          avgLatencyMs,
          p95LatencyMs,
          p99LatencyMs,
          statusCodeDistribution,
          topCallerIps,
        } = req.body;

        if (!apiId || typeof apiId !== "string") {
          return res.status(400).json({ message: "apiId is required" });
        }

        // Verify API belongs to org
        const [api] = await db
          .select()
          .from(apiInventory)
          .where(and(eq(apiInventory.id, apiId), eq(apiInventory.orgId, orgId)))
          .limit(1);

        if (!api) {
          return res.status(404).json({ message: "API endpoint not found" });
        }

        // Compute anomaly score against recent baselines
        const recentBaselines = await db
          .select()
          .from(apiTrafficBaselines)
          .where(and(eq(apiTrafficBaselines.apiId, apiId), eq(apiTrafficBaselines.orgId, orgId)))
          .orderBy(desc(apiTrafficBaselines.windowStart))
          .limit(10);

        let anomalyScore = 0;
        if (recentBaselines.length > 0) {
          const avgReq = recentBaselines.reduce((s, b) => s + b.requestCount, 0) / recentBaselines.length;
          const avgErr =
            recentBaselines.reduce((s, b) => s + (b.requestCount > 0 ? b.errorCount / b.requestCount : 0), 0) /
            recentBaselines.length;
          const avgLat = recentBaselines.reduce((s, b) => s + b.avgLatencyMs, 0) / recentBaselines.length;
          const avgUni = recentBaselines.reduce((s, b) => s + b.uniqueCallers, 0) / recentBaselines.length;

          const result = detectTrafficAnomalies(
            {
              requestCount: requestCount || 0,
              uniqueCallers: uniqueCallers || 0,
              errorCount: errorCount || 0,
              avgLatencyMs: avgLatencyMs || 0,
              statusCodeDistribution: statusCodeDistribution || {},
            },
            { avgRequestCount: avgReq, avgErrorRate: avgErr, avgLatencyMs: avgLat, avgUnique: avgUni },
          );
          anomalyScore = result.anomalyScore;

          // Auto-create findings for high anomaly scores
          if (anomalyScore > 70) {
            for (const anomaly of result.anomalies) {
              const findingType =
                anomaly.metric === "unique_callers"
                  ? "credential_stuffing"
                  : anomaly.metric === "client_errors"
                    ? "scraping"
                    : "rate_abuse";
              await db.insert(apiFindings).values({
                orgId,
                apiId,
                findingType,
                severity: anomalyScore > 85 ? "critical" : "high",
                title: `Traffic anomaly: ${anomaly.description}`,
                description: `Anomaly detected on ${api.method} ${api.path}: ${anomaly.description}`,
                endpoint: `${api.method} ${api.path}`,
                method: api.method,
                owaspCategory: OWASP_CATEGORIES[findingType] || null,
                evidence: { anomaly, anomalyScore },
              });
            }
          }
        }

        const [baseline] = await db
          .insert(apiTrafficBaselines)
          .values({
            orgId,
            apiId,
            windowStart: windowStart ? new Date(windowStart) : new Date(Date.now() - 3600000),
            windowEnd: windowEnd ? new Date(windowEnd) : new Date(),
            requestCount: requestCount || 0,
            uniqueCallers: uniqueCallers || 0,
            errorCount: errorCount || 0,
            avgLatencyMs: avgLatencyMs || 0,
            p95LatencyMs: p95LatencyMs || 0,
            p99LatencyMs: p99LatencyMs || 0,
            statusCodeDistribution: statusCodeDistribution || {},
            topCallerIps: topCallerIps || [],
            anomalyScore,
          })
          .returning();

        res.status(201).json(baseline);
      } catch (error) {
        log.error("Failed to record baseline", { error: String(error) });
        res.status(500).json({ message: "Failed to record baseline" });
      }
    },
  );

  // ==========================================================================
  // RISK RECALCULATION — Recalculate risk scores for all APIs
  // ==========================================================================

  app.post(
    "/api/api-security/recalculate-risk",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);

        const apis = await db.select().from(apiInventory).where(eq(apiInventory.orgId, orgId));

        let updated = 0;
        for (const api of apis) {
          // Count open findings
          const [{ value: openFindings }] = await db
            .select({ value: count() })
            .from(apiFindings)
            .where(and(eq(apiFindings.apiId, api.id), eq(apiFindings.orgId, orgId), eq(apiFindings.status, "open")));

          const riskScore = computeApiRiskScore({
            authType: api.authType,
            isShadow: api.isShadow,
            isDeprecated: api.isDeprecated,
            errorRate24h: api.errorRate24h,
            sensitiveDataTypes: api.sensitiveDataTypes,
            openFindings: Number(openFindings),
          });

          await db.update(apiInventory).set({ riskScore, updatedAt: new Date() }).where(eq(apiInventory.id, api.id));

          updated++;
        }

        log.info(`Risk scores recalculated for ${updated} APIs`, { orgId });
        res.json({ message: `Recalculated risk scores for ${updated} APIs`, updated });
      } catch (error) {
        log.error("Failed to recalculate risk", { error: String(error) });
        res.status(500).json({ message: "Failed to recalculate risk" });
      }
    },
  );

  // ==========================================================================
  // DAST SCAN TRIGGER — Trigger a DAST scan for an API
  // ==========================================================================

  app.post(
    "/api/api-security/dast-scan",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { apiId, scanType } = req.body;

        if (!apiId || typeof apiId !== "string") {
          return res.status(400).json({ message: "apiId is required" });
        }

        const validScanTypes = ["quick", "full", "auth_test", "injection_test"];
        if (scanType && !validScanTypes.includes(scanType)) {
          return res.status(400).json({ message: `scanType must be one of: ${validScanTypes.join(", ")}` });
        }

        // Verify API belongs to org
        const [api] = await db
          .select()
          .from(apiInventory)
          .where(and(eq(apiInventory.id, apiId), eq(apiInventory.orgId, orgId)))
          .limit(1);

        if (!api) {
          return res.status(404).json({ message: "API endpoint not found" });
        }

        // Simulate DAST scan results based on API characteristics
        const scanFindings: Array<{ type: string; severity: string; title: string; cwe: string; remediation: string }> =
          [];

        // Check for no-auth endpoints
        if (api.authType === "none") {
          scanFindings.push({
            type: "broken_auth",
            severity: "critical",
            title: `No authentication on ${api.method} ${api.path}`,
            cwe: "CWE-306",
            remediation: "Add authentication (OAuth2, API Key, or Bearer token) to this endpoint",
          });
        }

        // Check for potential BOLA patterns (ID in path)
        if (/\/:?[a-z]*id/i.test(api.path) || /\/\d+/.test(api.path)) {
          scanFindings.push({
            type: "bola",
            severity: "high",
            title: `Potential BOLA vulnerability on ${api.method} ${api.path}`,
            cwe: "CWE-639",
            remediation: "Ensure object-level authorization checks verify the requesting user owns the resource",
          });
        }

        // Check for mutation endpoints without proper auth
        if (
          ["POST", "PUT", "PATCH", "DELETE"].includes(api.method) &&
          api.authType !== "oauth2" &&
          api.authType !== "mtls"
        ) {
          scanFindings.push({
            type: "bfla",
            severity: "medium",
            title: `Mutation endpoint may lack function-level auth: ${api.method} ${api.path}`,
            cwe: "CWE-285",
            remediation: "Implement role-based access control on mutation endpoints",
          });
        }

        // Create findings in DB
        for (const sf of scanFindings) {
          await db.insert(apiFindings).values({
            orgId,
            apiId,
            findingType: sf.type,
            severity: sf.severity,
            title: sf.title,
            description: `DAST scan (${scanType || "quick"}) detected: ${sf.title}`,
            endpoint: `${api.method} ${api.path}`,
            method: api.method,
            cweId: sf.cwe,
            owaspCategory: OWASP_CATEGORIES[sf.type] || null,
            remediation: sf.remediation,
            metadata: { scanType: scanType || "quick", scannedAt: new Date().toISOString() },
          });
        }

        log.info(`DAST scan completed: ${scanFindings.length} findings`, { orgId, apiId });
        res.json({
          message: `DAST scan complete: ${scanFindings.length} findings`,
          findingsCount: scanFindings.length,
          findings: scanFindings,
        });
      } catch (error) {
        log.error("Failed to run DAST scan", { error: String(error) });
        res.status(500).json({ message: "Failed to run DAST scan" });
      }
    },
  );

  // ==========================================================================
  // API TRAFFIC MONITORING (real-time metrics)
  // ==========================================================================

  app.get(
    "/api/api-security/traffic-monitor",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const windowHours = parseInt(String(req.query.hours || "24"));
        const hours = Math.min(Number.isNaN(windowHours) ? 24 : windowHours, 168);
        const since = new Date(Date.now() - hours * 3600000);

        // Aggregate traffic metrics across all APIs
        const apis = await db.select().from(apiInventory).where(eq(apiInventory.orgId, orgId));

        let totalRequests = 0;
        let totalErrors = 0;
        let totalLatency = 0;
        let apiCount = 0;
        const authSuccess: Record<string, number> = { authenticated: 0, unauthenticated: 0 };
        const methodBreakdown: Record<string, number> = {};
        const errorCodeBreakdown: Record<string, number> = {};
        const topEndpoints: Array<{
          method: string;
          path: string;
          host: string;
          requestCount: number;
          errorRate: number;
          avgLatency: number;
        }> = [];

        for (const api of apis) {
          apiCount++;
          totalRequests += api.requestCount24h;
          const errors = Math.round(api.errorRate24h * api.requestCount24h);
          totalErrors += errors;
          totalLatency += api.avgLatencyMs * api.requestCount24h;

          // Auth breakdown
          if (api.authType === "none") {
            authSuccess.unauthenticated += api.requestCount24h;
          } else {
            authSuccess.authenticated += api.requestCount24h;
          }

          // Method breakdown
          methodBreakdown[api.method] = (methodBreakdown[api.method] || 0) + api.requestCount24h;

          topEndpoints.push({
            method: api.method,
            path: api.path,
            host: api.host,
            requestCount: api.requestCount24h,
            errorRate: api.errorRate24h,
            avgLatency: api.avgLatencyMs,
          });
        }

        // Sort top endpoints by request count
        topEndpoints.sort((a, b) => b.requestCount - a.requestCount);

        // Get recent baselines for trend data
        const recentBaselines = await db
          .select()
          .from(apiTrafficBaselines)
          .where(and(eq(apiTrafficBaselines.orgId, orgId), sql`${apiTrafficBaselines.windowStart} >= ${since}`))
          .orderBy(desc(apiTrafficBaselines.windowStart))
          .limit(200);

        // Compute status code distribution from baselines
        for (const bl of recentBaselines) {
          const dist = bl.statusCodeDistribution as Record<string, number> | null;
          if (dist) {
            for (const [code, cnt] of Object.entries(dist)) {
              errorCodeBreakdown[code] = (errorCodeBreakdown[code] || 0) + Number(cnt);
            }
          }
        }

        const avgLatency = totalRequests > 0 ? totalLatency / totalRequests : 0;
        const overallErrorRate = totalRequests > 0 ? totalErrors / totalRequests : 0;

        res.json({
          windowHours: hours,
          apiCount,
          totalRequests,
          totalErrors,
          overallErrorRate,
          avgLatencyMs: Math.round(avgLatency * 100) / 100,
          authBreakdown: authSuccess,
          methodBreakdown,
          errorCodeBreakdown,
          topEndpoints: topEndpoints.slice(0, 20),
          baselineCount: recentBaselines.length,
          anomalies: recentBaselines.filter((b) => b.anomalyScore > 50).length,
        });
      } catch (error) {
        log.error("Failed to get traffic monitor data", { error: String(error) });
        res.status(500).json({ message: "Failed to get traffic monitor data" });
      }
    },
  );

  // ==========================================================================
  // ENHANCED DAST SCANNING ENGINE
  // ==========================================================================

  app.post(
    "/api/api-security/dast-scan-full",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { apiId, scanType, testCategories } = req.body;

        if (!apiId || typeof apiId !== "string") {
          return res.status(400).json({ message: "apiId is required" });
        }

        const validScanTypes = ["quick", "full", "auth_test", "injection_test", "comprehensive"];
        if (scanType && !validScanTypes.includes(scanType)) {
          return res.status(400).json({ message: `scanType must be one of: ${validScanTypes.join(", ")}` });
        }

        // Verify API belongs to org
        const [api] = await db
          .select()
          .from(apiInventory)
          .where(and(eq(apiInventory.id, apiId), eq(apiInventory.orgId, orgId)))
          .limit(1);

        if (!api) {
          return res.status(404).json({ message: "API endpoint not found" });
        }

        // DAST test categories
        const allCategories = [
          {
            category: "sql_injection",
            label: "SQL Injection",
            cwe: "CWE-89",
            owasp: "API8:2023 Security Misconfiguration",
            test: () => {
              // Check for dynamic path segments that could be injectable
              if (/\/:?\w*id/i.test(api.path) || /\/\d+/.test(api.path)) {
                return {
                  vulnerable: true,
                  title: `Potential SQL injection on ${api.method} ${api.path}`,
                  remediation:
                    "Use parameterized queries. Validate and sanitize all user input. Implement input whitelisting.",
                  severity: "critical" as const,
                };
              }
              return null;
            },
          },
          {
            category: "xss",
            label: "Cross-Site Scripting (XSS)",
            cwe: "CWE-79",
            owasp: "API8:2023 Security Misconfiguration",
            test: () => {
              if (["POST", "PUT", "PATCH"].includes(api.method)) {
                return {
                  vulnerable: true,
                  title: `Potential reflected XSS on ${api.method} ${api.path}`,
                  remediation:
                    "Encode all output. Use Content-Security-Policy headers. Validate input against an allowlist.",
                  severity: "high" as const,
                };
              }
              return null;
            },
          },
          {
            category: "ssrf",
            label: "Server-Side Request Forgery (SSRF)",
            cwe: "CWE-918",
            owasp: "API7:2023 Server Side Request Forgery",
            test: () => {
              if (/url|uri|link|redirect|callback|webhook/i.test(api.path)) {
                return {
                  vulnerable: true,
                  title: `Potential SSRF on ${api.method} ${api.path}`,
                  remediation:
                    "Validate and sanitize all URLs. Use allowlists for permitted domains. Block internal IP ranges (10.x, 172.16-31.x, 192.168.x).",
                  severity: "critical" as const,
                };
              }
              return null;
            },
          },
          {
            category: "auth_bypass",
            label: "Authentication Bypass",
            cwe: "CWE-287",
            owasp: "API2:2023 Broken Authentication",
            test: () => {
              if (api.authType === "none") {
                return {
                  vulnerable: true,
                  title: `No authentication on ${api.method} ${api.path}`,
                  remediation:
                    "Add authentication (OAuth2, API Key, or Bearer token). Implement rate limiting. Use HTTPS only.",
                  severity: "critical" as const,
                };
              }
              if (api.authType === "api_key" && ["DELETE", "PUT", "PATCH"].includes(api.method)) {
                return {
                  vulnerable: true,
                  title: `Weak auth (API key) on mutation endpoint ${api.method} ${api.path}`,
                  remediation:
                    "Upgrade to OAuth2 or mTLS for mutation endpoints. API keys should be used for read-only access.",
                  severity: "medium" as const,
                };
              }
              return null;
            },
          },
          {
            category: "authz_flaws",
            label: "Authorization Flaws (BOLA/BFLA)",
            cwe: "CWE-639",
            owasp: "API1:2023 Broken Object Level Authorization",
            test: () => {
              const findings = [];
              if (/\/:?[a-z]*id/i.test(api.path) || /\/\d+/.test(api.path)) {
                findings.push({
                  vulnerable: true,
                  title: `Potential BOLA on ${api.method} ${api.path} — object ID in path`,
                  remediation:
                    "Implement object-level authorization. Verify the requesting user owns or has access to the resource.",
                  severity: "high" as const,
                });
              }
              if (
                ["POST", "PUT", "PATCH", "DELETE"].includes(api.method) &&
                api.authType !== "oauth2" &&
                api.authType !== "mtls"
              ) {
                findings.push({
                  vulnerable: true,
                  title: `Potential BFLA on ${api.method} ${api.path} — mutation without strong auth`,
                  remediation:
                    "Implement function-level authorization with RBAC. Verify user roles before allowing mutations.",
                  severity: "medium" as const,
                });
              }
              return findings.length > 0 ? findings : null;
            },
          },
        ];

        // Filter categories if specified
        const categoriesToRun =
          testCategories && Array.isArray(testCategories)
            ? allCategories.filter((c) => testCategories.includes(c.category))
            : allCategories;

        const scanResults: Array<{
          category: string;
          label: string;
          cwe: string;
          owasp: string;
          severity: string;
          title: string;
          remediation: string;
        }> = [];

        for (const cat of categoriesToRun) {
          const result = cat.test();
          if (result) {
            const items = Array.isArray(result) ? result : [result];
            for (const item of items) {
              if (item && item.vulnerable) {
                scanResults.push({
                  category: cat.category,
                  label: cat.label,
                  cwe: cat.cwe,
                  owasp: cat.owasp,
                  severity: item.severity,
                  title: item.title,
                  remediation: item.remediation,
                });

                // Persist finding to DB
                await db.insert(apiFindings).values({
                  orgId,
                  apiId,
                  findingType: cat.category === "authz_flaws" ? "bola" : cat.category,
                  severity: item.severity,
                  title: item.title,
                  description: `DAST comprehensive scan (${scanType || "full"}) detected: ${item.title}`,
                  endpoint: `${api.method} ${api.path}`,
                  method: api.method,
                  cweId: cat.cwe,
                  owaspCategory: cat.owasp,
                  remediation: item.remediation,
                  metadata: {
                    scanType: scanType || "full",
                    category: cat.category,
                    scannedAt: new Date().toISOString(),
                  },
                });
              }
            }
          }
        }

        log.info(`DAST full scan completed: ${scanResults.length} findings`, { orgId, apiId });
        res.json({
          message: `DAST comprehensive scan complete: ${scanResults.length} findings`,
          endpoint: `${api.method} ${api.path}`,
          categoriesTested: categoriesToRun.map((c) => c.label),
          findingsCount: scanResults.length,
          findings: scanResults,
          summary: {
            critical: scanResults.filter((r) => r.severity === "critical").length,
            high: scanResults.filter((r) => r.severity === "high").length,
            medium: scanResults.filter((r) => r.severity === "medium").length,
            low: scanResults.filter((r) => r.severity === "low").length,
          },
        });
      } catch (error) {
        log.error("Failed to run DAST full scan", { error: String(error) });
        res.status(500).json({ message: "Failed to run DAST full scan" });
      }
    },
  );

  // ==========================================================================
  // UPDATE API ENDPOINT — Mark deprecated, change auth type, etc.
  // ==========================================================================

  app.patch(
    "/api/api-security/inventory/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const apiId = String(req.params.id);

        const [api] = await db
          .select()
          .from(apiInventory)
          .where(and(eq(apiInventory.id, apiId), eq(apiInventory.orgId, orgId)))
          .limit(1);

        if (!api) {
          return res.status(404).json({ message: "API endpoint not found" });
        }

        const allowedFields = ["authType", "isDeprecated", "isShadow", "version", "tags"];
        const updates: Record<string, unknown> = { updatedAt: new Date() };

        for (const field of allowedFields) {
          if (req.body[field] !== undefined) {
            if (field === "authType" && !API_AUTH_TYPES.includes(req.body[field] as any)) {
              return res.status(400).json({
                message: `authType must be one of: ${API_AUTH_TYPES.join(", ")}`,
              });
            }
            updates[field] = req.body[field];
          }
        }

        const [updated] = await db.update(apiInventory).set(updates).where(eq(apiInventory.id, apiId)).returning();

        res.json(updated);
      } catch (error) {
        log.error("Failed to update API endpoint", { error: String(error) });
        res.status(500).json({ message: "Failed to update API endpoint" });
      }
    },
  );
}

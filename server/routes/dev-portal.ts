import type { Express, Request, Response } from "express";
import { lookup } from "dns/promises";
import { isAuthenticated } from "../auth";
import { requireSuperAdmin } from "../middleware/super-admin";
import { sendEnvelope } from "./shared";
import { db, getPoolHealth, checkPoolConnectivity } from "../db";
import { sql } from "drizzle-orm";
import { logger } from "../logger";
import { config } from "../config";
import { buildOpenApiSpec } from "../openapi";

const log = logger.child("dev-portal");

const BLOCKED_HOSTS = new Set([
  "localhost",
  "127.0.0.1",
  "::1",
  "0.0.0.0",
  "[::1]",
  "169.254.169.254",
  "metadata.google.internal",
]);

function isPrivateIp(hostname: string): boolean {
  if (BLOCKED_HOSTS.has(hostname.toLowerCase())) return true;
  let normalized = hostname.replace(/^\[|\]$/g, "");
  if (/^::ffff:/i.test(normalized)) {
    normalized = normalized.replace(/^::ffff:/i, "");
  }
  if (/^127\./.test(normalized)) return true;
  if (/^0\./.test(normalized)) return true;
  if (/^10\./.test(normalized)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(normalized)) return true;
  if (/^192\.168\./.test(normalized)) return true;
  if (/^169\.254\./.test(normalized)) return true;
  if (/^fc00:|^fd/i.test(normalized)) return true;
  if (/^fe80:/i.test(normalized)) return true;
  if (/^::$/i.test(normalized)) return true;
  if (/^::1$/i.test(normalized)) return true;
  return false;
}

const MAX_QUERY_ROWS = 500;
const DEFAULT_QUERY_ROWS = 100;
const MAX_WHERE_CLAUSES = 20;
const MAX_IN_VALUES = 200;

export function registerDevPortalRoutes(app: Express): void {
  app.get("/api/dev-portal/openapi", isAuthenticated, requireSuperAdmin, (_req: Request, res: Response) => {
    try {
      const spec = buildOpenApiSpec();
      res.json(spec);
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      log.error("Failed to build OpenAPI spec", { error: message });
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "OPENAPI_FAILED", message: "Failed to generate OpenAPI spec" }],
      });
    }
  });

  app.get("/api/dev-portal/openapi/summary", isAuthenticated, requireSuperAdmin, (_req: Request, res: Response) => {
    try {
      const spec = buildOpenApiSpec();
      const paths = spec.paths || {};
      const tags = new Map<string, { endpoints: number; methods: string[] }>();

      for (const [path, methods] of Object.entries(paths)) {
        for (const [method, operation] of Object.entries(methods as Record<string, any>)) {
          const opTags = operation.tags || ["Untagged"];
          for (const tag of opTags) {
            const existing = tags.get(tag) || { endpoints: 0, methods: [] };
            existing.endpoints++;
            if (!existing.methods.includes(method.toUpperCase())) {
              existing.methods.push(method.toUpperCase());
            }
            tags.set(tag, existing);
          }
        }
      }

      const totalEndpoints = Object.keys(paths).length;
      const totalOperations = Object.values(paths).reduce(
        (sum, methods) => sum + Object.keys(methods as object).length,
        0,
      );

      return sendEnvelope(res, {
        totalEndpoints,
        totalOperations,
        tags: Array.from(tags.entries()).map(([name, data]) => ({
          name,
          ...data,
        })),
      });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      log.error("Failed to build OpenAPI summary", { error: message });
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "OPENAPI_SUMMARY_FAILED", message: "Failed to generate API summary" }],
      });
    }
  });

  app.post(
    "/api/dev-portal/api-playground",
    isAuthenticated,
    requireSuperAdmin,
    async (req: Request, res: Response) => {
      try {
        const { method, path, body, headers: customHeaders } = req.body;
        if (!method || !path) {
          return sendEnvelope(res, null, {
            status: 400,
            errors: [{ code: "MISSING_PARAMS", message: "method and path are required" }],
          });
        }

        const allowedMethods = ["GET", "POST", "PUT", "PATCH", "DELETE"];
        const upperMethod = String(method).toUpperCase();
        if (!allowedMethods.includes(upperMethod)) {
          return sendEnvelope(res, null, {
            status: 400,
            errors: [{ code: "INVALID_METHOD", message: `Method must be one of: ${allowedMethods.join(", ")}` }],
          });
        }

        const sanitizedPath = String(path);
        if (!sanitizedPath.startsWith("/api/")) {
          return sendEnvelope(res, null, {
            status: 400,
            errors: [{ code: "INVALID_PATH", message: "Path must start with /api/" }],
          });
        }

        if (/\.\.|%2e%2e|%00/i.test(sanitizedPath)) {
          return sendEnvelope(res, null, {
            status: 400,
            errors: [{ code: "INVALID_PATH", message: "Path contains invalid characters" }],
          });
        }

        const url = `http://127.0.0.1:${config.port}${sanitizedPath}`;

        const fetchHeaders: Record<string, string> = {
          "Content-Type": "application/json",
          Cookie: req.headers.cookie || "",
        };

        const csrfToken = req.headers["x-csrf-token"] as string;
        if (csrfToken) {
          fetchHeaders["X-CSRF-Token"] = csrfToken;
        }

        const orgIdHeader = req.headers["x-org-id"] as string;
        if (orgIdHeader) {
          fetchHeaders["X-Org-Id"] = orgIdHeader;
        }

        if (customHeaders && typeof customHeaders === "object") {
          const safeHeaders = ["X-Api-Key", "X-Idempotency-Key", "Accept"];
          for (const key of safeHeaders) {
            if (customHeaders[key]) {
              fetchHeaders[key] = String(customHeaders[key]);
            }
          }
        }

        const startTime = Date.now();
        const fetchOptions: RequestInit = {
          method: upperMethod,
          headers: fetchHeaders,
        };
        if (body && upperMethod !== "GET" && upperMethod !== "HEAD") {
          fetchOptions.body = JSON.stringify(body);
        }

        const response = await fetch(url, fetchOptions);
        const elapsed = Date.now() - startTime;

        let responseBody: unknown;
        const contentType = response.headers.get("content-type") || "";
        if (contentType.includes("application/json")) {
          responseBody = await response.json();
        } else {
          responseBody = await response.text();
        }

        const responseHeaders: Record<string, string> = {};
        response.headers.forEach((value, key) => {
          responseHeaders[key] = value;
        });

        return sendEnvelope(res, {
          status: response.status,
          statusText: response.statusText,
          headers: responseHeaders,
          body: responseBody,
          elapsed,
        });
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        log.error("API playground request failed", { error: message });
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "PLAYGROUND_FAILED", message: `Request failed: ${message}` }],
        });
      }
    },
  );

  app.get(
    "/api/dev-portal/webhooks/recent",
    isAuthenticated,
    requireSuperAdmin,
    async (_req: Request, res: Response) => {
      try {
        const logs = await db.execute(
          sql`SELECT owl.id, owl.webhook_id, owl.event, owl.response_status, owl.success, owl.created_at,
                   ow.url, ow.org_id
            FROM outbound_webhook_logs owl
            LEFT JOIN outbound_webhooks ow ON owl.webhook_id = ow.id
            ORDER BY owl.created_at DESC
            LIMIT 50`,
        );
        return sendEnvelope(res, logs.rows || []);
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        log.error("Failed to fetch webhook logs", { error: message });
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "WEBHOOK_LOGS_FAILED", message: "Failed to fetch webhook logs" }],
        });
      }
    },
  );

  app.post("/api/dev-portal/webhooks/test", isAuthenticated, requireSuperAdmin, async (req: Request, res: Response) => {
    try {
      const { url: rawUrl, event, payload } = req.body;
      if (!rawUrl || !event) {
        return sendEnvelope(res, null, {
          status: 400,
          errors: [{ code: "MISSING_PARAMS", message: "url and event are required" }],
        });
      }

      let parsedUrl: URL;
      try {
        parsedUrl = new URL(String(rawUrl));
      } catch {
        return sendEnvelope(res, null, {
          status: 400,
          errors: [{ code: "INVALID_URL", message: "Invalid URL format" }],
        });
      }

      if (!parsedUrl.protocol.startsWith("https")) {
        return sendEnvelope(res, null, {
          status: 400,
          errors: [{ code: "HTTPS_REQUIRED", message: "Only HTTPS URLs are allowed for webhook testing" }],
        });
      }

      if (isPrivateIp(parsedUrl.hostname)) {
        return sendEnvelope(res, null, {
          status: 400,
          errors: [{ code: "PRIVATE_IP_BLOCKED", message: "Requests to private/internal IPs are not allowed" }],
        });
      }

      try {
        const resolved = await lookup(parsedUrl.hostname, { all: true, verbatim: true });
        if (resolved.some((r) => isPrivateIp(r.address))) {
          return sendEnvelope(res, null, {
            status: 400,
            errors: [{ code: "PRIVATE_IP_BLOCKED", message: "URL resolves to a private/internal IP" }],
          });
        }
      } catch {
        return sendEnvelope(res, null, {
          status: 400,
          errors: [{ code: "DNS_FAILED", message: "Failed to resolve hostname" }],
        });
      }

      const url = parsedUrl.toString();

      const testPayload = payload || {
        event,
        timestamp: new Date().toISOString(),
        test: true,
        data: { message: "This is a test webhook delivery from SecureNexus Dev Portal" },
      };

      const startTime = Date.now();
      const response = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(testPayload),
        signal: AbortSignal.timeout(10000),
      });
      const elapsed = Date.now() - startTime;

      let responseBody: string;
      try {
        responseBody = await response.text();
      } catch {
        responseBody = "(unable to read response body)";
      }

      return sendEnvelope(res, {
        success: response.ok,
        status: response.status,
        statusText: response.statusText,
        elapsed,
        responseBody: responseBody.slice(0, 2000),
      });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      return sendEnvelope(res, {
        success: false,
        status: 0,
        statusText: "Connection Failed",
        elapsed: 0,
        responseBody: message,
      });
    }
  });

  app.get("/api/dev-portal/db/tables", isAuthenticated, requireSuperAdmin, async (_req: Request, res: Response) => {
    try {
      const result = await db.execute(
        sql`SELECT
              t.table_name,
              pg_size_pretty(pg_total_relation_size(quote_ident(t.table_name))) as total_size,
              pg_total_relation_size(quote_ident(t.table_name)) as size_bytes,
              (SELECT reltuples::bigint FROM pg_class WHERE relname = t.table_name) as estimated_rows
            FROM information_schema.tables t
            WHERE t.table_schema = 'public'
              AND t.table_type = 'BASE TABLE'
            ORDER BY pg_total_relation_size(quote_ident(t.table_name)) DESC`,
      );
      return sendEnvelope(res, result.rows || []);
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      log.error("Failed to fetch table info", { error: message });
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "DB_TABLES_FAILED", message: "Failed to fetch table info" }],
      });
    }
  });

  app.get(
    "/api/dev-portal/db/table/:name/schema",
    isAuthenticated,
    requireSuperAdmin,
    async (req: Request, res: Response) => {
      try {
        const tableName = String(req.params.name || "");
        if (!tableName || !/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(tableName)) {
          return sendEnvelope(res, null, {
            status: 400,
            errors: [{ code: "INVALID_TABLE", message: "Invalid table name" }],
          });
        }

        const columns = await db.execute(
          sql`SELECT column_name, data_type, is_nullable, column_default, character_maximum_length
            FROM information_schema.columns
            WHERE table_schema = 'public' AND table_name = ${tableName}
            ORDER BY ordinal_position`,
        );

        const indexes = await db.execute(
          sql`SELECT indexname, indexdef
            FROM pg_indexes
            WHERE schemaname = 'public' AND tablename = ${tableName}`,
        );

        return sendEnvelope(res, {
          tableName,
          columns: columns.rows || [],
          indexes: indexes.rows || [],
        });
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        log.error("Failed to fetch table schema", { error: message });
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "DB_SCHEMA_FAILED", message: "Failed to fetch table schema" }],
        });
      }
    },
  );

  app.post("/api/dev-portal/db/query", isAuthenticated, requireSuperAdmin, async (req: Request, res: Response) => {
    try {
      const { table, where, limit, offset, orderBy, orderDir } = req.body as {
        table?: unknown;
        where?: unknown;
        limit?: unknown;
        offset?: unknown;
        orderBy?: unknown;
        orderDir?: unknown;
      };

      const tableName = String(table || "");
      if (!tableName || !/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(tableName)) {
        return sendEnvelope(res, null, {
          status: 400,
          errors: [{ code: "INVALID_TABLE", message: "Invalid table name" }],
        });
      }

      const limitNumberRaw = Number(limit ?? DEFAULT_QUERY_ROWS);
      const limitNumber = Number.isFinite(limitNumberRaw)
        ? Math.max(1, Math.min(MAX_QUERY_ROWS, Math.floor(limitNumberRaw)))
        : DEFAULT_QUERY_ROWS;

      const offsetNumberRaw = Number(offset ?? 0);
      const offsetNumber = Number.isFinite(offsetNumberRaw) ? Math.max(0, Math.floor(offsetNumberRaw)) : 0;

      const orderByColumn = orderBy ? String(orderBy) : null;
      const orderDirection = String(orderDir || "desc").toLowerCase() === "asc" ? "ASC" : "DESC";

      const existsResult = await db.execute(
        sql`SELECT 1
            FROM information_schema.tables
            WHERE table_schema = 'public'
              AND table_type = 'BASE TABLE'
              AND table_name = ${tableName}
            LIMIT 1`,
      );

      if (!existsResult.rows?.length) {
        return sendEnvelope(res, null, {
          status: 404,
          errors: [{ code: "TABLE_NOT_FOUND", message: "Table not found" }],
        });
      }

      const columnsResult = await db.execute(
        sql`SELECT column_name
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = ${tableName}`,
      );

      const validColumns = new Set(
        (columnsResult.rows || []).map((row) => String((row as { column_name: unknown }).column_name)),
      );

      if (orderByColumn && !validColumns.has(orderByColumn)) {
        return sendEnvelope(res, null, {
          status: 400,
          errors: [{ code: "INVALID_ORDER_BY", message: "Invalid orderBy column" }],
        });
      }

      const whereClauses = Array.isArray(where) ? where : [];
      if (whereClauses.length > MAX_WHERE_CLAUSES) {
        return sendEnvelope(res, null, {
          status: 400,
          errors: [{ code: "TOO_MANY_FILTERS", message: `Too many filters (max ${MAX_WHERE_CLAUSES})` }],
        });
      }

      const conditionSql: any[] = [];

      for (const clause of whereClauses) {
        if (!clause || typeof clause !== "object") {
          return sendEnvelope(res, null, {
            status: 400,
            errors: [{ code: "INVALID_FILTER", message: "Invalid filter clause" }],
          });
        }

        const column = String((clause as any).column || "");
        const op = String((clause as any).op || "=").toLowerCase();
        const value = (clause as any).value as unknown;

        if (!column || !validColumns.has(column)) {
          return sendEnvelope(res, null, {
            status: 400,
            errors: [{ code: "INVALID_FILTER_COLUMN", message: "Invalid filter column" }],
          });
        }

        const col = sql.identifier(column);

        if (value === null || value === undefined) {
          if (op === "=" || op === "eq") {
            conditionSql.push(sql`${col} IS NULL`);
            continue;
          }
          if (op === "!=" || op === "neq") {
            conditionSql.push(sql`${col} IS NOT NULL`);
            continue;
          }

          return sendEnvelope(res, null, {
            status: 400,
            errors: [{ code: "INVALID_FILTER", message: "NULL filters only support = or !=" }],
          });
        }

        if (op === "in") {
          if (!Array.isArray(value) || value.length === 0 || value.length > MAX_IN_VALUES) {
            return sendEnvelope(res, null, {
              status: 400,
              errors: [
                { code: "INVALID_FILTER", message: `IN filters must be a non-empty array (max ${MAX_IN_VALUES})` },
              ],
            });
          }

          if (value.some((v) => typeof v === "object")) {
            return sendEnvelope(res, null, {
              status: 400,
              errors: [{ code: "INVALID_FILTER", message: "IN filter values must be primitives" }],
            });
          }

          conditionSql.push(sql`${col} = ANY(${value as any})`);
          continue;
        }

        if (typeof value === "object") {
          return sendEnvelope(res, null, {
            status: 400,
            errors: [{ code: "INVALID_FILTER", message: "Filter value must be a primitive" }],
          });
        }

        if (op === "=" || op === "eq") {
          conditionSql.push(sql`${col} = ${value}`);
        } else if (op === "!=" || op === "neq") {
          conditionSql.push(sql`${col} <> ${value}`);
        } else if (op === ">" || op === "gt") {
          conditionSql.push(sql`${col} > ${value}`);
        } else if (op === ">=" || op === "gte") {
          conditionSql.push(sql`${col} >= ${value}`);
        } else if (op === "<" || op === "lt") {
          conditionSql.push(sql`${col} < ${value}`);
        } else if (op === "<=" || op === "lte") {
          conditionSql.push(sql`${col} <= ${value}`);
        } else if (op === "like") {
          conditionSql.push(sql`${col} LIKE ${String(value)}`);
        } else if (op === "ilike") {
          conditionSql.push(sql`${col} ILIKE ${String(value)}`);
        } else {
          return sendEnvelope(res, null, {
            status: 400,
            errors: [{ code: "INVALID_FILTER", message: `Unsupported operator: ${op}` }],
          });
        }
      }

      const whereSql = conditionSql.length ? sql` WHERE ${sql.join(conditionSql, sql` AND `)}` : sql``;
      const orderSql = orderByColumn
        ? sql` ORDER BY ${sql.identifier(orderByColumn)} ${sql.raw(orderDirection)}`
        : sql``;

      log.info("Dev portal DB query executed", {
        userId: (req as any).user?.id,
        table: tableName,
        limit: limitNumber,
        offset: offsetNumber,
        orderBy: orderByColumn,
        orderDir: orderDirection,
        filters: conditionSql.length,
      });

      const startTime = Date.now();
      const result = await db.execute(
        sql`SELECT * FROM ${sql.identifier(tableName)}${whereSql}${orderSql} LIMIT ${limitNumber} OFFSET ${offsetNumber}`,
      );
      const elapsed = Date.now() - startTime;

      const rows = result.rows || [];

      return sendEnvelope(res, {
        rows,
        rowCount: rows.length,
        elapsed,
        truncated: limitNumber === MAX_QUERY_ROWS && rows.length >= MAX_QUERY_ROWS,
      });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      return sendEnvelope(res, null, {
        status: 400,
        errors: [{ code: "QUERY_ERROR", message: message }],
      });
    }
  });

  app.get("/api/dev-portal/config", isAuthenticated, requireSuperAdmin, async (_req: Request, res: Response) => {
    try {
      const safeConfig: Record<string, unknown> = {
        nodeEnv: config.nodeEnv,
        port: config.port,
        sessionSecret: "••••••••",
        databaseUrl: config.databaseUrl ? "••••••••(set)" : "(not set)",
        awsRegion: config.aws.region,
        aiBackend: config.ai.backend,
        aiModelId: config.ai.modelId,
      };

      let featureFlags: unknown[] = [];
      try {
        const ffResult = await db.execute(
          sql`SELECT key, name, enabled, rollout_pct, created_at FROM feature_flags ORDER BY key`,
        );
        featureFlags = ffResult.rows || [];
      } catch {
        featureFlags = [];
      }

      const poolHealth = getPoolHealth();

      return sendEnvelope(res, {
        config: safeConfig,
        featureFlags,
        pool: poolHealth,
        runtime: {
          nodeVersion: process.version,
          platform: process.platform,
          arch: process.arch,
          uptime: process.uptime(),
          memoryUsage: process.memoryUsage(),
          pid: process.pid,
        },
      });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      log.error("Failed to fetch config", { error: message });
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "CONFIG_FAILED", message: "Failed to fetch configuration" }],
      });
    }
  });

  app.get("/api/dev-portal/deployment", isAuthenticated, requireSuperAdmin, async (_req: Request, res: Response) => {
    try {
      const dbConnectivity = await checkPoolConnectivity();
      const poolHealth = getPoolHealth();

      let dbVersion = "unknown";
      try {
        const vResult = await db.execute(sql`SELECT version()`);
        dbVersion = String((vResult.rows?.[0] as any)?.version || "unknown");
      } catch {
        dbVersion = "unavailable";
      }

      let tableCount = 0;
      try {
        const tcResult = await db.execute(
          sql`SELECT count(*) as cnt FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE'`,
        );
        tableCount = Number((tcResult.rows?.[0] as any)?.cnt || 0);
      } catch {
        tableCount = 0;
      }

      return sendEnvelope(res, {
        application: {
          name: "SecureNexus",
          version: "1.0.0",
          environment: config.nodeEnv,
          uptime: process.uptime(),
          startedAt: new Date(Date.now() - process.uptime() * 1000).toISOString(),
          nodeVersion: process.version,
          pid: process.pid,
        },
        database: {
          connected: dbConnectivity,
          version: dbVersion,
          tableCount,
          pool: poolHealth,
        },
        memory: {
          rss: process.memoryUsage().rss,
          heapTotal: process.memoryUsage().heapTotal,
          heapUsed: process.memoryUsage().heapUsed,
          external: process.memoryUsage().external,
        },
        endpoints: {
          health: "/api/health",
          openapi: "/api/dev-portal/openapi",
          staging: process.env.STAGING_URL || null,
          production: process.env.PRODUCTION_URL || null,
        },
      });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      log.error("Failed to fetch deployment status", { error: message });
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "DEPLOYMENT_FAILED", message: "Failed to fetch deployment status" }],
      });
    }
  });
}

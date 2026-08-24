import type { Express, Request, Response } from "express";
import { lookup } from "dns/promises";
import { isAuthenticated } from "../auth";
import { requireSuperAdmin } from "../middleware/super-admin";
import { sendEnvelope } from "./shared";
import { db, getPoolHealth, checkPoolConnectivity } from "../db";
import { sql, type SQL } from "drizzle-orm";
import { logger } from "../logger";
import { config } from "../config";
import { buildOpenApiSpec } from "../openapi";
import { createAuditLog } from "../storage/audit";
import { reply, replyBadRequest, replyInternal } from "../api-response";

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
const DB_QUERY_TIMEOUT_MS = 5_000;
const REDACTED_VALUE = "[REDACTED]";
const SENSITIVE_TABLE_COLUMNS = new Set([
  "connectors:config",
  "api_keys:key",
  "api_keys:secret",
  "organizations:sovereign_key_config",
  "password_reset_tokens:token",
  "sessions:sess",
  "sessions:sid",
  "org_sso_configs:certificate",
  "outbound_webhooks:headers",
  // This short identifier helps correlate a collector, but it is derived from an authentication key.
  "collector_instances:api_key_prefix",
]);
const SENSITIVE_WORD_PATTERN =
  /(^|_)(secret|secrets|token|tokens|api_?key|apikey|credential|credentials|private_?key|key_hash|passphrase|password|certificate|certificates?|backup_?codes?|recovery_?codes?|sid|session|sessions|otp|pin)(_|$)/i;
const OPERATIONAL_SUFFIX_PATTERN =
  /(^|_)(at|on|date|time|timestamp|days?|hours?|minutes?|count|counts|status|state|type|prefix|length|age|rotation|expires?|expiry|required|enabled|active|ref|name|path|provider|classification|advisory|certifications?|submitted|start|end|metadata)$/i;
const OPERATIONAL_COLUMN_PATTERNS = [
  /^password_(min_length|expiry_days|require_[a-z_]+)$/i,
  /^password_(changed_at|change_required)$/i,
  /^(is|has|can|should)_encrypted$/i,
  /(^|_)(api_?key|credential|secret|token)_id$/i,
  /^(ai_tokens_per_month|daily_(input|output)_tokens|(input|output)_tokens|max_tokens)$/i,
  /^max_concurrent_sessions$/i,
  /^secrets_found$/i,
  /^secret_field$/i,
  /^submitted_credentials$/i,
  /^accessed_credential$/i,
  /^supersession_match_basis$/i,
];

type FilterPrimitive = string | number | boolean;
type RawFilterClause = {
  column?: unknown;
  op?: unknown;
  value?: unknown;
};

export function isSensitiveColumn(tableName: string, columnName: string): boolean {
  const normalizedColumn = columnName.toLowerCase();
  if (SENSITIVE_TABLE_COLUMNS.has(`${tableName}:${normalizedColumn}`)) return true;
  if (!SENSITIVE_WORD_PATTERN.test(normalizedColumn)) return false;
  if (OPERATIONAL_COLUMN_PATTERNS.some((pattern) => pattern.test(normalizedColumn))) return false;
  return !OPERATIONAL_SUFFIX_PATTERN.test(normalizedColumn);
}

function redactRows(rows: unknown[], tableName: string, redactedColumns: Set<string>): Record<string, unknown>[] {
  return rows.map((row) => {
    if (!row || typeof row !== "object" || Array.isArray(row)) return { value: row };
    return Object.fromEntries(
      Object.entries(row).map(([column, value]) => [
        column,
        redactedColumns.has(column) || isSensitiveColumn(tableName, column) ? REDACTED_VALUE : value,
      ]),
    );
  });
}

export function registerDevPortalRoutes(app: Express): void {
  app.get("/api/developer-portal/openapi", isAuthenticated, (_req: Request, res: Response) => {
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

  app.get("/api/developer-portal/openapi/summary", isAuthenticated, (_req: Request, res: Response) => {
    try {
      const spec = buildOpenApiSpec();
      const paths = spec.paths || {};
      const tags = new Map<string, { endpoints: number; methods: string[] }>();

      for (const [, methods] of Object.entries(paths)) {
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
      log.error("Failed to build OpenAPI summary (developer-portal)", { error: message });
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "OPENAPI_SUMMARY_FAILED", message: "Failed to generate API summary" }],
      });
    }
  });

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
      const redactedColumns = new Set(
        Array.from(validColumns).filter((column) => isSensitiveColumn(tableName, column)),
      );

      if (orderByColumn && !validColumns.has(orderByColumn)) {
        return replyBadRequest(res, "Invalid orderBy column.", "INVALID_ORDER_BY");
      }
      if (orderByColumn && redactedColumns.has(orderByColumn)) {
        return replyBadRequest(res, "Ordering by a sensitive column is not permitted.", "SENSITIVE_COLUMN");
      }

      const whereClauses = Array.isArray(where) ? where : [];
      if (whereClauses.length > MAX_WHERE_CLAUSES) {
        return replyBadRequest(res, `Too many filters (max ${MAX_WHERE_CLAUSES}).`, "TOO_MANY_FILTERS");
      }

      const conditionSql: SQL[] = [];
      const filterColumns: string[] = [];

      for (const rawClause of whereClauses) {
        const clause = rawClause as RawFilterClause;
        if (!clause || typeof clause !== "object") {
          return replyBadRequest(res, "Invalid filter clause.", "INVALID_FILTER");
        }

        const column = typeof clause.column === "string" ? clause.column : "";
        const op = typeof clause.op === "string" ? clause.op.toLowerCase() : "=";
        const value = clause.value;

        if (!column || !validColumns.has(column)) {
          return replyBadRequest(res, "Invalid filter column.", "INVALID_FILTER_COLUMN");
        }
        if (redactedColumns.has(column)) {
          return replyBadRequest(res, "Filtering by a sensitive column is not permitted.", "SENSITIVE_COLUMN");
        }
        filterColumns.push(column);

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

          return replyBadRequest(res, "NULL filters only support = or !=.", "INVALID_FILTER");
        }

        if (op === "in") {
          if (!Array.isArray(value) || value.length === 0 || value.length > MAX_IN_VALUES) {
            return replyBadRequest(
              res,
              `IN filters must be a non-empty array (max ${MAX_IN_VALUES}).`,
              "INVALID_FILTER",
            );
          }

          if (
            value.some(
              (item): item is object | null =>
                item === null || (typeof item !== "string" && typeof item !== "number" && typeof item !== "boolean"),
            )
          ) {
            return replyBadRequest(res, "IN filter values must be primitives.", "INVALID_FILTER");
          }

          conditionSql.push(sql`${col} = ANY(${value as FilterPrimitive[]})`);
          continue;
        }

        if (value !== null && typeof value !== "string" && typeof value !== "number" && typeof value !== "boolean") {
          return replyBadRequest(res, "Filter value must be a primitive.", "INVALID_FILTER");
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
          return replyBadRequest(res, `Unsupported operator: ${op}.`, "INVALID_FILTER");
        }
      }

      const whereSql = conditionSql.length ? sql` WHERE ${sql.join(conditionSql, sql` AND `)}` : sql``;
      const orderSql = orderByColumn
        ? sql` ORDER BY ${sql.identifier(orderByColumn)} ${sql.raw(orderDirection)}`
        : sql``;

      const actor = req.user as { id?: unknown; email?: unknown } | undefined;
      if (typeof actor?.id !== "string" || actor.id.length === 0) {
        return replyInternal(res, "A resolved platform-admin actor is required.");
      }

      log.info("Dev portal DB query started", {
        userId: actor.id,
        table: tableName,
        limit: limitNumber,
        offset: offsetNumber,
        orderBy: orderByColumn,
        orderDir: orderDirection,
        filters: conditionSql.length,
      });

      const startTime = Date.now();
      const result = await db.transaction(async (tx) => {
        await tx.execute(sql.raw(`SET LOCAL statement_timeout = '${DB_QUERY_TIMEOUT_MS}ms'`));
        return tx.execute(
          sql`SELECT * FROM ${sql.identifier(tableName)}${whereSql}${orderSql} LIMIT ${limitNumber} OFFSET ${offsetNumber}`,
        );
      });
      const elapsed = Date.now() - startTime;

      const rows = result.rows || [];
      const redactedRows = redactRows(rows, tableName, redactedColumns);

      await createAuditLog({
        userId: actor.id,
        userName: typeof actor.email === "string" ? actor.email : "unknown",
        orgId: (req as Request & { orgId?: string }).orgId ?? null,
        action: "platform_db_query",
        resourceType: "dev_portal_database",
        resourceId: tableName,
        details: {
          actor: actor.id,
          table: tableName,
          filterColumns,
          rowCount: redactedRows.length,
          elapsed,
        },
      });

      log.info("Dev portal DB query completed", {
        userId: actor.id,
        table: tableName,
        rowCount: redactedRows.length,
        elapsed,
      });

      return reply(res, {
        rows: redactedRows,
        rowCount: redactedRows.length,
        elapsed,
        truncated: limitNumber === MAX_QUERY_ROWS && redactedRows.length >= MAX_QUERY_ROWS,
      });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      log.error("Dev portal DB query failed", { error: message });
      return replyInternal(res, "Database query failed.");
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

/**
 * API Security Analyzer — traffic analysis, schema validation, abuse detection,
 * sensitive data exposure scanning, and shadow API discovery.
 */

import { db } from "./db";
import { sql, eq, and, desc } from "drizzle-orm";
import { apiInventory, apiFindings, apiTrafficBaselines } from "../shared/schema";

// ─── Sensitive Data Patterns ────────────────────────────────────────────────

const SENSITIVE_PATTERNS: Array<{ name: string; pattern: RegExp; severity: string }> = [
  { name: "credit_card", pattern: /\b(?:\d[ -]*?){13,19}\b/, severity: "critical" },
  { name: "ssn", pattern: /\b\d{3}-\d{2}-\d{4}\b/, severity: "critical" },
  { name: "email", pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/, severity: "medium" },
  { name: "phone", pattern: /\b\+?1?\s*\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/, severity: "low" },
  {
    name: "api_key",
    pattern: /(?:api[_-]?key|apikey|token)\s*[:=]\s*["']?[a-zA-Z0-9_\-]{20,}["']?/i,
    severity: "high",
  },
  { name: "jwt", pattern: /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/, severity: "high" },
  { name: "password", pattern: /(?:password|passwd|pwd)\s*[:=]\s*["']?[^\s"']{4,}["']?/i, severity: "critical" },
  { name: "aws_key", pattern: /AKIA[0-9A-Z]{16}/, severity: "critical" },
  { name: "private_key", pattern: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/, severity: "critical" },
  { name: "iban", pattern: /\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b/, severity: "high" },
];

// ─── OWASP API Security Top 10 Categories ───────────────────────────────────

const OWASP_CATEGORIES: Record<string, string> = {
  bola: "API1:2023 Broken Object Level Authorization",
  broken_auth: "API2:2023 Broken Authentication",
  bfla: "API5:2023 Broken Function Level Authorization",
  mass_assignment: "API6:2023 Unrestricted Access to Sensitive Business Flows",
  ssrf: "API7:2023 Server Side Request Forgery",
  injection: "API8:2023 Security Misconfiguration",
  credential_stuffing: "API2:2023 Broken Authentication",
  scraping: "API6:2023 Unrestricted Access to Sensitive Business Flows",
  schema_violation: "API8:2023 Security Misconfiguration",
  sensitive_data_exposure: "API3:2023 Broken Object Property Level Authorization",
  rate_abuse: "API4:2023 Unrestricted Resource Consumption",
  auth_bypass: "API2:2023 Broken Authentication",
};

// ─── Schema Validation ──────────────────────────────────────────────────────

interface SchemaViolation {
  field: string;
  expected: string;
  actual: string;
  location: "path" | "query" | "header" | "body";
}

export function validateAgainstSchema(
  spec: Record<string, unknown> | null,
  method: string,
  path: string,
  request: { headers?: Record<string, string>; query?: Record<string, string>; body?: unknown },
): SchemaViolation[] {
  if (!spec) return [];
  const violations: SchemaViolation[] = [];

  const paths = spec.paths as Record<string, Record<string, unknown>> | undefined;
  if (!paths) return [];

  const pathSpec = paths[path];
  if (!pathSpec) {
    violations.push({ field: path, expected: "defined in spec", actual: "not found", location: "path" });
    return violations;
  }

  const methodSpec = pathSpec[method.toLowerCase()] as Record<string, unknown> | undefined;
  if (!methodSpec) {
    violations.push({ field: method, expected: "defined in spec", actual: "not found", location: "path" });
    return violations;
  }

  // Check required parameters
  const parameters = (methodSpec.parameters || []) as Array<Record<string, unknown>>;
  for (const param of parameters) {
    if (param.required && param.in === "query" && request.query) {
      const paramName = String(param.name);
      if (!(paramName in request.query)) {
        violations.push({
          field: paramName,
          expected: "required",
          actual: "missing",
          location: "query",
        });
      }
    }
  }

  return violations;
}

// ─── Sensitive Data Scanner ─────────────────────────────────────────────────

export function scanForSensitiveData(content: string): Array<{ type: string; severity: string; snippet: string }> {
  const results: Array<{ type: string; severity: string; snippet: string }> = [];

  for (const { name, pattern, severity } of SENSITIVE_PATTERNS) {
    const match = pattern.exec(content);
    if (match) {
      // Mask the sensitive data for safe storage
      const raw = match[0];
      const masked = raw.length > 8 ? raw.slice(0, 4) + "***" + raw.slice(-4) : "***";
      results.push({ type: name, severity, snippet: masked });
    }
  }

  return results;
}

// ─── Traffic Anomaly Detection ──────────────────────────────────────────────

interface TrafficSnapshot {
  requestCount: number;
  uniqueCallers: number;
  errorCount: number;
  avgLatencyMs: number;
  statusCodeDistribution: Record<string, number>;
}

interface AnomalyResult {
  anomalyScore: number;
  anomalies: Array<{ metric: string; deviation: number; description: string }>;
}

export function detectTrafficAnomalies(
  current: TrafficSnapshot,
  baseline: { avgRequestCount: number; avgErrorRate: number; avgLatencyMs: number; avgUnique: number },
): AnomalyResult {
  const anomalies: Array<{ metric: string; deviation: number; description: string }> = [];

  // Request volume spike
  if (baseline.avgRequestCount > 0) {
    const volumeRatio = current.requestCount / baseline.avgRequestCount;
    if (volumeRatio > 3) {
      anomalies.push({
        metric: "request_volume",
        deviation: volumeRatio,
        description: `Request volume ${volumeRatio.toFixed(1)}x above baseline`,
      });
    }
  }

  // Error rate spike
  const currentErrorRate = current.requestCount > 0 ? current.errorCount / current.requestCount : 0;
  if (baseline.avgErrorRate > 0 && currentErrorRate > baseline.avgErrorRate * 3) {
    anomalies.push({
      metric: "error_rate",
      deviation: currentErrorRate / baseline.avgErrorRate,
      description: `Error rate ${(currentErrorRate * 100).toFixed(1)}% vs baseline ${(baseline.avgErrorRate * 100).toFixed(1)}%`,
    });
  }

  // Latency spike
  if (baseline.avgLatencyMs > 0 && current.avgLatencyMs > baseline.avgLatencyMs * 2.5) {
    anomalies.push({
      metric: "latency",
      deviation: current.avgLatencyMs / baseline.avgLatencyMs,
      description: `Latency ${current.avgLatencyMs.toFixed(0)}ms vs baseline ${baseline.avgLatencyMs.toFixed(0)}ms`,
    });
  }

  // Unique caller count anomaly (potential credential stuffing)
  if (baseline.avgUnique > 0) {
    const callerRatio = current.uniqueCallers / baseline.avgUnique;
    if (callerRatio > 5) {
      anomalies.push({
        metric: "unique_callers",
        deviation: callerRatio,
        description: `${current.uniqueCallers} unique IPs vs baseline avg ${baseline.avgUnique}`,
      });
    }
  }

  // 4xx spike (potential scraping/brute force)
  const client4xx = Object.entries(current.statusCodeDistribution)
    .filter(([code]) => code.startsWith("4"))
    .reduce((sum, [, count]) => sum + count, 0);
  if (current.requestCount > 10 && client4xx / current.requestCount > 0.5) {
    anomalies.push({
      metric: "client_errors",
      deviation: client4xx / current.requestCount,
      description: `${((client4xx / current.requestCount) * 100).toFixed(0)}% of requests returning 4xx`,
    });
  }

  // Calculate composite anomaly score (0–100)
  const anomalyScore = Math.min(
    100,
    anomalies.reduce((sum, a) => sum + Math.min(25, a.deviation * 5), 0),
  );

  return { anomalyScore, anomalies };
}

// ─── Shadow API Detection ───────────────────────────────────────────────────

export async function detectShadowApis(orgId: string): Promise<number> {
  // Shadow APIs = APIs seen in traffic but not in any uploaded OpenAPI spec
  const result = await db.execute(sql`
    UPDATE api_inventory
    SET is_shadow = true, updated_at = NOW()
    WHERE org_id = ${orgId}
      AND openapi_spec IS NULL
      AND spec_source IS NULL
      AND is_shadow = false
    RETURNING id
  `);
  const rows = (result as unknown as { rows: Array<{ id: string }> }).rows || [];
  return rows.length;
}

// ─── Risk Score Computation ─────────────────────────────────────────────────

export function computeApiRiskScore(api: {
  authType: string;
  isShadow: boolean;
  isDeprecated: boolean;
  errorRate24h: number;
  sensitiveDataTypes: unknown;
  openFindings: number;
}): number {
  let score = 0;

  // No authentication
  if (api.authType === "none") score += 30;
  else if (api.authType === "basic") score += 15;

  // Shadow API
  if (api.isShadow) score += 25;

  // Deprecated
  if (api.isDeprecated) score += 10;

  // High error rate
  if (api.errorRate24h > 0.1) score += 15;
  else if (api.errorRate24h > 0.05) score += 8;

  // Sensitive data exposure
  const sensitiveTypes = api.sensitiveDataTypes as string[] | null;
  if (sensitiveTypes && sensitiveTypes.length > 0) {
    score += Math.min(20, sensitiveTypes.length * 5);
  }

  // Open findings
  score += Math.min(30, api.openFindings * 5);

  return Math.min(100, score);
}

// ─── OpenAPI Spec Import ────────────────────────────────────────────────────

interface DiscoveredEndpoint {
  method: string;
  path: string;
  host: string;
  authType: string;
  version: string | null;
}

export function parseOpenApiSpec(spec: Record<string, unknown>, host: string): DiscoveredEndpoint[] {
  const endpoints: DiscoveredEndpoint[] = [];
  const paths = spec.paths as Record<string, Record<string, unknown>> | undefined;
  if (!paths) return endpoints;

  const version = (spec.info as Record<string, unknown> | undefined)?.version as string | undefined;
  const globalSecurity = spec.security as unknown[] | undefined;

  for (const [path, methods] of Object.entries(paths)) {
    for (const [method, _opSpec] of Object.entries(methods)) {
      if (["get", "post", "put", "patch", "delete", "head", "options"].includes(method)) {
        const opSpec = _opSpec as Record<string, unknown>;
        let authType = "none";

        const opSecurity = (opSpec.security ?? globalSecurity) as Array<Record<string, unknown>> | undefined;
        if (opSecurity && opSecurity.length > 0) {
          const firstScheme = Object.keys(opSecurity[0])[0];
          const securitySchemes =
            ((spec.components as Record<string, unknown> | undefined)?.securitySchemes as Record<
              string,
              Record<string, unknown>
            >) || {};
          const scheme = securitySchemes[firstScheme];
          if (scheme) {
            if (scheme.type === "oauth2") authType = "oauth2";
            else if (scheme.type === "http" && scheme.scheme === "bearer") authType = "bearer";
            else if (scheme.type === "http" && scheme.scheme === "basic") authType = "basic";
            else if (scheme.type === "apiKey") authType = "api_key";
            else if (scheme.type === "mutualTLS") authType = "mtls";
            else authType = "custom";
          }
        }

        endpoints.push({
          method: method.toUpperCase(),
          path,
          host,
          authType,
          version: version || null,
        });
      }
    }
  }

  return endpoints;
}

// ─── Aggregate Stats Helper ─────────────────────────────────────────────────

export async function getApiSecuritySummary(orgId: string) {
  const result = await db.execute(sql`
    SELECT
      COUNT(*) AS total_apis,
      COUNT(*) FILTER (WHERE is_shadow = true) AS shadow_count,
      COUNT(*) FILTER (WHERE is_deprecated = true) AS deprecated_count,
      COUNT(*) FILTER (WHERE auth_type = 'none') AS no_auth_count,
      AVG(risk_score) AS avg_risk_score,
      SUM(request_count_24h) AS total_requests_24h
    FROM api_inventory
    WHERE org_id = ${orgId}
  `);

  const findingsResult = await db.execute(sql`
    SELECT
      COUNT(*) AS total_findings,
      COUNT(*) FILTER (WHERE status = 'open') AS open_findings,
      COUNT(*) FILTER (WHERE severity = 'critical') AS critical_count,
      COUNT(*) FILTER (WHERE severity = 'high') AS high_count,
      COUNT(*) FILTER (WHERE severity = 'medium') AS medium_count,
      COUNT(*) FILTER (WHERE severity = 'low') AS low_count,
      COUNT(*) FILTER (WHERE finding_type = 'bola') AS bola_count,
      COUNT(*) FILTER (WHERE finding_type = 'bfla') AS bfla_count,
      COUNT(*) FILTER (WHERE finding_type = 'credential_stuffing') AS cred_stuffing_count,
      COUNT(*) FILTER (WHERE finding_type = 'sensitive_data_exposure') AS sensitive_data_count,
      COUNT(*) FILTER (WHERE finding_type = 'schema_violation') AS schema_violation_count,
      COUNT(*) FILTER (WHERE finding_type = 'shadow_api') AS shadow_finding_count,
      COUNT(*) FILTER (WHERE finding_type = 'injection') AS injection_count,
      COUNT(*) FILTER (WHERE finding_type = 'rate_abuse') AS rate_abuse_count
    FROM api_findings
    WHERE org_id = ${orgId}
  `);

  const apiRow = (result as unknown as { rows: Array<Record<string, string>> }).rows?.[0] || {};
  const findingsRow = (findingsResult as unknown as { rows: Array<Record<string, string>> }).rows?.[0] || {};

  return {
    inventory: {
      totalApis: parseInt(apiRow.total_apis || "0"),
      shadowCount: parseInt(apiRow.shadow_count || "0"),
      deprecatedCount: parseInt(apiRow.deprecated_count || "0"),
      noAuthCount: parseInt(apiRow.no_auth_count || "0"),
      avgRiskScore: parseFloat(apiRow.avg_risk_score || "0"),
      totalRequests24h: parseInt(apiRow.total_requests_24h || "0"),
    },
    findings: {
      total: parseInt(findingsRow.total_findings || "0"),
      open: parseInt(findingsRow.open_findings || "0"),
      critical: parseInt(findingsRow.critical_count || "0"),
      high: parseInt(findingsRow.high_count || "0"),
      medium: parseInt(findingsRow.medium_count || "0"),
      low: parseInt(findingsRow.low_count || "0"),
      bola: parseInt(findingsRow.bola_count || "0"),
      bfla: parseInt(findingsRow.bfla_count || "0"),
      credentialStuffing: parseInt(findingsRow.cred_stuffing_count || "0"),
      sensitiveData: parseInt(findingsRow.sensitive_data_count || "0"),
      schemaViolation: parseInt(findingsRow.schema_violation_count || "0"),
      shadow: parseInt(findingsRow.shadow_finding_count || "0"),
      injection: parseInt(findingsRow.injection_count || "0"),
      rateAbuse: parseInt(findingsRow.rate_abuse_count || "0"),
    },
  };
}

export { OWASP_CATEGORIES };

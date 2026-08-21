/**
 * Threat-hunting execution engine.
 *
 * Compilers emit only allowlisted structured conditions. This module maps
 * those conditions to real Drizzle columns and binds every value.
 */

import { sql } from "drizzle-orm";
import { alerts, ingestionLogs, sensorEvents } from "@shared/schema";
import { db } from "./db";
import { compileQuery, type CompiledFilter, type HuntCondition, type HuntTable } from "./sigma-compiler";
import { logger } from "./logger";

const log = logger.child("hunt-engine");
const MAX_RESULT_ROWS = 500;
const QUERY_TIMEOUT_MS = 30_000;

export type HuntExecutionStatus = "completed" | "failed" | "rejected";

export interface HuntExecutionResult {
  status: HuntExecutionStatus;
  eventCount: number;
  events: Record<string, unknown>[];
  executionDurationMs: number;
  targetTable: string;
  explanation: string;
  reason?: string;
}

function physicalColumn(table: HuntTable, field: string) {
  const columns = {
    alerts: {
      title: alerts.title,
      description: alerts.description,
      severity: alerts.severity,
      status: alerts.status,
      source: alerts.source,
      category: alerts.category,
      sourceIp: alerts.sourceIp,
      destIp: alerts.destIp,
      userId: alerts.userId,
      hostname: alerts.hostname,
      fileHash: alerts.fileHash,
      url: alerts.url,
      domain: alerts.domain,
    },
    ingestion_logs: {
      source: ingestionLogs.source,
      status: ingestionLogs.status,
      errorMessage: ingestionLogs.errorMessage,
      requestId: ingestionLogs.requestId,
      ipAddress: ingestionLogs.ipAddress,
    },
    sensor_events: {
      eventType: sensorEvents.eventType,
      processName: sensorEvents.processName,
      processPath: sensorEvents.processPath,
      processArgs: sensorEvents.processArgs,
      parentProcess: sensorEvents.parentProcess,
      userName: sensorEvents.userName,
      srcIp: sensorEvents.srcIp,
      dstIp: sensorEvents.dstIp,
      filePath: sensorEvents.filePath,
      fileHash: sensorEvents.fileHash,
      authAction: sensorEvents.authAction,
      authResult: sensorEvents.authResult,
      dnsQuery: sensorEvents.dnsQuery,
      logSource: sensorEvents.logSource,
      logLevel: sensorEvents.logLevel,
      logMessage: sensorEvents.logMessage,
    },
  }[table];
  return columns[field as keyof typeof columns] || null;
}

function payloadCondition(table: HuntTable, condition: HuntCondition) {
  if (condition.field !== "payloadText") return null;
  const pattern = condition.operator === "contains" ? `%${String(condition.value)}%` : String(condition.value);
  if (table === "alerts") {
    return sql`(${alerts.rawData}::text ILIKE ${pattern} OR ${alerts.normalizedData}::text ILIKE ${pattern} OR ${alerts.ocsfData}::text ILIKE ${pattern})`;
  }
  if (table === "sensor_events") return sql`${sensorEvents.rawData}::text ILIKE ${pattern}`;
  return null;
}

function conditionSql(table: HuntTable, condition: HuntCondition) {
  const column = physicalColumn(table, condition.field) || payloadCondition(table, condition);
  if (!column) throw new Error(`Unsupported compiled field "${condition.field}" for ${table}`);
  if (condition.field === "payloadText") return column;

  switch (condition.operator) {
    case "eq":
      return sql`${column} = ${condition.value}`;
    case "neq":
      return sql`${column} != ${condition.value}`;
    case "contains":
      return sql`${column} ILIKE ${`%${String(condition.value)}%`}`;
    case "startsWith":
      return sql`${column} ILIKE ${`${String(condition.value)}%`}`;
    case "endsWith":
      return sql`${column} ILIKE ${`%${String(condition.value)}`}`;
    case "gt":
      return sql`${column} > ${condition.value}`;
    case "lt":
      return sql`${column} < ${condition.value}`;
    default:
      throw new Error(`Unsupported operator "${condition.operator}"`);
  }
}

function tableParts(table: HuntTable) {
  if (table === "alerts") return { org: alerts.orgId, created: alerts.createdAt };
  if (table === "ingestion_logs") return { org: ingestionLogs.orgId, created: ingestionLogs.receivedAt };
  return { org: sensorEvents.orgId, created: sensorEvents.timestamp };
}

async function queryTable(compiled: CompiledFilter, orgId: string, limit: number): Promise<Record<string, unknown>[]> {
  const tableName = compiled.targetTable;
  const tableRef = sql.raw(`"${tableName}"`);
  const { org, created } = tableParts(tableName);
  const filters = compiled.conditions.map((item) => conditionSql(tableName, item));
  const conditionFragment =
    filters.length === 0
      ? sql`TRUE`
      : compiled.conditionLogic === "or"
        ? sql`(${sql.join(filters, sql` OR `)})`
        : sql`(${sql.join(filters, sql` AND `)})`;

  return db.transaction(async (tx) => {
    await tx.execute(sql.raw(`SET LOCAL statement_timeout = '${QUERY_TIMEOUT_MS}ms'`));
    const result = await tx.execute(
      sql`SELECT * FROM ${tableRef} WHERE ${org} = ${orgId} AND ${conditionFragment} ORDER BY ${created} DESC LIMIT ${limit}`,
    );
    const rows = result as unknown as { rows?: Record<string, unknown>[] };
    return Array.isArray(result) ? (result as unknown as Record<string, unknown>[]) : rows.rows || [];
  });
}

export async function executeHunt(
  queryType: string,
  queryText: string,
  orgId: string,
  limit: number = 100,
): Promise<HuntExecutionResult> {
  const startMs = Date.now();
  const compiled = compileQuery(queryType, queryText);
  const cappedLimit = Math.min(Math.max(1, limit), MAX_RESULT_ROWS);
  if (compiled.rejected) {
    return {
      status: "rejected",
      eventCount: 0,
      events: [],
      executionDurationMs: Date.now() - startMs,
      targetTable: compiled.targetTable,
      explanation: compiled.explanation,
      reason: compiled.rejectionReason || compiled.explanation,
    };
  }

  try {
    const events = await queryTable(compiled, orgId, cappedLimit);
    return {
      status: "completed",
      eventCount: events.length,
      events,
      executionDurationMs: Date.now() - startMs,
      targetTable: compiled.targetTable,
      explanation: compiled.explanation,
    };
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    log.error("Hunt execution failed", { error: reason, orgId, targetTable: compiled.targetTable });
    return {
      status: "failed",
      eventCount: 0,
      events: [],
      executionDurationMs: Date.now() - startMs,
      targetTable: compiled.targetTable,
      explanation: "Hunt execution failed.",
      reason,
    };
  }
}

export async function pivotOnIoc(
  _iocType: string,
  iocValue: string,
  orgId: string,
): Promise<{ alerts: Record<string, unknown>[]; ingestionLogs: Record<string, unknown>[]; totalHits: number }> {
  const searchPattern = `%${iocValue}%`;
  const alertResult = await db.execute(
    sql`SELECT id, title, severity, status, source, created_at, raw_data, normalized_data, ocsf_data
        FROM alerts
        WHERE org_id = ${orgId}
          AND (title ILIKE ${searchPattern} OR description ILIKE ${searchPattern}
            OR raw_data::text ILIKE ${searchPattern}
            OR normalized_data::text ILIKE ${searchPattern}
            OR ocsf_data::text ILIKE ${searchPattern})
        ORDER BY created_at DESC LIMIT 50`,
  );
  const logResult = await db.execute(
    sql`SELECT id, source, status, error_message, request_id, ip_address, received_at
        FROM ingestion_logs
        WHERE org_id = ${orgId}
          AND (source ILIKE ${searchPattern} OR status ILIKE ${searchPattern}
            OR error_message ILIKE ${searchPattern} OR request_id ILIKE ${searchPattern}
            OR ip_address ILIKE ${searchPattern})
        ORDER BY received_at DESC LIMIT 50`,
  );
  const alertsRows = Array.isArray(alertResult)
    ? (alertResult as unknown as Record<string, unknown>[])
    : (alertResult as any).rows || [];
  const logsRows = Array.isArray(logResult)
    ? (logResult as unknown as Record<string, unknown>[])
    : (logResult as any).rows || [];
  return { alerts: alertsRows, ingestionLogs: logsRows, totalHits: alertsRows.length + logsRows.length };
}

export function generateHuntHypotheses(
  recentAlerts: { severity: string; source: string; category: string | null }[],
): { hypothesis: string; queryType: string; suggestedQuery: string; mitreTechnique: string; confidence: string }[] {
  const severityCounts: Record<string, number> = {};
  const sourceCounts: Record<string, number> = {};
  const categoryCounts: Record<string, number> = {};
  for (const alert of recentAlerts) {
    severityCounts[alert.severity] = (severityCounts[alert.severity] || 0) + 1;
    sourceCounts[alert.source] = (sourceCounts[alert.source] || 0) + 1;
    if (alert.category) categoryCounts[alert.category] = (categoryCounts[alert.category] || 0) + 1;
  }
  const hypotheses: {
    hypothesis: string;
    queryType: string;
    suggestedQuery: string;
    mitreTechnique: string;
    confidence: string;
  }[] = [];
  if ((severityCounts.critical || 0) > 3) {
    hypotheses.push({
      hypothesis: "Active compromise detected — high volume of critical alerts may indicate lateral movement",
      queryType: "kql",
      suggestedQuery: 'alerts | where severity == "critical" | where status != "resolved"',
      mitreTechnique: "T1021",
      confidence: "high",
    });
  }
  if (Object.keys(sourceCounts).length > 3) {
    hypotheses.push({
      hypothesis: "Multi-vector attack — alerts from multiple sources may indicate coordinated campaign",
      queryType: "sigma",
      suggestedQuery:
        "title: Multi-Source Alert Correlation\nlogsource:\n  category: alert\ndetection:\n  selection:\n    severity: critical\n  condition: selection",
      mitreTechnique: "T1071",
      confidence: "medium",
    });
  }
  if ((categoryCounts.credential_access || 0) > 0 || (categoryCounts.authentication || 0) > 0) {
    hypotheses.push({
      hypothesis: "Credential harvesting — authentication-related alerts may indicate credential theft campaign",
      queryType: "kql",
      suggestedQuery: 'alerts | where category contains "credential" | where severity != "low"',
      mitreTechnique: "T1003",
      confidence: "high",
    });
  }
  if ((categoryCounts.malware || 0) > 0 || (categoryCounts.endpoint || 0) > 0) {
    hypotheses.push({
      hypothesis: "Initial access attempt — endpoint alerts suggest potential malware delivery",
      queryType: "kql",
      suggestedQuery: 'alerts | where category contains "malware"',
      mitreTechnique: "T1204",
      confidence: "medium",
    });
  }
  return hypotheses;
}

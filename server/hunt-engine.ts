/**
 * Hunt Engine
 *
 * Executes compiled hunt queries against the event store (alerts, ingestion_logs,
 * sensor_events) and returns matched events with timing metadata.
 */

import { db } from "./db";
import { sql } from "drizzle-orm";
import { compileQuery, type CompiledFilter } from "./sigma-compiler";
import { logger } from "./logger";

const log = logger.child("hunt-engine");

export interface HuntExecutionResult {
  eventCount: number;
  events: Record<string, unknown>[];
  executionDurationMs: number;
  targetTable: string;
  explanation: string;
}

const MAX_RESULT_ROWS = 500;
const QUERY_TIMEOUT_MS = 30_000;

/**
 * Execute a hunt query and return matched events.
 *
 * @param queryType  One of sigma | yara | kql | sql | custom
 * @param queryText  The raw query text
 * @param orgId      Tenant isolation — always scoped
 * @param limit      Max rows to return (capped at MAX_RESULT_ROWS)
 */
export async function executeHunt(
  queryType: string,
  queryText: string,
  orgId: string,
  limit: number = 100,
): Promise<HuntExecutionResult> {
  const startMs = Date.now();
  const compiled = compileQuery(queryType, queryText);
  const cappedLimit = Math.min(Math.max(1, limit), MAX_RESULT_ROWS);

  try {
    const events = await queryTable(compiled, orgId, cappedLimit);
    const durationMs = Date.now() - startMs;

    return {
      eventCount: events.length,
      events,
      executionDurationMs: durationMs,
      targetTable: compiled.targetTable,
      explanation: compiled.explanation,
    };
  } catch (error) {
    const durationMs = Date.now() - startMs;
    return {
      eventCount: 0,
      events: [],
      executionDurationMs: durationMs,
      targetTable: compiled.targetTable,
      explanation: `Execution error: ${String(error)}`,
    };
  }
}

const ALLOWED_TABLES = ["alerts", "ingestion_logs", "sensor_events"] as const;

async function queryTable(compiled: CompiledFilter, orgId: string, limit: number): Promise<Record<string, unknown>[]> {
  // Validate target table against allowlist to prevent injection
  if (!ALLOWED_TABLES.includes(compiled.targetTable)) {
    return [];
  }

  // Use a transaction so SET LOCAL scopes the timeout to this transaction only,
  // preventing connection contamination across the shared pool.
  return await db.transaction(async (tx) => {
    await tx.execute(sql.raw(`SET LOCAL statement_timeout = '${QUERY_TIMEOUT_MS}ms'`));

    try {
      const whereFragment = compiled.whereClause || "1=1";
      const rows = await tx.execute(
        sql`SELECT * FROM ${sql.raw('"' + compiled.targetTable + '"')} WHERE org_id = ${orgId} AND (${sql.raw(whereFragment)}) ORDER BY created_at DESC LIMIT ${limit}`,
      );
      const wrapped = rows as unknown as { rows?: Record<string, unknown>[] };
      return Array.isArray(rows) ? (rows as unknown as Record<string, unknown>[]) : wrapped.rows || [];
    } catch (error) {
      // If the table doesn't exist yet (e.g. sensor_events), return empty
      const msg = String(error);
      if (msg.includes("does not exist") || msg.includes("relation")) {
        return [];
      }
      throw error;
    }
    // No finally-reset needed: SET LOCAL automatically resets at transaction end
  });
}

/**
 * Pivot on an IOC value — search across multiple tables for any reference.
 */
export async function pivotOnIoc(
  iocType: string,
  iocValue: string,
  orgId: string,
): Promise<{
  alerts: Record<string, unknown>[];
  ingestionLogs: Record<string, unknown>[];
  totalHits: number;
}> {
  const searchPattern = `%${iocValue}%`;

  // Search alerts
  let alertRows: Record<string, unknown>[] = [];
  try {
    const alertResult = await db.execute(
      sql`SELECT id, title, severity, status, source, created_at, raw_payload
          FROM alerts
          WHERE org_id = ${orgId}
            AND (
              title ILIKE ${searchPattern}
              OR description ILIKE ${searchPattern}
              OR raw_payload::text ILIKE ${searchPattern}
            )
          ORDER BY created_at DESC
          LIMIT 50`,
    );
    const ar = alertResult as unknown as { rows?: Record<string, unknown>[] };
    alertRows = Array.isArray(alertResult) ? (alertResult as unknown as Record<string, unknown>[]) : ar.rows || [];
  } catch {
    // table may not exist
  }

  // Search ingestion logs
  let logRows: Record<string, unknown>[] = [];
  try {
    const logResult = await db.execute(
      sql`SELECT id, source, event_count, status, created_at, raw_payload
          FROM ingestion_logs
          WHERE org_id = ${orgId}
            AND (
              source ILIKE ${searchPattern}
              OR raw_payload::text ILIKE ${searchPattern}
            )
          ORDER BY created_at DESC
          LIMIT 50`,
    );
    const lr = logResult as unknown as { rows?: Record<string, unknown>[] };
    logRows = Array.isArray(logResult) ? (logResult as unknown as Record<string, unknown>[]) : lr.rows || [];
  } catch {
    // table may not exist
  }

  return {
    alerts: alertRows,
    ingestionLogs: logRows,
    totalHits: alertRows.length + logRows.length,
  };
}

/**
 * Generate AI hunt hypotheses based on recent alert patterns.
 */
export function generateHuntHypotheses(
  recentAlerts: { severity: string; source: string; category: string | null }[],
): { hypothesis: string; queryType: string; suggestedQuery: string; mitreTechnique: string; confidence: string }[] {
  const hypotheses: {
    hypothesis: string;
    queryType: string;
    suggestedQuery: string;
    mitreTechnique: string;
    confidence: string;
  }[] = [];

  // Analyze patterns
  const severityCounts: Record<string, number> = {};
  const sourceCounts: Record<string, number> = {};
  const categoryCounts: Record<string, number> = {};

  for (const a of recentAlerts) {
    severityCounts[a.severity] = (severityCounts[a.severity] || 0) + 1;
    sourceCounts[a.source] = (sourceCounts[a.source] || 0) + 1;
    if (a.category) categoryCounts[a.category] = (categoryCounts[a.category] || 0) + 1;
  }

  // High critical alert volume suggests active compromise
  if ((severityCounts["critical"] || 0) > 3) {
    hypotheses.push({
      hypothesis: "Active compromise detected — high volume of critical alerts may indicate lateral movement",
      queryType: "kql",
      suggestedQuery: 'alerts | where severity == "critical" | where status != "resolved"',
      mitreTechnique: "T1021",
      confidence: "high",
    });
  }

  // Multiple sources suggest coordinated attack
  if (Object.keys(sourceCounts).length > 3) {
    hypotheses.push({
      hypothesis: "Multi-vector attack — alerts from multiple sources may indicate coordinated campaign",
      queryType: "sigma",
      suggestedQuery: `title: Multi-Source Alert Correlation
description: Detect alerts from multiple sources within short timeframe
logsource:
  category: alert
detection:
  selection:
    severity: critical
  condition: selection
level: high`,
      mitreTechnique: "T1071",
      confidence: "medium",
    });
  }

  // Credential-related alerts suggest credential theft
  if ((categoryCounts["credential_access"] || 0) > 0 || (categoryCounts["authentication"] || 0) > 0) {
    hypotheses.push({
      hypothesis: "Credential harvesting — authentication-related alerts may indicate credential theft campaign",
      queryType: "kql",
      suggestedQuery: 'alerts | where category contains "credential" | where severity != "low"',
      mitreTechnique: "T1003",
      confidence: "high",
    });
  }

  // Malware/endpoint alerts suggest initial access
  if ((categoryCounts["malware"] || 0) > 0 || (categoryCounts["endpoint"] || 0) > 0) {
    hypotheses.push({
      hypothesis: "Initial access attempt — endpoint alerts suggest potential malware delivery",
      queryType: "yara",
      suggestedQuery: `rule SuspiciousPayload {
  strings:
    $s1 = "powershell" nocase
    $s2 = "cmd.exe /c" nocase
    $s3 = "certutil -decode" nocase
    $s4 = "bitsadmin /transfer" nocase
  condition:
    any of them
}`,
      mitreTechnique: "T1059",
      confidence: "medium",
    });
  }

  // Data exfiltration hypothesis
  if ((categoryCounts["network"] || 0) > 0 || (categoryCounts["data_loss"] || 0) > 0) {
    hypotheses.push({
      hypothesis: "Data exfiltration risk — network anomalies may indicate data staging or exfiltration",
      queryType: "kql",
      suggestedQuery: 'alerts | where category contains "network" | where severity == "high"',
      mitreTechnique: "T1041",
      confidence: "medium",
    });
  }

  // Always include a persistence check
  hypotheses.push({
    hypothesis: "Persistence mechanism check — hunt for scheduled tasks, registry modifications, or startup items",
    queryType: "sigma",
    suggestedQuery: `title: Persistence Mechanism Detection
description: Detect common persistence techniques
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - 'schtasks /create'
      - 'reg add'
      - 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'
  condition: selection
level: high`,
    mitreTechnique: "T1053",
    confidence: "medium",
  });

  return hypotheses;
}

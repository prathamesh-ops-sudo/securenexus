/**
 * Native Detection Engine — evaluates Sigma-compatible rules against raw sensor events.
 *
 * On each event ingestion batch, every enabled rule is evaluated.
 * Matches produce detection_alerts that feed the existing AI correlation engine.
 */

import { db } from "../db";
import { eq, and, or, isNull, sql } from "drizzle-orm";
import {
  detectionRules,
  detectionAlerts,
  sensorEvents,
  alerts,
  type DetectionRule,
  type SensorEvent,
} from "../../shared/schema";
import { evaluateCondition, collectMatchedFields, type ConditionNode } from "./evaluator";
import { BUILTIN_RULES } from "./builtin-rules";
import { logger } from "../routes/shared";
import { publishAlertCreated } from "../alert-events";

const log = logger.child("native-detection-engine");

/**
 * Evaluate all enabled rules against a single event row.
 * Returns array of detection alerts to insert.
 */
export async function evaluateEvent(
  event: SensorEvent,
  orgId: string,
  sensorId: string,
  enabledRules?: DetectionRule[],
): Promise<
  Array<{
    ruleId: string;
    severity: string;
    title: string;
    description: string | null;
    mitreTactic: string | null;
    mitreTechnique: string | null;
    matchedFields: Record<string, unknown>;
  }>
> {
  // Fetch enabled rules for this org (global built-in + org-specific)
  const rules =
    enabledRules ??
    (await db
      .select()
      .from(detectionRules)
      .where(
        and(eq(detectionRules.status, "enabled"), or(eq(detectionRules.orgId, orgId), isNull(detectionRules.orgId))),
      ));

  // Build a flat event object for the evaluator
  const eventObj: Record<string, unknown> = {
    eventType: event.eventType,
    processName: event.processName,
    processPath: event.processPath,
    processArgs: event.processArgs,
    parentProcess: event.parentProcess,
    pid: event.pid,
    ppid: event.ppid,
    userName: event.userName,
    srcIp: event.srcIp,
    dstIp: event.dstIp,
    srcPort: event.srcPort,
    dstPort: event.dstPort,
    protocol: event.protocol,
    bytesIn: event.bytesIn,
    bytesOut: event.bytesOut,
    filePath: event.filePath,
    fileAction: event.fileAction,
    fileHash: event.fileHash,
    fileSize: event.fileSize,
    authAction: event.authAction,
    authResult: event.authResult,
    authMethod: event.authMethod,
    dnsQuery: event.dnsQuery,
    dnsType: event.dnsType,
    dnsResponse: event.dnsResponse,
    logSource: event.logSource,
    logLevel: event.logLevel,
    logMessage: event.logMessage,
    // Also include raw data fields if present
    ...(typeof event.rawData === "object" && event.rawData !== null ? (event.rawData as Record<string, unknown>) : {}),
  };

  const matches: Array<{
    ruleId: string;
    severity: string;
    title: string;
    description: string | null;
    mitreTactic: string | null;
    mitreTechnique: string | null;
    matchedFields: Record<string, unknown>;
  }> = [];

  for (const rule of rules) {
    // Skip rules that don't cover this event type
    const ruleEventTypes = rule.eventTypes ?? [];
    if (ruleEventTypes.length > 0 && !ruleEventTypes.includes(event.eventType)) {
      continue;
    }

    try {
      const condTree = rule.conditionTree as ConditionNode;
      if (evaluateCondition(eventObj, condTree)) {
        const matchedFields = collectMatchedFields(eventObj, condTree);
        matches.push({
          ruleId: rule.id,
          severity: rule.severity,
          title: rule.name,
          description: rule.description,
          mitreTactic: rule.mitreTactic,
          mitreTechnique: rule.mitreTechnique,
          matchedFields,
        });
      }
    } catch (err) {
      log.warn(`Rule ${rule.id} evaluation error: ${err}`);
    }
  }

  return matches;
}

/**
 * Process a batch of sensor events: evaluate rules, create detection alerts,
 * and create platform alerts that feed the AI correlation engine.
 */
export async function processEventBatch(
  eventRows: SensorEvent[],
  orgId: string,
  sensorId: string,
): Promise<{ alertsCreated: number; eventsMatched: number }> {
  if (eventRows.length === 0) return { alertsCreated: 0, eventsMatched: 0 };

  // Pre-fetch enabled rules once for the batch
  const enabledRules = await db
    .select()
    .from(detectionRules)
    .where(
      and(eq(detectionRules.status, "enabled"), or(eq(detectionRules.orgId, orgId), isNull(detectionRules.orgId))),
    );

  let alertsCreated = 0;
  let eventsMatched = 0;
  const ruleMatchCounts: Record<string, number> = {};

  for (const event of eventRows) {
    const matches = await evaluateEvent(event, orgId, sensorId, enabledRules);

    if (matches.length > 0) {
      eventsMatched++;

      for (const match of matches) {
        // Create detection alert
        const [detAlert] = await db
          .insert(detectionAlerts)
          .values({
            orgId,
            ruleId: match.ruleId,
            sensorId,
            eventId: event.id,
            severity: match.severity,
            title: match.title,
            description: match.description,
            mitreTactic: match.mitreTactic,
            mitreTechnique: match.mitreTechnique,
            matchedFields: match.matchedFields,
            rawEvent: {
              eventType: event.eventType,
              processName: event.processName,
              processArgs: event.processArgs,
              filePath: event.filePath,
              srcIp: event.srcIp,
              dstIp: event.dstIp,
              dnsQuery: event.dnsQuery,
              userName: event.userName,
            },
          })
          .returning();

        // Also create a platform alert for the AI correlation engine
        const [platformAlert] = await db
          .insert(alerts)
          .values({
            orgId,
            source: "native-sensor",
            sourceEventId: detAlert.id,
            category: "threat",
            severity: match.severity,
            title: `[Detection] ${match.title}`,
            description: match.description,
            hostname: undefined,
            mitreTactic: match.mitreTactic ?? undefined,
            mitreTechnique: match.mitreTechnique ?? undefined,
            rawData: match.matchedFields,
            status: "new",
          })
          .returning();
        if (platformAlert) await publishAlertCreated(platformAlert);

        alertsCreated++;
        ruleMatchCounts[match.ruleId] = (ruleMatchCounts[match.ruleId] ?? 0) + 1;
      }

      // Mark event as matched
      await db.update(sensorEvents).set({ detectionMatched: true }).where(eq(sensorEvents.id, event.id));
    }
  }

  // Update rule match counts
  for (const [ruleId, count] of Object.entries(ruleMatchCounts)) {
    await db
      .update(detectionRules)
      .set({
        matchCount: sql`${detectionRules.matchCount} + ${count}`,
        lastMatchAt: new Date(),
      })
      .where(eq(detectionRules.id, ruleId));
  }

  if (alertsCreated > 0) {
    log.info(`Processed ${eventRows.length} events, ${eventsMatched} matched, ${alertsCreated} alerts created`);
  }

  return { alertsCreated, eventsMatched };
}

/**
 * Seed the 45 built-in MITRE ATT&CK detection rules.
 * Only inserts rules that don't already exist (by name + null orgId).
 */
export async function seedBuiltinRules(): Promise<number> {
  let inserted = 0;

  for (const rule of BUILTIN_RULES) {
    // Check if rule already exists
    const existing = await db
      .select({ id: detectionRules.id })
      .from(detectionRules)
      .where(and(eq(detectionRules.name, rule.name), isNull(detectionRules.orgId), eq(detectionRules.isBuiltin, true)))
      .limit(1);

    if (existing.length === 0) {
      await db.insert(detectionRules).values({
        orgId: null,
        name: rule.name,
        description: rule.description,
        severity: rule.severity,
        status: "enabled",
        mitreTactic: rule.mitreTactic,
        mitreTechnique: rule.mitreTechnique,
        mitreSubtechnique: rule.mitreSubtechnique ?? null,
        eventTypes: rule.eventTypes,
        conditionTree: rule.conditionTree,
        author: "ATS Built-in",
        tags: rule.tags,
        falsePositiveNotes: rule.falsePositiveNotes ?? null,
        references: rule.references,
        isBuiltin: true,
      });
      inserted++;
    }
  }

  if (inserted > 0) {
    log.info(`Seeded ${inserted} built-in detection rules`);
  }

  return inserted;
}

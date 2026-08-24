import type { Express, NextFunction, Request, Response } from "express";
import rateLimit from "express-rate-limit";
import { randomBytes, randomUUID } from "node:crypto";
import { and, desc, eq, gt, inArray, isNull, lt, or, sql } from "drizzle-orm";
import { z } from "zod";
import { db } from "../db";
import {
  collectorEvents,
  collectorInstances,
  collectorIngestBatches,
  nativeSensors,
  SENSOR_EVENT_TYPES,
  SENSOR_PLATFORMS,
  sensorEnrollmentTokens,
  sensorEvents,
  sensorIngestBatches,
  sensorPackageBatches,
  vulnPackages,
  vulnFindings,
  cveEntries,
  VULN_PKG_MANAGERS,
} from "../../shared/schema";
import { createAuditLog } from "../storage/audit";
import { processEventBatch } from "../native-detections";
import { expireTimedOutResponseActions } from "../response-action-timeouts";
import { logger, getOrgId, hashApiKey } from "./shared";
import { isAuthenticated } from "../auth";
import { resolveOrgContext, requireOrgId, requireMinRole } from "../rbac";
import {
  agentAuth,
  collectorAgentAuth,
  createCollectorAgentKey,
  createSensorAgentKey,
  type AgentContext,
} from "../agent-auth";
import {
  ERROR_CODES,
  reply,
  replyBadRequest,
  replyConflict,
  replyError,
  replyNotFound,
  replyUnauthenticated,
} from "../api-response";
import { evaluateInventoryPackages, type InventoryPackage } from "../vulnerability-evaluation";
import { getSensorSupersessionMatches } from "../native-sensor-identity";

const log = logger.child("agent-api");
const MAX_SENSOR_EVENTS = 500;
const MAX_COLLECTOR_EVENTS = 500;
const MAX_SENSOR_PACKAGES = 5000;

const enrollmentTokenSchema = z.object({
  label: z.string().trim().min(1).max(200),
  maxUses: z.number().int().min(1).max(100_000).default(1),
  expiresAt: z.coerce.date(),
  platformHint: z.enum(SENSOR_PLATFORMS).optional(),
});

const enrollSchema = z
  .object({
    agentType: z.enum(["sensor", "collector"]).default("sensor"),
    collectorId: z.string().uuid().optional(),
    enrollmentToken: z.string().trim().min(1).max(300),
    hostname: z.string().trim().min(1).max(200),
    platform: z.enum(SENSOR_PLATFORMS),
    osVersion: z.string().trim().max(200).optional(),
    agentVersion: z.string().trim().max(100).optional(),
    machineIdentity: z.string().trim().min(1).max(300).optional(),
    machineIdentitySource: z.enum(["machine_id", "dmi_product_uuid", "hostname_fallback"]).optional(),
  })
  .superRefine((value, context) => {
    if (value.agentType === "sensor" && Boolean(value.machineIdentity) !== Boolean(value.machineIdentitySource)) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["machineIdentity"],
        message: "machineIdentity and machineIdentitySource must be supplied together.",
      });
    }
  });

const heartbeatSchema = z.object({
  cpuUsage: z.number().finite().min(0).max(100).optional(),
  memoryUsage: z.number().finite().min(0).max(100).optional(),
  diskUsage: z.number().finite().min(0).max(100).optional(),
  agentVersion: z.string().trim().max(100).optional(),
  ipAddress: z.string().trim().max(45).optional(),
});

const sensorEventSchema = z.object({
  eventType: z.enum(SENSOR_EVENT_TYPES),
  timestamp: z.coerce.date().optional(),
  processName: z.string().max(500).optional(),
  processPath: z.string().max(2000).optional(),
  processArgs: z.string().max(4000).optional(),
  parentProcess: z.string().max(500).optional(),
  pid: z.number().int().nonnegative().optional(),
  ppid: z.number().int().nonnegative().optional(),
  userName: z.string().max(500).optional(),
  srcIp: z.string().max(45).optional(),
  dstIp: z.string().max(45).optional(),
  srcPort: z.number().int().min(0).max(65535).optional(),
  dstPort: z.number().int().min(0).max(65535).optional(),
  protocol: z.string().max(50).optional(),
  bytesIn: z.number().int().nonnegative().optional(),
  bytesOut: z.number().int().nonnegative().optional(),
  filePath: z.string().max(2000).optional(),
  fileAction: z.string().max(100).optional(),
  fileHash: z.string().max(200).optional(),
  fileSize: z.number().int().nonnegative().optional(),
  authAction: z.string().max(100).optional(),
  authResult: z.string().max(100).optional(),
  authMethod: z.string().max(100).optional(),
  dnsQuery: z.string().max(500).optional(),
  dnsType: z.string().max(100).optional(),
  dnsResponse: z.string().max(2000).optional(),
  logSource: z.string().max(500).optional(),
  logLevel: z.string().max(100).optional(),
  logMessage: z.string().max(4000).optional(),
  rawData: z.record(z.unknown()).optional(),
});

const sensorEventsSchema = z.object({
  batchId: z.string().trim().min(1).max(200).optional(),
  events: z.array(sensorEventSchema).min(1).max(MAX_SENSOR_EVENTS),
});

const sensorPackagesSchema = z.object({
  batchId: z.string().trim().min(1).max(200).optional(),
  host: z
    .object({
      osId: z.string().trim().max(100).optional(),
      versionId: z.string().trim().max(100).optional(),
      platform: z.string().trim().max(100).optional(),
    })
    .optional(),
  packages: z
    .array(
      z.object({
        packageManager: z.enum(VULN_PKG_MANAGERS),
        packageName: z.string().trim().min(1).max(300),
        installedVersion: z.string().trim().min(1).max(300),
        packageVendor: z.string().trim().max(300).optional(),
        source: z.string().trim().max(100).optional(),
        evidence: z.record(z.unknown()).optional(),
      }),
    )
    .min(1)
    .max(MAX_SENSOR_PACKAGES),
});

const collectorHeartbeatSchema = z.object({
  hostInfo: z.record(z.unknown()).default({}),
  metrics: z.record(z.number().finite().min(0)).default({}),
});

const collectorIngestSchema = z.object({
  batchId: z.string().trim().min(1).max(200).optional(),
  events: z
    .array(
      z.object({
        eventType: z.string().trim().min(1).max(200),
        severity: z.enum(["info", "low", "medium", "high", "critical"]),
        source: z.string().trim().min(1).max(200),
        rawData: z.record(z.unknown()),
        tags: z.array(z.string().max(50)).max(20).optional(),
      }),
    )
    .min(1)
    .max(MAX_COLLECTOR_EVENTS),
});

const collectorPackagesSchema = z.object({
  batchId: z.string().trim().min(1).max(200).optional(),
  host: sensorPackagesSchema.shape.host,
  packages: sensorPackagesSchema.shape.packages,
});

const actionResultSchema = z.object({
  status: z.enum(["completed", "failed"]),
  resultOutput: z.string().max(4000).optional(),
  resultError: z.string().max(4000).optional(),
});

class EnrollmentError extends Error {
  constructor(
    message: string,
    readonly code: string,
  ) {
    super(message);
  }
}

function sensorContext(req: Request): AgentContext {
  if (!req.agentContext) throw new Error("Agent context missing");
  return req.agentContext;
}

function sensorPathMatchesContext(req: Request, res: Response, next: NextFunction): void {
  const context = sensorContext(req);
  if (String(req.params.id) !== context.sensorId) {
    replyUnauthenticated(res, "Sensor credential does not match the requested sensor.", ERROR_CODES.API_KEY_INVALID);
    return;
  }
  next();
}

function sensorEventValues(
  event: z.infer<typeof sensorEventSchema>,
  orgId: string,
  sensorId: string,
  batchId: string,
  batchEventIndex: number,
) {
  return {
    orgId,
    sensorId,
    eventType: event.eventType,
    batchId,
    batchEventIndex,
    timestamp: event.timestamp ?? new Date(),
    processName: event.processName ?? null,
    processPath: event.processPath ?? null,
    processArgs: event.processArgs ?? null,
    parentProcess: event.parentProcess ?? null,
    pid: event.pid ?? null,
    ppid: event.ppid ?? null,
    userName: event.userName ?? null,
    srcIp: event.srcIp ?? null,
    dstIp: event.dstIp ?? null,
    srcPort: event.srcPort ?? null,
    dstPort: event.dstPort ?? null,
    protocol: event.protocol ?? null,
    bytesIn: event.bytesIn ?? null,
    bytesOut: event.bytesOut ?? null,
    filePath: event.filePath ?? null,
    fileAction: event.fileAction ?? null,
    fileHash: event.fileHash ?? null,
    fileSize: event.fileSize ?? null,
    authAction: event.authAction ?? null,
    authResult: event.authResult ?? null,
    authMethod: event.authMethod ?? null,
    dnsQuery: event.dnsQuery ?? null,
    dnsType: event.dnsType ?? null,
    dnsResponse: event.dnsResponse ?? null,
    logSource: event.logSource ?? null,
    logLevel: event.logLevel ?? null,
    logMessage: event.logMessage ?? null,
    rawData: event.rawData ?? null,
  };
}

async function handleSensorHeartbeat(req: Request, res: Response): Promise<void> {
  const { sensorId, orgId } = sensorContext(req);
  const parsed = heartbeatSchema.safeParse(req.body);
  if (!parsed.success) {
    replyBadRequest(res, "Invalid heartbeat payload.", ERROR_CODES.VALIDATION_ERROR);
    return;
  }

  const [updated] = await db
    .update(nativeSensors)
    .set({
      lastHeartbeat: new Date(),
      status: "online",
      cpuUsage: parsed.data.cpuUsage,
      memoryUsage: parsed.data.memoryUsage,
      diskUsage: parsed.data.diskUsage,
      agentVersion: parsed.data.agentVersion,
      ipAddress: parsed.data.ipAddress,
      updatedAt: new Date(),
    })
    .where(and(eq(nativeSensors.id, sensorId), eq(nativeSensors.orgId, orgId), isNull(nativeSensors.revokedAt)))
    .returning({ id: nativeSensors.id });

  if (!updated) {
    replyUnauthenticated(res, "Sensor is revoked or no longer exists.", ERROR_CODES.API_KEY_INVALID);
    return;
  }
  reply(res, { status: "ok", serverTime: new Date().toISOString() });
}

async function handleSensorEvents(req: Request, res: Response): Promise<void> {
  const { sensorId, orgId } = sensorContext(req);
  const parsed = sensorEventsSchema.safeParse(req.body);
  if (!parsed.success) {
    replyBadRequest(res, "Invalid event batch.", ERROR_CODES.VALIDATION_ERROR);
    return;
  }

  const batchId = parsed.data.batchId ?? randomUUID();
  const [batch] = await db
    .insert(sensorIngestBatches)
    .values({ orgId, sensorId, batchId, status: "processing" })
    .onConflictDoNothing({ target: [sensorIngestBatches.sensorId, sensorIngestBatches.batchId] })
    .returning();

  if (!batch) {
    const [existing] = await db
      .select()
      .from(sensorIngestBatches)
      .where(
        and(
          eq(sensorIngestBatches.sensorId, sensorId),
          eq(sensorIngestBatches.orgId, orgId),
          eq(sensorIngestBatches.batchId, batchId),
        ),
      )
      .limit(1);
    if (existing?.status === "completed") {
      reply(res, {
        accepted: existing.accepted,
        rejected: existing.rejected,
        alertsCreated: existing.alertsCreated,
        eventsMatched: existing.eventsMatched,
        duplicate: true,
      });
      return;
    }
    replyConflict(res, "This batch is already being processed.", "BATCH_IN_PROGRESS");
    return;
  }

  try {
    const eventRows = await db
      .insert(sensorEvents)
      .values(parsed.data.events.map((event, index) => sensorEventValues(event, orgId, sensorId, batchId, index)))
      .returning();
    const detectionResult = await processEventBatch(eventRows, orgId, sensorId);

    await db
      .update(nativeSensors)
      .set({
        lastTelemetryAt: new Date(),
        eventsIngested: sql`${nativeSensors.eventsIngested} + ${eventRows.length}`,
        alertsGenerated: sql`${nativeSensors.alertsGenerated} + ${detectionResult.alertsCreated}`,
        updatedAt: new Date(),
      })
      .where(and(eq(nativeSensors.id, sensorId), eq(nativeSensors.orgId, orgId), isNull(nativeSensors.revokedAt)));

    const result = {
      accepted: eventRows.length,
      rejected: 0,
      alertsCreated: detectionResult.alertsCreated,
      eventsMatched: detectionResult.eventsMatched,
      duplicate: false,
    };
    await db
      .update(sensorIngestBatches)
      .set({
        accepted: result.accepted,
        rejected: result.rejected,
        alertsCreated: result.alertsCreated,
        eventsMatched: result.eventsMatched,
        status: "completed",
        completedAt: new Date(),
      })
      .where(and(eq(sensorIngestBatches.id, batch.id), eq(sensorIngestBatches.orgId, orgId)));
    reply(res, result);
  } catch (error) {
    await db
      .update(sensorIngestBatches)
      .set({ status: "failed", completedAt: new Date() })
      .where(and(eq(sensorIngestBatches.id, batch.id), eq(sensorIngestBatches.orgId, orgId)));
    log.error("Sensor event ingestion failed", { error: String(error), sensorId, orgId, batchId });
    replyError(res, 500, [{ code: ERROR_CODES.INTERNAL_ERROR, message: "Event ingestion failed." }]);
  }
}

async function handleSensorPackages(req: Request, res: Response): Promise<void> {
  const { sensorId, orgId } = sensorContext(req);
  const parsed = sensorPackagesSchema.safeParse(req.body);
  if (!parsed.success) {
    replyBadRequest(res, "Invalid package inventory batch.", ERROR_CODES.VALIDATION_ERROR);
    return;
  }
  const batchId = parsed.data.batchId ?? randomUUID();
  const [batch] = await db
    .insert(sensorPackageBatches)
    .values({ orgId, sensorId, batchId, status: "processing" })
    .onConflictDoNothing({ target: [sensorPackageBatches.sensorId, sensorPackageBatches.batchId] })
    .returning();
  if (!batch) {
    const [existing] = await db
      .select()
      .from(sensorPackageBatches)
      .where(
        and(
          eq(sensorPackageBatches.sensorId, sensorId),
          eq(sensorPackageBatches.orgId, orgId),
          eq(sensorPackageBatches.batchId, batchId),
        ),
      )
      .limit(1);
    if (existing?.status === "completed") {
      reply(res, {
        batchId,
        packagesProcessed: existing.packagesProcessed,
        findingsCreated: existing.findingsCreated,
        duplicate: true,
      });
      return;
    }
    replyConflict(res, "This package batch is already being processed.", "BATCH_IN_PROGRESS");
    return;
  }
  try {
    const host = parsed.data.host;
    const inventory: InventoryPackage[] = parsed.data.packages.map((pkg) => ({
      ...pkg,
      hostOsId: host?.osId ?? null,
      hostOsVersion: host?.versionId ?? null,
      hostPlatform: host?.platform ?? null,
      evidence: pkg.evidence ?? null,
    }));
    const evaluated = await evaluateInventoryPackages(inventory);
    const cveIds = Array.from(new Set(evaluated.flatMap((pkg) => pkg.matches.map((match) => match.cveId))));
    const catalogueRows =
      cveIds.length > 0 ? await db.select().from(cveEntries).where(inArray(cveEntries.cveId, cveIds)) : [];
    const catalogue = new Map(catalogueRows.map((entry) => [entry.cveId, entry]));
    const { findingsCreated } = await db.transaction(async (tx) => {
      const now = new Date();
      const storedPackages = await tx
        .insert(vulnPackages)
        .values(
          evaluated.map((pkg) => ({
            orgId,
            sensorId,
            packageManager: pkg.packageManager,
            packageName: pkg.packageName,
            installedVersion: pkg.installedVersion,
            packageVendor: pkg.packageVendor ?? null,
            hostOsId: pkg.hostOsId ?? null,
            hostOsVersion: pkg.hostOsVersion ?? null,
            hostPlatform: pkg.hostPlatform ?? null,
            inventorySource: pkg.source ?? pkg.packageManager,
            evidence: pkg.evidence ?? null,
            evaluationStatus: pkg.evaluationStatus,
            evaluationReason: pkg.evaluationReason,
            isVulnerable: pkg.matches.length > 0,
            cveCount: pkg.matches.length,
            reportedAt: now,
            lastEvaluatedAt: now,
            updatedAt: now,
          })),
        )
        .onConflictDoUpdate({
          target: [vulnPackages.orgId, vulnPackages.sensorId, vulnPackages.packageManager, vulnPackages.packageName],
          set: {
            installedVersion: sql.raw(`excluded.installed_version`),
            packageVendor: sql.raw(`excluded.package_vendor`),
            hostOsId: sql.raw(`excluded.host_os_id`),
            hostOsVersion: sql.raw(`excluded.host_os_version`),
            hostPlatform: sql.raw(`excluded.host_platform`),
            inventorySource: sql.raw(`excluded.inventory_source`),
            evidence: sql.raw(`excluded.evidence`),
            evaluationStatus: sql.raw(`excluded.evaluation_status`),
            evaluationReason: sql.raw(`excluded.evaluation_reason`),
            isVulnerable: sql.raw(`excluded.is_vulnerable`),
            cveCount: sql.raw(`excluded.cve_count`),
            reportedAt: now,
            updatedAt: now,
          },
        })
        .returning({
          id: vulnPackages.id,
          packageManager: vulnPackages.packageManager,
          packageName: vulnPackages.packageName,
        });
      const packageIds = new Map(
        storedPackages.map((stored) => [`${stored.packageManager}\0${stored.packageName}`, stored.id]),
      );
      const existingFindings = await tx
        .select()
        .from(vulnFindings)
        .where(and(eq(vulnFindings.orgId, orgId), eq(vulnFindings.sensorId, sensorId)));
      const currentKeys = new Set<string>();
      const newFindings = [];
      for (const pkg of evaluated) {
        const packageId = packageIds.get(`${pkg.packageManager}\0${pkg.packageName}`);
        for (const match of pkg.matches) {
          const key = `${pkg.packageName}\0${match.source}\0${match.advisoryId ?? match.cveId}`;
          currentKeys.add(key);
          const cve = catalogue.get(match.cveId);
          const existing = existingFindings.find(
            (finding) => `${finding.packageName}\0${finding.source}\0${finding.advisoryId ?? finding.cveId}` === key,
          );
          const values = {
            packageId: packageId ?? null,
            source: match.source,
            cveId: match.cveId,
            packageName: pkg.packageName,
            installedVersion: pkg.installedVersion,
            fixedVersion: match.fixedVersion,
            severity: cve?.severity ?? "none",
            cvssScore: cve?.cvssScore ?? null,
            cvssVector: cve?.cvssVector ?? null,
            epssScore: cve?.epssScore ?? null,
            epssPercentile: cve?.epssPercentile ?? null,
            epssDate: cve?.epssDate ?? null,
            exploitAvailable: cve?.exploitAvailable ?? null,
            kevDateAdded: cve?.kevDateAdded ?? null,
            description: cve?.description ?? null,
            references: cve?.references ?? null,
            matchedCpe: match.matchedCpe,
            matchedVersionRange: match.matchedVersionRange,
            advisoryEcosystem: match.advisoryEcosystem,
            matchSource: match.source,
            advisoryId: match.advisoryId,
            findingConfidence: match.confidence,
            findingBasis: match.basis,
            status: existing?.status === "remediated" ? "open" : (existing?.status ?? "open"),
            closedReason: null,
            closedAt: null,
            updatedAt: now,
          };
          if (existing) {
            await tx
              .update(vulnFindings)
              .set(values)
              .where(and(eq(vulnFindings.id, existing.id), eq(vulnFindings.orgId, orgId)));
          } else {
            newFindings.push({ orgId, sensorId, ...values });
          }
        }
      }
      for (const finding of existingFindings) {
        const key = `${finding.packageName}\0${finding.source}\0${finding.advisoryId ?? finding.cveId}`;
        if (
          (finding.source === "osv" || finding.source === "nvd_cpe") &&
          !currentKeys.has(key) &&
          finding.status !== "remediated" &&
          finding.status !== "false_positive"
        ) {
          await tx
            .update(vulnFindings)
            .set({
              status: "remediated",
              closedReason: "No longer matched by the current installed package version.",
              closedAt: now,
              remediatedAt: now,
              updatedAt: now,
            })
            .where(and(eq(vulnFindings.id, finding.id), eq(vulnFindings.orgId, orgId)));
        }
      }
      for (let index = 0; index < newFindings.length; index += 500) {
        await tx.insert(vulnFindings).values(newFindings.slice(index, index + 500));
      }
      return { findingsCreated: newFindings.length };
    });
    await db
      .update(sensorPackageBatches)
      .set({
        status: "completed",
        packagesProcessed: parsed.data.packages.length,
        findingsCreated,
        completedAt: new Date(),
      })
      .where(and(eq(sensorPackageBatches.id, batch.id), eq(sensorPackageBatches.orgId, orgId)));
    reply(res, { batchId, packagesProcessed: parsed.data.packages.length, findingsCreated, duplicate: false });
  } catch (error) {
    await db
      .update(sensorPackageBatches)
      .set({ status: "failed", completedAt: new Date() })
      .where(and(eq(sensorPackageBatches.id, batch.id), eq(sensorPackageBatches.orgId, orgId)));
    log.error("Sensor package ingestion failed", { error: String(error), sensorId, orgId, batchId });
    replyError(res, 500, [{ code: ERROR_CODES.INTERNAL_ERROR, message: "Package inventory ingestion failed." }]);
  }
}

async function handlePendingActions(req: Request, res: Response): Promise<void> {
  const { sensorId, orgId } = sensorContext(req);
  await expireTimedOutResponseActions(orgId);
  const claimedActions = await db.execute(sql`
    UPDATE agent_response_actions
    SET status = 'executing', dispatched_at = NOW(), updated_at = NOW()
    WHERE id IN (
      SELECT id FROM agent_response_actions
      WHERE sensor_id = ${sensorId}
        AND org_id = ${orgId}
        AND status = 'approved'
        AND dispatched_at IS NULL
      ORDER BY created_at ASC
      LIMIT 10
      FOR UPDATE SKIP LOCKED
    )
    RETURNING id, action_type, status, target_pid, target_process_name,
      target_ip, target_file_path, target_user_name, target_domain,
      target_service_name, script_content, script_type, parameters,
      reason, timeout_seconds, created_at
  `);
  const rows = (claimedActions as { rows?: Array<Record<string, unknown>> }).rows ?? [];
  reply(res, {
    actions: rows.map((row) => ({
      id: row.id,
      actionType: row.action_type,
      status: row.status,
      targetPid: row.target_pid,
      targetProcessName: row.target_process_name,
      targetIp: row.target_ip,
      targetFilePath: row.target_file_path,
      targetUserName: row.target_user_name,
      targetDomain: row.target_domain,
      targetServiceName: row.target_service_name,
      scriptContent: row.script_content,
      scriptType: row.script_type,
      parameters: row.parameters,
      reason: row.reason,
      timeoutSeconds: row.timeout_seconds,
      createdAt: row.created_at,
    })),
  });
}

async function handleRotateSensorKey(req: Request, res: Response): Promise<void> {
  const { sensorId, orgId } = sensorContext(req);
  const { key, hash } = createSensorAgentKey(sensorId);
  const [updated] = await db
    .update(nativeSensors)
    .set({ apiKey: hash, updatedAt: new Date() })
    .where(and(eq(nativeSensors.id, sensorId), eq(nativeSensors.orgId, orgId), isNull(nativeSensors.revokedAt)))
    .returning({ id: nativeSensors.id });
  if (!updated) {
    replyUnauthenticated(res, "Sensor is revoked or no longer exists.", ERROR_CODES.API_KEY_INVALID);
    return;
  }
  await createAuditLog({
    orgId,
    action: "sensor_key_rotated",
    resourceType: "native_sensor",
    resourceId: sensorId,
    details: { initiatedBy: "agent" },
  });
  reply(res, { sensorId, apiKey: key }, {});
}

async function handleDeregisterSensor(req: Request, res: Response): Promise<void> {
  const { sensorId, orgId } = sensorContext(req);
  const [updated] = await db
    .update(nativeSensors)
    .set({ revokedAt: new Date(), status: "revoked", updatedAt: new Date() })
    .where(and(eq(nativeSensors.id, sensorId), eq(nativeSensors.orgId, orgId), isNull(nativeSensors.revokedAt)))
    .returning({ id: nativeSensors.id });
  if (!updated) {
    replyUnauthenticated(res, "Sensor is revoked or no longer exists.", ERROR_CODES.API_KEY_INVALID);
    return;
  }
  await createAuditLog({
    orgId,
    action: "sensor_deregistered",
    resourceType: "native_sensor",
    resourceId: sensorId,
    details: { initiatedBy: "agent" },
  });
  reply(res, { sensorId, status: "revoked" });
}

async function handleActionResult(req: Request, res: Response): Promise<void> {
  const { sensorId, orgId } = sensorContext(req);
  const parsed = actionResultSchema.safeParse(req.body);
  if (!parsed.success) {
    replyBadRequest(res, "Invalid action result.", ERROR_CODES.VALIDATION_ERROR);
    return;
  }
  const actionId = String(req.params.actionId);
  const existing = await db.execute(sql`
    SELECT id, action_type, status
    FROM agent_response_actions
    WHERE id = ${actionId} AND sensor_id = ${sensorId} AND org_id = ${orgId}
    LIMIT 1
  `);
  const actionRow = existing.rows?.[0];
  const action =
    actionRow &&
    typeof actionRow.id === "string" &&
    typeof actionRow.action_type === "string" &&
    typeof actionRow.status === "string"
      ? actionRow
      : null;
  if (!action) {
    replyNotFound(res, "Action not found for this sensor.");
    return;
  }
  if (action.status !== "executing") {
    replyConflict(res, `Action cannot accept a result from status '${action.status}'.`, "ACTION_NOT_EXECUTING");
    return;
  }
  const updated = await db.execute(sql`
    UPDATE agent_response_actions
    SET status = ${parsed.data.status},
        completed_at = NOW(),
        result_output = ${parsed.data.resultOutput ?? ""},
        result_error = ${parsed.data.resultError ?? null},
        updated_at = NOW()
    WHERE id = ${actionId} AND sensor_id = ${sensorId} AND org_id = ${orgId} AND status = 'executing'
    RETURNING id
  `);
  const rows = (updated as { rows?: unknown[] }).rows ?? [];
  if (rows.length === 0) {
    replyConflict(res, "Action is no longer executing.", "ACTION_NOT_EXECUTING");
    return;
  }
  reply(res, { actionId, status: parsed.data.status });
}

async function handleCollectorHeartbeat(req: Request, res: Response): Promise<void> {
  const context = req.collectorAgentContext;
  if (!context) {
    replyUnauthenticated(res, "Collector authentication required.", ERROR_CODES.API_KEY_INVALID);
    return;
  }
  const parsed = collectorHeartbeatSchema.safeParse(req.body);
  if (!parsed.success) {
    replyBadRequest(res, "Invalid collector heartbeat.", ERROR_CODES.VALIDATION_ERROR);
    return;
  }
  const [updated] = await db
    .update(collectorInstances)
    .set({
      hostInfo: parsed.data.hostInfo,
      metrics: parsed.data.metrics,
      lastHeartbeatAt: new Date(),
      status: "active",
      lifecycleState: sql`CASE WHEN ${collectorInstances.lastDataAt} IS NULL THEN 'online-but-zero-telemetry' ELSE 'receiving-telemetry' END`,
      updatedAt: new Date(),
    })
    .where(
      and(
        eq(collectorInstances.id, context.collectorId),
        eq(collectorInstances.orgId, context.orgId),
        isNull(collectorInstances.revokedAt),
      ),
    )
    .returning({ id: collectorInstances.id, lastHeartbeatAt: collectorInstances.lastHeartbeatAt });
  if (!updated) {
    replyUnauthenticated(res, "Collector is revoked or no longer exists.", ERROR_CODES.API_KEY_INVALID);
    return;
  }
  reply(res, { status: "ok", collectorId: updated.id, lastHeartbeatAt: updated.lastHeartbeatAt });
}

async function handleCollectorEvents(req: Request, res: Response): Promise<void> {
  const context = req.collectorAgentContext;
  if (!context) {
    replyUnauthenticated(res, "Collector authentication required.", ERROR_CODES.API_KEY_INVALID);
    return;
  }
  const parsed = collectorIngestSchema.safeParse(req.body);
  if (!parsed.success) {
    replyBadRequest(res, "Invalid collector event batch.", ERROR_CODES.VALIDATION_ERROR);
    return;
  }
  const batchId = parsed.data.batchId ?? `collector-${Date.now()}-${randomUUID()}`;
  const result = await db.transaction(async (tx) => {
    const [claimed] = await tx
      .insert(collectorIngestBatches)
      .values({ orgId: context.orgId, collectorId: context.collectorId, batchId, accepted: 0 })
      .onConflictDoNothing({
        target: [collectorIngestBatches.collectorId, collectorIngestBatches.batchId],
      })
      .returning({ id: collectorIngestBatches.id });
    if (!claimed) {
      const [existingBatch] = await tx
        .select({ accepted: collectorIngestBatches.accepted })
        .from(collectorIngestBatches)
        .where(
          and(
            eq(collectorIngestBatches.collectorId, context.collectorId),
            eq(collectorIngestBatches.orgId, context.orgId),
            eq(collectorIngestBatches.batchId, batchId),
          ),
        )
        .limit(1);
      return { accepted: existingBatch?.accepted ?? 0, duplicate: true };
    }
    const created = await tx
      .insert(collectorEvents)
      .values(
        parsed.data.events.map((event) => ({
          collectorId: context.collectorId,
          orgId: context.orgId,
          eventType: event.eventType,
          severity: event.severity,
          source: event.source,
          rawData: event.rawData,
          tags: event.tags ?? [],
        })),
      )
      .returning({ id: collectorEvents.id });
    await tx
      .update(collectorInstances)
      .set({ lastDataAt: new Date(), lifecycleState: "receiving-telemetry", updatedAt: new Date() })
      .where(and(eq(collectorInstances.id, context.collectorId), eq(collectorInstances.orgId, context.orgId)));
    await tx
      .update(collectorIngestBatches)
      .set({ accepted: created.length })
      .where(
        and(
          eq(collectorIngestBatches.id, claimed.id),
          eq(collectorIngestBatches.orgId, context.orgId),
          eq(collectorIngestBatches.collectorId, context.collectorId),
        ),
      );
    return { accepted: created.length, duplicate: false };
  });
  reply(res, { ...result, batchId });
}

async function handleCollectorPackages(req: Request, res: Response): Promise<void> {
  const context = req.collectorAgentContext;
  if (!context) {
    replyUnauthenticated(res, "Collector authentication required.", ERROR_CODES.API_KEY_INVALID);
    return;
  }
  const parsed = collectorPackagesSchema.safeParse(req.body);
  if (!parsed.success) {
    replyBadRequest(res, "Invalid collector package inventory.", ERROR_CODES.VALIDATION_ERROR);
    return;
  }
  const batchId = parsed.data.batchId ?? `packages-${Date.now()}-${randomUUID()}`;
  const result = await db.transaction(async (tx) => {
    const [claimed] = await tx
      .insert(collectorIngestBatches)
      .values({ orgId: context.orgId, collectorId: context.collectorId, batchId, accepted: 0 })
      .onConflictDoNothing({ target: [collectorIngestBatches.collectorId, collectorIngestBatches.batchId] })
      .returning({ id: collectorIngestBatches.id });
    if (!claimed) {
      const [existingBatch] = await tx
        .select({ accepted: collectorIngestBatches.accepted })
        .from(collectorIngestBatches)
        .where(
          and(
            eq(collectorIngestBatches.collectorId, context.collectorId),
            eq(collectorIngestBatches.orgId, context.orgId),
            eq(collectorIngestBatches.batchId, batchId),
          ),
        )
        .limit(1);
      return { accepted: existingBatch?.accepted ?? 0, duplicate: true };
    }
    const created = await tx
      .insert(collectorEvents)
      .values(
        parsed.data.packages.map((pkg) => ({
          collectorId: context.collectorId,
          orgId: context.orgId,
          eventType: "package_inventory",
          severity: "info" as const,
          source: pkg.source ?? pkg.packageManager,
          rawData: {
            packageManager: pkg.packageManager,
            packageName: pkg.packageName,
            installedVersion: pkg.installedVersion,
            host: parsed.data.host ?? null,
            evidence: pkg.evidence ?? null,
          },
        })),
      )
      .returning({ id: collectorEvents.id });
    await tx
      .update(collectorInstances)
      .set({ lastDataAt: new Date(), lifecycleState: "receiving-telemetry", updatedAt: new Date() })
      .where(and(eq(collectorInstances.id, context.collectorId), eq(collectorInstances.orgId, context.orgId)));
    await tx
      .update(collectorIngestBatches)
      .set({ accepted: created.length })
      .where(
        and(
          eq(collectorIngestBatches.id, claimed.id),
          eq(collectorIngestBatches.orgId, context.orgId),
          eq(collectorIngestBatches.collectorId, context.collectorId),
        ),
      );
    return { accepted: created.length, duplicate: false };
  });
  reply(res, { ...result, batchId });
}

async function handleEnrollment(req: Request, res: Response): Promise<void> {
  const parsed = enrollSchema.safeParse(req.body);
  if (!parsed.success) {
    replyBadRequest(res, "Invalid enrollment payload.", ERROR_CODES.VALIDATION_ERROR);
    return;
  }

  const tokenHash = hashApiKey(parsed.data.enrollmentToken);
  try {
    const result = await db.transaction(async (tx) => {
      const [token] = await tx
        .select()
        .from(sensorEnrollmentTokens)
        .where(eq(sensorEnrollmentTokens.tokenHash, tokenHash))
        .limit(1);
      const now = new Date();
      if (!token || token.revokedAt || token.expiresAt <= now) {
        throw new EnrollmentError("Enrollment token is expired, revoked, or invalid.", "ENROLLMENT_TOKEN_INVALID");
      }
      if (token.useCount >= token.maxUses) {
        throw new EnrollmentError("Enrollment token has reached its maximum uses.", "ENROLLMENT_TOKEN_EXHAUSTED");
      }
      if (token.platformHint && token.platformHint !== parsed.data.platform) {
        throw new EnrollmentError(
          "Enrollment token is restricted to another platform.",
          "ENROLLMENT_PLATFORM_MISMATCH",
        );
      }

      const [claimed] = await tx
        .update(sensorEnrollmentTokens)
        .set({ useCount: sql`${sensorEnrollmentTokens.useCount} + 1`, updatedAt: now })
        .where(
          and(
            eq(sensorEnrollmentTokens.id, token.id),
            lt(sensorEnrollmentTokens.useCount, sensorEnrollmentTokens.maxUses),
            isNull(sensorEnrollmentTokens.revokedAt),
            gt(sensorEnrollmentTokens.expiresAt, now),
          ),
        )
        .returning({ orgId: sensorEnrollmentTokens.orgId, createdBy: sensorEnrollmentTokens.createdBy });
      if (!claimed) {
        throw new EnrollmentError("Enrollment token has reached its maximum uses.", "ENROLLMENT_TOKEN_EXHAUSTED");
      }

      if (parsed.data.agentType === "collector") {
        if (!parsed.data.collectorId) {
          throw new EnrollmentError("collectorId is required for collector enrollment.", "COLLECTOR_ID_REQUIRED");
        }
        const [collector] = await tx
          .select({ id: collectorInstances.id, orgId: collectorInstances.orgId })
          .from(collectorInstances)
          .where(
            and(
              eq(collectorInstances.id, parsed.data.collectorId),
              eq(collectorInstances.orgId, claimed.orgId),
              isNull(collectorInstances.revokedAt),
            ),
          )
          .limit(1);
        if (!collector) throw new EnrollmentError("Collector not found for this organization.", "COLLECTOR_NOT_FOUND");
        const { key, hash, prefix } = createCollectorAgentKey(collector.id);
        await tx
          .update(collectorInstances)
          .set({ apiKey: hash, apiKeyPrefix: prefix, revokedAt: null, updatedAt: now })
          .where(and(eq(collectorInstances.id, collector.id), eq(collectorInstances.orgId, claimed.orgId)));
        return { collector, key, orgId: claimed.orgId, createdBy: claimed.createdBy };
      }
      const sensorId = randomUUID();
      const { key, hash } = createSensorAgentKey(sensorId);
      const machineIdentity = parsed.data.machineIdentity ?? null;
      const machineIdentitySource = parsed.data.machineIdentitySource ?? null;
      const identityCondition =
        machineIdentity && machineIdentitySource
          ? and(
              eq(nativeSensors.machineIdentity, machineIdentity),
              eq(nativeSensors.machineIdentitySource, machineIdentitySource),
            )
          : null;
      const legacyCondition = and(
        isNull(nativeSensors.machineIdentity),
        isNull(nativeSensors.machineIdentitySource),
        eq(nativeSensors.hostname, parsed.data.hostname),
        eq(nativeSensors.platform, parsed.data.platform),
      );
      const priorConditions = and(
        eq(nativeSensors.orgId, claimed.orgId),
        isNull(nativeSensors.revokedAt),
        sql`${nativeSensors.status} <> 'superseded'`,
        identityCondition ? or(identityCondition, legacyCondition) : legacyCondition,
      );
      const priorCandidates = await tx
        .select({
          id: nativeSensors.id,
          hostname: nativeSensors.hostname,
          platform: nativeSensors.platform,
          machineIdentity: nativeSensors.machineIdentity,
          machineIdentitySource: nativeSensors.machineIdentitySource,
        })
        .from(nativeSensors)
        .where(priorConditions)
        .orderBy(
          sql`CASE WHEN ${nativeSensors.machineIdentity} IS NULL THEN 1 ELSE 0 END`,
          desc(nativeSensors.createdAt),
        );
      const supersessionMatches = getSensorSupersessionMatches(priorCandidates, {
        hostname: parsed.data.hostname,
        platform: parsed.data.platform,
        machineIdentity,
        machineIdentitySource,
      });
      const supersessionBases = new Set(supersessionMatches.map(({ basis }) => basis));
      const supersessionMatchBasis =
        supersessionBases.size === 0 ? null : supersessionBases.size === 1 ? supersessionMatches[0].basis : "multiple";
      const [sensor] = await tx
        .insert(nativeSensors)
        .values({
          id: sensorId,
          orgId: claimed.orgId,
          hostname: parsed.data.hostname,
          platform: parsed.data.platform,
          osVersion: parsed.data.osVersion ?? null,
          agentVersion: parsed.data.agentVersion ?? null,
          machineIdentity,
          machineIdentitySource,
          supersessionMatchBasis,
          apiKey: hash,
          status: "provisioning",
        })
        .returning({ id: nativeSensors.id, orgId: nativeSensors.orgId, hostname: nativeSensors.hostname });
      if (!sensor) throw new EnrollmentError("Failed to create sensor.", "ENROLLMENT_FAILED");
      for (const { candidate, basis } of supersessionMatches) {
        await tx
          .update(nativeSensors)
          .set({
            status: "superseded",
            supersededAt: now,
            supersededBySensorId: sensor.id,
            supersessionMatchBasis: basis,
            updatedAt: now,
          })
          .where(
            and(
              eq(nativeSensors.id, candidate.id),
              eq(nativeSensors.orgId, claimed.orgId),
              isNull(nativeSensors.revokedAt),
              sql`${nativeSensors.status} <> 'superseded'`,
            ),
          );
      }
      return { sensor, key, orgId: claimed.orgId, createdBy: claimed.createdBy };
    });

    if ("collector" in result) {
      if (!result.collector) {
        replyError(res, 400, [{ code: "ENROLLMENT_FAILED", message: "Failed to enroll collector." }]);
        return;
      }
      await createAuditLog({
        orgId: result.orgId,
        userId: result.createdBy,
        action: "collector_enrolled",
        resourceType: "collector_instance",
        resourceId: result.collector.id,
        details: { platform: parsed.data.platform },
      });
      reply(res, { collectorId: result.collector.id, apiKey: result.key }, {}, 201);
    } else {
      await createAuditLog({
        orgId: result.orgId,
        userId: result.createdBy,
        action: "sensor_enrolled",
        resourceType: "native_sensor",
        resourceId: result.sensor.id,
        details: { hostname: result.sensor.hostname, platform: parsed.data.platform },
      });
      reply(res, { sensorId: result.sensor.id, apiKey: result.key }, {}, 201);
    }
  } catch (error) {
    if (error instanceof EnrollmentError) {
      replyError(res, 400, [{ code: error.code, message: error.message }]);
      return;
    }
    log.error("Sensor enrollment failed", { error: String(error) });
    replyError(res, 500, [{ code: ERROR_CODES.INTERNAL_ERROR, message: "Sensor enrollment failed." }]);
  }
}

export function registerAgentRoutes(app: Express): void {
  const sensorLimiter = rateLimit({
    windowMs: 60_000,
    limit: 120,
    keyGenerator: (req) => req.agentContext?.sensorId ?? "unauthenticated",
    standardHeaders: true,
    legacyHeaders: false,
  });
  const collectorLimiter = rateLimit({
    windowMs: 60_000,
    limit: 120,
    keyGenerator: (req) => req.collectorAgentContext?.collectorId ?? "unauthenticated",
    standardHeaders: true,
    legacyHeaders: false,
  });
  const enrollmentLimiter = rateLimit({
    windowMs: 60_000,
    limit: 20,
    standardHeaders: true,
    legacyHeaders: false,
  });

  app.post("/api/agent/v1/enroll", enrollmentLimiter, handleEnrollment);
  app.post(
    "/api/agent/v1/sensors/:id/heartbeat",
    agentAuth,
    sensorLimiter,
    sensorPathMatchesContext,
    handleSensorHeartbeat,
  );
  app.post("/api/agent/v1/sensors/:id/events", agentAuth, sensorLimiter, sensorPathMatchesContext, handleSensorEvents);
  app.post(
    "/api/agent/v1/sensors/:id/packages",
    agentAuth,
    sensorLimiter,
    sensorPathMatchesContext,
    handleSensorPackages,
  );
  app.get(
    "/api/agent/v1/sensors/:id/pending-actions",
    agentAuth,
    sensorLimiter,
    sensorPathMatchesContext,
    handlePendingActions,
  );
  app.post(
    "/api/agent/v1/sensors/:id/rotate-key",
    agentAuth,
    sensorLimiter,
    sensorPathMatchesContext,
    handleRotateSensorKey,
  );
  app.post(
    "/api/agent/v1/sensors/:id/action-result/:actionId",
    agentAuth,
    sensorLimiter,
    sensorPathMatchesContext,
    handleActionResult,
  );
  app.delete("/api/agent/v1/sensors/:id", agentAuth, sensorLimiter, sensorPathMatchesContext, handleDeregisterSensor);
  app.post("/api/agent/v1/collectors/heartbeat", collectorAgentAuth, collectorLimiter, handleCollectorHeartbeat);
  app.post("/api/agent/v1/collectors/events", collectorAgentAuth, collectorLimiter, handleCollectorEvents);
  app.post("/api/agent/v1/collectors/packages", collectorAgentAuth, collectorLimiter, handleCollectorPackages);

  app.post(
    "/api/native-sensors/enrollment-tokens",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      const parsed = enrollmentTokenSchema.safeParse(req.body);
      if (!parsed.success) {
        replyBadRequest(res, "Invalid enrollment token request.", ERROR_CODES.VALIDATION_ERROR);
        return;
      }
      if (parsed.data.expiresAt <= new Date()) {
        replyBadRequest(res, "expiresAt must be in the future.", ERROR_CODES.VALIDATION_ERROR);
        return;
      }
      const plaintextToken = `snx_enroll_${randomBytes(32).toString("hex")}`;
      const [token] = await db
        .insert(sensorEnrollmentTokens)
        .values({
          orgId: getOrgId(req),
          tokenHash: hashApiKey(plaintextToken),
          label: parsed.data.label,
          maxUses: parsed.data.maxUses,
          expiresAt: parsed.data.expiresAt,
          createdBy: String((req.user as { id?: string } | undefined)?.id ?? ""),
          platformHint: parsed.data.platformHint ?? null,
        })
        .returning({
          id: sensorEnrollmentTokens.id,
          orgId: sensorEnrollmentTokens.orgId,
          label: sensorEnrollmentTokens.label,
          maxUses: sensorEnrollmentTokens.maxUses,
          expiresAt: sensorEnrollmentTokens.expiresAt,
          platformHint: sensorEnrollmentTokens.platformHint,
        });
      reply(res, { ...token, enrollmentToken: plaintextToken }, {}, 201);
    },
  );

  app.post(
    "/api/native-sensors/:id/revoke",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      const orgId = getOrgId(req);
      const [updated] = await db
        .update(nativeSensors)
        .set({ revokedAt: new Date(), status: "revoked", updatedAt: new Date() })
        .where(
          and(
            eq(nativeSensors.id, String(req.params.id)),
            eq(nativeSensors.orgId, orgId),
            isNull(nativeSensors.revokedAt),
          ),
        )
        .returning({ id: nativeSensors.id });
      if (!updated) {
        replyNotFound(res, "Sensor not found.");
        return;
      }
      await createAuditLog({
        orgId,
        userId: String((req.user as { id?: string } | undefined)?.id ?? ""),
        action: "sensor_revoked",
        resourceType: "native_sensor",
        resourceId: updated.id,
      });
      reply(res, { sensorId: updated.id, status: "revoked" });
    },
  );

  app.post(
    "/api/native-sensors/enrollment-tokens/:id/revoke",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      const orgId = getOrgId(req);
      const [updated] = await db
        .update(sensorEnrollmentTokens)
        .set({ revokedAt: new Date(), updatedAt: new Date() })
        .where(
          and(
            eq(sensorEnrollmentTokens.id, String(req.params.id)),
            eq(sensorEnrollmentTokens.orgId, orgId),
            isNull(sensorEnrollmentTokens.revokedAt),
          ),
        )
        .returning({ id: sensorEnrollmentTokens.id });
      if (!updated) {
        replyNotFound(res, "Enrollment token not found.");
        return;
      }
      await createAuditLog({
        orgId,
        userId: String((req.user as { id?: string } | undefined)?.id ?? ""),
        action: "sensor_enrollment_token_revoked",
        resourceType: "sensor_enrollment_token",
        resourceId: updated.id,
      });
      reply(res, { tokenId: updated.id, status: "revoked" });
    },
  );
}

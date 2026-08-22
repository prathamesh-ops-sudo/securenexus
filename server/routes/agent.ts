import type { Express, NextFunction, Request, Response } from "express";
import rateLimit from "express-rate-limit";
import { randomBytes, randomUUID } from "node:crypto";
import { and, eq, gt, isNull, lt, sql } from "drizzle-orm";
import { z } from "zod";
import { db } from "../db";
import {
  collectorEvents,
  collectorInstances,
  nativeSensors,
  SENSOR_EVENT_TYPES,
  SENSOR_PLATFORMS,
  sensorEnrollmentTokens,
  sensorEvents,
  sensorIngestBatches,
} from "../../shared/schema";
import { createAuditLog } from "../storage/audit";
import { processEventBatch } from "../native-detections";
import { expireTimedOutResponseActions } from "../response-action-timeouts";
import { logger, getOrgId, hashApiKey } from "./shared";
import { isAuthenticated } from "../auth";
import { resolveOrgContext, requireOrgId, requireMinRole } from "../rbac";
import { agentAuth, collectorAgentAuth, createSensorAgentKey, type AgentContext } from "../agent-auth";
import {
  ERROR_CODES,
  reply,
  replyBadRequest,
  replyConflict,
  replyError,
  replyNotFound,
  replyUnauthenticated,
} from "../api-response";

const log = logger.child("agent-api");
const MAX_SENSOR_EVENTS = 500;
const MAX_COLLECTOR_EVENTS = 500;

const enrollmentTokenSchema = z.object({
  label: z.string().trim().min(1).max(200),
  maxUses: z.number().int().min(1).max(100_000).default(1),
  expiresAt: z.coerce.date(),
  platformHint: z.enum(SENSOR_PLATFORMS).optional(),
});

const enrollSchema = z.object({
  enrollmentToken: z.string().trim().min(1).max(300),
  hostname: z.string().trim().min(1).max(200),
  platform: z.enum(SENSOR_PLATFORMS),
  osVersion: z.string().trim().max(200).optional(),
  agentVersion: z.string().trim().max(100).optional(),
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
  const created = await db
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
  await db
    .update(collectorInstances)
    .set({ lastDataAt: new Date(), updatedAt: new Date() })
    .where(and(eq(collectorInstances.id, context.collectorId), eq(collectorInstances.orgId, context.orgId)));
  reply(res, { accepted: created.length, duplicate: false });
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

      const sensorId = randomUUID();
      const { key, hash } = createSensorAgentKey(sensorId);
      const [sensor] = await tx
        .insert(nativeSensors)
        .values({
          id: sensorId,
          orgId: claimed.orgId,
          hostname: parsed.data.hostname,
          platform: parsed.data.platform,
          osVersion: parsed.data.osVersion ?? null,
          agentVersion: parsed.data.agentVersion ?? null,
          apiKey: hash,
          status: "provisioning",
        })
        .returning({ id: nativeSensors.id, orgId: nativeSensors.orgId, hostname: nativeSensors.hostname });
      return { sensor, key, orgId: claimed.orgId, createdBy: claimed.createdBy };
    });

    await createAuditLog({
      orgId: result.orgId,
      userId: result.createdBy,
      action: "sensor_enrolled",
      resourceType: "native_sensor",
      resourceId: result.sensor.id,
      details: { hostname: result.sensor.hostname, platform: parsed.data.platform },
    });
    reply(res, { sensorId: result.sensor.id, apiKey: result.key }, {}, 201);
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

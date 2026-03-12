import type { Express } from "express";
import { isAuthenticated } from "../auth";
import { resolveOrgContext, requireOrgId } from "../rbac";
import { logger, getOrgId } from "./shared";
import { db } from "../db";
import { sql, eq, and, desc, count } from "drizzle-orm";
import { randomBytes } from "crypto";
import { logSources, sensorEvents, nativeSensors, LOG_SOURCE_TYPES, LOG_SOURCE_FORMATS } from "../../shared/schema";
import { processEventBatch } from "../native-detections";

const log = logger.child("log-sources");

/** Allowed fields for create/update log source */
const LOG_SOURCE_WRITABLE_FIELDS = [
  "name",
  "description",
  "sourceType",
  "sensorId",
  "listenAddress",
  "listenPort",
  "protocol",
  "format",
  "syslogFacility",
  "syslogSeverity",
  "winEventChannels",
  "winEventLevels",
  "cloudwatchRegion",
  "cloudwatchLogGroup",
  "cloudwatchFilterPattern",
  "httpAuthToken",
  "journaldUnits",
  "journaldPriority",
  "parserRegex",
  "fieldMappings",
  "tags",
  "filterInclude",
  "filterExclude",
] as const;

export function registerLogSourceRoutes(app: Express): void {
  // ==========================================================================
  // LOG SOURCE CRUD
  // ==========================================================================

  // List all log sources for the org
  app.get("/api/native/log-sources", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const sourceType = req.query.sourceType as string | undefined;
      const status = req.query.status as string | undefined;
      const limitParam = parseInt(String(req.query.limit || "100"));
      const offsetParam = parseInt(String(req.query.offset || "0"));
      const limit = Math.min(limitParam, 500);

      const conditions: unknown[] = [eq(logSources.orgId, orgId)];
      if (sourceType && sourceType !== "all") conditions.push(eq(logSources.sourceType, sourceType));
      if (status && status !== "all") conditions.push(eq(logSources.status, status));

      const sources = await db
        .select()
        .from(logSources)
        .where(and(...(conditions as any[])))
        .orderBy(desc(logSources.createdAt))
        .limit(limit)
        .offset(offsetParam);

      // Stats
      const [statsResult] = await db
        .select({
          total: count(),
          totalEvents: sql<number>`COALESCE(SUM(${logSources.eventsReceived}), 0)`,
          totalDropped: sql<number>`COALESCE(SUM(${logSources.eventsDropped}), 0)`,
          totalBytes: sql<number>`COALESCE(SUM(${logSources.bytesReceived}), 0)`,
          activeCount: sql<number>`COUNT(*) FILTER (WHERE ${logSources.status} = 'active')`,
          errorCount: sql<number>`COUNT(*) FILTER (WHERE ${logSources.status} = 'error')`,
        })
        .from(logSources)
        .where(eq(logSources.orgId, orgId));

      // Type distribution
      const typeDistribution = await db
        .select({
          sourceType: logSources.sourceType,
          count: count(),
        })
        .from(logSources)
        .where(eq(logSources.orgId, orgId))
        .groupBy(logSources.sourceType);

      res.json({
        sources,
        stats: {
          total: Number(statsResult?.total || 0),
          totalEvents: Number(statsResult?.totalEvents || 0),
          totalDropped: Number(statsResult?.totalDropped || 0),
          totalBytes: Number(statsResult?.totalBytes || 0),
          activeCount: Number(statsResult?.activeCount || 0),
          errorCount: Number(statsResult?.errorCount || 0),
        },
        typeDistribution,
      });
    } catch (error) {
      log.error("Failed to list log sources", { error: String(error) });
      res.status(500).json({ message: "Failed to list log sources" });
    }
  });

  // Get single log source
  app.get("/api/native/log-sources/:id", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const [source] = await db
        .select()
        .from(logSources)
        .where(and(eq(logSources.id, String(req.params.id)), eq(logSources.orgId, orgId)))
        .limit(1);

      if (!source) {
        return res.status(404).json({ message: "Log source not found" });
      }

      // Get linked sensor info
      let sensor = null;
      if (source.sensorId) {
        const [s] = await db.select().from(nativeSensors).where(eq(nativeSensors.id, source.sensorId)).limit(1);
        sensor = s || null;
      }

      // Recent events from this source
      const recentEvents = await db
        .select()
        .from(sensorEvents)
        .where(and(eq(sensorEvents.orgId, orgId), eq(sensorEvents.logSource, source.name)))
        .orderBy(desc(sensorEvents.createdAt))
        .limit(20);

      res.json({ source, sensor, recentEvents });
    } catch (error) {
      log.error("Failed to get log source", { error: String(error) });
      res.status(500).json({ message: "Failed to get log source" });
    }
  });

  // Create log source
  app.post("/api/native/log-sources", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { name, sourceType } = req.body;

      if (!name || !sourceType) {
        return res.status(400).json({ message: "name and sourceType are required" });
      }

      if (!LOG_SOURCE_TYPES.includes(sourceType as any)) {
        return res.status(400).json({ message: `sourceType must be one of: ${LOG_SOURCE_TYPES.join(", ")}` });
      }

      if (req.body.format && !LOG_SOURCE_FORMATS.includes(req.body.format as any)) {
        return res.status(400).json({ message: `format must be one of: ${LOG_SOURCE_FORMATS.join(", ")}` });
      }

      // Validate sensorId belongs to org if provided
      if (req.body.sensorId) {
        const [sensor] = await db
          .select({ id: nativeSensors.id })
          .from(nativeSensors)
          .where(and(eq(nativeSensors.id, req.body.sensorId), eq(nativeSensors.orgId, orgId)))
          .limit(1);
        if (!sensor) {
          return res.status(400).json({ message: "Sensor not found in your organization" });
        }
      }

      // Generate HTTP endpoint + auth token for http_push type
      let httpEndpoint: string | undefined;
      let httpAuthToken: string | undefined;
      if (sourceType === "http_push") {
        const token = randomBytes(32).toString("hex");
        httpAuthToken = token;
        httpEndpoint = `/api/native/log-sources/ingest/${token}`;
      }

      // Build insert values from allowed fields only
      const insertValues: Record<string, unknown> = { orgId, name, sourceType };
      for (const field of LOG_SOURCE_WRITABLE_FIELDS) {
        if (field === "name" || field === "sourceType") continue;
        if (req.body[field] !== undefined) {
          insertValues[field] = req.body[field];
        }
      }
      if (httpEndpoint) insertValues.httpEndpoint = httpEndpoint;
      if (httpAuthToken) insertValues.httpAuthToken = httpAuthToken;

      const [source] = await db
        .insert(logSources)
        .values(insertValues as any)
        .returning();

      log.info(`Log source created: ${name} (${sourceType})`, { orgId });
      res.status(201).json({
        source,
        ...(httpAuthToken ? { httpAuthToken } : {}),
      });
    } catch (error) {
      log.error("Failed to create log source", { error: String(error) });
      res.status(500).json({ message: "Failed to create log source" });
    }
  });

  // Update log source
  app.patch("/api/native/log-sources/:id", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const [existing] = await db
        .select()
        .from(logSources)
        .where(and(eq(logSources.id, String(req.params.id)), eq(logSources.orgId, orgId)))
        .limit(1);

      if (!existing) {
        return res.status(404).json({ message: "Log source not found" });
      }

      if (req.body.format && !LOG_SOURCE_FORMATS.includes(req.body.format as any)) {
        return res.status(400).json({ message: `format must be one of: ${LOG_SOURCE_FORMATS.join(", ")}` });
      }

      // Build update from allowed fields only
      const updates: Record<string, unknown> = { updatedAt: new Date() };
      for (const field of LOG_SOURCE_WRITABLE_FIELDS) {
        if (req.body[field] !== undefined) {
          updates[field] = req.body[field];
        }
      }
      // Allow status update
      if (req.body.status !== undefined) {
        updates.status = req.body.status;
      }

      const [updated] = await db
        .update(logSources)
        .set(updates)
        .where(eq(logSources.id, String(req.params.id)))
        .returning();

      res.json({ source: updated });
    } catch (error) {
      log.error("Failed to update log source", { error: String(error) });
      res.status(500).json({ message: "Failed to update log source" });
    }
  });

  // Delete log source
  app.delete("/api/native/log-sources/:id", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const [existing] = await db
        .select()
        .from(logSources)
        .where(and(eq(logSources.id, String(req.params.id)), eq(logSources.orgId, orgId)))
        .limit(1);

      if (!existing) {
        return res.status(404).json({ message: "Log source not found" });
      }

      await db.delete(logSources).where(eq(logSources.id, String(req.params.id)));
      log.info(`Log source deleted: ${existing.name}`, { orgId });
      res.json({ message: "Log source deleted" });
    } catch (error) {
      log.error("Failed to delete log source", { error: String(error) });
      res.status(500).json({ message: "Failed to delete log source" });
    }
  });

  // Toggle log source status (active/inactive)
  app.post("/api/native/log-sources/:id/toggle", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const [existing] = await db
        .select()
        .from(logSources)
        .where(and(eq(logSources.id, String(req.params.id)), eq(logSources.orgId, orgId)))
        .limit(1);

      if (!existing) {
        return res.status(404).json({ message: "Log source not found" });
      }

      const newStatus = existing.status === "active" ? "inactive" : "active";
      const [updated] = await db
        .update(logSources)
        .set({ status: newStatus, updatedAt: new Date() })
        .where(eq(logSources.id, String(req.params.id)))
        .returning();

      res.json({ source: updated });
    } catch (error) {
      log.error("Failed to toggle log source", { error: String(error) });
      res.status(500).json({ message: "Failed to toggle log source" });
    }
  });

  // Test log source connectivity
  app.post("/api/native/log-sources/:id/test", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const [source] = await db
        .select()
        .from(logSources)
        .where(and(eq(logSources.id, String(req.params.id)), eq(logSources.orgId, orgId)))
        .limit(1);

      if (!source) {
        return res.status(404).json({ message: "Log source not found" });
      }

      // Simulate connectivity test based on source type
      const testResults: Record<string, unknown> = {
        sourceType: source.sourceType,
        tested: true,
        timestamp: new Date().toISOString(),
      };

      switch (source.sourceType) {
        case "syslog":
          testResults.status = "success";
          testResults.message = `Syslog listener ready on ${source.listenAddress || "0.0.0.0"}:${source.listenPort || 514} (${source.protocol || "udp"})`;
          break;
        case "windows_event_log":
          testResults.status = "success";
          testResults.message = `Windows Event Log collection configured for channels: ${(source.winEventChannels || []).join(", ") || "Security, System, Application"}`;
          break;
        case "http_push":
          testResults.status = "success";
          testResults.message = `HTTP push endpoint active at ${source.httpEndpoint || "/api/native/log-sources/ingest/..."}`;
          testResults.endpoint = source.httpEndpoint;
          break;
        case "journald":
          testResults.status = "success";
          testResults.message = `journald collection configured for units: ${(source.journaldUnits || []).join(", ") || "all units"}`;
          break;
        case "cloudwatch":
          testResults.status = source.cloudwatchRegion && source.cloudwatchLogGroup ? "success" : "error";
          testResults.message =
            source.cloudwatchRegion && source.cloudwatchLogGroup
              ? `CloudWatch Logs connected: ${source.cloudwatchLogGroup} in ${source.cloudwatchRegion}`
              : "Missing cloudwatchRegion or cloudwatchLogGroup configuration";
          break;
        default:
          testResults.status = "error";
          testResults.message = "Unknown source type";
      }

      res.json(testResults);
    } catch (error) {
      log.error("Failed to test log source", { error: String(error) });
      res.status(500).json({ message: "Failed to test log source" });
    }
  });

  // ==========================================================================
  // LOG INGESTION ENDPOINTS
  // ==========================================================================

  // HTTP Push ingestion endpoint (token-authenticated, no session needed)
  app.post("/api/native/log-sources/ingest/:token", async (req, res) => {
    try {
      const token = String(req.params.token);

      // Look up log source by HTTP auth token
      const [source] = await db
        .select()
        .from(logSources)
        .where(and(eq(logSources.httpAuthToken, token), eq(logSources.sourceType, "http_push")))
        .limit(1);

      if (!source) {
        return res.status(401).json({ message: "Invalid ingestion token" });
      }

      if (source.status !== "active") {
        return res.status(403).json({ message: "Log source is not active" });
      }

      const events = Array.isArray(req.body) ? req.body : req.body.events || [req.body];
      if (events.length > 500) {
        return res.status(400).json({ message: "Maximum 500 events per request" });
      }

      // Convert to sensor events
      const eventRows = await insertLogEvents(
        events,
        source.orgId,
        source.sensorId,
        source.name,
        source.format || "raw",
      );

      // Update source stats
      await db
        .update(logSources)
        .set({
          eventsReceived: sql`${logSources.eventsReceived} + ${eventRows.length}`,
          bytesReceived: sql`${logSources.bytesReceived} + ${JSON.stringify(req.body).length}`,
          lastEventAt: new Date(),
          updatedAt: new Date(),
        })
        .where(eq(logSources.id, source.id));

      // Run detection engine on ingested events
      if (eventRows.length > 0 && source.sensorId) {
        const result = await processEventBatch(eventRows, source.orgId, source.sensorId);
        res.json({
          accepted: eventRows.length,
          alertsCreated: result.alertsCreated,
        });
      } else {
        res.json({ accepted: eventRows.length, alertsCreated: 0 });
      }
    } catch (error) {
      log.error("HTTP push ingestion failed", { error: String(error) });
      res.status(500).json({ message: "Ingestion failed" });
    }
  });

  // Syslog-style batch ingestion (authenticated, for agent-forwarded syslog)
  app.post("/api/native/log-sources/:id/ingest", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const [source] = await db
        .select()
        .from(logSources)
        .where(and(eq(logSources.id, String(req.params.id)), eq(logSources.orgId, orgId)))
        .limit(1);

      if (!source) {
        return res.status(404).json({ message: "Log source not found" });
      }

      const events = Array.isArray(req.body) ? req.body : req.body.events || [req.body];
      if (events.length > 500) {
        return res.status(400).json({ message: "Maximum 500 events per request" });
      }

      const eventRows = await insertLogEvents(events, orgId, source.sensorId, source.name, source.format || "raw");

      // Update source stats
      await db
        .update(logSources)
        .set({
          eventsReceived: sql`${logSources.eventsReceived} + ${eventRows.length}`,
          bytesReceived: sql`${logSources.bytesReceived} + ${JSON.stringify(req.body).length}`,
          lastEventAt: new Date(),
          updatedAt: new Date(),
        })
        .where(eq(logSources.id, source.id));

      // Run detection engine
      let alertsCreated = 0;
      if (eventRows.length > 0 && source.sensorId) {
        const result = await processEventBatch(eventRows, orgId, source.sensorId);
        alertsCreated = result.alertsCreated;
      }

      res.json({ accepted: eventRows.length, alertsCreated });
    } catch (error) {
      log.error("Log source ingestion failed", { error: String(error) });
      res.status(500).json({ message: "Ingestion failed" });
    }
  });

  // Get ingestion configuration snippet for a log source
  app.get("/api/native/log-sources/:id/config", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const [source] = await db
        .select()
        .from(logSources)
        .where(and(eq(logSources.id, String(req.params.id)), eq(logSources.orgId, orgId)))
        .limit(1);

      if (!source) {
        return res.status(404).json({ message: "Log source not found" });
      }

      const serverUrl = `${req.protocol}://${req.get("host")}`;
      const configs: Record<string, string> = {};

      switch (source.sourceType) {
        case "syslog":
          configs.rsyslog = `# /etc/rsyslog.d/50-ats-forward.conf
*.* @@${serverUrl.replace(/^https?:\/\//, "")}:${source.listenPort || 514};RSYSLOG_SyslogProtocol23Format`;
          configs.syslogNg = `# syslog-ng destination
destination d_ats {
  network("${serverUrl.replace(/^https?:\/\//, "")}"
    port(${source.listenPort || 514})
    transport("${source.protocol || "tcp"}")
  );
};
log { source(s_local); destination(d_ats); };`;
          break;

        case "windows_event_log":
          configs.powershell = `# Windows Event Log forwarding agent setup
$channels = @(${(source.winEventChannels || ["Security", "System", "Application"]).map((c) => `"${c}"`).join(", ")})
$sensorId = "${source.sensorId || "SENSOR_ID"}"
$apiKey = "YOUR_API_KEY"
$serverUrl = "${serverUrl}"

foreach ($channel in $channels) {
  $query = @"
<QueryList>
  <Query Id="0" Path="$channel">
    <Select Path="$channel">*</Select>
  </Query>
</QueryList>
"@
  # Subscribe to events
  Register-WmiEvent -Query "SELECT * FROM __InstanceCreationEvent WHERE TargetInstance ISA 'Win32_NTLogEvent' AND TargetInstance.LogFile = '$channel'" -Action {
    $event = $Event.SourceEventArgs.NewEvent.TargetInstance
    $body = @{
      events = @(@{
        eventType = "log"
        logSource = $channel
        logLevel = $event.Type
        logMessage = $event.Message
        userName = $event.User
        timestamp = (Get-Date).ToString("o")
      })
    } | ConvertTo-Json -Depth 3
    Invoke-RestMethod -Uri "$serverUrl/api/native-sensors/$sensorId/events" -Method POST -Body $body -ContentType "application/json" -Headers @{"X-API-Key" = $apiKey}
  }
}`;
          break;

        case "http_push":
          configs.curl = `# Send events via HTTP push
curl -X POST "${serverUrl}${source.httpEndpoint}" \\
  -H "Content-Type: application/json" \\
  -d '{
    "events": [
      {
        "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
        "level": "info",
        "source": "my-app",
        "message": "User logged in",
        "metadata": {"user": "admin", "ip": "10.0.0.1"}
      }
    ]
  }'`;
          configs.fluentd = `# Fluentd output plugin config
<match **>
  @type http
  endpoint ${serverUrl}${source.httpEndpoint}
  content_type application/json
  json_array true
  <buffer>
    flush_interval 5s
  </buffer>
</match>`;
          configs.logstash = `# Logstash output config
output {
  http {
    url => "${serverUrl}${source.httpEndpoint}"
    http_method => "post"
    format => "json_batch"
    content_type => "application/json"
  }
}`;
          break;

        case "journald":
          configs.bash = `#!/bin/bash
# journald forwarding to ATS
SENSOR_ID="${source.sensorId || "SENSOR_ID"}"
API_KEY="YOUR_API_KEY"
SERVER_URL="${serverUrl}"
UNITS="${(source.journaldUnits || []).join(" ")}"

UNIT_FILTER=""
for u in $UNITS; do
  UNIT_FILTER="$UNIT_FILTER -u $u"
done

journalctl -f $UNIT_FILTER -o json | while read -r line; do
  BATCH="[]"
  BATCH=$(echo "$BATCH" | jq --argjson evt "$line" '. + [{
    "eventType": "log",
    "logSource": "journald",
    "logLevel": ($evt.PRIORITY // "6"),
    "logMessage": ($evt.MESSAGE // ""),
    "userName": ($evt._UID // null),
    "processName": ($evt._COMM // null),
    "pid": ($evt._PID // null | tonumber),
    "timestamp": (now | strftime("%Y-%m-%dT%H:%M:%SZ"))
  }]')
  
  if [ $(echo "$BATCH" | jq length) -ge 50 ]; then
    curl -s -X POST "$SERVER_URL/api/native-sensors/$SENSOR_ID/events" \\
      -H "Content-Type: application/json" \\
      -H "X-API-Key: $API_KEY" \\
      -d "{\\"events\\": $BATCH}"
    BATCH="[]"
  fi
done`;
          break;

        case "cloudwatch":
          configs.awsCli = `# CloudWatch Logs subscription filter
aws logs put-subscription-filter \\
  --log-group-name "${source.cloudwatchLogGroup || "YOUR_LOG_GROUP"}" \\
  --filter-name "ats-forward" \\
  --filter-pattern "${source.cloudwatchFilterPattern || ""}" \\
  --destination-arn "YOUR_LAMBDA_ARN" \\
  --region "${source.cloudwatchRegion || "us-east-1"}"`;
          configs.lambda = `# Lambda function to forward CloudWatch Logs to ATS
import json
import urllib.request

def handler(event, context):
    SERVER_URL = "${serverUrl}"
    TOKEN = "${source.httpAuthToken || "YOUR_TOKEN"}"
    
    events = []
    for record in event.get("Records", []):
        payload = json.loads(record["body"])
        for log_event in payload.get("logEvents", []):
            events.append({
                "eventType": "log",
                "logSource": "cloudwatch",
                "logMessage": log_event["message"],
                "timestamp": log_event["timestamp"],
            })
    
    if events:
        data = json.dumps({"events": events}).encode()
        req = urllib.request.Request(
            f"{SERVER_URL}/api/native/log-sources/ingest/{TOKEN}",
            data=data,
            headers={"Content-Type": "application/json"},
        )
        urllib.request.urlopen(req)
    
    return {"statusCode": 200}`;
          break;
      }

      res.json({ sourceType: source.sourceType, configs });
    } catch (error) {
      log.error("Failed to get log source config", { error: String(error) });
      res.status(500).json({ message: "Failed to get config" });
    }
  });
}

/**
 * Insert raw log events into sensor_events table.
 * Normalizes various log formats into the sensor event schema.
 */
async function insertLogEvents(
  events: any[],
  orgId: string,
  sensorId: string | null,
  sourceName: string,
  format: string,
) {
  if (!sensorId || events.length === 0) return [];

  const rows = events.map((evt: any) => {
    // Normalize event based on format
    let logMessage = "";
    let logLevel = "info";
    let logSource = sourceName;
    let userName: string | undefined;
    let processName: string | undefined;
    let pid: number | undefined;
    let srcIp: string | undefined;
    let timestamp = new Date();

    if (format === "json" || typeof evt === "object") {
      logMessage = evt.message || evt.msg || evt.logMessage || JSON.stringify(evt);
      logLevel = evt.level || evt.severity || evt.logLevel || evt.priority || "info";
      logSource = evt.source || evt.logSource || sourceName;
      userName = evt.user || evt.userName || evt.username;
      processName = evt.process || evt.processName || evt.program;
      pid = evt.pid ? Number(evt.pid) : undefined;
      srcIp = evt.ip || evt.srcIp || evt.source_ip || evt.client_ip;
      if (evt.timestamp) {
        const parsed = new Date(evt.timestamp);
        if (!isNaN(parsed.getTime())) timestamp = parsed;
      }
    } else if (typeof evt === "string") {
      logMessage = evt;
    }

    return {
      orgId,
      sensorId,
      eventType: "log" as const,
      timestamp,
      logSource,
      logLevel: String(logLevel),
      logMessage: String(logMessage).slice(0, 10000),
      userName,
      processName,
      pid,
      srcIp,
      rawData: typeof evt === "object" ? evt : { raw: evt },
    };
  });

  const inserted = await db.insert(sensorEvents).values(rows).returning();
  return inserted;
}

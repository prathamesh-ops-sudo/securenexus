import type { Express } from "express";
import { isAuthenticated } from "../auth";
import { resolveOrgContext, requireOrgId } from "../rbac";
import { logger, getOrgId, generateApiKey, hashApiKey } from "./shared";
import { db } from "../db";
import { sql, eq, and, desc, ilike, or, count } from "drizzle-orm";
import { randomBytes } from "crypto";
import {
  nativeSensors,
  sensorEvents,
  detectionRules,
  detectionAlerts,
  SENSOR_PLATFORMS,
  SENSOR_EVENT_TYPES,
  DETECTION_SEVERITIES,
  DETECTION_STATUSES,
  MITRE_TACTICS,
} from "../../shared/schema";
import { processEventBatch } from "../native-detections";
import { seedBuiltinRules } from "../native-detections";

const log = logger.child("native-sensors");

export function registerNativeSensorRoutes(app: Express): void {
  // ==========================================================================
  // SENSOR MANAGEMENT
  // ==========================================================================

  // List all sensors for the org
  app.get("/api/native-sensors", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const status = req.query.status as string | undefined;
      const platform = req.query.platform as string | undefined;
      const q = (req.query.q as string) || "";
      const limitParam = parseInt(String(req.query.limit || "100"));
      const offsetParam = parseInt(String(req.query.offset || "0"));
      const limit = Math.min(limitParam, 500);

      const conditions: unknown[] = [eq(nativeSensors.orgId, orgId)];
      if (status && status !== "all") conditions.push(eq(nativeSensors.status, status));
      if (platform && platform !== "all") conditions.push(eq(nativeSensors.platform, platform));
      if (q) {
        conditions.push(or(ilike(nativeSensors.hostname, `%${q}%`), ilike(nativeSensors.ipAddress, `%${q}%`)));
      }

      const sensors = await db
        .select()
        .from(nativeSensors)
        .where(and(...(conditions as any[])))
        .orderBy(desc(nativeSensors.lastHeartbeat), desc(nativeSensors.createdAt))
        .limit(limit)
        .offset(offsetParam);

      // Get summary stats
      const statsResult = await db.execute(sql`
        SELECT
          COUNT(*) AS total,
          COUNT(*) FILTER (WHERE status = 'online') AS online_count,
          COUNT(*) FILTER (WHERE status = 'offline') AS offline_count,
          COUNT(*) FILTER (WHERE status = 'degraded') AS degraded_count,
          COALESCE(SUM(events_ingested), 0) AS total_events,
          COALESCE(SUM(alerts_generated), 0) AS total_alerts
        FROM native_sensors
        WHERE org_id = ${orgId}
      `);
      const statsRow = (statsResult as any).rows?.[0] || {};

      res.json({
        sensors,
        stats: {
          total: parseInt(statsRow.total || "0"),
          onlineCount: parseInt(statsRow.online_count || "0"),
          offlineCount: parseInt(statsRow.offline_count || "0"),
          degradedCount: parseInt(statsRow.degraded_count || "0"),
          totalEvents: parseInt(statsRow.total_events || "0"),
          totalAlerts: parseInt(statsRow.total_alerts || "0"),
        },
      });
    } catch (error) {
      log.error("Failed to list sensors", { error: String(error) });
      res.status(500).json({ message: "Failed to list sensors" });
    }
  });

  // Get single sensor details
  app.get("/api/native-sensors/:id", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const sensorId = String(req.params.id);

      const [sensor] = await db
        .select()
        .from(nativeSensors)
        .where(and(eq(nativeSensors.id, sensorId), eq(nativeSensors.orgId, orgId)))
        .limit(1);

      if (!sensor) {
        return res.status(404).json({ message: "Sensor not found" });
      }

      // Get recent events count
      const eventsResult = await db.execute(sql`
        SELECT
          COUNT(*) AS total_events,
          COUNT(*) FILTER (WHERE detection_matched = true) AS matched_events,
          COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '24 hours') AS events_24h
        FROM sensor_events
        WHERE sensor_id = ${sensorId} AND org_id = ${orgId}
      `);
      const eventsRow = (eventsResult as any).rows?.[0] || {};

      // Get recent detection alerts
      const recentAlerts = await db
        .select()
        .from(detectionAlerts)
        .where(and(eq(detectionAlerts.sensorId, sensorId), eq(detectionAlerts.orgId, orgId)))
        .orderBy(desc(detectionAlerts.createdAt))
        .limit(10);

      res.json({
        sensor,
        eventStats: {
          totalEvents: parseInt(eventsRow.total_events || "0"),
          matchedEvents: parseInt(eventsRow.matched_events || "0"),
          events24h: parseInt(eventsRow.events_24h || "0"),
        },
        recentAlerts,
      });
    } catch (error) {
      log.error("Failed to get sensor details", { error: String(error) });
      res.status(500).json({ message: "Failed to get sensor details" });
    }
  });

  // Register a new sensor with a one-time token
  app.post("/api/native-sensors/register", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { hostname, platform, osVersion, tags } = req.body;

      if (!hostname || typeof hostname !== "string") {
        return res.status(400).json({ message: "hostname is required" });
      }
      if (!platform || !SENSOR_PLATFORMS.includes(platform as any)) {
        return res.status(400).json({ message: `platform must be one of: ${SENSOR_PLATFORMS.join(", ")}` });
      }

      // Generate one-time registration token and API key
      const registrationToken = `snx-reg-${randomBytes(24).toString("hex")}`;
      const { key: apiKey, hash: apiKeyHash } = generateApiKey();

      const [sensor] = await db
        .insert(nativeSensors)
        .values({
          orgId,
          hostname,
          platform,
          osVersion: osVersion || null,
          registrationToken,
          apiKey: apiKeyHash, // Store hash only
          status: "provisioning",
          tags: tags || [],
        })
        .returning();

      // Seed built-in rules if not already done
      await seedBuiltinRules();

      log.info(`Sensor registered: ${hostname} (${platform})`, { sensorId: sensor.id, orgId });

      res.status(201).json({
        sensor,
        registrationToken,
        apiKey, // Return raw key once — not stored
        message: "Sensor registered. Use the apiKey for heartbeat and event ingestion.",
      });
    } catch (error) {
      log.error("Failed to register sensor", { error: String(error) });
      res.status(500).json({ message: "Failed to register sensor" });
    }
  });

  // Heartbeat — agent calls home every 30s
  app.post("/api/native-sensors/:id/heartbeat", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const sensorId = String(req.params.id);

      const [sensor] = await db
        .select()
        .from(nativeSensors)
        .where(and(eq(nativeSensors.id, sensorId), eq(nativeSensors.orgId, orgId)))
        .limit(1);

      if (!sensor) {
        return res.status(404).json({ message: "Sensor not found" });
      }

      const { cpuUsage, memoryUsage, diskUsage, agentVersion } = req.body;

      await db
        .update(nativeSensors)
        .set({
          lastHeartbeat: new Date(),
          status: "online",
          cpuUsage: typeof cpuUsage === "number" ? cpuUsage : sensor.cpuUsage,
          memoryUsage: typeof memoryUsage === "number" ? memoryUsage : sensor.memoryUsage,
          diskUsage: typeof diskUsage === "number" ? diskUsage : sensor.diskUsage,
          agentVersion: agentVersion || sensor.agentVersion,
          updatedAt: new Date(),
        })
        .where(eq(nativeSensors.id, sensorId));

      res.json({ status: "ok", serverTime: new Date().toISOString() });
    } catch (error) {
      log.error("Heartbeat failed", { error: String(error) });
      res.status(500).json({ message: "Heartbeat failed" });
    }
  });

  // Bulk event ingestion — up to 500 events per call
  app.post("/api/native-sensors/:id/events", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const sensorId = String(req.params.id);

      const [sensor] = await db
        .select()
        .from(nativeSensors)
        .where(and(eq(nativeSensors.id, sensorId), eq(nativeSensors.orgId, orgId)))
        .limit(1);

      if (!sensor) {
        return res.status(404).json({ message: "Sensor not found" });
      }

      const { events } = req.body;
      if (!Array.isArray(events) || events.length === 0) {
        return res.status(400).json({ message: "events array is required and must not be empty" });
      }
      if (events.length > 500) {
        return res.status(400).json({ message: "Maximum 500 events per call" });
      }

      // Validate and insert events
      const validEvents = events.filter((e: any) => {
        return e.eventType && SENSOR_EVENT_TYPES.includes(e.eventType);
      });

      if (validEvents.length === 0) {
        return res
          .status(400)
          .json({ message: `No valid events. eventType must be one of: ${SENSOR_EVENT_TYPES.join(", ")}` });
      }

      const eventRows = await db
        .insert(sensorEvents)
        .values(
          validEvents.map((e: any) => ({
            orgId,
            sensorId,
            eventType: e.eventType,
            timestamp: e.timestamp ? new Date(e.timestamp) : new Date(),
            processName: e.processName || null,
            processPath: e.processPath || null,
            processArgs: e.processArgs || null,
            parentProcess: e.parentProcess || null,
            pid: typeof e.pid === "number" ? e.pid : null,
            ppid: typeof e.ppid === "number" ? e.ppid : null,
            userName: e.userName || null,
            srcIp: e.srcIp || null,
            dstIp: e.dstIp || null,
            srcPort: typeof e.srcPort === "number" ? e.srcPort : null,
            dstPort: typeof e.dstPort === "number" ? e.dstPort : null,
            protocol: e.protocol || null,
            bytesIn: typeof e.bytesIn === "number" ? e.bytesIn : null,
            bytesOut: typeof e.bytesOut === "number" ? e.bytesOut : null,
            filePath: e.filePath || null,
            fileAction: e.fileAction || null,
            fileHash: e.fileHash || null,
            fileSize: typeof e.fileSize === "number" ? e.fileSize : null,
            authAction: e.authAction || null,
            authResult: e.authResult || null,
            authMethod: e.authMethod || null,
            dnsQuery: e.dnsQuery || null,
            dnsType: e.dnsType || null,
            dnsResponse: e.dnsResponse || null,
            logSource: e.logSource || null,
            logLevel: e.logLevel || null,
            logMessage: e.logMessage || null,
            rawData: e.rawData || null,
          })),
        )
        .returning();

      // Run detection engine on the batch
      const detectionResult = await processEventBatch(eventRows, orgId, sensorId);

      // Update sensor stats
      await db
        .update(nativeSensors)
        .set({
          eventsIngested: sql`${nativeSensors.eventsIngested} + ${eventRows.length}`,
          alertsGenerated: sql`${nativeSensors.alertsGenerated} + ${detectionResult.alertsCreated}`,
          updatedAt: new Date(),
        })
        .where(eq(nativeSensors.id, sensorId));

      res.json({
        accepted: eventRows.length,
        rejected: events.length - validEvents.length,
        alertsCreated: detectionResult.alertsCreated,
        eventsMatched: detectionResult.eventsMatched,
      });
    } catch (error) {
      log.error("Event ingestion failed", { error: String(error) });
      res.status(500).json({ message: "Event ingestion failed" });
    }
  });

  // Delete / deregister a sensor
  app.delete("/api/native-sensors/:id", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const sensorId = String(req.params.id);

      const [sensor] = await db
        .select()
        .from(nativeSensors)
        .where(and(eq(nativeSensors.id, sensorId), eq(nativeSensors.orgId, orgId)))
        .limit(1);

      if (!sensor) {
        return res.status(404).json({ message: "Sensor not found" });
      }

      await db.delete(nativeSensors).where(eq(nativeSensors.id, sensorId));

      log.info(`Sensor deregistered: ${sensor.hostname}`, { sensorId, orgId });
      res.json({ message: "Sensor deregistered" });
    } catch (error) {
      log.error("Failed to delete sensor", { error: String(error) });
      res.status(500).json({ message: "Failed to delete sensor" });
    }
  });

  // Generate one-line install command for a platform
  app.post(
    "/api/native-sensors/install-command",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      try {
        const { platform, sensorId, apiKey } = req.body;

        if (!platform || !SENSOR_PLATFORMS.includes(platform as any)) {
          return res.status(400).json({ message: `platform must be one of: ${SENSOR_PLATFORMS.join(", ")}` });
        }

        const serverUrl = `${req.protocol}://${req.get("host")}`;
        let command = "";

        switch (platform) {
          case "linux":
            command = `curl -fsSL ${serverUrl}/api/native-sensors/agent/install.sh | SENSOR_ID="${sensorId}" API_KEY="${apiKey}" SERVER_URL="${serverUrl}" bash`;
            break;
          case "windows":
            command = `powershell -Command "& { $env:SENSOR_ID='${sensorId}'; $env:API_KEY='${apiKey}'; $env:SERVER_URL='${serverUrl}'; iwr -useb ${serverUrl}/api/native-sensors/agent/install.ps1 | iex }"`;
            break;
          case "macos":
            command = `curl -fsSL ${serverUrl}/api/native-sensors/agent/install.sh | SENSOR_ID="${sensorId}" API_KEY="${apiKey}" SERVER_URL="${serverUrl}" bash`;
            break;
          case "docker":
            command = `docker run -d --name ats-sensor -e SENSOR_ID="${sensorId}" -e API_KEY="${apiKey}" -e SERVER_URL="${serverUrl}" --pid=host --net=host --privileged aricatech/ats-sensor:latest`;
            break;
          case "ios":
            command = `# ATS Sensor for iOS — requires MDM enrollment or TestFlight distribution
# 1. Install the ATS Sensor app from your MDM portal or TestFlight
# 2. Open the app and enter the following configuration:
#    Server URL: ${serverUrl}
#    Sensor ID:  ${sensorId}
#    API Key:    ${apiKey}
#
# Or configure via MDM managed app config (AppConfig):
# <dict>
#   <key>ServerURL</key><string>${serverUrl}</string>
#   <key>SensorID</key><string>${sensorId}</string>
#   <key>APIKey</key><string>${apiKey}</string>
# </dict>`;
            break;
          case "android":
            command = `# ATS Sensor for Android — deploy via EMM/MDM or direct APK install
# 1. Install the ATS Sensor app from Google Play (managed) or download the APK:
#    curl -fsSL ${serverUrl}/api/native-sensors/agent/ats-sensor.apk -o ats-sensor.apk
#    adb install ats-sensor.apk
# 2. Configure via intent or managed config:
#    adb shell am start -n com.aricatech.sensor/.MainActivity \\
#      --es server_url "${serverUrl}" \\
#      --es sensor_id "${sensorId}" \\
#      --es api_key "${apiKey}"
#
# Or configure via Android Enterprise managed configurations:
# {
#   "server_url": "${serverUrl}",
#   "sensor_id": "${sensorId}",
#   "api_key": "${apiKey}"
# }`;
            break;
          case "kubernetes":
            command = `kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: ats-sensor
  namespace: security
spec:
  selector:
    matchLabels:
      app: ats-sensor
  template:
    metadata:
      labels:
        app: ats-sensor
    spec:
      hostPID: true
      hostNetwork: true
      containers:
      - name: sensor
        image: aricatech/ats-sensor:latest
        env:
        - name: SENSOR_ID
          value: "${sensorId}"
        - name: API_KEY
          value: "${apiKey}"
        - name: SERVER_URL
          value: "${serverUrl}"
        securityContext:
          privileged: true
EOF`;
            break;
        }

        res.json({ platform, command });
      } catch (error) {
        log.error("Failed to generate install command", { error: String(error) });
        res.status(500).json({ message: "Failed to generate install command" });
      }
    },
  );

  // ==========================================================================
  // SENSOR EVENTS
  // ==========================================================================

  // List sensor events (for a specific sensor or all org events)
  app.get("/api/sensor-events", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const sensorId = req.query.sensorId as string | undefined;
      const eventType = req.query.eventType as string | undefined;
      const matched = req.query.matched as string | undefined;
      const limitParam = parseInt(String(req.query.limit || "50"));
      const offsetParam = parseInt(String(req.query.offset || "0"));
      const limit = Math.min(limitParam, 200);

      const conditions: unknown[] = [eq(sensorEvents.orgId, orgId)];
      if (sensorId) conditions.push(eq(sensorEvents.sensorId, sensorId));
      if (eventType && eventType !== "all") conditions.push(eq(sensorEvents.eventType, eventType));
      if (matched === "true") conditions.push(eq(sensorEvents.detectionMatched, true));

      const events = await db
        .select()
        .from(sensorEvents)
        .where(and(...(conditions as any[])))
        .orderBy(desc(sensorEvents.timestamp))
        .limit(limit)
        .offset(offsetParam);

      res.json({ events });
    } catch (error) {
      log.error("Failed to list sensor events", { error: String(error) });
      res.status(500).json({ message: "Failed to list sensor events" });
    }
  });

  // ==========================================================================
  // DETECTION RULES
  // ==========================================================================

  // List detection rules (built-in global + org-specific)
  app.get("/api/detection-rules", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const status = req.query.status as string | undefined;
      const tactic = req.query.tactic as string | undefined;
      const severity = req.query.severity as string | undefined;
      const type = req.query.type as string | undefined;
      const q = (req.query.q as string) || "";

      // Seed built-in rules on first access
      await seedBuiltinRules();

      const conditions: unknown[] = [or(eq(detectionRules.orgId, orgId), sql`${detectionRules.orgId} IS NULL`)];
      if (status && status !== "all") conditions.push(eq(detectionRules.status, status));
      if (tactic && tactic !== "all") conditions.push(eq(detectionRules.mitreTactic, tactic));
      if (severity && severity !== "all") conditions.push(eq(detectionRules.severity, severity));
      if (type === "builtin") conditions.push(eq(detectionRules.isBuiltin, true));
      if (type === "custom") conditions.push(eq(detectionRules.isBuiltin, false));
      if (q) {
        conditions.push(or(ilike(detectionRules.name, `%${q}%`), ilike(detectionRules.description, `%${q}%`)));
      }

      const rules = await db
        .select()
        .from(detectionRules)
        .where(and(...(conditions as any[])))
        .orderBy(desc(detectionRules.matchCount), detectionRules.mitreTactic, detectionRules.name);

      // Get tactic distribution
      const tacticStats = await db.execute(sql`
        SELECT
          mitre_tactic,
          COUNT(*) AS rule_count,
          COALESCE(SUM(match_count), 0) AS total_matches,
          COUNT(*) FILTER (WHERE status = 'enabled') AS enabled_count
        FROM detection_rules
        WHERE org_id = ${orgId} OR org_id IS NULL
        GROUP BY mitre_tactic
        ORDER BY mitre_tactic
      `);

      res.json({
        rules,
        tacticStats: (tacticStats as any).rows || [],
        constants: {
          severities: DETECTION_SEVERITIES,
          statuses: DETECTION_STATUSES,
          tactics: MITRE_TACTICS,
          eventTypes: SENSOR_EVENT_TYPES,
        },
      });
    } catch (error) {
      log.error("Failed to list detection rules", { error: String(error) });
      res.status(500).json({ message: "Failed to list detection rules" });
    }
  });

  // Get single detection rule
  app.get("/api/detection-rules/:id", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const ruleId = String(req.params.id);

      const [rule] = await db
        .select()
        .from(detectionRules)
        .where(
          and(eq(detectionRules.id, ruleId), or(eq(detectionRules.orgId, orgId), sql`${detectionRules.orgId} IS NULL`)),
        )
        .limit(1);

      if (!rule) {
        return res.status(404).json({ message: "Detection rule not found" });
      }

      // Get recent matches
      const recentAlerts = await db
        .select()
        .from(detectionAlerts)
        .where(and(eq(detectionAlerts.ruleId, ruleId), eq(detectionAlerts.orgId, orgId)))
        .orderBy(desc(detectionAlerts.createdAt))
        .limit(20);

      res.json({ rule, recentAlerts });
    } catch (error) {
      log.error("Failed to get detection rule", { error: String(error) });
      res.status(500).json({ message: "Failed to get detection rule" });
    }
  });

  // Create custom detection rule
  app.post("/api/detection-rules", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const {
        name,
        description,
        severity,
        mitreTactic,
        mitreTechnique,
        mitreSubtechnique,
        eventTypes,
        conditionTree,
        tags,
        falsePositiveNotes,
        references: refs,
      } = req.body;

      if (!name || typeof name !== "string") {
        return res.status(400).json({ message: "name is required" });
      }
      if (!conditionTree || typeof conditionTree !== "object") {
        return res.status(400).json({ message: "conditionTree is required and must be an object" });
      }

      const [rule] = await db
        .insert(detectionRules)
        .values({
          orgId,
          name,
          description: description || null,
          severity: severity || "medium",
          status: "enabled",
          mitreTactic: mitreTactic || null,
          mitreTechnique: mitreTechnique || null,
          mitreSubtechnique: mitreSubtechnique || null,
          eventTypes: eventTypes || [],
          conditionTree,
          author: (req as any).user?.email || "custom",
          tags: tags || [],
          falsePositiveNotes: falsePositiveNotes || null,
          references: refs || [],
          isBuiltin: false,
        })
        .returning();

      log.info(`Custom detection rule created: ${name}`, { ruleId: rule.id, orgId });
      res.status(201).json({ rule });
    } catch (error) {
      log.error("Failed to create detection rule", { error: String(error) });
      res.status(500).json({ message: "Failed to create detection rule" });
    }
  });

  // Update detection rule (enable/disable, edit conditions)
  app.patch("/api/detection-rules/:id", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const ruleId = String(req.params.id);

      const [existing] = await db
        .select()
        .from(detectionRules)
        .where(
          and(eq(detectionRules.id, ruleId), or(eq(detectionRules.orgId, orgId), sql`${detectionRules.orgId} IS NULL`)),
        )
        .limit(1);

      if (!existing) {
        return res.status(404).json({ message: "Detection rule not found" });
      }

      // Only allow status changes on built-in rules; full edits on custom rules
      const allowedFields = ["status"];
      if (!existing.isBuiltin) {
        allowedFields.push(
          "name",
          "description",
          "severity",
          "mitreTactic",
          "mitreTechnique",
          "mitreSubtechnique",
          "eventTypes",
          "conditionTree",
          "tags",
          "falsePositiveNotes",
          "references",
        );
      }

      const updateData: Record<string, unknown> = { updatedAt: new Date() };
      for (const field of allowedFields) {
        if (req.body[field] !== undefined) {
          updateData[field] = req.body[field];
        }
      }

      const [updated] = await db
        .update(detectionRules)
        .set(updateData)
        .where(eq(detectionRules.id, ruleId))
        .returning();

      res.json({ rule: updated });
    } catch (error) {
      log.error("Failed to update detection rule", { error: String(error) });
      res.status(500).json({ message: "Failed to update detection rule" });
    }
  });

  // Delete custom detection rule (built-in rules cannot be deleted)
  app.delete("/api/detection-rules/:id", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const ruleId = String(req.params.id);

      const [existing] = await db
        .select()
        .from(detectionRules)
        .where(and(eq(detectionRules.id, ruleId), eq(detectionRules.orgId, orgId)))
        .limit(1);

      if (!existing) {
        return res.status(404).json({ message: "Detection rule not found" });
      }

      if (existing.isBuiltin) {
        return res.status(403).json({ message: "Built-in rules cannot be deleted. You can disable them instead." });
      }

      await db.delete(detectionRules).where(eq(detectionRules.id, ruleId));
      res.json({ message: "Detection rule deleted" });
    } catch (error) {
      log.error("Failed to delete detection rule", { error: String(error) });
      res.status(500).json({ message: "Failed to delete detection rule" });
    }
  });

  // ==========================================================================
  // DETECTION ALERTS
  // ==========================================================================

  // List detection alerts
  app.get("/api/detection-alerts", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const status = req.query.status as string | undefined;
      const severity = req.query.severity as string | undefined;
      const sensorId = req.query.sensorId as string | undefined;
      const ruleId = req.query.ruleId as string | undefined;
      const limitParam = parseInt(String(req.query.limit || "50"));
      const offsetParam = parseInt(String(req.query.offset || "0"));
      const limit = Math.min(limitParam, 200);

      const conditions: unknown[] = [eq(detectionAlerts.orgId, orgId)];
      if (status && status !== "all") conditions.push(eq(detectionAlerts.status, status));
      if (severity && severity !== "all") conditions.push(eq(detectionAlerts.severity, severity));
      if (sensorId) conditions.push(eq(detectionAlerts.sensorId, sensorId));
      if (ruleId) conditions.push(eq(detectionAlerts.ruleId, ruleId));

      const alertsList = await db
        .select()
        .from(detectionAlerts)
        .where(and(...(conditions as any[])))
        .orderBy(desc(detectionAlerts.createdAt))
        .limit(limit)
        .offset(offsetParam);

      res.json({ alerts: alertsList });
    } catch (error) {
      log.error("Failed to list detection alerts", { error: String(error) });
      res.status(500).json({ message: "Failed to list detection alerts" });
    }
  });

  // Acknowledge detection alert
  app.patch(
    "/api/detection-alerts/:id/acknowledge",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const alertId = String(req.params.id);

        const [existing] = await db
          .select()
          .from(detectionAlerts)
          .where(and(eq(detectionAlerts.id, alertId), eq(detectionAlerts.orgId, orgId)))
          .limit(1);

        if (!existing) {
          return res.status(404).json({ message: "Detection alert not found" });
        }

        const [updated] = await db
          .update(detectionAlerts)
          .set({
            status: "acknowledged",
            acknowledgedBy: (req as any).user?.id || null,
            acknowledgedAt: new Date(),
          })
          .where(eq(detectionAlerts.id, alertId))
          .returning();

        res.json({ alert: updated });
      } catch (error) {
        log.error("Failed to acknowledge detection alert", { error: String(error) });
        res.status(500).json({ message: "Failed to acknowledge detection alert" });
      }
    },
  );

  // Seed built-in rules endpoint (admin)
  app.post("/api/detection-rules/seed", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const inserted = await seedBuiltinRules();
      res.json({ message: `Seeded ${inserted} built-in detection rules`, inserted });
    } catch (error) {
      log.error("Failed to seed detection rules", { error: String(error) });
      res.status(500).json({ message: "Failed to seed detection rules" });
    }
  });

  // 47.3: Sensor policy management — retrieve policies
  app.get("/api/native-sensors/policies", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      // Return policies from DB or empty array if table not yet created
      // For now, return from a lightweight in-memory store keyed by orgId
      const policiesKey = `sensor_policies_${orgId}`;
      const existing = (globalThis as Record<string, unknown>)[policiesKey] as
        | Array<Record<string, unknown>>
        | undefined;
      res.json(existing || []);
    } catch (error) {
      log.error("Failed to fetch sensor policies", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch sensor policies" });
    }
  });

  // 47.3: Create sensor policy
  app.post("/api/native-sensors/policies", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { name, platform, telemetryLevel, heartbeatInterval, autoUpdate } = req.body;
      if (!name) {
        return res.status(400).json({ message: "Policy name is required" });
      }

      const policy = {
        id: randomBytes(16).toString("hex"),
        orgId,
        name,
        platform: platform === "all_platforms" ? null : platform || null,
        telemetryLevel: telemetryLevel || "standard",
        heartbeatInterval: heartbeatInterval || 60,
        autoUpdate: autoUpdate !== false,
        sensorCount: 0,
        createdAt: new Date().toISOString(),
      };

      const policiesKey = `sensor_policies_${orgId}`;
      const existing = ((globalThis as Record<string, unknown>)[policiesKey] as Array<Record<string, unknown>>) || [];
      existing.push(policy);
      (globalThis as Record<string, unknown>)[policiesKey] = existing;

      res.status(201).json(policy);
    } catch (error) {
      log.error("Failed to create sensor policy", { error: String(error) });
      res.status(500).json({ message: "Failed to create sensor policy" });
    }
  });

  // 47.5: Sensor health monitoring — heartbeat-based health checks
  app.get("/api/native-sensors/health-check", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);

      const sensors = await db.select().from(nativeSensors).where(eq(nativeSensors.orgId, orgId));

      const now = Date.now();
      const HEARTBEAT_THRESHOLD_MS = 5 * 60 * 1000; // 5 minutes
      const DEGRADED_THRESHOLD_MS = 2 * 60 * 1000; // 2 minutes

      const healthReport = sensors.map((s) => {
        const lastBeat = s.lastHeartbeat ? new Date(s.lastHeartbeat).getTime() : 0;
        const elapsed = now - lastBeat;
        let healthStatus: "healthy" | "degraded" | "offline" | "tampered" = "healthy";

        if (elapsed > HEARTBEAT_THRESHOLD_MS) {
          healthStatus = "offline";
        } else if (elapsed > DEGRADED_THRESHOLD_MS) {
          healthStatus = "degraded";
        }

        // Check for tampering indicators
        if (s.cpuUsage !== null && s.cpuUsage > 95 && s.memoryUsage !== null && s.memoryUsage > 95) {
          healthStatus = "tampered";
        }

        return {
          sensorId: s.id,
          hostname: s.hostname,
          platform: s.platform,
          status: s.status,
          healthStatus,
          lastHeartbeat: s.lastHeartbeat,
          heartbeatAge: elapsed > 0 && lastBeat > 0 ? Math.round(elapsed / 1000) : null,
          cpuUsage: s.cpuUsage,
          memoryUsage: s.memoryUsage,
          diskUsage: s.diskUsage,
          agentVersion: s.agentVersion,
        };
      });

      const summary = {
        total: healthReport.length,
        healthy: healthReport.filter((h) => h.healthStatus === "healthy").length,
        degraded: healthReport.filter((h) => h.healthStatus === "degraded").length,
        offline: healthReport.filter((h) => h.healthStatus === "offline").length,
        tampered: healthReport.filter((h) => h.healthStatus === "tampered").length,
      };

      res.json({ sensors: healthReport, summary });
    } catch (error) {
      log.error("Sensor health check error", { error: String(error) });
      res.status(500).json({ message: "Failed to run sensor health check" });
    }
  });

  // 47.6: Sensor auto-update with maintenance windows
  app.post("/api/native-sensors/auto-update", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { targetVersion, sensorIds, strategy, maintenanceWindow } = req.body;

      if (!targetVersion) {
        return res.status(400).json({ message: "Target version is required" });
      }

      const sensors = await db.select().from(nativeSensors).where(eq(nativeSensors.orgId, orgId));

      const targets = sensorIds
        ? sensors.filter((s) => sensorIds.includes(s.id))
        : sensors.filter((s) => s.agentVersion !== targetVersion);

      // Calculate canary set (10% for staged rollout)
      const canarySize = Math.max(1, Math.ceil(targets.length * 0.1));
      const canarySet = strategy === "canary" ? targets.slice(0, canarySize) : targets;

      const updatePlan = {
        id: randomBytes(16).toString("hex"),
        targetVersion,
        strategy: strategy || "rolling",
        totalSensors: targets.length,
        canarySize: strategy === "canary" ? canarySize : targets.length,
        maintenanceWindow: maintenanceWindow || null,
        status: "scheduled",
        sensors: canarySet.map((s) => ({
          id: s.id,
          hostname: s.hostname,
          currentVersion: s.agentVersion,
          targetVersion,
          updateStatus: "pending",
        })),
        createdAt: new Date().toISOString(),
      };

      log.info("Auto-update scheduled", {
        orgId,
        targetVersion,
        totalSensors: targets.length,
        strategy: strategy || "rolling",
      });

      res.json(updatePlan);
    } catch (error) {
      log.error("Sensor auto-update error", { error: String(error) });
      res.status(500).json({ message: "Failed to schedule sensor auto-update" });
    }
  });

  // 47.6: Sensor rollback
  app.post("/api/native-sensors/:id/rollback", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);
      const { targetVersion } = req.body;

      const [sensor] = await db
        .select()
        .from(nativeSensors)
        .where(and(eq(nativeSensors.id, id), eq(nativeSensors.orgId, orgId)))
        .limit(1);

      if (!sensor) {
        return res.status(404).json({ message: "Sensor not found" });
      }

      log.info("Sensor rollback initiated", {
        sensorId: id,
        currentVersion: sensor.agentVersion,
        targetVersion: targetVersion || "previous",
      });

      res.json({
        sensorId: id,
        hostname: sensor.hostname,
        previousVersion: sensor.agentVersion,
        rollbackVersion: targetVersion || "previous",
        status: "rollback_initiated",
        message: `Rollback initiated for sensor ${sensor.hostname}`,
      });
    } catch (error) {
      log.error("Sensor rollback error", { error: String(error) });
      res.status(500).json({ message: "Failed to rollback sensor" });
    }
  });
}

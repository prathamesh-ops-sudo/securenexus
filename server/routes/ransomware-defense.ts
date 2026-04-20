/* eslint-disable @typescript-eslint/no-explicit-any */
import type { Express } from "express";
import { randomBytes } from "crypto";
import { isAuthenticated } from "../auth";
import { resolveOrgContext, requireOrgId } from "../rbac";
import { requirePermission } from "../rbac";
import { logger, getOrgId } from "./shared";
import { db } from "../db";
import { sql, eq, and, desc, ilike, or, count } from "drizzle-orm";
import {
  ransomwareKillSwitchEvents,
  ransomwareCanaryFiles,
  ransomwareGroups,
  recoveryRunbooks,
  tabletopExercises,
  backupVerifications,
  nativeSensors,
  agentResponseActions,
  KILL_SWITCH_STATUSES,
  CANARY_FILE_STATUSES,
  BACKUP_VERIFICATION_STATUSES,
  TABLETOP_EXERCISE_STATUSES,
  RECOVERY_RUNBOOK_STATUSES,
} from "../../shared/schema";
import {
  KNOWN_RANSOMWARE_GROUPS,
  CANARY_FILE_TEMPLATES,
  TABLETOP_SCENARIOS,
  generateRecoverySteps,
  computeCanaryHash,
  computeReadinessScore,
} from "../ransomware-intelligence";

const log = logger.child("ransomware-defense");

export function registerRansomwareDefenseRoutes(app: Express): void {
  // ==========================================================================
  // SUMMARY — dashboard overview
  // ==========================================================================

  app.get("/api/ransomware-defense/summary", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);

      // Count kill switch events
      const [{ value: killSwitchCount }] = await db
        .select({ value: count() })
        .from(ransomwareKillSwitchEvents)
        .where(eq(ransomwareKillSwitchEvents.orgId, orgId));

      // Count canary files
      const [{ value: totalCanaries }] = await db
        .select({ value: count() })
        .from(ransomwareCanaryFiles)
        .where(eq(ransomwareCanaryFiles.orgId, orgId));

      const [{ value: activeCanaries }] = await db
        .select({ value: count() })
        .from(ransomwareCanaryFiles)
        .where(and(eq(ransomwareCanaryFiles.orgId, orgId), eq(ransomwareCanaryFiles.status, "active")));

      const [{ value: triggeredCanaries }] = await db
        .select({ value: count() })
        .from(ransomwareCanaryFiles)
        .where(and(eq(ransomwareCanaryFiles.orgId, orgId), eq(ransomwareCanaryFiles.status, "triggered")));

      // Count ransomware groups tracked
      const [{ value: groupsTracked }] = await db
        .select({ value: count() })
        .from(ransomwareGroups)
        .where(eq(ransomwareGroups.orgId, orgId));

      // Count recovery runbooks
      const [{ value: runbookCount }] = await db
        .select({ value: count() })
        .from(recoveryRunbooks)
        .where(eq(recoveryRunbooks.orgId, orgId));

      // Count tabletop exercises
      const [{ value: exerciseCount }] = await db
        .select({ value: count() })
        .from(tabletopExercises)
        .where(eq(tabletopExercises.orgId, orgId));

      const [{ value: completedExercises }] = await db
        .select({ value: count() })
        .from(tabletopExercises)
        .where(and(eq(tabletopExercises.orgId, orgId), eq(tabletopExercises.status, "completed")));

      // Count backup verifications
      const [{ value: totalBackups }] = await db
        .select({ value: count() })
        .from(backupVerifications)
        .where(eq(backupVerifications.orgId, orgId));

      const [{ value: passedBackups }] = await db
        .select({ value: count() })
        .from(backupVerifications)
        .where(and(eq(backupVerifications.orgId, orgId), eq(backupVerifications.status, "passed")));

      const [{ value: failedBackups }] = await db
        .select({ value: count() })
        .from(backupVerifications)
        .where(and(eq(backupVerifications.orgId, orgId), eq(backupVerifications.status, "failed")));

      // Get last kill switch event
      const [lastKillSwitch] = await db
        .select()
        .from(ransomwareKillSwitchEvents)
        .where(eq(ransomwareKillSwitchEvents.orgId, orgId))
        .orderBy(desc(ransomwareKillSwitchEvents.createdAt))
        .limit(1);

      // Get last completed tabletop
      const [lastTabletop] = await db
        .select()
        .from(tabletopExercises)
        .where(and(eq(tabletopExercises.orgId, orgId), eq(tabletopExercises.status, "completed")))
        .orderBy(desc(tabletopExercises.completedAt))
        .limit(1);

      // Compute readiness score
      const readiness = computeReadinessScore({
        hasKillSwitch: Number(killSwitchCount) > 0,
        canaryFileCount: Number(activeCanaries),
        backupVerifiedCount: Number(passedBackups),
        backupFailedCount: Number(failedBackups),
        lastTabletopDate: lastTabletop?.completedAt || null,
        hasRecoveryRunbook: Number(runbookCount) > 0,
        lastKillSwitchTest: lastKillSwitch?.createdAt || null,
      });

      res.json({
        killSwitch: {
          totalEvents: Number(killSwitchCount),
          lastEvent: lastKillSwitch || null,
        },
        canaryFiles: {
          total: Number(totalCanaries),
          active: Number(activeCanaries),
          triggered: Number(triggeredCanaries),
        },
        ransomwareGroups: {
          tracked: Number(groupsTracked),
        },
        recoveryRunbooks: {
          total: Number(runbookCount),
        },
        tabletopExercises: {
          total: Number(exerciseCount),
          completed: Number(completedExercises),
          lastCompleted: lastTabletop || null,
        },
        backupVerifications: {
          total: Number(totalBackups),
          passed: Number(passedBackups),
          failed: Number(failedBackups),
        },
        readiness,
      });
    } catch (error) {
      log.error("Failed to fetch ransomware defense summary", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch summary" });
    }
  });

  // ==========================================================================
  // KILL SWITCH — one-click isolate all endpoints
  // ==========================================================================

  app.post(
    "/api/ransomware-defense/kill-switch/activate",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const userId = (req as any).user?.id || "unknown";
        const userName = (req as any).user?.username || (req as any).user?.email || "unknown";
        const { reason, incidentId } = req.body;

        // Get all active sensors in the org
        const sensors = await db
          .select()
          .from(nativeSensors)
          .where(and(eq(nativeSensors.orgId, orgId), eq(nativeSensors.status, "active")));

        if (sensors.length === 0) {
          return res.status(400).json({
            message: "No active sensors found. Deploy endpoint sensors to use kill switch.",
          });
        }

        // Create kill switch event
        const [event] = await db
          .insert(ransomwareKillSwitchEvents)
          .values({
            orgId,
            status: "in_progress",
            triggeredBy: userId,
            triggeredByName: userName,
            reason: reason || "Emergency ransomware kill switch activated",
            totalSensors: sensors.length,
            incidentId: incidentId || null,
          })
          .returning();

        // Create isolate_host response actions for each sensor
        const actionIds: string[] = [];
        const failedSensors: { sensorId: string; hostname: string; error: string }[] = [];

        for (const sensor of sensors) {
          try {
            const [action] = await db
              .insert(agentResponseActions)
              .values({
                orgId,
                sensorId: sensor.id,
                actionType: "isolate_host",
                riskLevel: "high",
                status: "approved", // Auto-approved for kill switch
                requestedBy: userId,
                requestedByName: userName,
                approvedBy: userId,
                approvedByName: `${userName} (kill switch auto-approve)`,
                approvedAt: new Date(),
                reason: `Kill switch activation: ${reason || "Emergency isolation"}`,
                incidentId: incidentId || null,
                timeoutSeconds: 600,
              })
              .returning();
            actionIds.push(action.id);
          } catch (err) {
            failedSensors.push({
              sensorId: sensor.id,
              hostname: sensor.hostname || "unknown",
              error: String(err),
            });
          }
        }

        const isolatedCount = actionIds.length;
        const failedCount = failedSensors.length;
        const finalStatus = failedCount === 0 ? "completed" : isolatedCount === 0 ? "failed" : "partial_failure";

        // Update kill switch event
        await db
          .update(ransomwareKillSwitchEvents)
          .set({
            status: finalStatus,
            isolatedCount,
            failedCount,
            actionIds,
            failedSensors: failedSensors.length > 0 ? failedSensors : null,
            completedAt: new Date(),
            updatedAt: new Date(),
          })
          .where(eq(ransomwareKillSwitchEvents.id, event.id));

        res.json({
          id: event.id,
          status: finalStatus,
          totalSensors: sensors.length,
          isolatedCount,
          failedCount,
          actionIds,
          failedSensors,
          message:
            finalStatus === "completed"
              ? `Successfully isolated all ${isolatedCount} endpoints`
              : `Isolated ${isolatedCount}/${sensors.length} endpoints. ${failedCount} failed.`,
        });
      } catch (error) {
        log.error("Kill switch activation failed", { error: String(error) });
        res.status(500).json({ message: "Kill switch activation failed" });
      }
    },
  );

  // Rollback kill switch — un-isolate all endpoints
  app.post(
    "/api/ransomware-defense/kill-switch/rollback/:eventId",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const userId = (req as any).user?.id || "unknown";
        const eventId = String(req.params.eventId);

        const [event] = await db
          .select()
          .from(ransomwareKillSwitchEvents)
          .where(and(eq(ransomwareKillSwitchEvents.id, eventId), eq(ransomwareKillSwitchEvents.orgId, orgId)));

        if (!event) {
          return res.status(404).json({ message: "Kill switch event not found" });
        }

        if (event.status === "rolled_back") {
          return res.status(400).json({ message: "Kill switch already rolled back" });
        }

        // Create un-isolate actions for each original action
        const originalActionIds = (event.actionIds as string[]) || [];
        let rolledBackCount = 0;

        for (const actionId of originalActionIds) {
          const [original] = await db
            .select()
            .from(agentResponseActions)
            .where(and(eq(agentResponseActions.id, actionId), eq(agentResponseActions.orgId, orgId)));

          if (original) {
            await db.insert(agentResponseActions).values({
              orgId,
              sensorId: original.sensorId,
              actionType: "unisolate_host",
              riskLevel: "high",
              status: "approved",
              requestedBy: userId,
              approvedBy: userId,
              approvedAt: new Date(),
              reason: `Kill switch rollback for event ${eventId}`,
              incidentId: event.incidentId,
              timeoutSeconds: 600,
            });
            rolledBackCount++;
          }
        }

        await db
          .update(ransomwareKillSwitchEvents)
          .set({
            status: "rolled_back",
            rollbackAt: new Date(),
            rollbackBy: userId,
            updatedAt: new Date(),
          })
          .where(eq(ransomwareKillSwitchEvents.id, eventId));

        res.json({
          message: `Rolled back kill switch — ${rolledBackCount} endpoints being un-isolated`,
          rolledBackCount,
        });
      } catch (error) {
        log.error("Kill switch rollback failed", { error: String(error) });
        res.status(500).json({ message: "Kill switch rollback failed" });
      }
    },
  );

  // List kill switch events
  app.get("/api/ransomware-defense/kill-switch", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const events = await db
        .select()
        .from(ransomwareKillSwitchEvents)
        .where(eq(ransomwareKillSwitchEvents.orgId, orgId))
        .orderBy(desc(ransomwareKillSwitchEvents.createdAt))
        .limit(50);

      res.json(events);
    } catch (error) {
      log.error("Failed to list kill switch events", { error: String(error) });
      res.status(500).json({ message: "Failed to list kill switch events" });
    }
  });

  // ==========================================================================
  // CANARY FILES — deploy fake important files
  // ==========================================================================

  // List canary files
  app.get(
    "/api/ransomware-defense/canary-files",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const status = req.query.status as string | undefined;
        const search = req.query.search as string | undefined;

        const conditions = [eq(ransomwareCanaryFiles.orgId, orgId)];
        if (status && CANARY_FILE_STATUSES.includes(status as any)) {
          conditions.push(eq(ransomwareCanaryFiles.status, status));
        }
        if (search) {
          conditions.push(
            or(
              ilike(ransomwareCanaryFiles.fileName, `%${search}%`),
              ilike(ransomwareCanaryFiles.filePath, `%${search}%`),
              ilike(ransomwareCanaryFiles.deployedToHost, `%${search}%`),
            )!,
          );
        }

        const files = await db
          .select()
          .from(ransomwareCanaryFiles)
          .where(and(...conditions))
          .orderBy(desc(ransomwareCanaryFiles.createdAt))
          .limit(100);

        res.json(files);
      } catch (error) {
        log.error("Failed to list canary files", { error: String(error) });
        res.status(500).json({ message: "Failed to list canary files" });
      }
    },
  );

  // Deploy canary file
  app.post(
    "/api/ransomware-defense/canary-files",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const userId = (req as any).user?.id || "unknown";
        const { fileName, filePath, fileType, deployedToHost, deployedToSensorId } = req.body;

        if (!fileName || typeof fileName !== "string") {
          return res.status(400).json({ message: "fileName is required" });
        }
        if (!filePath || typeof filePath !== "string") {
          return res.status(400).json({ message: "filePath is required" });
        }
        if (!fileType || typeof fileType !== "string") {
          return res.status(400).json({ message: "fileType is required" });
        }

        const fileHash = computeCanaryHash(fileName, filePath, Date.now());

        const [file] = await db
          .insert(ransomwareCanaryFiles)
          .values({
            orgId,
            fileName,
            filePath,
            fileType,
            fileHash,
            deployedToHost: deployedToHost || null,
            deployedToSensorId: deployedToSensorId || null,
            status: "active",
            createdBy: userId,
          })
          .returning();

        res.json(file);
      } catch (error) {
        log.error("Failed to deploy canary file", { error: String(error) });
        res.status(500).json({ message: "Failed to deploy canary file" });
      }
    },
  );

  // Deploy canary files from template
  app.post(
    "/api/ransomware-defense/canary-files/deploy-templates",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const userId = (req as any).user?.id || "unknown";
        const { deployPath, hostName, sensorId } = req.body;

        if (!deployPath || typeof deployPath !== "string") {
          return res.status(400).json({ message: "deployPath is required" });
        }

        const deployed: string[] = [];
        for (const template of CANARY_FILE_TEMPLATES) {
          const fullPath = `${deployPath}/${template.fileName}`;
          const fileHash = computeCanaryHash(template.fileName, fullPath, Date.now());

          await db.insert(ransomwareCanaryFiles).values({
            orgId,
            fileName: template.fileName,
            filePath: fullPath,
            fileType: template.fileType,
            fileHash,
            deployedToHost: hostName || null,
            deployedToSensorId: sensorId || null,
            status: "active",
            createdBy: userId,
          });
          deployed.push(template.fileName);
        }

        res.json({
          message: `Deployed ${deployed.length} canary files to ${deployPath}`,
          files: deployed,
        });
      } catch (error) {
        log.error("Failed to deploy canary templates", { error: String(error) });
        res.status(500).json({ message: "Failed to deploy canary templates" });
      }
    },
  );

  // Get canary file templates
  app.get(
    "/api/ransomware-defense/canary-files/templates",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (_req, res) => {
      res.json(CANARY_FILE_TEMPLATES);
    },
  );

  // Trigger canary alert (simulates file being encrypted/modified)
  app.post(
    "/api/ransomware-defense/canary-files/:id/trigger",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const id = String(req.params.id);
        const { triggerType } = req.body;

        const [file] = await db
          .select()
          .from(ransomwareCanaryFiles)
          .where(and(eq(ransomwareCanaryFiles.id, id), eq(ransomwareCanaryFiles.orgId, orgId)));

        if (!file) {
          return res.status(404).json({ message: "Canary file not found" });
        }

        const validTriggerTypes = ["encrypted", "deleted", "modified", "renamed"];
        const trigger = validTriggerTypes.includes(triggerType) ? triggerType : "modified";

        await db
          .update(ransomwareCanaryFiles)
          .set({
            status: "triggered",
            triggeredAt: new Date(),
            triggerType: trigger,
            alertSent: true,
            updatedAt: new Date(),
          })
          .where(eq(ransomwareCanaryFiles.id, id));

        res.json({
          message: `Canary file alert triggered: ${file.fileName} was ${trigger}`,
          fileId: id,
          triggerType: trigger,
          alert: {
            severity: "critical",
            title: `Ransomware Alert: Canary file ${trigger}`,
            description: `The canary file "${file.fileName}" at ${file.filePath} was ${trigger}. This may indicate active ransomware encryption.`,
            host: file.deployedToHost,
          },
        });
      } catch (error) {
        log.error("Failed to trigger canary file alert", { error: String(error) });
        res.status(500).json({ message: "Failed to trigger canary alert" });
      }
    },
  );

  // Update canary file status
  app.patch(
    "/api/ransomware-defense/canary-files/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const id = String(req.params.id);
        const { status } = req.body;

        const [file] = await db
          .select()
          .from(ransomwareCanaryFiles)
          .where(and(eq(ransomwareCanaryFiles.id, id), eq(ransomwareCanaryFiles.orgId, orgId)));

        if (!file) {
          return res.status(404).json({ message: "Canary file not found" });
        }

        if (status && !CANARY_FILE_STATUSES.includes(status as any)) {
          return res.status(400).json({
            message: `status must be one of: ${CANARY_FILE_STATUSES.join(", ")}`,
          });
        }

        const [updated] = await db
          .update(ransomwareCanaryFiles)
          .set({ status, updatedAt: new Date() })
          .where(eq(ransomwareCanaryFiles.id, id))
          .returning();

        res.json(updated);
      } catch (error) {
        log.error("Failed to update canary file", { error: String(error) });
        res.status(500).json({ message: "Failed to update canary file" });
      }
    },
  );

  // Delete canary file
  app.delete(
    "/api/ransomware-defense/canary-files/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const id = String(req.params.id);

        const [file] = await db
          .select()
          .from(ransomwareCanaryFiles)
          .where(and(eq(ransomwareCanaryFiles.id, id), eq(ransomwareCanaryFiles.orgId, orgId)));

        if (!file) {
          return res.status(404).json({ message: "Canary file not found" });
        }

        await db.delete(ransomwareCanaryFiles).where(eq(ransomwareCanaryFiles.id, id));

        res.json({ message: "Canary file deleted" });
      } catch (error) {
        log.error("Failed to delete canary file", { error: String(error) });
        res.status(500).json({ message: "Failed to delete canary file" });
      }
    },
  );

  // ==========================================================================
  // RANSOMWARE GROUP INTELLIGENCE
  // ==========================================================================

  // List ransomware groups (org-specific + seed data)
  app.get("/api/ransomware-defense/groups", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const search = req.query.search as string | undefined;
      const threatLevel = req.query.threatLevel as string | undefined;

      const conditions = [eq(ransomwareGroups.orgId, orgId)];
      if (threatLevel) {
        conditions.push(eq(ransomwareGroups.threatLevel, threatLevel));
      }
      if (search) {
        conditions.push(ilike(ransomwareGroups.name, `%${search}%`));
      }

      const groups = await db
        .select()
        .from(ransomwareGroups)
        .where(and(...conditions))
        .orderBy(desc(ransomwareGroups.updatedAt))
        .limit(100);

      // Also return seed data for reference if no org groups exist
      const seedGroups = groups.length === 0 ? KNOWN_RANSOMWARE_GROUPS : [];

      res.json({ groups, seedGroups });
    } catch (error) {
      log.error("Failed to list ransomware groups", { error: String(error) });
      res.status(500).json({ message: "Failed to list ransomware groups" });
    }
  });

  // Import seed ransomware groups into org
  app.post(
    "/api/ransomware-defense/groups/import-seed",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        let imported = 0;

        for (const group of KNOWN_RANSOMWARE_GROUPS) {
          // Check if already imported
          const [existing] = await db
            .select()
            .from(ransomwareGroups)
            .where(and(eq(ransomwareGroups.orgId, orgId), eq(ransomwareGroups.name, group.name)))
            .limit(1);

          if (!existing) {
            await db.insert(ransomwareGroups).values({
              orgId,
              name: group.name,
              aliases: group.aliases,
              threatLevel: group.threatLevel,
              isActive: group.isActive,
              firstSeen: group.firstSeen,
              lastActive: group.lastActive,
              description: group.description,
              ttps: group.ttps,
              targetIndustries: group.targetIndustries,
              targetRegions: group.targetRegions,
              ransomwareVariants: group.ransomwareVariants,
              knownPaymentAddresses: group.knownPaymentAddresses,
              avgRansomDemandUsd: group.avgRansomDemandUsd,
              decryptorAvailable: group.decryptorAvailable,
              decryptorSource: group.decryptorSource,
              iocIndicators: group.iocIndicators,
              referenceUrls: group.referenceUrls,
            });
            imported++;
          }
        }

        res.json({
          message: `Imported ${imported} ransomware group profiles`,
          imported,
          total: KNOWN_RANSOMWARE_GROUPS.length,
        });
      } catch (error) {
        log.error("Failed to import seed groups", { error: String(error) });
        res.status(500).json({ message: "Failed to import seed groups" });
      }
    },
  );

  // Add custom ransomware group
  app.post(
    "/api/ransomware-defense/groups",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const {
          name,
          aliases,
          threatLevel,
          isActive,
          firstSeen,
          lastActive,
          description,
          ttps,
          targetIndustries,
          targetRegions,
          ransomwareVariants,
          knownPaymentAddresses,
          avgRansomDemandUsd,
          decryptorAvailable,
          decryptorSource,
          iocIndicators,
          referenceUrls,
        } = req.body;

        if (!name || typeof name !== "string") {
          return res.status(400).json({ message: "name is required" });
        }

        const [group] = await db
          .insert(ransomwareGroups)
          .values({
            orgId,
            name,
            aliases: aliases || [],
            threatLevel: threatLevel || "high",
            isActive: isActive !== false,
            firstSeen: firstSeen || null,
            lastActive: lastActive || null,
            description: description || null,
            ttps: ttps || [],
            targetIndustries: targetIndustries || [],
            targetRegions: targetRegions || [],
            ransomwareVariants: ransomwareVariants || [],
            knownPaymentAddresses: knownPaymentAddresses || [],
            avgRansomDemandUsd: avgRansomDemandUsd || null,
            decryptorAvailable: decryptorAvailable || false,
            decryptorSource: decryptorSource || null,
            iocIndicators: iocIndicators || [],
            referenceUrls: referenceUrls || [],
          })
          .returning();

        res.json(group);
      } catch (error) {
        log.error("Failed to create ransomware group", { error: String(error) });
        res.status(500).json({ message: "Failed to create ransomware group" });
      }
    },
  );

  // Get single ransomware group
  app.get("/api/ransomware-defense/groups/:id", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);

      const [group] = await db
        .select()
        .from(ransomwareGroups)
        .where(and(eq(ransomwareGroups.id, id), eq(ransomwareGroups.orgId, orgId)));

      if (!group) {
        return res.status(404).json({ message: "Ransomware group not found" });
      }

      res.json(group);
    } catch (error) {
      log.error("Failed to get ransomware group", { error: String(error) });
      res.status(500).json({ message: "Failed to get ransomware group" });
    }
  });

  // Delete ransomware group
  app.delete(
    "/api/ransomware-defense/groups/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const id = String(req.params.id);

        const [group] = await db
          .select()
          .from(ransomwareGroups)
          .where(and(eq(ransomwareGroups.id, id), eq(ransomwareGroups.orgId, orgId)));

        if (!group) {
          return res.status(404).json({ message: "Ransomware group not found" });
        }

        await db.delete(ransomwareGroups).where(eq(ransomwareGroups.id, id));
        res.json({ message: "Ransomware group deleted" });
      } catch (error) {
        log.error("Failed to delete ransomware group", { error: String(error) });
        res.status(500).json({ message: "Failed to delete ransomware group" });
      }
    },
  );

  // ==========================================================================
  // RECOVERY RUNBOOKS — AI-generated recovery plans
  // ==========================================================================

  // List recovery runbooks
  app.get("/api/ransomware-defense/runbooks", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const status = req.query.status as string | undefined;

      const conditions = [eq(recoveryRunbooks.orgId, orgId)];
      if (status && RECOVERY_RUNBOOK_STATUSES.includes(status as any)) {
        conditions.push(eq(recoveryRunbooks.status, status));
      }

      const runbooks = await db
        .select()
        .from(recoveryRunbooks)
        .where(and(...conditions))
        .orderBy(desc(recoveryRunbooks.createdAt))
        .limit(50);

      res.json(runbooks);
    } catch (error) {
      log.error("Failed to list recovery runbooks", { error: String(error) });
      res.status(500).json({ message: "Failed to list recovery runbooks" });
    }
  });

  // Generate recovery runbook (AI)
  app.post(
    "/api/ransomware-defense/runbooks/generate",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const {
          title,
          scenario,
          affectedSystems,
          affectedDataTypes,
          ransomwareVariant,
          incidentId,
          hasBackups,
          backupAge,
        } = req.body;

        if (!scenario || typeof scenario !== "string") {
          return res.status(400).json({ message: "scenario description is required" });
        }

        const systems = Array.isArray(affectedSystems) ? affectedSystems : [];
        const dataTypes = Array.isArray(affectedDataTypes) ? affectedDataTypes : [];

        // Check if a decryptor exists for this variant
        let decryptorAvailable = false;
        if (ransomwareVariant) {
          const matchingGroup = KNOWN_RANSOMWARE_GROUPS.find(
            (g) =>
              g.ransomwareVariants.some((v) => v.name.toLowerCase() === ransomwareVariant.toLowerCase()) ||
              g.name.toLowerCase() === ransomwareVariant.toLowerCase(),
          );
          if (matchingGroup) {
            decryptorAvailable = matchingGroup.decryptorAvailable;
          }
        }

        const recovery = generateRecoverySteps({
          ransomwareVariant,
          affectedSystems: systems,
          affectedDataTypes: dataTypes,
          hasBackups: hasBackups !== false,
          backupAge,
          decryptorAvailable,
        });

        const [runbook] = await db
          .insert(recoveryRunbooks)
          .values({
            orgId,
            title: title || `Recovery Runbook — ${new Date().toISOString().split("T")[0]}`,
            incidentId: incidentId || null,
            status: "generated",
            scenario,
            affectedSystems: systems,
            affectedDataTypes: dataTypes,
            ransomwareVariant: ransomwareVariant || null,
            estimatedDowntimeHours: recovery.estimatedDowntimeHours,
            estimatedRecoveryCostUsd: recovery.estimatedRecoveryCostUsd,
            steps: recovery.steps,
            priorityActions: recovery.priorityActions,
            communicationPlan: recovery.communicationPlan,
            legalRequirements: recovery.legalRequirements,
            generatedBy: "ai",
          })
          .returning();

        res.json(runbook);
      } catch (error) {
        log.error("Failed to generate recovery runbook", { error: String(error) });
        res.status(500).json({ message: "Failed to generate recovery runbook" });
      }
    },
  );

  // Get single runbook
  app.get(
    "/api/ransomware-defense/runbooks/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const id = String(req.params.id);

        const [runbook] = await db
          .select()
          .from(recoveryRunbooks)
          .where(and(eq(recoveryRunbooks.id, id), eq(recoveryRunbooks.orgId, orgId)));

        if (!runbook) {
          return res.status(404).json({ message: "Recovery runbook not found" });
        }

        res.json(runbook);
      } catch (error) {
        log.error("Failed to get recovery runbook", { error: String(error) });
        res.status(500).json({ message: "Failed to get recovery runbook" });
      }
    },
  );

  // Update runbook status
  app.patch(
    "/api/ransomware-defense/runbooks/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const userId = (req as any).user?.id || "unknown";
        const id = String(req.params.id);
        const { status } = req.body;

        const [runbook] = await db
          .select()
          .from(recoveryRunbooks)
          .where(and(eq(recoveryRunbooks.id, id), eq(recoveryRunbooks.orgId, orgId)));

        if (!runbook) {
          return res.status(404).json({ message: "Recovery runbook not found" });
        }

        if (!RECOVERY_RUNBOOK_STATUSES.includes(status as any)) {
          return res.status(400).json({
            message: `status must be one of: ${RECOVERY_RUNBOOK_STATUSES.join(", ")}`,
          });
        }

        const updates: Record<string, unknown> = { status, updatedAt: new Date() };
        if (status === "reviewed") {
          updates.reviewedBy = userId;
          updates.reviewedAt = new Date();
        } else if (status === "approved") {
          updates.approvedBy = userId;
          updates.approvedAt = new Date();
        }

        const [updated] = await db.update(recoveryRunbooks).set(updates).where(eq(recoveryRunbooks.id, id)).returning();

        res.json(updated);
      } catch (error) {
        log.error("Failed to update recovery runbook", { error: String(error) });
        res.status(500).json({ message: "Failed to update recovery runbook" });
      }
    },
  );

  // Delete runbook
  app.delete(
    "/api/ransomware-defense/runbooks/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const id = String(req.params.id);

        const [runbook] = await db
          .select()
          .from(recoveryRunbooks)
          .where(and(eq(recoveryRunbooks.id, id), eq(recoveryRunbooks.orgId, orgId)));

        if (!runbook) {
          return res.status(404).json({ message: "Recovery runbook not found" });
        }

        await db.delete(recoveryRunbooks).where(eq(recoveryRunbooks.id, id));
        res.json({ message: "Recovery runbook deleted" });
      } catch (error) {
        log.error("Failed to delete recovery runbook", { error: String(error) });
        res.status(500).json({ message: "Failed to delete recovery runbook" });
      }
    },
  );

  // ==========================================================================
  // TABLETOP EXERCISES — simulate ransomware attacks for training
  // ==========================================================================

  // List exercises
  app.get("/api/ransomware-defense/exercises", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const status = req.query.status as string | undefined;

      const conditions = [eq(tabletopExercises.orgId, orgId)];
      if (status && TABLETOP_EXERCISE_STATUSES.includes(status as any)) {
        conditions.push(eq(tabletopExercises.status, status));
      }

      const exercises = await db
        .select()
        .from(tabletopExercises)
        .where(and(...conditions))
        .orderBy(desc(tabletopExercises.createdAt))
        .limit(50);

      res.json(exercises);
    } catch (error) {
      log.error("Failed to list tabletop exercises", { error: String(error) });
      res.status(500).json({ message: "Failed to list exercises" });
    }
  });

  // Get exercise templates
  app.get(
    "/api/ransomware-defense/exercises/templates",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (_req, res) => {
      res.json(TABLETOP_SCENARIOS);
    },
  );

  // Create exercise from template or custom
  app.post(
    "/api/ransomware-defense/exercises",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const userId = (req as any).user?.id || "unknown";
        const {
          title,
          description,
          scenarioType,
          difficulty,
          ransomwareGroup,
          scenario,
          injects,
          participants,
          scheduledAt,
          durationMinutes,
          templateIndex,
        } = req.body;

        // If using a template
        if (templateIndex !== undefined && templateIndex >= 0 && templateIndex < TABLETOP_SCENARIOS.length) {
          const template = TABLETOP_SCENARIOS[templateIndex];
          const [exercise] = await db
            .insert(tabletopExercises)
            .values({
              orgId,
              title: title || template.title,
              description: description || template.description,
              status: scheduledAt ? "scheduled" : "draft",
              scenarioType: template.scenarioType,
              difficulty: template.difficulty,
              ransomwareGroup: ransomwareGroup || null,
              scenario: template.scenario,
              injects: template.injects,
              participants: participants || [],
              scheduledAt: scheduledAt ? new Date(scheduledAt) : null,
              durationMinutes: template.durationMinutes,
              facilitatedBy: userId,
            })
            .returning();

          return res.json(exercise);
        }

        // Custom exercise
        if (!title || typeof title !== "string") {
          return res.status(400).json({ message: "title is required" });
        }
        if (!scenarioType || typeof scenarioType !== "string") {
          return res.status(400).json({ message: "scenarioType is required" });
        }

        const [exercise] = await db
          .insert(tabletopExercises)
          .values({
            orgId,
            title,
            description: description || null,
            status: scheduledAt ? "scheduled" : "draft",
            scenarioType,
            difficulty: difficulty || "intermediate",
            ransomwareGroup: ransomwareGroup || null,
            scenario: scenario || null,
            injects: injects || [],
            participants: participants || [],
            scheduledAt: scheduledAt ? new Date(scheduledAt) : null,
            durationMinutes: durationMinutes || 90,
            facilitatedBy: userId,
          })
          .returning();

        res.json(exercise);
      } catch (error) {
        log.error("Failed to create tabletop exercise", { error: String(error) });
        res.status(500).json({ message: "Failed to create exercise" });
      }
    },
  );

  // Get single exercise
  app.get(
    "/api/ransomware-defense/exercises/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const id = String(req.params.id);

        const [exercise] = await db
          .select()
          .from(tabletopExercises)
          .where(and(eq(tabletopExercises.id, id), eq(tabletopExercises.orgId, orgId)));

        if (!exercise) {
          return res.status(404).json({ message: "Exercise not found" });
        }

        res.json(exercise);
      } catch (error) {
        log.error("Failed to get exercise", { error: String(error) });
        res.status(500).json({ message: "Failed to get exercise" });
      }
    },
  );

  // Update exercise status
  app.patch(
    "/api/ransomware-defense/exercises/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const id = String(req.params.id);
        const { status, findings, score, afterActionReport } = req.body;

        const [exercise] = await db
          .select()
          .from(tabletopExercises)
          .where(and(eq(tabletopExercises.id, id), eq(tabletopExercises.orgId, orgId)));

        if (!exercise) {
          return res.status(404).json({ message: "Exercise not found" });
        }

        const updates: Record<string, unknown> = { updatedAt: new Date() };

        if (status) {
          if (!TABLETOP_EXERCISE_STATUSES.includes(status as any)) {
            return res.status(400).json({
              message: `status must be one of: ${TABLETOP_EXERCISE_STATUSES.join(", ")}`,
            });
          }
          updates.status = status;
          if (status === "in_progress") updates.startedAt = new Date();
          if (status === "completed") updates.completedAt = new Date();
        }
        if (findings !== undefined) updates.findings = findings;
        if (score !== undefined) updates.score = score;
        if (afterActionReport !== undefined) updates.afterActionReport = afterActionReport;

        const [updated] = await db
          .update(tabletopExercises)
          .set(updates)
          .where(eq(tabletopExercises.id, id))
          .returning();

        res.json(updated);
      } catch (error) {
        log.error("Failed to update exercise", { error: String(error) });
        res.status(500).json({ message: "Failed to update exercise" });
      }
    },
  );

  // Delete exercise
  app.delete(
    "/api/ransomware-defense/exercises/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const id = String(req.params.id);

        const [exercise] = await db
          .select()
          .from(tabletopExercises)
          .where(and(eq(tabletopExercises.id, id), eq(tabletopExercises.orgId, orgId)));

        if (!exercise) {
          return res.status(404).json({ message: "Exercise not found" });
        }

        await db.delete(tabletopExercises).where(eq(tabletopExercises.id, id));
        res.json({ message: "Exercise deleted" });
      } catch (error) {
        log.error("Failed to delete exercise", { error: String(error) });
        res.status(500).json({ message: "Failed to delete exercise" });
      }
    },
  );

  // ==========================================================================
  // BACKUP INTEGRITY VERIFICATION
  // ==========================================================================

  // List backup verifications
  app.get("/api/ransomware-defense/backups", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const status = req.query.status as string | undefined;

      const conditions = [eq(backupVerifications.orgId, orgId)];
      if (status && BACKUP_VERIFICATION_STATUSES.includes(status as any)) {
        conditions.push(eq(backupVerifications.status, status));
      }

      const backups = await db
        .select()
        .from(backupVerifications)
        .where(and(...conditions))
        .orderBy(desc(backupVerifications.createdAt))
        .limit(100);

      res.json(backups);
    } catch (error) {
      log.error("Failed to list backup verifications", { error: String(error) });
      res.status(500).json({ message: "Failed to list backups" });
    }
  });

  // Create / register a backup for verification
  app.post(
    "/api/ransomware-defense/backups",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const userId = (req as any).user?.id || "unknown";
        const {
          backupName,
          backupType,
          backupLocation,
          backupSizeBytes,
          backupCreatedAt,
          retentionDays,
          encryptionStatus,
          encryptionAlgorithm,
          coveredSystems,
          rpoHours,
          rtoHours,
        } = req.body;

        if (!backupName || typeof backupName !== "string") {
          return res.status(400).json({ message: "backupName is required" });
        }
        if (!backupType || typeof backupType !== "string") {
          return res.status(400).json({ message: "backupType is required" });
        }
        if (!backupLocation || typeof backupLocation !== "string") {
          return res.status(400).json({ message: "backupLocation is required" });
        }

        const [backup] = await db
          .insert(backupVerifications)
          .values({
            orgId,
            backupName,
            backupType,
            backupLocation,
            status: "pending",
            backupSizeBytes: backupSizeBytes || null,
            backupCreatedAt: backupCreatedAt ? new Date(backupCreatedAt) : null,
            retentionDays: retentionDays || null,
            encryptionStatus: encryptionStatus || "unknown",
            encryptionAlgorithm: encryptionAlgorithm || null,
            coveredSystems: coveredSystems || [],
            rpoHours: rpoHours || null,
            rtoHours: rtoHours || null,
            verifiedBy: userId,
          })
          .returning();

        res.json(backup);
      } catch (error) {
        log.error("Failed to register backup", { error: String(error) });
        res.status(500).json({ message: "Failed to register backup" });
      }
    },
  );

  // Run backup verification (simulated)
  app.post(
    "/api/ransomware-defense/backups/:id/verify",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const id = String(req.params.id);

        const [backup] = await db
          .select()
          .from(backupVerifications)
          .where(and(eq(backupVerifications.id, id), eq(backupVerifications.orgId, orgId)));

        if (!backup) {
          return res.status(404).json({ message: "Backup not found" });
        }

        // Simulate verification process
        // In production, this would connect to backup infrastructure
        const isEncrypted = backup.encryptionStatus === "encrypted";
        const issues: { type: string; description: string; severity: string }[] = [];

        if (!isEncrypted) {
          issues.push({
            type: "encryption",
            description: "Backup is not encrypted — vulnerable to tampering",
            severity: "high",
          });
        }

        if (!backup.retentionDays || backup.retentionDays < 30) {
          issues.push({
            type: "retention",
            description: "Retention period is less than 30 days — insufficient for ransomware recovery",
            severity: "medium",
          });
        }

        if (!backup.rpoHours || backup.rpoHours > 24) {
          issues.push({
            type: "rpo",
            description: "RPO exceeds 24 hours — significant data loss risk in a ransomware event",
            severity: "medium",
          });
        }

        const verificationResult = issues.some((i) => i.severity === "high") ? "failed" : "passed";
        const restoreTestResult = "passed"; // Simulated

        const startTime = Date.now();
        // Estimate verification duration based on number of issues found
        const durationSeconds = 30 + issues.length * 15;

        const [updated] = await db
          .update(backupVerifications)
          .set({
            status: verificationResult === "passed" ? "passed" : "failed",
            integrityCheckResult: verificationResult,
            restoreTestResult,
            lastVerifiedAt: new Date(),
            nextScheduledVerification: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
            verificationDurationSeconds: durationSeconds,
            issues: issues.length > 0 ? issues : null,
            updatedAt: new Date(),
          })
          .where(eq(backupVerifications.id, id))
          .returning();

        res.json({
          backup: updated,
          verification: {
            result: verificationResult,
            restoreTest: restoreTestResult,
            durationSeconds,
            issues,
          },
        });
      } catch (error) {
        log.error("Failed to verify backup", { error: String(error) });
        res.status(500).json({ message: "Failed to verify backup" });
      }
    },
  );

  // Delete backup verification
  app.delete(
    "/api/ransomware-defense/backups/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const id = String(req.params.id);

        const [backup] = await db
          .select()
          .from(backupVerifications)
          .where(and(eq(backupVerifications.id, id), eq(backupVerifications.orgId, orgId)));

        if (!backup) {
          return res.status(404).json({ message: "Backup not found" });
        }

        await db.delete(backupVerifications).where(eq(backupVerifications.id, id));
        res.json({ message: "Backup verification record deleted" });
      } catch (error) {
        log.error("Failed to delete backup", { error: String(error) });
        res.status(500).json({ message: "Failed to delete backup" });
      }
    },
  );

  // ==========================================================================
  // BACKUP VERIFICATION AUTOMATION
  // ==========================================================================

  app.post(
    "/api/ransomware-defense/backups/verify-all",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);

        // Fetch all registered backups for the org
        const allBackups = await db.select().from(backupVerifications).where(eq(backupVerifications.orgId, orgId));

        if (allBackups.length === 0) {
          return res.json({
            message: "No backups registered",
            results: [],
            summary: { total: 0, passed: 0, failed: 0, skipped: 0 },
          });
        }

        const results: Array<{
          backupId: string;
          backupName: string;
          previousStatus: string;
          newStatus: string;
          issues: { type: string; description: string; severity: string }[];
          durationSeconds: number;
        }> = [];

        for (const backup of allBackups) {
          // Check if verification is needed (skip if verified in last 24 hours)
          if (backup.lastVerifiedAt) {
            const hoursSinceVerified = (Date.now() - new Date(backup.lastVerifiedAt).getTime()) / (1000 * 60 * 60);
            if (hoursSinceVerified < 24) {
              results.push({
                backupId: backup.id,
                backupName: backup.backupName,
                previousStatus: backup.status,
                newStatus: backup.status,
                issues: [],
                durationSeconds: 0,
              });
              continue;
            }
          }

          const issues: { type: string; description: string; severity: string }[] = [];

          // Encryption check
          if (backup.encryptionStatus !== "encrypted") {
            issues.push({
              type: "encryption",
              description: "Backup is not encrypted — vulnerable to tampering",
              severity: "high",
            });
          }

          // Retention check
          if (!backup.retentionDays || backup.retentionDays < 30) {
            issues.push({
              type: "retention",
              description: "Retention period is less than 30 days — insufficient for ransomware recovery",
              severity: "medium",
            });
          }

          // RPO check
          if (!backup.rpoHours || backup.rpoHours > 24) {
            issues.push({
              type: "rpo",
              description: "RPO exceeds 24 hours — significant data loss risk",
              severity: "medium",
            });
          }

          // RTO check
          if (!backup.rtoHours || backup.rtoHours > 8) {
            issues.push({ type: "rto", description: "RTO exceeds 8 hours — slow recovery time", severity: "low" });
          }

          // Staleness check — backup data age
          if (backup.backupCreatedAt) {
            const ageHours = (Date.now() - new Date(backup.backupCreatedAt).getTime()) / (1000 * 60 * 60);
            if (ageHours > 168) {
              issues.push({
                type: "staleness",
                description: "Backup data is over 7 days old — consider more frequent backups",
                severity: "medium",
              });
            }
          }

          // Size check — zero-byte backup
          if (backup.backupSizeBytes != null && backup.backupSizeBytes === 0) {
            issues.push({
              type: "integrity",
              description: "Backup file is 0 bytes — likely corrupt or empty",
              severity: "critical",
            });
          }

          const verificationResult = issues.some((i) => i.severity === "critical" || i.severity === "high")
            ? "failed"
            : "passed";
          const durationSeconds = 30 + issues.length * 15;

          await db
            .update(backupVerifications)
            .set({
              status: verificationResult === "passed" ? "passed" : "failed",
              integrityCheckResult: verificationResult,
              restoreTestResult: verificationResult === "passed" ? "passed" : "failed",
              lastVerifiedAt: new Date(),
              nextScheduledVerification: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
              verificationDurationSeconds: durationSeconds,
              issues: issues.length > 0 ? issues : null,
              updatedAt: new Date(),
            })
            .where(eq(backupVerifications.id, backup.id));

          results.push({
            backupId: backup.id,
            backupName: backup.backupName,
            previousStatus: backup.status,
            newStatus: verificationResult,
            issues,
            durationSeconds,
          });
        }

        const passed = results.filter((r) => r.newStatus === "passed").length;
        const failed = results.filter((r) => r.newStatus === "failed").length;
        const skipped = results.filter((r) => r.durationSeconds === 0).length;

        log.info("Automated backup verification completed", { total: results.length, passed, failed, skipped });
        res.json({
          message: `Verified ${results.length} backups: ${passed} passed, ${failed} failed, ${skipped} skipped (recently verified)`,
          results,
          summary: { total: results.length, passed, failed, skipped },
        });
      } catch (error) {
        log.error("Failed to run automated backup verification", { error: String(error) });
        res.status(500).json({ message: "Failed to run automated backup verification" });
      }
    },
  );

  // ==========================================================================
  // RANSOMWARE INTELLIGENCE INTEGRATION
  // ==========================================================================

  app.get(
    "/api/ransomware-defense/intelligence-feed",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);

        // Fetch all tracked ransomware groups for the org
        const orgGroups = await db.select().from(ransomwareGroups).where(eq(ransomwareGroups.orgId, orgId));

        // Build intelligence feed from tracked groups + known groups seed data
        const knownVariants = KNOWN_RANSOMWARE_GROUPS.map((g) => ({
          name: g.name,
          aliases: g.aliases || [],
          threatLevel: g.threatLevel,
          isActive: g.isActive,
          decryptorAvailable: g.decryptorAvailable,
          decryptorSource: g.decryptorSource || null,
          targetIndustries: g.targetIndustries || [],
          iocIndicators: g.iocIndicators || [],
          avgRansomDemandUsd: g.avgRansomDemandUsd || null,
        }));

        // Check which known groups are actively tracked by the org
        const trackedNames = new Set(orgGroups.map((g) => g.name.toLowerCase()));

        // Generate intelligence alerts based on active groups targeting org's potential sectors
        const alerts: Array<{
          type: string;
          severity: string;
          title: string;
          description: string;
          group: string;
          iocs: { type: string; value: string }[];
        }> = [];

        for (const variant of knownVariants) {
          if (!variant.isActive) continue;

          // Alert for active high-threat groups not yet tracked
          if (
            !trackedNames.has(variant.name.toLowerCase()) &&
            (variant.threatLevel === "critical" || variant.threatLevel === "high")
          ) {
            alerts.push({
              type: "new_variant",
              severity: variant.threatLevel,
              title: `Active ransomware group "${variant.name}" not tracked`,
              description: `${variant.name} is an active ${variant.threatLevel}-threat ransomware group targeting ${variant.targetIndustries.join(", ") || "multiple industries"}. Import intelligence data to track IOCs.`,
              group: variant.name,
              iocs: variant.iocIndicators.slice(0, 5),
            });
          }

          // Alert for groups with new decryptors available
          if (variant.decryptorAvailable && trackedNames.has(variant.name.toLowerCase())) {
            const orgGroup = orgGroups.find((g) => g.name.toLowerCase() === variant.name.toLowerCase());
            if (orgGroup && !orgGroup.decryptorAvailable) {
              alerts.push({
                type: "decryptor_available",
                severity: "informational",
                title: `Decryptor now available for ${variant.name}`,
                description: `A decryptor has been released for ${variant.name} via ${variant.decryptorSource || "security researchers"}. Update your recovery runbooks accordingly.`,
                group: variant.name,
                iocs: [],
              });
            }
          }
        }

        // Build IOC summary from all tracked groups
        const allIocs: { type: string; value: string; group: string }[] = [];
        for (const g of orgGroups) {
          const indicators = g.iocIndicators as { type: string; value: string }[] | null;
          if (indicators) {
            for (const ioc of indicators) {
              allIocs.push({ ...ioc, group: g.name });
            }
          }
        }

        // Ransom demand trends
        const demandTracking = orgGroups
          .filter((g) => g.avgRansomDemandUsd != null)
          .map((g) => ({
            group: g.name,
            avgDemandUsd: g.avgRansomDemandUsd,
            threatLevel: g.threatLevel,
            isActive: g.isActive,
          }))
          .sort((a, b) => (b.avgDemandUsd || 0) - (a.avgDemandUsd || 0));

        res.json({
          trackedGroups: orgGroups.length,
          knownVariants: knownVariants.length,
          activeThreats: knownVariants.filter((v) => v.isActive).length,
          decryptorsAvailable: knownVariants.filter((v) => v.decryptorAvailable).length,
          alerts,
          totalIocs: allIocs.length,
          iocsByType: allIocs.reduce<Record<string, number>>((acc, i) => {
            acc[i.type] = (acc[i.type] || 0) + 1;
            return acc;
          }, {}),
          demandTracking,
        });
      } catch (error) {
        log.error("Failed to fetch ransomware intelligence feed", { error: String(error) });
        res.status(500).json({ message: "Failed to fetch intelligence feed" });
      }
    },
  );
}

import {
  type NativeSensor,
  type InsertNativeSensor,
  type DetectionRule,
  type InsertDetectionRule,
  type SensorEvent,
  type InsertSensorEvent,
  type DetectionAlert,
  type InsertDetectionAlert,
  type SensorPolicy,
  type InsertSensorPolicy,
  type DetectionRuleVersion,
  type InsertDetectionRuleVersion,
  nativeSensors,
  sensorPolicies,
  detectionRules,
  detectionRuleVersions,
  sensorEvents,
  detectionAlerts,
} from "@shared/schema";
import { db } from "../db";
import { and, count, desc, eq } from "drizzle-orm";

// ── Native Sensors ──

export async function getNativeSensors(orgId: string): Promise<NativeSensor[]> {
  return db.select().from(nativeSensors).where(eq(nativeSensors.orgId, orgId)).orderBy(desc(nativeSensors.createdAt));
}

export async function getNativeSensor(id: string): Promise<NativeSensor | undefined> {
  const [sensor] = await db.select().from(nativeSensors).where(eq(nativeSensors.id, id));
  return sensor;
}

export async function createNativeSensor(sensor: InsertNativeSensor): Promise<NativeSensor> {
  const [created] = await db.insert(nativeSensors).values(sensor).returning();
  return created;
}

export async function updateNativeSensor(
  id: string,
  updates: Partial<InsertNativeSensor>,
): Promise<NativeSensor | undefined> {
  const [updated] = await db
    .update(nativeSensors)
    .set({ ...updates, updatedAt: new Date() })
    .where(eq(nativeSensors.id, id))
    .returning();
  return updated;
}

export async function deleteNativeSensor(id: string): Promise<boolean> {
  const result = await db.delete(nativeSensors).where(eq(nativeSensors.id, id));
  return (result.rowCount ?? 0) > 0;
}

export async function countNativeSensors(orgId: string): Promise<number> {
  const [row] = await db.select({ total: count() }).from(nativeSensors).where(eq(nativeSensors.orgId, orgId));
  return row?.total ?? 0;
}

export async function getSensorPolicies(orgId: string): Promise<SensorPolicy[]> {
  return db
    .select()
    .from(sensorPolicies)
    .where(eq(sensorPolicies.orgId, orgId))
    .orderBy(desc(sensorPolicies.createdAt));
}

export async function createSensorPolicy(policy: InsertSensorPolicy): Promise<SensorPolicy> {
  const [created] = await db.insert(sensorPolicies).values(policy).returning();
  return created;
}

export async function getDetectionRuleVersions(ruleId: string, orgId: string): Promise<DetectionRuleVersion[]> {
  return db
    .select()
    .from(detectionRuleVersions)
    .where(and(eq(detectionRuleVersions.ruleId, ruleId), eq(detectionRuleVersions.orgId, orgId)))
    .orderBy(desc(detectionRuleVersions.version));
}

export async function createDetectionRuleVersion(version: InsertDetectionRuleVersion): Promise<DetectionRuleVersion> {
  const [created] = await db.insert(detectionRuleVersions).values(version).returning();
  return created;
}

// ── Detection Rules ──

export async function getDetectionRules(orgId: string): Promise<DetectionRule[]> {
  return db
    .select()
    .from(detectionRules)
    .where(eq(detectionRules.orgId, orgId))
    .orderBy(desc(detectionRules.createdAt));
}

export async function getDetectionRule(id: string): Promise<DetectionRule | undefined> {
  const [rule] = await db.select().from(detectionRules).where(eq(detectionRules.id, id));
  return rule;
}

export async function createDetectionRule(rule: InsertDetectionRule): Promise<DetectionRule> {
  const [created] = await db.insert(detectionRules).values(rule).returning();
  return created;
}

export async function updateDetectionRule(
  id: string,
  updates: Partial<InsertDetectionRule>,
): Promise<DetectionRule | undefined> {
  const [updated] = await db
    .update(detectionRules)
    .set({ ...updates, updatedAt: new Date() })
    .where(eq(detectionRules.id, id))
    .returning();
  return updated;
}

export async function deleteDetectionRule(id: string): Promise<boolean> {
  const result = await db.delete(detectionRules).where(eq(detectionRules.id, id));
  return (result.rowCount ?? 0) > 0;
}

export async function countDetectionRules(orgId: string): Promise<number> {
  const [row] = await db.select({ total: count() }).from(detectionRules).where(eq(detectionRules.orgId, orgId));
  return row?.total ?? 0;
}

// ── Sensor Events ──

export async function getSensorEvents(orgId: string, limit = 100, offset = 0): Promise<SensorEvent[]> {
  return db
    .select()
    .from(sensorEvents)
    .where(eq(sensorEvents.orgId, orgId))
    .orderBy(desc(sensorEvents.timestamp))
    .limit(limit)
    .offset(offset);
}

export async function getSensorEventsBySensor(sensorId: string, limit = 100): Promise<SensorEvent[]> {
  return db
    .select()
    .from(sensorEvents)
    .where(eq(sensorEvents.sensorId, sensorId))
    .orderBy(desc(sensorEvents.timestamp))
    .limit(limit);
}

export async function createSensorEvent(event: InsertSensorEvent): Promise<SensorEvent> {
  const [created] = await db.insert(sensorEvents).values(event).returning();
  return created;
}

export async function countSensorEvents(orgId: string): Promise<number> {
  const [row] = await db.select({ total: count() }).from(sensorEvents).where(eq(sensorEvents.orgId, orgId));
  return row?.total ?? 0;
}

// ── Detection Alerts ──

export async function getDetectionAlerts(orgId: string, limit = 100, offset = 0): Promise<DetectionAlert[]> {
  return db
    .select()
    .from(detectionAlerts)
    .where(eq(detectionAlerts.orgId, orgId))
    .orderBy(desc(detectionAlerts.createdAt))
    .limit(limit)
    .offset(offset);
}

export async function getDetectionAlertsByRule(ruleId: string): Promise<DetectionAlert[]> {
  return db
    .select()
    .from(detectionAlerts)
    .where(eq(detectionAlerts.ruleId, ruleId))
    .orderBy(desc(detectionAlerts.createdAt));
}

export async function createDetectionAlert(alert: InsertDetectionAlert): Promise<DetectionAlert> {
  const [created] = await db.insert(detectionAlerts).values(alert).returning();
  return created;
}

export async function countDetectionAlerts(orgId: string): Promise<number> {
  const [row] = await db.select({ total: count() }).from(detectionAlerts).where(eq(detectionAlerts.orgId, orgId));
  return row?.total ?? 0;
}

export async function countDetectionAlertsByRule(ruleId: string): Promise<number> {
  const [row] = await db.select({ total: count() }).from(detectionAlerts).where(eq(detectionAlerts.ruleId, ruleId));
  return row?.total ?? 0;
}

import { sql, relations } from "drizzle-orm";
import { pgTable, text, varchar, integer, timestamp, boolean, jsonb, real, index } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export * from "./models/auth";

export const organizations = pgTable("organizations", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  name: text("name").notNull(),
  slug: text("slug").notNull().unique(),
  createdAt: timestamp("created_at").defaultNow(),
});

export const alerts = pgTable("alerts", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  orgId: varchar("org_id").references(() => organizations.id),
  source: text("source").notNull(),
  severity: text("severity").notNull(),
  title: text("title").notNull(),
  description: text("description"),
  rawData: jsonb("raw_data"),
  normalizedData: jsonb("normalized_data"),
  sourceIp: text("source_ip"),
  destIp: text("dest_ip"),
  userId: text("user_id_field"),
  hostname: text("hostname"),
  fileHash: text("file_hash"),
  mitreTactic: text("mitre_tactic"),
  mitreTechnique: text("mitre_technique"),
  status: text("status").notNull().default("new"),
  incidentId: varchar("incident_id"),
  createdAt: timestamp("created_at").defaultNow(),
}, (table) => [
  index("idx_alerts_org").on(table.orgId),
  index("idx_alerts_status").on(table.status),
  index("idx_alerts_severity").on(table.severity),
]);

export const incidents = pgTable("incidents", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  orgId: varchar("org_id").references(() => organizations.id),
  title: text("title").notNull(),
  summary: text("summary"),
  severity: text("severity").notNull(),
  status: text("status").notNull().default("open"),
  confidence: real("confidence"),
  attackerProfile: jsonb("attacker_profile"),
  mitreTactics: text("mitre_tactics").array(),
  mitreTechniques: text("mitre_techniques").array(),
  alertCount: integer("alert_count").default(0),
  aiNarrative: text("ai_narrative"),
  mitigationSteps: jsonb("mitigation_steps"),
  assignedTo: varchar("assigned_to"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
}, (table) => [
  index("idx_incidents_org").on(table.orgId),
  index("idx_incidents_status").on(table.status),
]);

export const auditLogs = pgTable("audit_logs", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  orgId: varchar("org_id"),
  userId: varchar("user_id"),
  action: text("action").notNull(),
  resourceType: text("resource_type"),
  resourceId: varchar("resource_id"),
  details: jsonb("details"),
  createdAt: timestamp("created_at").defaultNow(),
});

export const insertAlertSchema = createInsertSchema(alerts).omit({ id: true, createdAt: true });
export const insertIncidentSchema = createInsertSchema(incidents).omit({ id: true, createdAt: true, updatedAt: true });
export const insertOrgSchema = createInsertSchema(organizations).omit({ id: true, createdAt: true });

export type InsertAlert = z.infer<typeof insertAlertSchema>;
export type Alert = typeof alerts.$inferSelect;
export type InsertIncident = z.infer<typeof insertIncidentSchema>;
export type Incident = typeof incidents.$inferSelect;
export type Organization = typeof organizations.$inferSelect;
export type InsertOrganization = z.infer<typeof insertOrgSchema>;
export type AuditLog = typeof auditLogs.$inferSelect;

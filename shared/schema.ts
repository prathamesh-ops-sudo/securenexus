import { sql, relations } from "drizzle-orm";
import { pgTable, text, varchar, integer, timestamp, boolean, jsonb, real, index } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export * from "./models/auth";

export const ALERT_SEVERITIES = ["critical", "high", "medium", "low", "informational"] as const;
export const ALERT_STATUSES = ["new", "triaged", "correlated", "investigating", "resolved", "dismissed", "false_positive"] as const;
export const INCIDENT_SEVERITIES = ["critical", "high", "medium", "low"] as const;
export const INCIDENT_STATUSES = ["open", "investigating", "contained", "eradicated", "recovered", "resolved", "closed"] as const;
export const ALERT_SOURCES = ["CrowdStrike EDR", "Splunk SIEM", "Palo Alto Firewall", "AWS GuardDuty", "Suricata IDS", "Microsoft Defender", "Custom"] as const;
export const ALERT_CATEGORIES = ["malware", "intrusion", "phishing", "data_exfiltration", "privilege_escalation", "lateral_movement", "credential_access", "reconnaissance", "persistence", "command_and_control", "cloud_misconfiguration", "policy_violation", "other"] as const;

export const organizations = pgTable("organizations", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  name: text("name").notNull(),
  slug: text("slug").notNull().unique(),
  industry: text("industry"),
  contactEmail: text("contact_email"),
  maxUsers: integer("max_users").default(10),
  createdAt: timestamp("created_at").defaultNow(),
});

export const alerts = pgTable("alerts", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  orgId: varchar("org_id").references(() => organizations.id),
  source: text("source").notNull(),
  sourceEventId: text("source_event_id"),
  category: text("category").default("other"),
  severity: text("severity").notNull(),
  title: text("title").notNull(),
  description: text("description"),
  rawData: jsonb("raw_data"),
  normalizedData: jsonb("normalized_data"),
  sourceIp: text("source_ip"),
  destIp: text("dest_ip"),
  sourcePort: integer("source_port"),
  destPort: integer("dest_port"),
  protocol: text("protocol"),
  userId: text("user_id_field"),
  hostname: text("hostname"),
  fileHash: text("file_hash"),
  url: text("url"),
  domain: text("domain"),
  mitreTactic: text("mitre_tactic"),
  mitreTechnique: text("mitre_technique"),
  status: text("status").notNull().default("new"),
  incidentId: varchar("incident_id").references(() => incidents.id),
  correlationScore: real("correlation_score"),
  correlationReason: text("correlation_reason"),
  analystNotes: text("analyst_notes"),
  assignedTo: varchar("assigned_to"),
  detectedAt: timestamp("detected_at"),
  ingestedAt: timestamp("ingested_at").defaultNow(),
  createdAt: timestamp("created_at").defaultNow(),
}, (table) => [
  index("idx_alerts_org").on(table.orgId),
  index("idx_alerts_status").on(table.status),
  index("idx_alerts_severity").on(table.severity),
  index("idx_alerts_incident").on(table.incidentId),
  index("idx_alerts_source").on(table.source),
  index("idx_alerts_category").on(table.category),
  index("idx_alerts_org_created").on(table.orgId, table.createdAt),
]);

export const incidents = pgTable("incidents", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  orgId: varchar("org_id").references(() => organizations.id),
  title: text("title").notNull(),
  summary: text("summary"),
  severity: text("severity").notNull(),
  status: text("status").notNull().default("open"),
  priority: integer("priority").default(3),
  confidence: real("confidence"),
  attackerProfile: jsonb("attacker_profile"),
  mitreTactics: text("mitre_tactics").array(),
  mitreTechniques: text("mitre_techniques").array(),
  alertCount: integer("alert_count").default(0),
  aiNarrative: text("ai_narrative"),
  aiSummary: text("ai_summary"),
  mitigationSteps: jsonb("mitigation_steps"),
  affectedAssets: jsonb("affected_assets"),
  iocs: jsonb("iocs"),
  assignedTo: varchar("assigned_to"),
  leadAnalyst: varchar("lead_analyst"),
  escalated: boolean("escalated").default(false),
  escalatedAt: timestamp("escalated_at"),
  containedAt: timestamp("contained_at"),
  resolvedAt: timestamp("resolved_at"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
}, (table) => [
  index("idx_incidents_org").on(table.orgId),
  index("idx_incidents_status").on(table.status),
  index("idx_incidents_severity").on(table.severity),
  index("idx_incidents_org_created").on(table.orgId, table.createdAt),
  index("idx_incidents_assigned").on(table.assignedTo),
]);

export const incidentComments = pgTable("incident_comments", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  incidentId: varchar("incident_id").notNull().references(() => incidents.id),
  userId: varchar("user_id"),
  userName: text("user_name"),
  body: text("body").notNull(),
  isInternal: boolean("is_internal").default(false),
  createdAt: timestamp("created_at").defaultNow(),
}, (table) => [
  index("idx_comments_incident").on(table.incidentId),
]);

export const tags = pgTable("tags", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  name: text("name").notNull().unique(),
  color: text("color").default("#6366f1"),
  category: text("category"),
  createdAt: timestamp("created_at").defaultNow(),
});

export const alertTags = pgTable("alert_tags", {
  alertId: varchar("alert_id").notNull().references(() => alerts.id, { onDelete: "cascade" }),
  tagId: varchar("tag_id").notNull().references(() => tags.id, { onDelete: "cascade" }),
}, (table) => [
  index("idx_alert_tags_alert").on(table.alertId),
  index("idx_alert_tags_tag").on(table.tagId),
]);

export const incidentTags = pgTable("incident_tags", {
  incidentId: varchar("incident_id").notNull().references(() => incidents.id, { onDelete: "cascade" }),
  tagId: varchar("tag_id").notNull().references(() => tags.id, { onDelete: "cascade" }),
}, (table) => [
  index("idx_incident_tags_incident").on(table.incidentId),
  index("idx_incident_tags_tag").on(table.tagId),
]);

export const auditLogs = pgTable("audit_logs", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  orgId: varchar("org_id"),
  userId: varchar("user_id"),
  userName: text("user_name"),
  action: text("action").notNull(),
  resourceType: text("resource_type"),
  resourceId: varchar("resource_id"),
  details: jsonb("details"),
  ipAddress: text("ip_address"),
  createdAt: timestamp("created_at").defaultNow(),
});

// Relations
export const organizationsRelations = relations(organizations, ({ many }) => ({
  alerts: many(alerts),
  incidents: many(incidents),
}));

export const alertsRelations = relations(alerts, ({ one, many }) => ({
  organization: one(organizations, { fields: [alerts.orgId], references: [organizations.id] }),
  incident: one(incidents, { fields: [alerts.incidentId], references: [incidents.id] }),
  tags: many(alertTags),
}));

export const incidentsRelations = relations(incidents, ({ one, many }) => ({
  organization: one(organizations, { fields: [incidents.orgId], references: [organizations.id] }),
  alerts: many(alerts),
  comments: many(incidentComments),
  tags: many(incidentTags),
}));

export const incidentCommentsRelations = relations(incidentComments, ({ one }) => ({
  incident: one(incidents, { fields: [incidentComments.incidentId], references: [incidents.id] }),
}));

export const alertTagsRelations = relations(alertTags, ({ one }) => ({
  alert: one(alerts, { fields: [alertTags.alertId], references: [alerts.id] }),
  tag: one(tags, { fields: [alertTags.tagId], references: [tags.id] }),
}));

export const incidentTagsRelations = relations(incidentTags, ({ one }) => ({
  incident: one(incidents, { fields: [incidentTags.incidentId], references: [incidents.id] }),
  tag: one(tags, { fields: [incidentTags.tagId], references: [tags.id] }),
}));

// Insert schemas
export const insertAlertSchema = createInsertSchema(alerts).omit({ id: true, createdAt: true, ingestedAt: true });
export const insertIncidentSchema = createInsertSchema(incidents).omit({ id: true, createdAt: true, updatedAt: true });
export const insertOrgSchema = createInsertSchema(organizations).omit({ id: true, createdAt: true });
export const insertCommentSchema = createInsertSchema(incidentComments).omit({ id: true, createdAt: true });
export const insertTagSchema = createInsertSchema(tags).omit({ id: true, createdAt: true });

// Types
export type InsertAlert = z.infer<typeof insertAlertSchema>;
export type Alert = typeof alerts.$inferSelect;
export type InsertIncident = z.infer<typeof insertIncidentSchema>;
export type Incident = typeof incidents.$inferSelect;
export type Organization = typeof organizations.$inferSelect;
export type InsertOrganization = z.infer<typeof insertOrgSchema>;
export type AuditLog = typeof auditLogs.$inferSelect;
export type IncidentComment = typeof incidentComments.$inferSelect;
export type InsertComment = z.infer<typeof insertCommentSchema>;
export type Tag = typeof tags.$inferSelect;
export type InsertTag = z.infer<typeof insertTagSchema>;

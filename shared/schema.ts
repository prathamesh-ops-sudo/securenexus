import { sql, relations } from "drizzle-orm";
import { pgTable, text, varchar, integer, timestamp, boolean, jsonb, real, index, uniqueIndex } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export * from "./models/auth";

export const ALERT_SEVERITIES = ["critical", "high", "medium", "low", "informational"] as const;
export const ALERT_STATUSES = ["new", "triaged", "correlated", "investigating", "resolved", "dismissed", "false_positive"] as const;
export const INCIDENT_SEVERITIES = ["critical", "high", "medium", "low"] as const;
export const INCIDENT_STATUSES = ["open", "investigating", "contained", "eradicated", "recovered", "resolved", "closed"] as const;
export const ALERT_SOURCES = [
  "CrowdStrike EDR", "Splunk SIEM", "Palo Alto Firewall", "AWS GuardDuty", "Suricata IDS",
  "Microsoft Defender", "Wiz Cloud", "Wazuh SIEM", "SentinelOne EDR",
  "Elastic Security", "IBM QRadar", "Fortinet FortiGate", "Carbon Black EDR",
  "Qualys VMDR", "Tenable Nessus", "Cisco Umbrella", "Darktrace",
  "Rapid7 InsightIDR", "Trend Micro Vision One", "Okta Identity",
  "Proofpoint Email", "Snort IDS", "Zscaler ZIA", "Check Point", "Custom",
] as const;
export const CONNECTOR_TYPES = [
  "crowdstrike", "splunk", "wiz", "wazuh", "paloalto", "guardduty", "defender", "sentinelone", "suricata",
  "elastic", "qradar", "fortigate", "carbonblack", "qualys", "tenable", "umbrella", "darktrace",
  "rapid7", "trendmicro", "okta", "proofpoint", "snort", "zscaler", "checkpoint",
] as const;
export const CONNECTOR_STATUSES = ["active", "inactive", "error", "syncing"] as const;
export const CONNECTOR_AUTH_TYPES = ["oauth2", "api_key", "basic", "aws_credentials", "token", "certificate"] as const;
export const ALERT_CATEGORIES = ["malware", "intrusion", "phishing", "data_exfiltration", "privilege_escalation", "lateral_movement", "credential_access", "reconnaissance", "persistence", "command_and_control", "cloud_misconfiguration", "policy_violation", "other"] as const;
export const INGESTION_STATUSES = ["success", "partial", "failed", "deduped"] as const;
export const PLAYBOOK_STATUSES = ["active", "inactive", "draft"] as const;
export const PLAYBOOK_TRIGGERS = ["alert_created", "alert_critical", "incident_created", "incident_escalated", "manual"] as const;
export const ENTITY_TYPES = ["user", "host", "ip", "domain", "file_hash", "email", "url", "process"] as const;
export const INTEGRATION_TYPES = ["jira", "servicenow", "slack", "teams", "email", "pagerduty", "webhook"] as const;
export const INTEGRATION_STATUSES = ["active", "inactive", "error"] as const;
export const CHANNEL_TYPES = ["slack", "teams", "email", "webhook", "pagerduty"] as const;
export const RESPONSE_ACTION_TYPES = ["isolate_host", "block_ip", "quarantine_file", "disable_user", "block_domain", "kill_process"] as const;
export const RESPONSE_ACTION_STATUSES = ["pending", "executing", "completed", "failed", "simulated"] as const;

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
  ocsfData: jsonb("ocsf_data"),
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
  correlationClusterId: varchar("correlation_cluster_id"),
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
  uniqueIndex("idx_alerts_dedup").on(table.orgId, table.source, table.sourceEventId),
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
  reasoningTrace: text("reasoning_trace"),
  mitigationSteps: jsonb("mitigation_steps"),
  affectedAssets: jsonb("affected_assets"),
  iocs: jsonb("iocs"),
  referencedAlertIds: text("referenced_alert_ids").array(),
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
  entryHash: text("entry_hash"),
  prevHash: text("prev_hash"),
  sequenceNum: integer("sequence_num"),
  createdAt: timestamp("created_at").defaultNow(),
}, (table) => [
  index("idx_audit_logs_org_seq").on(table.orgId, table.sequenceNum),
]);

export const apiKeys = pgTable("api_keys", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  orgId: varchar("org_id").references(() => organizations.id),
  name: text("name").notNull(),
  keyHash: text("key_hash").notNull(),
  keyPrefix: text("key_prefix").notNull(),
  scopes: text("scopes").array().default(sql`ARRAY['ingest']`),
  isActive: boolean("is_active").default(true),
  webhookSecret: text("webhook_secret"),
  lastUsedAt: timestamp("last_used_at"),
  createdBy: varchar("created_by"),
  createdAt: timestamp("created_at").defaultNow(),
  revokedAt: timestamp("revoked_at"),
}, (table) => [
  index("idx_api_keys_org").on(table.orgId),
  index("idx_api_keys_hash").on(table.keyHash),
]);

export const ingestionLogs = pgTable("ingestion_logs", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  orgId: varchar("org_id").references(() => organizations.id),
  source: text("source").notNull(),
  status: text("status").notNull().default("success"),
  alertsReceived: integer("alerts_received").default(0),
  alertsCreated: integer("alerts_created").default(0),
  alertsDeduped: integer("alerts_deduped").default(0),
  alertsFailed: integer("alerts_failed").default(0),
  errorMessage: text("error_message"),
  requestId: varchar("request_id"),
  ipAddress: text("ip_address"),
  processingTimeMs: integer("processing_time_ms"),
  receivedAt: timestamp("received_at").defaultNow(),
}, (table) => [
  index("idx_ingestion_logs_org").on(table.orgId),
  index("idx_ingestion_logs_source").on(table.source),
  index("idx_ingestion_logs_received").on(table.receivedAt),
  index("idx_ingestion_logs_org_received").on(table.orgId, table.receivedAt),
]);

export const connectors = pgTable("connectors", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  orgId: varchar("org_id").references(() => organizations.id),
  name: text("name").notNull(),
  type: text("type").notNull(),
  authType: text("auth_type").notNull(),
  config: jsonb("config").notNull(),
  status: text("status").notNull().default("inactive"),
  pollingIntervalMin: integer("polling_interval_min").default(5),
  lastSyncAt: timestamp("last_sync_at"),
  lastSyncStatus: text("last_sync_status"),
  lastSyncAlerts: integer("last_sync_alerts").default(0),
  lastSyncError: text("last_sync_error"),
  totalAlertsSynced: integer("total_alerts_synced").default(0),
  createdBy: varchar("created_by"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
}, (table) => [
  index("idx_connectors_org").on(table.orgId),
  index("idx_connectors_type").on(table.type),
  index("idx_connectors_status").on(table.status),
]);

export const aiFeedback = pgTable("ai_feedback", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  orgId: varchar("org_id"),
  userId: varchar("user_id"),
  userName: text("user_name"),
  resourceType: text("resource_type").notNull(),
  resourceId: varchar("resource_id"),
  rating: integer("rating").notNull(),
  comment: text("comment"),
  aiOutput: jsonb("ai_output"),
  createdAt: timestamp("created_at").defaultNow(),
}, (table) => [
  index("idx_ai_feedback_org").on(table.orgId),
  index("idx_ai_feedback_resource").on(table.resourceType, table.resourceId),
  index("idx_ai_feedback_created").on(table.createdAt),
]);

export const playbooks = pgTable("playbooks", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  orgId: varchar("org_id"),
  name: text("name").notNull(),
  description: text("description"),
  trigger: text("trigger").notNull(),
  conditions: jsonb("conditions"),
  actions: jsonb("actions").notNull(),
  status: text("status").notNull().default("draft"),
  lastTriggeredAt: timestamp("last_triggered_at"),
  triggerCount: integer("trigger_count").default(0),
  createdBy: varchar("created_by"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
}, (table) => [
  index("idx_playbooks_org").on(table.orgId),
  index("idx_playbooks_status").on(table.status),
  index("idx_playbooks_trigger").on(table.trigger),
]);

export const playbookExecutions = pgTable("playbook_executions", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  playbookId: varchar("playbook_id").notNull().references(() => playbooks.id),
  triggeredBy: text("triggered_by"),
  triggerEvent: text("trigger_event"),
  resourceType: text("resource_type"),
  resourceId: varchar("resource_id"),
  status: text("status").notNull().default("running"),
  actionsExecuted: jsonb("actions_executed"),
  result: jsonb("result"),
  errorMessage: text("error_message"),
  executionTimeMs: integer("execution_time_ms"),
  createdAt: timestamp("created_at").defaultNow(),
}, (table) => [
  index("idx_playbook_executions_playbook").on(table.playbookId),
  index("idx_playbook_executions_status").on(table.status),
  index("idx_playbook_executions_created").on(table.createdAt),
]);

export const entities = pgTable("entities", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  orgId: varchar("org_id").references(() => organizations.id),
  type: text("type").notNull(),
  value: text("value").notNull(),
  displayName: text("display_name"),
  metadata: jsonb("metadata"),
  firstSeenAt: timestamp("first_seen_at").defaultNow(),
  lastSeenAt: timestamp("last_seen_at").defaultNow(),
  alertCount: integer("alert_count").default(0),
  riskScore: real("risk_score").default(0),
  createdAt: timestamp("created_at").defaultNow(),
}, (table) => [
  index("idx_entities_org").on(table.orgId),
  index("idx_entities_type").on(table.type),
  index("idx_entities_value").on(table.value),
  uniqueIndex("idx_entities_org_type_value").on(table.orgId, table.type, table.value),
]);

export const entityAliases = pgTable("entity_aliases", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  entityId: varchar("entity_id").notNull().references(() => entities.id, { onDelete: "cascade" }),
  aliasType: text("alias_type").notNull(),
  aliasValue: text("alias_value").notNull(),
  source: text("source"),
  createdAt: timestamp("created_at").defaultNow(),
}, (table) => [
  index("idx_entity_aliases_entity").on(table.entityId),
  index("idx_entity_aliases_value").on(table.aliasValue),
]);

export const alertEntities = pgTable("alert_entities", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  alertId: varchar("alert_id").notNull().references(() => alerts.id, { onDelete: "cascade" }),
  entityId: varchar("entity_id").notNull().references(() => entities.id, { onDelete: "cascade" }),
  role: text("role").notNull(),
  createdAt: timestamp("created_at").defaultNow(),
}, (table) => [
  index("idx_alert_entities_alert").on(table.alertId),
  index("idx_alert_entities_entity").on(table.entityId),
]);

export const correlationClusters = pgTable("correlation_clusters", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  orgId: varchar("org_id").references(() => organizations.id),
  incidentId: varchar("incident_id").references(() => incidents.id),
  confidence: real("confidence").notNull().default(0),
  method: text("method").notNull(),
  sharedEntities: jsonb("shared_entities"),
  reasoningTrace: text("reasoning_trace"),
  alertIds: text("alert_ids").array(),
  status: text("status").notNull().default("pending"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
}, (table) => [
  index("idx_correlation_clusters_org").on(table.orgId),
  index("idx_correlation_clusters_incident").on(table.incidentId),
  index("idx_correlation_clusters_status").on(table.status),
]);

export const attackPaths = pgTable("attack_paths", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  orgId: varchar("org_id").references(() => organizations.id),
  clusterId: varchar("cluster_id").references(() => correlationClusters.id),
  campaignId: varchar("campaign_id"),
  alertIds: text("alert_ids").array(),
  entityIds: text("entity_ids").array(),
  nodes: jsonb("nodes").notNull(),
  edges: jsonb("edges").notNull(),
  tacticsSequence: text("tactics_sequence").array(),
  techniquesUsed: text("techniques_used").array(),
  hopCount: integer("hop_count").default(0),
  confidence: real("confidence").notNull().default(0),
  timeSpanHours: real("time_span_hours"),
  firstAlertAt: timestamp("first_alert_at"),
  lastAlertAt: timestamp("last_alert_at"),
  createdAt: timestamp("created_at").defaultNow(),
}, (table) => [
  index("idx_attack_paths_org").on(table.orgId),
  index("idx_attack_paths_cluster").on(table.clusterId),
  index("idx_attack_paths_campaign").on(table.campaignId),
]);

export const campaigns = pgTable("campaigns", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  orgId: varchar("org_id").references(() => organizations.id),
  name: text("name").notNull(),
  fingerprint: text("fingerprint").notNull(),
  tacticsSequence: text("tactics_sequence").array(),
  entitySignature: text("entity_signature").array(),
  sourceSignature: text("source_signature").array(),
  clusterIds: text("cluster_ids").array(),
  attackPathIds: text("attack_path_ids").array(),
  confidence: real("confidence").notNull().default(0),
  alertCount: integer("alert_count").default(0),
  status: text("status").notNull().default("active"),
  firstSeenAt: timestamp("first_seen_at"),
  lastSeenAt: timestamp("last_seen_at"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
}, (table) => [
  index("idx_campaigns_org").on(table.orgId),
  index("idx_campaigns_fingerprint").on(table.fingerprint),
  index("idx_campaigns_status").on(table.status),
]);

export const COMPLIANCE_FRAMEWORKS = ["gdpr", "dpdp", "hipaa", "sox", "pci_dss", "iso27001", "nist"] as const;
export const DSAR_STATUSES = ["pending", "in_progress", "fulfilled", "rejected", "expired"] as const;

export const compliancePolicies = pgTable("compliance_policies", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  orgId: varchar("org_id").references(() => organizations.id),
  alertRetentionDays: integer("alert_retention_days").default(365),
  incidentRetentionDays: integer("incident_retention_days").default(730),
  auditLogRetentionDays: integer("audit_log_retention_days").default(2555),
  piiMaskingEnabled: boolean("pii_masking_enabled").default(false),
  pseudonymizeExports: boolean("pseudonymize_exports").default(true),
  enabledFrameworks: text("enabled_frameworks").array().default(sql`ARRAY['gdpr']`),
  dataProcessingBasis: text("data_processing_basis").default("legitimate_interest"),
  dpoEmail: text("dpo_email"),
  dsarSlaDays: integer("dsar_sla_days").default(30),
  retentionLastRunAt: timestamp("retention_last_run_at"),
  retentionLastDeletedCount: integer("retention_last_deleted_count").default(0),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
}, (table) => [
  uniqueIndex("idx_compliance_policies_org").on(table.orgId),
]);

export const dsarRequests = pgTable("dsar_requests", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  orgId: varchar("org_id").references(() => organizations.id),
  requestorEmail: text("requestor_email").notNull(),
  requestType: text("request_type").notNull().default("access"),
  subjectIdentifiers: jsonb("subject_identifiers").notNull(),
  status: text("status").notNull().default("pending"),
  dueDate: timestamp("due_date"),
  notes: text("notes"),
  resultSummary: jsonb("result_summary"),
  fulfilledAt: timestamp("fulfilled_at"),
  fulfilledBy: varchar("fulfilled_by"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
}, (table) => [
  index("idx_dsar_requests_org").on(table.orgId),
  index("idx_dsar_requests_status").on(table.status),
  index("idx_dsar_requests_due").on(table.dueDate),
]);

export const threatIntelConfigs = pgTable("threat_intel_configs", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  orgId: varchar("org_id").references(() => organizations.id),
  provider: text("provider").notNull(),
  apiKey: text("api_key"),
  enabled: boolean("enabled").default(true),
  lastTestedAt: timestamp("last_tested_at"),
  lastTestStatus: text("last_test_status"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
}, (table) => [
  index("idx_threat_intel_configs_org").on(table.orgId),
  uniqueIndex("idx_threat_intel_configs_org_provider").on(table.orgId, table.provider),
]);

export const integrationConfigs = pgTable("integration_configs", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  orgId: varchar("org_id").references(() => organizations.id),
  type: text("type").notNull(),
  name: text("name").notNull(),
  config: jsonb("config").notNull(),
  status: text("status").notNull().default("inactive"),
  lastTestedAt: timestamp("last_tested_at"),
  lastTestStatus: text("last_test_status"),
  createdBy: varchar("created_by"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
}, (table) => [
  index("idx_integration_configs_org").on(table.orgId),
  index("idx_integration_configs_type").on(table.type),
]);

export const notificationChannels = pgTable("notification_channels", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  orgId: varchar("org_id").references(() => organizations.id),
  name: text("name").notNull(),
  type: text("type").notNull(),
  config: jsonb("config").notNull(),
  isDefault: boolean("is_default").default(false),
  events: text("events").array().default(sql`ARRAY['incident_created']`),
  status: text("status").notNull().default("active"),
  lastNotifiedAt: timestamp("last_notified_at"),
  createdBy: varchar("created_by"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
}, (table) => [
  index("idx_notification_channels_org").on(table.orgId),
  index("idx_notification_channels_type").on(table.type),
]);

export const responseActions = pgTable("response_actions", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  orgId: varchar("org_id").references(() => organizations.id),
  actionType: text("action_type").notNull(),
  connectorId: varchar("connector_id"),
  incidentId: varchar("incident_id").references(() => incidents.id),
  alertId: varchar("alert_id"),
  targetType: text("target_type"),
  targetValue: text("target_value"),
  status: text("status").notNull().default("pending"),
  requestPayload: jsonb("request_payload"),
  responsePayload: jsonb("response_payload"),
  errorMessage: text("error_message"),
  executedBy: varchar("executed_by"),
  executedAt: timestamp("executed_at"),
  createdAt: timestamp("created_at").defaultNow(),
}, (table) => [
  index("idx_response_actions_org").on(table.orgId),
  index("idx_response_actions_incident").on(table.incidentId),
  index("idx_response_actions_status").on(table.status),
  index("idx_response_actions_type").on(table.actionType),
]);

// Relations
export const connectorsRelations = relations(connectors, ({ one }) => ({
  organization: one(organizations, { fields: [connectors.orgId], references: [organizations.id] }),
}));

export const aiFeedbackRelations = relations(aiFeedback, ({ one }) => ({
}));

export const playbooksRelations = relations(playbooks, ({ one, many }) => ({
  executions: many(playbookExecutions),
}));

export const playbookExecutionsRelations = relations(playbookExecutions, ({ one }) => ({
  playbook: one(playbooks, { fields: [playbookExecutions.playbookId], references: [playbooks.id] }),
}));

export const organizationsRelations = relations(organizations, ({ many }) => ({
  alerts: many(alerts),
  incidents: many(incidents),
  apiKeys: many(apiKeys),
  ingestionLogs: many(ingestionLogs),
  connectors: many(connectors),
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

export const apiKeysRelations = relations(apiKeys, ({ one }) => ({
  organization: one(organizations, { fields: [apiKeys.orgId], references: [organizations.id] }),
}));

export const ingestionLogsRelations = relations(ingestionLogs, ({ one }) => ({
  organization: one(organizations, { fields: [ingestionLogs.orgId], references: [organizations.id] }),
}));

export const entitiesRelations = relations(entities, ({ one, many }) => ({
  organization: one(organizations, { fields: [entities.orgId], references: [organizations.id] }),
  aliases: many(entityAliases),
  alertEntities: many(alertEntities),
}));

export const entityAliasesRelations = relations(entityAliases, ({ one }) => ({
  entity: one(entities, { fields: [entityAliases.entityId], references: [entities.id] }),
}));

export const alertEntitiesRelations = relations(alertEntities, ({ one }) => ({
  alert: one(alerts, { fields: [alertEntities.alertId], references: [alerts.id] }),
  entity: one(entities, { fields: [alertEntities.entityId], references: [entities.id] }),
}));

export const correlationClustersRelations = relations(correlationClusters, ({ one }) => ({
  organization: one(organizations, { fields: [correlationClusters.orgId], references: [organizations.id] }),
  incident: one(incidents, { fields: [correlationClusters.incidentId], references: [incidents.id] }),
}));

export const attackPathsRelations = relations(attackPaths, ({ one }) => ({
  organization: one(organizations, { fields: [attackPaths.orgId], references: [organizations.id] }),
  cluster: one(correlationClusters, { fields: [attackPaths.clusterId], references: [correlationClusters.id] }),
}));

export const campaignsRelations = relations(campaigns, ({ one }) => ({
  organization: one(organizations, { fields: [campaigns.orgId], references: [organizations.id] }),
}));

export const threatIntelConfigsRelations = relations(threatIntelConfigs, ({ one }) => ({
  organization: one(organizations, { fields: [threatIntelConfigs.orgId], references: [organizations.id] }),
}));

export const compliancePoliciesRelations = relations(compliancePolicies, ({ one }) => ({
  organization: one(organizations, { fields: [compliancePolicies.orgId], references: [organizations.id] }),
}));

export const dsarRequestsRelations = relations(dsarRequests, ({ one }) => ({
  organization: one(organizations, { fields: [dsarRequests.orgId], references: [organizations.id] }),
}));

export const integrationConfigsRelations = relations(integrationConfigs, ({ one }) => ({
  organization: one(organizations, { fields: [integrationConfigs.orgId], references: [organizations.id] }),
}));

export const notificationChannelsRelations = relations(notificationChannels, ({ one }) => ({
  organization: one(organizations, { fields: [notificationChannels.orgId], references: [organizations.id] }),
}));

export const responseActionsRelations = relations(responseActions, ({ one }) => ({
  organization: one(organizations, { fields: [responseActions.orgId], references: [organizations.id] }),
  incident: one(incidents, { fields: [responseActions.incidentId], references: [incidents.id] }),
}));

// Insert schemas
export const insertAlertSchema = createInsertSchema(alerts).omit({ id: true, createdAt: true, ingestedAt: true });
export const insertIncidentSchema = createInsertSchema(incidents).omit({ id: true, createdAt: true, updatedAt: true });
export const insertOrgSchema = createInsertSchema(organizations).omit({ id: true, createdAt: true });
export const insertCommentSchema = createInsertSchema(incidentComments).omit({ id: true, createdAt: true });
export const insertTagSchema = createInsertSchema(tags).omit({ id: true, createdAt: true });
export const insertApiKeySchema = createInsertSchema(apiKeys).omit({ id: true, createdAt: true, lastUsedAt: true, revokedAt: true });
export const insertIngestionLogSchema = createInsertSchema(ingestionLogs).omit({ id: true, receivedAt: true });
export const insertConnectorSchema = createInsertSchema(connectors).omit({ id: true, createdAt: true, updatedAt: true, lastSyncAt: true, lastSyncStatus: true, lastSyncAlerts: true, lastSyncError: true, totalAlertsSynced: true });
export const insertAiFeedbackSchema = createInsertSchema(aiFeedback).omit({ id: true, createdAt: true });
export const insertPlaybookSchema = createInsertSchema(playbooks).omit({ id: true, createdAt: true, updatedAt: true, lastTriggeredAt: true });
export const insertPlaybookExecutionSchema = createInsertSchema(playbookExecutions).omit({ id: true, createdAt: true });
export const insertEntitySchema = createInsertSchema(entities).omit({ id: true, createdAt: true, firstSeenAt: true, lastSeenAt: true });
export const insertEntityAliasSchema = createInsertSchema(entityAliases).omit({ id: true, createdAt: true });
export const insertAlertEntitySchema = createInsertSchema(alertEntities).omit({ id: true, createdAt: true });
export const insertCorrelationClusterSchema = createInsertSchema(correlationClusters).omit({ id: true, createdAt: true, updatedAt: true });
export const insertAttackPathSchema = createInsertSchema(attackPaths).omit({ id: true, createdAt: true });
export const insertCampaignSchema = createInsertSchema(campaigns).omit({ id: true, createdAt: true, updatedAt: true });
export const insertThreatIntelConfigSchema = createInsertSchema(threatIntelConfigs).omit({ id: true, createdAt: true, updatedAt: true, lastTestedAt: true, lastTestStatus: true });
export const insertCompliancePolicySchema = createInsertSchema(compliancePolicies).omit({ id: true, createdAt: true, updatedAt: true, retentionLastRunAt: true, retentionLastDeletedCount: true });
export const insertDsarRequestSchema = createInsertSchema(dsarRequests).omit({ id: true, createdAt: true, updatedAt: true, fulfilledAt: true, fulfilledBy: true, resultSummary: true });
export const insertIntegrationConfigSchema = createInsertSchema(integrationConfigs).omit({ id: true, createdAt: true, updatedAt: true, lastTestedAt: true, lastTestStatus: true });
export const insertNotificationChannelSchema = createInsertSchema(notificationChannels).omit({ id: true, createdAt: true, updatedAt: true, lastNotifiedAt: true });
export const insertResponseActionSchema = createInsertSchema(responseActions).omit({ id: true, createdAt: true, executedAt: true });

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
export type ApiKey = typeof apiKeys.$inferSelect;
export type InsertApiKey = z.infer<typeof insertApiKeySchema>;
export type IngestionLog = typeof ingestionLogs.$inferSelect;
export type InsertIngestionLog = z.infer<typeof insertIngestionLogSchema>;
export type Connector = typeof connectors.$inferSelect;
export type InsertConnector = z.infer<typeof insertConnectorSchema>;
export type AiFeedback = typeof aiFeedback.$inferSelect;
export type InsertAiFeedback = z.infer<typeof insertAiFeedbackSchema>;
export type Playbook = typeof playbooks.$inferSelect;
export type InsertPlaybook = z.infer<typeof insertPlaybookSchema>;
export type PlaybookExecution = typeof playbookExecutions.$inferSelect;
export type InsertPlaybookExecution = z.infer<typeof insertPlaybookExecutionSchema>;
export type Entity = typeof entities.$inferSelect;
export type InsertEntity = z.infer<typeof insertEntitySchema>;
export type EntityAlias = typeof entityAliases.$inferSelect;
export type InsertEntityAlias = z.infer<typeof insertEntityAliasSchema>;
export type AlertEntity = typeof alertEntities.$inferSelect;
export type InsertAlertEntity = z.infer<typeof insertAlertEntitySchema>;
export type CorrelationCluster = typeof correlationClusters.$inferSelect;
export type InsertCorrelationCluster = z.infer<typeof insertCorrelationClusterSchema>;
export type AttackPath = typeof attackPaths.$inferSelect;
export type InsertAttackPath = z.infer<typeof insertAttackPathSchema>;
export type Campaign = typeof campaigns.$inferSelect;
export type InsertCampaign = z.infer<typeof insertCampaignSchema>;
export type ThreatIntelConfig = typeof threatIntelConfigs.$inferSelect;
export type InsertThreatIntelConfig = z.infer<typeof insertThreatIntelConfigSchema>;
export type CompliancePolicy = typeof compliancePolicies.$inferSelect;
export type InsertCompliancePolicy = z.infer<typeof insertCompliancePolicySchema>;
export type DsarRequest = typeof dsarRequests.$inferSelect;
export type InsertDsarRequest = z.infer<typeof insertDsarRequestSchema>;
export type IntegrationConfig = typeof integrationConfigs.$inferSelect;
export type InsertIntegrationConfig = z.infer<typeof insertIntegrationConfigSchema>;
export type NotificationChannel = typeof notificationChannels.$inferSelect;
export type InsertNotificationChannel = z.infer<typeof insertNotificationChannelSchema>;
export type ResponseAction = typeof responseActions.$inferSelect;
export type InsertResponseAction = z.infer<typeof insertResponseActionSchema>;

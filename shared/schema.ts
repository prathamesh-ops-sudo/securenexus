import { sql, relations } from "drizzle-orm";
import {
  pgTable,
  text,
  varchar,
  integer,
  bigint,
  timestamp,
  boolean,
  jsonb,
  real,
  doublePrecision,
  serial,
  index,
  uniqueIndex,
  uuid,
  vector,
} from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export * from "./models/auth";

export const ALERT_SEVERITIES = ["critical", "high", "medium", "low", "informational"] as const;
export const ALERT_STATUSES = [
  "new",
  "triaged",
  "correlated",
  "investigating",
  "resolved",
  "dismissed",
  "false_positive",
  "deduped",
] as const;
export const INCIDENT_SEVERITIES = ["critical", "high", "medium", "low"] as const;
export const INCIDENT_STATUSES = [
  "open",
  "investigating",
  "contained",
  "eradicated",
  "recovered",
  "resolved",
  "closed",
] as const;
export const ALERT_SOURCES = [
  "CrowdStrike EDR",
  "Splunk SIEM",
  "Palo Alto Firewall",
  "AWS GuardDuty",
  "Suricata IDS",
  "Microsoft Defender",
  "Wiz Cloud",
  "Wazuh SIEM",
  "SentinelOne EDR",
  "Elastic Security",
  "IBM QRadar",
  "Fortinet FortiGate",
  "Carbon Black EDR",
  "Qualys VMDR",
  "Tenable Nessus",
  "Cisco Umbrella",
  "Darktrace",
  "Rapid7 InsightIDR",
  "Trend Micro Vision One",
  "Okta Identity",
  "Proofpoint Email",
  "Snort IDS",
  "Zscaler ZIA",
  "Check Point",
  "Custom",
] as const;
export const CONNECTOR_TYPES = [
  "crowdstrike",
  "splunk",
  "wiz",
  "wazuh",
  "paloalto",
  "guardduty",
  "defender",
  "sentinelone",
  "suricata",
  "elastic",
  "qradar",
  "fortigate",
  "carbonblack",
  "qualys",
  "tenable",
  "umbrella",
  "darktrace",
  "rapid7",
  "trendmicro",
  "okta",
  "proofpoint",
  "snort",
  "zscaler",
  "checkpoint",
] as const;
export const CONNECTOR_STATUSES = ["active", "inactive", "error", "syncing"] as const;
export const CONNECTOR_AUTH_TYPES = ["oauth2", "api_key", "basic", "aws_credentials", "token", "certificate"] as const;
export const ALERT_CATEGORIES = [
  "malware",
  "intrusion",
  "phishing",
  "data_exfiltration",
  "privilege_escalation",
  "lateral_movement",
  "credential_access",
  "reconnaissance",
  "persistence",
  "command_and_control",
  "cloud_misconfiguration",
  "policy_violation",
  "deception_hit",
  "other",
] as const;
export const INGESTION_STATUSES = ["success", "partial", "failed", "deduped"] as const;
export const PLAYBOOK_STATUSES = ["active", "inactive", "draft"] as const;
export const PLAYBOOK_TRIGGERS = [
  "alert_created",
  "alert_critical",
  "incident_created",
  "incident_escalated",
  "alert_category_deception",
  "manual",
] as const;
export const ENTITY_TYPES = ["user", "host", "ip", "domain", "file_hash", "email", "url", "process"] as const;
export const INTEGRATION_TYPES = ["jira", "servicenow", "slack", "teams", "email", "pagerduty", "webhook"] as const;
export const INTEGRATION_STATUSES = ["active", "inactive", "error"] as const;
export const CHANNEL_TYPES = ["slack", "teams", "email", "webhook", "pagerduty"] as const;
export const RESPONSE_ACTION_TYPES = [
  "isolate_host",
  "block_ip",
  "quarantine_file",
  "disable_user",
  "block_domain",
  "kill_process",
] as const;
export const RESPONSE_ACTION_STATUSES = ["pending", "executing", "completed", "failed", "simulated"] as const;
export const ANOMALY_KINDS = [
  "volume_spike",
  "new_vector",
  "timing_anomaly",
  "severity_escalation",
  "source_deviation",
] as const;
export const FORECAST_TYPES = [
  "ransomware",
  "data_exfiltration",
  "phishing_campaign",
  "lateral_movement",
  "privilege_escalation",
  "apt_campaign",
] as const;
export const RECOMMENDATION_PRIORITIES = ["critical", "high", "medium", "low"] as const;
export const RECOMMENDATION_STATUSES = ["open", "accepted", "in_progress", "dismissed", "completed"] as const;
export const AUTO_RESPONSE_POLICY_STATUSES = ["active", "inactive", "testing"] as const;
export const AUTO_RESPONSE_TRIGGER_TYPES = [
  "incident_created",
  "incident_severity_change",
  "alert_critical",
  "correlation_detected",
] as const;
export const INVESTIGATION_RUN_STATUSES = ["queued", "running", "completed", "failed", "cancelled"] as const;
export const INVESTIGATION_STEP_TYPES = [
  "gather_alerts",
  "enrich_entities",
  "correlate_evidence",
  "mitre_mapping",
  "ai_analysis",
  "recommendation",
  "action_taken",
] as const;
export const ROLLBACK_STATUSES = ["pending", "completed", "failed", "not_applicable"] as const;

export const ORG_ROLES = ["owner", "admin", "analyst", "read_only"] as const;
export const MEMBERSHIP_STATUSES = ["active", "suspended", "invited"] as const;
export const PERMISSION_SCOPES = [
  "incidents",
  "connectors",
  "api_keys",
  "response_actions",
  "settings",
  "team",
] as const;
export const PERMISSION_ACTIONS = ["read", "write", "admin"] as const;
export const TEAM_MEMBERSHIP_ROLES = ["lead", "member"] as const;
export const SAVED_VIEW_RESOURCE_TYPES = ["alerts", "incidents", "entities", "connectors"] as const;
export const SAVED_VIEW_VISIBILITIES = ["private", "team", "org"] as const;
export const SUPPRESSION_MATCHER_OPS = ["eq", "neq", "contains", "not_contains", "regex", "in", "not_in"] as const;
export const APPROVAL_SUBJECT_TYPES = ["response_action", "playbook"] as const;
export const APPROVAL_DECISIONS = ["approved", "rejected", "abstained"] as const;
export const CONNECTOR_RETRY_STRATEGIES = ["exponential", "linear", "fixed"] as const;
export const AUDIT_VERIFICATION_STATUSES = ["running", "completed", "failed"] as const;
export const AUDIT_VERIFICATION_TRIGGERS = ["scheduled", "manual", "system"] as const;

export const ROLE_PERMISSIONS: Record<string, Record<string, string[]>> = {
  owner: {
    incidents: ["read", "write", "admin"],
    connectors: ["read", "write", "admin"],
    api_keys: ["read", "write", "admin"],
    response_actions: ["read", "write", "admin"],
    settings: ["read", "write", "admin"],
    team: ["read", "write", "admin"],
  },
  admin: {
    incidents: ["read", "write", "admin"],
    connectors: ["read", "write", "admin"],
    api_keys: ["read", "write", "admin"],
    response_actions: ["read", "write", "admin"],
    settings: ["read", "write"],
    team: ["read", "write"],
  },
  analyst: {
    incidents: ["read", "write"],
    connectors: ["read"],
    api_keys: ["read"],
    response_actions: ["read", "write"],
    settings: ["read"],
    team: ["read"],
  },
  read_only: {
    incidents: ["read"],
    connectors: ["read"],
    api_keys: [],
    response_actions: ["read"],
    settings: ["read"],
    team: ["read"],
  },
};

export const ORG_TYPES = ["standard", "mssp_parent", "mssp_child"] as const;

export const organizations = pgTable("organizations", {
  id: varchar("id")
    .primaryKey()
    .default(sql`gen_random_uuid()`),
  name: text("name").notNull(),
  slug: text("slug").notNull().unique(),
  industry: text("industry"),
  contactEmail: text("contact_email"),
  billingEmail: text("billing_email"),
  phone: text("phone"),
  address: jsonb("address"),
  companySize: text("company_size"),
  logoUrl: text("logo_url"),
  primaryColor: text("primary_color"),
  maxUsers: integer("max_users").default(10),
  locale: text("locale").default("en-US"),
  timezone: text("timezone").default("UTC"),
  orgType: text("org_type").notNull().default("standard"),
  parentOrgId: varchar("parent_org_id"),
  dataResidency: text("data_residency").default("us-east-1"),
  dataRegion: text("data_region").default("US"),
  sovereignKeyConfig: jsonb("sovereign_key_config"),
  crossBorderFlowControls: jsonb("cross_border_flow_controls"),
  defaultMemberRole: text("default_member_role").notNull().default("analyst"),
  requireApproval: boolean("require_approval").notNull().default(false),
  deletedAt: timestamp("deleted_at"),
  updatedAt: timestamp("updated_at").defaultNow(),
  createdAt: timestamp("created_at").defaultNow(),
});

export const alerts = pgTable(
  "alerts",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
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
    suppressed: boolean("suppressed").default(false),
    suppressedBy: varchar("suppressed_by"),
    suppressionRuleId: varchar("suppression_rule_id"),
    confidenceScore: real("confidence_score"),
    confidenceSource: text("confidence_source"),
    confidenceNotes: text("confidence_notes"),
    dedupClusterId: varchar("dedup_cluster_id"),
    occurrenceCount: integer("occurrence_count").default(1),
    analystNotes: text("analyst_notes"),
    assignedTo: varchar("assigned_to"),
    detectedAt: timestamp("detected_at"),
    ingestedAt: timestamp("ingested_at").defaultNow(),
    lastSeenAt: timestamp("last_seen_at"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_alerts_org").on(table.orgId),
    index("idx_alerts_status").on(table.status),
    index("idx_alerts_severity").on(table.severity),
    index("idx_alerts_incident").on(table.incidentId),
    index("idx_alerts_source").on(table.source),
    index("idx_alerts_category").on(table.category),
    index("idx_alerts_org_created").on(table.orgId, table.createdAt),
    index("idx_alerts_org_status_created").on(table.orgId, table.status, table.createdAt),
    index("idx_alerts_org_severity_created").on(table.orgId, table.severity, table.createdAt),
    index("idx_alerts_org_source_created").on(table.orgId, table.source, table.createdAt),
    uniqueIndex("idx_alerts_dedup").on(table.orgId, table.source, table.sourceEventId),
  ],
);

export const incidents = pgTable(
  "incidents",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").references(() => organizations.id),
    title: text("title").notNull(),
    summary: text("summary"),
    severity: text("severity").notNull(),
    status: text("status").notNull().default("open"),
    priority: integer("priority").default(3),
    confidence: real("confidence"),
    needsReview: boolean("needs_review").default(false),
    algorithmScores: jsonb("algorithm_scores"),
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
    ackDueAt: timestamp("ack_due_at"),
    containDueAt: timestamp("contain_due_at"),
    resolveDueAt: timestamp("resolve_due_at"),
    ackAt: timestamp("ack_at"),
    slaBreached: boolean("sla_breached").default(false),
    // comma-separated list of breached milestone names, e.g. "ack,contain"
    slaBreachType: text("sla_breach_type"),
    // total number of SLA milestones breached (0–3: ack / contain / resolve)
    slaBreachCount: integer("sla_breach_count").notNull().default(0),
    // per-milestone breach timestamps (set by the SLO alerting job the moment it detects a breach)
    ackBreachedAt: timestamp("ack_breached_at"),
    containBreachedAt: timestamp("contain_breached_at"),
    resolveBreachedAt: timestamp("resolve_breached_at"),
    // timestamp when the first breach-alert notification was dispatched
    slaNotifiedAt: timestamp("sla_notified_at"),
    // SLA clock pause/resume support (e.g. waiting for external party response)
    slaPausedAt: timestamp("sla_paused_at"),
    slaResumedAt: timestamp("sla_resumed_at"),
    // accumulated pause time in minutes; SLA deadline calculators must add this offset
    slaTotalPausedMinutes: integer("sla_total_paused_minutes").notNull().default(0),
    // Mean Time To Resolve in minutes, computed and stored when the incident is resolved/closed
    mttrMinutes: integer("mttr_minutes"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_incidents_org").on(table.orgId),
    index("idx_incidents_status").on(table.status),
    index("idx_incidents_severity").on(table.severity),
    index("idx_incidents_org_created").on(table.orgId, table.createdAt),
    index("idx_incidents_org_status_created").on(table.orgId, table.status, table.createdAt),
    index("idx_incidents_org_severity_created").on(table.orgId, table.severity, table.createdAt),
    index("idx_incidents_assigned").on(table.assignedTo),
    index("idx_incidents_sla_breached").on(table.orgId, table.slaBreached),
  ],
);

export const incidentComments = pgTable(
  "incident_comments",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    incidentId: varchar("incident_id")
      .notNull()
      .references(() => incidents.id),
    userId: varchar("user_id"),
    userName: text("user_name"),
    body: text("body").notNull(),
    isInternal: boolean("is_internal").default(false),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [index("idx_comments_incident").on(table.incidentId)],
);

export const tags = pgTable("tags", {
  id: varchar("id")
    .primaryKey()
    .default(sql`gen_random_uuid()`),
  name: text("name").notNull().unique(),
  color: text("color").default("#6366f1"),
  category: text("category"),
  createdAt: timestamp("created_at").defaultNow(),
});

export const alertTags = pgTable(
  "alert_tags",
  {
    alertId: varchar("alert_id")
      .notNull()
      .references(() => alerts.id, { onDelete: "cascade" }),
    tagId: varchar("tag_id")
      .notNull()
      .references(() => tags.id, { onDelete: "cascade" }),
  },
  (table) => [index("idx_alert_tags_alert").on(table.alertId), index("idx_alert_tags_tag").on(table.tagId)],
);

export const incidentTags = pgTable(
  "incident_tags",
  {
    incidentId: varchar("incident_id")
      .notNull()
      .references(() => incidents.id, { onDelete: "cascade" }),
    tagId: varchar("tag_id")
      .notNull()
      .references(() => tags.id, { onDelete: "cascade" }),
  },
  (table) => [index("idx_incident_tags_incident").on(table.incidentId), index("idx_incident_tags_tag").on(table.tagId)],
);

export const auditLogs = pgTable(
  "audit_logs",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id"),
    userId: varchar("user_id"),
    userName: text("user_name"),
    action: text("action").notNull(),
    resourceType: text("resource_type"),
    resourceId: varchar("resource_id"),
    details: jsonb("details"),
    ipAddress: text("ip_address"),
    userAgent: text("user_agent"),
    impersonatedBy: varchar("impersonated_by"),
    requestId: varchar("request_id"),
    entryHash: text("entry_hash"),
    prevHash: text("prev_hash"),
    sequenceNum: integer("sequence_num"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_audit_logs_org_seq").on(table.orgId, table.sequenceNum),
    index("idx_audit_logs_org_created").on(table.orgId, table.createdAt),
    index("idx_audit_logs_org_action_created").on(table.orgId, table.action, table.createdAt),
    index("idx_audit_logs_org_user_created").on(table.orgId, table.userId, table.createdAt),
    index("idx_audit_logs_org_resource").on(table.orgId, table.resourceType, table.resourceId),
  ],
);

/**
 * Records the results of background tamper-evidence validation jobs.
 *
 * Each run validates a contiguous range of audit_log sequence numbers for
 * an org, re-computing each entry's hash and confirming the hash chain
 * is intact.  Findings are stored so security engineers can review past
 * verifications without re-running them.
 *
 * Triggered by: the scheduled nightly job, a manual admin action, or the
 * system after a suspicious audit-log query.
 */
export const auditVerificationRuns = pgTable(
  "audit_verification_runs",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    // matches AUDIT_VERIFICATION_STATUSES
    status: text("status").notNull().default("running"),
    // inclusive sequence-number range that was validated
    rangeStart: integer("range_start").notNull(),
    rangeEnd: integer("range_end").notNull(),
    recordsChecked: integer("records_checked").notNull().default(0),
    // true = every hash in the range matched and no gaps were found
    chainValid: boolean("chain_valid"),
    // sequenceNum of the first hash mismatch, null when chain is valid
    firstBreakAt: integer("first_break_at"),
    // count of records whose recomputed hash did not match entryHash
    tamperedCount: integer("tampered_count").notNull().default(0),
    // jsonb array of { sequenceNum, storedHash, expectedHash } for each tampered record
    tamperedRecords: jsonb("tampered_records"),
    // integer array of sequenceNums that were expected but missing (gaps in the chain)
    missingSequences: integer("missing_sequences").array(),
    // matches AUDIT_VERIFICATION_TRIGGERS
    triggeredBy: text("triggered_by").notNull().default("scheduled"),
    triggeredByUserId: varchar("triggered_by_user_id"),
    triggeredByUserName: text("triggered_by_user_name"),
    // wall-clock time the verification job ran for
    verificationDurationMs: integer("verification_duration_ms"),
    // timestamp when the verification completed (null while still running)
    verifiedAt: timestamp("verified_at"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_audit_verif_org").on(table.orgId),
    index("idx_audit_verif_org_created").on(table.orgId, table.createdAt),
    index("idx_audit_verif_chain_valid").on(table.orgId, table.chainValid),
    index("idx_audit_verif_status").on(table.status),
  ],
);

export const apiKeys = pgTable(
  "api_keys",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").references(() => organizations.id),
    name: text("name").notNull(),
    keyHash: text("key_hash").notNull(),
    keyPrefix: text("key_prefix").notNull(),
    scopes: text("scopes")
      .array()
      .default(sql`ARRAY['ingest']`),
    isActive: boolean("is_active").default(true),
    webhookSecret: text("webhook_secret"),
    lastUsedAt: timestamp("last_used_at"),
    createdBy: varchar("created_by"),
    createdAt: timestamp("created_at").defaultNow(),
    revokedAt: timestamp("revoked_at"),
    deprecatedAt: timestamp("deprecated_at"),
    graceExpiresAt: timestamp("grace_expires_at"),
    replacedByKeyId: varchar("replaced_by_key_id"),
  },
  (table) => [index("idx_api_keys_org").on(table.orgId), index("idx_api_keys_hash").on(table.keyHash)],
);

export const ingestionLogs = pgTable(
  "ingestion_logs",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
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
  },
  (table) => [
    index("idx_ingestion_logs_org").on(table.orgId),
    index("idx_ingestion_logs_source").on(table.source),
    index("idx_ingestion_logs_received").on(table.receivedAt),
    index("idx_ingestion_logs_org_received").on(table.orgId, table.receivedAt),
    index("idx_ingestion_logs_org_status_received").on(table.orgId, table.status, table.receivedAt),
  ],
);

export const connectors = pgTable(
  "connectors",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
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
  },
  (table) => [
    index("idx_connectors_org").on(table.orgId),
    index("idx_connectors_type").on(table.type),
    index("idx_connectors_status").on(table.status),
    index("idx_connectors_org_status").on(table.orgId, table.status),
    index("idx_connectors_org_created").on(table.orgId, table.createdAt),
  ],
);

export const aiFeedback = pgTable(
  "ai_feedback",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id"),
    userId: varchar("user_id"),
    userName: text("user_name"),
    resourceType: text("resource_type").notNull(),
    resourceId: varchar("resource_id"),
    rating: integer("rating").notNull(),
    comment: text("comment"),
    correctionReason: text("correction_reason"),
    correctedSeverity: text("corrected_severity"),
    correctedCategory: text("corrected_category"),
    aiOutput: jsonb("ai_output"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_ai_feedback_org").on(table.orgId),
    index("idx_ai_feedback_resource").on(table.resourceType, table.resourceId),
    index("idx_ai_feedback_created").on(table.createdAt),
  ],
);

export const playbooks = pgTable(
  "playbooks",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
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
  },
  (table) => [
    index("idx_playbooks_org").on(table.orgId),
    index("idx_playbooks_status").on(table.status),
    index("idx_playbooks_trigger").on(table.trigger),
  ],
);

export const playbookExecutions = pgTable(
  "playbook_executions",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    playbookId: varchar("playbook_id")
      .notNull()
      .references(() => playbooks.id),
    triggeredBy: text("triggered_by"),
    triggerEvent: text("trigger_event"),
    resourceType: text("resource_type"),
    resourceId: varchar("resource_id"),
    status: text("status").notNull().default("running"),
    dryRun: boolean("dry_run").default(false),
    actionsExecuted: jsonb("actions_executed"),
    result: jsonb("result"),
    errorMessage: text("error_message"),
    executionTimeMs: integer("execution_time_ms"),
    pausedAtNodeId: varchar("paused_at_node_id"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_playbook_executions_playbook").on(table.playbookId),
    index("idx_playbook_executions_status").on(table.status),
    index("idx_playbook_executions_created").on(table.createdAt),
  ],
);

export const APPROVAL_STATUSES = ["pending", "approved", "rejected", "expired"] as const;

export const playbookApprovals = pgTable(
  "playbook_approvals",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    executionId: varchar("execution_id")
      .notNull()
      .references(() => playbookExecutions.id),
    playbookId: varchar("playbook_id")
      .notNull()
      .references(() => playbooks.id),
    nodeId: varchar("node_id").notNull(),
    status: text("status").notNull().default("pending"),
    requestedBy: text("requested_by"),
    approverRole: text("approver_role"),
    approvalMessage: text("approval_message"),
    decidedBy: text("decided_by"),
    decisionNote: text("decision_note"),
    requestedAt: timestamp("requested_at").defaultNow(),
    decidedAt: timestamp("decided_at"),
  },
  (table) => [
    index("idx_playbook_approvals_execution").on(table.executionId),
    index("idx_playbook_approvals_status").on(table.status),
  ],
);

export const entities = pgTable(
  "entities",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
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
  },
  (table) => [
    index("idx_entities_org").on(table.orgId),
    index("idx_entities_type").on(table.type),
    index("idx_entities_value").on(table.value),
    uniqueIndex("idx_entities_org_type_value").on(table.orgId, table.type, table.value),
  ],
);

export const entityAliases = pgTable(
  "entity_aliases",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    entityId: varchar("entity_id")
      .notNull()
      .references(() => entities.id, { onDelete: "cascade" }),
    aliasType: text("alias_type").notNull(),
    aliasValue: text("alias_value").notNull(),
    source: text("source"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_entity_aliases_entity").on(table.entityId),
    index("idx_entity_aliases_value").on(table.aliasValue),
  ],
);

export const entityMergeHistory = pgTable(
  "entity_merge_history",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").references(() => organizations.id),
    targetEntityId: varchar("target_entity_id").notNull(),
    sourceEntityId: varchar("source_entity_id").notNull(),
    sourceEntitySnapshot: jsonb("source_entity_snapshot").notNull(),
    targetEntitySnapshot: jsonb("target_entity_snapshot").notNull(),
    movedAlertIds: text("moved_alert_ids").array(),
    movedAliasIds: text("moved_alias_ids").array(),
    mergedBy: varchar("merged_by"),
    undone: boolean("undone").default(false),
    undoneAt: timestamp("undone_at"),
    undoneBy: varchar("undone_by"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_entity_merge_history_org").on(table.orgId),
    index("idx_entity_merge_history_target").on(table.targetEntityId),
    index("idx_entity_merge_history_source").on(table.sourceEntityId),
  ],
);

export const alertEntities = pgTable(
  "alert_entities",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    alertId: varchar("alert_id")
      .notNull()
      .references(() => alerts.id, { onDelete: "cascade" }),
    entityId: varchar("entity_id")
      .notNull()
      .references(() => entities.id, { onDelete: "cascade" }),
    role: text("role").notNull(),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_alert_entities_alert").on(table.alertId),
    index("idx_alert_entities_entity").on(table.entityId),
  ],
);

export const correlationClusters = pgTable(
  "correlation_clusters",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
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
  },
  (table) => [
    index("idx_correlation_clusters_org").on(table.orgId),
    index("idx_correlation_clusters_incident").on(table.incidentId),
    index("idx_correlation_clusters_status").on(table.status),
  ],
);

export const attackPaths = pgTable(
  "attack_paths",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
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
  },
  (table) => [
    index("idx_attack_paths_org").on(table.orgId),
    index("idx_attack_paths_cluster").on(table.clusterId),
    index("idx_attack_paths_campaign").on(table.campaignId),
  ],
);

export const campaigns = pgTable(
  "campaigns",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
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
  },
  (table) => [
    index("idx_campaigns_org").on(table.orgId),
    index("idx_campaigns_fingerprint").on(table.fingerprint),
    index("idx_campaigns_status").on(table.status),
  ],
);

export const COMPLIANCE_FRAMEWORKS = [
  "gdpr",
  "dpdp",
  "hipaa",
  "sox",
  "pci_dss",
  "iso27001",
  "nist",
  "soc2",
  "nis2",
  "dora",
  "cbest",
  "mas_trm",
  "ifsca",
  "pdpa",
  "popia",
  "lgpd",
  "pipeda",
  "asd_essential8",
  "ccpa",
  "cmmc",
  "nerc_cip",
  "swift_csp",
  "iec_62443",
] as const;
export const DSAR_STATUSES = ["pending", "in_progress", "fulfilled", "rejected", "expired"] as const;

export const compliancePolicies = pgTable(
  "compliance_policies",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").references(() => organizations.id),
    alertRetentionDays: integer("alert_retention_days").default(365),
    incidentRetentionDays: integer("incident_retention_days").default(730),
    auditLogRetentionDays: integer("audit_log_retention_days").default(2555),
    piiMaskingEnabled: boolean("pii_masking_enabled").default(false),
    pseudonymizeExports: boolean("pseudonymize_exports").default(true),
    enabledFrameworks: text("enabled_frameworks")
      .array()
      .default(sql`ARRAY['gdpr']`),
    dataProcessingBasis: text("data_processing_basis").default("legitimate_interest"),
    dpoEmail: text("dpo_email"),
    dsarSlaDays: integer("dsar_sla_days").default(30),
    retentionLastRunAt: timestamp("retention_last_run_at"),
    retentionLastDeletedCount: integer("retention_last_deleted_count").default(0),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [uniqueIndex("idx_compliance_policies_org").on(table.orgId)],
);

export const dsarRequests = pgTable(
  "dsar_requests",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
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
  },
  (table) => [
    index("idx_dsar_requests_org").on(table.orgId),
    index("idx_dsar_requests_status").on(table.status),
    index("idx_dsar_requests_due").on(table.dueDate),
  ],
);

export const threatIntelConfigs = pgTable(
  "threat_intel_configs",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").references(() => organizations.id),
    provider: text("provider").notNull(),
    apiKey: text("api_key"),
    enabled: boolean("enabled").default(true),
    lastTestedAt: timestamp("last_tested_at"),
    lastTestStatus: text("last_test_status"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_threat_intel_configs_org").on(table.orgId),
    uniqueIndex("idx_threat_intel_configs_org_provider").on(table.orgId, table.provider),
  ],
);

export const integrationConfigs = pgTable(
  "integration_configs",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
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
  },
  (table) => [
    index("idx_integration_configs_org").on(table.orgId),
    index("idx_integration_configs_type").on(table.type),
  ],
);

export const notificationChannels = pgTable(
  "notification_channels",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").references(() => organizations.id),
    name: text("name").notNull(),
    type: text("type").notNull(),
    config: jsonb("config").notNull(),
    isDefault: boolean("is_default").default(false),
    events: text("events")
      .array()
      .default(sql`ARRAY['incident_created']`),
    status: text("status").notNull().default("active"),
    lastNotifiedAt: timestamp("last_notified_at"),
    createdBy: varchar("created_by"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_notification_channels_org").on(table.orgId),
    index("idx_notification_channels_type").on(table.type),
  ],
);

export const notificationUserPreferences = pgTable(
  "notification_user_preferences",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    userId: varchar("user_id").notNull(),
    orgId: varchar("org_id").references(() => organizations.id),
    channelIds: text("channel_ids")
      .array()
      .default(sql`ARRAY[]::text[]`),
    eventTypes: text("event_types")
      .array()
      .default(sql`ARRAY['incident_created']`),
    minSeverity: text("min_severity").default("info"),
    quietHoursStart: integer("quiet_hours_start"),
    quietHoursEnd: integer("quiet_hours_end"),
    digestEnabled: boolean("digest_enabled").default(false),
    digestFrequencyHours: integer("digest_frequency_hours").default(24),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_notification_user_prefs_user").on(table.userId),
    index("idx_notification_user_prefs_org").on(table.orgId),
    uniqueIndex("idx_notification_user_prefs_user_org").on(table.userId, table.orgId),
  ],
);

export const notificationDeliveryLog = pgTable(
  "notification_delivery_log",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    channelId: varchar("channel_id").notNull(),
    channelName: text("channel_name").notNull(),
    channelType: text("channel_type").notNull(),
    orgId: varchar("org_id").references(() => organizations.id),
    eventType: text("event_type").notNull(),
    title: text("title").notNull(),
    severity: text("severity").notNull(),
    success: boolean("success").notNull(),
    errorMessage: text("error_message"),
    deliveredAt: timestamp("delivered_at").defaultNow(),
    metadata: jsonb("metadata"),
  },
  (table) => [
    index("idx_notification_delivery_log_channel").on(table.channelId),
    index("idx_notification_delivery_log_org_delivered").on(table.orgId, table.deliveredAt),
    index("idx_notification_delivery_log_delivered").on(table.deliveredAt),
  ],
);

export const responseActions = pgTable(
  "response_actions",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
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
  },
  (table) => [
    index("idx_response_actions_org").on(table.orgId),
    index("idx_response_actions_incident").on(table.incidentId),
    index("idx_response_actions_status").on(table.status),
    index("idx_response_actions_type").on(table.actionType),
    index("idx_response_actions_org_created").on(table.orgId, table.createdAt),
    index("idx_response_actions_org_status_created").on(table.orgId, table.status, table.createdAt),
  ],
);

export const predictiveAnomalies = pgTable("predictive_anomalies", {
  id: varchar("id")
    .primaryKey()
    .default(sql`gen_random_uuid()`),
  orgId: varchar("org_id").references(() => organizations.id),
  kind: text("kind").notNull(),
  metric: text("metric").notNull(),
  baseline: real("baseline").notNull(),
  current: real("current").notNull(),
  zScore: real("z_score").notNull(),
  severity: text("severity").notNull().default("medium"),
  windowStart: timestamp("window_start").notNull(),
  windowEnd: timestamp("window_end").notNull(),
  topSignals: jsonb("top_signals"),
  description: text("description"),
  createdAt: timestamp("created_at").defaultNow(),
});

export const attackSurfaceAssets = pgTable("attack_surface_assets", {
  id: varchar("id")
    .primaryKey()
    .default(sql`gen_random_uuid()`),
  orgId: varchar("org_id").references(() => organizations.id),
  entityType: text("entity_type").notNull(),
  entityValue: text("entity_value").notNull(),
  firstSeenAt: timestamp("first_seen_at").notNull(),
  lastSeenAt: timestamp("last_seen_at").notNull(),
  riskScore: real("risk_score").notNull().default(0),
  alertCount: integer("alert_count").notNull().default(0),
  criticalCount: integer("critical_count").notNull().default(0),
  exposures: jsonb("exposures"),
  relatedSources: text("related_sources").array(),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export const riskForecasts = pgTable("risk_forecasts", {
  id: varchar("id")
    .primaryKey()
    .default(sql`gen_random_uuid()`),
  orgId: varchar("org_id").references(() => organizations.id),
  forecastType: text("forecast_type").notNull(),
  probability: real("probability").notNull(),
  predictedWindowHours: integer("predicted_window_hours").notNull(),
  confidence: real("confidence").notNull().default(0),
  drivers: jsonb("drivers"),
  description: text("description"),
  status: text("status").notNull().default("active"),
  createdAt: timestamp("created_at").defaultNow(),
});

export const anomalySubscriptions = pgTable("anomaly_subscriptions", {
  id: varchar("id")
    .primaryKey()
    .default(sql`gen_random_uuid()`),
  orgId: varchar("org_id").references(() => organizations.id),
  name: text("name").notNull(),
  metricPrefix: text("metric_prefix").default(""),
  minimumSeverity: text("minimum_severity").notNull().default("medium"),
  minDelta: real("min_delta").notNull().default(10),
  channel: text("channel").notNull().default("in_app"),
  target: text("target"),
  status: text("status").notNull().default("active"),
  createdBy: varchar("created_by"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export const forecastQualitySnapshots = pgTable("forecast_quality_snapshots", {
  id: varchar("id")
    .primaryKey()
    .default(sql`gen_random_uuid()`),
  orgId: varchar("org_id").references(() => organizations.id),
  module: text("module").notNull(),
  precision: real("precision").notNull().default(0),
  recall: real("recall").notNull().default(0),
  sampleSize: integer("sample_size").notNull().default(0),
  measuredAt: timestamp("measured_at").defaultNow(),
});

export const hardeningRecommendations = pgTable("hardening_recommendations", {
  id: varchar("id")
    .primaryKey()
    .default(sql`gen_random_uuid()`),
  orgId: varchar("org_id").references(() => organizations.id),
  title: text("title").notNull(),
  rationale: text("rationale").notNull(),
  priority: text("priority").notNull().default("medium"),
  category: text("category"),
  relatedEntities: jsonb("related_entities"),
  relatedForecasts: jsonb("related_forecasts"),
  status: text("status").notNull().default("open"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export const autoResponsePolicies = pgTable("auto_response_policies", {
  id: varchar("id")
    .primaryKey()
    .default(sql`gen_random_uuid()`),
  orgId: varchar("org_id").references(() => organizations.id),
  name: text("name").notNull(),
  description: text("description"),
  triggerType: text("trigger_type").notNull(),
  conditions: jsonb("conditions").notNull(),
  actions: jsonb("actions").notNull(),
  confidenceThreshold: real("confidence_threshold").notNull().default(0.85),
  severityFilter: text("severity_filter").array(),
  requiresApproval: boolean("requires_approval").default(true),
  maxActionsPerHour: integer("max_actions_per_hour").default(10),
  cooldownMinutes: integer("cooldown_minutes").default(30),
  status: text("status").notNull().default("inactive"),
  executionCount: integer("execution_count").default(0),
  lastTriggeredAt: timestamp("last_triggered_at"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export const investigationRuns = pgTable("investigation_runs", {
  id: varchar("id")
    .primaryKey()
    .default(sql`gen_random_uuid()`),
  orgId: varchar("org_id").references(() => organizations.id),
  incidentId: varchar("incident_id").references(() => incidents.id),
  triggeredBy: text("triggered_by").notNull(),
  triggerSource: text("trigger_source").default("manual"),
  status: text("status").notNull().default("queued"),
  summary: text("summary"),
  findings: jsonb("findings"),
  recommendedActions: jsonb("recommended_actions"),
  evidenceCount: integer("evidence_count").default(0),
  confidenceScore: real("confidence_score"),
  duration: integer("duration"),
  error: text("error"),
  createdAt: timestamp("created_at").defaultNow(),
  completedAt: timestamp("completed_at"),
});

export const investigationSteps = pgTable("investigation_steps", {
  id: varchar("id")
    .primaryKey()
    .default(sql`gen_random_uuid()`),
  runId: varchar("run_id")
    .notNull()
    .references(() => investigationRuns.id),
  stepType: text("step_type").notNull(),
  stepOrder: integer("step_order").notNull(),
  title: text("title").notNull(),
  description: text("description"),
  status: text("status").notNull().default("pending"),
  result: jsonb("result"),
  artifacts: jsonb("artifacts"),
  duration: integer("duration"),
  createdAt: timestamp("created_at").defaultNow(),
});

export const responseActionRollbacks = pgTable("response_action_rollbacks", {
  id: varchar("id")
    .primaryKey()
    .default(sql`gen_random_uuid()`),
  orgId: varchar("org_id").references(() => organizations.id),
  originalActionId: varchar("original_action_id"),
  actionType: text("action_type").notNull(),
  target: text("target").notNull(),
  rollbackAction: jsonb("rollback_action").notNull(),
  status: text("status").notNull().default("pending"),
  executedBy: text("executed_by"),
  result: jsonb("result"),
  error: text("error"),
  createdAt: timestamp("created_at").defaultNow(),
  executedAt: timestamp("executed_at"),
});

// ==========================================
// 8.2 — Incident Response Lifecycle
// ==========================================

export const EVIDENCE_CHAIN_ENTRY_TYPES = [
  "evidence_added",
  "evidence_removed",
  "status_change",
  "assignment_change",
  "escalation",
  "containment",
  "approval_requested",
  "approval_granted",
  "approval_denied",
  "response_action",
  "comment",
  "attachment",
  "external_update",
] as const;

export const RESPONSE_APPROVAL_STATUSES = ["pending", "approved", "rejected", "expired", "bypassed"] as const;

export const PIR_STATUSES = ["draft", "in_review", "published", "archived"] as const;

export const evidenceChainEntries = pgTable(
  "evidence_chain_entries",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").references(() => organizations.id),
    incidentId: varchar("incident_id")
      .notNull()
      .references(() => incidents.id),
    sequenceNum: integer("sequence_num").notNull(),
    entryType: text("entry_type").notNull(),
    actorId: varchar("actor_id"),
    actorName: text("actor_name"),
    summary: text("summary").notNull(),
    details: jsonb("details"),
    relatedResourceType: text("related_resource_type"),
    relatedResourceId: varchar("related_resource_id"),
    entryHash: text("entry_hash").notNull(),
    previousHash: text("previous_hash"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_evidence_chain_incident").on(table.incidentId),
    index("idx_evidence_chain_org").on(table.orgId),
    uniqueIndex("uq_evidence_chain_incident_seq").on(table.incidentId, table.sequenceNum),
    index("idx_evidence_chain_type").on(table.entryType),
  ],
);

export const incidentResponseApprovals = pgTable(
  "incident_response_approvals",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").references(() => organizations.id),
    incidentId: varchar("incident_id")
      .notNull()
      .references(() => incidents.id),
    actionType: text("action_type").notNull(),
    actionDescription: text("action_description").notNull(),
    actionPayload: jsonb("action_payload"),
    status: text("status").notNull().default("pending"),
    requestedBy: varchar("requested_by"),
    requestedByName: text("requested_by_name"),
    requiredApproverRole: text("required_approver_role").notNull().default("admin"),
    decidedBy: varchar("decided_by"),
    decidedByName: text("decided_by_name"),
    decisionNote: text("decision_note"),
    expiresAt: timestamp("expires_at"),
    requestedAt: timestamp("requested_at").defaultNow(),
    decidedAt: timestamp("decided_at"),
  },
  (table) => [
    index("idx_ir_approvals_incident").on(table.incidentId),
    index("idx_ir_approvals_org").on(table.orgId),
    index("idx_ir_approvals_status").on(table.status),
    index("idx_ir_approvals_org_status").on(table.orgId, table.status),
  ],
);

export const postIncidentReviews = pgTable(
  "post_incident_reviews",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").references(() => organizations.id),
    incidentId: varchar("incident_id")
      .notNull()
      .references(() => incidents.id),
    status: text("status").notNull().default("draft"),
    title: text("title").notNull(),
    summary: text("summary"),
    timelineJson: jsonb("timeline_json"),
    rootCauseAnalysis: text("root_cause_analysis"),
    impactAssessment: text("impact_assessment"),
    lessonsLearned: jsonb("lessons_learned"),
    actionItems: jsonb("action_items"),
    participants: text("participants").array(),
    reviewDate: timestamp("review_date"),
    leadReviewer: varchar("lead_reviewer"),
    leadReviewerName: text("lead_reviewer_name"),
    createdBy: varchar("created_by"),
    createdByName: text("created_by_name"),
    publishedAt: timestamp("published_at"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_pir_incident").on(table.incidentId),
    index("idx_pir_org").on(table.orgId),
    index("idx_pir_status").on(table.status),
    index("idx_pir_org_created").on(table.orgId, table.createdAt),
  ],
);

export const pirActionItems = pgTable(
  "pir_action_items",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    reviewId: varchar("review_id")
      .notNull()
      .references(() => postIncidentReviews.id),
    orgId: varchar("org_id").references(() => organizations.id),
    title: text("title").notNull(),
    description: text("description"),
    assigneeId: varchar("assignee_id"),
    assigneeName: text("assignee_name"),
    priority: text("priority").notNull().default("medium"),
    status: text("status").notNull().default("open"),
    dueDate: timestamp("due_date"),
    completedAt: timestamp("completed_at"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_pir_action_items_review").on(table.reviewId),
    index("idx_pir_action_items_org").on(table.orgId),
    index("idx_pir_action_items_status").on(table.status),
  ],
);

// ==========================================
// 8.3 — Playbook Governance
// ==========================================

export const PLAYBOOK_VERSION_STATUSES = ["draft", "active", "deprecated", "archived"] as const;
export const SIMULATION_STATUSES = ["pending", "running", "completed", "failed"] as const;

export const playbookVersions = pgTable(
  "playbook_versions",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    playbookId: varchar("playbook_id")
      .notNull()
      .references(() => playbooks.id),
    orgId: varchar("org_id").references(() => organizations.id),
    version: integer("version").notNull(),
    status: text("status").notNull().default("draft"),
    actions: jsonb("actions").notNull(),
    conditions: jsonb("conditions"),
    changeDescription: text("change_description"),
    approvalRequired: boolean("approval_required").default(false),
    approvedBy: varchar("approved_by"),
    approvedByName: text("approved_by_name"),
    approvedAt: timestamp("approved_at"),
    rollbackToVersion: integer("rollback_to_version"),
    createdBy: varchar("created_by"),
    createdByName: text("created_by_name"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_pb_versions_playbook").on(table.playbookId),
    index("idx_pb_versions_org").on(table.orgId),
    index("idx_pb_versions_status").on(table.status),
    index("idx_pb_versions_playbook_version").on(table.playbookId, table.version),
  ],
);

export const blastRadiusPreviews = pgTable(
  "blast_radius_previews",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").references(() => organizations.id),
    playbookId: varchar("playbook_id")
      .notNull()
      .references(() => playbooks.id),
    executionContext: jsonb("execution_context"),
    affectedEntities: jsonb("affected_entities"),
    affectedEntityCount: integer("affected_entity_count").notNull().default(0),
    riskLevel: text("risk_level").notNull().default("low"),
    riskFactors: jsonb("risk_factors"),
    estimatedDurationMs: integer("estimated_duration_ms"),
    rollbackPlan: jsonb("rollback_plan"),
    reversible: boolean("reversible").default(true),
    previewedBy: varchar("previewed_by"),
    previewedByName: text("previewed_by_name"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_blast_radius_playbook").on(table.playbookId),
    index("idx_blast_radius_org").on(table.orgId),
    index("idx_blast_radius_risk").on(table.riskLevel),
  ],
);

export const playbookSimulations = pgTable(
  "playbook_simulations",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").references(() => organizations.id),
    playbookId: varchar("playbook_id")
      .notNull()
      .references(() => playbooks.id),
    executionId: varchar("execution_id").references(() => playbookExecutions.id),
    status: text("status").notNull().default("pending"),
    simulatedActions: jsonb("simulated_actions"),
    impactAnalysis: jsonb("impact_analysis"),
    predictedOutcome: text("predicted_outcome"),
    riskScore: real("risk_score"),
    warnings: jsonb("warnings"),
    simulatedBy: varchar("simulated_by"),
    simulatedByName: text("simulated_by_name"),
    durationMs: integer("duration_ms"),
    createdAt: timestamp("created_at").defaultNow(),
    completedAt: timestamp("completed_at"),
  },
  (table) => [
    index("idx_pb_simulations_playbook").on(table.playbookId),
    index("idx_pb_simulations_org").on(table.orgId),
    index("idx_pb_simulations_status").on(table.status),
  ],
);

export const playbookRollbackPlans = pgTable(
  "playbook_rollback_plans",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").references(() => organizations.id),
    playbookId: varchar("playbook_id")
      .notNull()
      .references(() => playbooks.id),
    executionId: varchar("execution_id").references(() => playbookExecutions.id),
    rollbackSteps: jsonb("rollback_steps").notNull(),
    status: text("status").notNull().default("ready"),
    autoRollbackEnabled: boolean("auto_rollback_enabled").default(false),
    triggerConditions: jsonb("trigger_conditions"),
    executedAt: timestamp("executed_at"),
    executedBy: varchar("executed_by"),
    executedByName: text("executed_by_name"),
    result: jsonb("result"),
    error: text("error"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_pb_rollback_playbook").on(table.playbookId),
    index("idx_pb_rollback_execution").on(table.executionId),
    index("idx_pb_rollback_org").on(table.orgId),
    index("idx_pb_rollback_status").on(table.status),
  ],
);

// ==========================================
// 9.0 — Attack Graph Persistence (AI Deep Investigation)
// ==========================================

export const ATTACK_GRAPH_NODE_TYPES = [
  "initial_access",
  "host",
  "user",
  "process",
  "file",
  "network",
  "credential",
  "persistence",
  "lateral_movement",
  "exfiltration",
  "c2",
  "objective",
] as const;

export const attackGraphs = pgTable(
  "attack_graphs",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").references(() => organizations.id),
    incidentId: varchar("incident_id")
      .notNull()
      .references(() => incidents.id),
    investigationId: varchar("investigation_id"),
    initialAccessDescription: text("initial_access_description"),
    currentPosition: text("current_position"),
    objectivesAchieved: text("objectives_achieved")
      .array()
      .default(sql`ARRAY[]::text[]`),
    objectivesInProgress: text("objectives_in_progress")
      .array()
      .default(sql`ARRAY[]::text[]`),
    totalNodes: integer("total_nodes").default(0),
    totalEdges: integer("total_edges").default(0),
    maxDepth: integer("max_depth").default(0),
    confidence: real("confidence").default(0),
    metadata: jsonb("metadata"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_attack_graphs_org").on(table.orgId),
    index("idx_attack_graphs_incident").on(table.incidentId),
    index("idx_attack_graphs_created").on(table.createdAt),
  ],
);

export const attackGraphNodes = pgTable(
  "attack_graph_nodes",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    graphId: varchar("graph_id")
      .notNull()
      .references(() => attackGraphs.id, { onDelete: "cascade" }),
    nodeId: text("node_id").notNull(),
    nodeType: text("node_type").notNull(),
    label: text("label").notNull(),
    description: text("description"),
    mitreTechnique: text("mitre_technique"),
    mitreTactic: text("mitre_tactic"),
    confidence: real("confidence").default(0),
    severity: text("severity"),
    evidence: text("evidence")
      .array()
      .default(sql`ARRAY[]::text[]`),
    metadata: jsonb("metadata"),
    positionX: real("position_x"),
    positionY: real("position_y"),
    depth: integer("depth").default(0),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_agn_graph").on(table.graphId),
    index("idx_agn_type").on(table.nodeType),
    index("idx_agn_mitre").on(table.mitreTechnique),
  ],
);

export const attackGraphEdges = pgTable(
  "attack_graph_edges",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    graphId: varchar("graph_id")
      .notNull()
      .references(() => attackGraphs.id, { onDelete: "cascade" }),
    sourceNodeId: text("source_node_id").notNull(),
    targetNodeId: text("target_node_id").notNull(),
    relationship: text("relationship").notNull(),
    technique: text("technique"),
    confidence: real("confidence").default(0),
    timestamp: text("timestamp"),
    evidence: text("evidence")
      .array()
      .default(sql`ARRAY[]::text[]`),
    metadata: jsonb("metadata"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_age_graph").on(table.graphId),
    index("idx_age_source").on(table.sourceNodeId),
    index("idx_age_target").on(table.targetNodeId),
  ],
);

export const attackGraphsRelations = relations(attackGraphs, ({ one, many }) => ({
  organization: one(organizations, { fields: [attackGraphs.orgId], references: [organizations.id] }),
  incident: one(incidents, { fields: [attackGraphs.incidentId], references: [incidents.id] }),
  nodes: many(attackGraphNodes),
  edges: many(attackGraphEdges),
}));

export const attackGraphNodesRelations = relations(attackGraphNodes, ({ one }) => ({
  graph: one(attackGraphs, { fields: [attackGraphNodes.graphId], references: [attackGraphs.id] }),
}));

export const attackGraphEdgesRelations = relations(attackGraphEdges, ({ one }) => ({
  graph: one(attackGraphs, { fields: [attackGraphEdges.graphId], references: [attackGraphs.id] }),
}));

export const WIZARD_STEPS = ["choose_plan", "invite_team", "connect_integration", "dashboard_tour"] as const;

export const wizardProgress = pgTable(
  "wizard_progress",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").references(() => organizations.id),
    userId: varchar("user_id").notNull(),
    currentStep: integer("current_step").notNull().default(0),
    completedSteps: jsonb("completed_steps")
      .notNull()
      .default(sql`'[]'::jsonb`),
    skippedSteps: jsonb("skipped_steps")
      .notNull()
      .default(sql`'[]'::jsonb`),
    completedAt: timestamp("completed_at"),
    tourCompletedAt: timestamp("tour_completed_at"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_wizard_progress_org").on(table.orgId),
    index("idx_wizard_progress_user").on(table.userId),
    uniqueIndex("idx_wizard_progress_user_unique").on(table.userId),
  ],
);

// Relations
export const connectorsRelations = relations(connectors, ({ one }) => ({
  organization: one(organizations, { fields: [connectors.orgId], references: [organizations.id] }),
}));

export const aiFeedbackRelations = relations(aiFeedback, ({ one }) => ({}));

export const playbooksRelations = relations(playbooks, ({ one, many }) => ({
  executions: many(playbookExecutions),
}));

export const playbookExecutionsRelations = relations(playbookExecutions, ({ one, many }) => ({
  playbook: one(playbooks, { fields: [playbookExecutions.playbookId], references: [playbooks.id] }),
  approvals: many(playbookApprovals),
}));

export const playbookApprovalsRelations = relations(playbookApprovals, ({ one }) => ({
  execution: one(playbookExecutions, { fields: [playbookApprovals.executionId], references: [playbookExecutions.id] }),
  playbook: one(playbooks, { fields: [playbookApprovals.playbookId], references: [playbooks.id] }),
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

export const notificationUserPreferencesRelations = relations(notificationUserPreferences, ({ one }) => ({
  organization: one(organizations, { fields: [notificationUserPreferences.orgId], references: [organizations.id] }),
}));

export const notificationDeliveryLogRelations = relations(notificationDeliveryLog, ({ one }) => ({
  organization: one(organizations, { fields: [notificationDeliveryLog.orgId], references: [organizations.id] }),
}));

export const responseActionsRelations = relations(responseActions, ({ one }) => ({
  organization: one(organizations, { fields: [responseActions.orgId], references: [organizations.id] }),
  incident: one(incidents, { fields: [responseActions.incidentId], references: [incidents.id] }),
}));

export const predictiveAnomaliesRelations = relations(predictiveAnomalies, ({ one }) => ({
  organization: one(organizations, { fields: [predictiveAnomalies.orgId], references: [organizations.id] }),
}));

export const attackSurfaceAssetsRelations = relations(attackSurfaceAssets, ({ one }) => ({
  organization: one(organizations, { fields: [attackSurfaceAssets.orgId], references: [organizations.id] }),
}));

export const riskForecastsRelations = relations(riskForecasts, ({ one }) => ({
  organization: one(organizations, { fields: [riskForecasts.orgId], references: [organizations.id] }),
}));

export const anomalySubscriptionsRelations = relations(anomalySubscriptions, ({ one }) => ({
  organization: one(organizations, { fields: [anomalySubscriptions.orgId], references: [organizations.id] }),
}));

export const forecastQualitySnapshotsRelations = relations(forecastQualitySnapshots, ({ one }) => ({
  organization: one(organizations, { fields: [forecastQualitySnapshots.orgId], references: [organizations.id] }),
}));

export const hardeningRecommendationsRelations = relations(hardeningRecommendations, ({ one }) => ({
  organization: one(organizations, { fields: [hardeningRecommendations.orgId], references: [organizations.id] }),
}));

export const evidenceChainEntriesRelations = relations(evidenceChainEntries, ({ one }) => ({
  organization: one(organizations, { fields: [evidenceChainEntries.orgId], references: [organizations.id] }),
  incident: one(incidents, { fields: [evidenceChainEntries.incidentId], references: [incidents.id] }),
}));

export const incidentResponseApprovalsRelations = relations(incidentResponseApprovals, ({ one }) => ({
  organization: one(organizations, { fields: [incidentResponseApprovals.orgId], references: [organizations.id] }),
  incident: one(incidents, { fields: [incidentResponseApprovals.incidentId], references: [incidents.id] }),
}));

export const postIncidentReviewsRelations = relations(postIncidentReviews, ({ one, many }) => ({
  organization: one(organizations, { fields: [postIncidentReviews.orgId], references: [organizations.id] }),
  incident: one(incidents, { fields: [postIncidentReviews.incidentId], references: [incidents.id] }),
  actionItemsList: many(pirActionItems),
}));

export const pirActionItemsRelations = relations(pirActionItems, ({ one }) => ({
  review: one(postIncidentReviews, { fields: [pirActionItems.reviewId], references: [postIncidentReviews.id] }),
  organization: one(organizations, { fields: [pirActionItems.orgId], references: [organizations.id] }),
}));

export const playbookVersionsRelations = relations(playbookVersions, ({ one }) => ({
  playbook: one(playbooks, { fields: [playbookVersions.playbookId], references: [playbooks.id] }),
  organization: one(organizations, { fields: [playbookVersions.orgId], references: [organizations.id] }),
}));

export const blastRadiusPreviewsRelations = relations(blastRadiusPreviews, ({ one }) => ({
  playbook: one(playbooks, { fields: [blastRadiusPreviews.playbookId], references: [playbooks.id] }),
  organization: one(organizations, { fields: [blastRadiusPreviews.orgId], references: [organizations.id] }),
}));

export const playbookSimulationsRelations = relations(playbookSimulations, ({ one }) => ({
  playbook: one(playbooks, { fields: [playbookSimulations.playbookId], references: [playbooks.id] }),
  organization: one(organizations, { fields: [playbookSimulations.orgId], references: [organizations.id] }),
  execution: one(playbookExecutions, {
    fields: [playbookSimulations.executionId],
    references: [playbookExecutions.id],
  }),
}));

export const playbookRollbackPlansRelations = relations(playbookRollbackPlans, ({ one }) => ({
  playbook: one(playbooks, { fields: [playbookRollbackPlans.playbookId], references: [playbooks.id] }),
  organization: one(organizations, { fields: [playbookRollbackPlans.orgId], references: [organizations.id] }),
  execution: one(playbookExecutions, {
    fields: [playbookRollbackPlans.executionId],
    references: [playbookExecutions.id],
  }),
}));

// Insert schemas
export const insertAlertSchema = createInsertSchema(alerts).omit({ id: true, createdAt: true, ingestedAt: true });
export const insertIncidentSchema = createInsertSchema(incidents).omit({ id: true, createdAt: true, updatedAt: true });
export const insertOrgSchema = createInsertSchema(organizations).omit({ id: true, createdAt: true });
export const insertCommentSchema = createInsertSchema(incidentComments).omit({ id: true, createdAt: true });
export const insertTagSchema = createInsertSchema(tags).omit({ id: true, createdAt: true });
export const insertApiKeySchema = createInsertSchema(apiKeys).omit({
  id: true,
  createdAt: true,
  lastUsedAt: true,
  revokedAt: true,
  deprecatedAt: true,
  graceExpiresAt: true,
  replacedByKeyId: true,
});
export const insertIngestionLogSchema = createInsertSchema(ingestionLogs).omit({ id: true, receivedAt: true });
export const insertConnectorSchema = createInsertSchema(connectors).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
  lastSyncAt: true,
  lastSyncStatus: true,
  lastSyncAlerts: true,
  lastSyncError: true,
  totalAlertsSynced: true,
});
export const insertAiFeedbackSchema = createInsertSchema(aiFeedback).omit({ id: true, createdAt: true });
export const insertPlaybookSchema = createInsertSchema(playbooks).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
  lastTriggeredAt: true,
});
export const insertPlaybookExecutionSchema = createInsertSchema(playbookExecutions).omit({ id: true, createdAt: true });
export const insertEntitySchema = createInsertSchema(entities).omit({
  id: true,
  createdAt: true,
  firstSeenAt: true,
  lastSeenAt: true,
});
export const insertEntityAliasSchema = createInsertSchema(entityAliases).omit({ id: true, createdAt: true });
export const insertEntityMergeHistorySchema = createInsertSchema(entityMergeHistory).omit({
  id: true,
  createdAt: true,
  undone: true,
  undoneAt: true,
  undoneBy: true,
});
export const insertAlertEntitySchema = createInsertSchema(alertEntities).omit({ id: true, createdAt: true });
export const insertCorrelationClusterSchema = createInsertSchema(correlationClusters).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});
export const insertAttackPathSchema = createInsertSchema(attackPaths).omit({ id: true, createdAt: true });
export const insertCampaignSchema = createInsertSchema(campaigns).omit({ id: true, createdAt: true, updatedAt: true });
export const insertThreatIntelConfigSchema = createInsertSchema(threatIntelConfigs).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
  lastTestedAt: true,
  lastTestStatus: true,
});
export const insertCompliancePolicySchema = createInsertSchema(compliancePolicies).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
  retentionLastRunAt: true,
  retentionLastDeletedCount: true,
});
export const insertDsarRequestSchema = createInsertSchema(dsarRequests).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
  fulfilledAt: true,
  fulfilledBy: true,
  resultSummary: true,
});
export const insertIntegrationConfigSchema = createInsertSchema(integrationConfigs).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
  lastTestedAt: true,
  lastTestStatus: true,
});
export const insertNotificationChannelSchema = createInsertSchema(notificationChannels).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
  lastNotifiedAt: true,
});
export const insertNotificationUserPreferencesSchema = createInsertSchema(notificationUserPreferences).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});
export const insertNotificationDeliveryLogSchema = createInsertSchema(notificationDeliveryLog).omit({
  id: true,
  deliveredAt: true,
});
export const insertResponseActionSchema = createInsertSchema(responseActions).omit({
  id: true,
  createdAt: true,
  executedAt: true,
});
export const insertPredictiveAnomalySchema = createInsertSchema(predictiveAnomalies).omit({
  id: true,
  createdAt: true,
});
export const insertAttackSurfaceAssetSchema = createInsertSchema(attackSurfaceAssets).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});
export const insertRiskForecastSchema = createInsertSchema(riskForecasts).omit({ id: true, createdAt: true });
export const insertAnomalySubscriptionSchema = createInsertSchema(anomalySubscriptions).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});
export const insertForecastQualitySnapshotSchema = createInsertSchema(forecastQualitySnapshots).omit({
  id: true,
  measuredAt: true,
});
export const insertHardeningRecommendationSchema = createInsertSchema(hardeningRecommendations).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});
export const insertAutoResponsePolicySchema = createInsertSchema(autoResponsePolicies).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
  executionCount: true,
  lastTriggeredAt: true,
});
export const insertInvestigationRunSchema = createInsertSchema(investigationRuns).omit({
  id: true,
  createdAt: true,
  completedAt: true,
  duration: true,
  error: true,
});
export const insertInvestigationStepSchema = createInsertSchema(investigationSteps).omit({ id: true, createdAt: true });
export const insertResponseActionRollbackSchema = createInsertSchema(responseActionRollbacks).omit({
  id: true,
  createdAt: true,
  executedAt: true,
});
export const insertPlaybookApprovalSchema = createInsertSchema(playbookApprovals).omit({
  id: true,
  requestedAt: true,
  decidedAt: true,
});
export const insertEvidenceChainEntrySchema = createInsertSchema(evidenceChainEntries).omit({
  id: true,
  createdAt: true,
});
export const insertIncidentResponseApprovalSchema = createInsertSchema(incidentResponseApprovals).omit({
  id: true,
  requestedAt: true,
  decidedAt: true,
});
export const insertPostIncidentReviewSchema = createInsertSchema(postIncidentReviews).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
  publishedAt: true,
});
export const insertPirActionItemSchema = createInsertSchema(pirActionItems).omit({
  id: true,
  createdAt: true,
  completedAt: true,
});
export const insertPlaybookVersionSchema = createInsertSchema(playbookVersions).omit({
  id: true,
  createdAt: true,
  approvedAt: true,
});
export const insertBlastRadiusPreviewSchema = createInsertSchema(blastRadiusPreviews).omit({
  id: true,
  createdAt: true,
});
export const insertPlaybookSimulationSchema = createInsertSchema(playbookSimulations).omit({
  id: true,
  createdAt: true,
  completedAt: true,
});
export const insertPlaybookRollbackPlanSchema = createInsertSchema(playbookRollbackPlans).omit({
  id: true,
  createdAt: true,
  executedAt: true,
});
export const insertAttackGraphSchema = createInsertSchema(attackGraphs).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});
export const insertAttackGraphNodeSchema = createInsertSchema(attackGraphNodes).omit({
  id: true,
  createdAt: true,
});
export const insertAttackGraphEdgeSchema = createInsertSchema(attackGraphEdges).omit({
  id: true,
  createdAt: true,
});

// Types
export type InsertAlert = z.infer<typeof insertAlertSchema>;
export type Alert = typeof alerts.$inferSelect;
export type InsertIncident = z.infer<typeof insertIncidentSchema>;
export type Incident = typeof incidents.$inferSelect;
export type Organization = typeof organizations.$inferSelect;
export type InsertOrganization = z.infer<typeof insertOrgSchema>;
export type AuditLog = typeof auditLogs.$inferSelect;
export const insertAuditVerificationRunSchema = createInsertSchema(auditVerificationRuns).omit({
  id: true,
  createdAt: true,
  verifiedAt: true,
});
export type AuditVerificationRun = typeof auditVerificationRuns.$inferSelect;
export type InsertAuditVerificationRun = z.infer<typeof insertAuditVerificationRunSchema>;
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
export type EntityMergeHistory = typeof entityMergeHistory.$inferSelect;
export type InsertEntityMergeHistory = z.infer<typeof insertEntityMergeHistorySchema>;
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
export type NotificationUserPreferences = typeof notificationUserPreferences.$inferSelect;
export type InsertNotificationUserPreferences = z.infer<typeof insertNotificationUserPreferencesSchema>;
export type NotificationDeliveryLog = typeof notificationDeliveryLog.$inferSelect;
export type InsertNotificationDeliveryLog = z.infer<typeof insertNotificationDeliveryLogSchema>;
export type ResponseAction = typeof responseActions.$inferSelect;
export type InsertResponseAction = z.infer<typeof insertResponseActionSchema>;
export type PredictiveAnomaly = typeof predictiveAnomalies.$inferSelect;
export type InsertPredictiveAnomaly = z.infer<typeof insertPredictiveAnomalySchema>;
export type AttackSurfaceAsset = typeof attackSurfaceAssets.$inferSelect;
export type InsertAttackSurfaceAsset = z.infer<typeof insertAttackSurfaceAssetSchema>;
export type RiskForecast = typeof riskForecasts.$inferSelect;
export type InsertRiskForecast = z.infer<typeof insertRiskForecastSchema>;
export type AnomalySubscription = typeof anomalySubscriptions.$inferSelect;
export type InsertAnomalySubscription = z.infer<typeof insertAnomalySubscriptionSchema>;
export type ForecastQualitySnapshot = typeof forecastQualitySnapshots.$inferSelect;
export type InsertForecastQualitySnapshot = z.infer<typeof insertForecastQualitySnapshotSchema>;
export type HardeningRecommendation = typeof hardeningRecommendations.$inferSelect;
export type InsertHardeningRecommendation = z.infer<typeof insertHardeningRecommendationSchema>;
export type AutoResponsePolicy = typeof autoResponsePolicies.$inferSelect;
export type InsertAutoResponsePolicy = z.infer<typeof insertAutoResponsePolicySchema>;
export type InvestigationRun = typeof investigationRuns.$inferSelect;
export type InsertInvestigationRun = z.infer<typeof insertInvestigationRunSchema>;
export type InvestigationStep = typeof investigationSteps.$inferSelect;
export type InsertInvestigationStep = z.infer<typeof insertInvestigationStepSchema>;
export type ResponseActionRollback = typeof responseActionRollbacks.$inferSelect;
export type InsertResponseActionRollback = z.infer<typeof insertResponseActionRollbackSchema>;
export type PlaybookApproval = typeof playbookApprovals.$inferSelect;
export type InsertPlaybookApproval = z.infer<typeof insertPlaybookApprovalSchema>;
export type EvidenceChainEntry = typeof evidenceChainEntries.$inferSelect;
export type InsertEvidenceChainEntry = z.infer<typeof insertEvidenceChainEntrySchema>;
export type IncidentResponseApproval = typeof incidentResponseApprovals.$inferSelect;
export type InsertIncidentResponseApproval = z.infer<typeof insertIncidentResponseApprovalSchema>;
export type PostIncidentReview = typeof postIncidentReviews.$inferSelect;
export type InsertPostIncidentReview = z.infer<typeof insertPostIncidentReviewSchema>;
export type PirActionItem = typeof pirActionItems.$inferSelect;
export type InsertPirActionItem = z.infer<typeof insertPirActionItemSchema>;
export type PlaybookVersion = typeof playbookVersions.$inferSelect;
export type InsertPlaybookVersion = z.infer<typeof insertPlaybookVersionSchema>;
export type BlastRadiusPreview = typeof blastRadiusPreviews.$inferSelect;
export type InsertBlastRadiusPreview = z.infer<typeof insertBlastRadiusPreviewSchema>;
export type PlaybookSimulation = typeof playbookSimulations.$inferSelect;
export type InsertPlaybookSimulation = z.infer<typeof insertPlaybookSimulationSchema>;
export type PlaybookRollbackPlan = typeof playbookRollbackPlans.$inferSelect;
export type InsertPlaybookRollbackPlan = z.infer<typeof insertPlaybookRollbackPlanSchema>;
export type AttackGraph = typeof attackGraphs.$inferSelect;
export type InsertAttackGraph = z.infer<typeof insertAttackGraphSchema>;
export type AttackGraphNode = typeof attackGraphNodes.$inferSelect;
export type InsertAttackGraphNode = z.infer<typeof insertAttackGraphNodeSchema>;
export type AttackGraphEdge = typeof attackGraphEdges.$inferSelect;
export type InsertAttackGraphEdge = z.infer<typeof insertAttackGraphEdgeSchema>;

export const CLOUD_PROVIDERS = ["aws", "azure", "gcp"] as const;
export const CSPM_SCAN_STATUSES = ["pending", "running", "completed", "failed"] as const;
export const CSPM_FINDING_SEVERITIES = ["critical", "high", "medium", "low", "informational"] as const;
export const CSPM_FINDING_STATUSES = ["open", "resolved", "suppressed", "accepted_risk"] as const;
export const CSPM_COMPLIANCE_FRAMEWORKS = [
  "cis",
  "nist",
  "pci_dss",
  "hipaa",
  "soc2",
  "gdpr",
  "iso27001",
  "nis2",
  "dora",
  "ccpa",
  "cmmc",
  "nerc_cip",
  "swift_csp",
  "iec_62443",
  "asd_essential8",
] as const;
export const ENDPOINT_OS_TYPES = ["windows", "linux", "macos"] as const;
export const ENDPOINT_STATUSES = ["online", "offline", "degraded", "isolated"] as const;
export const AI_BACKENDS = ["bedrock", "sagemaker", "on_prem", "azure_openai"] as const;

export const cspmAccounts = pgTable("cspm_accounts", {
  id: varchar("id")
    .primaryKey()
    .default(sql`gen_random_uuid()`),
  orgId: text("org_id").notNull(),
  cloudProvider: text("cloud_provider").notNull(),
  accountId: text("account_id").notNull(),
  displayName: text("display_name").notNull(),
  regions: text("regions")
    .array()
    .default(sql`ARRAY[]::text[]`),
  status: text("status").default("active"),
  config: jsonb("config").default({}),
  lastScanAt: timestamp("last_scan_at"),
  createdAt: timestamp("created_at").defaultNow(),
});

export const cspmScans = pgTable("cspm_scans", {
  id: varchar("id")
    .primaryKey()
    .default(sql`gen_random_uuid()`),
  orgId: text("org_id").notNull(),
  accountId: varchar("account_id")
    .notNull()
    .references(() => cspmAccounts.id),
  status: text("status").default("pending"),
  findingsCount: integer("findings_count").default(0),
  summary: jsonb("summary").default({}),
  startedAt: timestamp("started_at").defaultNow(),
  completedAt: timestamp("completed_at"),
});

export const cspmFindings = pgTable("cspm_findings", {
  id: varchar("id")
    .primaryKey()
    .default(sql`gen_random_uuid()`),
  orgId: text("org_id").notNull(),
  scanId: varchar("scan_id").notNull(),
  accountId: varchar("account_id").notNull(),
  ruleId: text("rule_id").notNull(),
  ruleName: text("rule_name").notNull(),
  severity: text("severity").notNull(),
  resourceType: text("resource_type").notNull(),
  resourceId: text("resource_id").notNull(),
  resourceRegion: text("resource_region"),
  description: text("description").notNull(),
  remediation: text("remediation"),
  complianceFrameworks: text("compliance_frameworks")
    .array()
    .default(sql`ARRAY[]::text[]`),
  status: text("status").default("open"),
  detectedAt: timestamp("detected_at").defaultNow(),
});

// CSPM Drift Baselines — approved configuration snapshots for drift detection
export const cspmDriftBaselines = pgTable("cspm_drift_baselines", {
  id: varchar("id")
    .primaryKey()
    .default(sql`gen_random_uuid()`),
  orgId: text("org_id").notNull(),
  accountId: varchar("account_id").notNull(),
  resourceId: text("resource_id").notNull(),
  resourceType: text("resource_type").notNull(),
  region: text("region"),
  approvedConfig: jsonb("approved_config").default({}),
  snapshotAt: timestamp("snapshot_at").defaultNow(),
  createdBy: text("created_by"),
});

// CSPM Drift Events — detected configuration changes from baseline
export const cspmDriftEvents = pgTable("cspm_drift_events", {
  id: varchar("id")
    .primaryKey()
    .default(sql`gen_random_uuid()`),
  orgId: text("org_id").notNull(),
  accountId: varchar("account_id").notNull(),
  resourceId: text("resource_id").notNull(),
  resourceType: text("resource_type").notNull(),
  region: text("region"),
  driftType: text("drift_type").notNull(), // added, removed, modified
  field: text("field").notNull(),
  baselineValue: jsonb("baseline_value"),
  currentValue: jsonb("current_value"),
  severity: text("severity").notNull(),
  description: text("description").notNull(),
  status: text("status").default("open"), // open, acknowledged, resolved, suppressed
  detectedAt: timestamp("detected_at").defaultNow(),
});

// CSPM DSPM Findings — sensitive data discoveries in cloud storage
export const cspmDspmFindings = pgTable("cspm_dspm_findings", {
  id: varchar("id")
    .primaryKey()
    .default(sql`gen_random_uuid()`),
  orgId: text("org_id").notNull(),
  accountId: varchar("account_id").notNull(),
  resourceId: text("resource_id").notNull(),
  resourceType: text("resource_type").notNull(),
  region: text("region"),
  dataClassification: text("data_classification").notNull(),
  sensitivityLevel: text("sensitivity_level").notNull(), // critical, high, medium, low
  dataCategories: text("data_categories")
    .array()
    .default(sql`ARRAY[]::text[]`),
  objectCount: integer("object_count").default(0),
  sampleObjects: text("sample_objects")
    .array()
    .default(sql`ARRAY[]::text[]`),
  description: text("description").notNull(),
  remediation: text("remediation"),
  status: text("status").default("open"),
  detectedAt: timestamp("detected_at").defaultNow(),
});

// CSPM Attack Paths — multi-cloud lateral movement analysis
export const cspmAttackPaths = pgTable("cspm_attack_paths", {
  id: varchar("id")
    .primaryKey()
    .default(sql`gen_random_uuid()`),
  orgId: text("org_id").notNull(),
  name: text("name").notNull(),
  description: text("description").notNull(),
  severity: text("severity").notNull(),
  riskScore: integer("risk_score").default(0),
  nodes: jsonb("nodes").default([]),
  edges: jsonb("edges").default([]),
  mitigations: text("mitigations")
    .array()
    .default(sql`ARRAY[]::text[]`),
  isCrossCloud: boolean("is_cross_cloud").default(false),
  status: text("status").default("active"), // active, mitigated, suppressed
  detectedAt: timestamp("detected_at").defaultNow(),
});

// CSPM Remediation History — auto-remediation execution log
export const cspmRemediations = pgTable("cspm_remediations", {
  id: varchar("id")
    .primaryKey()
    .default(sql`gen_random_uuid()`),
  orgId: text("org_id").notNull(),
  accountId: varchar("account_id").notNull(),
  findingId: varchar("finding_id"),
  playbookId: text("playbook_id").notNull(),
  playbookName: text("playbook_name").notNull(),
  resourceId: text("resource_id").notNull(),
  ruleId: text("rule_id").notNull(),
  status: text("status").notNull(), // success, failed, partial, pending, approved, rejected
  actionsExecuted: integer("actions_executed").default(0),
  actionsTotal: integer("actions_total").default(0),
  error: text("error"),
  details: jsonb("details").default({}),
  requestedBy: text("requested_by"),
  approvedBy: text("approved_by"),
  executedAt: timestamp("executed_at").defaultNow(),
});

export const endpointAssets = pgTable("endpoint_assets", {
  id: varchar("id")
    .primaryKey()
    .default(sql`gen_random_uuid()`),
  orgId: text("org_id").notNull(),
  hostname: text("hostname").notNull(),
  os: text("os").notNull(),
  osVersion: text("os_version"),
  agentVersion: text("agent_version"),
  agentStatus: text("agent_status").default("online"),
  ipAddress: text("ip_address"),
  macAddress: text("mac_address"),
  lastSeenAt: timestamp("last_seen_at").defaultNow(),
  riskScore: integer("risk_score").default(0),
  tags: text("tags")
    .array()
    .default(sql`ARRAY[]::text[]`),
  metadata: jsonb("metadata").default({}),
  createdAt: timestamp("created_at").defaultNow(),
});

export const endpointTelemetry = pgTable("endpoint_telemetry", {
  id: varchar("id")
    .primaryKey()
    .default(sql`gen_random_uuid()`),
  orgId: text("org_id").notNull(),
  assetId: varchar("asset_id")
    .notNull()
    .references(() => endpointAssets.id),
  metricType: text("metric_type").notNull(),
  metricValue: jsonb("metric_value").notNull(),
  collectedAt: timestamp("collected_at").defaultNow(),
});

export const postureScores = pgTable("posture_scores", {
  id: varchar("id")
    .primaryKey()
    .default(sql`gen_random_uuid()`),
  orgId: text("org_id").notNull(),
  overallScore: integer("overall_score").notNull(),
  cspmScore: integer("cspm_score").default(0),
  endpointScore: integer("endpoint_score").default(0),
  incidentScore: integer("incident_score").default(0),
  complianceScore: integer("compliance_score").default(0),
  breakdown: jsonb("breakdown").default({}),
  generatedAt: timestamp("generated_at").defaultNow(),
});

export const aiDeploymentConfigs = pgTable("ai_deployment_configs", {
  id: varchar("id")
    .primaryKey()
    .default(sql`gen_random_uuid()`),
  orgId: text("org_id").notNull().unique(),
  backend: text("backend").default("bedrock"),
  modelId: text("model_id"),
  endpointUrl: text("endpoint_url"),
  region: text("region").default("us-east-1"),
  dataResidency: text("data_residency").default("us"),
  allowExternalCalls: boolean("allow_external_calls").default(true),
  config: jsonb("config").default({}),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export const organizationMemberships = pgTable(
  "organization_memberships",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    userId: varchar("user_id").notNull(),
    role: text("role").notNull().default("analyst"),
    // customRoleId references a custom org-defined role; null = use the system role above
    customRoleId: varchar("custom_role_id").references(() => orgRoles.id, { onDelete: "set null" }),
    status: text("status").notNull().default("active"),
    invitedBy: varchar("invited_by"),
    invitedEmail: text("invited_email"),
    invitedAt: timestamp("invited_at"),
    joinedAt: timestamp("joined_at"),
    suspendedAt: timestamp("suspended_at"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    uniqueIndex("idx_membership_org_user").on(table.orgId, table.userId),
    index("idx_membership_org").on(table.orgId),
    index("idx_membership_user").on(table.userId),
  ],
);

export const orgInvitations = pgTable(
  "org_invitations",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    email: text("email").notNull(),
    role: text("role").notNull().default("analyst"),
    token: text("token").notNull().unique(),
    invitedBy: varchar("invited_by").notNull(),
    expiresAt: timestamp("expires_at").notNull(),
    acceptedAt: timestamp("accepted_at"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_invitation_org").on(table.orgId),
    index("idx_invitation_email").on(table.email),
    index("idx_invitation_token").on(table.token),
  ],
);

// ============================
// Explicit RBAC: Custom Roles, Role Permissions, Teams
// ============================

/**
 * Org-defined custom roles.  System roles (owner/admin/analyst/read_only) are
 * represented here with isSystem=true so that role_permissions rows can point
 * to them.  Custom roles set isSystem=false and may inherit from a base system
 * role via baseRole for additive grants.
 */
export const orgRoles = pgTable(
  "org_roles",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    name: text("name").notNull(),
    description: text("description"),
    // true for the four built-in roles seeded per org; false for custom ones
    isSystem: boolean("is_system").notNull().default(false),
    // which ORG_ROLES constant this inherits from (null for fully custom)
    baseRole: text("base_role"),
    createdBy: varchar("created_by"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    uniqueIndex("idx_org_roles_org_name").on(table.orgId, table.name),
    index("idx_org_roles_org").on(table.orgId),
    index("idx_org_roles_system").on(table.isSystem),
  ],
);

/**
 * Fine-grained permission rows for a role.  Each row grants a single
 * (scope, action) pair.  The full effective permission set for a member
 * is the union of their role's rows plus any rows on custom roles they
 * carry via organizationMemberships.customRoleId.
 */
export const orgRolePermissions = pgTable(
  "org_role_permissions",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    roleId: varchar("role_id")
      .notNull()
      .references(() => orgRoles.id, { onDelete: "cascade" }),
    // matches PERMISSION_SCOPES constant
    scope: text("scope").notNull(),
    // matches PERMISSION_ACTIONS constant
    action: text("action").notNull(),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    uniqueIndex("idx_role_perms_role_scope_action").on(table.roleId, table.scope, table.action),
    index("idx_role_perms_role").on(table.roleId),
  ],
);

/**
 * Logical teams within an org (e.g. "Tier-1 SOC", "Cloud Security").
 * Teams can be used to scope savedViews and to assign incidents/alerts
 * in bulk.
 */
export const orgTeams = pgTable(
  "org_teams",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    name: text("name").notNull(),
    description: text("description"),
    color: text("color").default("#6366f1"),
    createdBy: varchar("created_by"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    uniqueIndex("idx_org_teams_org_name").on(table.orgId, table.name),
    index("idx_org_teams_org").on(table.orgId),
  ],
);

/**
 * Maps users to teams.  A user can be "lead" or "member" within a team.
 * Team leads can manage team-scoped savedViews and see team-assigned work.
 */
export const orgTeamMemberships = pgTable(
  "org_team_memberships",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    teamId: varchar("team_id")
      .notNull()
      .references(() => orgTeams.id, { onDelete: "cascade" }),
    userId: varchar("user_id").notNull(),
    // matches TEAM_MEMBERSHIP_ROLES constant: "lead" | "member"
    role: text("role").notNull().default("member"),
    addedBy: varchar("added_by"),
    addedAt: timestamp("added_at").defaultNow(),
  },
  (table) => [
    uniqueIndex("idx_team_memberships_team_user").on(table.teamId, table.userId),
    index("idx_team_memberships_team").on(table.teamId),
    index("idx_team_memberships_user").on(table.userId),
  ],
);

// ============================
// Saved Views
// ============================

/**
 * Persisted filter / column / sort presets per resource list page.
 * visibility controls sharing:
 *   "private" – only the owning userId can see it
 *   "team"    – all members of teamId can see it (teamId required)
 *   "org"     – every member of the org can see it (analyst role+)
 *
 * The filters column stores a serialized filter state specific to the
 * resourceType page (e.g. {severity: ["critical"], status: ["new"]}).
 * The columns column stores an ordered list of visible column keys.
 */
export const savedViews = pgTable(
  "saved_views",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    // userId of the creator / owner – required even for org-visible views
    userId: varchar("user_id").notNull(),
    // set when visibility = "team"
    teamId: varchar("team_id").references(() => orgTeams.id, { onDelete: "set null" }),
    name: text("name").notNull(),
    // matches SAVED_VIEW_RESOURCE_TYPES: "alerts" | "incidents" | "entities" | "connectors"
    resourceType: text("resource_type").notNull(),
    // serialised filter state: shape depends on resourceType
    filters: jsonb("filters").notNull().default({}),
    // ordered list of visible column keys; null = use page default
    columns: text("columns").array(),
    sortField: text("sort_field"),
    // "asc" | "desc"
    sortDir: text("sort_dir").default("desc"),
    // at most one default view per (userId, resourceType)
    isDefault: boolean("is_default").notNull().default(false),
    // matches SAVED_VIEW_VISIBILITIES: "private" | "team" | "org"
    visibility: text("visibility").notNull().default("private"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_saved_views_org").on(table.orgId),
    index("idx_saved_views_user").on(table.userId),
    index("idx_saved_views_team").on(table.teamId),
    index("idx_saved_views_resource").on(table.orgId, table.resourceType),
    index("idx_saved_views_visibility").on(table.orgId, table.visibility),
  ],
);

export const IOC_FEED_TYPES = ["misp", "stix", "taxii", "otx", "virustotal", "csv", "custom"] as const;
export const IOC_ENTRY_STATUSES = ["active", "expired", "revoked", "whitelisted"] as const;
export const IOC_TYPES = ["ip", "domain", "url", "hash", "email", "hostname", "cidr", "cve"] as const;

export const iocFeeds = pgTable(
  "ioc_feeds",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").references(() => organizations.id),
    name: text("name").notNull(),
    feedType: text("feed_type").notNull(),
    url: text("url"),
    apiKeyRef: text("api_key_ref"),
    schedule: text("schedule").default("manual"),
    enabled: boolean("enabled").default(true),
    config: jsonb("config").default({}),
    lastFetchAt: timestamp("last_fetch_at"),
    lastFetchStatus: text("last_fetch_status"),
    lastFetchCount: integer("last_fetch_count").default(0),
    totalIocCount: integer("total_ioc_count").default(0),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [index("idx_ioc_feeds_org").on(table.orgId)],
);

export const iocEntries = pgTable(
  "ioc_entries",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").references(() => organizations.id),
    feedId: varchar("feed_id").references(() => iocFeeds.id, { onDelete: "cascade" }),
    iocType: text("ioc_type").notNull(),
    iocValue: text("ioc_value").notNull(),
    confidence: integer("confidence").default(50),
    severity: text("severity").default("medium"),
    malwareFamily: text("malware_family"),
    campaignId: text("campaign_id"),
    campaignName: text("campaign_name"),
    tags: text("tags")
      .array()
      .default(sql`ARRAY[]::text[]`),
    metadata: jsonb("metadata").default({}),
    source: text("source"),
    status: text("status").default("active"),
    firstSeen: timestamp("first_seen").defaultNow(),
    lastSeen: timestamp("last_seen").defaultNow(),
    expiresAt: timestamp("expires_at"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_ioc_entries_org").on(table.orgId),
    index("idx_ioc_entries_feed").on(table.feedId),
    index("idx_ioc_entries_type").on(table.iocType),
    index("idx_ioc_entries_value").on(table.iocValue),
    index("idx_ioc_entries_type_value").on(table.iocType, table.iocValue),
    index("idx_ioc_entries_org_created").on(table.orgId, table.createdAt),
    index("idx_ioc_entries_org_type_created").on(table.orgId, table.iocType, table.createdAt),
    index("idx_ioc_entries_status").on(table.status),
  ],
);

export const iocWatchlists = pgTable(
  "ioc_watchlists",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").references(() => organizations.id),
    name: text("name").notNull(),
    description: text("description"),
    color: text("color").default("#3b82f6"),
    autoMatch: boolean("auto_match").default(true),
    createdBy: varchar("created_by"),
    entryCount: integer("entry_count").default(0),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [index("idx_ioc_watchlists_org").on(table.orgId)],
);

export const iocWatchlistEntries = pgTable(
  "ioc_watchlist_entries",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    watchlistId: varchar("watchlist_id")
      .notNull()
      .references(() => iocWatchlists.id, { onDelete: "cascade" }),
    iocEntryId: varchar("ioc_entry_id")
      .notNull()
      .references(() => iocEntries.id, { onDelete: "cascade" }),
    addedBy: varchar("added_by"),
    addedAt: timestamp("added_at").defaultNow(),
  },
  (table) => [
    index("idx_ioc_watchlist_entries_wl").on(table.watchlistId),
    index("idx_ioc_watchlist_entries_ioc").on(table.iocEntryId),
  ],
);

export const iocMatchRules = pgTable(
  "ioc_match_rules",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").references(() => organizations.id),
    feedId: varchar("feed_id").references(() => iocFeeds.id),
    name: text("name").notNull(),
    description: text("description"),
    iocTypes: text("ioc_types")
      .array()
      .default(sql`ARRAY[]::text[]`),
    matchFields: text("match_fields")
      .array()
      .default(sql`ARRAY[]::text[]`),
    minConfidence: integer("min_confidence").default(0),
    enabled: boolean("enabled").default(true),
    autoEnrich: boolean("auto_enrich").default(true),
    action: text("action").default("tag"),
    actionConfig: jsonb("action_config").default({}),
    matchCount: integer("match_count").default(0),
    lastMatchAt: timestamp("last_match_at"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [index("idx_ioc_match_rules_org").on(table.orgId)],
);

export const iocMatches = pgTable(
  "ioc_matches",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").references(() => organizations.id),
    ruleId: varchar("rule_id").references(() => iocMatchRules.id),
    iocEntryId: varchar("ioc_entry_id")
      .notNull()
      .references(() => iocEntries.id),
    alertId: varchar("alert_id").references(() => alerts.id, { onDelete: "set null" }),
    incidentId: varchar("incident_id").references(() => incidents.id),
    entityId: varchar("entity_id").references(() => entities.id),
    matchField: text("match_field").notNull(),
    matchValue: text("match_value").notNull(),
    confidence: integer("confidence").default(50),
    enrichmentData: jsonb("enrichment_data").default({}),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_ioc_matches_org").on(table.orgId),
    index("idx_ioc_matches_alert").on(table.alertId),
    index("idx_ioc_matches_ioc").on(table.iocEntryId),
  ],
);

export const evidenceItems = pgTable(
  "evidence_items",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").references(() => organizations.id),
    incidentId: varchar("incident_id")
      .notNull()
      .references(() => incidents.id, { onDelete: "cascade" }),
    type: text("type").notNull(),
    title: text("title").notNull(),
    description: text("description"),
    storageKey: text("storage_key"),
    url: text("url"),
    mimeType: text("mime_type"),
    fileSize: integer("file_size"),
    checksumSha256: text("checksum_sha256"),
    uploadStatus: text("upload_status").notNull().default("pending"),
    uploadedAt: timestamp("uploaded_at"),
    metadata: jsonb("metadata"),
    createdBy: varchar("created_by"),
    createdByName: text("created_by_name"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_evidence_items_incident").on(table.incidentId),
    index("idx_evidence_items_org").on(table.orgId),
  ],
);

export const investigationHypotheses = pgTable(
  "investigation_hypotheses",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").references(() => organizations.id),
    incidentId: varchar("incident_id")
      .notNull()
      .references(() => incidents.id, { onDelete: "cascade" }),
    title: text("title").notNull(),
    description: text("description"),
    status: text("status").notNull().default("open"),
    confidence: real("confidence").default(0),
    evidenceFor: text("evidence_for").array(),
    evidenceAgainst: text("evidence_against").array(),
    mitreTactics: text("mitre_tactics").array(),
    createdBy: varchar("created_by"),
    createdByName: text("created_by_name"),
    validatedAt: timestamp("validated_at"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_hypotheses_incident").on(table.incidentId),
    index("idx_hypotheses_org").on(table.orgId),
    index("idx_hypotheses_status").on(table.status),
  ],
);

export const investigationTasks = pgTable(
  "investigation_tasks",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").references(() => organizations.id),
    incidentId: varchar("incident_id")
      .notNull()
      .references(() => incidents.id, { onDelete: "cascade" }),
    title: text("title").notNull(),
    description: text("description"),
    status: text("status").notNull().default("open"),
    priority: integer("priority").default(3),
    assignedTo: varchar("assigned_to"),
    assignedToName: text("assigned_to_name"),
    dueDate: timestamp("due_date"),
    completedAt: timestamp("completed_at"),
    createdBy: varchar("created_by"),
    createdByName: text("created_by_name"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_inv_tasks_incident").on(table.incidentId),
    index("idx_inv_tasks_org").on(table.orgId),
    index("idx_inv_tasks_assigned").on(table.assignedTo),
    index("idx_inv_tasks_status").on(table.status),
  ],
);

export const runbookTemplates = pgTable(
  "runbook_templates",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").references(() => organizations.id),
    incidentType: text("incident_type").notNull(),
    title: text("title").notNull(),
    description: text("description"),
    severity: text("severity").default("medium"),
    estimatedDuration: text("estimated_duration"),
    tags: text("tags").array(),
    isBuiltIn: boolean("is_built_in").default(false),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_runbook_templates_type").on(table.incidentType),
    index("idx_runbook_templates_org").on(table.orgId),
  ],
);

export const runbookSteps = pgTable(
  "runbook_steps",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    templateId: varchar("template_id")
      .notNull()
      .references(() => runbookTemplates.id, { onDelete: "cascade" }),
    stepOrder: integer("step_order").notNull(),
    title: text("title").notNull(),
    instructions: text("instructions"),
    actionType: text("action_type"),
    isRequired: boolean("is_required").default(true),
    estimatedMinutes: integer("estimated_minutes"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [index("idx_runbook_steps_template").on(table.templateId)],
);

export const insertEvidenceItemSchema = createInsertSchema(evidenceItems).omit({ id: true, createdAt: true });
export const insertInvestigationHypothesisSchema = createInsertSchema(investigationHypotheses).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
  validatedAt: true,
});
export const insertInvestigationTaskSchema = createInsertSchema(investigationTasks).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
  completedAt: true,
});
export const insertRunbookTemplateSchema = createInsertSchema(runbookTemplates).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});
export const insertRunbookStepSchema = createInsertSchema(runbookSteps).omit({ id: true, createdAt: true });

export type EvidenceItem = typeof evidenceItems.$inferSelect;
export type InsertEvidenceItem = z.infer<typeof insertEvidenceItemSchema>;
export type InvestigationHypothesis = typeof investigationHypotheses.$inferSelect;
export type InsertInvestigationHypothesis = z.infer<typeof insertInvestigationHypothesisSchema>;
export type InvestigationTask = typeof investigationTasks.$inferSelect;
export type InsertInvestigationTask = z.infer<typeof insertInvestigationTaskSchema>;
export type RunbookTemplate = typeof runbookTemplates.$inferSelect;
export type InsertRunbookTemplate = z.infer<typeof insertRunbookTemplateSchema>;
export type RunbookStep = typeof runbookSteps.$inferSelect;
export type InsertRunbookStep = z.infer<typeof insertRunbookStepSchema>;

export const insertCspmAccountSchema = createInsertSchema(cspmAccounts).omit({
  id: true,
  createdAt: true,
  lastScanAt: true,
});
export const insertCspmScanSchema = createInsertSchema(cspmScans).omit({
  id: true,
  startedAt: true,
  completedAt: true,
});
export const insertCspmFindingSchema = createInsertSchema(cspmFindings).omit({ id: true, detectedAt: true });
export const insertCspmDriftBaselineSchema = createInsertSchema(cspmDriftBaselines).omit({
  id: true,
  snapshotAt: true,
});
export const insertCspmDriftEventSchema = createInsertSchema(cspmDriftEvents).omit({ id: true, detectedAt: true });
export const insertCspmDspmFindingSchema = createInsertSchema(cspmDspmFindings).omit({ id: true, detectedAt: true });
export const insertCspmAttackPathSchema = createInsertSchema(cspmAttackPaths).omit({ id: true, detectedAt: true });
export const insertCspmRemediationSchema = createInsertSchema(cspmRemediations).omit({ id: true, executedAt: true });
export const insertEndpointAssetSchema = createInsertSchema(endpointAssets).omit({
  id: true,
  createdAt: true,
  lastSeenAt: true,
});
export const insertEndpointTelemetrySchema = createInsertSchema(endpointTelemetry).omit({
  id: true,
  collectedAt: true,
});
export const insertPostureScoreSchema = createInsertSchema(postureScores).omit({ id: true, generatedAt: true });
export const insertAiDeploymentConfigSchema = createInsertSchema(aiDeploymentConfigs).omit({
  id: true,
  updatedAt: true,
});

export type CspmAccount = typeof cspmAccounts.$inferSelect;
export type InsertCspmAccount = z.infer<typeof insertCspmAccountSchema>;
export type CspmScan = typeof cspmScans.$inferSelect;
export type InsertCspmScan = z.infer<typeof insertCspmScanSchema>;
export type CspmFinding = typeof cspmFindings.$inferSelect;
export type InsertCspmFinding = z.infer<typeof insertCspmFindingSchema>;
export type CspmDriftBaseline = typeof cspmDriftBaselines.$inferSelect;
export type InsertCspmDriftBaseline = z.infer<typeof insertCspmDriftBaselineSchema>;
export type CspmDriftEvent = typeof cspmDriftEvents.$inferSelect;
export type InsertCspmDriftEvent = z.infer<typeof insertCspmDriftEventSchema>;
export type CspmDspmFinding = typeof cspmDspmFindings.$inferSelect;
export type InsertCspmDspmFinding = z.infer<typeof insertCspmDspmFindingSchema>;
export type CspmAttackPath = typeof cspmAttackPaths.$inferSelect;
export type InsertCspmAttackPath = z.infer<typeof insertCspmAttackPathSchema>;
export type CspmRemediation = typeof cspmRemediations.$inferSelect;
export type InsertCspmRemediation = z.infer<typeof insertCspmRemediationSchema>;
export type EndpointAsset = typeof endpointAssets.$inferSelect;
export type InsertEndpointAsset = z.infer<typeof insertEndpointAssetSchema>;
export type EndpointTelemetry = typeof endpointTelemetry.$inferSelect;
export type InsertEndpointTelemetry = z.infer<typeof insertEndpointTelemetrySchema>;
export type PostureScore = typeof postureScores.$inferSelect;
export type InsertPostureScore = z.infer<typeof insertPostureScoreSchema>;
export type AiDeploymentConfig = typeof aiDeploymentConfigs.$inferSelect;
export type InsertAiDeploymentConfig = z.infer<typeof insertAiDeploymentConfigSchema>;

export const insertOrganizationMembershipSchema = createInsertSchema(organizationMemberships).omit({
  id: true,
  createdAt: true,
});
export const insertOrgInvitationSchema = createInsertSchema(orgInvitations).omit({ id: true, createdAt: true });
export const insertOrgRoleSchema = createInsertSchema(orgRoles).omit({ id: true, createdAt: true, updatedAt: true });
export const insertOrgRolePermissionSchema = createInsertSchema(orgRolePermissions).omit({ id: true, createdAt: true });
export const insertOrgTeamSchema = createInsertSchema(orgTeams).omit({ id: true, createdAt: true, updatedAt: true });
export const insertOrgTeamMembershipSchema = createInsertSchema(orgTeamMemberships).omit({ id: true, addedAt: true });
export const insertSavedViewSchema = createInsertSchema(savedViews).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export type OrganizationMembership = typeof organizationMemberships.$inferSelect;
export type InsertOrganizationMembership = z.infer<typeof insertOrganizationMembershipSchema>;
export type OrgInvitation = typeof orgInvitations.$inferSelect;
export type InsertOrgInvitation = z.infer<typeof insertOrgInvitationSchema>;
export type OrgRole = typeof orgRoles.$inferSelect;
export type InsertOrgRole = z.infer<typeof insertOrgRoleSchema>;
export type OrgRolePermission = typeof orgRolePermissions.$inferSelect;
export type InsertOrgRolePermission = z.infer<typeof insertOrgRolePermissionSchema>;
export type OrgTeam = typeof orgTeams.$inferSelect;
export type InsertOrgTeam = z.infer<typeof insertOrgTeamSchema>;
export type OrgTeamMembership = typeof orgTeamMemberships.$inferSelect;
export type InsertOrgTeamMembership = z.infer<typeof insertOrgTeamMembershipSchema>;
export type SavedView = typeof savedViews.$inferSelect;
export type InsertSavedView = z.infer<typeof insertSavedViewSchema>;

export const REPORT_TYPES = [
  "soc_kpi",
  "incidents",
  "attack_coverage",
  "connector_health",
  "executive_summary",
  "compliance",
] as const;
export const REPORT_FORMATS = ["pdf", "csv", "json"] as const;
export const REPORT_CADENCES = ["daily", "weekly", "biweekly", "monthly", "quarterly"] as const;
export const REPORT_DELIVERY_TYPES = ["email", "s3", "webhook"] as const;
export const REPORT_RUN_STATUSES = ["queued", "running", "completed", "failed"] as const;
export const DASHBOARD_ROLES = ["ciso", "soc_manager", "analyst"] as const;

export const reportTemplates = pgTable("report_templates", {
  id: varchar("id")
    .primaryKey()
    .default(sql`gen_random_uuid()`),
  orgId: varchar("org_id").references(() => organizations.id),
  name: text("name").notNull(),
  description: text("description"),
  reportType: text("report_type").notNull(),
  format: text("format").notNull().default("pdf"),
  config: text("config"),
  dashboardRole: text("dashboard_role"),
  isBuiltIn: boolean("is_built_in").default(false),
  createdBy: varchar("created_by"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export const reportSchedules = pgTable("report_schedules", {
  id: varchar("id")
    .primaryKey()
    .default(sql`gen_random_uuid()`),
  orgId: varchar("org_id").references(() => organizations.id),
  templateId: varchar("template_id")
    .references(() => reportTemplates.id)
    .notNull(),
  name: text("name").notNull(),
  cadence: text("cadence").notNull(),
  timezone: text("timezone").default("UTC"),
  deliveryTargets: text("delivery_targets"),
  enabled: boolean("enabled").default(true),
  lastRunAt: timestamp("last_run_at"),
  nextRunAt: timestamp("next_run_at"),
  createdBy: varchar("created_by"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export const reportRuns = pgTable("report_runs", {
  id: varchar("id")
    .primaryKey()
    .default(sql`gen_random_uuid()`),
  orgId: varchar("org_id").references(() => organizations.id),
  templateId: varchar("template_id")
    .references(() => reportTemplates.id)
    .notNull(),
  scheduleId: varchar("schedule_id").references(() => reportSchedules.id),
  status: text("status").notNull().default("queued"),
  format: text("format").notNull().default("pdf"),
  outputLocation: text("output_location"),
  fileSize: integer("file_size"),
  error: text("error"),
  startedAt: timestamp("started_at"),
  completedAt: timestamp("completed_at"),
  createdBy: varchar("created_by"),
  createdAt: timestamp("created_at").defaultNow(),
});

export const insertReportTemplateSchema = createInsertSchema(reportTemplates).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});
export const insertReportScheduleSchema = createInsertSchema(reportSchedules).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
  lastRunAt: true,
  nextRunAt: true,
});
export const insertReportRunSchema = createInsertSchema(reportRuns).omit({
  id: true,
  createdAt: true,
  startedAt: true,
  completedAt: true,
});

export type ReportTemplate = typeof reportTemplates.$inferSelect;
export type InsertReportTemplate = z.infer<typeof insertReportTemplateSchema>;
export type ReportSchedule = typeof reportSchedules.$inferSelect;
export type InsertReportSchedule = z.infer<typeof insertReportScheduleSchema>;
export type ReportRun = typeof reportRuns.$inferSelect;
export type InsertReportRun = z.infer<typeof insertReportRunSchema>;

export const insertIocFeedSchema = createInsertSchema(iocFeeds).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
  lastFetchAt: true,
  lastFetchStatus: true,
  lastFetchCount: true,
  totalIocCount: true,
});
export const insertIocEntrySchema = createInsertSchema(iocEntries).omit({
  id: true,
  createdAt: true,
  firstSeen: true,
  lastSeen: true,
});
export const insertIocWatchlistSchema = createInsertSchema(iocWatchlists).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
  entryCount: true,
});
export const insertIocWatchlistEntrySchema = createInsertSchema(iocWatchlistEntries).omit({ id: true, addedAt: true });
export const insertIocMatchRuleSchema = createInsertSchema(iocMatchRules).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
  matchCount: true,
  lastMatchAt: true,
});
export const insertIocMatchSchema = createInsertSchema(iocMatches).omit({ id: true, createdAt: true });

export type IocFeed = typeof iocFeeds.$inferSelect;
export type InsertIocFeed = z.infer<typeof insertIocFeedSchema>;
export type IocEntry = typeof iocEntries.$inferSelect;
export type InsertIocEntry = z.infer<typeof insertIocEntrySchema>;
export type IocWatchlist = typeof iocWatchlists.$inferSelect;
export type InsertIocWatchlist = z.infer<typeof insertIocWatchlistSchema>;
export type IocWatchlistEntry = typeof iocWatchlistEntries.$inferSelect;
export type InsertIocWatchlistEntry = z.infer<typeof insertIocWatchlistEntrySchema>;
export type IocMatchRule = typeof iocMatchRules.$inferSelect;
export type InsertIocMatchRule = z.infer<typeof insertIocMatchRuleSchema>;
export type IocMatch = typeof iocMatches.$inferSelect;
export type InsertIocMatch = z.infer<typeof insertIocMatchSchema>;

export const SUPPRESSION_SCOPES = [
  "source",
  "category",
  "severity",
  "title_regex",
  "entity",
  "source_ip",
  "dest_ip",
  "hostname",
  "domain",
] as const;

export const suppressionRules = pgTable(
  "suppression_rules",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").references(() => organizations.id),
    name: text("name").notNull(),
    description: text("description"),
    // Primary scope field (SUPPRESSION_SCOPES): coarse dimension to match on
    scope: text("scope").notNull(),
    // Simple scalar value for the scope (retained for backwards compat)
    scopeValue: text("scope_value").notNull(),
    /**
     * Optional complex matcher – an array of condition objects evaluated with
     * AND logic.  Each element shape:
     *   { field: string, op: SUPPRESSION_MATCHER_OPS[number], value: string | string[] }
     * Example: [{field:"title",op:"regex",value:"^test"},{field:"source",op:"eq",value:"Wazuh SIEM"}]
     * When null the rule falls back to the simple scope/scopeValue check.
     */
    matcher: jsonb("matcher"),
    // Explicit business reason this rule exists (e.g. "Approved by CISO 2025-03-01, ticket SNX-4421")
    reason: text("reason"),
    source: text("source"),
    severity: text("severity"),
    category: text("category"),
    enabled: boolean("enabled").default(true),
    expiresAt: timestamp("expires_at"),
    matchCount: integer("match_count").default(0),
    lastMatchAt: timestamp("last_match_at"),
    // Immutable creator
    createdBy: varchar("created_by"),
    // Mutable current responsible owner (may differ from creator after reassignment)
    ownedBy: varchar("owned_by"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_suppression_rules_org").on(table.orgId),
    index("idx_suppression_rules_enabled").on(table.enabled),
    index("idx_suppression_rules_expires").on(table.expiresAt),
    index("idx_suppression_rules_owner").on(table.ownedBy),
  ],
);

export const alertDedupClusters = pgTable(
  "alert_dedup_clusters",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").references(() => organizations.id),
    canonicalAlertId: varchar("canonical_alert_id").references(() => alerts.id, { onDelete: "set null" }),
    matchReason: text("match_reason").notNull(),
    matchConfidence: real("match_confidence").default(0),
    alertCount: integer("alert_count").default(1),
    firstSeenAt: timestamp("first_seen_at").defaultNow(),
    lastSeenAt: timestamp("last_seen_at").defaultNow(),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_dedup_clusters_org").on(table.orgId),
    index("idx_dedup_clusters_canonical").on(table.canonicalAlertId),
  ],
);

export const SLA_SEVERITY_LEVELS = ["critical", "high", "medium", "low"] as const;

export const incidentSlaPolicies = pgTable(
  "incident_sla_policies",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").references(() => organizations.id),
    name: text("name").notNull(),
    severity: text("severity").notNull(),
    ackMinutes: integer("ack_minutes").notNull(),
    containMinutes: integer("contain_minutes").notNull(),
    resolveMinutes: integer("resolve_minutes").notNull(),
    enabled: boolean("enabled").default(true),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [index("idx_sla_policies_org").on(table.orgId), index("idx_sla_policies_severity").on(table.severity)],
);

export const connectorJobRuns = pgTable(
  "connector_job_runs",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    connectorId: varchar("connector_id")
      .notNull()
      .references(() => connectors.id, { onDelete: "cascade" }),
    orgId: varchar("org_id"),
    status: text("status").notNull().default("running"),
    attempt: integer("attempt").notNull().default(1),
    maxAttempts: integer("max_attempts").notNull().default(3),
    alertsReceived: integer("alerts_received").default(0),
    alertsCreated: integer("alerts_created").default(0),
    alertsDeduped: integer("alerts_deduped").default(0),
    alertsFailed: integer("alerts_failed").default(0),
    latencyMs: integer("latency_ms"),
    errorMessage: text("error_message"),
    errorType: text("error_type"),
    httpStatus: integer("http_status"),
    throttled: boolean("throttled").default(false),
    isDeadLetter: boolean("is_dead_letter").default(false),
    // ── Retry scheduling ────────────────────────────────────────────────
    // matches CONNECTOR_RETRY_STRATEGIES: "exponential" | "linear" | "fixed"
    retryStrategy: text("retry_strategy").default("exponential"),
    // computed wait in seconds before the next attempt is scheduled
    backoffSeconds: integer("backoff_seconds"),
    // absolute timestamp when the next retry should be picked up by the worker
    nextRetryAt: timestamp("next_retry_at"),
    // ── Checkpoint / resume ─────────────────────────────────────────────
    /**
     * Opaque mid-run cursor saved at regular intervals so a retry can
     * resume from the last known-good position instead of re-fetching
     * from the beginning.  Shape is connector-specific, e.g.:
     *   CrowdStrike: { offset: number, filter: string }
     *   Splunk:      { lastEventTime: string, sessionKey: string }
     *   GuardDuty:   { nextToken: string }
     */
    checkpointData: jsonb("checkpoint_data"),
    // when checkpointData was last written
    checkpointAt: timestamp("checkpoint_at"),
    // convenience scalar: the opaque pagination/cursor token from the last
    // successful page fetch (redundant with checkpointData for simple connectors)
    paginationCursor: text("pagination_cursor"),
    // ── Fetch window ────────────────────────────────────────────────────
    // time range that was (or is being) fetched in this run; used for
    // gap detection and audit when the same window is retried
    fetchWindowStart: timestamp("fetch_window_start"),
    fetchWindowEnd: timestamp("fetch_window_end"),
    startedAt: timestamp("started_at").defaultNow(),
    completedAt: timestamp("completed_at"),
  },
  (table) => [
    index("idx_connector_job_runs_connector").on(table.connectorId),
    index("idx_connector_job_runs_status").on(table.status),
    index("idx_connector_job_runs_dead_letter").on(table.isDeadLetter),
    index("idx_connector_job_runs_started").on(table.startedAt),
    index("idx_connector_job_runs_next_retry").on(table.nextRetryAt),
    index("idx_connector_job_runs_connector_started").on(table.connectorId, table.startedAt),
  ],
);

export const connectorProviderState = pgTable("connector_provider_state", {
  provider: varchar("provider").primaryKey(),
  activeCount: integer("active_count").notNull().default(0),
  maxConcurrency: integer("max_concurrency").notNull().default(3),
  backoffUntil: timestamp("backoff_until"),
  backoffFactor: integer("backoff_factor").notNull().default(1),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export type ConnectorProviderState = typeof connectorProviderState.$inferSelect;

export const orgAiBudgets = pgTable(
  "org_ai_budgets",
  {
    orgId: varchar("org_id").primaryKey(),
    budgetUsd: doublePrecision("budget_usd").notNull().default(50),
    invocationCap: integer("invocation_cap").notNull().default(5000),
    dailySpendUsd: doublePrecision("daily_spend_usd").notNull().default(0),
    dailyInvocations: integer("daily_invocations").notNull().default(0),
    dailyInputTokens: integer("daily_input_tokens").notNull().default(0),
    dailyOutputTokens: integer("daily_output_tokens").notNull().default(0),
    lastResetAt: timestamp("last_reset_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [index("idx_org_ai_budgets_org_id").on(table.orgId)],
);

export type OrgAiBudget = typeof orgAiBudgets.$inferSelect;

export const orgAiSecuritySettings = pgTable(
  "org_ai_security_settings",
  {
    orgId: varchar("org_id")
      .primaryKey()
      .references(() => organizations.id, { onDelete: "cascade" }),
    injectionMode: text("injection_mode").notNull().default("flag_and_gate"),
    piiMasking: text("pii_masking").notNull().default("mask_identifiers"),
    aiEnabled: boolean("ai_enabled").notNull().default(true),
    updatedBy: varchar("updated_by"),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [index("idx_org_ai_security_settings_org").on(table.orgId)],
);

export const aiGuardEvents = pgTable(
  "ai_guard_events",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()::text`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    createdAt: timestamp("created_at").defaultNow(),
    invocationId: varchar("invocation_id").notNull(),
    feature: text("feature").notNull(),
    modelId: text("model_id").notNull(),
    injectionScore: integer("injection_score").notNull().default(0),
    signals: jsonb("signals").notNull().default([]),
    enforcementMode: text("enforcement_mode").notNull(),
    actionTaken: text("action_taken").notNull(),
    redactionCounts: jsonb("redaction_counts").notNull().default([]),
    humanReviewRequired: boolean("human_review_required").notNull().default(false),
    alertId: varchar("alert_id"),
    incidentId: varchar("incident_id"),
  },
  (table) => [
    index("idx_ai_guard_events_org_created").on(table.orgId, table.createdAt),
    index("idx_ai_guard_events_org_feature").on(table.orgId, table.feature),
    index("idx_ai_guard_events_org_score").on(table.orgId, table.injectionScore),
    index("idx_ai_guard_events_alert").on(table.orgId, table.alertId),
    index("idx_ai_guard_events_incident").on(table.orgId, table.incidentId),
  ],
);

export type OrgAiSecuritySettings = typeof orgAiSecuritySettings.$inferSelect;
export type AiGuardEvent = typeof aiGuardEvents.$inferSelect;

export const aiFewShotExamples = pgTable(
  "ai_few_shot_examples",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()::text`),
    orgId: varchar("org_id").references(() => organizations.id, { onDelete: "set null" }),
    domain: varchar("domain").notNull(),
    input: text("input").notNull(),
    incorrectOutput: text("incorrect_output").notNull(),
    correctOutput: text("correct_output").notNull(),
    lesson: text("lesson").notNull(),
    alertSource: varchar("alert_source"),
    alertCategory: varchar("alert_category"),
    feedbackId: varchar("feedback_id"),
    active: boolean("active").notNull().default(true),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_few_shot_org_domain").on(table.orgId, table.domain),
    index("idx_few_shot_active").on(table.active),
    index("idx_few_shot_feedback").on(table.feedbackId),
  ],
);

export const aiSourceSignalScores = pgTable(
  "ai_source_signal_scores",
  {
    id: serial("id").primaryKey(),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    source: varchar("source").notNull(),
    category: varchar("category").notNull().default(""),
    totalFeedback: integer("total_feedback").notNull().default(0),
    overriddenCount: integer("overridden_count").notNull().default(0),
    dismissedCount: integer("dismissed_count").notNull().default(0),
    fpRate: doublePrecision("fp_rate").notNull().default(0),
    suppressed: boolean("suppressed").notNull().default(false),
    manualOverride: boolean("manual_override").notNull().default(false),
    lastUpdated: timestamp("last_updated").defaultNow(),
  },
  (table) => [
    index("idx_source_signal_org").on(table.orgId),
    index("idx_source_signal_suppressed").on(table.orgId, table.suppressed),
    uniqueIndex("uq_ai_source_signal_org_source_category").on(table.orgId, table.source, table.category),
  ],
);

export const aiFeedbackLearningLog = pgTable(
  "ai_feedback_learning_log",
  {
    id: serial("id").primaryKey(),
    orgId: varchar("org_id").references(() => organizations.id, { onDelete: "set null" }),
    feedbackId: varchar("feedback_id").notNull(),
    action: varchar("action").notNull(),
    domain: varchar("domain"),
    fewShotExampleId: varchar("few_shot_example_id"),
    source: varchar("source"),
    category: varchar("category"),
    details: jsonb("details"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [index("idx_feedback_learning_org").on(table.orgId)],
);

export const ragKnowledgeBase = pgTable(
  "rag_knowledge_base",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    orgId: varchar("org_id").references(() => organizations.id, { onDelete: "set null" }),
    category: text("category").notNull(),
    sourceType: text("source_type").notNull(),
    sourceId: text("source_id"),
    title: text("title").notNull(),
    content: text("content").notNull(),
    metadata: jsonb("metadata").default({}),
    embedding: vector("embedding", { dimensions: 1024 }),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow(),
  },
  (table) => [
    index("idx_rag_kb_category").on(table.category),
    index("idx_rag_kb_org").on(table.orgId),
    index("idx_rag_kb_source").on(table.sourceType, table.sourceId),
    index("idx_rag_kb_embedding").using("ivfflat", table.embedding.op("vector_cosine_ops")).with({ lists: 10 }),
    uniqueIndex("idx_rag_kb_source_unique")
      .on(table.orgId, table.sourceType, table.sourceId)
      .where(sql`source_id IS NOT NULL`),
  ],
);

export const ragIncidentEmbeddings = pgTable(
  "rag_incident_embeddings",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    incidentId: text("incident_id").notNull(),
    title: text("title").notNull(),
    summary: text("summary"),
    severity: text("severity"),
    mitreTactics: text("mitre_tactics").array(),
    mitreTechniques: text("mitre_techniques").array(),
    iocs: text("iocs").array(),
    content: text("content").notNull(),
    embedding: vector("embedding", { dimensions: 1024 }),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow(),
  },
  (table) => [
    index("idx_rag_incident_org").on(table.orgId),
    uniqueIndex("rag_incident_embeddings_org_incident_unique").on(table.orgId, table.incidentId),
  ],
);

export const connectorHealthChecks = pgTable(
  "connector_health_checks",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    connectorId: varchar("connector_id")
      .notNull()
      .references(() => connectors.id, { onDelete: "cascade" }),
    orgId: varchar("org_id"),
    status: text("status").notNull().default("healthy"),
    latencyMs: integer("latency_ms"),
    errorMessage: text("error_message"),
    credentialExpiresAt: timestamp("credential_expires_at"),
    credentialStatus: text("credential_status").default("valid"),
    checkedAt: timestamp("checked_at").defaultNow(),
  },
  (table) => [
    index("idx_connector_health_connector").on(table.connectorId),
    index("idx_connector_health_checked").on(table.checkedAt),
  ],
);

export const insertSuppressionRuleSchema = createInsertSchema(suppressionRules).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
  matchCount: true,
  lastMatchAt: true,
});
export const insertAlertDedupClusterSchema = createInsertSchema(alertDedupClusters).omit({
  id: true,
  createdAt: true,
  firstSeenAt: true,
  lastSeenAt: true,
});
export const insertIncidentSlaPolicySchema = createInsertSchema(incidentSlaPolicies).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});
export const insertConnectorJobRunSchema = createInsertSchema(connectorJobRuns).omit({
  id: true,
  startedAt: true,
  completedAt: true,
});
export const insertConnectorHealthCheckSchema = createInsertSchema(connectorHealthChecks).omit({
  id: true,
  checkedAt: true,
});

export type SuppressionRule = typeof suppressionRules.$inferSelect;
export type InsertSuppressionRule = z.infer<typeof insertSuppressionRuleSchema>;
export type AlertDedupCluster = typeof alertDedupClusters.$inferSelect;
export type InsertAlertDedupCluster = z.infer<typeof insertAlertDedupClusterSchema>;
export type IncidentSlaPolicy = typeof incidentSlaPolicies.$inferSelect;
export type InsertIncidentSlaPolicy = z.infer<typeof insertIncidentSlaPolicySchema>;
export type ConnectorJobRun = typeof connectorJobRuns.$inferSelect;
export type InsertConnectorJobRun = z.infer<typeof insertConnectorJobRunSchema>;
export type ConnectorHealthCheck = typeof connectorHealthChecks.$inferSelect;
export type InsertConnectorHealthCheck = z.infer<typeof insertConnectorHealthCheckSchema>;

export const POLICY_CHECK_SEVERITIES = ["critical", "high", "medium", "low", "informational"] as const;
export const POLICY_CHECK_STATUSES = ["active", "disabled", "draft"] as const;
export const POLICY_RESULT_STATUSES = ["pass", "fail", "error", "skip"] as const;

export const policyChecks = pgTable(
  "policy_checks",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: text("org_id").notNull(),
    name: text("name").notNull(),
    description: text("description"),
    cloudProvider: text("cloud_provider"),
    resourceType: text("resource_type"),
    severity: text("severity").notNull().default("medium"),
    ruleLogic: jsonb("rule_logic").notNull(),
    remediation: text("remediation"),
    complianceFrameworks: text("compliance_frameworks")
      .array()
      .default(sql`ARRAY[]::text[]`),
    controlIds: text("control_ids")
      .array()
      .default(sql`ARRAY[]::text[]`),
    status: text("status").default("active"),
    isBuiltIn: boolean("is_built_in").default(false),
    lastRunAt: timestamp("last_run_at"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_policy_checks_org").on(table.orgId),
    index("idx_policy_checks_provider").on(table.cloudProvider),
    index("idx_policy_checks_status").on(table.status),
  ],
);

export const policyResults = pgTable(
  "policy_results",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: text("org_id").notNull(),
    policyCheckId: varchar("policy_check_id")
      .notNull()
      .references(() => policyChecks.id, { onDelete: "cascade" }),
    scanId: varchar("scan_id"),
    resourceId: text("resource_id").notNull(),
    resourceType: text("resource_type"),
    resourceRegion: text("resource_region"),
    status: text("status").notNull().default("fail"),
    details: jsonb("details").default({}),
    evaluatedAt: timestamp("evaluated_at").defaultNow(),
  },
  (table) => [
    index("idx_policy_results_org").on(table.orgId),
    index("idx_policy_results_check").on(table.policyCheckId),
    index("idx_policy_results_status").on(table.status),
  ],
);

export const COMPLIANCE_CONTROL_FRAMEWORKS = ["nist_csf", "iso_27001", "cis", "soc2"] as const;

export const complianceControls = pgTable(
  "compliance_controls",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    framework: text("framework").notNull(),
    controlId: text("control_id").notNull(),
    title: text("title").notNull(),
    description: text("description"),
    category: text("category"),
    parentControlId: text("parent_control_id"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_compliance_controls_framework").on(table.framework),
    index("idx_compliance_controls_control_id").on(table.controlId),
  ],
);

export const complianceControlMappings = pgTable(
  "compliance_control_mappings",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: text("org_id").notNull(),
    controlId: varchar("control_id")
      .notNull()
      .references(() => complianceControls.id, { onDelete: "cascade" }),
    resourceType: text("resource_type").notNull(),
    resourceId: text("resource_id").notNull(),
    status: text("status").notNull().default("not_assessed"),
    evidenceNotes: text("evidence_notes"),
    lastAssessedAt: timestamp("last_assessed_at"),
    assessedBy: text("assessed_by"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_control_mappings_org").on(table.orgId),
    index("idx_control_mappings_control").on(table.controlId),
    index("idx_control_mappings_resource").on(table.resourceType, table.resourceId),
  ],
);

export const EVIDENCE_LOCKER_TYPES = [
  "screenshot",
  "log",
  "config_snapshot",
  "report",
  "policy_result",
  "scan_result",
  "communication",
  "other",
] as const;
export const EVIDENCE_LOCKER_STATUSES = ["active", "archived", "expired"] as const;

export const evidenceLockerItems = pgTable(
  "evidence_locker_items",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: text("org_id").notNull(),
    title: text("title").notNull(),
    description: text("description"),
    artifactType: text("artifact_type").notNull(),
    framework: text("framework"),
    controlId: text("control_id"),
    storageKey: text("storage_key"),
    url: text("url"),
    mimeType: text("mime_type"),
    fileSize: integer("file_size"),
    checksum: text("checksum"),
    retentionDays: integer("retention_days").default(365),
    expiresAt: timestamp("expires_at"),
    status: text("status").default("active"),
    metadata: jsonb("metadata").default({}),
    tags: text("tags")
      .array()
      .default(sql`ARRAY[]::text[]`),
    uploadedBy: text("uploaded_by"),
    uploadedByName: text("uploaded_by_name"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_evidence_locker_org").on(table.orgId),
    index("idx_evidence_locker_framework").on(table.framework),
    index("idx_evidence_locker_type").on(table.artifactType),
    index("idx_evidence_locker_status").on(table.status),
  ],
);

// ==========================================
// 8.4 — Reporting & Compliance as First-Class Products
// ==========================================

export const REPORT_TEMPLATE_VERSION_STATUSES = ["draft", "active", "deprecated", "archived"] as const;

export const reportTemplateVersions = pgTable(
  "report_template_versions",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: text("org_id").notNull(),
    templateId: varchar("template_id")
      .notNull()
      .references(() => reportTemplates.id, { onDelete: "cascade" }),
    version: integer("version").notNull(),
    changeDescription: text("change_description").notNull(),
    config: text("config"),
    format: text("format"),
    status: text("status").notNull().default("draft"),
    approvedBy: text("approved_by"),
    approvedAt: timestamp("approved_at"),
    createdBy: text("created_by"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_report_tpl_ver_template").on(table.templateId),
    index("idx_report_tpl_ver_org").on(table.orgId),
    uniqueIndex("uq_report_tpl_ver_version").on(table.templateId, table.version),
  ],
);

export const EVIDENCE_ATTACHMENT_STATUSES = ["pending_upload", "uploaded", "verified", "expired", "rejected"] as const;

export const evidenceAttachments = pgTable(
  "evidence_attachments",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: text("org_id").notNull(),
    controlMappingId: varchar("control_mapping_id").references(() => complianceControlMappings.id, {
      onDelete: "cascade",
    }),
    evidenceLockerId: varchar("evidence_locker_id").references(() => evidenceLockerItems.id, { onDelete: "set null" }),
    fileName: text("file_name").notNull(),
    mimeType: text("mime_type"),
    fileSize: integer("file_size"),
    s3Bucket: text("s3_bucket"),
    s3Key: text("s3_key"),
    checksum: text("checksum"),
    status: text("status").notNull().default("pending_upload"),
    reviewedBy: text("reviewed_by"),
    reviewedAt: timestamp("reviewed_at"),
    reviewNotes: text("review_notes"),
    expiresAt: timestamp("expires_at"),
    uploadedBy: text("uploaded_by"),
    uploadedByName: text("uploaded_by_name"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_evidence_attach_org").on(table.orgId),
    index("idx_evidence_attach_mapping").on(table.controlMappingId),
    index("idx_evidence_attach_locker").on(table.evidenceLockerId),
    index("idx_evidence_attach_status").on(table.status),
  ],
);

export const COMPLIANCE_CONTROL_HELPER_TYPES = [
  "gap_analysis",
  "cross_map",
  "coverage_report",
  "readiness_check",
] as const;

export const complianceControlHelpers = pgTable(
  "compliance_control_helpers",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: text("org_id").notNull(),
    helperType: text("helper_type").notNull(),
    sourceFramework: text("source_framework"),
    targetFramework: text("target_framework"),
    result: jsonb("result").default({}),
    status: text("status").notNull().default("pending"),
    createdBy: text("created_by"),
    createdAt: timestamp("created_at").defaultNow(),
    completedAt: timestamp("completed_at"),
  },
  (table) => [
    index("idx_compliance_helpers_org").on(table.orgId),
    index("idx_compliance_helpers_type").on(table.helperType),
  ],
);

export const insertReportTemplateVersionSchema = createInsertSchema(reportTemplateVersions).omit({
  id: true,
  createdAt: true,
  approvedAt: true,
});
export const insertEvidenceAttachmentSchema = createInsertSchema(evidenceAttachments).omit({
  id: true,
  createdAt: true,
  reviewedAt: true,
});
export const insertComplianceControlHelperSchema = createInsertSchema(complianceControlHelpers).omit({
  id: true,
  createdAt: true,
  completedAt: true,
});

export type ReportTemplateVersion = typeof reportTemplateVersions.$inferSelect;
export type InsertReportTemplateVersion = z.infer<typeof insertReportTemplateVersionSchema>;
export type EvidenceAttachment = typeof evidenceAttachments.$inferSelect;
export type InsertEvidenceAttachment = z.infer<typeof insertEvidenceAttachmentSchema>;
export type ComplianceControlHelper = typeof complianceControlHelpers.$inferSelect;
export type InsertComplianceControlHelper = z.infer<typeof insertComplianceControlHelperSchema>;

export const reportTemplateVersionsRelations = relations(reportTemplateVersions, ({ one }) => ({
  template: one(reportTemplates, { fields: [reportTemplateVersions.templateId], references: [reportTemplates.id] }),
}));

export const evidenceAttachmentsRelations = relations(evidenceAttachments, ({ one }) => ({
  controlMapping: one(complianceControlMappings, {
    fields: [evidenceAttachments.controlMappingId],
    references: [complianceControlMappings.id],
  }),
  evidenceLocker: one(evidenceLockerItems, {
    fields: [evidenceAttachments.evidenceLockerId],
    references: [evidenceLockerItems.id],
  }),
}));

export const OUTBOUND_WEBHOOK_EVENTS = [
  "incident.created",
  "incident.updated",
  "incident.closed",
  "incident.escalated",
  "alert.created",
  "alert.correlated",
  "alert.closed",
  "scan.completed",
  "policy.violation",
] as const;

export const outboundWebhooks = pgTable(
  "outbound_webhooks",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: text("org_id").notNull(),
    name: text("name").notNull(),
    url: text("url").notNull(),
    secret: text("secret"),
    events: text("events").array().notNull(),
    isActive: boolean("is_active").default(true),
    retryCount: integer("retry_count").default(3),
    timeoutMs: integer("timeout_ms").default(10000),
    headers: jsonb("headers").default({}),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_outbound_webhooks_org").on(table.orgId),
    index("idx_outbound_webhooks_active").on(table.isActive),
  ],
);

export const outboundWebhookLogs = pgTable(
  "outbound_webhook_logs",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    webhookId: varchar("webhook_id")
      .notNull()
      .references(() => outboundWebhooks.id, { onDelete: "cascade" }),
    event: text("event").notNull(),
    payload: jsonb("payload").default({}),
    responseStatus: integer("response_status"),
    responseBody: text("response_body"),
    attempt: integer("attempt").default(1),
    success: boolean("success").default(false),
    errorMessage: text("error_message"),
    deliveredAt: timestamp("delivered_at").defaultNow(),
  },
  (table) => [
    index("idx_webhook_logs_webhook").on(table.webhookId),
    index("idx_webhook_logs_event").on(table.event),
    index("idx_webhook_logs_delivered").on(table.deliveredAt),
  ],
);

export const idempotencyKeys = pgTable(
  "idempotency_keys",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: text("org_id").notNull(),
    idempotencyKey: text("idempotency_key").notNull(),
    endpoint: text("endpoint").notNull(),
    method: text("method").notNull(),
    responseStatus: integer("response_status"),
    responseBody: jsonb("response_body"),
    expiresAt: timestamp("expires_at").notNull(),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [index("idx_idempotency_org_key").on(table.orgId, table.idempotencyKey, table.endpoint)],
);

export const insertPolicyCheckSchema = createInsertSchema(policyChecks).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
  lastRunAt: true,
});
export const insertPolicyResultSchema = createInsertSchema(policyResults).omit({ id: true, evaluatedAt: true });
export const insertComplianceControlSchema = createInsertSchema(complianceControls).omit({ id: true, createdAt: true });
export const insertComplianceControlMappingSchema = createInsertSchema(complianceControlMappings).omit({
  id: true,
  createdAt: true,
  lastAssessedAt: true,
});
export const insertEvidenceLockerItemSchema = createInsertSchema(evidenceLockerItems).omit({
  id: true,
  createdAt: true,
});
export const insertOutboundWebhookSchema = createInsertSchema(outboundWebhooks).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});
export const insertOutboundWebhookLogSchema = createInsertSchema(outboundWebhookLogs).omit({
  id: true,
  deliveredAt: true,
});
export const insertIdempotencyKeySchema = createInsertSchema(idempotencyKeys).omit({ id: true, createdAt: true });

export type PolicyCheck = typeof policyChecks.$inferSelect;
export type InsertPolicyCheck = z.infer<typeof insertPolicyCheckSchema>;
export type PolicyResult = typeof policyResults.$inferSelect;
export type InsertPolicyResult = z.infer<typeof insertPolicyResultSchema>;
export type ComplianceControl = typeof complianceControls.$inferSelect;
export type InsertComplianceControl = z.infer<typeof insertComplianceControlSchema>;
export type ComplianceControlMapping = typeof complianceControlMappings.$inferSelect;
export type InsertComplianceControlMapping = z.infer<typeof insertComplianceControlMappingSchema>;
export type EvidenceLockerItem = typeof evidenceLockerItems.$inferSelect;
export type InsertEvidenceLockerItem = z.infer<typeof insertEvidenceLockerItemSchema>;
export type OutboundWebhook = typeof outboundWebhooks.$inferSelect;
export type InsertOutboundWebhook = z.infer<typeof insertOutboundWebhookSchema>;
export type OutboundWebhookLog = typeof outboundWebhookLogs.$inferSelect;
export type InsertOutboundWebhookLog = z.infer<typeof insertOutboundWebhookLogSchema>;
export type IdempotencyKey = typeof idempotencyKeys.$inferSelect;
export type InsertIdempotencyKey = z.infer<typeof insertIdempotencyKeySchema>;

export const JOB_TYPES = [
  "connector_sync",
  "threat_enrichment",
  "report_generation",
  "cache_refresh",
  "archive_alerts",
  "daily_stats_rollup",
  "sli_collection",
] as const;
export const JOB_STATUSES = ["pending", "running", "completed", "failed", "cancelled"] as const;
export const DR_CATEGORIES = ["backup", "restore", "failover", "data_recovery", "incident_response"] as const;
export const SLI_SERVICES = ["api", "ingestion", "ai", "enrichment", "connector"] as const;
export const SLI_METRICS = [
  "latency_p50",
  "latency_p95",
  "latency_p99",
  "error_rate",
  "throughput",
  "availability",
] as const;
export const ARCHIVE_REASONS = ["retention", "manual", "cold_storage"] as const;

export const alertsArchive = pgTable(
  "alerts_archive",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id"),
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
    incidentId: varchar("incident_id"),
    correlationScore: real("correlation_score"),
    correlationReason: text("correlation_reason"),
    correlationClusterId: varchar("correlation_cluster_id"),
    suppressed: boolean("suppressed").default(false),
    suppressedBy: varchar("suppressed_by"),
    suppressionRuleId: varchar("suppression_rule_id"),
    confidenceScore: real("confidence_score"),
    confidenceSource: text("confidence_source"),
    confidenceNotes: text("confidence_notes"),
    dedupClusterId: varchar("dedup_cluster_id"),
    occurrenceCount: integer("occurrence_count").default(1),
    analystNotes: text("analyst_notes"),
    assignedTo: varchar("assigned_to"),
    detectedAt: timestamp("detected_at"),
    ingestedAt: timestamp("ingested_at").defaultNow(),
    lastSeenAt: timestamp("last_seen_at"),
    createdAt: timestamp("created_at").defaultNow(),
    archivedAt: timestamp("archived_at").defaultNow(),
    archiveReason: text("archive_reason"),
  },
  (table) => [
    index("idx_alerts_archive_org_archived").on(table.orgId, table.archivedAt),
    index("idx_alerts_archive_org_severity").on(table.orgId, table.severity),
  ],
);

export const jobQueue = pgTable(
  "job_queue",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id"),
    type: text("type").notNull(),
    status: text("status").notNull().default("pending"),
    payload: jsonb("payload"),
    result: jsonb("result"),
    priority: integer("priority").default(0),
    runAt: timestamp("run_at").defaultNow(),
    startedAt: timestamp("started_at"),
    completedAt: timestamp("completed_at"),
    attempts: integer("attempts").default(0),
    maxAttempts: integer("max_attempts").default(3),
    lastError: text("last_error"),
    fingerprint: varchar("fingerprint", { length: 32 }),
    fingerprintExpiresAt: timestamp("fingerprint_expires_at"),
    lockedBy: varchar("locked_by", { length: 64 }),
    lockedUntil: timestamp("locked_until"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_job_queue_status_run").on(table.status, table.runAt),
    index("idx_job_queue_org").on(table.orgId),
    index("idx_job_queue_type_status").on(table.type, table.status),
    index("idx_job_queue_fingerprint").on(table.fingerprint),
    index("idx_job_queue_locked_until").on(table.lockedUntil),
  ],
);

export const dashboardMetricsCache = pgTable(
  "dashboard_metrics_cache",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    metricType: text("metric_type").notNull(),
    payload: jsonb("payload").notNull(),
    generatedAt: timestamp("generated_at").defaultNow(),
    expiresAt: timestamp("expires_at").notNull(),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_dashboard_cache_org_type").on(table.orgId, table.metricType),
    index("idx_dashboard_cache_expires").on(table.expiresAt),
    uniqueIndex("idx_dashboard_cache_org_type_unique").on(table.orgId, table.metricType),
  ],
);

export const alertDailyStats = pgTable(
  "alert_daily_stats",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    date: text("date").notNull(),
    totalAlerts: integer("total_alerts").default(0),
    criticalCount: integer("critical_count").default(0),
    highCount: integer("high_count").default(0),
    mediumCount: integer("medium_count").default(0),
    lowCount: integer("low_count").default(0),
    infoCount: integer("info_count").default(0),
    sourceCounts: jsonb("source_counts"),
    categoryCounts: jsonb("category_counts"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    uniqueIndex("idx_alert_daily_stats_org_date_unique").on(table.orgId, table.date),
    index("idx_alert_daily_stats_org_date").on(table.orgId, table.date),
  ],
);

export const sliMetrics = pgTable(
  "sli_metrics",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    service: text("service").notNull(),
    metric: text("metric").notNull(),
    value: real("value").notNull(),
    labels: jsonb("labels"),
    recordedAt: timestamp("recorded_at").defaultNow(),
  },
  (table) => [
    index("idx_sli_metrics_service_metric_recorded").on(table.service, table.metric, table.recordedAt),
    index("idx_sli_metrics_recorded").on(table.recordedAt),
  ],
);

export const sloTargets = pgTable(
  "slo_targets",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    service: text("service").notNull(),
    metric: text("metric").notNull(),
    endpoint: text("endpoint").notNull().default("*"),
    target: real("target").notNull(),
    operator: text("operator").notNull().default("gte"),
    windowMinutes: integer("window_minutes").notNull().default(60),
    alertOnBreach: boolean("alert_on_breach").default(true),
    description: text("description"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [uniqueIndex("idx_slo_targets_service_metric_endpoint").on(table.service, table.metric, table.endpoint)],
);

export const drRunbooks = pgTable(
  "dr_runbooks",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id"),
    title: text("title").notNull(),
    description: text("description"),
    category: text("category").notNull(),
    steps: jsonb("steps").notNull(),
    rtoMinutes: integer("rto_minutes"),
    rpoMinutes: integer("rpo_minutes"),
    owner: text("owner"),
    lastTestedAt: timestamp("last_tested_at"),
    lastTestResult: text("last_test_result"),
    testNotes: text("test_notes"),
    status: text("status").default("active"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [index("idx_dr_runbooks_org").on(table.orgId), index("idx_dr_runbooks_category").on(table.category)],
);

export const drDrillResults = pgTable(
  "dr_drill_results",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    runbookId: varchar("runbook_id").references(() => drRunbooks.id),
    orgId: varchar("org_id"),
    dryRun: boolean("dry_run").default(true),
    status: text("status").notNull().default("pending"),
    triggeredBy: text("triggered_by").notNull().default("scheduler"),
    rtoTargetMinutes: integer("rto_target_minutes"),
    rpoTargetMinutes: integer("rpo_target_minutes"),
    rtoActualMinutes: real("rto_actual_minutes"),
    rpoActualMinutes: real("rpo_actual_minutes"),
    rtoMet: boolean("rto_met"),
    rpoMet: boolean("rpo_met"),
    stepResults: jsonb("step_results"),
    totalDurationMs: integer("total_duration_ms"),
    errorMessage: text("error_message"),
    notes: text("notes"),
    startedAt: timestamp("started_at").defaultNow(),
    completedAt: timestamp("completed_at"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_dr_drill_results_runbook").on(table.runbookId),
    index("idx_dr_drill_results_org").on(table.orgId),
    index("idx_dr_drill_results_status").on(table.status),
    index("idx_dr_drill_results_created").on(table.createdAt),
  ],
);

export const insertAlertsArchiveSchema = createInsertSchema(alertsArchive).omit({
  id: true,
  ingestedAt: true,
  createdAt: true,
  archivedAt: true,
});
export const insertJobQueueSchema = createInsertSchema(jobQueue).omit({ id: true, createdAt: true });
export const insertDashboardMetricsCacheSchema = createInsertSchema(dashboardMetricsCache).omit({
  id: true,
  generatedAt: true,
  createdAt: true,
});
export const insertAlertDailyStatsSchema = createInsertSchema(alertDailyStats).omit({ id: true, createdAt: true });
export const insertSliMetricsSchema = createInsertSchema(sliMetrics).omit({ id: true, recordedAt: true });
export const insertSloTargetsSchema = createInsertSchema(sloTargets).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});
export const insertDrRunbooksSchema = createInsertSchema(drRunbooks).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});
export const insertDrDrillResultsSchema = createInsertSchema(drDrillResults).omit({
  id: true,
  createdAt: true,
});

export type AlertArchive = typeof alertsArchive.$inferSelect;
export type InsertAlertArchive = z.infer<typeof insertAlertsArchiveSchema>;
export type JobQueue = typeof jobQueue.$inferSelect;
export type InsertJobQueue = z.infer<typeof insertJobQueueSchema>;
export type DashboardMetricsCache = typeof dashboardMetricsCache.$inferSelect;
export type InsertDashboardMetricsCache = z.infer<typeof insertDashboardMetricsCacheSchema>;
export type AlertDailyStats = typeof alertDailyStats.$inferSelect;
export type InsertAlertDailyStats = z.infer<typeof insertAlertDailyStatsSchema>;
export type SliMetric = typeof sliMetrics.$inferSelect;
export type InsertSliMetric = z.infer<typeof insertSliMetricsSchema>;
export type SloTarget = typeof sloTargets.$inferSelect;
export type InsertSloTarget = z.infer<typeof insertSloTargetsSchema>;
export type DrRunbook = typeof drRunbooks.$inferSelect;
export type InsertDrRunbook = z.infer<typeof insertDrRunbooksSchema>;
export type DrDrillResult = typeof drDrillResults.$inferSelect;
export type InsertDrDrillResult = z.infer<typeof insertDrDrillResultsSchema>;

// ==========================================================================
// CVE Entries (for CVE Browser)
// ==========================================================================

export const CVE_SEVERITIES = ["critical", "high", "medium", "low"] as const;

export const cveEntries = pgTable(
  "cve_entries",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    cveId: text("cve_id").notNull().unique(),
    description: text("description").notNull(),
    severity: text("severity").notNull().default("medium"),
    cvssScore: doublePrecision("cvss_score").default(0),
    publishedDate: timestamp("published_date"),
    modifiedDate: timestamp("modified_date"),
    affectedProducts: jsonb("affected_products").default(sql`'[]'::jsonb`),
    references: jsonb("references").default(sql`'[]'::jsonb`),
    cweIds: jsonb("cwe_ids").default(sql`'[]'::jsonb`),
    exploitAvailable: boolean("exploit_available").default(false),
    source: text("source").default("NVD"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_cve_entries_cve_id").on(table.cveId),
    index("idx_cve_entries_severity").on(table.severity),
    index("idx_cve_entries_cvss").on(table.cvssScore),
    index("idx_cve_entries_published").on(table.publishedDate),
  ],
);

export type CveEntry = typeof cveEntries.$inferSelect;
export const insertCveEntrySchema = createInsertSchema(cveEntries).omit({ id: true, createdAt: true });
export type InsertCveEntry = z.infer<typeof insertCveEntrySchema>;

export const TICKET_SYNC_STATUSES = ["pending", "syncing", "synced", "error"] as const;
export const TICKET_SYNC_DIRECTIONS = ["outbound", "inbound", "bidirectional"] as const;

export const ticketSyncJobs = pgTable(
  "ticket_sync_jobs",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id"),
    integrationId: varchar("integration_id")
      .notNull()
      .references(() => integrationConfigs.id, { onDelete: "cascade" }),
    incidentId: varchar("incident_id").references(() => incidents.id),
    externalTicketId: text("external_ticket_id"),
    externalTicketUrl: text("external_ticket_url"),
    direction: text("direction").notNull().default("bidirectional"),
    syncStatus: text("sync_status").notNull().default("pending"),
    lastSyncedAt: timestamp("last_synced_at"),
    lastSyncError: text("last_sync_error"),
    fieldMapping: jsonb("field_mapping").default({}),
    statusMapping: jsonb("status_mapping").default({}),
    commentsMirrored: integer("comments_mirrored").default(0),
    statusSyncs: integer("status_syncs").default(0),
    createdBy: varchar("created_by"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_ticket_sync_org").on(table.orgId),
    index("idx_ticket_sync_integration").on(table.integrationId),
    index("idx_ticket_sync_incident").on(table.incidentId),
  ],
);

export const responseActionApprovals = pgTable(
  "response_action_approvals",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id"),
    actionType: text("action_type").notNull(),
    targetType: text("target_type"),
    targetValue: text("target_value"),
    incidentId: varchar("incident_id").references(() => incidents.id),
    requestPayload: jsonb("request_payload"),
    dryRunResult: jsonb("dry_run_result"),
    status: text("status").notNull().default("pending"),
    requiredApprovers: integer("required_approvers").notNull().default(1),
    currentApprovals: integer("current_approvals").default(0),
    approvers: jsonb("approvers").default([]),
    requestedBy: varchar("requested_by"),
    requestedByName: text("requested_by_name"),
    decidedBy: varchar("decided_by"),
    decidedByName: text("decided_by_name"),
    decisionNote: text("decision_note"),
    expiresAt: timestamp("expires_at"),
    requestedAt: timestamp("requested_at").defaultNow(),
    decidedAt: timestamp("decided_at"),
  },
  (table) => [
    index("idx_resp_approval_org").on(table.orgId),
    index("idx_resp_approval_status").on(table.status),
    index("idx_resp_approval_incident").on(table.incidentId),
  ],
);

/**
 * Individual per-approver decision records for multi-approver workflows.
 *
 * Both response-action approvals and playbook gate approvals are represented
 * via the (approvalSubjectType, approvalSubjectId) polymorphic key so that
 * one table covers all approval types.
 *
 * This supplements the aggregate counters on responseActionApprovals and
 * playbookApprovals with a full immutable vote log: who decided what, when,
 * and why.  These rows must never be deleted; use the audit trail for forensics.
 */
export const approvalDecisionRecords = pgTable(
  "approval_decision_records",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").references(() => organizations.id),
    // matches APPROVAL_SUBJECT_TYPES: "response_action" | "playbook"
    approvalSubjectType: text("approval_subject_type").notNull(),
    // FK to responseActionApprovals.id or playbookApprovals.id depending on approvalSubjectType
    approvalSubjectId: varchar("approval_subject_id").notNull(),
    // matches APPROVAL_DECISIONS: "approved" | "rejected" | "abstained"
    decision: text("decision").notNull(),
    // free-text justification the approver provided with their decision
    reason: text("reason"),
    approverUserId: varchar("approver_user_id").notNull(),
    approverUserName: text("approver_user_name"),
    // role the approver held at the time of the decision (snapshot for audit)
    approverRole: text("approver_role"),
    // IP from which the decision was submitted
    ipAddress: text("ip_address"),
    decidedAt: timestamp("decided_at").defaultNow(),
  },
  (table) => [
    index("idx_approval_decisions_subject").on(table.approvalSubjectType, table.approvalSubjectId),
    index("idx_approval_decisions_approver").on(table.approverUserId),
    index("idx_approval_decisions_org").on(table.orgId),
    index("idx_approval_decisions_decided").on(table.decidedAt),
  ],
);

export const legalHolds = pgTable(
  "legal_holds",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id"),
    name: text("name").notNull(),
    description: text("description"),
    holdType: text("hold_type").notNull().default("full"),
    tableScope: text("table_scope")
      .array()
      .default(sql`ARRAY['alerts','incidents','audit_logs']`),
    filterCriteria: jsonb("filter_criteria").default({}),
    reason: text("reason"),
    caseReference: text("case_reference"),
    isActive: boolean("is_active").default(true),
    activatedBy: varchar("activated_by"),
    activatedByName: text("activated_by_name"),
    deactivatedBy: varchar("deactivated_by"),
    deactivatedAt: timestamp("deactivated_at"),
    activatedAt: timestamp("activated_at").defaultNow(),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [index("idx_legal_holds_org").on(table.orgId), index("idx_legal_holds_active").on(table.isActive)],
);

export const connectorSecretRotations = pgTable(
  "connector_secret_rotations",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    connectorId: varchar("connector_id")
      .notNull()
      .references(() => connectors.id, { onDelete: "cascade" }),
    orgId: varchar("org_id"),
    secretField: text("secret_field").notNull(),
    lastRotatedAt: timestamp("last_rotated_at"),
    nextRotationDue: timestamp("next_rotation_due"),
    rotationIntervalDays: integer("rotation_interval_days").default(90),
    status: text("status").notNull().default("current"),
    rotatedBy: varchar("rotated_by"),
    rotatedByName: text("rotated_by_name"),
    reminderSentAt: timestamp("reminder_sent_at"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_secret_rotation_connector").on(table.connectorId),
    index("idx_secret_rotation_due").on(table.nextRotationDue),
  ],
);

export const insertTicketSyncJobSchema = createInsertSchema(ticketSyncJobs).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});
export const insertResponseActionApprovalSchema = createInsertSchema(responseActionApprovals).omit({
  id: true,
  requestedAt: true,
  decidedAt: true,
});
export const insertApprovalDecisionRecordSchema = createInsertSchema(approvalDecisionRecords).omit({
  id: true,
  decidedAt: true,
});
export const insertLegalHoldSchema = createInsertSchema(legalHolds).omit({
  id: true,
  createdAt: true,
  activatedAt: true,
});
export const insertConnectorSecretRotationSchema = createInsertSchema(connectorSecretRotations).omit({
  id: true,
  createdAt: true,
});

export type TicketSyncJob = typeof ticketSyncJobs.$inferSelect;
export type InsertTicketSyncJob = z.infer<typeof insertTicketSyncJobSchema>;
export type ResponseActionApproval = typeof responseActionApprovals.$inferSelect;
export type InsertResponseActionApproval = z.infer<typeof insertResponseActionApprovalSchema>;
export type ApprovalDecisionRecord = typeof approvalDecisionRecords.$inferSelect;
export type InsertApprovalDecisionRecord = z.infer<typeof insertApprovalDecisionRecordSchema>;
export type LegalHold = typeof legalHolds.$inferSelect;
export type InsertLegalHold = z.infer<typeof insertLegalHoldSchema>;
export type ConnectorSecretRotation = typeof connectorSecretRotations.$inferSelect;
export type InsertConnectorSecretRotation = z.infer<typeof insertConnectorSecretRotationSchema>;

// ============================
// Commercial / Operations
// ============================

export const PLAN_TIERS = ["free", "starter", "professional", "enterprise"] as const;
export const USAGE_METRIC_TYPES = [
  "events_ingested",
  "connectors_active",
  "ai_tokens_used",
  "automation_runs",
  "api_calls",
  "storage_bytes",
] as const;

export const orgPlanLimits = pgTable(
  "org_plan_limits",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    planTier: text("plan_tier").notNull().default("free"),
    eventsPerMonth: integer("events_per_month").notNull().default(10000),
    maxConnectors: integer("max_connectors").notNull().default(3),
    aiTokensPerMonth: integer("ai_tokens_per_month").notNull().default(5000),
    automationRunsPerMonth: integer("automation_runs_per_month").notNull().default(100),
    apiCallsPerMonth: integer("api_calls_per_month").notNull().default(10000),
    storageGb: integer("storage_gb").notNull().default(5),
    softThresholdPct: integer("soft_threshold_pct").notNull().default(80),
    hardThresholdPct: integer("hard_threshold_pct").notNull().default(95),
    overageAllowed: boolean("overage_allowed").default(false),
    billingCycleStart: timestamp("billing_cycle_start").defaultNow(),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [uniqueIndex("idx_org_plan_unique").on(table.orgId)],
);

export const usageMeterSnapshots = pgTable(
  "usage_meter_snapshots",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    metricType: text("metric_type").notNull(),
    periodStart: timestamp("period_start").notNull(),
    periodEnd: timestamp("period_end").notNull(),
    currentValue: integer("current_value").notNull().default(0),
    limitValue: integer("limit_value"),
    pctUsed: real("pct_used").default(0),
    metadata: jsonb("metadata").default({}),
    snapshotAt: timestamp("snapshot_at").defaultNow(),
  },
  (table) => [
    index("idx_usage_meter_org").on(table.orgId),
    index("idx_usage_meter_type").on(table.metricType),
    index("idx_usage_meter_period").on(table.periodStart, table.periodEnd),
  ],
);

export const onboardingProgress = pgTable(
  "onboarding_progress",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    stepKey: text("step_key").notNull(),
    stepLabel: text("step_label").notNull(),
    stepDescription: text("step_description"),
    category: text("category").notNull().default("setup"),
    sortOrder: integer("sort_order").notNull().default(0),
    isCompleted: boolean("is_completed").default(false),
    completedAt: timestamp("completed_at"),
    completedBy: varchar("completed_by"),
    targetUrl: text("target_url"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    uniqueIndex("idx_onboarding_org_step").on(table.orgId, table.stepKey),
    index("idx_onboarding_org").on(table.orgId),
  ],
);

export const workspaceTemplates = pgTable("workspace_templates", {
  id: varchar("id")
    .primaryKey()
    .default(sql`gen_random_uuid()`),
  name: text("name").notNull(),
  slug: text("slug").notNull().unique(),
  description: text("description"),
  category: text("category").notNull().default("general"),
  icon: text("icon"),
  isDefault: boolean("is_default").default(false),
  config: jsonb("config").notNull().default({}),
  connectorsConfig: jsonb("connectors_config").default([]),
  playbooksConfig: jsonb("playbooks_config").default([]),
  notificationConfig: jsonb("notification_config").default([]),
  complianceConfig: jsonb("compliance_config").default({}),
  dashboardLayout: jsonb("dashboard_layout").default({}),
  createdAt: timestamp("created_at").defaultNow(),
});

export const insertOrgPlanLimitsSchema = createInsertSchema(orgPlanLimits).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});
export const insertUsageMeterSnapshotSchema = createInsertSchema(usageMeterSnapshots).omit({
  id: true,
  snapshotAt: true,
});
export const insertOnboardingProgressSchema = createInsertSchema(onboardingProgress).omit({
  id: true,
  createdAt: true,
});
export const insertWorkspaceTemplateSchema = createInsertSchema(workspaceTemplates).omit({ id: true, createdAt: true });
export const insertWizardProgressSchema = createInsertSchema(wizardProgress).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export type OrgPlanLimit = typeof orgPlanLimits.$inferSelect;
export type InsertOrgPlanLimit = z.infer<typeof insertOrgPlanLimitsSchema>;
export type UsageMeterSnapshot = typeof usageMeterSnapshots.$inferSelect;
export type InsertUsageMeterSnapshot = z.infer<typeof insertUsageMeterSnapshotSchema>;
export type OnboardingProgressItem = typeof onboardingProgress.$inferSelect;
export type InsertOnboardingProgress = z.infer<typeof insertOnboardingProgressSchema>;
export type WorkspaceTemplate = typeof workspaceTemplates.$inferSelect;
export type InsertWorkspaceTemplate = z.infer<typeof insertWorkspaceTemplateSchema>;
export type WizardProgress = typeof wizardProgress.$inferSelect;
export type InsertWizardProgress = z.infer<typeof insertWizardProgressSchema>;

// ============================
// Feature Flags
// ============================

export const featureFlags = pgTable(
  "feature_flags",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    key: text("key").notNull().unique(),
    name: text("name").notNull(),
    description: text("description"),
    enabled: boolean("enabled").default(false),
    rolloutPct: integer("rollout_pct").default(100),
    targetOrgs: text("target_orgs")
      .array()
      .default(sql`ARRAY[]::text[]`),
    targetRoles: text("target_roles")
      .array()
      .default(sql`ARRAY[]::text[]`),
    metadata: jsonb("metadata").default({}),
    createdBy: varchar("created_by"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [index("idx_feature_flags_key").on(table.key), index("idx_feature_flags_enabled").on(table.enabled)],
);

export const insertFeatureFlagSchema = createInsertSchema(featureFlags).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export type FeatureFlag = typeof featureFlags.$inferSelect;
export type InsertFeatureFlag = z.infer<typeof insertFeatureFlagSchema>;

// ============================
// Outbox / Event Replay
// ============================

export const OUTBOX_EVENT_STATUSES = ["pending", "dispatched", "failed", "replayed"] as const;
export const OUTBOX_EVENT_TYPES = [
  "alert.created",
  "alert.updated",
  "alert.correlated",
  "alert.closed",
  "incident.created",
  "incident.updated",
  "incident.closed",
  "incident.escalated",
  "connector.synced",
  "connector.failed",
  "response_action.executed",
  "response_action.failed",
  "scan.completed",
  "policy.violation",
  "enrichment.completed",
  "report.generated",
] as const;

export const outboxEvents = pgTable(
  "outbox_events",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id"),
    eventType: text("event_type").notNull(),
    aggregateType: text("aggregate_type").notNull(),
    aggregateId: varchar("aggregate_id").notNull(),
    payload: jsonb("payload").notNull(),
    status: text("status").notNull().default("pending"),
    fingerprint: text("fingerprint").notNull(),
    dispatchedAt: timestamp("dispatched_at"),
    attempts: integer("attempts").default(0),
    maxAttempts: integer("max_attempts").default(5),
    lastError: text("last_error"),
    nextRetryAt: timestamp("next_retry_at"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_outbox_status_next_retry").on(table.status, table.nextRetryAt),
    index("idx_outbox_org").on(table.orgId),
    index("idx_outbox_aggregate").on(table.aggregateType, table.aggregateId),
    index("idx_outbox_fingerprint").on(table.fingerprint),
    index("idx_outbox_event_type").on(table.eventType),
  ],
);

export const insertOutboxEventSchema = createInsertSchema(outboxEvents).omit({
  id: true,
  createdAt: true,
  dispatchedAt: true,
});

export type OutboxEvent = typeof outboxEvents.$inferSelect;
export type InsertOutboxEvent = z.infer<typeof insertOutboxEventSchema>;

// ============================
// Enterprise Org Identity Lifecycle (8.1)
// ============================

export const DOMAIN_VERIFICATION_METHODS = ["dns_txt", "dns_cname", "meta_tag"] as const;
export const DOMAIN_VERIFICATION_STATUSES = ["pending", "verified", "failed", "expired"] as const;
export const SSO_PROVIDER_TYPES = ["saml", "oidc", "google", "github"] as const;
export const SECURITY_POLICY_TYPES = ["mfa", "session", "password", "device", "ip_allowlist"] as const;

export const orgSecurityPolicies = pgTable(
  "org_security_policies",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    mfaRequired: boolean("mfa_required").notNull().default(false),
    sessionTimeoutMinutes: integer("session_timeout_minutes").notNull().default(480),
    maxConcurrentSessions: integer("max_concurrent_sessions").notNull().default(5),
    passwordMinLength: integer("password_min_length").notNull().default(12),
    passwordRequireUppercase: boolean("password_require_uppercase").notNull().default(true),
    passwordRequireNumber: boolean("password_require_number").notNull().default(true),
    passwordRequireSpecial: boolean("password_require_special").notNull().default(true),
    passwordExpiryDays: integer("password_expiry_days").notNull().default(90),
    ipAllowlistEnabled: boolean("ip_allowlist_enabled").notNull().default(false),
    ipAllowlistCidrs: text("ip_allowlist_cidrs")
      .array()
      .default(sql`ARRAY[]::text[]`),
    deviceTrustRequired: boolean("device_trust_required").notNull().default(false),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [uniqueIndex("idx_org_security_policies_org").on(table.orgId)],
);

export const orgDomainVerifications = pgTable(
  "org_domain_verifications",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    domain: text("domain").notNull(),
    verificationMethod: text("verification_method").notNull().default("dns_txt"),
    verificationToken: text("verification_token").notNull(),
    status: text("status").notNull().default("pending"),
    verifiedAt: timestamp("verified_at"),
    expiresAt: timestamp("expires_at"),
    lastCheckedAt: timestamp("last_checked_at"),
    autoJoin: boolean("auto_join").notNull().default(false),
    defaultRole: text("default_role").notNull().default("analyst"),
    createdBy: varchar("created_by"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    uniqueIndex("idx_domain_verifications_org_domain").on(table.orgId, table.domain),
    uniqueIndex("idx_domain_verifications_domain").on(table.domain),
    index("idx_domain_verifications_org").on(table.orgId),
    index("idx_domain_verifications_status").on(table.status),
  ],
);

export const orgSsoConfigs = pgTable(
  "org_sso_configs",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    providerType: text("provider_type").notNull(),
    enforced: boolean("enforced").notNull().default(false),
    metadataUrl: text("metadata_url"),
    entityId: text("entity_id"),
    ssoUrl: text("sso_url"),
    certificate: text("certificate"),
    clientId: text("client_id"),
    clientSecret: text("client_secret"),
    allowedDomains: text("allowed_domains")
      .array()
      .default(sql`ARRAY[]::text[]`),
    autoProvision: boolean("auto_provision").notNull().default(true),
    defaultRole: text("default_role").notNull().default("analyst"),
    enabled: boolean("enabled").notNull().default(false),
    createdBy: varchar("created_by"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [uniqueIndex("idx_sso_configs_org").on(table.orgId)],
);

export const orgScimConfigs = pgTable(
  "org_scim_configs",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    enabled: boolean("enabled").notNull().default(false),
    endpointUrl: text("endpoint_url"),
    bearerTokenHash: text("bearer_token_hash"),
    bearerTokenPrefix: text("bearer_token_prefix"),
    defaultRole: text("default_role").notNull().default("analyst"),
    autoDeprovision: boolean("auto_deprovision").notNull().default(true),
    lastSyncAt: timestamp("last_sync_at"),
    lastSyncStatus: text("last_sync_status"),
    lastSyncUserCount: integer("last_sync_user_count").default(0),
    createdBy: varchar("created_by"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [uniqueIndex("idx_scim_configs_org").on(table.orgId)],
);

export const insertOrgSecurityPolicySchema = createInsertSchema(orgSecurityPolicies).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});
export const insertOrgDomainVerificationSchema = createInsertSchema(orgDomainVerifications).omit({
  id: true,
  createdAt: true,
});
export const insertOrgSsoConfigSchema = createInsertSchema(orgSsoConfigs).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});
export const insertOrgScimConfigSchema = createInsertSchema(orgScimConfigs).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export type OrgSecurityPolicy = typeof orgSecurityPolicies.$inferSelect;
export type InsertOrgSecurityPolicy = z.infer<typeof insertOrgSecurityPolicySchema>;
export type OrgDomainVerification = typeof orgDomainVerifications.$inferSelect;
export type InsertOrgDomainVerification = z.infer<typeof insertOrgDomainVerificationSchema>;
export type OrgSsoConfig = typeof orgSsoConfigs.$inferSelect;
export type InsertOrgSsoConfig = z.infer<typeof insertOrgSsoConfigSchema>;
export type OrgScimConfig = typeof orgScimConfigs.$inferSelect;
export type InsertOrgScimConfig = z.infer<typeof insertOrgScimConfigSchema>;

// ============================
// Relations for RBAC + Saved Views tables
// (placed here — after all table declarations — to satisfy TS temporal dead zone)
// ============================

export const orgRolesRelations = relations(orgRoles, ({ one, many }) => ({
  organization: one(organizations, { fields: [orgRoles.orgId], references: [organizations.id] }),
  permissions: many(orgRolePermissions),
  memberships: many(organizationMemberships),
}));

export const orgRolePermissionsRelations = relations(orgRolePermissions, ({ one }) => ({
  role: one(orgRoles, { fields: [orgRolePermissions.roleId], references: [orgRoles.id] }),
}));

export const orgTeamsRelations = relations(orgTeams, ({ one, many }) => ({
  organization: one(organizations, { fields: [orgTeams.orgId], references: [organizations.id] }),
  teamMemberships: many(orgTeamMemberships),
  savedViews: many(savedViews),
}));

export const orgTeamMembershipsRelations = relations(orgTeamMemberships, ({ one }) => ({
  team: one(orgTeams, { fields: [orgTeamMemberships.teamId], references: [orgTeams.id] }),
}));

export const organizationMembershipsRelations = relations(organizationMemberships, ({ one }) => ({
  organization: one(organizations, { fields: [organizationMemberships.orgId], references: [organizations.id] }),
  customRole: one(orgRoles, { fields: [organizationMemberships.customRoleId], references: [orgRoles.id] }),
}));

export const savedViewsRelations = relations(savedViews, ({ one }) => ({
  organization: one(organizations, { fields: [savedViews.orgId], references: [organizations.id] }),
  team: one(orgTeams, { fields: [savedViews.teamId], references: [orgTeams.id] }),
}));

export const auditVerificationRunsRelations = relations(auditVerificationRuns, ({ one }) => ({
  organization: one(organizations, { fields: [auditVerificationRuns.orgId], references: [organizations.id] }),
}));

export const approvalDecisionRecordsRelations = relations(approvalDecisionRecords, ({ one }) => ({
  organization: one(organizations, { fields: [approvalDecisionRecords.orgId], references: [organizations.id] }),
}));

// ── 10.3 Large-table archival tables ────────────────────────────────────────

export const endpointTelemetryArchive = pgTable(
  "endpoint_telemetry_archive",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: text("org_id").notNull(),
    assetId: varchar("asset_id").notNull(),
    metricType: text("metric_type").notNull(),
    metricValue: jsonb("metric_value").notNull(),
    collectedAt: timestamp("collected_at"),
    archivedAt: timestamp("archived_at").defaultNow(),
    archiveReason: text("archive_reason").default("retention"),
  },
  (table) => [
    index("idx_telemetry_archive_org_archived").on(table.orgId, table.archivedAt),
    index("idx_telemetry_archive_asset").on(table.assetId, table.archivedAt),
  ],
);

export const ingestionLogsArchive = pgTable(
  "ingestion_logs_archive",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id"),
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
    receivedAt: timestamp("received_at"),
    archivedAt: timestamp("archived_at").defaultNow(),
    archiveReason: text("archive_reason").default("retention"),
  },
  (table) => [index("idx_ingestion_archive_org_archived").on(table.orgId, table.archivedAt)],
);

export const connectorJobRunsArchive = pgTable(
  "connector_job_runs_archive",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    connectorId: varchar("connector_id").notNull(),
    orgId: varchar("org_id"),
    status: text("status").notNull().default("running"),
    attempt: integer("attempt").notNull().default(1),
    alertsReceived: integer("alerts_received").default(0),
    alertsCreated: integer("alerts_created").default(0),
    alertsDeduped: integer("alerts_deduped").default(0),
    alertsFailed: integer("alerts_failed").default(0),
    latencyMs: integer("latency_ms"),
    errorMessage: text("error_message"),
    startedAt: timestamp("started_at"),
    completedAt: timestamp("completed_at"),
    archivedAt: timestamp("archived_at").defaultNow(),
    archiveReason: text("archive_reason").default("retention"),
  },
  (table) => [
    index("idx_connector_runs_archive_org").on(table.orgId, table.archivedAt),
    index("idx_connector_runs_archive_connector").on(table.connectorId, table.archivedAt),
  ],
);

// ── 10.3 Partition management tracking ──────────────────────────────────────

export const tablePartitions = pgTable(
  "table_partitions",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    tableName: text("table_name").notNull(),
    partitionName: text("partition_name").notNull(),
    rangeStart: timestamp("range_start").notNull(),
    rangeEnd: timestamp("range_end").notNull(),
    rowCountEstimate: integer("row_count_estimate").default(0),
    sizeBytes: integer("size_bytes").default(0),
    status: text("status").notNull().default("active"),
    createdAt: timestamp("created_at").defaultNow(),
    detachedAt: timestamp("detached_at"),
  },
  (table) => [
    uniqueIndex("idx_table_partitions_unique").on(table.tableName, table.partitionName),
    index("idx_table_partitions_table_status").on(table.tableName, table.status),
  ],
);

// ── 11.1 SLI metrics rollup tables ─────────────────────────────────────────

export const sliMetricsHourly = pgTable(
  "sli_metrics_hourly",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    service: text("service").notNull(),
    metric: text("metric").notNull(),
    hour: timestamp("hour").notNull(),
    minValue: real("min_value").notNull(),
    maxValue: real("max_value").notNull(),
    avgValue: real("avg_value").notNull(),
    p50Value: real("p50_value"),
    p95Value: real("p95_value"),
    p99Value: real("p99_value"),
    sampleCount: integer("sample_count").notNull().default(0),
    labels: jsonb("labels"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    uniqueIndex("idx_sli_hourly_unique").on(table.service, table.metric, table.hour),
    index("idx_sli_hourly_hour").on(table.hour),
    index("idx_sli_hourly_service_hour").on(table.service, table.hour),
  ],
);

export const sliMetricsDaily = pgTable(
  "sli_metrics_daily",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    service: text("service").notNull(),
    metric: text("metric").notNull(),
    day: timestamp("day").notNull(),
    minValue: real("min_value").notNull(),
    maxValue: real("max_value").notNull(),
    avgValue: real("avg_value").notNull(),
    p50Value: real("p50_value"),
    p95Value: real("p95_value"),
    p99Value: real("p99_value"),
    sampleCount: integer("sample_count").notNull().default(0),
    labels: jsonb("labels"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    uniqueIndex("idx_sli_daily_unique").on(table.service, table.metric, table.day),
    index("idx_sli_daily_day").on(table.day),
    index("idx_sli_daily_service_day").on(table.service, table.day),
  ],
);

export type EndpointTelemetryArchive = typeof endpointTelemetryArchive.$inferSelect;
export type IngestionLogsArchive = typeof ingestionLogsArchive.$inferSelect;
export type ConnectorJobRunsArchive = typeof connectorJobRunsArchive.$inferSelect;
export type TablePartition = typeof tablePartitions.$inferSelect;
export type SliMetricHourly = typeof sliMetricsHourly.$inferSelect;
export type SliMetricDaily = typeof sliMetricsDaily.$inferSelect;

// ============================
// Subscription & Billing (Phase 3)
// ============================

export const BILLING_PLAN_TIERS = ["free", "pro", "enterprise", "custom"] as const;
export const SUBSCRIPTION_STATUSES = ["trialing", "active", "past_due", "cancelled", "paused"] as const;
export const BILLING_CYCLES = ["monthly", "annual"] as const;
export const INVOICE_STATUSES = ["draft", "open", "paid", "void", "uncollectible"] as const;

export const plans = pgTable(
  "plans",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    name: text("name").notNull().unique(),
    displayName: text("display_name").notNull(),
    description: text("description"),
    monthlyPriceCents: integer("monthly_price_cents").notNull().default(0),
    annualPriceCents: integer("annual_price_cents").notNull().default(0),
    stripePriceIdMonthly: text("stripe_price_id_monthly"),
    stripePriceIdAnnual: text("stripe_price_id_annual"),
    features: jsonb("features").notNull().default({}),
    isActive: boolean("is_active").default(true),
    sortOrder: integer("sort_order").notNull().default(0),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [index("idx_plans_active").on(table.isActive), index("idx_plans_sort").on(table.sortOrder)],
);

export const subscriptions = pgTable(
  "subscriptions",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    planId: varchar("plan_id")
      .notNull()
      .references(() => plans.id),
    status: text("status").notNull().default("active"),
    billingCycle: text("billing_cycle").notNull().default("monthly"),
    stripeCustomerId: text("stripe_customer_id"),
    stripeSubscriptionId: text("stripe_subscription_id"),
    trialEndDate: timestamp("trial_end_date"),
    currentPeriodStart: timestamp("current_period_start"),
    currentPeriodEnd: timestamp("current_period_end"),
    cancelledAt: timestamp("cancelled_at"),
    cancelReason: text("cancel_reason"),
    customOverrides: jsonb("custom_overrides"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    uniqueIndex("idx_subscriptions_org").on(table.orgId),
    index("idx_subscriptions_stripe_customer").on(table.stripeCustomerId),
    index("idx_subscriptions_status").on(table.status),
  ],
);

export const invoices = pgTable(
  "invoices",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    subscriptionId: varchar("subscription_id").references(() => subscriptions.id),
    stripeInvoiceId: text("stripe_invoice_id").unique(),
    amountDueCents: integer("amount_due_cents").notNull().default(0),
    amountPaidCents: integer("amount_paid_cents").notNull().default(0),
    currency: text("currency").notNull().default("usd"),
    status: text("status").notNull().default("draft"),
    pdfUrl: text("pdf_url"),
    hostedUrl: text("hosted_url"),
    periodStart: timestamp("period_start"),
    periodEnd: timestamp("period_end"),
    paidAt: timestamp("paid_at"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_invoices_org").on(table.orgId),
    index("idx_invoices_subscription").on(table.subscriptionId),
    index("idx_invoices_stripe").on(table.stripeInvoiceId),
  ],
);

export const subscriptionsRelations = relations(subscriptions, ({ one }) => ({
  organization: one(organizations, { fields: [subscriptions.orgId], references: [organizations.id] }),
  plan: one(plans, { fields: [subscriptions.planId], references: [plans.id] }),
}));

export const invoicesRelations = relations(invoices, ({ one }) => ({
  organization: one(organizations, { fields: [invoices.orgId], references: [organizations.id] }),
  subscription: one(subscriptions, { fields: [invoices.subscriptionId], references: [subscriptions.id] }),
}));

export const insertPlanSchema = createInsertSchema(plans).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});
export const insertSubscriptionSchema = createInsertSchema(subscriptions).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});
export const insertInvoiceSchema = createInsertSchema(invoices).omit({
  id: true,
  createdAt: true,
});

export type Plan = typeof plans.$inferSelect;
export type InsertPlan = z.infer<typeof insertPlanSchema>;
export type Subscription = typeof subscriptions.$inferSelect;
export type InsertSubscription = z.infer<typeof insertSubscriptionSchema>;
export type Invoice = typeof invoices.$inferSelect;
export type InsertInvoice = z.infer<typeof insertInvoiceSchema>;

// Phase 4: Password Reset Tokens
export const passwordResetTokens = pgTable(
  "password_reset_tokens",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    userId: varchar("user_id").notNull(),
    token: text("token").notNull().unique(),
    expiresAt: timestamp("expires_at").notNull(),
    usedAt: timestamp("used_at"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [index("idx_password_reset_user").on(table.userId), index("idx_password_reset_token").on(table.token)],
);

export const insertPasswordResetTokenSchema = createInsertSchema(passwordResetTokens).omit({
  id: true,
  createdAt: true,
});

export type PasswordResetToken = typeof passwordResetTokens.$inferSelect;
export type InsertPasswordResetToken = z.infer<typeof insertPasswordResetTokenSchema>;

// Phase 7: MSSP / Parent-Child Organizations
export const MSSP_ACCESS_GRANT_ROLES = ["viewer", "analyst", "manager", "admin"] as const;

export const msspAccessGrants = pgTable(
  "mssp_access_grants",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    parentOrgId: varchar("parent_org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    childOrgId: varchar("child_org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    grantedRole: text("granted_role").notNull().default("viewer"),
    scope: jsonb("scope").notNull().default({}),
    grantedBy: varchar("granted_by").notNull(),
    grantedAt: timestamp("granted_at").defaultNow(),
    revokedAt: timestamp("revoked_at"),
    revokedBy: varchar("revoked_by"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_mssp_grant_parent_child").on(table.parentOrgId, table.childOrgId),
    index("idx_mssp_grant_parent").on(table.parentOrgId),
    index("idx_mssp_grant_child").on(table.childOrgId),
  ],
);

export const msspAccessGrantsRelations = relations(msspAccessGrants, ({ one }) => ({
  parentOrg: one(organizations, {
    fields: [msspAccessGrants.parentOrgId],
    references: [organizations.id],
    relationName: "msspParent",
  }),
  childOrg: one(organizations, {
    fields: [msspAccessGrants.childOrgId],
    references: [organizations.id],
    relationName: "msspChild",
  }),
}));

export const insertMsspAccessGrantSchema = createInsertSchema(msspAccessGrants).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
  grantedAt: true,
  revokedAt: true,
  revokedBy: true,
});

export type MsspAccessGrant = typeof msspAccessGrants.$inferSelect;
export type InsertMsspAccessGrant = z.infer<typeof insertMsspAccessGrantSchema>;

// Phase 8: Usage Metering & Plan Enforcement
export const USAGE_METRIC_NAMES = [
  "alerts_ingested",
  "api_calls",
  "ai_analyses",
  "storage_bytes",
  "connector_syncs",
  "connectors",
  "users",
  "api_keys",
  "playbooks",
] as const;

export const usageRecords = pgTable(
  "usage_records",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    metric: text("metric").notNull(),
    value: integer("value").notNull().default(0),
    periodStart: timestamp("period_start").notNull(),
    periodEnd: timestamp("period_end").notNull(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    uniqueIndex("idx_usage_records_org_metric_period").on(table.orgId, table.metric, table.periodStart),
    index("idx_usage_records_org").on(table.orgId),
    index("idx_usage_records_period").on(table.periodStart, table.periodEnd),
  ],
);

export const usageRecordsRelations = relations(usageRecords, ({ one }) => ({
  organization: one(organizations, { fields: [usageRecords.orgId], references: [organizations.id] }),
}));

export const insertUsageRecordSchema = createInsertSchema(usageRecords).omit({
  id: true,
  updatedAt: true,
});

export type UsageRecord = typeof usageRecords.$inferSelect;
export type InsertUsageRecord = z.infer<typeof insertUsageRecordSchema>;

// Engine Controls: per-org, per-engine policy tuning, dry-run, explainability
export const ENGINE_NAMES = ["predictive", "pii", "posture", "rollback"] as const;

export const engineConfigs = pgTable(
  "engine_configs",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    engineName: text("engine_name").notNull(),
    enabled: boolean("enabled").notNull().default(true),
    dryRunMode: boolean("dry_run_mode").notNull().default(false),
    policyConfig: jsonb("policy_config").notNull().default({}),
    lastDryRunAt: timestamp("last_dry_run_at"),
    lastDryRunResult: jsonb("last_dry_run_result"),
    updatedBy: varchar("updated_by"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    uniqueIndex("idx_engine_configs_org_engine").on(table.orgId, table.engineName),
    index("idx_engine_configs_org").on(table.orgId),
  ],
);

export const engineConfigsRelations = relations(engineConfigs, ({ one }) => ({
  organization: one(organizations, { fields: [engineConfigs.orgId], references: [organizations.id] }),
}));

export const insertEngineConfigSchema = createInsertSchema(engineConfigs).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export type EngineConfig = typeof engineConfigs.$inferSelect;
export type InsertEngineConfig = z.infer<typeof insertEngineConfigSchema>;

export const engineDryRuns = pgTable(
  "engine_dry_runs",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    engineName: text("engine_name").notNull(),
    inputParams: jsonb("input_params").notNull().default({}),
    simulatedResult: jsonb("simulated_result"),
    status: text("status").notNull().default("pending"),
    durationMs: integer("duration_ms"),
    executedBy: varchar("executed_by"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_engine_dry_runs_org").on(table.orgId),
    index("idx_engine_dry_runs_engine").on(table.orgId, table.engineName),
  ],
);

export const engineDryRunsRelations = relations(engineDryRuns, ({ one }) => ({
  organization: one(organizations, { fields: [engineDryRuns.orgId], references: [organizations.id] }),
}));

export const insertEngineDryRunSchema = createInsertSchema(engineDryRuns).omit({
  id: true,
  createdAt: true,
});

export type EngineDryRun = typeof engineDryRuns.$inferSelect;
export type InsertEngineDryRun = z.infer<typeof insertEngineDryRunSchema>;

export const engineExplainabilityLogs = pgTable(
  "engine_explainability_logs",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    engineName: text("engine_name").notNull(),
    executionId: varchar("execution_id"),
    decisionType: text("decision_type").notNull(),
    decisionOutcome: text("decision_outcome").notNull(),
    drivers: jsonb("drivers").notNull().default([]),
    confidence: integer("confidence"),
    inputSnapshot: jsonb("input_snapshot"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_engine_explain_org").on(table.orgId),
    index("idx_engine_explain_engine").on(table.orgId, table.engineName),
  ],
);

export const engineExplainabilityLogsRelations = relations(engineExplainabilityLogs, ({ one }) => ({
  organization: one(organizations, { fields: [engineExplainabilityLogs.orgId], references: [organizations.id] }),
}));

export const insertEngineExplainabilityLogSchema = createInsertSchema(engineExplainabilityLogs).omit({
  id: true,
  createdAt: true,
});

export type EngineExplainabilityLog = typeof engineExplainabilityLogs.$inferSelect;
export type InsertEngineExplainabilityLog = z.infer<typeof insertEngineExplainabilityLogSchema>;

export const PROMPT_TIERS = ["triage", "narrative", "correlation", "health", "general"] as const;

export const aiPrompts = pgTable(
  "ai_prompts",
  {
    id: varchar("id").primaryKey(),
    orgId: varchar("org_id"),
    name: varchar("name").notNull(),
    description: text("description").notNull().default(""),
    tier: varchar("tier").notNull().default("general"),
    systemPrompt: text("system_prompt").notNull(),
    userTemplate: text("user_template").notNull(),
    outputSchema: jsonb("output_schema"),
    maxTokens: integer("max_tokens").notNull().default(2048),
    temperature: doublePrecision("temperature").notNull().default(0.1),
    version: integer("version").notNull().default(1),
    deprecated: boolean("deprecated").notNull().default(false),
    deprecatedAt: timestamp("deprecated_at"),
    supersededBy: varchar("superseded_by"),
    tags: jsonb("tags").notNull().default([]),
    isActive: boolean("is_active").notNull().default(true),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [index("idx_ai_prompts_org").on(table.orgId), index("idx_ai_prompts_tier").on(table.tier)],
);

export const aiPromptsRelations = relations(aiPrompts, ({ one }) => ({
  organization: one(organizations, { fields: [aiPrompts.orgId], references: [organizations.id] }),
}));

export const insertAiPromptSchema = createInsertSchema(aiPrompts).omit({
  createdAt: true,
  updatedAt: true,
});

export type AiPrompt = typeof aiPrompts.$inferSelect;
export type InsertAiPrompt = z.infer<typeof insertAiPromptSchema>;

export const aiPromptVersions = pgTable(
  "ai_prompt_versions",
  {
    id: integer("id").primaryKey().generatedAlwaysAsIdentity(),
    promptId: varchar("prompt_id").notNull(),
    orgId: varchar("org_id"),
    version: integer("version").notNull(),
    name: varchar("name").notNull(),
    description: text("description").notNull().default(""),
    tier: varchar("tier").notNull().default("general"),
    systemPrompt: text("system_prompt").notNull(),
    userTemplate: text("user_template").notNull(),
    outputSchema: jsonb("output_schema"),
    maxTokens: integer("max_tokens").notNull().default(2048),
    temperature: doublePrecision("temperature").notNull().default(0.1),
    tags: jsonb("tags").notNull().default([]),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    uniqueIndex("idx_ai_prompt_versions_prompt_version").on(table.promptId, table.version),
    index("idx_ai_prompt_versions_prompt").on(table.promptId),
    index("idx_ai_prompt_versions_org").on(table.orgId),
  ],
);

export const aiPromptVersionsRelations = relations(aiPromptVersions, ({ one }) => ({
  organization: one(organizations, { fields: [aiPromptVersions.orgId], references: [organizations.id] }),
}));

export type AiPromptVersion = typeof aiPromptVersions.$inferSelect;

export const aiPromptAuditLog = pgTable(
  "ai_prompt_audit_log",
  {
    id: integer("id").primaryKey().generatedAlwaysAsIdentity(),
    promptId: varchar("prompt_id").notNull(),
    version: integer("version").notNull(),
    action: varchar("action").notNull(),
    metadata: jsonb("metadata"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_ai_prompt_audit_prompt").on(table.promptId),
    index("idx_ai_prompt_audit_action").on(table.action),
  ],
);

export type AiPromptAuditEntry = typeof aiPromptAuditLog.$inferSelect;

// ==========================================
// STANDALONE SECURITY PLATFORM — Asset Inventory
// ==========================================

export const ASSET_TYPES = [
  "server",
  "workstation",
  "laptop",
  "mobile",
  "network_device",
  "firewall",
  "cloud_instance",
  "container",
  "database",
  "application",
  "iot_device",
  "printer",
  "storage",
  "virtual_machine",
  "other",
] as const;

export const ASSET_CRITICALITIES = ["critical", "high", "medium", "low"] as const;
export const ASSET_LIFECYCLE_STATUSES = ["procurement", "active", "maintenance", "decommissioning", "retired"] as const;
export const ASSET_ENVIRONMENTS = ["production", "staging", "development", "testing", "dr"] as const;

export const assetInventory = pgTable(
  "asset_inventory",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    name: text("name").notNull(),
    assetType: text("asset_type").notNull(),
    criticality: text("criticality").notNull().default("medium"),
    lifecycleStatus: text("lifecycle_status").notNull().default("active"),
    environment: text("environment").default("production"),
    // Network info
    ipAddress: text("ip_address"),
    macAddress: text("mac_address"),
    hostname: text("hostname"),
    fqdn: text("fqdn"),
    // Ownership
    owner: text("owner"),
    department: text("department"),
    location: text("location"),
    // Technical details
    operatingSystem: text("operating_system"),
    osVersion: text("os_version"),
    manufacturer: text("manufacturer"),
    model: text("model"),
    serialNumber: text("serial_number"),
    // Software & patches
    installedSoftware: jsonb("installed_software").default([]),
    lastPatchDate: timestamp("last_patch_date"),
    // Risk
    riskScore: integer("risk_score").notNull().default(0),
    vulnerabilityCount: integer("vulnerability_count").notNull().default(0),
    openFindings: integer("open_findings").notNull().default(0),
    // Compliance
    complianceTags: text("compliance_tags")
      .array()
      .default(sql`ARRAY[]::text[]`),
    // Metadata
    tags: text("tags")
      .array()
      .default(sql`ARRAY[]::text[]`),
    notes: text("notes"),
    purchaseDate: timestamp("purchase_date"),
    warrantyExpiry: timestamp("warranty_expiry"),
    endOfLife: timestamp("end_of_life"),
    lastSeenAt: timestamp("last_seen_at"),
    discoveredBy: text("discovered_by"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_asset_inv_org").on(table.orgId),
    index("idx_asset_inv_type").on(table.orgId, table.assetType),
    index("idx_asset_inv_criticality").on(table.orgId, table.criticality),
    index("idx_asset_inv_status").on(table.orgId, table.lifecycleStatus),
    index("idx_asset_inv_risk").on(table.orgId, table.riskScore),
  ],
);

export const assetInventoryRelations = relations(assetInventory, ({ one }) => ({
  organization: one(organizations, { fields: [assetInventory.orgId], references: [organizations.id] }),
}));

export type AssetInventoryItem = typeof assetInventory.$inferSelect;
export type InsertAssetInventoryItem = typeof assetInventory.$inferInsert;

// ==========================================
// STANDALONE SECURITY PLATFORM — Risk Register
// ==========================================

export const RISK_CATEGORIES = [
  "operational",
  "technical",
  "compliance",
  "strategic",
  "financial",
  "reputational",
  "third_party",
  "physical",
] as const;

export const RISK_TREATMENTS = ["mitigate", "accept", "transfer", "avoid"] as const;
export const RISK_STATUSES = ["identified", "assessing", "treating", "monitoring", "closed"] as const;

export const riskRegister = pgTable(
  "risk_register",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    title: text("title").notNull(),
    description: text("description"),
    category: text("category").notNull(),
    // Risk scoring (1-5 scale)
    likelihood: integer("likelihood").notNull().default(3),
    impact: integer("impact").notNull().default(3),
    inherentRiskScore: integer("inherent_risk_score").notNull().default(9),
    // Residual risk after controls
    residualLikelihood: integer("residual_likelihood"),
    residualImpact: integer("residual_impact"),
    residualRiskScore: integer("residual_risk_score"),
    // Treatment
    treatment: text("treatment").notNull().default("mitigate"),
    treatmentPlan: text("treatment_plan"),
    controls: jsonb("controls").default([]),
    // Ownership
    riskOwner: text("risk_owner"),
    status: text("status").notNull().default("identified"),
    // Review
    lastReviewDate: timestamp("last_review_date"),
    nextReviewDate: timestamp("next_review_date"),
    // Related items
    relatedAssets: text("related_assets")
      .array()
      .default(sql`ARRAY[]::text[]`),
    relatedFrameworks: text("related_frameworks")
      .array()
      .default(sql`ARRAY[]::text[]`),
    tags: text("tags")
      .array()
      .default(sql`ARRAY[]::text[]`),
    createdBy: varchar("created_by"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_risk_reg_org").on(table.orgId),
    index("idx_risk_reg_category").on(table.orgId, table.category),
    index("idx_risk_reg_status").on(table.orgId, table.status),
    index("idx_risk_reg_score").on(table.orgId, table.inherentRiskScore),
  ],
);

export const riskRegisterRelations = relations(riskRegister, ({ one }) => ({
  organization: one(organizations, { fields: [riskRegister.orgId], references: [organizations.id] }),
}));

export type RiskRegisterEntry = typeof riskRegister.$inferSelect;
export type InsertRiskRegisterEntry = typeof riskRegister.$inferInsert;

// ==========================================
// STANDALONE SECURITY PLATFORM — Security Assessments
// ==========================================

export const ASSESSMENT_FRAMEWORKS = [
  "cis_controls_v8",
  "nist_csf_2",
  "iso_27001",
  "soc2_type2",
  "pci_dss_4",
  "hipaa",
  "gdpr",
  "essential_eight",
] as const;

export const ASSESSMENT_STATUSES = ["draft", "in_progress", "completed", "archived"] as const;

export const securityAssessments = pgTable(
  "security_assessments",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    framework: text("framework").notNull(),
    title: text("title").notNull(),
    description: text("description"),
    status: text("status").notNull().default("draft"),
    // Scoring
    totalControls: integer("total_controls").notNull().default(0),
    implementedControls: integer("implemented_controls").notNull().default(0),
    partialControls: integer("partial_controls").notNull().default(0),
    notImplementedControls: integer("not_implemented_controls").notNull().default(0),
    notApplicableControls: integer("not_applicable_controls").notNull().default(0),
    overallScore: integer("overall_score").notNull().default(0),
    // Metadata
    assessor: text("assessor"),
    reviewedBy: text("reviewed_by"),
    startedAt: timestamp("started_at"),
    completedAt: timestamp("completed_at"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_sec_assess_org").on(table.orgId),
    index("idx_sec_assess_framework").on(table.orgId, table.framework),
    index("idx_sec_assess_status").on(table.orgId, table.status),
  ],
);

export const assessmentResponses = pgTable(
  "assessment_responses",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    assessmentId: varchar("assessment_id")
      .notNull()
      .references(() => securityAssessments.id, { onDelete: "cascade" }),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    controlId: text("control_id").notNull(),
    controlTitle: text("control_title").notNull(),
    controlDescription: text("control_description"),
    category: text("category"),
    // Response
    status: text("status").notNull().default("not_assessed"),
    notes: text("notes"),
    evidence: text("evidence"),
    // Gap info
    gapDescription: text("gap_description"),
    recommendedAction: text("recommended_action"),
    priority: text("priority").default("medium"),
    // Scoring
    weight: integer("weight").notNull().default(1),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_assess_resp_assessment").on(table.assessmentId),
    index("idx_assess_resp_org").on(table.orgId),
    index("idx_assess_resp_status").on(table.assessmentId, table.status),
  ],
);

export const securityAssessmentsRelations = relations(securityAssessments, ({ one, many }) => ({
  organization: one(organizations, { fields: [securityAssessments.orgId], references: [organizations.id] }),
  responses: many(assessmentResponses),
}));

export const assessmentResponsesRelations = relations(assessmentResponses, ({ one }) => ({
  assessment: one(securityAssessments, {
    fields: [assessmentResponses.assessmentId],
    references: [securityAssessments.id],
  }),
  organization: one(organizations, { fields: [assessmentResponses.orgId], references: [organizations.id] }),
}));

export type SecurityAssessment = typeof securityAssessments.$inferSelect;
export type InsertSecurityAssessment = typeof securityAssessments.$inferInsert;
export type AssessmentResponse = typeof assessmentResponses.$inferSelect;
export type InsertAssessmentResponse = typeof assessmentResponses.$inferInsert;

// ==========================================
// STANDALONE SECURITY PLATFORM — Threat Reports (Employee Portal)
// ==========================================

export const THREAT_REPORT_CATEGORIES = [
  "phishing",
  "social_engineering",
  "suspicious_device",
  "policy_violation",
  "physical_security",
  "data_leak",
  "malware",
  "unauthorized_access",
  "other",
] as const;

export const THREAT_REPORT_STATUSES = ["submitted", "reviewing", "investigating", "resolved", "dismissed"] as const;

export const THREAT_REPORT_SEVERITIES = ["critical", "high", "medium", "low", "informational"] as const;

export const threatReports = pgTable(
  "threat_reports",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    // Reporter info
    reporterUserId: varchar("reporter_user_id"),
    reporterName: text("reporter_name"),
    reporterEmail: text("reporter_email"),
    isAnonymous: boolean("is_anonymous").notNull().default(false),
    // Report details
    category: text("category").notNull(),
    severity: text("severity").notNull().default("medium"),
    title: text("title").notNull(),
    description: text("description").notNull(),
    // What happened
    dateOccurred: timestamp("date_occurred"),
    locationDescription: text("location_description"),
    affectedSystems: text("affected_systems"),
    suspectInfo: text("suspect_info"),
    // Evidence
    attachments: jsonb("attachments").default([]),
    // Processing
    status: text("status").notNull().default("submitted"),
    assignedTo: varchar("assigned_to"),
    // Link to alert/incident if created
    linkedAlertId: varchar("linked_alert_id"),
    linkedIncidentId: varchar("linked_incident_id"),
    // Resolution
    resolution: text("resolution"),
    resolvedAt: timestamp("resolved_at"),
    resolvedBy: varchar("resolved_by"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_threat_reports_org").on(table.orgId),
    index("idx_threat_reports_status").on(table.orgId, table.status),
    index("idx_threat_reports_category").on(table.orgId, table.category),
    index("idx_threat_reports_reporter").on(table.reporterUserId),
  ],
);

export const threatReportsRelations = relations(threatReports, ({ one }) => ({
  organization: one(organizations, { fields: [threatReports.orgId], references: [organizations.id] }),
}));

export type ThreatReport = typeof threatReports.$inferSelect;
export type InsertThreatReport = typeof threatReports.$inferInsert;

// ==========================================
// NATIVE SENSOR AGENT PROTOCOL
// ==========================================

export const SENSOR_STATUSES = ["online", "offline", "degraded", "provisioning"] as const;
export const SENSOR_PLATFORMS = ["linux", "windows", "macos", "ios", "android", "docker", "kubernetes"] as const;
export const SENSOR_EVENT_TYPES = ["process", "network", "file", "auth", "dns", "log"] as const;

export const nativeSensors = pgTable(
  "native_sensors",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    hostname: text("hostname").notNull(),
    platform: text("platform").notNull(),
    osVersion: text("os_version"),
    agentVersion: text("agent_version"),
    registrationToken: text("registration_token").notNull(),
    apiKey: text("api_key"),
    status: text("status").notNull().default("provisioning"),
    ipAddress: text("ip_address"),
    macAddress: text("mac_address"),
    tags: text("tags")
      .array()
      .default(sql`ARRAY[]::text[]`),
    lastHeartbeat: timestamp("last_heartbeat"),
    cpuUsage: real("cpu_usage"),
    memoryUsage: real("memory_usage"),
    diskUsage: real("disk_usage"),
    eventsIngested: integer("events_ingested").notNull().default(0),
    alertsGenerated: integer("alerts_generated").notNull().default(0),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_native_sensors_org").on(table.orgId),
    index("idx_native_sensors_status").on(table.orgId, table.status),
    index("idx_native_sensors_hostname").on(table.orgId, table.hostname),
    uniqueIndex("idx_native_sensors_token").on(table.registrationToken),
  ],
);

export const nativeSensorsRelations = relations(nativeSensors, ({ one }) => ({
  organization: one(organizations, { fields: [nativeSensors.orgId], references: [organizations.id] }),
}));

export type NativeSensor = typeof nativeSensors.$inferSelect;
export type InsertNativeSensor = typeof nativeSensors.$inferInsert;

export const sensorEvents = pgTable(
  "sensor_events",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    sensorId: varchar("sensor_id")
      .notNull()
      .references(() => nativeSensors.id),
    eventType: text("event_type").notNull(),
    timestamp: timestamp("timestamp").notNull(),
    // Process events
    processName: text("process_name"),
    processPath: text("process_path"),
    processArgs: text("process_args"),
    parentProcess: text("parent_process"),
    pid: integer("pid"),
    ppid: integer("ppid"),
    userName: text("user_name"),
    // Network events
    srcIp: text("src_ip"),
    dstIp: text("dst_ip"),
    srcPort: integer("src_port"),
    dstPort: integer("dst_port"),
    protocol: text("protocol"),
    bytesIn: integer("bytes_in"),
    bytesOut: integer("bytes_out"),
    // File events
    filePath: text("file_path"),
    fileAction: text("file_action"),
    fileHash: text("file_hash"),
    fileSize: integer("file_size"),
    // Auth events
    authAction: text("auth_action"),
    authResult: text("auth_result"),
    authMethod: text("auth_method"),
    // DNS events
    dnsQuery: text("dns_query"),
    dnsType: text("dns_type"),
    dnsResponse: text("dns_response"),
    // Log events
    logSource: text("log_source"),
    logLevel: text("log_level"),
    logMessage: text("log_message"),
    // Raw data
    rawData: jsonb("raw_data"),
    // Detection linkage
    detectionMatched: boolean("detection_matched").default(false),
    detectionRuleId: varchar("detection_rule_id"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_sensor_events_org").on(table.orgId),
    index("idx_sensor_events_sensor").on(table.sensorId),
    index("idx_sensor_events_type").on(table.orgId, table.eventType),
    index("idx_sensor_events_ts").on(table.orgId, table.timestamp),
  ],
);

export const sensorEventsRelations = relations(sensorEvents, ({ one }) => ({
  organization: one(organizations, { fields: [sensorEvents.orgId], references: [organizations.id] }),
  sensor: one(nativeSensors, { fields: [sensorEvents.sensorId], references: [nativeSensors.id] }),
}));

export type SensorEvent = typeof sensorEvents.$inferSelect;
export type InsertSensorEvent = typeof sensorEvents.$inferInsert;

// ==========================================
// NATIVE COLLECTORS (DB-BACKED)
// ==========================================

export const COLLECTOR_STATUSES = ["pending_install", "active", "degraded", "offline", "error", "disabled"] as const;

export const collectorInstances = pgTable(
  "collector_instances",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    templateSlug: text("template_slug").notNull(),
    name: text("name").notNull(),
    status: text("status").notNull().default("pending_install"),
    platform: text("platform").notNull(),
    deploymentMethod: text("deployment_method").notNull(),
    config: jsonb("config").default({}),
    hostInfo: jsonb("host_info"),
    metrics: jsonb("metrics").default({
      eventsPerSecond: 0,
      bytesIngested: 0,
      errorsLast24h: 0,
      uptimePercent: 0,
      latencyP50Ms: 0,
      latencyP99Ms: 0,
      lastEventCount: 0,
      totalEventsIngested: 0,
    }),
    version: text("version").default("1.0.0"),
    tags: text("tags")
      .array()
      .default(sql`ARRAY[]::text[]`),
    lastHeartbeatAt: timestamp("last_heartbeat_at"),
    lastDataAt: timestamp("last_data_at"),
    installedAt: timestamp("installed_at").defaultNow(),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_collector_instances_org").on(table.orgId),
    index("idx_collector_instances_status").on(table.orgId, table.status),
    index("idx_collector_instances_template").on(table.orgId, table.templateSlug),
  ],
);

export const collectorInstancesRelations = relations(collectorInstances, ({ one }) => ({
  organization: one(organizations, { fields: [collectorInstances.orgId], references: [organizations.id] }),
}));

export type CollectorInstance = typeof collectorInstances.$inferSelect;
export type InsertCollectorInstance = typeof collectorInstances.$inferInsert;

export const collectorEvents = pgTable(
  "collector_events",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    collectorId: varchar("collector_id")
      .notNull()
      .references(() => collectorInstances.id, { onDelete: "cascade" }),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    eventType: text("event_type").notNull(),
    severity: text("severity").notNull().default("info"),
    source: text("source").notNull(),
    timestamp: timestamp("timestamp").defaultNow(),
    rawData: jsonb("raw_data").default({}),
    parsedFields: jsonb("parsed_fields").default({}),
    tags: text("tags")
      .array()
      .default(sql`ARRAY[]::text[]`),
    processed: boolean("processed").notNull().default(false),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_collector_events_org").on(table.orgId),
    index("idx_collector_events_collector").on(table.collectorId),
    index("idx_collector_events_type").on(table.orgId, table.eventType),
    index("idx_collector_events_ts").on(table.orgId, table.timestamp),
  ],
);

export const collectorEventsRelations = relations(collectorEvents, ({ one }) => ({
  organization: one(organizations, { fields: [collectorEvents.orgId], references: [organizations.id] }),
  collector: one(collectorInstances, { fields: [collectorEvents.collectorId], references: [collectorInstances.id] }),
}));

export type CollectorEvent = typeof collectorEvents.$inferSelect;
export type InsertCollectorEvent = typeof collectorEvents.$inferInsert;

export const collectorScans = pgTable(
  "collector_scans",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    collectorId: varchar("collector_id")
      .notNull()
      .references(() => collectorInstances.id, { onDelete: "cascade" }),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    scanType: text("scan_type").notNull(),
    status: text("status").notNull().default("running"),
    targets: text("targets")
      .array()
      .default(sql`ARRAY[]::text[]`),
    findings: jsonb("findings").default([]),
    summary: jsonb("summary").default({}),
    startedAt: timestamp("started_at").defaultNow(),
    completedAt: timestamp("completed_at"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_collector_scans_org").on(table.orgId),
    index("idx_collector_scans_collector").on(table.collectorId),
    index("idx_collector_scans_type").on(table.orgId, table.scanType),
  ],
);

export const collectorScansRelations = relations(collectorScans, ({ one }) => ({
  organization: one(organizations, { fields: [collectorScans.orgId], references: [organizations.id] }),
  collector: one(collectorInstances, { fields: [collectorScans.collectorId], references: [collectorInstances.id] }),
}));

export type CollectorScan = typeof collectorScans.$inferSelect;
export type InsertCollectorScan = typeof collectorScans.$inferInsert;

// ==========================================
// NATIVE DETECTION ENGINE
// ==========================================

export const DETECTION_SEVERITIES = ["critical", "high", "medium", "low", "informational"] as const;
export const DETECTION_STATUSES = ["enabled", "disabled", "testing"] as const;

export const MITRE_TACTICS = [
  "initial_access",
  "execution",
  "persistence",
  "privilege_escalation",
  "defense_evasion",
  "credential_access",
  "discovery",
  "lateral_movement",
  "collection",
  "command_and_control",
  "exfiltration",
  "impact",
] as const;

export const detectionRules = pgTable(
  "detection_rules",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").references(() => organizations.id),
    name: text("name").notNull(),
    description: text("description"),
    severity: text("severity").notNull().default("medium"),
    status: text("status").notNull().default("enabled"),
    // MITRE ATT&CK mapping
    mitreTactic: text("mitre_tactic"),
    mitreTechnique: text("mitre_technique"),
    mitreSubtechnique: text("mitre_subtechnique"),
    // Rule logic — Sigma-compatible condition tree
    eventTypes: text("event_types")
      .array()
      .default(sql`ARRAY[]::text[]`),
    conditionTree: jsonb("condition_tree").notNull(),
    // Metadata
    author: text("author"),
    tags: text("tags")
      .array()
      .default(sql`ARRAY[]::text[]`),
    falsePositiveNotes: text("false_positive_notes"),
    references: text("references")
      .array()
      .default(sql`ARRAY[]::text[]`),
    isBuiltin: boolean("is_builtin").default(false),
    matchCount: integer("match_count").notNull().default(0),
    lastMatchAt: timestamp("last_match_at"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_detection_rules_org").on(table.orgId),
    index("idx_detection_rules_status").on(table.status),
    index("idx_detection_rules_tactic").on(table.mitreTactic),
    index("idx_detection_rules_severity").on(table.severity),
  ],
);

export const detectionRulesRelations = relations(detectionRules, ({ one }) => ({
  organization: one(organizations, { fields: [detectionRules.orgId], references: [organizations.id] }),
}));

export type DetectionRule = typeof detectionRules.$inferSelect;
export type InsertDetectionRule = typeof detectionRules.$inferInsert;

export const detectionAlerts = pgTable(
  "detection_alerts",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    ruleId: varchar("rule_id")
      .notNull()
      .references(() => detectionRules.id),
    sensorId: varchar("sensor_id")
      .notNull()
      .references(() => nativeSensors.id),
    eventId: varchar("event_id").references(() => sensorEvents.id),
    severity: text("severity").notNull(),
    title: text("title").notNull(),
    description: text("description"),
    mitreTactic: text("mitre_tactic"),
    mitreTechnique: text("mitre_technique"),
    matchedFields: jsonb("matched_fields"),
    rawEvent: jsonb("raw_event"),
    // Linkage to platform alerts
    linkedAlertId: varchar("linked_alert_id"),
    status: text("status").notNull().default("new"),
    acknowledgedBy: varchar("acknowledged_by"),
    acknowledgedAt: timestamp("acknowledged_at"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_detection_alerts_org").on(table.orgId),
    index("idx_detection_alerts_rule").on(table.ruleId),
    index("idx_detection_alerts_sensor").on(table.sensorId),
    index("idx_detection_alerts_status").on(table.orgId, table.status),
    index("idx_detection_alerts_created").on(table.orgId, table.createdAt),
  ],
);

export const detectionAlertsRelations = relations(detectionAlerts, ({ one }) => ({
  organization: one(organizations, { fields: [detectionAlerts.orgId], references: [organizations.id] }),
  rule: one(detectionRules, { fields: [detectionAlerts.ruleId], references: [detectionRules.id] }),
  sensor: one(nativeSensors, { fields: [detectionAlerts.sensorId], references: [nativeSensors.id] }),
  event: one(sensorEvents, { fields: [detectionAlerts.eventId], references: [sensorEvents.id] }),
}));

export type DetectionAlert = typeof detectionAlerts.$inferSelect;
export type InsertDetectionAlert = typeof detectionAlerts.$inferInsert;

// ==========================================
// LOG SOURCE INGESTION
// ==========================================

export const LOG_SOURCE_TYPES = ["syslog", "windows_event_log", "http_push", "journald", "cloudwatch"] as const;

export const LOG_SOURCE_STATUSES = ["active", "inactive", "error", "configuring"] as const;

export const LOG_SOURCE_FORMATS = ["json", "cef", "leef", "raw", "csv", "key_value"] as const;

export const logSources = pgTable(
  "log_sources",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    sensorId: varchar("sensor_id").references(() => nativeSensors.id),
    name: text("name").notNull(),
    description: text("description"),
    sourceType: text("source_type").notNull(),
    status: text("status").notNull().default("configuring"),
    // Connection config
    listenAddress: text("listen_address"),
    listenPort: integer("listen_port"),
    protocol: text("protocol"),
    format: text("format").default("raw"),
    // Syslog-specific
    syslogFacility: text("syslog_facility"),
    syslogSeverity: text("syslog_severity"),
    // Windows Event Log
    winEventChannels: text("win_event_channels")
      .array()
      .default(sql`ARRAY[]::text[]`),
    winEventLevels: text("win_event_levels")
      .array()
      .default(sql`ARRAY[]::text[]`),
    // CloudWatch
    cloudwatchRegion: text("cloudwatch_region"),
    cloudwatchLogGroup: text("cloudwatch_log_group"),
    cloudwatchFilterPattern: text("cloudwatch_filter_pattern"),
    // HTTP Push
    httpEndpoint: text("http_endpoint"),
    httpAuthToken: text("http_auth_token"),
    // journald
    journaldUnits: text("journald_units")
      .array()
      .default(sql`ARRAY[]::text[]`),
    journaldPriority: text("journald_priority"),
    // Parsing
    parserRegex: text("parser_regex"),
    fieldMappings: jsonb("field_mappings"),
    // Tags and filtering
    tags: text("tags")
      .array()
      .default(sql`ARRAY[]::text[]`),
    filterInclude: text("filter_include"),
    filterExclude: text("filter_exclude"),
    // Stats
    eventsReceived: bigint("events_received", { mode: "number" }).notNull().default(0),
    eventsDropped: bigint("events_dropped", { mode: "number" }).notNull().default(0),
    bytesReceived: bigint("bytes_received", { mode: "number" }).notNull().default(0),
    lastEventAt: timestamp("last_event_at"),
    lastError: text("last_error"),
    lastErrorAt: timestamp("last_error_at"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_log_sources_org").on(table.orgId),
    index("idx_log_sources_sensor").on(table.sensorId),
    index("idx_log_sources_type").on(table.orgId, table.sourceType),
    index("idx_log_sources_status").on(table.orgId, table.status),
    uniqueIndex("idx_log_sources_http_auth_token").on(table.httpAuthToken),
  ],
);

export const logSourcesRelations = relations(logSources, ({ one }) => ({
  organization: one(organizations, { fields: [logSources.orgId], references: [organizations.id] }),
  sensor: one(nativeSensors, { fields: [logSources.sensorId], references: [nativeSensors.id] }),
}));

export type LogSource = typeof logSources.$inferSelect;
export type InsertLogSource = typeof logSources.$inferInsert;

// =============================================================================
// VULNERABILITY SCANNER
// =============================================================================

export const VULN_PKG_MANAGERS = ["apt", "rpm", "pip", "npm", "gem", "cargo", "nuget"] as const;
export const VULN_FINDING_STATUSES = ["open", "acknowledged", "remediated", "false_positive"] as const;
export const VULN_SEVERITIES = ["critical", "high", "medium", "low", "none"] as const;

export const vulnPackages = pgTable(
  "vuln_packages",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    sensorId: varchar("sensor_id")
      .notNull()
      .references(() => nativeSensors.id, { onDelete: "cascade" }),
    packageManager: text("package_manager").notNull(),
    packageName: text("package_name").notNull(),
    installedVersion: text("installed_version").notNull(),
    isVulnerable: boolean("is_vulnerable").notNull().default(false),
    cveCount: integer("cve_count").notNull().default(0),
    reportedAt: timestamp("reported_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_vuln_packages_org").on(table.orgId),
    index("idx_vuln_packages_sensor").on(table.sensorId),
    index("idx_vuln_packages_vuln").on(table.orgId, table.isVulnerable),
    uniqueIndex("idx_vuln_packages_unique").on(table.orgId, table.sensorId, table.packageManager, table.packageName),
  ],
);

export const vulnFindings = pgTable(
  "vuln_findings",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    sensorId: varchar("sensor_id").references(() => nativeSensors.id, { onDelete: "cascade" }),
    source: text("source").notNull().default("native_sensor"),
    packageId: varchar("package_id").references(() => vulnPackages.id, { onDelete: "cascade" }),
    cveId: text("cve_id").notNull(),
    packageName: text("package_name").notNull(),
    installedVersion: text("installed_version").notNull(),
    fixedVersion: text("fixed_version"),
    severity: text("severity").notNull().default("medium"),
    cvssScore: real("cvss_score"),
    description: text("description"),
    references: jsonb("references"),
    status: text("status").notNull().default("open"),
    acknowledgedBy: varchar("acknowledged_by"),
    acknowledgedAt: timestamp("acknowledged_at"),
    remediatedBy: varchar("remediated_by"),
    remediatedAt: timestamp("remediated_at"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_vuln_findings_org").on(table.orgId),
    index("idx_vuln_findings_sensor").on(table.sensorId),
    index("idx_vuln_findings_cve").on(table.cveId),
    index("idx_vuln_findings_status").on(table.orgId, table.status),
    index("idx_vuln_findings_severity").on(table.orgId, table.severity),
  ],
);

export const vulnPackagesRelations = relations(vulnPackages, ({ one }) => ({
  organization: one(organizations, { fields: [vulnPackages.orgId], references: [organizations.id] }),
  sensor: one(nativeSensors, { fields: [vulnPackages.sensorId], references: [nativeSensors.id] }),
}));

export const vulnFindingsRelations = relations(vulnFindings, ({ one }) => ({
  organization: one(organizations, { fields: [vulnFindings.orgId], references: [organizations.id] }),
  sensor: one(nativeSensors, { fields: [vulnFindings.sensorId], references: [nativeSensors.id] }),
  package: one(vulnPackages, { fields: [vulnFindings.packageId], references: [vulnPackages.id] }),
}));

export type VulnPackage = typeof vulnPackages.$inferSelect;
export type InsertVulnPackage = typeof vulnPackages.$inferInsert;
export type VulnFinding = typeof vulnFindings.$inferSelect;
export type InsertVulnFinding = typeof vulnFindings.$inferInsert;

// =============================================================================
// UEBA BEHAVIORAL ANALYTICS
// =============================================================================

export const UEBA_ENTITY_TYPES = ["user", "host"] as const;
export const UEBA_ANOMALY_TYPES = [
  "off_hours_login",
  "new_geo_location",
  "suspicious_process",
  "traffic_volume_spike",
  "new_source_ip",
  "brute_force_attempt",
  "privilege_escalation",
  "data_exfiltration",
] as const;
export const UEBA_RISK_LEVELS = ["critical", "high", "medium", "low", "none"] as const;

export const uebaBaselines = pgTable(
  "ueba_baselines",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    entityType: text("entity_type").notNull(),
    entityId: text("entity_id").notNull(),
    entityName: text("entity_name"),
    normalLoginHoursStart: integer("normal_login_hours_start"),
    normalLoginHoursEnd: integer("normal_login_hours_end"),
    knownSourceIps: text("known_source_ips")
      .array()
      .default(sql`ARRAY[]::text[]`),
    processAllowList: text("process_allow_list")
      .array()
      .default(sql`ARRAY[]::text[]`),
    avgDailyEventVolume: real("avg_daily_event_volume").default(0),
    avgDailyDataBytes: real("avg_daily_data_bytes").default(0),
    baselineWindowDays: integer("baseline_window_days").notNull().default(30),
    lastUpdated: timestamp("last_updated").defaultNow(),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_ueba_baselines_org").on(table.orgId),
    index("idx_ueba_baselines_entity").on(table.orgId, table.entityType, table.entityId),
  ],
);

export const uebaAnomalies = pgTable(
  "ueba_anomalies",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    entityType: text("entity_type").notNull(),
    entityId: text("entity_id").notNull(),
    entityName: text("entity_name"),
    anomalyType: text("anomaly_type").notNull(),
    severity: text("severity").notNull().default("medium"),
    riskScore: integer("risk_score").notNull().default(0),
    description: text("description"),
    details: jsonb("details"),
    sourceIp: text("source_ip"),
    geoLocation: text("geo_location"),
    processName: text("process_name"),
    alertCreated: boolean("alert_created").default(false),
    alertId: varchar("alert_id"),
    dismissed: boolean("dismissed").default(false),
    dismissedBy: varchar("dismissed_by"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_ueba_anomalies_org").on(table.orgId),
    index("idx_ueba_anomalies_entity").on(table.orgId, table.entityType, table.entityId),
    index("idx_ueba_anomalies_type").on(table.orgId, table.anomalyType),
    index("idx_ueba_anomalies_created").on(table.orgId, table.createdAt),
  ],
);

export const uebaEntityScores = pgTable(
  "ueba_entity_scores",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    entityType: text("entity_type").notNull(),
    entityId: text("entity_id").notNull(),
    entityName: text("entity_name"),
    riskScore: integer("risk_score").notNull().default(0),
    riskLevel: text("risk_level").notNull().default("none"),
    anomalyCount: integer("anomaly_count").notNull().default(0),
    lastAnomalyAt: timestamp("last_anomaly_at"),
    updatedAt: timestamp("updated_at").defaultNow(),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_ueba_scores_org").on(table.orgId),
    index("idx_ueba_scores_risk").on(table.orgId, table.riskScore),
    index("idx_ueba_scores_entity").on(table.orgId, table.entityType, table.entityId),
  ],
);

export const uebaBaselinesRelations = relations(uebaBaselines, ({ one }) => ({
  organization: one(organizations, { fields: [uebaBaselines.orgId], references: [organizations.id] }),
}));
export const uebaAnomaliesRelations = relations(uebaAnomalies, ({ one }) => ({
  organization: one(organizations, { fields: [uebaAnomalies.orgId], references: [organizations.id] }),
}));
export const uebaEntityScoresRelations = relations(uebaEntityScores, ({ one }) => ({
  organization: one(organizations, { fields: [uebaEntityScores.orgId], references: [organizations.id] }),
}));

export type UebaBaseline = typeof uebaBaselines.$inferSelect;
export type InsertUebaBaseline = typeof uebaBaselines.$inferInsert;
export type UebaAnomaly = typeof uebaAnomalies.$inferSelect;
export type InsertUebaAnomaly = typeof uebaAnomalies.$inferInsert;
export type UebaEntityScore = typeof uebaEntityScores.$inferSelect;
export type InsertUebaEntityScore = typeof uebaEntityScores.$inferInsert;

// =============================================================================
// AGENT REMOTE RESPONSE ACTIONS
// =============================================================================

export const AGENT_ACTION_TYPES = [
  "kill_process",
  "isolate_host",
  "block_ip",
  "quarantine_file",
  "delete_file",
  "disable_user",
  "collect_forensics",
  "run_script",
  "block_domain",
  "enable_logging",
  "restart_service",
  "unisolate_host",
  "unblock_ip",
  "unblock_domain",
  "restore_file",
  "enable_user",
] as const;
export const RESPONSE_ACTION_DISPATCH_INTERVAL_SECONDS = 30;
export const MIN_RESPONSE_ACTION_TIMEOUT_SECONDS = RESPONSE_ACTION_DISPATCH_INTERVAL_SECONDS * 2;
export const MAX_RESPONSE_ACTION_TIMEOUT_SECONDS = 3600;
export const DEFAULT_RESPONSE_ACTION_TIMEOUT_SECONDS = 300;
export const AGENT_ACTION_RISK_LEVELS = ["low", "medium", "high"] as const;
export const AGENT_ACTION_STATUSES = [
  "pending_approval",
  "approved",
  "dispatched",
  "executing",
  "completed",
  "failed",
  "rejected",
  "timed_out",
  "cancelled",
] as const;

export const agentResponseActions = pgTable(
  "agent_response_actions",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    sensorId: varchar("sensor_id")
      .notNull()
      .references(() => nativeSensors.id, { onDelete: "cascade" }),
    actionType: text("action_type").notNull(),
    riskLevel: text("risk_level").notNull().default("medium"),
    status: text("status").notNull().default("pending_approval"),
    // Action-specific parameters
    targetPid: integer("target_pid"),
    targetProcessName: text("target_process_name"),
    targetIp: text("target_ip"),
    targetFilePath: text("target_file_path"),
    targetUserName: text("target_user_name"),
    targetDomain: text("target_domain"),
    targetServiceName: text("target_service_name"),
    scriptContent: text("script_content"),
    scriptType: text("script_type"),
    parameters: jsonb("parameters"),
    // Workflow
    requestedBy: varchar("requested_by"),
    requestedByName: text("requested_by_name"),
    approvedBy: varchar("approved_by"),
    approvedByName: text("approved_by_name"),
    approvedAt: timestamp("approved_at"),
    rejectedBy: varchar("rejected_by"),
    rejectedReason: text("rejected_reason"),
    rejectedAt: timestamp("rejected_at"),
    // Execution
    dispatchedAt: timestamp("dispatched_at"),
    completedAt: timestamp("completed_at"),
    resultOutput: text("result_output"),
    resultError: text("result_error"),
    timeoutSeconds: integer("timeout_seconds").notNull().default(300),
    expiresAt: timestamp("expires_at"),
    // Audit
    incidentId: varchar("incident_id"),
    reason: text("reason"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_agent_actions_org").on(table.orgId),
    index("idx_agent_actions_sensor").on(table.sensorId),
    index("idx_agent_actions_status").on(table.orgId, table.status),
    index("idx_agent_actions_type").on(table.orgId, table.actionType),
    index("idx_agent_actions_created").on(table.orgId, table.createdAt),
  ],
);

export const agentResponseActionsRelations = relations(agentResponseActions, ({ one }) => ({
  organization: one(organizations, { fields: [agentResponseActions.orgId], references: [organizations.id] }),
  sensor: one(nativeSensors, { fields: [agentResponseActions.sensorId], references: [nativeSensors.id] }),
}));

export type AgentResponseAction = typeof agentResponseActions.$inferSelect;
export type InsertAgentResponseAction = typeof agentResponseActions.$inferInsert;

// =============================================================================
// SUPPLY CHAIN SECURITY
// =============================================================================

export const SBOM_FORMATS = ["cyclonedx", "spdx"] as const;
export const SBOM_STATUSES = ["processing", "completed", "failed"] as const;
export const SC_FINDING_TYPES = [
  "vulnerable_dependency",
  "typosquatting",
  "maintainer_risk",
  "outdated_dependency",
  "license_risk",
  "iac_misconfiguration",
  "container_vulnerability",
  "provenance_failure",
] as const;
export const SC_FINDING_SEVERITIES = ["critical", "high", "medium", "low", "informational"] as const;
export const SC_FINDING_STATUSES = ["open", "acknowledged", "remediated", "false_positive"] as const;
export const SC_PKG_ECOSYSTEMS = [
  "npm",
  "pypi",
  "rubygems",
  "nuget",
  "cargo",
  "go",
  "maven",
  "docker",
  "terraform",
  "helm",
  "kubernetes",
] as const;

export const sbomArtifacts = pgTable(
  "sbom_artifacts",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    name: text("name").notNull(),
    version: text("version"),
    format: text("format").notNull(), // cyclonedx | spdx
    source: text("source"), // CI/CD pipeline name, manual upload, etc.
    componentCount: integer("component_count").notNull().default(0),
    vulnerabilityCount: integer("vulnerability_count").notNull().default(0),
    licenseCount: integer("license_count").notNull().default(0),
    status: text("status").notNull().default("processing"),
    rawData: jsonb("raw_data"), // original SBOM JSON
    metadata: jsonb("metadata"), // tool, timestamp, serial number
    uploadedBy: varchar("uploaded_by"),
    processedAt: timestamp("processed_at"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_sbom_artifacts_org").on(table.orgId),
    index("idx_sbom_artifacts_org_created").on(table.orgId, table.createdAt),
    index("idx_sbom_artifacts_status").on(table.orgId, table.status),
  ],
);

export const dependencyGraph = pgTable(
  "dependency_graph",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    sbomId: varchar("sbom_id")
      .notNull()
      .references(() => sbomArtifacts.id, { onDelete: "cascade" }),
    packageName: text("package_name").notNull(),
    packageVersion: text("package_version"),
    ecosystem: text("ecosystem").notNull(), // npm, pypi, rubygems, nuget, etc.
    isDirect: boolean("is_direct").notNull().default(true),
    parentPackageId: varchar("parent_package_id"), // self-ref for transitive deps
    license: text("license"),
    publisher: text("publisher"),
    publisherEmail: text("publisher_email"),
    repositoryUrl: text("repository_url"),
    latestVersion: text("latest_version"),
    isOutdated: boolean("is_outdated").default(false),
    isVulnerable: boolean("is_vulnerable").default(false),
    cveCount: integer("cve_count").notNull().default(0),
    // Maintainer reputation scoring
    maintainerScore: real("maintainer_score"), // 0-100
    maintainerNewPublisher: boolean("maintainer_new_publisher").default(false),
    maintainerRecentTransfer: boolean("maintainer_recent_transfer").default(false),
    maintainerLowDownloads: boolean("maintainer_low_downloads").default(false),
    // Provenance
    provenanceVerified: boolean("provenance_verified"),
    provenanceSignature: text("provenance_signature"),
    // Typosquatting
    typosquatCandidate: boolean("typosquat_candidate").default(false),
    typosquatSimilarTo: text("typosquat_similar_to"),
    typosquatDistance: integer("typosquat_distance"),
    depth: integer("depth").notNull().default(0), // 0 = direct, 1+ = transitive
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_dep_graph_org").on(table.orgId),
    index("idx_dep_graph_sbom").on(table.sbomId),
    index("idx_dep_graph_pkg").on(table.orgId, table.packageName),
    index("idx_dep_graph_ecosystem").on(table.orgId, table.ecosystem),
    index("idx_dep_graph_vulnerable").on(table.orgId, table.isVulnerable),
    index("idx_dep_graph_typosquat").on(table.orgId, table.typosquatCandidate),
  ],
);

export const supplyChainFindings = pgTable(
  "supply_chain_findings",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    sbomId: varchar("sbom_id").references(() => sbomArtifacts.id, { onDelete: "cascade" }),
    dependencyId: varchar("dependency_id").references(() => dependencyGraph.id, { onDelete: "cascade" }),
    findingType: text("finding_type").notNull(),
    severity: text("severity").notNull().default("medium"),
    status: text("status").notNull().default("open"),
    title: text("title").notNull(),
    description: text("description"),
    packageName: text("package_name"),
    packageVersion: text("package_version"),
    ecosystem: text("ecosystem"),
    cveId: text("cve_id"),
    cvssScore: real("cvss_score"),
    fixedVersion: text("fixed_version"),
    // IaC-specific fields
    iacResourceType: text("iac_resource_type"),
    iacFilePath: text("iac_file_path"),
    iacRule: text("iac_rule"),
    // Container-specific fields
    containerImage: text("container_image"),
    containerLayer: text("container_layer"),
    // Metadata
    details: jsonb("details"),
    acknowledgedBy: varchar("acknowledged_by"),
    acknowledgedAt: timestamp("acknowledged_at"),
    remediatedBy: varchar("remediated_by"),
    remediatedAt: timestamp("remediated_at"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_sc_findings_org").on(table.orgId),
    index("idx_sc_findings_sbom").on(table.sbomId),
    index("idx_sc_findings_type").on(table.orgId, table.findingType),
    index("idx_sc_findings_severity").on(table.orgId, table.severity),
    index("idx_sc_findings_status").on(table.orgId, table.status),
    index("idx_sc_findings_cve").on(table.cveId),
    index("idx_sc_findings_pkg").on(table.orgId, table.packageName),
  ],
);

export const sbomArtifactsRelations = relations(sbomArtifacts, ({ one, many }) => ({
  organization: one(organizations, { fields: [sbomArtifacts.orgId], references: [organizations.id] }),
  dependencies: many(dependencyGraph),
  findings: many(supplyChainFindings),
}));

export const dependencyGraphRelations = relations(dependencyGraph, ({ one }) => ({
  organization: one(organizations, { fields: [dependencyGraph.orgId], references: [organizations.id] }),
  sbom: one(sbomArtifacts, { fields: [dependencyGraph.sbomId], references: [sbomArtifacts.id] }),
}));

export const supplyChainFindingsRelations = relations(supplyChainFindings, ({ one }) => ({
  organization: one(organizations, { fields: [supplyChainFindings.orgId], references: [organizations.id] }),
  sbom: one(sbomArtifacts, { fields: [supplyChainFindings.sbomId], references: [sbomArtifacts.id] }),
  dependency: one(dependencyGraph, { fields: [supplyChainFindings.dependencyId], references: [dependencyGraph.id] }),
}));

export type SbomArtifact = typeof sbomArtifacts.$inferSelect;
export type InsertSbomArtifact = typeof sbomArtifacts.$inferInsert;
export type DependencyGraphEntry = typeof dependencyGraph.$inferSelect;
export type InsertDependencyGraphEntry = typeof dependencyGraph.$inferInsert;
export type SupplyChainFinding = typeof supplyChainFindings.$inferSelect;
export type InsertSupplyChainFinding = typeof supplyChainFindings.$inferInsert;

// =============================================================================
// IDENTITY GOVERNANCE & PAM
// =============================================================================

export const ACCESS_REVIEW_STATUSES = ["pending", "approved", "revoked", "expired", "cancelled"] as const;
export const ACCESS_REVIEW_CAMPAIGN_STATUSES = ["draft", "active", "completed", "cancelled"] as const;
export const PAM_SESSION_STATUSES = [
  "requested",
  "approved",
  "active",
  "completed",
  "denied",
  "expired",
  "terminated",
] as const;
export const SCIM_OPERATION_TYPES = [
  "create",
  "update",
  "delete",
  "activate",
  "deactivate",
  "group_add",
  "group_remove",
] as const;
export const SCIM_PROVIDER_TYPES = ["azure_ad", "okta", "google_workspace", "onelogin", "jumpcloud"] as const;
export const IDENTITY_RISK_LEVELS = ["critical", "high", "medium", "low"] as const;

export const accessReviewCampaigns = pgTable(
  "access_review_campaigns",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    name: text("name").notNull(),
    description: text("description"),
    cadence: text("cadence").notNull().default("quarterly"), // quarterly, monthly, annual
    status: text("status").notNull().default("draft"),
    reviewerUserId: varchar("reviewer_user_id"),
    reviewerName: text("reviewer_name"),
    totalEntitlements: integer("total_entitlements").notNull().default(0),
    reviewedCount: integer("reviewed_count").notNull().default(0),
    approvedCount: integer("approved_count").notNull().default(0),
    revokedCount: integer("revoked_count").notNull().default(0),
    dueDate: timestamp("due_date"),
    startedAt: timestamp("started_at"),
    completedAt: timestamp("completed_at"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [index("idx_arc_org").on(table.orgId), index("idx_arc_status").on(table.orgId, table.status)],
);

export const accessReviewEntitlements = pgTable(
  "access_review_entitlements",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    campaignId: varchar("campaign_id")
      .notNull()
      .references(() => accessReviewCampaigns.id, { onDelete: "cascade" }),
    userId: varchar("user_id").notNull(),
    userName: text("user_name").notNull(),
    userEmail: text("user_email"),
    entitlementType: text("entitlement_type").notNull(), // role, permission, group, resource
    entitlementName: text("entitlement_name").notNull(),
    entitlementDescription: text("entitlement_description"),
    grantedAt: timestamp("granted_at"),
    lastUsedAt: timestamp("last_used_at"),
    riskLevel: text("risk_level").default("low"),
    status: text("status").notNull().default("pending"),
    decision: text("decision"), // approve, revoke
    decisionBy: varchar("decision_by"),
    decisionAt: timestamp("decision_at"),
    decisionReason: text("decision_reason"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_are_org").on(table.orgId),
    index("idx_are_campaign").on(table.campaignId),
    index("idx_are_user").on(table.userId),
    index("idx_are_status").on(table.orgId, table.status),
  ],
);

export const pamSessions = pgTable(
  "pam_sessions",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    requesterId: varchar("requester_id").notNull(),
    requesterName: text("requester_name").notNull(),
    requesterEmail: text("requester_email"),
    targetSystem: text("target_system").notNull(),
    targetHost: text("target_host"),
    targetAccount: text("target_account").notNull(), // e.g. root, admin, db_admin
    accessLevel: text("access_level").notNull(), // read, write, admin, superadmin
    justification: text("justification").notNull(),
    incidentId: varchar("incident_id"),
    status: text("status").notNull().default("requested"),
    durationMinutes: integer("duration_minutes").notNull().default(60),
    approvedBy: varchar("approved_by"),
    approvedAt: timestamp("approved_at"),
    deniedBy: varchar("denied_by"),
    deniedReason: text("denied_reason"),
    activatedAt: timestamp("activated_at"),
    expiresAt: timestamp("expires_at"),
    terminatedAt: timestamp("terminated_at"),
    terminatedBy: varchar("terminated_by"),
    terminationReason: text("termination_reason"),
    sessionToken: text("session_token"),
    // Session recording
    recordingEnabled: boolean("recording_enabled").notNull().default(true),
    recordingSize: integer("recording_size"), // bytes
    commandCount: integer("command_count").default(0),
    keystrokeCount: integer("keystroke_count").default(0),
    // Risk assessment
    riskScore: integer("risk_score"), // 0-100
    riskFactors: jsonb("risk_factors"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_pam_org").on(table.orgId),
    index("idx_pam_requester").on(table.orgId, table.requesterId),
    index("idx_pam_status").on(table.orgId, table.status),
    index("idx_pam_target").on(table.orgId, table.targetSystem),
    index("idx_pam_expires").on(table.expiresAt),
  ],
);

export const scimProvisioningLogs = pgTable(
  "scim_provisioning_logs",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    provider: text("provider").notNull(), // azure_ad, okta, google_workspace
    operationType: text("operation_type").notNull(),
    externalUserId: text("external_user_id"),
    externalUserName: text("external_user_name"),
    externalEmail: text("external_email"),
    internalUserId: varchar("internal_user_id"),
    groupName: text("group_name"),
    success: boolean("success").notNull().default(true),
    errorMessage: text("error_message"),
    rawPayload: jsonb("raw_payload"),
    processedAt: timestamp("processed_at").defaultNow(),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_scim_org").on(table.orgId),
    index("idx_scim_provider").on(table.orgId, table.provider),
    index("idx_scim_operation").on(table.orgId, table.operationType),
    index("idx_scim_ext_user").on(table.externalUserId),
  ],
);

export const identityRiskProfiles = pgTable(
  "identity_risk_profiles",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    userId: varchar("user_id").notNull(),
    userName: text("user_name").notNull(),
    userEmail: text("user_email"),
    riskLevel: text("risk_level").notNull().default("low"),
    riskScore: integer("risk_score").notNull().default(0), // 0-100
    // Stale account detection
    isStale: boolean("is_stale").default(false),
    lastActivityAt: timestamp("last_activity_at"),
    daysSinceActivity: integer("days_since_activity"),
    isServiceAccount: boolean("is_service_account").default(false),
    lastCredentialRotation: timestamp("last_credential_rotation"),
    credentialAge: integer("credential_age_days"),
    // Blast radius
    blastRadiusScore: integer("blast_radius_score").default(0), // 0-100
    accessibleSystems: integer("accessible_systems").default(0),
    accessibleSecrets: integer("accessible_secrets").default(0),
    privilegedRoles: jsonb("privileged_roles"), // array of role names
    // Lateral movement
    lateralMovementPaths: integer("lateral_movement_paths").default(0),
    canReachCritical: boolean("can_reach_critical").default(false),
    pivotPoints: jsonb("pivot_points"), // systems this identity can pivot through
    // Risk factors
    mfaEnabled: boolean("mfa_enabled").default(false),
    hasExcessivePermissions: boolean("has_excessive_permissions").default(false),
    unusedPermissions: jsonb("unused_permissions"),
    anomalousLoginCount: integer("anomalous_login_count").default(0),
    failedLoginCount: integer("failed_login_count").default(0),
    // Metadata
    lastAssessedAt: timestamp("last_assessed_at"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_irp_org").on(table.orgId),
    index("idx_irp_user").on(table.orgId, table.userId),
    index("idx_irp_risk").on(table.orgId, table.riskLevel),
    index("idx_irp_stale").on(table.orgId, table.isStale),
    index("idx_irp_blast").on(table.orgId, table.blastRadiusScore),
  ],
);

export const identityAccessGraph = pgTable(
  "identity_access_graph",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    sourceUserId: varchar("source_user_id").notNull(),
    sourceUserName: text("source_user_name").notNull(),
    targetSystem: text("target_system").notNull(),
    targetResource: text("target_resource"),
    accessType: text("access_type").notNull(), // direct, inherited, delegated
    permissionLevel: text("permission_level").notNull(), // read, write, admin, superadmin
    grantedVia: text("granted_via"), // role name, group name, direct assignment
    isActive: boolean("is_active").notNull().default(true),
    lastUsedAt: timestamp("last_used_at"),
    expiresAt: timestamp("expires_at"),
    riskWeight: integer("risk_weight").default(1), // higher = riskier path
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_iag_org").on(table.orgId),
    index("idx_iag_source").on(table.orgId, table.sourceUserId),
    index("idx_iag_target").on(table.orgId, table.targetSystem),
    index("idx_iag_active").on(table.orgId, table.isActive),
  ],
);

// Relations
export const accessReviewCampaignsRelations = relations(accessReviewCampaigns, ({ one, many }) => ({
  organization: one(organizations, { fields: [accessReviewCampaigns.orgId], references: [organizations.id] }),
  entitlements: many(accessReviewEntitlements),
}));

export const accessReviewEntitlementsRelations = relations(accessReviewEntitlements, ({ one }) => ({
  organization: one(organizations, { fields: [accessReviewEntitlements.orgId], references: [organizations.id] }),
  campaign: one(accessReviewCampaigns, {
    fields: [accessReviewEntitlements.campaignId],
    references: [accessReviewCampaigns.id],
  }),
}));

export const pamSessionsRelations = relations(pamSessions, ({ one }) => ({
  organization: one(organizations, { fields: [pamSessions.orgId], references: [organizations.id] }),
}));

export const scimProvisioningLogsRelations = relations(scimProvisioningLogs, ({ one }) => ({
  organization: one(organizations, { fields: [scimProvisioningLogs.orgId], references: [organizations.id] }),
}));

export const identityRiskProfilesRelations = relations(identityRiskProfiles, ({ one }) => ({
  organization: one(organizations, { fields: [identityRiskProfiles.orgId], references: [organizations.id] }),
}));

export const identityAccessGraphRelations = relations(identityAccessGraph, ({ one }) => ({
  organization: one(organizations, { fields: [identityAccessGraph.orgId], references: [organizations.id] }),
}));

// Types
export type AccessReviewCampaign = typeof accessReviewCampaigns.$inferSelect;
export type InsertAccessReviewCampaign = typeof accessReviewCampaigns.$inferInsert;
export type AccessReviewEntitlement = typeof accessReviewEntitlements.$inferSelect;
export type InsertAccessReviewEntitlement = typeof accessReviewEntitlements.$inferInsert;
export type PamSession = typeof pamSessions.$inferSelect;
export type InsertPamSession = typeof pamSessions.$inferInsert;
export type ScimProvisioningLog = typeof scimProvisioningLogs.$inferSelect;
export type InsertScimProvisioningLog = typeof scimProvisioningLogs.$inferInsert;
export type IdentityRiskProfile = typeof identityRiskProfiles.$inferSelect;
export type InsertIdentityRiskProfile = typeof identityRiskProfiles.$inferInsert;
export type IdentityAccessGraphEntry = typeof identityAccessGraph.$inferSelect;
export type InsertIdentityAccessGraphEntry = typeof identityAccessGraph.$inferInsert;

// =========================================================================
// DECEPTION TECHNOLOGY
// =========================================================================

export const CANARY_TOKEN_TYPES = [
  "aws_key",
  "database_credential",
  "api_key",
  "document",
  "email_pixel",
  "dns_token",
  "url_token",
  "kubeconfig",
  "ssh_key",
  "slack_webhook",
] as const;

export const HONEYPOT_ASSET_TYPES = [
  "honey_account",
  "honeypot_endpoint",
  "deception_fileshare",
  "network_decoy",
  "fake_rdp",
  "fake_ssh",
  "fake_admin_panel",
  "fake_database",
] as const;

export const DECEPTION_HIT_SEVERITIES = ["critical", "high", "medium", "low"] as const;

export const DEPLOYMENT_TARGETS = [
  "s3_bucket",
  "github_repo",
  "email",
  "shared_drive",
  "active_directory",
  "kubernetes",
  "ci_cd_pipeline",
  "internal_wiki",
] as const;

export const canaryTokens = pgTable(
  "canary_tokens",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    name: text("name").notNull(),
    description: text("description"),
    tokenType: text("token_type").notNull(), // from CANARY_TOKEN_TYPES
    tokenValue: text("token_value").notNull(), // the fake credential value
    tokenHash: text("token_hash").notNull(), // SHA-256 hash for fast lookup
    callbackUrl: text("callback_url").notNull(), // unique URL that triggers on access
    callbackSecret: text("callback_secret").notNull(), // HMAC secret for validating callbacks
    deployedTo: text("deployed_to"), // where it's planted
    deploymentTarget: text("deployment_target"), // from DEPLOYMENT_TARGETS
    deploymentMetadata: jsonb("deployment_metadata"), // target-specific config
    isActive: boolean("is_active").notNull().default(true),
    hitCount: integer("hit_count").notNull().default(0),
    lastHitAt: timestamp("last_hit_at"),
    createdBy: varchar("created_by"),
    expiresAt: timestamp("expires_at"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_canary_tokens_org").on(table.orgId),
    index("idx_canary_tokens_type").on(table.tokenType),
    index("idx_canary_tokens_hash").on(table.tokenHash),
    index("idx_canary_tokens_active").on(table.orgId, table.isActive),
    uniqueIndex("idx_canary_tokens_callback").on(table.callbackUrl),
  ],
);

export const honeypotAssets = pgTable(
  "honeypot_assets",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    name: text("name").notNull(),
    description: text("description"),
    assetType: text("asset_type").notNull(), // from HONEYPOT_ASSET_TYPES
    // For honey accounts
    fakeUsername: text("fake_username"),
    fakeEmail: text("fake_email"),
    fakeDomain: text("fake_domain"),
    // For honeypot endpoints
    listenAddress: text("listen_address"), // e.g., "10.0.0.50:3389"
    protocol: text("protocol"), // rdp, ssh, http, smb
    // For deception fileshares
    sharePath: text("share_path"), // e.g., "\\\\fileserver\\executive-salaries"
    decoyFiles: jsonb("decoy_files"), // list of fake file names/sizes
    // For network decoys
    decoyHostname: text("decoy_hostname"),
    decoyIp: text("decoy_ip"),
    openPorts: jsonb("open_ports"), // list of open ports
    // General
    configuration: jsonb("configuration"), // full config blob
    isActive: boolean("is_active").notNull().default(true),
    hitCount: integer("hit_count").notNull().default(0),
    lastHitAt: timestamp("last_hit_at"),
    createdBy: varchar("created_by"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_honeypot_assets_org").on(table.orgId),
    index("idx_honeypot_assets_type").on(table.assetType),
    index("idx_honeypot_assets_active").on(table.orgId, table.isActive),
  ],
);

export const deceptionHits = pgTable(
  "deception_hits",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    // Link to source
    canaryTokenId: varchar("canary_token_id").references(() => canaryTokens.id),
    honeypotAssetId: varchar("honeypot_asset_id").references(() => honeypotAssets.id),
    // Hit details
    sourceIp: text("source_ip"),
    sourceHostname: text("source_hostname"),
    sourceUserAgent: text("source_user_agent"),
    sourceGeoCountry: text("source_geo_country"),
    sourceGeoCity: text("source_geo_city"),
    sourceAsn: text("source_asn"),
    // Attribution
    attributedUserId: text("attributed_user_id"),
    attributedUsername: text("attributed_username"),
    attributedService: text("attributed_service"),
    // Hit classification
    severity: text("severity").notNull().default("critical"), // from DECEPTION_HIT_SEVERITIES
    isInternal: boolean("is_internal").default(false),
    isTorExit: boolean("is_tor_exit").default(false),
    isKnownBad: boolean("is_known_bad").default(false),
    // Response
    alertId: varchar("alert_id").references(() => alerts.id),
    incidentId: varchar("incident_id").references(() => incidents.id),
    autoContained: boolean("auto_contained").default(false),
    containmentAction: text("containment_action"),
    // Metadata
    rawRequest: jsonb("raw_request"), // full request data
    httpMethod: text("http_method"),
    httpPath: text("http_path"),
    accessedCredential: text("accessed_credential"), // which fake cred was used
    hitAt: timestamp("hit_at").defaultNow(),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_deception_hits_org").on(table.orgId),
    index("idx_deception_hits_token").on(table.canaryTokenId),
    index("idx_deception_hits_honeypot").on(table.honeypotAssetId),
    index("idx_deception_hits_severity").on(table.orgId, table.severity),
    index("idx_deception_hits_time").on(table.orgId, table.hitAt),
    index("idx_deception_hits_source_ip").on(table.sourceIp),
  ],
);

// Relations
export const canaryTokensRelations = relations(canaryTokens, ({ one, many }) => ({
  organization: one(organizations, { fields: [canaryTokens.orgId], references: [organizations.id] }),
  hits: many(deceptionHits),
}));

export const honeypotAssetsRelations = relations(honeypotAssets, ({ one, many }) => ({
  organization: one(organizations, { fields: [honeypotAssets.orgId], references: [organizations.id] }),
  hits: many(deceptionHits),
}));

export const deceptionHitsRelations = relations(deceptionHits, ({ one }) => ({
  organization: one(organizations, { fields: [deceptionHits.orgId], references: [organizations.id] }),
  canaryToken: one(canaryTokens, { fields: [deceptionHits.canaryTokenId], references: [canaryTokens.id] }),
  honeypotAsset: one(honeypotAssets, { fields: [deceptionHits.honeypotAssetId], references: [honeypotAssets.id] }),
}));

// Types
export type CanaryToken = typeof canaryTokens.$inferSelect;
export type InsertCanaryToken = typeof canaryTokens.$inferInsert;
export type HoneypotAsset = typeof honeypotAssets.$inferSelect;
export type InsertHoneypotAsset = typeof honeypotAssets.$inferInsert;
export type DeceptionHit = typeof deceptionHits.$inferSelect;
export type InsertDeceptionHit = typeof deceptionHits.$inferInsert;

// =========================================================================
// OT/ICS SECURITY
// =========================================================================

export const OT_ASSET_TYPES = [
  "plc",
  "hmi",
  "scada_server",
  "rtu",
  "dcs",
  "engineering_workstation",
  "historian",
  "safety_system",
  "network_switch",
  "firewall",
  "gateway",
  "sensor",
  "actuator",
  "drive",
  "robot",
  "meter",
  "relay",
  "other",
] as const;

export const OT_PROTOCOLS = [
  "modbus_tcp",
  "modbus_rtu",
  "dnp3",
  "opc_ua",
  "opc_da",
  "ethernet_ip",
  "profinet",
  "bacnet",
  "iec_61850",
  "iec_104",
  "s7comm",
  "fins",
  "hart",
  "mqtt",
  "coap",
  "unknown",
] as const;

export const PURDUE_LEVELS = [
  "level_0", // Physical process
  "level_1", // Basic control (PLCs, RTUs)
  "level_2", // Area supervisory (HMIs, SCADA)
  "level_3", // Site operations (historians, MES)
  "level_3_5", // DMZ (firewalls, jump hosts)
  "level_4", // Enterprise IT (ERP, email)
  "level_5", // Enterprise network / Internet
] as const;

export const OT_ANOMALY_TYPES = [
  "unauthorized_access",
  "firmware_change",
  "configuration_change",
  "ladder_logic_modification",
  "setpoint_change",
  "network_scan",
  "new_device",
  "protocol_violation",
  "it_ot_boundary_crossing",
  "safety_system_bypass",
  "hmi_anomaly",
  "denial_of_service",
  "replay_attack",
  "man_in_the_middle",
  "plc_stop_command",
  "plc_mode_change",
  "unexpected_write",
  "process_value_anomaly",
  "communication_loss",
  "unknown",
] as const;

export const OT_ANOMALY_SEVERITIES = ["critical", "high", "medium", "low", "informational"] as const;

export const otAssets = pgTable(
  "ot_assets",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    name: text("name").notNull(),
    description: text("description"),
    assetType: text("asset_type").notNull(), // from OT_ASSET_TYPES
    // Network identity
    ipAddress: text("ip_address"),
    macAddress: text("mac_address"),
    hostname: text("hostname"),
    // Purdue Model placement
    purdueLevel: text("purdue_level"), // from PURDUE_LEVELS
    zone: text("zone"), // logical zone name
    // Device details
    vendor: text("vendor"),
    model: text("model"),
    firmwareVersion: text("firmware_version"),
    serialNumber: text("serial_number"),
    hardwareRevision: text("hardware_revision"),
    // Protocol support
    protocols: jsonb("protocols"), // array of OT_PROTOCOLS
    // Location
    facility: text("facility"),
    area: text("area"),
    line: text("line"),
    // State
    status: text("status").notNull().default("online"), // online, offline, maintenance, unknown
    lastSeen: timestamp("last_seen"),
    firstSeen: timestamp("first_seen"),
    isManaged: boolean("is_managed").notNull().default(false),
    isCritical: boolean("is_critical").notNull().default(false),
    // Safety
    isSafetySystem: boolean("is_safety_system").notNull().default(false),
    silRating: text("sil_rating"), // SIL 1-4
    // Vulnerability tracking
    cveCount: integer("cve_count").notNull().default(0),
    highestCvss: real("highest_cvss"),
    lastVulnScan: timestamp("last_vuln_scan"),
    // Metadata
    tags: jsonb("tags"),
    metadata: jsonb("metadata"),
    discoveredBy: text("discovered_by"), // passive, manual, sensor
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_ot_assets_org").on(table.orgId),
    index("idx_ot_assets_type").on(table.orgId, table.assetType),
    index("idx_ot_assets_purdue").on(table.orgId, table.purdueLevel),
    index("idx_ot_assets_ip").on(table.orgId, table.ipAddress),
    index("idx_ot_assets_vendor").on(table.orgId, table.vendor),
    index("idx_ot_assets_status").on(table.orgId, table.status),
    index("idx_ot_assets_critical").on(table.orgId, table.isCritical),
  ],
);

export const otConnections = pgTable(
  "ot_connections",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    sourceAssetId: varchar("source_asset_id").references(() => otAssets.id),
    destAssetId: varchar("dest_asset_id").references(() => otAssets.id),
    // Connection details
    sourceIp: text("source_ip"),
    destIp: text("dest_ip"),
    sourcePort: integer("source_port"),
    destPort: integer("dest_port"),
    protocol: text("protocol"), // from OT_PROTOCOLS
    // Purdue levels
    sourcePurdueLevel: text("source_purdue_level"),
    destPurdueLevel: text("dest_purdue_level"),
    // Classification
    crossesBoundary: boolean("crosses_boundary").notNull().default(false), // IT/OT boundary crossing
    isAllowed: boolean("is_allowed").default(true),
    ruleId: text("rule_id"), // firewall rule or policy reference
    // Traffic stats
    packetCount: bigint("packet_count", { mode: "number" }).default(0),
    byteCount: bigint("byte_count", { mode: "number" }).default(0),
    lastActivity: timestamp("last_activity"),
    firstSeen: timestamp("first_seen").defaultNow(),
    // Metadata
    metadata: jsonb("metadata"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_ot_connections_org").on(table.orgId),
    index("idx_ot_connections_source").on(table.sourceAssetId),
    index("idx_ot_connections_dest").on(table.destAssetId),
    index("idx_ot_connections_boundary").on(table.orgId, table.crossesBoundary),
    index("idx_ot_connections_protocol").on(table.orgId, table.protocol),
  ],
);

export const otAnomalies = pgTable(
  "ot_anomalies",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    assetId: varchar("asset_id").references(() => otAssets.id),
    connectionId: varchar("connection_id").references(() => otConnections.id),
    // Anomaly classification
    anomalyType: text("anomaly_type").notNull(), // from OT_ANOMALY_TYPES
    severity: text("severity").notNull().default("high"), // from OT_ANOMALY_SEVERITIES
    title: text("title").notNull(),
    description: text("description"),
    // ICS context
    protocol: text("protocol"), // protocol involved
    functionCode: integer("function_code"), // Modbus function code, DNP3 function, etc.
    registerAddress: integer("register_address"), // Modbus register, DNP3 point
    previousValue: text("previous_value"), // before the anomaly
    newValue: text("new_value"), // after the anomaly
    // Source attribution
    sourceIp: text("source_ip"),
    destIp: text("dest_ip"),
    sourcePort: integer("source_port"),
    destPort: integer("dest_port"),
    // Threat intel
    icsCertAdvisory: text("ics_cert_advisory"), // related ICS-CERT advisory ID
    mitreTactic: text("mitre_tactic"),
    mitreTechnique: text("mitre_technique"), // ICS ATT&CK technique
    // Response
    alertId: varchar("alert_id").references(() => alerts.id),
    status: text("status").notNull().default("new"), // new, investigating, resolved, false_positive
    resolvedBy: varchar("resolved_by"),
    resolvedAt: timestamp("resolved_at"),
    // Metadata
    rawPacket: jsonb("raw_packet"), // captured packet data
    metadata: jsonb("metadata"),
    detectedAt: timestamp("detected_at").defaultNow(),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_ot_anomalies_org").on(table.orgId),
    index("idx_ot_anomalies_asset").on(table.assetId),
    index("idx_ot_anomalies_type").on(table.orgId, table.anomalyType),
    index("idx_ot_anomalies_severity").on(table.orgId, table.severity),
    index("idx_ot_anomalies_status").on(table.orgId, table.status),
    index("idx_ot_anomalies_time").on(table.orgId, table.detectedAt),
  ],
);

export const industrialProtocolEvents = pgTable(
  "industrial_protocol_events",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    assetId: varchar("asset_id").references(() => otAssets.id),
    // Protocol details
    protocol: text("protocol").notNull(), // from OT_PROTOCOLS
    functionCode: integer("function_code"),
    functionName: text("function_name"), // human-readable function name
    // Request/response
    sourceIp: text("source_ip"),
    destIp: text("dest_ip"),
    sourcePort: integer("source_port"),
    destPort: integer("dest_port"),
    // Payload
    registerAddress: integer("register_address"),
    registerCount: integer("register_count"),
    writeValue: text("write_value"),
    readValue: text("read_value"),
    unitId: integer("unit_id"), // Modbus unit ID / DNP3 address
    // Classification
    isWrite: boolean("is_write").notNull().default(false),
    isAnomalous: boolean("is_anomalous").notNull().default(false),
    anomalyId: varchar("anomaly_id").references(() => otAnomalies.id),
    // Metadata
    rawData: jsonb("raw_data"),
    capturedAt: timestamp("captured_at").defaultNow(),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_ipe_org").on(table.orgId),
    index("idx_ipe_asset").on(table.assetId),
    index("idx_ipe_protocol").on(table.orgId, table.protocol),
    index("idx_ipe_write").on(table.orgId, table.isWrite),
    index("idx_ipe_anomalous").on(table.orgId, table.isAnomalous),
    index("idx_ipe_time").on(table.orgId, table.capturedAt),
  ],
);

// OT/ICS Relations
export const otAssetsRelations = relations(otAssets, ({ one, many }) => ({
  organization: one(organizations, { fields: [otAssets.orgId], references: [organizations.id] }),
  sourceConnections: many(otConnections),
  anomalies: many(otAnomalies),
  protocolEvents: many(industrialProtocolEvents),
}));

export const otConnectionsRelations = relations(otConnections, ({ one }) => ({
  organization: one(organizations, { fields: [otConnections.orgId], references: [organizations.id] }),
  sourceAsset: one(otAssets, { fields: [otConnections.sourceAssetId], references: [otAssets.id] }),
  destAsset: one(otAssets, { fields: [otConnections.destAssetId], references: [otAssets.id] }),
}));

export const otAnomaliesRelations = relations(otAnomalies, ({ one }) => ({
  organization: one(organizations, { fields: [otAnomalies.orgId], references: [organizations.id] }),
  asset: one(otAssets, { fields: [otAnomalies.assetId], references: [otAssets.id] }),
  connection: one(otConnections, { fields: [otAnomalies.connectionId], references: [otConnections.id] }),
  alert: one(alerts, { fields: [otAnomalies.alertId], references: [alerts.id] }),
}));

export const industrialProtocolEventsRelations = relations(industrialProtocolEvents, ({ one }) => ({
  organization: one(organizations, { fields: [industrialProtocolEvents.orgId], references: [organizations.id] }),
  asset: one(otAssets, { fields: [industrialProtocolEvents.assetId], references: [otAssets.id] }),
  anomaly: one(otAnomalies, { fields: [industrialProtocolEvents.anomalyId], references: [otAnomalies.id] }),
}));

// OT/ICS Types
export type OtAsset = typeof otAssets.$inferSelect;
export type InsertOtAsset = typeof otAssets.$inferInsert;
export type OtConnection = typeof otConnections.$inferSelect;
export type InsertOtConnection = typeof otConnections.$inferInsert;
export type OtAnomaly = typeof otAnomalies.$inferSelect;
export type InsertOtAnomaly = typeof otAnomalies.$inferInsert;
export type IndustrialProtocolEvent = typeof industrialProtocolEvents.$inferSelect;
export type InsertIndustrialProtocolEvent = typeof industrialProtocolEvents.$inferInsert;

// ─── Investigation Chat Messages ───────────────────────────────────────────────
export const investigationChatMessages = pgTable(
  "investigation_chat_messages",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    incidentId: varchar("incident_id")
      .notNull()
      .references(() => incidents.id),
    threadId: varchar("thread_id").notNull(),
    role: text("role").notNull(), // "user" | "assistant"
    content: text("content").notNull(),
    metadata: jsonb("metadata"), // model used, token counts, latency, etc.
    createdAt: timestamp("created_at").defaultNow().notNull(),
  },
  (table) => [
    index("idx_chat_messages_thread").on(table.threadId),
    index("idx_chat_messages_incident").on(table.incidentId),
    index("idx_chat_messages_org").on(table.orgId),
  ],
);

export const investigationChatMessagesRelations = relations(investigationChatMessages, ({ one }) => ({
  organization: one(organizations, { fields: [investigationChatMessages.orgId], references: [organizations.id] }),
  incident: one(incidents, { fields: [investigationChatMessages.incidentId], references: [incidents.id] }),
}));

export type InvestigationChatMessage = typeof investigationChatMessages.$inferSelect;
export type InsertInvestigationChatMessage = typeof investigationChatMessages.$inferInsert;

// ─── AI-Generated Detection Rules ──────────────────────────────────────────────
export const aiGeneratedRules = pgTable(
  "ai_generated_rules",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    sourceIncidentId: varchar("source_incident_id").references(() => incidents.id),
    name: text("name").notNull(),
    description: text("description"),
    ruleContent: jsonb("rule_content").notNull(), // Sigma-compatible rule object
    sigmaNormalized: text("sigma_normalized"), // Sigma YAML string
    confidence: real("confidence").notNull().default(0.5),
    status: text("status").notNull().default("draft"), // draft | review | accepted | rejected
    mitreTactic: text("mitre_tactic"),
    mitreTechnique: text("mitre_technique"),
    generatedBy: text("generated_by").notNull().default("claude-opus"), // model that generated it
    createdAt: timestamp("created_at").defaultNow().notNull(),
    reviewedAt: timestamp("reviewed_at"),
    reviewedBy: varchar("reviewed_by"),
  },
  (table) => [
    index("idx_ai_rules_org").on(table.orgId),
    index("idx_ai_rules_incident").on(table.sourceIncidentId),
    index("idx_ai_rules_status").on(table.status),
  ],
);

export const aiGeneratedRulesRelations = relations(aiGeneratedRules, ({ one }) => ({
  organization: one(organizations, { fields: [aiGeneratedRules.orgId], references: [organizations.id] }),
  sourceIncident: one(incidents, { fields: [aiGeneratedRules.sourceIncidentId], references: [incidents.id] }),
}));

export type AiGeneratedRule = typeof aiGeneratedRules.$inferSelect;
export type InsertAiGeneratedRule = typeof aiGeneratedRules.$inferInsert;

// ─── War Rooms (Persistent) ──────────────────────────────────────────────────
export const WAR_ROOM_STATUSES = ["active", "standby", "closed"] as const;
export const WAR_ROOM_SEVERITIES = ["critical", "high", "medium", "low"] as const;
export const WAR_ROOM_PARTICIPANT_ROLES = ["commander", "responder", "observer"] as const;

export const warRooms = pgTable(
  "war_rooms",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    incidentId: varchar("incident_id")
      .notNull()
      .references(() => incidents.id),
    name: text("name").notNull(),
    status: text("status").notNull().default("active"), // active | standby | closed
    severity: text("severity").notNull().default("high"), // critical | high | medium | low
    commander: varchar("commander").notNull(),
    commanderName: text("commander_name").notNull().default("Commander"),
    slackChannelId: text("slack_channel_id"),
    slackChannelName: text("slack_channel_name"),
    teamsChannelId: text("teams_channel_id"),
    resolution: text("resolution"),
    templateId: varchar("template_id"), // from which template this room was created (15.3)
    archivedAt: timestamp("archived_at"), // (15.6)
    archivedBy: varchar("archived_by"), // (15.6)
    createdAt: timestamp("created_at").defaultNow().notNull(),
    closedAt: timestamp("closed_at"),
    updatedAt: timestamp("updated_at").defaultNow().notNull(),
  },
  (table) => [
    index("idx_war_rooms_org").on(table.orgId),
    index("idx_war_rooms_incident").on(table.incidentId),
    index("idx_war_rooms_status").on(table.status),
  ],
);

export const warRoomsRelations = relations(warRooms, ({ one, many }) => ({
  organization: one(organizations, { fields: [warRooms.orgId], references: [organizations.id] }),
  incident: one(incidents, { fields: [warRooms.incidentId], references: [incidents.id] }),
  messages: many(warRoomMessages),
  actionItems: many(warRoomActionItems),
  participants: many(warRoomParticipants),
  handoffs: many(warRoomHandoffs),
}));

export type WarRoom = typeof warRooms.$inferSelect;
export type InsertWarRoom = typeof warRooms.$inferInsert;

// ─── War Room Participants ──────────────────────────────────────────────────
export const warRoomParticipants = pgTable(
  "war_room_participants",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    warRoomId: varchar("war_room_id")
      .notNull()
      .references(() => warRooms.id),
    userId: varchar("user_id").notNull(),
    displayName: text("display_name").notNull(),
    role: text("role").notNull().default("responder"), // commander | responder | observer
    joinedAt: timestamp("joined_at").defaultNow().notNull(),
    leftAt: timestamp("left_at"),
  },
  (table) => [
    index("idx_wr_participants_room").on(table.warRoomId),
    index("idx_wr_participants_user").on(table.userId),
  ],
);

export const warRoomParticipantsRelations = relations(warRoomParticipants, ({ one }) => ({
  warRoom: one(warRooms, { fields: [warRoomParticipants.warRoomId], references: [warRooms.id] }),
}));

export type WarRoomParticipant = typeof warRoomParticipants.$inferSelect;
export type InsertWarRoomParticipant = typeof warRoomParticipants.$inferInsert;

// ─── War Room Messages (Timeline) ──────────────────────────────────────────
export const WAR_ROOM_MESSAGE_TYPES = [
  "message",
  "action",
  "status_change",
  "evidence",
  "decision",
  "hypothesis",
  "handoff",
  "system",
] as const;

export const warRoomMessages = pgTable(
  "war_room_messages",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    warRoomId: varchar("war_room_id")
      .notNull()
      .references(() => warRooms.id),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    actor: text("actor").notNull(),
    actorId: varchar("actor_id"),
    type: text("type").notNull().default("message"),
    content: text("content").notNull(),
    contentFormat: text("content_format").notNull().default("plain"), // plain | markdown
    parentMessageId: varchar("parent_message_id"), // for threading (15.2)
    attachments: jsonb("attachments").default([]), // file attachments (15.1)
    metadata: jsonb("metadata").default({}),
    createdAt: timestamp("created_at").defaultNow().notNull(),
  },
  (table) => [
    index("idx_wr_messages_room").on(table.warRoomId),
    index("idx_wr_messages_org").on(table.orgId),
    index("idx_wr_messages_created").on(table.createdAt),
    index("idx_wr_messages_parent").on(table.parentMessageId),
  ],
);

export const warRoomMessagesRelations = relations(warRoomMessages, ({ one }) => ({
  warRoom: one(warRooms, { fields: [warRoomMessages.warRoomId], references: [warRooms.id] }),
  organization: one(organizations, { fields: [warRoomMessages.orgId], references: [organizations.id] }),
}));

export type WarRoomMessage = typeof warRoomMessages.$inferSelect;
export type InsertWarRoomMessage = typeof warRoomMessages.$inferInsert;

// ─── War Room Action Items ──────────────────────────────────────────────────
export const warRoomActionItems = pgTable(
  "war_room_action_items",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    warRoomId: varchar("war_room_id")
      .notNull()
      .references(() => warRooms.id),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    title: text("title").notNull(),
    assignee: text("assignee").notNull().default("unassigned"),
    assigneeId: varchar("assignee_id"),
    status: text("status").notNull().default("pending"), // pending | in_progress | completed | blocked
    priority: text("priority").notNull().default("medium"), // critical | high | medium | low
    dueAt: timestamp("due_at"),
    createdAt: timestamp("created_at").defaultNow().notNull(),
    completedAt: timestamp("completed_at"),
  },
  (table) => [
    index("idx_wr_actions_room").on(table.warRoomId),
    index("idx_wr_actions_org").on(table.orgId),
    index("idx_wr_actions_status").on(table.status),
  ],
);

export const warRoomActionItemsRelations = relations(warRoomActionItems, ({ one }) => ({
  warRoom: one(warRooms, { fields: [warRoomActionItems.warRoomId], references: [warRooms.id] }),
  organization: one(organizations, { fields: [warRoomActionItems.orgId], references: [organizations.id] }),
}));

export type WarRoomActionItem = typeof warRoomActionItems.$inferSelect;
export type InsertWarRoomActionItem = typeof warRoomActionItems.$inferInsert;

// ─── War Room Handoffs (Shift Changes) ──────────────────────────────────────
export const warRoomHandoffs = pgTable(
  "war_room_handoffs",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    warRoomId: varchar("war_room_id")
      .notNull()
      .references(() => warRooms.id),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    fromUserId: varchar("from_user_id").notNull(),
    fromUserName: text("from_user_name").notNull(),
    toUserId: varchar("to_user_id").notNull(),
    toUserName: text("to_user_name").notNull(),
    summary: text("summary").notNull(), // State transfer document
    openActions: jsonb("open_actions").default([]), // Snapshot of pending action items
    keyFindings: jsonb("key_findings").default([]), // Array of key findings so far
    nextSteps: jsonb("next_steps").default([]), // Array of recommended next steps
    status: text("status").notNull().default("pending"), // pending | acknowledged
    createdAt: timestamp("created_at").defaultNow().notNull(),
    acknowledgedAt: timestamp("acknowledged_at"),
  },
  (table) => [index("idx_wr_handoffs_room").on(table.warRoomId), index("idx_wr_handoffs_org").on(table.orgId)],
);

export const warRoomHandoffsRelations = relations(warRoomHandoffs, ({ one }) => ({
  warRoom: one(warRooms, { fields: [warRoomHandoffs.warRoomId], references: [warRooms.id] }),
  organization: one(organizations, { fields: [warRoomHandoffs.orgId], references: [organizations.id] }),
}));

export type WarRoomHandoff = typeof warRoomHandoffs.$inferSelect;
export type InsertWarRoomHandoff = typeof warRoomHandoffs.$inferInsert;

// ─── War Room Templates (15.3) ──────────────────────────────────────────────
export const warRoomTemplates = pgTable(
  "war_room_templates",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    name: text("name").notNull(),
    description: text("description"),
    incidentType: text("incident_type").notNull(), // ransomware | data_breach | phishing | ddos | insider_threat | supply_chain | generic
    severity: text("severity").notNull().default("high"),
    channels: jsonb("channels").default([]), // pre-configured channels/topics
    checklist: jsonb("checklist").default([]), // pre-created action items
    roleAssignments: jsonb("role_assignments").default([]), // default role assignments
    isBuiltIn: boolean("is_built_in").notNull().default(false),
    createdBy: varchar("created_by"),
    createdAt: timestamp("created_at").defaultNow().notNull(),
    updatedAt: timestamp("updated_at").defaultNow().notNull(),
  },
  (table) => [index("idx_wr_templates_org").on(table.orgId), index("idx_wr_templates_type").on(table.incidentType)],
);

export const warRoomTemplatesRelations = relations(warRoomTemplates, ({ one }) => ({
  organization: one(organizations, { fields: [warRoomTemplates.orgId], references: [organizations.id] }),
}));

export type WarRoomTemplate = typeof warRoomTemplates.$inferSelect;
export type InsertWarRoomTemplate = typeof warRoomTemplates.$inferInsert;

// ─── War Room Activity Log (15.5) ───────────────────────────────────────────
export const warRoomActivityLog = pgTable(
  "war_room_activity_log",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    warRoomId: varchar("war_room_id")
      .notNull()
      .references(() => warRooms.id),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    action: text("action").notNull(), // joined | left | evidence_pinned | evidence_unpinned | status_changed | playbook_triggered | role_changed | call_started | call_ended | archived | template_applied
    actorId: varchar("actor_id"),
    actorName: text("actor_name").notNull(),
    details: jsonb("details").default({}),
    createdAt: timestamp("created_at").defaultNow().notNull(),
  },
  (table) => [
    index("idx_wr_activity_room").on(table.warRoomId),
    index("idx_wr_activity_org").on(table.orgId),
    index("idx_wr_activity_created").on(table.createdAt),
  ],
);

export const warRoomActivityLogRelations = relations(warRoomActivityLog, ({ one }) => ({
  warRoom: one(warRooms, { fields: [warRoomActivityLog.warRoomId], references: [warRooms.id] }),
  organization: one(organizations, { fields: [warRoomActivityLog.orgId], references: [organizations.id] }),
}));

export type WarRoomActivity = typeof warRoomActivityLog.$inferSelect;
export type InsertWarRoomActivity = typeof warRoomActivityLog.$inferInsert;

// ─── Threat Hunting Workbench ───────────────────────────────────────────────

export const HUNT_QUERY_TYPES = ["sigma", "yara", "kql", "sql", "custom"] as const;
export const HUNT_STATUSES = ["draft", "ready", "running", "completed", "failed", "cancelled"] as const;

export const threatHunts = pgTable(
  "threat_hunts",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    orgId: text("org_id").notNull(),
    name: text("name").notNull(),
    description: text("description"),
    queryType: text("query_type").notNull(), // sigma | yara | kql | sql | custom
    queryText: text("query_text").notNull(),
    compiledQuery: text("compiled_query"), // compiled version ready for execution
    status: text("status").notNull().default("draft"),
    hypothesis: text("hypothesis"), // analyst hypothesis being tested
    mitreTechniques: jsonb("mitre_techniques").default([]), // array of MITRE ATT&CK technique IDs
    tags: jsonb("tags").default([]),
    lastRunAt: timestamp("last_run_at"),
    lastRunDurationMs: integer("last_run_duration_ms"),
    lastRunEventCount: integer("last_run_event_count"),
    createdBy: text("created_by"),
    createdAt: timestamp("created_at").defaultNow().notNull(),
    updatedAt: timestamp("updated_at").defaultNow().notNull(),
  },
  (table) => [index("idx_th_hunts_org").on(table.orgId), index("idx_th_hunts_status").on(table.status)],
);

export const huntResults = pgTable(
  "hunt_results",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    orgId: text("org_id").notNull(),
    huntId: uuid("hunt_id")
      .notNull()
      .references(() => threatHunts.id, { onDelete: "cascade" }),
    eventCount: integer("event_count").notNull().default(0),
    eventsJson: jsonb("events_json").default([]), // matched events
    summary: text("summary"), // AI-generated result summary
    falsePositiveCount: integer("false_positive_count").default(0),
    truePositiveCount: integer("true_positive_count").default(0),
    executionDurationMs: integer("execution_duration_ms"),
    executedAt: timestamp("executed_at").defaultNow().notNull(),
    executedBy: text("executed_by"),
    linkedIncidentId: varchar("linked_incident_id").references(() => incidents.id),
  },
  (table) => [index("idx_th_results_hunt").on(table.huntId), index("idx_th_results_org").on(table.orgId)],
);

export const huntLibrary = pgTable(
  "hunt_library",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    orgId: text("org_id").notNull(),
    huntId: uuid("hunt_id")
      .notNull()
      .references(() => threatHunts.id, { onDelete: "cascade" }),
    isPublic: boolean("is_public").notNull().default(false),
    sharedBy: text("shared_by"),
    category: text("category"), // apt, ransomware, insider_threat, lateral_movement, etc.
    difficulty: text("difficulty"), // beginner, intermediate, advanced
    rating: integer("rating").default(0),
    downloadCount: integer("download_count").default(0),
    sharedAt: timestamp("shared_at").defaultNow().notNull(),
  },
  (table) => [index("idx_th_library_org").on(table.orgId), index("idx_th_library_public").on(table.isPublic)],
);

export const huntSchedules = pgTable(
  "hunt_schedules",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    orgId: text("org_id").notNull(),
    huntId: uuid("hunt_id")
      .notNull()
      .references(() => threatHunts.id, { onDelete: "cascade" }),
    cadence: text("cadence").notNull(), // daily, weekly, biweekly, monthly
    dayOfWeek: integer("day_of_week"), // 0=Sun, 6=Sat (for weekly/biweekly)
    hourUtc: integer("hour_utc").notNull().default(8), // hour of day UTC
    enabled: boolean("enabled").notNull().default(true),
    nextRunAt: timestamp("next_run_at"),
    lastRunAt: timestamp("last_run_at"),
    createdAt: timestamp("created_at").defaultNow().notNull(),
  },
  (table) => [index("idx_th_schedules_org").on(table.orgId), index("idx_th_schedules_hunt").on(table.huntId)],
);

export const huntPlaybooks = pgTable(
  "hunt_playbooks",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    orgId: text("org_id").notNull(),
    name: text("name").notNull(),
    description: text("description"),
    threatActor: text("threat_actor"), // APT29, FIN7, Lazarus, etc.
    mitreTechniques: jsonb("mitre_techniques").default([]),
    steps: jsonb("steps").default([]), // array of { order, title, description, queryType, queryText, expectedOutcome }
    difficulty: text("difficulty").default("intermediate"),
    estimatedTimeMin: integer("estimated_time_min"),
    datasourcesRequired: jsonb("datasources_required").default([]),
    createdBy: text("created_by"),
    createdAt: timestamp("created_at").defaultNow().notNull(),
    updatedAt: timestamp("updated_at").defaultNow().notNull(),
  },
  (table) => [index("idx_th_playbooks_org").on(table.orgId)],
);

export const threatHuntsRelations = relations(threatHunts, ({ one, many }) => ({
  organization: one(organizations, { fields: [threatHunts.orgId], references: [organizations.id] }),
  results: many(huntResults),
  schedules: many(huntSchedules),
}));

export const huntResultsRelations = relations(huntResults, ({ one }) => ({
  hunt: one(threatHunts, { fields: [huntResults.huntId], references: [threatHunts.id] }),
}));

export const huntLibraryRelations = relations(huntLibrary, ({ one }) => ({
  hunt: one(threatHunts, { fields: [huntLibrary.huntId], references: [threatHunts.id] }),
}));

export const huntSchedulesRelations = relations(huntSchedules, ({ one }) => ({
  hunt: one(threatHunts, { fields: [huntSchedules.huntId], references: [threatHunts.id] }),
}));

export const huntPlaybooksRelations = relations(huntPlaybooks, ({ one }) => ({
  organization: one(organizations, { fields: [huntPlaybooks.orgId], references: [organizations.id] }),
}));

export type ThreatHunt = typeof threatHunts.$inferSelect;
export type InsertThreatHunt = typeof threatHunts.$inferInsert;
export type HuntResult = typeof huntResults.$inferSelect;
export type InsertHuntResult = typeof huntResults.$inferInsert;
export type HuntLibraryEntry = typeof huntLibrary.$inferSelect;
export type InsertHuntLibraryEntry = typeof huntLibrary.$inferInsert;
export type HuntSchedule = typeof huntSchedules.$inferSelect;
export type InsertHuntSchedule = typeof huntSchedules.$inferInsert;
export type HuntPlaybook = typeof huntPlaybooks.$inferSelect;
export type InsertHuntPlaybook = typeof huntPlaybooks.$inferInsert;

// ─── Threat Hunting Notebooks (16.3) ────────────────────────────────────────
export const huntNotebooks = pgTable(
  "hunt_notebooks",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    orgId: text("org_id").notNull(),
    name: text("name").notNull(),
    description: text("description"),
    steps: jsonb("steps").default([]), // array of { id, title, queryType, queryText, notes, resultSummary, outputVariables }
    createdBy: text("created_by"),
    createdAt: timestamp("created_at").defaultNow().notNull(),
    updatedAt: timestamp("updated_at").defaultNow().notNull(),
  },
  (table) => [index("idx_th_notebooks_org").on(table.orgId)],
);

export const huntNotebooksRelations = relations(huntNotebooks, ({ one }) => ({
  organization: one(organizations, { fields: [huntNotebooks.orgId], references: [organizations.id] }),
}));

export type HuntNotebook = typeof huntNotebooks.$inferSelect;
export type InsertHuntNotebook = typeof huntNotebooks.$inferInsert;

// ─── Hunt Result Cache (16.6) ───────────────────────────────────────────────
export const huntCache = pgTable(
  "hunt_cache",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    orgId: text("org_id").notNull(),
    queryHash: text("query_hash").notNull(),
    queryType: text("query_type").notNull(),
    queryText: text("query_text").notNull(),
    resultJson: jsonb("result_json").default({}),
    eventCount: integer("event_count").notNull().default(0),
    executionDurationMs: integer("execution_duration_ms"),
    ttlSeconds: integer("ttl_seconds").notNull().default(3600),
    hitCount: integer("hit_count").notNull().default(0),
    cachedAt: timestamp("cached_at").defaultNow().notNull(),
    expiresAt: timestamp("expires_at").notNull(),
  },
  (table) => [index("idx_th_cache_org").on(table.orgId), index("idx_th_cache_hash").on(table.queryHash)],
);

export type HuntCacheEntry = typeof huntCache.$inferSelect;
export type InsertHuntCacheEntry = typeof huntCache.$inferInsert;

// ─── Hunt Collaboration Sessions (16.4) ─────────────────────────────────────
export const huntCollaborations = pgTable(
  "hunt_collaborations",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    orgId: text("org_id").notNull(),
    huntId: uuid("hunt_id").references(() => threatHunts.id, { onDelete: "cascade" }),
    sessionName: text("session_name").notNull(),
    participants: jsonb("participants").default([]), // array of { userId, name, color, cursorPosition, joinedAt }
    sharedResults: jsonb("shared_results").default([]),
    chatMessages: jsonb("chat_messages").default([]), // array of { userId, name, message, timestamp }
    status: text("status").notNull().default("active"), // active | ended
    startedAt: timestamp("started_at").defaultNow().notNull(),
    endedAt: timestamp("ended_at"),
  },
  (table) => [index("idx_th_collab_org").on(table.orgId), index("idx_th_collab_hunt").on(table.huntId)],
);

export const huntCollaborationsRelations = relations(huntCollaborations, ({ one }) => ({
  hunt: one(threatHunts, { fields: [huntCollaborations.huntId], references: [threatHunts.id] }),
}));

export type HuntCollaboration = typeof huntCollaborations.$inferSelect;
export type InsertHuntCollaboration = typeof huntCollaborations.$inferInsert;

// ─── Hunt Schedule Drift Detection (16.7) ───────────────────────────────────
export const huntScheduleDrifts = pgTable(
  "hunt_schedule_drifts",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    orgId: text("org_id").notNull(),
    scheduleId: uuid("schedule_id").references(() => huntSchedules.id, { onDelete: "cascade" }),
    huntId: uuid("hunt_id").references(() => threatHunts.id, { onDelete: "cascade" }),
    previousEventCount: integer("previous_event_count").notNull(),
    currentEventCount: integer("current_event_count").notNull(),
    driftPercentage: integer("drift_percentage").notNull(), // percentage change
    driftDirection: text("drift_direction").notNull(), // increase | decrease | stable
    isSignificant: boolean("is_significant").notNull().default(false),
    detectedAt: timestamp("detected_at").defaultNow().notNull(),
    acknowledged: boolean("acknowledged").notNull().default(false),
  },
  (table) => [index("idx_th_drift_org").on(table.orgId), index("idx_th_drift_schedule").on(table.scheduleId)],
);

export const huntScheduleDriftsRelations = relations(huntScheduleDrifts, ({ one }) => ({
  schedule: one(huntSchedules, { fields: [huntScheduleDrifts.scheduleId], references: [huntSchedules.id] }),
  hunt: one(threatHunts, { fields: [huntScheduleDrifts.huntId], references: [threatHunts.id] }),
}));

export type HuntScheduleDrift = typeof huntScheduleDrifts.$inferSelect;
export type InsertHuntScheduleDrift = typeof huntScheduleDrifts.$inferInsert;

// ─── Community Hunt Shares (16.10) ──────────────────────────────────────────
export const communityHuntShares = pgTable(
  "community_hunt_shares",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    orgId: text("org_id").notNull(),
    huntId: uuid("hunt_id").references(() => threatHunts.id, { onDelete: "cascade" }),
    title: text("title").notNull(),
    description: text("description"),
    queryType: text("query_type").notNull(),
    queryText: text("query_text").notNull(),
    category: text("category"),
    mitreTechniques: jsonb("mitre_techniques").default([]),
    tags: jsonb("tags").default([]),
    anonymizedStats: jsonb("anonymized_stats").default({}), // { detectionRate, avgExecutionMs, totalRuns }
    upvotes: integer("upvotes").notNull().default(0),
    downloads: integer("downloads").notNull().default(0),
    sharedBy: text("shared_by"),
    sharedAt: timestamp("shared_at").defaultNow().notNull(),
  },
  (table) => [index("idx_th_community_org").on(table.orgId), index("idx_th_community_category").on(table.category)],
);

export const communityHuntSharesRelations = relations(communityHuntShares, ({ one }) => ({
  hunt: one(threatHunts, { fields: [communityHuntShares.huntId], references: [threatHunts.id] }),
}));

export type CommunityHuntShare = typeof communityHuntShares.$inferSelect;
export type InsertCommunityHuntShare = typeof communityHuntShares.$inferInsert;

// ============================
// Security Data Lake
// ============================

export const DATA_LAKE_COMPLIANCE_FRAMEWORKS = [
  "gdpr",
  "sox",
  "hipaa",
  "pci_dss",
  "iso27001",
  "nist",
  "soc2",
  "nis2",
  "dora",
  "cbest",
  "mas_trm",
  "ifsca",
  "pdpa",
  "popia",
  "lgpd",
  "pipeda",
  "asd_essential8",
  "ccpa",
  "cmmc",
  "nerc_cip",
  "swift_csp",
  "iec_62443",
  "custom",
] as const;
export const TIERING_JOB_STATUSES = ["pending", "running", "completed", "failed", "cancelled"] as const;
export const EDISCOVERY_STATUSES = ["requested", "processing", "ready", "downloaded", "expired", "failed"] as const;
export const RETENTION_DATA_TYPES = [
  "alerts",
  "incidents",
  "audit_logs",
  "sli_metrics",
  "jobs",
  "connector_job_runs",
  "outbox_events",
  "ingestion_logs",
] as const;

export const dataLakeRetentionPolicies = pgTable(
  "data_lake_retention_policies",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    orgId: text("org_id").notNull(),
    name: text("name").notNull(),
    dataType: text("data_type").notNull(), // alerts, incidents, audit_logs, etc.
    complianceFramework: text("compliance_framework").notNull().default("custom"), // gdpr, sox, hipaa, etc.
    hotRetentionDays: integer("hot_retention_days").notNull().default(90),
    warmRetentionDays: integer("warm_retention_days").notNull().default(365),
    coldRetentionDays: integer("cold_retention_days").notNull().default(2555), // 7 years
    purgeAfterDays: integer("purge_after_days"), // null = never purge
    compressionFormat: text("compression_format").notNull().default("parquet"), // parquet, gzip_json
    isActive: boolean("is_active").notNull().default(true),
    priority: integer("priority").notNull().default(0), // higher = higher priority when multiple match
    filterCriteria: jsonb("filter_criteria").default({}), // optional filters (severity, source, etc.)
    createdBy: text("created_by"),
    updatedBy: text("updated_by"),
    createdAt: timestamp("created_at").defaultNow().notNull(),
    updatedAt: timestamp("updated_at").defaultNow().notNull(),
  },
  (table) => [
    index("idx_dl_retention_org").on(table.orgId),
    index("idx_dl_retention_org_type").on(table.orgId, table.dataType),
    index("idx_dl_retention_framework").on(table.complianceFramework),
  ],
);

export const tieringJobs = pgTable(
  "tiering_jobs",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    orgId: text("org_id").notNull(),
    dataType: text("data_type").notNull(),
    sourceTier: text("source_tier").notNull(), // hot, warm
    targetTier: text("target_tier").notNull(), // warm, cold
    status: text("status").notNull().default("pending"), // pending, running, completed, failed, cancelled
    recordCount: integer("record_count").default(0),
    recordsProcessed: integer("records_processed").default(0),
    compressedSizeBytes: bigint("compressed_size_bytes", { mode: "number" }).default(0),
    s3KeyPrefix: text("s3_key_prefix"),
    parquetManifest: jsonb("parquet_manifest").default({}), // { files: [...], schema: {...} }
    errorMessage: text("error_message"),
    retentionPolicyId: uuid("retention_policy_id"),
    startedAt: timestamp("started_at"),
    completedAt: timestamp("completed_at"),
    createdAt: timestamp("created_at").defaultNow().notNull(),
  },
  (table) => [
    index("idx_tiering_jobs_org").on(table.orgId),
    index("idx_tiering_jobs_status").on(table.status),
    index("idx_tiering_jobs_org_type").on(table.orgId, table.dataType),
  ],
);

export const eDiscoveryExports = pgTable(
  "ediscovery_exports",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    orgId: text("org_id").notNull(),
    name: text("name").notNull(),
    description: text("description"),
    status: text("status").notNull().default("requested"), // requested, processing, ready, downloaded, expired, failed
    legalHoldId: varchar("legal_hold_id"), // reference to legal hold if applicable
    dataTypes: jsonb("data_types").default([]), // array of data types to include
    dateRangeStart: timestamp("date_range_start"),
    dateRangeEnd: timestamp("date_range_end"),
    filterCriteria: jsonb("filter_criteria").default({}),
    exportFormat: text("export_format").notNull().default("json"), // json, csv, parquet
    includeMetadata: boolean("include_metadata").notNull().default(true),
    includeChainOfCustody: boolean("include_chain_of_custody").notNull().default(true),
    totalRecords: integer("total_records").default(0),
    exportSizeBytes: bigint("export_size_bytes", { mode: "number" }).default(0),
    s3Key: text("s3_key"),
    checksumSha256: text("checksum_sha256"),
    downloadCount: integer("download_count").default(0),
    expiresAt: timestamp("expires_at"),
    requestedBy: text("requested_by"),
    requestedByName: text("requested_by_name"),
    approvedBy: text("approved_by"),
    approvedAt: timestamp("approved_at"),
    completedAt: timestamp("completed_at"),
    createdAt: timestamp("created_at").defaultNow().notNull(),
  },
  (table) => [
    index("idx_ediscovery_org").on(table.orgId),
    index("idx_ediscovery_status").on(table.status),
    index("idx_ediscovery_hold").on(table.legalHoldId),
  ],
);

export const coldStorageInventory = pgTable(
  "cold_storage_inventory",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    orgId: text("org_id").notNull(),
    dataType: text("data_type").notNull(),
    tier: text("tier").notNull().default("cold"), // warm, cold
    s3Key: text("s3_key").notNull(),
    format: text("format").notNull().default("parquet"), // parquet, gzip_json
    recordCount: integer("record_count").notNull().default(0),
    compressedSizeBytes: bigint("compressed_size_bytes", { mode: "number" }).notNull().default(0),
    oldestRecord: timestamp("oldest_record"),
    newestRecord: timestamp("newest_record"),
    checksumSha256: text("checksum_sha256"),
    tieringJobId: uuid("tiering_job_id"),
    retentionPolicyId: uuid("retention_policy_id"),
    purgeEligibleAt: timestamp("purge_eligible_at"), // when this data can be deleted
    isRehydrated: boolean("is_rehydrated").notNull().default(false),
    rehydratedAt: timestamp("rehydrated_at"),
    createdAt: timestamp("created_at").defaultNow().notNull(),
  },
  (table) => [
    index("idx_cold_inv_org").on(table.orgId),
    index("idx_cold_inv_org_type").on(table.orgId, table.dataType),
    index("idx_cold_inv_tier").on(table.tier),
    index("idx_cold_inv_purge").on(table.purgeEligibleAt),
  ],
);

export const dataLakeQueries = pgTable(
  "data_lake_queries",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    orgId: text("org_id").notNull(),
    queryText: text("query_text").notNull(),
    queryType: text("query_type").notNull().default("federated"), // federated, hot_only, cold_only
    dataTypes: jsonb("data_types").default([]),
    dateRangeStart: timestamp("date_range_start"),
    dateRangeEnd: timestamp("date_range_end"),
    status: text("status").notNull().default("pending"), // pending, running, completed, failed
    hotResultCount: integer("hot_result_count").default(0),
    coldResultCount: integer("cold_result_count").default(0),
    totalResultCount: integer("total_result_count").default(0),
    executionTimeMs: integer("execution_time_ms"),
    resultS3Key: text("result_s3_key"), // for large result sets stored in S3
    errorMessage: text("error_message"),
    executedBy: text("executed_by"),
    createdAt: timestamp("created_at").defaultNow().notNull(),
    completedAt: timestamp("completed_at"),
  },
  (table) => [index("idx_dl_queries_org").on(table.orgId), index("idx_dl_queries_status").on(table.status)],
);

export const dataLakeRetentionPoliciesRelations = relations(dataLakeRetentionPolicies, ({ one }) => ({
  organization: one(organizations, { fields: [dataLakeRetentionPolicies.orgId], references: [organizations.id] }),
}));

export const tieringJobsRelations = relations(tieringJobs, ({ one }) => ({
  organization: one(organizations, { fields: [tieringJobs.orgId], references: [organizations.id] }),
}));

export const eDiscoveryExportsRelations = relations(eDiscoveryExports, ({ one }) => ({
  organization: one(organizations, { fields: [eDiscoveryExports.orgId], references: [organizations.id] }),
}));

export const coldStorageInventoryRelations = relations(coldStorageInventory, ({ one }) => ({
  organization: one(organizations, { fields: [coldStorageInventory.orgId], references: [organizations.id] }),
}));

export const dataLakeQueriesRelations = relations(dataLakeQueries, ({ one }) => ({
  organization: one(organizations, { fields: [dataLakeQueries.orgId], references: [organizations.id] }),
}));

export type DataLakeRetentionPolicy = typeof dataLakeRetentionPolicies.$inferSelect;
export type InsertDataLakeRetentionPolicy = typeof dataLakeRetentionPolicies.$inferInsert;
export type TieringJob = typeof tieringJobs.$inferSelect;
export type InsertTieringJob = typeof tieringJobs.$inferInsert;
export type EDiscoveryExport = typeof eDiscoveryExports.$inferSelect;
export type InsertEDiscoveryExport = typeof eDiscoveryExports.$inferInsert;
export type ColdStorageInventoryEntry = typeof coldStorageInventory.$inferSelect;
export type InsertColdStorageInventoryEntry = typeof coldStorageInventory.$inferInsert;
export type DataLakeQuery = typeof dataLakeQueries.$inferSelect;
export type InsertDataLakeQuery = typeof dataLakeQueries.$inferInsert;

/* ── Data Residency & Sovereignty ────────────────────────────────── */

export const DATA_REGIONS = ["US", "EU", "APAC", "ME"] as const;
export type DataRegion = (typeof DATA_REGIONS)[number];

export const DATA_REGION_ENDPOINTS: Record<
  DataRegion,
  { primary: string; label: string; awsRegion: string; gdprApplicable: boolean }
> = {
  US: { primary: "us-east-1", label: "United States", awsRegion: "us-east-1", gdprApplicable: false },
  EU: { primary: "eu-central-1", label: "European Union (Frankfurt)", awsRegion: "eu-central-1", gdprApplicable: true },
  APAC: {
    primary: "ap-southeast-1",
    label: "Asia Pacific (Singapore)",
    awsRegion: "ap-southeast-1",
    gdprApplicable: false,
  },
  ME: { primary: "me-south-1", label: "Middle East (Bahrain)", awsRegion: "me-south-1", gdprApplicable: false },
};

export const SOVEREIGN_KEY_STATUSES = ["active", "rotating", "revoked", "expired"] as const;
export type SovereignKeyStatus = (typeof SOVEREIGN_KEY_STATUSES)[number];

export const sovereignKeys = pgTable(
  "sovereign_keys",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    keyAlias: text("key_alias").notNull(),
    keyProvider: text("key_provider").notNull().default("aws-kms"),
    keyArn: text("key_arn"),
    keyFingerprint: text("key_fingerprint"),
    status: text("status").notNull().default("active"),
    rotationIntervalDays: integer("rotation_interval_days").default(90),
    lastRotatedAt: timestamp("last_rotated_at"),
    nextRotationAt: timestamp("next_rotation_at"),
    metadata: jsonb("metadata"),
    createdBy: varchar("created_by"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [index("idx_sovereign_keys_org").on(table.orgId), index("idx_sovereign_keys_status").on(table.status)],
);

export const crossBorderFlowRules = pgTable(
  "cross_border_flow_rules",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    name: text("name").notNull(),
    sourceRegion: text("source_region").notNull(),
    destinationRegion: text("destination_region").notNull(),
    action: text("action").notNull().default("block"),
    dataClassification: text("data_classification").default("all"),
    requiresApproval: boolean("requires_approval").notNull().default(true),
    enabled: boolean("enabled").notNull().default(true),
    justification: text("justification"),
    approvedBy: varchar("approved_by"),
    approvedAt: timestamp("approved_at"),
    createdBy: varchar("created_by"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_cbf_rules_org").on(table.orgId),
    index("idx_cbf_rules_regions").on(table.sourceRegion, table.destinationRegion),
  ],
);

export const crossBorderFlowAudit = pgTable(
  "cross_border_flow_audit",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    sourceRegion: text("source_region").notNull(),
    destinationRegion: text("destination_region").notNull(),
    dataType: text("data_type").notNull(),
    action: text("action").notNull(),
    ruleId: varchar("rule_id"),
    blocked: boolean("blocked").notNull().default(false),
    userId: varchar("user_id"),
    ipAddress: text("ip_address"),
    userAgent: text("user_agent"),
    details: jsonb("details"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [index("idx_cbf_audit_org").on(table.orgId), index("idx_cbf_audit_created").on(table.createdAt)],
);

export const sovereignKeysRelations = relations(sovereignKeys, ({ one }) => ({
  organization: one(organizations, { fields: [sovereignKeys.orgId], references: [organizations.id] }),
}));

export const crossBorderFlowRulesRelations = relations(crossBorderFlowRules, ({ one }) => ({
  organization: one(organizations, { fields: [crossBorderFlowRules.orgId], references: [organizations.id] }),
}));

export const crossBorderFlowAuditRelations = relations(crossBorderFlowAudit, ({ one }) => ({
  organization: one(organizations, { fields: [crossBorderFlowAudit.orgId], references: [organizations.id] }),
}));

export type SovereignKey = typeof sovereignKeys.$inferSelect;
export type InsertSovereignKey = typeof sovereignKeys.$inferInsert;
export type CrossBorderFlowRule = typeof crossBorderFlowRules.$inferSelect;
export type InsertCrossBorderFlowRule = typeof crossBorderFlowRules.$inferInsert;
export type CrossBorderFlowAuditEntry = typeof crossBorderFlowAudit.$inferSelect;
export type InsertCrossBorderFlowAuditEntry = typeof crossBorderFlowAudit.$inferInsert;

/* ========================================================================
 * MOBILE & REMOTE WORKER SECURITY
 * ======================================================================== */

export const MOBILE_PLATFORMS = ["android", "ios", "windows", "macos", "linux", "chromeos"] as const;
export type MobilePlatform = (typeof MOBILE_PLATFORMS)[number];

export const DEVICE_COMPLIANCE_STATUSES = ["compliant", "non-compliant", "pending", "unknown"] as const;
export type DeviceComplianceStatus = (typeof DEVICE_COMPLIANCE_STATUSES)[number];

export const MDM_PROVIDERS = ["jamf", "intune", "workspace-one", "manual"] as const;
export type MdmProvider = (typeof MDM_PROVIDERS)[number];

export const ZTNA_ACTIONS = ["allow", "deny", "step-up-mfa", "quarantine", "monitor"] as const;
export type ZtnaAction = (typeof ZTNA_ACTIONS)[number];

export const DEVICE_RISK_LEVELS = ["low", "medium", "high", "critical"] as const;
export type DeviceRiskLevel = (typeof DEVICE_RISK_LEVELS)[number];

export const MOBILE_THREAT_TYPES = [
  "sideloaded-app",
  "rooted-jailbroken",
  "outdated-os",
  "missing-encryption",
  "malicious-app",
  "network-attack",
  "phishing",
  "data-leakage",
  "suspicious-permissions",
  "unknown-wifi",
  "vpn-bypass",
  "certificate-anomaly",
] as const;
export type MobileThreatType = (typeof MOBILE_THREAT_TYPES)[number];

export const mobileDevices = pgTable(
  "mobile_devices",
  {
    id: varchar("id", { length: 36 })
      .primaryKey()
      .$defaultFn(() => crypto.randomUUID()),
    orgId: varchar("org_id", { length: 36 }).notNull(),
    userId: varchar("user_id", { length: 36 }),
    deviceName: text("device_name").notNull(),
    platform: text("platform").notNull(),
    osVersion: text("os_version"),
    model: text("model"),
    manufacturer: text("manufacturer"),
    serialNumber: text("serial_number"),
    imei: text("imei"),
    macAddress: text("mac_address"),
    mdmProvider: text("mdm_provider"),
    mdmDeviceId: text("mdm_device_id"),
    mdmEnrolledAt: timestamp("mdm_enrolled_at"),
    lastCheckIn: timestamp("last_check_in"),
    complianceStatus: text("compliance_status").notNull().default("unknown"),
    riskLevel: text("risk_level").notNull().default("low"),
    riskScore: integer("risk_score").notNull().default(0),
    isEncrypted: boolean("is_encrypted").default(false),
    isRooted: boolean("is_rooted").default(false),
    isJailbroken: boolean("is_jailbroken").default(false),
    hasMdm: boolean("has_mdm").default(false),
    hasScreenLock: boolean("has_screen_lock").default(false),
    hasFirewall: boolean("has_firewall").default(false),
    isVpnActive: boolean("is_vpn_active").default(false),
    vpnProvider: text("vpn_provider"),
    lastKnownIp: text("last_known_ip"),
    lastKnownLocation: text("last_known_location"),
    lastKnownCountry: text("last_known_country"),
    installedApps: jsonb("installed_apps"),
    sideloadedApps: jsonb("sideloaded_apps"),
    certificates: jsonb("certificates"),
    tags: jsonb("tags"),
    metadata: jsonb("metadata"),
    status: text("status").notNull().default("active"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_mobile_devices_org").on(table.orgId),
    index("idx_mobile_devices_user").on(table.userId),
    index("idx_mobile_devices_compliance").on(table.complianceStatus),
    index("idx_mobile_devices_risk").on(table.riskLevel),
  ],
);

export const devicePostureChecks = pgTable(
  "device_posture_checks",
  {
    id: varchar("id", { length: 36 })
      .primaryKey()
      .$defaultFn(() => crypto.randomUUID()),
    orgId: varchar("org_id", { length: 36 }).notNull(),
    deviceId: varchar("device_id", { length: 36 }).notNull(),
    checkType: text("check_type").notNull(),
    checkName: text("check_name").notNull(),
    passed: boolean("passed").notNull(),
    details: text("details"),
    severity: text("severity").notNull().default("medium"),
    remediationHint: text("remediation_hint"),
    checkedAt: timestamp("checked_at").defaultNow(),
  },
  (table) => [index("idx_posture_checks_org").on(table.orgId), index("idx_posture_checks_device").on(table.deviceId)],
);

export const mobileThreats = pgTable(
  "mobile_threats",
  {
    id: varchar("id", { length: 36 })
      .primaryKey()
      .$defaultFn(() => crypto.randomUUID()),
    orgId: varchar("org_id", { length: 36 }).notNull(),
    deviceId: varchar("device_id", { length: 36 }).notNull(),
    threatType: text("threat_type").notNull(),
    severity: text("severity").notNull().default("medium"),
    title: text("title").notNull(),
    description: text("description"),
    appName: text("app_name"),
    appPackage: text("app_package"),
    networkSsid: text("network_ssid"),
    sourceIp: text("source_ip"),
    mitreTactic: text("mitre_tactic"),
    mitreTechnique: text("mitre_technique"),
    status: text("status").notNull().default("new"),
    resolvedBy: varchar("resolved_by", { length: 36 }),
    resolvedAt: timestamp("resolved_at"),
    alertId: varchar("alert_id", { length: 36 }),
    metadata: jsonb("metadata"),
    detectedAt: timestamp("detected_at").defaultNow(),
  },
  (table) => [
    index("idx_mobile_threats_org").on(table.orgId),
    index("idx_mobile_threats_device").on(table.deviceId),
    index("idx_mobile_threats_status").on(table.status),
  ],
);

export const ztnaPolicies = pgTable(
  "ztna_policies",
  {
    id: varchar("id", { length: 36 })
      .primaryKey()
      .$defaultFn(() => crypto.randomUUID()),
    orgId: varchar("org_id", { length: 36 }).notNull(),
    name: text("name").notNull(),
    description: text("description"),
    enabled: boolean("enabled").notNull().default(true),
    priority: integer("priority").notNull().default(100),
    conditions: jsonb("conditions").notNull(),
    action: text("action").notNull().default("deny"),
    requireMfa: boolean("require_mfa").default(false),
    allowedPlatforms: jsonb("allowed_platforms"),
    minOsVersion: jsonb("min_os_version"),
    requireEncryption: boolean("require_encryption").default(false),
    requireMdm: boolean("require_mdm").default(false),
    requireScreenLock: boolean("require_screen_lock").default(false),
    blockRooted: boolean("block_rooted").default(true),
    maxRiskScore: integer("max_risk_score").default(70),
    allowedCountries: jsonb("allowed_countries"),
    blockedCountries: jsonb("blocked_countries"),
    timeRestrictions: jsonb("time_restrictions"),
    createdBy: varchar("created_by", { length: 36 }),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [index("idx_ztna_policies_org").on(table.orgId)],
);

export const remoteWorkerSessions = pgTable(
  "remote_worker_sessions",
  {
    id: varchar("id", { length: 36 })
      .primaryKey()
      .$defaultFn(() => crypto.randomUUID()),
    orgId: varchar("org_id", { length: 36 }).notNull(),
    userId: varchar("user_id", { length: 36 }).notNull(),
    deviceId: varchar("device_id", { length: 36 }),
    sessionStart: timestamp("session_start").defaultNow(),
    sessionEnd: timestamp("session_end"),
    ipAddress: text("ip_address"),
    country: text("country"),
    city: text("city"),
    vpnConnected: boolean("vpn_connected").default(false),
    vpnProvider: text("vpn_provider"),
    isOffHours: boolean("is_off_hours").default(false),
    isNewLocation: boolean("is_new_location").default(false),
    riskScore: integer("risk_score").notNull().default(0),
    riskFactors: jsonb("risk_factors"),
    ztnaDecision: text("ztna_decision"),
    policyId: varchar("policy_id", { length: 36 }),
    metadata: jsonb("metadata"),
  },
  (table) => [
    index("idx_remote_sessions_org").on(table.orgId),
    index("idx_remote_sessions_user").on(table.userId),
    index("idx_remote_sessions_device").on(table.deviceId),
  ],
);

export const mobileDevicesRelations = relations(mobileDevices, ({ one }) => ({
  organization: one(organizations, { fields: [mobileDevices.orgId], references: [organizations.id] }),
}));

export const devicePostureChecksRelations = relations(devicePostureChecks, ({ one }) => ({
  organization: one(organizations, { fields: [devicePostureChecks.orgId], references: [organizations.id] }),
  device: one(mobileDevices, { fields: [devicePostureChecks.deviceId], references: [mobileDevices.id] }),
}));

export const mobileThreatsRelations = relations(mobileThreats, ({ one }) => ({
  organization: one(organizations, { fields: [mobileThreats.orgId], references: [organizations.id] }),
  device: one(mobileDevices, { fields: [mobileThreats.deviceId], references: [mobileDevices.id] }),
}));

export const ztnaPoliciesRelations = relations(ztnaPolicies, ({ one }) => ({
  organization: one(organizations, { fields: [ztnaPolicies.orgId], references: [organizations.id] }),
}));

export const remoteWorkerSessionsRelations = relations(remoteWorkerSessions, ({ one }) => ({
  organization: one(organizations, { fields: [remoteWorkerSessions.orgId], references: [organizations.id] }),
  device: one(mobileDevices, { fields: [remoteWorkerSessions.deviceId], references: [mobileDevices.id] }),
}));

export type MobileDevice = typeof mobileDevices.$inferSelect;
export type InsertMobileDevice = typeof mobileDevices.$inferInsert;
export type DevicePostureCheck = typeof devicePostureChecks.$inferSelect;
export type InsertDevicePostureCheck = typeof devicePostureChecks.$inferInsert;
export type MobileThreat = typeof mobileThreats.$inferSelect;
export type InsertMobileThreat = typeof mobileThreats.$inferInsert;
export type ZtnaPolicy = typeof ztnaPolicies.$inferSelect;
export type InsertZtnaPolicy = typeof ztnaPolicies.$inferInsert;
export type RemoteWorkerSession = typeof remoteWorkerSessions.$inferSelect;
export type InsertRemoteWorkerSession = typeof remoteWorkerSessions.$inferInsert;

// ════════════════════════════════════════════════════════════════════════════
// API SECURITY
// ════════════════════════════════════════════════════════════════════════════

export const API_SECURITY_FINDING_TYPES = [
  "schema_violation",
  "bola",
  "bfla",
  "credential_stuffing",
  "scraping",
  "sensitive_data_exposure",
  "injection",
  "rate_abuse",
  "shadow_api",
  "deprecated_api",
  "auth_bypass",
  "mass_assignment",
  "ssrf",
  "broken_auth",
] as const;

export const API_SECURITY_FINDING_SEVERITIES = ["critical", "high", "medium", "low", "informational"] as const;
export const API_SECURITY_FINDING_STATUSES = ["open", "acknowledged", "mitigated", "false_positive"] as const;
export const API_AUTH_TYPES = ["none", "api_key", "bearer", "oauth2", "basic", "mtls", "custom"] as const;

export const apiInventory = pgTable(
  "api_inventory",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    method: text("method").notNull(),
    path: text("path").notNull(),
    host: text("host").notNull(),
    version: text("version"),
    specSource: text("spec_source"),
    isShadow: boolean("is_shadow").notNull().default(false),
    isDeprecated: boolean("is_deprecated").notNull().default(false),
    authType: text("auth_type").notNull().default("none"),
    riskScore: integer("risk_score").notNull().default(0),
    requestCount24h: integer("request_count_24h").notNull().default(0),
    errorRate24h: real("error_rate_24h").notNull().default(0),
    avgLatencyMs: real("avg_latency_ms").notNull().default(0),
    lastSeenAt: timestamp("last_seen_at"),
    firstSeenAt: timestamp("first_seen_at").defaultNow(),
    openApiSpec: jsonb("openapi_spec"),
    tags: jsonb("tags"),
    sensitiveDataTypes: jsonb("sensitive_data_types"),
    metadata: jsonb("metadata"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_api_inventory_org").on(table.orgId),
    index("idx_api_inventory_host").on(table.orgId, table.host),
    index("idx_api_inventory_shadow").on(table.orgId, table.isShadow),
    index("idx_api_inventory_risk").on(table.orgId, table.riskScore),
    uniqueIndex("idx_api_inventory_unique").on(table.orgId, table.method, table.path, table.host),
  ],
);

export const apiFindings = pgTable(
  "api_findings",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    apiId: varchar("api_id").references(() => apiInventory.id, { onDelete: "cascade" }),
    findingType: text("finding_type").notNull(),
    severity: text("severity").notNull().default("medium"),
    status: text("status").notNull().default("open"),
    title: text("title").notNull(),
    description: text("description"),
    endpoint: text("endpoint"),
    method: text("method"),
    evidence: jsonb("evidence"),
    remediation: text("remediation"),
    cweId: text("cwe_id"),
    owaspCategory: text("owasp_category"),
    requestSample: text("request_sample"),
    responseSample: text("response_sample"),
    detectedAt: timestamp("detected_at").defaultNow(),
    acknowledgedBy: varchar("acknowledged_by"),
    acknowledgedAt: timestamp("acknowledged_at"),
    mitigatedBy: varchar("mitigated_by"),
    mitigatedAt: timestamp("mitigated_at"),
    metadata: jsonb("metadata"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_api_findings_org").on(table.orgId),
    index("idx_api_findings_api").on(table.apiId),
    index("idx_api_findings_type").on(table.orgId, table.findingType),
    index("idx_api_findings_severity").on(table.orgId, table.severity),
    index("idx_api_findings_status").on(table.orgId, table.status),
  ],
);

export const apiTrafficBaselines = pgTable(
  "api_traffic_baselines",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    apiId: varchar("api_id")
      .notNull()
      .references(() => apiInventory.id, { onDelete: "cascade" }),
    windowStart: timestamp("window_start").notNull(),
    windowEnd: timestamp("window_end").notNull(),
    requestCount: integer("request_count").notNull().default(0),
    uniqueCallers: integer("unique_callers").notNull().default(0),
    errorCount: integer("error_count").notNull().default(0),
    avgLatencyMs: real("avg_latency_ms").notNull().default(0),
    p95LatencyMs: real("p95_latency_ms").notNull().default(0),
    p99LatencyMs: real("p99_latency_ms").notNull().default(0),
    statusCodeDistribution: jsonb("status_code_distribution"),
    topCallerIps: jsonb("top_caller_ips"),
    anomalyScore: real("anomaly_score").notNull().default(0),
    metadata: jsonb("metadata"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_api_baselines_org").on(table.orgId),
    index("idx_api_baselines_api").on(table.apiId),
    index("idx_api_baselines_window").on(table.apiId, table.windowStart),
    index("idx_api_baselines_anomaly").on(table.orgId, table.anomalyScore),
  ],
);

export const apiInventoryRelations = relations(apiInventory, ({ one }) => ({
  organization: one(organizations, { fields: [apiInventory.orgId], references: [organizations.id] }),
}));

export const apiFindingsRelations = relations(apiFindings, ({ one }) => ({
  organization: one(organizations, { fields: [apiFindings.orgId], references: [organizations.id] }),
  api: one(apiInventory, { fields: [apiFindings.apiId], references: [apiInventory.id] }),
}));

export const apiTrafficBaselinesRelations = relations(apiTrafficBaselines, ({ one }) => ({
  organization: one(organizations, { fields: [apiTrafficBaselines.orgId], references: [organizations.id] }),
  api: one(apiInventory, { fields: [apiTrafficBaselines.apiId], references: [apiInventory.id] }),
}));

export type ApiInventoryEntry = typeof apiInventory.$inferSelect;
export type InsertApiInventoryEntry = typeof apiInventory.$inferInsert;
export type ApiFinding = typeof apiFindings.$inferSelect;
export type InsertApiFinding = typeof apiFindings.$inferInsert;
export type ApiTrafficBaseline = typeof apiTrafficBaselines.$inferSelect;
export type InsertApiTrafficBaseline = typeof apiTrafficBaselines.$inferInsert;

// =============================================================================
// RANSOMWARE DEFENSE SUITE
// =============================================================================

export const KILL_SWITCH_STATUSES = [
  "initiated",
  "in_progress",
  "completed",
  "partial_failure",
  "failed",
  "rolled_back",
] as const;

export const CANARY_FILE_STATUSES = ["active", "triggered", "disabled", "deleted"] as const;

export const RANSOMWARE_GROUP_THREAT_LEVELS = ["critical", "high", "medium", "low"] as const;

export const BACKUP_VERIFICATION_STATUSES = ["pending", "in_progress", "passed", "failed", "partial"] as const;

export const TABLETOP_EXERCISE_STATUSES = ["draft", "scheduled", "in_progress", "completed", "cancelled"] as const;

export const RECOVERY_RUNBOOK_STATUSES = ["draft", "generated", "reviewed", "approved", "executed"] as const;

// Kill switch events — one-click isolate all endpoints
export const ransomwareKillSwitchEvents = pgTable(
  "ransomware_kill_switch_events",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    status: text("status").notNull().default("initiated"),
    triggeredBy: varchar("triggered_by").notNull(),
    triggeredByName: text("triggered_by_name"),
    reason: text("reason"),
    totalSensors: integer("total_sensors").notNull().default(0),
    isolatedCount: integer("isolated_count").notNull().default(0),
    failedCount: integer("failed_count").notNull().default(0),
    skippedCount: integer("skipped_count").notNull().default(0),
    actionIds: jsonb("action_ids"), // array of response action IDs created
    failedSensors: jsonb("failed_sensors"), // array of {sensorId, error}
    rollbackAt: timestamp("rollback_at"),
    rollbackBy: varchar("rollback_by"),
    completedAt: timestamp("completed_at"),
    incidentId: varchar("incident_id"),
    metadata: jsonb("metadata"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_kill_switch_org").on(table.orgId),
    index("idx_kill_switch_status").on(table.orgId, table.status),
    index("idx_kill_switch_created").on(table.orgId, table.createdAt),
  ],
);

// Canary files — fake important files that alert if encrypted
export const ransomwareCanaryFiles = pgTable(
  "ransomware_canary_files",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    fileName: text("file_name").notNull(),
    filePath: text("file_path").notNull(),
    fileType: text("file_type").notNull(), // docx, xlsx, pdf, pptx, sql, key
    fileHash: text("file_hash").notNull(), // SHA-256 of the canary file content
    deployedToHost: text("deployed_to_host"),
    deployedToSensorId: varchar("deployed_to_sensor_id"),
    status: text("status").notNull().default("active"),
    lastCheckedAt: timestamp("last_checked_at"),
    lastCheckedHash: text("last_checked_hash"),
    triggeredAt: timestamp("triggered_at"),
    triggerType: text("trigger_type"), // encrypted, deleted, modified, renamed
    alertSent: boolean("alert_sent").notNull().default(false),
    createdBy: varchar("created_by"),
    metadata: jsonb("metadata"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_canary_files_org").on(table.orgId),
    index("idx_canary_files_status").on(table.orgId, table.status),
    index("idx_canary_files_host").on(table.orgId, table.deployedToHost),
  ],
);

// Ransomware group intelligence profiles
export const ransomwareGroups = pgTable(
  "ransomware_groups",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    name: text("name").notNull(),
    aliases: jsonb("aliases"), // array of known aliases
    threatLevel: text("threat_level").notNull().default("high"),
    isActive: boolean("is_active").notNull().default(true),
    firstSeen: text("first_seen"),
    lastActive: text("last_active"),
    description: text("description"),
    ttps: jsonb("ttps"), // MITRE ATT&CK TTPs
    targetIndustries: jsonb("target_industries"), // array of industries
    targetRegions: jsonb("target_regions"), // array of regions
    ransomwareVariants: jsonb("ransomware_variants"), // array of {name, type}
    knownPaymentAddresses: jsonb("known_payment_addresses"), // array of {currency, address}
    avgRansomDemandUsd: integer("avg_ransom_demand_usd"),
    decryptorAvailable: boolean("decryptor_available").notNull().default(false),
    decryptorSource: text("decryptor_source"), // e.g. "No More Ransom", "Emsisoft"
    negotiationNotes: text("negotiation_notes"),
    iocIndicators: jsonb("ioc_indicators"), // array of {type, value}
    referenceUrls: jsonb("reference_urls"), // array of reference URLs
    metadata: jsonb("metadata"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_ransomware_groups_org").on(table.orgId),
    index("idx_ransomware_groups_threat").on(table.orgId, table.threatLevel),
    index("idx_ransomware_groups_active").on(table.orgId, table.isActive),
  ],
);

// Recovery runbooks — AI-generated step-by-step recovery plans
export const recoveryRunbooks = pgTable(
  "recovery_runbooks",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    title: text("title").notNull(),
    incidentId: varchar("incident_id"),
    status: text("status").notNull().default("draft"),
    scenario: text("scenario").notNull(), // description of what was hit
    affectedSystems: jsonb("affected_systems"), // array of system names
    affectedDataTypes: jsonb("affected_data_types"), // array of data classifications
    ransomwareVariant: text("ransomware_variant"),
    estimatedDowntimeHours: integer("estimated_downtime_hours"),
    estimatedRecoveryCostUsd: integer("estimated_recovery_cost_usd"),
    steps: jsonb("steps"), // array of {order, title, description, responsible, estimatedMinutes, status}
    priorityActions: jsonb("priority_actions"), // array of immediate actions
    communicationPlan: jsonb("communication_plan"), // stakeholder notifications
    legalRequirements: jsonb("legal_requirements"), // regulatory obligations
    generatedBy: text("generated_by").default("ai"), // "ai" or "manual"
    reviewedBy: varchar("reviewed_by"),
    reviewedAt: timestamp("reviewed_at"),
    approvedBy: varchar("approved_by"),
    approvedAt: timestamp("approved_at"),
    metadata: jsonb("metadata"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_recovery_runbooks_org").on(table.orgId),
    index("idx_recovery_runbooks_status").on(table.orgId, table.status),
    index("idx_recovery_runbooks_incident").on(table.incidentId),
  ],
);

// Tabletop exercise simulator
export const tabletopExercises = pgTable(
  "tabletop_exercises",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    title: text("title").notNull(),
    description: text("description"),
    status: text("status").notNull().default("draft"),
    scenarioType: text("scenario_type").notNull(), // ransomware, data_breach, insider_threat, supply_chain
    difficulty: text("difficulty").notNull().default("intermediate"), // beginner, intermediate, advanced
    ransomwareGroup: text("ransomware_group"), // simulated group
    scenario: jsonb("scenario"), // {background, initialCompromise, escalation, impact, objectives}
    injects: jsonb("injects"), // array of {order, time, description, expectedResponse, hint}
    participants: jsonb("participants"), // array of {userId, role, name}
    findings: jsonb("findings"), // array of {category, description, severity, recommendation}
    score: integer("score"), // 0-100
    scheduledAt: timestamp("scheduled_at"),
    startedAt: timestamp("started_at"),
    completedAt: timestamp("completed_at"),
    durationMinutes: integer("duration_minutes"),
    facilitatedBy: varchar("facilitated_by"),
    afterActionReport: text("after_action_report"),
    metadata: jsonb("metadata"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_tabletop_org").on(table.orgId),
    index("idx_tabletop_status").on(table.orgId, table.status),
    index("idx_tabletop_type").on(table.orgId, table.scenarioType),
    index("idx_tabletop_scheduled").on(table.orgId, table.scheduledAt),
  ],
);

// Backup integrity verification
export const backupVerifications = pgTable(
  "backup_verifications",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    backupName: text("backup_name").notNull(),
    backupType: text("backup_type").notNull(), // full, incremental, differential, snapshot
    backupLocation: text("backup_location").notNull(), // s3://..., nfs://..., etc
    status: text("status").notNull().default("pending"),
    integrityCheckResult: text("integrity_check_result"), // passed, failed, corrupted, partial
    restoreTestResult: text("restore_test_result"), // passed, failed, not_tested
    backupSizeBytes: integer("backup_size_bytes"),
    backupCreatedAt: timestamp("backup_created_at"),
    retentionDays: integer("retention_days"),
    encryptionStatus: text("encryption_status"), // encrypted, unencrypted, unknown
    encryptionAlgorithm: text("encryption_algorithm"),
    lastVerifiedAt: timestamp("last_verified_at"),
    nextScheduledVerification: timestamp("next_scheduled_verification"),
    verificationDurationSeconds: integer("verification_duration_seconds"),
    issues: jsonb("issues"), // array of {type, description, severity}
    coveredSystems: jsonb("covered_systems"), // array of system names
    rpoHours: integer("rpo_hours"), // recovery point objective
    rtoHours: integer("rto_hours"), // recovery time objective
    verifiedBy: varchar("verified_by"),
    metadata: jsonb("metadata"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_backup_verify_org").on(table.orgId),
    index("idx_backup_verify_status").on(table.orgId, table.status),
    index("idx_backup_verify_type").on(table.orgId, table.backupType),
  ],
);

// Relations
export const ransomwareKillSwitchEventsRelations = relations(ransomwareKillSwitchEvents, ({ one }) => ({
  organization: one(organizations, {
    fields: [ransomwareKillSwitchEvents.orgId],
    references: [organizations.id],
  }),
}));

export const ransomwareCanaryFilesRelations = relations(ransomwareCanaryFiles, ({ one }) => ({
  organization: one(organizations, {
    fields: [ransomwareCanaryFiles.orgId],
    references: [organizations.id],
  }),
}));

export const ransomwareGroupsRelations = relations(ransomwareGroups, ({ one }) => ({
  organization: one(organizations, {
    fields: [ransomwareGroups.orgId],
    references: [organizations.id],
  }),
}));

export const recoveryRunbooksRelations = relations(recoveryRunbooks, ({ one }) => ({
  organization: one(organizations, {
    fields: [recoveryRunbooks.orgId],
    references: [organizations.id],
  }),
}));

export const tabletopExercisesRelations = relations(tabletopExercises, ({ one }) => ({
  organization: one(organizations, {
    fields: [tabletopExercises.orgId],
    references: [organizations.id],
  }),
}));

export const backupVerificationsRelations = relations(backupVerifications, ({ one }) => ({
  organization: one(organizations, {
    fields: [backupVerifications.orgId],
    references: [organizations.id],
  }),
}));

export type RansomwareKillSwitchEvent = typeof ransomwareKillSwitchEvents.$inferSelect;
export type InsertRansomwareKillSwitchEvent = typeof ransomwareKillSwitchEvents.$inferInsert;
export type RansomwareCanaryFile = typeof ransomwareCanaryFiles.$inferSelect;
export type InsertRansomwareCanaryFile = typeof ransomwareCanaryFiles.$inferInsert;
export type RansomwareGroup = typeof ransomwareGroups.$inferSelect;
export type InsertRansomwareGroup = typeof ransomwareGroups.$inferInsert;
export type RecoveryRunbook = typeof recoveryRunbooks.$inferSelect;
export type InsertRecoveryRunbook = typeof recoveryRunbooks.$inferInsert;
export type TabletopExercise = typeof tabletopExercises.$inferSelect;
export type InsertTabletopExercise = typeof tabletopExercises.$inferInsert;
export type BackupVerification = typeof backupVerifications.$inferSelect;
export type InsertBackupVerification = typeof backupVerifications.$inferInsert;

// ── Community Threat Intelligence Network ─────────────────────────────────────

export const COMMUNITY_IOC_TYPES = [
  "ip",
  "domain",
  "url",
  "hash_md5",
  "hash_sha1",
  "hash_sha256",
  "email",
  "file_name",
  "cidr",
  "certificate",
] as const;

export const IOC_SEVERITY_LEVELS = ["critical", "high", "medium", "low", "informational"] as const;

export const SHARING_CONSENT_LEVELS = ["none", "ioc_only", "detection_patterns", "full_telemetry"] as const;

export const INDUSTRY_SECTORS = [
  "healthcare",
  "finance",
  "technology",
  "manufacturing",
  "energy",
  "government",
  "education",
  "retail",
  "telecom",
  "defense",
  "legal",
  "media",
  "transportation",
  "other",
] as const;

export const sharedIocs = pgTable(
  "shared_iocs",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    contributorOrgId: text("contributor_org_id").notNull(),
    anonymousContributorHash: text("anonymous_contributor_hash").notNull(), // SHA-256 of orgId — hides identity
    iocType: text("ioc_type").notNull(), // ip, domain, url, hash, etc.
    iocValue: text("ioc_value").notNull(), // the actual indicator value
    iocValueHash: text("ioc_value_hash").notNull(), // SHA-256 of normalized value for dedup
    severity: text("severity").notNull().default("medium"),
    confidence: integer("confidence").notNull().default(70), // 0-100 confidence score
    tlpLevel: text("tlp_level").notNull().default("amber"), // white, green, amber, red
    tags: jsonb("tags").default([]), // e.g. ["ransomware", "c2", "phishing"]
    threatActorRef: text("threat_actor_ref"), // optional MITRE ATT&CK group reference
    campaignRef: text("campaign_ref"), // optional campaign correlation ID
    context: text("context"), // anonymized context description
    firstSeenAt: timestamp("first_seen_at").notNull().defaultNow(),
    lastSeenAt: timestamp("last_seen_at").notNull().defaultNow(),
    sightingCount: integer("sighting_count").notNull().default(1), // how many orgs reported this
    reportingOrgs: jsonb("reporting_orgs").default([]), // array of anonymous org hashes
    industrySectors: jsonb("industry_sectors").default([]), // which sectors saw this IOC
    expiresAt: timestamp("expires_at"), // TTL for IOC validity
    isActive: boolean("is_active").notNull().default(true),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("shared_iocs_type_idx").on(table.iocType),
    index("shared_iocs_value_hash_idx").on(table.iocValueHash),
    index("shared_iocs_severity_idx").on(table.severity),
    index("shared_iocs_active_idx").on(table.isActive),
    index("shared_iocs_first_seen_idx").on(table.firstSeenAt),
  ],
);

export const communityFeeds = pgTable(
  "community_feeds",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: text("org_id").notNull(),
    feedName: text("feed_name").notNull(),
    feedType: text("feed_type").notNull().default("industry"), // global, industry, custom
    industrySector: text("industry_sector"), // null for global feeds
    description: text("description"),
    iocCount: integer("ioc_count").notNull().default(0),
    memberCount: integer("member_count").notNull().default(0),
    lastUpdatedAt: timestamp("last_updated_at").defaultNow(),
    isSubscribed: boolean("is_subscribed").notNull().default(false),
    subscribedAt: timestamp("subscribed_at"),
    autoIngest: boolean("auto_ingest").notNull().default(false), // auto-add IOCs to org threat intel
    filterSeverity: text("filter_severity").default("medium"), // minimum severity to ingest
    filterConfidence: integer("filter_confidence").default(50), // minimum confidence to ingest
    stats: jsonb("stats").default({}), // { ipsShared, domainsShared, hashesShared, ... }
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("community_feeds_org_idx").on(table.orgId),
    index("community_feeds_type_idx").on(table.feedType),
    index("community_feeds_sector_idx").on(table.industrySector),
  ],
);

export const sharingConsents = pgTable(
  "sharing_consents",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: text("org_id").notNull().unique(),
    consentLevel: text("consent_level").notNull().default("none"), // none, ioc_only, detection_patterns, full_telemetry
    industrySector: text("industry_sector").notNull().default("other"),
    companySize: text("company_size").notNull().default("medium"), // small, medium, large, enterprise
    anonymousOrgHash: text("anonymous_org_hash").notNull(), // SHA-256 of orgId for anonymous contribution
    shareIocs: boolean("share_iocs").notNull().default(false),
    shareDetectionPatterns: boolean("share_detection_patterns").notNull().default(false),
    shareTelemetry: boolean("share_telemetry").notNull().default(false),
    receiveGlobalFeed: boolean("receive_global_feed").notNull().default(true),
    receiveIndustryFeed: boolean("receive_industry_feed").notNull().default(true),
    autoContribute: boolean("auto_contribute").notNull().default(false), // auto-share new IOCs
    contributedIocCount: integer("contributed_ioc_count").notNull().default(0),
    receivedIocCount: integer("received_ioc_count").notNull().default(0),
    lastContributedAt: timestamp("last_contributed_at"),
    lastReceivedAt: timestamp("last_received_at"),
    consentGrantedAt: timestamp("consent_granted_at"),
    consentUpdatedAt: timestamp("consent_updated_at").defaultNow(),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("sharing_consents_org_idx").on(table.orgId),
    index("sharing_consents_sector_idx").on(table.industrySector),
  ],
);

export const communityThreatCampaigns = pgTable(
  "community_threat_campaigns",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    campaignName: text("campaign_name").notNull(),
    threatActorName: text("threat_actor_name"),
    description: text("description"),
    mitreAttackIds: jsonb("mitre_attack_ids").default([]),
    targetSectors: jsonb("target_sectors").default([]),
    iocIds: jsonb("ioc_ids").default([]), // linked shared IOC IDs
    iocCount: integer("ioc_count").notNull().default(0),
    affectedOrgCount: integer("affected_org_count").notNull().default(0),
    firstSeenAt: timestamp("first_seen_at").notNull().defaultNow(),
    lastSeenAt: timestamp("last_seen_at").notNull().defaultNow(),
    status: text("status").notNull().default("active"), // active, dormant, resolved
    severity: text("severity").notNull().default("high"),
    tlpLevel: text("tlp_level").notNull().default("amber"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("community_campaigns_status_idx").on(table.status),
    index("community_campaigns_actor_idx").on(table.threatActorName),
    index("community_campaigns_first_seen_idx").on(table.firstSeenAt),
  ],
);

// Relations
export const sharedIocsRelations = relations(sharedIocs, ({ one }) => ({
  contributorOrg: one(organizations, {
    fields: [sharedIocs.contributorOrgId],
    references: [organizations.id],
  }),
}));

export const communityFeedsRelations = relations(communityFeeds, ({ one }) => ({
  organization: one(organizations, {
    fields: [communityFeeds.orgId],
    references: [organizations.id],
  }),
}));

export const sharingConsentsRelations = relations(sharingConsents, ({ one }) => ({
  organization: one(organizations, {
    fields: [sharingConsents.orgId],
    references: [organizations.id],
  }),
}));

export type SharedIoc = typeof sharedIocs.$inferSelect;
export type InsertSharedIoc = typeof sharedIocs.$inferInsert;
export type CommunityFeed = typeof communityFeeds.$inferSelect;
export type InsertCommunityFeed = typeof communityFeeds.$inferInsert;
export type SharingConsent = typeof sharingConsents.$inferSelect;
export type InsertSharingConsent = typeof sharingConsents.$inferInsert;
export type CommunityThreatCampaign = typeof communityThreatCampaigns.$inferSelect;
export type InsertCommunityThreatCampaign = typeof communityThreatCampaigns.$inferInsert;

// ── Security Posture Score & Public Trust Center ──────────────────────────────

export const POSTURE_DOMAINS = ["identity", "endpoint", "cloud", "network", "application", "data"] as const;

export const QUESTIONNAIRE_STATUSES = ["draft", "in_progress", "completed", "submitted", "expired"] as const;

export const TRUST_PAGE_STATUSES = ["draft", "published", "archived"] as const;

export const postureSubScores = pgTable(
  "posture_sub_scores",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: text("org_id").notNull(),
    postureScoreId: varchar("posture_score_id"),
    domain: text("domain").notNull(), // identity, endpoint, cloud, network, application, data
    score: integer("score").notNull().default(0),
    weight: integer("weight").notNull().default(16), // percentage weight for domain
    findings: jsonb("findings").default([]), // array of finding objects
    recommendations: jsonb("recommendations").default([]),
    controlsEvaluated: integer("controls_evaluated").default(0),
    controlsPassed: integer("controls_passed").default(0),
    controlsFailed: integer("controls_failed").default(0),
    riskFactors: jsonb("risk_factors").default([]),
    generatedAt: timestamp("generated_at").defaultNow(),
  },
  (table) => [
    index("posture_sub_scores_org_idx").on(table.orgId),
    index("posture_sub_scores_domain_idx").on(table.orgId, table.domain),
  ],
);

export const peerBenchmarks = pgTable(
  "peer_benchmarks",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: text("org_id").notNull(),
    industrySegment: text("industry_segment").notNull(),
    companySize: text("company_size").notNull(), // small, medium, large, enterprise
    overallScore: integer("overall_score").notNull(),
    identityScore: integer("identity_score").default(0),
    endpointScore: integer("endpoint_score").default(0),
    cloudScore: integer("cloud_score").default(0),
    networkScore: integer("network_score").default(0),
    applicationScore: integer("application_score").default(0),
    dataScore: integer("data_score").default(0),
    percentileRank: integer("percentile_rank").default(50), // "you score higher than X%"
    peerCount: integer("peer_count").default(0), // how many orgs in peer group
    topStrengths: jsonb("top_strengths").default([]),
    topWeaknesses: jsonb("top_weaknesses").default([]),
    calculatedAt: timestamp("calculated_at").defaultNow(),
  },
  (table) => [
    index("peer_benchmarks_org_idx").on(table.orgId),
    index("peer_benchmarks_industry_idx").on(table.industrySegment, table.companySize),
  ],
);

export const publicTrustPages = pgTable(
  "public_trust_pages",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: text("org_id").notNull(),
    slug: text("slug").notNull().unique(), // acme-corp → /trust/acme-corp
    status: text("status").notNull().default("draft"), // draft, published, archived
    companyName: text("company_name").notNull(),
    companyLogo: text("company_logo"),
    tagline: text("tagline"),
    overallScore: integer("overall_score").default(0),
    domainScores: jsonb("domain_scores").default({}), // { identity: 85, endpoint: 90, ... }
    certifications: jsonb("certifications").default([]), // array of { name, status, date }
    lastAuditDate: timestamp("last_audit_date"),
    showSubScores: boolean("show_sub_scores").default(true),
    showCertifications: boolean("show_certifications").default(true),
    showLastAudit: boolean("show_last_audit").default(true),
    showPercentile: boolean("show_percentile").default(false),
    customSections: jsonb("custom_sections").default([]),
    contactEmail: text("contact_email"),
    brandColor: text("brand_color").default("#0ea5e9"),
    visitCount: integer("visit_count").default(0),
    publishedAt: timestamp("published_at"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [index("public_trust_pages_org_idx").on(table.orgId), index("public_trust_pages_slug_idx").on(table.slug)],
);

export const securityQuestionnaires = pgTable(
  "security_questionnaires",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: text("org_id").notNull(),
    title: text("title").notNull(),
    framework: text("framework").notNull(), // SOC2, ISO27001, HIPAA, PCI-DSS, etc.
    status: text("status").notNull().default("draft"),
    totalQuestions: integer("total_questions").default(0),
    answeredQuestions: integer("answered_questions").default(0),
    autoAnsweredQuestions: integer("auto_answered_questions").default(0),
    manualQuestions: integer("manual_questions").default(0),
    confidenceScore: integer("confidence_score").default(0), // average confidence of auto-answers
    requestedBy: text("requested_by"), // who requested the questionnaire
    requestedByEmail: text("requested_by_email"),
    assignedTo: text("assigned_to"),
    dueDate: timestamp("due_date"),
    completedAt: timestamp("completed_at"),
    submittedAt: timestamp("submitted_at"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("security_questionnaires_org_idx").on(table.orgId),
    index("security_questionnaires_status_idx").on(table.orgId, table.status),
  ],
);

export const questionnaireResponses = pgTable(
  "questionnaire_responses",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: text("org_id").notNull(),
    questionnaireId: varchar("questionnaire_id").notNull(),
    questionNumber: integer("question_number").notNull(),
    questionText: text("question_text").notNull(),
    category: text("category"), // e.g. "Access Control", "Encryption", etc.
    answerText: text("answer_text"),
    answerSource: text("answer_source").notNull().default("manual"), // manual, auto, ai_suggested
    confidencePercent: integer("confidence_percent").default(0),
    evidenceRefs: jsonb("evidence_refs").default([]), // links to artifacts, policies, etc.
    reviewedBy: text("reviewed_by"),
    reviewedAt: timestamp("reviewed_at"),
    status: text("status").notNull().default("pending"), // pending, answered, reviewed, flagged
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("questionnaire_responses_org_idx").on(table.orgId),
    index("questionnaire_responses_qid_idx").on(table.questionnaireId),
  ],
);

export const postureScoreHistory = pgTable(
  "posture_score_history",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: text("org_id").notNull(),
    overallScore: integer("overall_score").notNull(),
    identityScore: integer("identity_score").default(0),
    endpointScore: integer("endpoint_score").default(0),
    cloudScore: integer("cloud_score").default(0),
    networkScore: integer("network_score").default(0),
    applicationScore: integer("application_score").default(0),
    dataScore: integer("data_score").default(0),
    percentileRank: integer("percentile_rank").default(50),
    changeFromPrevious: integer("change_from_previous").default(0),
    period: text("period").notNull(), // "2026-03", "2026-W10", "2026-03-12"
    periodType: text("period_type").notNull().default("monthly"), // daily, weekly, monthly
    generatedAt: timestamp("generated_at").defaultNow(),
  },
  (table) => [
    index("posture_score_history_org_idx").on(table.orgId),
    index("posture_score_history_period_idx").on(table.orgId, table.periodType),
  ],
);

// Relations
export const postureSubScoresRelations = relations(postureSubScores, ({ one }) => ({
  organization: one(organizations, {
    fields: [postureSubScores.orgId],
    references: [organizations.id],
  }),
}));

export const peerBenchmarksRelations = relations(peerBenchmarks, ({ one }) => ({
  organization: one(organizations, {
    fields: [peerBenchmarks.orgId],
    references: [organizations.id],
  }),
}));

export const publicTrustPagesRelations = relations(publicTrustPages, ({ one }) => ({
  organization: one(organizations, {
    fields: [publicTrustPages.orgId],
    references: [organizations.id],
  }),
}));

export const securityQuestionnairesRelations = relations(securityQuestionnaires, ({ one }) => ({
  organization: one(organizations, {
    fields: [securityQuestionnaires.orgId],
    references: [organizations.id],
  }),
}));

export const questionnaireResponsesRelations = relations(questionnaireResponses, ({ one }) => ({
  organization: one(organizations, {
    fields: [questionnaireResponses.orgId],
    references: [organizations.id],
  }),
  questionnaire: one(securityQuestionnaires, {
    fields: [questionnaireResponses.questionnaireId],
    references: [securityQuestionnaires.id],
  }),
}));

export const postureScoreHistoryRelations = relations(postureScoreHistory, ({ one }) => ({
  organization: one(organizations, {
    fields: [postureScoreHistory.orgId],
    references: [organizations.id],
  }),
}));

export type PostureSubScore = typeof postureSubScores.$inferSelect;
export type InsertPostureSubScore = typeof postureSubScores.$inferInsert;
export type PeerBenchmark = typeof peerBenchmarks.$inferSelect;
export type InsertPeerBenchmark = typeof peerBenchmarks.$inferInsert;
export type PublicTrustPage = typeof publicTrustPages.$inferSelect;
export type InsertPublicTrustPage = typeof publicTrustPages.$inferInsert;
export type SecurityQuestionnaire = typeof securityQuestionnaires.$inferSelect;
export type InsertSecurityQuestionnaire = typeof securityQuestionnaires.$inferInsert;
export type QuestionnaireResponse = typeof questionnaireResponses.$inferSelect;
export type InsertQuestionnaireResponse = typeof questionnaireResponses.$inferInsert;
export type PostureScoreHistoryEntry = typeof postureScoreHistory.$inferSelect;
export type InsertPostureScoreHistoryEntry = typeof postureScoreHistory.$inferInsert;

// ─── Security Chaos Engineering ───────────────────────────────────────────────

export const chaosSimulations = pgTable("chaos_simulations", {
  id: uuid("id").primaryKey().defaultRandom(),
  orgId: varchar("org_id")
    .notNull()
    .references(() => organizations.id, { onDelete: "cascade" }),
  name: text("name").notNull(),
  description: text("description"),
  mitreId: text("mitre_id").notNull(),
  mitreTactic: text("mitre_tactic").notNull(),
  mitreTechnique: text("mitre_technique").notNull(),
  domain: text("domain").notNull().default("endpoint"),
  platform: text("platform").notNull().default("windows"),
  severity: text("severity").notNull().default("medium"),
  payload: text("payload"),
  expectedOutcome: text("expected_outcome"),
  status: text("status").notNull().default("pending"),
  verdict: text("verdict"),
  durationMs: integer("duration_ms"),
  output: text("output"),
  trigger: text("trigger").notNull().default("manual"),
  executedBy: text("executed_by"),
  executedAt: timestamp("executed_at"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
});

export const controlEffectiveness = pgTable("control_effectiveness", {
  id: uuid("id").primaryKey().defaultRandom(),
  orgId: varchar("org_id")
    .notNull()
    .references(() => organizations.id, { onDelete: "cascade" }),
  controlName: text("control_name").notNull(),
  controlType: text("control_type").notNull(),
  totalTests: integer("total_tests").notNull().default(0),
  passedTests: integer("passed_tests").notNull().default(0),
  failedTests: integer("failed_tests").notNull().default(0),
  effectivenessScore: integer("effectiveness_score").notNull().default(0),
  lastTestedAt: timestamp("last_tested_at"),
  mitreIds: text("mitre_ids").array(),
  status: text("status").notNull().default("untested"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
});

export const detectionGaps = pgTable("detection_gaps", {
  id: uuid("id").primaryKey().defaultRandom(),
  orgId: varchar("org_id")
    .notNull()
    .references(() => organizations.id, { onDelete: "cascade" }),
  mitreId: text("mitre_id").notNull(),
  mitreTactic: text("mitre_tactic").notNull(),
  mitreTechnique: text("mitre_technique").notNull(),
  coverageStatus: text("coverage_status").notNull().default("no_coverage"),
  detectionRuleCount: integer("detection_rule_count").notNull().default(0),
  lastSimulatedAt: timestamp("last_simulated_at"),
  recommendation: text("recommendation"),
  priority: text("priority").notNull().default("medium"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
});

export const chaosSchedules = pgTable("chaos_schedules", {
  id: uuid("id").primaryKey().defaultRandom(),
  orgId: varchar("org_id")
    .notNull()
    .references(() => organizations.id, { onDelete: "cascade" }),
  name: text("name").notNull(),
  description: text("description"),
  frequency: text("frequency").notNull().default("weekly"),
  simulationIds: text("simulation_ids").array(),
  mitreIds: text("mitre_ids").array(),
  enabled: boolean("enabled").notNull().default(true),
  lastRunAt: timestamp("last_run_at"),
  nextRunAt: timestamp("next_run_at"),
  totalRuns: integer("total_runs").notNull().default(0),
  lastScore: integer("last_score"),
  previousScore: integer("previous_score"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
});

export const purpleTeamExercises = pgTable("purple_team_exercises", {
  id: uuid("id").primaryKey().defaultRandom(),
  orgId: varchar("org_id")
    .notNull()
    .references(() => organizations.id, { onDelete: "cascade" }),
  name: text("name").notNull(),
  description: text("description"),
  attackScenario: text("attack_scenario").notNull(),
  mitreChain: text("mitre_chain").array(),
  redTeamActions: text("red_team_actions"),
  blueTeamExpected: text("blue_team_expected"),
  blueTeamActual: text("blue_team_actual"),
  status: text("status").notNull().default("planned"),
  overallVerdict: text("overall_verdict"),
  detectionTime: integer("detection_time"),
  responseTime: integer("response_time"),
  containmentTime: integer("containment_time"),
  gapsIdentified: text("gaps_identified").array(),
  improvements: text("improvements").array(),
  executedAt: timestamp("executed_at"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
});

export const chaosSimulationsRelations = relations(chaosSimulations, ({ one }) => ({
  organization: one(organizations, {
    fields: [chaosSimulations.orgId],
    references: [organizations.id],
  }),
}));

export const controlEffectivenessRelations = relations(controlEffectiveness, ({ one }) => ({
  organization: one(organizations, {
    fields: [controlEffectiveness.orgId],
    references: [organizations.id],
  }),
}));

export const detectionGapsRelations = relations(detectionGaps, ({ one }) => ({
  organization: one(organizations, {
    fields: [detectionGaps.orgId],
    references: [organizations.id],
  }),
}));

export const chaosSchedulesRelations = relations(chaosSchedules, ({ one }) => ({
  organization: one(organizations, {
    fields: [chaosSchedules.orgId],
    references: [organizations.id],
  }),
}));

export const purpleTeamExercisesRelations = relations(purpleTeamExercises, ({ one }) => ({
  organization: one(organizations, {
    fields: [purpleTeamExercises.orgId],
    references: [organizations.id],
  }),
}));

export type ChaosSimulation = typeof chaosSimulations.$inferSelect;
export type InsertChaosSimulation = typeof chaosSimulations.$inferInsert;
export type ControlEffectiveness = typeof controlEffectiveness.$inferSelect;
export type InsertControlEffectiveness = typeof controlEffectiveness.$inferInsert;
export type DetectionGap = typeof detectionGaps.$inferSelect;
export type InsertDetectionGap = typeof detectionGaps.$inferInsert;
export type ChaosSchedule = typeof chaosSchedules.$inferSelect;
export type InsertChaosSchedule = typeof chaosSchedules.$inferInsert;
export type PurpleTeamExercise = typeof purpleTeamExercises.$inferSelect;
export type InsertPurpleTeamExercise = typeof purpleTeamExercises.$inferInsert;

// ─── AI-Native Detection Rule Generation ──────────────────────────────────────

export const RULE_GENERATION_SOURCES = ["incident", "threat_intel", "manual", "log_analysis"] as const;

export const RULE_GENERATION_STATUSES = ["pending", "generating", "completed", "failed"] as const;

export const RULE_FORMATS = ["sigma", "yara", "custom"] as const;

export const AB_TEST_STATUSES = ["pending", "running", "completed", "cancelled"] as const;

export const MARKETPLACE_STATUSES = ["draft", "published", "deprecated", "removed"] as const;

export const LIFECYCLE_ACTIONS = [
  "created",
  "enabled",
  "disabled",
  "shadow_mode",
  "promoted",
  "deprecated",
  "archived",
] as const;

export const ruleGenerationJobs = pgTable(
  "rule_generation_jobs",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    source: text("source").notNull().default("manual"),
    sourceId: text("source_id"),
    sourceContext: text("source_context"),
    ruleFormat: text("rule_format").notNull().default("sigma"),
    status: text("status").notNull().default("pending"),
    generatedRuleId: varchar("generated_rule_id"),
    generatedSigmaYaml: text("generated_sigma_yaml"),
    generatedYaraRule: text("generated_yara_rule"),
    generatedConditionTree: jsonb("generated_condition_tree"),
    generatedName: text("generated_name"),
    generatedDescription: text("generated_description"),
    generatedSeverity: text("generated_severity"),
    generatedMitreTactic: text("generated_mitre_tactic"),
    generatedMitreTechnique: text("generated_mitre_technique"),
    generatedTags: text("generated_tags")
      .array()
      .default(sql`ARRAY[]::text[]`),
    qualityScore: integer("quality_score"),
    estimatedFpRate: real("estimated_fp_rate"),
    qualityBreakdown: jsonb("quality_breakdown"),
    modelId: text("model_id"),
    promptVersion: integer("prompt_version"),
    inputTokens: integer("input_tokens"),
    outputTokens: integer("output_tokens"),
    costUsd: real("cost_usd"),
    latencyMs: integer("latency_ms"),
    errorMessage: text("error_message"),
    requestedBy: text("requested_by"),
    createdAt: timestamp("created_at").defaultNow().notNull(),
    completedAt: timestamp("completed_at"),
  },
  (table) => [index("idx_rule_gen_jobs_org").on(table.orgId), index("idx_rule_gen_jobs_status").on(table.status)],
);

export const ruleAbTests = pgTable(
  "rule_ab_tests",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    name: text("name").notNull(),
    description: text("description"),
    ruleId: varchar("rule_id").notNull(),
    status: text("status").notNull().default("pending"),
    shadowModeEnabled: boolean("shadow_mode_enabled").notNull().default(true),
    startedAt: timestamp("started_at"),
    endedAt: timestamp("ended_at"),
    durationDays: integer("duration_days").notNull().default(7),
    shadowMatches: integer("shadow_matches").notNull().default(0),
    falsePositives: integer("false_positives").notNull().default(0),
    truePositives: integer("true_positives").notNull().default(0),
    matchSamples: jsonb("match_samples").default(sql`'[]'::jsonb`),
    verdict: text("verdict"),
    verdictReason: text("verdict_reason"),
    promotedAt: timestamp("promoted_at"),
    createdBy: text("created_by"),
    createdAt: timestamp("created_at").defaultNow().notNull(),
    updatedAt: timestamp("updated_at").defaultNow().notNull(),
  },
  (table) => [
    index("idx_rule_ab_tests_org").on(table.orgId),
    index("idx_rule_ab_tests_rule").on(table.ruleId),
    index("idx_rule_ab_tests_status").on(table.status),
  ],
);

export const ruleMarketplace = pgTable(
  "rule_marketplace",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    ruleId: varchar("rule_id").notNull(),
    title: text("title").notNull(),
    description: text("description"),
    category: text("category").notNull().default("general"),
    ruleFormat: text("rule_format").notNull().default("sigma"),
    sigmaYaml: text("sigma_yaml"),
    yaraRule: text("yara_rule"),
    conditionTree: jsonb("condition_tree"),
    mitreTactic: text("mitre_tactic"),
    mitreTechnique: text("mitre_technique"),
    severity: text("severity").notNull().default("medium"),
    tags: text("tags")
      .array()
      .default(sql`ARRAY[]::text[]`),
    status: text("status").notNull().default("draft"),
    version: integer("version").notNull().default(1),
    downloads: integer("downloads").notNull().default(0),
    rating: real("rating"),
    ratingCount: integer("rating_count").notNull().default(0),
    publishedBy: text("published_by"),
    publishedAt: timestamp("published_at"),
    createdAt: timestamp("created_at").defaultNow().notNull(),
    updatedAt: timestamp("updated_at").defaultNow().notNull(),
  },
  (table) => [
    index("idx_rule_marketplace_status").on(table.status),
    index("idx_rule_marketplace_category").on(table.category),
  ],
);

export const ruleLifecycleEvents = pgTable(
  "rule_lifecycle_events",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    ruleId: varchar("rule_id").notNull(),
    action: text("action").notNull(),
    previousStatus: text("previous_status"),
    newStatus: text("new_status"),
    reason: text("reason"),
    matchCountAtAction: integer("match_count_at_action").notNull().default(0),
    performedBy: text("performed_by"),
    metadata: jsonb("metadata"),
    createdAt: timestamp("created_at").defaultNow().notNull(),
  },
  (table) => [index("idx_rule_lifecycle_org").on(table.orgId), index("idx_rule_lifecycle_rule").on(table.ruleId)],
);

export const ruleGenerationJobsRelations = relations(ruleGenerationJobs, ({ one }) => ({
  organization: one(organizations, {
    fields: [ruleGenerationJobs.orgId],
    references: [organizations.id],
  }),
}));

export const ruleAbTestsRelations = relations(ruleAbTests, ({ one }) => ({
  organization: one(organizations, {
    fields: [ruleAbTests.orgId],
    references: [organizations.id],
  }),
}));

export const ruleMarketplaceRelations = relations(ruleMarketplace, ({ one }) => ({
  organization: one(organizations, {
    fields: [ruleMarketplace.orgId],
    references: [organizations.id],
  }),
}));

export const ruleLifecycleEventsRelations = relations(ruleLifecycleEvents, ({ one }) => ({
  organization: one(organizations, {
    fields: [ruleLifecycleEvents.orgId],
    references: [organizations.id],
  }),
}));

export type RuleGenerationJob = typeof ruleGenerationJobs.$inferSelect;
export type InsertRuleGenerationJob = typeof ruleGenerationJobs.$inferInsert;
export type RuleAbTest = typeof ruleAbTests.$inferSelect;
export type InsertRuleAbTest = typeof ruleAbTests.$inferInsert;
export type RuleMarketplaceEntry = typeof ruleMarketplace.$inferSelect;
export type InsertRuleMarketplaceEntry = typeof ruleMarketplace.$inferInsert;
export type RuleLifecycleEvent = typeof ruleLifecycleEvents.$inferSelect;
export type InsertRuleLifecycleEvent = typeof ruleLifecycleEvents.$inferInsert;

// ── MSSP White-Label + Partner Portal ──────────────────────────────

export const SLA_PRIORITY_LEVELS = ["critical", "high", "medium", "low"] as const;
export const SLA_STATUSES = ["active", "paused", "breached", "resolved"] as const;
export const MSSP_BILLING_STATUSES = ["draft", "sent", "paid", "overdue", "cancelled"] as const;

export const msspWhiteLabelConfigs = pgTable(
  "mssp_white_label_configs",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    customLogoUrl: text("custom_logo_url"),
    customFaviconUrl: text("custom_favicon_url"),
    primaryColor: text("primary_color").default("#0ea5e9"),
    secondaryColor: text("secondary_color").default("#6366f1"),
    accentColor: text("accent_color").default("#10b981"),
    customDomain: text("custom_domain"),
    customAppName: text("custom_app_name"),
    customSupportEmail: text("custom_support_email"),
    customSupportUrl: text("custom_support_url"),
    loginPageHtml: text("login_page_html"),
    emailHeaderHtml: text("email_header_html"),
    emailFooterHtml: text("email_footer_html"),
    reportHeaderHtml: text("report_header_html"),
    reportFooterHtml: text("report_footer_html"),
    hidePoweredBy: boolean("hide_powered_by").notNull().default(false),
    customCss: text("custom_css"),
    isActive: boolean("is_active").notNull().default(true),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [uniqueIndex("idx_mssp_wl_org").on(table.orgId)],
);

export const msspClientSlas = pgTable(
  "mssp_client_slas",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    parentOrgId: varchar("parent_org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    childOrgId: varchar("child_org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    name: text("name").notNull(),
    priority: text("priority").notNull().default("medium"),
    responseTimeMinutes: integer("response_time_minutes").notNull().default(60),
    resolutionTimeMinutes: integer("resolution_time_minutes").notNull().default(480),
    escalationContactEmail: text("escalation_contact_email"),
    escalationContactPhone: text("escalation_contact_phone"),
    autoEscalateOnBreach: boolean("auto_escalate_on_breach").notNull().default(true),
    businessHoursOnly: boolean("business_hours_only").notNull().default(false),
    businessHoursStart: text("business_hours_start").default("09:00"),
    businessHoursEnd: text("business_hours_end").default("17:00"),
    businessTimezone: text("business_timezone").default("UTC"),
    isActive: boolean("is_active").notNull().default(true),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_mssp_sla_parent").on(table.parentOrgId),
    index("idx_mssp_sla_child").on(table.childOrgId),
    index("idx_mssp_sla_parent_child").on(table.parentOrgId, table.childOrgId),
  ],
);

export const msspSlaBreaches = pgTable(
  "mssp_sla_breaches",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    slaId: varchar("sla_id")
      .notNull()
      .references(() => msspClientSlas.id, { onDelete: "cascade" }),
    parentOrgId: varchar("parent_org_id").notNull(),
    childOrgId: varchar("child_org_id").notNull(),
    incidentId: varchar("incident_id"),
    alertId: varchar("alert_id"),
    breachType: text("breach_type").notNull().default("response"),
    targetMinutes: integer("target_minutes").notNull(),
    actualMinutes: integer("actual_minutes").notNull(),
    status: text("status").notNull().default("breached"),
    resolvedAt: timestamp("resolved_at"),
    resolvedBy: text("resolved_by"),
    notes: text("notes"),
    notifiedAt: timestamp("notified_at"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_mssp_sla_breach_sla").on(table.slaId),
    index("idx_mssp_sla_breach_parent").on(table.parentOrgId),
    index("idx_mssp_sla_breach_child").on(table.childOrgId),
    index("idx_mssp_sla_breach_status").on(table.status),
  ],
);

export const msspBillingRecords = pgTable(
  "mssp_billing_records",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    parentOrgId: varchar("parent_org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    childOrgId: varchar("child_org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    periodStart: timestamp("period_start").notNull(),
    periodEnd: timestamp("period_end").notNull(),
    baseFee: integer("base_fee").notNull().default(0),
    markupPercent: real("markup_percent").notNull().default(0),
    alertsIngested: integer("alerts_ingested").notNull().default(0),
    alertsCost: integer("alerts_cost").notNull().default(0),
    aiAnalyses: integer("ai_analyses").notNull().default(0),
    aiCost: integer("ai_cost").notNull().default(0),
    storageGb: real("storage_gb").notNull().default(0),
    storageCost: integer("storage_cost").notNull().default(0),
    userCount: integer("user_count").notNull().default(0),
    userCost: integer("user_cost").notNull().default(0),
    subtotal: integer("subtotal").notNull().default(0),
    markupAmount: integer("markup_amount").notNull().default(0),
    totalAmount: integer("total_amount").notNull().default(0),
    currency: text("currency").notNull().default("USD"),
    status: text("status").notNull().default("draft"),
    invoiceUrl: text("invoice_url"),
    paidAt: timestamp("paid_at"),
    notes: text("notes"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_mssp_billing_parent").on(table.parentOrgId),
    index("idx_mssp_billing_child").on(table.childOrgId),
    index("idx_mssp_billing_period").on(table.parentOrgId, table.periodStart),
    index("idx_mssp_billing_status").on(table.status),
  ],
);

export const msspClientOnboarding = pgTable(
  "mssp_client_onboarding",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    parentOrgId: varchar("parent_org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    childOrgId: varchar("child_org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    status: text("status").notNull().default("pending"),
    steps: jsonb("steps")
      .notNull()
      .default(
        sql`'[{"key":"org_created","label":"Organization Created","done":true},{"key":"admin_invited","label":"Admin User Invited","done":false},{"key":"connectors_configured","label":"Connectors Configured","done":false},{"key":"sla_defined","label":"SLA Defined","done":false},{"key":"branding_applied","label":"Branding Applied","done":false},{"key":"go_live","label":"Go Live","done":false}]'::jsonb`,
      ),
    assignedTo: text("assigned_to"),
    targetGoLiveDate: timestamp("target_go_live_date"),
    actualGoLiveDate: timestamp("actual_go_live_date"),
    notes: text("notes"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_mssp_onboarding_parent").on(table.parentOrgId),
    index("idx_mssp_onboarding_child").on(table.childOrgId),
    index("idx_mssp_onboarding_status").on(table.status),
  ],
);

export const msspWhiteLabelConfigsRelations = relations(msspWhiteLabelConfigs, ({ one }) => ({
  organization: one(organizations, {
    fields: [msspWhiteLabelConfigs.orgId],
    references: [organizations.id],
  }),
}));

export const msspClientSlasRelations = relations(msspClientSlas, ({ one }) => ({
  parentOrg: one(organizations, {
    fields: [msspClientSlas.parentOrgId],
    references: [organizations.id],
    relationName: "slaParent",
  }),
  childOrg: one(organizations, {
    fields: [msspClientSlas.childOrgId],
    references: [organizations.id],
    relationName: "slaChild",
  }),
}));

export const msspSlaBreachesRelations = relations(msspSlaBreaches, ({ one }) => ({
  sla: one(msspClientSlas, {
    fields: [msspSlaBreaches.slaId],
    references: [msspClientSlas.id],
  }),
}));

export const msspBillingRecordsRelations = relations(msspBillingRecords, ({ one }) => ({
  parentOrg: one(organizations, {
    fields: [msspBillingRecords.parentOrgId],
    references: [organizations.id],
    relationName: "billingParent",
  }),
  childOrg: one(organizations, {
    fields: [msspBillingRecords.childOrgId],
    references: [organizations.id],
    relationName: "billingChild",
  }),
}));

export const msspClientOnboardingRelations = relations(msspClientOnboarding, ({ one }) => ({
  parentOrg: one(organizations, {
    fields: [msspClientOnboarding.parentOrgId],
    references: [organizations.id],
    relationName: "onboardingParent",
  }),
  childOrg: one(organizations, {
    fields: [msspClientOnboarding.childOrgId],
    references: [organizations.id],
    relationName: "onboardingChild",
  }),
}));

export type MsspWhiteLabelConfig = typeof msspWhiteLabelConfigs.$inferSelect;
export type InsertMsspWhiteLabelConfig = typeof msspWhiteLabelConfigs.$inferInsert;
export type MsspClientSla = typeof msspClientSlas.$inferSelect;
export type InsertMsspClientSla = typeof msspClientSlas.$inferInsert;
export type MsspSlaBreach = typeof msspSlaBreaches.$inferSelect;
export type InsertMsspSlaBreach = typeof msspSlaBreaches.$inferInsert;
export type MsspBillingRecord = typeof msspBillingRecords.$inferSelect;
export type InsertMsspBillingRecord = typeof msspBillingRecords.$inferInsert;
export type MsspClientOnboardingRecord = typeof msspClientOnboarding.$inferSelect;
export type InsertMsspClientOnboardingRecord = typeof msspClientOnboarding.$inferInsert;

// ── Autonomous SOC — AI Analyst Tiers ─────────────────────────────

export const AI_ANALYST_TIERS = ["tier1_autonomous", "tier2_semi_autonomous", "tier3_assisted"] as const;
export const AI_DECISION_OUTCOMES = [
  "true_positive",
  "false_positive",
  "escalate_tier2",
  "escalate_tier3",
  "escalate_human",
  "needs_investigation",
  "auto_resolved",
  "auto_contained",
] as const;
export const AUTONOMY_LOG_ACTIONS = [
  "alert_triaged",
  "alert_enriched",
  "correlation_run",
  "hypothesis_tested",
  "action_executed",
  "action_blocked",
  "escalated",
  "case_closed",
  "case_reopened",
  "confidence_updated",
  "human_override",
] as const;

export const aiAnalystDecisions = pgTable(
  "ai_analyst_decisions",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    alertId: varchar("alert_id").references(() => alerts.id, { onDelete: "set null" }),
    incidentId: varchar("incident_id").references(() => incidents.id, { onDelete: "set null" }),
    tier: text("tier").notNull().default("tier1_autonomous"),
    outcome: text("outcome").notNull(),
    confidenceScore: real("confidence_score").notNull(),
    confidenceFactors: jsonb("confidence_factors"),
    enrichmentData: jsonb("enrichment_data"),
    correlationResults: jsonb("correlation_results"),
    hypotheses: jsonb("hypotheses"),
    reasoning: text("reasoning"),
    executiveSummary: text("executive_summary"),
    recommendedActions: jsonb("recommended_actions"),
    executedActions: jsonb("executed_actions"),
    mitreTactics: text("mitre_tactics").array(),
    mitreTechniques: text("mitre_techniques").array(),
    relatedAlertIds: text("related_alert_ids").array(),
    timeToDecisionMs: integer("time_to_decision_ms"),
    humanOverride: boolean("human_override").notNull().default(false),
    humanOverrideBy: text("human_override_by"),
    humanOverrideReason: text("human_override_reason"),
    humanOverrideAt: timestamp("human_override_at"),
    status: text("status").notNull().default("pending"),
    safetyVetoes: jsonb("safety_vetoes"),
    reviewedBy: text("reviewed_by"),
    reviewedAt: timestamp("reviewed_at"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_ai_decisions_org").on(table.orgId),
    index("idx_ai_decisions_alert").on(table.alertId),
    index("idx_ai_decisions_incident").on(table.incidentId),
    index("idx_ai_decisions_tier").on(table.orgId, table.tier),
    index("idx_ai_decisions_outcome").on(table.orgId, table.outcome),
    index("idx_ai_decisions_status").on(table.orgId, table.status),
    index("idx_ai_decisions_created").on(table.orgId, table.createdAt),
  ],
);

export const autonomyLog = pgTable(
  "autonomy_log",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    decisionId: varchar("decision_id").references(() => aiAnalystDecisions.id, { onDelete: "cascade" }),
    action: text("action").notNull(),
    tier: text("tier").notNull(),
    alertId: varchar("alert_id"),
    incidentId: varchar("incident_id"),
    details: jsonb("details"),
    confidenceBefore: real("confidence_before"),
    confidenceAfter: real("confidence_after"),
    durationMs: integer("duration_ms"),
    success: boolean("success").notNull().default(true),
    error: text("error"),
    triggeredBy: text("triggered_by").notNull().default("ai_analyst"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_autonomy_log_org").on(table.orgId),
    index("idx_autonomy_log_decision").on(table.decisionId),
    index("idx_autonomy_log_action").on(table.orgId, table.action),
    index("idx_autonomy_log_tier").on(table.orgId, table.tier),
    index("idx_autonomy_log_created").on(table.orgId, table.createdAt),
  ],
);

export const aiAnalystDecisionsRelations = relations(aiAnalystDecisions, ({ one }) => ({
  organization: one(organizations, {
    fields: [aiAnalystDecisions.orgId],
    references: [organizations.id],
  }),
  alert: one(alerts, {
    fields: [aiAnalystDecisions.alertId],
    references: [alerts.id],
  }),
  incident: one(incidents, {
    fields: [aiAnalystDecisions.incidentId],
    references: [incidents.id],
  }),
}));

export const autonomyLogRelations = relations(autonomyLog, ({ one }) => ({
  decision: one(aiAnalystDecisions, {
    fields: [autonomyLog.decisionId],
    references: [aiAnalystDecisions.id],
  }),
}));

export type AiAnalystDecision = typeof aiAnalystDecisions.$inferSelect;
export type InsertAiAnalystDecision = typeof aiAnalystDecisions.$inferInsert;
export type AutonomyLogEntry = typeof autonomyLog.$inferSelect;
export type InsertAutonomyLogEntry = typeof autonomyLog.$inferInsert;

// ── Developer Security (Shift-Left Platform) ──────────────────────

export const SAST_SEVERITY = ["critical", "high", "medium", "low", "info"] as const;
export const SAST_CATEGORIES = [
  "sql_injection",
  "xss",
  "path_traversal",
  "command_injection",
  "insecure_deserialization",
  "hardcoded_secret",
  "weak_crypto",
  "ssrf",
  "open_redirect",
  "xxe",
  "idor",
  "missing_auth",
  "race_condition",
  "prototype_pollution",
  "regex_dos",
] as const;
export const SECRET_TYPES = [
  "aws_access_key",
  "aws_secret_key",
  "github_token",
  "gitlab_token",
  "api_key",
  "jwt_secret",
  "private_key",
  "database_url",
  "oauth_secret",
  "slack_token",
  "stripe_key",
  "sendgrid_key",
  "twilio_key",
  "generic_password",
  "generic_secret",
] as const;
export const CI_GATE_STATUSES = ["passed", "failed", "warning", "skipped"] as const;

export const sastFindings = pgTable(
  "sast_findings",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    repository: text("repository").notNull(),
    branch: text("branch").notNull().default("main"),
    commitSha: text("commit_sha"),
    pullRequestId: text("pull_request_id"),
    filePath: text("file_path").notNull(),
    startLine: integer("start_line").notNull(),
    endLine: integer("end_line"),
    codeSnippet: text("code_snippet"),
    category: text("category").notNull(),
    severity: text("severity").notNull().default("medium"),
    title: text("title").notNull(),
    description: text("description").notNull(),
    remediation: text("remediation"),
    cweId: text("cwe_id"),
    owaspCategory: text("owasp_category"),
    confidence: real("confidence").notNull().default(0.8),
    status: text("status").notNull().default("open"),
    assignee: text("assignee"),
    falsePositive: boolean("false_positive").notNull().default(false),
    falsePositiveBy: text("false_positive_by"),
    falsePositiveReason: text("false_positive_reason"),
    fixedInCommit: text("fixed_in_commit"),
    fixedAt: timestamp("fixed_at"),
    firstSeenAt: timestamp("first_seen_at").defaultNow(),
    lastSeenAt: timestamp("last_seen_at").defaultNow(),
    scanId: varchar("scan_id"),
    ruleId: text("rule_id"),
    metadata: jsonb("metadata"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_sast_findings_org").on(table.orgId),
    index("idx_sast_findings_repo").on(table.orgId, table.repository),
    index("idx_sast_findings_severity").on(table.orgId, table.severity),
    index("idx_sast_findings_category").on(table.orgId, table.category),
    index("idx_sast_findings_status").on(table.orgId, table.status),
    index("idx_sast_findings_pr").on(table.orgId, table.pullRequestId),
    index("idx_sast_findings_commit").on(table.orgId, table.commitSha),
  ],
);

export const secretsExposed = pgTable(
  "secrets_exposed",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    repository: text("repository").notNull(),
    branch: text("branch").notNull().default("main"),
    commitSha: text("commit_sha").notNull(),
    commitAuthor: text("commit_author"),
    commitDate: timestamp("commit_date"),
    filePath: text("file_path").notNull(),
    line: integer("line").notNull(),
    secretType: text("secret_type").notNull(),
    secretHash: text("secret_hash").notNull(),
    maskedValue: text("masked_value"),
    severity: text("severity").notNull().default("critical"),
    status: text("status").notNull().default("active"),
    rotated: boolean("rotated").notNull().default(false),
    rotatedAt: timestamp("rotated_at"),
    rotatedBy: text("rotated_by"),
    falsePositive: boolean("false_positive").notNull().default(false),
    falsePositiveBy: text("false_positive_by"),
    pullRequestId: text("pull_request_id"),
    prCommentPosted: boolean("pr_comment_posted").notNull().default(false),
    scanId: varchar("scan_id"),
    metadata: jsonb("metadata"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_secrets_exposed_org").on(table.orgId),
    index("idx_secrets_exposed_repo").on(table.orgId, table.repository),
    index("idx_secrets_exposed_type").on(table.orgId, table.secretType),
    index("idx_secrets_exposed_status").on(table.orgId, table.status),
    index("idx_secrets_exposed_commit").on(table.orgId, table.commitSha),
  ],
);

export const ciGates = pgTable(
  "ci_gates",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    repository: text("repository").notNull(),
    branch: text("branch").notNull(),
    commitSha: text("commit_sha").notNull(),
    pullRequestId: text("pull_request_id"),
    pipelineProvider: text("pipeline_provider").notNull().default("github_actions"),
    pipelineRunId: text("pipeline_run_id"),
    status: text("status").notNull().default("passed"),
    criticalFindings: integer("critical_findings").notNull().default(0),
    highFindings: integer("high_findings").notNull().default(0),
    mediumFindings: integer("medium_findings").notNull().default(0),
    lowFindings: integer("low_findings").notNull().default(0),
    secretsFound: integer("secrets_found").notNull().default(0),
    policyViolations: integer("policy_violations").notNull().default(0),
    gatePolicy: jsonb("gate_policy"),
    failureReasons: text("failure_reasons").array(),
    scanDurationMs: integer("scan_duration_ms"),
    reportUrl: text("report_url"),
    metadata: jsonb("metadata"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_ci_gates_org").on(table.orgId),
    index("idx_ci_gates_repo").on(table.orgId, table.repository),
    index("idx_ci_gates_status").on(table.orgId, table.status),
    index("idx_ci_gates_commit").on(table.orgId, table.commitSha),
    index("idx_ci_gates_pr").on(table.orgId, table.pullRequestId),
  ],
);

export const codeReviewFindings = pgTable(
  "code_review_findings",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    repository: text("repository").notNull(),
    pullRequestId: text("pull_request_id").notNull(),
    commitSha: text("commit_sha").notNull(),
    filePath: text("file_path").notNull(),
    line: integer("line").notNull(),
    category: text("category").notNull(),
    severity: text("severity").notNull().default("medium"),
    title: text("title").notNull(),
    description: text("description").notNull(),
    suggestion: text("suggestion"),
    commentPosted: boolean("comment_posted").notNull().default(false),
    commentId: text("comment_id"),
    accepted: boolean("accepted"),
    acceptedBy: text("accepted_by"),
    metadata: jsonb("metadata"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_code_review_org").on(table.orgId),
    index("idx_code_review_repo").on(table.orgId, table.repository),
    index("idx_code_review_pr").on(table.orgId, table.pullRequestId),
  ],
);

export const securityDebtItems = pgTable(
  "security_debt_items",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    repository: text("repository").notNull(),
    category: text("category").notNull(),
    severity: text("severity").notNull().default("medium"),
    title: text("title").notNull(),
    description: text("description").notNull(),
    filePath: text("file_path"),
    findingCount: integer("finding_count").notNull().default(1),
    exploitability: text("exploitability").notNull().default("medium"),
    effortToFix: text("effort_to_fix").notNull().default("medium"),
    priority: integer("priority").notNull().default(50),
    status: text("status").notNull().default("open"),
    assignee: text("assignee"),
    dueDate: timestamp("due_date"),
    relatedFindingIds: text("related_finding_ids").array(),
    metadata: jsonb("metadata"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_security_debt_org").on(table.orgId),
    index("idx_security_debt_repo").on(table.orgId, table.repository),
    index("idx_security_debt_priority").on(table.orgId, table.priority),
    index("idx_security_debt_status").on(table.orgId, table.status),
  ],
);

export const sastFindingsRelations = relations(sastFindings, ({ one }) => ({
  organization: one(organizations, {
    fields: [sastFindings.orgId],
    references: [organizations.id],
  }),
}));

export const secretsExposedRelations = relations(secretsExposed, ({ one }) => ({
  organization: one(organizations, {
    fields: [secretsExposed.orgId],
    references: [organizations.id],
  }),
}));

export const ciGatesRelations = relations(ciGates, ({ one }) => ({
  organization: one(organizations, {
    fields: [ciGates.orgId],
    references: [organizations.id],
  }),
}));

export const codeReviewFindingsRelations = relations(codeReviewFindings, ({ one }) => ({
  organization: one(organizations, {
    fields: [codeReviewFindings.orgId],
    references: [organizations.id],
  }),
}));

export const securityDebtItemsRelations = relations(securityDebtItems, ({ one }) => ({
  organization: one(organizations, {
    fields: [securityDebtItems.orgId],
    references: [organizations.id],
  }),
}));

export type SastFinding = typeof sastFindings.$inferSelect;
export type InsertSastFinding = typeof sastFindings.$inferInsert;
export type SecretExposed = typeof secretsExposed.$inferSelect;
export type InsertSecretExposed = typeof secretsExposed.$inferInsert;
export type CiGate = typeof ciGates.$inferSelect;
export type InsertCiGate = typeof ciGates.$inferInsert;
export type CodeReviewFinding = typeof codeReviewFindings.$inferSelect;
export type InsertCodeReviewFinding = typeof codeReviewFindings.$inferInsert;
export type SecurityDebtItem = typeof securityDebtItems.$inferSelect;
export type InsertSecurityDebtItem = typeof securityDebtItems.$inferInsert;

// ── Third-Party Risk Management (TPRM) ───────────────────────────

export const VENDOR_RISK_TIERS = ["critical", "high", "medium", "low", "minimal"] as const;
export const VENDOR_STATUSES = ["active", "under_review", "probation", "offboarded", "pending_onboard"] as const;
export const VENDOR_CATEGORIES = [
  "saas",
  "infrastructure",
  "payment_processing",
  "cloud_hosting",
  "identity_provider",
  "analytics",
  "communications",
  "development_tools",
  "security",
  "data_processing",
  "consulting",
  "staffing",
  "hardware",
  "other",
] as const;
export const VENDOR_ASSESSMENT_STATUSES = [
  "draft",
  "sent",
  "in_progress",
  "completed",
  "overdue",
  "cancelled",
] as const;
export const QUESTIONNAIRE_TYPES = ["caiq", "sig_lite", "sig_full", "custom", "iso27001", "soc2", "nist"] as const;

export const vendors = pgTable(
  "vendors",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    name: text("name").notNull(),
    domain: text("domain"),
    website: text("website"),
    category: text("category").notNull().default("other"),
    description: text("description"),
    status: text("status").notNull().default("active"),
    riskTier: text("risk_tier").notNull().default("medium"),
    overallRiskScore: integer("overall_risk_score"),
    securityScore: integer("security_score"),
    complianceCertifications: text("compliance_certifications").array(),
    dataAccessLevel: text("data_access_level"),
    dataTypes: text("data_types").array(),
    contractStartDate: timestamp("contract_start_date"),
    contractEndDate: timestamp("contract_end_date"),
    contractValue: integer("contract_value"),
    primaryContact: text("primary_contact"),
    primaryContactEmail: text("primary_contact_email"),
    securityContact: text("security_contact"),
    securityContactEmail: text("security_contact_email"),
    fourthPartyVendors: jsonb("fourth_party_vendors"),
    reviewCadence: text("review_cadence").notNull().default("annually"),
    lastReviewDate: timestamp("last_review_date"),
    nextReviewDate: timestamp("next_review_date"),
    onboardedBy: text("onboarded_by"),
    notes: text("notes"),
    metadata: jsonb("metadata"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_vendors_org").on(table.orgId),
    index("idx_vendors_status").on(table.orgId, table.status),
    index("idx_vendors_risk_tier").on(table.orgId, table.riskTier),
    index("idx_vendors_category").on(table.orgId, table.category),
    index("idx_vendors_domain").on(table.orgId, table.domain),
    index("idx_vendors_next_review").on(table.orgId, table.nextReviewDate),
  ],
);

export const vendorAssessments = pgTable(
  "vendor_assessments",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    vendorId: varchar("vendor_id")
      .notNull()
      .references(() => vendors.id, { onDelete: "cascade" }),
    questionnaireType: text("questionnaire_type").notNull().default("custom"),
    title: text("title").notNull(),
    status: text("status").notNull().default("draft"),
    sentAt: timestamp("sent_at"),
    dueDate: timestamp("due_date"),
    completedAt: timestamp("completed_at"),
    respondentName: text("respondent_name"),
    respondentEmail: text("respondent_email"),
    totalQuestions: integer("total_questions").notNull().default(0),
    answeredQuestions: integer("answered_questions").notNull().default(0),
    score: integer("score"),
    maxScore: integer("max_score"),
    riskRating: text("risk_rating"),
    findings: jsonb("findings"),
    responses: jsonb("responses"),
    attachments: text("attachments").array(),
    reviewedBy: text("reviewed_by"),
    reviewedAt: timestamp("reviewed_at"),
    reviewNotes: text("review_notes"),
    metadata: jsonb("metadata"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_vendor_assessments_org").on(table.orgId),
    index("idx_vendor_assessments_vendor").on(table.orgId, table.vendorId),
    index("idx_vendor_assessments_status").on(table.orgId, table.status),
    index("idx_vendor_assessments_due").on(table.orgId, table.dueDate),
  ],
);

export const vendorRisks = pgTable(
  "vendor_risks",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    vendorId: varchar("vendor_id")
      .notNull()
      .references(() => vendors.id, { onDelete: "cascade" }),
    category: text("category").notNull(),
    title: text("title").notNull(),
    description: text("description").notNull(),
    severity: text("severity").notNull().default("medium"),
    status: text("status").notNull().default("open"),
    source: text("source").notNull().default("manual"),
    evidence: text("evidence"),
    remediation: text("remediation"),
    mitigatedAt: timestamp("mitigated_at"),
    mitigatedBy: text("mitigated_by"),
    acceptedAt: timestamp("accepted_at"),
    acceptedBy: text("accepted_by"),
    acceptanceReason: text("acceptance_reason"),
    dueDate: timestamp("due_date"),
    metadata: jsonb("metadata"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_vendor_risks_org").on(table.orgId),
    index("idx_vendor_risks_vendor").on(table.orgId, table.vendorId),
    index("idx_vendor_risks_severity").on(table.orgId, table.severity),
    index("idx_vendor_risks_status").on(table.orgId, table.status),
  ],
);

export const vendorMonitoring = pgTable(
  "vendor_monitoring",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    vendorId: varchar("vendor_id")
      .notNull()
      .references(() => vendors.id, { onDelete: "cascade" }),
    checkType: text("check_type").notNull(),
    status: text("status").notNull().default("ok"),
    details: text("details"),
    previousValue: text("previous_value"),
    currentValue: text("current_value"),
    severity: text("severity").notNull().default("info"),
    acknowledged: boolean("acknowledged").notNull().default(false),
    acknowledgedBy: text("acknowledged_by"),
    acknowledgedAt: timestamp("acknowledged_at"),
    metadata: jsonb("metadata"),
    checkedAt: timestamp("checked_at").defaultNow(),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_vendor_monitoring_org").on(table.orgId),
    index("idx_vendor_monitoring_vendor").on(table.orgId, table.vendorId),
    index("idx_vendor_monitoring_type").on(table.orgId, table.checkType),
    index("idx_vendor_monitoring_status").on(table.orgId, table.status),
  ],
);

export const vendorBreachAlerts = pgTable(
  "vendor_breach_alerts",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    vendorId: varchar("vendor_id")
      .notNull()
      .references(() => vendors.id, { onDelete: "cascade" }),
    title: text("title").notNull(),
    description: text("description").notNull(),
    source: text("source").notNull(),
    sourceUrl: text("source_url"),
    breachDate: timestamp("breach_date"),
    impactAssessment: text("impact_assessment"),
    affectedDataTypes: text("affected_data_types").array(),
    severity: text("severity").notNull().default("high"),
    status: text("status").notNull().default("new"),
    acknowledgedBy: text("acknowledged_by"),
    acknowledgedAt: timestamp("acknowledged_at"),
    responseActions: jsonb("response_actions"),
    metadata: jsonb("metadata"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_vendor_breach_alerts_org").on(table.orgId),
    index("idx_vendor_breach_alerts_vendor").on(table.orgId, table.vendorId),
    index("idx_vendor_breach_alerts_status").on(table.orgId, table.status),
  ],
);

export const vendorsRelations = relations(vendors, ({ one, many }) => ({
  organization: one(organizations, {
    fields: [vendors.orgId],
    references: [organizations.id],
  }),
  assessments: many(vendorAssessments),
  risks: many(vendorRisks),
  monitoring: many(vendorMonitoring),
  breachAlerts: many(vendorBreachAlerts),
}));

export const vendorAssessmentsRelations = relations(vendorAssessments, ({ one }) => ({
  organization: one(organizations, {
    fields: [vendorAssessments.orgId],
    references: [organizations.id],
  }),
  vendor: one(vendors, {
    fields: [vendorAssessments.vendorId],
    references: [vendors.id],
  }),
}));

export const vendorRisksRelations = relations(vendorRisks, ({ one }) => ({
  organization: one(organizations, {
    fields: [vendorRisks.orgId],
    references: [organizations.id],
  }),
  vendor: one(vendors, {
    fields: [vendorRisks.vendorId],
    references: [vendors.id],
  }),
}));

export const vendorMonitoringRelations = relations(vendorMonitoring, ({ one }) => ({
  organization: one(organizations, {
    fields: [vendorMonitoring.orgId],
    references: [organizations.id],
  }),
  vendor: one(vendors, {
    fields: [vendorMonitoring.vendorId],
    references: [vendors.id],
  }),
}));

export const vendorBreachAlertsRelations = relations(vendorBreachAlerts, ({ one }) => ({
  organization: one(organizations, {
    fields: [vendorBreachAlerts.orgId],
    references: [organizations.id],
  }),
  vendor: one(vendors, {
    fields: [vendorBreachAlerts.vendorId],
    references: [vendors.id],
  }),
}));

export type Vendor = typeof vendors.$inferSelect;
export type InsertVendor = typeof vendors.$inferInsert;
export type VendorAssessment = typeof vendorAssessments.$inferSelect;
export type InsertVendorAssessment = typeof vendorAssessments.$inferInsert;
export type VendorRisk = typeof vendorRisks.$inferSelect;
export type InsertVendorRisk = typeof vendorRisks.$inferInsert;
export type VendorMonitoringEntry = typeof vendorMonitoring.$inferSelect;
export type InsertVendorMonitoringEntry = typeof vendorMonitoring.$inferInsert;
export type VendorBreachAlert = typeof vendorBreachAlerts.$inferSelect;
export type InsertVendorBreachAlert = typeof vendorBreachAlerts.$inferInsert;

// =============================================================================
// DARK WEB MONITORING
// =============================================================================

export const DARK_WEB_EXPOSURE_TYPES = [
  "credential_leak",
  "data_breach",
  "brand_mention",
  "executive_exposure",
  "source_code_leak",
  "pii_exposure",
  "credit_card_exposure",
  "threat_actor_mention",
  "domain_mention",
  "paste_site",
] as const;

export const DARK_WEB_SEVERITY_LEVELS = ["critical", "high", "medium", "low", "info"] as const;

export const DARK_WEB_EXPOSURE_STATUSES = [
  "new",
  "investigating",
  "confirmed",
  "mitigated",
  "false_positive",
  "ignored",
] as const;

export const BREACH_MONITOR_TARGET_TYPES = [
  "email",
  "domain",
  "executive_email",
  "brand_keyword",
  "source_code_keyword",
  "credit_card_bin",
  "api_key_pattern",
  "ip_range",
] as const;

export const DARK_WEB_SOURCE_TYPES = [
  "hibp",
  "dehashed",
  "paste_site",
  "dark_web_forum",
  "telegram_channel",
  "marketplace",
  "ransomware_blog",
  "github_search",
  "pastebin",
  "manual",
] as const;

export const breachMonitoringTargets = pgTable("breach_monitoring_targets", {
  id: uuid("id").defaultRandom().primaryKey(),
  orgId: varchar("org_id")
    .notNull()
    .references(() => organizations.id, { onDelete: "cascade" }),
  targetType: text("target_type").notNull(), // BREACH_MONITOR_TARGET_TYPES
  targetValue: text("target_value").notNull(),
  label: text("label"), // friendly name
  isActive: boolean("is_active").default(true).notNull(),
  lastCheckedAt: timestamp("last_checked_at"),
  exposureCount: integer("exposure_count").default(0).notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
});

export const darkWebExposures = pgTable("dark_web_exposures", {
  id: uuid("id").defaultRandom().primaryKey(),
  orgId: varchar("org_id")
    .notNull()
    .references(() => organizations.id, { onDelete: "cascade" }),
  targetId: uuid("target_id").references(() => breachMonitoringTargets.id, { onDelete: "set null" }),
  exposureType: text("exposure_type").notNull(), // DARK_WEB_EXPOSURE_TYPES
  severity: text("severity").default("medium").notNull(), // DARK_WEB_SEVERITY_LEVELS
  status: text("status").default("new").notNull(), // DARK_WEB_EXPOSURE_STATUSES
  title: text("title").notNull(),
  description: text("description"),
  sourceType: text("source_type").notNull(), // DARK_WEB_SOURCE_TYPES
  sourceName: text("source_name"), // e.g., "LinkedIn 2021 breach", "pastebin.com"
  sourceUrl: text("source_url"), // redacted/sanitized link if available
  breachDate: timestamp("breach_date"), // when the breach occurred
  discoveredAt: timestamp("discovered_at").defaultNow().notNull(), // when we found it
  affectedData: jsonb("affected_data").$type<string[]>().default([]), // e.g., ["email","password","phone"]
  affectedCount: integer("affected_count"), // number of records exposed
  rawData: jsonb("raw_data").$type<Record<string, unknown>>(), // raw API response (redacted)
  matchedValue: text("matched_value"), // what we searched for that matched
  confidenceScore: integer("confidence_score").default(70), // 0-100
  mitigationNotes: text("mitigation_notes"),
  assignedTo: uuid("assigned_to"),
  resolvedAt: timestamp("resolved_at"),
  resolvedBy: uuid("resolved_by"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
});

export const darkWebMonitoringConfig = pgTable("dark_web_monitoring_config", {
  id: uuid("id").defaultRandom().primaryKey(),
  orgId: varchar("org_id")
    .notNull()
    .references(() => organizations.id, { onDelete: "cascade" }),
  isEnabled: boolean("is_enabled").default(true).notNull(),
  scanFrequencyHours: integer("scan_frequency_hours").default(24).notNull(),
  autoCreateAlerts: boolean("auto_create_alerts").default(true).notNull(),
  alertSeverityThreshold: text("alert_severity_threshold").default("medium").notNull(),
  notifyOnNewExposure: boolean("notify_on_new_exposure").default(true).notNull(),
  hibpApiKey: text("hibp_api_key"), // AES-256-GCM encrypted via sso-crypto
  dehashedApiKey: text("dehashed_api_key"), // AES-256-GCM encrypted via sso-crypto
  lastFullScanAt: timestamp("last_full_scan_at"),
  totalExposuresFound: integer("total_exposures_found").default(0).notNull(),
  totalExposuresResolved: integer("total_exposures_resolved").default(0).notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
});

export const darkWebScanHistory = pgTable("dark_web_scan_history", {
  id: uuid("id").defaultRandom().primaryKey(),
  orgId: varchar("org_id")
    .notNull()
    .references(() => organizations.id, { onDelete: "cascade" }),
  scanType: text("scan_type").notNull(), // "full", "incremental", "manual"
  status: text("status").default("running").notNull(), // "running", "completed", "failed"
  targetsScanned: integer("targets_scanned").default(0).notNull(),
  newExposuresFound: integer("new_exposures_found").default(0).notNull(),
  sourcesChecked: jsonb("sources_checked").$type<string[]>().default([]),
  errorMessage: text("error_message"),
  startedAt: timestamp("started_at").defaultNow().notNull(),
  completedAt: timestamp("completed_at"),
  durationMs: integer("duration_ms"),
});

// Relations
export const breachMonitoringTargetsRelations = relations(breachMonitoringTargets, ({ one }) => ({
  organization: one(organizations, {
    fields: [breachMonitoringTargets.orgId],
    references: [organizations.id],
  }),
}));

export const darkWebExposuresRelations = relations(darkWebExposures, ({ one }) => ({
  organization: one(organizations, {
    fields: [darkWebExposures.orgId],
    references: [organizations.id],
  }),
  target: one(breachMonitoringTargets, {
    fields: [darkWebExposures.targetId],
    references: [breachMonitoringTargets.id],
  }),
}));

export const darkWebMonitoringConfigRelations = relations(darkWebMonitoringConfig, ({ one }) => ({
  organization: one(organizations, {
    fields: [darkWebMonitoringConfig.orgId],
    references: [organizations.id],
  }),
}));

export const darkWebScanHistoryRelations = relations(darkWebScanHistory, ({ one }) => ({
  organization: one(organizations, {
    fields: [darkWebScanHistory.orgId],
    references: [organizations.id],
  }),
}));

// Types
export type BreachMonitoringTarget = typeof breachMonitoringTargets.$inferSelect;
export type InsertBreachMonitoringTarget = typeof breachMonitoringTargets.$inferInsert;
export type DarkWebExposure = typeof darkWebExposures.$inferSelect;
export type InsertDarkWebExposure = typeof darkWebExposures.$inferInsert;
export type DarkWebMonitoringConfig = typeof darkWebMonitoringConfig.$inferSelect;
export type InsertDarkWebMonitoringConfig = typeof darkWebMonitoringConfig.$inferInsert;
export type DarkWebScanHistoryEntry = typeof darkWebScanHistory.$inferSelect;
export type InsertDarkWebScanHistoryEntry = typeof darkWebScanHistory.$inferInsert;

// ============================================================================
// Physical Security Convergence
// ============================================================================

export const BADGE_EVENT_TYPES = [
  "access_granted",
  "access_denied",
  "door_forced",
  "door_held",
  "tailgate_detected",
  "antipassback_violation",
  "duress_alarm",
  "card_unknown",
] as const;

export const PHYSICAL_ASSET_TYPES = [
  "access_point",
  "camera",
  "server_room",
  "data_center",
  "office",
  "parking_gate",
  "elevator",
  "turnstile",
  "cabinet",
  "safe",
] as const;

export const PHYSICAL_INCIDENT_STATUSES = ["open", "investigating", "resolved", "escalated"] as const;

export const VISITOR_STATUSES = ["pre_registered", "checked_in", "checked_out", "denied", "escorted"] as const;

export const physicalAssets = pgTable("physical_assets", {
  id: uuid("id").defaultRandom().primaryKey(),
  orgId: varchar("org_id")
    .notNull()
    .references(() => organizations.id, { onDelete: "cascade" }),
  name: text("name").notNull(),
  assetType: text("asset_type").notNull(), // PHYSICAL_ASSET_TYPES
  location: text("location").notNull(),
  building: text("building"),
  floor: text("floor"),
  zone: text("zone"),
  controllerType: text("controller_type"), // "lenel", "genetec", "honeywell", "generic"
  controllerId: text("controller_id"),
  ipAddress: text("ip_address"),
  isOnline: boolean("is_online").default(true).notNull(),
  lastHeartbeat: timestamp("last_heartbeat"),
  metadata: jsonb("metadata").$type<Record<string, unknown>>().default({}),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
});

export const badgeEvents = pgTable("badge_events", {
  id: uuid("id").defaultRandom().primaryKey(),
  orgId: varchar("org_id")
    .notNull()
    .references(() => organizations.id, { onDelete: "cascade" }),
  assetId: uuid("asset_id").references(() => physicalAssets.id, { onDelete: "set null" }),
  eventType: text("event_type").notNull(), // BADGE_EVENT_TYPES
  badgeNumber: text("badge_number"),
  employeeName: text("employee_name"),
  employeeEmail: text("employee_email"),
  employeeDepartment: text("employee_department"),
  location: text("location").notNull(),
  doorName: text("door_name"),
  direction: text("direction"), // "entry", "exit"
  isAnomaly: boolean("is_anomaly").default(false).notNull(),
  anomalyReason: text("anomaly_reason"),
  correlatedAlertId: uuid("correlated_alert_id"),
  rawPayload: jsonb("raw_payload").$type<Record<string, unknown>>().default({}),
  occurredAt: timestamp("occurred_at").defaultNow().notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const physicalIncidents = pgTable("physical_incidents", {
  id: uuid("id").defaultRandom().primaryKey(),
  orgId: varchar("org_id")
    .notNull()
    .references(() => organizations.id, { onDelete: "cascade" }),
  title: text("title").notNull(),
  description: text("description"),
  incidentType: text("incident_type").notNull(), // "tailgate", "forced_entry", "after_hours", "unauthorized_access", "suspicious_activity", "equipment_tamper"
  severity: text("severity").default("medium").notNull(),
  status: text("status").default("open").notNull(), // PHYSICAL_INCIDENT_STATUSES
  location: text("location"),
  badgeEventIds: jsonb("badge_event_ids").$type<string[]>().default([]),
  correlatedDigitalIncidentId: uuid("correlated_digital_incident_id"),
  correlatedAlertIds: jsonb("correlated_alert_ids").$type<string[]>().default([]),
  assignedTo: text("assigned_to"),
  resolvedAt: timestamp("resolved_at"),
  resolutionNotes: text("resolution_notes"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
});

export const visitors = pgTable("visitors", {
  id: uuid("id").defaultRandom().primaryKey(),
  orgId: varchar("org_id")
    .notNull()
    .references(() => organizations.id, { onDelete: "cascade" }),
  name: text("name").notNull(),
  email: text("email"),
  company: text("company"),
  hostEmployeeName: text("host_employee_name"),
  hostEmployeeEmail: text("host_employee_email"),
  purpose: text("purpose"),
  status: text("status").default("pre_registered").notNull(), // VISITOR_STATUSES
  badgeNumber: text("badge_number"),
  scheduledAt: timestamp("scheduled_at"),
  checkedInAt: timestamp("checked_in_at"),
  checkedOutAt: timestamp("checked_out_at"),
  areasAuthorized: jsonb("areas_authorized").$type<string[]>().default([]),
  correlatedEvents: jsonb("correlated_events").$type<string[]>().default([]),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const physicalSecurityConfig = pgTable("physical_security_config", {
  id: uuid("id").defaultRandom().primaryKey(),
  orgId: varchar("org_id")
    .notNull()
    .references(() => organizations.id, { onDelete: "cascade" }),
  isEnabled: boolean("is_enabled").default(true).notNull(),
  controllerIntegrations: jsonb("controller_integrations")
    .$type<Array<{ type: string; name: string; apiEndpoint: string; isActive: boolean }>>()
    .default([]),
  afterHoursStart: text("after_hours_start").default("20:00"),
  afterHoursEnd: text("after_hours_end").default("06:00"),
  tailgateDetectionEnabled: boolean("tailgate_detection_enabled").default(true).notNull(),
  anomalyCorrelationEnabled: boolean("anomaly_correlation_enabled").default(true).notNull(),
  autoCreateDigitalIncidents: boolean("auto_create_digital_incidents").default(true).notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
});

// Relations
export const physicalAssetsRelations = relations(physicalAssets, ({ one }) => ({
  organization: one(organizations, {
    fields: [physicalAssets.orgId],
    references: [organizations.id],
  }),
}));

export const badgeEventsRelations = relations(badgeEvents, ({ one }) => ({
  organization: one(organizations, {
    fields: [badgeEvents.orgId],
    references: [organizations.id],
  }),
  asset: one(physicalAssets, {
    fields: [badgeEvents.assetId],
    references: [physicalAssets.id],
  }),
}));

export const physicalIncidentsRelations = relations(physicalIncidents, ({ one }) => ({
  organization: one(organizations, {
    fields: [physicalIncidents.orgId],
    references: [organizations.id],
  }),
}));

export const visitorsRelations = relations(visitors, ({ one }) => ({
  organization: one(organizations, {
    fields: [visitors.orgId],
    references: [organizations.id],
  }),
}));

export const physicalSecurityConfigRelations = relations(physicalSecurityConfig, ({ one }) => ({
  organization: one(organizations, {
    fields: [physicalSecurityConfig.orgId],
    references: [organizations.id],
  }),
}));

// Types
export type PhysicalAsset = typeof physicalAssets.$inferSelect;
export type InsertPhysicalAsset = typeof physicalAssets.$inferInsert;
export type BadgeEvent = typeof badgeEvents.$inferSelect;
export type InsertBadgeEvent = typeof badgeEvents.$inferInsert;
export type PhysicalIncident = typeof physicalIncidents.$inferSelect;
export type InsertPhysicalIncident = typeof physicalIncidents.$inferInsert;
export type Visitor = typeof visitors.$inferSelect;
export type InsertVisitor = typeof visitors.$inferInsert;
export type PhysicalSecurityConfig = typeof physicalSecurityConfig.$inferSelect;
export type InsertPhysicalSecurityConfig = typeof physicalSecurityConfig.$inferInsert;

// ============================================================================
// Phishing Simulation & Security Awareness
// ============================================================================

export const PHISHING_CAMPAIGN_STATUSES = ["draft", "scheduled", "running", "completed", "paused"] as const;

export const PHISHING_TEMPLATE_CATEGORIES = [
  "credential_harvest",
  "malware_download",
  "data_entry",
  "reply_to",
  "smishing",
  "vishing",
  "spear_phishing",
  "whaling",
] as const;

export const TRAINING_MODULE_TYPES = [
  "video",
  "quiz",
  "interactive",
  "document",
  "simulation",
  "micro_learning",
] as const;

export const phishingCampaigns = pgTable("phishing_campaigns", {
  id: uuid("id").defaultRandom().primaryKey(),
  orgId: varchar("org_id")
    .notNull()
    .references(() => organizations.id, { onDelete: "cascade" }),
  name: text("name").notNull(),
  description: text("description"),
  status: text("status").default("draft").notNull(), // PHISHING_CAMPAIGN_STATUSES
  templateId: uuid("template_id"),
  templateCategory: text("template_category"), // PHISHING_TEMPLATE_CATEGORIES
  senderName: text("sender_name"),
  senderEmail: text("sender_email"),
  subject: text("subject"),
  emailBody: text("email_body"),
  landingPageHtml: text("landing_page_html"),
  targetDepartments: jsonb("target_departments").$type<string[]>().default([]),
  targetEmails: jsonb("target_emails").$type<string[]>().default([]),
  totalRecipients: integer("total_recipients").default(0).notNull(),
  emailsSent: integer("emails_sent").default(0).notNull(),
  emailsOpened: integer("emails_opened").default(0).notNull(),
  linksClicked: integer("links_clicked").default(0).notNull(),
  credentialsSubmitted: integer("credentials_submitted").default(0).notNull(),
  reported: integer("reported").default(0).notNull(),
  scheduledAt: timestamp("scheduled_at"),
  startedAt: timestamp("started_at"),
  completedAt: timestamp("completed_at"),
  createdBy: uuid("created_by"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
});

export const phishingTemplates = pgTable("phishing_templates", {
  id: uuid("id").defaultRandom().primaryKey(),
  orgId: varchar("org_id")
    .notNull()
    .references(() => organizations.id, { onDelete: "cascade" }),
  name: text("name").notNull(),
  category: text("category").notNull(), // PHISHING_TEMPLATE_CATEGORIES
  difficulty: text("difficulty").default("medium").notNull(), // "easy", "medium", "hard", "expert"
  industry: text("industry"), // optional industry-specific
  subject: text("subject").notNull(),
  senderName: text("sender_name").notNull(),
  senderEmail: text("sender_email").notNull(),
  emailBody: text("email_body").notNull(),
  landingPageHtml: text("landing_page_html"),
  isBuiltIn: boolean("is_built_in").default(false).notNull(),
  usageCount: integer("usage_count").default(0).notNull(),
  successRate: real("success_rate"), // % of recipients who fell for it
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const phishingResults = pgTable("phishing_results", {
  id: uuid("id").defaultRandom().primaryKey(),
  orgId: varchar("org_id")
    .notNull()
    .references(() => organizations.id, { onDelete: "cascade" }),
  campaignId: uuid("campaign_id")
    .notNull()
    .references(() => phishingCampaigns.id, { onDelete: "cascade" }),
  recipientEmail: text("recipient_email").notNull(),
  recipientName: text("recipient_name"),
  department: text("department"),
  emailSentAt: timestamp("email_sent_at"),
  emailOpenedAt: timestamp("email_opened_at"),
  linkClickedAt: timestamp("link_clicked_at"),
  credentialSubmittedAt: timestamp("credential_submitted_at"),
  reportedAt: timestamp("reported_at"),
  userAgent: text("user_agent"),
  ipAddress: text("ip_address"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const employeeRiskScores = pgTable("employee_risk_scores", {
  id: uuid("id").defaultRandom().primaryKey(),
  orgId: varchar("org_id")
    .notNull()
    .references(() => organizations.id, { onDelete: "cascade" }),
  email: text("email").notNull(),
  name: text("name"),
  department: text("department"),
  riskScore: real("risk_score").default(50).notNull(), // 0-100
  phishingClickRate: real("phishing_click_rate").default(0).notNull(), // %
  reportRate: real("report_rate").default(0).notNull(), // %
  trainingCompletionRate: real("training_completion_rate").default(0).notNull(), // %
  campaignsReceived: integer("campaigns_received").default(0).notNull(),
  campaignsClicked: integer("campaigns_clicked").default(0).notNull(),
  campaignsReported: integer("campaigns_reported").default(0).notNull(),
  trainingsCompleted: integer("trainings_completed").default(0).notNull(),
  trainingsAssigned: integer("trainings_assigned").default(0).notNull(),
  lastPhishingTestAt: timestamp("last_phishing_test_at"),
  lastTrainingCompletedAt: timestamp("last_training_completed_at"),
  riskTrend: text("risk_trend").default("stable").notNull(), // "improving", "stable", "worsening"
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
});

export const trainingModules = pgTable("training_modules", {
  id: uuid("id").defaultRandom().primaryKey(),
  orgId: varchar("org_id")
    .notNull()
    .references(() => organizations.id, { onDelete: "cascade" }),
  title: text("title").notNull(),
  description: text("description"),
  moduleType: text("module_type").notNull(), // TRAINING_MODULE_TYPES
  category: text("category").notNull(), // "phishing_awareness", "password_security", "social_engineering", "data_handling", "insider_threat", "physical_security"
  difficulty: text("difficulty").default("beginner").notNull(),
  durationMinutes: integer("duration_minutes").default(15).notNull(),
  contentUrl: text("content_url"),
  passingScore: integer("passing_score").default(80),
  isBuiltIn: boolean("is_built_in").default(false).notNull(),
  isActive: boolean("is_active").default(true).notNull(),
  completionCount: integer("completion_count").default(0).notNull(),
  averageScore: real("average_score"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const trainingAssignments = pgTable("training_assignments", {
  id: uuid("id").defaultRandom().primaryKey(),
  orgId: varchar("org_id")
    .notNull()
    .references(() => organizations.id, { onDelete: "cascade" }),
  moduleId: uuid("module_id")
    .notNull()
    .references(() => trainingModules.id, { onDelete: "cascade" }),
  employeeEmail: text("employee_email").notNull(),
  employeeName: text("employee_name"),
  assignedReason: text("assigned_reason"), // "phishing_click", "onboarding", "periodic", "manual"
  assignedAt: timestamp("assigned_at").defaultNow().notNull(),
  dueAt: timestamp("due_at"),
  startedAt: timestamp("started_at"),
  completedAt: timestamp("completed_at"),
  score: integer("score"),
  passed: boolean("passed"),
  attempts: integer("attempts").default(0).notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const securityAwarenessConfig = pgTable("security_awareness_config", {
  id: uuid("id").defaultRandom().primaryKey(),
  orgId: varchar("org_id")
    .notNull()
    .references(() => organizations.id, { onDelete: "cascade" }),
  isEnabled: boolean("is_enabled").default(true).notNull(),
  autoEnrollOnClick: boolean("auto_enroll_on_click").default(true).notNull(),
  defaultTrainingModuleId: uuid("default_training_module_id"),
  phishingFrequencyDays: integer("phishing_frequency_days").default(30).notNull(),
  vishingEnabled: boolean("vishing_enabled").default(false).notNull(),
  smishingEnabled: boolean("smishing_enabled").default(false).notNull(),
  riskScoreThreshold: integer("risk_score_threshold").default(75).notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
});

// Relations
export const phishingCampaignsRelations = relations(phishingCampaigns, ({ one }) => ({
  organization: one(organizations, {
    fields: [phishingCampaigns.orgId],
    references: [organizations.id],
  }),
}));

export const phishingTemplatesRelations = relations(phishingTemplates, ({ one }) => ({
  organization: one(organizations, {
    fields: [phishingTemplates.orgId],
    references: [organizations.id],
  }),
}));

export const phishingResultsRelations = relations(phishingResults, ({ one }) => ({
  organization: one(organizations, {
    fields: [phishingResults.orgId],
    references: [organizations.id],
  }),
  campaign: one(phishingCampaigns, {
    fields: [phishingResults.campaignId],
    references: [phishingCampaigns.id],
  }),
}));

export const employeeRiskScoresRelations = relations(employeeRiskScores, ({ one }) => ({
  organization: one(organizations, {
    fields: [employeeRiskScores.orgId],
    references: [organizations.id],
  }),
}));

export const trainingModulesRelations = relations(trainingModules, ({ one }) => ({
  organization: one(organizations, {
    fields: [trainingModules.orgId],
    references: [organizations.id],
  }),
}));

export const trainingAssignmentsRelations = relations(trainingAssignments, ({ one }) => ({
  organization: one(organizations, {
    fields: [trainingAssignments.orgId],
    references: [organizations.id],
  }),
  module: one(trainingModules, {
    fields: [trainingAssignments.moduleId],
    references: [trainingModules.id],
  }),
}));

export const securityAwarenessConfigRelations = relations(securityAwarenessConfig, ({ one }) => ({
  organization: one(organizations, {
    fields: [securityAwarenessConfig.orgId],
    references: [organizations.id],
  }),
}));

// Types
export type PhishingCampaign = typeof phishingCampaigns.$inferSelect;
export type InsertPhishingCampaign = typeof phishingCampaigns.$inferInsert;
export type PhishingTemplate = typeof phishingTemplates.$inferSelect;
export type InsertPhishingTemplate = typeof phishingTemplates.$inferInsert;
export type PhishingResult = typeof phishingResults.$inferSelect;
export type InsertPhishingResult = typeof phishingResults.$inferInsert;
export type EmployeeRiskScore = typeof employeeRiskScores.$inferSelect;
export type InsertEmployeeRiskScore = typeof employeeRiskScores.$inferInsert;
export type TrainingModule = typeof trainingModules.$inferSelect;
export type InsertTrainingModule = typeof trainingModules.$inferInsert;
export type TrainingAssignment = typeof trainingAssignments.$inferSelect;
export type InsertTrainingAssignment = typeof trainingAssignments.$inferInsert;
export type SecurityAwarenessConfig = typeof securityAwarenessConfig.$inferSelect;
export type InsertSecurityAwarenessConfig = typeof securityAwarenessConfig.$inferInsert;

// ============================================================================
// Quantum Readiness Assessment
// ============================================================================

export const CRYPTO_ALGORITHM_TYPES = [
  "RSA-1024",
  "RSA-2048",
  "RSA-3072",
  "RSA-4096",
  "ECDSA-P256",
  "ECDSA-P384",
  "ECDSA-P521",
  "ECDH-P256",
  "ECDH-P384",
  "Ed25519",
  "DH-2048",
  "DH-4096",
  "DSA-1024",
  "DSA-2048",
  "AES-128",
  "AES-256",
  "3DES",
  "SHA-1",
  "SHA-256",
  "SHA-384",
  "SHA-512",
  "MD5",
  "HMAC-SHA256",
  "ChaCha20-Poly1305",
  "CRYSTALS-Kyber",
  "CRYSTALS-Dilithium",
  "FALCON",
  "SPHINCS+",
  "BIKE",
  "HQC",
  "unknown",
] as const;

export const QUANTUM_RISK_LEVELS = ["critical", "high", "medium", "low", "safe"] as const;

export const CRYPTO_ASSET_SOURCES = [
  "tls_certificate",
  "ssh_key",
  "api_key",
  "vpn_tunnel",
  "code_signing",
  "database_encryption",
  "file_encryption",
  "email_signing",
  "jwt_signing",
  "ipsec",
  "disk_encryption",
  "key_exchange",
  "password_hashing",
  "configuration",
  "library",
  "manual_entry",
] as const;

export const PQC_MIGRATION_STATUSES = [
  "not_started",
  "assessed",
  "planned",
  "in_progress",
  "migrated",
  "verified",
  "deferred",
] as const;

export const NIST_PQC_STANDARDS = [
  "FIPS-203", // ML-KEM (CRYSTALS-Kyber)
  "FIPS-204", // ML-DSA (CRYSTALS-Dilithium)
  "FIPS-205", // SLH-DSA (SPHINCS+)
  "FIPS-206", // FN-DSA (FALCON) — draft
] as const;

export const cryptoInventory = pgTable("crypto_inventory", {
  id: uuid("id").defaultRandom().primaryKey(),
  orgId: varchar("org_id")
    .notNull()
    .references(() => organizations.id, { onDelete: "cascade" }),
  assetName: text("asset_name").notNull(),
  algorithm: text("algorithm").notNull(), // CRYPTO_ALGORITHM_TYPES
  keyLength: integer("key_length"),
  source: text("source").notNull(), // CRYPTO_ASSET_SOURCES
  hostname: text("hostname"),
  port: integer("port"),
  serviceName: text("service_name"),
  filePath: text("file_path"),
  expiresAt: timestamp("expires_at"),
  isQuantumVulnerable: boolean("is_quantum_vulnerable").default(false).notNull(),
  quantumRiskLevel: text("quantum_risk_level").default("medium").notNull(), // QUANTUM_RISK_LEVELS
  isHardcoded: boolean("is_hardcoded").default(false).notNull(),
  canBeUpgraded: boolean("can_be_upgraded").default(true).notNull(),
  pqcReplacement: text("pqc_replacement"), // recommended PQC algorithm
  migrationStatus: text("migration_status").default("not_started").notNull(), // PQC_MIGRATION_STATUSES
  migrationPriority: integer("migration_priority").default(50).notNull(), // 1-100
  migrationNotes: text("migration_notes"),
  lastScannedAt: timestamp("last_scanned_at"),
  metadata: jsonb("metadata").$type<Record<string, unknown>>().default({}),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
});

export const quantumRiskScores = pgTable("quantum_risk_scores", {
  id: uuid("id").defaultRandom().primaryKey(),
  orgId: varchar("org_id")
    .notNull()
    .references(() => organizations.id, { onDelete: "cascade" }),
  overallScore: integer("overall_score").default(0).notNull(), // 0-100 (100 = fully quantum-safe)
  cryptoAgility: integer("crypto_agility").default(0).notNull(), // 0-100
  algorithmDiversity: integer("algorithm_diversity").default(0).notNull(), // 0-100
  pqcReadiness: integer("pqc_readiness").default(0).notNull(), // 0-100
  complianceScore: integer("compliance_score").default(0).notNull(), // 0-100
  totalAssets: integer("total_assets").default(0).notNull(),
  vulnerableAssets: integer("vulnerable_assets").default(0).notNull(),
  migratedAssets: integer("migrated_assets").default(0).notNull(),
  criticalRiskCount: integer("critical_risk_count").default(0).notNull(),
  highRiskCount: integer("high_risk_count").default(0).notNull(),
  mediumRiskCount: integer("medium_risk_count").default(0).notNull(),
  lowRiskCount: integer("low_risk_count").default(0).notNull(),
  estimatedMigrationMonths: integer("estimated_migration_months"),
  estimatedMigrationCost: integer("estimated_migration_cost"), // in cents
  nistComplianceStatus: jsonb("nist_compliance_status")
    .$type<Record<string, { status: string; progress: number; notes: string }>>()
    .default({}),
  scoredAt: timestamp("scored_at").defaultNow().notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const quantumMigrationTasks = pgTable("quantum_migration_tasks", {
  id: uuid("id").defaultRandom().primaryKey(),
  orgId: varchar("org_id")
    .notNull()
    .references(() => organizations.id, { onDelete: "cascade" }),
  title: text("title").notNull(),
  description: text("description"),
  cryptoInventoryId: uuid("crypto_inventory_id").references(() => cryptoInventory.id, { onDelete: "set null" }),
  currentAlgorithm: text("current_algorithm").notNull(),
  targetAlgorithm: text("target_algorithm").notNull(),
  priority: text("priority").default("medium").notNull(), // critical, high, medium, low
  status: text("status").default("not_started").notNull(), // PQC_MIGRATION_STATUSES
  effortEstimateDays: integer("effort_estimate_days"),
  assignedTo: text("assigned_to"),
  dueDate: timestamp("due_date"),
  completedAt: timestamp("completed_at"),
  blockers: text("blockers"),
  nistStandard: text("nist_standard"), // NIST_PQC_STANDARDS
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
});

export const quantumScanHistory = pgTable("quantum_scan_history", {
  id: uuid("id").defaultRandom().primaryKey(),
  orgId: varchar("org_id")
    .notNull()
    .references(() => organizations.id, { onDelete: "cascade" }),
  scanType: text("scan_type").notNull(), // "full", "tls", "ssh", "code", "config"
  status: text("status").default("running").notNull(), // "running", "completed", "failed"
  assetsDiscovered: integer("assets_discovered").default(0).notNull(),
  vulnerableFound: integer("vulnerable_found").default(0).notNull(),
  scanDurationMs: integer("scan_duration_ms"),
  scanTargets: jsonb("scan_targets").$type<string[]>().default([]),
  errorMessage: text("error_message"),
  startedAt: timestamp("started_at").defaultNow().notNull(),
  completedAt: timestamp("completed_at"),
});

// Relations
export const cryptoInventoryRelations = relations(cryptoInventory, ({ one }) => ({
  organization: one(organizations, {
    fields: [cryptoInventory.orgId],
    references: [organizations.id],
  }),
}));

export const quantumRiskScoresRelations = relations(quantumRiskScores, ({ one }) => ({
  organization: one(organizations, {
    fields: [quantumRiskScores.orgId],
    references: [organizations.id],
  }),
}));

export const quantumMigrationTasksRelations = relations(quantumMigrationTasks, ({ one }) => ({
  organization: one(organizations, {
    fields: [quantumMigrationTasks.orgId],
    references: [organizations.id],
  }),
  cryptoAsset: one(cryptoInventory, {
    fields: [quantumMigrationTasks.cryptoInventoryId],
    references: [cryptoInventory.id],
  }),
}));

export const quantumScanHistoryRelations = relations(quantumScanHistory, ({ one }) => ({
  organization: one(organizations, {
    fields: [quantumScanHistory.orgId],
    references: [organizations.id],
  }),
}));

// Types
export type CryptoInventoryItem = typeof cryptoInventory.$inferSelect;
export type InsertCryptoInventoryItem = typeof cryptoInventory.$inferInsert;
export type QuantumRiskScore = typeof quantumRiskScores.$inferSelect;
export type InsertQuantumRiskScore = typeof quantumRiskScores.$inferInsert;
export type QuantumMigrationTask = typeof quantumMigrationTasks.$inferSelect;
export type InsertQuantumMigrationTask = typeof quantumMigrationTasks.$inferInsert;
export type QuantumScanHistoryEntry = typeof quantumScanHistory.$inferSelect;
export type InsertQuantumScanHistoryEntry = typeof quantumScanHistory.$inferInsert;

// ============================================================================
// Privacy Engineering (DSPM++)
// ============================================================================

export const DATA_CLASSIFICATION_LEVELS = ["public", "internal", "confidential", "restricted", "top_secret"] as const;

export const PII_CATEGORIES = [
  "name",
  "email",
  "phone",
  "address",
  "ssn",
  "national_id",
  "passport",
  "date_of_birth",
  "financial_account",
  "credit_card",
  "ip_address",
  "biometric",
  "health_record",
  "genetic_data",
  "location",
  "device_id",
  "cookie_id",
  "username",
  "password_hash",
  "other_pii",
] as const;

export const DATA_ASSET_TYPES = [
  "database_table",
  "database_column",
  "s3_bucket",
  "file_share",
  "api_endpoint",
  "log_stream",
  "email_system",
  "saas_app",
  "data_warehouse",
  "cache",
  "message_queue",
  "backup",
] as const;

export const DATA_FLOW_STATUSES = ["active", "inactive", "deprecated", "under_review"] as const;

export const PIA_STATUSES = ["draft", "in_review", "approved", "rejected", "needs_revision", "expired"] as const;

export const PIA_RISK_LEVELS = ["negligible", "low", "medium", "high", "very_high"] as const;

export const CONSENT_PURPOSES = [
  "marketing",
  "analytics",
  "personalization",
  "third_party_sharing",
  "profiling",
  "automated_decision",
  "research",
  "service_delivery",
  "legal_obligation",
] as const;

export const PRIVACY_SCAN_STATUSES = ["queued", "running", "completed", "failed"] as const;

export const DSAR_TYPES = [
  "access",
  "deletion",
  "rectification",
  "portability",
  "restriction",
  "objection",
  "withdraw_consent",
] as const;

export const DSAR_FULFILLMENT_STATUSES = [
  "pending",
  "in_progress",
  "awaiting_verification",
  "fulfilled",
  "partially_fulfilled",
  "denied",
  "expired",
] as const;

export const JURISDICTIONS = [
  "EU",
  "US",
  "US-CA",
  "US-VA",
  "US-CO",
  "US-CT",
  "UK",
  "BR",
  "CA",
  "IN",
  "SG",
  "AU",
  "ZA",
  "JP",
  "KR",
  "CN",
  "OTHER",
] as const;

// Data Assets — discovered or manually registered data stores containing personal data
export const dataAssets = pgTable(
  "data_assets",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    name: text("name").notNull(),
    description: text("description"),
    assetType: text("asset_type").notNull(), // DATA_ASSET_TYPES
    connectionString: text("connection_string"), // encrypted reference
    hostname: text("hostname"),
    database: text("database"),
    schema: text("schema"),
    tableName: text("table_name"),
    bucketName: text("bucket_name"),
    filePath: text("file_path"),
    classification: text("classification").default("internal").notNull(), // DATA_CLASSIFICATION_LEVELS
    piiCategories: jsonb("pii_categories").$type<string[]>().default([]),
    recordCount: integer("record_count"),
    dataSubjectCount: integer("data_subject_count"),
    jurisdiction: text("jurisdiction").default("OTHER").notNull(), // JURISDICTIONS
    retentionDays: integer("retention_days"),
    isEncrypted: boolean("is_encrypted").default(false).notNull(),
    encryptionMethod: text("encryption_method"),
    dataOwner: text("data_owner"),
    dataProcessor: text("data_processor"),
    legalBasis: text("legal_basis"),
    lastScannedAt: timestamp("last_scanned_at"),
    scanFindings: jsonb("scan_findings").$type<Record<string, unknown>>().default({}),
    minimizationRecommendations: jsonb("minimization_recommendations").$type<string[]>().default([]),
    riskScore: integer("risk_score").default(0).notNull(), // 0-100
    metadata: jsonb("metadata").$type<Record<string, unknown>>().default({}),
    createdAt: timestamp("created_at").defaultNow().notNull(),
    updatedAt: timestamp("updated_at").defaultNow().notNull(),
  },
  (table) => [
    index("idx_data_assets_org").on(table.orgId),
    index("idx_data_assets_type").on(table.assetType),
    index("idx_data_assets_classification").on(table.classification),
    index("idx_data_assets_jurisdiction").on(table.jurisdiction),
  ],
);

// Data Flows — mapping where PII originates, travels, and who processes it
export const dataFlows = pgTable(
  "data_flows",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    name: text("name").notNull(),
    description: text("description"),
    sourceAssetId: uuid("source_asset_id").references(() => dataAssets.id, { onDelete: "set null" }),
    sourceName: text("source_name").notNull(),
    sourceJurisdiction: text("source_jurisdiction").default("OTHER").notNull(),
    destinationAssetId: uuid("destination_asset_id").references(() => dataAssets.id, { onDelete: "set null" }),
    destinationName: text("destination_name").notNull(),
    destinationJurisdiction: text("destination_jurisdiction").default("OTHER").notNull(),
    dataCategories: jsonb("data_categories").$type<string[]>().default([]),
    piiCategories: jsonb("pii_categories").$type<string[]>().default([]),
    purpose: text("purpose"),
    legalBasis: text("legal_basis"),
    processorName: text("processor_name"),
    isCrossBorder: boolean("is_cross_border").default(false).notNull(),
    crossBorderMechanism: text("cross_border_mechanism"), // SCCs, BCRs, Adequacy decision
    transferRiskLevel: text("transfer_risk_level"), // PIA_RISK_LEVELS
    status: text("status").default("active").notNull(), // DATA_FLOW_STATUSES
    volumePerDay: integer("volume_per_day"), // approximate records/day
    frequency: text("frequency"), // real_time, hourly, daily, weekly, monthly
    encryptionInTransit: boolean("encryption_in_transit").default(false).notNull(),
    metadata: jsonb("metadata").$type<Record<string, unknown>>().default({}),
    createdAt: timestamp("created_at").defaultNow().notNull(),
    updatedAt: timestamp("updated_at").defaultNow().notNull(),
  },
  (table) => [
    index("idx_data_flows_org").on(table.orgId),
    index("idx_data_flows_source").on(table.sourceAssetId),
    index("idx_data_flows_dest").on(table.destinationAssetId),
    index("idx_data_flows_cross_border").on(table.isCrossBorder),
  ],
);

// Privacy Impact Assessments — guided assessments for new products/features
export const privacyImpactAssessments = pgTable(
  "privacy_impact_assessments",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    title: text("title").notNull(),
    description: text("description"),
    projectName: text("project_name"),
    assessorName: text("assessor_name"),
    assessorEmail: text("assessor_email"),
    status: text("status").default("draft").notNull(), // PIA_STATUSES
    overallRisk: text("overall_risk").default("medium").notNull(), // PIA_RISK_LEVELS
    dataCollected: jsonb("data_collected").$type<string[]>().default([]), // PII_CATEGORIES
    dataSubjectTypes: jsonb("data_subject_types").$type<string[]>().default([]),
    processingPurposes: jsonb("processing_purposes").$type<string[]>().default([]),
    legalBasis: text("legal_basis"),
    retentionPeriod: text("retention_period"),
    thirdPartyRecipients: jsonb("third_party_recipients").$type<string[]>().default([]),
    crossBorderTransfers: boolean("cross_border_transfers").default(false).notNull(),
    crossBorderDestinations: jsonb("cross_border_destinations").$type<string[]>().default([]),
    securityMeasures: jsonb("security_measures").$type<string[]>().default([]),
    privacyRisks: jsonb("privacy_risks")
      .$type<Array<{ risk: string; likelihood: string; impact: string; mitigation: string }>>()
      .default([]),
    mitigationPlan: text("mitigation_plan"),
    dpoApproval: boolean("dpo_approval").default(false).notNull(),
    dpoComments: text("dpo_comments"),
    reviewDate: timestamp("review_date"),
    expiresAt: timestamp("expires_at"),
    completedAt: timestamp("completed_at"),
    metadata: jsonb("metadata").$type<Record<string, unknown>>().default({}),
    createdAt: timestamp("created_at").defaultNow().notNull(),
    updatedAt: timestamp("updated_at").defaultNow().notNull(),
  },
  (table) => [
    index("idx_pia_org").on(table.orgId),
    index("idx_pia_status").on(table.status),
    index("idx_pia_risk").on(table.overallRisk),
  ],
);

// Privacy Scans — automated PII/PHI/PCI discovery scan history
export const privacyScans = pgTable(
  "privacy_scans",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    scanType: text("scan_type").notNull(), // "full", "pii", "phi", "pci", "classification"
    targetAssetId: uuid("target_asset_id").references(() => dataAssets.id, { onDelete: "set null" }),
    targetDescription: text("target_description"),
    status: text("status").default("queued").notNull(), // PRIVACY_SCAN_STATUSES
    findingsCount: integer("findings_count").default(0).notNull(),
    piiFieldsFound: integer("pii_fields_found").default(0).notNull(),
    phiFieldsFound: integer("phi_fields_found").default(0).notNull(),
    pciFieldsFound: integer("pci_fields_found").default(0).notNull(),
    classificationResults: jsonb("classification_results")
      .$type<
        Array<{
          field: string;
          detectedType: string;
          confidence: number;
          sampleCount: number;
          classification: string;
        }>
      >()
      .default([]),
    minimizationFindings: jsonb("minimization_findings")
      .$type<Array<{ field: string; reason: string; recommendation: string }>>()
      .default([]),
    scanDurationMs: integer("scan_duration_ms"),
    errorMessage: text("error_message"),
    startedAt: timestamp("started_at").defaultNow().notNull(),
    completedAt: timestamp("completed_at"),
  },
  (table) => [index("idx_privacy_scans_org").on(table.orgId), index("idx_privacy_scans_status").on(table.status)],
);

// Consent Records — consent management integration records
export const consentRecords = pgTable(
  "consent_records",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    dataSubjectId: text("data_subject_id").notNull(), // external identifier
    dataSubjectEmail: text("data_subject_email"),
    purpose: text("purpose").notNull(), // CONSENT_PURPOSES
    granted: boolean("granted").default(false).notNull(),
    source: text("source").default("manual").notNull(), // "onetrust", "cookiebot", "manual", "api"
    externalConsentId: text("external_consent_id"),
    legalBasis: text("legal_basis"),
    jurisdiction: text("jurisdiction"),
    consentVersion: text("consent_version"),
    grantedAt: timestamp("granted_at"),
    withdrawnAt: timestamp("withdrawn_at"),
    expiresAt: timestamp("expires_at"),
    metadata: jsonb("metadata").$type<Record<string, unknown>>().default({}),
    createdAt: timestamp("created_at").defaultNow().notNull(),
    updatedAt: timestamp("updated_at").defaultNow().notNull(),
  },
  (table) => [
    index("idx_consent_org").on(table.orgId),
    index("idx_consent_subject").on(table.dataSubjectId),
    index("idx_consent_purpose").on(table.purpose),
  ],
);

// Cross-Border Transfer Alerts — alert when PII moves across jurisdictional boundaries
export const crossBorderTransferAlerts = pgTable(
  "cross_border_transfer_alerts",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    dataFlowId: uuid("data_flow_id").references(() => dataFlows.id, { onDelete: "set null" }),
    sourceJurisdiction: text("source_jurisdiction").notNull(),
    destinationJurisdiction: text("destination_jurisdiction").notNull(),
    dataCategories: jsonb("data_categories").$type<string[]>().default([]),
    riskLevel: text("risk_level").default("medium").notNull(), // PIA_RISK_LEVELS
    alertReason: text("alert_reason").notNull(),
    legalMechanism: text("legal_mechanism"), // what legal basis covers this transfer
    requiresAction: boolean("requires_action").default(true).notNull(),
    resolvedAt: timestamp("resolved_at"),
    resolvedBy: text("resolved_by"),
    resolutionNotes: text("resolution_notes"),
    metadata: jsonb("metadata").$type<Record<string, unknown>>().default({}),
    createdAt: timestamp("created_at").defaultNow().notNull(),
  },
  (table) => [
    index("idx_cbt_alerts_org").on(table.orgId),
    index("idx_cbt_alerts_flow").on(table.dataFlowId),
    index("idx_cbt_alerts_risk").on(table.riskLevel),
  ],
);

// DSAR Fulfillment Tasks — automated DSAR fulfillment across connected systems
export const dsarFulfillmentTasks = pgTable(
  "dsar_fulfillment_tasks",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    dsarRequestId: varchar("dsar_request_id").references(() => dsarRequests.id, { onDelete: "cascade" }),
    targetSystem: text("target_system").notNull(), // name of the system to process
    targetAssetId: uuid("target_asset_id").references(() => dataAssets.id, { onDelete: "set null" }),
    taskType: text("task_type").notNull(), // "locate", "extract", "delete", "anonymize", "export"
    status: text("status").default("pending").notNull(), // "pending", "in_progress", "completed", "failed", "skipped"
    recordsAffected: integer("records_affected").default(0).notNull(),
    errorMessage: text("error_message"),
    executionLog: jsonb("execution_log").$type<string[]>().default([]),
    startedAt: timestamp("started_at"),
    completedAt: timestamp("completed_at"),
    createdAt: timestamp("created_at").defaultNow().notNull(),
  },
  (table) => [
    index("idx_dsar_tasks_org").on(table.orgId),
    index("idx_dsar_tasks_request").on(table.dsarRequestId),
    index("idx_dsar_tasks_status").on(table.status),
  ],
);

// Relations
export const dataAssetsRelations = relations(dataAssets, ({ one }) => ({
  organization: one(organizations, {
    fields: [dataAssets.orgId],
    references: [organizations.id],
  }),
}));

export const dataFlowsRelations = relations(dataFlows, ({ one }) => ({
  organization: one(organizations, {
    fields: [dataFlows.orgId],
    references: [organizations.id],
  }),
  sourceAsset: one(dataAssets, {
    fields: [dataFlows.sourceAssetId],
    references: [dataAssets.id],
    relationName: "sourceFlows",
  }),
  destinationAsset: one(dataAssets, {
    fields: [dataFlows.destinationAssetId],
    references: [dataAssets.id],
    relationName: "destFlows",
  }),
}));

export const privacyImpactAssessmentsRelations = relations(privacyImpactAssessments, ({ one }) => ({
  organization: one(organizations, {
    fields: [privacyImpactAssessments.orgId],
    references: [organizations.id],
  }),
}));

export const privacyScansRelations = relations(privacyScans, ({ one }) => ({
  organization: one(organizations, {
    fields: [privacyScans.orgId],
    references: [organizations.id],
  }),
  targetAsset: one(dataAssets, {
    fields: [privacyScans.targetAssetId],
    references: [dataAssets.id],
  }),
}));

export const consentRecordsRelations = relations(consentRecords, ({ one }) => ({
  organization: one(organizations, {
    fields: [consentRecords.orgId],
    references: [organizations.id],
  }),
}));

export const crossBorderTransferAlertsRelations = relations(crossBorderTransferAlerts, ({ one }) => ({
  organization: one(organizations, {
    fields: [crossBorderTransferAlerts.orgId],
    references: [organizations.id],
  }),
  dataFlow: one(dataFlows, {
    fields: [crossBorderTransferAlerts.dataFlowId],
    references: [dataFlows.id],
  }),
}));

export const dsarFulfillmentTasksRelations = relations(dsarFulfillmentTasks, ({ one }) => ({
  organization: one(organizations, {
    fields: [dsarFulfillmentTasks.orgId],
    references: [organizations.id],
  }),
  targetAsset: one(dataAssets, {
    fields: [dsarFulfillmentTasks.targetAssetId],
    references: [dataAssets.id],
  }),
}));

// Types
export type DataAsset = typeof dataAssets.$inferSelect;
export type InsertDataAsset = typeof dataAssets.$inferInsert;
export type DataFlow = typeof dataFlows.$inferSelect;
export type InsertDataFlow = typeof dataFlows.$inferInsert;
export type PrivacyImpactAssessment = typeof privacyImpactAssessments.$inferSelect;
export type InsertPrivacyImpactAssessment = typeof privacyImpactAssessments.$inferInsert;
export type PrivacyScan = typeof privacyScans.$inferSelect;
export type InsertPrivacyScan = typeof privacyScans.$inferInsert;
export type ConsentRecord = typeof consentRecords.$inferSelect;
export type InsertConsentRecord = typeof consentRecords.$inferInsert;
export type CrossBorderTransferAlert = typeof crossBorderTransferAlerts.$inferSelect;
export type InsertCrossBorderTransferAlert = typeof crossBorderTransferAlerts.$inferInsert;
export type DsarFulfillmentTask = typeof dsarFulfillmentTasks.$inferSelect;
export type InsertDsarFulfillmentTask = typeof dsarFulfillmentTasks.$inferInsert;

// ─── Security Metrics Intelligence ───────────────────────────────────────────

export const METRIC_KPI_TYPES = [
  "mttr",
  "mttd",
  "incident_volume",
  "alert_volume",
  "false_positive_rate",
  "sla_compliance",
  "coverage_score",
  "roi_savings",
  "cost_per_incident",
  "analyst_efficiency",
] as const;

export const METRIC_PERIOD_TYPES = ["daily", "weekly", "monthly", "quarterly"] as const;

export const SLA_SEVERITY_TARGETS = ["critical", "high", "medium", "low"] as const;

export const securityKpiSnapshots = pgTable(
  "security_kpi_snapshots",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    kpiType: text("kpi_type").notNull(),
    period: text("period").notNull().default("daily"),
    value: doublePrecision("value").notNull(),
    previousValue: doublePrecision("previous_value"),
    unit: text("unit"),
    metadata: jsonb("metadata"),
    periodStart: timestamp("period_start").notNull(),
    periodEnd: timestamp("period_end").notNull(),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_kpi_snapshots_org").on(table.orgId),
    index("idx_kpi_snapshots_org_type").on(table.orgId, table.kpiType),
    index("idx_kpi_snapshots_org_period").on(table.orgId, table.periodStart),
  ],
);

export const vulnerabilitySlaTargets = pgTable(
  "vulnerability_sla_targets",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    severity: text("severity").notNull(),
    targetHours: integer("target_hours").notNull(),
    enabled: boolean("enabled").notNull().default(true),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_vuln_sla_org").on(table.orgId),
    uniqueIndex("idx_vuln_sla_org_severity").on(table.orgId, table.severity),
  ],
);

export const securityToolOverlaps = pgTable(
  "security_tool_overlaps",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    capability: text("capability").notNull(),
    tools: jsonb("tools").notNull(),
    annualCost: doublePrecision("annual_cost"),
    recommendation: text("recommendation"),
    potentialSavings: doublePrecision("potential_savings"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [index("idx_tool_overlaps_org").on(table.orgId)],
);

export const boardKpiConfigs = pgTable(
  "board_kpi_configs",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    kpiType: text("kpi_type").notNull(),
    displayName: text("display_name").notNull(),
    position: integer("position").notNull().default(0),
    visible: boolean("visible").notNull().default(true),
    targetValue: doublePrecision("target_value"),
    warningThreshold: doublePrecision("warning_threshold"),
    criticalThreshold: doublePrecision("critical_threshold"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [index("idx_board_kpi_org").on(table.orgId)],
);

export const securityKpiSnapshotsRelations = relations(securityKpiSnapshots, ({ one }) => ({
  organization: one(organizations, {
    fields: [securityKpiSnapshots.orgId],
    references: [organizations.id],
  }),
}));

export const vulnerabilitySlaTargetsRelations = relations(vulnerabilitySlaTargets, ({ one }) => ({
  organization: one(organizations, {
    fields: [vulnerabilitySlaTargets.orgId],
    references: [organizations.id],
  }),
}));

export const securityToolOverlapsRelations = relations(securityToolOverlaps, ({ one }) => ({
  organization: one(organizations, {
    fields: [securityToolOverlaps.orgId],
    references: [organizations.id],
  }),
}));

export const boardKpiConfigsRelations = relations(boardKpiConfigs, ({ one }) => ({
  organization: one(organizations, {
    fields: [boardKpiConfigs.orgId],
    references: [organizations.id],
  }),
}));

export type SecurityKpiSnapshot = typeof securityKpiSnapshots.$inferSelect;
export type InsertSecurityKpiSnapshot = typeof securityKpiSnapshots.$inferInsert;
export type VulnerabilitySlaTarget = typeof vulnerabilitySlaTargets.$inferSelect;
export type InsertVulnerabilitySlaTarget = typeof vulnerabilitySlaTargets.$inferInsert;
export type SecurityToolOverlap = typeof securityToolOverlaps.$inferSelect;
export type InsertSecurityToolOverlap = typeof securityToolOverlaps.$inferInsert;
export type BoardKpiConfig = typeof boardKpiConfigs.$inferSelect;
export type InsertBoardKpiConfig = typeof boardKpiConfigs.$inferInsert;

// ─── DNS Security Layer ─────────────────────────────────────────────────────

export const DNS_EVENT_TYPES = [
  "query",
  "response",
  "blocked",
  "sinkholed",
  "tunneling_detected",
  "exfiltration_detected",
  "dga_detected",
  "nrd_alert",
] as const;

export const DNS_FINDING_SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

export const DNS_FINDING_TYPES = [
  "dga_domain",
  "dns_tunneling",
  "dns_exfiltration",
  "newly_registered_domain",
  "sinkholed_hit",
  "high_entropy_query",
  "excessive_nxdomain",
  "suspicious_txt_record",
] as const;

export const SINKHOLE_STATUSES = ["active", "inactive", "expired"] as const;

export const dnsEvents = pgTable(
  "dns_events",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    eventType: text("event_type").notNull(),
    queryName: text("query_name").notNull(),
    queryType: text("query_type").default("A"),
    responseCode: text("response_code"),
    responseData: text("response_data"),
    sourceIp: text("source_ip"),
    sourceHostname: text("source_hostname"),
    destinationIp: text("destination_ip"),
    serverIp: text("server_ip"),
    querySize: integer("query_size"),
    responseSize: integer("response_size"),
    entropy: doublePrecision("entropy"),
    isSuspicious: boolean("is_suspicious").default(false),
    findingId: varchar("finding_id"),
    rawData: jsonb("raw_data"),
    timestamp: timestamp("timestamp").defaultNow(),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_dns_events_org").on(table.orgId),
    index("idx_dns_events_org_type").on(table.orgId, table.eventType),
    index("idx_dns_events_org_query").on(table.orgId, table.queryName),
    index("idx_dns_events_org_timestamp").on(table.orgId, table.timestamp),
    index("idx_dns_events_source_ip").on(table.orgId, table.sourceIp),
  ],
);

export const dnsFindings = pgTable(
  "dns_findings",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    findingType: text("finding_type").notNull(),
    severity: text("severity").notNull().default("medium"),
    domain: text("domain").notNull(),
    description: text("description"),
    confidence: doublePrecision("confidence"),
    sourceIp: text("source_ip"),
    sourceHostname: text("source_hostname"),
    indicators: jsonb("indicators"),
    mitreTechnique: text("mitre_technique"),
    status: text("status").notNull().default("open"),
    analystNotes: text("analyst_notes"),
    resolvedAt: timestamp("resolved_at"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_dns_findings_org").on(table.orgId),
    index("idx_dns_findings_org_type").on(table.orgId, table.findingType),
    index("idx_dns_findings_org_severity").on(table.orgId, table.severity),
    index("idx_dns_findings_org_status").on(table.orgId, table.status),
    index("idx_dns_findings_domain").on(table.orgId, table.domain),
  ],
);

export const sinkholedDomains = pgTable(
  "sinkholed_domains",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    domain: text("domain").notNull(),
    reason: text("reason"),
    source: text("source").default("manual"),
    status: text("status").notNull().default("active"),
    hitCount: integer("hit_count").notNull().default(0),
    lastHitAt: timestamp("last_hit_at"),
    expiresAt: timestamp("expires_at"),
    addedBy: varchar("added_by"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_sinkholed_org").on(table.orgId),
    uniqueIndex("idx_sinkholed_org_domain").on(table.orgId, table.domain),
    index("idx_sinkholed_org_status").on(table.orgId, table.status),
  ],
);

export const passiveDnsRecords = pgTable(
  "passive_dns_records",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    domain: text("domain").notNull(),
    recordType: text("record_type").notNull(),
    resolvedValue: text("resolved_value").notNull(),
    firstSeen: timestamp("first_seen").defaultNow(),
    lastSeen: timestamp("last_seen").defaultNow(),
    queryCount: integer("query_count").notNull().default(1),
    sources: jsonb("sources"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_passive_dns_org").on(table.orgId),
    index("idx_passive_dns_domain").on(table.orgId, table.domain),
    index("idx_passive_dns_resolved").on(table.orgId, table.resolvedValue),
    uniqueIndex("idx_passive_dns_unique").on(table.orgId, table.domain, table.recordType, table.resolvedValue),
  ],
);

export const dnsEventsRelations = relations(dnsEvents, ({ one }) => ({
  organization: one(organizations, {
    fields: [dnsEvents.orgId],
    references: [organizations.id],
  }),
}));

export const dnsFindingsRelations = relations(dnsFindings, ({ one }) => ({
  organization: one(organizations, {
    fields: [dnsFindings.orgId],
    references: [organizations.id],
  }),
}));

export const sinkholedDomainsRelations = relations(sinkholedDomains, ({ one }) => ({
  organization: one(organizations, {
    fields: [sinkholedDomains.orgId],
    references: [organizations.id],
  }),
}));

export const passiveDnsRecordsRelations = relations(passiveDnsRecords, ({ one }) => ({
  organization: one(organizations, {
    fields: [passiveDnsRecords.orgId],
    references: [organizations.id],
  }),
}));

export type DnsEvent = typeof dnsEvents.$inferSelect;
export type InsertDnsEvent = typeof dnsEvents.$inferInsert;
export type DnsFinding = typeof dnsFindings.$inferSelect;
export type InsertDnsFinding = typeof dnsFindings.$inferInsert;
export type SinkholedDomain = typeof sinkholedDomains.$inferSelect;
export type InsertSinkholedDomain = typeof sinkholedDomains.$inferInsert;
export type PassiveDnsRecord = typeof passiveDnsRecords.$inferSelect;
export type InsertPassiveDnsRecord = typeof passiveDnsRecords.$inferInsert;

// ─── Email Security ──────────────────────────────────────────────────────────

export const EMAIL_FINDING_TYPES = [
  "spf_fail",
  "dkim_fail",
  "dmarc_fail",
  "bec_attempt",
  "lookalike_domain",
  "executive_impersonation",
  "thread_injection",
  "malicious_attachment",
  "malicious_url",
  "phishing",
  "spam",
  "retroactive_ioc_match",
  "suspicious_header",
  "url_rewrite_block",
] as const;

export const EMAIL_FINDING_SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

export const EMAIL_FINDING_STATUSES = ["open", "investigating", "resolved", "false_positive"] as const;

export const EMAIL_POLICY_ACTIONS = ["quarantine", "block", "tag", "allow", "redirect"] as const;

export const emailMessages = pgTable(
  "email_messages",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    messageId: text("message_id"),
    internetMessageId: text("internet_message_id"),
    subject: text("subject"),
    senderAddress: text("sender_address").notNull(),
    senderDisplayName: text("sender_display_name"),
    recipientAddresses: jsonb("recipient_addresses"),
    ccAddresses: jsonb("cc_addresses"),
    replyTo: text("reply_to"),
    returnPath: text("return_path"),
    receivedAt: timestamp("received_at").defaultNow(),
    direction: text("direction").default("inbound"),
    hasAttachments: boolean("has_attachments").default(false),
    attachmentCount: integer("attachment_count").default(0),
    attachmentNames: jsonb("attachment_names"),
    urlCount: integer("url_count").default(0),
    extractedUrls: jsonb("extracted_urls"),
    spfResult: text("spf_result"),
    dkimResult: text("dkim_result"),
    dmarcResult: text("dmarc_result"),
    authenticationResults: text("authentication_results"),
    senderReputation: doublePrecision("sender_reputation"),
    threadId: text("thread_id"),
    inReplyTo: text("in_reply_to"),
    references: jsonb("email_references"),
    headers: jsonb("headers"),
    bodyPreview: text("body_preview"),
    isSuspicious: boolean("is_suspicious").default(false),
    source: text("source").default("manual"),
    rawData: jsonb("raw_data"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_email_messages_org").on(table.orgId),
    index("idx_email_messages_org_sender").on(table.orgId, table.senderAddress),
    index("idx_email_messages_org_received").on(table.orgId, table.receivedAt),
    index("idx_email_messages_org_thread").on(table.orgId, table.threadId),
    index("idx_email_messages_org_suspicious").on(table.orgId, table.isSuspicious),
  ],
);

export const emailFindings = pgTable(
  "email_findings",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    emailMessageId: varchar("email_message_id"),
    findingType: text("finding_type").notNull(),
    severity: text("severity").notNull().default("medium"),
    confidence: doublePrecision("confidence"),
    title: text("title").notNull(),
    description: text("description"),
    senderAddress: text("sender_address"),
    recipientAddress: text("recipient_address"),
    domain: text("domain"),
    indicators: jsonb("indicators"),
    mitreTechnique: text("mitre_technique"),
    status: text("status").notNull().default("open"),
    analystNotes: text("analyst_notes"),
    actionTaken: text("action_taken"),
    resolvedAt: timestamp("resolved_at"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_email_findings_org").on(table.orgId),
    index("idx_email_findings_org_type").on(table.orgId, table.findingType),
    index("idx_email_findings_org_severity").on(table.orgId, table.severity),
    index("idx_email_findings_org_status").on(table.orgId, table.status),
    index("idx_email_findings_org_sender").on(table.orgId, table.senderAddress),
  ],
);

export const emailPolicies = pgTable(
  "email_policies",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    name: text("name").notNull(),
    description: text("description"),
    policyType: text("policy_type").notNull(),
    action: text("action").notNull().default("quarantine"),
    conditions: jsonb("conditions"),
    enabled: boolean("enabled").notNull().default(true),
    priority: integer("priority").notNull().default(0),
    matchCount: integer("match_count").notNull().default(0),
    lastMatchAt: timestamp("last_match_at"),
    createdBy: varchar("created_by"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_email_policies_org").on(table.orgId),
    index("idx_email_policies_org_type").on(table.orgId, table.policyType),
  ],
);

export const emailUrlRewrites = pgTable(
  "email_url_rewrites",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    originalUrl: text("original_url").notNull(),
    rewrittenUrl: text("rewritten_url"),
    emailMessageId: varchar("email_message_id"),
    clickCount: integer("click_count").notNull().default(0),
    lastClickAt: timestamp("last_click_at"),
    scanResult: text("scan_result"),
    isMalicious: boolean("is_malicious").default(false),
    scanDetails: jsonb("scan_details"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_email_url_rewrites_org").on(table.orgId),
    index("idx_email_url_rewrites_org_url").on(table.orgId, table.originalUrl),
  ],
);

export const emailQuarantineItems = pgTable(
  "email_quarantine_items",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id),
    emailMessageId: varchar("email_message_id"),
    reason: text("reason").notNull(),
    findingId: varchar("finding_id"),
    policyId: varchar("policy_id"),
    status: text("status").notNull().default("quarantined"),
    releasedBy: varchar("released_by"),
    releasedAt: timestamp("released_at"),
    expiresAt: timestamp("expires_at"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_email_quarantine_org").on(table.orgId),
    index("idx_email_quarantine_org_status").on(table.orgId, table.status),
  ],
);

export const emailMessagesRelations = relations(emailMessages, ({ one }) => ({
  organization: one(organizations, {
    fields: [emailMessages.orgId],
    references: [organizations.id],
  }),
}));

export const emailFindingsRelations = relations(emailFindings, ({ one }) => ({
  organization: one(organizations, {
    fields: [emailFindings.orgId],
    references: [organizations.id],
  }),
}));

export const emailPoliciesRelations = relations(emailPolicies, ({ one }) => ({
  organization: one(organizations, {
    fields: [emailPolicies.orgId],
    references: [organizations.id],
  }),
}));

export const emailUrlRewritesRelations = relations(emailUrlRewrites, ({ one }) => ({
  organization: one(organizations, {
    fields: [emailUrlRewrites.orgId],
    references: [organizations.id],
  }),
}));

export const emailQuarantineItemsRelations = relations(emailQuarantineItems, ({ one }) => ({
  organization: one(organizations, {
    fields: [emailQuarantineItems.orgId],
    references: [organizations.id],
  }),
}));

export type EmailMessage = typeof emailMessages.$inferSelect;
export type InsertEmailMessage = typeof emailMessages.$inferInsert;
export type EmailFinding = typeof emailFindings.$inferSelect;
export type InsertEmailFinding = typeof emailFindings.$inferInsert;
export type EmailPolicy = typeof emailPolicies.$inferSelect;
export type InsertEmailPolicy = typeof emailPolicies.$inferInsert;
export type EmailUrlRewrite = typeof emailUrlRewrites.$inferSelect;
export type InsertEmailUrlRewrite = typeof emailUrlRewrites.$inferInsert;
export type EmailQuarantineItem = typeof emailQuarantineItems.$inferSelect;
export type InsertEmailQuarantineItem = typeof emailQuarantineItems.$inferInsert;

// ─── AI Inference Log ─────────────────────────────────────────────────────────

export const aiInferenceLog = pgTable(
  "ai_inference_log",
  {
    id: serial("id").primaryKey(),
    tier: varchar("tier").notNull(),
    model: varchar("model").notNull(),
    promptId: varchar("prompt_id"),
    promptVersion: integer("prompt_version"),
    inputTokens: integer("input_tokens").notNull().default(0),
    outputTokens: integer("output_tokens").notNull().default(0),
    latencyMs: integer("latency_ms").notNull().default(0),
    costEstimateUsd: doublePrecision("cost_estimate_usd").notNull().default(0),
    cached: boolean("cached").notNull().default(false),
    success: boolean("success").notNull().default(true),
    errorMessage: text("error_message"),
    orgId: varchar("org_id"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_ai_inference_log_tier").on(table.tier),
    index("idx_ai_inference_log_created").on(table.createdAt),
    index("idx_ai_inference_log_org").on(table.orgId),
  ],
);

export type AiInferenceLog = typeof aiInferenceLog.$inferSelect;
export type InsertAiInferenceLog = typeof aiInferenceLog.$inferInsert;

// ==========================================
// SECURITY GRAPH ASSETS & RELATIONSHIPS
// ==========================================

export const securityGraphAssets = pgTable(
  "security_graph_assets",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    name: text("name").notNull(),
    type: text("type").notNull(), // code, cloud, identity, data, network, compute, container, endpoint, saas, runtime, remediation, vulnerability
    subType: text("sub_type").notNull(),
    environment: text("environment").notNull().default("production"), // production, staging, development, shared
    riskScore: real("risk_score").notNull().default(0),
    metadata: jsonb("metadata").default({}),
    tags: text("tags")
      .array()
      .default(sql`ARRAY[]::text[]`),
    owner: text("owner"),
    lastScannedAt: timestamp("last_scanned_at"),
    resolutionKey: text("resolution_key").notNull(),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_sg_assets_org").on(table.orgId),
    index("idx_sg_assets_type").on(table.orgId, table.type),
    index("idx_sg_assets_env").on(table.orgId, table.environment),
    index("idx_sg_assets_resolution").on(table.orgId, table.resolutionKey),
  ],
);

export type SecurityGraphAsset = typeof securityGraphAssets.$inferSelect;
export type InsertSecurityGraphAsset = typeof securityGraphAssets.$inferInsert;

export const securityGraphRelationships = pgTable(
  "security_graph_relationships",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    sourceId: varchar("source_id")
      .notNull()
      .references(() => securityGraphAssets.id, { onDelete: "cascade" }),
    targetId: varchar("target_id")
      .notNull()
      .references(() => securityGraphAssets.id, { onDelete: "cascade" }),
    relationship: text("relationship").notNull(),
    weight: real("weight").notNull().default(1),
    metadata: jsonb("metadata").default({}),
    bidirectional: boolean("bidirectional").notNull().default(false),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_sg_rels_org").on(table.orgId),
    index("idx_sg_rels_source").on(table.sourceId),
    index("idx_sg_rels_target").on(table.targetId),
    index("idx_sg_rels_type").on(table.orgId, table.relationship),
  ],
);

export type SecurityGraphRelationship = typeof securityGraphRelationships.$inferSelect;
export type InsertSecurityGraphRelationship = typeof securityGraphRelationships.$inferInsert;

// ==========================================
// TRUST CENTER ARTIFACTS & DOWNLOAD LOG
// ==========================================

export const trustCenterArtifacts = pgTable(
  "trust_center_artifacts",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    category: text("category").notNull(), // soc2_report, iso27001_cert, pentest_report, etc.
    title: text("title").notNull(),
    description: text("description").default(""),
    version: text("version").default("1.0"),
    fileName: text("file_name").notNull(),
    fileSize: integer("file_size").default(0),
    mimeType: text("mime_type").default("application/pdf"),
    uploadedBy: text("uploaded_by").notNull(),
    uploadedAt: timestamp("uploaded_at").defaultNow(),
    lastReviewedAt: timestamp("last_reviewed_at"),
    nextReviewDue: timestamp("next_review_due"),
    freshnessSlaDays: integer("freshness_sla_days").default(180),
    status: text("status").notNull().default("current"), // current, expiring_soon, expired, under_review
    accessLevel: text("access_level").notNull().default("customer_only"), // public, nda_required, customer_only, internal
    downloadCount: integer("download_count").default(0),
    tags: text("tags")
      .array()
      .default(sql`ARRAY[]::text[]`),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_tc_artifacts_org").on(table.orgId),
    index("idx_tc_artifacts_category").on(table.orgId, table.category),
    index("idx_tc_artifacts_status").on(table.orgId, table.status),
  ],
);

export type TrustCenterArtifact = typeof trustCenterArtifacts.$inferSelect;
export type InsertTrustCenterArtifact = typeof trustCenterArtifacts.$inferInsert;

export const trustCenterDownloadLog = pgTable(
  "trust_center_download_log",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    artifactId: varchar("artifact_id")
      .notNull()
      .references(() => trustCenterArtifacts.id, { onDelete: "cascade" }),
    userId: text("user_id").notNull(),
    userEmail: text("user_email"),
    ipAddress: text("ip_address"),
    userAgent: text("user_agent"),
    downloadedAt: timestamp("downloaded_at").defaultNow(),
  },
  (table) => [index("idx_tc_downloads_org").on(table.orgId), index("idx_tc_downloads_artifact").on(table.artifactId)],
);

export type TrustCenterDownload = typeof trustCenterDownloadLog.$inferSelect;
export type InsertTrustCenterDownload = typeof trustCenterDownloadLog.$inferInsert;

// ==========================================
// POLICY PACK ACTIVATIONS
// ==========================================

export const policyPackActivations = pgTable(
  "policy_pack_activations",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    packId: text("pack_id").notNull(),
    strictnessOverride: text("strictness_override"), // null = use pack default
    enabledRuleIds: text("enabled_rule_ids")
      .array()
      .default(sql`ARRAY[]::text[]`),
    disabledRuleIds: text("disabled_rule_ids")
      .array()
      .default(sql`ARRAY[]::text[]`),
    status: text("status").notNull().default("active"), // active, paused, disabled
    activatedBy: text("activated_by"),
    activatedAt: timestamp("activated_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_ppa_org").on(table.orgId),
    index("idx_ppa_pack").on(table.orgId, table.packId),
    index("idx_ppa_status").on(table.orgId, table.status),
  ],
);

export type PolicyPackActivation = typeof policyPackActivations.$inferSelect;
export type InsertPolicyPackActivation = typeof policyPackActivations.$inferInsert;

// ==========================================
// INTEGRATION MARKETPLACE INSTANCES
// ==========================================

export const marketplaceInstances = pgTable(
  "marketplace_instances",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    connectorSlug: text("connector_slug").notNull(),
    authMethod: text("auth_method").notNull(), // oauth2, service_account, api_key, basic, aws_iam
    syncDirection: text("sync_direction").notNull().default("inbound"), // inbound, outbound, bidirectional
    permissionMode: text("permission_mode").notNull().default("read_only"), // read_only, scoped_write, full_write
    config: jsonb("config").default({}),
    syncIntervalMinutes: integer("sync_interval_minutes").default(15),
    status: text("status").notNull().default("pending"), // pending, active, paused, error, disabled
    lastSyncAt: timestamp("last_sync_at"),
    lastSyncStatus: text("last_sync_status"), // success, partial, error
    lastSyncError: text("last_sync_error"),
    eventsIngested: integer("events_ingested").default(0),
    fieldMappings: jsonb("field_mappings").default([]),
    healthScore: integer("health_score").default(100),
    installedBy: text("installed_by"),
    installedAt: timestamp("installed_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_mi_org").on(table.orgId),
    index("idx_mi_connector").on(table.orgId, table.connectorSlug),
    index("idx_mi_status").on(table.orgId, table.status),
  ],
);

export type MarketplaceInstance = typeof marketplaceInstances.$inferSelect;
export type InsertMarketplaceInstance = typeof marketplaceInstances.$inferInsert;

export const marketplaceWebhookEvents = pgTable(
  "marketplace_webhook_events",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    instanceId: varchar("instance_id")
      .notNull()
      .references(() => marketplaceInstances.id, { onDelete: "cascade" }),
    eventType: text("event_type").notNull(),
    payload: jsonb("payload").default({}),
    idempotencyKey: text("idempotency_key"),
    status: text("status").notNull().default("received"), // received, processed, failed
    processedAt: timestamp("processed_at"),
    errorMessage: text("error_message"),
    receivedAt: timestamp("received_at").defaultNow(),
  },
  (table) => [
    index("idx_mwe_org").on(table.orgId),
    index("idx_mwe_instance").on(table.instanceId),
    index("idx_mwe_ikey").on(table.idempotencyKey),
  ],
);

export type MarketplaceWebhookEvent = typeof marketplaceWebhookEvents.$inferSelect;
export type InsertMarketplaceWebhookEvent = typeof marketplaceWebhookEvents.$inferInsert;

export const marketplaceDeadLetters = pgTable(
  "marketplace_dead_letters",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    instanceId: varchar("instance_id")
      .notNull()
      .references(() => marketplaceInstances.id, { onDelete: "cascade" }),
    eventType: text("event_type").notNull(),
    payload: jsonb("payload").default({}),
    errorMessage: text("error_message"),
    retryCount: integer("retry_count").default(0),
    status: text("status").notNull().default("pending"), // pending, retried, discarded
    originalReceivedAt: timestamp("original_received_at"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_mdl_org").on(table.orgId),
    index("idx_mdl_instance").on(table.instanceId),
    index("idx_mdl_status").on(table.orgId, table.status),
  ],
);

export type MarketplaceDeadLetter = typeof marketplaceDeadLetters.$inferSelect;
export type InsertMarketplaceDeadLetter = typeof marketplaceDeadLetters.$inferInsert;

export const marketplaceSyncHistory = pgTable(
  "marketplace_sync_history",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    instanceId: varchar("instance_id")
      .notNull()
      .references(() => marketplaceInstances.id, { onDelete: "cascade" }),
    syncType: text("sync_type").notNull().default("scheduled"), // scheduled, manual, webhook
    status: text("status").notNull().default("running"), // running, success, partial, error
    eventsIngested: integer("events_ingested").default(0),
    errorMessage: text("error_message"),
    durationMs: integer("duration_ms"),
    startedAt: timestamp("started_at").defaultNow(),
    completedAt: timestamp("completed_at"),
  },
  (table) => [
    index("idx_msh_org").on(table.orgId),
    index("idx_msh_instance").on(table.instanceId),
    index("idx_msh_started").on(table.startedAt),
  ],
);

export type MarketplaceSyncHistoryEntry = typeof marketplaceSyncHistory.$inferSelect;
export type InsertMarketplaceSyncHistoryEntry = typeof marketplaceSyncHistory.$inferInsert;

// ==========================================
// CROSS-CUTTING: EVIDENCE, DRIFT, OVERRIDES
// ==========================================

export const crossCuttingEvidence = pgTable(
  "cross_cutting_evidence",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    evidenceType: text("evidence_type").notNull(), // detection, policy_check, vulnerability, compliance, audit
    sourceModule: text("source_module").notNull(), // e.g. "cspm", "endpoint", "identity"
    resourceId: text("resource_id"),
    resourceType: text("resource_type"),
    title: text("title").notNull(),
    description: text("description"),
    severity: text("severity").default("info"),
    status: text("status").notNull().default("open"), // open, acknowledged, resolved, suppressed
    metadata: jsonb("metadata").default({}),
    detectedAt: timestamp("detected_at").defaultNow(),
    resolvedAt: timestamp("resolved_at"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_cce_org").on(table.orgId),
    index("idx_cce_type").on(table.orgId, table.evidenceType),
    index("idx_cce_status").on(table.orgId, table.status),
    index("idx_cce_resource").on(table.orgId, table.resourceId),
  ],
);

export type CrossCuttingEvidence = typeof crossCuttingEvidence.$inferSelect;
export type InsertCrossCuttingEvidence = typeof crossCuttingEvidence.$inferInsert;

export const crossCuttingDrift = pgTable(
  "cross_cutting_drift",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    driftType: text("drift_type").notNull(), // policy, integration, identity, control
    sourceModule: text("source_module").notNull(),
    resourceId: text("resource_id"),
    resourceType: text("resource_type"),
    expectedState: jsonb("expected_state"),
    actualState: jsonb("actual_state"),
    severity: text("severity").default("medium"),
    status: text("status").notNull().default("detected"), // detected, acknowledged, remediated, accepted
    remediationAction: text("remediation_action"),
    detectedAt: timestamp("detected_at").defaultNow(),
    remediatedAt: timestamp("remediated_at"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_ccd_org").on(table.orgId),
    index("idx_ccd_type").on(table.orgId, table.driftType),
    index("idx_ccd_status").on(table.orgId, table.status),
  ],
);

export type CrossCuttingDriftRecord = typeof crossCuttingDrift.$inferSelect;
export type InsertCrossCuttingDriftRecord = typeof crossCuttingDrift.$inferInsert;

export const crossCuttingOverrides = pgTable(
  "cross_cutting_overrides",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    overrideType: text("override_type").notNull(), // policy_exception, risk_acceptance, suppression
    targetModule: text("target_module").notNull(),
    targetResourceId: text("target_resource_id"),
    targetResourceType: text("target_resource_type"),
    reason: text("reason").notNull(),
    approvedBy: text("approved_by"),
    expiresAt: timestamp("expires_at"),
    status: text("status").notNull().default("active"), // active, expired, revoked
    metadata: jsonb("metadata").default({}),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_cco_org").on(table.orgId),
    index("idx_cco_type").on(table.orgId, table.overrideType),
    index("idx_cco_status").on(table.orgId, table.status),
    index("idx_cco_target").on(table.orgId, table.targetModule, table.targetResourceId),
  ],
);

export type CrossCuttingOverride = typeof crossCuttingOverrides.$inferSelect;
export type InsertCrossCuttingOverride = typeof crossCuttingOverrides.$inferInsert;

// ==========================================
// JIT SECRET ACCESS REQUESTS
// ==========================================

export const jitAccessRequests = pgTable(
  "jit_access_requests",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    requesterId: text("requester_id").notNull(),
    requesterEmail: text("requester_email"),
    secretPath: text("secret_path").notNull(),
    secretProvider: text("secret_provider").notNull(), // aws_secrets_manager, hashicorp_vault, azure_keyvault, gcp_secret_manager
    reason: text("reason").notNull(),
    durationMinutes: integer("duration_minutes").notNull().default(60),
    status: text("status").notNull().default("pending"), // pending, approved, denied, expired, revoked
    approvedBy: text("approved_by"),
    approvedAt: timestamp("approved_at"),
    expiresAt: timestamp("expires_at"),
    revokedAt: timestamp("revoked_at"),
    accessedAt: timestamp("accessed_at"),
    metadata: jsonb("metadata").default({}),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_jar_org").on(table.orgId),
    index("idx_jar_requester").on(table.orgId, table.requesterId),
    index("idx_jar_status").on(table.orgId, table.status),
    index("idx_jar_secret").on(table.orgId, table.secretPath),
  ],
);

export type JitAccessRequest = typeof jitAccessRequests.$inferSelect;
export type InsertJitAccessRequest = typeof jitAccessRequests.$inferInsert;

// ==========================================
// ADVERSARIAL TESTING: EXECUTIONS & SCHEDULES
// ==========================================

export const adversarialTestExecutions = pgTable(
  "adversarial_test_executions",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    testCaseId: text("test_case_id").notNull(),
    testCaseName: text("test_case_name").notNull(),
    domain: text("domain").notNull(), // application, identity, cloud, ai_agent
    category: text("category").notNull(),
    phase: text("phase").notNull().default("pre_production"),
    status: text("status").notNull().default("pending"), // pending, running, passed, failed, error, skipped
    trigger: text("trigger").notNull().default("manual"),
    severity: text("severity").default("medium"),
    result: jsonb("result").default({}),
    duration: integer("duration"),
    startedAt: timestamp("started_at").defaultNow(),
    completedAt: timestamp("completed_at"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_ate_org").on(table.orgId),
    index("idx_ate_status").on(table.orgId, table.status),
    index("idx_ate_domain").on(table.orgId, table.domain),
    index("idx_ate_testcase").on(table.orgId, table.testCaseId),
  ],
);

export type AdversarialTestExecution = typeof adversarialTestExecutions.$inferSelect;
export type InsertAdversarialTestExecution = typeof adversarialTestExecutions.$inferInsert;

export const adversarialTestSchedules = pgTable(
  "adversarial_test_schedules",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    name: text("name").notNull(),
    testCaseIds: text("test_case_ids")
      .array()
      .default(sql`ARRAY[]::text[]`),
    frequency: text("frequency").notNull().default("weekly"), // hourly, daily, weekly, monthly, on_deploy
    enabled: boolean("enabled").notNull().default(true),
    lastRunAt: timestamp("last_run_at"),
    nextRunAt: timestamp("next_run_at"),
    config: jsonb("config").default({}),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [index("idx_ats_org").on(table.orgId), index("idx_ats_enabled").on(table.orgId, table.enabled)],
);

export type AdversarialTestSchedule = typeof adversarialTestSchedules.$inferSelect;
export type InsertAdversarialTestSchedule = typeof adversarialTestSchedules.$inferInsert;

export const adversarialRemediations = pgTable(
  "adversarial_remediations",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    executionId: text("execution_id").notNull(),
    testCaseName: text("test_case_name").notNull(),
    severity: text("severity").notNull().default("medium"),
    status: text("status").notNull().default("open"), // open, in_progress, resolved, wont_fix
    assignee: text("assignee"),
    recommendation: text("recommendation"),
    resolvedAt: timestamp("resolved_at"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [index("idx_ar_org").on(table.orgId), index("idx_ar_status").on(table.orgId, table.status)],
);

export type AdversarialRemediation = typeof adversarialRemediations.$inferSelect;
export type InsertAdversarialRemediation = typeof adversarialRemediations.$inferInsert;

// ==========================================
// AGENT TOOL SECURITY: INVOCATIONS, ANOMALIES, POLICIES, BOUNDARY RULES
// ==========================================

export const agentToolInvocations = pgTable(
  "agent_tool_invocations",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    toolId: text("tool_id").notNull(),
    toolName: text("tool_name").notNull(),
    agentId: text("agent_id").notNull(),
    verdict: text("verdict").notNull().default("allowed"), // allowed, denied, throttled, flagged
    inputHash: text("input_hash"),
    outputSummary: text("output_summary"),
    durationMs: integer("duration_ms"),
    riskScore: real("risk_score").default(0),
    metadata: jsonb("metadata").default({}),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_ati_org").on(table.orgId),
    index("idx_ati_tool").on(table.orgId, table.toolId),
    index("idx_ati_agent").on(table.orgId, table.agentId),
    index("idx_ati_verdict").on(table.orgId, table.verdict),
  ],
);

export type AgentToolInvocation = typeof agentToolInvocations.$inferSelect;
export type InsertAgentToolInvocation = typeof agentToolInvocations.$inferInsert;

export const agentToolAnomalies = pgTable(
  "agent_tool_anomalies",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    toolId: text("tool_id").notNull(),
    agentId: text("agent_id").notNull(),
    anomalyType: text("anomaly_type").notNull(), // unusual_chaining, scope_escalation, rate_spike, destination_drift, payload_anomaly
    severity: text("severity").notNull().default("medium"),
    description: text("description"),
    acknowledged: boolean("acknowledged").notNull().default(false),
    acknowledgedBy: text("acknowledged_by"),
    acknowledgedAt: timestamp("acknowledged_at"),
    metadata: jsonb("metadata").default({}),
    detectedAt: timestamp("detected_at").defaultNow(),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_ata_org").on(table.orgId),
    index("idx_ata_type").on(table.orgId, table.anomalyType),
    index("idx_ata_ack").on(table.orgId, table.acknowledged),
  ],
);

export type AgentToolAnomaly = typeof agentToolAnomalies.$inferSelect;
export type InsertAgentToolAnomaly = typeof agentToolAnomalies.$inferInsert;

export const agentToolPolicies = pgTable(
  "agent_tool_policies",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    toolId: text("tool_id").notNull(),
    maxCallsPerMinute: integer("max_calls_per_minute").default(60),
    maxCallsPerHour: integer("max_calls_per_hour").default(1000),
    requireApprovalAboveRisk: real("require_approval_above_risk").default(0.8),
    allowedAgentIds: text("allowed_agent_ids")
      .array()
      .default(sql`ARRAY[]::text[]`),
    blocked: boolean("blocked").notNull().default(false),
    metadata: jsonb("metadata").default({}),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [index("idx_atp_org").on(table.orgId), index("idx_atp_tool").on(table.orgId, table.toolId)],
);

export type AgentToolPolicy = typeof agentToolPolicies.$inferSelect;
export type InsertAgentToolPolicy = typeof agentToolPolicies.$inferInsert;

export const agentTrustBoundaryRules = pgTable(
  "agent_trust_boundary_rules",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    name: text("name").notNull(),
    sourceBoundary: text("source_boundary").notNull(), // internal, external, privileged, sandboxed
    targetBoundary: text("target_boundary").notNull(),
    action: text("action").notNull().default("deny"), // allow, deny, require_approval
    priority: integer("priority").notNull().default(100),
    enabled: boolean("enabled").notNull().default(true),
    metadata: jsonb("metadata").default({}),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [index("idx_atbr_org").on(table.orgId), index("idx_atbr_source").on(table.orgId, table.sourceBoundary)],
);

export type AgentTrustBoundaryRule = typeof agentTrustBoundaryRules.$inferSelect;
export type InsertAgentTrustBoundaryRule = typeof agentTrustBoundaryRules.$inferInsert;

// ==========================================
// BROWSER DEFENSE: SESSIONS, DOM EVENTS, EGRESS RULES, TRUSTED PATHS
// ==========================================

export const browserDefenseSessions = pgTable(
  "browser_defense_sessions",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    agentId: text("agent_id").notNull(),
    url: text("url").notNull(),
    state: text("state").notNull().default("active"), // active, isolated, terminated, expired
    threatLevel: text("threat_level").default("none"),
    domEventsCount: integer("dom_events_count").default(0),
    egressBlockedCount: integer("egress_blocked_count").default(0),
    metadata: jsonb("metadata").default({}),
    startedAt: timestamp("started_at").defaultNow(),
    endedAt: timestamp("ended_at"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_bds_org").on(table.orgId),
    index("idx_bds_state").on(table.orgId, table.state),
    index("idx_bds_agent").on(table.orgId, table.agentId),
  ],
);

export type BrowserDefenseSession = typeof browserDefenseSessions.$inferSelect;
export type InsertBrowserDefenseSession = typeof browserDefenseSessions.$inferInsert;

export const browserEgressRules = pgTable(
  "browser_egress_rules",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    name: text("name").notNull(),
    domain: text("domain").notNull(),
    protocol: text("protocol").notNull().default("https"),
    direction: text("direction").notNull().default("outbound"),
    verdict: text("verdict").notNull().default("allow"), // allow, block, challenge, log_only
    priority: integer("priority").notNull().default(100),
    enabled: boolean("enabled").notNull().default(true),
    metadata: jsonb("metadata").default({}),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [index("idx_ber_org").on(table.orgId), index("idx_ber_domain").on(table.orgId, table.domain)],
);

export type BrowserEgressRule = typeof browserEgressRules.$inferSelect;
export type InsertBrowserEgressRule = typeof browserEgressRules.$inferInsert;

export const browserTrustedPaths = pgTable(
  "browser_trusted_paths",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    name: text("name").notNull(),
    description: text("description"),
    steps: jsonb("steps").default([]),
    enabled: boolean("enabled").notNull().default(true),
    metadata: jsonb("metadata").default({}),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [index("idx_btp_org").on(table.orgId)],
);

export type BrowserTrustedPath = typeof browserTrustedPaths.$inferSelect;
export type InsertBrowserTrustedPath = typeof browserTrustedPaths.$inferInsert;

// ==========================================
// RUNTIME GUARDRAILS: POLICIES, DECISIONS, OVERRIDES
// ==========================================

export const runtimeGuardrailPolicies = pgTable(
  "runtime_guardrail_policies",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    name: text("name").notNull(),
    description: text("description"),
    action: text("action").notNull(), // ai_agent_invoke, ai_agent_tool_call, api_outbound_call, etc.
    scope: text("scope").notNull().default("global"),
    mode: text("mode").notNull().default("enforce"), // enforce, dry_run, audit_only, disabled
    conditions: jsonb("conditions").default([]),
    priority: integer("priority").notNull().default(100),
    enabled: boolean("enabled").notNull().default(true),
    metadata: jsonb("metadata").default({}),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_rgp_org").on(table.orgId),
    index("idx_rgp_action").on(table.orgId, table.action),
    index("idx_rgp_scope").on(table.orgId, table.scope),
  ],
);

export type RuntimeGuardrailPolicy = typeof runtimeGuardrailPolicies.$inferSelect;
export type InsertRuntimeGuardrailPolicy = typeof runtimeGuardrailPolicies.$inferInsert;

export const runtimeGuardrailDecisions = pgTable(
  "runtime_guardrail_decisions",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    policyId: text("policy_id"),
    policyName: text("policy_name"),
    action: text("action").notNull(),
    verdict: text("verdict").notNull(), // allow, deny, quarantine
    reason: text("reason"),
    actorId: text("actor_id"),
    resourceId: text("resource_id"),
    metadata: jsonb("metadata").default({}),
    evaluatedAt: timestamp("evaluated_at").defaultNow(),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_rgd_org").on(table.orgId),
    index("idx_rgd_verdict").on(table.orgId, table.verdict),
    index("idx_rgd_policy").on(table.orgId, table.policyId),
  ],
);

export type RuntimeGuardrailDecision = typeof runtimeGuardrailDecisions.$inferSelect;
export type InsertRuntimeGuardrailDecision = typeof runtimeGuardrailDecisions.$inferInsert;

export const runtimeGuardrailOverrides = pgTable(
  "runtime_guardrail_overrides",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    policyId: text("policy_id").notNull(),
    requestedBy: text("requested_by").notNull(),
    reason: text("reason").notNull(),
    status: text("status").notNull().default("pending"), // pending, approved, denied, expired
    approvedBy: text("approved_by"),
    approvedAt: timestamp("approved_at"),
    expiresAt: timestamp("expires_at"),
    metadata: jsonb("metadata").default({}),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_rgo_org").on(table.orgId),
    index("idx_rgo_status").on(table.orgId, table.status),
    index("idx_rgo_policy").on(table.orgId, table.policyId),
  ],
);

export type RuntimeGuardrailOverride = typeof runtimeGuardrailOverrides.$inferSelect;
export type InsertRuntimeGuardrailOverride = typeof runtimeGuardrailOverrides.$inferInsert;

// ─── Executive Risk ──────────────────────────────────────────────────────────
export const boardSummaries = pgTable(
  "board_summaries",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    period: text("period").notNull().default("monthly"),
    title: text("title").notNull(),
    executiveSynopsis: text("executive_synopsis"),
    keyFindings: jsonb("key_findings").default([]),
    riskPosture: jsonb("risk_posture").default({}),
    recommendations: jsonb("recommendations").default([]),
    mttr: jsonb("mttr").default({}),
    exploitability: jsonb("exploitability").default({}),
    remediationThroughput: jsonb("remediation_throughput").default({}),
    automationSavings: jsonb("automation_savings").default({}),
    generatedBy: text("generated_by"),
    generatedAt: timestamp("generated_at").defaultNow(),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [index("idx_board_org").on(table.orgId), index("idx_board_period").on(table.orgId, table.period)],
);

export type BoardSummary = typeof boardSummaries.$inferSelect;
export type InsertBoardSummary = typeof boardSummaries.$inferInsert;

export const executiveMetrics = pgTable(
  "executive_metrics",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    name: text("name").notNull(),
    description: text("description"),
    category: text("category").notNull().default("action"),
    value: doublePrecision("value").notNull().default(0),
    unit: text("unit").notNull().default("count"),
    trend: text("trend").notNull().default("stable"),
    changePercent: doublePrecision("change_percent").default(0),
    target: doublePrecision("target"),
    targetMet: boolean("target_met").default(false),
    sparkline: jsonb("sparkline").default([]),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [index("idx_execmetric_org").on(table.orgId), index("idx_execmetric_cat").on(table.orgId, table.category)],
);

export type ExecutiveMetric = typeof executiveMetrics.$inferSelect;
export type InsertExecutiveMetric = typeof executiveMetrics.$inferInsert;

// ─── SOC Copilot ─────────────────────────────────────────────────────────────
export const copilotTriages = pgTable(
  "copilot_triages",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    alertId: text("alert_id"),
    alertTitle: text("alert_title"),
    severity: text("severity").notNull().default("medium"),
    verdict: text("verdict").notNull().default("needs_investigation"),
    confidence: doublePrecision("confidence").default(0),
    reasoning: text("reasoning"),
    suggestedActions: jsonb("suggested_actions").default([]),
    contextSummary: text("context_summary"),
    relatedAlerts: jsonb("related_alerts").default([]),
    analystNotes: text("analyst_notes"),
    status: text("status").notNull().default("pending"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_triage_org").on(table.orgId),
    index("idx_triage_verdict").on(table.orgId, table.verdict),
    index("idx_triage_alert").on(table.orgId, table.alertId),
  ],
);

export type CopilotTriage = typeof copilotTriages.$inferSelect;
export type InsertCopilotTriage = typeof copilotTriages.$inferInsert;

export const copilotActions = pgTable(
  "copilot_actions",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    triageId: text("triage_id"),
    actionClass: text("action_class").notNull().default("SUGGEST"),
    actionType: text("action_type").notNull(),
    description: text("description"),
    target: text("target"),
    parameters: jsonb("parameters").default({}),
    status: text("status").notNull().default("pending_approval"),
    approvedBy: text("approved_by"),
    approvedAt: timestamp("approved_at"),
    executedAt: timestamp("executed_at"),
    result: jsonb("result"),
    rollbackInfo: jsonb("rollback_info"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_copact_org").on(table.orgId),
    index("idx_copact_status").on(table.orgId, table.status),
    index("idx_copact_triage").on(table.orgId, table.triageId),
  ],
);

export type CopilotAction = typeof copilotActions.$inferSelect;
export type InsertCopilotAction = typeof copilotActions.$inferInsert;

export const copilotHypotheses = pgTable(
  "copilot_hypotheses",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    incidentId: text("incident_id"),
    hypothesis: text("hypothesis").notNull(),
    confidence: text("confidence").notNull().default("medium"),
    status: text("status").notNull().default("active"),
    supportingEvidence: jsonb("supporting_evidence").default([]),
    contradictingEvidence: jsonb("contradicting_evidence").default([]),
    suggestedInvestigations: jsonb("suggested_investigations").default([]),
    analystVerdict: text("analyst_verdict"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [index("idx_cophyp_org").on(table.orgId), index("idx_cophyp_status").on(table.orgId, table.status)],
);

export type CopilotHypothesis = typeof copilotHypotheses.$inferSelect;
export type InsertCopilotHypothesis = typeof copilotHypotheses.$inferInsert;

export const copilotFeedback = pgTable(
  "copilot_feedback",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    domain: text("domain").notNull(),
    referenceId: text("reference_id"),
    outcome: text("outcome").notNull(),
    analystId: text("analyst_id"),
    comment: text("comment"),
    metadata: jsonb("metadata").default({}),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [index("idx_copfb_org").on(table.orgId), index("idx_copfb_domain").on(table.orgId, table.domain)],
);

export type CopilotFeedbackRecord = typeof copilotFeedback.$inferSelect;
export type InsertCopilotFeedback = typeof copilotFeedback.$inferInsert;

// ─── Finding Lineage ─────────────────────────────────────────────────────────
export const findingLineageRecords = pgTable(
  "finding_lineage_records",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    title: text("title").notNull(),
    description: text("description"),
    severity: text("severity").notNull().default("medium"),
    source: text("source").notNull(),
    status: text("status").notNull().default("open"),
    riskScore: doublePrecision("risk_score").default(0),
    cweId: text("cwe_id"),
    cveId: text("cve_id"),
    sourceLocation: jsonb("source_location").default({}),
    deployedAsset: jsonb("deployed_asset").default({}),
    owner: jsonb("owner").default({}),
    evidence: jsonb("evidence").default([]),
    remediations: jsonb("remediations").default([]),
    lineage: jsonb("lineage").default([]),
    firstDetectedAt: timestamp("first_detected_at").defaultNow(),
    lastSeenAt: timestamp("last_seen_at").defaultNow(),
    resolvedAt: timestamp("resolved_at"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_flr_org").on(table.orgId),
    index("idx_flr_severity").on(table.orgId, table.severity),
    index("idx_flr_status").on(table.orgId, table.status),
    index("idx_flr_source").on(table.orgId, table.source),
  ],
);

export type FindingLineageRecord = typeof findingLineageRecords.$inferSelect;
export type InsertFindingLineageRecord = typeof findingLineageRecords.$inferInsert;

// ─── Compliance Gap ──────────────────────────────────────────────────────────
export const complianceGapAssessments = pgTable(
  "compliance_gap_assessments",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    frameworkId: text("framework_id").notNull(),
    frameworkName: text("framework_name"),
    controlId: text("control_id").notNull(),
    controlName: text("control_name"),
    category: text("category"),
    status: text("status").notNull().default("missing"),
    evidence: jsonb("evidence").default([]),
    remediationPriority: text("remediation_priority").default("medium"),
    estimatedEffort: text("estimated_effort"),
    description: text("description"),
    assessedBy: text("assessed_by"),
    assessedAt: timestamp("assessed_at").defaultNow(),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_cga_org").on(table.orgId),
    index("idx_cga_framework").on(table.orgId, table.frameworkId),
    index("idx_cga_status").on(table.orgId, table.status),
  ],
);

export type ComplianceGapAssessment = typeof complianceGapAssessments.$inferSelect;
export type InsertComplianceGapAssessment = typeof complianceGapAssessments.$inferInsert;

// ─── Vulnerability Scanner (Scans — vulnFindings already defined above) ──────
export const vulnScans = pgTable(
  "vuln_scans",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    name: text("name").notNull(),
    scanType: text("scan_type").notNull().default("full"),
    targets: jsonb("targets").default([]),
    status: text("status").notNull().default("pending"),
    progress: integer("progress").default(0),
    findingsCount: integer("findings_count").default(0),
    criticalCount: integer("critical_count").default(0),
    highCount: integer("high_count").default(0),
    mediumCount: integer("medium_count").default(0),
    lowCount: integer("low_count").default(0),
    startedAt: timestamp("started_at"),
    completedAt: timestamp("completed_at"),
    scheduledBy: text("scheduled_by"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [index("idx_vscan_org").on(table.orgId), index("idx_vscan_status").on(table.orgId, table.status)],
);

export type VulnScan = typeof vulnScans.$inferSelect;
export type InsertVulnScan = typeof vulnScans.$inferInsert;

// ─── Identity Governance ─────────────────────────────────────────────────────
export const accessReviews = pgTable(
  "access_reviews",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    name: text("name").notNull(),
    description: text("description"),
    reviewType: text("review_type").notNull().default("periodic"),
    scope: text("scope"),
    status: text("status").notNull().default("pending"),
    reviewerId: text("reviewer_id"),
    reviewerName: text("reviewer_name"),
    totalEntitlements: integer("total_entitlements").default(0),
    reviewedCount: integer("reviewed_count").default(0),
    approvedCount: integer("approved_count").default(0),
    revokedCount: integer("revoked_count").default(0),
    dueDate: timestamp("due_date"),
    completedAt: timestamp("completed_at"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [index("idx_accessrev_org").on(table.orgId), index("idx_accessrev_status").on(table.orgId, table.status)],
);

export type AccessReview = typeof accessReviews.$inferSelect;
export type InsertAccessReview = typeof accessReviews.$inferInsert;

export const identityEntitlements = pgTable(
  "identity_entitlements",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    userId: text("user_id").notNull(),
    userName: text("user_name"),
    resourceType: text("resource_type").notNull(),
    resourceName: text("resource_name").notNull(),
    accessLevel: text("access_level").notNull(),
    riskLevel: text("risk_level").default("low"),
    lastUsedAt: timestamp("last_used_at"),
    grantedAt: timestamp("granted_at").defaultNow(),
    expiresAt: timestamp("expires_at"),
    status: text("status").notNull().default("active"),
    reviewId: text("review_id"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_ident_org").on(table.orgId),
    index("idx_ident_user").on(table.orgId, table.userId),
    index("idx_ident_review").on(table.orgId, table.reviewId),
  ],
);

export type IdentityEntitlement = typeof identityEntitlements.$inferSelect;
export type InsertIdentityEntitlement = typeof identityEntitlements.$inferInsert;

// ─── TPRM (Third-Party Risk Management) ─────────────────────────────────────
export const tprmVendors = pgTable(
  "tprm_vendors",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    name: text("name").notNull(),
    description: text("description"),
    category: text("category"),
    tier: text("tier").notNull().default("standard"),
    riskRating: text("risk_rating").default("medium"),
    overallScore: doublePrecision("overall_score").default(0),
    securityScore: doublePrecision("security_score").default(0),
    complianceScore: doublePrecision("compliance_score").default(0),
    dataAccess: jsonb("data_access").default([]),
    integrations: jsonb("integrations").default([]),
    contactName: text("contact_name"),
    contactEmail: text("contact_email"),
    contractExpiry: timestamp("contract_expiry"),
    lastAssessedAt: timestamp("last_assessed_at"),
    status: text("status").notNull().default("active"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_tprm_org").on(table.orgId),
    index("idx_tprm_tier").on(table.orgId, table.tier),
    index("idx_tprm_risk").on(table.orgId, table.riskRating),
  ],
);

export type TprmVendor = typeof tprmVendors.$inferSelect;
export type InsertTprmVendor = typeof tprmVendors.$inferInsert;

export const tprmAssessments = pgTable(
  "tprm_assessments",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    vendorId: text("vendor_id").notNull(),
    assessmentType: text("assessment_type").notNull().default("security"),
    status: text("status").notNull().default("pending"),
    score: doublePrecision("score").default(0),
    findings: jsonb("findings").default([]),
    questionnaire: jsonb("questionnaire").default({}),
    assessorId: text("assessor_id"),
    dueDate: timestamp("due_date"),
    completedAt: timestamp("completed_at"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_tprma_org").on(table.orgId),
    index("idx_tprma_vendor").on(table.orgId, table.vendorId),
    index("idx_tprma_status").on(table.orgId, table.status),
  ],
);

export type TprmAssessment = typeof tprmAssessments.$inferSelect;
export type InsertTprmAssessment = typeof tprmAssessments.$inferInsert;

// ─── Deception Technology ────────────────────────────────────────────────────
export const deceptionAssets = pgTable(
  "deception_assets",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    name: text("name").notNull(),
    assetType: text("asset_type").notNull(),
    decoyType: text("decoy_type"),
    network: text("network"),
    ipAddress: text("ip_address"),
    status: text("status").notNull().default("active"),
    interactions: integer("interactions").default(0),
    lastInteractionAt: timestamp("last_interaction_at"),
    config: jsonb("config").default({}),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_decep_org").on(table.orgId),
    index("idx_decep_type").on(table.orgId, table.assetType),
    index("idx_decep_status").on(table.orgId, table.status),
  ],
);

export type DeceptionAsset = typeof deceptionAssets.$inferSelect;
export type InsertDeceptionAsset = typeof deceptionAssets.$inferInsert;

export const deceptionInteractions = pgTable(
  "deception_interactions",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    assetId: text("asset_id").notNull(),
    sourceIp: text("source_ip"),
    sourceHostname: text("source_hostname"),
    interactionType: text("interaction_type").notNull(),
    protocol: text("protocol"),
    details: jsonb("details").default({}),
    severity: text("severity").default("medium"),
    attackStage: text("attack_stage"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [index("idx_decepint_org").on(table.orgId), index("idx_decepint_asset").on(table.orgId, table.assetId)],
);

export type DeceptionInteraction = typeof deceptionInteractions.$inferSelect;
export type InsertDeceptionInteraction = typeof deceptionInteractions.$inferInsert;

// ─── Email Security ──────────────────────────────────────────────────────────
export const emailSecurityEvents = pgTable(
  "email_security_events",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    direction: text("direction").notNull().default("inbound"),
    sender: text("sender"),
    recipient: text("recipient"),
    subject: text("subject"),
    verdict: text("verdict").notNull().default("clean"),
    threatType: text("threat_type"),
    confidence: doublePrecision("confidence").default(0),
    quarantined: boolean("quarantined").default(false),
    details: jsonb("details").default({}),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [index("idx_emailsec_org").on(table.orgId), index("idx_emailsec_verdict").on(table.orgId, table.verdict)],
);

export type EmailSecurityEvent = typeof emailSecurityEvents.$inferSelect;
export type InsertEmailSecurityEvent = typeof emailSecurityEvents.$inferInsert;

// ─── DNS Security ────────────────────────────────────────────────────────────
export const dnsSecurityEvents = pgTable(
  "dns_security_events",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    queryDomain: text("query_domain").notNull(),
    queryType: text("query_type"),
    sourceIp: text("source_ip"),
    verdict: text("verdict").notNull().default("allowed"),
    threatCategory: text("threat_category"),
    blocked: boolean("blocked").default(false),
    policyId: text("policy_id"),
    details: jsonb("details").default({}),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [index("idx_dnssec_org").on(table.orgId), index("idx_dnssec_verdict").on(table.orgId, table.verdict)],
);

export type DnsSecurityEvent = typeof dnsSecurityEvents.$inferSelect;
export type InsertDnsSecurityEvent = typeof dnsSecurityEvents.$inferInsert;

export const dnsSecurityPolicies = pgTable(
  "dns_security_policies",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    name: text("name").notNull(),
    description: text("description"),
    action: text("action").notNull().default("block"),
    categories: jsonb("categories").default([]),
    customDomains: jsonb("custom_domains").default([]),
    enabled: boolean("enabled").default(true),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [index("idx_dnspol_org").on(table.orgId)],
);

export type DnsSecurityPolicy = typeof dnsSecurityPolicies.$inferSelect;
export type InsertDnsSecurityPolicy = typeof dnsSecurityPolicies.$inferInsert;

// ─── API Security ────────────────────────────────────────────────────────────
export const apiSecurityEndpoints = pgTable(
  "api_security_endpoints",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    method: text("method").notNull(),
    path: text("path").notNull(),
    serviceName: text("service_name"),
    authType: text("auth_type"),
    riskScore: doublePrecision("risk_score").default(0),
    sensitiveDataExposed: boolean("sensitive_data_exposed").default(false),
    lastCalledAt: timestamp("last_called_at"),
    totalCalls: integer("total_calls").default(0),
    errorRate: doublePrecision("error_rate").default(0),
    avgLatencyMs: doublePrecision("avg_latency_ms").default(0),
    status: text("status").notNull().default("active"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [index("idx_apisec_org").on(table.orgId), index("idx_apisec_risk").on(table.orgId, table.riskScore)],
);

export type ApiSecurityEndpoint = typeof apiSecurityEndpoints.$inferSelect;
export type InsertApiSecurityEndpoint = typeof apiSecurityEndpoints.$inferInsert;

export const apiSecurityThreats = pgTable(
  "api_security_threats",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    endpointId: text("endpoint_id"),
    threatType: text("threat_type").notNull(),
    severity: text("severity").notNull().default("medium"),
    sourceIp: text("source_ip"),
    description: text("description"),
    blocked: boolean("blocked").default(false),
    details: jsonb("details").default({}),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_apithreat_org").on(table.orgId),
    index("idx_apithreat_severity").on(table.orgId, table.severity),
  ],
);

export type ApiSecurityThreat = typeof apiSecurityThreats.$inferSelect;
export type InsertApiSecurityThreat = typeof apiSecurityThreats.$inferInsert;

// ─── Supply Chain Security ───────────────────────────────────────────────────
export const supplyChainComponents = pgTable(
  "supply_chain_components",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    name: text("name").notNull(),
    version: text("version"),
    componentType: text("component_type").notNull(),
    ecosystem: text("ecosystem"),
    license: text("license"),
    riskScore: doublePrecision("risk_score").default(0),
    vulnerabilities: integer("vulnerabilities").default(0),
    directDependency: boolean("direct_dependency").default(true),
    maintainerScore: doublePrecision("maintainer_score").default(0),
    lastUpdatedUpstream: timestamp("last_updated_upstream"),
    status: text("status").notNull().default("monitored"),
    metadata: jsonb("metadata").default({}),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_scc_org").on(table.orgId),
    index("idx_scc_type").on(table.orgId, table.componentType),
    index("idx_scc_risk").on(table.orgId, table.riskScore),
  ],
);

export type SupplyChainComponent = typeof supplyChainComponents.$inferSelect;
export type InsertSupplyChainComponent = typeof supplyChainComponents.$inferInsert;

// ─── Ransomware Defense ──────────────────────────────────────────────────────
export const ransomwareIndicators = pgTable(
  "ransomware_indicators",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    indicatorType: text("indicator_type").notNull(),
    value: text("value").notNull(),
    threatFamily: text("threat_family"),
    confidence: doublePrecision("confidence").default(0),
    severity: text("severity").notNull().default("high"),
    source: text("source"),
    status: text("status").notNull().default("active"),
    details: jsonb("details").default({}),
    firstSeenAt: timestamp("first_seen_at").defaultNow(),
    lastSeenAt: timestamp("last_seen_at").defaultNow(),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_ransom_org").on(table.orgId),
    index("idx_ransom_type").on(table.orgId, table.indicatorType),
    index("idx_ransom_family").on(table.orgId, table.threatFamily),
  ],
);

export type RansomwareIndicator = typeof ransomwareIndicators.$inferSelect;
export type InsertRansomwareIndicator = typeof ransomwareIndicators.$inferInsert;

// ─── Community Intel ─────────────────────────────────────────────────────────
export const communityIntelFeeds = pgTable(
  "community_intel_feeds",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    name: text("name").notNull(),
    feedType: text("feed_type").notNull(),
    source: text("source"),
    description: text("description"),
    enabled: boolean("enabled").default(true),
    lastSyncAt: timestamp("last_sync_at"),
    indicatorCount: integer("indicator_count").default(0),
    reliability: doublePrecision("reliability").default(0),
    config: jsonb("config").default({}),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [index("idx_cif_org").on(table.orgId), index("idx_cif_type").on(table.orgId, table.feedType)],
);

export type CommunityIntelFeed = typeof communityIntelFeeds.$inferSelect;
export type InsertCommunityIntelFeed = typeof communityIntelFeeds.$inferInsert;

export const communityIntelIndicators = pgTable(
  "community_intel_indicators",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    feedId: text("feed_id"),
    indicatorType: text("indicator_type").notNull(),
    value: text("value").notNull(),
    threatType: text("threat_type"),
    confidence: doublePrecision("confidence").default(0),
    severity: text("severity").default("medium"),
    tags: jsonb("tags").default([]),
    firstSeenAt: timestamp("first_seen_at").defaultNow(),
    lastSeenAt: timestamp("last_seen_at").defaultNow(),
    expiresAt: timestamp("expires_at"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_cii_org").on(table.orgId),
    index("idx_cii_feed").on(table.orgId, table.feedId),
    index("idx_cii_type").on(table.orgId, table.indicatorType),
  ],
);

export type CommunityIntelIndicator = typeof communityIntelIndicators.$inferSelect;
export type InsertCommunityIntelIndicator = typeof communityIntelIndicators.$inferInsert;

// ─── Security Awareness ──────────────────────────────────────────────────────
export const awarenessPrograms = pgTable(
  "awareness_programs",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    name: text("name").notNull(),
    description: text("description"),
    programType: text("program_type").notNull().default("training"),
    status: text("status").notNull().default("active"),
    targetAudience: jsonb("target_audience").default([]),
    completionRate: doublePrecision("completion_rate").default(0),
    participantCount: integer("participant_count").default(0),
    passRate: doublePrecision("pass_rate").default(0),
    startDate: timestamp("start_date"),
    endDate: timestamp("end_date"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [index("idx_awprog_org").on(table.orgId), index("idx_awprog_type").on(table.orgId, table.programType)],
);

export type AwarenessProgram = typeof awarenessPrograms.$inferSelect;
export type InsertAwarenessProgram = typeof awarenessPrograms.$inferInsert;

export const phishingSimulations = pgTable(
  "phishing_simulations",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    campaignName: text("campaign_name").notNull(),
    templateType: text("template_type"),
    status: text("status").notNull().default("draft"),
    sentCount: integer("sent_count").default(0),
    openedCount: integer("opened_count").default(0),
    clickedCount: integer("clicked_count").default(0),
    reportedCount: integer("reported_count").default(0),
    submittedCredentials: integer("submitted_credentials").default(0),
    launchedAt: timestamp("launched_at"),
    completedAt: timestamp("completed_at"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [index("idx_phishsim_org").on(table.orgId), index("idx_phishsim_status").on(table.orgId, table.status)],
);

export type PhishingSimulation = typeof phishingSimulations.$inferSelect;
export type InsertPhishingSimulation = typeof phishingSimulations.$inferInsert;

// ─── Prompt-to-Artifact Investigations ───────────────────────────────────────
export const promptInvestigations = pgTable(
  "prompt_investigations",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    prompt: text("prompt").notNull(),
    intent: text("intent").notNull().default(""),
    status: text("status").notNull().default("pending"),
    summary: text("summary"),
    steps: jsonb("steps").default([]),
    artifacts: jsonb("artifacts").default([]),
    citations: jsonb("citations").default([]),
    createdAt: timestamp("created_at").defaultNow(),
    completedAt: timestamp("completed_at"),
  },
  (table) => [index("idx_promptinv_org").on(table.orgId), index("idx_promptinv_status").on(table.orgId, table.status)],
);

export type PromptInvestigation = typeof promptInvestigations.$inferSelect;
export type InsertPromptInvestigation = typeof promptInvestigations.$inferInsert;

// ─── Prompt History ──────────────────────────────────────────────────────────
export const promptHistory = pgTable(
  "prompt_history",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    prompt: text("prompt").notNull(),
    artifactType: text("artifact_type").notNull(),
    isFavorite: boolean("is_favorite").default(false),
    sharedWith: jsonb("shared_with").default([]),
    usedAt: timestamp("used_at").defaultNow(),
    resultId: text("result_id"),
  },
  (table) => [
    index("idx_prompthist_org").on(table.orgId),
    index("idx_prompthist_fav").on(table.orgId, table.isFavorite),
  ],
);

export type PromptHistoryEntry = typeof promptHistory.$inferSelect;
export type InsertPromptHistoryEntry = typeof promptHistory.$inferInsert;

// ─── Artifact Approvals ──────────────────────────────────────────────────────
export const artifactApprovals = pgTable(
  "artifact_approvals",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    artifactId: text("artifact_id").notNull(),
    investigationId: text("investigation_id").notNull(),
    reason: text("reason").notNull(),
    requiredRole: text("required_role").notNull().default("admin"),
    status: text("status").notNull().default("pending_approval"),
    requestedBy: text("requested_by").notNull(),
    requestedAt: timestamp("requested_at").defaultNow(),
    reviewedBy: text("reviewed_by"),
    reviewedAt: timestamp("reviewed_at"),
    reviewNotes: text("review_notes"),
  },
  (table) => [index("idx_artappr_org").on(table.orgId), index("idx_artappr_status").on(table.orgId, table.status)],
);

export type ArtifactApproval = typeof artifactApprovals.$inferSelect;
export type InsertArtifactApproval = typeof artifactApprovals.$inferInsert;

// ─── Artifact Deployments ────────────────────────────────────────────────────
export const artifactDeployments = pgTable(
  "artifact_deployments",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    artifactId: text("artifact_id").notNull(),
    investigationId: text("investigation_id").notNull(),
    artifactType: text("artifact_type").notNull(),
    targetPage: text("target_page").notNull(),
    status: text("status").notNull().default("pending"),
    deployedAt: timestamp("deployed_at").defaultNow(),
    rolledBackAt: timestamp("rolled_back_at"),
    deployedBy: text("deployed_by").notNull(),
    snapshotContent: jsonb("snapshot_content").default({}),
  },
  (table) => [index("idx_artdeploy_org").on(table.orgId), index("idx_artdeploy_status").on(table.orgId, table.status)],
);

export type ArtifactDeployment = typeof artifactDeployments.$inferSelect;
export type InsertArtifactDeployment = typeof artifactDeployments.$inferInsert;

// ─── Remediation Fixes ───────────────────────────────────────────────────────
export const remediationFixes = pgTable(
  "remediation_fixes",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    type: text("type").notNull(),
    title: text("title").notNull(),
    description: text("description").notNull(),
    priority: text("priority").notNull().default("medium"),
    status: text("status").notNull().default("suggested"),
    finding: jsonb("finding").default({}),
    codeChange: jsonb("code_change"),
    ownerId: text("owner_id"),
    estimatedEffort: text("estimated_effort"),
    mitreTactics: jsonb("mitre_tactics").default([]),
    cweIds: jsonb("cwe_ids").default([]),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_remfix_org").on(table.orgId),
    index("idx_remfix_status").on(table.orgId, table.status),
    index("idx_remfix_priority").on(table.orgId, table.priority),
  ],
);

export type RemediationFix = typeof remediationFixes.$inferSelect;
export type InsertRemediationFix = typeof remediationFixes.$inferInsert;

// ─── Code Owners ─────────────────────────────────────────────────────────────
export const codeOwners = pgTable(
  "code_owners",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    name: text("name").notNull(),
    email: text("email").notNull(),
    team: text("team").notNull(),
    filesOwned: jsonb("files_owned").default([]),
    reviewCount: integer("review_count").default(0),
    lastActive: timestamp("last_active").defaultNow(),
  },
  (table) => [index("idx_codeown_org").on(table.orgId)],
);

export type CodeOwner = typeof codeOwners.$inferSelect;
export type InsertCodeOwner = typeof codeOwners.$inferInsert;

// ─── Tenant Data Export/Deletion Jobs ────────────────────────────────────────
export const tenantDataJobs = pgTable(
  "tenant_data_jobs",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    jobType: text("job_type").notNull(), // 'export' | 'deletion'
    status: text("status").notNull().default("pending"),
    format: text("format"),
    scope: jsonb("scope").default({}),
    progress: integer("progress").default(0),
    totalRecords: integer("total_records").default(0),
    processedRecords: integer("processed_records").default(0),
    downloadUrl: text("download_url"),
    error: text("error"),
    requestedBy: text("requested_by"),
    createdAt: timestamp("created_at").defaultNow(),
    completedAt: timestamp("completed_at"),
  },
  (table) => [
    index("idx_tdj_org").on(table.orgId),
    index("idx_tdj_type").on(table.orgId, table.jobType),
    index("idx_tdj_status").on(table.orgId, table.status),
  ],
);

export type TenantDataJob = typeof tenantDataJobs.$inferSelect;
export type InsertTenantDataJob = typeof tenantDataJobs.$inferInsert;

// ─── Endpoint Scan Schedules ─────────────────────────────────────────────────
export const endpointScanSchedules = pgTable(
  "endpoint_scan_schedules",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    assetId: text("asset_id").notNull(),
    scanType: text("scan_type").notNull(),
    cronExpression: text("cron_expression"),
    enabled: boolean("enabled").default(true),
    lastRunAt: timestamp("last_run_at"),
    nextRunAt: timestamp("next_run_at"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [index("idx_epss_org").on(table.orgId), index("idx_epss_asset").on(table.orgId, table.assetId)],
);

export type EndpointScanSchedule = typeof endpointScanSchedules.$inferSelect;
export type InsertEndpointScanSchedule = typeof endpointScanSchedules.$inferInsert;

// ─── Endpoint Heartbeats ─────────────────────────────────────────────────────
export const endpointHeartbeats = pgTable(
  "endpoint_heartbeats",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    assetId: text("asset_id").notNull(),
    lastHeartbeat: timestamp("last_heartbeat").defaultNow(),
    status: text("status").notNull().default("online"),
    metadata: jsonb("metadata").default({}),
  },
  (table) => [index("idx_ephb_org").on(table.orgId), index("idx_ephb_asset").on(table.orgId, table.assetId)],
);

export type EndpointHeartbeat = typeof endpointHeartbeats.$inferSelect;
export type InsertEndpointHeartbeat = typeof endpointHeartbeats.$inferInsert;

// ─── Playbook Template Catalog ───────────────────────────────────────────────
export const playbookTemplateCatalog = pgTable(
  "playbook_template_catalog",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id"),
    name: text("name").notNull(),
    description: text("description").notNull(),
    category: text("category").notNull(),
    severity: text("severity").notNull().default("medium"),
    steps: jsonb("steps").default([]),
    tags: jsonb("tags").default([]),
    author: text("author"),
    version: text("version").default("1.0.0"),
    isBuiltIn: boolean("is_built_in").default(false),
    usageCount: integer("usage_count").default(0),
    rating: real("rating").default(0),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [index("idx_pbtc_org").on(table.orgId), index("idx_pbtc_cat").on(table.category)],
);

export type PlaybookTemplateCatalogEntry = typeof playbookTemplateCatalog.$inferSelect;
export type InsertPlaybookTemplateCatalogEntry = typeof playbookTemplateCatalog.$inferInsert;

// ─── Graph Snapshots ─────────────────────────────────────────────────────────
export const graphSnapshots = pgTable(
  "graph_snapshots",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    name: text("name").notNull(),
    description: text("description"),
    graphData: jsonb("graph_data").default({}),
    nodeCount: integer("node_count").default(0),
    edgeCount: integer("edge_count").default(0),
    createdBy: text("created_by"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [index("idx_graphsnap_org").on(table.orgId)],
);

export type GraphSnapshot = typeof graphSnapshots.$inferSelect;
export type InsertGraphSnapshot = typeof graphSnapshots.$inferInsert;

// ─── CSPM Remediation Safety Records ─────────────────────────────────────────
export const cspmRemediationSafetyRecords = pgTable(
  "cspm_remediation_safety_records",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    accountId: text("account_id").notNull(),
    findingId: text("finding_id"),
    playbookId: text("playbook_id").notNull(),
    resourceId: text("resource_id").notNull(),
    mode: text("mode").notNull().default("dry_run"),
    dryRunResult: jsonb("dry_run_result").default({}),
    approvedBy: text("approved_by"),
    approvedAt: timestamp("approved_at"),
    executedAt: timestamp("executed_at"),
    rollbackAvailable: boolean("rollback_available").default(true),
    rollbackExecutedAt: timestamp("rollback_executed_at"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [index("idx_cspmrem_org").on(table.orgId), index("idx_cspmrem_mode").on(table.orgId, table.mode)],
);

export type CspmRemediationSafetyRecord = typeof cspmRemediationSafetyRecords.$inferSelect;
export type InsertCspmRemediationSafetyRecord = typeof cspmRemediationSafetyRecords.$inferInsert;

// ─── Endpoint Groups ─────────────────────────────────────────────────────────
export const endpointGroups = pgTable(
  "endpoint_groups",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    name: text("name").notNull(),
    groupBy: text("group_by").notNull(),
    criteria: jsonb("criteria").default({}),
    policies: jsonb("policies").default([]),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [index("idx_epgrp_org").on(table.orgId)],
);

export type EndpointGroup = typeof endpointGroups.$inferSelect;
export type InsertEndpointGroup = typeof endpointGroups.$inferInsert;

// ─── Prompt A/B Tests ─────────────────────────────────────────────────────────
export const promptAbTests = pgTable(
  "prompt_ab_tests",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    promptId: varchar("prompt_id").notNull(),
    versionA: integer("version_a").notNull(),
    versionB: integer("version_b").notNull(),
    status: varchar("status", { length: 20 }).notNull().default("running"),
    sampleSize: integer("sample_size").notNull().default(100),
    results: jsonb("results").default({}),
    startedAt: timestamp("started_at").defaultNow(),
    completedAt: timestamp("completed_at"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [index("idx_prompt_ab_org").on(table.orgId), index("idx_prompt_ab_prompt").on(table.promptId)],
);

export type PromptAbTest = typeof promptAbTests.$inferSelect;
export type InsertPromptAbTest = typeof promptAbTests.$inferInsert;

// ─── Prompt Quality Scores ──────────────────────────────────────────────────
export const promptQualityScores = pgTable(
  "prompt_quality_scores",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    promptId: varchar("prompt_id").notNull(),
    version: integer("version").notNull().default(1),
    relevance: integer("relevance").notNull(),
    accuracy: integer("accuracy").notNull(),
    actionability: integer("actionability").notNull(),
    formatCompliance: integer("format_compliance").notNull(),
    overall: integer("overall").notNull(),
    sampleOutput: text("sample_output").default(""),
    evaluatedAt: timestamp("evaluated_at").defaultNow(),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [index("idx_prompt_qs_org").on(table.orgId), index("idx_prompt_qs_prompt").on(table.promptId)],
);

export type PromptQualityScore = typeof promptQualityScores.$inferSelect;
export type InsertPromptQualityScore = typeof promptQualityScores.$inferInsert;

// ─── Cross-Cutting Kill Switches ────────────────────────────────────────────
export const crossCuttingKillSwitches = pgTable(
  "cross_cutting_kill_switches",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    featureName: text("feature_name").notNull(),
    engineName: text("engine_name").notNull(),
    state: varchar("state", { length: 20 }).notNull().default("armed"),
    confidenceThreshold: integer("confidence_threshold").notNull().default(70),
    currentConfidence: integer("current_confidence").notNull().default(100),
    lastTriggeredAt: timestamp("last_triggered_at"),
    triggeredBy: text("triggered_by"),
    triggerReason: text("trigger_reason"),
    rollbackInstructions: text("rollback_instructions").notNull().default(""),
    updatedAt: timestamp("updated_at").defaultNow(),
    updatedBy: text("updated_by").notNull().default("system"),
  },
  (table) => [index("idx_cc_ks_org").on(table.orgId), index("idx_cc_ks_feature").on(table.orgId, table.featureName)],
);

export type CrossCuttingKillSwitch = typeof crossCuttingKillSwitches.$inferSelect;
export type InsertCrossCuttingKillSwitch = typeof crossCuttingKillSwitches.$inferInsert;

// ─── Time-to-Value Milestones ───────────────────────────────────────────────
export const ttvMilestones = pgTable(
  "ttv_milestones",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    kind: varchar("kind", { length: 50 }).notNull(),
    label: text("label").notNull(),
    achievedAt: timestamp("achieved_at"),
    durationFromSignupMs: integer("duration_from_signup_ms"),
    triggeredByAction: text("triggered_by_action"),
    triggeredByActor: text("triggered_by_actor"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [index("idx_ttv_org").on(table.orgId), index("idx_ttv_kind").on(table.orgId, table.kind)],
);

export type TtvMilestone = typeof ttvMilestones.$inferSelect;
export type InsertTtvMilestone = typeof ttvMilestones.$inferInsert;

// ─── JIT Managed Secrets ────────────────────────────────────────────────────
export const jitManagedSecrets = pgTable(
  "jit_managed_secrets",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    name: text("name").notNull(),
    description: text("description").notNull().default(""),
    secretType: varchar("secret_type", { length: 30 }).notNull(),
    classification: varchar("classification", { length: 20 }).notNull().default("internal"),
    ownerId: varchar("owner_id").notNull(),
    ownerName: text("owner_name").notNull(),
    environment: varchar("environment", { length: 30 }).notNull().default("production"),
    service: text("service").notNull().default(""),
    lastRotatedAt: timestamp("last_rotated_at").defaultNow(),
    rotationIntervalDays: integer("rotation_interval_days").notNull().default(90),
    needsRotation: boolean("needs_rotation").notNull().default(false),
    noPlaintextSharing: boolean("no_plaintext_sharing").notNull().default(true),
    accessCount: integer("access_count").notNull().default(0),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [index("idx_jit_ms_org").on(table.orgId), index("idx_jit_ms_owner").on(table.orgId, table.ownerId)],
);

export type JitManagedSecret = typeof jitManagedSecrets.$inferSelect;
export type InsertJitManagedSecret = typeof jitManagedSecrets.$inferInsert;

// ─── JIT Secret Access Requests (V2 — engine-backed) ────────────────────────
export const jitSecretAccessRequests = pgTable(
  "jit_secret_access_requests",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    secretId: varchar("secret_id").notNull(),
    secretName: text("secret_name").notNull(),
    requesterId: varchar("requester_id").notNull(),
    requesterName: text("requester_name").notNull(),
    reason: text("reason").notNull(),
    durationMinutes: integer("duration_minutes").notNull().default(60),
    status: varchar("status", { length: 20 }).notNull().default("pending"),
    approverRole: varchar("approver_role", { length: 20 }).notNull().default("owner"),
    approvedBy: text("approved_by"),
    approvedAt: timestamp("approved_at"),
    deniedBy: text("denied_by"),
    deniedAt: timestamp("denied_at"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [index("idx_jit_sar_org").on(table.orgId), index("idx_jit_sar_secret").on(table.orgId, table.secretId)],
);

export type JitSecretAccessRequest = typeof jitSecretAccessRequests.$inferSelect;
export type InsertJitSecretAccessRequest = typeof jitSecretAccessRequests.$inferInsert;

// ─── JIT External Shares ────────────────────────────────────────────────────
export const jitExternalShares = pgTable(
  "jit_external_shares",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    secretId: varchar("secret_id").notNull(),
    secretName: text("secret_name").notNull(),
    createdBy: text("created_by").notNull(),
    recipientEmail: text("recipient_email").notNull(),
    shareToken: text("share_token").notNull(),
    expiresAt: timestamp("expires_at").notNull(),
    maxUses: integer("max_uses").notNull().default(1),
    currentUses: integer("current_uses").notNull().default(0),
    status: varchar("status", { length: 20 }).notNull().default("active"),
    noPlaintext: boolean("no_plaintext").notNull().default(true),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [index("idx_jit_es_org").on(table.orgId), index("idx_jit_es_token").on(table.shareToken)],
);

export type JitExternalShare = typeof jitExternalShares.$inferSelect;
export type InsertJitExternalShare = typeof jitExternalShares.$inferInsert;

// ─── JIT Ownership Transfers ────────────────────────────────────────────────
export const jitOwnershipTransfers = pgTable(
  "jit_ownership_transfers",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    secretId: varchar("secret_id").notNull(),
    secretName: text("secret_name").notNull(),
    fromOwnerId: varchar("from_owner_id").notNull(),
    fromOwnerName: text("from_owner_name").notNull(),
    toOwnerId: varchar("to_owner_id").notNull(),
    toOwnerName: text("to_owner_name").notNull(),
    action: varchar("action", { length: 30 }).notNull(),
    reason: text("reason").notNull(),
    isOffboarding: boolean("is_offboarding").notNull().default(false),
    initiatedBy: text("initiated_by").notNull(),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [index("idx_jit_ot_org").on(table.orgId)],
);

export type JitOwnershipTransfer = typeof jitOwnershipTransfers.$inferSelect;
export type InsertJitOwnershipTransfer = typeof jitOwnershipTransfers.$inferInsert;

// ─── JIT Break Glass Access ─────────────────────────────────────────────────
export const jitBreakGlassAccess = pgTable(
  "jit_break_glass_access",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    secretId: varchar("secret_id").notNull(),
    secretName: text("secret_name").notNull(),
    requesterId: varchar("requester_id").notNull(),
    requesterName: text("requester_name").notNull(),
    justification: text("justification").notNull(),
    incidentId: varchar("incident_id"),
    status: varchar("status", { length: 20 }).notNull().default("active"),
    ephemeralToken: text("ephemeral_token").notNull(),
    expiresAt: timestamp("expires_at").notNull(),
    durationMinutes: integer("duration_minutes").notNull().default(60),
    reviewedBy: text("reviewed_by"),
    reviewedAt: timestamp("reviewed_at"),
    reviewNotes: text("review_notes"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [index("idx_jit_bg_org").on(table.orgId)],
);

export type JitBreakGlassAccessEntry = typeof jitBreakGlassAccess.$inferSelect;
export type InsertJitBreakGlassAccessEntry = typeof jitBreakGlassAccess.$inferInsert;

// ─── JIT Audit Log ──────────────────────────────────────────────────────────
export const jitAuditLog = pgTable(
  "jit_audit_log",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    action: text("action").notNull(),
    actor: text("actor").notNull(),
    details: text("details"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [index("idx_jit_al_org").on(table.orgId)],
);

export type JitAuditLogEntry = typeof jitAuditLog.$inferSelect;
export type InsertJitAuditLogEntry = typeof jitAuditLog.$inferInsert;

// ─── Browser DOM Events ─────────────────────────────────────────────────────
export const browserDomEvents = pgTable(
  "browser_dom_events",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    sessionId: varchar("session_id").notNull(),
    eventType: varchar("event_type", { length: 30 }).notNull(),
    target: text("target").notNull(),
    severity: varchar("severity", { length: 20 }).notNull().default("info"),
    verdict: varchar("verdict", { length: 20 }).notNull().default("allow"),
    details: jsonb("details").default({}),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [index("idx_bde_org").on(table.orgId), index("idx_bde_session").on(table.orgId, table.sessionId)],
);

export type BrowserDomEvent = typeof browserDomEvents.$inferSelect;
export type InsertBrowserDomEvent = typeof browserDomEvents.$inferInsert;

// ─── Browser Injection Patterns ─────────────────────────────────────────────
export const browserInjectionPatterns = pgTable(
  "browser_injection_patterns",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id").notNull(),
    name: text("name").notNull(),
    pattern: text("pattern").notNull(),
    patternType: varchar("pattern_type", { length: 20 }).notNull().default("regex"),
    severity: varchar("severity", { length: 20 }).notNull().default("high"),
    enabled: boolean("enabled").notNull().default(true),
    matchCount: integer("match_count").notNull().default(0),
    lastMatchedAt: timestamp("last_matched_at"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [index("idx_bip_org").on(table.orgId)],
);

export type BrowserInjectionPattern = typeof browserInjectionPatterns.$inferSelect;
export type InsertBrowserInjectionPattern = typeof browserInjectionPatterns.$inferInsert;

export const evidenceTags = pgTable(
  "evidence_tags",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    evidenceId: varchar("evidence_id")
      .notNull()
      .references(() => evidenceItems.id, { onDelete: "cascade" }),
    tag: text("tag").notNull(),
    category: text("category").notNull().default("other"),
    createdBy: varchar("created_by"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_evidence_tags_org").on(table.orgId),
    index("idx_evidence_tags_evidence").on(table.evidenceId),
    uniqueIndex("uq_evidence_tags_evidence_tag").on(table.evidenceId, table.tag),
  ],
);

export const evidenceAccessRequests = pgTable(
  "evidence_access_requests",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    evidenceId: varchar("evidence_id")
      .notNull()
      .references(() => evidenceItems.id, { onDelete: "cascade" }),
    requestedBy: varchar("requested_by"),
    requestedByName: text("requested_by_name"),
    reason: text("reason").notNull(),
    accessType: text("access_type").notNull().default("view"),
    status: text("status").notNull().default("pending"),
    decisionNote: text("decision_note"),
    decidedBy: varchar("decided_by"),
    decidedByName: text("decided_by_name"),
    decidedAt: timestamp("decided_at"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_evidence_access_org").on(table.orgId),
    index("idx_evidence_access_evidence").on(table.evidenceId),
    index("idx_evidence_access_status").on(table.orgId, table.status),
  ],
);

export const investigationAnnotations = pgTable(
  "investigation_annotations",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    investigationId: varchar("investigation_id")
      .notNull()
      .references(() => investigationRuns.id, { onDelete: "cascade" }),
    text: text("text").notNull(),
    markerType: text("marker_type").notNull().default("note"),
    color: text("color").notNull().default("#3b82f6"),
    createdBy: varchar("created_by"),
    createdByName: text("created_by_name"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_investigation_annotations_org").on(table.orgId),
    index("idx_investigation_annotations_investigation").on(table.investigationId),
  ],
);

export type EvidenceTag = typeof evidenceTags.$inferSelect;
export type InsertEvidenceTag = typeof evidenceTags.$inferInsert;
export type EvidenceAccessRequest = typeof evidenceAccessRequests.$inferSelect;
export type InsertEvidenceAccessRequest = typeof evidenceAccessRequests.$inferInsert;
export type InvestigationAnnotation = typeof investigationAnnotations.$inferSelect;
export type InsertInvestigationAnnotation = typeof investigationAnnotations.$inferInsert;

export const playbookTemplateRatings = pgTable(
  "playbook_template_ratings",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: varchar("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    templateId: varchar("template_id").notNull(),
    rating: integer("rating").notNull(),
    ratedBy: varchar("rated_by"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (table) => [
    index("idx_template_ratings_org").on(table.orgId),
    index("idx_template_ratings_template").on(table.templateId),
    uniqueIndex("uq_template_ratings_org_template").on(table.orgId, table.templateId),
  ],
);

export type PlaybookTemplateRating = typeof playbookTemplateRatings.$inferSelect;
export type InsertPlaybookTemplateRating = typeof playbookTemplateRatings.$inferInsert;

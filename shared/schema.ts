import { sql, relations } from "drizzle-orm";
import {
  pgTable,
  text,
  varchar,
  integer,
  timestamp,
  boolean,
  jsonb,
  real,
  index,
  uniqueIndex,
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
  "other",
] as const;
export const INGESTION_STATUSES = ["success", "partial", "failed", "deduped"] as const;
export const PLAYBOOK_STATUSES = ["active", "inactive", "draft"] as const;
export const PLAYBOOK_TRIGGERS = [
  "alert_created",
  "alert_critical",
  "incident_created",
  "incident_escalated",
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
    analystNotes: text("analyst_notes"),
    assignedTo: varchar("assigned_to"),
    detectedAt: timestamp("detected_at"),
    ingestedAt: timestamp("ingested_at").defaultNow(),
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

export const COMPLIANCE_FRAMEWORKS = ["gdpr", "dpdp", "hipaa", "sox", "pci_dss", "iso27001", "nist"] as const;
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

export const WIZARD_STEPS = [
  "create_org",
  "choose_plan",
  "invite_team",
  "connect_integration",
  "dashboard_tour",
] as const;

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

export const CLOUD_PROVIDERS = ["aws", "azure", "gcp"] as const;
export const CSPM_SCAN_STATUSES = ["pending", "running", "completed", "failed"] as const;
export const CSPM_FINDING_SEVERITIES = ["critical", "high", "medium", "low", "informational"] as const;
export const CSPM_FINDING_STATUSES = ["open", "resolved", "suppressed", "accepted_risk"] as const;
export const CSPM_COMPLIANCE_FRAMEWORKS = ["cis", "nist", "pci_dss", "hipaa", "soc2", "gdpr", "iso27001"] as const;
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
    analystNotes: text("analyst_notes"),
    assignedTo: varchar("assigned_to"),
    detectedAt: timestamp("detected_at"),
    ingestedAt: timestamp("ingested_at").defaultNow(),
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

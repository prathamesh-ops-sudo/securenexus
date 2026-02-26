# Index Contracts for High-Write Tables

This document maintains the "index contract" for every high-write table in SecureNexus. Each entry lists the required composite indexes, the query patterns they serve, the rationale for their existence, and the conditions under which they may be removed.

All p95 latency targets are defined in `server/db-performance.ts` under `PERFORMANCE_BUDGETS`.

---

## alerts

Primary write path: alert ingestion via `/api/ingest/:source` and `/api/v1/ingest/bulk`.

| Index Name | Columns | Query Pattern | Rationale | Removal Condition |
|---|---|---|---|---|
| idx_alerts_org_created | orgId, createdAt | Default listing sorted by time | Covers the most common listing query (all alerts for an org, newest first). Enables index-only scans for time-range filters. | Never remove while alerts listing exists. |
| idx_alerts_org_status_created | orgId, status, createdAt | Filter by status then sort by time | The alerts listing page filters by status (open, acknowledged, resolved) in over 80 percent of queries. Without this index the planner falls back to a sequential scan on the status column. | Remove only if status filtering is dropped from the UI and API. |
| idx_alerts_org_severity_created | orgId, severity, createdAt | Filter by severity then sort by time | Severity filtering is the second most common filter after status. Composite index avoids a bitmap heap scan when both severity and time range are specified. | Remove only if severity filtering is dropped. |
| idx_alerts_org_source_created | orgId, source, createdAt | Filter by source then sort by time | Source filtering is used in connector-specific views and ingestion debugging. | Remove if source filtering is no longer exposed in the API. |
| idx_alerts_dedup (unique) | orgId, source, sourceEventId | Deduplication on ingest | Prevents duplicate alert creation during ingestion. Must remain unique. | Never remove. |

---

## incidents

Primary write path: incident creation from alert correlation, manual creation, and escalation.

| Index Name | Columns | Query Pattern | Rationale | Removal Condition |
|---|---|---|---|---|
| idx_incidents_org_created | orgId, createdAt | Default listing sorted by time | Same rationale as alerts. Covers the default incidents listing query. | Never remove while incidents listing exists. |
| idx_incidents_org_status_created | orgId, status, createdAt | Filter by status then sort by time | Incident queues (open, investigating, resolved, closed) are the primary navigation pattern. | Remove only if status filtering is dropped. |
| idx_incidents_org_severity_created | orgId, severity, createdAt | Filter by severity then sort by time | Severity-based triage is a core SOC workflow. | Remove only if severity filtering is dropped. |
| idx_incidents_sla_breached | orgId, slaBreached | SLA breach dashboard widget | Used by the dashboard to count breached SLAs per org. Low cardinality but high read frequency. | Remove if SLA tracking is deprecated. |

---

## audit_logs

Primary write path: every mutation in the system creates an audit log entry (create, update, delete operations).

| Index Name | Columns | Query Pattern | Rationale | Removal Condition |
|---|---|---|---|---|
| idx_audit_logs_org_seq | orgId, sequenceNum | Tamper-evidence verification | Used by the audit verification system to detect gaps in the sequence. Must remain. | Never remove. |
| idx_audit_logs_org_created | orgId, createdAt | Default listing sorted by time | Covers the standard audit log viewer. | Never remove while audit logs are exposed. |
| idx_audit_logs_org_action_created | orgId, action, createdAt | Filter by action type then sort | The audit log viewer filters by action (e.g. "alert.created", "incident.updated"). Composite index avoids a bitmap scan. | Remove if action filtering is dropped from the API. |
| idx_audit_logs_org_user_created | orgId, userId, createdAt | Filter by user then sort | Used to show "my activity" or investigate a specific user's actions. | Remove if user-scoped audit queries are no longer needed. |
| idx_audit_logs_org_resource | orgId, resourceType, resourceId | Lookup logs for a specific resource | Used by the alert/incident detail drawers to show related audit trail. | Remove if resource-scoped audit queries are dropped. |

---

## ioc_entries

Primary write path: IOC feed ingestion (STIX/TAXII, CSV, API). Can ingest thousands of entries per sync cycle.

| Index Name | Columns | Query Pattern | Rationale | Removal Condition |
|---|---|---|---|---|
| idx_ioc_entries_type_value | iocType, iocValue | IOC matching (lookup by type+value) | The IOC matcher looks up entries by type and value to check for matches against alert observables. This is the hottest read path for IOC data. | Never remove while IOC matching is active. |
| idx_ioc_entries_org_created | orgId, createdAt | IOC listing sorted by time | Covers the default IOC entries listing for an org. | Remove if IOC listing is no longer paginated by time. |
| idx_ioc_entries_org_type_created | orgId, iocType, createdAt | Filter by IOC type then sort | Used when viewing IOCs filtered by type (IP, domain, hash, etc.). | Remove if type filtering is dropped from the IOC viewer. |
| idx_ioc_entries_status | status | Filter active vs expired IOCs | Used by the retention scheduler to find expired entries and by the matcher to skip inactive entries. | Remove if IOC status tracking is deprecated. |

---

## response_actions

Primary write path: automated and manual response actions dispatched via playbooks and the action dispatcher.

| Index Name | Columns | Query Pattern | Rationale | Removal Condition |
|---|---|---|---|---|
| idx_response_actions_org_created | orgId, createdAt | Response action history sorted by time | Covers the default response actions listing. | Remove if response action history is no longer exposed. |
| idx_response_actions_org_status_created | orgId, status, createdAt | Filter by status then sort | Used to find pending or failed actions that need attention. | Remove if status filtering is dropped. |
| idx_response_actions_incident | incidentId | Actions for a specific incident | Used by the incident detail view to show associated response actions. | Remove if incident-scoped action listing is dropped. |

---

## connector_job_runs

Primary write path: every connector sync cycle creates a job run record. High-frequency connectors (e.g. CrowdStrike, Splunk) can generate runs every 5 minutes.

| Index Name | Columns | Query Pattern | Rationale | Removal Condition |
|---|---|---|---|---|
| idx_connector_job_runs_connector_started | connectorId, startedAt | Sync history for a specific connector | The connector detail view shows recent sync history. Composite index avoids a full table scan when a connector has thousands of runs. | Remove if per-connector sync history is dropped. |
| idx_connector_job_runs_status | status | Filter by run status | Used by the dead letter queue and retry logic to find failed runs. | Remove if dead letter / retry logic is removed. |
| idx_connector_job_runs_dead_letter | isDeadLetter | Dead letter queue listing | Used by the dead letter management UI. | Remove if dead letter queue feature is deprecated. |
| idx_connector_job_runs_next_retry | nextRetryAt | Retry scheduler | Used by the retry worker to find runs due for retry. | Remove if retry logic is removed. |

---

## ingestion_logs

Primary write path: every ingest request creates a log entry.

| Index Name | Columns | Query Pattern | Rationale | Removal Condition |
|---|---|---|---|---|
| idx_ingestion_logs_org_received | orgId, receivedAt | Default listing sorted by time | Covers the standard ingestion log viewer. | Never remove while ingestion logs are exposed. |
| idx_ingestion_logs_org_status_received | orgId, status, receivedAt | Filter by status then sort | Used to find failed ingestion attempts for debugging. | Remove if status filtering is dropped from the ingestion log viewer. |

---

## investigation_runs

Primary write path: AI investigation agent creates runs on demand and via automated triggers.

| Index Name | Columns | Query Pattern | Rationale | Removal Condition |
|---|---|---|---|---|
| (none currently needed beyond PK) | - | - | Investigation runs are low-volume relative to alerts/incidents. The existing single-column indexes on orgId and incidentId are sufficient. | Add composite indexes if run volume exceeds 10,000 per org per month. |

---

## Monitoring

Continuous monitoring of index health is available via:

- `GET /api/v1/monitoring/db-performance` returns index hit rates, table scan stats, unused indexes, cache hit ratios, and recent slow queries.
- `GET /api/v1/monitoring/index-stats` returns index hit rates and unused indexes specifically.
- `GET /api/v1/monitoring/slow-queries` returns recent slow queries (queries exceeding 200ms threshold).

All endpoints require admin role. Performance budgets (p95 latency targets per endpoint per environment) are defined in `server/db-performance.ts`.

---

## Review Schedule

Index contracts should be reviewed quarterly or whenever:
- A new high-cardinality endpoint is added
- Query patterns change significantly (new filters, new sort orders)
- Table row counts exceed 1 million rows
- Slow query monitoring detects repeated sequential scans on indexed tables
- Unused index monitoring shows indexes with zero scans for 30 or more days

# Phase 6: Incident Management Detailed Implementation Report

## 1. Executive Summary
Phase 6 must convert incident handling from basic CRUD into a governed lifecycle system with enforceable workflow transitions, SLA-driven execution, forensic evidence handling, and auditable analyst collaboration. This phase is the operational backbone for all later automation and compliance features.

## 2. Target Outcomes
- Incident workflow is deterministic, role-aware, and audit-complete.
- Incident ownership and escalation are visible in API, UI, and reporting.
- SLA timers are policy-driven and measurable across severity tiers.
- Alert-to-incident linkage is reliable at scale with bulk operations.
- Evidence records support incident reconstruction and governance.

## 3. Current State Baseline
- Incidents exist with key lifecycle fields in `shared/schema.ts`.
- Incident list and detail views are implemented.
- Comments and tags exist.
- Core weaknesses:
- No strict transition engine.
- No durable status history table.
- No watcher/notification model.
- No structured evidence chain.
- Incomplete merge/split/reopen behavior.

## 4. Detailed Gap Analysis
### 4.1 Workflow Integrity
- Status changes can occur without validated prerequisites.
- Required data for state progression is not enforced.
- Timeline reconstruction depends on sparse timestamps instead of event history.

### 4.2 Ownership and Accountability
- Assignment model is shallow and not permission-aware.
- Escalation lacks reason code, target team, and escalation policy linkage.

### 4.3 Alert Relationship Management
- Analysts need bulk attach/detach.
- Merge and split create data consistency risks without explicit transaction strategy.

### 4.4 Evidence and Forensic Readiness
- Unstructured notes are not sufficient for post-incident analysis.
- Chain-of-custody metadata and artifact integrity checks are missing.

## 5. Required Data Model Changes
### 5.1 New Tables
- `incident_status_history`
- `id`, `incidentId`, `orgId`, `fromStatus`, `toStatus`, `reason`, `changedBy`, `changedAt`, `meta`
- `incident_assignments`
- `id`, `incidentId`, `orgId`, `assigneeId`, `assignedBy`, `assignedAt`, `unassignedAt`
- `incident_watchers`
- `incidentId`, `orgId`, `userId`, `createdAt`
- `incident_evidence`
- `id`, `incidentId`, `orgId`, `type`, `title`, `description`, `source`, `sourceRef`, `integrityHash`, `storageUrl`, `createdBy`, `createdAt`
- `incident_sla_policy`
- `id`, `orgId`, `severity`, `priority`, `ackTargetMinutes`, `containTargetMinutes`, `resolveTargetMinutes`, `isActive`
- `incident_sla_state`
- `incidentId`, `orgId`, `policyId`, `ackDueAt`, `containDueAt`, `resolveDueAt`, `ackBreachedAt`, `containBreachedAt`, `resolveBreachedAt`

### 5.2 Indexes and Constraints
- Composite indexes on `(orgId, incidentId)` across all incident child tables.
- Unique constraint for active assignment per incident.
- Foreign keys with tenant-safe references.

## 6. Workflow and Business Rules
### 6.1 Allowed Status Transitions
- `open -> investigating -> contained -> eradicated -> recovered -> resolved -> closed`
- `resolved -> investigating` for reopen with mandatory reason.
- `closed` should be terminal unless override permission.

### 6.2 Transition Preconditions
- Move to `contained` requires at least one containment action record.
- Move to `resolved` requires mitigation summary and closure notes.
- Move to `closed` requires quality checklist complete.

### 6.3 Merge Rules
- Parent incident survives; children are archived and linked.
- Child alerts, comments, tags, and evidence are re-associated transactionally.

### 6.4 Split Rules
- Selected alerts/evidence/comments move to new incident with provenance links.
- System records split operator, rationale, and object counts.

## 7. API Design (Detailed)
- `POST /api/incidents/:id/transition`
- Validates role, transition matrix, and preconditions.
- Writes status change and SLA side effects in one transaction.
- `POST /api/incidents/:id/assign`
- Supports assign and unassign actions with audit events.
- `POST /api/incidents/:id/escalate`
- Captures reason, priority bump, and routing target.
- `POST /api/incidents/:id/merge`
- Accepts list of incident IDs and conflict strategy.
- `POST /api/incidents/:id/split`
- Accepts subset payload for alerts/evidence and new incident metadata.
- `GET /api/incidents/:id/history`
- Returns normalized timeline of transitions, assignments, escalations, and evidence events.
- `POST /api/incidents/:id/evidence`
- Creates evidence record and optional file metadata.

## 8. UI/UX Detailed Changes
- Incident timeline component with event filtering and actor details.
- Ownership panel with assignee, lead analyst, escalation status, and watcher controls.
- SLA cards with countdown, breach states, and color-coded urgency.
- Merge and split wizards with dry-run preview.
- Evidence tab with categories, validation states, and source linkage.

## 9. Security, Governance, and Audit
- Every incident mutation emits an audit log with actor, org, object, and change payload.
- All queries enforce org scoping server-side.
- Sensitive evidence metadata access controlled by role.

## 10. Observability Requirements
- Metrics: transition latency, assignment latency, SLA breach rates by severity.
- Structured logs for all workflow operations.
- Alerting on repeated failed transitions and merge errors.

## 11. Testing Strategy
- Unit tests: transition graph, precondition engine, SLA due date calculation.
- Integration tests: merge/split with rollback on partial failure.
- API contract tests: validation errors and permission paths.
- UI tests: timeline render, assignment flow, evidence add/edit.

## 12. Rollout Plan
- Step 1: Introduce tables and dual-write status history.
- Step 2: Enable transition API with feature flag.
- Step 3: Migrate UI to new endpoints.
- Step 4: Enforce strict transition validation.

## 13. Risks and Mitigations
- Risk: merge/split data corruption.
- Mitigation: transaction boundaries plus reconciliation job.
- Risk: SLA false positives due to timezone issues.
- Mitigation: UTC-only storage and tested date utility layer.

## 14. Definition of Done
- All status transitions validated and auditable.
- SLA calculations accurate and visible.
- Merge/split flows complete and tested.
- Evidence records persist with integrity metadata.

## 15. Estimated Effort
- Backend model and APIs: 8 to 10 engineering days.
- UI workflows: 6 to 8 engineering days.
- Testing and hardening: 4 to 5 engineering days.
- Total: approximately 4 weeks with one full-stack engineer.

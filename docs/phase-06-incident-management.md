# Phase 6: Incident Management Detailed Report

## Goal
Build a complete incident lifecycle system with strict workflow rules, ownership, escalation, SLA tracking, and evidence management.

## What Must Be Fixed
- Incident status changes are not fully enforced.
- Assignment and escalation are not consistently audited.
- Alert-to-incident bulk linking and merge/split flows are incomplete.
- Evidence is not structured for forensic traceability.

## Required Work
- Add transition engine with allowed state graph.
- Add status history timeline table.
- Add assignment/watchers model.
- Add incident SLA policy and runtime state tracking.
- Add merge/split endpoints with transactional safety.
- Add evidence records with source, hash, and owner metadata.

## Data and API Scope
- New tables: `incident_status_history`, `incident_assignments`, `incident_watchers`, `incident_evidence`, `incident_sla_policy`, `incident_sla_state`.
- New APIs: transition, assign, escalate, merge, split, history, evidence.

## UI Scope
- Timeline panel, SLA countdowns, ownership panel, merge/split wizards, evidence tab.

## Security and Audit
- Audit every status/assignment/escalation change.
- Enforce tenant scoping and role checks.

## Testing
- Unit: transition and SLA rules.
- Integration: merge/split and rollback behavior.
- UI: timeline and assignment workflows.

## Definition of Done
- Workflow is enforceable and auditable end-to-end.
- SLA breach states are correct.
- Evidence and bulk operations are stable.

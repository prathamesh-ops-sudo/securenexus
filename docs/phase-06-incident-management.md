# Phase 6: Incident Management Detailed Implementation Report

## Objective
Build a complete incident lifecycle system with enforceable states, ownership, SLA controls, incident evidence, and auditable operations.

## Current Baseline
- Incident CRUD exists.
- Basic incident fields exist (status/severity/priority/assigned fields).
- Comments and tags exist.

## Critical Gaps
- No strict transition policy.
- Limited ownership governance and escalation controls.
- No durable status history stream.
- Merge/split workflows are incomplete.
- Evidence model is insufficient for forensic readiness.

## Required Fixes
- Enforce finite-state transitions with preconditions.
- Add assignment and watcher model.
- Add escalation workflow with reason and target.
- Add incident merge/split APIs with transaction safety.
- Add evidence artifacts with hash/source metadata.
- Add SLA policy and runtime breach tracking.

## Data Model
- `incident_status_history`: transition records and actor metadata.
- `incident_assignments`: assignment events and active assignee.
- `incident_watchers`: notification subscribers.
- `incident_evidence`: structured artifact metadata.
- `incident_sla_policy`: severity/priority targets.
- `incident_sla_state`: due times and breach timestamps.

## API Plan
- `POST /api/incidents/:id/transition`
- `POST /api/incidents/:id/assign`
- `POST /api/incidents/:id/watch`
- `POST /api/incidents/:id/escalate`
- `POST /api/incidents/:id/merge`
- `POST /api/incidents/:id/split`
- `GET /api/incidents/:id/history`
- `POST /api/incidents/:id/evidence`

## UI Plan
- Timeline with transition and assignment events.
- SLA countdown and breach badges.
- Ownership panel.
- Merge/split wizard.
- Evidence tab with validation fields.

## Testing
- Transition rule unit tests.
- SLA calculator tests.
- Merge/split integration tests.
- UI tests for timeline and assignment.

## Definition of Done
- Incident lifecycle is enforced and auditable.
- SLA states are accurate.
- Evidence and bulk relationship workflows are stable.

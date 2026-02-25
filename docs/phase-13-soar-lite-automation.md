# Phase 13: SOAR-Lite Automation Detailed Implementation Report

## Objective
Implement safe workflow automation with playbooks, approvals, execution traces, and connector actions.

## Current Baseline
- Playbook stubs exist.

## Critical Gaps
- No runtime engine.
- No approval gates for risky actions.
- No complete run-step history.

## Required Fixes
- Create playbook model: triggers, steps, conditions.
- Build execution worker with retries and idempotency.
- Add manual approval step type.
- Add connector abstraction for external actions.

## Data Model
- `playbooks`
- `playbook_steps`
- `playbook_runs`
- `playbook_step_runs`
- `playbook_approvals`

## API Plan
- `POST /api/playbooks`
- `PATCH /api/playbooks/:id`
- `POST /api/playbooks/:id/validate`
- `POST /api/playbooks/:id/run`
- `GET /api/playbook-runs`
- `POST /api/playbook-runs/:id/approve`

## UI Plan
- Playbook builder.
- Execution timeline.
- Approval inbox.

## Testing
- Engine unit tests.
- Connector retry/failure tests.
- Approval path end-to-end tests.

## Definition of Done
- Playbooks run reliably and high-impact actions are approval-controlled.

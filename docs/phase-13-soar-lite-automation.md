# Phase 13: SOAR-Lite Automation Detailed Report

## Goal
Provide safe, approval-aware automation playbooks for repetitive SOC response actions.

## What Must Be Fixed
- No robust playbook runtime, run tracking, or approval gates for high-impact actions.

## Required Work
- Build playbook model with triggers, steps, and conditions.
- Build execution engine with retries, idempotency, and timeout controls.
- Add approval gates for destructive/external actions.

## Data and API Scope
- Tables: `playbooks`, `playbook_steps`, `playbook_runs`, `playbook_step_runs`, `playbook_approvals`.
- APIs: playbook CRUD, validate, run, list runs, approve step.

## UI Scope
- Playbook builder, run timeline, approval inbox.

## Security
- Secret-managed connector credentials.
- Full audit of all automated actions.

## Testing
- Step engine tests.
- Connector failure and retry tests.

## Definition of Done
- Automation runs are safe, controlled, and auditable.

# Phase 7: AI-Generated Narratives Detailed Implementation Report

## Objective
Deliver governed AI narratives with versioning, approvals, confidence scoring, and complete generation provenance.

## Current Baseline
- Narrative generation exists.
- Incident detail can display AI output.

## Critical Gaps
- No version history.
- No approval lifecycle.
- Incomplete provenance and auditability.
- No robust confidence policy.

## Required Fixes
- Add narrative versions (immutable).
- Add review states: `draft`, `pending_review`, `approved`, `rejected`, `superseded`.
- Store model, prompt hash, input hash, and generation config.
- Add regeneration modes for style/depth.
- Add confidence and uncertainty annotations.

## Data Model
- `incident_narratives` with version and state.
- `ai_generation_jobs` for async processing.
- `prompt_templates` with version and ownership.

## API Plan
- `POST /api/incidents/:id/narratives/generate`
- `GET /api/incidents/:id/narratives`
- `GET /api/incidents/:id/narratives/:version`
- `POST /api/incidents/:id/narratives/:version/approve`
- `POST /api/incidents/:id/narratives/:version/reject`
- `POST /api/incidents/:id/narratives/:version/promote`

## UI Plan
- Version picker and comparison view.
- Approval controls and comments.
- Provenance panel.
- Confidence warning badges.

## Testing
- Narrative state machine tests.
- Async generation queue tests.
- Permission tests for reviewer actions.

## Definition of Done
- Analysts can generate, compare, approve, and publish narratives safely.

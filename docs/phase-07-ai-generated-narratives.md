# Phase 7: AI-Generated Narratives Detailed Implementation Report

## 1. Executive Summary
Phase 7 should evolve AI narratives from single-shot text generation into a governed intelligence product: versioned, explainable, reviewable, and measurable. The system must support analyst trust, compliance traceability, and model quality iteration.

## 2. Core Objectives
- Produce structured incident narratives with timeline, attacker intent, confidence, and evidence links.
- Implement human approval workflow before narratives become authoritative.
- Track provenance: model version, prompt template, inference parameters, and grounding inputs.
- Enable narrative version comparison and rollback.
- Capture quality metrics and user feedback.

## 3. Current State Baseline
- AI correlation and narrative logic exists in `server/ai.ts`.
- Narrative surfaces in incident detail UI.
- Main limitations:
- No version history.
- No approval states.
- Weak provenance storage.
- Limited confidence calibration.

## 4. Detailed Requirements
### 4.1 Narrative Structure
- Mandatory sections:
- Executive summary.
- Chronological attack chain.
- MITRE mapping with confidence.
- Kill chain progression.
- Containment and mitigation recommendations.
- Open questions for analysts.

### 4.2 Lifecycle States
- `draft`, `pending_review`, `approved`, `superseded`, `rejected`.
- Only `approved` narrative is displayed as canonical in high-level incident listings.

### 4.3 Regeneration Policy
- Allow regeneration with objective tags: `clarity`, `brevity`, `technical_depth`, `executive_format`.
- Preserve prior versions immutable.

## 5. Data Model Changes
- `incident_narratives`
- `id`, `incidentId`, `orgId`, `version`, `state`, `summary`, `body`, `timelineJson`, `confidenceScore`, `generatedByModel`, `modelVersion`, `promptTemplateId`, `promptHash`, `inputHash`, `createdBy`, `createdAt`, `approvedBy`, `approvedAt`, `rejectedReason`.
- `ai_generation_jobs`
- `id`, `orgId`, `jobType`, `targetId`, `status`, `error`, `startedAt`, `completedAt`, `runtimeMs`.
- `prompt_templates`
- `id`, `orgId`, `name`, `category`, `template`, `isActive`, `createdAt`, `updatedAt`.

## 6. API Design
- `POST /api/incidents/:id/narratives/generate`
- Accepts mode, style, and optional template.
- Returns async job ID.
- `GET /api/incidents/:id/narratives`
- Lists versions and metadata.
- `GET /api/incidents/:id/narratives/:version`
- Full narrative payload.
- `POST /api/incidents/:id/narratives/:version/approve`
- Requires reviewer role.
- `POST /api/incidents/:id/narratives/:version/reject`
- Requires reason.
- `POST /api/incidents/:id/narratives/:version/promote`
- Marks as canonical if approved.

## 7. Prompting and Guardrails
- Use grounded context only from incident-linked records.
- Enforce explicit uncertainty handling in prompt.
- Hard stop for unsupported claims unless marked as hypothesis.
- Redaction layer for sensitive identities if required by org policy.

## 8. UI/UX Changes
- Narrative panel with:
- version selector.
- lifecycle badge.
- confidence indicator.
- provenance details drawer.
- Diff view between versions with section-level highlights.
- Approval actions with comment requirement.

## 9. Quality Measurement
- Metrics:
- acceptance rate.
- revision count before approval.
- average confidence by model/template.
- analyst quality score.
- false assertion rate.

## 10. Testing Strategy
- Unit tests for state transitions and canonical promotion logic.
- Integration tests for async job orchestration.
- Snapshot tests for schema validity of generated output.
- Permission tests for approval/rejection routes.

## 11. Risks and Mitigations
- Risk: hallucinated causal claims.
- Mitigation: strict prompt grounding and confidence penalties.
- Risk: operational delays from async queue buildup.
- Mitigation: queue backpressure and retry controls.

## 12. Rollout Plan
- Step 1: introduce versioned storage and write path.
- Step 2: expose read-only version history in UI.
- Step 3: enable approvals and canonical narrative switch.
- Step 4: enforce governance on default narrative display.

## 13. Definition of Done
- Narrative versions are persistent and immutable.
- Approval lifecycle is enforced.
- Provenance is visible and queryable.
- Analysts can compare versions and trust output context.

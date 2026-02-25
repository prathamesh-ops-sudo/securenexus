# Phase 8: MITRE ATT&CK Integration Detailed Implementation Report

## 1. Executive Summary
Phase 8 must establish ATT&CK as a first-class knowledge layer with normalized tactics/techniques, robust mapping workflows, and analytics-grade reporting for posture evaluation.

## 2. Objectives
- Build local ATT&CK dataset storage with refresh pipeline.
- Standardize alert/incident mapping with confidence and source attribution.
- Expose ATT&CK matrix and heatmap visualization.
- Allow analyst overrides with audit traceability.

## 3. Current State Baseline
- Basic tactic/technique fields exist.
- Dashboard displays partial MITRE statistics.
- Missing:
- canonical ATT&CK tables.
- sub-technique support.
- override governance.

## 4. Data Model Changes
- `mitre_tactics`
- `id`, `externalId`, `name`, `description`, `url`, `isActive`, `version`.
- `mitre_techniques`
- `id`, `externalId`, `name`, `description`, `tacticId`, `isSubTechnique`, `parentTechniqueId`, `detection`, `mitigation`, `platforms`, `version`.
- `alert_mitre_mapping`
- `alertId`, `orgId`, `techniqueId`, `confidence`, `sourceType` (`rule`, `ai`, `manual`), `mappedBy`, `createdAt`.
- `incident_mitre_mapping`
- same structure for incident-level mapping.
- `mitre_override_log`
- change log with before/after values and actor.

## 5. Ingestion and Sync
- Scheduled ATT&CK dataset refresh job with semantic version tag.
- Diff detection for tactic/technique deprecation and additions.
- Backward compatibility mapping for renamed techniques.

## 6. Mapping Engine
- Deterministic rule layer first.
- AI-assisted mapping second with confidence normalization.
- Manual analyst overrides highest priority.
- Conflict resolution policy:
- prefer manual > deterministic > AI.

## 7. API Surface
- `GET /api/mitre/tactics`
- `GET /api/mitre/techniques`
- `GET /api/mitre/techniques/:id`
- `GET /api/mitre/matrix`
- `GET /api/mitre/heatmap?window=30d`
- `POST /api/mitre/map/alerts`
- `POST /api/mitre/map/incidents`
- `POST /api/mitre/override`

## 8. UI/UX Changes
- ATT&CK matrix page with tactic columns and technique cells.
- Cell intensity reflects activity and confidence.
- Click-through to technique detail drawer.
- Override action with mandatory reason capture.

## 9. Security and Governance
- Override permission restricted to analyst+ roles.
- Every override event logged to audit trail.
- Tenant isolation for mapping tables and queries.

## 10. Testing
- Unit tests for precedence logic and confidence normalization.
- Integration tests for matrix aggregation queries.
- Regression tests for ATT&CK version refresh.

## 11. Metrics
- mapping coverage rate.
- low-confidence mapping ratio.
- manual override frequency.

## 12. Definition of Done
- ATT&CK data model deployed.
- Mappings available for alerts and incidents.
- Matrix and heatmap visible with filters.
- Overrides auditable and enforceable.

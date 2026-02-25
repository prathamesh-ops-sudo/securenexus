# Phase 8: MITRE ATT&CK Integration Detailed Implementation Report

## Objective
Establish ATT&CK as a normalized, queryable domain layer with explainable mappings and analyst override governance.

## Current Baseline
- Basic MITRE fields exist on alerts/incidents.
- Partial dashboard-level stats exist.

## Critical Gaps
- No canonical ATT&CK dataset tables.
- Sub-techniques are not modeled robustly.
- No override governance and confidence provenance.

## Required Fixes
- Ingest and version ATT&CK catalog.
- Build tactic/technique lookup APIs.
- Add mapping precedence: manual > deterministic > AI.
- Add matrix and heatmap analytics.

## Data Model
- `mitre_tactics`
- `mitre_techniques`
- `alert_mitre_mapping`
- `incident_mitre_mapping`
- `mitre_override_log`

## API Plan
- `GET /api/mitre/tactics`
- `GET /api/mitre/techniques`
- `GET /api/mitre/matrix`
- `GET /api/mitre/heatmap`
- `POST /api/mitre/override`

## UI Plan
- ATT&CK matrix page.
- Technique details drawer.
- Manual override form with reason.

## Testing
- Mapping precedence tests.
- ATT&CK sync regression tests.
- Aggregation accuracy tests.

## Definition of Done
- ATT&CK mappings are complete, explainable, and auditable.

# Phase 8: MITRE ATT&CK Integration Detailed Report

## Goal
Implement ATT&CK as a first-class intelligence layer with robust tactic/technique mapping and analyst override.

## What Must Be Fixed
- MITRE mapping is field-level only, not knowledge-layer backed.
- Technique metadata and sub-technique support are incomplete.

## Required Work
- Create normalized ATT&CK tables and refresh pipeline.
- Build mapping engine (rule + AI + manual override precedence).
- Add ATT&CK matrix and heatmap analytics.

## Data and API Scope
- Tables: `mitre_tactics`, `mitre_techniques`, `alert_mitre_mapping`, `incident_mitre_mapping`, `mitre_override_log`.
- APIs: tactics, techniques, matrix, heatmap, manual override.

## UI Scope
- ATT&CK matrix page with filters and confidence indicators.
- Technique detail drawer and override workflow.

## Testing
- Mapping precedence and confidence normalization tests.
- ATT&CK version refresh regression tests.

## Definition of Done
- ATT&CK mapping is explainable, queryable, and auditable.

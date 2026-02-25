# Phase 12: Analyst Feedback Loop Detailed Report

## Goal
Capture structured analyst feedback on AI output and convert it into measurable model quality improvements.

## What Must Be Fixed
- Feedback data is not systematically collected or linked to model versions.

## Required Work
- Add feedback forms for narrative, mapping, correlation quality.
- Track rating plus correction notes.
- Aggregate quality metrics by model/template/time.
- Export curated feedback for retraining.

## Data and API Scope
- Tables: `ai_feedback`, `ai_feedback_summary`.
- APIs: submit feedback, list feedback, summary metrics, export set.

## UI Scope
- Inline feedback controls near AI outputs.
- Admin quality dashboard.

## Testing
- Validation tests for feedback payloads.
- Aggregation accuracy tests.

## Definition of Done
- Feedback loop is operational and measurable.

# Phase 7: AI-Generated Narratives Detailed Report

## Goal
Deliver versioned, explainable, reviewable AI incident narratives with confidence and provenance.

## What Must Be Fixed
- Narrative generation is not version-governed.
- No review/approval lifecycle.
- Prompt/model provenance is not fully tracked.

## Required Work
- Add narrative version storage and canonical version selection.
- Add approval workflow (`draft`, `pending_review`, `approved`, `rejected`, `superseded`).
- Store model ID, prompt hash, input hash, and confidence score.
- Add regeneration options with style/objective controls.

## Data and API Scope
- Tables: `incident_narratives`, `ai_generation_jobs`, `prompt_templates`.
- APIs: generate, list versions, get version, approve/reject/promote.

## UI Scope
- Version selector, diff viewer, approval controls, provenance drawer.

## Risk Controls
- Ground responses only to incident evidence.
- Mark uncertain claims explicitly.

## Testing
- State machine tests for narrative lifecycle.
- Async job tests for generation pipeline.

## Definition of Done
- Analysts can compare versions, approve safely, and trust provenance.

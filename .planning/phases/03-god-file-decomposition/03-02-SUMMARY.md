---
phase: 03-god-file-decomposition
plan: 02
subsystem: api
tags: [express, routes, ai, decomposition, barrel-pattern]

requires:
  - phase: 03-01
    provides: storage decomposition pattern and barrel index.ts delegation
provides:
  - server/routes/ai/ directory with 13 domain modules
  - Barrel index.ts exporting registerAiRoutes with circuit breaker event listener
  - Each AI route domain isolated for targeted changes
affects: [04-logging-replacement, ai-engine-improvements]

tech-stack:
  added: []
  patterns: [barrel-index delegation for route modules, domain-split route registration]

key-files:
  created:
    - server/routes/ai/index.ts
    - server/routes/ai/helpers.ts
    - server/routes/ai/setup.ts
    - server/routes/ai/triage.ts
    - server/routes/ai/narrative.ts
    - server/routes/ai/feedback.ts
    - server/routes/ai/prompts.ts
    - server/routes/ai/active-learning.ts
    - server/routes/ai/deployment.ts
    - server/routes/ai/investigation.ts
    - server/routes/ai/context.ts
    - server/routes/ai/models.ts
    - server/routes/ai/detection-rules.ts
  modified: []

key-decisions:
  - "Event listener (eventBus.on) placed in barrel index.ts to ensure single registration"
  - "Budget routes grouped with setup.ts since they share admin/org middleware patterns"
  - "Response action routes grouped with models.ts to keep investigation.ts focused on AI analysis"
  - "Playbook authoring propose kept in feedback.ts as it shares gateway invoke patterns"

patterns-established:
  - "Route barrel pattern: index.ts calls registerXRoutes(app) for each sub-module"
  - "Domain grouping: endpoints split by functional concern (triage, narrative, investigation, etc.)"

requirements-completed: [SPLIT-01]

duration: 12min
completed: 2026-03-25
---

# Phase 03 Plan 02: AI Routes Decomposition Summary

**Decomposed 3,544-line server/routes/ai.ts into 13 domain modules under server/routes/ai/ with barrel index.ts preserving registerAiRoutes export**

## What Was Done

Split the monolithic AI routes file (70+ endpoints across 3,544 lines) into domain-focused modules:

| Module | Lines | Endpoints | Domain |
|--------|-------|-----------|--------|
| setup.ts | 705 | 18 | Health, config, metrics, budget management |
| investigation.ts | 565 | 13 | Deep investigation, threat hunt, behavioral, attack graphs, chat |
| prompts.ts | 464 | 12 | Prompt catalog, A/B testing, variables, quality, rollback |
| feedback.ts | 412 | 8 | Feedback submission, analytics, inline, playbook propose |
| models.ts | 372 | 8 | Model listing, tier assignment, data sources, response actions |
| narrative.ts | 293 | 3 | Narrative generation, SSE streaming (narrative + deep investigation) |
| context.ts | 182 | 2 | Context optimization, hallucination detection |
| triage.ts | 172 | 3 | Triage, correlate, correlate/apply |
| detection-rules.ts | 138 | 3 | Rule generation, listing, status updates |
| helpers.ts | 107 | 0 | persistAttackGraph utility |
| active-learning.ts | 60 | 2 | Few-shot examples, suppression status |
| index.ts | 54 | 0 | Barrel + circuit breaker event listener |
| deployment.ts | 42 | 2 | AI deployment config CRUD |

## Verification Results

- Zero TypeScript errors in server/routes/ai/ (pre-existing errors in other files unchanged)
- All 181 tests pass without modification
- No file exceeds 800 lines (max: 705 in setup.ts)
- Import in server/routes/index.ts unchanged: `from "./ai"` resolves to `./ai/index.ts`
- eventBus.on appears exactly once (in index.ts barrel)
- Original server/routes/ai.ts deleted

## Deviations from Plan

None - plan executed exactly as written.

## Commits

| Task | Commit | Description |
|------|--------|-------------|
| 1 | 7d57e69 | Create 13 AI route domain modules and barrel index.ts |
| 2 | d83376c | Delete original ai.ts, verify compilation and tests |

## Self-Check: PASSED

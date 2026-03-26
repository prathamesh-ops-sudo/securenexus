# Phase 3: God File Decomposition - Context

**Gathered:** 2026-03-25
**Status:** Ready for planning

<domain>
## Phase Boundary

Split the three largest files (storage.ts ~6200 lines, routes/ai.ts ~3542 lines, routes/playbooks.ts ~3541 lines) into navigable domain modules with barrel exports preserving all existing import paths. No behavioral changes — pure structural refactoring.

</domain>

<decisions>
## Implementation Decisions

### Claude's Discretion
All implementation choices are at Claude's discretion — structural refactoring phase. Key guidance:
- storage.ts → server/storage/ directory with domain modules + barrel index.ts
- routes/ai.ts → domain modules (triage, narrative, correlation, context-optimization, embeddings)
- routes/playbooks.ts → domain modules (crud, execution, scheduling, templates)
- Barrel exports must preserve all existing import paths (backward compatibility)
- No single file in split domains should exceed 800 lines
- No route contract changes — all endpoints keep same paths and behavior
- No behavioral changes — this is purely structural

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `shared/schema.ts` — Type definitions used by storage methods
- `server/db.ts` — Database connection shared by all storage modules
- `server/api-response.ts` — Response helpers used by route modules

### Established Patterns
- Drizzle ORM for all database operations
- Express Router for route registration
- Storage methods called via `storage.*` pattern throughout codebase

### Integration Points
- `server/storage.ts` — imported by virtually every route file and background service
- `server/routes/ai.ts` — registered in routes.ts, uses storage and AI services
- `server/routes/playbooks.ts` — registered in routes.ts, uses storage and action dispatcher
- `server/routes.ts` — where route modules are registered (must update imports)

</code_context>

<specifics>
## Specific Ideas

No specific requirements beyond SPLIT-01, SPLIT-02, SPLIT-03 scope.

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope.

</deferred>

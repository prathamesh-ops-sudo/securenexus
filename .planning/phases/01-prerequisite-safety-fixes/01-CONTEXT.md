# Phase 1: Prerequisite Safety Fixes - Context

**Gathered:** 2026-03-25
**Status:** Ready for planning

<domain>
## Phase Boundary

Fix all empty catch blocks and eliminate `any` types in critical modules (correlation engine, action dispatcher, auth, AI). This phase makes errors visible and establishes type safety so all subsequent hardening work produces trustworthy signals.

</domain>

<decisions>
## Implementation Decisions

### Claude's Discretion
All implementation choices are at Claude's discretion — pure infrastructure phase. Key guidance:
- Priority order for `any` elimination: correlation engine > action dispatcher > auth session > AI functions
- Empty catches should log at minimum, re-throw where appropriate
- Use existing Zod schemas from shared/schema.ts where possible for type definitions
- Prefer narrow interface types over broad union types

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `shared/schema.ts` — Contains Drizzle table definitions and Zod schemas that can inform TypeScript interfaces
- `server/logger.ts` — Structured logger already exists for catch block logging
- Existing type definitions in `shared/models/auth.ts`

### Established Patterns
- Drizzle ORM provides typed query results via table inference
- Zod schemas in shared/schema.ts for request validation
- `ApiEnvelope<T>` pattern for response typing

### Integration Points
- `server/correlation-engine.ts` and `server/graph-correlation.ts` — primary `any[]` targets
- `server/action-dispatcher.ts` — `config: any` parameter
- `server/auth/session.ts` — OAuth profile callbacks with `any` types
- `server/ai.ts` — multiple functions with `any[]` alert/entity parameters
- 23 empty catch blocks across auth, AI routes, outbox processor

</code_context>

<specifics>
## Specific Ideas

No specific requirements — infrastructure phase focused on type safety and error visibility.

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope.

</deferred>

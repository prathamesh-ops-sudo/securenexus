# Phase 4: Structured Logging & Observability - Context

**Gathered:** 2026-03-25
**Status:** Ready for planning

<domain>
## Phase Boundary

Replace remaining console.log/error/warn calls with structured logger, enrich the health endpoint with subsystem status, and ensure unhandled errors carry full request context. The structured logger infrastructure (server/logger.ts) already exists with AsyncLocalStorage correlation IDs, PII redaction, and child logger pattern.

</domain>

<decisions>
## Implementation Decisions

### Claude's Discretion
All implementation choices are at Claude's discretion — observability/infrastructure phase. Key guidance:
- Replace 24 remaining console.* calls across server/ with logger.child("module") calls
- Enrich GET /api/health to report: DB pool utilization, connector status summary, job queue depth, AI service availability
- Add global unhandled rejection/uncaught exception handler with full request context
- OBS-01 (correlation IDs) is already implemented in logger.ts via AsyncLocalStorage — verify it's wired into all request paths
- No behavioral changes to existing features — purely logging and observability improvements
- After completion, ESLint no-console rule should find zero violations in server/

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `server/logger.ts` — Full structured logging with AsyncLocalStorage correlation, PII redaction, child logger pattern, request/job/outbox context helpers
- `server/request-lifecycle.ts` — checkLiveness() for uptime/memory stats
- `server/db.ts` — Database pool connection (check for pool stats)
- `server/connector-engine.ts` — Connector status tracking
- `server/routes/health.ts` — Current minimal health endpoint (status, uptime, pid, memoryMB)

### Established Patterns
- `logger.child("module-name")` for per-module structured logging
- `correlationMiddleware` wired into Express middleware chain
- `withJobContext()` and `withOutboxContext()` for background task logging

### Integration Points
- 24 remaining console.* calls across: server/ai/enhanced-prompts.ts (1), server/cloud-connectors/aws.ts (8), server/cloud-connectors/gcp.ts (4), server/cloud-connectors/azure.ts (4), server/cloud-connectors/dspm-scanner.ts (2), server/cspm-scanner.ts (1), server/deception-engine.ts (1), server/integrations/slack-channel.ts (3)
- `server/routes/health.ts` — Must be enriched with subsystem checks
- `server/index.ts` — Where global error handlers should be installed

</code_context>

<specifics>
## Specific Ideas

No specific requirements beyond QUAL-02, OBS-01, OBS-02, OBS-03 scope.

</specifics>

<deferred>
## Deferred Ideas

None — scope is well-defined.

</deferred>

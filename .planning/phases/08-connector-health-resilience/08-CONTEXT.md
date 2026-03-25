# Phase 8: Connector Health & Resilience - Context

**Gathered:** 2026-03-26
**Status:** Ready for planning

<domain>
## Phase Boundary

This phase adds self-monitoring, auto-recovery, and real-time health visibility to the connector subsystem. Connectors will run periodic health checks, implement per-connector circuit breakers, auto-restart on failure with exponential backoff, and display health status in the UI.

</domain>

<decisions>
## Implementation Decisions

### Health Check & Circuit Breaker Architecture
- Health check loop runs as an in-process setInterval timer, consistent with existing schedulers (report, SLO, metrics)
- Circuit breaker state stored in-memory Map per process — simple, no DB overhead, resets on restart (acceptable for this use case)
- Health check method reuses existing `testConnector()` from connector-engine.ts — already validates credentials + connectivity
- Extend CONNECTOR_STATUSES in schema.ts with "degraded" and "failed" to match the marketplace engine pattern

### UI Status Display
- Badge component with green/yellow/red dot + text label (healthy/degraded/failed) in the connectors table
- Real-time updates via SSE on existing `/api/events` — push status changes as they happen
- Tooltip showing last sync time, error count, and circuit breaker state on hover
- New "Status" column in the connectors table, next to existing status field

### Testing Strategy
- Mock external APIs using Vitest mock modules — mock each connector plugin's fetch/test methods
- Parameterized test matrix: each failure type (timeout, 401, 403, rate limit) × each connector behavior
- Unit test the circuit breaker state machine directly with Vitest fake timers
- Pagination test mocks returning 3 pages of 50 alerts each, verifying all 150 processed

### Claude's Discretion
- Internal implementation details of the circuit breaker state machine
- Exact structure of health check result objects
- SSE event naming and payload format for health updates
- Order of health check execution across multiple connectors

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `server/connector-engine.ts` — `testConnector()` function for health checks, distributed concurrency/backoff system
- `server/distributed-concurrency.ts` — Provider-level backoff with `distributedApplyBackoff`/`distributedCheckBackoff`
- `server/connectors/connector-plugin.ts` — Plugin interface with `test()` method
- `shared/schema.ts` — `CONNECTOR_STATUSES = ["active", "inactive", "error", "syncing"]`, connectors table
- `server/storage/connectors.ts` — Connector CRUD operations
- `server/integration-marketplace-engine.ts` — Already uses `"degraded"` status concept
- `client/src/pages/connectors.tsx` — Existing connectors page UI

### Established Patterns
- Background schedulers: `setInterval` with graceful shutdown registration (see report-scheduler, slo-alerting)
- SSE events: `server/event-bus.ts` for publishing, `/api/events` endpoint for consuming
- Status badges: shadcn/ui Badge component used across dashboard
- Storage pattern: Domain modules in `server/storage/` with barrel export via `index.ts`

### Integration Points
- `server/index.ts` — Bootstrap health check scheduler on app start
- `server/routes/connectors.ts` — Add health status to GET responses
- `client/src/pages/connectors.tsx` — Add status column with badge
- `server/event-bus.ts` — Publish health change events

</code_context>

<specifics>
## Specific Ideas

No specific requirements — open to standard approaches following existing codebase patterns.

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope.

</deferred>

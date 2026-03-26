# Phase 9: API Resilience & Performance - Context

**Gathered:** 2026-03-26
**Status:** Ready for planning

<domain>
## Phase Boundary

This phase hardens the API layer so it degrades gracefully under pressure instead of cascading failures. Three concerns converge:

1. **Database resilience** -- The connection pool (20 max in prod) already monitors utilization via `getPoolHealth()` in `server/db.ts` and logs warnings at 80%, but never rejects requests. API-01 adds a circuit breaker that returns 503 + Retry-After when utilization exceeds the threshold, protecting the DB from overload.

2. **AI degradation** -- AI features (triage, narrative, correlation, investigation) currently fail hard when Bedrock is unavailable. The model-gateway circuit breaker in `server/ai/model-gateway.ts` throws errors that propagate as 500s to the client. API-02 requires these features to return cached results or a structured "AI unavailable" status, keeping non-AI features unaffected. API-03 converts the synchronous triage endpoint (`POST /api/ai/triage/:alertId`) into an async 202 Accepted flow with job ID and SSE notification.

3. **Caching and budgets** -- Entity graph queries hit the DB on every call with no caching. The query-cache module (`server/query-cache.ts`) already defines `CACHE_TTL.ENTITY_GRAPH = 5 * 60 * 1000` but entity-resolver.ts does not use it. PERF-01 through PERF-05 add LRU caching with event-driven invalidation, token budget enforcement for narratives, and performance guardrails.

**Out of scope:** Redis/ElastiCache shared caching (deferred to horizontal scaling), Prometheus metric additions (Phase 4), connector-level circuit breakers (Phase 8).
</domain>

<decisions>
## Implementation Decisions

### D1: Pool circuit breaker as Express middleware vs. inline check in db.ts

**Decision:** Implement as Express middleware (`server/middleware/pool-circuit-breaker.ts`).

**Rationale:** The existing `performanceBudgetMiddleware` in `server/db-performance.ts` already follows the middleware pattern for request-level guardrails. A pool circuit breaker middleware can call `getPoolHealth()` from `server/db.ts` and short-circuit with 503 before the route handler ever acquires a connection. This keeps `db.ts` focused on pool management and avoids wrapping every `pool.query()` call. The `startPoolHealthMonitor()` already checks utilization every 60s; the middleware adds per-request checking. Health check and metrics endpoints should be exempt (matching the rate limiter skip pattern already in the codebase).

### D2: AI graceful degradation via try-catch wrapper vs. dedicated fallback layer

**Decision:** Create an AI fallback wrapper module (`server/ai/fallback.ts`) that wraps each AI function with cache-on-success and stale-serve-on-failure logic.

**Rationale:** The model-gateway already has a response cache (`responseCache` Map with 5-min TTL, 200 max entries) keyed by model+prompt hash. However, this cache is prompt-level, not result-level for triage/narrative. A higher-level fallback wrapper can: (1) cache the latest successful triage/narrative result per alert/incident, (2) serve stale cached results when the gateway circuit breaker is open, and (3) return a structured `{ status: "ai_unavailable", cachedAt: ..., data: ... }` envelope. This avoids modifying the 20+ AI call sites in routes -- each just wraps with `withAiFallback()`.

### D3: Async triage via job_queue table vs. in-memory Promise tracking

**Decision:** Use the existing `job_queue` table and `JOB_HANDLERS` pattern from `server/job-queue.ts`.

**Rationale:** The job queue already supports: deduplication via fingerprinting, dead-letter after 3 attempts, visibility timeout, heartbeat extension, and stale job reaping. Adding an `ai_triage` handler follows the same pattern as `connector_sync`. The triage route returns 202 with the job ID, and the handler broadcasts completion via `broadcastEvent()` using the SSE event bus (which already supports org-scoped delivery and subscription filtering). This gives persistence, retry, and distributed delivery for free. The event bus already defines `EventType` -- we add `"ai:triage_complete"` to the union.

### D4: Entity graph cache invalidation via event-bus subscription vs. manual cache purge

**Decision:** Subscribe to `entity:resolved` events on the event bus to invalidate entity cache entries.

**Rationale:** The event bus in `server/event-bus.ts` already emits `"entity:resolved"` events. The query-cache module supports prefix-based invalidation via `cacheInvalidate(pattern)`. Entity cache keys can be prefixed with `entity-graph:{orgId}:` so that when an entity changes, `cacheInvalidate("entity-graph:{orgId}:")` clears all cached graph queries for that org. This is event-driven (no polling), tenant-scoped (no cross-org leakage), and uses existing infrastructure. The `CACHE_TTL.ENTITY_GRAPH` constant (5 min) is already defined but unused -- we wire it into `entity-resolver.ts` via `cacheGetOrLoad()`.
</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets

| Asset | Location | Relevance |
|-------|----------|-----------|
| `getPoolHealth()` | `server/db.ts:48-63` | Returns `utilizationPercent` and `healthy` boolean. Pool circuit breaker middleware calls this per-request. Already tracks `totalCount`, `idleCount`, `waitingCount` against max. |
| `cacheGetOrLoad()` | `server/query-cache.ts:145-169` | Deduplicates concurrent loads for the same key (inflight request map). Use for entity graph caching -- avoids thundering herd on cache miss. |
| `buildCacheKey()` | `server/query-cache.ts:171-175` | Tenant-scoped cache key builder using `orgId` in hash. Entity graph keys must use this to maintain tenant isolation. |
| `cacheInvalidate(pattern)` | `server/query-cache.ts:95-104` | Prefix-based cache eviction. Use `entity-graph:{orgId}:` prefix for org-scoped invalidation. |
| `CACHE_TTL.ENTITY_GRAPH` | `server/query-cache.ts:206` | Already defined as 5 * 60 * 1000 (5 minutes). Currently unused -- wire into entity-resolver. |
| Model gateway circuit breaker | `server/ai/model-gateway.ts:64-117` | Per-model circuit breaker with 5-failure threshold, 60s reset. `isCircuitOpen()` and `getCircuitBreakerStatus()` are exported. Use status to determine if AI is available for fallback decisions. |
| Model gateway response cache | `server/ai/model-gateway.ts:119-217` | 200-entry, 5-min TTL prompt-level cache. Only caches when `temperature <= 0.2`. Triage uses temperature 0.1, so results are cached. |
| Job queue + handlers | `server/job-queue.ts` | `JOB_HANDLERS` registry, dedup fingerprinting, dead-letter at 3 attempts, heartbeat extension. Add `ai_triage` handler. |
| Event bus + SSE | `server/event-bus.ts` | `broadcastEvent()` delivers to org-scoped SSE clients. `EventType` union needs `"ai:triage_complete"` added. Supports subscription filtering, backpressure, and slow client detection. |
| `broadcastEvent()` | `server/event-bus.ts:304-322` | Emits to EventEmitter (for in-process listeners) and SSE clients. The `eventBus.emit()` call means we can `eventBus.on("entity:resolved", ...)` for cache invalidation. |
| `checkBudget()` | `server/ai/budget.ts` | Per-org daily spend and invocation cap checking. Already integrated in model-gateway `invokeModel()`. Token budget enforcement for PERF-01 can extend this. |
| `countTokens()` | `server/ai/tokenizer.ts` (imported by model-gateway) | Token counting for budget enforcement. Use in narrative generation to count input context size and reserve response space. |
| `performanceBudgetMiddleware` | `server/db-performance.ts:198-225` | Existing middleware pattern for latency budget checks. Pool circuit breaker follows the same pattern. |

### Established Patterns

1. **Middleware-based request guards**: `performanceBudgetMiddleware`, `requestTimeoutMiddleware`, `inFlightMiddleware` in `server/request-lifecycle.ts` all follow the pattern of checking conditions early and short-circuiting before handler execution. Pool circuit breaker uses the same pattern.

2. **Circuit breaker implementation**: Two existing circuit breakers to reference -- the model-gateway circuit breaker (per-model, in-memory, 5 failures / 60s reset) in `server/ai/model-gateway.ts` and the connector circuit breaker (per-connector, closed/open/half-open state machine, 5 failures in 60s window, 30s half-open) in `server/connector-circuit-breaker.ts`. The connector version is more mature with explicit state machine and windowed failure tracking.

3. **Job queue handler registration**: `server/job-queue.ts` uses a `JOB_HANDLERS` record keyed by job type string. Handlers are async functions that receive the job object and return a result. The `connector_sync` handler demonstrates the full pattern including storage calls, audit logging, and status updates.

4. **SSE event delivery**: `broadcastEvent()` takes `{ type, orgId, data }`, adds timestamp and podId, emits to EventEmitter and SSE clients. Org-scoped delivery means triage completion events only reach the requesting user's org.

5. **Cache key conventions**: All cache keys use `prefix:hash` format via `buildCacheKey()`. Existing prefixes include dashboard, analytics, ingestion, compliance. Entity graph should use `entity-graph` prefix.

### Integration Points

| Requirement | Touches | New Files |
|-------------|---------|-----------|
| API-01: Pool circuit breaker | `server/db.ts` (read `getPoolHealth()`), `server/index.ts` (register middleware) | `server/middleware/pool-circuit-breaker.ts` |
| API-02: AI degradation | `server/ai/model-gateway.ts` (read circuit state), all AI route handlers in `server/routes/ai/` | `server/ai/fallback.ts` |
| API-03: Async triage | `server/routes/ai/triage.ts` (modify endpoint), `server/job-queue.ts` (add handler), `server/event-bus.ts` (add event type) | None (modifications only) |
| API-04: Entity cache | `server/entity-resolver.ts` (add caching), `server/query-cache.ts` (use existing), `server/event-bus.ts` (subscribe) | None (modifications only) |
| PERF-01: Token budgets | `server/ai.ts` (narrative generation functions), `server/ai/budget.ts`, `server/ai/tokenizer.ts` | None (modifications only) |
</code_context>

<specifics>
## Specific Ideas

1. **Pool circuit breaker middleware** should use a sampling approach -- check `getPoolHealth()` on every request but use a fast path (cached utilization value refreshed every 1s) to avoid calling pool stats on every single request. Return `503 Service Unavailable` with `Retry-After: 5` header. Log the rejection with org context for monitoring.

2. **AI fallback wrapper** function signature: `withAiFallback<T>(cacheKey: string, orgId: string, fn: () => Promise<T>): Promise<{ data: T; source: "live" | "cached" | "unavailable"; cachedAt?: string }>`. The wrapper checks gateway circuit state via `getCircuitBreakerStatus()` before even attempting the call. If all model circuits are open, serve from cache immediately without wasting a request.

3. **Async triage endpoint** returns `{ jobId: string, status: "accepted", pollUrl: "/api/ai/triage/jobs/{jobId}" }` with 202 status. Add a `GET /api/ai/triage/jobs/:jobId` polling endpoint as a fallback for clients that cannot use SSE. The SSE event `ai:triage_complete` includes `{ jobId, alertId, result }` in its data payload.

4. **Entity graph cache invalidation** registers an `eventBus.on("entity:resolved", ...)` listener at module load in `entity-resolver.ts`. The listener extracts `orgId` from the event and calls `cacheInvalidate("entity-graph:{orgId}:")`. This keeps invalidation co-located with the caching logic.

5. **Token budget enforcement for narratives** should use a "context window packing" approach: (a) count tokens in system prompt, (b) count tokens in each RAG chunk from `buildRAGContext()`, (c) sort chunks by relevance score, (d) pack highest-value chunks until remaining tokens minus response reservation is reached. The `countTokens()` function from `server/ai/tokenizer.ts` already exists for this.

6. **Performance budget for AI endpoints** -- extend `PERFORMANCE_BUDGETS` in `server/db-performance.ts` with entries for `POST /api/ai/triage/:alertId` (2000ms staging, 1500ms production) and `POST /api/ai/narrative` (3000ms staging, 2000ms production) to catch AI latency regressions.
</specifics>

<deferred>
## Deferred Ideas

1. **Redis-backed shared cache** -- The query-cache module is explicitly designed for Redis promotion (comment in `query-cache.ts` lines 11-16 describes the Tier 2 architecture). Deferring until horizontal scaling requires shared state across pods.

2. **AI request priority queue** -- Triage and narrative requests could be prioritized by alert severity (critical alerts get AI attention first). The job queue supports this conceptually but needs a priority column. Defer to avoid schema changes in this phase.

3. **Adaptive pool circuit breaker threshold** -- Instead of a fixed 80% threshold, dynamically adjust based on historical utilization patterns (e.g., lower threshold during known peak hours). Over-engineering for the current single-pod deployment.

4. **AI response streaming to SSE** -- Instead of buffering the full triage result and sending it as a single SSE event, stream model-gateway chunks directly to the SSE client for perceived-latency improvement. The streaming infrastructure exists (`invokeModelStream` in model-gateway) but wiring it to SSE adds complexity.

5. **Entity graph materialized views** -- For frequently-accessed entity subgraphs, maintain pre-computed views in the DB. This is a DB-level optimization that belongs in a future database performance phase.

6. **Cross-org cache warming** -- Threat intel enrichment results (IOC lookups, OSINT feeds) are org-independent and could be pre-warmed. Defer as it requires careful tenant isolation review.
</deferred>

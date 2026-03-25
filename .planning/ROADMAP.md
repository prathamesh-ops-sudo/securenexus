# Roadmap: SecureNexus Production Hardening

## Overview

SecureNexus has a complete feature surface (28 pages, 110+ routes, 8 connectors) but prototype-quality internals: empty catch blocks, any types everywhere, zero test coverage on critical paths, and god files blocking maintainability. This roadmap sequences 50 production-hardening requirements across 10 phases ordered by risk dependency. Each phase produces observable improvements. The sequence ensures safety nets exist before structural changes, structural changes complete before behavioral testing, and behavioral testing validates before shipping.

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [x] **Phase 1: Prerequisite Safety Fixes** - Fix empty catches, eliminate any types in critical modules, make error surface visible
- [x] **Phase 2: Dependency Security & Build Hardening** - Upgrade vulnerable deps, move runtime DDL to migrations, secure API key rotation
- [x] **Phase 3: God File Decomposition** - Split storage.ts, ai.ts, and playbooks.ts into domain modules with barrel exports
- [ ] **Phase 4: Structured Logging & Observability** - Replace console.log calls with structured logger, enrich health endpoint, add error context
- [ ] **Phase 5: Correlation Engine Hardening** - Transaction isolation, conflict resolution, confidence scoring, and full test suite
- [ ] **Phase 6: Alert Pipeline Hardening** - Temporal deduplication, suppression rules, dashboard metrics, and stub elimination
- [ ] **Phase 7: Automated Response Safety** - Zod validation, dry-run mode, rollback API, audit trail, and dispatcher tests
- [ ] **Phase 8: Connector Health & Resilience** - Health check loop, auto-restart, circuit breaker, status UI, and connector tests
- [ ] **Phase 9: API Resilience & Performance** - Pool circuit breaker, AI degradation, async processing, caching, token budgets, billing fix
- [ ] **Phase 10: Test Coverage & Quality Gates** - OAuth tests, RBAC boundary tests, billing tests, ESLint pre-commit hooks

## Phase Details

### Phase 1: Prerequisite Safety Fixes
**Goal**: Errors are visible and type safety exists in critical modules so all subsequent hardening work produces trustworthy signals
**Depends on**: Nothing (first phase)
**Requirements**: QUAL-01, QUAL-04
**Success Criteria** (what must be TRUE):
  1. Zero empty catch blocks remain in the codebase -- every catch either logs, re-throws, or has an explicit comment justifying silence
  2. Correlation engine, action dispatcher, auth, and AI modules use typed interfaces instead of any[] parameters
  3. Running the test suite produces meaningful error output when something breaks (no silently swallowed failures)
**Plans**: 2 plans

Plans:
- [x] 01-01-PLAN.md -- Fix 22 empty .catch(() => {}) handlers with warn-level logging
- [x] 01-02-PLAN.md -- Eliminate any types in 6 critical modules (correlation, action dispatcher, auth, AI)

### Phase 2: Dependency Security & Build Hardening
**Goal**: Known vulnerabilities are eliminated, runtime DDL hacks are replaced with proper migrations, and API keys can be safely rotated
**Depends on**: Phase 1
**Requirements**: SEC-01, SEC-02, SEC-03, SEC-04, SEC-05
**Success Criteria** (what must be TRUE):
  1. @xmldom, passport-github2, passport-google-oauth20, and Stripe SDK are upgraded to latest stable with no regressions in existing OAuth flows
  2. ai_inference_log table creation happens via Drizzle migration at deploy time, not at runtime in ai.ts
  3. API key rotation endpoint allows generating a new key with a 24-hour grace period on the old key, with soft-delete audit trail
  4. No npm audit high/critical findings in the dependency tree
**Plans**: 2 plans

Plans:
- [ ] 02-01-PLAN.md -- Upgrade xmldom/stripe/passport deps and move ai_inference_log to Drizzle migration
- [ ] 02-02-PLAN.md -- Implement API key rotation endpoint with 24h grace period

### Phase 3: God File Decomposition
**Goal**: The three largest files are split into navigable domain modules without breaking any existing imports or behavior
**Depends on**: Phase 1 (type safety makes split verifiable)
**Requirements**: SPLIT-01, SPLIT-02, SPLIT-03
**Success Criteria** (what must be TRUE):
  1. server/storage.ts is replaced by server/storage/ directory with domain modules and a barrel index.ts that preserves all existing import paths
  2. server/routes/ai.ts is split into domain modules (triage, narrative, correlation, context-optimization, embeddings) with no route contract changes
  3. server/routes/playbooks.ts is split into domain modules (crud, execution, scheduling, templates) with no route contract changes
  4. All existing tests pass without modification after the split
  5. No single file in the split domains exceeds 800 lines
**Plans**: 3 plans

Plans:
- [x] 03-01-PLAN.md -- Split storage.ts (6,243 lines) into ~18 domain modules with barrel index.ts
- [ ] 03-02-PLAN.md -- Split routes/ai.ts (3,544 lines) into ~12 domain modules
- [ ] 03-03-PLAN.md -- Split routes/playbooks.ts (3,541 lines) into ~5 domain modules

### Phase 4: Structured Logging & Observability
**Goal**: Every log call is structured and searchable, the health endpoint reveals subsystem status, and unhandled errors carry full context
**Depends on**: Phase 3 (split files make targeted logging replacement manageable)
**Requirements**: QUAL-02, OBS-01, OBS-02, OBS-03
**Success Criteria** (what must be TRUE):
  1. Zero console.log/console.error calls remain in server code -- all replaced with logger.child("module") calls
  2. Every log entry includes a request correlation ID from AsyncLocalStorage when called within a request context
  3. GET /api/health returns subsystem health for DB pool, connector status, job queue depth, and AI service availability
  4. Unhandled errors logged with request context, org context, and full stack trace
**Plans**: 2 plans

Plans:
- [ ] 04-01-PLAN.md -- Replace 24 console.* calls with logger.child() and enhance error tracker context (QUAL-02, OBS-01, OBS-03)
- [ ] 04-02-PLAN.md -- Enrich /api/health with subsystem health: DB pool, connectors, job queue, AI (OBS-02)

### Phase 5: Correlation Engine Hardening
**Goal**: The correlation engine -- the platform's core value -- produces correct, conflict-free incident groupings backed by a full test suite
**Depends on**: Phase 3 (storage split provides testable domain modules), Phase 1 (typed interfaces)
**Requirements**: CORR-01, CORR-02, CORR-03, CORR-04, CORR-05, CORR-06
**Success Criteria** (what must be TRUE):
  1. All correlation writes are wrapped in database transactions with serializable isolation -- concurrent ingestion does not produce duplicate or orphaned incidents
  2. When AI semantic, graph-based, and rule-based algorithms disagree, a weighted scoring mechanism picks the winner and flags divergent cases for analyst review
  3. Correlation confidence score is populated from algorithm consensus and visible in the incident detail UI
  4. Integration tests ingest 10+ alerts from 3+ sources and verify correct incident grouping end-to-end
  5. Each correlation algorithm has isolated unit tests with mocked storage
**Plans**: 3 plans

Plans:
- [ ] 05-01: TBD
- [ ] 05-02: TBD
- [ ] 05-03: TBD

### Phase 6: Alert Pipeline Hardening
**Goal**: Alert ingestion is production-grade with intelligent deduplication, operator-controlled suppression, and zero stub endpoints remaining
**Depends on**: Phase 5 (correlation engine must be stable before changing alert flow)
**Requirements**: DEDUP-01, DEDUP-02, DEDUP-03, STUB-01, STUB-02, STUB-03
**Success Criteria** (what must be TRUE):
  1. Duplicate alerts within a configurable time window update lastSeenAt and increment occurrenceCount instead of creating new records
  2. Operators can create suppression rules (by source, severity, title pattern, time window) that suppress noisy alerts while preserving the data
  3. Dashboard shows deduplication and suppression metrics (count per period)
  4. Every API endpoint returns real data -- zero hardcoded/mock responses remain, including AI context-optimization
  5. All dashboard widgets display real aggregated data, not placeholder values
**Plans**: 3 plans

Plans:
- [ ] 06-01: TBD
- [ ] 06-02: TBD
- [ ] 06-03: TBD

### Phase 7: Automated Response Safety
**Goal**: Response actions are safe to execute in production with validation, dry-run preview, rollback capability, and full audit trail
**Depends on**: Phase 5 (correlation stability), Phase 1 (typed interfaces for action types)
**Requirements**: RESP-01, RESP-02, RESP-03, RESP-04, RESP-05
**Success Criteria** (what must be TRUE):
  1. Every action type (IsolateHost, BlockIP, QuarantineFile, etc.) has a Zod schema that validates inputs before dispatch
  2. Dry-run mode validates inputs, checks permissions, and logs planned actions without executing anything
  3. POST /api/incidents/{id}/rollback-actions generates and executes reverse operations with a full audit trail
  4. Every response action creates an audit_logs entry with action type, parameters, result, duration, and triggering user
  5. Test suite covers dry-run, rollback, permission checks, and concurrent execution on the same incident
**Plans**: 3 plans

Plans:
- [ ] 07-01: TBD
- [ ] 07-02: TBD

### Phase 8: Connector Health & Resilience
**Goal**: Connectors self-monitor, auto-recover from failures, and show real-time health status in the UI
**Depends on**: Phase 3 (storage split for connector domain module)
**Requirements**: CONN-01, CONN-02, CONN-03, CONN-04, TEST-02
**Success Criteria** (what must be TRUE):
  1. Each connector runs a health check every 60 seconds reporting healthy/degraded/failed based on last sync time, connection test, and error rate
  2. Connectors auto-restart after 3 consecutive failed polls with exponential backoff (30s, 60s, 120s, max 5min)
  3. Connector status is visible on the connectors page with green/yellow/red indicators
  4. Per-connector circuit breaker opens after 5 failures in 60 seconds, half-opens after 30 seconds, and closes on success
  5. Connector integration tests cover failure modes (timeout, 401, 403, rate limit) and large paginated results
**Plans**: 3 plans

Plans:
- [ ] 08-01: TBD
- [ ] 08-02: TBD

### Phase 9: API Resilience & Performance
**Goal**: The API layer handles failures gracefully, AI operations run asynchronously, and expensive operations are cached or budget-limited
**Depends on**: Phase 4 (observability for monitoring), Phase 5 (correlation stability for AI features)
**Requirements**: API-01, API-02, API-03, API-04, PERF-01, PERF-02, PERF-03, PERF-04, PERF-05
**Success Criteria** (what must be TRUE):
  1. Connection pool circuit breaker returns 503 + Retry-After when pool utilization exceeds 80%
  2. AI-dependent features return cached results or "AI unavailable" status on Bedrock failure -- non-AI features are unaffected
  3. AI triage requests return 202 Accepted with a job ID and notify via SSE when processing completes
  4. Entity graph uses LRU cache with 5-minute TTL, invalidated on entity change events
  5. AI narrative generation enforces token budgets -- counts tokens, reserves response space, selects highest-value RAG chunks
**Plans**: 3 plans

Plans:
- [ ] 09-01: TBD
- [ ] 09-02: TBD
- [ ] 09-03: TBD

### Phase 10: Test Coverage & Quality Gates
**Goal**: Security-critical boundaries are verified by automated tests and ESLint rules prevent regression of fixed issues
**Depends on**: Phase 2 (dep upgrades before OAuth tests), Phase 3 (split files enable targeted test suites)
**Requirements**: TEST-01, TEST-03, TEST-04, QUAL-03, API-03
**Success Criteria** (what must be TRUE):
  1. OAuth flow tests cover Google/GitHub profile parsing, token refresh, and session fixation prevention
  2. Parameterized RBAC boundary tests verify every role x scope x action combination with expected allow/deny results
  3. Billing/metering tests verify Stripe webhook handling, usage calculation accuracy, and org limit enforcement
  4. ESLint pre-commit hooks enforce no-console: error and @typescript-eslint/no-explicit-any: error -- commits with violations are rejected
  5. All endpoints have verified org-level rate limits via a rate limiting consistency audit
**Plans**: 3 plans

Plans:
- [ ] 10-01: TBD
- [ ] 10-02: TBD
- [ ] 10-03: TBD

## Progress

**Execution Order:**
Phases execute in numeric order: 1 -> 2 -> 3 -> 4 -> 5 -> 6 -> 7 -> 8 -> 9 -> 10

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Prerequisite Safety Fixes | 2/2 | Complete | 2026-03-25 |
| 2. Dependency Security & Build Hardening | 2/2 | Complete | 2026-03-25 |
| 3. God File Decomposition | 3/3 | Complete | 2026-03-25 |
| 4. Structured Logging & Observability | 0/2 | Not started | - |
| 5. Correlation Engine Hardening | 0/3 | Not started | - |
| 6. Alert Pipeline Hardening | 0/3 | Not started | - |
| 7. Automated Response Safety | 0/2 | Not started | - |
| 8. Connector Health & Resilience | 0/2 | Not started | - |
| 9. API Resilience & Performance | 0/3 | Not started | - |
| 10. Test Coverage & Quality Gates | 0/3 | Not started | - |

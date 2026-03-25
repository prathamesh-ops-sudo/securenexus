# Requirements: SecureNexus — Production Hardening

**Defined:** 2026-03-25
**Core Value:** Every feature that exists in the UI must actually work end-to-end with real data — no stubs, no hardcoded returns, no demo-quality shortcuts.

## v1 Requirements

Requirements for production-hardening milestone. Each maps to roadmap phases.

### Correlation Engine Reliability

- [x] **CORR-01**: Correlation engine wraps all writes in database transactions with appropriate isolation level
- [x] **CORR-02**: Conflict resolution algorithm resolves disagreements between AI semantic, graph-based, and rule-based correlation (weighted scoring with analyst review flag on divergence)
- [x] **CORR-03**: Integration test suite: ingest 10+ alerts across 3 sources and verify correct incident grouping
- [x] **CORR-04**: Unit test suite: each correlation algorithm tested in isolation with mocked storage
- [x] **CORR-05**: Replace `any[]` parameters in graph-correlation.ts and correlation-engine.ts with typed `Alert[]` and `Entity[]` interfaces
- [x] **CORR-06**: Correlation confidence scoring populated meaningfully from algorithm consensus and displayed in incident detail UI

### Automated Response Safety

- [ ] **RESP-01**: Dry-run mode on action dispatcher — validates inputs, checks permissions, logs planned actions without executing
- [ ] **RESP-02**: Action rollback API (`POST /api/incidents/{id}/rollback-actions`) generates and executes reverse operations with full audit trail
- [ ] **RESP-03**: Zod validation schema for each action type (IsolateHost, BlockIP, QuarantineFile, etc.) validated before dispatch
- [ ] **RESP-04**: Every response action writes to audit_logs with action type, parameters, result, duration, and triggering user
- [ ] **RESP-05**: Action dispatcher test suite covering dry-run, rollback, permission checks, and concurrent execution on same incident

### Alert Deduplication & Suppression

- [x] **DEDUP-01**: Temporal deduplication — alerts with same (orgId, source, sourceEventId) within configurable time window update lastSeenAt and increment occurrenceCount instead of creating duplicate
- [ ] **DEDUP-02**: Suppression rules engine — operators can define conditions (source, severity, title pattern, time window) to suppress noisy alerts while preserving data
- [ ] **DEDUP-03**: Dedup/suppression metrics visible on dashboard (how many alerts deduplicated/suppressed per period)

### Connector Health & Failover

- [ ] **CONN-01**: Health check loop per connector (every 60s) reporting healthy/degraded/failed based on last sync time, connection test, error rate
- [ ] **CONN-02**: Auto-restart after 3 consecutive failed polls with exponential backoff (30s, 60s, 120s, max 5min)
- [ ] **CONN-03**: Connector status visible on connectors page with green/yellow/red indicators
- [ ] **CONN-04**: Per-connector circuit breaker — open after 5 failures in 60s, half-open after 30s, close on success

### Test Coverage

- [ ] **TEST-01**: OAuth flow tests covering Google/GitHub profile parsing, token refresh, session fixation prevention
- [ ] **TEST-02**: Connector integration tests covering failure modes (timeout, 401, 403, rate limit) and large paginated results
- [ ] **TEST-03**: RBAC boundary tests — parameterized tests for every role x scope x action = expected allow/deny
- [ ] **TEST-04**: Billing/metering tests — Stripe webhook handling, usage calculation accuracy, org limit enforcement

### Code Quality

- [x] **QUAL-01**: Eliminate `any` types in 41 identified files — replace with explicit TypeScript interfaces (priority: correlation, action dispatcher, auth, AI)
- [ ] **QUAL-02**: Replace 238 console.log/error calls across 78 files with structured `logger.child("module")` calls
- [ ] **QUAL-03**: ESLint pre-commit hooks enforcing `no-console: error` and `@typescript-eslint/no-explicit-any: error`
- [ ] **QUAL-04**: Fix 23 empty catch blocks with proper error handling or explicit logging

### God File Decomposition

- [ ] **SPLIT-01**: Split server/routes/ai.ts (3,542 lines) into domain modules (triage, narrative, correlation, context-optimization, embeddings)
- [ ] **SPLIT-02**: Split server/routes/playbooks.ts (3,541 lines) into domain modules (crud, execution, scheduling, templates)
- [x] **SPLIT-03**: Split server/storage.ts (6,222 lines) into domain modules (alerts, incidents, connectors, auth, etc.) with barrel export for backward compatibility

### Structured Logging & Observability

- [ ] **OBS-01**: All log calls include request correlation ID from async context
- [ ] **OBS-02**: `/api/health` reports subsystem health: DB pool, connector status, job queue depth, AI service availability
- [ ] **OBS-03**: All unhandled errors include request context, org context, and stack trace via error tracker

### API Resilience

- [ ] **API-01**: Connection pool circuit breaker — fail-fast with 503 + Retry-After when pool >80% utilized
- [ ] **API-02**: Graceful degradation on Bedrock failure — AI-dependent features return cached results or "AI unavailable" status, non-AI features unaffected
- [ ] **API-03**: Rate limiting consistency audit — verify all endpoints have appropriate org-level rate limits
- [ ] **API-04**: AI triage endpoints use async job queue processing instead of blocking request thread

### Dependency Security

- [ ] **SEC-01**: Upgrade @xmldom to 1.0.0+ with strict DTD disabling
- [ ] **SEC-02**: Upgrade passport-github2 and passport-google-oauth20 to latest with end-to-end OAuth flow testing
- [ ] **SEC-03**: Upgrade Stripe SDK to latest stable
- [ ] **SEC-04**: API key rotation endpoint — generate new key, deprecate old with 24h grace period, soft-delete
- [ ] **SEC-05**: Move ai_inference_log CREATE TABLE from runtime ai.ts to Drizzle migration

### Performance

- [ ] **PERF-01**: Token budget enforcement for AI narrative generation — count tokens with js-tiktoken, reserve response space, greedily select highest-value RAG chunks
- [ ] **PERF-02**: Async PDF report generation via job queue — return 202 Accepted with job ID, notify via SSE when ready
- [ ] **PERF-03**: Entity graph LRU cache with TTL (5 min), invalidated on entity change events
- [ ] **PERF-04**: Fix AI usage tracking for MSSP billing — query ai_inference_log by period and orgId instead of hardcoded $0
- [ ] **PERF-05**: AI cost attribution per user — add userId to ai_inference_log, audit endpoint for per-user inference spend

### Stub Elimination

- [ ] **STUB-01**: Audit all API endpoints — identify and fix any returning hardcoded/mock data
- [ ] **STUB-02**: AI context-optimization endpoint (currently stub) returns real optimized context
- [ ] **STUB-03**: All dashboard widgets display real aggregated data, not placeholder values

## v2 Requirements

Deferred to future release. Tracked but not in current roadmap.

### Advanced Automation

- **AUTO-01**: Multi-step approval workflows for response actions (analyst proposes, senior approves, system executes)
- **AUTO-02**: ML-based alert suppression learning from resolution patterns

### Scalability

- **SCALE-01**: Read replicas for analytics queries
- **SCALE-02**: Redis-backed distributed job queue
- **SCALE-03**: Multi-pod SSE via Redis pub/sub
- **SCALE-04**: Alert batching for high-volume ingestion (accumulate 100, insert in single transaction)

### Infrastructure

- **INFRA-01**: Multi-region deployment with cross-region failover
- **INFRA-02**: Hot/cold storage (PostgreSQL for 30 days, S3 Parquet for archive)

## Out of Scope

| Feature | Reason |
|---------|--------|
| New connector types | Existing 8 connectors need reliability first |
| New AI models / model switching | Current Bedrock/Mistral stack sufficient, focus on reliability |
| UI redesign or new pages | 28 pages exist, fix backend data quality |
| Multi-region deployment | Infrastructure concern, separate ops milestone |
| Real-time collaboration | SSE exists, collaboration is separate feature milestone |
| Custom detection rule DSL | Scope creep — existing rule-based correlation works |
| Mobile app | SOC analysts use large monitors, web-first |
| GraphQL API | REST + envelope established, migration during hardening is high-risk |
| Kubernetes/EKS config changes | Infrastructure milestone, not code quality |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| QUAL-01 | Phase 1 | Complete |
| QUAL-04 | Phase 1 | Pending |
| SEC-01 | Phase 2 | Pending |
| SEC-02 | Phase 2 | Pending |
| SEC-03 | Phase 2 | Pending |
| SEC-04 | Phase 2 | Pending |
| SEC-05 | Phase 2 | Pending |
| SPLIT-01 | Phase 3 | Pending |
| SPLIT-02 | Phase 3 | Pending |
| SPLIT-03 | Phase 3 | Complete |
| QUAL-02 | Phase 4 | Pending |
| OBS-01 | Phase 4 | Pending |
| OBS-02 | Phase 4 | Pending |
| OBS-03 | Phase 4 | Pending |
| CORR-01 | Phase 5 | Complete |
| CORR-02 | Phase 5 | Complete |
| CORR-03 | Phase 5 | Complete |
| CORR-04 | Phase 5 | Complete |
| CORR-05 | Phase 5 | Complete |
| CORR-06 | Phase 5 | Complete |
| DEDUP-01 | Phase 6 | Complete |
| DEDUP-02 | Phase 6 | Pending |
| DEDUP-03 | Phase 6 | Pending |
| STUB-01 | Phase 6 | Pending |
| STUB-02 | Phase 6 | Pending |
| STUB-03 | Phase 6 | Pending |
| RESP-01 | Phase 7 | Pending |
| RESP-02 | Phase 7 | Pending |
| RESP-03 | Phase 7 | Pending |
| RESP-04 | Phase 7 | Pending |
| RESP-05 | Phase 7 | Pending |
| CONN-01 | Phase 8 | Pending |
| CONN-02 | Phase 8 | Pending |
| CONN-03 | Phase 8 | Pending |
| CONN-04 | Phase 8 | Pending |
| TEST-02 | Phase 8 | Pending |
| API-01 | Phase 9 | Pending |
| API-02 | Phase 9 | Pending |
| API-03 | Phase 10 | Pending |
| API-04 | Phase 9 | Pending |
| PERF-01 | Phase 9 | Pending |
| PERF-02 | Phase 9 | Pending |
| PERF-03 | Phase 9 | Pending |
| PERF-04 | Phase 9 | Pending |
| PERF-05 | Phase 9 | Pending |
| TEST-01 | Phase 10 | Pending |
| TEST-03 | Phase 10 | Pending |
| TEST-04 | Phase 10 | Pending |
| QUAL-03 | Phase 10 | Pending |

**Coverage:**
- v1 requirements: 49 total
- Mapped to phases: 49
- Unmapped: 0

---
*Requirements defined: 2026-03-25*
*Last updated: 2026-03-25 after roadmap creation -- traceability populated*

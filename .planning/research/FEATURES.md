# Feature Landscape

**Domain:** Security Orchestration & Intelligence Platform (SOAR) -- Production Hardening
**Researched:** 2026-03-25
**Overall Confidence:** MEDIUM (training data + extensive codebase analysis; web search unavailable)

## Table Stakes

Features users expect. Missing = platform is unreliable in production.

### Correlation Engine Reliability

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| Transaction-isolated correlation | Concurrent alert ingestion currently corrupts correlation state. Any production SOAR must handle concurrent writes without data loss. | Med | Wrap correlation in `BEGIN...COMMIT` with `SERIALIZABLE` or `REPEATABLE READ` isolation. Retry on serialization failures. |
| Correlation conflict resolution | Three algorithms (AI semantic, graph, rule-based) produce conflicting incident groupings with no tiebreaker. Operators cannot trust results. | Med | Implement weighted scoring: rule-based (highest confidence, deterministic) > graph (entity overlap) > AI semantic (lowest, suggestive). Merge when 2/3 agree, flag divergence for analyst review. |
| Correlation engine test suite | Zero test coverage on the platform's core value proposition. Any regression silently breaks incident detection. | Med | Integration tests: ingest 10+ alerts across 3 sources, verify incident grouping. Unit tests: each algorithm in isolation with mocked storage. |
| Type-safe correlation inputs | `any[]` parameters in graph-correlation.ts mean wrong data shapes cause runtime crashes, not compile-time errors. | Low | Replace `any[]` with `Alert[]` and `Entity[]` interfaces. Zod validation at correlation entry points. |

### Automated Response Safety

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| Dry-run mode for response actions | Production SOAR platforms (Palo Alto XSOAR, Splunk SOAR, Tines) all offer dry-run. Without it, operators fear clicking "Execute Playbook" because actions (isolate host, block IP) are irreversible. | Med | Add `dryRun: boolean` parameter to action dispatcher. In dry-run, validate inputs, check permissions, log what *would* happen, return planned actions without executing. |
| Action rollback mechanism | `response_action_rollbacks` table exists but no API triggers it. False positive incidents with executed actions require manual sysadmin intervention. | Med | `POST /api/incidents/{id}/rollback-actions`: fetch executed actions, generate reverse operations (restore user, unblock IP, unisolate host), execute with full audit trail. |
| Zod validation on action configs | `config: any` in action-dispatcher.ts means a malformed payload can crash the dispatcher or execute wrong action type at runtime. | Low | One Zod schema per action type (IsolateHostConfig, BlockIPConfig, QuarantineFileConfig). Validate before dispatch. |
| Action execution audit trail | Every response action must be fully auditable: who triggered it, what parameters, what outcome, timestamp. Required for SOC2 and incident post-mortems. | Low | Already partially exists via audit_logs. Ensure every action dispatch writes to audit_logs with action type, parameters, result, and duration. |

### Alert Deduplication & Suppression

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| Temporal deduplication (time-window) | Same alert from same source fires every 5 min = 288 duplicates/day. Alert fatigue is the #1 complaint in SOC operations. Every production SIEM/SOAR has this. | Med | If alert with same `(orgId, source, sourceEventId)` arrives within configurable window (default 10 min), update `lastSeenAt` timestamp and increment `occurrenceCount` instead of creating duplicate row. |
| Suppression rules engine | Operators need to silence known-noisy alerts (e.g., "Windows Defender real-time scan" firing 1000x/day) without losing the data. | Med | `suppression_rules` table with conditions (source, severity, title pattern, time window). Suppressed alerts still stored but marked `status: suppressed` and excluded from correlation. |
| Dedup metrics dashboard | Operators need visibility into how many alerts were deduplicated/suppressed to tune rules and prove platform value. | Low | Aggregate counts from dedup/suppression events. Add to existing dashboard stats endpoint. |

### Connector Health & Failover

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| Health check loop per connector | If Splunk connector hangs, no alerts ingest until manual restart. Unacceptable for 24/7 SOC operations. | Med | Periodic health probe (every 60s): check last successful sync time, connection test, error rate. Status: healthy/degraded/failed. |
| Auto-restart on failure | After 3 consecutive failed polls, connector should auto-restart with exponential backoff. | Low | Already have connector job runs tracking. Add failure counter, auto-restart logic with backoff (30s, 60s, 120s, max 5min). |
| Connector status dashboard | SOC operators need at-a-glance view of which data sources are flowing vs. stalled. | Low | Aggregate health check data into existing connectors page. Green/yellow/red status indicators. |
| Circuit breaker on connector APIs | Failing connector should not saturate the connection pool or block other connectors. | Med | Per-connector circuit breaker: open after 5 failures in 60s, half-open after 30s cooldown, close on success. Prevents cascade failures. |

### Test Coverage for Security-Critical Paths

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| Action dispatcher test suite | Safety-critical code with zero test coverage. Untested automated response = liability. | Med | Test dry-run mode, rollback on failure, permission checks, concurrent execution on same incident. |
| OAuth flow tests | Security boundary with `any` types and no tests. Authentication bypass = total compromise. | Med | Test Google/GitHub profile parsing, token refresh, session fixation prevention, scope validation. |
| Connector integration tests | Data integrity boundary. Corrupted ingestion poisons all downstream correlation. | Med | Test failure modes (timeout, 401, 403, rate limit), large paginated results, schema evolution handling. |
| RBAC boundary tests | Already partially covered (rbac.test.ts exists). Expand to cover all permission combinations. | Low | Parameterized tests: every role x every scope x every action = expected allow/deny matrix. |

### Code Quality Enforcement

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| Eliminate `any` types (41 files) | Type safety is the primary defense against runtime crashes in TypeScript. `any` defeats the purpose of using TypeScript. | High | Create explicit interfaces for each function. Priority: correlation engine, action dispatcher, auth session, AI functions. 41 files identified. |
| Replace console.log with structured logger | 238 console calls across 78 files. Production debugging requires structured, searchable, level-aware logs. Console output is lost in container environments. | Low | Mechanical replacement: `console.log()` -> `logger.child("module").info()`, `console.error()` -> `logger.child("module").error()`. Add pre-commit hook to reject new console calls. |
| Pre-commit hook: reject console.log | Prevent regression after cleanup. | Low | Already have Husky + lint-staged. ESLint `no-console: error` (upgrade from `warn`). |
| Pre-commit hook: reject `any` types | Prevent regression after cleanup. | Low | ESLint `@typescript-eslint/no-explicit-any: error` (upgrade from `warn`). May need gradual rollout with file-level overrides. |

### Structured Logging & Observability

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| Consistent child logger usage | Logger infrastructure exists (`server/logger.ts`) but 238 calls bypass it. Every module must use `logger.child("module-name")` for searchable, filterable logs. | Low | Mechanical. Already have logger imported in most files. |
| Request correlation IDs on all logs | `correlationMiddleware` exists but not all log calls include request context. Critical for tracing a request through the system. | Low | Ensure all `logger.child()` calls inherit correlation ID from async context. |
| Health endpoint enrichment | `/api/health` exists. Needs to report subsystem health: DB pool, connector status, job queue depth, AI service availability. | Med | Aggregate health from DB pool stats, connector health checks, job queue table count, Bedrock ping. Return structured health object. |
| Error tracking with context | `error-tracker.ts` exists. Ensure all unhandled errors include request context, org context, and stack trace. | Low | Already partially implemented. Verify all paths feed into error tracker. |

### API Resilience

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| Connection pool circuit breaker | Pool set to max 20. AI inference holds connections during 2-5s Bedrock roundtrips. Pool exhaustion = total API failure. | Med | Fail-fast when pool is saturated (>80% utilized). Return 503 with Retry-After header instead of queuing indefinitely. |
| Graceful degradation on AI failure | Bedrock outage should not prevent alert viewing, incident management, or connector sync. Only AI-dependent features should degrade. | Med | Wrap all Bedrock calls in try-catch. Return cached results or "AI unavailable" status. Feature flags to disable AI features independently. |
| Rate limiting per org (already exists) | Verify existing `org-rate-limit.ts` middleware is applied consistently across all endpoints. | Low | Audit route registration to ensure all endpoints have appropriate rate limits. |
| Request timeout enforcement | `request-timeout.ts` exists (30s). Verify it covers all routes including long-running AI operations. | Low | AI triage endpoints may need longer timeout (60s) or async processing via job queue. |

### Dependency Security

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| Upgrade vulnerable deps | @xmldom 0.8.11 (XXE risk), passport-github2 0.1.12, passport-google-oauth20 2.0.0, Stripe 20.4.0. Known CVEs in production = audit failure. | Med | Upgrade each with targeted testing. OAuth libs need end-to-end flow testing after upgrade. |
| API key rotation mechanism | Keys are SHA-256 hashed (good) but no rotation API. Compromised keys require manual DB intervention. | Med | `POST /api/api-keys/{id}/rotate`: generate new key, return plaintext once, mark old key deprecated with grace period (24h), then soft-delete. |
| Runtime CREATE TABLE removal | `server/ai.ts:61-82` creates table at runtime. Bypasses migration system. Production deployments may fail if DB user lacks DDL permissions. | Low | Move to Drizzle migration. Remove runtime DDL. |

### God File Decomposition

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| Split ai.ts (3,542 lines) | Untestable, unreviewable. Blocks all AI-related changes. | High | Split into `server/routes/ai/triage.ts`, `narrative.ts`, `correlation.ts`, `context-optimization.ts`, `embeddings.ts`. |
| Split playbooks.ts (3,541 lines) | Same problem. Safety-critical code buried in massive file. | High | Split into `server/routes/playbooks/crud.ts`, `execution.ts`, `scheduling.ts`, `templates.ts`. |
| Split storage.ts (6,222 lines) | Every test must mock this monster. Every change risks breaking unrelated queries. | High | Split by domain: `server/storage/alerts.ts`, `incidents.ts`, `connectors.ts`, `auth.ts`, etc. Keep barrel export for backward compatibility. |

## Differentiators

Features that set the platform apart. Not expected, but valued.

| Feature | Value Proposition | Complexity | Notes |
|---------|-------------------|------------|-------|
| Approval workflows for response actions | Most SOAR platforms execute immediately or have simple manual approval. Multi-step approval chains (analyst proposes, senior approves, system executes) reduce false-positive damage. | High | Requires workflow state machine, notification system, approval API. Defer to after safety basics (dry-run, rollback) are solid. |
| Correlation confidence scoring | Instead of binary "correlated/not", show confidence percentage and which algorithms agreed. Analysts can prioritize high-confidence incidents. | Med | Already have `correlationScore` field. Populate it meaningfully from algorithm consensus. Display in incident detail UI. |
| AI cost attribution per user | Track which analysts run expensive AI operations. Enables chargeback, usage fairness, budget enforcement per team. | Med | Add `userId` to `ai_inference_log`. Already have token counting via js-tiktoken. Sum by user for billing dashboard. |
| Intelligent alert suppression with ML | Beyond rule-based suppression: learn which alerts are consistently closed without action and auto-suppress after pattern detection. | High | Requires training data (alert + resolution pairs). Could use Bedrock embeddings for similarity. Defer until manual suppression rules prove value. |
| Connector schema evolution detection | When upstream APIs change field names/types, detect and alert rather than silently ingesting malformed data. | Med | Compare incoming alert schema against expected schema per connector. Log warnings on drift. Auto-adapt where possible. |
| Token budget enforcement for AI | Prevent context window exhaustion during narrative generation with 100+ alerts. Intelligently select most relevant context within budget. | Med | js-tiktoken already in deps. Count tokens, reserve space for response, greedily select highest-value RAG chunks. Critical for reliability but not common in competing platforms. |
| Async PDF generation via job queue | Return job ID immediately, notify via SSE when ready. Eliminates 10-30s blocking on report generation. | Med | Job queue infrastructure exists. Move PDF rendering to job worker. Return `202 Accepted` with job ID. |
| Entity graph LRU cache | Cache computed entity relationships with TTL. Eliminates 5s+ dashboard loads on repeat visits. | Med | In-memory LRU (query-cache.ts pattern exists). Invalidate on entity change events. |

## Anti-Features

Features to explicitly NOT build during this hardening milestone.

| Anti-Feature | Why Avoid | What to Do Instead |
|--------------|-----------|-------------------|
| New connector types | Existing 8 connectors need to work reliably first. Adding #9 while #1-8 are fragile compounds the problem. | Harden existing connectors with health checks, failover, and integration tests. |
| New AI models / model switching | Bedrock + Mistral/Claude stack is sufficient. Model diversity adds complexity without reliability gains. | Focus on making current AI calls reliable: error handling, token budgets, graceful degradation. |
| UI redesign or new pages | 28 pages exist. Visual polish does not fix backend reliability. | Fix backend data quality so existing pages show real, trustworthy data. |
| Multi-region deployment | Infrastructure concern, not code quality. Adds massive complexity for marginal reliability gain at current scale. | Ensure single-region is rock-solid first. Document multi-region as future ops milestone. |
| Real-time collaboration (multi-user editing) | Nice-to-have but not reliability-related. Adds WebSocket complexity during a hardening sprint. | SSE event stream already provides real-time updates. Collaboration is a separate feature milestone. |
| Custom detection rule language / DSL | Tempting but scope creep. Rule-based correlation already works. A DSL is a product feature, not a hardening task. | Ensure existing rule-based correlation is tested and reliable. |
| Mobile app or responsive redesign | Web-first platform. SOC analysts work on large monitors. Mobile adds testing surface without hardening value. | Keep desktop-optimized. |
| GraphQL API | REST + envelope pattern is established. GraphQL migration during hardening is high-risk refactoring. | Ensure REST API is consistent, documented (OpenAPI spec exists), and resilient. |
| Kubernetes/EKS config changes | Infrastructure milestone, not code quality. Mixing infra and code changes in one milestone is a recipe for confusion. | Keep deployment config stable. Focus on application-level reliability. |

## Feature Dependencies

```
Correlation Transaction Isolation --> Correlation Conflict Resolution
  (must have safe writes before adding merge logic)

Correlation Conflict Resolution --> Correlation Confidence Scoring
  (need scoring to expose confidence meaningfully)

Zod Action Validation --> Dry-Run Mode --> Rollback Mechanism --> Approval Workflows
  (safety chain: validate inputs, then preview, then undo, then gate)

Temporal Deduplication --> Suppression Rules Engine --> ML-Based Suppression
  (start simple, add rules, then learn patterns)

Connector Health Checks --> Auto-Restart --> Circuit Breaker
  (must detect failure before reacting to it)

Eliminate any Types --> Pre-commit Hook (reject any)
  (clean up before enforcing)

Console.log Replacement --> Pre-commit Hook (reject console)
  (clean up before enforcing)

God File Splits --> Targeted Test Suites
  (smaller files are testable; monoliths are not)

Vulnerable Dep Upgrades --> OAuth Flow Tests
  (test after upgrading passport libs)

Connection Pool Circuit Breaker --> Graceful AI Degradation
  (pool protection enables selective feature degradation)

AI Cost Attribution --> Token Budget Enforcement
  (track costs, then enforce budgets)
```

## MVP Recommendation

Prioritize (in this order):

1. **Correlation engine transaction isolation + conflict resolution** -- Core value. Without reliable correlation, the platform's primary feature is untrustworthy.

2. **Eliminate `any` types in critical paths** -- Type safety in correlation engine, action dispatcher, and auth is prerequisite for safe refactoring.

3. **Action dispatcher safety chain** -- Zod validation, dry-run mode, rollback. Operators must trust automated response before they will use it.

4. **Structured logging cleanup** -- Replace 238 console calls. Fast, mechanical, enables production debugging for everything that follows.

5. **Correlation engine + action dispatcher test suites** -- Prove the critical paths work. Without tests, every subsequent change is a gamble.

6. **Temporal alert deduplication** -- Reduces alert fatigue and improves correlation accuracy by eliminating noise.

7. **Connector health monitoring + auto-restart** -- Ensures data keeps flowing without manual intervention.

8. **God file decomposition** -- Unblocks testability and maintainability for all future work.

9. **Vulnerable dependency upgrades** -- Required for any security audit. Lower priority than functional reliability because current versions work.

10. **API resilience (circuit breakers, graceful degradation)** -- Polish for production readiness. Prevents cascade failures under load.

Defer:
- **Approval workflows**: High complexity, requires dry-run and rollback first. Phase 2+ feature.
- **ML-based suppression**: Needs training data from manual suppression rules running in production first.
- **Async PDF generation**: Quality-of-life improvement, not reliability-critical.
- **Entity graph caching**: Performance optimization, not correctness.

## Confidence Notes

| Area | Confidence | Reason |
|------|------------|--------|
| Table stakes features | HIGH | Derived directly from codebase analysis (CONCERNS.md) cross-referenced with standard SOAR platform capabilities (Palo Alto XSOAR, Splunk SOAR, Tines, Swimlane patterns from training data) |
| Differentiators | MEDIUM | Based on training data knowledge of competing platforms. Could not verify latest feature sets via web search. |
| Anti-features | HIGH | Directly aligned with PROJECT.md out-of-scope decisions and hardening milestone goals |
| Complexity estimates | MEDIUM | Based on codebase structure analysis. Actual effort depends on hidden coupling in god files. |
| Feature dependencies | HIGH | Derived from logical analysis of the codebase and feature relationships |

## Sources

- `.planning/PROJECT.md` -- Project requirements and scope
- `.planning/codebase/CONCERNS.md` -- Detailed issue inventory with file paths and severity
- `.planning/codebase/ARCHITECTURE.md` -- System structure and data flows
- `.planning/codebase/TESTING.md` -- Current test patterns and coverage gaps
- `.planning/codebase/CONVENTIONS.md` -- Coding standards and patterns
- `.planning/codebase/STACK.md` -- Technology inventory
- Training data knowledge of SOAR platforms (Palo Alto XSOAR, Splunk SOAR, Tines, Swimlane) -- MEDIUM confidence, not verified against current docs

---

*Feature landscape: 2026-03-25*

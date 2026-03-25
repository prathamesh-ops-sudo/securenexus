# Project Research Summary

**Project:** SecureNexus Production Hardening
**Domain:** Security-critical SaaS platform — production readiness, testing, and reliability
**Researched:** 2026-03-25
**Confidence:** MEDIUM-HIGH (codebase analysis HIGH; library version numbers need `npm info` verification before installation)

## Executive Summary

SecureNexus is a mature full-stack security orchestration platform with strong foundational choices already in production: structured logging with deep redaction, graceful shutdown, Prometheus metrics, distributed tracing, rate limiting, and an EKS-based canary deployment pipeline. This hardening effort is not a rebuild — it is closing specific reliability gaps that become blocking issues as the platform scales beyond a single pod replica. The research identifies five categories of work: shared state migration (Redis), test infrastructure uplift, code quality gates, production runtime configuration, and a safe refactoring path for the monolithic storage layer.

The recommended approach is to sequence work by risk rather than feature value. The most dangerous problems are currently invisible: 23 empty catch blocks that silently swallow errors in auth, AI, and outbox-processor paths; a 6,222-line `storage.ts` god object that 110+ files import directly; and 4 in-memory state stores that will cause split-brain failures as soon as EKS HPA scales beyond one pod. These must be addressed before reliability can be claimed. Standard improvements (dependency scanning in CI, memory limits in the Dockerfile, coverage threshold increases) can proceed in parallel and are low-risk with high safety yield.

The key risk in this project is not technological — the stack is sound. The risk is execution order. Attempting storage refactoring before establishing a barrel-file facade breaks 110+ import paths simultaneously. Touching auth without feature flags forces a mass logout of production users. Adding database tests without transaction isolation creates flaky CI that erodes team confidence. Every phase below is ordered to prevent the next phase from being blocked by a self-inflicted failure.

## Key Findings

### Recommended Stack

The existing stack requires no replacement. The research verdict is "harden what exists, add only what is missing." The one new production dependency is Redis (via `ioredis`) for shared state that must be consistent across pods. New dev dependencies include `supertest` for integration testing the real middleware stack, `fast-check` for property-based fuzzing of the normalizer and PII engine, `eslint-plugin-security` for lint-time vulnerability detection, and `knip` for dead code elimination. The TypeScript upgrade to 5.7+ enables `--isolatedDeclarations` for faster builds and activates `noUncheckedIndexedAccess` for catching silent undefined access.

**Core technologies and decisions:**
- `ioredis` (production): Redis client for shared circuit-breaker, rate-bucket, and SLO-cooldown state — required for multi-pod correctness
- AWS RDS Proxy (infrastructure): Managed connection pooler; preferred over PgBouncer because SecureNexus is already fully in AWS and the operational burden of a sidecar is unnecessary
- `supertest` (dev): HTTP integration tests against the real Express app without `listen()` — tests the actual middleware chain including auth, CSRF, and rate limiting
- `fast-check` (dev): Property-based testing for normalizer inputs (24+ source formats), PII detection patterns, and API validation boundaries
- `eslint-plugin-security` (dev): Detects `eval()`, prototype pollution, non-literal RegExp at lint time — essential for a security product
- `knip` (dev): Dead code detection; `storage.ts` at 244KB likely contains significant unused exports
- Keep custom `logger.ts`: Already has AsyncLocalStorage propagation, 17+ redaction patterns, and child logger isolation. Pino migration is explicitly ruled out — migration cost exceeds marginal serialization gain at current scale.
- No `node:cluster`: EKS HPA handles horizontal scaling. Clustering inside pods conflicts with the graceful shutdown already correctly implemented.

### Expected Features

The feature research identifies a clear priority stack for production safety. The table-stakes items are blocking — they represent either outage risks or trust failures for a security product.

**Must have (table stakes — blocking production safety):**
- Zero `console.log` in server code — security platforms cannot emit unstructured debug output; 24 occurrences remain in 8 files
- Dependency vulnerability gate in CI — `npm audit --audit-level=high` in GitHub Actions; a security platform shipping known vulns is a trust failure
- Redis for shared state — 4 `scaling-state.ts`-identified stores break at >1 pod; blocks EKS HPA scale-out
- Memory limits in Dockerfile — `--max-old-space-size` prevents OOM kills causing mid-request data loss
- Source maps in production builds — without them, stack traces point to bundled line numbers, making production debugging impossible
- RBAC boundary test coverage — every endpoint verified with every role (owner/admin/analyst/read_only)
- Org isolation test coverage — every storage query proven to scope by `orgId`; multi-tenant data leak is catastrophic

**Should have (differentiators — elevate quality):**
- Property-based testing on the normalizer (24+ source format parsers)
- Dead code elimination via `knip` scan and pruning
- Security-specific ESLint rules (`eslint-plugin-security`)
- Runtime log-level control via `LOG_LEVEL` env var (no redeployment to change verbosity)
- Read replica routing for analytics and dashboard queries
- Supertest API contract tests verifying real middleware behavior
- License compliance check in CI (`license-checker --failOn "GPL-3.0;AGPL-3.0"`)
- Heap memory Prometheus metric via `process.memoryUsage()`

**Defer to v2+:**
- Read replica routing — the current 20-connection pool is adequate for moderate load; implement when analytics query latency becomes a complaint
- Snyk paid tier — `npm audit` + Dependabot covers the security surface; Snyk adds cost without proportional benefit at current scale
- Pino logger migration — explicitly ruled out; custom logger already meets all requirements

### Architecture Approach

The architecture is a well-structured Express monolith with domain-separated route files (110+) but a single god-object storage layer (`server/storage.ts`, 6,222 lines, imported by 49+ files). The production hardening target is not microservices — it is domain-aligned storage modules behind a barrel re-export facade that preserves all existing import paths during the transition. No existing data flows change. Alert ingestion, correlation, and incident management pipelines remain identical. The changes are additive: Redis replaces in-memory Maps for 4 specific stores, a `readDb` pool optionally routes analytics queries to a replica, and CI gets enforcement gates.

**Major components and their hardening responsibilities:**
1. `server/storage.ts` — split into domain modules (`storage/alerts.ts`, `storage/incidents.ts`, etc.) behind a `storage/index.ts` barrel; migrate one domain at a time
2. `server/scaling-state.ts` — source of truth for which stores need Redis migration; follow its `needs-shared-store` tags exactly; do not over-migrate
3. `server/db.ts` — add `readDb` pool pointing to RDS read replica; reduce per-pod pool size from 20 to 10 (RDS Proxy absorbs the actual DB connection pool)
4. `server/logger.ts` — add `LOG_LEVEL` env var support, fix 24 `console.log` calls, add high-volume path sampling; do not replace
5. `server/prometheus.ts` — add `process.memoryUsage()` and `process.cpuUsage()` metrics for OOM detection
6. `.github/workflows/` — add `npm audit`, `license-checker`, coverage enforcement gates
7. `Dockerfile` — add `--max-old-space-size=1536 --enable-source-maps` to CMD; enable `sourcemap: true` in `script/build.ts`
8. `vitest.config.ts` / test suite — raise thresholds, add transaction-isolated storage tests, typed mocks, RBAC boundary tests

### Critical Pitfalls

1. **Storage split without a barrel facade breaks 110+ import paths simultaneously** — create `server/storage/index.ts` that re-exports everything before moving any function; split one domain per PR; never defer mock path updates to a separate PR
2. **Empty catch blocks swallow errors during hardening** — audit and fix all 23 empty catches before any other work begins; add `logger.warn()` at minimum; add ESLint `no-empty` rule to prevent regression
3. **Database migrations without lock safety cause production outages** — never use `drizzle-kit push` in production; always use `CREATE INDEX CONCURRENTLY`; always set `lock_timeout = '5s'` in migration scripts; test against production-sized data
4. **Auth session refactoring triggers mass logout** — any change to `server/auth/session.ts` serialization must support both old and new formats simultaneously; deploy behind a feature flag; fix `CachedUser: any` type first to make breaking changes compile-visible
5. **Real-database storage tests without transaction isolation create flaky CI** — wrap each test in a `BEGIN`/`ROLLBACK` transaction; run storage tests serially (`singleFork`); use a separate test database with a 2-3 connection pool

## Implications for Roadmap

Based on combined research, the recommended phase structure is ordered by risk dependencies, not feature desirability. Each phase must be stable before the next begins.

### Phase 0: Prerequisite Safety Fixes
**Rationale:** The 23 empty catch blocks are a prerequisite for all other work — they make it impossible to trust that refactoring changes are working. Any behavior change during hardening may be silently swallowed. Fix these before touching anything else.
**Delivers:** Visible error surface; trustworthy test signals; audit-ready code
**Addresses:** Console.log elimination, empty catch remediation, `CachedUser: any` type fix
**Avoids:** Pitfall 5 (silent catch blocks swallowing hardening bugs); Pitfall 6 (cascading type errors when `as any` is removed without interfaces first)
**Research flag:** Standard patterns — no deeper research needed

### Phase 1: CI and Build Hardening
**Rationale:** CI gates and Dockerfile configuration are low-risk, high-yield, and unblock every subsequent phase. Getting `npm audit`, coverage enforcement, and source maps in place means all future phases operate with safety nets. Establish the migration safety protocol here before any schema changes occur.
**Delivers:** Dependency vulnerability gate, license compliance check, source maps in production, memory limits in Dockerfile, heap memory Prometheus metric, migration safety protocol documented
**Addresses:** All FEATURES.md table-stakes items that are configuration-only (no code refactoring required)
**Avoids:** Pitfall 14 (pool exhaustion during migrations — establish migration safety protocol in this phase)
**Research flag:** Standard patterns — well-documented CI and Docker practices

### Phase 2: Test Infrastructure Foundation
**Rationale:** Before splitting storage or touching auth, a reliable test infrastructure must exist. The current 7-file test suite with 10% thresholds and untyped mocks provides false safety. This phase establishes the isolation patterns that all subsequent test additions depend on.
**Delivers:** Transaction-isolated storage test infrastructure, typed mock pattern, supertest integration test scaffolding, coverage thresholds raised to 30%
**Addresses:** FEATURES.md — supertest API contract tests, RBAC boundary test scaffolding
**Avoids:** Pitfall 4 (flaky CI from real-DB tests); Pitfall 9 (false safety from untyped mocks)
**Research flag:** Verify supertest compatibility with Express 5 async error handling before committing to the integration test pattern

### Phase 3: Redis Shared State Migration
**Rationale:** Redis is a hard dependency for EKS HPA scale-out. Until the 4 `needs-shared-store` items in `scaling-state.ts` are migrated, the platform cannot safely run more than one pod replica. This is a blocking correctness issue, not a nice-to-have.
**Delivers:** Redis/ElastiCache deployment, circuit-breaker state migrated to Redis, webhook rate-bucket state migrated to Redis, SLO breach cooldown migrated to Redis, AI circuit-breaker state migrated to Redis
**Addresses:** FEATURES.md table stake — Redis for shared state; unblocks EKS HPA
**Avoids:** Split-brain state causing duplicate alerts or false-positive circuit trips at >1 pod
**Research flag:** Verify ElastiCache single-node vs. cluster-mode sizing at actual traffic volumes; `ioredis` version confirmed stable

### Phase 4: Storage Layer Refactoring
**Rationale:** The 6,222-line god object is a long-term maintainability risk and the most complex refactoring in the project. It must come after tests exist (Phase 2) so every split can be verified, and after Redis is stable (Phase 3) so there are no competing infrastructure changes.
**Delivers:** `server/storage/` domain modules with barrel facade; all existing import paths preserved; one domain migrated per PR in sequence (alerts, incidents, connectors, compliance, threat-intel)
**Addresses:** ARCHITECTURE.md — domain-aligned storage modules; code reviewability
**Avoids:** Pitfall 1 (cascading import breakage across 110+ files); Pitfall 10 (Drizzle ORM/Kit version mismatch — upgrade both together in this phase)
**Research flag:** Verify Drizzle `withReplicas()` API compatibility with the currently installed `drizzle-orm` version before including read replica routing in this phase

### Phase 5: Auth and Security Hardening
**Rationale:** Auth changes have the highest blast radius in the codebase. They must be done in complete isolation from other refactoring, after test infrastructure exists to verify behavior, and with feature flags for gradual production rollout.
**Delivers:** Feature-flagged auth session safety, `CachedUser` type made concrete (no `as any`), RBAC boundary tests at 70% coverage for auth module, org isolation tests for all storage query paths, ESLint `strict-type-checked` preset enabled
**Addresses:** FEATURES.md — RBAC boundary test coverage, org isolation test coverage
**Avoids:** Pitfall 3 (mass session logout from serialization format change); Pitfall 7 (middleware order breakage from Passport upgrades)
**Research flag:** Needs research — verify Passport.js 0.7+ serialization behavior changes and `connect-pg-simple` major version compatibility before upgrading; Google/GitHub OAuth callback sensitivity to session ordering must be tested

### Phase 6: Code Quality Uplift
**Rationale:** ESLint hardening, dead code elimination, and property-based testing are valuable but not blocking. They belong after structural work is stable and the test suite provides confidence.
**Delivers:** `eslint-plugin-security` enabled, `no-console` escalated to error, `knip` dead code scan and prune, `fast-check` property tests on normalizer and PII engine, TypeScript upgraded to 5.7+, `noUncheckedIndexedAccess` enabled, coverage thresholds raised to 50% overall and 70% for security modules
**Addresses:** FEATURES.md differentiators — dead code elimination, property-based testing, security-specific ESLint rules
**Avoids:** Pitfall 6 (cascading type errors — approach `as any` removal one module at a time with interfaces defined first); Pitfall 8 (logger replacement — this phase explicitly does NOT replace the logger)
**Research flag:** Standard patterns — TypeScript 5.7 migration is well-documented official material

### Phase Ordering Rationale

- Phase 0 before everything: empty catches make all other work untrustworthy; cannot verify any change is working
- Phase 1 (CI) before refactoring: safety nets must exist before structural changes begin; migration safety protocol blocks any schema work
- Phase 2 (tests) before storage split: the split must be verifiable; tests are the verification mechanism
- Phase 3 (Redis) before auth: no competing infrastructure risk during the highest-blast-radius phase; Redis unlocks EKS HPA scale-out
- Phase 4 (storage split) before auth: storage must be stable before auth refactoring changes the storage queries it depends on
- Phase 5 (auth) isolated: highest blast radius, never combined with other structural changes
- Phase 6 (quality) last: incremental improvement, does not block production safety

### Research Flags

Phases needing deeper research during planning:
- **Phase 2:** Verify supertest + Express 5 compatibility; confirm app factory extraction from `server/index.ts` is straightforward
- **Phase 3:** Verify ElastiCache sizing (single-node vs. cluster-mode) and confirm SSE cross-pod broadcasting via Redis Pub/Sub is in scope for this phase
- **Phase 4:** Verify Drizzle `withReplicas()` API is compatible with currently installed version before including read replica routing
- **Phase 5:** Verify Passport.js 0.7+ and `connect-pg-simple` compatibility; confirm OAuth callback behavior under any session middleware changes

Phases with standard patterns (skip research-phase):
- **Phase 0:** Empty catch audit and type annotation are standard refactoring with no library dependencies
- **Phase 1:** `npm audit` CI integration and Docker CMD flags follow official documentation
- **Phase 6:** TypeScript 5.7 migration follows official release notes; `knip` has stable documented API

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | MEDIUM | Architecture decisions are HIGH (direct codebase analysis); exact library version numbers are LOW — verify all with `npm info [package] version` before installation; WebSearch was unavailable during research |
| Features | HIGH | Based on direct codebase analysis identifying specific gaps: exact counts confirmed (23 empty catches, 24 console.log calls, 4 needs-shared-store items, 74+ `as any` casts) |
| Architecture | HIGH | Based on direct file analysis of `storage.ts` (6,222 lines), `scaling-state.ts` (store registry), `server/index.ts` (middleware order), `shared/schema.ts` (80+ tables). No inference required. |
| Pitfalls | HIGH | Based on grep analysis confirming exact counts, direct code reading of risky paths, and established PostgreSQL/Express/Passport documented behaviors |

**Overall confidence:** MEDIUM-HIGH

The analysis is grounded in direct codebase reading, which is the most reliable source available. The only material uncertainty is library version numbers, which change over time and must be verified with `npm info` before installation. All architectural recommendations are derived from the actual code.

### Gaps to Address

- **Drizzle `withReplicas()` compatibility:** Research flags this as LOW confidence due to Drizzle's fast-moving version cadence. Verify against the exact installed version before committing read-replica routing to the Phase 4 plan.
- **RDS Proxy latency overhead:** Research cites ~15% latency overhead vs. PgBouncer. This is acceptable given operational simplicity, but should be measured against actual p99 latency requirements once load testing data is available.
- **SSE cross-pod broadcasting:** At 3+ pods, server-sent events (`/api/events`) require Redis Pub/Sub for cross-pod broadcast. Documented in ARCHITECTURE.md scalability table but not assigned to a phase. Assign explicitly to Phase 3 if multi-pod rollout is imminent.
- **TypeScript 5.8 availability:** STACK.md references 5.8 as potentially available. Verify actual release status with `npm info typescript version` and target the latest stable 5.x.
- **All library version numbers:** Every version number in STACK.md was generated from training data. Verify each with `npm info [package] version` before `npm install`.

## Sources

### Primary (HIGH confidence — direct codebase analysis)
- `server/storage.ts` — 6,222 lines, 49+ importers confirmed via grep
- `server/scaling-state.ts` — 4 stores tagged `needs-shared-store`, upgrade paths documented inline
- `server/auth/session.ts` — `CachedUser` type with `any`, deserialize cache logic, auto-promote superadmin on deserialize
- `server/logger.ts` — AsyncLocalStorage propagation, 17+ redaction patterns, child logger API
- `shared/schema.ts` — 80+ table definitions (12,814 lines), migration risk surface
- `server/db.ts` — pool configuration (max 20, min 4, idle 30s, statement_timeout 30s)
- `server/index.ts` — middleware registration order
- `vitest.config.ts` — 10% coverage threshold confirmed
- Grep results — 74+ `as any` occurrences, 23 empty catch blocks across 9 files, 24 `console.log` calls in 8 files (specific locations documented in PITFALLS.md)

### Secondary (MEDIUM confidence — established documentation)
- PostgreSQL `ACCESS EXCLUSIVE` lock behavior during DDL — well-documented standard behavior
- Express 5 async error handling changes — documented in official Express 5 migration guide
- Passport.js 0.7+ serialization changes — documented in Passport changelog
- `ioredis` vs `node-redis` comparison — community consensus across multiple sources
- AWS RDS Proxy latency characteristics — AWS official documentation

### Tertiary (LOW confidence — version-sensitive, verify before use)
- All library version numbers in STACK.md — training data may be stale; verify with `npm info [package] version`
- Drizzle `withReplicas()` API stability — was in active development as of research; verify against installed version
- TypeScript 5.8 availability — may not be released; target 5.7 as confirmed stable baseline

---
*Research completed: 2026-03-25*
*Ready for roadmap: yes*

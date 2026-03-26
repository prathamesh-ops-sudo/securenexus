# Technology Stack: Production Hardening

**Project:** SecureNexus Production Hardening
**Researched:** 2026-03-25
**Overall Confidence:** MEDIUM (WebSearch unavailable; recommendations based on training data verified against existing codebase analysis)

## Current State Assessment

SecureNexus already has significant production infrastructure in place. This research focuses on gaps and improvements, not re-building what works.

### What Already Works Well (Keep As-Is)

| Component | Current | Verdict |
|-----------|---------|---------|
| Structured Logger | Custom `server/logger.ts` with AsyncLocalStorage, JSON output, deep redaction, correlation IDs | Sufficient. Custom logger is well-designed. Pino migration is optional, not urgent. |
| Connection Pooling | `pg.Pool` with health monitoring, statement timeouts, utilization alerts | Sufficient for single-instance. Needs PgBouncer for multi-pod. |
| Graceful Shutdown | `scaling-state.ts` handler registry, `request-lifecycle.ts` in-flight drain | Well-implemented. |
| TypeScript Strict | `strict: true` already enabled in tsconfig.json | Good baseline. |
| Rate Limiting | `express-rate-limit` per-IP and per-org | Solid. |
| Security Headers | `helmet` v8 | Current. |
| Testing | Vitest 4.x + Playwright 1.58 + coverage | Solid framework in place. |
| Linting | ESLint 9 flat config + typescript-eslint + Prettier + Husky | Modern setup. |
| Metrics | Prometheus + custom SLI/SLO | Already production-grade. |
| Tracing | Jaeger-compatible distributed tracing | Present. |

## Recommended Additions

### 1. Structured Logging Improvements

**Current gap:** 24 `console.log` calls remain in 8 server files. Custom logger works but lacks log shipping.

| Technology | Version | Purpose | Why | Confidence |
|------------|---------|---------|-----|------------|
| Keep custom `logger.ts` | N/A | Structured JSON logging | Already has redaction, AsyncLocalStorage context, child loggers. Replacing with Pino gains marginal perf at high migration cost for 230-line custom logger that works well. | HIGH |
| `eslint-plugin-no-console` (via existing `no-console` rule) | Built-in | Eliminate remaining console.log | Already configured as `warn` in ESLint. Upgrade to `error` to enforce. Zero new deps. | HIGH |
| Log shipping via stdout | N/A | CloudWatch/Datadog ingestion | Logger already writes JSON to stdout/stderr. K8s FluentBit sidecar or CloudWatch agent picks this up. No code changes needed. | HIGH |

**Decision: Do NOT migrate to Pino.** The custom logger already handles structured JSON, redaction of 20+ sensitive patterns, AsyncLocalStorage context propagation, and child logger isolation. Pino would provide ~10% faster serialization which is irrelevant at current scale. The migration cost (touching every file that imports logger) outweighs the benefit.

**Do instead:**
1. Fix the 24 remaining `console.log` calls in 8 files
2. Escalate ESLint `no-console` rule from `warn` to `error`
3. Add log level filtering via `LOG_LEVEL` environment variable (currently hardcoded by NODE_ENV)
4. Add log sampling for high-volume debug paths (correlation engine, connector sync)

### 2. TypeScript Strict Mode Hardening

**Current gap:** `strict: true` is on, but `@typescript-eslint/no-explicit-any` is only `warn`. Test files heavily use `as any`.

| Technology | Version | Purpose | Why | Confidence |
|------------|---------|---------|-----|------------|
| typescript | 5.7+ | Upgrade from 5.6.3 | 5.7 adds `--isolatedDeclarations` for faster builds and better DX. 5.8 (if available) adds further strictness. | MEDIUM |
| `@typescript-eslint/strict-type-checked` | Bundled with typescript-eslint 8.x | Stricter type rules | Adds `no-unsafe-argument`, `no-unsafe-assignment`, `no-unsafe-call`, `no-unsafe-member-access`, `no-unsafe-return`. These catch real bugs in a security platform. | HIGH |
| `eslint-plugin-security` | ^3.0.0 | Security-specific lint rules | Detects `eval()`, non-literal RegExp, `child_process` misuse, prototype pollution patterns. Essential for a security product. | MEDIUM |
| `knip` | ^5.0.0 | Dead code detection | Finds unused exports, files, dependencies. Large codebase (storage.ts is 244KB) likely has dead code. | HIGH |

**TypeScript strict progression:**
1. Phase 1: Upgrade to TS 5.7+, enable `noUncheckedIndexedAccess` in tsconfig
2. Phase 2: Escalate `no-explicit-any` to `error` in production code (keep `warn` in test files)
3. Phase 3: Enable `strict-type-checked` eslint preset
4. Phase 4: Run `knip` to find and remove dead exports

### 3. Connection Pooling & Database Hardening

**Current gap:** Direct `pg.Pool` with max 20 connections. No read replicas. No external connection pooler.

| Technology | Version | Purpose | Why | Confidence |
|------------|---------|---------|-----|------------|
| PgBouncer | 1.23+ | External connection pooler | With multi-pod EKS deployment, each pod opens 20 connections. 3 pods = 60 connections. PgBouncer in transaction mode pools these down to ~20 actual DB connections. Deploy as sidecar or shared service. | HIGH |
| AWS RDS Proxy | Managed | Alternative to PgBouncer | Managed connection pooler for RDS. Zero operational overhead but ~15% latency overhead vs PgBouncer. Supports IAM auth. Choose this if ops team is small. | HIGH |
| Read replica routing | N/A | Offload read queries | Add a `readDb` pool pointing to RDS read replica for analytics, dashboard stats, entity graph queries. Keep `db` for writes. | MEDIUM |
| `drizzle-orm` read replica support | 0.39+ | Built-in read/write split | Drizzle supports `withReplicas()` for automatic read/write routing. Verify with current version. | LOW |

**Recommendation: Use AWS RDS Proxy** because SecureNexus is already all-in on AWS (EKS, Bedrock, S3, SES). RDS Proxy eliminates PgBouncer operational burden and integrates with IAM for passwordless DB auth.

**Connection pool tuning for production:**
```
Current: max=20, min=4, idle=30s, statement_timeout=30s
Recommended: max=10 (per pod, let RDS Proxy handle pooling), min=2, idle=10s
```
With RDS Proxy, each pod should use fewer connections since the proxy handles the actual DB connection pool.

### 4. Node.js Production Hardening

**Current gap:** No clustering (single process per pod). Memory limits rely on K8s resource limits only. No heap monitoring.

| Technology | Version | Purpose | Why | Confidence |
|------------|---------|---------|-----|------------|
| Node.js `--max-old-space-size` | Built-in | Heap memory limit | Set to 75% of K8s container memory limit. Prevents OOM kill by triggering GC pressure before K8s kills the pod. | HIGH |
| `--enable-source-maps` | Built-in | Production stack traces | The app builds to `dist/index.cjs` via esbuild. Without source maps, stack traces point to bundled code. | HIGH |
| `clinic.js` | ^14.0.0 | Performance profiling (dev dep) | Flame graphs, event loop analysis for debugging production perf issues. Not shipped to production. | MEDIUM |
| `node:cluster` | Built-in | Multi-process | NOT recommended. EKS horizontal pod autoscaling is the correct scaling mechanism. Clustering inside a pod complicates graceful shutdown (already implemented) and K8s health checks. | HIGH (not to use) |

**Do NOT use Node.js clustering.** The codebase already handles horizontal scaling via EKS with Argo Rollouts canary deployments. Clustering adds complexity to the already-correct pattern of "one process per pod, scale pods horizontally."

**Node.js flags for production Dockerfile:**
```dockerfile
CMD ["node", "--max-old-space-size=1536", "--enable-source-maps", "dist/index.cjs"]
```

**Additional hardening:**
- Add `process.memoryUsage()` to the existing Prometheus metrics endpoint
- Set `--max-http-header-size=16384` (default 16KB is fine, but be explicit)
- Enable `UV_THREADPOOL_SIZE=16` for workloads with filesystem/DNS operations (connector syncs, report PDF generation)

### 5. Dependency Audit & Vulnerability Scanning

**Current gap:** No automated dependency scanning in CI. `npm audit` exists but is not enforced.

| Technology | Version | Purpose | Why | Confidence |
|------------|---------|---------|-----|------------|
| `npm audit --audit-level=high` | Built-in | CI pipeline gate | Free, zero config. Block merges on high/critical vulns. Already available. | HIGH |
| Socket.dev GitHub App | SaaS | Supply chain attack detection | Goes beyond CVEs -- detects typosquatting, install scripts, network access, telemetry in dependencies. For a security platform, this matters. Free for open source. | MEDIUM |
| `better-npm-audit` | ^3.11.0 | Allowlist known issues | Wraps `npm audit` with exception management. Lets you acknowledge accepted risks without breaking CI. | MEDIUM |
| Dependabot | GitHub native | Automated dependency PRs | Already available in GitHub. Configure for security updates only (not version bumps) to reduce noise. | HIGH |
| Snyk | SaaS | Deep vuln scanning | Most comprehensive DB but expensive. Use only if Socket.dev + npm audit is insufficient. | LOW |
| `license-checker` | ^25.0.0 | License compliance | Ensure no GPL/AGPL deps in a commercial SaaS product. Run in CI. | MEDIUM |

**Recommended CI pipeline additions:**
```yaml
# In GitHub Actions
- npm audit --audit-level=high --omit=dev
- npx license-checker --failOn "GPL-3.0;AGPL-3.0"
```

**Do NOT use Snyk** unless Socket.dev proves insufficient. Snyk's free tier is limited, and `npm audit` + Socket.dev covers the vast majority of supply chain risks for Node.js.

### 6. Testing for Security-Critical Applications

**Current gap:** 10% coverage threshold is a placeholder. No security-specific test patterns. No contract tests for API stability.

| Technology | Version | Purpose | Why | Confidence |
|------------|---------|---------|-----|------------|
| Vitest (keep) | 4.x | Unit/integration testing | Already in place. Increase coverage thresholds. | HIGH |
| Playwright (keep) | 1.58+ | E2E testing | Already in place. Add auth flow and RBAC E2E tests. | HIGH |
| `supertest` | ^7.0.0 | HTTP integration tests | Test Express routes with real middleware stack without starting server. Better than mocking req/res for API contract testing. | HIGH |
| `@faker-js/faker` | ^9.0.0 | Realistic test data | Current test factories use hardcoded values. Faker generates realistic security data for fuzz-like testing. | MEDIUM |
| `msw` (Mock Service Worker) | ^2.7.0 | External service mocking | Mock AWS Bedrock, S3, connector APIs in integration tests. Better than `vi.mock` for HTTP-level mocking -- tests real serialization. | MEDIUM |
| Property-based testing via `fast-check` | ^4.0.0 | Input fuzzing | For a security platform: fuzz normalizer inputs, API validation boundaries, PII detection patterns. Finds edge cases unit tests miss. | MEDIUM |

**Coverage threshold progression:**
- Phase 1: Raise to 30% (current baseline + critical paths)
- Phase 2: Raise to 50% (after adding supertest API tests)
- Phase 3: Target 70% for security-critical modules (normalizer, RBAC, auth, PII engine, correlation)

**Security-specific test categories to add:**
1. **RBAC boundary tests**: Every endpoint tested with every role (owner/admin/analyst/read_only) to verify access control
2. **Org isolation tests**: Verify tenant A cannot access tenant B's data across all query paths
3. **Input validation fuzz**: Property-based tests on normalizer, API inputs, webhook payloads
4. **Auth flow tests**: Session fixation, token reuse, API key scope enforcement
5. **Audit log integrity**: Verify chain-hash is unbroken after operations

### 7. Additional Production Hardening

| Technology | Version | Purpose | Why | Confidence |
|------------|---------|---------|-----|------------|
| Redis / ElastiCache | 7.x | Shared state for multi-pod | `scaling-state.ts` identifies 4 stores needing shared backend: AI circuit breakers, webhook circuit breakers, webhook rate buckets, SLO breach cooldown. Required before scaling beyond 1 replica. | HIGH |
| `ioredis` | ^5.4.0 | Redis client | Supports clustering, sentinels, pipeline. Standard choice for Node.js + Redis. | HIGH |
| `tsx` removal for production | N/A | Avoid dev tooling in prod | Production already uses `node dist/index.cjs`. Verify Dockerfile does not use tsx. | HIGH |
| Source map generation | esbuild config | Production debugging | Enable `sourcemap: true` in `script/build.ts` for esbuild. Combine with `--enable-source-maps` flag. | HIGH |

## Alternatives Considered

| Category | Recommended | Alternative | Why Not |
|----------|-------------|-------------|---------|
| Logger | Keep custom logger.ts | Pino 9 | Custom logger already has redaction, AsyncLocalStorage, child loggers. Migration cost > marginal perf gain. |
| Logger | Keep custom logger.ts | Winston 3 | Winston is slower than both Pino and the custom logger. No benefit. |
| Connection Pooler | AWS RDS Proxy | PgBouncer sidecar | PgBouncer is better perf but adds operational burden. RDS Proxy is managed. |
| Clustering | EKS HPA (don't cluster) | node:cluster | Clustering inside pods conflicts with K8s scaling model. Already solved. |
| Vuln Scanning | npm audit + Socket.dev | Snyk | Snyk free tier is limited. npm audit + Socket.dev covers 95% of cases. |
| Test Runner | Vitest (keep) | Jest | Already on Vitest. No reason to switch. |
| HTTP Test | supertest | Vitest mocks | supertest tests real middleware stack, not just handler logic. |
| Property Testing | fast-check | N/A | Only mature property testing lib for JS/TS. |
| Redis Client | ioredis | node-redis | ioredis has better cluster support, pipeline API, and TypeScript types. |

## Installation

```bash
# New production dependencies
npm install ioredis

# New dev dependencies
npm install -D supertest @types/supertest @faker-js/faker fast-check msw knip eslint-plugin-security better-npm-audit license-checker

# TypeScript upgrade (verify latest stable first)
npm install -D typescript@~5.7
```

## Environment Variable Additions

| Variable | Required | Description |
|----------|----------|-------------|
| `REDIS_URL` | Yes (multi-pod) | Redis/ElastiCache connection string |
| `LOG_LEVEL` | No | Override log level (debug/info/warn/error) |
| `UV_THREADPOOL_SIZE` | No | libuv thread pool size (default 4, recommend 16) |
| `NODE_OPTIONS` | No | `--max-old-space-size=1536 --enable-source-maps` |

## Sources & Confidence Notes

- Codebase analysis: HIGH confidence (directly read all relevant files)
- Library recommendations: MEDIUM confidence (based on training data, WebSearch was unavailable for version verification)
- Version numbers: LOW confidence for newest releases -- verify `npm info [pkg] version` before installing
- Architecture decisions (no clustering, keep custom logger, use RDS Proxy): HIGH confidence (based on codebase-specific analysis)

**Key caveat:** All version numbers should be verified with `npm info [package] version` before installation. Training data may be stale on exact latest versions.

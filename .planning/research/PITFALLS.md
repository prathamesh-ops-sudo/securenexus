# Domain Pitfalls

**Domain:** Security platform production hardening (refactoring, testing, migration, dependency upgrades)
**Researched:** 2026-03-25
**Confidence:** HIGH (based on direct codebase analysis + established engineering patterns)

## Critical Pitfalls

Mistakes that cause production outages, data loss, or multi-week rewrites.

---

### Pitfall 1: Splitting storage.ts Without a Facade Creates Cascading Import Breakage

**What goes wrong:** `storage.ts` is 6,222 lines with ~6,000 query functions. Every route handler, engine, and background worker imports from it. Splitting it into domain modules (e.g., `storage/alerts.ts`, `storage/incidents.ts`) changes the import path for every consumer. A single missed re-export breaks compilation, and since tests mock `../storage`, every test file needs mock path updates too.

**Why it happens:** Teams split the file by moving functions but forget that:
1. The import path `../storage` is used in 110+ route files, 40+ engines, 7 test files, and background workers.
2. Vitest mocks use `vi.mock("../storage", ...)` with the exact path string. Changing the module structure silently breaks mocks (tests pass but mock the wrong thing, or fail entirely).
3. Circular dependencies emerge when storage submodules import from each other (e.g., incident storage needs alert storage for correlation queries).

**Consequences:** Build failures across dozens of files. Tests that appear to pass but no longer mock correctly (false positives). Potential circular dependency runtime crashes in production.

**Warning signs:**
- PR touches > 30 files simultaneously
- Test mock paths diverge from actual import paths
- `import { storage } from "../storage"` still works but resolves to a barrel file re-exporting from subdirectories (barrel files cause treeshaking and circular issues)

**Prevention:**
1. Create a barrel `server/storage/index.ts` that re-exports everything from submodules. Every existing import continues to work unchanged.
2. Split one domain at a time (alerts first, then incidents, etc.) and verify imports after each split.
3. Add a CI check: `grep -r 'from.*storage/' server/ --include='*.ts' | grep -v 'storage/index'` to catch direct submodule imports (force everything through the barrel during transition).
4. Update test mocks in the same PR as the split. Never defer mock updates.

**Phase:** Early hardening. Do this first because every subsequent change touches storage imports.

---

### Pitfall 2: Database Migration Locks on 80+ Table Schema in Production PostgreSQL

**What goes wrong:** `shared/schema.ts` defines 80+ tables. During hardening, you will add columns (e.g., indexes for performance), change types (e.g., `text` to `varchar(255)`), or add NOT NULL constraints. In PostgreSQL, `ALTER TABLE ... ADD COLUMN ... DEFAULT ...` (with a volatile default) acquires an `ACCESS EXCLUSIVE` lock on the entire table. On `alerts` or `incidents` tables with millions of rows, this lock blocks all reads and writes for seconds to minutes, causing API timeouts and dropped connections.

**Why it happens:** Drizzle Kit's `drizzle-kit push` generates DDL that may not be migration-safe. It does not distinguish between online-safe and lock-heavy operations. Teams run `db:push` in staging (fast, small data) and assume production will behave the same.

**Consequences:** Full production outage for the duration of the migration. Connection pool exhaustion (20 connections in prod) as queries queue behind the lock. Background workers (job queue, SLO alerting, report scheduler) fail and retry, amplifying load.

**Warning signs:**
- Migration adds `NOT NULL` column to table with > 100K rows
- Migration changes column type on populated table
- Migration adds index without `CONCURRENTLY`
- `drizzle-kit push` used in production instead of versioned migrations

**Prevention:**
1. Never use `drizzle-kit push` in production. Use `drizzle-kit generate` to create SQL migration files, then review and modify them before applying.
2. For adding columns: always use `ADD COLUMN ... DEFAULT NULL` (no NOT NULL). Backfill data separately. Then add the NOT NULL constraint in a second migration after backfill completes.
3. For adding indexes: manually edit the generated SQL to use `CREATE INDEX CONCURRENTLY` (Drizzle Kit does not generate this).
4. For changing types: create a new column, backfill, swap in application code, then drop the old column in a later migration.
5. Test migrations against a production-sized dataset in staging/UAT before applying to production.
6. Set `statement_timeout` and `lock_timeout` in migration scripts (e.g., `SET lock_timeout = '5s'`) so migrations fail fast instead of blocking.

**Phase:** Must be established as a process before any schema changes. Define the migration safety protocol in Phase 1.

---

### Pitfall 3: Refactoring Auth Session Layer Breaks All Active Sessions

**What goes wrong:** The auth system uses `connect-pg-simple` for PostgreSQL session storage with a custom deserialize cache (30-second TTL, max 500 entries) and auto-promotes superadmin on deserialize. Refactoring the session module (e.g., upgrading Passport, changing serialization format, restructuring the user object) invalidates all existing sessions in the `sessions` table. Every logged-in user gets logged out simultaneously.

**Why it happens:** `passport.serializeUser` stores a user ID in the session. `passport.deserializeUser` loads the user from DB using that ID. If the serialized format changes (even slightly), or if the user object shape changes (e.g., renaming `orgId` to `organizationId`), existing sessions cannot deserialize. The custom cache (`deserializeCache`) masks the problem briefly -- cached users work fine, but cache misses hit the new code path and fail.

**Consequences:** All users logged out. OAuth flows break if callback URLs or strategy configs change. API key auth is unaffected (stateless), so some functionality continues, masking the session failure. SOC analysts lose their active investigation context mid-incident.

**Warning signs:**
- Changes to `server/auth/session.ts` serialization or deserialization logic
- Passport.js major version upgrade (strategy API changes)
- Changes to the `users` table schema or `organizationMemberships` joins in deserialize
- The `CachedUser` type uses `any` (line 28) -- type changes are invisible

**Prevention:**
1. Never change the session serialization format without a migration path. If you must change it, write a deserialization function that handles both old and new formats.
2. Test session deserialization with production session data (export a few anonymized sessions from the `sessions` table).
3. Deploy auth changes behind a feature flag. Route a small percentage of requests through the new code path first.
4. Fix the `CachedUser` type from `any` to a concrete type -- this makes breaking changes compile-time visible.
5. Keep Passport strategy upgrades separate from business logic changes. One PR for the upgrade, one for refactoring.

**Phase:** Auth hardening must happen in its own isolated phase with careful rollout. Not combined with other refactoring.

---

### Pitfall 4: Adding Tests to storage.ts With Real DB Creates Flaky CI

**What goes wrong:** `storage.ts` has 6,222 lines of query functions and zero direct tests. The instinct is to write integration tests that hit a real PostgreSQL database. This creates test interdependence (tests share DB state), ordering-dependent failures, and CI that passes locally but fails in GitHub Actions due to connection limits, parallel test execution, and missing seed data.

**Why it happens:** The existing test pattern (7 test files) mocks `storage` entirely. Testing `storage.ts` itself requires either (a) a real database or (b) mocking Drizzle ORM internals, which is brittle and defeats the purpose. Teams choose option (a) but underestimate the complexity of multi-tenant test isolation (every query filters by `orgId`), foreign key constraints across 80+ tables, and connection pool management in tests.

**Consequences:** CI build times increase from minutes to 15+ minutes. Flaky tests erode trust in the test suite, and teams start ignoring failures. Connection pool exhaustion in CI (test parallelism creates dozens of connections). Tests become the bottleneck for all PRs.

**Warning signs:**
- Tests create rows in shared tables without cleanup
- Tests run in parallel against same database
- Connection pool errors in CI logs
- Tests pass individually but fail when run together

**Prevention:**
1. Use transaction-based test isolation: begin a transaction before each test, rollback after. This is fast and prevents cross-test contamination.
2. Configure Vitest to run storage tests serially (`{ pool: 'forks', poolOptions: { forks: { singleFork: true } } }` for the storage test file).
3. Use a separate test database (not the development database). Seed it with minimal fixture data.
4. Set the connection pool to 2-3 connections in test environment (`server/db.ts` already has 5 for dev).
5. Prefer testing storage through the route handlers (existing integration test pattern) rather than testing storage functions in isolation. Add storage-specific tests only for complex query logic (joins, aggregations, window functions).
6. Consider a lightweight approach: test the top 20 most-used storage functions first, not all 6,000.

**Phase:** Testing phase. Establish the test database infrastructure and isolation pattern before writing any storage tests.

---

### Pitfall 5: Silent Empty Catch Blocks Swallow Production Errors During Hardening

**What goes wrong:** The codebase has 23 empty catch blocks across 9 files, including critical paths like `auth/routes.ts` (4 occurrences), `routes/ai.ts` (8 occurrences), and `outbox-processor.ts` (2 occurrences). During hardening, when behavior changes (new validation, stricter types, upgraded dependencies), these empty catches silently swallow errors that would have been caught. Features appear to work but produce incorrect results.

**Why it happens:** Empty catches were added during rapid development to prevent crashes. During hardening, the code inside the try block changes behavior (e.g., a Zod schema becomes stricter, a function signature changes), but the catch block eats the error. The developer sees no failure, commits the change, and the bug reaches production.

**Consequences:** Data corruption (partial writes succeed, failures are swallowed). AI responses silently degrade (8 empty catches in AI routes). OAuth callbacks fail silently (4 empty catches in auth routes). Webhook delivery appears to succeed but doesn't (outbox processor catches).

**Warning signs:**
- `catch (e) {}` or `catch (_) {}` patterns anywhere
- Features that "work" in development but produce wrong results
- Missing error logs for operations that should occasionally fail
- Monitoring shows zero errors for a service that handles external API calls (impossible)

**Prevention:**
1. Before any hardening work, audit and fix all 23 empty catch blocks. At minimum, add `logger.warn("Suppressed error", { error: e })`.
2. Add an ESLint rule: `no-empty` with `allowEmptyCatch: false`. This prevents new empty catches.
3. For intentional suppression, require an explicit comment: `catch (_e) { /* intentionally suppressed: [reason] */ }`.
4. Prioritize fixing catches in `auth/routes.ts` and `outbox-processor.ts` first (security and data integrity).

**Phase:** Phase 0 / prerequisite. Fix these before any other hardening work begins. Without this, you cannot trust that refactoring changes are actually working.

---

## Moderate Pitfalls

---

### Pitfall 6: TypeScript Strict Mode Is Already Enabled -- The Real Problem Is `as any`

**What goes wrong:** Teams plan a "strict mode migration" but discover `strict: true` is already in `tsconfig.json`. The actual type safety debt is ~74+ `as any` casts scattered across the server code (notably 16 in `job-queue.ts`, 8 in `native-collectors-engine.ts`, 6 in `auth/session.ts`). Removing `as any` casts one by one triggers type errors that cascade through the module's consumers.

**Why it happens:** `as any` was used to bypass type checking during rapid development. Each `as any` masks a real type mismatch. Removing one often reveals that the function signature, return type, or interface is wrong, which propagates to all callers.

**Prevention:**
1. Do not attempt to remove all `as any` at once. Prioritize by risk: auth (session.ts has `CachedUser.user: any`), then security middleware, then business logic.
2. Create proper TypeScript interfaces before removing casts. Define what the type should be, then fix the cast.
3. Use `unknown` as an intermediate step: replace `as any` with proper type narrowing using type guards.
4. Track progress: `grep -c "as any" server/**/*.ts` as a CI metric.

**Phase:** Spread across multiple phases. Fix auth types first, then progressively address others.

---

### Pitfall 7: Upgrading Express 5 or Passport Breaks Session Middleware Order

**What goes wrong:** Express middleware executes in registration order. The current `server/index.ts` carefully orders: compression, security headers, CSRF, rate limiting, session, passport, org context, routes. Upgrading Express, Passport, or session middleware can change when middleware runs, especially if new middleware is async or if error handling changes. A subtle reordering means CSRF protection runs before sessions initialize, or rate limiting runs before auth (making per-user limits impossible).

**Why it happens:** Express 5 changed error handling (Promise rejections are caught automatically). Passport 0.7+ changed serialization behavior. `connect-pg-simple` major versions change session store APIs. These are not breaking in isolation but interact badly.

**Prevention:**
1. Upgrade one dependency at a time, not as a batch.
2. Write an integration test that verifies middleware order: make a request and assert that `req.user` is populated before route handlers execute.
3. Pin exact versions in `package.json` during the hardening phase (no `^` ranges for core middleware).
4. Test OAuth flows end-to-end after any middleware change (Google and GitHub OAuth callbacks are especially sensitive to session/CSRF ordering).

**Phase:** Dependency upgrade phase. Do this after refactoring is stable, not during.

---

### Pitfall 8: Replacing Custom Logger Without Preserving Correlation ID Flow

**What goes wrong:** The custom `server/logger.ts` uses `AsyncLocalStorage` for request-scoped context (request ID, org ID, user ID). If hardening replaces this with Pino, Winston, or another structured logger, the `AsyncLocalStorage` integration must be preserved. Without it, production logs lose the ability to trace a single request across route handler, storage calls, engine invocations, and background workers.

**Why it happens:** The custom logger appears simple (just writes JSON to stdout). Teams replace it with Pino for performance, but Pino's child logger pattern works differently from the custom `.child("component-name")` pattern. The 110+ route files use `logger.child("component")`, which returns a logger with the component name baked in. Pino's `.child({component})` returns a new logger instance with merged bindings. The migration requires touching every file that creates a child logger.

**Prevention:**
1. If the custom logger works, consider enhancing it rather than replacing it. Add Pino as the transport layer underneath, keeping the existing `.child()` API.
2. If replacing, create an adapter that matches the current `logger.child("name")` API and delegates to the new logger internally.
3. Verify `AsyncLocalStorage` context propagation works with the new logger by testing inside a `setInterval` callback (background workers) and inside `Promise.all` (parallel operations).
4. The REDACT_PATTERNS in the current logger (lines 38-59) handle sensitive data masking. Any replacement must preserve these 17 redaction patterns or you will log secrets.

**Phase:** Late in hardening. Logger replacement is low-value/high-risk unless there is a specific performance problem.

---

### Pitfall 9: Mocking Storage in Route Tests Creates False Safety

**What goes wrong:** All 7 existing test files mock `storage` completely. This means route handler tests verify that "the handler calls `storage.createAlert()`" but never verify that `storage.createAlert()` actually works. During hardening, if you change the storage function signature (add a required parameter, rename a field), the route tests still pass because they mock the function. The bug only appears in production.

**Why it happens:** The test pattern `vi.mock("../storage", () => ({ storage: { createAlert: vi.fn().mockResolvedValue({}) } }))` pins the mock to a specific API. When the real `storage.createAlert` changes, the mock doesn't update. TypeScript doesn't type-check mock implementations.

**Prevention:**
1. Use typed mocks: `vi.fn<Parameters<typeof storage.createAlert>, ReturnType<typeof storage.createAlert>>()` so that signature changes cause compile errors in test files.
2. Add a small number of "contract tests" that verify the mock's return shape matches the real function's return shape (snapshot the actual return type).
3. When changing a storage function signature, search for all mocks of that function: `grep -r "createAlert" server/__tests__/`.
4. Consider adding a thin integration test layer that tests route -> storage -> DB for critical paths (alert ingestion, incident creation, auth flows).

**Phase:** Testing phase. Fix mock typing before adding new tests.

---

### Pitfall 10: Drizzle ORM Version Mismatch Between Kit and ORM

**What goes wrong:** The project uses `drizzle-kit` 0.31.8 for migrations and `drizzle-orm` for queries. Upgrading either independently can create schema drift: the ORM generates queries assuming one schema shape, while the migration tool generates DDL assuming another. This manifests as subtle query failures (wrong column names, missing relations) that only appear with specific data patterns.

**Why it happens:** Drizzle's ecosystem moves fast. `drizzle-kit` and `drizzle-orm` have coupled internal APIs. A minor version bump in one can assume features from the other.

**Prevention:**
1. Always upgrade `drizzle-kit` and `drizzle-orm` together in the same PR.
2. After upgrading, run `drizzle-kit generate` and verify the output SQL matches expectations. If it generates unexpected migrations, the version mismatch is real.
3. Run the full test suite after Drizzle upgrades (the normalizer and correlation engine tests exercise storage queries).
4. Check the Drizzle changelog for breaking changes in schema inference.

**Phase:** Dependency upgrade phase. Pair with database migration safety work.

---

## Minor Pitfalls

---

### Pitfall 11: Route File Splitting Breaks OpenAPI Spec Generation

**What goes wrong:** `server/openapi.ts` generates the API specification. If route files are reorganized or renamed, and the OpenAPI spec relies on scanning route files or their exports, the spec becomes stale or incomplete. External API consumers (who use the spec for code generation) get incorrect types.

**Prevention:** After any route reorganization, regenerate the OpenAPI spec and diff it against the previous version. Add a CI check that the spec is up to date.

**Phase:** After route refactoring.

---

### Pitfall 12: Background Worker Changes Without Graceful Shutdown Testing

**What goes wrong:** The app starts 4+ background workers on boot (report scheduler, job worker, SLI collection, SLO alerting). Refactoring these workers (e.g., moving from `setInterval` to a proper queue) without testing graceful shutdown causes in-flight jobs to be lost during deployment.

**Prevention:** Test the shutdown path: `process.emit('SIGTERM')` and verify `waitForInFlightDrain()` actually waits for active jobs. Canary deployments via Argo Rollouts help, but only if the canary version handles inflight work correctly.

**Phase:** Background worker hardening, after core refactoring.

---

### Pitfall 13: CSRF Token Changes Break Frontend Without Coordinated Deploy

**What goes wrong:** If the CSRF middleware is upgraded or reconfigured, existing CSRF tokens in browser sessions become invalid. Every in-flight form submission and mutation fails with 403 until the user refreshes. The React frontend's TanStack Query retries the mutation, hitting rate limits.

**Prevention:** Deploy backend CSRF changes to accept both old and new token formats for a transition period. Add a frontend interceptor that auto-refreshes the CSRF token on 403 responses.

**Phase:** Security middleware hardening.

---

### Pitfall 14: Connection Pool Exhaustion During Migration + Live Traffic

**What goes wrong:** The production pool has 20 connections. Running a migration (which holds connections for the duration of DDL statements) while handling live traffic can exhaust the pool. Background workers (job queue, report scheduler) hold long-running connections. With 20 connections, a migration that takes 30 seconds can cause 20+ queued requests to timeout.

**Prevention:** Run migrations during low-traffic windows. Use a separate migration connection (not from the application pool). The `performanceBudgetMiddleware` already rejects requests at 80% pool utilization -- leverage this as an early warning. Consider increasing pool size to 30 during migration windows.

**Phase:** Every phase that includes schema changes.

---

## Phase-Specific Warnings

| Phase Topic | Likely Pitfall | Mitigation |
|-------------|---------------|------------|
| storage.ts split | Import path breakage across 110+ files (#1) | Barrel file re-export pattern |
| Adding tests | Flaky CI from real DB tests (#4) | Transaction isolation, serial execution |
| Adding tests | False safety from untyped mocks (#9) | Typed mocks with signature enforcement |
| Schema changes | Table locks on large tables (#2) | Manual SQL review, CONCURRENTLY, lock_timeout |
| Schema changes | Pool exhaustion during migration (#14) | Separate connection, low-traffic window |
| Auth refactoring | Session invalidation (#3) | Dual-format deserialization, feature flags |
| Auth refactoring | Middleware order breakage (#7) | Integration test for middleware chain |
| Dependency upgrades | Express/Passport interaction bugs (#7) | One-at-a-time upgrades |
| Dependency upgrades | Drizzle ORM/Kit version mismatch (#10) | Always upgrade together |
| Logger replacement | Lost correlation IDs and secret redaction (#8) | Adapter pattern, preserve AsyncLocalStorage |
| CSRF/security middleware | Frontend token breakage (#13) | Dual-format transition period |
| Type safety cleanup | Cascading type errors from removing `as any` (#6) | One module at a time, interfaces first |
| Empty catch audit | Discovering hidden bugs (#5) | Do this before other hardening |
| Route reorganization | OpenAPI spec drift (#11) | CI check for spec freshness |
| Background workers | Lost in-flight jobs on deploy (#12) | Test graceful shutdown path |

## Recommended Hardening Order (Risk-Minimizing)

Based on dependency analysis of the pitfalls above:

1. **Phase 0: Fix empty catches + type audit** -- prerequisite for all other work (#5, #6)
2. **Phase 1: Migration safety protocol** -- establish before any schema changes (#2, #14)
3. **Phase 2: Test infrastructure** -- transaction isolation, typed mocks (#4, #9)
4. **Phase 3: storage.ts split** -- barrel pattern, import verification (#1)
5. **Phase 4: Auth hardening** -- isolated, careful rollout (#3)
6. **Phase 5: Dependency upgrades** -- one at a time after tests exist (#7, #10)
7. **Phase 6: Logger/middleware hardening** -- low priority unless problems exist (#8, #13)

## Sources

- Direct codebase analysis: `server/storage.ts` (6,222 lines), `shared/schema.ts` (12,814 lines, 80+ tables), `server/auth/session.ts` (custom deserialize cache with `any` types), `server/logger.ts` (AsyncLocalStorage + 17 redaction patterns)
- Grep analysis: 74+ `as any` occurrences across server, 23 empty catch blocks across 9 files, 4 migration files in `migrations/`
- Testing analysis: 7 test files, all mock `storage` entirely, 10% coverage threshold
- PostgreSQL locking behavior: established documentation on `ACCESS EXCLUSIVE` locks during DDL
- Drizzle ORM migration patterns: `drizzle-kit push` vs `drizzle-kit generate` behavioral differences
- Express 5 middleware ordering: documented behavioral changes from Express 4

---

*Pitfall analysis: 2026-03-25*

# Phase 10: Test Coverage & Quality Gates - Context

**Gathered:** 2026-03-26
**Status:** Ready for planning

<domain>
## Phase Boundary

This phase adds automated test coverage for security-critical boundaries and enforces code quality gates via ESLint pre-commit hooks. Five concerns converge:

1. **OAuth flow testing (TEST-01)** -- The `server/auth/session.ts` module configures Google and GitHub OAuth strategies via Passport.js. Google strategy extracts `profile.emails?.[0]?.value`, `profile.name?.givenName`, `profile.name?.familyName`, and `profile.photos?.[0]?.value`. GitHub strategy extracts the verified primary email via `emails.find(e => e.primary && e.verified && e.value)` and parses `profile.displayName` into first/last name. Both strategies check for disabled accounts and auto-promote super-admins. The `server/auth/routes.ts` callbacks enforce consumer email domain blocking, org membership provisioning, login policy checks, and max concurrent sessions. No tests exist for any of this -- profile parsing edge cases (missing emails, multiple emails, null displayName), token refresh behavior, and session fixation prevention are all untested.

2. **RBAC boundary testing (TEST-03)** -- The `server/rbac.ts` module defines four middleware functions: `resolveOrgContext`, `requireOrgId`, `requireOrgRole`, and `requirePermission`. The existing `server/__tests__/rbac.test.ts` has 22 tests covering the middleware in isolation. However, the ROLE_PERMISSIONS matrix in `shared/schema.ts` defines 4 roles x 6 scopes x 3 actions = 72 combinations, and only ~8 are explicitly tested. The test does not use parameterized tests to cover every role x scope x action combination systematically. Missing coverage: the `requireMinRole` hierarchy edge cases (unknown roles defaulting to level 0), interaction between `resolveOrgContext` and `requirePermission` in a middleware chain, and org context switch audit logging.

3. **Billing/metering testing (TEST-04)** -- The `server/routes/billing.ts` module defines 10 endpoints for Stripe billing. The `server/stripe-service.ts` module handles 6 webhook event types: `checkout.session.completed`, `invoice.paid`, `invoice.payment_failed`, `customer.subscription.updated`, `customer.subscription.deleted`, and `customer.subscription.trial_will_end`. The `getUsageVsLimits()` function delegates to `server/middleware/plan-enforcement.ts` for usage calculation. Zero test coverage exists for any billing/metering logic. The webhook handler requires raw body Buffer and stripe-signature header validation. The billing routes require admin role and Stripe enablement checks.

4. **ESLint quality gates (QUAL-03)** -- The current `eslint.config.js` sets `no-console: warn` (allowing console.warn/error) and `@typescript-eslint/no-explicit-any: warn`. Phase 10 requires upgrading both to `error` level and enforcing via pre-commit hooks. Husky is already installed but has execution format errors on the current system. The ESLint config uses the flat config format (ESLint 9 + typescript-eslint).

5. **Rate limit consistency audit (API-03)** -- The `server/middleware/org-rate-limit.ts` exports `orgRateLimitMiddleware` which is applied globally to `/api` routes in `server/routes.ts`. It uses plan-tier-based limits (free: 1000, pro: 5000, enterprise: 10000 per 15-minute window). The global rate limiter in `server/index.ts` uses `express-rate-limit` at 300 req/min per IP in production. Health check endpoints are exempt. An audit must verify all endpoints are covered and identify any gaps.

**Out of scope:** E2E Playwright auth flow tests (frontend testing), property-based testing with fast-check (future phase), supertest HTTP integration tests (separate tooling phase), Redis-backed rate limiting (horizontal scaling phase).
</domain>

<decisions>
## Implementation Decisions

### D1: OAuth test strategy -- mock Passport strategies vs. test verify callbacks directly

**Decision:** Test the Passport strategy verify callbacks directly by extracting them and calling with mock profile objects.

**Rationale:** The Google and GitHub strategy verify callbacks are inline anonymous functions in `setupAuth()`. Testing them requires either: (a) extracting the callbacks into named, exported functions, or (b) mocking the Passport infrastructure and testing the full OAuth flow. Option (a) is cleaner -- extract `googleVerifyCallback` and `githubVerifyCallback` as named exports from `server/auth/session.ts`, then unit-test with mock `passport.Profile` objects. This avoids complex Passport mocking and tests the actual profile parsing logic directly. Session fixation prevention is tested by verifying that `getSession()` configures `resave: false` and `saveUninitialized: false`, and that the session cookie has `httpOnly: true` and `sameSite: "lax"`.

### D2: RBAC boundary test approach -- exhaustive parameterized matrix vs. selective boundary tests

**Decision:** Use a parameterized test matrix that iterates every role x scope x action combination from `ROLE_PERMISSIONS`.

**Rationale:** The existing `rbac.test.ts` tests ~8 specific combinations manually. With 4 roles, 6 scopes, and 3 actions (read/write/admin), the full matrix is 72 combinations. A parameterized test generates all 72 cases from the `ROLE_PERMISSIONS` constant, asserting allow for combinations present in the permission map and deny for all others. This catches permission regressions automatically when ROLE_PERMISSIONS changes and ensures no accidental privilege escalation. The test should also cover edge cases: unknown role (level 0), empty scope, and null role.

### D3: Billing test mocking strategy -- mock Stripe SDK vs. mock stripe-service functions

**Decision:** Mock the `stripe-service.ts` exports when testing billing routes, and mock the Stripe SDK constructor when testing `stripe-service.ts` internals.

**Rationale:** Billing route tests should verify middleware enforcement (auth, org context, admin role, Stripe enablement) and correct delegation to stripe-service functions. These are route-level concerns and do not need real Stripe SDK behavior. For stripe-service unit tests (webhook signature verification, event type routing, usage calculation), mock the Stripe constructor to return controlled objects. The `constructEvent()` mock should test both valid signatures (returns event) and invalid signatures (throws). This two-layer approach matches the existing test patterns (e.g., action-dispatcher tests mock storage, not the DB directly).

### D4: ESLint enforcement strategy -- upgrade rules in-place vs. add strict override block

**Decision:** Upgrade the existing `no-console` and `no-explicit-any` rules from `warn` to `error` in the main rules block, and add a pre-commit lint-staged hook.

**Rationale:** Changing the existing rules from `warn` to `error` immediately surfaces all current violations during development. Since the codebase already uses `/* eslint-disable */` comments where `any` is intentional (visible in test files), the upgrade should not break the build for legitimate uses. A `.lintstagedrc` configuration runs ESLint on staged files during pre-commit, rejecting commits that introduce new violations. This is more practical than running ESLint on the entire codebase in a pre-commit hook (which would be slow for 110+ route files).

### D5: Rate limit audit approach -- static code analysis vs. runtime verification test

**Decision:** Perform a static analysis that greps all registered route paths and verifies each has rate limiting middleware in its chain.

**Rationale:** The global `orgRateLimitMiddleware` is applied to all `/api` routes via `app.use("/api", orgRateLimitMiddleware)` in `routes.ts`. However, some routes might be registered outside this scope or before the middleware. A static audit script/test reads all route registrations, identifies any that bypass the global limiter, and documents exemptions (health checks, webhook endpoints). This is codified as a test that fails if a new unprotected route is added without explicit exemption documentation.
</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets

| Asset | Location | Relevance |
|-------|----------|-----------|
| `setupAuth()` | `server/auth/session.ts:151-338` | Configures Google + GitHub OAuth strategies with inline verify callbacks. Extract callbacks for testability. |
| `GoogleStrategy` verify callback | `server/auth/session.ts:194-227` | Extracts email from `profile.emails[0].value`, creates user if new, checks disabled status. |
| `GitHubStrategy` verify callback | `server/auth/session.ts:248-280` | Finds verified primary email from `profile.emails`, splits displayName into first/last. |
| `resolveCallbackUrl()` | `server/auth/session.ts:135-149` | Resolves relative OAuth callback URLs using APP_BASE_URL. Testable pure function. |
| `SessionUser` interface | `server/auth/session.ts:27-30` | Extends `User` with optional `orgId` and `orgRole`. Used by all auth tests. |
| `ROLE_PERMISSIONS` | `shared/schema.ts:195-228` | Complete role x scope x action matrix. 4 roles, 6 scopes, variable actions. Source of truth for parameterized tests. |
| `requirePermission()` | `server/rbac.ts:145-158` | Checks `ROLE_PERMISSIONS[role][scope].includes(action)`. Target for exhaustive matrix testing. |
| `rbac.test.ts` mock patterns | `server/__tests__/rbac.test.ts` | Established mock patterns for storage, logger, api-response, and @shared/schema. Extend for matrix tests. |
| `handleWebhookEvent()` | `server/stripe-service.ts:180-210` | Routes 6 Stripe event types. Uses `client.webhooks.constructEvent()` for signature verification. |
| `getUsageVsLimits()` | `server/stripe-service.ts:447-477` | Delegates to `plan-enforcement.ts` for usage summary. Returns plan + usage metrics. |
| `isStripeEnabled()` | `server/stripe-service.ts:29-31` | Guards all billing routes. Returns false when STRIPE_SECRET_KEY is missing. |
| `orgRateLimitMiddleware` | `server/middleware/org-rate-limit.ts` | Plan-tier rate limiting. In-memory bucket map with 15-min window. Testable with mock storage. |
| `eslint.config.js` | Root | Flat config with warn-level rules for no-console and no-explicit-any. Upgrade targets. |
| Husky hooks | `.husky/` directory | Pre-commit hooks exist but have exec format errors. Need fixing or replacement with lint-staged. |

### Established Patterns

1. **Test file structure**: All tests in `server/__tests__/` use Vitest with `vi.mock()` for dependencies. Standard pattern: mock logger, mock storage, mock api-response, then import module under test. See `rbac.test.ts` and `action-dispatcher.test.ts` for examples.

2. **Mock req/res helpers**: `rbac.test.ts` defines `mockReq()` and `mockRes()` helpers that create minimal Express Request/Response mocks. These should be extracted to a shared test utility for reuse across OAuth, billing, and rate limit tests.

3. **ESLint disable comments**: Test files use `/* eslint-disable @typescript-eslint/no-explicit-any */` at the top. This pattern must be preserved when upgrading `no-explicit-any` to error level.

4. **Consumer email domain blocking**: `server/auth/routes.ts` uses `CONSUMER_EMAIL_DOMAINS` Set and `isConsumerEmailDomain()` for OAuth callback validation. OAuth tests must cover this flow.

5. **Billing route middleware chain**: Every billing mutation route follows `isAuthenticated -> resolveOrgContext -> requireOrgId -> requireMinRole("admin")` chain. Tests verify each guard independently.

### Integration Points

| Requirement | Touches | New Files |
|-------------|---------|-----------|
| TEST-01: OAuth flow tests | `server/auth/session.ts` (extract callbacks), `server/auth/routes.ts` (callback behavior) | `server/__tests__/oauth-flows.test.ts` |
| TEST-03: RBAC boundary tests | `server/__tests__/rbac.test.ts` (extend with matrix) | `server/__tests__/rbac-matrix.test.ts` |
| TEST-04: Billing tests | `server/stripe-service.ts`, `server/routes/billing.ts` | `server/__tests__/billing.test.ts`, `server/__tests__/stripe-webhooks.test.ts` |
| QUAL-03: ESLint gates | `eslint.config.js`, `.lintstagedrc`, `.husky/pre-commit` | `.lintstagedrc.json` (if not exists) |
| API-03: Rate limit audit | `server/middleware/org-rate-limit.ts`, `server/routes.ts`, `server/index.ts` | `server/__tests__/rate-limit-audit.test.ts` |
</code_context>

<specifics>
## Specific Ideas

1. **OAuth verify callback extraction** -- Extract the Google and GitHub verify callbacks from `setupAuth()` into named, exported async functions: `googleVerifyCallback(accessToken, refreshToken, profile, done)` and `githubVerifyCallback(accessToken, refreshToken, profile, done)`. Tests create mock `passport.Profile` objects with edge cases: no emails array, empty emails array, email without value property, multiple emails with none primary, displayName as single word, null displayName, photos array empty.

2. **RBAC exhaustive matrix test** -- Generate test cases from `ROLE_PERMISSIONS` constant:
   ```
   for (role of [owner, admin, analyst, read_only]):
     for (scope of [incidents, connectors, api_keys, response_actions, settings, team]):
       for (action of [read, write, admin]):
         expected = ROLE_PERMISSIONS[role]?.[scope]?.includes(action) ?? false
         test: requirePermission(scope, action) with role => expected ? allow : deny
   ```
   This produces 72 test cases automatically and catches any permission matrix change.

3. **Billing webhook test structure** -- Mock `Stripe` constructor to return object with `webhooks.constructEvent()`. Test: valid signature returns constructed event and routes to correct handler. Test: invalid signature throws and returns 400. Test: missing stripe-signature header returns 400. Test: unknown event type logs but does not error. Test: checkout.session.completed creates subscription record. Test: invoice.payment_failed sends notification email.

4. **ESLint rule upgrade** -- Change `"no-console": ["warn", ...]` to `"no-console": ["error", ...]` and `"@typescript-eslint/no-explicit-any": "warn"` to `"@typescript-eslint/no-explicit-any": "error"`. Then audit the codebase for files that need `eslint-disable` comments added. Test files already have the disable comment. Production code using `(req as any).user` in `server/rbac.ts` and routes will need targeted disable comments or type assertion fixes.

5. **Rate limit coverage test** -- Create a test that imports route registration functions and verifies the middleware chain. Since the global `orgRateLimitMiddleware` is applied via `app.use("/api", ...)`, all `/api/*` routes are covered. The test should verify: (a) the middleware is registered before route handlers, (b) health/ready/live endpoints are exempt, (c) the webhook endpoint has appropriate rate limiting or is documented as exempt, (d) no routes are registered outside the `/api` prefix without rate limiting.

6. **Session security assertions** -- Test `getSession()` configuration: `resave: false` (prevents session fixation via race conditions), `saveUninitialized: false` (no empty sessions created), `cookie.httpOnly: true` (prevents XSS session theft), `cookie.sameSite: "lax"` (CSRF protection), `cookie.secure: true` in production. These are configuration assertions, not behavioral tests, but they document security invariants.
</specifics>

<deferred>
## Deferred Ideas

1. **E2E OAuth flow tests with Playwright** -- Full browser-based OAuth testing requires mock OAuth providers (or test accounts). Playwright E2E tests for login/registration flows are valuable but belong in a dedicated E2E testing phase with proper test infrastructure (mock OAuth server, test database seeding).

2. **Property-based testing for RBAC with fast-check** -- Generate random role/scope/action combinations and verify consistency with ROLE_PERMISSIONS. This catches edge cases in role hierarchy logic but requires fast-check dependency (recommended in CLAUDE.md but not yet installed).

3. **Stripe webhook replay protection** -- Stripe webhooks include idempotency handling via event IDs. Testing replay protection (duplicate event ID rejection) requires maintaining a seen-events store. Defer to when billing is production-critical.

4. **ESLint rule for org-scoped queries** -- A custom ESLint rule that flags database queries missing `orgId` in WHERE clauses. This would prevent tenant isolation bugs at lint time. Requires writing a custom ESLint plugin, which is significant effort.

5. **Rate limit load testing** -- Verify rate limiting behavior under concurrent load using autocannon or k6. Integration-level testing that requires a running server. Defer to performance testing phase.

6. **Coverage threshold enforcement in CI** -- Add Vitest coverage thresholds that fail CI when coverage drops below target. The CLAUDE.md recommends Phase 1: 30%, Phase 2: 50%, Phase 3: 70% for security-critical modules. Implement after sufficient test coverage exists to set meaningful baselines.
</deferred>

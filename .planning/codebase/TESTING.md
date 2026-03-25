# Testing Patterns

**Analysis Date:** 2026-03-25

## Test Framework

**Unit/Integration Runner:**
- Vitest 4.x
- Config: `vitest.config.ts`
- Globals enabled (`describe`, `it`, `expect`, `vi` available without import)
- Environment: `node`
- Pool: `forks` (process isolation)
- Test timeout: 15,000ms
- Hook timeout: 10,000ms

**E2E Runner:**
- Playwright 1.58.x
- Config: `playwright.config.ts`
- Browser: Chromium only
- Base URL: `http://localhost:5173` (dev) / `http://localhost:4173` (CI)
- Retries: 2 in CI, 0 locally
- Traces: on first retry
- Screenshots: only on failure

**Run Commands:**
```bash
npm test                  # Run all unit/integration tests (vitest run)
npm run test:watch        # Watch mode (vitest)
npm run test:coverage     # Coverage report (vitest run --coverage)
npx playwright test       # Run E2E tests
npx playwright test --ui  # E2E with interactive UI
```

## Test File Organization

**Unit/Integration Tests:**
- Location: `server/__tests__/` (centralized, not co-located)
- Naming: `{module-name}.test.ts` for unit tests, `{module-name}.integration.test.ts` for integration tests
- Include pattern: `server/__tests__/**/*.test.ts`, `shared/__tests__/**/*.test.ts`

**E2E Tests:**
- Location: `e2e/` at project root
- Naming: `{feature}.spec.ts`
- Fixtures: `e2e/fixtures.ts`

**Structure:**
```
server/
  __tests__/
    rbac.test.ts
    normalizer.test.ts
    correlation-engine.test.ts
    predictive-engine.test.ts
    org-boundary.test.ts
    connectors.integration.test.ts
    webhooks.integration.test.ts
e2e/
  fixtures.ts
  login.spec.ts
  alert-triage.spec.ts
  connector-setup.spec.ts
  incident-creation.spec.ts
  onboarding.spec.ts
  org-selection.spec.ts
  playbook-execution.spec.ts
  a11y.spec.ts
```

## Test Structure

**Suite Organization:**
```typescript
import { describe, it, expect, vi, beforeEach } from "vitest";

describe("ModuleName", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("functionName", () => {
    it("describes expected behavior", async () => {
      // Arrange
      const input = makeFixture({ overrides });

      // Act
      const result = await functionUnderTest(input);

      // Assert
      expect(result).toBe(expected);
    });

    it("handles edge case", () => { ... });
  });
});
```

**Patterns:**
- `beforeEach(() => vi.clearAllMocks())` in every `describe` block
- Nested `describe` blocks for grouping by function/feature
- Descriptive `it` strings: "returns 401 when no user is present", "rejects analyst from writing connectors"
- Arrange-Act-Assert pattern (implicit, not commented)

## Mocking

**Framework:** Vitest `vi.mock()` and `vi.fn()`

**Module Mocking Pattern:**
```typescript
// Mock entire module at top of file, BEFORE imports of the module under test
vi.mock("../storage", () => ({
  storage: {
    getUserMemberships: vi.fn(),
    createAuditLog: vi.fn().mockResolvedValue({}),
  },
}));

vi.mock("../logger", () => ({
  logger: {
    child: () => ({
      debug: vi.fn(),
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
    }),
  },
}));

// Then import the module under test (hoisted mocks take effect)
import { storage } from "../storage";
import { functionUnderTest } from "../module-under-test";
```

**Logger Mock (standard, copy this exactly):**
```typescript
vi.mock("../logger", () => ({
  logger: {
    child: () => ({
      debug: vi.fn(),
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
    }),
  },
}));
```

**API Response Mock (when testing RBAC/middleware):**
```typescript
vi.mock("../api-response", () => ({
  replyUnauthenticated: vi.fn().mockImplementation((res: any) => {
    res.status(401);
    res.json({ data: null, errors: [{ code: "UNAUTHENTICATED", message: "Authentication required" }] });
    return res;
  }),
  replyForbidden: vi.fn().mockImplementation((res: any, message: string) => {
    res.status(403);
    res.json({ data: null, errors: [{ code: "FORBIDDEN", message }] });
    return res;
  }),
  ERROR_CODES: {
    UNAUTHENTICATED: "UNAUTHENTICATED",
    FORBIDDEN: "FORBIDDEN",
    PERMISSION_DENIED: "PERMISSION_DENIED",
    ORG_ACCESS_DENIED: "ORG_ACCESS_DENIED",
    ORG_MEMBERSHIP_REQUIRED: "ORG_MEMBERSHIP_REQUIRED",
  },
}));
```

**Drizzle DB Mock (for tests that need database layer):**
```typescript
vi.mock("../db", () => ({
  db: {
    select: vi.fn().mockReturnThis(),
    from: vi.fn().mockReturnThis(),
    where: vi.fn().mockReturnThis(),
    orderBy: vi.fn().mockReturnThis(),
    limit: vi.fn().mockResolvedValue([]),
    insert: vi.fn().mockReturnThis(),
    values: vi.fn().mockReturnThis(),
    returning: vi.fn().mockResolvedValue([{ id: "mock-id" }]),
    update: vi.fn().mockReturnThis(),
    set: vi.fn().mockReturnThis(),
  },
}));
```

**What to Mock:**
- `storage` - always mock; tests should not hit a real database
- `logger` - always mock; prevents noisy output during tests
- `../db` - mock when testing modules that use Drizzle directly (e.g., correlation engine)
- `@shared/schema` - mock when testing modules that import schema constants
- External API calls (AWS Bedrock, etc.)

**What NOT to Mock:**
- The module under test itself
- Pure utility functions (normalizer, validators)
- Type-only imports

## Fixtures and Factories

**Request/Response Mocks (for middleware tests):**
```typescript
function mockReq(overrides: Record<string, unknown> = {}): Request {
  return {
    headers: {},
    path: "/api/alerts",
    method: "GET",
    user: { id: "user-1", email: "test@example.com" },
    ...overrides,
  } as unknown as Request;
}

function mockRes(): Response {
  const res: any = {
    status: vi.fn().mockReturnThis(),
    json: vi.fn().mockReturnThis(),
    setHeader: vi.fn(),
  };
  return res as Response;
}
```

**Entity Factories (for domain tests):**
```typescript
function makeAlert(overrides: Partial<Alert> = {}): Alert {
  return {
    id: "alert-1",
    orgId: "org-1",
    source: "CrowdStrike EDR",
    sourceEventId: "evt-1",
    category: "malware",
    severity: "high",
    title: "Test Alert",
    description: "Test description",
    rawData: {},
    normalizedData: {},
    ocsfData: null,
    sourceIp: "10.0.0.1",
    destIp: "192.168.1.1",
    sourcePort: null,
    destPort: null,
    protocol: null,
    userId: null,
    hostname: "host-1",
    fileHash: null,
    url: null,
    domain: null,
    mitreTactic: "execution",
    mitreTechnique: "T1059",
    status: "new",
    correlationScore: null,
    correlationClusterId: null,
    correlationReason: null,
    incidentId: null,
    detectedAt: new Date("2026-02-26T10:00:00Z"),
    createdAt: new Date("2026-02-26T10:00:00Z"),
    updatedAt: null,
    ...overrides,
  } as Alert;
}
```

**Storage Mock Factory (for engine tests):**
```typescript
function makeStorage(alerts: Alert[] = []) {
  return {
    getAlerts: vi.fn().mockResolvedValue(alerts),
    clearPredictiveAnomalies: vi.fn().mockResolvedValue(undefined),
    createPredictiveAnomaly: vi.fn().mockImplementation((a) => Promise.resolve(a)),
    // ... other methods as needed
  };
}
```

**Location:**
- Fixtures defined inline within each test file (no shared fixture directory for unit tests)
- E2E fixtures in `e2e/fixtures.ts`

## E2E Test Patterns

**Fixture System:**
Playwright custom fixtures extend the base test with authenticated page context:
```typescript
// e2e/fixtures.ts
export const test = base.extend<{ authenticatedPage: Page }>({
  authenticatedPage: async ({ page }, use) => {
    await mockAuthenticatedSession(page);
    await use(page);
  },
});
```

**API Route Mocking (E2E):**
```typescript
// Mock API responses via Playwright route interception
await page.route("**/api/auth/user", (route) =>
  route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify(envelope(MOCK_USER)),
  }),
);
```

**Envelope Helper (E2E):**
```typescript
function envelope<T>(data: T, meta: Record<string, unknown> = {}) {
  return { data, meta, errors: null };
}
```

**E2E Test Structure:**
```typescript
import { test, expect, MOCK_USER, envelope } from "./fixtures";

test.describe("Feature Name", () => {
  test("scenario description", async ({ page }) => {
    // Setup route mocks
    await page.route("**/api/endpoint", (route) => route.fulfill({ ... }));

    // Navigate
    await page.goto("/path");

    // Interact
    await page.fill('input[type="email"]', "user@example.com");
    await page.locator('button[type="submit"]').click();

    // Assert
    await expect(page.locator("text=Expected Text")).toBeVisible();
  });
});
```

**E2E Authentication:**
All authenticated E2E tests must mock these endpoints:
- `**/api/auth/user` - Returns user object
- `**/api/auth/me` - Returns memberships
- `**/api/events` - Abort (SSE stream)
- `**/api/onboarding/**` - Return empty array
- `**/api/plan-limits**` - Return within limits

## Coverage

**Requirements:**
- Minimum thresholds (currently low): 10% statements, 10% branches, 10% functions, 10% lines
- Provider: v8
- Includes: `server/**/*.ts`, `shared/**/*.ts`
- Excludes: `server/__tests__/**`, `server/vite.ts`, `server/static.ts`, `shared/__tests__/**`, `**/*.d.ts`

**View Coverage:**
```bash
npm run test:coverage    # Generates coverage report
```

## Test Types

**Unit Tests (7 files in `server/__tests__/`):**
- `normalizer.test.ts` - Pure function tests for alert normalization across 15+ source types
- `rbac.test.ts` - Middleware tests for org context resolution, role checks, permission checks
- `org-boundary.test.ts` - Cross-tenant boundary enforcement tests
- `correlation-engine.test.ts` - Alert correlation logic with mocked DB
- `predictive-engine.test.ts` - Predictive analysis engine with mock storage
- `connectors.integration.test.ts` - Connector normalization end-to-end with fixtures
- `webhooks.integration.test.ts` - Webhook URL validation, circuit breakers, rate limiting

**E2E Tests (8 files in `e2e/`):**
- `login.spec.ts` - Login/register flows with OAuth buttons
- `alert-triage.spec.ts` - Alert triage workflow
- `connector-setup.spec.ts` - Connector configuration
- `incident-creation.spec.ts` - Incident creation flow
- `onboarding.spec.ts` - Onboarding wizard
- `org-selection.spec.ts` - Organization switching
- `playbook-execution.spec.ts` - Playbook execution flow
- `a11y.spec.ts` - Accessibility checks (likely uses `@axe-core/playwright`)

## Common Patterns

**Async Testing:**
```typescript
it("returns data when called with valid params", async () => {
  (storage.getUserMemberships as any).mockResolvedValue([
    { orgId: "org-1", role: "admin", status: "active" },
  ]);

  const req = mockReq();
  const res = mockRes();
  const next = vi.fn();

  await resolveOrgContext(req, res, next);

  expect(next).toHaveBeenCalled();
  expect((req as any).orgId).toBe("org-1");
});
```

**Error Testing:**
```typescript
it("returns 403 when user lacks permission", () => {
  const middleware = requirePermission("connectors", "write");
  const req = mockReq({ orgRole: "analyst" });
  const res = mockRes();
  const next = vi.fn();

  middleware(req, res, next);

  expect(next).not.toHaveBeenCalled();
  expect(res.status).toHaveBeenCalledWith(403);
});
```

**Parameterized Testing:**
```typescript
it("allows all roles when minimum is read_only", () => {
  const middleware = requireMinRole("read_only");

  for (const role of ["owner", "admin", "analyst", "read_only"]) {
    const req = mockReq({ orgRole: role });
    const res = mockRes();
    const next = vi.fn();

    middleware(req, res, next);

    expect(next).toHaveBeenCalled();
  }
});
```

**Audit Log Assertion:**
```typescript
it("audits cross-org access attempt", async () => {
  // ... setup ...
  await resolveOrgContext(req, res, next);

  expect(storage.createAuditLog).toHaveBeenCalledWith(
    expect.objectContaining({
      action: "org_access_denied",
      resourceId: "org-other",
    }),
  );
});
```

## Adding New Tests

**For a new server module:**
1. Create `server/__tests__/{module-name}.test.ts`
2. Add `vi.mock("../logger", ...)` and `vi.mock("../storage", ...)` at top
3. Import the module under test AFTER the mocks
4. Use `makeXxx()` factory functions for test data
5. Use `mockReq()` / `mockRes()` for middleware tests
6. Group tests with nested `describe` blocks per function

**For a new E2E flow:**
1. Create `e2e/{feature-name}.spec.ts`
2. Import from `./fixtures`: `test`, `expect`, `MOCK_USER`, `MOCK_ORG`, `envelope`
3. Use `authenticatedPage` fixture for logged-in tests, or mock auth manually
4. Mock all required API routes before navigating
5. Use Playwright locators and assertions

**ESLint Disable for Tests:**
Test files commonly need this at the top:
```typescript
/* eslint-disable @typescript-eslint/no-explicit-any, @typescript-eslint/no-unused-vars */
```

---

*Testing analysis: 2026-03-25*

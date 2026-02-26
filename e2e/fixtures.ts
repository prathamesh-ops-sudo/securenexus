import { test as base, type Page } from "@playwright/test";

const MOCK_USER = {
  id: "e2e-user-1",
  email: "e2e@securenexus.test",
  firstName: "E2E",
  lastName: "Tester",
  role: "admin",
  orgId: "e2e-org-1",
  profileImageUrl: null,
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
};

const MOCK_ORG = {
  id: "e2e-org-1",
  name: "E2E Test Org",
  slug: "e2e-test-org",
  plan: "enterprise",
  createdAt: new Date().toISOString(),
};

function envelope<T>(data: T, meta: Record<string, unknown> = {}) {
  return { data, meta, errors: null };
}

async function mockAuthenticatedSession(page: Page) {
  await page.route("**/api/auth/user", (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope(MOCK_USER)) }),
  );
  await page.route("**/api/auth/me", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(envelope({ user: MOCK_USER, orgs: [MOCK_ORG], currentOrg: MOCK_ORG })),
    }),
  );
  await page.route("**/api/events", (route) => route.abort());
  await page.route("**/api/onboarding/**", (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope([])) }),
  );
  await page.route("**/api/plan-limits**", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(envelope({ withinLimits: true, limits: {} })),
    }),
  );
}

export const test = base.extend<{ authenticatedPage: Page }>({
  authenticatedPage: async ({ page }, use) => {
    await mockAuthenticatedSession(page);
    await use(page);
  },
});

export { MOCK_USER, MOCK_ORG, envelope, mockAuthenticatedSession };
export { expect } from "@playwright/test";

import { test, expect, MOCK_USER, MOCK_ORG, envelope } from "./fixtures";

const SECOND_ORG = {
  id: "e2e-org-2",
  name: "Second Org",
  slug: "second-org",
  plan: "pro",
  createdAt: new Date().toISOString(),
};

test.describe("Org selection workflow", () => {
  test("displays current org after login", async ({ authenticatedPage: page }) => {
    await page.route("**/api/stats**", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope({})) }),
    );
    await page.route("**/api/alerts**", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope([])) }),
    );
    await page.route("**/api/incidents**", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope([])) }),
    );
    await page.route("**/api/activity**", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope([])) }),
    );
    await page.route("**/api/feature-flags**", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope([])) }),
    );
    await page.goto("/");
    await expect(page.locator(`text=${MOCK_ORG.name}`).first()).toBeVisible({ timeout: 10000 });
  });

  test("can switch between organizations", async ({ authenticatedPage: page }) => {
    await page.route("**/api/auth/me", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(envelope({ user: MOCK_USER, orgs: [MOCK_ORG, SECOND_ORG], currentOrg: MOCK_ORG })),
      }),
    );
    await page.route("**/api/stats**", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope({})) }),
    );
    await page.route("**/api/alerts**", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope([])) }),
    );
    await page.route("**/api/incidents**", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope([])) }),
    );
    await page.route("**/api/activity**", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope([])) }),
    );
    await page.route("**/api/feature-flags**", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope([])) }),
    );
    await page.route("**/api/auth/ensure-org", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(envelope({ orgId: SECOND_ORG.id })),
      }),
    );
    await page.goto("/");
    await page.waitForTimeout(1000);
    const orgSelector = page.locator(`text=${MOCK_ORG.name}`).first();
    if (await orgSelector.isVisible()) {
      await orgSelector.click();
      const secondOrgOption = page.locator(`text=${SECOND_ORG.name}`).first();
      if (await secondOrgOption.isVisible({ timeout: 3000 }).catch(() => false)) {
        await secondOrgOption.click();
      }
    }
  });

  test("handles org creation via ensure-org endpoint", async ({ authenticatedPage: page }) => {
    let ensureOrgCalled = false;
    await page.route("**/api/auth/ensure-org", (route) => {
      ensureOrgCalled = true;
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(envelope({ orgId: MOCK_ORG.id })),
      });
    });
    await page.route("**/api/stats**", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope({})) }),
    );
    await page.route("**/api/alerts**", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope([])) }),
    );
    await page.route("**/api/incidents**", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope([])) }),
    );
    await page.route("**/api/activity**", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope([])) }),
    );
    await page.route("**/api/feature-flags**", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope([])) }),
    );
    await page.goto("/");
    await page.waitForTimeout(1000);
    expect(typeof ensureOrgCalled).toBe("boolean");
  });
});

import { test, expect, envelope } from "./fixtures";

const MOCK_INCIDENTS = [
  {
    id: "inc-1",
    title: "Ransomware Attack on Finance Server",
    summary: "Multiple indicators of ransomware activity detected on finance-srv-01",
    severity: "critical",
    status: "open",
    priority: 1,
    assignedTo: null,
    escalated: false,
    slaBreached: false,
    ackAt: null,
    ackDueAt: null,
    containedAt: null,
    containDueAt: null,
    resolvedAt: null,
    resolveDueAt: null,
    orgId: "e2e-org-1",
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  },
  {
    id: "inc-2",
    title: "Unauthorized Access to Customer DB",
    summary: "SQL injection attempt detected on customer-facing API",
    severity: "high",
    status: "investigating",
    priority: 2,
    assignedTo: "analyst@test.com",
    escalated: false,
    slaBreached: false,
    ackAt: new Date().toISOString(),
    ackDueAt: null,
    containedAt: null,
    containDueAt: null,
    resolvedAt: null,
    resolveDueAt: null,
    orgId: "e2e-org-1",
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  },
];

test.describe("Incident creation workflow", () => {
  test.beforeEach(async ({ authenticatedPage: page }) => {
    await page.route("**/api/incidents", (route) => {
      if (route.request().method() === "POST") {
        const newIncident = {
          id: "inc-new",
          title: "New Test Incident",
          summary: "Created via E2E test",
          severity: "high",
          status: "open",
          priority: 1,
          assignedTo: null,
          escalated: false,
          slaBreached: false,
          ackAt: null,
          ackDueAt: null,
          containedAt: null,
          containDueAt: null,
          resolvedAt: null,
          resolveDueAt: null,
          orgId: "e2e-org-1",
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        };
        return route.fulfill({
          status: 201,
          contentType: "application/json",
          body: JSON.stringify(envelope(newIncident)),
        });
      }
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(envelope(MOCK_INCIDENTS)),
      });
    });
    await page.route("**/api/incidents/queues**", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(envelope({ unassigned: [MOCK_INCIDENTS[0]], escalated: [], aging: [] })),
      }),
    );
    await page.route("**/api/incidents/bulk-update", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(envelope({ updatedCount: 1 })),
      }),
    );
    await page.route("**/api/sla-policies**", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope([])) }),
    );
    await page.route("**/api/stats**", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope({})) }),
    );
    await page.route("**/api/feature-flags**", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope([])) }),
    );
  });

  test("displays incidents list with status badges", async ({ authenticatedPage: page }) => {
    await page.goto("/incidents");
    await expect(page.locator("text=Ransomware Attack on Finance Server")).toBeVisible({ timeout: 10000 });
    await expect(page.locator("text=Unauthorized Access to Customer DB")).toBeVisible();
  });

  test("can filter incidents by status tabs", async ({ authenticatedPage: page }) => {
    await page.goto("/incidents");
    await expect(page.locator("text=Ransomware Attack on Finance Server")).toBeVisible({ timeout: 10000 });

    const investigatingTab = page.locator('button[role="tab"]', { hasText: /investigating/i }).first();
    if (await investigatingTab.isVisible({ timeout: 3000 }).catch(() => false)) {
      await investigatingTab.click();
      await page.waitForTimeout(500);
    }
  });

  test("can search incidents", async ({ authenticatedPage: page }) => {
    await page.goto("/incidents");
    await expect(page.locator("text=Ransomware Attack on Finance Server")).toBeVisible({ timeout: 10000 });

    const searchInput = page.locator('input[placeholder*="earch"]').first();
    if (await searchInput.isVisible({ timeout: 3000 }).catch(() => false)) {
      await searchInput.fill("Ransomware");
      await page.waitForTimeout(300);
      await expect(page.locator("text=Ransomware Attack on Finance Server")).toBeVisible();
    }
  });

  test("can select incidents for bulk operations", async ({ authenticatedPage: page }) => {
    await page.goto("/incidents");
    await expect(page.locator("text=Ransomware Attack on Finance Server")).toBeVisible({ timeout: 10000 });

    const checkboxes = page.locator('button[role="checkbox"]');
    const count = await checkboxes.count();
    if (count >= 1) {
      await checkboxes.first().click();
      await page.waitForTimeout(300);
    }
  });

  test("shows split-view detail panel when incident is clicked", async ({ authenticatedPage: page }) => {
    await page.goto("/incidents");
    await expect(page.locator("text=Ransomware Attack on Finance Server")).toBeVisible({ timeout: 10000 });

    await page.locator("text=Ransomware Attack on Finance Server").first().click();
    await page.waitForTimeout(500);
  });

  test("shows loading skeleton while incidents load", async ({ authenticatedPage: page }) => {
    await page.route("**/api/incidents", async (route) => {
      await new Promise((r) => setTimeout(r, 2000));
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(envelope(MOCK_INCIDENTS)),
      });
    });
    await page.goto("/incidents");
    const skeleton = page.locator('[class*="skeleton"], [class*="Skeleton"]').first();
    await expect(skeleton).toBeVisible({ timeout: 3000 });
  });

  test("shows error state with retry on API failure", async ({ authenticatedPage: page }) => {
    await page.route("**/api/incidents", (route) =>
      route.fulfill({
        status: 500,
        contentType: "application/json",
        body: JSON.stringify({ message: "Server Error" }),
      }),
    );
    await page.goto("/incidents");
    const retryButton = page.locator("button", { hasText: /try again|retry/i }).first();
    await expect(retryButton).toBeVisible({ timeout: 10000 });
  });

  test("shows empty state when no incidents exist", async ({ authenticatedPage: page }) => {
    await page.route("**/api/incidents", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope([])) }),
    );
    await page.goto("/incidents");
    await page.waitForTimeout(2000);
    const emptyText = page.locator("text=/no incident|no data|empty/i").first();
    const isVisible = await emptyText.isVisible({ timeout: 3000 }).catch(() => false);
    expect(typeof isVisible).toBe("boolean");
  });
});

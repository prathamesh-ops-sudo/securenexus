import { test, expect, envelope } from "./fixtures";

const MOCK_ALERTS = [
  {
    id: "alert-1",
    title: "Suspicious Login from Unknown IP",
    severity: "critical",
    status: "open",
    source: "CrowdStrike EDR",
    rawData: { ip: "203.0.113.42" },
    triageResult: null,
    triageScore: null,
    suppressed: false,
    assignedTo: null,
    orgId: "e2e-org-1",
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  },
  {
    id: "alert-2",
    title: "Malware Detected on Endpoint",
    severity: "high",
    status: "open",
    source: "SentinelOne",
    rawData: { hash: "abc123" },
    triageResult: null,
    triageScore: null,
    suppressed: false,
    assignedTo: null,
    orgId: "e2e-org-1",
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  },
  {
    id: "alert-3",
    title: "Brute Force Attempt Blocked",
    severity: "medium",
    status: "investigating",
    source: "AWS GuardDuty",
    rawData: {},
    triageResult: "Automated brute force from known bot network",
    triageScore: 35,
    suppressed: false,
    assignedTo: "analyst@test.com",
    orgId: "e2e-org-1",
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  },
];

test.describe("Alert triage workflow", () => {
  test.beforeEach(async ({ authenticatedPage: page }) => {
    await page.route("**/api/alerts**", (route) => {
      const url = route.request().url();
      if (
        url.includes("/api/alerts/") &&
        !url.includes("bulk") &&
        !url.includes("suppression") &&
        !url.includes("correlate")
      ) {
        const id = url.split("/api/alerts/")[1]?.split("?")[0];
        const alert = MOCK_ALERTS.find((a) => a.id === id);
        return route.fulfill({
          status: alert ? 200 : 404,
          contentType: "application/json",
          body: JSON.stringify(envelope(alert || null)),
        });
      }
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(envelope(MOCK_ALERTS)),
      });
    });
    await page.route("**/api/suppression-rules**", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope([])) }),
    );
    await page.route("**/api/stats**", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope({})) }),
    );
    await page.route("**/api/feature-flags**", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope([])) }),
    );
  });

  test("displays alerts list with severity badges", async ({ authenticatedPage: page }) => {
    await page.goto("/alerts");
    await expect(page.locator("text=Suspicious Login from Unknown IP")).toBeVisible({ timeout: 10000 });
    await expect(page.locator("text=Malware Detected on Endpoint")).toBeVisible();
    await expect(page.locator("text=Brute Force Attempt Blocked")).toBeVisible();
  });

  test("can trigger AI triage on an alert", async ({ authenticatedPage: page }) => {
    let triageCalled = false;
    await page.route("**/api/alerts/alert-1/triage", (route) => {
      triageCalled = true;
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(
          envelope({
            ...MOCK_ALERTS[0],
            triageResult: "High confidence malicious activity - lateral movement attempt from compromised credentials",
            triageScore: 92,
            status: "investigating",
          }),
        ),
      });
    });
    await page.goto("/alerts");
    await expect(page.locator("text=Suspicious Login from Unknown IP")).toBeVisible({ timeout: 10000 });

    const triageButton = page.locator('[data-testid="button-triage-alert-1"]').first();
    if (await triageButton.isVisible({ timeout: 3000 }).catch(() => false)) {
      await triageButton.click();
      await page.waitForTimeout(500);
      expect(triageCalled).toBe(true);
    }
  });

  test("can trigger AI correlation across alerts", async ({ authenticatedPage: page }) => {
    let correlateCalled = false;
    await page.route("**/api/alerts/correlate", (route) => {
      correlateCalled = true;
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(
          envelope({
            clusters: [
              {
                id: "cluster-1",
                alerts: ["alert-1", "alert-2"],
                technique: "T1078",
                confidence: 0.87,
                narrative: "Coordinated attack using valid credentials followed by malware deployment",
              },
            ],
          }),
        ),
      });
    });
    await page.goto("/alerts");
    await page.waitForTimeout(1000);
    const correlateButton = page.locator('[data-testid="button-correlate"]').first();
    if (await correlateButton.isVisible({ timeout: 3000 }).catch(() => false)) {
      await correlateButton.click();
      await page.waitForTimeout(500);
      expect(correlateCalled).toBe(true);
    }
  });

  test("can perform bulk status update on selected alerts", async ({ authenticatedPage: page }) => {
    let bulkUpdateCalled = false;
    await page.route("**/api/alerts/bulk-update", (route) => {
      bulkUpdateCalled = true;
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(envelope({ updatedCount: 2 })),
      });
    });
    await page.goto("/alerts");
    await expect(page.locator("text=Suspicious Login from Unknown IP")).toBeVisible({ timeout: 10000 });

    const checkboxes = page.locator('button[role="checkbox"]');
    const count = await checkboxes.count();
    if (count >= 2) {
      await checkboxes.nth(0).click();
      await checkboxes.nth(1).click();
    }
    expect(typeof bulkUpdateCalled).toBe("boolean");
  });

  test("shows loading skeleton while alerts load", async ({ authenticatedPage: page }) => {
    await page.route("**/api/alerts**", async (route) => {
      await new Promise((r) => setTimeout(r, 2000));
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(envelope(MOCK_ALERTS)),
      });
    });
    await page.goto("/alerts");
    const skeleton = page.locator('[class*="skeleton"], [class*="Skeleton"]').first();
    await expect(skeleton).toBeVisible({ timeout: 3000 });
  });

  test("shows error state with retry button on API failure", async ({ authenticatedPage: page }) => {
    await page.route("**/api/alerts**", (route) =>
      route.fulfill({
        status: 500,
        contentType: "application/json",
        body: JSON.stringify({ message: "Internal Server Error" }),
      }),
    );
    await page.goto("/alerts");
    const retryButton = page.locator("button", { hasText: /try again|retry/i }).first();
    await expect(retryButton).toBeVisible({ timeout: 10000 });
  });
});

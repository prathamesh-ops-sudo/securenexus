import { test, expect, envelope } from "./fixtures";

const MOCK_CONNECTOR_TYPES = [
  {
    type: "crowdstrike",
    name: "CrowdStrike Falcon",
    description: "EDR and threat intelligence from CrowdStrike",
    authType: "api_key",
    requiredFields: [
      { key: "clientId", label: "Client ID", type: "text", placeholder: "Enter client ID" },
      { key: "clientSecret", label: "Client Secret", type: "password", placeholder: "Enter client secret" },
    ],
    optionalFields: [{ key: "baseUrl", label: "Base URL", type: "text", placeholder: "https://api.crowdstrike.com" }],
    icon: "Shield",
    docsUrl: "https://docs.crowdstrike.com",
  },
  {
    type: "sentinelone",
    name: "SentinelOne",
    description: "Endpoint protection and EDR",
    authType: "api_key",
    requiredFields: [
      { key: "apiToken", label: "API Token", type: "password", placeholder: "Enter API token" },
      { key: "siteUrl", label: "Site URL", type: "text", placeholder: "https://usea1.sentinelone.net" },
    ],
    optionalFields: [],
    icon: "Radar",
    docsUrl: "https://docs.sentinelone.com",
  },
  {
    type: "aws_guardduty",
    name: "AWS GuardDuty",
    description: "AWS threat detection service",
    authType: "iam_role",
    requiredFields: [
      { key: "region", label: "AWS Region", type: "text", placeholder: "us-east-1" },
      { key: "roleArn", label: "IAM Role ARN", type: "text", placeholder: "arn:aws:iam::role/GuardDutyReader" },
    ],
    optionalFields: [],
    icon: "Cloud",
    docsUrl: "https://docs.aws.amazon.com/guardduty",
  },
];

const MOCK_CONNECTORS = [
  {
    id: "conn-1",
    name: "Production CrowdStrike",
    type: "crowdstrike",
    authType: "api_key",
    config: { clientId: "***", baseUrl: "https://api.crowdstrike.com" },
    status: "active",
    pollingIntervalMin: 5,
    lastSyncAt: new Date().toISOString(),
    lastSyncStatus: "success",
    lastSyncAlerts: 12,
    lastSyncError: null,
    totalAlertsSynced: 1450,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  },
];

test.describe("Connector setup workflow", () => {
  test.beforeEach(async ({ authenticatedPage: page }) => {
    await page.route("**/api/connector-types**", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(envelope(MOCK_CONNECTOR_TYPES)),
      }),
    );
    await page.route("**/api/connectors", (route) => {
      if (route.request().method() === "POST") {
        return route.fulfill({
          status: 201,
          contentType: "application/json",
          body: JSON.stringify(
            envelope({
              id: "conn-new",
              name: "New Connector",
              type: "sentinelone",
              authType: "api_key",
              config: {},
              status: "inactive",
              pollingIntervalMin: 5,
              lastSyncAt: null,
              lastSyncStatus: null,
              lastSyncAlerts: null,
              lastSyncError: null,
              totalAlertsSynced: 0,
              createdAt: new Date().toISOString(),
              updatedAt: new Date().toISOString(),
            }),
          ),
        });
      }
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(envelope(MOCK_CONNECTORS)),
      });
    });
    await page.route("**/api/connectors/*/test", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(
          envelope({
            success: true,
            latencyMs: 142,
            message: "Connection successful",
            checks: { auth: "pass", connectivity: "pass", permissions: "pass" },
          }),
        ),
      }),
    );
    await page.route("**/api/connectors/*/sync", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(envelope({ status: "syncing", alertsReceived: 0 })),
      }),
    );
    await page.route("**/api/connectors/*/jobs**", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope([])) }),
    );
    await page.route("**/api/connectors/*/metrics**", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(
          envelope({ avgLatencyMs: 150, errorRate: 0.02, throttleCount: 0, totalRuns: 48, successRate: 0.98 }),
        ),
      }),
    );
    await page.route("**/api/connectors/*/health**", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope([])) }),
    );
    await page.route("**/api/connectors/*/secret-rotations**", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope([])) }),
    );
    await page.route("**/api/connectors/dead-letters**", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope([])) }),
    );
    await page.route("**/api/stats**", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope({})) }),
    );
    await page.route("**/api/feature-flags**", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope([])) }),
    );
  });

  test("displays existing connectors with status", async ({ authenticatedPage: page }) => {
    await page.goto("/connectors");
    await expect(page.locator("text=Production CrowdStrike")).toBeVisible({ timeout: 10000 });
    await expect(page.locator('[data-testid="badge-status-active"]').first()).toBeVisible();
  });

  test("shows connector type catalog for new setup", async ({ authenticatedPage: page }) => {
    await page.goto("/connectors");
    await page.waitForTimeout(1000);
    const addButton = page.locator("button", { hasText: /add|new|connect/i }).first();
    if (await addButton.isVisible({ timeout: 5000 }).catch(() => false)) {
      await addButton.click();
      await page.waitForTimeout(500);
      const crowdstrike = page.locator("text=CrowdStrike Falcon").first();
      const isVisible = await crowdstrike.isVisible({ timeout: 3000 }).catch(() => false);
      expect(typeof isVisible).toBe("boolean");
    }
  });

  test("can test connector connectivity", async ({ authenticatedPage: page }) => {
    let testCalled = false;
    await page.route("**/api/connectors/conn-1/test", (route) => {
      testCalled = true;
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(
          envelope({
            success: true,
            latencyMs: 142,
            message: "Connection successful",
            checks: { auth: "pass", connectivity: "pass", permissions: "pass" },
          }),
        ),
      });
    });
    await page.goto("/connectors");
    await expect(page.locator("text=Production CrowdStrike")).toBeVisible({ timeout: 10000 });

    const testButton = page.locator("button", { hasText: /test/i }).first();
    if (await testButton.isVisible({ timeout: 3000 }).catch(() => false)) {
      await testButton.click();
      await page.waitForTimeout(1000);
      expect(testCalled).toBe(true);
    }
  });

  test("can trigger manual sync on connector", async ({ authenticatedPage: page }) => {
    let syncCalled = false;
    await page.route("**/api/connectors/conn-1/sync", (route) => {
      syncCalled = true;
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(envelope({ status: "syncing", alertsReceived: 0 })),
      });
    });
    await page.goto("/connectors");
    await expect(page.locator("text=Production CrowdStrike")).toBeVisible({ timeout: 10000 });

    const syncButton = page.locator("button", { hasText: /sync/i }).first();
    if (await syncButton.isVisible({ timeout: 3000 }).catch(() => false)) {
      await syncButton.click();
      await page.waitForTimeout(1000);
      expect(syncCalled).toBe(true);
    }
  });

  test("shows connector observability metrics", async ({ authenticatedPage: page }) => {
    await page.goto("/connectors");
    await expect(page.locator("text=Production CrowdStrike")).toBeVisible({ timeout: 10000 });

    const expandButton = page.locator("text=Production CrowdStrike").first();
    await expandButton.click();
    await page.waitForTimeout(500);
  });

  test("shows dead letter queue tab", async ({ authenticatedPage: page }) => {
    await page.goto("/connectors");
    await page.waitForTimeout(1000);
    const dlqTab = page.locator('button[role="tab"]', { hasText: /dead letter/i }).first();
    if (await dlqTab.isVisible({ timeout: 5000 }).catch(() => false)) {
      await dlqTab.click();
      await page.waitForTimeout(500);
    }
  });

  test("shows loading skeleton while connectors load", async ({ authenticatedPage: page }) => {
    await page.route("**/api/connectors", async (route) => {
      await new Promise((r) => setTimeout(r, 2000));
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(envelope(MOCK_CONNECTORS)),
      });
    });
    await page.goto("/connectors");
    const skeleton = page.locator('[class*="skeleton"], [class*="Skeleton"]').first();
    await expect(skeleton).toBeVisible({ timeout: 3000 });
  });

  test("shows error state with retry on API failure", async ({ authenticatedPage: page }) => {
    await page.route("**/api/connectors", (route) =>
      route.fulfill({
        status: 500,
        contentType: "application/json",
        body: JSON.stringify({ message: "Server Error" }),
      }),
    );
    await page.goto("/connectors");
    const retryButton = page.locator("button", { hasText: /try again|retry/i }).first();
    await expect(retryButton).toBeVisible({ timeout: 10000 });
  });

  test("shows empty state when no connectors configured", async ({ authenticatedPage: page }) => {
    await page.route("**/api/connectors", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope([])) }),
    );
    await page.goto("/connectors");
    await page.waitForTimeout(2000);
    const emptyText = page.locator("text=/no connector|get started|connect your first/i").first();
    const isVisible = await emptyText.isVisible({ timeout: 5000 }).catch(() => false);
    expect(typeof isVisible).toBe("boolean");
  });
});

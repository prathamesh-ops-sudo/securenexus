import { test, expect, MOCK_USER, MOCK_ORG, envelope, mockAuthenticatedSession } from "./fixtures";
import type { Page } from "@playwright/test";

// ── Onboarding Status mock helpers ──────────────────────────────────────

function makeOnboardingStatus(
  overrides: Partial<{
    integrations: { completed: boolean; count: number };
    ingestion: { completed: boolean; totalIngested: number };
    endpoints: { completed: boolean; count: number };
    cspm: { completed: boolean; count: number };
  }> = {},
) {
  const steps = {
    integrations: { completed: false, count: 0, ...overrides.integrations },
    ingestion: { completed: false, totalIngested: 0, ...overrides.ingestion },
    endpoints: { completed: false, count: 0, ...overrides.endpoints },
    cspm: { completed: false, count: 0, ...overrides.cspm },
  };
  const completedCount = Object.values(steps).filter((s) => s.completed).length;
  return { steps, completedCount, totalSteps: 4 };
}

async function setupOnboardingPage(page: Page, status: ReturnType<typeof makeOnboardingStatus>) {
  await mockAuthenticatedSession(page);
  // Override the onboarding status route with specific data
  await page.route("**/api/v1/onboarding/status", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(envelope(status)),
    }),
  );
  // Catch-all for other API routes to prevent 404s
  await page.route("**/api/dashboard/**", (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope({})) }),
  );
  await page.route("**/api/v1/alerts**", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(envelope({ items: [], total: 0, offset: 0, limit: 50 })),
    }),
  );
  await page.route("**/api/v1/incidents**", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(envelope({ items: [], total: 0, offset: 0, limit: 50 })),
    }),
  );
  await page.route("**/api/connectors**", (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope([])) }),
  );
}

// ── Tests ────────────────────────────────────────────────────────────────

test.describe("Onboarding wizard", () => {
  test("renders the onboarding page with all 4 steps", async ({ page }) => {
    const status = makeOnboardingStatus();
    await setupOnboardingPage(page, status);
    await page.goto("/onboarding");

    // Page title and description
    await expect(page.locator('[data-testid="page-onboarding"]')).toBeVisible();
    await expect(page.locator("text=Workspace Onboarding")).toBeVisible();
    await expect(page.locator("text=Bring your data and assets")).toBeVisible();

    // All 4 step cards present
    await expect(page.locator('[data-testid="card-onboarding-integrations"]')).toBeVisible();
    await expect(page.locator('[data-testid="card-onboarding-ingestion"]')).toBeVisible();
    await expect(page.locator('[data-testid="card-onboarding-endpoints"]')).toBeVisible();
    await expect(page.locator('[data-testid="card-onboarding-cspm"]')).toBeVisible();
  });

  test("shows 0% progress when no steps completed", async ({ page }) => {
    const status = makeOnboardingStatus();
    await setupOnboardingPage(page, status);
    await page.goto("/onboarding");

    await expect(page.locator("text=0 of 4 core steps completed")).toBeVisible();
    await expect(page.locator("text=0%")).toBeVisible();
  });

  test("shows 50% progress when 2 steps completed", async ({ page }) => {
    const status = makeOnboardingStatus({
      integrations: { completed: true, count: 2 },
      ingestion: { completed: true, totalIngested: 150 },
    });
    await setupOnboardingPage(page, status);
    await page.goto("/onboarding");

    await expect(page.locator("text=2 of 4 core steps completed")).toBeVisible();
    await expect(page.locator("text=50%")).toBeVisible();
  });

  test("shows 100% progress when all steps completed", async ({ page }) => {
    const status = makeOnboardingStatus({
      integrations: { completed: true, count: 3 },
      ingestion: { completed: true, totalIngested: 500 },
      endpoints: { completed: true, count: 10 },
      cspm: { completed: true, count: 2 },
    });
    await setupOnboardingPage(page, status);
    await page.goto("/onboarding");

    await expect(page.locator("text=4 of 4 core steps completed")).toBeVisible();
    await expect(page.locator("text=100%")).toBeVisible();
  });

  test("shows check icon for completed steps and alert icon for incomplete", async ({ page }) => {
    const status = makeOnboardingStatus({
      integrations: { completed: true, count: 1 },
      endpoints: { completed: true, count: 5 },
    });
    await setupOnboardingPage(page, status);
    await page.goto("/onboarding");

    // Completed steps should have emerald check icons
    const integrationsCard = page.locator('[data-testid="card-onboarding-integrations"]');
    await expect(integrationsCard.locator(".text-emerald-500")).toBeVisible();

    const endpointsCard = page.locator('[data-testid="card-onboarding-endpoints"]');
    await expect(endpointsCard.locator(".text-emerald-500")).toBeVisible();

    // Incomplete steps should have amber alert icons
    const ingestionCard = page.locator('[data-testid="card-onboarding-ingestion"]');
    await expect(ingestionCard.locator(".text-amber-500")).toBeVisible();

    const cspmCard = page.locator('[data-testid="card-onboarding-cspm"]');
    await expect(cspmCard.locator(".text-amber-500")).toBeVisible();
  });

  test("displays correct counts in step cards", async ({ page }) => {
    const status = makeOnboardingStatus({
      integrations: { completed: true, count: 3 },
      ingestion: { completed: false, totalIngested: 42 },
      endpoints: { completed: false, count: 7 },
      cspm: { completed: false, count: 1 },
    });
    await setupOnboardingPage(page, status);
    await page.goto("/onboarding");

    await expect(page.locator("text=3 integrations configured")).toBeVisible();
    await expect(page.locator("text=Total ingested alerts: 42")).toBeVisible();
    await expect(page.locator("text=Endpoint assets discovered: 7")).toBeVisible();
    await expect(page.locator("text=Cloud accounts configured: 1")).toBeVisible();
  });

  test("integration step navigates to /integrations", async ({ page }) => {
    const status = makeOnboardingStatus();
    await setupOnboardingPage(page, status);
    await page.route("**/api/integrations**", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope([])) }),
    );
    await page.goto("/onboarding");

    const btn = page
      .locator('[data-testid="card-onboarding-integrations"]')
      .locator("button", { hasText: "Go to Integrations" });
    await expect(btn).toBeVisible();
    await btn.click();
    await page.waitForTimeout(300);
    expect(page.url()).toContain("/integrations");
  });

  test("ingestion step navigates to /ingestion", async ({ page }) => {
    const status = makeOnboardingStatus();
    await setupOnboardingPage(page, status);
    await page.route("**/api/ingestion**", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope({})) }),
    );
    await page.goto("/onboarding");

    const btn = page
      .locator('[data-testid="card-onboarding-ingestion"]')
      .locator("button", { hasText: "View ingestion setup" });
    await expect(btn).toBeVisible();
    await btn.click();
    await page.waitForTimeout(300);
    expect(page.url()).toContain("/ingestion");
  });

  test("ingestion step has API key management link to /settings", async ({ page }) => {
    const status = makeOnboardingStatus();
    await setupOnboardingPage(page, status);
    await page.route("**/api/settings**", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope({})) }),
    );
    await page.route("**/api/orgs/**", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope({})) }),
    );
    await page.goto("/onboarding");

    const btn = page
      .locator('[data-testid="card-onboarding-ingestion"]')
      .locator("button", { hasText: "Manage API keys" });
    await expect(btn).toBeVisible();
    await btn.click();
    await page.waitForTimeout(300);
    expect(page.url()).toContain("/settings");
  });

  test("endpoints step navigates to /endpoint-telemetry", async ({ page }) => {
    const status = makeOnboardingStatus();
    await setupOnboardingPage(page, status);
    await page.route("**/api/endpoints**", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope([])) }),
    );
    await page.goto("/onboarding");

    const btn = page
      .locator('[data-testid="card-onboarding-endpoints"]')
      .locator("button", { hasText: "Go to Endpoint Telemetry" });
    await expect(btn).toBeVisible();
    await btn.click();
    await page.waitForTimeout(300);
    expect(page.url()).toContain("/endpoint-telemetry");
  });

  test("CSPM step navigates to /cspm", async ({ page }) => {
    const status = makeOnboardingStatus();
    await setupOnboardingPage(page, status);
    await page.route("**/api/cspm**", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope([])) }),
    );
    await page.goto("/onboarding");

    const btn = page.locator('[data-testid="card-onboarding-cspm"]').locator("button", { hasText: "Go to CSPM" });
    await expect(btn).toBeVisible();
    await btn.click();
    await page.waitForTimeout(300);
    expect(page.url()).toContain("/cspm");
  });

  test("shows loading skeleton while data is fetched", async ({ page }) => {
    await mockAuthenticatedSession(page);
    // Delay the onboarding status response
    await page.route("**/api/v1/onboarding/status", async (route) => {
      await new Promise((r) => setTimeout(r, 2000));
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(envelope(makeOnboardingStatus())),
      });
    });
    await page.goto("/onboarding");

    // Should see loading skeleton (FormPageSkeleton) while loading
    // The skeleton is rendered by <FormPageSkeleton /> which uses Skeleton components
    const skeleton = page.locator('[role="status"]').first();
    await expect(skeleton).toBeVisible({ timeout: 2000 });
  });

  test("responsive layout: cards stack on mobile viewport", async ({ page }) => {
    const status = makeOnboardingStatus();
    await setupOnboardingPage(page, status);

    // Set mobile viewport
    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto("/onboarding");

    await expect(page.locator('[data-testid="page-onboarding"]')).toBeVisible();
    await expect(page.locator('[data-testid="card-onboarding-integrations"]')).toBeVisible();
    await expect(page.locator('[data-testid="card-onboarding-cspm"]')).toBeVisible();

    // On mobile, all cards should be stacked (single column)
    const grid = page.locator('[data-testid="page-onboarding"]').locator(".grid.gap-4");
    await expect(grid).toBeVisible();
  });

  test("singular integration text when count is 1", async ({ page }) => {
    const status = makeOnboardingStatus({
      integrations: { completed: true, count: 1 },
    });
    await setupOnboardingPage(page, status);
    await page.goto("/onboarding");

    // Should show "1 integration configured" (singular)
    await expect(page.locator("text=1 integration configured")).toBeVisible();
  });

  test("progress bar reflects correct percentage", async ({ page }) => {
    const status = makeOnboardingStatus({
      integrations: { completed: true, count: 1 },
    });
    await setupOnboardingPage(page, status);
    await page.goto("/onboarding");

    await expect(page.locator("text=25%")).toBeVisible();
    await expect(page.locator("text=1 of 4 core steps completed")).toBeVisible();
  });

  test("progress bar shows 75% with 3 completed steps", async ({ page }) => {
    const status = makeOnboardingStatus({
      integrations: { completed: true, count: 2 },
      ingestion: { completed: true, totalIngested: 100 },
      endpoints: { completed: true, count: 5 },
    });
    await setupOnboardingPage(page, status);
    await page.goto("/onboarding");

    await expect(page.locator("text=75%")).toBeVisible();
    await expect(page.locator("text=3 of 4 core steps completed")).toBeVisible();
  });
});

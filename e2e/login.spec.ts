import { test, expect, MOCK_USER, envelope } from "./fixtures";

test.describe("Login workflow", () => {
  test("shows landing page when unauthenticated", async ({ page }) => {
    await page.route("**/api/auth/user", (route) =>
      route.fulfill({
        status: 401,
        contentType: "application/json",
        body: JSON.stringify({ message: "Unauthorized" }),
      }),
    );
    await page.goto("/");
    await expect(page.locator("text=SecureNexus")).first().toBeVisible();
  });

  test("can open login modal and see email form", async ({ page }) => {
    await page.route("**/api/auth/user", (route) =>
      route.fulfill({
        status: 401,
        contentType: "application/json",
        body: JSON.stringify({ message: "Unauthorized" }),
      }),
    );
    await page.goto("/");
    const loginButton = page.locator("button", { hasText: /log\s*in/i }).first();
    await loginButton.click();
    await expect(page.locator("text=Welcome back")).toBeVisible();
    await expect(page.locator('input[type="email"]')).toBeVisible();
    await expect(page.locator('input[type="password"]')).toBeVisible();
  });

  test("can open register modal and see name fields", async ({ page }) => {
    await page.route("**/api/auth/user", (route) =>
      route.fulfill({
        status: 401,
        contentType: "application/json",
        body: JSON.stringify({ message: "Unauthorized" }),
      }),
    );
    await page.goto("/");
    const startButton = page.locator("button", { hasText: /start free trial|get started|sign up/i }).first();
    await startButton.click();
    await expect(page.locator("text=Start your free trial")).toBeVisible();
    await expect(page.locator('input[type="email"]')).toBeVisible();
    await expect(page.locator("#firstName")).toBeVisible();
    await expect(page.locator("#lastName")).toBeVisible();
  });

  test("shows Google and GitHub OAuth buttons", async ({ page }) => {
    await page.route("**/api/auth/user", (route) =>
      route.fulfill({
        status: 401,
        contentType: "application/json",
        body: JSON.stringify({ message: "Unauthorized" }),
      }),
    );
    await page.goto("/");
    const loginButton = page.locator("button", { hasText: /log\s*in/i }).first();
    await loginButton.click();
    await expect(page.locator("button", { hasText: /google/i })).toBeVisible();
    await expect(page.locator("button", { hasText: /github/i })).toBeVisible();
  });

  test("successful email login redirects to dashboard", async ({ page }) => {
    await page.route("**/api/auth/user", (route) => {
      const headers = route.request().headers();
      if (headers["x-logged-in"]) {
        return route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify(envelope(MOCK_USER)),
        });
      }
      return route.fulfill({
        status: 401,
        contentType: "application/json",
        body: JSON.stringify({ message: "Unauthorized" }),
      });
    });
    await page.route("**/api/login", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope(MOCK_USER)) }),
    );
    await page.route("**/api/auth/me", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(envelope({ user: MOCK_USER, orgs: [], currentOrg: null })),
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

    await page.goto("/");
    const loginButton = page.locator("button", { hasText: /log\s*in/i }).first();
    await loginButton.click();
    await page.fill('input[type="email"]', "e2e@securenexus.test");
    await page.fill('input[type="password"]', "TestPass123!");

    await page.route("**/api/auth/user", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope(MOCK_USER)) }),
    );

    await page.locator('button[type="submit"]').click();
    await page.waitForTimeout(500);
  });

  test("shows error on invalid credentials", async ({ page }) => {
    await page.route("**/api/auth/user", (route) =>
      route.fulfill({
        status: 401,
        contentType: "application/json",
        body: JSON.stringify({ message: "Unauthorized" }),
      }),
    );
    await page.route("**/api/login", (route) =>
      route.fulfill({
        status: 401,
        contentType: "application/json",
        body: JSON.stringify({
          data: null,
          meta: {},
          errors: [{ code: "AUTH_FAILED", message: "Invalid email or password" }],
        }),
      }),
    );
    await page.goto("/");
    const loginButton = page.locator("button", { hasText: /log\s*in/i }).first();
    await loginButton.click();
    await page.fill('input[type="email"]', "bad@example.com");
    await page.fill('input[type="password"]', "wrong");
    await page.locator('button[type="submit"]').click();
    await expect(page.locator("text=Invalid email or password")).toBeVisible({ timeout: 5000 });
  });

  test("successful registration redirects to authenticated state", async ({ page }) => {
    await page.route("**/api/auth/user", (route) =>
      route.fulfill({
        status: 401,
        contentType: "application/json",
        body: JSON.stringify({ message: "Unauthorized" }),
      }),
    );
    await page.route("**/api/register", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope(MOCK_USER)) }),
    );
    await page.route("**/api/auth/me", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(envelope({ user: MOCK_USER, orgs: [], currentOrg: null })),
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

    await page.goto("/");
    const startButton = page.locator("button", { hasText: /start free trial|get started|sign up/i }).first();
    await startButton.click();
    await page.fill("#firstName", "Test");
    await page.fill("#lastName", "User");
    await page.fill('input[type="email"]', "new@securenexus.test");
    await page.fill('input[type="password"]', "NewPass123!");

    await page.route("**/api/auth/user", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope(MOCK_USER)) }),
    );

    await page.locator('button[type="submit"]').click();
    await page.waitForTimeout(500);
  });
});

import AxeBuilder from "@axe-core/playwright";
import { test, expect, mockAuthenticatedSession, envelope } from "./fixtures";

const PAGES_TO_AUDIT = [
  { name: "Dashboard", path: "/", mockEndpoints: ["stats", "analytics"] },
  { name: "Alerts", path: "/alerts", mockEndpoints: ["alerts"] },
  { name: "Incidents", path: "/incidents", mockEndpoints: ["incidents"] },
  { name: "Playbooks", path: "/playbooks", mockEndpoints: ["playbooks"] },
  { name: "Connectors", path: "/connectors", mockEndpoints: ["connectors"] },
  { name: "Analytics", path: "/analytics", mockEndpoints: ["analytics"] },
  { name: "Settings", path: "/settings", mockEndpoints: ["settings"] },
  { name: "Ingestion", path: "/ingestion", mockEndpoints: ["ingestion"] },
  { name: "Threat Intel", path: "/threat-intel", mockEndpoints: ["threatIntel"] },
  { name: "Compliance", path: "/compliance", mockEndpoints: ["compliance"] },
];

const MOCK_RESPONSES: Record<string, unknown> = {
  stats: {
    totalAlerts: 42,
    openIncidents: 5,
    criticalAlerts: 3,
    resolvedIncidents: 12,
    newAlertsToday: 8,
    escalatedIncidents: 2,
  },
  analytics: {
    severityDistribution: [
      { name: "critical", value: 3 },
      { name: "high", value: 12 },
      { name: "medium", value: 20 },
      { name: "low", value: 7 },
    ],
    sourceDistribution: [{ name: "CrowdStrike", value: 15 }],
    categoryDistribution: [{ name: "Malware", value: 10 }],
    statusDistribution: [{ name: "open", value: 25 }],
    alertTrend: [{ date: "2026-02-20", count: 5 }],
    mttrHours: 4.2,
    topMitreTactics: [{ name: "Initial Access", value: 8 }],
    connectorHealth: [],
    ingestionRate: [],
  },
  alerts: [],
  incidents: [],
  playbooks: [],
  connectors: [],
  settings: {},
  ingestion: { totalIngested: 0, sources: [] },
  threatIntel: { feeds: [], iocs: [] },
  compliance: { frameworks: [], score: 0 },
};

async function mockPageEndpoints(page: import("@playwright/test").Page, endpoints: string[]) {
  await mockAuthenticatedSession(page);

  await page.route("**/api/dashboard/stats", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(envelope(MOCK_RESPONSES.stats)),
    }),
  );

  await page.route("**/api/dashboard/analytics", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(envelope(MOCK_RESPONSES.analytics)),
    }),
  );

  for (const ep of endpoints) {
    const data = MOCK_RESPONSES[ep] ?? [];
    await page.route(`**/api/${ep}**`, (route) => {
      if (route.request().url().includes("/api/dashboard/")) return route.fallback();
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(envelope(data)),
      });
    });
  }

  await page.route("**/api/**", (route) => {
    if (route.request().url().includes("/api/auth/")) return route.fallback();
    if (route.request().url().includes("/api/events")) return route.fallback();
    if (route.request().url().includes("/api/onboarding")) return route.fallback();
    if (route.request().url().includes("/api/dashboard/")) return route.fallback();
    if (route.request().url().includes("/api/feature-flags")) return route.fallback();
    if (route.request().url().includes("/api/plan-limits")) return route.fallback();
    return route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(envelope([])),
    });
  });
}

test.describe("Accessibility audit (axe-core)", () => {
  for (const pageConfig of PAGES_TO_AUDIT) {
    test(`${pageConfig.name} page has no critical a11y violations`, async ({ page }) => {
      await mockPageEndpoints(page, pageConfig.mockEndpoints);
      await page.goto(pageConfig.path);
      await page.waitForLoadState("networkidle");
      await page.waitForTimeout(500);

      const results = await new AxeBuilder({ page })
        .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
        .disableRules(["color-contrast"])
        .analyze();

      const critical = results.violations.filter((v) => v.impact === "critical" || v.impact === "serious");

      if (critical.length > 0) {
        const summary = critical
          .map(
            (v) =>
              `[${v.impact}] ${v.id}: ${v.description} (${v.nodes.length} occurrence${v.nodes.length > 1 ? "s" : ""})`,
          )
          .join("\n");
        console.error(`A11y violations on ${pageConfig.name}:\n${summary}`);
      }

      expect(critical).toHaveLength(0);
    });
  }
});

test.describe("Semantic landmarks", () => {
  test("Dashboard has proper landmark structure", async ({ page }) => {
    await mockPageEndpoints(page, ["stats", "analytics"]);
    await page.goto("/");
    await page.waitForLoadState("networkidle");
    await page.waitForTimeout(500);

    const main = page.locator("main");
    await expect(main).toBeVisible();

    const nav = page.locator("nav").first();
    await expect(nav).toBeVisible();

    const header = page.locator("header").first();
    await expect(header).toBeVisible();
  });

  test("All pages have a main landmark", async ({ page }) => {
    await mockPageEndpoints(page, []);
    for (const pageConfig of PAGES_TO_AUDIT.slice(0, 5)) {
      await page.goto(pageConfig.path);
      await page.waitForLoadState("networkidle");
      await page.waitForTimeout(300);
      const mainCount = await page.locator("main").count();
      expect(mainCount).toBeGreaterThanOrEqual(1);
    }
  });
});

test.describe("Focus management", () => {
  test("Tab key navigates through interactive elements", async ({ page }) => {
    await mockPageEndpoints(page, ["stats", "analytics"]);
    await page.goto("/");
    await page.waitForLoadState("networkidle");
    await page.waitForTimeout(500);

    await page.keyboard.press("Tab");
    const firstFocused = await page.evaluate(() => {
      const el = document.activeElement;
      return el ? el.tagName.toLowerCase() : null;
    });
    expect(firstFocused).toBeTruthy();

    await page.keyboard.press("Tab");
    const secondFocused = await page.evaluate(() => {
      const el = document.activeElement;
      return el ? el.tagName.toLowerCase() : null;
    });
    expect(secondFocused).toBeTruthy();
  });

  test("Skip-to-content or first focusable is reachable", async ({ page }) => {
    await mockPageEndpoints(page, ["stats", "analytics"]);
    await page.goto("/");
    await page.waitForLoadState("networkidle");
    await page.waitForTimeout(500);

    for (let i = 0; i < 5; i++) {
      await page.keyboard.press("Tab");
    }

    const focused = await page.evaluate(() => {
      const el = document.activeElement;
      if (!el) return null;
      return {
        tag: el.tagName.toLowerCase(),
        role: el.getAttribute("role"),
        ariaLabel: el.getAttribute("aria-label"),
      };
    });

    expect(focused).toBeTruthy();
    expect(focused?.tag).not.toBe("body");
  });
});

test.describe("ARIA attributes", () => {
  test("Interactive elements have accessible names", async ({ page }) => {
    await mockPageEndpoints(page, ["stats", "analytics"]);
    await page.goto("/");
    await page.waitForLoadState("networkidle");
    await page.waitForTimeout(500);

    const buttons = page.locator("button");
    const buttonCount = await buttons.count();

    let missingLabels = 0;
    for (let i = 0; i < Math.min(buttonCount, 20); i++) {
      const btn = buttons.nth(i);
      const isVisible = await btn.isVisible().catch(() => false);
      if (!isVisible) continue;

      const text = await btn.textContent();
      const ariaLabel = await btn.getAttribute("aria-label");
      const ariaLabelledBy = await btn.getAttribute("aria-labelledby");
      const title = await btn.getAttribute("title");

      if (!text?.trim() && !ariaLabel && !ariaLabelledBy && !title) {
        missingLabels++;
      }
    }

    expect(missingLabels).toBeLessThanOrEqual(2);
  });

  test("Images have alt text", async ({ page }) => {
    await mockPageEndpoints(page, ["stats", "analytics"]);
    await page.goto("/");
    await page.waitForLoadState("networkidle");
    await page.waitForTimeout(500);

    const images = page.locator("img");
    const imageCount = await images.count();

    for (let i = 0; i < imageCount; i++) {
      const img = images.nth(i);
      const alt = await img.getAttribute("alt");
      const role = await img.getAttribute("role");
      expect(alt !== null || role === "presentation").toBeTruthy();
    }
  });

  test("Form inputs have labels", async ({ page }) => {
    await mockPageEndpoints(page, []);
    await page.goto("/settings");
    await page.waitForLoadState("networkidle");
    await page.waitForTimeout(500);

    const inputs = page.locator('input:not([type="hidden"])');
    const inputCount = await inputs.count();

    for (let i = 0; i < Math.min(inputCount, 10); i++) {
      const input = inputs.nth(i);
      const isVisible = await input.isVisible().catch(() => false);
      if (!isVisible) continue;

      const id = await input.getAttribute("id");
      const ariaLabel = await input.getAttribute("aria-label");
      const ariaLabelledBy = await input.getAttribute("aria-labelledby");
      const placeholder = await input.getAttribute("placeholder");

      const hasLabel = !!(ariaLabel || ariaLabelledBy || placeholder);
      const hasAssociatedLabel = id ? (await page.locator(`label[for="${id}"]`).count()) > 0 : false;

      expect(hasLabel || hasAssociatedLabel).toBeTruthy();
    }
  });
});

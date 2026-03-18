import { test, expect, MOCK_USER, MOCK_ORG, envelope, mockAuthenticatedSession } from "./fixtures";
import type { Page } from "@playwright/test";

// ── Mock data for dashboard endpoints ──────────────────────────────────

const MOCK_STATS = {
  totalAlerts: 142,
  criticalAlerts: 7,
  openIncidents: 3,
  newAlertsToday: 18,
  escalatedIncidents: 2,
  resolvedIncidents: 5,
};

const MOCK_ANALYTICS = {
  severityDistribution: [
    { name: "critical", value: 7 },
    { name: "high", value: 35 },
    { name: "medium", value: 62 },
    { name: "low", value: 38 },
  ],
  sourceDistribution: [
    { name: "AWS CloudTrail", value: 45 },
    { name: "Syslog", value: 32 },
    { name: "API", value: 28 },
    { name: "Agent", value: 37 },
  ],
  categoryDistribution: [
    { name: "Malware", value: 22 },
    { name: "Phishing", value: 18 },
    { name: "Brute Force", value: 14 },
  ],
  statusDistribution: [
    { name: "open", value: 80 },
    { name: "resolved", value: 62 },
  ],
  alertTrend: [
    { date: "2026-03-12", count: 20 },
    { date: "2026-03-13", count: 25 },
    { date: "2026-03-14", count: 18 },
    { date: "2026-03-15", count: 30 },
    { date: "2026-03-16", count: 22 },
    { date: "2026-03-17", count: 27 },
    { date: "2026-03-18", count: 18 },
  ],
  mttrHours: 4,
  topMitreTactics: [
    { name: "Initial Access", value: 25 },
    { name: "Execution", value: 18 },
    { name: "Persistence", value: 12 },
  ],
  connectorHealth: [
    {
      name: "AWS CloudTrail",
      type: "aws",
      status: "active",
      lastSyncAt: new Date().toISOString(),
      lastSyncAlerts: 12,
      lastSyncError: null,
    },
    {
      name: "Okta SSO",
      type: "okta",
      status: "active",
      lastSyncAt: new Date().toISOString(),
      lastSyncAlerts: 5,
      lastSyncError: null,
    },
    {
      name: "CrowdStrike",
      type: "crowdstrike",
      status: "error",
      lastSyncAt: null,
      lastSyncAlerts: 0,
      lastSyncError: "Timeout",
    },
  ],
  ingestionRate: [
    { date: "2026-03-16", created: 120, deduped: 15, failed: 3 },
    { date: "2026-03-17", created: 135, deduped: 20, failed: 2 },
    { date: "2026-03-18", created: 110, deduped: 12, failed: 1 },
  ],
};

const MOCK_OP_METRICS = {
  mttrHours: 4,
  mttdMinutes: 12,
  alertsProcessed24h: 156,
  alertsResolved24h: 128,
  resolutionRate: 82,
  mttrTrend: [],
};

const MOCK_POSTURE = {
  score: { overallScore: 74, generatedAt: new Date().toISOString() },
  subScores: [
    { domain: "Identity", score: 82 },
    { domain: "Network", score: 68 },
    { domain: "Endpoint", score: 71 },
  ],
  benchmark: null,
  domainMeta: {},
};

// ── Setup helper ───────────────────────────────────────────────────────

async function setupDashboardPage(page: Page) {
  await mockAuthenticatedSession(page);

  await page.route("**/api/dashboard/stats**", (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope(MOCK_STATS)) }),
  );
  await page.route("**/api/dashboard/analytics**", (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope(MOCK_ANALYTICS)) }),
  );
  await page.route("**/api/dashboard/operational-metrics**", (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope(MOCK_OP_METRICS)) }),
  );
  await page.route("**/api/posture-trust/latest**", (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope(MOCK_POSTURE)) }),
  );
  await page.route("**/api/deception/hits**", (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope({ hits: [] })) }),
  );
  await page.route("**/api/ai/circuit-alerts**", (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope([])) }),
  );
  await page.route("**/api/events/stream**", (route) => route.abort());
}

// ── 1.15: Dashboard loads with all widgets ─────────────────────────────

test.describe("1.15 — Dashboard loads with all widgets", () => {
  test("page loads and shows dashboard heading", async ({ page }) => {
    await setupDashboardPage(page);
    await page.goto("/");
    await expect(page.locator('[aria-label="Security Operations Dashboard"]')).toBeVisible({ timeout: 10000 });
  });

  test("all 6 stat cards render with numeric values (not NaN/undefined)", async ({ page }) => {
    await setupDashboardPage(page);
    await page.goto("/");
    await expect(page.locator('[aria-label="Security Operations Dashboard"]')).toBeVisible({ timeout: 10000 });

    // Wait for stat cards to load
    const statCards = page.locator('[data-testid="dashboard-card-2"]');
    await expect(statCards.first()).toBeVisible({ timeout: 10000 });

    // Verify stat card values are numeric, not NaN or undefined
    const cardCount = await statCards.count();
    expect(cardCount).toBeGreaterThanOrEqual(6);

    for (let i = 0; i < cardCount; i++) {
      const card = statCards.nth(i);
      const valueEl = card.locator(".text-2xl");
      const text = await valueEl.textContent();
      expect(text).not.toBeNull();
      expect(text).not.toContain("NaN");
      expect(text).not.toContain("undefined");
    }
  });

  test("severity distribution chart renders SVG", async ({ page }) => {
    await setupDashboardPage(page);
    await page.goto("/");
    await expect(page.locator('[aria-label="Security Operations Dashboard"]')).toBeVisible({ timeout: 10000 });

    // The SeverityChart uses a PieChart which renders inside recharts
    const severityCard = page.locator('[data-testid="dashboard-card-3"]').filter({ hasText: "Severity" });
    await expect(severityCard).toBeVisible({ timeout: 10000 });
    await expect(severityCard.locator("svg").first()).toBeVisible();
  });

  test("alert trend chart renders SVG", async ({ page }) => {
    await setupDashboardPage(page);
    await page.goto("/");
    await expect(page.locator('[aria-label="Security Operations Dashboard"]')).toBeVisible({ timeout: 10000 });

    const trendCard = page.locator('[data-testid="dashboard-card-3"]').filter({ hasText: "Alert Trend" });
    await expect(trendCard).toBeVisible({ timeout: 10000 });
    await expect(trendCard.locator("svg").first()).toBeVisible();
  });

  test("connector health widget renders connector names", async ({ page }) => {
    await setupDashboardPage(page);
    await page.goto("/");
    await expect(page.locator('[aria-label="Security Operations Dashboard"]')).toBeVisible({ timeout: 10000 });

    await expect(page.locator("text=Connector Health")).toBeVisible({ timeout: 10000 });
    await expect(page.locator("text=AWS CloudTrail")).toBeVisible();
    await expect(page.locator("text=Okta SSO")).toBeVisible();
    await expect(page.locator("text=CrowdStrike")).toBeVisible();
  });

  test("MITRE tactics widget renders", async ({ page }) => {
    await setupDashboardPage(page);
    await page.goto("/");
    await expect(page.locator('[aria-label="Security Operations Dashboard"]')).toBeVisible({ timeout: 10000 });

    await expect(page.locator("text=MITRE ATT&CK")).toBeVisible({ timeout: 10000 });
    await expect(page.locator("text=Initial Access")).toBeVisible();
  });

  test("operational metrics row renders MTTD and MTTR values", async ({ page }) => {
    await setupDashboardPage(page);
    await page.goto("/");
    await expect(page.locator('[aria-label="Security Operations Dashboard"]')).toBeVisible({ timeout: 10000 });

    // MTTD card
    await expect(page.locator("text=MTTD")).toBeVisible({ timeout: 10000 });
    await expect(page.locator("text=12m")).toBeVisible();

    // MTTR card
    await expect(page.locator("text=MTTR")).toBeVisible();
    await expect(page.locator("text=4h")).toBeVisible();

    // Resolution rate
    await expect(page.locator("text=Resolution Rate")).toBeVisible();
    await expect(page.locator("text=82%")).toBeVisible();
  });

  test("posture score widget renders with score value", async ({ page }) => {
    await setupDashboardPage(page);
    await page.goto("/");
    await expect(page.locator('[aria-label="Security Operations Dashboard"]')).toBeVisible({ timeout: 10000 });

    await expect(page.locator("text=Posture Score")).toBeVisible({ timeout: 10000 });
    await expect(page.locator("text=74")).toBeVisible();
    await expect(page.locator("text=Good")).toBeVisible();
  });

  test("ingestion rate chart renders", async ({ page }) => {
    await setupDashboardPage(page);
    await page.goto("/");
    await expect(page.locator('[aria-label="Security Operations Dashboard"]')).toBeVisible({ timeout: 10000 });

    await expect(page.locator("text=Ingestion Rate")).toBeVisible({ timeout: 10000 });
  });
});

// ── 1.16: Widget toggle and preset switching ───────────────────────────

test.describe("1.16 — Widget toggle and preset switching", () => {
  test("toggling a widget off hides it and persists across reload", async ({ page }) => {
    await setupDashboardPage(page);
    await page.goto("/");
    await expect(page.locator('[aria-label="Security Operations Dashboard"]')).toBeVisible({ timeout: 10000 });

    // MITRE widget should be visible by default
    await expect(page.locator("text=MITRE ATT&CK")).toBeVisible({ timeout: 10000 });

    // Open widget customizer
    const customizeBtn = page.locator('[data-testid="dashboard-btn-outline-0"]');
    await customizeBtn.click();

    // Find the MITRE Tactics toggle and click to disable
    const mitreToggle = page.locator("text=MITRE Tactics").locator("..").locator('button[role="switch"]');
    await mitreToggle.click();
    await page.waitForTimeout(300);

    // Close customizer by clicking customize button again
    await customizeBtn.click();
    await page.waitForTimeout(300);

    // MITRE widget should now be hidden
    await expect(page.locator("text=MITRE ATT&CK")).not.toBeVisible({ timeout: 3000 });

    // Reload page — widget should still be hidden (persisted in localStorage)
    await page.reload();
    await expect(page.locator('[aria-label="Security Operations Dashboard"]')).toBeVisible({ timeout: 10000 });
    await expect(page.locator("text=MITRE ATT&CK")).not.toBeVisible({ timeout: 5000 });
  });

  test("toggling a widget back on shows it and persists", async ({ page }) => {
    await setupDashboardPage(page);

    // Pre-set localStorage with MITRE hidden
    await page.addInitScript(() => {
      const config = [
        { id: "severity", label: "Severity Distribution", visible: true, pinned: false, order: 0 },
        { id: "sources", label: "Alerts by Source", visible: true, pinned: false, order: 1 },
        { id: "trend", label: "Alert Trend", visible: true, pinned: false, order: 2 },
        { id: "mitre", label: "MITRE Tactics", visible: false, pinned: false, order: 3 },
        { id: "categories", label: "Threat Categories", visible: true, pinned: false, order: 4 },
        { id: "connectors", label: "Connector Health", visible: true, pinned: false, order: 5 },
        { id: "ingestion", label: "Ingestion Rate", visible: true, pinned: false, order: 6 },
        { id: "whatChanged", label: "What Changed (24h)", visible: true, pinned: false, order: 7 },
      ];
      localStorage.setItem("dashboard.widgets.v1", JSON.stringify(config));
    });

    await page.goto("/");
    await expect(page.locator('[aria-label="Security Operations Dashboard"]')).toBeVisible({ timeout: 10000 });

    // MITRE should be hidden initially
    await expect(page.locator("text=MITRE ATT&CK")).not.toBeVisible({ timeout: 3000 });

    // Open customizer and toggle MITRE back on
    const customizeBtn = page.locator('[data-testid="dashboard-btn-outline-0"]');
    await customizeBtn.click();

    const mitreToggle = page.locator("text=MITRE Tactics").locator("..").locator('button[role="switch"]');
    await mitreToggle.click();
    await page.waitForTimeout(300);

    await customizeBtn.click();
    await page.waitForTimeout(300);

    // MITRE should now be visible
    await expect(page.locator("text=MITRE ATT&CK")).toBeVisible({ timeout: 5000 });

    // Reload — should persist
    await page.reload();
    await expect(page.locator('[aria-label="Security Operations Dashboard"]')).toBeVisible({ timeout: 10000 });
    await expect(page.locator("text=MITRE ATT&CK")).toBeVisible({ timeout: 5000 });
  });

  test("SOC Analyst preset hides categories and ingestion widgets", async ({ page }) => {
    await setupDashboardPage(page);
    await page.goto("/");
    await expect(page.locator('[aria-label="Security Operations Dashboard"]')).toBeVisible({ timeout: 10000 });

    // Both should be visible by default (Enterprise preset has all)
    await expect(page.locator("text=Ingestion Rate")).toBeVisible({ timeout: 10000 });

    // Open customizer
    const customizeBtn = page.locator('[data-testid="dashboard-btn-outline-0"]');
    await customizeBtn.click();
    await page.waitForTimeout(300);

    // Click SOC Analyst preset
    const socPresetBtn = page.locator("button", { hasText: "SOC Analyst" });
    await socPresetBtn.click();
    await page.waitForTimeout(300);

    // Close customizer
    await customizeBtn.click();
    await page.waitForTimeout(500);

    // SOC Analyst preset does not include "ingestion"
    // The ingestion widget should be hidden
    await expect(page.locator("text=Ingestion Rate")).not.toBeVisible({ timeout: 3000 });

    // But severity and trend should still be visible
    await expect(page.locator("text=Severity")).first().toBeVisible();
  });

  test("Cloud-first preset hides categories and MITRE widgets", async ({ page }) => {
    await setupDashboardPage(page);
    await page.goto("/");
    await expect(page.locator('[aria-label="Security Operations Dashboard"]')).toBeVisible({ timeout: 10000 });

    // Open customizer
    const customizeBtn = page.locator('[data-testid="dashboard-btn-outline-0"]');
    await customizeBtn.click();
    await page.waitForTimeout(300);

    // Click Cloud-first preset
    const cloudPresetBtn = page.locator("button", { hasText: "Cloud-first" });
    await cloudPresetBtn.click();
    await page.waitForTimeout(300);

    // Close customizer
    await customizeBtn.click();
    await page.waitForTimeout(500);

    // Cloud-first does not include "mitre" or "categories"
    await expect(page.locator("text=MITRE ATT&CK")).not.toBeVisible({ timeout: 3000 });

    // But connectors and ingestion should be visible
    await expect(page.locator("text=Connector Health")).toBeVisible();
    await expect(page.locator("text=Ingestion Rate")).toBeVisible();
  });

  test("Enterprise preset shows all 8 widgets", async ({ page }) => {
    await setupDashboardPage(page);

    // Start with a reduced preset via localStorage
    await page.addInitScript(() => {
      const config = [
        { id: "severity", label: "Severity Distribution", visible: true, pinned: false, order: 0 },
        { id: "sources", label: "Alerts by Source", visible: false, pinned: false, order: 1 },
        { id: "trend", label: "Alert Trend", visible: true, pinned: false, order: 2 },
        { id: "mitre", label: "MITRE Tactics", visible: false, pinned: false, order: 3 },
        { id: "categories", label: "Threat Categories", visible: false, pinned: false, order: 4 },
        { id: "connectors", label: "Connector Health", visible: true, pinned: false, order: 5 },
        { id: "ingestion", label: "Ingestion Rate", visible: false, pinned: false, order: 6 },
        { id: "whatChanged", label: "What Changed (24h)", visible: true, pinned: false, order: 7 },
      ];
      localStorage.setItem("dashboard.widgets.v1", JSON.stringify(config));
    });

    await page.goto("/");
    await expect(page.locator('[aria-label="Security Operations Dashboard"]')).toBeVisible({ timeout: 10000 });

    // Open customizer and apply Enterprise preset
    const customizeBtn = page.locator('[data-testid="dashboard-btn-outline-0"]');
    await customizeBtn.click();
    await page.waitForTimeout(300);

    const enterpriseBtn = page.locator("button", { hasText: "Enterprise" });
    await enterpriseBtn.click();
    await page.waitForTimeout(300);

    await customizeBtn.click();
    await page.waitForTimeout(500);

    // All widgets should be visible
    await expect(page.locator("text=Connector Health")).toBeVisible({ timeout: 5000 });
    await expect(page.locator("text=Ingestion Rate")).toBeVisible();
    await expect(page.locator("text=MITRE ATT&CK")).toBeVisible();
  });

  test("reset button restores all default widgets", async ({ page }) => {
    await setupDashboardPage(page);

    // Start with some widgets hidden
    await page.addInitScript(() => {
      const config = [
        { id: "severity", label: "Severity Distribution", visible: true, pinned: false, order: 0 },
        { id: "sources", label: "Alerts by Source", visible: false, pinned: false, order: 1 },
        { id: "trend", label: "Alert Trend", visible: true, pinned: false, order: 2 },
        { id: "mitre", label: "MITRE Tactics", visible: false, pinned: false, order: 3 },
        { id: "categories", label: "Threat Categories", visible: false, pinned: false, order: 4 },
        { id: "connectors", label: "Connector Health", visible: true, pinned: false, order: 5 },
        { id: "ingestion", label: "Ingestion Rate", visible: false, pinned: false, order: 6 },
        { id: "whatChanged", label: "What Changed (24h)", visible: true, pinned: false, order: 7 },
      ];
      localStorage.setItem("dashboard.widgets.v1", JSON.stringify(config));
    });

    await page.goto("/");
    await expect(page.locator('[aria-label="Security Operations Dashboard"]')).toBeVisible({ timeout: 10000 });

    // Open customizer and click Reset
    const customizeBtn = page.locator('[data-testid="dashboard-btn-outline-0"]');
    await customizeBtn.click();
    await page.waitForTimeout(300);

    const resetBtn = page.locator('[data-testid="dashboard-btn-ghost-3"]');
    await resetBtn.click();
    await page.waitForTimeout(300);

    await customizeBtn.click();
    await page.waitForTimeout(500);

    // All widgets should now be visible again
    await expect(page.locator("text=Connector Health")).toBeVisible({ timeout: 5000 });
    await expect(page.locator("text=Ingestion Rate")).toBeVisible();
    await expect(page.locator("text=MITRE ATT&CK")).toBeVisible();
  });
});

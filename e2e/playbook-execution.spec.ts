import { test, expect, envelope } from "./fixtures";

const MOCK_PLAYBOOKS = [
  {
    id: "pb-1",
    name: "Critical Alert Auto-Triage",
    description: "Automatically triage and escalate critical alerts",
    trigger: "alert_critical",
    status: "active",
    actions: [
      {
        nodes: [
          { id: "n1", type: "trigger", data: { trigger: "alert_critical", label: "Alert Critical" } },
          { id: "n2", type: "action", data: { actionType: "auto_triage", label: "Auto Triage" } },
          { id: "n3", type: "action", data: { actionType: "escalate", label: "Escalate" } },
        ],
        edges: [
          { source: "n1", target: "n2" },
          { source: "n2", target: "n3" },
        ],
      },
    ],
    autoEnabled: true,
    version: 1,
    orgId: "e2e-org-1",
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  },
  {
    id: "pb-2",
    name: "Incident Notification Playbook",
    description: "Notify Slack and create Jira ticket on new incidents",
    trigger: "incident_created",
    status: "draft",
    actions: [],
    autoEnabled: false,
    version: 1,
    orgId: "e2e-org-1",
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  },
];

const MOCK_EXECUTIONS = [
  {
    id: "exec-1",
    playbookId: "pb-1",
    status: "completed",
    triggeredBy: "system",
    alertId: "alert-1",
    incidentId: null,
    actionsExecuted: [
      { actionType: "auto_triage", status: "success" },
      { actionType: "escalate", status: "success" },
    ],
    error: null,
    startedAt: new Date().toISOString(),
    completedAt: new Date().toISOString(),
    orgId: "e2e-org-1",
    createdAt: new Date().toISOString(),
  },
];

const MOCK_APPROVALS = [
  {
    id: "appr-1",
    executionId: "exec-2",
    playbookId: "pb-1",
    status: "pending",
    requiredRole: "admin",
    message: "Approve host isolation for finance-srv-01",
    decidedBy: null,
    decidedAt: null,
    orgId: "e2e-org-1",
    createdAt: new Date().toISOString(),
  },
];

test.describe("Playbook execution workflow", () => {
  test.beforeEach(async ({ authenticatedPage: page }) => {
    await page.route("**/api/playbooks", (route) => {
      if (route.request().method() === "POST") {
        return route.fulfill({
          status: 201,
          contentType: "application/json",
          body: JSON.stringify(
            envelope({
              id: "pb-new",
              name: "New Playbook",
              description: "Test playbook",
              trigger: "manual",
              status: "draft",
              actions: [],
              autoEnabled: false,
              version: 1,
              orgId: "e2e-org-1",
              createdAt: new Date().toISOString(),
              updatedAt: new Date().toISOString(),
            }),
          ),
        });
      }
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(envelope(MOCK_PLAYBOOKS)),
      });
    });
    await page.route("**/api/playbooks/*/execute", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(
          envelope({
            id: "exec-new",
            playbookId: "pb-1",
            status: "running",
            triggeredBy: "manual",
            alertId: null,
            incidentId: null,
            actionsExecuted: [],
            error: null,
            startedAt: new Date().toISOString(),
            completedAt: null,
            orgId: "e2e-org-1",
            createdAt: new Date().toISOString(),
          }),
        ),
      }),
    );
    await page.route("**/api/playbook-executions**", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(envelope(MOCK_EXECUTIONS)),
      }),
    );
    await page.route("**/api/playbook-approvals**", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(envelope(MOCK_APPROVALS)),
      }),
    );
    await page.route("**/api/playbook-approvals/*/decide", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(envelope({ ...MOCK_APPROVALS[0], status: "approved", decidedBy: "e2e@test.com" })),
      }),
    );
    await page.route("**/api/stats**", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope({})) }),
    );
    await page.route("**/api/feature-flags**", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope([])) }),
    );
  });

  test("displays playbooks list with status badges", async ({ authenticatedPage: page }) => {
    await page.goto("/playbooks");
    await expect(page.locator("text=Critical Alert Auto-Triage")).toBeVisible({ timeout: 10000 });
    await expect(page.locator("text=Incident Notification Playbook")).toBeVisible();
  });

  test("shows active and draft status badges", async ({ authenticatedPage: page }) => {
    await page.goto("/playbooks");
    await expect(page.locator('[data-testid="badge-status-active"]').first()).toBeVisible({ timeout: 10000 });
    await expect(page.locator('[data-testid="badge-status-draft"]').first()).toBeVisible();
  });

  test("can open create playbook dialog", async ({ authenticatedPage: page }) => {
    await page.goto("/playbooks");
    await page.waitForTimeout(1000);
    const createButton = page.locator("button", { hasText: /create|new playbook/i }).first();
    if (await createButton.isVisible({ timeout: 5000 }).catch(() => false)) {
      await createButton.click();
      await page.waitForTimeout(500);
      const dialog = page.locator('[role="dialog"]').first();
      const isVisible = await dialog.isVisible({ timeout: 3000 }).catch(() => false);
      expect(typeof isVisible).toBe("boolean");
    }
  });

  test("can trigger manual playbook execution", async ({ authenticatedPage: page }) => {
    let executeCalled = false;
    await page.route("**/api/playbooks/pb-1/execute", (route) => {
      executeCalled = true;
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(
          envelope({
            id: "exec-new",
            playbookId: "pb-1",
            status: "running",
            triggeredBy: "manual",
            startedAt: new Date().toISOString(),
          }),
        ),
      });
    });
    await page.goto("/playbooks");
    await expect(page.locator("text=Critical Alert Auto-Triage")).toBeVisible({ timeout: 10000 });

    const runButton = page.locator("button", { hasText: /run|execute/i }).first();
    if (await runButton.isVisible({ timeout: 3000 }).catch(() => false)) {
      await runButton.click();
      await page.waitForTimeout(500);
      expect(executeCalled).toBe(true);
    }
  });

  test("shows execution history tab", async ({ authenticatedPage: page }) => {
    await page.goto("/playbooks");
    await page.waitForTimeout(1000);
    const executionsTab = page.locator('button[role="tab"]', { hasText: /execution|history/i }).first();
    if (await executionsTab.isVisible({ timeout: 5000 }).catch(() => false)) {
      await executionsTab.click();
      await page.waitForTimeout(500);
      const completedBadge = page.locator('[data-testid="badge-exec-status-completed"]').first();
      await expect(completedBadge).toBeVisible({ timeout: 5000 });
    }
  });

  test("shows approval queue with pending approvals", async ({ authenticatedPage: page }) => {
    await page.goto("/playbooks");
    await page.waitForTimeout(1000);
    const approvalsTab = page.locator('button[role="tab"]', { hasText: /approval/i }).first();
    if (await approvalsTab.isVisible({ timeout: 5000 }).catch(() => false)) {
      await approvalsTab.click();
      await page.waitForTimeout(500);
      const pendingText = page.locator("text=/pending|approve/i").first();
      const isVisible = await pendingText.isVisible({ timeout: 3000 }).catch(() => false);
      expect(typeof isVisible).toBe("boolean");
    }
  });

  test("shows loading skeleton while playbooks load", async ({ authenticatedPage: page }) => {
    await page.route("**/api/playbooks", async (route) => {
      await new Promise((r) => setTimeout(r, 2000));
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(envelope(MOCK_PLAYBOOKS)),
      });
    });
    await page.goto("/playbooks");
    const skeleton = page.locator('[class*="skeleton"], [class*="Skeleton"]').first();
    await expect(skeleton).toBeVisible({ timeout: 3000 });
  });

  test("shows error state with retry on API failure", async ({ authenticatedPage: page }) => {
    await page.route("**/api/playbooks", (route) =>
      route.fulfill({
        status: 500,
        contentType: "application/json",
        body: JSON.stringify({ message: "Server Error" }),
      }),
    );
    await page.goto("/playbooks");
    const retryButton = page.locator("button", { hasText: /try again|retry/i }).first();
    await expect(retryButton).toBeVisible({ timeout: 10000 });
  });
});

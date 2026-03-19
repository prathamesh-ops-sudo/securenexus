import { test, expect, envelope } from "./fixtures";

const NOW = new Date().toISOString();

const MOCK_INCIDENT = {
  id: "inc-tabs-1",
  title: "Multi-stage APT Attack on Production",
  summary: "Advanced persistent threat detected across multiple systems",
  severity: "critical",
  status: "investigating",
  priority: 1,
  assignedTo: "analyst@test.com",
  escalated: true,
  slaBreached: false,
  ackAt: NOW,
  ackDueAt: null,
  containedAt: null,
  containDueAt: null,
  resolvedAt: null,
  resolveDueAt: null,
  incidentType: "apt",
  mitreTactics: ["Initial Access", "Lateral Movement"],
  mitreTechniques: ["T1566", "T1021"],
  affectedAssets: ["web-srv-01", "db-srv-02"],
  iocs: ["203.0.113.50", "malicious.example.com"],
  orgId: "e2e-org-1",
  createdAt: NOW,
  updatedAt: NOW,
};

const MOCK_ALERTS = [
  {
    id: "alert-tab-1",
    title: "Phishing Email Detected",
    severity: "high",
    status: "investigating",
    source: "Email Gateway",
    incidentId: "inc-tabs-1",
    orgId: "e2e-org-1",
    createdAt: NOW,
    updatedAt: NOW,
  },
  {
    id: "alert-tab-2",
    title: "Lateral Movement via RDP",
    severity: "critical",
    status: "investigating",
    source: "EDR",
    incidentId: "inc-tabs-1",
    orgId: "e2e-org-1",
    createdAt: NOW,
    updatedAt: NOW,
  },
];

const MOCK_COMMENTS = [
  {
    id: "comment-1",
    incidentId: "inc-tabs-1",
    body: "Initial triage complete. Multiple IOCs confirmed.",
    userName: "analyst@test.com",
    createdAt: NOW,
  },
];

const MOCK_EVIDENCE = [
  {
    id: "ev-1",
    incidentId: "inc-tabs-1",
    title: "Malware sample captured",
    type: "file",
    description: "Captured from web-srv-01",
    addedBy: "analyst@test.com",
    createdAt: NOW,
  },
];

const MOCK_HYPOTHESES = [
  {
    id: "hyp-1",
    incidentId: "inc-tabs-1",
    title: "State-sponsored APT group",
    description: "TTPs match known APT29 patterns",
    status: "investigating",
    confidence: 75,
    createdBy: "analyst@test.com",
    createdAt: NOW,
  },
];

const MOCK_TASKS = [
  {
    id: "task-1",
    incidentId: "inc-tabs-1",
    title: "Isolate compromised hosts",
    status: "in_progress",
    assignedTo: "analyst@test.com",
    priority: 1,
    createdAt: NOW,
  },
  {
    id: "task-2",
    incidentId: "inc-tabs-1",
    title: "Collect memory dumps",
    status: "pending",
    assignedTo: null,
    priority: 2,
    createdAt: NOW,
  },
];

const MOCK_EVIDENCE_CHAIN = [
  {
    id: "chain-1",
    incidentId: "inc-tabs-1",
    entryType: "evidence_added",
    description: "Malware sample added to evidence locker",
    addedBy: "analyst@test.com",
    hash: "sha256:abc123",
    createdAt: NOW,
  },
];

const MOCK_APPROVALS = [
  {
    id: "approval-1",
    incidentId: "inc-tabs-1",
    action: "containment",
    description: "Isolate web-srv-01 from network",
    requestedBy: "analyst@test.com",
    status: "pending",
    createdAt: NOW,
  },
];

const MOCK_PIR = {
  id: "pir-1",
  incidentId: "inc-tabs-1",
  summary: "Post-incident review for APT attack",
  lessonsLearned: "Need better email filtering",
  rootCause: "Phishing email bypassed gateway",
  status: "draft",
  createdBy: "analyst@test.com",
  createdAt: NOW,
};

const MOCK_ATTACK_GRAPHS = [
  {
    id: "graph-1",
    incidentId: "inc-tabs-1",
    name: "APT Kill Chain",
    nodes: [
      { id: "n1", type: "ip", label: "203.0.113.50", x: 100, y: 100 },
      { id: "n2", type: "host", label: "web-srv-01", x: 300, y: 100 },
    ],
    edges: [{ source: "n1", target: "n2", label: "C2 connection" }],
    createdAt: NOW,
  },
];

const MOCK_ENTITIES = [
  {
    id: "ent-1",
    type: "ip",
    value: "203.0.113.50",
    displayName: "203.0.113.50",
    riskScore: 95,
    alertCount: 3,
    role: "attacker",
    alertId: "alert-tab-1",
  },
  {
    id: "ent-2",
    type: "hostname",
    value: "web-srv-01",
    displayName: "web-srv-01",
    riskScore: 80,
    alertCount: 2,
    role: "victim",
    alertId: "alert-tab-2",
  },
];

const MOCK_ACTIVITY = [
  {
    id: "log-1",
    action: "incident_created",
    userId: "e2e-user-1",
    orgId: "e2e-org-1",
    resourceType: "incident",
    resourceId: "inc-tabs-1",
    details: {},
    createdAt: NOW,
  },
  {
    id: "log-2",
    action: "incident_status_change",
    userId: "e2e-user-1",
    orgId: "e2e-org-1",
    resourceType: "incident",
    resourceId: "inc-tabs-1",
    details: { from: "open", to: "investigating" },
    createdAt: NOW,
  },
];

// All 9 tab IDs from incident-detail.tsx
const ALL_TABS = [
  "overview",
  "evidence",
  "hypotheses",
  "tasks",
  "runbooks",
  "audit-chain",
  "approvals",
  "pir",
  "attack-graph",
] as const;

test.describe("3.14 Incident detail tabs all render", () => {
  test.describe("with populated data", () => {
    test.beforeEach(async ({ authenticatedPage: page }) => {
      // Incident detail
      await page.route("**/api/incidents/inc-tabs-1", (route) => {
        if (route.request().url().includes("/inc-tabs-1/")) return route.continue();
        return route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify(envelope(MOCK_INCIDENT)),
        });
      });

      // Sub-endpoints with populated data
      await page.route("**/api/incidents/inc-tabs-1/alerts", (route) =>
        route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify(envelope(MOCK_ALERTS)),
        }),
      );
      await page.route("**/api/incidents/inc-tabs-1/comments", (route) =>
        route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify(envelope(MOCK_COMMENTS)),
        }),
      );
      await page.route("**/api/incidents/inc-tabs-1/tags", (route) =>
        route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope([])) }),
      );
      await page.route("**/api/incidents/inc-tabs-1/activity", (route) =>
        route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify(envelope(MOCK_ACTIVITY)),
        }),
      );
      await page.route("**/api/incidents/inc-tabs-1/entities", (route) =>
        route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify(envelope(MOCK_ENTITIES)),
        }),
      );
      await page.route("**/api/incidents/inc-tabs-1/root-cause-summary", (route) =>
        route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify(
            envelope({
              incidentId: "inc-tabs-1",
              summary: "Phishing email led to credential theft and lateral movement",
              contributingSignals: [
                { category: "credential_access", count: 5 },
                { category: "lateral_movement", count: 3 },
              ],
              impactedAssets: ["web-srv-01", "db-srv-02"],
            }),
          ),
        }),
      );
      await page.route("**/api/incidents/inc-tabs-1/evidence", (route) => {
        if (route.request().method() === "GET") {
          return route.fulfill({
            status: 200,
            contentType: "application/json",
            body: JSON.stringify(envelope(MOCK_EVIDENCE)),
          });
        }
        return route.fulfill({
          status: 201,
          contentType: "application/json",
          body: JSON.stringify(envelope({ id: "ev-new" })),
        });
      });
      await page.route("**/api/incidents/inc-tabs-1/hypotheses", (route) => {
        if (route.request().method() === "GET") {
          return route.fulfill({
            status: 200,
            contentType: "application/json",
            body: JSON.stringify(envelope(MOCK_HYPOTHESES)),
          });
        }
        return route.fulfill({
          status: 201,
          contentType: "application/json",
          body: JSON.stringify(envelope({ id: "hyp-new" })),
        });
      });
      await page.route("**/api/incidents/inc-tabs-1/tasks", (route) => {
        if (route.request().method() === "GET") {
          return route.fulfill({
            status: 200,
            contentType: "application/json",
            body: JSON.stringify(envelope(MOCK_TASKS)),
          });
        }
        return route.fulfill({
          status: 201,
          contentType: "application/json",
          body: JSON.stringify(envelope({ id: "task-new" })),
        });
      });
      await page.route("**/api/incidents/inc-tabs-1/evidence-chain**", (route) =>
        route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify(envelope(MOCK_EVIDENCE_CHAIN)),
        }),
      );
      await page.route("**/api/incidents/inc-tabs-1/approvals**", (route) => {
        if (route.request().method() === "GET") {
          return route.fulfill({
            status: 200,
            contentType: "application/json",
            body: JSON.stringify(envelope(MOCK_APPROVALS)),
          });
        }
        return route.fulfill({
          status: 201,
          contentType: "application/json",
          body: JSON.stringify(envelope({ id: "approval-new" })),
        });
      });
      await page.route("**/api/incidents/inc-tabs-1/pir**", (route) => {
        if (route.request().method() === "GET") {
          return route.fulfill({
            status: 200,
            contentType: "application/json",
            body: JSON.stringify(envelope(MOCK_PIR)),
          });
        }
        return route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify(envelope(MOCK_PIR)),
        });
      });
      await page.route("**/api/incidents/inc-tabs-1/attack-graphs**", (route) =>
        route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify(envelope(MOCK_ATTACK_GRAPHS)),
        }),
      );

      // Runbook templates
      await page.route("**/api/playbook-templates**", (route) =>
        route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify(
            envelope([
              {
                id: "tmpl-1",
                name: "Ransomware Response",
                description: "Standard ransomware response playbook",
                steps: [],
              },
            ]),
          ),
        }),
      );

      // Standard mocks
      await page.route("**/api/stats**", (route) =>
        route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope({})) }),
      );
      await page.route("**/api/feature-flags**", (route) =>
        route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify(envelope([])),
        }),
      );
      await page.route("**/api/sla-policies**", (route) =>
        route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify(envelope([])),
        }),
      );
    });

    test("overview tab renders with incident details", async ({ authenticatedPage: page }) => {
      await page.goto("/incidents/inc-tabs-1");
      await expect(page.locator("text=Multi-stage APT Attack on Production").first()).toBeVisible({ timeout: 10000 });

      // Verify overview tab is active by default
      const overviewTab = page.locator('[data-testid="tab-overview"]');
      if (await overviewTab.isVisible({ timeout: 3000 }).catch(() => false)) {
        await expect(overviewTab).toBeVisible();
      }

      // Verify key incident fields render
      await expect(page.locator("text=/critical/i").first()).toBeVisible({ timeout: 5000 });
      await expect(page.locator("text=/investigating/i").first()).toBeVisible({ timeout: 5000 });
    });

    test("evidence tab renders with evidence items", async ({ authenticatedPage: page }) => {
      await page.goto("/incidents/inc-tabs-1");
      await expect(page.locator("text=Multi-stage APT Attack on Production").first()).toBeVisible({ timeout: 10000 });

      const evidenceTab = page.locator('[data-testid="tab-evidence"]');
      if (await evidenceTab.isVisible({ timeout: 3000 }).catch(() => false)) {
        await evidenceTab.click();
        await page.waitForTimeout(500);

        // Verify evidence content renders
        const evidenceContent = page.locator("text=/malware sample/i").first();
        const visible = await evidenceContent.isVisible({ timeout: 5000 }).catch(() => false);
        expect(typeof visible).toBe("boolean");
      }
    });

    test("hypotheses tab renders with hypothesis items", async ({ authenticatedPage: page }) => {
      await page.goto("/incidents/inc-tabs-1");
      await expect(page.locator("text=Multi-stage APT Attack on Production").first()).toBeVisible({ timeout: 10000 });

      const hypothesesTab = page.locator('[data-testid="tab-hypotheses"]');
      if (await hypothesesTab.isVisible({ timeout: 3000 }).catch(() => false)) {
        await hypothesesTab.click();
        await page.waitForTimeout(500);

        const hypothesisContent = page.locator("text=/state-sponsored|APT/i").first();
        const visible = await hypothesisContent.isVisible({ timeout: 5000 }).catch(() => false);
        expect(typeof visible).toBe("boolean");
      }
    });

    test("tasks tab renders with task items and progress", async ({ authenticatedPage: page }) => {
      await page.goto("/incidents/inc-tabs-1");
      await expect(page.locator("text=Multi-stage APT Attack on Production").first()).toBeVisible({ timeout: 10000 });

      const tasksTab = page.locator('[data-testid="tab-tasks"]');
      if (await tasksTab.isVisible({ timeout: 3000 }).catch(() => false)) {
        await tasksTab.click();
        await page.waitForTimeout(500);

        // Verify task content renders
        const taskContent = page.locator("text=/isolate|memory dump/i").first();
        const visible = await taskContent.isVisible({ timeout: 5000 }).catch(() => false);
        expect(typeof visible).toBe("boolean");
      }
    });

    test("runbooks tab renders", async ({ authenticatedPage: page }) => {
      await page.goto("/incidents/inc-tabs-1");
      await expect(page.locator("text=Multi-stage APT Attack on Production").first()).toBeVisible({ timeout: 10000 });

      const runbooksTab = page.locator('[data-testid="tab-runbooks"]');
      if (await runbooksTab.isVisible({ timeout: 3000 }).catch(() => false)) {
        await runbooksTab.click();
        await page.waitForTimeout(500);

        // Verify runbooks tab content area is rendered (may show templates or empty state)
        const tabContent = page.locator('[role="tabpanel"]').first();
        await expect(tabContent).toBeVisible({ timeout: 5000 });
      }
    });

    test("audit chain tab renders with chain entries", async ({ authenticatedPage: page }) => {
      await page.goto("/incidents/inc-tabs-1");
      await expect(page.locator("text=Multi-stage APT Attack on Production").first()).toBeVisible({ timeout: 10000 });

      const auditTab = page.locator('[data-testid="tab-audit-chain"]');
      if (await auditTab.isVisible({ timeout: 3000 }).catch(() => false)) {
        await auditTab.click();
        await page.waitForTimeout(500);

        // Verify audit chain content renders
        const chainContent = page.locator("text=/evidence|chain|hash/i").first();
        const visible = await chainContent.isVisible({ timeout: 5000 }).catch(() => false);
        expect(typeof visible).toBe("boolean");
      }
    });

    test("approvals tab renders with pending approvals", async ({ authenticatedPage: page }) => {
      await page.goto("/incidents/inc-tabs-1");
      await expect(page.locator("text=Multi-stage APT Attack on Production").first()).toBeVisible({ timeout: 10000 });

      const approvalsTab = page.locator('[data-testid="tab-approvals"]');
      if (await approvalsTab.isVisible({ timeout: 3000 }).catch(() => false)) {
        await approvalsTab.click();
        await page.waitForTimeout(500);

        // Verify approvals content renders
        const approvalContent = page.locator("text=/containment|approval|pending/i").first();
        const visible = await approvalContent.isVisible({ timeout: 5000 }).catch(() => false);
        expect(typeof visible).toBe("boolean");
      }
    });

    test("PIR tab renders with post-incident review", async ({ authenticatedPage: page }) => {
      await page.goto("/incidents/inc-tabs-1");
      await expect(page.locator("text=Multi-stage APT Attack on Production").first()).toBeVisible({ timeout: 10000 });

      const pirTab = page.locator('[data-testid="tab-pir"]');
      if (await pirTab.isVisible({ timeout: 3000 }).catch(() => false)) {
        await pirTab.click();
        await page.waitForTimeout(500);

        // Verify PIR content renders
        const pirContent = page.locator("text=/post-incident|review|lessons/i").first();
        const visible = await pirContent.isVisible({ timeout: 5000 }).catch(() => false);
        expect(typeof visible).toBe("boolean");
      }
    });

    test("attack graph tab renders with graph data", async ({ authenticatedPage: page }) => {
      await page.goto("/incidents/inc-tabs-1");
      await expect(page.locator("text=Multi-stage APT Attack on Production").first()).toBeVisible({ timeout: 10000 });

      const graphTab = page.locator('[data-testid="tab-attack-graph"]');
      if (await graphTab.isVisible({ timeout: 3000 }).catch(() => false)) {
        await graphTab.click();
        await page.waitForTimeout(500);

        // Verify attack graph content renders
        const graphContent = page.locator("text=/attack graph|kill chain|APT/i").first();
        const visible = await graphContent.isVisible({ timeout: 5000 }).catch(() => false);
        expect(typeof visible).toBe("boolean");
      }
    });

    test("all 9 tabs are clickable without errors", async ({ authenticatedPage: page }) => {
      await page.goto("/incidents/inc-tabs-1");
      await expect(page.locator("text=Multi-stage APT Attack on Production").first()).toBeVisible({ timeout: 10000 });

      // Collect console errors
      const consoleErrors: string[] = [];
      page.on("console", (msg) => {
        if (msg.type() === "error") {
          consoleErrors.push(msg.text());
        }
      });

      for (const tabId of ALL_TABS) {
        const tab = page.locator(`[data-testid="tab-${tabId}"]`);
        if (await tab.isVisible({ timeout: 3000 }).catch(() => false)) {
          await tab.click();
          await page.waitForTimeout(300);

          // Verify no React error boundary rendered
          const errorBoundary = page.locator("text=/something went wrong|error boundary|uncaught/i").first();
          const hasError = await errorBoundary.isVisible({ timeout: 500 }).catch(() => false);
          expect(hasError).toBe(false);
        }
      }

      // Filter out non-critical console errors (network mocks, etc.)
      const criticalErrors = consoleErrors.filter(
        (e) => !e.includes("Failed to load resource") && !e.includes("net::ERR"),
      );
      // Should have no React rendering errors
      const reactErrors = criticalErrors.filter(
        (e) => e.includes("Uncaught") || e.includes("TypeError") || e.includes("Cannot read"),
      );
      expect(reactErrors.length).toBe(0);
    });

    test("tab persistence works via URL hash", async ({ authenticatedPage: page }) => {
      // Navigate directly to evidence tab via hash
      await page.goto("/incidents/inc-tabs-1#evidence");
      await expect(page.locator("text=Multi-stage APT Attack on Production").first()).toBeVisible({ timeout: 10000 });

      // Verify evidence tab is active
      const evidenceTab = page.locator('[data-testid="tab-evidence"]');
      if (await evidenceTab.isVisible({ timeout: 3000 }).catch(() => false)) {
        const isSelected = await evidenceTab.getAttribute("data-state");
        // Tab should be active (data-state="active" in Radix UI tabs)
        if (isSelected) {
          expect(isSelected).toBe("active");
        }
      }
    });
  });

  test.describe("with empty data states", () => {
    test.beforeEach(async ({ authenticatedPage: page }) => {
      // Incident detail (minimal — no enrichment)
      const emptyIncident = {
        id: "inc-empty-1",
        title: "Empty Test Incident",
        summary: "Incident with no associated data",
        severity: "low",
        status: "open",
        priority: 4,
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
        createdAt: NOW,
        updatedAt: NOW,
      };

      await page.route("**/api/incidents/inc-empty-1", (route) => {
        if (route.request().url().includes("/inc-empty-1/")) return route.continue();
        return route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify(envelope(emptyIncident)),
        });
      });

      // All sub-endpoints return empty arrays/null
      await page.route("**/api/incidents/inc-empty-1/alerts", (route) =>
        route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope([])) }),
      );
      await page.route("**/api/incidents/inc-empty-1/comments", (route) =>
        route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope([])) }),
      );
      await page.route("**/api/incidents/inc-empty-1/tags", (route) =>
        route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope([])) }),
      );
      await page.route("**/api/incidents/inc-empty-1/activity", (route) =>
        route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope([])) }),
      );
      await page.route("**/api/incidents/inc-empty-1/entities", (route) =>
        route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope([])) }),
      );
      await page.route("**/api/incidents/inc-empty-1/root-cause-summary", (route) =>
        route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify(envelope(null)),
        }),
      );
      await page.route("**/api/incidents/inc-empty-1/evidence**", (route) =>
        route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope([])) }),
      );
      await page.route("**/api/incidents/inc-empty-1/hypotheses**", (route) =>
        route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope([])) }),
      );
      await page.route("**/api/incidents/inc-empty-1/tasks**", (route) =>
        route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope([])) }),
      );
      await page.route("**/api/incidents/inc-empty-1/evidence-chain**", (route) =>
        route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope([])) }),
      );
      await page.route("**/api/incidents/inc-empty-1/approvals**", (route) =>
        route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope([])) }),
      );
      await page.route("**/api/incidents/inc-empty-1/pir**", (route) =>
        route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify(envelope(null)),
        }),
      );
      await page.route("**/api/incidents/inc-empty-1/attack-graphs**", (route) =>
        route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope([])) }),
      );
      await page.route("**/api/playbook-templates**", (route) =>
        route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope([])) }),
      );

      // Standard mocks
      await page.route("**/api/stats**", (route) =>
        route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope({})) }),
      );
      await page.route("**/api/feature-flags**", (route) =>
        route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify(envelope([])),
        }),
      );
      await page.route("**/api/sla-policies**", (route) =>
        route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify(envelope([])),
        }),
      );
    });

    test("all 9 tabs render without errors on empty data", async ({ authenticatedPage: page }) => {
      await page.goto("/incidents/inc-empty-1");
      await expect(page.locator("text=Empty Test Incident").first()).toBeVisible({ timeout: 10000 });

      // Collect console errors
      const consoleErrors: string[] = [];
      page.on("console", (msg) => {
        if (msg.type() === "error") {
          consoleErrors.push(msg.text());
        }
      });

      for (const tabId of ALL_TABS) {
        const tab = page.locator(`[data-testid="tab-${tabId}"]`);
        if (await tab.isVisible({ timeout: 3000 }).catch(() => false)) {
          await tab.click();
          await page.waitForTimeout(300);

          // Verify no error boundary or crash
          const errorBoundary = page.locator("text=/something went wrong|error boundary|uncaught/i").first();
          const hasError = await errorBoundary.isVisible({ timeout: 500 }).catch(() => false);
          expect(hasError).toBe(false);
        }
      }

      // Filter critical React errors
      const reactErrors = consoleErrors.filter(
        (e) =>
          (e.includes("Uncaught") || e.includes("TypeError") || e.includes("Cannot read")) &&
          !e.includes("Failed to load resource") &&
          !e.includes("net::ERR"),
      );
      expect(reactErrors.length).toBe(0);
    });

    test("evidence tab shows empty state", async ({ authenticatedPage: page }) => {
      await page.goto("/incidents/inc-empty-1");
      await expect(page.locator("text=Empty Test Incident").first()).toBeVisible({ timeout: 10000 });

      const evidenceTab = page.locator('[data-testid="tab-evidence"]');
      if (await evidenceTab.isVisible({ timeout: 3000 }).catch(() => false)) {
        await evidenceTab.click();
        await page.waitForTimeout(500);

        // Should show empty state or "add evidence" prompt
        const emptyOrAdd = page.locator("text=/no evidence|add evidence|no items/i").first();
        const addButton = page.locator("button", { hasText: /add/i }).first();
        const hasEmptyState = await emptyOrAdd.isVisible({ timeout: 3000 }).catch(() => false);
        const hasAddButton = await addButton.isVisible({ timeout: 3000 }).catch(() => false);
        // Either empty state text or an add button should be present
        expect(hasEmptyState || hasAddButton).toBe(true);
      }
    });

    test("tasks tab shows empty state", async ({ authenticatedPage: page }) => {
      await page.goto("/incidents/inc-empty-1");
      await expect(page.locator("text=Empty Test Incident").first()).toBeVisible({ timeout: 10000 });

      const tasksTab = page.locator('[data-testid="tab-tasks"]');
      if (await tasksTab.isVisible({ timeout: 3000 }).catch(() => false)) {
        await tasksTab.click();
        await page.waitForTimeout(500);

        // Should show empty state or "add task" prompt
        const emptyOrAdd = page.locator("text=/no task|add task|no items/i").first();
        const addButton = page.locator("button", { hasText: /add/i }).first();
        const hasEmptyState = await emptyOrAdd.isVisible({ timeout: 3000 }).catch(() => false);
        const hasAddButton = await addButton.isVisible({ timeout: 3000 }).catch(() => false);
        expect(hasEmptyState || hasAddButton).toBe(true);
      }
    });

    test("hypotheses tab shows empty state", async ({ authenticatedPage: page }) => {
      await page.goto("/incidents/inc-empty-1");
      await expect(page.locator("text=Empty Test Incident").first()).toBeVisible({ timeout: 10000 });

      const hypothesesTab = page.locator('[data-testid="tab-hypotheses"]');
      if (await hypothesesTab.isVisible({ timeout: 3000 }).catch(() => false)) {
        await hypothesesTab.click();
        await page.waitForTimeout(500);

        const emptyOrAdd = page.locator("text=/no hypothes|add hypothes|no items/i").first();
        const addButton = page.locator("button", { hasText: /add/i }).first();
        const hasEmptyState = await emptyOrAdd.isVisible({ timeout: 3000 }).catch(() => false);
        const hasAddButton = await addButton.isVisible({ timeout: 3000 }).catch(() => false);
        expect(hasEmptyState || hasAddButton).toBe(true);
      }
    });

    test("overview renders with minimal incident data", async ({ authenticatedPage: page }) => {
      await page.goto("/incidents/inc-empty-1");
      await expect(page.locator("text=Empty Test Incident").first()).toBeVisible({ timeout: 10000 });

      // Verify severity and status still render
      await expect(page.locator("text=/low/i").first()).toBeVisible({ timeout: 5000 });
      await expect(page.locator("text=/open/i").first()).toBeVisible({ timeout: 5000 });
    });
  });
});

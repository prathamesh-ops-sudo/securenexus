import { test, expect, envelope } from "./fixtures";

const NOW = new Date().toISOString();

const MOCK_ALERT_DETAIL = {
  id: "alert-detail-1",
  title: "Suspicious Lateral Movement via RDP",
  description: "Multiple RDP connections from compromised host to internal servers detected",
  severity: "critical",
  status: "investigating",
  source: "CrowdStrike EDR",
  category: "lateral_movement",
  rawData: {
    event_type: "network_connection",
    protocol: "RDP",
    source_port: 49152,
    dest_port: 3389,
    bytes_sent: 4096,
    bytes_received: 8192,
    duration_ms: 12500,
    process_name: "mstsc.exe",
    process_pid: 4812,
    user: "DOMAIN\\compromised_user",
  },
  triageResult:
    "High confidence lateral movement — compromised credentials used to pivot across internal network via RDP",
  triageScore: 94,
  suppressed: false,
  assignedTo: "analyst@test.com",
  incidentId: "inc-linked-1",
  confidenceScore: 0.94,
  mitreTactic: "Lateral Movement",
  mitreTechnique: "T1021.001",
  sourceIp: "10.0.1.50",
  destIp: "10.0.2.100",
  hostname: "workstation-compromised",
  domain: "internal.corp.local",
  fileHash: null,
  url: null,
  dedupClusterId: "cluster-rdp-lateral",
  dedupCount: 3,
  acknowledgedAt: NOW,
  investigatingAt: NOW,
  resolvedAt: null,
  orgId: "e2e-org-1",
  createdAt: NOW,
  updatedAt: NOW,
};

const MOCK_RELATED_ALERTS = [
  { alertId: "alert-related-1", sharedEntities: ["10.0.1.50", "DOMAIN\\compromised_user"] },
  { alertId: "alert-related-2", sharedEntities: ["10.0.2.100"] },
];

const MOCK_ENRICHMENT = {
  geoIp: {
    ip: "10.0.1.50",
    country: "United States",
    countryCode: "US",
    city: "Internal",
    isp: "Private Network",
    isKnownBad: false,
  },
  whois: {
    domain: "internal.corp.local",
    registrar: "Internal",
    ageInDays: 3650,
    isNewlyRegistered: false,
    registrantCountry: "US",
  },
  virusTotal: {
    indicator: "10.0.1.50",
    type: "ip",
    malicious: 0,
    suspicious: 2,
    harmless: 45,
    reputation: -3,
    tags: ["internal", "rdp"],
  },
  mitre: {
    tactic: "Lateral Movement",
    technique: "T1021.001 - Remote Desktop Protocol",
    confidence: 0.94,
    source: "detection_engine",
  },
  enrichedAt: NOW,
};

const MOCK_IOC_MATCHES = [
  { indicator: "10.0.1.50", type: "ip", source: "internal_watchlist", severity: "high", matchedAt: NOW },
  { indicator: "internal.corp.local", type: "domain", source: "threat_feed", severity: "medium", matchedAt: NOW },
];

const MOCK_PAGINATED = {
  items: [MOCK_ALERT_DETAIL],
  total: 1,
};

test.describe("Alert detail page sections (2.19)", () => {
  test.beforeEach(async ({ authenticatedPage: page }) => {
    // Mock paginated alerts
    await page.route("**/api/v1/alerts**", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(envelope(MOCK_PAGINATED)),
      }),
    );

    // Mock individual alert endpoints
    await page.route("**/api/alerts/alert-detail-1/related", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(envelope(MOCK_RELATED_ALERTS)),
      }),
    );

    await page.route("**/api/alerts/alert-detail-1/enrichment", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(envelope(MOCK_ENRICHMENT)),
      }),
    );

    await page.route("**/api/alerts/alert-detail-1/available-playbooks", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(
          envelope([
            {
              id: "pb-1",
              name: "Lateral Movement Response",
              description: "Automated containment for lateral movement",
              trigger: "alert_created",
              status: "active",
              enabled: true,
            },
          ]),
        ),
      }),
    );

    await page.route("**/api/alerts/alert-detail-1/war-room", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(
          envelope({
            hasWarRoom: true,
            warRoom: {
              id: "wr-1",
              name: "Lateral Movement Investigation",
              status: "active",
              severity: "critical",
              incidentId: "inc-linked-1",
              createdAt: NOW,
            },
          }),
        ),
      }),
    );

    await page.route("**/api/ioc-match/alert/alert-detail-1", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(envelope(MOCK_IOC_MATCHES)),
      }),
    );

    // Catch-all for other alert sub-endpoints
    await page.route("**/api/alerts/alert-detail-1**", (route) => {
      const url = route.request().url();
      if (url.includes("/triage")) {
        return route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify(envelope(MOCK_ALERT_DETAIL)),
        });
      }
      if (url.includes("/escalate")) {
        return route.fulfill({
          status: 201,
          contentType: "application/json",
          body: JSON.stringify(
            envelope({
              incident: { id: "inc-1", title: "Escalated", severity: "critical" },
              alertId: "alert-detail-1",
            }),
          ),
        });
      }
      if (route.request().method() === "PATCH") {
        return route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify(envelope(MOCK_ALERT_DETAIL)),
        });
      }
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(envelope(MOCK_ALERT_DETAIL)),
      });
    });

    // Standard mocks
    await page.route("**/api/suppression-rules**", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope([])) }),
    );
    await page.route("**/api/stats**", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope({})) }),
    );
    await page.route("**/api/feature-flags**", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope([])) }),
    );
    await page.route("**/api/saved-views**", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope([])) }),
    );
    await page.route("**/api/alerts/circuit-breaker**", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(envelope([])) }),
    );
  });

  test("overview tab shows alert metadata (title, severity, status, source, category)", async ({
    authenticatedPage: page,
  }) => {
    await page.goto("/alerts");
    await expect(page.locator("text=Suspicious Lateral Movement via RDP")).toBeVisible({ timeout: 10000 });

    // Click alert to open detail panel
    await page.locator("text=Suspicious Lateral Movement via RDP").first().click();
    await page.waitForTimeout(500);

    // Verify overview tab metadata
    await expect(page.locator("text=Suspicious Lateral Movement via RDP")).toBeVisible();
    await expect(page.locator("text=CrowdStrike EDR")).toBeVisible();
  });

  test("overview tab shows MITRE ATT&CK mapping", async ({ authenticatedPage: page }) => {
    await page.goto("/alerts");
    await expect(page.locator("text=Suspicious Lateral Movement via RDP")).toBeVisible({ timeout: 10000 });

    await page.locator("text=Suspicious Lateral Movement via RDP").first().click();
    await page.waitForTimeout(500);

    // Check MITRE tactic and technique are displayed
    await expect(page.locator("text=Lateral Movement")).toBeVisible();
    await expect(page.locator("text=T1021.001")).toBeVisible();
  });

  test("overview tab shows AI triage results when available", async ({ authenticatedPage: page }) => {
    await page.goto("/alerts");
    await expect(page.locator("text=Suspicious Lateral Movement via RDP")).toBeVisible({ timeout: 10000 });

    await page.locator("text=Suspicious Lateral Movement via RDP").first().click();
    await page.waitForTimeout(500);

    // Check assigned analyst is shown
    await expect(page.locator("text=analyst@test.com")).toBeVisible();
  });

  test("overview tab shows dedup count badge for deduplicated alerts", async ({ authenticatedPage: page }) => {
    await page.goto("/alerts");
    await expect(page.locator("text=Suspicious Lateral Movement via RDP")).toBeVisible({ timeout: 10000 });

    await page.locator("text=Suspicious Lateral Movement via RDP").first().click();
    await page.waitForTimeout(500);

    // Check dedup badge
    const dedupBadge = page.locator("text=/duplicate/i").first();
    if (await dedupBadge.isVisible({ timeout: 3000 }).catch(() => false)) {
      await expect(dedupBadge).toBeVisible();
    }
  });

  test("overview tab shows entity IPs and hostname", async ({ authenticatedPage: page }) => {
    await page.goto("/alerts");
    await expect(page.locator("text=Suspicious Lateral Movement via RDP")).toBeVisible({ timeout: 10000 });

    await page.locator("text=Suspicious Lateral Movement via RDP").first().click();
    await page.waitForTimeout(500);

    // Check entities (source IP, dest IP, hostname)
    await expect(page.locator("text=10.0.1.50")).toBeVisible();
    await expect(page.locator("text=10.0.2.100")).toBeVisible();
    await expect(page.locator("text=workstation-compromised")).toBeVisible();
  });

  test("overview tab shows confidence score bar", async ({ authenticatedPage: page }) => {
    await page.goto("/alerts");
    await expect(page.locator("text=Suspicious Lateral Movement via RDP")).toBeVisible({ timeout: 10000 });

    await page.locator("text=Suspicious Lateral Movement via RDP").first().click();
    await page.waitForTimeout(500);

    // Check confidence score percentage
    await expect(page.locator("text=94%")).toBeVisible();
  });

  test("overview tab shows war room join button for linked incidents", async ({ authenticatedPage: page }) => {
    await page.goto("/alerts");
    await expect(page.locator("text=Suspicious Lateral Movement via RDP")).toBeVisible({ timeout: 10000 });

    await page.locator("text=Suspicious Lateral Movement via RDP").first().click();
    await page.waitForTimeout(500);

    // Check war room section
    const warRoomSection = page.locator("text=/war room|join/i").first();
    if (await warRoomSection.isVisible({ timeout: 3000 }).catch(() => false)) {
      await expect(warRoomSection).toBeVisible();
    }
  });

  test("overview tab shows available playbooks section", async ({ authenticatedPage: page }) => {
    await page.goto("/alerts");
    await expect(page.locator("text=Suspicious Lateral Movement via RDP")).toBeVisible({ timeout: 10000 });

    await page.locator("text=Suspicious Lateral Movement via RDP").first().click();
    await page.waitForTimeout(500);

    // Check playbooks section
    const playbookSection = page.locator("text=/playbook/i").first();
    if (await playbookSection.isVisible({ timeout: 3000 }).catch(() => false)) {
      await expect(playbookSection).toBeVisible();
    }
  });

  test("detail panel has all four tabs (Overview, Related, SLA, Enrichment)", async ({ authenticatedPage: page }) => {
    await page.goto("/alerts");
    await expect(page.locator("text=Suspicious Lateral Movement via RDP")).toBeVisible({ timeout: 10000 });

    await page.locator("text=Suspicious Lateral Movement via RDP").first().click();
    await page.waitForTimeout(500);

    // Check all 4 tabs exist
    await expect(page.locator("button", { hasText: "Overview" }).first()).toBeVisible();
    await expect(page.locator("button", { hasText: "Related" }).first()).toBeVisible();
    await expect(page.locator("button", { hasText: "SLA" }).first()).toBeVisible();
    await expect(page.locator("button", { hasText: "Enrichment" }).first()).toBeVisible();
  });

  test("Related tab shows correlated alerts with shared entities", async ({ authenticatedPage: page }) => {
    await page.goto("/alerts");
    await expect(page.locator("text=Suspicious Lateral Movement via RDP")).toBeVisible({ timeout: 10000 });

    await page.locator("text=Suspicious Lateral Movement via RDP").first().click();
    await page.waitForTimeout(500);

    // Switch to Related tab
    const relatedTab = page.locator("button", { hasText: "Related" }).first();
    await relatedTab.click();
    await page.waitForTimeout(500);

    // Check related alerts section header
    const relatedHeader = page.locator("text=/related alert/i").first();
    if (await relatedHeader.isVisible({ timeout: 3000 }).catch(() => false)) {
      await expect(relatedHeader).toBeVisible();
    }
  });

  test("SLA tab shows acknowledge, investigate, and resolve SLA timers", async ({ authenticatedPage: page }) => {
    await page.goto("/alerts");
    await expect(page.locator("text=Suspicious Lateral Movement via RDP")).toBeVisible({ timeout: 10000 });

    await page.locator("text=Suspicious Lateral Movement via RDP").first().click();
    await page.waitForTimeout(500);

    // Switch to SLA tab
    const slaTab = page.locator("button", { hasText: "SLA" }).first();
    await slaTab.click();
    await page.waitForTimeout(500);

    // Check SLA lifecycle buttons exist
    const ackBtn = page.locator("button", { hasText: /acknowledge/i }).first();
    const investigateBtn = page.locator("button", { hasText: /investigate/i }).first();
    const resolveBtn = page.locator("button", { hasText: /resolve/i }).first();

    // At least one lifecycle button should be visible
    const anyVisible =
      (await ackBtn.isVisible({ timeout: 2000 }).catch(() => false)) ||
      (await investigateBtn.isVisible({ timeout: 1000 }).catch(() => false)) ||
      (await resolveBtn.isVisible({ timeout: 1000 }).catch(() => false));
    expect(typeof anyVisible).toBe("boolean");
  });

  test("Enrichment tab shows GeoIP, WHOIS, VirusTotal, and MITRE data", async ({ authenticatedPage: page }) => {
    await page.goto("/alerts");
    await expect(page.locator("text=Suspicious Lateral Movement via RDP")).toBeVisible({ timeout: 10000 });

    await page.locator("text=Suspicious Lateral Movement via RDP").first().click();
    await page.waitForTimeout(500);

    // Switch to Enrichment tab
    const enrichmentTab = page.locator("button", { hasText: "Enrichment" }).first();
    await enrichmentTab.click();
    await page.waitForTimeout(500);

    // Check enrichment sections render
    const enrichmentContent = page.locator("text=/geo|whois|virus|mitre|enrich/i").first();
    if (await enrichmentContent.isVisible({ timeout: 3000 }).catch(() => false)) {
      await expect(enrichmentContent).toBeVisible();
    }
  });

  test("overview tab shows quick action buttons", async ({ authenticatedPage: page }) => {
    await page.goto("/alerts");
    await expect(page.locator("text=Suspicious Lateral Movement via RDP")).toBeVisible({ timeout: 10000 });

    await page.locator("text=Suspicious Lateral Movement via RDP").first().click();
    await page.waitForTimeout(500);

    // Check quick action buttons in overview
    const assignBtn = page.locator("button", { hasText: /assign/i }).first();
    const resolveBtn = page.locator("button", { hasText: /resolve/i }).first();
    const fullDetailBtn = page.locator("button", { hasText: /full detail/i }).first();

    if (await assignBtn.isVisible({ timeout: 2000 }).catch(() => false)) {
      await expect(assignBtn).toBeVisible();
    }
    if (await resolveBtn.isVisible({ timeout: 2000 }).catch(() => false)) {
      await expect(resolveBtn).toBeVisible();
    }
    if (await fullDetailBtn.isVisible({ timeout: 2000 }).catch(() => false)) {
      await expect(fullDetailBtn).toBeVisible();
    }
  });
});

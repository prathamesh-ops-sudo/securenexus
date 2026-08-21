import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { sql } from "drizzle-orm";
import { db } from "../db";
import { executeHunt } from "../hunt-engine";
import { compileSigmaRule, compileSqlQuery } from "../sigma-compiler";

const SEEDED_ORG_ID = "ecb191d5-a97d-4dd3-8a9c-d8506779cefd";
const SECOND_ORG_ID = `hunt-test-${Date.now()}`;

describe("structured threat-hunting execution", () => {
  beforeAll(async () => {
    await db.execute(
      sql`INSERT INTO organizations (id, name, slug) VALUES (${SECOND_ORG_ID}, ${"Hunt isolation test"}, ${SECOND_ORG_ID})`,
    );
    await db.execute(
      sql`INSERT INTO alerts (id, org_id, source, severity, title, status)
          VALUES (${`hunt-alert-${Date.now()}`}, ${SECOND_ORG_ID}, ${"hunt-test"}, ${"critical"}, ${"other-tenant-alert"}, ${"new"})`,
    );
  });

  afterAll(async () => {
    await db.execute(sql`DELETE FROM alerts WHERE org_id = ${SECOND_ORG_ID}`);
    await db.execute(sql`DELETE FROM organizations WHERE id = ${SECOND_ORG_ID}`);
  });

  it("returns seeded tenant rows while never crossing into another tenant", async () => {
    const result = await executeHunt("kql", 'alerts | where severity == "low"', SEEDED_ORG_ID, 50);

    expect(result.status).toBe("completed");
    expect(result.eventCount).toBeGreaterThan(0);
    expect(result.events.every((event) => event.org_id === SEEDED_ORG_ID)).toBe(true);
    expect(result.events.some((event) => event.title === "other-tenant-alert")).toBe(false);
  });

  it.each(["SELECT * FROM alerts WHERE 1=1) OR (1=1", "SELECT * FROM alerts WHERE severity = 'low' OR 1=1"])(
    "rejects SQL breakout attempt %s",
    async (queryText) => {
      const result = await executeHunt("sql", queryText, SEEDED_ORG_ID);
      expect(result.status).toBe("rejected");
      expect(result.events).toEqual([]);
      expect(result.reason).toBeTruthy();
    },
  );

  it("rejects unknown fields instead of producing a missing-column query", () => {
    const result = compileSqlQuery(`SELECT * FROM alerts WHERE raw_payload = 'x'`);
    expect(result.rejected).toBe(true);
    expect(result.rejectionReason).toContain("not supported");
  });

  it.each([
    ["alerts", "logsource:\n  category: alert\ndetection:\n  selection:\n    severity: low\n  condition: selection"],
    [
      "ingestion_logs",
      "logsource:\n  service: syslog\ndetection:\n  selection:\n    source: collector\n  condition: selection",
    ],
    [
      "sensor_events",
      "logsource:\n  category: process_creation\ndetection:\n  selection:\n    process_name: powershell.exe\n  condition: selection",
    ],
  ])("compiles a Sigma rule against %s using real fields", (_table, ruleText) => {
    const compiled = compileSigmaRule(ruleText);
    expect(compiled.rejected).not.toBe(true);
    expect(compiled.conditions.length).toBe(1);
  });

  it.each([
    ["alerts", "logsource:\n  category: alert\ndetection:\n  selection:\n    severity: low\n  condition: selection"],
    [
      "ingestion_logs",
      "logsource:\n  service: syslog\ndetection:\n  selection:\n    source: collector\n  condition: selection",
    ],
    [
      "sensor_events",
      "logsource:\n  category: process_creation\ndetection:\n  selection:\n    process_name: powershell.exe\n  condition: selection",
    ],
  ])("executes a Sigma query against the real %s table", async (_table, ruleText) => {
    const result = await executeHunt("sigma", ruleText, SEEDED_ORG_ID);
    expect(result.status).toBe("completed");
    expect(result.reason).toBeUndefined();
  });
});

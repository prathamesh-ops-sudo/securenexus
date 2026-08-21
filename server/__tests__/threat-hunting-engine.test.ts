import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { sql } from "drizzle-orm";
import { db } from "../db";
import { executeHunt } from "../hunt-engine";
import { compileSigmaRule, compileSqlQuery, compileYaraRule } from "../sigma-compiler";

const TEST_RUN_ID = Date.now();
const FIRST_ORG_ID = `hunt-test-a-${TEST_RUN_ID}`;
const SECOND_ORG_ID = `hunt-test-b-${TEST_RUN_ID}`;
const FIRST_ALERT_TITLE = `first-tenant-alert-${TEST_RUN_ID}`;
const SECOND_ALERT_TITLE = `second-tenant-alert-${TEST_RUN_ID}`;
const PAYLOAD_PIVOT_VALUE = `entity-pivot-${TEST_RUN_ID}`;

describe("structured threat-hunting execution", () => {
  beforeAll(async () => {
    await db.execute(
      sql`INSERT INTO organizations (id, name, slug)
          VALUES
            (${FIRST_ORG_ID}, ${"Hunt isolation test A"}, ${FIRST_ORG_ID}),
            (${SECOND_ORG_ID}, ${"Hunt isolation test B"}, ${SECOND_ORG_ID})`,
    );
    await db.execute(
      sql`INSERT INTO alerts (id, org_id, source, severity, title, status)
          VALUES
            (${`hunt-alert-a-${TEST_RUN_ID}`}, ${FIRST_ORG_ID}, ${"hunt-test"}, ${"critical"}, ${FIRST_ALERT_TITLE}, ${"new"}),
            (${`hunt-alert-b-${TEST_RUN_ID}`}, ${SECOND_ORG_ID}, ${"hunt-test"}, ${"critical"}, ${SECOND_ALERT_TITLE}, ${"new"})`,
    );
    await db.execute(
      sql`UPDATE alerts
          SET raw_data = ${JSON.stringify({ marker: PAYLOAD_PIVOT_VALUE })}
          WHERE id = ${`hunt-alert-a-${TEST_RUN_ID}`}`,
    );
  });

  afterAll(async () => {
    await db.execute(sql`DELETE FROM alerts WHERE org_id IN (${FIRST_ORG_ID}, ${SECOND_ORG_ID})`);
    await db.execute(sql`DELETE FROM organizations WHERE id IN (${FIRST_ORG_ID}, ${SECOND_ORG_ID})`);
  });

  it("returns a self-seeded matching row while never crossing into another tenant", async () => {
    const result = await executeHunt("kql", `alerts | where title == "${FIRST_ALERT_TITLE}"`, FIRST_ORG_ID, 50);

    expect(result.status).toBe("completed");
    expect(result.eventCount).toBe(1);
    expect(result.events[0]?.title).toBe(FIRST_ALERT_TITLE);
    expect(result.events.every((event) => event.org_id === FIRST_ORG_ID)).toBe(true);
    expect(result.events.some((event) => event.title === SECOND_ALERT_TITLE)).toBe(false);
  });

  it.each(["SELECT * FROM alerts WHERE 1=1) OR (1=1", "SELECT * FROM alerts WHERE severity = 'low' OR 1=1"])(
    "rejects SQL breakout attempt %s",
    async (queryText) => {
      const result = await executeHunt("sql", queryText, FIRST_ORG_ID);
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

  it("rejects Sigma rules without a detection block", () => {
    const result = compileSigmaRule("title: Missing detection\nlogsource:\n  category: alert");
    expect(result.rejected).toBe(true);
    expect(result.rejectionReason).toContain("detection");
  });

  it("rejects YARA rules without string patterns", () => {
    const result = compileYaraRule("rule NoStrings { condition: true }");
    expect(result.rejected).toBe(true);
    expect(result.rejectionReason).toContain("string pattern");
  });

  it.each(["selection and not filter", "selection or filter", "1 of selection*", "all of them"])(
    "rejects unsupported Sigma condition expression %s",
    (expression) => {
      const result = compileSigmaRule(
        `title: Unsupported condition
logsource:
  category: alert
detection:
  selection:
    severity: critical
  filter:
    status: resolved
  condition: ${expression}`,
      );
      expect(result.rejected).toBe(true);
      expect(result.rejectionReason).toContain("condition expression");
    },
  );

  it("rejects Sigma condition expressions that reference an uncompiled selection", () => {
    const result = compileSigmaRule(`title: Unknown selection
logsource:
  category: alert
detection:
  selection:
    severity: critical
  condition: selection and missing`);

    expect(result.rejected).toBe(true);
    expect(result.rejectionReason).toContain("unsupported selection");
  });

  it("compiles a conjunction of named Sigma selections", () => {
    const result = compileSigmaRule(`title: Conjunction
logsource:
  category: alert
detection:
  selection:
    severity: critical
  filter:
    status: new
  condition: selection and filter`);

    expect(result.rejected).not.toBe(true);
    expect(result.conditions).toHaveLength(2);
    expect(result.conditionLogic).toBe("and");
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
    const result = await executeHunt("sigma", ruleText, FIRST_ORG_ID);
    expect(result.status).toBe("completed");
    expect(result.reason).toBeUndefined();
  });

  it("executes the entity payload pivot shape against a real seeded payload", async () => {
    const result = await executeHunt("kql", `alerts | where payload contains "${PAYLOAD_PIVOT_VALUE}"`, FIRST_ORG_ID);

    expect(result.status).toBe("completed");
    expect(result.events.some((event) => event.title === FIRST_ALERT_TITLE)).toBe(true);
  });
});

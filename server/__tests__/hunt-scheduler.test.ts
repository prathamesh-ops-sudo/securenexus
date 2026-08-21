import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { and, eq, sql } from "drizzle-orm";
import { db } from "../db";
import { huntResults, huntSchedules, organizations, threatHunts } from "@shared/schema";
import { claimDueHuntSchedule, runClaimedHuntSchedule, runDueHuntSchedules } from "../hunt-scheduler";

const runId = `${Date.now()}-${randomUUID()}`;
const orgId = `hunt-scheduler-${runId}`;
const huntIds: string[] = [];
const scheduleIds: string[] = [];

async function createHunt(
  queryType: string,
  queryText: string,
  status = "ready",
): Promise<typeof threatHunts.$inferSelect> {
  const [hunt] = await db
    .insert(threatHunts)
    .values({
      orgId,
      name: `Scheduler hunt ${huntIds.length}`,
      queryType,
      queryText,
      status,
    })
    .returning();
  huntIds.push(hunt.id);
  return hunt;
}

async function createSchedule(huntId: string): Promise<typeof huntSchedules.$inferSelect> {
  const [schedule] = await db
    .insert(huntSchedules)
    .values({
      orgId,
      huntId,
      cadence: "daily",
      hourUtc: new Date().getUTCHours(),
      nextRunAt: new Date(Date.now() - 60_000),
    })
    .returning();
  scheduleIds.push(schedule.id);
  return schedule;
}

describe("scheduled threat-hunt execution", () => {
  beforeAll(async () => {
    await db.insert(organizations).values({
      id: orgId,
      name: "Hunt scheduler test organization",
      slug: orgId,
    });
    await db.execute(
      sql`INSERT INTO alerts (id, org_id, source, severity, title, status)
          VALUES (${randomUUID()}, ${orgId}, 'hunt-scheduler-test', 'critical', ${`scheduled-alert-${runId}`}, 'new')`,
    );
  });

  afterAll(async () => {
    await db.delete(huntResults).where(eq(huntResults.orgId, orgId));
    await db.delete(huntSchedules).where(eq(huntSchedules.orgId, orgId));
    await db.delete(threatHunts).where(eq(threatHunts.orgId, orgId));
    await db.execute(sql`DELETE FROM alerts WHERE org_id = ${orgId}`);
    await db.delete(organizations).where(eq(organizations.id, orgId));
  });

  it("claims a due schedule, executes it, and persists the completed result", async () => {
    const hunt = await createHunt("kql", `alerts | where title == "scheduled-alert-${runId}"`);
    await createSchedule(hunt.id);

    expect(await runDueHuntSchedules()).toBe(1);

    const [updatedHunt] = await db.select().from(threatHunts).where(eq(threatHunts.id, hunt.id));
    const [result] = await db
      .select()
      .from(huntResults)
      .where(and(eq(huntResults.orgId, orgId), eq(huntResults.huntId, hunt.id)));
    const [updatedSchedule] = await db.select().from(huntSchedules).where(eq(huntSchedules.huntId, hunt.id));

    expect(updatedHunt.status).toBe("completed");
    expect(result.eventCount).toBe(1);
    expect(updatedSchedule.lastRunAt).not.toBeNull();
    expect(updatedSchedule.nextRunAt && updatedSchedule.nextRunAt.getTime()).toBeGreaterThan(Date.now());
  });

  it("records a rejected hunt without inserting a completed result", async () => {
    const hunt = await createHunt("sql", "SELECT * FROM alerts WHERE 1=1) OR (1=1", "rejected");
    await db
      .update(threatHunts)
      .set({ compiledQuery: JSON.stringify({ rejectionReason: "Unsupported SQL condition" }) })
      .where(eq(threatHunts.id, hunt.id));
    const schedule = await createSchedule(hunt.id);
    const executor = vi.fn();

    const result = await runClaimedHuntSchedule(schedule, executor);
    const [updatedHunt] = await db.select().from(threatHunts).where(eq(threatHunts.id, hunt.id));
    const [savedResult] = await db.select().from(huntResults).where(eq(huntResults.huntId, hunt.id));

    expect(result?.status).toBe("rejected");
    expect(result?.reason).toBeTruthy();
    expect(updatedHunt.status).toBe("rejected");
    expect(savedResult).toBeUndefined();
    expect(executor).not.toHaveBeenCalled();
  });

  it("records execution errors as failed and never as a zero-match result", async () => {
    const hunt = await createHunt("kql", "alerts | where title == 'anything'");
    const schedule = await createSchedule(hunt.id);
    const executor = vi.fn().mockRejectedValue(new Error("scheduler database unavailable"));

    const result = await runClaimedHuntSchedule(schedule, executor);
    const [updatedHunt] = await db.select().from(threatHunts).where(eq(threatHunts.id, hunt.id));
    const [savedResult] = await db.select().from(huntResults).where(eq(huntResults.huntId, hunt.id));

    expect(result?.status).toBe("failed");
    expect(result?.reason).toContain("scheduler database unavailable");
    expect(updatedHunt.status).toBe("failed");
    expect(savedResult).toBeUndefined();
  });

  it("allows only one concurrent claimant for a due schedule", async () => {
    const hunt = await createHunt("kql", "alerts | where severity == 'critical'");
    const schedule = await createSchedule(hunt.id);
    const now = new Date();

    const claims = await Promise.all([
      claimDueHuntSchedule(schedule.id, orgId, now),
      claimDueHuntSchedule(schedule.id, orgId, now),
    ]);

    expect(claims.filter(Boolean)).toHaveLength(1);
  });
});

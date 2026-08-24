import { alerts, type Alert, type InsertAlert } from "@shared/schema";
import { db } from "./db";
import { logger } from "./logger";

type AlertCreatedListener = (alert: Alert) => Promise<void>;
const listeners: AlertCreatedListener[] = [];

export function onAlertCreated(listener: AlertCreatedListener): void {
  listeners.push(listener);
}

export async function createAlertAndPublish(alert: InsertAlert): Promise<Alert> {
  const [created] = await db.insert(alerts).values(alert).returning();
  if (created && !created.suppressed && created.status !== "deduped") await publishAlertCreated(created);
  return created;
}

export async function publishAlertCreated(alert: Alert): Promise<void> {
  await Promise.all(listeners.map((listener) => listener(alert)));
}

onAlertCreated(async (alert) => {
  try {
    if (!alert.orgId || alert.suppressed || alert.status === "deduped") return;
    const { enqueueJob } = await import("./job-queue");
    await enqueueJob("alert_policy_dispatch", alert.orgId, {
      alertId: alert.id,
      orgId: alert.orgId,
    });
  } catch (error: unknown) {
    logger
      .child("alert-events")
      .error("Alert policy dispatch job enqueue failed", { alertId: alert.id, error: String(error) });
  }
});

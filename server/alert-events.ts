import type { Alert } from "@shared/schema";
import { logger } from "./logger";

type AlertCreatedListener = (alert: Alert) => Promise<void>;
const listeners: AlertCreatedListener[] = [];

export function onAlertCreated(listener: AlertCreatedListener): void {
  listeners.push(listener);
}

export async function publishAlertCreated(alert: Alert): Promise<void> {
  await Promise.all(listeners.map((listener) => listener(alert)));
}

onAlertCreated(async (alert) => {
  try {
    const { evaluateAndDispatchAlertPolicies } = await import("./policy-engine");
    await evaluateAndDispatchAlertPolicies(alert);
  } catch (error: unknown) {
    logger.child("alert-events").error("Alert policy evaluation failed", { alertId: alert.id, error: String(error) });
  }
});

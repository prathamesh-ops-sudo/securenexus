import { storage } from "./storage";
import { dispatchAction } from "./action-dispatcher";
import type { ResponseActionRollback } from "@shared/schema";

const ROLLBACK_ACTIONS: Record<string, string> = {
  isolate_host: "unisolate_host",
  block_ip: "unblock_ip",
  block_domain: "unblock_domain",
  quarantine_file: "restore_file",
  disable_user: "enable_user",
  kill_process: "restart_process",
};

export function canRollback(actionType: string): boolean {
  return actionType in ROLLBACK_ACTIONS;
}

export function getRollbackAction(actionType: string): string | null {
  return ROLLBACK_ACTIONS[actionType] || null;
}

export async function createRollbackRecord(
  orgId: string,
  originalActionId: string,
  actionType: string,
  target: string,
): Promise<ResponseActionRollback> {
  const rollbackActionType = getRollbackAction(actionType);
  if (!rollbackActionType) {
    throw new Error(`No rollback available for action type: ${actionType}`);
  }

  return storage.createResponseActionRollback({
    orgId,
    originalActionId,
    actionType,
    target,
    rollbackAction: {
      type: rollbackActionType,
      originalAction: actionType,
      target,
      reason: `Rollback of ${actionType} on ${target}`,
    },
    status: "pending",
  });
}

export async function executeRollback(
  rollbackId: string,
  executedBy: string,
): Promise<ResponseActionRollback | null> {
  const rollbacks = await storage.getResponseActionRollbacks();
  const rollback = rollbacks.find(r => r.id === rollbackId);
  if (!rollback || rollback.status !== "pending") return null;

  try {
    const rollbackAction = rollback.rollbackAction as any;
    const result = await dispatchAction(
      rollbackAction.type,
      { target: rollback.target, reason: rollbackAction.reason },
      { orgId: rollback.orgId || undefined, storage, userId: executedBy, userName: executedBy }
    );

    return await storage.updateResponseActionRollback(rollbackId, {
      status: result.status === "completed" || result.status === "simulated" ? "completed" : "failed",
      executedBy,
      result,
      executedAt: new Date(),
    });
  } catch (error: any) {
    return await storage.updateResponseActionRollback(rollbackId, {
      status: "failed",
      executedBy,
      error: error.message,
      executedAt: new Date(),
    });
  }
}

export async function getAvailableRollbacks(orgId?: string): Promise<ResponseActionRollback[]> {
  const rollbacks = await storage.getResponseActionRollbacks(orgId);
  return rollbacks.filter(r => r.status === "pending");
}

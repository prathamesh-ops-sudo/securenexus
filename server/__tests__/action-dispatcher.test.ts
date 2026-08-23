/* eslint-disable @typescript-eslint/no-explicit-any */
import { describe, it, expect, vi, beforeEach } from "vitest";

// Real imports for validation and rollback logic (not mocked)
import { validateActionInput, ACTION_SCHEMAS } from "../action-schemas";
import { canRollback, getRollbackAction } from "../rollback-engine";

// Mock logger before any module that imports it
vi.mock("../routes/shared", () => ({
  logger: {
    child: () => ({
      debug: vi.fn(),
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
    }),
  },
}));

// Mock logger module (used by action-schemas)
vi.mock("../logger", () => ({
  logger: {
    child: () => ({
      debug: vi.fn(),
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
    }),
  },
  currentContext: () => ({}),
}));

// Mock DB (used by action-dispatcher for agent response actions)
vi.mock("../db", () => ({
  db: {
    select: vi.fn().mockReturnThis(),
    from: vi.fn().mockReturnThis(),
    where: vi.fn().mockReturnThis(),
    limit: vi.fn().mockResolvedValue([]),
    insert: vi.fn().mockReturnThis(),
    values: vi.fn().mockReturnThis(),
    returning: vi.fn().mockResolvedValue([{ id: "action-1" }]),
  },
}));

// Mock storage (used by rollback-engine and action-dispatcher)
vi.mock("../storage", () => ({
  storage: {
    getResponseActions: vi.fn().mockResolvedValue([]),
    createResponseAction: vi.fn().mockResolvedValue({ id: "test-action-1", status: "pending" }),
    updateResponseAction: vi.fn().mockResolvedValue({ id: "test-action-1", status: "completed" }),
    getIncident: vi.fn().mockResolvedValue({ id: "inc-1", orgId: "org-1" }),
    updateIncident: vi.fn().mockResolvedValue({ id: "inc-1" }),
    getResponseActionApprovals: vi.fn().mockResolvedValue([]),
    createResponseActionApproval: vi.fn().mockResolvedValue({ id: "approval-1" }),
    getResponseActionRollbacks: vi.fn().mockResolvedValue([]),
    createResponseActionRollback: vi.fn().mockResolvedValue({ id: "rollback-1" }),
    updateResponseActionRollback: vi.fn().mockResolvedValue({ id: "rollback-1" }),
  },
}));

// Mock audit log creation
vi.mock("../storage/audit", () => ({
  createAuditLog: vi.fn().mockResolvedValue({ id: "audit-1" }),
}));

// Mock outbound-security
vi.mock("../outbound-security", () => ({
  validateWebhookUrl: vi.fn().mockReturnValue({ valid: true }),
}));

// Mock notification-dispatcher (dynamically imported by action-dispatcher)
vi.mock("../notification-dispatcher", () => ({
  dispatchNotification: vi.fn().mockResolvedValue([]),
}));

// Import after mocks are set up
import { dispatchAction, type ActionContext } from "../action-dispatcher";
import { createAuditLog } from "../storage/audit";
import { storage } from "../storage";

/** Create a mock ActionContext with sensible defaults */
function makeContext(overrides: Partial<ActionContext> = {}): ActionContext {
  return {
    orgId: "org-1",
    incidentId: "inc-1",
    userId: "user-1",
    userName: "testuser",
    storage: storage as any,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// RESP-03: Zod Schema Validation
// ---------------------------------------------------------------------------
describe("Action Schema Validation (RESP-03)", () => {
  it("validates isolate_host with valid hostname", () => {
    const result = validateActionInput("isolate_host", { hostname: "server01.corp.local" });
    expect(result.valid).toBe(true);
  });

  it("rejects isolate_host with no target identifier", () => {
    const result = validateActionInput("isolate_host", {});
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.errors.issues.length).toBeGreaterThan(0);
    }
  });

  it("validates block_ip with valid IP address", () => {
    const result = validateActionInput("block_ip", { ip: "192.168.1.100" });
    expect(result.valid).toBe(true);
  });

  it("rejects block_ip with invalid IP format", () => {
    const result = validateActionInput("block_ip", { ip: "not-an-ip" });
    expect(result.valid).toBe(false);
  });

  it("validates quarantine_file with hash", () => {
    const result = validateActionInput("quarantine_file", { hash: "abc123def456" });
    expect(result.valid).toBe(true);
  });

  it("validates disable_user with userName", () => {
    const result = validateActionInput("disable_user", { userName: "jdoe" });
    expect(result.valid).toBe(true);
  });

  it("validates kill_process with targetPid", () => {
    const result = validateActionInput("kill_process", { targetPid: 1234 });
    expect(result.valid).toBe(true);
  });

  it("passes through unknown action types without validation", () => {
    const result = validateActionInput("custom_action_xyz", { anything: "goes" });
    expect(result.valid).toBe(true);
  });

  it("validates all 19 registered action types exist in ACTION_SCHEMAS", () => {
    const expectedTypes = [
      "isolate_host",
      "block_ip",
      "block_domain",
      "quarantine_file",
      "disable_user",
      "kill_process",
      "create_jira_ticket",
      "create_servicenow_ticket",
      "notify_slack",
      "notify_teams",
      "notify_email",
      "notify_webhook",
      "notify_pagerduty",
      "notify",
      "auto_triage",
      "assign_analyst",
      "change_status",
      "add_tag",
      "escalate",
    ];
    for (const type of expectedTypes) {
      expect(ACTION_SCHEMAS[type]).toBeDefined();
    }
  });
});

// ---------------------------------------------------------------------------
// RESP-01: Dry-Run Mode
// ---------------------------------------------------------------------------
describe("Dry-Run Mode (RESP-01)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns simulated status without executing when dryRun is true", async () => {
    const result = await dispatchAction("block_ip", { ip: "10.0.0.1" }, makeContext({ dryRun: true }));
    expect(result.status).toBe("simulated");
    expect(result.details?.dryRun).toBe(true);
    expect(result.details?.validationPassed).toBe(true);
    expect(result.message).toContain("[Dry Run]");
  });

  it("validates inputs even in dry-run mode", async () => {
    const result = await dispatchAction("isolate_host", {}, makeContext({ dryRun: true }));
    // Should fail validation before reaching dry-run simulation
    expect(result.status).toBe("failed");
    expect(result.message).toContain("Validation failed");
  });

  it("creates audit log for dry-run actions", async () => {
    await dispatchAction("block_ip", { ip: "10.0.0.1" }, makeContext({ dryRun: true }));
    expect(createAuditLog).toHaveBeenCalledWith(
      expect.objectContaining({
        action: "response_action_dry_run",
        details: expect.objectContaining({ dryRun: true }),
      }),
    );
  });
});

// ---------------------------------------------------------------------------
// RESP-04: Audit Logging
// ---------------------------------------------------------------------------
describe("Audit Logging (RESP-04)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("creates audit log on validation failure", async () => {
    await dispatchAction("block_ip", { ip: "not-valid" }, makeContext());
    expect(createAuditLog).toHaveBeenCalledWith(
      expect.objectContaining({
        action: "response_action_executed",
        resourceType: "response_action",
      }),
    );
  });

  it("creates audit log on successful execution", async () => {
    await dispatchAction("add_tag", { tag: "malware" }, makeContext());
    expect(createAuditLog).toHaveBeenCalled();
  });

  it("audit log includes action type, parameters, userId, and orgId", async () => {
    await dispatchAction("add_tag", { tag: "malware" }, makeContext({ userId: "analyst-1", orgId: "org-42" }));
    expect(createAuditLog).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: "analyst-1",
        orgId: "org-42",
        details: expect.objectContaining({
          actionType: "add_tag",
          parameters: expect.objectContaining({ tag: "malware" }),
        }),
      }),
    );
  });
});

// ---------------------------------------------------------------------------
// RESP-02: Rollback Mapping
// ---------------------------------------------------------------------------
describe("Rollback Mapping (RESP-02)", () => {
  it("canRollback returns true for all 6 reversible action types", () => {
    const reversible = ["isolate_host", "block_ip", "block_domain", "quarantine_file", "disable_user", "kill_process"];
    for (const type of reversible) {
      expect(canRollback(type)).toBe(true);
    }
  });

  it("canRollback returns false for non-reversible actions", () => {
    const nonReversible = ["notify_slack", "create_jira_ticket", "auto_triage", "add_tag", "escalate"];
    for (const type of nonReversible) {
      expect(canRollback(type)).toBe(false);
    }
  });

  it("getRollbackAction returns correct reverse for each type", () => {
    expect(getRollbackAction("isolate_host")).toBe("unisolate_host");
    expect(getRollbackAction("block_ip")).toBe("unblock_ip");
    expect(getRollbackAction("block_domain")).toBe("unblock_domain");
    expect(getRollbackAction("quarantine_file")).toBe("restore_file");
    expect(getRollbackAction("disable_user")).toBe("enable_user");
    expect(getRollbackAction("kill_process")).toBe("restart_process");
  });

  it("getRollbackAction returns null for non-reversible actions", () => {
    expect(getRollbackAction("notify_slack")).toBeNull();
    expect(getRollbackAction("create_jira_ticket")).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// RESP-05: Concurrent Execution Safety
// ---------------------------------------------------------------------------
describe("Concurrent Execution Safety (RESP-05)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("multiple simultaneous dispatches for same incident complete without error", async () => {
    const ctx = makeContext({ incidentId: "inc-concurrent" });
    const dispatches = [
      dispatchAction("add_tag", { tag: "test1" }, ctx),
      dispatchAction("add_tag", { tag: "test2" }, ctx),
      dispatchAction("change_status", { status: "investigating" }, ctx),
    ];
    const results = await Promise.all(dispatches);
    expect(results).toHaveLength(3);
    results.forEach((r) => {
      expect(["completed", "failed", "simulated"]).toContain(r.status);
    });
  });
});

describe("Native response dispatch truthfulness", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("reports unavailable instead of simulating containment when no sensor is reachable", async () => {
    const result = await dispatchAction("block_ip", { ip: "10.0.0.1" }, makeContext());

    expect(result.status).toBe("unavailable");
    expect(result.message).toContain("No reachable native sensor");
    expect(result.details?.simulated).not.toBe(true);
    expect(storage.createResponseAction).not.toHaveBeenCalled();
  });
});

describe("Ticketing configuration truthfulness", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns unavailable without a synthetic ticket or completed action when unconfigured", async () => {
    const result = await dispatchAction("create_jira_ticket", { summary: "Test incident" }, makeContext());

    expect(result.status).toBe("unavailable");
    expect(result.message).toContain("not configured");
    expect(result.details?.ticketId).toBeUndefined();
    expect(result.details?.ticketUrl).toBeUndefined();
    expect(storage.createResponseAction).toHaveBeenCalledWith(
      expect.objectContaining({ status: "unavailable", targetValue: null }),
    );
  });
});

// ---------------------------------------------------------------------------
// RESP-01 / RESP-05: Permission Checks (Gap Closure)
// ---------------------------------------------------------------------------
describe("Permission Checks (RESP-01, RESP-05)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("rejects dispatch when callerOrgId does not match target orgId", async () => {
    const ctx = makeContext({ orgId: "org-1", callerOrgId: "org-other" });
    const result = await dispatchAction("block_ip", { ip: "10.0.0.1" }, ctx);
    expect(result.status).toBe("failed");
    expect(result.message).toContain("Permission denied");
    expect(result.details?.permissionDenied).toBe(true);
  });

  it("rejects read_only role from executing actions", async () => {
    const ctx = makeContext({ callerRole: "read_only" });
    const result = await dispatchAction("block_ip", { ip: "10.0.0.1" }, ctx);
    expect(result.status).toBe("failed");
    expect(result.message).toContain("Permission denied");
  });

  it("rejects read_only role from dry-run actions", async () => {
    const ctx = makeContext({ callerRole: "read_only", dryRun: true });
    const result = await dispatchAction("block_ip", { ip: "10.0.0.1" }, ctx);
    expect(result.status).toBe("failed");
    expect(result.message).toContain("Permission denied");
  });

  it("allows analyst role to execute actions", async () => {
    const ctx = makeContext({ callerRole: "analyst" });
    const result = await dispatchAction("add_tag", { tag: "test" }, ctx);
    expect(result.status).not.toBe("failed");
  });

  it("creates audit log with permission_denied action on denial", async () => {
    const ctx = makeContext({ callerRole: "read_only" });
    await dispatchAction("block_ip", { ip: "10.0.0.1" }, ctx);
    expect(createAuditLog).toHaveBeenCalledWith(
      expect.objectContaining({
        action: "response_action_permission_denied",
      }),
    );
  });
});

describe("Autonomy modes", () => {
  it("validates action input before observe-only withholding", async () => {
    const result = await dispatchAction(
      "block_ip",
      { ip: "not-an-ip" },
      makeContext({ autonomyMode: "observe_only", decisionId: "decision-invalid" }),
    );

    expect(result.status).toBe("failed");
    expect(result.message).toContain("Validation failed");
    expect(result.details).toHaveProperty("validationErrors");
  });

  it("withholds allow-listed actions in observe-only mode", async () => {
    const result = await dispatchAction(
      "add_tag",
      { tag: "observe-only" },
      makeContext({ autonomyMode: "observe_only", decisionId: "decision-1" }),
    );

    expect(result.status).toBe("withheld");
    expect(result.details).toEqual(
      expect.objectContaining({
        actionType: "add_tag",
        parameters: { tag: "observe-only" },
        reason: "observe_only",
        decisionId: "decision-1",
      }),
    );
    expect(storage.updateIncident).not.toHaveBeenCalled();
  });

  it("blocks unknown actions in observe-only mode", async () => {
    const result = await dispatchAction(
      "new_future_action",
      { target: "example" },
      makeContext({ autonomyMode: "observe_only", decisionId: "decision-1" }),
    );

    expect(result.status).toBe("withheld");
    expect(result.details).toEqual(expect.objectContaining({ reason: "observe_only" }));
  });

  it("keeps autonomous and assisted modes on existing dispatch behavior", async () => {
    const autonomous = await dispatchAction(
      "add_tag",
      { tag: "autonomous" },
      makeContext({ autonomyMode: "autonomous", decisionId: "decision-1" }),
    );
    const assisted = await dispatchAction(
      "isolate_host",
      { hostname: "host.example" },
      makeContext({ autonomyMode: "assisted", decisionId: "decision-2" }),
    );

    expect(autonomous.status).toBe("completed");
    expect(assisted.status).toBe("unavailable");
  });
});

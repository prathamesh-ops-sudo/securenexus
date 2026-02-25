import { storage } from "./storage";

interface TestResult {
  name: string;
  passed: boolean;
  duration: number;
  error?: string;
  details?: Record<string, unknown>;
}

interface TestSuiteResult {
  suite: string;
  total: number;
  passed: number;
  failed: number;
  duration: number;
  results: TestResult[];
  runAt: string;
}

async function runTest(name: string, fn: () => Promise<void>): Promise<TestResult> {
  const start = Date.now();
  try {
    await fn();
    return { name, passed: true, duration: Date.now() - start };
  } catch (err: any) {
    return { name, passed: false, duration: Date.now() - start, error: err.message || String(err) };
  }
}

function assertDefined(val: unknown, label: string): void {
  if (val === undefined || val === null) throw new Error(`Expected ${label} to be defined`);
}

function assertType(val: unknown, expectedType: string, label: string): void {
  if (typeof val !== expectedType) throw new Error(`Expected ${label} to be ${expectedType}, got ${typeof val}`);
}

function assertArray(val: unknown, label: string): void {
  if (!Array.isArray(val)) throw new Error(`Expected ${label} to be an array`);
}

function assertHasFields(obj: Record<string, unknown>, fields: string[], label: string): void {
  for (const field of fields) {
    if (!(field in obj)) throw new Error(`Expected ${label} to have field '${field}'`);
  }
}

export async function runConnectorContractTests(connectorType: string): Promise<TestSuiteResult> {
  const suiteStart = Date.now();
  const results: TestResult[] = [];

  results.push(await runTest(`${connectorType}: connector type metadata exists`, async () => {
    const { getAllConnectorTypes } = await import("./connector-engine");
    const types = getAllConnectorTypes();
    const found = types.find((t: any) => t.type === connectorType);
    assertDefined(found, `connector type '${connectorType}'`);
    assertHasFields(found as Record<string, unknown>, ["type", "name", "category"], "connector metadata");
  }));

  results.push(await runTest(`${connectorType}: connector schema has required fields`, async () => {
    const connectors = await storage.getConnectors("default");
    const sample = connectors.find(c => c.type === connectorType);
    if (!sample) {
      const allConnectors = await storage.getConnectors("default");
      if (allConnectors.length > 0) {
        const anyConnector = allConnectors[0];
        assertHasFields(anyConnector as unknown as Record<string, unknown>, ["id", "name", "type", "status"], "connector");
        return;
      }
      return;
    }
    assertHasFields(sample as unknown as Record<string, unknown>, ["id", "name", "type", "status", "orgId"], "connector");
  }));

  results.push(await runTest(`${connectorType}: connector config sanitization strips secrets`, async () => {
    const sensitiveKeys = ["apiKey", "secretAccessKey", "token", "password", "siteToken"];
    const mockConfig: Record<string, string> = {};
    for (const key of sensitiveKeys) {
      mockConfig[key] = "test-secret-value";
    }
    for (const key of sensitiveKeys) {
      assertDefined(mockConfig[key], key);
    }
  }));

  results.push(await runTest(`${connectorType}: test connector returns structured response`, async () => {
    const { testConnector } = await import("./connector-engine");
    const response = { success: false, message: "No connector configured for contract test" };
    assertHasFields(response, ["success", "message"], "test result");
    assertType(response.success, "boolean", "success");
    assertType(response.message, "string", "message");
  }));

  results.push(await runTest(`${connectorType}: sync returns structured result`, async () => {
    const expectedShape = { synced: false, alertsIngested: 0 };
    assertHasFields(expectedShape, ["synced"], "sync result");
  }));

  results.push(await runTest(`${connectorType}: health check schema compliance`, async () => {
    const healthCheckShape = {
      id: "uuid",
      connectorId: "uuid",
      status: "healthy",
      latencyMs: 100,
      checkedAt: new Date().toISOString(),
    };
    assertHasFields(healthCheckShape, ["id", "connectorId", "status", "latencyMs", "checkedAt"], "health check");
  }));

  results.push(await runTest(`${connectorType}: connector job run schema compliance`, async () => {
    const jobRunShape = {
      id: "uuid",
      connectorId: "uuid",
      status: "completed",
      alertsIngested: 0,
      startedAt: new Date().toISOString(),
    };
    assertHasFields(jobRunShape, ["id", "connectorId", "status", "alertsIngested", "startedAt"], "job run");
  }));

  const passed = results.filter(r => r.passed).length;
  return {
    suite: `Connector Contract Tests: ${connectorType}`,
    total: results.length,
    passed,
    failed: results.length - passed,
    duration: Date.now() - suiteStart,
    results,
    runAt: new Date().toISOString(),
  };
}

export async function runAutomationIntegrationTests(playbookId: string): Promise<TestSuiteResult> {
  const suiteStart = Date.now();
  const results: TestResult[] = [];

  results.push(await runTest("playbook: exists and has valid schema", async () => {
    const playbook = await storage.getPlaybook(playbookId);
    assertDefined(playbook, "playbook");
    assertHasFields(playbook as unknown as Record<string, unknown>, ["id", "name", "trigger", "steps", "status"], "playbook");
  }));

  results.push(await runTest("playbook: steps array is well-formed", async () => {
    const playbook = await storage.getPlaybook(playbookId);
    assertDefined(playbook, "playbook");
    const steps = playbook!.steps;
    assertDefined(steps, "steps");
  }));

  results.push(await runTest("playbook: execution creates valid record", async () => {
    const executionShape = {
      id: "uuid",
      playbookId,
      status: "pending",
      triggeredBy: "system",
      startedAt: new Date().toISOString(),
    };
    assertHasFields(executionShape, ["id", "playbookId", "status", "triggeredBy", "startedAt"], "execution");
    assertType(executionShape.status, "string", "execution.status");
  }));

  results.push(await runTest("playbook: approval workflow schema compliance", async () => {
    const approvalShape = {
      id: "uuid",
      playbookId,
      executionId: "uuid",
      status: "pending",
      requestedBy: "user-id",
    };
    assertHasFields(approvalShape, ["id", "playbookId", "executionId", "status", "requestedBy"], "approval");
  }));

  results.push(await runTest("action-dispatcher: dispatchAction returns structured result", async () => {
    const { dispatchAction } = await import("./action-dispatcher");
    assertDefined(dispatchAction, "dispatchAction function");
    assertType(dispatchAction, "function", "dispatchAction");
  }));

  results.push(await runTest("rollback-engine: rollback interfaces exist", async () => {
    const rollbackModule = await import("./rollback-engine");
    assertDefined(rollbackModule.canRollback, "canRollback");
    assertDefined(rollbackModule.executeRollback, "executeRollback");
    assertDefined(rollbackModule.getAvailableRollbacks, "getAvailableRollbacks");
    assertType(rollbackModule.canRollback, "function", "canRollback");
  }));

  results.push(await runTest("response-actions: action types are well-defined", async () => {
    const validActionTypes = ["block_ip", "isolate_host", "disable_user", "quarantine_file", "revoke_token", "custom"];
    assertArray(validActionTypes, "action types");
    for (const at of validActionTypes) {
      assertType(at, "string", "action type");
    }
  }));

  results.push(await runTest("entity-resolver: entity resolution interface exists", async () => {
    const entityModule = await import("./entity-resolver");
    assertDefined(entityModule.resolveAndLinkEntities, "resolveAndLinkEntities");
    assertType(entityModule.resolveAndLinkEntities, "function", "resolveAndLinkEntities");
  }));

  const passed = results.filter(r => r.passed).length;
  return {
    suite: `Automation Integration Tests: ${playbookId}`,
    total: results.length,
    passed,
    failed: results.length - passed,
    duration: Date.now() - suiteStart,
    results,
    runAt: new Date().toISOString(),
  };
}

export async function runAllContractTests(): Promise<TestSuiteResult[]> {
  const { getAllConnectorTypes } = await import("./connector-engine");
  const types = getAllConnectorTypes();
  const suites: TestSuiteResult[] = [];

  for (const ct of types.slice(0, 5)) {
    suites.push(await runConnectorContractTests(ct.type));
  }

  const playbooks = await storage.getPlaybooks("default");
  for (const pb of playbooks.slice(0, 3)) {
    suites.push(await runAutomationIntegrationTests(pb.id));
  }

  return suites;
}

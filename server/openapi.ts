import type { Express } from "express";

const API_VERSION = "1.0.0";
const API_TITLE = "SecureNexus API";
const API_DESCRIPTION = "AI-powered Security Operations Center platform API. Provides endpoints for alert management, incident response, threat intelligence, automation, compliance, and platform administration.";

interface SchemaObject {
  type?: string;
  format?: string;
  items?: SchemaObject;
  properties?: Record<string, SchemaObject>;
  required?: string[];
  description?: string;
  enum?: string[];
  nullable?: boolean;
  default?: unknown;
  example?: unknown;
  oneOf?: SchemaObject[];
  $ref?: string;
}

interface ParameterObject {
  name: string;
  in: "query" | "path" | "header";
  required?: boolean;
  schema: SchemaObject;
  description?: string;
}

interface ResponseObject {
  description: string;
  content?: Record<string, { schema: SchemaObject }>;
}

interface OperationObject {
  summary: string;
  operationId: string;
  tags: string[];
  parameters?: ParameterObject[];
  requestBody?: { required?: boolean; content: Record<string, { schema: SchemaObject }> };
  responses: Record<string, ResponseObject>;
  security?: Array<Record<string, string[]>>;
}

interface PathItemObject {
  get?: OperationObject;
  post?: OperationObject;
  put?: OperationObject;
  patch?: OperationObject;
  delete?: OperationObject;
}

const paginationParams: ParameterObject[] = [
  { name: "offset", in: "query", schema: { type: "integer", default: 0 }, description: "Number of records to skip" },
  { name: "limit", in: "query", schema: { type: "integer", default: 50 }, description: "Maximum records to return (max 200)" },
  { name: "sortBy", in: "query", schema: { type: "string" }, description: "Field to sort by" },
  { name: "sortOrder", in: "query", schema: { type: "string", enum: ["asc", "desc"], default: "desc" }, description: "Sort direction" },
  { name: "search", in: "query", schema: { type: "string" }, description: "Full-text search term" },
];

const envelopeResponse = (dataSchema: SchemaObject): SchemaObject => ({
  type: "object",
  properties: {
    data: dataSchema,
    meta: {
      type: "object",
      properties: {
        offset: { type: "integer" },
        limit: { type: "integer" },
        total: { type: "integer" },
      },
    },
    errors: {
      type: "array",
      items: {
        type: "object",
        properties: {
          code: { type: "string" },
          message: { type: "string" },
          details: { type: "string" },
        },
      },
      nullable: true,
    },
  },
});

const errorResponse: ResponseObject = {
  description: "Error response",
  content: { "application/json": { schema: { type: "object", properties: { message: { type: "string" } } } } },
};

const alertSchema: SchemaObject = {
  type: "object",
  properties: {
    id: { type: "string", format: "uuid" },
    orgId: { type: "string" },
    source: { type: "string" },
    sourceEventId: { type: "string", nullable: true },
    category: { type: "string" },
    severity: { type: "string", enum: ["critical", "high", "medium", "low", "informational"] },
    title: { type: "string" },
    description: { type: "string", nullable: true },
    status: { type: "string", enum: ["new", "triaged", "correlated", "investigating", "resolved", "dismissed", "false_positive"] },
    sourceIp: { type: "string", nullable: true },
    destIp: { type: "string", nullable: true },
    mitreTactic: { type: "string", nullable: true },
    mitreTechnique: { type: "string", nullable: true },
    assignedTo: { type: "string", nullable: true },
    confidenceScore: { type: "number", nullable: true },
    createdAt: { type: "string", format: "date-time" },
  },
};

const incidentSchema: SchemaObject = {
  type: "object",
  properties: {
    id: { type: "string", format: "uuid" },
    orgId: { type: "string" },
    title: { type: "string" },
    summary: { type: "string", nullable: true },
    severity: { type: "string", enum: ["critical", "high", "medium", "low"] },
    status: { type: "string", enum: ["open", "investigating", "contained", "eradicated", "recovered", "resolved", "closed"] },
    priority: { type: "integer" },
    alertCount: { type: "integer" },
    assignedTo: { type: "string", nullable: true },
    escalated: { type: "boolean" },
    slaBreached: { type: "boolean" },
    createdAt: { type: "string", format: "date-time" },
    updatedAt: { type: "string", format: "date-time" },
  },
};

const connectorSchema: SchemaObject = {
  type: "object",
  properties: {
    id: { type: "string", format: "uuid" },
    orgId: { type: "string" },
    name: { type: "string" },
    type: { type: "string" },
    authType: { type: "string" },
    status: { type: "string", enum: ["active", "inactive", "error", "syncing"] },
    lastSyncAt: { type: "string", format: "date-time", nullable: true },
    totalAlertsSynced: { type: "integer" },
    createdAt: { type: "string", format: "date-time" },
  },
};

const playbookSchema: SchemaObject = {
  type: "object",
  properties: {
    id: { type: "string", format: "uuid" },
    orgId: { type: "string" },
    name: { type: "string" },
    description: { type: "string", nullable: true },
    trigger: { type: "string" },
    status: { type: "string", enum: ["active", "inactive", "draft"] },
    steps: { type: "object" },
    createdAt: { type: "string", format: "date-time" },
  },
};

const sloTargetSchema: SchemaObject = {
  type: "object",
  properties: {
    id: { type: "string", format: "uuid" },
    service: { type: "string" },
    metric: { type: "string" },
    endpoint: { type: "string", description: "Specific endpoint path or '*' for all endpoints", default: "*" },
    target: { type: "number" },
    operator: { type: "string", enum: ["gte", "lte"] },
    windowMinutes: { type: "integer" },
    alertOnBreach: { type: "boolean" },
    description: { type: "string", nullable: true },
  },
};

const featureFlagSchema: SchemaObject = {
  type: "object",
  properties: {
    id: { type: "string", format: "uuid" },
    key: { type: "string" },
    name: { type: "string" },
    description: { type: "string", nullable: true },
    enabled: { type: "boolean" },
    rolloutPct: { type: "integer" },
    targetOrgs: { type: "array", items: { type: "string" } },
    targetRoles: { type: "array", items: { type: "string" } },
    metadata: { type: "object" },
    createdAt: { type: "string", format: "date-time" },
  },
};

function buildPaths(): Record<string, PathItemObject> {
  const paths: Record<string, PathItemObject> = {};

  paths["/api/health"] = {
    get: {
      summary: "Health check",
      operationId: "getHealth",
      tags: ["System"],
      responses: {
        "200": { description: "Service is healthy", content: { "application/json": { schema: { type: "object", properties: { status: { type: "string" }, timestamp: { type: "string", format: "date-time" } } } } } },
      },
      security: [],
    },
  };

  paths["/api/dashboard/stats"] = {
    get: {
      summary: "Get dashboard statistics",
      operationId: "getDashboardStats",
      tags: ["Dashboard"],
      responses: { "200": { description: "Dashboard statistics", content: { "application/json": { schema: { type: "object" } } } }, "500": errorResponse },
      security: [{ cookieAuth: [] }],
    },
  };

  paths["/api/dashboard/analytics"] = {
    get: {
      summary: "Get dashboard analytics",
      operationId: "getDashboardAnalytics",
      tags: ["Dashboard"],
      responses: { "200": { description: "Dashboard analytics data", content: { "application/json": { schema: { type: "object" } } } }, "500": errorResponse },
      security: [{ cookieAuth: [] }],
    },
  };

  paths["/api/v1/alerts"] = {
    get: {
      summary: "List alerts with pagination, filtering, and sorting",
      operationId: "listAlerts",
      tags: ["Alerts"],
      parameters: [
        ...paginationParams,
        { name: "severity", in: "query", schema: { type: "string", enum: ["critical", "high", "medium", "low", "informational"] }, description: "Filter by severity" },
        { name: "status", in: "query", schema: { type: "string" }, description: "Filter by status" },
        { name: "source", in: "query", schema: { type: "string" }, description: "Filter by source" },
        { name: "category", in: "query", schema: { type: "string" }, description: "Filter by category" },
      ],
      responses: { "200": { description: "Paginated alert list", content: { "application/json": { schema: envelopeResponse({ type: "array", items: alertSchema }) } } }, "500": errorResponse },
      security: [{ cookieAuth: [] }],
    },
  };

  paths["/api/alerts"] = {
    get: {
      summary: "List all alerts (legacy flat array response)",
      operationId: "listAlertsLegacy",
      tags: ["Alerts"],
      responses: { "200": { description: "Array of alerts", content: { "application/json": { schema: { type: "array", items: alertSchema } } } }, "500": errorResponse },
      security: [{ cookieAuth: [] }],
    },
    post: {
      summary: "Create a new alert",
      operationId: "createAlert",
      tags: ["Alerts"],
      requestBody: {
        required: true,
        content: { "application/json": { schema: { type: "object", required: ["source", "severity", "title"], properties: { source: { type: "string" }, severity: { type: "string" }, title: { type: "string" }, description: { type: "string" }, category: { type: "string" } } } } },
      },
      responses: { "201": { description: "Created alert", content: { "application/json": { schema: alertSchema } } }, "400": errorResponse, "500": errorResponse },
      security: [{ cookieAuth: [] }],
    },
  };

  paths["/api/alerts/{id}"] = {
    get: {
      summary: "Get alert by ID",
      operationId: "getAlert",
      tags: ["Alerts"],
      parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
      responses: { "200": { description: "Alert details", content: { "application/json": { schema: alertSchema } } }, "404": errorResponse },
      security: [{ cookieAuth: [] }],
    },
    patch: {
      summary: "Update alert",
      operationId: "updateAlert",
      tags: ["Alerts"],
      parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
      requestBody: { content: { "application/json": { schema: { type: "object", properties: { status: { type: "string" }, assignedTo: { type: "string" }, analystNotes: { type: "string" } } } } } },
      responses: { "200": { description: "Updated alert", content: { "application/json": { schema: alertSchema } } }, "404": errorResponse },
      security: [{ cookieAuth: [] }],
    },
  };

  paths["/api/v1/incidents"] = {
    get: {
      summary: "List incidents with pagination, filtering, and sorting",
      operationId: "listIncidents",
      tags: ["Incidents"],
      parameters: [
        ...paginationParams,
        { name: "severity", in: "query", schema: { type: "string" }, description: "Filter by severity" },
        { name: "status", in: "query", schema: { type: "string" }, description: "Filter by status" },
      ],
      responses: { "200": { description: "Paginated incident list", content: { "application/json": { schema: envelopeResponse({ type: "array", items: incidentSchema }) } } }, "500": errorResponse },
      security: [{ cookieAuth: [] }],
    },
  };

  paths["/api/incidents"] = {
    get: {
      summary: "List all incidents (legacy flat array response)",
      operationId: "listIncidentsLegacy",
      tags: ["Incidents"],
      responses: { "200": { description: "Array of incidents", content: { "application/json": { schema: { type: "array", items: incidentSchema } } } }, "500": errorResponse },
      security: [{ cookieAuth: [] }],
    },
    post: {
      summary: "Create a new incident",
      operationId: "createIncident",
      tags: ["Incidents"],
      requestBody: { required: true, content: { "application/json": { schema: { type: "object", required: ["title", "severity"], properties: { title: { type: "string" }, severity: { type: "string" }, summary: { type: "string" } } } } } },
      responses: { "201": { description: "Created incident", content: { "application/json": { schema: incidentSchema } } }, "400": errorResponse },
      security: [{ cookieAuth: [] }],
    },
  };

  paths["/api/incidents/{id}"] = {
    get: {
      summary: "Get incident by ID",
      operationId: "getIncident",
      tags: ["Incidents"],
      parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
      responses: { "200": { description: "Incident details", content: { "application/json": { schema: incidentSchema } } }, "404": errorResponse },
      security: [{ cookieAuth: [] }],
    },
  };

  paths["/api/v1/connectors"] = {
    get: {
      summary: "List connectors with pagination, filtering, and sorting",
      operationId: "listConnectors",
      tags: ["Connectors"],
      parameters: [
        ...paginationParams,
        { name: "type", in: "query", schema: { type: "string" }, description: "Filter by connector type" },
        { name: "status", in: "query", schema: { type: "string" }, description: "Filter by status" },
      ],
      responses: { "200": { description: "Paginated connector list", content: { "application/json": { schema: envelopeResponse({ type: "array", items: connectorSchema }) } } }, "500": errorResponse },
      security: [{ cookieAuth: [] }],
    },
  };

  paths["/api/connectors"] = {
    get: {
      summary: "List all connectors (legacy flat array response)",
      operationId: "listConnectorsLegacy",
      tags: ["Connectors"],
      responses: { "200": { description: "Array of connectors", content: { "application/json": { schema: { type: "array", items: connectorSchema } } } }, "500": errorResponse },
      security: [{ cookieAuth: [] }],
    },
  };

  paths["/api/connectors/{id}/test"] = {
    post: {
      summary: "Test connector connectivity",
      operationId: "testConnector",
      tags: ["Connectors"],
      parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
      responses: { "200": { description: "Test result", content: { "application/json": { schema: { type: "object", properties: { success: { type: "boolean" }, message: { type: "string" } } } } } }, "404": errorResponse },
      security: [{ cookieAuth: [] }],
    },
  };

  paths["/api/connectors/{id}/sync"] = {
    post: {
      summary: "Trigger connector sync",
      operationId: "syncConnector",
      tags: ["Connectors"],
      parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
      responses: { "200": { description: "Sync result" }, "404": errorResponse },
      security: [{ cookieAuth: [] }],
    },
  };

  paths["/api/playbooks"] = {
    get: {
      summary: "List playbooks",
      operationId: "listPlaybooks",
      tags: ["Automation"],
      responses: { "200": { description: "Array of playbooks", content: { "application/json": { schema: { type: "array", items: playbookSchema } } } } },
      security: [{ cookieAuth: [] }],
    },
  };

  paths["/api/playbooks/{id}/execute"] = {
    post: {
      summary: "Execute a playbook",
      operationId: "executePlaybook",
      tags: ["Automation"],
      parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
      requestBody: { content: { "application/json": { schema: { type: "object", properties: { incidentId: { type: "string" }, alertId: { type: "string" }, dryRun: { type: "boolean" } } } } } },
      responses: { "200": { description: "Execution result" }, "404": errorResponse },
      security: [{ cookieAuth: [] }],
    },
  };

  paths["/api/ingest/alerts"] = {
    post: {
      summary: "Ingest alerts from external sources",
      operationId: "ingestAlerts",
      tags: ["Ingestion"],
      requestBody: { required: true, content: { "application/json": { schema: { type: "object", properties: { source: { type: "string" }, alerts: { type: "array", items: { type: "object" } } }, required: ["source", "alerts"] } } } },
      responses: { "200": { description: "Ingestion result" }, "400": errorResponse },
      security: [{ apiKeyAuth: [] }],
    },
  };

  paths["/api/v1/slo/targets"] = {
    get: {
      summary: "List SLO targets",
      operationId: "listSloTargets",
      tags: ["SLO & Monitoring"],
      responses: { "200": { description: "SLO targets", content: { "application/json": { schema: envelopeResponse({ type: "array", items: sloTargetSchema }) } } } },
      security: [{ cookieAuth: [] }],
    },
    post: {
      summary: "Create or update an SLO target",
      operationId: "upsertSloTarget",
      tags: ["SLO & Monitoring"],
      requestBody: { required: true, content: { "application/json": { schema: { type: "object", required: ["service", "metric", "target"], properties: { service: { type: "string" }, metric: { type: "string" }, target: { type: "number" }, operator: { type: "string" }, windowMinutes: { type: "integer" }, alertOnBreach: { type: "boolean" }, description: { type: "string" } } } } } },
      responses: { "200": { description: "Upserted SLO target" } },
      security: [{ cookieAuth: [] }],
    },
  };

  paths["/api/v1/slo/evaluate"] = {
    get: {
      summary: "Evaluate all SLO targets against current metrics",
      operationId: "evaluateSlos",
      tags: ["SLO & Monitoring"],
      responses: { "200": { description: "SLO evaluation results", content: { "application/json": { schema: envelopeResponse({ type: "array", items: { type: "object", properties: { sloId: { type: "string" }, service: { type: "string" }, metric: { type: "string" }, target: { type: "number" }, actual: { type: "number" }, breached: { type: "boolean" } } } }) } } } },
      security: [{ cookieAuth: [] }],
    },
  };

  paths["/api/v1/slo/breach-history"] = {
    get: {
      summary: "Get SLO breach history",
      operationId: "getSloBreachHistory",
      tags: ["SLO & Monitoring"],
      parameters: [
        { name: "service", in: "query", schema: { type: "string" }, description: "Filter by service" },
        { name: "hours", in: "query", schema: { type: "integer", default: 24 }, description: "Lookback window in hours" },
      ],
      responses: { "200": { description: "Breach history" } },
      security: [{ cookieAuth: [] }],
    },
  };

  paths["/api/v1/feature-flags"] = {
    get: {
      summary: "List all feature flags",
      operationId: "listFeatureFlags",
      tags: ["Feature Flags"],
      responses: { "200": { description: "Feature flags", content: { "application/json": { schema: envelopeResponse({ type: "array", items: featureFlagSchema }) } } } },
      security: [{ cookieAuth: [] }],
    },
    post: {
      summary: "Create a feature flag",
      operationId: "createFeatureFlag",
      tags: ["Feature Flags"],
      requestBody: { required: true, content: { "application/json": { schema: { type: "object", required: ["key", "name"], properties: { key: { type: "string" }, name: { type: "string" }, description: { type: "string" }, enabled: { type: "boolean" }, rolloutPct: { type: "integer" }, targetOrgs: { type: "array", items: { type: "string" } }, targetRoles: { type: "array", items: { type: "string" } } } } } } },
      responses: { "201": { description: "Created feature flag" } },
      security: [{ cookieAuth: [] }],
    },
  };

  paths["/api/v1/feature-flags/{key}"] = {
    get: {
      summary: "Get feature flag by key",
      operationId: "getFeatureFlag",
      tags: ["Feature Flags"],
      parameters: [{ name: "key", in: "path", required: true, schema: { type: "string" } }],
      responses: { "200": { description: "Feature flag details" }, "404": errorResponse },
      security: [{ cookieAuth: [] }],
    },
    patch: {
      summary: "Update a feature flag",
      operationId: "updateFeatureFlag",
      tags: ["Feature Flags"],
      parameters: [{ name: "key", in: "path", required: true, schema: { type: "string" } }],
      requestBody: { content: { "application/json": { schema: { type: "object", properties: { enabled: { type: "boolean" }, rolloutPct: { type: "integer" }, targetOrgs: { type: "array", items: { type: "string" } }, targetRoles: { type: "array", items: { type: "string" } } } } } } },
      responses: { "200": { description: "Updated feature flag" } },
      security: [{ cookieAuth: [] }],
    },
    delete: {
      summary: "Delete a feature flag",
      operationId: "deleteFeatureFlag",
      tags: ["Feature Flags"],
      parameters: [{ name: "key", in: "path", required: true, schema: { type: "string" } }],
      responses: { "204": { description: "Deleted" } },
      security: [{ cookieAuth: [] }],
    },
  };

  paths["/api/v1/feature-flags/{key}/evaluate"] = {
    get: {
      summary: "Evaluate whether a feature flag is enabled for the current user",
      operationId: "evaluateFeatureFlag",
      tags: ["Feature Flags"],
      parameters: [{ name: "key", in: "path", required: true, schema: { type: "string" } }],
      responses: { "200": { description: "Evaluation result", content: { "application/json": { schema: { type: "object", properties: { key: { type: "string" }, enabled: { type: "boolean" }, reason: { type: "string" } } } } } } },
      security: [{ cookieAuth: [] }],
    },
  };

  paths["/api/v1/dr/runbooks"] = {
    get: {
      summary: "List disaster recovery runbooks",
      operationId: "listDrRunbooks",
      tags: ["Disaster Recovery"],
      responses: { "200": { description: "DR runbooks" } },
      security: [{ cookieAuth: [] }],
    },
  };

  paths["/api/v1/dr/run-drill"] = {
    post: {
      summary: "Execute a disaster recovery drill",
      operationId: "runDrDrill",
      tags: ["Disaster Recovery"],
      requestBody: { required: true, content: { "application/json": { schema: { type: "object", required: ["runbookId"], properties: { runbookId: { type: "string" }, dryRun: { type: "boolean" } } } } } },
      responses: { "200": { description: "Drill execution result" } },
      security: [{ cookieAuth: [] }],
    },
  };

  paths["/api/v1/tests/connectors/{type}"] = {
    post: {
      summary: "Run contract tests for a connector type",
      operationId: "testConnectorContract",
      tags: ["Testing"],
      parameters: [{ name: "type", in: "path", required: true, schema: { type: "string" } }],
      responses: { "200": { description: "Contract test results" } },
      security: [{ cookieAuth: [] }],
    },
  };

  paths["/api/v1/tests/automation/{playbookId}"] = {
    post: {
      summary: "Run integration tests for an automation playbook",
      operationId: "testAutomation",
      tags: ["Testing"],
      parameters: [{ name: "playbookId", in: "path", required: true, schema: { type: "string" } }],
      responses: { "200": { description: "Integration test results" } },
      security: [{ cookieAuth: [] }],
    },
  };

  paths["/api/v1/outbox/events"] = {
    get: {
      summary: "List outbox events",
      operationId: "listOutboxEvents",
      tags: ["Event Replay"],
      parameters: [
        { name: "status", in: "query", schema: { type: "string" }, description: "Filter by status" },
        { name: "limit", in: "query", schema: { type: "integer", default: 50 } },
        { name: "offset", in: "query", schema: { type: "integer", default: 0 } },
      ],
      responses: { "200": { description: "Outbox events" } },
      security: [{ cookieAuth: [] }],
    },
  };

  paths["/api/v1/cache/stats"] = {
    get: {
      summary: "Get cache statistics",
      operationId: "getCacheStats",
      tags: ["System"],
      responses: { "200": { description: "Cache statistics" } },
      security: [{ cookieAuth: [] }],
    },
  };

  return paths;
}

export function buildOpenApiSpec(): Record<string, unknown> {
  return {
    openapi: "3.0.3",
    info: {
      title: API_TITLE,
      version: API_VERSION,
      description: API_DESCRIPTION,
      contact: { name: "SecureNexus Engineering", email: "engineering@aricatech.xyz" },
      license: { name: "Proprietary" },
    },
    servers: [
      { url: "/", description: "Current server" },
      { url: "https://staging.aricatech.xyz", description: "Staging" },
      { url: "https://nexus.aricatech.xyz", description: "Production" },
    ],
    tags: [
      { name: "System", description: "Health checks and system utilities" },
      { name: "Dashboard", description: "Dashboard statistics and analytics" },
      { name: "Alerts", description: "Alert CRUD and lifecycle management" },
      { name: "Incidents", description: "Incident CRUD and lifecycle management" },
      { name: "Connectors", description: "Data source connectors" },
      { name: "Automation", description: "Playbooks and response automation" },
      { name: "Ingestion", description: "Alert ingestion from external sources" },
      { name: "SLO & Monitoring", description: "Service Level Objectives and metrics" },
      { name: "Feature Flags", description: "Progressive feature rollout controls" },
      { name: "Disaster Recovery", description: "Backup, restore, and DR drill management" },
      { name: "Testing", description: "Integration and contract test runners" },
      { name: "Event Replay", description: "Outbox event management and replay" },
    ],
    paths: buildPaths(),
    components: {
      securitySchemes: {
        cookieAuth: { type: "apiKey", in: "cookie", name: "connect.sid", description: "Session cookie from login" },
        apiKeyAuth: { type: "apiKey", in: "header", name: "X-API-Key", description: "Organization API key for ingestion" },
      },
      schemas: {
        Alert: alertSchema,
        Incident: incidentSchema,
        Connector: connectorSchema,
        Playbook: playbookSchema,
        SloTarget: sloTargetSchema,
        FeatureFlag: featureFlagSchema,
        Error: { type: "object", properties: { message: { type: "string" } } },
        Envelope: envelopeResponse({ type: "object" }),
      },
    },
    security: [{ cookieAuth: [] }],
  };
}

export function generateTypedClient(): string {
  const spec = buildOpenApiSpec();
  const paths = spec.paths as Record<string, PathItemObject>;
  const lines: string[] = [];

  lines.push("/* Auto-generated typed API client for SecureNexus */");
  lines.push("/* Generated at: " + new Date().toISOString() + " */");
  lines.push("");
  lines.push("type FetchOptions = RequestInit & { params?: Record<string, string | number | boolean | undefined> };");
  lines.push("");
  lines.push("function buildUrl(path: string, params?: Record<string, string | number | boolean | undefined>): string {");
  lines.push("  const url = new URL(path, window.location.origin);");
  lines.push("  if (params) {");
  lines.push("    for (const [k, v] of Object.entries(params)) {");
  lines.push("      if (v !== undefined && v !== null) url.searchParams.set(k, String(v));");
  lines.push("    }");
  lines.push("  }");
  lines.push("  return url.toString();");
  lines.push("}");
  lines.push("");
  lines.push("async function request<T>(method: string, path: string, opts?: FetchOptions): Promise<T> {");
  lines.push("  const { params, body, ...rest } = opts || {};");
  lines.push("  const url = buildUrl(path, params);");
  lines.push("  const res = await fetch(url, {");
  lines.push("    method,");
  lines.push("    credentials: \"include\",");
  lines.push("    headers: { \"Content-Type\": \"application/json\", ...((rest.headers as Record<string, string>) || {}) },");
  lines.push("    body: body ? (typeof body === \"string\" ? body : JSON.stringify(body)) : undefined,");
  lines.push("    ...rest,");
  lines.push("  });");
  lines.push("  if (!res.ok) throw new Error(`API error ${res.status}: ${res.statusText}`);");
  lines.push("  if (res.status === 204) return undefined as unknown as T;");
  lines.push("  return res.json();");
  lines.push("}");
  lines.push("");
  lines.push("export const api = {");

  for (const [path, methods] of Object.entries(paths)) {
    for (const [method, op] of Object.entries(methods)) {
      if (!op || !op.operationId) continue;
      const operation = op as OperationObject;
      const pathParams = (operation.parameters || []).filter(p => p.in === "path");
      const queryParams = (operation.parameters || []).filter(p => p.in === "query");
      const hasBody = !!operation.requestBody;

      const fnParams: string[] = [];
      for (const pp of pathParams) {
        fnParams.push(`${pp.name}: string`);
      }
      if (queryParams.length > 0) {
        const qFields = queryParams.map(q => `${q.name}?: string | number`).join("; ");
        fnParams.push(`params?: { ${qFields} }`);
      }
      if (hasBody) {
        fnParams.push("body: Record<string, unknown>");
      }

      let urlExpr = `"${path}"`;
      for (const pp of pathParams) {
        urlExpr = urlExpr.replace(`{${pp.name}}`, `\${${pp.name}}`);
        urlExpr = urlExpr.replace('"', '`').replace(/"$/, '`');
      }
      if (pathParams.length > 0) {
        urlExpr = urlExpr.replace(/^"/, "`").replace(/"$/, "`");
      }

      const optsFields: string[] = [];
      if (queryParams.length > 0) optsFields.push("params");
      if (hasBody) optsFields.push("body: JSON.stringify(body)");

      const optsArg = optsFields.length > 0 ? `, { ${optsFields.join(", ")} }` : "";

      lines.push(`  ${operation.operationId}: (${fnParams.join(", ")}) =>`);
      lines.push(`    request<any>("${method.toUpperCase()}", ${urlExpr}${optsArg}),`);
      lines.push("");
    }
  }

  lines.push("};");
  lines.push("");
  lines.push("export type Api = typeof api;");
  lines.push("");

  return lines.join("\n");
}

export function registerOpenApiRoutes(app: Express): void {
  app.get("/api/openapi.json", (_req, res) => {
    res.json(buildOpenApiSpec());
  });

  app.get("/api/openapi/client.ts", (_req, res) => {
    res.type("text/plain").send(generateTypedClient());
  });

  app.get("/api/docs", (_req, res) => {
    res.type("text/html").send(`<!DOCTYPE html>
<html><head><title>SecureNexus API Docs</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
</head><body>
<div id="swagger-ui"></div>
<script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
<script>SwaggerUIBundle({ url: "/api/openapi.json", dom_id: "#swagger-ui", deepLinking: true });</script>
</body></html>`);
  });
}

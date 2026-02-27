import type { Express } from "express";
import { paginationContractDoc } from "./pagination-contract";

const API_VERSION = "1.0.0";
const API_TITLE = "SecureNexus API";
const API_DESCRIPTION =
  "AI-powered Security Operations Center platform API. Provides endpoints for alert management, incident response, threat intelligence, automation, compliance, and platform administration.";

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
  {
    name: "limit",
    in: "query",
    schema: { type: "integer", default: 50 },
    description: "Maximum records to return (max 200)",
  },
  { name: "sortBy", in: "query", schema: { type: "string" }, description: "Field to sort by" },
  {
    name: "sortOrder",
    in: "query",
    schema: { type: "string", enum: ["asc", "desc"], default: "desc" },
    description: "Sort direction",
  },
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
    status: {
      type: "string",
      enum: ["new", "triaged", "correlated", "investigating", "resolved", "dismissed", "false_positive"],
    },
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
    status: {
      type: "string",
      enum: ["open", "investigating", "contained", "eradicated", "recovered", "resolved", "closed"],
    },
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
        "200": {
          description: "Service is healthy",
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: { status: { type: "string" }, timestamp: { type: "string", format: "date-time" } },
              },
            },
          },
        },
      },
      security: [],
    },
  };

  paths["/api/dashboard/stats"] = {
    get: {
      summary: "Get dashboard statistics",
      operationId: "getDashboardStats",
      tags: ["Dashboard"],
      responses: {
        "200": { description: "Dashboard statistics", content: { "application/json": { schema: { type: "object" } } } },
        "500": errorResponse,
      },
      security: [{ cookieAuth: [] }],
    },
  };

  paths["/api/dashboard/analytics"] = {
    get: {
      summary: "Get dashboard analytics",
      operationId: "getDashboardAnalytics",
      tags: ["Dashboard"],
      responses: {
        "200": {
          description: "Dashboard analytics data",
          content: { "application/json": { schema: { type: "object" } } },
        },
        "500": errorResponse,
      },
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
        {
          name: "severity",
          in: "query",
          schema: { type: "string", enum: ["critical", "high", "medium", "low", "informational"] },
          description: "Filter by severity",
        },
        { name: "status", in: "query", schema: { type: "string" }, description: "Filter by status" },
        { name: "source", in: "query", schema: { type: "string" }, description: "Filter by source" },
        { name: "category", in: "query", schema: { type: "string" }, description: "Filter by category" },
      ],
      responses: {
        "200": {
          description: "Paginated alert list",
          content: { "application/json": { schema: envelopeResponse({ type: "array", items: alertSchema }) } },
        },
        "500": errorResponse,
      },
      security: [{ cookieAuth: [] }],
    },
  };

  paths["/api/alerts"] = {
    get: {
      summary: "List all alerts (legacy flat array response)",
      operationId: "listAlertsLegacy",
      tags: ["Alerts"],
      responses: {
        "200": {
          description: "Array of alerts",
          content: { "application/json": { schema: { type: "array", items: alertSchema } } },
        },
        "500": errorResponse,
      },
      security: [{ cookieAuth: [] }],
    },
    post: {
      summary: "Create a new alert",
      operationId: "createAlert",
      tags: ["Alerts"],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              required: ["source", "severity", "title"],
              properties: {
                source: { type: "string" },
                severity: { type: "string" },
                title: { type: "string" },
                description: { type: "string" },
                category: { type: "string" },
              },
            },
          },
        },
      },
      responses: {
        "201": { description: "Created alert", content: { "application/json": { schema: alertSchema } } },
        "400": errorResponse,
        "500": errorResponse,
      },
      security: [{ cookieAuth: [] }],
    },
  };

  paths["/api/alerts/{id}"] = {
    get: {
      summary: "Get alert by ID",
      operationId: "getAlert",
      tags: ["Alerts"],
      parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
      responses: {
        "200": { description: "Alert details", content: { "application/json": { schema: alertSchema } } },
        "404": errorResponse,
      },
      security: [{ cookieAuth: [] }],
    },
    patch: {
      summary: "Update alert",
      operationId: "updateAlert",
      tags: ["Alerts"],
      parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
      requestBody: {
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                status: { type: "string" },
                assignedTo: { type: "string" },
                analystNotes: { type: "string" },
              },
            },
          },
        },
      },
      responses: {
        "200": { description: "Updated alert", content: { "application/json": { schema: alertSchema } } },
        "404": errorResponse,
      },
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
      responses: {
        "200": {
          description: "Paginated incident list",
          content: { "application/json": { schema: envelopeResponse({ type: "array", items: incidentSchema }) } },
        },
        "500": errorResponse,
      },
      security: [{ cookieAuth: [] }],
    },
  };

  paths["/api/incidents"] = {
    get: {
      summary: "List all incidents (legacy flat array response)",
      operationId: "listIncidentsLegacy",
      tags: ["Incidents"],
      responses: {
        "200": {
          description: "Array of incidents",
          content: { "application/json": { schema: { type: "array", items: incidentSchema } } },
        },
        "500": errorResponse,
      },
      security: [{ cookieAuth: [] }],
    },
    post: {
      summary: "Create a new incident",
      operationId: "createIncident",
      tags: ["Incidents"],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              required: ["title", "severity"],
              properties: { title: { type: "string" }, severity: { type: "string" }, summary: { type: "string" } },
            },
          },
        },
      },
      responses: {
        "201": { description: "Created incident", content: { "application/json": { schema: incidentSchema } } },
        "400": errorResponse,
      },
      security: [{ cookieAuth: [] }],
    },
  };

  paths["/api/incidents/{id}"] = {
    get: {
      summary: "Get incident by ID",
      operationId: "getIncident",
      tags: ["Incidents"],
      parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
      responses: {
        "200": { description: "Incident details", content: { "application/json": { schema: incidentSchema } } },
        "404": errorResponse,
      },
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
      responses: {
        "200": {
          description: "Paginated connector list",
          content: { "application/json": { schema: envelopeResponse({ type: "array", items: connectorSchema }) } },
        },
        "500": errorResponse,
      },
      security: [{ cookieAuth: [] }],
    },
  };

  paths["/api/connectors"] = {
    get: {
      summary: "List all connectors (legacy flat array response)",
      operationId: "listConnectorsLegacy",
      tags: ["Connectors"],
      responses: {
        "200": {
          description: "Array of connectors",
          content: { "application/json": { schema: { type: "array", items: connectorSchema } } },
        },
        "500": errorResponse,
      },
      security: [{ cookieAuth: [] }],
    },
  };

  paths["/api/connectors/{id}/test"] = {
    post: {
      summary: "Test connector connectivity",
      operationId: "testConnector",
      tags: ["Connectors"],
      parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
      responses: {
        "200": {
          description: "Test result",
          content: {
            "application/json": {
              schema: { type: "object", properties: { success: { type: "boolean" }, message: { type: "string" } } },
            },
          },
        },
        "404": errorResponse,
      },
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
      responses: {
        "200": {
          description: "Array of playbooks",
          content: { "application/json": { schema: { type: "array", items: playbookSchema } } },
        },
      },
      security: [{ cookieAuth: [] }],
    },
  };

  paths["/api/playbooks/{id}/execute"] = {
    post: {
      summary: "Execute a playbook",
      operationId: "executePlaybook",
      tags: ["Automation"],
      parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
      requestBody: {
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: { incidentId: { type: "string" }, alertId: { type: "string" }, dryRun: { type: "boolean" } },
            },
          },
        },
      },
      responses: { "200": { description: "Execution result" }, "404": errorResponse },
      security: [{ cookieAuth: [] }],
    },
  };

  paths["/api/ingest/alerts"] = {
    post: {
      summary: "Ingest alerts from external sources",
      operationId: "ingestAlerts",
      tags: ["Ingestion"],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: { source: { type: "string" }, alerts: { type: "array", items: { type: "object" } } },
              required: ["source", "alerts"],
            },
          },
        },
      },
      responses: { "200": { description: "Ingestion result" }, "400": errorResponse },
      security: [{ apiKeyAuth: [] }],
    },
  };

  paths["/api/v1/slo/targets"] = {
    get: {
      summary: "List SLO targets",
      operationId: "listSloTargets",
      tags: ["SLO & Monitoring"],
      responses: {
        "200": {
          description: "SLO targets",
          content: { "application/json": { schema: envelopeResponse({ type: "array", items: sloTargetSchema }) } },
        },
      },
      security: [{ cookieAuth: [] }],
    },
    post: {
      summary: "Create or update an SLO target",
      operationId: "upsertSloTarget",
      tags: ["SLO & Monitoring"],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              required: ["service", "metric", "target"],
              properties: {
                service: { type: "string" },
                metric: { type: "string" },
                target: { type: "number" },
                operator: { type: "string" },
                windowMinutes: { type: "integer" },
                alertOnBreach: { type: "boolean" },
                description: { type: "string" },
              },
            },
          },
        },
      },
      responses: { "200": { description: "Upserted SLO target" } },
      security: [{ cookieAuth: [] }],
    },
  };

  paths["/api/v1/slo/evaluate"] = {
    get: {
      summary: "Evaluate all SLO targets against current metrics",
      operationId: "evaluateSlos",
      tags: ["SLO & Monitoring"],
      responses: {
        "200": {
          description: "SLO evaluation results",
          content: {
            "application/json": {
              schema: envelopeResponse({
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    sloId: { type: "string" },
                    service: { type: "string" },
                    metric: { type: "string" },
                    target: { type: "number" },
                    actual: { type: "number" },
                    breached: { type: "boolean" },
                  },
                },
              }),
            },
          },
        },
      },
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
        {
          name: "hours",
          in: "query",
          schema: { type: "integer", default: 24 },
          description: "Lookback window in hours",
        },
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
      responses: {
        "200": {
          description: "Feature flags",
          content: { "application/json": { schema: envelopeResponse({ type: "array", items: featureFlagSchema }) } },
        },
      },
      security: [{ cookieAuth: [] }],
    },
    post: {
      summary: "Create a feature flag",
      operationId: "createFeatureFlag",
      tags: ["Feature Flags"],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              required: ["key", "name"],
              properties: {
                key: { type: "string" },
                name: { type: "string" },
                description: { type: "string" },
                enabled: { type: "boolean" },
                rolloutPct: { type: "integer" },
                targetOrgs: { type: "array", items: { type: "string" } },
                targetRoles: { type: "array", items: { type: "string" } },
              },
            },
          },
        },
      },
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
      requestBody: {
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                enabled: { type: "boolean" },
                rolloutPct: { type: "integer" },
                targetOrgs: { type: "array", items: { type: "string" } },
                targetRoles: { type: "array", items: { type: "string" } },
              },
            },
          },
        },
      },
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
      responses: {
        "200": {
          description: "Evaluation result",
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: { key: { type: "string" }, enabled: { type: "boolean" }, reason: { type: "string" } },
              },
            },
          },
        },
      },
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
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              required: ["runbookId"],
              properties: { runbookId: { type: "string" }, dryRun: { type: "boolean" } },
            },
          },
        },
      },
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

  addAlertEndpoints(paths);
  addIncidentEndpoints(paths);
  addConnectorEndpoints(paths);
  addPlaybookEndpoints(paths);
  addComplianceEndpoints(paths);
  addThreatIntelEndpoints(paths);
  addEntityEndpoints(paths);
  addIngestionEndpoints(paths);
  addIntegrationEndpoints(paths);
  addEndpointMgmtEndpoints(paths);
  addOrgEndpoints(paths);
  addDashboardEndpoints(paths);
  addAiEndpoints(paths);
  addReportEndpoints(paths);
  addOperationsEndpoints(paths);
  addCommercialEndpoints(paths);
  addLifecycleEndpoints(paths);
  addWebhookEndpoints(paths);
  addPredictiveEndpoints(paths);
  addResponseEndpoints(paths);
  addScalingEndpoints(paths);
  addTenantIsolationEndpoints(paths);
  addApiVersioningEndpoints(paths);
  addPaginationContractEndpoints(paths);

  return paths;
}

const idParam: ParameterObject = {
  name: "id",
  in: "path",
  required: true,
  schema: { type: "string" },
  description: "Resource ID",
};
const orgIdParam: ParameterObject = {
  name: "orgId",
  in: "path",
  required: true,
  schema: { type: "string" },
  description: "Organization ID",
};
const authedSecurity = [{ cookieAuth: [] }];
const stdResponses = {
  "401": { description: "Unauthenticated" },
  "403": { description: "Forbidden" },
  "500": errorResponse,
};
const stdGetResponses = { "200": { description: "Success" }, ...stdResponses };
const stdCreateResponses = { "201": { description: "Created" }, "400": errorResponse, ...stdResponses };
const stdMutateResponses = { "200": { description: "Updated" }, "404": errorResponse, ...stdResponses };
const stdDeleteResponses = { "200": { description: "Deleted" }, "404": errorResponse, ...stdResponses };

function op(summary: string, operationId: string, tags: string[], extra?: Partial<OperationObject>): OperationObject {
  return { summary, operationId, tags, responses: stdGetResponses, security: authedSecurity, ...extra };
}

function addAlertEndpoints(paths: Record<string, PathItemObject>): void {
  paths["/api/alerts/{id}/status"] = {
    patch: op("Update alert status", "updateAlertStatus", ["Alerts"], {
      parameters: [idParam],
      responses: stdMutateResponses,
    }),
  };
  paths["/api/alerts/{id}/confidence"] = {
    patch: op("Update alert confidence score", "updateAlertConfidence", ["Alerts"], {
      parameters: [idParam],
      responses: stdMutateResponses,
    }),
  };
  paths["/api/alerts/{id}/suppress"] = {
    post: op("Suppress alert", "suppressAlert", ["Alerts"], { parameters: [idParam], responses: stdMutateResponses }),
  };
  paths["/api/alerts/{id}/unsuppress"] = {
    post: op("Unsuppress alert", "unsuppressAlert", ["Alerts"], {
      parameters: [idParam],
      responses: stdMutateResponses,
    }),
  };
  paths["/api/alerts/{id}/tags"] = {
    post: op("Add tags to alert", "addAlertTags", ["Alerts"], { parameters: [idParam], responses: stdCreateResponses }),
  };
  paths["/api/alerts/bulk-update"] = {
    post: op("Bulk update alerts", "bulkUpdateAlerts", ["Alerts"], { responses: stdMutateResponses }),
  };
  paths["/api/alerts/archive"] = {
    get: op("List archived alerts", "listArchivedAlerts", ["Alerts"], { parameters: [...paginationParams] }),
    post: op("Archive alerts", "archiveAlerts", ["Alerts"], { responses: stdCreateResponses }),
  };
  paths["/api/alerts/archive/restore"] = {
    post: op("Restore archived alerts", "restoreArchivedAlerts", ["Alerts"], { responses: stdMutateResponses }),
  };
  paths["/api/suppression-rules"] = {
    get: op("List suppression rules", "listSuppressionRules", ["Alerts"]),
    post: op("Create suppression rule", "createSuppressionRule", ["Alerts"], { responses: stdCreateResponses }),
  };
  paths["/api/suppression-rules/{id}"] = {
    get: op("Get suppression rule", "getSuppressionRule", ["Alerts"], { parameters: [idParam] }),
    patch: op("Update suppression rule", "updateSuppressionRule", ["Alerts"], {
      parameters: [idParam],
      responses: stdMutateResponses,
    }),
    delete: op("Delete suppression rule", "deleteSuppressionRule", ["Alerts"], {
      parameters: [idParam],
      responses: stdDeleteResponses,
    }),
  };
  paths["/api/tags"] = {
    get: op("List tags", "listTags", ["Alerts"]),
    post: op("Create tag", "createTag", ["Alerts"], { responses: stdCreateResponses }),
  };
  paths["/api/dedup-clusters/scan"] = {
    post: op("Scan for duplicate alert clusters", "scanDedupClusters", ["Alerts"]),
  };
  paths["/api/correlation/scan"] = { post: op("Run correlation scan", "runCorrelationScan", ["Alerts"]) };
  paths["/api/correlation/graph-scan"] = {
    post: op("Run graph-based correlation scan", "runGraphCorrelationScan", ["Alerts"]),
  };
  paths["/api/correlation/clusters/{id}/promote"] = {
    post: op("Promote correlation cluster to incident", "promoteCorrelationCluster", ["Alerts"], {
      parameters: [idParam],
    }),
  };
}

function addIncidentEndpoints(paths: Record<string, PathItemObject>): void {
  paths["/api/incidents/{id}/acknowledge"] = {
    post: op("Acknowledge incident", "acknowledgeIncident", ["Incidents"], { parameters: [idParam] }),
  };
  paths["/api/incidents/{id}/comments"] = {
    post: op("Add incident comment", "addIncidentComment", ["Incidents"], {
      parameters: [idParam],
      responses: stdCreateResponses,
    }),
  };
  paths["/api/incidents/{id}/notify"] = {
    post: op("Send incident notification", "notifyIncident", ["Incidents"], { parameters: [idParam] }),
  };
  paths["/api/incidents/{id}/push"] = {
    post: op("Push incident to external system", "pushIncident", ["Incidents"], { parameters: [idParam] }),
  };
  paths["/api/incidents/{id}/apply-sla"] = {
    post: op("Apply SLA policy to incident", "applyIncidentSla", ["Incidents"], { parameters: [idParam] }),
  };
  paths["/api/incidents/{incidentId}/tasks"] = {
    get: op("List incident tasks", "listIncidentTasks", ["Incidents"], {
      parameters: [{ name: "incidentId", in: "path", required: true, schema: { type: "string" } }],
    }),
    post: op("Create incident task", "createIncidentTask", ["Incidents"], {
      parameters: [{ name: "incidentId", in: "path", required: true, schema: { type: "string" } }],
      responses: stdCreateResponses,
    }),
  };
  paths["/api/incidents/{incidentId}/tasks/{taskId}"] = {
    patch: op("Update incident task", "updateIncidentTask", ["Incidents"], {
      parameters: [
        { name: "incidentId", in: "path", required: true, schema: { type: "string" } },
        { name: "taskId", in: "path", required: true, schema: { type: "string" } },
      ],
      responses: stdMutateResponses,
    }),
  };
  paths["/api/incidents/{incidentId}/hypotheses"] = {
    get: op("List incident hypotheses", "listIncidentHypotheses", ["Incidents"], {
      parameters: [{ name: "incidentId", in: "path", required: true, schema: { type: "string" } }],
    }),
    post: op("Create incident hypothesis", "createIncidentHypothesis", ["Incidents"], {
      parameters: [{ name: "incidentId", in: "path", required: true, schema: { type: "string" } }],
      responses: stdCreateResponses,
    }),
  };
  paths["/api/incidents/{incidentId}/hypotheses/{hypothesisId}"] = {
    patch: op("Update hypothesis", "updateIncidentHypothesis", ["Incidents"], {
      parameters: [
        { name: "incidentId", in: "path", required: true, schema: { type: "string" } },
        { name: "hypothesisId", in: "path", required: true, schema: { type: "string" } },
      ],
      responses: stdMutateResponses,
    }),
  };
  paths["/api/incidents/{incidentId}/evidence"] = {
    post: op("Add evidence to incident", "addIncidentEvidence", ["Incidents"], {
      parameters: [{ name: "incidentId", in: "path", required: true, schema: { type: "string" } }],
      responses: stdCreateResponses,
    }),
  };
  paths["/api/incidents/{incidentId}/pir"] = {
    post: op("Create post-incident review", "createPIR", ["Incidents"], {
      parameters: [{ name: "incidentId", in: "path", required: true, schema: { type: "string" } }],
      responses: stdCreateResponses,
    }),
  };
  paths["/api/sla-policies"] = {
    get: op("List SLA policies", "listSlaPolicies", ["Incidents"]),
    post: op("Create SLA policy", "createSlaPolicy", ["Incidents"], { responses: stdCreateResponses }),
  };
  paths["/api/sla-policies/{id}"] = {
    get: op("Get SLA policy", "getSlaPolicy", ["Incidents"], { parameters: [idParam] }),
    patch: op("Update SLA policy", "updateSlaPolicy", ["Incidents"], {
      parameters: [idParam],
      responses: stdMutateResponses,
    }),
    delete: op("Delete SLA policy", "deleteSlaPolicy", ["Incidents"], {
      parameters: [idParam],
      responses: stdDeleteResponses,
    }),
  };
  paths["/api/pir/{id}"] = {
    get: op("Get post-incident review", "getPIR", ["Incidents"], { parameters: [idParam] }),
    patch: op("Update post-incident review", "updatePIR", ["Incidents"], {
      parameters: [idParam],
      responses: stdMutateResponses,
    }),
  };
  paths["/api/pir/{reviewId}/action-items"] = {
    get: op("List PIR action items", "listPIRActionItems", ["Incidents"], {
      parameters: [{ name: "reviewId", in: "path", required: true, schema: { type: "string" } }],
    }),
  };
  paths["/api/pir-action-items/{id}"] = {
    patch: op("Update PIR action item", "updatePIRActionItem", ["Incidents"], {
      parameters: [idParam],
      responses: stdMutateResponses,
    }),
  };
}

function addConnectorEndpoints(paths: Record<string, PathItemObject>): void {
  paths["/api/connectors"] = {
    ...paths["/api/connectors"],
    post: op("Create connector", "createConnector", ["Connectors"], { responses: stdCreateResponses }),
  };
  paths["/api/connectors/{id}"] = {
    get: op("Get connector by ID", "getConnector", ["Connectors"], { parameters: [idParam] }),
    patch: op("Update connector", "updateConnector", ["Connectors"], {
      parameters: [idParam],
      responses: stdMutateResponses,
    }),
    delete: op("Delete connector", "deleteConnector", ["Connectors"], {
      parameters: [idParam],
      responses: stdDeleteResponses,
    }),
  };
  paths["/api/connectors/{id}/health-check"] = {
    post: op("Run connector health check", "connectorHealthCheck", ["Connectors"], { parameters: [idParam] }),
  };
  paths["/api/connectors/{id}/jobs/{jobId}/replay"] = {
    post: op("Replay connector job", "replayConnectorJob", ["Connectors"], {
      parameters: [idParam, { name: "jobId", in: "path", required: true, schema: { type: "string" } }],
    }),
  };
  paths["/api/connectors/{id}/secret-rotations"] = {
    post: op("Create secret rotation for connector", "createConnectorSecretRotation", ["Connectors"], {
      parameters: [idParam],
      responses: stdCreateResponses,
    }),
  };
  paths["/api/connectors/{id}/secret-rotations/{rotationId}/rotate"] = {
    post: op("Execute secret rotation", "executeConnectorSecretRotation", ["Connectors"], {
      parameters: [idParam, { name: "rotationId", in: "path", required: true, schema: { type: "string" } }],
    }),
  };
  paths["/api/connectors/test"] = {
    post: op("Test connector config before creation", "testConnectorConfig", ["Connectors"]),
  };
  paths["/api/v1/connectors/sync-stats"] = {
    get: op("Get connector sync statistics", "getConnectorSyncStats", ["Connectors"]),
  };
  paths["/api/v1/connectors/concurrency"] = {
    put: op("Update connector concurrency settings", "updateConnectorConcurrency", ["Connectors"], {
      responses: stdMutateResponses,
    }),
  };
  paths["/api/secret-rotations/expiring"] = {
    get: op("List expiring secret rotations", "listExpiringSecretRotations", ["Connectors"]),
  };
}

function addPlaybookEndpoints(paths: Record<string, PathItemObject>): void {
  paths["/api/playbooks/{id}"] = {
    get: op("Get playbook by ID", "getPlaybook", ["Automation"], { parameters: [idParam] }),
    patch: op("Update playbook", "updatePlaybook", ["Automation"], {
      parameters: [idParam],
      responses: stdMutateResponses,
    }),
    delete: op("Delete playbook", "deletePlaybook", ["Automation"], {
      parameters: [idParam],
      responses: stdDeleteResponses,
    }),
  };
  paths["/api/playbooks"] = {
    ...paths["/api/playbooks"],
    post: op("Create playbook", "createPlaybook", ["Automation"], { responses: stdCreateResponses }),
  };
  paths["/api/playbook-executions/{id}/resume"] = {
    post: op("Resume paused playbook execution", "resumePlaybookExecution", ["Automation"], { parameters: [idParam] }),
  };
  paths["/api/playbook-executions/{id}/rollback"] = {
    post: op("Rollback playbook execution", "rollbackPlaybookExecution", ["Automation"], { parameters: [idParam] }),
  };
  paths["/api/playbook-approvals"] = { get: op("List playbook approvals", "listPlaybookApprovals", ["Automation"]) };
  paths["/api/playbook-simulations/{id}"] = {
    get: op("Get playbook simulation result", "getPlaybookSimulation", ["Automation"], { parameters: [idParam] }),
  };
  paths["/api/playbooks/{playbookId}/simulations"] = {
    get: op("List simulations for playbook", "listPlaybookSimulations", ["Automation"], {
      parameters: [{ name: "playbookId", in: "path", required: true, schema: { type: "string" } }],
    }),
  };
  paths["/api/playbook-versions/{id}"] = {
    get: op("Get playbook version", "getPlaybookVersion", ["Automation"], { parameters: [idParam] }),
    patch: op("Update playbook version", "updatePlaybookVersion", ["Automation"], {
      parameters: [idParam],
      responses: stdMutateResponses,
    }),
  };
  paths["/api/playbooks/{playbookId}/versions"] = {
    get: op("List playbook versions", "listPlaybookVersions", ["Automation"], {
      parameters: [{ name: "playbookId", in: "path", required: true, schema: { type: "string" } }],
    }),
  };
  paths["/api/runbook-templates"] = {
    get: op("List runbook templates", "listRunbookTemplates", ["Automation"]),
    post: op("Create runbook template", "createRunbookTemplate", ["Automation"], { responses: stdCreateResponses }),
  };
  paths["/api/runbook-templates/{id}"] = {
    get: op("Get runbook template", "getRunbookTemplate", ["Automation"], { parameters: [idParam] }),
  };
  paths["/api/runbook-templates/{id}/steps"] = {
    get: op("List runbook steps", "listRunbookSteps", ["Automation"], { parameters: [idParam] }),
    post: op("Add step to runbook", "addRunbookStep", ["Automation"], {
      parameters: [idParam],
      responses: stdCreateResponses,
    }),
  };
  paths["/api/runbook-templates/{id}/steps/{stepId}"] = {
    patch: op("Update runbook step", "updateRunbookStep", ["Automation"], {
      parameters: [idParam, { name: "stepId", in: "path", required: true, schema: { type: "string" } }],
      responses: stdMutateResponses,
    }),
  };
  paths["/api/runbook-templates/seed"] = {
    post: op("Seed default runbook templates", "seedRunbookTemplates", ["Automation"]),
  };
  paths["/api/autonomous/policies"] = {
    get: op("List autonomous response policies", "listAutonomousPolicies", ["Automation"]),
    post: op("Create autonomous policy", "createAutonomousPolicy", ["Automation"], { responses: stdCreateResponses }),
  };
  paths["/api/autonomous/policies/{id}"] = {
    patch: op("Update autonomous policy", "updateAutonomousPolicy", ["Automation"], {
      parameters: [idParam],
      responses: stdMutateResponses,
    }),
  };
  paths["/api/autonomous/policies/seed-defaults"] = {
    post: op("Seed default autonomous policies", "seedAutonomousPolicies", ["Automation"]),
  };
  paths["/api/autonomous/evaluate/{incidentId}"] = {
    post: op("Evaluate autonomous actions for incident", "evaluateAutonomousActions", ["Automation"], {
      parameters: [{ name: "incidentId", in: "path", required: true, schema: { type: "string" } }],
    }),
  };
  paths["/api/autonomous/investigations"] = {
    post: op("Start autonomous investigation", "startAutonomousInvestigation", ["Automation"], {
      responses: stdCreateResponses,
    }),
  };
  paths["/api/autonomous/rollbacks"] = {
    post: op("Create rollback record", "createRollback", ["Automation"], { responses: stdCreateResponses }),
  };
  paths["/api/autonomous/rollbacks/{id}/execute"] = {
    post: op("Execute rollback", "executeRollback", ["Automation"], { parameters: [idParam] }),
  };
}

function addComplianceEndpoints(paths: Record<string, PathItemObject>): void {
  paths["/api/compliance-controls"] = {
    get: op("List compliance controls", "listComplianceControls", ["Compliance"]),
    post: op("Create compliance control", "createComplianceControl", ["Compliance"], { responses: stdCreateResponses }),
  };
  paths["/api/compliance-controls/{id}"] = {
    patch: op("Update compliance control", "updateComplianceControl", ["Compliance"], {
      parameters: [idParam],
      responses: stdMutateResponses,
    }),
  };
  paths["/api/compliance-controls/seed"] = {
    post: op("Seed default compliance controls", "seedComplianceControls", ["Compliance"]),
  };
  paths["/api/compliance-control-mappings"] = {
    get: op("List compliance control mappings", "listComplianceControlMappings", ["Compliance"]),
    post: op("Create compliance control mapping", "createComplianceControlMapping", ["Compliance"], {
      responses: stdCreateResponses,
    }),
  };
  paths["/api/compliance-control-mappings/{id}"] = {
    patch: op("Update compliance control mapping", "updateComplianceControlMapping", ["Compliance"], {
      parameters: [idParam],
      responses: stdMutateResponses,
    }),
  };
  paths["/api/v1/audit-logs"] = {
    get: op("List audit logs with pagination", "listAuditLogs", ["Compliance"], {
      parameters: [
        ...paginationParams,
        { name: "action", in: "query", schema: { type: "string" }, description: "Filter by action type" },
        { name: "userId", in: "query", schema: { type: "string" }, description: "Filter by user" },
        { name: "resourceType", in: "query", schema: { type: "string" }, description: "Filter by resource type" },
      ],
    }),
  };
  paths["/api/audit-logs"] = { get: op("List audit logs (legacy)", "listAuditLogsLegacy", ["Compliance"]) };
  paths["/api/compliance/policy"] = {
    put: op("Update compliance policy", "updateCompliancePolicy", ["Compliance"], { responses: stdMutateResponses }),
  };
  paths["/api/compliance/dsar"] = {
    get: op("List data subject access requests", "listDSARs", ["Compliance"]),
    post: op("Create DSAR", "createDSAR", ["Compliance"], { responses: stdCreateResponses }),
  };
  paths["/api/compliance/dsar/{id}"] = {
    patch: op("Update DSAR", "updateDSAR", ["Compliance"], { parameters: [idParam], responses: stdMutateResponses }),
  };
  paths["/api/compliance/dsar/{id}/fulfill"] = {
    post: op("Fulfill DSAR request", "fulfillDSAR", ["Compliance"], { parameters: [idParam] }),
  };
  paths["/api/compliance/retention/run"] = {
    post: op("Run data retention policy", "runRetentionPolicy", ["Compliance"]),
  };
  paths["/api/legal-holds"] = {
    get: op("List legal holds", "listLegalHolds", ["Compliance"]),
    post: op("Create legal hold", "createLegalHold", ["Compliance"], { responses: stdCreateResponses }),
  };
  paths["/api/legal-holds/{id}"] = {
    patch: op("Update legal hold", "updateLegalHold", ["Compliance"], {
      parameters: [idParam],
      responses: stdMutateResponses,
    }),
  };
  paths["/api/legal-holds/{id}/deactivate"] = {
    post: op("Deactivate legal hold", "deactivateLegalHold", ["Compliance"], { parameters: [idParam] }),
  };
  paths["/api/evidence-locker"] = {
    get: op("List evidence locker items", "listEvidenceLocker", ["Compliance"]),
    post: op("Add to evidence locker", "createEvidenceLockerItem", ["Compliance"], { responses: stdCreateResponses }),
  };
  paths["/api/evidence-locker/{id}"] = {
    get: op("Get evidence locker item", "getEvidenceLockerItem", ["Compliance"], { parameters: [idParam] }),
    patch: op("Update evidence locker item", "updateEvidenceLockerItem", ["Compliance"], {
      parameters: [idParam],
      responses: stdMutateResponses,
    }),
    delete: op("Delete evidence locker item", "deleteEvidenceLockerItem", ["Compliance"], {
      parameters: [idParam],
      responses: stdDeleteResponses,
    }),
  };
  paths["/api/policy-checks"] = {
    get: op("List policy checks", "listPolicyChecks", ["Compliance"]),
    post: op("Create policy check", "createPolicyCheck", ["Compliance"], { responses: stdCreateResponses }),
  };
  paths["/api/policy-checks/{id}"] = {
    patch: op("Update policy check", "updatePolicyCheck", ["Compliance"], {
      parameters: [idParam],
      responses: stdMutateResponses,
    }),
  };
  paths["/api/policy-checks/{id}/run"] = {
    post: op("Execute policy check", "runPolicyCheck", ["Compliance"], { parameters: [idParam] }),
  };
  paths["/api/policy-results"] = { get: op("List policy check results", "listPolicyResults", ["Compliance"]) };
  paths["/api/compliance-helpers"] = {
    get: op("List compliance helpers", "listComplianceHelpers", ["Compliance"]),
    post: op("Create compliance helper", "createComplianceHelper", ["Compliance"], { responses: stdCreateResponses }),
  };
  paths["/api/compliance-helpers/run-gap-analysis"] = {
    post: op("Run gap analysis", "runGapAnalysis", ["Compliance"]),
  };
  paths["/api/compliance-helpers/run-cross-map"] = {
    post: op("Run cross-framework mapping", "runCrossMap", ["Compliance"]),
  };
  paths["/api/v1/compliance-helpers"] = {
    get: op("List compliance helpers (v1)", "listComplianceHelpersV1", ["Compliance"]),
  };
  paths["/api/evidence-attachments"] = {
    get: op("List evidence attachments", "listEvidenceAttachments", ["Compliance"]),
    post: op("Create evidence attachment", "createEvidenceAttachment", ["Compliance"], {
      responses: stdCreateResponses,
    }),
  };
  paths["/api/evidence-attachments/{id}"] = {
    get: op("Get evidence attachment", "getEvidenceAttachment", ["Compliance"], { parameters: [idParam] }),
    patch: op("Update evidence attachment", "updateEvidenceAttachment", ["Compliance"], {
      parameters: [idParam],
      responses: stdMutateResponses,
    }),
    delete: op("Delete evidence attachment", "deleteEvidenceAttachment", ["Compliance"], {
      parameters: [idParam],
      responses: stdDeleteResponses,
    }),
  };
  paths["/api/evidence-attachments/{id}/presign"] = {
    post: op("Get presigned S3 URL for evidence", "presignEvidenceAttachment", ["Compliance"], {
      parameters: [idParam],
    }),
  };
  paths["/api/v1/evidence-attachments"] = {
    get: op("List evidence attachments (v1)", "listEvidenceAttachmentsV1", ["Compliance"]),
  };
  paths["/api/cspm/accounts"] = {
    get: op("List CSPM cloud accounts", "listCSPMAccounts", ["Compliance"]),
    post: op("Register CSPM cloud account", "createCSPMAccount", ["Compliance"], { responses: stdCreateResponses }),
  };
  paths["/api/cspm/accounts/{id}"] = {
    patch: op("Update CSPM account", "updateCSPMAccount", ["Compliance"], {
      parameters: [idParam],
      responses: stdMutateResponses,
    }),
  };
  paths["/api/cspm/findings"] = { get: op("List CSPM findings", "listCSPMFindings", ["Compliance"]) };
  paths["/api/cspm/findings/{id}"] = {
    patch: op("Update CSPM finding", "updateCSPMFinding", ["Compliance"], {
      parameters: [idParam],
      responses: stdMutateResponses,
    }),
  };
  paths["/api/cspm/scans/{accountId}"] = {
    post: op("Trigger CSPM scan for account", "triggerCSPMScan", ["Compliance"], {
      parameters: [{ name: "accountId", in: "path", required: true, schema: { type: "string" } }],
    }),
  };
  paths["/api/posture/scores"] = { get: op("Get posture scores", "getPostureScores", ["Compliance"]) };
  paths["/api/posture/latest"] = { get: op("Get latest posture score", "getLatestPostureScore", ["Compliance"]) };
  paths["/api/posture/calculate"] = { post: op("Calculate posture score", "calculatePostureScore", ["Compliance"]) };
}

function addThreatIntelEndpoints(paths: Record<string, PathItemObject>): void {
  paths["/api/ioc-feeds"] = {
    get: op("List IOC feeds", "listIOCFeeds", ["Threat Intelligence"]),
    post: op("Create IOC feed", "createIOCFeed", ["Threat Intelligence"], { responses: stdCreateResponses }),
  };
  paths["/api/ioc-feeds/{id}"] = {
    patch: op("Update IOC feed", "updateIOCFeed", ["Threat Intelligence"], {
      parameters: [idParam],
      responses: stdMutateResponses,
    }),
  };
  paths["/api/ioc-feeds/{id}/ingest"] = {
    post: op("Ingest IOC feed data", "ingestIOCFeed", ["Threat Intelligence"], { parameters: [idParam] }),
  };
  paths["/api/ioc-entries"] = {
    get: op("List IOC entries", "listIOCEntries", ["Threat Intelligence"]),
    post: op("Create IOC entry", "createIOCEntry", ["Threat Intelligence"], { responses: stdCreateResponses }),
  };
  paths["/api/ioc-entries/{id}"] = {
    patch: op("Update IOC entry", "updateIOCEntry", ["Threat Intelligence"], {
      parameters: [idParam],
      responses: stdMutateResponses,
    }),
  };
  paths["/api/ioc-watchlists"] = {
    get: op("List IOC watchlists", "listIOCWatchlists", ["Threat Intelligence"]),
    post: op("Create IOC watchlist", "createIOCWatchlist", ["Threat Intelligence"], { responses: stdCreateResponses }),
  };
  paths["/api/ioc-watchlists/{id}"] = {
    patch: op("Update IOC watchlist", "updateIOCWatchlist", ["Threat Intelligence"], {
      parameters: [idParam],
      responses: stdMutateResponses,
    }),
  };
  paths["/api/ioc-watchlists/{id}/entries"] = {
    post: op("Add entries to IOC watchlist", "addIOCWatchlistEntries", ["Threat Intelligence"], {
      parameters: [idParam],
      responses: stdCreateResponses,
    }),
  };
  paths["/api/ioc-match-rules"] = {
    get: op("List IOC match rules", "listIOCMatchRules", ["Threat Intelligence"]),
    post: op("Create IOC match rule", "createIOCMatchRule", ["Threat Intelligence"], { responses: stdCreateResponses }),
  };
  paths["/api/ioc-match-rules/{id}"] = {
    patch: op("Update IOC match rule", "updateIOCMatchRule", ["Threat Intelligence"], {
      parameters: [idParam],
      responses: stdMutateResponses,
    }),
  };
  paths["/api/ioc-match/alert/{alertId}"] = {
    post: op("Match IOCs against alert", "matchIOCsForAlert", ["Threat Intelligence"], {
      parameters: [{ name: "alertId", in: "path", required: true, schema: { type: "string" } }],
    }),
  };
  paths["/api/osint-feeds"] = { get: op("List OSINT feeds", "listOSINTFeeds", ["Threat Intelligence"]) };
  paths["/api/osint-feeds/status"] = {
    get: op("Get OSINT feed status", "getOSINTFeedStatus", ["Threat Intelligence"]),
  };
  paths["/api/osint-feeds/{feedName}"] = {
    get: op("Get OSINT feed data", "getOSINTFeed", ["Threat Intelligence"], {
      parameters: [{ name: "feedName", in: "path", required: true, schema: { type: "string" } }],
    }),
  };
  paths["/api/osint-feeds/{feedName}/refresh"] = {
    post: op("Refresh OSINT feed", "refreshOSINTFeed", ["Threat Intelligence"], {
      parameters: [{ name: "feedName", in: "path", required: true, schema: { type: "string" } }],
    }),
  };
  paths["/api/threat-intel-configs"] = {
    get: op("List threat intel provider configs", "listThreatIntelConfigs", ["Threat Intelligence"]),
    post: op("Create threat intel config", "createThreatIntelConfig", ["Threat Intelligence"], {
      responses: stdCreateResponses,
    }),
  };
  paths["/api/threat-intel-configs/{provider}/test"] = {
    post: op("Test threat intel provider", "testThreatIntelConfig", ["Threat Intelligence"], {
      parameters: [{ name: "provider", in: "path", required: true, schema: { type: "string" } }],
    }),
  };
}

function addEntityEndpoints(paths: Record<string, PathItemObject>): void {
  paths["/api/entities"] = {
    get: op("List entities", "listEntities", ["Entities"], { parameters: [...paginationParams] }),
  };
  paths["/api/entities/{id}"] = { get: op("Get entity by ID", "getEntity", ["Entities"], { parameters: [idParam] }) };
  paths["/api/entities/{id}/metadata"] = {
    patch: op("Update entity metadata", "updateEntityMetadata", ["Entities"], {
      parameters: [idParam],
      responses: stdMutateResponses,
    }),
  };
  paths["/api/entities/{id}/aliases"] = {
    post: op("Add entity alias", "addEntityAlias", ["Entities"], {
      parameters: [idParam],
      responses: stdCreateResponses,
    }),
  };
  paths["/api/entities/{id}/enrich"] = {
    post: op("Enrich entity with external data", "enrichEntity", ["Entities"], { parameters: [idParam] }),
  };
  paths["/api/entities/merge"] = { post: op("Merge duplicate entities", "mergeEntities", ["Entities"]) };
}

function addIngestionEndpoints(paths: Record<string, PathItemObject>): void {
  paths["/api/ingest/{source}"] = {
    post: op("Ingest alert from source", "ingestFromSource", ["Ingestion"], {
      parameters: [{ name: "source", in: "path", required: true, schema: { type: "string" } }],
      security: [{ apiKeyAuth: [] }],
    }),
  };
  paths["/api/ingest/{source}/bulk"] = {
    post: op("Bulk ingest alerts from source", "bulkIngestFromSource", ["Ingestion"], {
      parameters: [{ name: "source", in: "path", required: true, schema: { type: "string" } }],
      security: [{ apiKeyAuth: [] }],
    }),
  };
  paths["/api/v1/ingestion/logs"] = {
    get: op("List ingestion logs (v1)", "listIngestionLogsV1", ["Ingestion"], { parameters: [...paginationParams] }),
  };
  paths["/api/v1/ingestion-logs"] = {
    get: op("List ingestion logs (v1 alt)", "listIngestionLogsV1Alt", ["Ingestion"], {
      parameters: [...paginationParams],
    }),
  };
  paths["/api/ingestion/logs"] = { get: op("List ingestion logs (legacy)", "listIngestionLogsLegacy", ["Ingestion"]) };
  paths["/api/v1/event-catalog"] = { get: op("List event catalog entries", "listEventCatalog", ["Ingestion"]) };
}

function addIntegrationEndpoints(paths: Record<string, PathItemObject>): void {
  paths["/api/integrations"] = {
    get: op("List integrations", "listIntegrations", ["Integrations"]),
    post: op("Create integration", "createIntegration", ["Integrations"], { responses: stdCreateResponses }),
  };
  paths["/api/integrations/{id}"] = {
    get: op("Get integration", "getIntegration", ["Integrations"], { parameters: [idParam] }),
    patch: op("Update integration", "updateIntegration", ["Integrations"], {
      parameters: [idParam],
      responses: stdMutateResponses,
    }),
    delete: op("Delete integration", "deleteIntegration", ["Integrations"], {
      parameters: [idParam],
      responses: stdDeleteResponses,
    }),
  };
  paths["/api/integrations/{id}/test"] = {
    post: op("Test integration", "testIntegration", ["Integrations"], { parameters: [idParam] }),
  };
  paths["/api/notification-channels"] = {
    get: op("List notification channels", "listNotificationChannels", ["Integrations"]),
    post: op("Create notification channel", "createNotificationChannel", ["Integrations"], {
      responses: stdCreateResponses,
    }),
  };
  paths["/api/notification-channels/{id}"] = {
    patch: op("Update notification channel", "updateNotificationChannel", ["Integrations"], {
      parameters: [idParam],
      responses: stdMutateResponses,
    }),
  };
  paths["/api/notification-channels/{id}/test"] = {
    post: op("Test notification channel", "testNotificationChannel", ["Integrations"], { parameters: [idParam] }),
  };
  paths["/api/notification-channels/{id}/severity-threshold"] = {
    patch: op("Update channel severity threshold", "updateChannelSeverityThreshold", ["Integrations"], {
      parameters: [idParam],
      responses: stdMutateResponses,
    }),
  };
  paths["/api/ticket-sync"] = {
    get: op("List ticket sync configs", "listTicketSyncConfigs", ["Integrations"]),
    post: op("Create ticket sync config", "createTicketSyncConfig", ["Integrations"], {
      responses: stdCreateResponses,
    }),
  };
  paths["/api/ticket-sync/{id}"] = {
    get: op("Get ticket sync config", "getTicketSyncConfig", ["Integrations"], { parameters: [idParam] }),
    patch: op("Update ticket sync config", "updateTicketSyncConfig", ["Integrations"], {
      parameters: [idParam],
      responses: stdMutateResponses,
    }),
  };
  paths["/api/ticket-sync/{id}/sync"] = {
    post: op("Trigger ticket sync", "triggerTicketSync", ["Integrations"], { parameters: [idParam] }),
  };
}

function addEndpointMgmtEndpoints(paths: Record<string, PathItemObject>): void {
  paths["/api/endpoints"] = {
    get: op("List endpoints", "listEndpoints", ["Endpoint Management"]),
    post: op("Register endpoint", "createEndpoint", ["Endpoint Management"], { responses: stdCreateResponses }),
  };
  paths["/api/endpoints/{id}"] = {
    get: op("Get endpoint", "getEndpoint", ["Endpoint Management"], { parameters: [idParam] }),
    patch: op("Update endpoint", "updateEndpoint", ["Endpoint Management"], {
      parameters: [idParam],
      responses: stdMutateResponses,
    }),
    delete: op("Delete endpoint", "deleteEndpoint", ["Endpoint Management"], {
      parameters: [idParam],
      responses: stdDeleteResponses,
    }),
  };
  paths["/api/endpoints/{id}/risk"] = {
    post: op("Calculate endpoint risk score", "calculateEndpointRisk", ["Endpoint Management"], {
      parameters: [idParam],
    }),
  };
  paths["/api/endpoints/{id}/telemetry"] = {
    post: op("Submit endpoint telemetry", "submitEndpointTelemetry", ["Endpoint Management"], {
      parameters: [idParam],
    }),
  };
  paths["/api/endpoints/seed"] = { post: op("Seed sample endpoints", "seedEndpoints", ["Endpoint Management"]) };
}

function addOrgEndpoints(paths: Record<string, PathItemObject>): void {
  paths["/api/orgs/{orgId}/members"] = {
    get: op("List org members", "listOrgMembers", ["Organization"], { parameters: [orgIdParam] }),
  };
  paths["/api/orgs/{orgId}/members/{memberId}/role"] = {
    patch: op("Update member role", "updateMemberRole", ["Organization"], {
      parameters: [orgIdParam, { name: "memberId", in: "path", required: true, schema: { type: "string" } }],
      responses: stdMutateResponses,
    }),
  };
  paths["/api/orgs/{orgId}/members/{memberId}/activate"] = {
    post: op("Activate member", "activateMember", ["Organization"], {
      parameters: [orgIdParam, { name: "memberId", in: "path", required: true, schema: { type: "string" } }],
    }),
  };
  paths["/api/orgs/{orgId}/members/{memberId}/suspend"] = {
    post: op("Suspend member", "suspendMember", ["Organization"], {
      parameters: [orgIdParam, { name: "memberId", in: "path", required: true, schema: { type: "string" } }],
    }),
  };
  paths["/api/orgs/{orgId}/invitations"] = {
    get: op("List org invitations", "listOrgInvitations", ["Organization"], { parameters: [orgIdParam] }),
    post: op("Create org invitation", "createOrgInvitation", ["Organization"], {
      parameters: [orgIdParam],
      responses: stdCreateResponses,
    }),
  };
  paths["/api/invitations/accept"] = { post: op("Accept invitation", "acceptInvitation", ["Organization"]) };
  paths["/api/orgs/{orgId}/domains"] = {
    get: op("List org domains", "listOrgDomains", ["Organization"], { parameters: [orgIdParam] }),
    post: op("Add org domain", "addOrgDomain", ["Organization"], {
      parameters: [orgIdParam],
      responses: stdCreateResponses,
    }),
  };
  paths["/api/orgs/{orgId}/sso"] = {
    get: op("Get SSO config", "getSSOConfig", ["Organization"], { parameters: [orgIdParam] }),
    put: op("Update SSO config", "updateSSOConfig", ["Organization"], {
      parameters: [orgIdParam],
      responses: stdMutateResponses,
    }),
  };
  paths["/api/orgs/{orgId}/scim"] = {
    get: op("Get SCIM config", "getSCIMConfig", ["Organization"], { parameters: [orgIdParam] }),
    put: op("Update SCIM config", "updateSCIMConfig", ["Organization"], {
      parameters: [orgIdParam],
      responses: stdMutateResponses,
    }),
  };
  paths["/api/orgs/{orgId}/scim/generate-token"] = {
    post: op("Generate SCIM token", "generateSCIMToken", ["Organization"], { parameters: [orgIdParam] }),
  };
  paths["/api/orgs/{orgId}/security-policy"] = {
    get: op("Get security policy", "getSecurityPolicy", ["Organization"], { parameters: [orgIdParam] }),
    put: op("Update security policy", "updateSecurityPolicy", ["Organization"], {
      parameters: [orgIdParam],
      responses: stdMutateResponses,
    }),
  };
  paths["/api/orgs/{orgId}/saved-views"] = {
    get: op("List saved views", "listSavedViews", ["Organization"], { parameters: [orgIdParam] }),
    post: op("Create saved view", "createSavedView", ["Organization"], {
      parameters: [orgIdParam],
      responses: stdCreateResponses,
    }),
  };
  paths["/api/orgs/{orgId}/saved-views/{viewId}"] = {
    put: op("Update saved view", "updateSavedView", ["Organization"], {
      parameters: [orgIdParam, { name: "viewId", in: "path", required: true, schema: { type: "string" } }],
      responses: stdMutateResponses,
    }),
  };
  paths["/api/auth/ensure-org"] = { post: op("Ensure user has organization", "ensureOrg", ["Organization"]) };
  paths["/api/api-keys"] = {
    post: op("Create API key", "createApiKey", ["Organization"], { responses: stdCreateResponses }),
  };
  paths["/api/v1/api-keys/policies"] = { get: op("List API key policies", "listApiKeyPolicies", ["Organization"]) };
  paths["/api/v1/api-keys/scopes"] = { get: op("List API key scopes", "listApiKeyScopes", ["Organization"]) };
}

function addDashboardEndpoints(paths: Record<string, PathItemObject>): void {
  paths["/api/dashboard/widgets"] = { get: op("List dashboard widgets", "listDashboardWidgets", ["Dashboard"]) };
  paths["/api/dashboard/recent"] = { get: op("Get recently viewed items", "getRecentItems", ["Dashboard"]) };
  paths["/api/ops/alert-daily-stats"] = { get: op("Get daily alert statistics", "getAlertDailyStats", ["Dashboard"]) };
}

function addAiEndpoints(paths: Record<string, PathItemObject>): void {
  paths["/api/ai/triage/{alertId}"] = {
    post: op("AI triage alert", "aiTriageAlert", ["AI Engine"], {
      parameters: [{ name: "alertId", in: "path", required: true, schema: { type: "string" } }],
    }),
  };
  paths["/api/ai/correlate"] = { post: op("AI correlate alerts", "aiCorrelateAlerts", ["AI Engine"]) };
  paths["/api/ai/correlate/apply"] = { post: op("Apply AI correlation results", "aiCorrelateApply", ["AI Engine"]) };
  paths["/api/ai/narrative/{incidentId}"] = {
    post: op("Generate AI incident narrative", "aiGenerateNarrative", ["AI Engine"], {
      parameters: [{ name: "incidentId", in: "path", required: true, schema: { type: "string" } }],
    }),
  };
  paths["/api/ai/feedback"] = { post: op("Submit AI feedback", "submitAiFeedback", ["AI Engine"]) };
  paths["/api/ai/cache/clear"] = { post: op("Clear AI cache", "clearAiCache", ["AI Engine"]) };
  paths["/api/ai/playbook-authoring/propose"] = { post: op("AI propose playbook", "aiProposePlaybook", ["AI Engine"]) };
  paths["/api/ai/budget"] = {
    put: op("Update AI budget", "updateAiBudget", ["AI Engine"], { responses: stdMutateResponses }),
  };
  paths["/api/ai-deployment/config"] = {
    put: op("Update AI deployment config", "updateAiDeploymentConfig", ["AI Engine"], {
      responses: stdMutateResponses,
    }),
  };
}

function addReportEndpoints(paths: Record<string, PathItemObject>): void {
  paths["/api/report-templates"] = {
    get: op("List report templates", "listReportTemplates", ["Reports"]),
    post: op("Create report template", "createReportTemplate", ["Reports"], { responses: stdCreateResponses }),
  };
  paths["/api/report-templates/{id}"] = {
    get: op("Get report template", "getReportTemplate", ["Reports"], { parameters: [idParam] }),
    patch: op("Update report template", "updateReportTemplate", ["Reports"], {
      parameters: [idParam],
      responses: stdMutateResponses,
    }),
  };
  paths["/api/report-templates/{templateId}/versions"] = {
    get: op("List template versions", "listTemplateVersions", ["Reports"], {
      parameters: [{ name: "templateId", in: "path", required: true, schema: { type: "string" } }],
    }),
    post: op("Create template version", "createTemplateVersion", ["Reports"], {
      parameters: [{ name: "templateId", in: "path", required: true, schema: { type: "string" } }],
      responses: stdCreateResponses,
    }),
  };
  paths["/api/report-template-versions/{id}"] = {
    get: op("Get template version", "getTemplateVersion", ["Reports"], { parameters: [idParam] }),
    patch: op("Update template version", "updateTemplateVersion", ["Reports"], {
      parameters: [idParam],
      responses: stdMutateResponses,
    }),
  };
  paths["/api/report-templates/seed"] = {
    post: op("Seed default report templates", "seedReportTemplates", ["Reports"]),
  };
  paths["/api/report-schedules"] = {
    get: op("List report schedules", "listReportSchedules", ["Reports"]),
    post: op("Create report schedule", "createReportSchedule", ["Reports"], { responses: stdCreateResponses }),
  };
  paths["/api/report-schedules/{id}"] = {
    get: op("Get report schedule", "getReportSchedule", ["Reports"], { parameters: [idParam] }),
    patch: op("Update report schedule", "updateReportSchedule", ["Reports"], {
      parameters: [idParam],
      responses: stdMutateResponses,
    }),
    delete: op("Delete report schedule", "deleteReportSchedule", ["Reports"], {
      parameters: [idParam],
      responses: stdDeleteResponses,
    }),
  };
  paths["/api/report-runs"] = { get: op("List report runs", "listReportRuns", ["Reports"]) };
  paths["/api/report-runs/{id}"] = {
    get: op("Get report run", "getReportRun", ["Reports"], { parameters: [idParam] }),
  };
  paths["/api/reports/generate"] = { post: op("Generate report", "generateReport", ["Reports"]) };
  paths["/api/reports/preview/{reportType}"] = {
    get: op("Preview report", "previewReport", ["Reports"], {
      parameters: [{ name: "reportType", in: "path", required: true, schema: { type: "string" } }],
    }),
  };
  paths["/api/reports/{runId}/download"] = {
    get: op("Download report", "downloadReport", ["Reports"], {
      parameters: [{ name: "runId", in: "path", required: true, schema: { type: "string" } }],
    }),
  };
  paths["/api/v1/report-templates/{templateId}/versions"] = {
    get: op("List template versions (v1)", "listTemplateVersionsV1", ["Reports"], {
      parameters: [{ name: "templateId", in: "path", required: true, schema: { type: "string" } }],
    }),
  };
}

function addOperationsEndpoints(paths: Record<string, PathItemObject>): void {
  paths["/api/ops/health"] = { get: op("Get operational health", "getOpsHealth", ["Operations"], { security: [] }) };
  paths["/api/ops/sli"] = { get: op("Get SLI metrics", "getOpsSLI", ["Operations"]) };
  paths["/api/ops/slo"] = { get: op("Get SLO status", "getOpsSLO", ["Operations"]) };
  paths["/api/ops/slo-targets"] = { get: op("Get SLO targets", "getOpsSLOTargets", ["Operations"]) };
  paths["/api/ops/jobs"] = { get: op("List background jobs", "listOpsJobs", ["Operations"]) };
  paths["/api/ops/jobs/stats"] = { get: op("Get job statistics", "getOpsJobStats", ["Operations"]) };
  paths["/api/ops/jobs"] = {
    ...paths["/api/ops/jobs"],
    post: op("Create background job", "createOpsJob", ["Operations"], { responses: stdCreateResponses }),
  };
  paths["/api/ops/jobs/{id}/cancel"] = {
    post: op("Cancel background job", "cancelOpsJob", ["Operations"], { parameters: [idParam] }),
  };
  paths["/api/ops/worker/status"] = { get: op("Get worker status", "getWorkerStatus", ["Operations"]) };
  paths["/api/ops/metrics-cache"] = { get: op("Get metrics cache", "getMetricsCache", ["Operations"]) };
  paths["/api/ops/metrics-cache/refresh"] = {
    post: op("Refresh metrics cache", "refreshMetricsCache", ["Operations"]),
  };
  paths["/api/ops/dr-runbooks"] = {
    get: op("List DR runbooks", "listDRRunbooks", ["Operations"]),
    post: op("Create DR runbook", "createDRRunbook", ["Operations"], { responses: stdCreateResponses }),
  };
  paths["/api/ops/dr-runbooks/{id}"] = {
    get: op("Get DR runbook", "getDRRunbook", ["Operations"], { parameters: [idParam] }),
    patch: op("Update DR runbook", "updateDRRunbook", ["Operations"], {
      parameters: [idParam],
      responses: stdMutateResponses,
    }),
  };
  paths["/api/ops/dr-runbooks/{id}/test"] = {
    post: op("Test DR runbook", "testDRRunbook", ["Operations"], { parameters: [idParam] }),
  };
  paths["/api/ops/dr-runbooks/seed"] = { post: op("Seed default DR runbooks", "seedDRRunbooks", ["Operations"]) };
  paths["/api/ops/slo-targets"] = {
    ...paths["/api/ops/slo-targets"],
    post: op("Create SLO target", "createOpsSLOTarget", ["Operations"], { responses: stdCreateResponses }),
  };
  paths["/api/ops/slo-targets/{id}"] = {
    patch: op("Update SLO target", "updateOpsSLOTarget", ["Operations"], {
      parameters: [idParam],
      responses: stdMutateResponses,
    }),
  };
  paths["/api/ops/slo-targets/seed"] = { post: op("Seed default SLO targets", "seedOpsSLOTargets", ["Operations"]) };
  paths["/api/v1/monitoring/db-performance"] = {
    get: op("Get DB performance metrics", "getDBPerformance", ["Operations"]),
  };
  paths["/api/v1/monitoring/slow-queries"] = { get: op("Get slow queries", "getSlowQueries", ["Operations"]) };
  paths["/api/v1/monitoring/index-stats"] = { get: op("Get index statistics", "getIndexStats", ["Operations"]) };
  paths["/api/v1/jobs/dead-letter"] = { get: op("List dead letter jobs", "listDeadLetterJobs", ["Operations"]) };
  paths["/api/v1/jobs/dead-letter/{id}/retry"] = {
    post: op("Retry dead letter job", "retryDeadLetterJob", ["Operations"], { parameters: [idParam] }),
  };
  paths["/api/v1/jobs/schedule"] = { post: op("Schedule a job", "scheduleJob", ["Operations"]) };
  paths["/api/v1/outbox/status"] = { get: op("Get outbox status", "getOutboxStatus", ["Operations"]) };
  paths["/api/v1/outbox/replay/{id}"] = {
    post: op("Replay single outbox event", "replaySingleOutboxEvent", ["Operations"], { parameters: [idParam] }),
  };
  paths["/api/v1/outbox/replay-batch"] = {
    post: op("Replay batch of outbox events", "replayBatchOutboxEvents", ["Operations"]),
  };
  paths["/api/v1/cache/invalidate"] = { post: op("Invalidate cache", "invalidateCache", ["Operations"]) };
  paths["/api/v1/tests/all"] = { post: op("Run all integration tests", "runAllTests", ["Testing"]) };
  paths["/api/files/upload"] = { post: op("Upload file", "uploadFile", ["Operations"]) };
}

function addCommercialEndpoints(paths: Record<string, PathItemObject>): void {
  paths["/api/usage-metering"] = { get: op("Get usage metering data", "getUsageMetering", ["Commercial"]) };
  paths["/api/usage-metering/history"] = {
    get: op("Get usage metering history", "getUsageMeteringHistory", ["Commercial"]),
  };
  paths["/api/plan-limits"] = {
    get: op("Get plan limits", "getPlanLimits", ["Commercial"]),
    put: op("Update plan limits", "updatePlanLimits", ["Commercial"], { responses: stdMutateResponses }),
  };
  paths["/api/onboarding-checklist"] = {
    get: op("Get onboarding checklist", "getOnboardingChecklist", ["Commercial"]),
  };
  paths["/api/onboarding-checklist/{stepKey}/complete"] = {
    post: op("Complete onboarding step", "completeOnboardingStep", ["Commercial"], {
      parameters: [{ name: "stepKey", in: "path", required: true, schema: { type: "string" } }],
    }),
  };
  paths["/api/onboarding-checklist/dismiss"] = {
    post: op("Dismiss onboarding checklist", "dismissOnboardingChecklist", ["Commercial"]),
  };
  paths["/api/v1/onboarding/status"] = {
    get: op("Get onboarding status (v1)", "getOnboardingStatusV1", ["Commercial"]),
  };
  paths["/api/workspace-templates"] = { get: op("List workspace templates", "listWorkspaceTemplates", ["Commercial"]) };
  paths["/api/workspace-templates/{id}"] = {
    get: op("Get workspace template", "getWorkspaceTemplate", ["Commercial"], { parameters: [idParam] }),
  };
  paths["/api/workspace-templates/{id}/apply"] = {
    post: op("Apply workspace template", "applyWorkspaceTemplate", ["Commercial"], { parameters: [idParam] }),
  };
  paths["/api/tenant-quotas"] = { get: op("List tenant quotas", "listTenantQuotas", ["Commercial"]) };
  paths["/api/tenant-quotas/status"] = { get: op("Get tenant quota status", "getTenantQuotaStatus", ["Commercial"]) };
  paths["/api/tenant-quotas/check/{category}"] = {
    get: op("Check quota for category", "checkTenantQuota", ["Commercial"], {
      parameters: [{ name: "category", in: "path", required: true, schema: { type: "string" } }],
    }),
  };
  paths["/api/tenant-quotas/override"] = {
    put: op("Override tenant quota", "overrideTenantQuota", ["Commercial"], { responses: stdMutateResponses }),
  };
}

function addLifecycleEndpoints(paths: Record<string, PathItemObject>): void {
  paths["/api/lifecycle/status"] = { get: op("Get data lifecycle status", "getLifecycleStatus", ["Data Lifecycle"]) };
  paths["/api/lifecycle/policies"] = {
    get: op("List lifecycle policies", "listLifecyclePolicies", ["Data Lifecycle"]),
  };
  paths["/api/lifecycle/delete"] = {
    post: op("Execute lifecycle deletion", "executeLifecycleDeletion", ["Data Lifecycle"]),
  };
  paths["/api/lifecycle/export"] = { post: op("Export data for lifecycle", "exportLifecycleData", ["Data Lifecycle"]) };
  paths["/api/lifecycle/rehydrate"] = {
    post: op("Rehydrate archived data", "rehydrateLifecycleData", ["Data Lifecycle"]),
  };
}

function addWebhookEndpoints(paths: Record<string, PathItemObject>): void {
  paths["/api/outbound-webhooks"] = {
    get: op("List outbound webhooks", "listOutboundWebhooks", ["Webhooks"]),
    post: op("Create outbound webhook", "createOutboundWebhook", ["Webhooks"], { responses: stdCreateResponses }),
  };
  paths["/api/outbound-webhooks/{id}"] = {
    patch: op("Update outbound webhook", "updateOutboundWebhook", ["Webhooks"], {
      parameters: [idParam],
      responses: stdMutateResponses,
    }),
  };
  paths["/api/outbound-webhooks/{id}/test"] = {
    post: op("Test outbound webhook", "testOutboundWebhook", ["Webhooks"], { parameters: [idParam] }),
  };
  paths["/api/outbound-webhooks/{id}/logs"] = {
    get: op("List outbound webhook logs", "listOutboundWebhookLogs", ["Webhooks"], { parameters: [idParam] }),
  };
  paths["/api/v1/webhooks"] = {
    get: op("List webhooks (v1)", "listWebhooksV1", ["Webhooks"]),
    post: op("Create webhook (v1)", "createWebhookV1", ["Webhooks"], { responses: stdCreateResponses }),
  };
  paths["/api/v1/webhooks/{id}"] = {
    patch: op("Update webhook (v1)", "updateWebhookV1", ["Webhooks"], {
      parameters: [idParam],
      responses: stdMutateResponses,
    }),
  };
  paths["/api/v1/webhooks/{id}/logs"] = {
    get: op("List webhook logs (v1)", "listWebhookLogsV1", ["Webhooks"], { parameters: [idParam] }),
  };
}

function addPredictiveEndpoints(paths: Record<string, PathItemObject>): void {
  paths["/api/predictive/forecasts"] = { get: op("List security forecasts", "listForecasts", ["Predictive"]) };
  paths["/api/predictive/anomalies"] = { get: op("List detected anomalies", "listAnomalies", ["Predictive"]) };
  paths["/api/predictive/anomaly-subscriptions"] = {
    get: op("List anomaly subscriptions", "listAnomalySubscriptions", ["Predictive"]),
    post: op("Create anomaly subscription", "createAnomalySubscription", ["Predictive"], {
      responses: stdCreateResponses,
    }),
  };
  paths["/api/predictive/recommendations"] = {
    get: op("List security recommendations", "listRecommendations", ["Predictive"]),
  };
  paths["/api/predictive/recommendations/{id}"] = {
    patch: op("Update recommendation status", "updateRecommendation", ["Predictive"], {
      parameters: [idParam],
      responses: stdMutateResponses,
    }),
  };
  paths["/api/predictive/attack-surface"] = {
    get: op("Get attack surface analysis", "getAttackSurface", ["Predictive"]),
  };
  paths["/api/predictive/forecast-quality"] = {
    get: op("Get forecast quality metrics", "getForecastQuality", ["Predictive"]),
  };
  paths["/api/predictive/recompute"] = { post: op("Recompute predictions", "recomputePredictions", ["Predictive"]) };
}

function addResponseEndpoints(paths: Record<string, PathItemObject>): void {
  paths["/api/response-actions"] = {
    get: op("List response actions", "listResponseActions", ["Response"]),
    post: op("Create response action", "createResponseAction", ["Response"], { responses: stdCreateResponses }),
  };
  paths["/api/response-actions/dry-run"] = {
    post: op("Dry-run response action", "dryRunResponseAction", ["Response"]),
  };
  paths["/api/response-approvals"] = {
    get: op("List response approvals", "listResponseApprovals", ["Response"]),
    post: op("Create response approval request", "createResponseApproval", ["Response"], {
      responses: stdCreateResponses,
    }),
  };
  paths["/api/response-approvals/{id}"] = {
    get: op("Get response approval", "getResponseApproval", ["Response"], { parameters: [idParam] }),
  };
  paths["/api/response-approvals/{id}/decide"] = {
    post: op("Decide on response approval", "decideResponseApproval", ["Response"], { parameters: [idParam] }),
  };
}

function addScalingEndpoints(paths: Record<string, PathItemObject>): void {
  paths["/api/scaling/readiness"] = { get: op("Get scaling readiness status", "getScalingReadiness", ["Scaling"]) };
  paths["/api/scaling/state-registry"] = { get: op("Get state registry", "getStateRegistry", ["Scaling"]) };
}

function addTenantIsolationEndpoints(paths: Record<string, PathItemObject>): void {
  paths["/api/tenant-isolation/config"] = {
    get: op("Get tenant isolation config", "getTenantIsolationConfig", ["Tenant Isolation"]),
    put: op("Update tenant isolation config", "updateTenantIsolationConfig", ["Tenant Isolation"], {
      responses: stdMutateResponses,
    }),
  };
  paths["/api/tenant-isolation/report"] = {
    get: op("Get tenant isolation report", "getTenantIsolationReport", ["Tenant Isolation"]),
  };
  paths["/api/tenant-isolation/noisy-neighbor"] = {
    get: op("Get noisy neighbor report", "getNoisyNeighborReport", ["Tenant Isolation"]),
  };
  paths["/api/tenant-isolation/dedicated-instance"] = {
    get: op("Get dedicated instance info", "getDedicatedInstance", ["Tenant Isolation"]),
  };
  paths["/api/tenant-isolation/provision-schema"] = {
    post: op("Provision tenant schema", "provisionTenantSchema", ["Tenant Isolation"]),
  };
  paths["/api/tenant-isolation/register-instance"] = {
    post: op("Register dedicated instance", "registerDedicatedInstance", ["Tenant Isolation"]),
  };
}

function addApiVersioningEndpoints(paths: Record<string, PathItemObject>): void {
  paths["/api/v1/version-policy"] = {
    get: op("Get API version policy", "getVersionPolicy", ["API Versioning"], { security: [] }),
  };
  paths["/api/v1/migration-guide"] = {
    get: op("Get API migration guide", "getMigrationGuide", ["API Versioning"], { security: [] }),
  };
  paths["/api/v1/status"] = { get: op("Get API v1 status", "getApiV1Status", ["API Versioning"], { security: [] }) };
}

function addPaginationContractEndpoints(paths: Record<string, PathItemObject>): void {
  paths["/api/v1/pagination-contract"] = {
    get: op("Get pagination contract documentation", "getPaginationContract", ["System"], { security: [] }),
  };
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
      { name: "System", description: "Health checks, pagination contract, and system utilities" },
      { name: "Dashboard", description: "Dashboard statistics and analytics" },
      { name: "Alerts", description: "Alert CRUD, lifecycle, suppression, correlation, and archiving" },
      { name: "Incidents", description: "Incident CRUD, lifecycle, tasks, hypotheses, SLA, and PIR" },
      { name: "Connectors", description: "Data source connectors, sync, health checks, and secret rotation" },
      { name: "Automation", description: "Playbooks, runbooks, autonomous response, and approvals" },
      { name: "Compliance", description: "Controls, mappings, audit logs, DSAR, legal holds, CSPM, and posture" },
      { name: "Threat Intelligence", description: "IOC feeds, entries, watchlists, match rules, and OSINT" },
      { name: "Entities", description: "Entity management, enrichment, and merging" },
      { name: "Ingestion", description: "Alert ingestion from external sources and event catalog" },
      { name: "Integrations", description: "Third-party integrations, notification channels, and ticket sync" },
      { name: "Endpoint Management", description: "Endpoint registration, telemetry, and risk scoring" },
      { name: "Organization", description: "Org members, invitations, SSO, SCIM, security policy, and API keys" },
      { name: "AI Engine", description: "AI triage, correlation, narrative generation, and budget management" },
      { name: "Reports", description: "Report templates, schedules, runs, and versioning" },
      { name: "Operations", description: "Jobs, DR runbooks, SLO targets, monitoring, caching, and outbox" },
      { name: "Commercial", description: "Usage metering, plan limits, onboarding, workspace templates, and quotas" },
      { name: "Data Lifecycle", description: "Data lifecycle policies, deletion, export, and rehydration" },
      { name: "Webhooks", description: "Outbound webhooks and webhook logs" },
      { name: "Predictive", description: "Forecasts, anomaly detection, recommendations, and attack surface" },
      { name: "Response", description: "Response actions, dry-run, and approval workflows" },
      { name: "Scaling", description: "Horizontal scaling readiness and state registry" },
      { name: "Tenant Isolation", description: "Multi-tenant isolation, noisy neighbor, and dedicated instances" },
      { name: "API Versioning", description: "Version policy, migration guide, and deprecation headers" },
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
        apiKeyAuth: {
          type: "apiKey",
          in: "header",
          name: "X-API-Key",
          description: "Organization API key for ingestion",
        },
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
  lines.push(
    "function buildUrl(path: string, params?: Record<string, string | number | boolean | undefined>): string {",
  );
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
  lines.push('    credentials: "include",');
  lines.push(
    '    headers: { "Content-Type": "application/json", ...((rest.headers as Record<string, string>) || {}) },',
  );
  lines.push('    body: body ? (typeof body === "string" ? body : JSON.stringify(body)) : undefined,');
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
      const pathParams = (operation.parameters || []).filter((p) => p.in === "path");
      const queryParams = (operation.parameters || []).filter((p) => p.in === "query");
      const hasBody = !!operation.requestBody;

      const fnParams: string[] = [];
      for (const pp of pathParams) {
        fnParams.push(`${pp.name}: string`);
      }
      if (queryParams.length > 0) {
        const qFields = queryParams.map((q) => `${q.name}?: string | number`).join("; ");
        fnParams.push(`params?: { ${qFields} }`);
      }
      if (hasBody) {
        fnParams.push("body: Record<string, unknown>");
      }

      let urlExpr = `"${path}"`;
      for (const pp of pathParams) {
        urlExpr = urlExpr.replace(`{${pp.name}}`, `\${${pp.name}}`);
        urlExpr = urlExpr.replace(/"/g, "`");
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

  app.get("/api/v1/pagination-contract", (_req, res) => {
    res.json(paginationContractDoc());
  });

  app.get("/api/openapi/validate", (_req, res) => {
    const spec = buildOpenApiSpec();
    const paths = spec.paths as Record<string, Record<string, unknown>>;
    const pathCount = Object.keys(paths).length;
    let operationCount = 0;
    for (const methods of Object.values(paths)) {
      for (const key of Object.keys(methods)) {
        if (["get", "post", "put", "patch", "delete"].includes(key)) operationCount++;
      }
    }
    res.json({
      valid: true,
      pathCount,
      operationCount,
      version: (spec.info as Record<string, unknown>).version,
      generatedAt: new Date().toISOString(),
    });
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

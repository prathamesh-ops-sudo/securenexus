import { logger } from "./logger";

export const EVENT_CATALOG_VERSION = "1.0.0";

export type EventDomain = "alert" | "incident" | "connector" | "entity" | "compliance" | "playbook" | "report" | "endpoint" | "investigation" | "webhook" | "system";

export interface EventSchema {
  name: string;
  version: number;
  domain: EventDomain;
  aggregateType: string;
  description: string;
  payloadContract: Record<string, FieldContract>;
  deprecated?: boolean;
  deprecatedAt?: string;
  supersededBy?: string;
  addedInCatalogVersion: string;
}

export interface FieldContract {
  type: "string" | "number" | "boolean" | "object" | "array" | "string[]" | "null";
  required: boolean;
  description: string;
}

function field(type: FieldContract["type"], required: boolean, description: string): FieldContract {
  return { type, required, description };
}

const CATALOG: Record<string, EventSchema> = {
  "alert.created": {
    name: "alert.created",
    version: 1,
    domain: "alert",
    aggregateType: "alert",
    description: "Emitted when a new alert is created via API or ingestion pipeline.",
    addedInCatalogVersion: "1.0.0",
    payloadContract: {
      title: field("string", true, "Alert title"),
      severity: field("string", true, "Alert severity: critical | high | medium | low | informational"),
      source: field("string", false, "Originating source system"),
      status: field("string", true, "Current status of the alert"),
      category: field("string", false, "MITRE-aligned category"),
    },
  },
  "alert.updated": {
    name: "alert.updated",
    version: 1,
    domain: "alert",
    aggregateType: "alert",
    description: "Emitted when an alert's fields are modified.",
    addedInCatalogVersion: "1.0.0",
    payloadContract: {
      changes: field("string[]", true, "List of field names that changed"),
      status: field("string", false, "New status after update"),
      severity: field("string", false, "New severity after update"),
    },
  },
  "alert.closed": {
    name: "alert.closed",
    version: 1,
    domain: "alert",
    aggregateType: "alert",
    description: "Emitted when an alert transitions to a terminal closed state.",
    addedInCatalogVersion: "1.0.0",
    payloadContract: {
      status: field("string", true, "Terminal status (resolved, dismissed, false_positive)"),
      previousStatus: field("string", false, "Status before closure"),
    },
  },
  "alert.correlated": {
    name: "alert.correlated",
    version: 1,
    domain: "alert",
    aggregateType: "alert",
    description: "Emitted when an alert is correlated into a cluster by the correlation engine.",
    addedInCatalogVersion: "1.0.0",
    payloadContract: {
      clusterId: field("string", true, "Correlation cluster ID"),
      confidence: field("number", true, "Correlation confidence score 0-1"),
      method: field("string", false, "Correlation method used"),
    },
  },
  "incident.created": {
    name: "incident.created",
    version: 1,
    domain: "incident",
    aggregateType: "incident",
    description: "Emitted when a new incident is created manually or via alert promotion.",
    addedInCatalogVersion: "1.0.0",
    payloadContract: {
      title: field("string", true, "Incident title"),
      severity: field("string", true, "Incident severity"),
      status: field("string", true, "Incident status"),
      priority: field("string", false, "Incident priority"),
    },
  },
  "incident.updated": {
    name: "incident.updated",
    version: 1,
    domain: "incident",
    aggregateType: "incident",
    description: "Emitted when incident fields are modified.",
    addedInCatalogVersion: "1.0.0",
    payloadContract: {
      changes: field("string[]", true, "List of field names that changed"),
      status: field("string", false, "New status"),
      severity: field("string", false, "New severity"),
    },
  },
  "incident.closed": {
    name: "incident.closed",
    version: 1,
    domain: "incident",
    aggregateType: "incident",
    description: "Emitted when an incident is resolved or closed.",
    addedInCatalogVersion: "1.0.0",
    payloadContract: {
      status: field("string", true, "Terminal status"),
      resolution: field("string", false, "Resolution summary"),
    },
  },
  "incident.escalated": {
    name: "incident.escalated",
    version: 1,
    domain: "incident",
    aggregateType: "incident",
    description: "Emitted when an incident severity is increased.",
    addedInCatalogVersion: "1.0.0",
    payloadContract: {
      changes: field("string[]", true, "Changed fields"),
      status: field("string", false, "Current status"),
      severity: field("string", true, "New severity after escalation"),
    },
  },
  "connector.synced": {
    name: "connector.synced",
    version: 1,
    domain: "connector",
    aggregateType: "connector",
    description: "Emitted after a connector completes a sync cycle.",
    addedInCatalogVersion: "1.0.0",
    payloadContract: {
      type: field("string", true, "Connector provider type"),
      name: field("string", true, "Connector display name"),
      alertsReceived: field("number", false, "Count of raw alerts fetched"),
      alertsCreated: field("number", false, "Count of new alerts persisted"),
    },
  },
  "connector.failed": {
    name: "connector.failed",
    version: 1,
    domain: "connector",
    aggregateType: "connector",
    description: "Emitted when a connector sync fails after all retry attempts.",
    addedInCatalogVersion: "1.0.0",
    payloadContract: {
      type: field("string", true, "Connector provider type"),
      errorType: field("string", true, "Error classification: throttle | auth_error | network_error | api_error"),
      errorMessage: field("string", true, "Human-readable error message"),
      attempts: field("number", true, "Number of attempts made"),
    },
  },
  "entity.resolved": {
    name: "entity.resolved",
    version: 1,
    domain: "entity",
    aggregateType: "entity",
    description: "Emitted when the entity resolver links or creates an entity from alert observables.",
    addedInCatalogVersion: "1.0.0",
    payloadContract: {
      entityType: field("string", true, "Entity type (ip, domain, user, host, hash, email)"),
      value: field("string", true, "Entity value"),
      alertId: field("string", false, "Triggering alert ID"),
    },
  },
  "entity.merged": {
    name: "entity.merged",
    version: 1,
    domain: "entity",
    aggregateType: "entity",
    description: "Emitted when two entities are merged into one.",
    addedInCatalogVersion: "1.0.0",
    payloadContract: {
      sourceId: field("string", true, "Entity absorbed into target"),
      targetId: field("string", true, "Surviving entity after merge"),
    },
  },
  "compliance.policy.evaluated": {
    name: "compliance.policy.evaluated",
    version: 1,
    domain: "compliance",
    aggregateType: "compliance_policy",
    description: "Emitted when a compliance policy is evaluated against the current state.",
    addedInCatalogVersion: "1.0.0",
    payloadContract: {
      policyId: field("string", true, "Policy ID evaluated"),
      result: field("string", true, "Evaluation result: pass | fail | warning"),
      score: field("number", false, "Numeric compliance score"),
    },
  },
  "compliance.control.updated": {
    name: "compliance.control.updated",
    version: 1,
    domain: "compliance",
    aggregateType: "compliance_control",
    description: "Emitted when a compliance control status changes.",
    addedInCatalogVersion: "1.0.0",
    payloadContract: {
      controlId: field("string", true, "Control ID"),
      status: field("string", true, "New control status"),
      framework: field("string", false, "Compliance framework name"),
    },
  },
  "playbook.executed": {
    name: "playbook.executed",
    version: 1,
    domain: "playbook",
    aggregateType: "playbook",
    description: "Emitted when a playbook execution completes.",
    addedInCatalogVersion: "1.0.0",
    payloadContract: {
      playbookId: field("string", true, "Playbook ID"),
      status: field("string", true, "Execution result: success | failed | partial"),
      stepsCompleted: field("number", false, "Number of steps completed"),
      duration: field("number", false, "Execution duration in milliseconds"),
    },
  },
  "playbook.step.completed": {
    name: "playbook.step.completed",
    version: 1,
    domain: "playbook",
    aggregateType: "playbook",
    description: "Emitted after each individual playbook step finishes.",
    addedInCatalogVersion: "1.0.0",
    payloadContract: {
      playbookId: field("string", true, "Parent playbook ID"),
      stepId: field("string", true, "Step ID"),
      status: field("string", true, "Step outcome: success | failed | skipped"),
    },
  },
  "report.generated": {
    name: "report.generated",
    version: 1,
    domain: "report",
    aggregateType: "report",
    description: "Emitted when a report is successfully generated.",
    addedInCatalogVersion: "1.0.0",
    payloadContract: {
      reportId: field("string", true, "Report ID"),
      templateId: field("string", false, "Template used for generation"),
      format: field("string", false, "Output format: pdf | csv | json"),
    },
  },
  "endpoint.risk.changed": {
    name: "endpoint.risk.changed",
    version: 1,
    domain: "endpoint",
    aggregateType: "endpoint",
    description: "Emitted when an endpoint risk score changes significantly.",
    addedInCatalogVersion: "1.0.0",
    payloadContract: {
      endpointId: field("string", true, "Endpoint asset ID"),
      previousScore: field("number", false, "Previous risk score"),
      newScore: field("number", true, "New risk score"),
    },
  },
  "investigation.started": {
    name: "investigation.started",
    version: 1,
    domain: "investigation",
    aggregateType: "investigation",
    description: "Emitted when an AI investigation is initiated.",
    addedInCatalogVersion: "1.0.0",
    payloadContract: {
      incidentId: field("string", true, "Incident under investigation"),
      investigationType: field("string", false, "Type of investigation"),
    },
  },
  "investigation.completed": {
    name: "investigation.completed",
    version: 1,
    domain: "investigation",
    aggregateType: "investigation",
    description: "Emitted when an AI investigation completes.",
    addedInCatalogVersion: "1.0.0",
    payloadContract: {
      incidentId: field("string", true, "Incident investigated"),
      hypothesesCount: field("number", false, "Number of hypotheses generated"),
      tasksCount: field("number", false, "Number of investigation tasks"),
    },
  },
  "webhook.delivered": {
    name: "webhook.delivered",
    version: 1,
    domain: "webhook",
    aggregateType: "webhook",
    description: "Emitted when an outbound webhook delivery succeeds.",
    addedInCatalogVersion: "1.0.0",
    payloadContract: {
      webhookId: field("string", true, "Webhook configuration ID"),
      eventType: field("string", true, "Event type that was delivered"),
      statusCode: field("number", true, "HTTP response status code"),
    },
  },
  "webhook.failed": {
    name: "webhook.failed",
    version: 1,
    domain: "webhook",
    aggregateType: "webhook",
    description: "Emitted when an outbound webhook delivery fails permanently.",
    addedInCatalogVersion: "1.0.0",
    payloadContract: {
      webhookId: field("string", true, "Webhook configuration ID"),
      eventType: field("string", true, "Event type that failed"),
      errorMessage: field("string", true, "Failure reason"),
      attempts: field("number", true, "Total delivery attempts"),
    },
  },
  "system.health": {
    name: "system.health",
    version: 1,
    domain: "system",
    aggregateType: "system",
    description: "Periodic system health heartbeat event.",
    addedInCatalogVersion: "1.0.0",
    payloadContract: {
      status: field("string", true, "System status: ok | degraded | down"),
      component: field("string", false, "Component name if scoped"),
    },
  },
};

const eventLog = logger.child("event-catalog");

export function getEventSchema(eventName: string): EventSchema | undefined {
  return CATALOG[eventName];
}

export function getAllEventSchemas(): EventSchema[] {
  return Object.values(CATALOG);
}

export function getEventsByDomain(domain: EventDomain): EventSchema[] {
  return Object.values(CATALOG).filter((s) => s.domain === domain);
}

export function isKnownEvent(eventName: string): boolean {
  return eventName in CATALOG;
}

export function isDeprecatedEvent(eventName: string): boolean {
  const schema = CATALOG[eventName];
  return schema?.deprecated === true;
}

export interface EventValidationResult {
  valid: boolean;
  warnings: string[];
  errors: string[];
}

export function validateEventPayload(
  eventName: string,
  payload: Record<string, unknown>,
): EventValidationResult {
  const result: EventValidationResult = { valid: true, warnings: [], errors: [] };

  const schema = CATALOG[eventName];
  if (!schema) {
    result.warnings.push(`Event "${eventName}" is not in the catalog — consider registering it.`);
    return result;
  }

  if (schema.deprecated) {
    result.warnings.push(
      `Event "${eventName}" is deprecated${schema.supersededBy ? ` — use "${schema.supersededBy}" instead` : ""}.`,
    );
  }

  for (const [fieldName, contract] of Object.entries(schema.payloadContract)) {
    const value = payload[fieldName];
    if (contract.required && (value === undefined || value === null)) {
      result.errors.push(`Missing required field "${fieldName}" (${contract.description}).`);
      result.valid = false;
    }
    if (value !== undefined && value !== null) {
      const actualType = Array.isArray(value) ? "array" : typeof value;
      if (contract.type === "string[]") {
        if (!Array.isArray(value)) {
          result.errors.push(`Field "${fieldName}" must be a string array, got ${actualType}.`);
          result.valid = false;
        }
      } else if (contract.type === "null") {
        // accept anything
      } else if (contract.type === "array") {
        if (!Array.isArray(value)) {
          result.errors.push(`Field "${fieldName}" must be an array, got ${actualType}.`);
          result.valid = false;
        }
      } else if (actualType !== contract.type) {
        result.errors.push(`Field "${fieldName}" must be ${contract.type}, got ${actualType}.`);
        result.valid = false;
      }
    }
  }

  return result;
}

export function validateAndLogEvent(
  eventName: string,
  aggregateType: string,
  aggregateId: string,
  payload: Record<string, unknown>,
): void {
  const result = validateEventPayload(eventName, payload);
  if (result.warnings.length > 0) {
    eventLog.warn("Event validation warnings", {
      event: eventName,
      aggregateType,
      aggregateId,
      warnings: result.warnings,
    });
  }
  if (!result.valid) {
    eventLog.error("Event payload contract violation", {
      event: eventName,
      aggregateType,
      aggregateId,
      errors: result.errors,
    });
  }
}

export function getDeprecatedEvents(): EventSchema[] {
  return Object.values(CATALOG).filter((s) => s.deprecated === true);
}

export function getCatalogSummary(): {
  version: string;
  totalEvents: number;
  domains: Record<string, number>;
  deprecated: number;
} {
  const domains: Record<string, number> = {};
  let deprecated = 0;
  for (const schema of Object.values(CATALOG)) {
    domains[schema.domain] = (domains[schema.domain] || 0) + 1;
    if (schema.deprecated) deprecated++;
  }
  return {
    version: EVENT_CATALOG_VERSION,
    totalEvents: Object.keys(CATALOG).length,
    domains,
    deprecated,
  };
}

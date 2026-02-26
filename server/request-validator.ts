import { z } from "zod";
import type { Request, Response, NextFunction } from "express";
import { logger } from "./logger";
import {
  ALERT_SEVERITIES,
  ALERT_STATUSES,
  ALERT_CATEGORIES,
  CONNECTOR_TYPES,
  CONNECTOR_AUTH_TYPES,
  INCIDENT_SEVERITIES,
  INCIDENT_STATUSES,
  PLAYBOOK_TRIGGERS,
  PLAYBOOK_STATUSES,
  INTEGRATION_TYPES,
  CHANNEL_TYPES,
  RESPONSE_ACTION_TYPES,
  ORG_ROLES,
} from "@shared/schema";

const MAX_STRING = 2000;
const MAX_NAME = 255;
const MAX_OFFSET = 1_000_000;
const MAX_LIMIT = 500;
const DEFAULT_LIMIT = 50;

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const idParam = z.string().min(1).max(255);

const paginationSchema = z.object({
  offset: z.coerce.number().int().min(0).max(MAX_OFFSET).default(0),
  limit: z.coerce.number().int().min(1).max(MAX_LIMIT).default(DEFAULT_LIMIT),
  sortOrder: z.enum(["asc", "desc"]).default("desc"),
  sortBy: z.string().max(64).optional(),
});

const searchSchema = paginationSchema.extend({
  search: z.string().max(MAX_STRING).optional(),
});

export const querySchemas = {
  alertsList: searchSchema.extend({
    severity: z.enum(ALERT_SEVERITIES).optional(),
    status: z.enum(ALERT_STATUSES).optional(),
    source: z.string().max(MAX_NAME).optional(),
  }),

  incidentsList: searchSchema.extend({
    severity: z.enum(INCIDENT_SEVERITIES).optional(),
    status: z.enum(INCIDENT_STATUSES).optional(),
    queue: z.string().max(MAX_NAME).optional(),
  }),

  pagination: paginationSchema,

  limitOnly: z.object({
    limit: z.coerce.number().int().min(1).max(MAX_LIMIT).default(DEFAULT_LIMIT),
  }),

  iocEntries: z.object({
    feedId: z.string().max(255).optional(),
    iocType: z.string().max(64).optional(),
    status: z.string().max(64).optional(),
    limit: z.coerce.number().int().min(1).max(MAX_LIMIT).optional(),
  }),

  feedbackMetrics: z.object({
    days: z.coerce.number().int().min(1).max(365).default(30),
  }),

  playbookExecutions: z.object({
    playbookId: z.string().max(255).optional(),
    limit: z.coerce.number().int().min(1).max(MAX_LIMIT).default(DEFAULT_LIMIT),
  }),

  approvalStatus: z.object({
    status: z.enum(["pending", "approved", "rejected"]).default("pending"),
  }),

  complianceControls: z.object({
    framework: z.string().max(MAX_NAME).optional(),
  }),

  policyResults: z.object({
    policyCheckId: z.string().max(255).optional(),
  }),

  responseActions: z.object({
    incidentId: z.string().max(255).optional(),
  }),

  aiFeedbackByQuery: z.object({
    resourceType: z.string().max(64).optional(),
    resourceId: z.string().max(255).optional(),
  }),
};

export const bodySchemas = {
  connectorCreate: z.object({
    name: z.string().min(1).max(MAX_NAME),
    type: z.enum(CONNECTOR_TYPES),
    authType: z.enum(CONNECTOR_AUTH_TYPES),
    config: z.record(z.unknown()),
    pollingIntervalMin: z.number().int().min(1).max(1440).optional(),
  }),

  connectorUpdate: z.object({
    name: z.string().min(1).max(MAX_NAME).optional(),
    config: z.record(z.unknown()).optional(),
    status: z.string().max(64).optional(),
    pollingIntervalMin: z.number().int().min(1).max(1440).optional(),
  }),

  connectorTest: z.object({
    type: z.enum(CONNECTOR_TYPES),
    config: z.record(z.unknown()),
  }),

  integrationCreate: z.object({
    name: z.string().min(1).max(MAX_NAME),
    type: z.enum(INTEGRATION_TYPES),
    config: z.record(z.unknown()),
  }),

  notificationChannelCreate: z.object({
    name: z.string().min(1).max(MAX_NAME),
    type: z.enum(CHANNEL_TYPES),
    config: z.record(z.unknown()),
    events: z.array(z.string().max(64)).optional(),
    isDefault: z.boolean().optional(),
  }),

  responseActionCreate: z.object({
    actionType: z.enum(RESPONSE_ACTION_TYPES),
    target: z.string().min(1).max(MAX_STRING),
    connectorId: z.string().max(255).optional(),
    incidentId: z.string().max(255).optional(),
    alertId: z.string().max(255).optional(),
  }),

  playbookCreate: z.object({
    name: z.string().min(1).max(MAX_NAME),
    description: z.string().max(MAX_STRING).optional(),
    trigger: z.enum(PLAYBOOK_TRIGGERS),
    conditions: z.unknown().optional(),
    actions: z.unknown(),
    status: z.enum(PLAYBOOK_STATUSES).optional(),
  }),

  aiFeedback: z.object({
    resourceType: z.string().min(1).max(64),
    resourceId: z.string().max(255).optional(),
    rating: z.number().int().min(1).max(5),
    comment: z.string().max(MAX_STRING).optional(),
    aiOutput: z.unknown().optional(),
    correctionReason: z.string().max(MAX_STRING).optional(),
    correctedSeverity: z.string().max(64).optional(),
    correctedCategory: z.string().max(64).optional(),
  }),

  approvalDecision: z.object({
    decision: z.enum(["approved", "rejected"]),
    note: z.string().max(MAX_STRING).optional(),
  }),

  bulkIncidentUpdate: z.object({
    incidentIds: z.array(z.string().max(255)).min(1).max(500),
    status: z.string().max(64).optional(),
    assignedTo: z.string().max(MAX_NAME).optional(),
    escalated: z.boolean().optional(),
    priority: z.number().int().min(1).max(5).optional(),
  }),

  correlateApply: z.object({
    group: z.object({
      alertIds: z.array(z.string().max(255)).min(1).max(1000),
      suggestedIncidentTitle: z.string().min(1).max(500),
      severity: z.enum(INCIDENT_SEVERITIES).optional(),
      reasoning: z.string().max(MAX_STRING).optional(),
      confidence: z.number().min(0).max(1).optional(),
      mitreTactics: z.array(z.string().max(128)).optional(),
      mitreTechniques: z.array(z.string().max(128)).optional(),
    }),
  }),

  apiKeyCreate: z.object({
    name: z.string().min(1).max(MAX_NAME),
    scopes: z.array(z.string().max(64)).optional(),
  }),

  invitationCreate: z.object({
    email: z.string().email().max(MAX_NAME),
    role: z.enum(["admin", "analyst", "read_only"]).optional(),
  }),

  memberRoleUpdate: z.object({
    role: z.enum(ORG_ROLES),
  }),

  slaPolicyCreate: z.object({
    name: z.string().min(1).max(MAX_NAME).optional(),
    severity: z.enum(INCIDENT_SEVERITIES),
    ackMinutes: z.number().int().min(1).max(10080),
    containMinutes: z.number().int().min(1).max(43200),
    resolveMinutes: z.number().int().min(1).max(43200),
    enabled: z.boolean().optional(),
  }),

  incidentTagAdd: z.object({
    tagId: z.string().min(1).max(255),
  }),

  invitationAccept: z.object({
    token: z.string().min(1).max(255),
  }),
};

export function validateQuery<T extends z.ZodType>(schema: T) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const result = schema.safeParse(req.query);
    if (!result.success) {
      res.status(400).json({
        message: "Invalid query parameters",
        errors: result.error.flatten(),
      });
      return;
    }
    (req as any).validatedQuery = result.data;
    next();
  };
}

export function validateBody<T extends z.ZodType>(schema: T) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const result = schema.safeParse(req.body);
    if (!result.success) {
      logger.child("validation").warn("Request body validation failed", {
        path: req.path,
        errors: result.error.issues.map(i => `${i.path.join(".")}: ${i.message}`),
      });
      res.status(400).json({
        message: "Invalid request body",
        errors: result.error.flatten(),
      });
      return;
    }
    (req as any).validatedBody = result.data;
    next();
  };
}

export function validatePathId(paramName: string) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const val = req.params[paramName];
    const result = idParam.safeParse(val);
    if (!result.success) {
      res.status(400).json({
        message: `Invalid path parameter: ${paramName}`,
        errors: result.error.flatten(),
      });
      return;
    }
    next();
  };
}

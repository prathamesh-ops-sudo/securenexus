import type { Express, Request, Response } from "express";
import { isAuthenticated } from "../auth";
import { requireMinRole, requireOrgId, resolveOrgContext } from "../rbac";
import { logger, getOrgId, sendEnvelope } from "./shared";
import {
  getAllPolicyPacks,
  getPolicyPackById,
  getPolicyPacksByDomain,
  getPolicyPacksByStrictness,
  getPolicyPackSummary,
  getPackChangelog,
  getDomainLabels,
  getStrictnessPresets,
  activatePackForOrg,
  deactivatePackForOrg,
  getOrgActivatedPacks,
  updatePackActivation,
  getEffectiveRules,
} from "../policy-packs-engine";
import type { PolicyDomain, StrictnessPreset } from "../policy-packs-engine";

const log = logger.child("policy-packs");

const VALID_DOMAINS: PolicyDomain[] = [
  "cloud_posture",
  "identity_risk",
  "appsec",
  "ai_runtime_safety",
  "regulated_workflows",
];
const VALID_STRICTNESS: StrictnessPreset[] = ["starter", "balanced", "regulated", "zero_trust"];

export function registerPolicyPacksRoutes(app: Express): void {
  app.get("/api/policy-packs/meta", isAuthenticated, async (_req: Request, res: Response) => {
    try {
      const domains = getDomainLabels();
      const presets = getStrictnessPresets();
      return sendEnvelope(res, { domains, presets });
    } catch (err) {
      log.error("Failed to get policy packs metadata", { error: String(err) });
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "INTERNAL_ERROR", message: "Failed to fetch metadata" }],
      });
    }
  });

  app.get("/api/policy-packs/summary", isAuthenticated, async (_req: Request, res: Response) => {
    try {
      const summary = getPolicyPackSummary();
      return sendEnvelope(res, summary);
    } catch (err) {
      log.error("Failed to get policy packs summary", { error: String(err) });
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "INTERNAL_ERROR", message: "Failed to fetch summary" }],
      });
    }
  });

  app.get("/api/policy-packs", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const domain = typeof req.query.domain === "string" ? req.query.domain : undefined;
      const strictness = typeof req.query.strictness === "string" ? req.query.strictness : undefined;

      let packs = getAllPolicyPacks();

      if (domain && VALID_DOMAINS.includes(domain as PolicyDomain)) {
        packs = getPolicyPacksByDomain(domain as PolicyDomain);
      }

      if (strictness && VALID_STRICTNESS.includes(strictness as StrictnessPreset)) {
        packs = packs.filter((p) => p.strictnessPreset === strictness);
      }

      return sendEnvelope(res, packs);
    } catch (err) {
      log.error("Failed to get policy packs", { error: String(err) });
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "INTERNAL_ERROR", message: "Failed to fetch policy packs" }],
      });
    }
  });

  app.get("/api/policy-packs/:id", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const id = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
      const pack = getPolicyPackById(id);
      if (!pack) {
        return sendEnvelope(res, null, {
          status: 404,
          errors: [{ code: "NOT_FOUND", message: "Policy pack not found" }],
        });
      }
      return sendEnvelope(res, pack);
    } catch (err) {
      log.error("Failed to get policy pack", { error: String(err) });
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "INTERNAL_ERROR", message: "Failed to fetch policy pack" }],
      });
    }
  });

  app.get("/api/policy-packs/:id/changelog", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const id = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
      const changelog = getPackChangelog(id);
      return sendEnvelope(res, changelog);
    } catch (err) {
      log.error("Failed to get changelog", { error: String(err) });
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "INTERNAL_ERROR", message: "Failed to fetch changelog" }],
      });
    }
  });

  app.get(
    "/api/policy-packs/:id/effective-rules",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const packId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
        const rules = getEffectiveRules(orgId, packId);
        if (!rules) {
          return sendEnvelope(res, null, {
            status: 404,
            errors: [{ code: "NOT_FOUND", message: "Policy pack not found" }],
          });
        }
        return sendEnvelope(res, rules);
      } catch (err) {
        log.error("Failed to get effective rules", { error: String(err) });
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "INTERNAL_ERROR", message: "Failed to fetch effective rules" }],
        });
      }
    },
  );

  app.get(
    "/api/policy-packs/org/activations",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const activations = getOrgActivatedPacks(orgId);
        return sendEnvelope(res, activations);
      } catch (err) {
        log.error("Failed to get org activations", { error: String(err) });
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "INTERNAL_ERROR", message: "Failed to fetch org activations" }],
        });
      }
    },
  );

  app.post(
    "/api/policy-packs/:id/activate",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const packId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
        const user = (req as any).user;
        const strictnessOverride =
          typeof req.body.strictnessOverride === "string" &&
          VALID_STRICTNESS.includes(req.body.strictnessOverride as StrictnessPreset)
            ? (req.body.strictnessOverride as StrictnessPreset)
            : undefined;

        const result = activatePackForOrg(orgId, packId, user?.id || "unknown", strictnessOverride);

        if ("error" in result) {
          return sendEnvelope(res, null, {
            status: 400,
            errors: [{ code: "ACTIVATION_ERROR", message: result.error }],
          });
        }

        return sendEnvelope(res, result, { status: 201 });
      } catch (err) {
        log.error("Failed to activate policy pack", { error: String(err) });
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "INTERNAL_ERROR", message: "Failed to activate policy pack" }],
        });
      }
    },
  );

  app.post(
    "/api/policy-packs/:id/deactivate",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const packId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
        const removed = deactivatePackForOrg(orgId, packId);

        if (!removed) {
          return sendEnvelope(res, null, {
            status: 404,
            errors: [{ code: "NOT_FOUND", message: "Activation not found for this organization" }],
          });
        }

        return sendEnvelope(res, { deactivated: true });
      } catch (err) {
        log.error("Failed to deactivate policy pack", { error: String(err) });
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "INTERNAL_ERROR", message: "Failed to deactivate policy pack" }],
        });
      }
    },
  );

  app.patch(
    "/api/policy-packs/:id/activation",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const packId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;

        const updates: Record<string, unknown> = {};
        if (req.body.strictnessOverride !== undefined) {
          if (
            req.body.strictnessOverride !== null &&
            !VALID_STRICTNESS.includes(req.body.strictnessOverride as StrictnessPreset)
          ) {
            return sendEnvelope(res, null, {
              status: 400,
              errors: [{ code: "VALIDATION_ERROR", message: "Invalid strictness preset" }],
            });
          }
          updates.strictnessOverride = req.body.strictnessOverride;
        }
        if (req.body.status !== undefined) {
          const validStatuses = ["active", "paused", "pending_review"];
          if (!validStatuses.includes(req.body.status)) {
            return sendEnvelope(res, null, {
              status: 400,
              errors: [{ code: "VALIDATION_ERROR", message: "Invalid status" }],
            });
          }
          updates.status = req.body.status;
        }
        if (req.body.ruleOverrides !== undefined) {
          updates.ruleOverrides = req.body.ruleOverrides;
        }

        const result = updatePackActivation(orgId, packId, updates as any);
        if (!result) {
          return sendEnvelope(res, null, {
            status: 404,
            errors: [{ code: "NOT_FOUND", message: "Activation not found for this organization" }],
          });
        }

        return sendEnvelope(res, result);
      } catch (err) {
        log.error("Failed to update activation", { error: String(err) });
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "INTERNAL_ERROR", message: "Failed to update activation" }],
        });
      }
    },
  );
}

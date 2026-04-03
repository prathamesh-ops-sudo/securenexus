import type { Express, Request, Response } from "express";
import { isAuthenticated } from "../auth";
import { requireMinRole, requireOrgId, resolveOrgContext } from "../rbac";
import { logger, getOrgId, sendEnvelope } from "./shared";
import {
  getAllPolicyPacks,
  getPolicyPackById,
  getPolicyPacksByDomain,
  getPolicyPackSummary,
  getPackChangelog,
  getDomainLabels,
  getStrictnessPresets,
} from "../policy-packs-engine";
import type { PolicyDomain, StrictnessPreset } from "../policy-packs-engine";
import { storage } from "../storage";

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
  // Static catalog endpoints (from engine)
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
        packs = packs.filter((pp) => pp.strictnessPreset === strictness);
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

  // Org-specific activation endpoints — persisted to DB
  app.get(
    "/api/policy-packs/org/activations",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const activations = await storage.getPolicyPackActivations(orgId);

        // Enrich activations with pack metadata
        const enriched = activations.map((activation) => {
          const pack = getPolicyPackById(activation.packId);
          return {
            ...activation,
            packName: pack?.name || activation.packId,
            packDomain: pack?.domain || "unknown",
            packStrictness: activation.strictnessOverride || pack?.strictnessPreset || "balanced",
          };
        });

        return sendEnvelope(res, enriched);
      } catch (err) {
        log.error("Failed to get org activations", { error: String(err) });
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "INTERNAL_ERROR", message: "Failed to fetch org activations" }],
        });
      }
    },
  );

  // Effective rules for a pack (combines pack catalog rules with org-level overrides from DB)
  app.get(
    "/api/policy-packs/:id/effective-rules",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const packId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;

        const pack = getPolicyPackById(packId);
        if (!pack) {
          return sendEnvelope(res, null, {
            status: 404,
            errors: [{ code: "NOT_FOUND", message: "Policy pack not found" }],
          });
        }

        // Get org activation from DB
        const activation = await storage.getPolicyPackActivation(orgId, packId);
        const disabledRules = new Set(activation?.disabledRuleIds || []);

        // Return pack rules with org-level enable/disable overlay
        const rules = pack.rules.map((rule: { id: string; [key: string]: unknown }) => ({
          ...rule,
          enabled: !disabledRules.has(rule.id),
          orgOverride: disabledRules.has(rule.id) ? "disabled" : null,
        }));

        return sendEnvelope(res, { packId, orgId, rules, activationId: activation?.id || null });
      } catch (err) {
        log.error("Failed to get effective rules", { error: String(err) });
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "INTERNAL_ERROR", message: "Failed to fetch effective rules" }],
        });
      }
    },
  );

  // Activate pack for org — persisted to DB
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
        const user = req.user as { id?: string } | undefined;

        // Verify pack exists in catalog
        const pack = getPolicyPackById(packId);
        if (!pack) {
          return sendEnvelope(res, null, {
            status: 404,
            errors: [{ code: "NOT_FOUND", message: "Policy pack not found in catalog" }],
          });
        }

        // Check if already activated
        const existing = await storage.getPolicyPackActivation(orgId, packId);
        if (existing) {
          return sendEnvelope(res, null, {
            status: 409,
            errors: [{ code: "ALREADY_ACTIVATED", message: "Policy pack is already activated for this organization" }],
          });
        }

        const strictnessOverride =
          typeof req.body.strictnessOverride === "string" &&
          VALID_STRICTNESS.includes(req.body.strictnessOverride as StrictnessPreset)
            ? req.body.strictnessOverride
            : null;

        const activation = await storage.createPolicyPackActivation({
          orgId,
          packId,
          strictnessOverride,
          enabledRuleIds: [],
          disabledRuleIds: [],
          status: "active",
          activatedBy: user?.id || "unknown",
        });

        return sendEnvelope(res, activation, { status: 201 });
      } catch (err) {
        log.error("Failed to activate policy pack", { error: String(err) });
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "INTERNAL_ERROR", message: "Failed to activate policy pack" }],
        });
      }
    },
  );

  // Deactivate pack for org — delete from DB
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

        const existing = await storage.getPolicyPackActivation(orgId, packId);
        if (!existing) {
          return sendEnvelope(res, null, {
            status: 404,
            errors: [{ code: "NOT_FOUND", message: "Activation not found for this organization" }],
          });
        }

        await storage.deletePolicyPackActivation(existing.id, orgId);
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

  // Update pack activation — persisted to DB
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

        const existing = await storage.getPolicyPackActivation(orgId, packId);
        if (!existing) {
          return sendEnvelope(res, null, {
            status: 404,
            errors: [{ code: "NOT_FOUND", message: "Activation not found for this organization" }],
          });
        }

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
          const validStatuses = ["active", "paused", "disabled"];
          if (!validStatuses.includes(req.body.status)) {
            return sendEnvelope(res, null, {
              status: 400,
              errors: [{ code: "VALIDATION_ERROR", message: "Invalid status" }],
            });
          }
          updates.status = req.body.status;
        }
        if (req.body.disabledRuleIds !== undefined) {
          if (!Array.isArray(req.body.disabledRuleIds)) {
            return sendEnvelope(res, null, {
              status: 400,
              errors: [{ code: "VALIDATION_ERROR", message: "disabledRuleIds must be an array" }],
            });
          }
          updates.disabledRuleIds = req.body.disabledRuleIds;
        }

        const result = await storage.updatePolicyPackActivation(existing.id, orgId, updates);
        if (!result) {
          return sendEnvelope(res, null, {
            status: 404,
            errors: [{ code: "NOT_FOUND", message: "Activation not found" }],
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

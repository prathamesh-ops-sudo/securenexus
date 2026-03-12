import type { Express } from "express";
import { getOrgId, sendEnvelope, storage, logger, randomBytes } from "./shared";
import { isAuthenticated } from "../auth";
import { WIZARD_STEPS } from "@shared/schema";
import { isStripeEnabled, createCheckoutSession } from "../stripe-service";
import { sendEmail } from "../email-service";
import { invitationEmail } from "../email-templates";
import { resolveOrgContext, requireOrgId } from "../rbac";

const INDUSTRY_OPTIONS = [
  "Technology",
  "Financial Services",
  "Healthcare",
  "Government",
  "Education",
  "Retail",
  "Manufacturing",
  "Energy",
  "Telecommunications",
  "Media & Entertainment",
  "Other",
] as const;

const COMPANY_SIZE_OPTIONS = ["1-10", "11-50", "51-200", "201-1000", "1001-5000", "5000+"] as const;

const PLAN_OPTIONS = [
  {
    id: "free",
    name: "Free",
    price: 0,
    features: ["Up to 5 users", "Basic alerting", "Community support", "7-day data retention"],
  },
  {
    id: "pro",
    name: "Pro",
    price: 49,
    features: [
      "Up to 50 users",
      "Advanced analytics",
      "Priority support",
      "90-day data retention",
      "Custom integrations",
    ],
  },
  {
    id: "enterprise",
    name: "Enterprise",
    price: 199,
    features: [
      "Unlimited users",
      "Full platform access",
      "Dedicated support",
      "1-year data retention",
      "SSO & SCIM",
      "Custom SLAs",
    ],
  },
] as const;

export function registerOnboardingRoutes(app: Express): void {
  app.get("/api/v1/onboarding/status", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);

      const [integrations, ingestionStats, endpoints, cspmAccounts] = await Promise.all([
        storage.getIntegrationConfigs(orgId),
        storage.getIngestionStats(orgId),
        storage.getEndpointAssets(orgId),
        storage.getCspmAccounts(orgId),
      ]);

      const hasIntegrations = integrations.length > 0;
      const hasIngestion = (ingestionStats.totalIngested ?? 0) > 0;
      const hasEndpoints = endpoints.length > 0;
      const hasCspmAccounts = cspmAccounts.length > 0;

      const completedSteps = [
        hasIntegrations && "integrations",
        hasIngestion && "ingestion",
        hasEndpoints && "endpoints",
        hasCspmAccounts && "cspm",
      ].filter(Boolean);

      const status = {
        steps: {
          integrations: { completed: hasIntegrations, count: integrations.length },
          ingestion: { completed: hasIngestion, totalIngested: ingestionStats.totalIngested ?? 0 },
          endpoints: { completed: hasEndpoints, count: endpoints.length },
          cspm: { completed: hasCspmAccounts, count: cspmAccounts.length },
        },
        completedCount: completedSteps.length,
        totalSteps: 4,
      };

      return sendEnvelope(res, status);
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "ONBOARDING_STATUS_FAILED", message: "Failed to fetch onboarding status", details: message }],
      });
    }
  });

  app.get("/api/wizard/status", isAuthenticated, async (req, res) => {
    try {
      const userId = (req as any).user?.id;
      if (!userId)
        return sendEnvelope(res, null, {
          status: 401,
          errors: [{ code: "AUTH_REQUIRED", message: "Not authenticated" }],
        });

      const progress = await storage.getWizardProgress(userId);
      if (!progress) {
        return sendEnvelope(res, {
          currentStep: 0,
          completedSteps: [],
          skippedSteps: [],
          totalSteps: WIZARD_STEPS.length,
          isComplete: false,
          steps: WIZARD_STEPS,
        });
      }

      return sendEnvelope(res, {
        currentStep: progress.currentStep,
        completedSteps: progress.completedSteps,
        skippedSteps: progress.skippedSteps,
        orgId: progress.orgId,
        totalSteps: WIZARD_STEPS.length,
        isComplete: !!progress.completedAt,
        tourCompleted: !!progress.tourCompletedAt,
        steps: WIZARD_STEPS,
      });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      logger.child("wizard").error("Failed to get wizard status", { error: message });
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "WIZARD_STATUS_FAILED", message: "Failed to fetch wizard status" }],
      });
    }
  });

  app.get("/api/wizard/options", isAuthenticated, async (_req, res) => {
    return sendEnvelope(res, {
      industries: INDUSTRY_OPTIONS,
      companySizes: COMPANY_SIZE_OPTIONS,
      plans: PLAN_OPTIONS,
    });
  });

  app.post("/api/wizard/create-org", isAuthenticated, async (req, res) => {
    try {
      const userId = (req as any).user?.id;
      const userEmail = (req as any).user?.email;
      if (!userId)
        return sendEnvelope(res, null, {
          status: 401,
          errors: [{ code: "AUTH_REQUIRED", message: "Not authenticated" }],
        });

      const existingProgress = await storage.getWizardProgress(userId);
      if (existingProgress?.orgId) {
        const existingOrg = await storage.getOrganization(existingProgress.orgId);
        if (existingOrg) {
          return sendEnvelope(res, { organization: existingOrg, alreadyCreated: true });
        }
      }

      const { name, industry, companySize } = req.body;
      if (!name || typeof name !== "string" || name.trim().length < 2 || name.trim().length > 100) {
        return sendEnvelope(res, null, {
          status: 400,
          errors: [{ code: "INVALID_ORG_NAME", message: "Organization name must be between 2 and 100 characters" }],
        });
      }

      const trimmedName = name.trim();
      const slug = `${trimmedName
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "-")
        .replace(/^-|-$/g, "")}-${Date.now()}`;

      const newOrg = await storage.createOrganization({
        name: trimmedName,
        slug,
        industry: industry || null,
        companySize: companySize || null,
        contactEmail: userEmail || undefined,
      });

      const membership = await storage.createOrgMembership({
        orgId: newOrg.id,
        userId,
        role: "owner",
        status: "active",
        joinedAt: new Date(),
      });

      await storage.upsertWizardProgress({
        userId,
        orgId: newOrg.id,
        currentStep: 1,
        completedSteps: ["create_org"],
        skippedSteps: [],
      });

      return sendEnvelope(res, { organization: newOrg, membership });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      logger.child("wizard").error("Failed to create org via wizard", { error: message });
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "WIZARD_CREATE_ORG_FAILED", message: "Failed to create organization" }],
      });
    }
  });

  app.post("/api/wizard/select-plan", isAuthenticated, async (req, res) => {
    try {
      const userId = (req as any).user?.id;
      if (!userId)
        return sendEnvelope(res, null, {
          status: 401,
          errors: [{ code: "AUTH_REQUIRED", message: "Not authenticated" }],
        });

      const { planId } = req.body;
      const validPlans = ["free", "pro", "enterprise"];
      if (!planId || !validPlans.includes(planId)) {
        return sendEnvelope(res, null, {
          status: 400,
          errors: [{ code: "INVALID_PLAN", message: "Invalid plan selection" }],
        });
      }

      const progress = await storage.getWizardProgress(userId);
      if (!progress?.orgId) {
        return sendEnvelope(res, null, {
          status: 400,
          errors: [{ code: "NO_ORG", message: "Create an organization first" }],
        });
      }

      await storage.upsertOrgPlanLimit({
        orgId: progress.orgId,
        planTier: planId,
        eventsPerMonth: planId === "free" ? 10000 : planId === "pro" ? 500000 : 9999999,
        maxConnectors: planId === "free" ? 3 : planId === "pro" ? 20 : 999,
        aiTokensPerMonth: planId === "free" ? 5000 : planId === "pro" ? 100000 : 9999999,
        automationRunsPerMonth: planId === "free" ? 100 : planId === "pro" ? 5000 : 999999,
        storageGb: planId === "free" ? 5 : planId === "pro" ? 50 : 500,
      });

      const completedSteps = Array.isArray(progress.completedSteps) ? [...(progress.completedSteps as string[])] : [];
      if (!completedSteps.includes("choose_plan")) completedSteps.push("choose_plan");

      await storage.updateWizardProgress(userId, {
        currentStep: 2,
        completedSteps,
      });

      if (planId !== "free") {
        if (isStripeEnabled()) {
          try {
            const user = (req as any).user;
            const appBaseUrl = process.env.APP_BASE_URL || "https://nexus.aricatech.xyz";
            const result = await createCheckoutSession({
              orgId: progress.orgId,
              planId,
              billingCycle: "monthly",
              successUrl: `${appBaseUrl}/onboarding-wizard?checkout=success`,
              cancelUrl: `${appBaseUrl}/onboarding-wizard?checkout=cancelled`,
              customerEmail: user?.email,
            });
            if (result?.url) {
              return sendEnvelope(res, {
                planId,
                requiresPayment: true,
                checkoutUrl: result.url,
              });
            }
          } catch (checkoutErr: unknown) {
            const errMsg = checkoutErr instanceof Error ? checkoutErr.message : String(checkoutErr);
            logger.child("wizard").warn("Stripe checkout session failed, activating as trial", { error: errMsg });
          }
        }
        return sendEnvelope(res, {
          planId,
          requiresPayment: false,
          trialActivated: true,
          message: "Plan activated as a trial. You can add payment details in Billing settings.",
        });
      }

      return sendEnvelope(res, { planId, requiresPayment: false });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      logger.child("wizard").error("Failed to select plan", { error: message });
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "WIZARD_PLAN_FAILED", message: "Failed to select plan" }],
      });
    }
  });

  app.post("/api/wizard/invite-team", isAuthenticated, async (req, res) => {
    try {
      const userId = (req as any).user?.id;
      if (!userId)
        return sendEnvelope(res, null, {
          status: 401,
          errors: [{ code: "AUTH_REQUIRED", message: "Not authenticated" }],
        });

      const progress = await storage.getWizardProgress(userId);
      if (!progress?.orgId) {
        return sendEnvelope(res, null, {
          status: 400,
          errors: [{ code: "NO_ORG", message: "Create an organization first" }],
        });
      }

      const { invitations } = req.body;
      const created: { email: string; role: string }[] = [];
      const errors: { email: string; reason: string }[] = [];

      if (Array.isArray(invitations)) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        const validRoles = ["admin", "analyst", "viewer"];
        const seen = new Set<string>();

        const org = await storage.getOrganization(progress.orgId);
        const inviterUser = (req as any).user;
        const inviterName = inviterUser?.firstName
          ? `${inviterUser.firstName} ${inviterUser.lastName || ""}`.trim()
          : "An administrator";
        const appBaseUrl = process.env.APP_BASE_URL || "https://nexus.aricatech.xyz";

        for (const inv of invitations.slice(0, 20)) {
          const email = typeof inv.email === "string" ? inv.email.trim().toLowerCase() : "";
          const role = validRoles.includes(inv.role) ? inv.role : "viewer";

          if (!email || !emailRegex.test(email)) {
            errors.push({ email: email || "(empty)", reason: "Invalid email format" });
            continue;
          }
          if (seen.has(email)) {
            errors.push({ email, reason: "Duplicate email" });
            continue;
          }
          seen.add(email);

          try {
            const token = randomBytes(32).toString("hex");
            const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
            await storage.createOrgInvitation({
              orgId: progress.orgId,
              email,
              role,
              invitedBy: userId,
              token,
              expiresAt,
            });
            created.push({ email, role });

            const acceptUrl = `${appBaseUrl}/accept-invitation?token=${token}`;

            const emailContent = invitationEmail({
              orgName: org?.name || "an organization",
              inviterName,
              role,
              acceptUrl,
              expiresAt,
            });

            sendEmail({
              to: email,
              subject: emailContent.subject,
              html: emailContent.html,
              text: emailContent.text,
            }).catch((emailErr) => {
              logger.child("wizard").error("Failed to send invitation email", { error: String(emailErr), email });
            });
          } catch (invErr: unknown) {
            const errMsg = invErr instanceof Error ? invErr.message : String(invErr);
            errors.push({ email, reason: errMsg });
          }
        }
      }

      const completedSteps = Array.isArray(progress.completedSteps) ? [...(progress.completedSteps as string[])] : [];
      if (!completedSteps.includes("invite_team")) completedSteps.push("invite_team");

      await storage.updateWizardProgress(userId, {
        currentStep: 3,
        completedSteps,
      });

      return sendEnvelope(res, { created, errors, totalInvited: created.length });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      logger.child("wizard").error("Failed to invite team", { error: message });
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "WIZARD_INVITE_FAILED", message: "Failed to invite team members" }],
      });
    }
  });

  app.post("/api/wizard/skip-step", isAuthenticated, async (req, res) => {
    try {
      const userId = (req as any).user?.id;
      if (!userId)
        return sendEnvelope(res, null, {
          status: 401,
          errors: [{ code: "AUTH_REQUIRED", message: "Not authenticated" }],
        });

      const { stepName } = req.body;
      const skippableSteps = ["choose_plan", "invite_team", "connect_integration"];
      if (!stepName || !skippableSteps.includes(stepName)) {
        return sendEnvelope(res, null, {
          status: 400,
          errors: [{ code: "INVALID_STEP", message: "This step cannot be skipped" }],
        });
      }

      const progress = await storage.getWizardProgress(userId);
      if (!progress) {
        return sendEnvelope(res, null, {
          status: 400,
          errors: [{ code: "NO_PROGRESS", message: "Start the wizard first" }],
        });
      }

      // Guard against multi-step jumps: all prior required steps must be completed or skipped
      const completedSteps = Array.isArray(progress.completedSteps) ? [...(progress.completedSteps as string[])] : [];
      const existingSkipped = Array.isArray(progress.skippedSteps) ? [...(progress.skippedSteps as string[])] : [];
      const stepIndex = WIZARD_STEPS.indexOf(stepName as (typeof WIZARD_STEPS)[number]);
      const MANDATORY_STEPS = ["create_org"] as const;
      for (let i = 0; i < stepIndex; i++) {
        const priorStep = WIZARD_STEPS[i];
        const isMandatory = MANDATORY_STEPS.includes(priorStep as (typeof MANDATORY_STEPS)[number]);
        if (!completedSteps.includes(priorStep) && !existingSkipped.includes(priorStep)) {
          if (isMandatory) {
            return sendEnvelope(res, null, {
              status: 400,
              errors: [
                {
                  code: "STEP_REQUIRED",
                  message: `Step "${priorStep}" must be completed before skipping "${stepName}"`,
                },
              ],
            });
          }
        }
      }

      const skippedSteps = [...existingSkipped];
      if (!skippedSteps.includes(stepName)) skippedSteps.push(stepName);
      if (!completedSteps.includes(stepName)) completedSteps.push(stepName);

      const nextStep = Math.min(stepIndex + 1, WIZARD_STEPS.length - 1);

      await storage.updateWizardProgress(userId, {
        currentStep: Math.max(progress.currentStep, nextStep),
        completedSteps,
        skippedSteps,
      });

      return sendEnvelope(res, { skipped: stepName, nextStep });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      logger.child("wizard").error("Failed to skip step", { error: message });
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "WIZARD_SKIP_FAILED", message: "Failed to skip step" }],
      });
    }
  });

  app.post("/api/wizard/connect-integration", isAuthenticated, async (req, res) => {
    try {
      const userId = (req as any).user?.id;
      if (!userId)
        return sendEnvelope(res, null, {
          status: 401,
          errors: [{ code: "AUTH_REQUIRED", message: "Not authenticated" }],
        });

      const progress = await storage.getWizardProgress(userId);
      if (!progress?.orgId) {
        return sendEnvelope(res, null, {
          status: 400,
          errors: [{ code: "NO_ORG", message: "Create an organization first" }],
        });
      }

      const completedSteps = Array.isArray(progress.completedSteps) ? [...(progress.completedSteps as string[])] : [];
      if (!completedSteps.includes("connect_integration")) completedSteps.push("connect_integration");

      await storage.updateWizardProgress(userId, {
        currentStep: 4,
        completedSteps,
      });

      return sendEnvelope(res, { marked: true });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      logger.child("wizard").error("Failed to mark integration step", { error: message });
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "WIZARD_INTEGRATION_FAILED", message: "Failed to complete integration step" }],
      });
    }
  });

  app.post("/api/wizard/complete-tour", isAuthenticated, async (req, res) => {
    try {
      const userId = (req as any).user?.id;
      if (!userId)
        return sendEnvelope(res, null, {
          status: 401,
          errors: [{ code: "AUTH_REQUIRED", message: "Not authenticated" }],
        });

      const progress = await storage.getWizardProgress(userId);
      if (!progress) {
        return sendEnvelope(res, null, {
          status: 400,
          errors: [{ code: "NO_PROGRESS", message: "Start the wizard first" }],
        });
      }

      const completedSteps = Array.isArray(progress.completedSteps) ? [...(progress.completedSteps as string[])] : [];
      if (!completedSteps.includes("dashboard_tour")) completedSteps.push("dashboard_tour");

      await storage.updateWizardProgress(userId, {
        currentStep: WIZARD_STEPS.length,
        completedSteps,
        tourCompletedAt: new Date(),
        completedAt: new Date(),
      });

      return sendEnvelope(res, { completed: true });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      logger.child("wizard").error("Failed to complete tour", { error: message });
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "WIZARD_TOUR_FAILED", message: "Failed to complete dashboard tour" }],
      });
    }
  });

  app.post("/api/wizard/complete", isAuthenticated, async (req, res) => {
    try {
      const userId = (req as any).user?.id;
      if (!userId)
        return sendEnvelope(res, null, {
          status: 401,
          errors: [{ code: "AUTH_REQUIRED", message: "Not authenticated" }],
        });

      const progress = await storage.getWizardProgress(userId);
      if (!progress) {
        return sendEnvelope(res, null, {
          status: 400,
          errors: [{ code: "NO_PROGRESS", message: "Start the wizard first" }],
        });
      }

      // Validate mandatory steps are actually completed (not merely skipped)
      const completedSteps = Array.isArray(progress.completedSteps) ? (progress.completedSteps as string[]) : [];
      const skippedSteps = Array.isArray(progress.skippedSteps) ? (progress.skippedSteps as string[]) : [];
      const MANDATORY_COMPLETE_STEPS = ["create_org", "choose_plan"] as const;
      const missingSteps = MANDATORY_COMPLETE_STEPS.filter(
        (s) => !completedSteps.includes(s) || skippedSteps.includes(s),
      );
      if (missingSteps.length > 0) {
        return sendEnvelope(res, null, {
          status: 400,
          errors: [
            {
              code: "STEPS_INCOMPLETE",
              message: `Complete required steps before finishing: ${missingSteps.join(", ")}`,
            },
          ],
        });
      }

      await storage.updateWizardProgress(userId, {
        completedAt: new Date(),
        currentStep: WIZARD_STEPS.length,
      });

      return sendEnvelope(res, { completed: true, orgId: progress.orgId });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      logger.child("wizard").error("Failed to complete wizard", { error: message });
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "WIZARD_COMPLETE_FAILED", message: "Failed to complete onboarding wizard" }],
      });
    }
  });
}

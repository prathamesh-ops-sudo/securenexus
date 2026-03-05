import type { Express, Request, Response } from "express";
import { isAuthenticated } from "../auth";
import { requireSuperAdmin } from "../middleware/super-admin";
import { sendEnvelope } from "./shared";
import { logger } from "../logger";
import { sendEmail, isEmailEnabled } from "../email-service";
import * as templates from "../email-templates";

const log = logger.child("email-templates-routes");

interface TemplateDescriptor {
  id: string;
  name: string;
  description: string;
  category: "auth" | "billing" | "team" | "lifecycle";
  variables: { name: string; description: string; required: boolean }[];
}

const TEMPLATE_CATALOG: TemplateDescriptor[] = [
  {
    id: "invitation",
    name: "Team Invitation",
    description: "Sent when a user is invited to join an organization",
    category: "team",
    variables: [
      { name: "recipientName", description: "Name of the invitee", required: false },
      { name: "orgName", description: "Organization name", required: true },
      { name: "inviterName", description: "Name of person who sent the invite", required: true },
      { name: "role", description: "Role being assigned", required: true },
      { name: "acceptUrl", description: "URL to accept the invitation", required: true },
      { name: "expiresAt", description: "Expiration date (ISO string)", required: true },
    ],
  },
  {
    id: "welcome",
    name: "Welcome",
    description: "Sent when a new user account is created",
    category: "auth",
    variables: [
      { name: "firstName", description: "User first name", required: false },
      { name: "email", description: "User email address", required: true },
      { name: "loginUrl", description: "Login page URL", required: true },
    ],
  },
  {
    id: "password-reset",
    name: "Password Reset",
    description: "Sent when a user requests a password reset",
    category: "auth",
    variables: [
      { name: "firstName", description: "User first name", required: false },
      { name: "resetUrl", description: "Password reset URL", required: true },
      { name: "expiresInMinutes", description: "Link expiration in minutes", required: true },
    ],
  },
  {
    id: "payment-failed",
    name: "Payment Failed",
    description: "Sent when a subscription payment fails",
    category: "billing",
    variables: [
      { name: "orgName", description: "Organization name", required: true },
      { name: "amountDue", description: "Amount that failed (e.g. $29.00)", required: true },
      { name: "retryDate", description: "When payment will be retried", required: false },
      { name: "billingUrl", description: "Billing settings URL", required: true },
    ],
  },
  {
    id: "trial-ending",
    name: "Trial Ending",
    description: "Sent when a free trial is about to expire",
    category: "billing",
    variables: [
      { name: "orgName", description: "Organization name", required: true },
      { name: "trialEndDate", description: "Trial end date string", required: true },
      { name: "billingUrl", description: "Billing/upgrade URL", required: true },
    ],
  },
  {
    id: "subscription-cancelled",
    name: "Subscription Cancelled",
    description: "Sent when a subscription is cancelled",
    category: "billing",
    variables: [
      { name: "orgName", description: "Organization name", required: true },
      { name: "accessEndDate", description: "When access expires", required: true },
      { name: "reactivateUrl", description: "URL to reactivate", required: true },
    ],
  },
  {
    id: "member-suspended",
    name: "Member Suspended",
    description: "Sent when a team member is suspended",
    category: "team",
    variables: [
      { name: "memberName", description: "Member name", required: false },
      { name: "orgName", description: "Organization name", required: true },
      { name: "reason", description: "Suspension reason", required: false },
    ],
  },
  {
    id: "member-role-changed",
    name: "Role Changed",
    description: "Sent when a member's role is updated",
    category: "team",
    variables: [
      { name: "memberName", description: "Member name", required: false },
      { name: "orgName", description: "Organization name", required: true },
      { name: "oldRole", description: "Previous role", required: true },
      { name: "newRole", description: "New role", required: true },
    ],
  },
];

const SAMPLE_DATA: Record<string, Record<string, unknown>> = {
  invitation: {
    recipientName: "Jane Smith",
    orgName: "Acme Security",
    inviterName: "John Doe",
    role: "analyst",
    acceptUrl: "https://nexus.aricatech.xyz/accept-invitation?token=sample-token",
    expiresAt: new Date(Date.now() + 7 * 86400000).toISOString(),
  },
  welcome: {
    firstName: "Jane",
    email: "jane@example.com",
    loginUrl: "https://nexus.aricatech.xyz",
  },
  "password-reset": {
    firstName: "Jane",
    resetUrl: "https://nexus.aricatech.xyz/reset-password?token=sample-token",
    expiresInMinutes: 30,
  },
  "payment-failed": {
    orgName: "Acme Security",
    amountDue: "$49.00",
    retryDate: "March 15, 2026",
    billingUrl: "https://nexus.aricatech.xyz/billing",
  },
  "trial-ending": {
    orgName: "Acme Security",
    trialEndDate: "March 20, 2026",
    billingUrl: "https://nexus.aricatech.xyz/billing",
  },
  "subscription-cancelled": {
    orgName: "Acme Security",
    accessEndDate: "April 1, 2026",
    reactivateUrl: "https://nexus.aricatech.xyz/billing",
  },
  "member-suspended": {
    memberName: "Jane Smith",
    orgName: "Acme Security",
    reason: "Policy violation",
  },
  "member-role-changed": {
    memberName: "Jane Smith",
    orgName: "Acme Security",
    oldRole: "viewer",
    newRole: "analyst",
  },
};

type TemplateGenerator = (params: Record<string, unknown>) => { subject: string; html: string; text: string };

const TEMPLATE_GENERATORS: Record<string, TemplateGenerator> = {
  invitation: (p) =>
    templates.invitationEmail({
      recipientName: p.recipientName as string | undefined,
      orgName: String(p.orgName ?? ""),
      inviterName: String(p.inviterName ?? ""),
      role: String(p.role ?? ""),
      acceptUrl: String(p.acceptUrl ?? ""),
      expiresAt: new Date(String(p.expiresAt ?? new Date().toISOString())),
    }),
  welcome: (p) =>
    templates.welcomeEmail({
      firstName: p.firstName as string | undefined,
      email: String(p.email ?? ""),
      loginUrl: String(p.loginUrl ?? ""),
    }),
  "password-reset": (p) =>
    templates.passwordResetEmail({
      firstName: p.firstName as string | undefined,
      resetUrl: String(p.resetUrl ?? ""),
      expiresInMinutes: Number(p.expiresInMinutes ?? 30),
    }),
  "payment-failed": (p) =>
    templates.paymentFailedEmail({
      orgName: String(p.orgName ?? ""),
      amountDue: String(p.amountDue ?? ""),
      retryDate: p.retryDate as string | undefined,
      billingUrl: String(p.billingUrl ?? ""),
    }),
  "trial-ending": (p) =>
    templates.trialEndingEmail({
      orgName: String(p.orgName ?? ""),
      trialEndDate: String(p.trialEndDate ?? ""),
      billingUrl: String(p.billingUrl ?? ""),
    }),
  "subscription-cancelled": (p) =>
    templates.subscriptionCancelledEmail({
      orgName: String(p.orgName ?? ""),
      accessEndDate: String(p.accessEndDate ?? ""),
      reactivateUrl: String(p.reactivateUrl ?? ""),
    }),
  "member-suspended": (p) =>
    templates.memberSuspendedEmail({
      memberName: p.memberName as string | undefined,
      orgName: String(p.orgName ?? ""),
      reason: p.reason as string | undefined,
    }),
  "member-role-changed": (p) =>
    templates.memberRoleChangedEmail({
      memberName: p.memberName as string | undefined,
      orgName: String(p.orgName ?? ""),
      oldRole: String(p.oldRole ?? ""),
      newRole: String(p.newRole ?? ""),
    }),
};

const VALID_TEMPLATE_IDS = new Set(TEMPLATE_CATALOG.map((t) => t.id));

export function registerEmailTemplateRoutes(app: Express): void {
  app.get("/api/email-templates", isAuthenticated, requireSuperAdmin, (_req: Request, res: Response) => {
    return sendEnvelope(res, TEMPLATE_CATALOG);
  });

  app.get("/api/email-templates/status", isAuthenticated, requireSuperAdmin, (_req: Request, res: Response) => {
    return sendEnvelope(res, {
      emailEnabled: isEmailEnabled(),
      fromAddress: "noreply@aricatech.xyz",
      templateCount: TEMPLATE_CATALOG.length,
      categories: Array.from(new Set(TEMPLATE_CATALOG.map((t) => t.category))),
    });
  });

  app.get("/api/email-templates/:id", isAuthenticated, requireSuperAdmin, (req: Request, res: Response) => {
    const id = String(req.params.id);
    if (!VALID_TEMPLATE_IDS.has(id)) {
      return sendEnvelope(res, null, {
        status: 404,
        errors: [{ code: "TEMPLATE_NOT_FOUND", message: `Template '${id}' not found` }],
      });
    }
    const template = TEMPLATE_CATALOG.find((t) => t.id === id);
    return sendEnvelope(res, { template, sampleData: SAMPLE_DATA[id] ?? {} });
  });

  app.post("/api/email-templates/:id/preview", isAuthenticated, requireSuperAdmin, (req: Request, res: Response) => {
    const id = String(req.params.id);
    if (!VALID_TEMPLATE_IDS.has(id)) {
      return sendEnvelope(res, null, {
        status: 404,
        errors: [{ code: "TEMPLATE_NOT_FOUND", message: `Template '${id}' not found` }],
      });
    }

    const generator = TEMPLATE_GENERATORS[id];
    if (!generator) {
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "GENERATOR_MISSING", message: "Template generator not found" }],
      });
    }

    const variables = req.body?.variables;
    const data = variables && typeof variables === "object" ? (variables as Record<string, unknown>) : SAMPLE_DATA[id];

    try {
      const result = generator(data ?? {});
      return sendEnvelope(res, { subject: result.subject, html: result.html, text: result.text });
    } catch (err) {
      log.error("Template preview failed", { templateId: id, error: String(err) });
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "PREVIEW_FAILED", message: "Failed to generate preview" }],
      });
    }
  });

  app.post(
    "/api/email-templates/:id/test-send",
    isAuthenticated,
    requireSuperAdmin,
    async (req: Request, res: Response) => {
      const id = String(req.params.id);
      if (!VALID_TEMPLATE_IDS.has(id)) {
        return sendEnvelope(res, null, {
          status: 404,
          errors: [{ code: "TEMPLATE_NOT_FOUND", message: `Template '${id}' not found` }],
        });
      }

      const { recipientEmail, variables } = req.body as {
        recipientEmail?: unknown;
        variables?: unknown;
      };

      const email = String(recipientEmail ?? "");
      if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return sendEnvelope(res, null, {
          status: 400,
          errors: [{ code: "INVALID_EMAIL", message: "A valid recipient email is required" }],
        });
      }

      const generator = TEMPLATE_GENERATORS[id];
      if (!generator) {
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "GENERATOR_MISSING", message: "Template generator not found" }],
        });
      }

      const data =
        variables && typeof variables === "object" ? (variables as Record<string, unknown>) : SAMPLE_DATA[id];

      try {
        const result = generator(data ?? {});
        const emailEnabled = isEmailEnabled();

        if (!emailEnabled) {
          log.info("Test email simulated (non-production)", { templateId: id, to: email });
          return sendEnvelope(res, {
            sent: false,
            simulated: true,
            message: "Email sending is disabled in this environment. Preview generated successfully.",
            subject: result.subject,
          });
        }

        const success = await sendEmail({
          to: email,
          subject: `[TEST] ${result.subject}`,
          html: result.html,
          text: result.text,
        });

        if (success) {
          log.info("Test email sent", { templateId: id, to: email });
          return sendEnvelope(res, { sent: true, simulated: false, message: `Test email sent to ${email}` });
        }

        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "SEND_FAILED", message: "Failed to send test email via SES" }],
        });
      } catch (err) {
        log.error("Test send failed", { templateId: id, to: email, error: String(err) });
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "SEND_FAILED", message: "Failed to send test email" }],
        });
      }
    },
  );
}

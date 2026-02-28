import type { Express, Request, Response } from "express";
import { isAuthenticated } from "../auth";
import { requireOrgId, resolveOrgContext } from "../rbac";
import { storage, logger, getOrgId, sendEnvelope } from "./shared";
import { getUsageSummary } from "../middleware/plan-enforcement";
import { sendEmail, isEmailEnabled } from "../email-service";

const log = logger.child("usage");

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

export function registerUsageRoutes(app: Express): void {
  app.get(
    "/api/usage/summary",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const summary = await getUsageSummary(orgId);
        return sendEnvelope(res, summary);
      } catch (err) {
        log.error("Failed to fetch usage summary", { error: String(err) });
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "USAGE_FETCH_FAILED", message: "Failed to fetch usage summary" }],
        });
      }
    },
  );

  app.get(
    "/api/usage/history",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const records = await storage.getUsageRecords(orgId);
        return sendEnvelope(res, records);
      } catch (err) {
        log.error("Failed to fetch usage history", { error: String(err) });
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "USAGE_HISTORY_FAILED", message: "Failed to fetch usage history" }],
        });
      }
    },
  );

  app.post(
    "/api/usage/check-limits",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const summary = await getUsageSummary(orgId);

        const warnings: { metric: string; pct: number; current: number; limit: number }[] = [];
        const critical: { metric: string; pct: number; current: number; limit: number }[] = [];

        for (const [metric, data] of Object.entries(summary.metrics)) {
          if (data.status === "warning") {
            warnings.push({ metric, pct: data.pct, current: data.current, limit: data.limit });
          } else if (data.status === "critical") {
            critical.push({ metric, pct: data.pct, current: data.current, limit: data.limit });
          }
        }

        if ((warnings.length > 0 || critical.length > 0) && isEmailEnabled()) {
          const org = await storage.getOrganization(orgId);
          if (org) {
            const orgMembers = await storage.getOrgMemberships(orgId);
            const adminEmails = orgMembers
              .filter((m) => m.role === "admin" || m.role === "owner")
              .map((m) => m.invitedEmail)
              .filter((e): e is string => Boolean(e));

            const safeName = escapeHtml(org.name);
            const appUrl = (process.env.APP_URL || "https://staging.aricatech.xyz").replace(/[^a-zA-Z0-9:/.\-_]/g, "");
            if (adminEmails.length > 0 && critical.length > 0) {
              sendEmail({
                to: adminEmails,
                subject: `[SecureNexus] Plan limit reached for ${org.name}`,
                html: `<h2>Plan Limit Reached</h2>
                  <p>The following limits have been reached for <strong>${safeName}</strong>:</p>
                  <ul>${critical.map((c) => `<li><strong>${escapeHtml(c.metric)}</strong>: ${Number(c.current)} / ${Number(c.limit)} (${Number(c.pct)}%)</li>`).join("")}</ul>
                  <p>New operations for these resources will be blocked until you upgrade your plan.</p>
                  <p><a href="${appUrl}/billing">Upgrade Plan</a></p>`,
              }).catch((err) => log.warn("Failed to send limit-reached email", { error: String(err) }));
            } else if (adminEmails.length > 0 && warnings.length > 0) {
              sendEmail({
                to: adminEmails,
                subject: `[SecureNexus] Approaching plan limits for ${org.name}`,
                html: `<h2>Approaching Plan Limits</h2>
                  <p>The following metrics are approaching limits for <strong>${safeName}</strong>:</p>
                  <ul>${warnings.map((w) => `<li><strong>${escapeHtml(w.metric)}</strong>: ${Number(w.current)} / ${Number(w.limit)} (${Number(w.pct)}%)</li>`).join("")}</ul>
                  <p>Consider upgrading your plan to avoid disruptions.</p>
                  <p><a href="${appUrl}/billing">Upgrade Plan</a></p>`,
              }).catch((err) => log.warn("Failed to send usage-warning email", { error: String(err) }));
            }
          }
        }

        return sendEnvelope(res, { warnings, critical, tier: summary.tier });
      } catch (err) {
        log.error("Failed to check limits", { error: String(err) });
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "LIMIT_CHECK_FAILED", message: "Failed to check plan limits" }],
        });
      }
    },
  );
}

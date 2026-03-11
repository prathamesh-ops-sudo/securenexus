import type { Express } from "express";
import { isAuthenticated } from "../auth";
import { sendEnvelope, logger } from "./shared";

/**
 * Phase 2 Stub Routes
 *
 * These endpoints are registered so the frontend router doesn't 404,
 * but the backing features are not yet implemented. Each returns a
 * 501 "Not Implemented" envelope so the UI can render an honest
 * "Coming Soon" state instead of displaying fake data.
 */

function notImplemented(res: any, feature: string): void {
  sendEnvelope(res, null, {
    status: 501,
    errors: [{ code: "NOT_IMPLEMENTED", message: `${feature} is not yet implemented` }],
  });
}

export function registerPhase2StubRoutes(app: Express): void {
  const log = logger.child("phase2-stubs");

  // -- CVE Browser --
  app.get("/api/v1/cves", isAuthenticated, (_req, res) => {
    notImplemented(res, "CVE Browser");
  });

  // -- Role-Based Dashboard --
  app.get("/api/dashboard/role", isAuthenticated, (_req, res) => {
    notImplemented(res, "Role-based dashboard");
  });

  // -- AI Budget --
  app.get("/api/ai/budget-usage", isAuthenticated, (_req, res) => {
    notImplemented(res, "AI budget usage tracking");
  });

  app.get("/api/ai/budget-alerts", isAuthenticated, (_req, res) => {
    notImplemented(res, "AI budget alerts");
  });

  app.patch("/api/ai/budget-config", isAuthenticated, (_req, res) => {
    notImplemented(res, "AI budget configuration");
  });

  // -- Job Queue --
  app.get("/api/jobs/stats", isAuthenticated, (_req, res) => {
    notImplemented(res, "Job queue statistics");
  });

  app.post("/api/jobs/:jobId/retry", isAuthenticated, (_req, res) => {
    notImplemented(res, "Job retry");
  });

  app.post("/api/jobs/purge-dead", isAuthenticated, (_req, res) => {
    notImplemented(res, "Job purge");
  });

  // -- Data Lifecycle --
  app.get("/api/data-lifecycle/status", isAuthenticated, (_req, res) => {
    notImplemented(res, "Data lifecycle management");
  });

  app.post("/api/data-lifecycle/purge/:policyId", isAuthenticated, (_req, res) => {
    notImplemented(res, "Data lifecycle purge");
  });

  // -- DR Drills --
  app.get("/api/dr-drills", isAuthenticated, (_req, res) => {
    notImplemented(res, "Disaster recovery drills");
  });

  app.post("/api/dr-drills", isAuthenticated, (_req, res) => {
    notImplemented(res, "Disaster recovery drill creation");
  });

  // -- Usage Metering --
  app.get("/api/usage-metering/analytics", isAuthenticated, (_req, res) => {
    notImplemented(res, "Usage metering analytics");
  });

  // -- Post-Incident Review --
  app.get("/api/pir", isAuthenticated, (_req, res) => {
    notImplemented(res, "Post-incident review");
  });
}

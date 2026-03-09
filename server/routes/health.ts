import type { Express, Request, Response } from "express";
import { getCatalogSummary, getAllEventSchemas, getEventsByDomain, type EventDomain } from "../event-catalog";
import { checkLiveness } from "../request-lifecycle";

export function registerHealthRoutes(app: Express): void {
  app.get("/api/health", (_req, res) => {
    const liveness = checkLiveness();
    res.json({
      status: "ok",
      version: "1.0.0",
      timestamp: new Date().toISOString(),
      uptime: liveness.uptime,
      pid: liveness.pid,
      memoryMB: liveness.memoryMB,
    });
  });

  // Versioned API
  app.get("/api/v1/status", async (_req, res) => {
    res.json({
      version: "1.0.0",
      name: "SecureNexus API",
      status: "operational",
      timestamp: new Date().toISOString(),
    });
  });

  app.get("/api/v1/event-catalog", (_req, res) => {
    const domain = _req.query.domain as string | undefined;
    if (domain) {
      const events = getEventsByDomain(domain as EventDomain);
      res.json({ ok: true, data: events });
      return;
    }
    res.json({ ok: true, data: { summary: getCatalogSummary(), events: getAllEventSchemas() } });
  });
}

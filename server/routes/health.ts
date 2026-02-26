import type { Express, Request, Response } from "express";
import { getCatalogSummary, getAllEventSchemas, getEventsByDomain, type EventDomain } from "../event-catalog";

export function registerHealthRoutes(app: Express): void {
  app.get("/api/health", (_req, res) => {
    res.json({ status: "ok", timestamp: new Date().toISOString() });
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

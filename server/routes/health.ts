import type { Express, Request, Response } from "express";

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

}

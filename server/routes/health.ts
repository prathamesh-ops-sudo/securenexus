import type { Express, Request, Response } from "express";
import { getCsrfEndpointHandler } from "../security-middleware";

export function registerHealthRoutes(app: Express): void {
  app.get("/api/health", (_req, res) => {
    res.json({ status: "ok", timestamp: new Date().toISOString() });
  });

  app.get("/api/csrf-token", getCsrfEndpointHandler);

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

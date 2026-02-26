import type { Express } from "express";
import type { Server } from "http";
import { setupAuth, registerAuthRoutes } from "./auth";
import { applyCsrfProtection, getCsrfEndpointHandler } from "./security-middleware";
import { startOutboxProcessor } from "./outbox-processor";
import { registerOpenApiRoutes } from "./openapi";
import { registerAllDomainRoutes } from "./routes/index";

export async function registerRoutes(
  httpServer: Server,
  app: Express
): Promise<Server> {
  await setupAuth(app);
  registerAuthRoutes(app);

  applyCsrfProtection(app);
  app.get("/api/csrf-token", getCsrfEndpointHandler);

  startOutboxProcessor();

  registerAllDomainRoutes(app);

  registerOpenApiRoutes(app);

  return httpServer;
}

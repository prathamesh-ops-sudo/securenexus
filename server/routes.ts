import type { Express } from "express";
import type { Server } from "http";
import { setupAuth, registerAuthRoutes } from "./auth";
import { applyCsrfProtection, getCsrfEndpointHandler } from "./security-middleware";
import { startOutboxProcessor } from "./outbox-processor";
import { registerOpenApiRoutes } from "./openapi";
import { registerAllDomainRoutes } from "./routes/index";
import { orgRateLimitMiddleware } from "./middleware/org-rate-limit";
import { securityPolicyEnforcement } from "./middleware/security-policy-enforcement";
import { passwordChangeRequiredMiddleware } from "./auth/password-change-enforcement";

export async function registerRoutes(httpServer: Server, app: Express): Promise<Server> {
  await setupAuth(app);
  app.use(passwordChangeRequiredMiddleware);
  registerAuthRoutes(app);

  applyCsrfProtection(app);
  app.get("/api/csrf-token", getCsrfEndpointHandler);

  app.use("/api", orgRateLimitMiddleware);
  app.use("/api", securityPolicyEnforcement);

  startOutboxProcessor();

  registerAllDomainRoutes(app);

  registerOpenApiRoutes(app);

  return httpServer;
}

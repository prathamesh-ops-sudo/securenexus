import type { Express, Request, Response } from "express";
import { eventBus } from "../event-bus";
import { replyUnauthenticated } from "../api-response";
import { resolveOrgContext } from "../rbac";

export function registerEventsRoutes(app: Express): void {
  app.get("/api/events/stream", (req: Request, res: Response) => {
    if (!req.isAuthenticated()) {
      return replyUnauthenticated(res, "Authentication required for SSE stream");
    }

    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");
    res.setHeader("X-Accel-Buffering", "no");
    res.flushHeaders();

    const orgId = (req as any).user?.orgId ?? null;
    const clientId = eventBus.generateClientId();

    const VALID_EVENT_TYPES: Set<string> = new Set([
      "alert:created",
      "alert:updated",
      "incident:created",
      "incident:updated",
      "correlation:found",
      "entity:resolved",
      "system:health",
    ]);
    const rawTypes = req.query.types as string | undefined;
    const subscriptions = rawTypes
      ? (rawTypes
          .split(",")
          .map((t) => t.trim())
          .filter((t) => VALID_EVENT_TYPES.has(t)) as any[])
      : undefined;

    eventBus.addClient({
      id: clientId,
      orgId,
      res,
      connectedAt: new Date(),
      subscriptions,
    });

    const connectEvent = {
      type: "connected",
      clientId,
      subscriptions: subscriptions || "all",
      timestamp: new Date().toISOString(),
    };
    res.write(`event: connected\ndata: ${JSON.stringify(connectEvent)}\n\n`);

    req.on("close", () => {
      eventBus.removeClient(clientId);
    });
  });

  app.get("/api/events/status", (req: Request, res: Response) => {
    if (!req.isAuthenticated()) {
      return replyUnauthenticated(res, "Authentication required");
    }

    const orgId = (req as any).user?.orgId ?? null;
    const stats = eventBus.getStats();
    res.json({
      connected: stats.totalClients,
      orgClients: orgId ? eventBus.getOrgClientCount(orgId) : 0,
      slowClients: stats.slowClients,
      totalDropped: stats.totalDropped,
      totalBuffered: stats.totalBuffered,
    });
  });
}

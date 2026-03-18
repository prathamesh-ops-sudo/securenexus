import type { Request, Response, NextFunction } from "express";
import { logger } from "./logger";

const log = logger.child("request-timeout");

/**
 * HTTP request timeout middleware.
 * Aborts slow requests before they exhaust server resources (slow loris prevention).
 * SSE/streaming endpoints are excluded since they are long-lived by design.
 */
export function requestTimeoutMiddleware(timeoutMs = 30_000) {
  return (req: Request, res: Response, next: NextFunction): void => {
    // Skip SSE/streaming endpoints — they are long-lived by design
    if (req.headers.accept === "text/event-stream" || req.path.includes("/stream") || req.path.includes("/sse")) {
      next();
      return;
    }

    // Skip health/readiness probes — they have their own timeouts
    if (
      req.path === "/api/ops/health" ||
      req.path === "/api/ops/ready" ||
      req.path === "/api/ops/live" ||
      req.path === "/api/health" ||
      req.path === "/ping"
    ) {
      next();
      return;
    }

    const timer = setTimeout(() => {
      if (!res.headersSent) {
        log.warn("Request timeout", {
          method: req.method,
          path: req.path,
          timeoutMs,
        });
        res.status(408).json({
          data: null,
          meta: {},
          errors: [{ code: "REQUEST_TIMEOUT", message: "Request timed out" }],
        });
      }
    }, timeoutMs);

    // Clean up timer when response finishes
    res.on("finish", () => clearTimeout(timer));
    res.on("close", () => clearTimeout(timer));

    next();
  };
}

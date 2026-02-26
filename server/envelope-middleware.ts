import type { Request, Response, NextFunction } from "express";
import type { ApiEnvelope, ApiMeta } from "./api-response";
import { ERROR_CODES } from "./api-response";
import { currentContext } from "./logger";

// ─── Shape detection ─────────────────────────────────────────────────────────
// Returns true when the body already conforms to { data, meta, errors }.

function isEnvelope(body: unknown): body is ApiEnvelope {
  if (typeof body !== "object" || body === null || Array.isArray(body)) return false;
  const obj = body as Record<string, unknown>;
  return (
    "data" in obj &&
    "meta" in obj &&
    "errors" in obj &&
    typeof obj.meta === "object" &&
    (obj.errors === null || Array.isArray(obj.errors))
  );
}

// ─── Map HTTP status to canonical error code ─────────────────────────────────

function statusToErrorCode(status: number): string {
  switch (status) {
    case 400: return ERROR_CODES.BAD_REQUEST;
    case 401: return ERROR_CODES.UNAUTHENTICATED;
    case 403: return ERROR_CODES.FORBIDDEN;
    case 404: return ERROR_CODES.NOT_FOUND;
    case 409: return ERROR_CODES.CONFLICT;
    case 422: return ERROR_CODES.VALIDATION_ERROR;
    case 429: return ERROR_CODES.RATE_LIMITED;
    case 501: return ERROR_CODES.NOT_IMPLEMENTED;
    case 502: return ERROR_CODES.UPSTREAM_ERROR;
    default:  return ERROR_CODES.INTERNAL_ERROR;
  }
}

// ─── Extract a human-readable message from a legacy error body ───────────────

function extractMessage(body: Record<string, unknown>): string {
  if (typeof body.message === "string") return body.message;
  if (typeof body.error === "string") return body.error;
  return "An error occurred";
}

// ─── Middleware ───────────────────────────────────────────────────────────────
// Monkey-patches res.json() so every JSON response leaving the server conforms
// to the ApiEnvelope shape.  Responses that are already enveloped (produced by
// the reply* helpers in api-response.ts) pass through untouched.

export function envelopeMiddleware(req: Request, res: Response, next: NextFunction): void {
  const originalJson = res.json.bind(res);

  res.json = function wrappedJson(body?: any): Response {
    // Non-API paths (health probes at /ops/*, static assets, etc.) pass through.
    if (!req.path.startsWith("/api")) {
      return originalJson(body);
    }

    // Already an envelope – pass through.
    if (isEnvelope(body)) {
      return originalJson(body);
    }

    const status = res.statusCode;

    const requestId = currentContext().requestId ?? (res.getHeader("x-request-id") as string | undefined);
    const baseMeta: ApiMeta = requestId ? { requestId } : {};

    // Error responses (4xx / 5xx)
    if (status >= 400) {
      const message = (typeof body === "object" && body !== null && !Array.isArray(body))
        ? extractMessage(body as Record<string, unknown>)
        : "An error occurred";

      const code = statusToErrorCode(status);

      // Preserve Zod validation details when present.
      const details = (typeof body === "object" && body !== null && (body as any).errors)
        ? (body as any).errors
        : undefined;

      const envelope: ApiEnvelope<null> = {
        data: null,
        meta: baseMeta,
        errors: [{ code, message, ...(details ? { details } : {}) }],
      };
      return originalJson(envelope);
    }

    // Success responses – wrap data.
    const envelope: ApiEnvelope = { data: body ?? null, meta: baseMeta, errors: null };
    return originalJson(envelope);
  } as any;

  next();
}

// ─── Legacy deprecation middleware ───────────────────────────────────────────
// Adds RFC 8594 Deprecation + Sunset headers to any /api/* route that does NOT
// contain a version prefix (e.g. /api/v1/).  This lets consumers discover that
// un-versioned endpoints will be removed on LEGACY_SUNSET_DATE.

import { LEGACY_SUNSET_DATE } from "./api-response";

const V_PREFIX_RE = /^\/api\/v\d+\//;

export function autoDeprecationMiddleware(req: Request, res: Response, next: NextFunction): void {
  if (req.path.startsWith("/api/") && !V_PREFIX_RE.test(req.path)) {
    // Build the v1 successor path heuristically: /api/foo → /api/v1/foo
    const successor = req.path.replace(/^\/api\//, "/api/v1/");
    res.set("Deprecation", "true");
    res.set("Sunset", new Date(LEGACY_SUNSET_DATE).toUTCString());
    res.set("Link", `<${successor}>; rel="successor-version"`);
  }
  next();
}

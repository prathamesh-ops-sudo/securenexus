import { QueryClient, QueryFunction } from "@tanstack/react-query";

let csrfTokenCache: string | null = null;
let csrfTokenFetchedAt = 0;
const CSRF_CACHE_TTL_MS = 5 * 60 * 1000;

export function clearCsrfTokenCache(): void {
  csrfTokenCache = null;
  csrfTokenFetchedAt = 0;
}

export async function fetchCsrfToken(): Promise<string | null> {
  if (csrfTokenCache && Date.now() - csrfTokenFetchedAt < CSRF_CACHE_TTL_MS) {
    return csrfTokenCache;
  }
  try {
    const res = await fetch("/api/csrf-token", { credentials: "include" });
    if (res.ok) {
      const body = await res.json();
      csrfTokenCache = body.data?.token ?? body.token ?? null;
      csrfTokenFetchedAt = Date.now();
      return csrfTokenCache;
    }
  } catch {
    /* network error — proceed without token */
  }
  return null;
}

// ─── Envelope-aware helpers ──────────────────────────────────────────────────
// Every API response is now wrapped: { data, meta, errors }.

interface ApiEnvelope<T = unknown> {
  data: T | null;
  meta: Record<string, unknown>;
  errors: { code: string; message: string; field?: string; details?: unknown }[] | null;
}

export class ApiRequestError extends Error {
  readonly status: number;
  readonly code?: string;

  constructor(status: number, message: string, code?: string) {
    super(`${status}: ${message}`);
    this.name = "ApiRequestError";
    this.status = status;
    this.code = code;
  }
}

function isEnvelope(body: unknown): body is ApiEnvelope {
  if (typeof body !== "object" || body === null || Array.isArray(body)) return false;
  const obj = body as Record<string, unknown>;
  return "data" in obj && "meta" in obj && "errors" in obj;
}

function firstApiError(body: unknown): { code: string; message: string } | null {
  if (!isEnvelope(body) || !Array.isArray(body.errors) || body.errors.length === 0) {
    return null;
  }

  const [error] = body.errors;
  return error && typeof error.code === "string" && typeof error.message === "string"
    ? { code: error.code, message: error.message }
    : null;
}

/** Extract a human-readable error string from an envelope (or fall back to raw text). */
export function extractApiError(body: unknown, fallback: string): string {
  const apiError = firstApiError(body);
  if (apiError) {
    return apiError.message;
  }
  if (typeof body === "object" && body !== null && "message" in body) {
    return String((body as any).message);
  }
  return fallback;
}

/** Unwrap the `.data` field from an envelope, or return the body as-is for non-enveloped responses. */
function unwrapEnvelope<T>(body: unknown): T {
  if (isEnvelope(body)) {
    return body.data as T;
  }
  return body as T;
}

/**
 * Safely extract an array from a value that may be a raw array, an envelope
 * `{ data: [...] }`, or something else entirely.  Returns `[]` when the value
 * is not coercible to an array.  Use at every consumption-point where query
 * data is expected to be an array — this guards against the Response.json()
 * override not firing (browser compat) and against stale React-Query cache
 * entries that predate the envelope unwrap logic.
 */
export function ensureArray<T = unknown>(val: unknown): T[] {
  if (Array.isArray(val)) return val;
  if (val && typeof val === "object" && "data" in val) {
    const inner = (val as Record<string, unknown>).data;
    if (Array.isArray(inner)) return inner;
  }
  return [];
}

// ─── Request helpers ─────────────────────────────────────────────────────────

async function throwIfResNotOk(res: Response) {
  if (!res.ok) {
    let errorMessage: string = res.statusText;
    let errorCode: string | undefined;
    try {
      const body = await res.json();
      const apiError = firstApiError(body);
      errorMessage = apiError?.message ?? extractApiError(body, res.statusText);
      errorCode = apiError?.code;
    } catch {
      // Body wasn't JSON – use statusText.
    }
    throw new ApiRequestError(res.status, errorMessage, errorCode);
  }
}

export async function apiRequest(method: string, url: string, data?: unknown | undefined): Promise<Response> {
  const headers: Record<string, string> = {};
  if (data) {
    headers["Content-Type"] = "application/json";
  }
  if (method !== "GET" && method !== "HEAD") {
    const csrfToken = await fetchCsrfToken();
    if (csrfToken) headers["X-CSRF-Token"] = csrfToken;
  }
  try {
    const activeOrgId = localStorage.getItem("securenexus.activeOrgId");
    if (activeOrgId) headers["X-Org-Id"] = activeOrgId;
  } catch {
    /* SSR / privacy mode */
  }
  const res = await fetch(url, {
    method,
    headers,
    body: data ? JSON.stringify(data) : undefined,
    credentials: "include",
  });

  await throwIfResNotOk(res);

  // Override .json() so callers automatically receive the unwrapped payload
  // rather than the raw envelope.  The body stream can only be consumed once,
  // so this is safe from double-unwrap issues.
  try {
    const originalJson = res.json.bind(res);
    const patchedJson = async () => {
      const body = await originalJson();
      return unwrapEnvelope(body);
    };
    Object.defineProperty(res, "json", {
      value: patchedJson,
      writable: true,
      configurable: true,
    });
  } catch {
    // Fallback: some environments disallow property override on Response.
    // Callers should use ensureArray() as a safety net.
  }

  return res;
}

type UnauthorizedBehavior = "returnNull" | "throw";
export const getQueryFn: <T>(options: { on401: UnauthorizedBehavior }) => QueryFunction<T> =
  ({ on401: unauthorizedBehavior }) =>
  async ({ queryKey }) => {
    const reqHeaders: Record<string, string> = {};
    try {
      const activeOrgId = localStorage.getItem("securenexus.activeOrgId");
      if (activeOrgId) reqHeaders["X-Org-Id"] = activeOrgId;
    } catch {
      /* SSR / privacy mode */
    }
    const res = await fetch(queryKey.join("/") as string, {
      credentials: "include",
      headers: reqHeaders,
    });

    if (unauthorizedBehavior === "returnNull" && res.status === 401) {
      return null;
    }

    await throwIfResNotOk(res);
    const body = await res.json();
    return unwrapEnvelope(body) as Awaited<ReturnType<QueryFunction<any>>>;
  };

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
}

export async function fetchPaginated<T>(
  basePath: string,
  params: Record<string, string | number | undefined>,
): Promise<PaginatedResponse<T>> {
  const reqHeaders: Record<string, string> = {};
  try {
    const activeOrgId = localStorage.getItem("securenexus.activeOrgId");
    if (activeOrgId) reqHeaders["X-Org-Id"] = activeOrgId;
  } catch {
    /* SSR / privacy mode */
  }
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== "") qs.set(k, String(v));
  }
  const url = qs.toString() ? `${basePath}?${qs.toString()}` : basePath;
  const res = await fetch(url, { credentials: "include", headers: reqHeaders });
  await throwIfResNotOk(res);
  const body = await res.json();
  if (isEnvelope(body)) {
    const meta = body.meta as Record<string, unknown>;
    return {
      items: (body.data ?? []) as T[],
      total: typeof meta.total === "number" ? meta.total : 0,
    };
  }
  const arr = Array.isArray(body) ? body : [];
  return { items: arr as T[], total: arr.length };
}

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      queryFn: getQueryFn({ on401: "throw" }),
      refetchInterval: false,
      refetchOnWindowFocus: false,
      staleTime: Infinity,
      retry: false,
    },
    mutations: {
      retry: false,
    },
  },
});

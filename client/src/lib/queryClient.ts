import { QueryClient, QueryFunction } from "@tanstack/react-query";

function getCsrfToken(): string | null {
  const match = document.cookie.match(/(?:^|;\s*)XSRF-TOKEN=([^;]*)/);
  return match ? decodeURIComponent(match[1]) : null;
}

// ─── Envelope-aware helpers ──────────────────────────────────────────────────
// Every API response is now wrapped: { data, meta, errors }.

interface ApiEnvelope<T = unknown> {
  data: T | null;
  meta: Record<string, unknown>;
  errors: { code: string; message: string; field?: string; details?: unknown }[] | null;
}

function isEnvelope(body: unknown): body is ApiEnvelope {
  if (typeof body !== "object" || body === null || Array.isArray(body)) return false;
  const obj = body as Record<string, unknown>;
  return "data" in obj && "meta" in obj && "errors" in obj;
}

/** Extract a human-readable error string from an envelope (or fall back to raw text). */
export function extractApiError(body: unknown, fallback: string): string {
  if (isEnvelope(body) && Array.isArray(body.errors) && body.errors.length > 0) {
    return body.errors[0].message;
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

// ─── Request helpers ─────────────────────────────────────────────────────────

async function throwIfResNotOk(res: Response) {
  if (!res.ok) {
    let errorMessage: string = res.statusText;
    try {
      const body = await res.json();
      errorMessage = extractApiError(body, res.statusText);
    } catch {
      // Body wasn't JSON – use statusText.
    }
    throw new Error(`${res.status}: ${errorMessage}`);
  }
}

export async function apiRequest(method: string, url: string, data?: unknown | undefined): Promise<Response> {
  const headers: Record<string, string> = {};
  if (data) {
    headers["Content-Type"] = "application/json";
  }
  const csrfToken = getCsrfToken();
  if (csrfToken && method !== "GET" && method !== "HEAD") {
    headers["X-CSRF-Token"] = csrfToken;
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
  const originalJson = res.json.bind(res);
  (res as any).json = async () => {
    const body = await originalJson();
    return unwrapEnvelope(body);
  };

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

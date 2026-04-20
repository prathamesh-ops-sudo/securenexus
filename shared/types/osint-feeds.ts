/**
 * Shape of an OSINT indicator feed's status record, as returned by the
 * `/api/osint-feeds/status` endpoint (server/osint-feeds.ts) and consumed by
 * the OSINT Feeds configuration page (client/src/pages/osint-feeds-config.tsx).
 *
 * Declared here so the server handler and client page cannot drift.
 *
 * NOTE: The `FeedStatus` interfaces in `client/src/pages/threat-intel-feeds.tsx`
 * and `client/src/pages/threat-intel.tsx` describe different endpoints
 * (RSS/blog threat intel article feeds) and are intentionally NOT consolidated
 * with this type.
 */
export interface FeedStatus {
  name: string;
  slug: string;
  url: string;
  description: string;
  category: string;
  indicatorTypes: string[];
  lastFetched: string | null;
  lastSuccess: string | null;
  lastError: string | null;
  lastErrorMessage: string | null;
  totalIndicators: number;
  status: "success" | "error" | "never_fetched";
  enabled: boolean;
  refreshIntervalMinutes: number;
  successRate: number;
  avgResponseTimeMs: number;
  totalFetches: number;
  consecutiveErrors: number;
  requiresApiKey: false;
}

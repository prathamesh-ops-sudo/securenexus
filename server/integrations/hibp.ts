import { logger } from "../logger";

const log = logger.child("hibp-integration");

export interface HibpBreach {
  Name: string;
  Title: string;
  Domain: string;
  BreachDate: string;
  AddedDate: string;
  ModifiedDate: string;
  PwnCount: number;
  Description: string;
  LogoPath: string;
  DataClasses: string[];
  IsVerified: boolean;
  IsFabricated: boolean;
  IsSensitive: boolean;
  IsRetired: boolean;
  IsSpamList: boolean;
}

export interface HibpPaste {
  Id: string;
  Source: string;
  Title: string;
  Date: string;
  EmailCount: number;
}

const HIBP_BASE_URL = "https://haveibeenpwned.com/api/v3";
const HIBP_USER_AGENT = "SecureNexus-DarkWebMonitor";

/**
 * Check if an email address appears in any known data breaches via HIBP API.
 * Requires a paid HIBP API key for production use.
 */
export async function checkEmailBreaches(email: string, apiKey: string | null): Promise<HibpBreach[]> {
  if (!apiKey) {
    log.warn("HIBP API key not configured — returning empty results");
    return [];
  }

  try {
    const resp = await fetch(`${HIBP_BASE_URL}/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`, {
      headers: {
        "hibp-api-key": apiKey,
        "user-agent": HIBP_USER_AGENT,
      },
    });

    if (resp.status === 404) return []; // No breaches found
    if (resp.status === 429) {
      log.warn("HIBP rate limit hit — retry after delay");
      return [];
    }
    if (!resp.ok) {
      log.error("HIBP API error", { status: resp.status, statusText: resp.statusText });
      return [];
    }

    const data: HibpBreach[] = await resp.json();
    return data.filter((b) => !b.IsRetired && !b.IsFabricated && !b.IsSpamList);
  } catch (error) {
    log.error("Failed to check HIBP breaches", { email: email.replace(/@.*/, "@***"), error: String(error) });
    return [];
  }
}

/**
 * Check if an email appears in any pastes (paste sites like Pastebin).
 */
export async function checkEmailPastes(email: string, apiKey: string | null): Promise<HibpPaste[]> {
  if (!apiKey) return [];

  try {
    const resp = await fetch(`${HIBP_BASE_URL}/pasteaccount/${encodeURIComponent(email)}`, {
      headers: {
        "hibp-api-key": apiKey,
        "user-agent": HIBP_USER_AGENT,
      },
    });

    if (resp.status === 404) return [];
    if (resp.status === 429) return [];
    if (!resp.ok) return [];

    return await resp.json();
  } catch (error) {
    log.error("Failed to check HIBP pastes", { error: String(error) });
    return [];
  }
}

/**
 * Get all known breaches in the HIBP database (no API key required for this endpoint).
 */
export async function getAllBreaches(): Promise<HibpBreach[]> {
  try {
    const resp = await fetch(`${HIBP_BASE_URL}/breaches`, {
      headers: { "user-agent": HIBP_USER_AGENT },
    });

    if (!resp.ok) return [];
    return await resp.json();
  } catch (error) {
    log.error("Failed to fetch all breaches", { error: String(error) });
    return [];
  }
}

/**
 * Check a domain against known breaches.
 * Returns breaches where the domain matches.
 */
export async function checkDomainBreaches(domain: string): Promise<HibpBreach[]> {
  try {
    const allBreaches = await getAllBreaches();
    return allBreaches.filter(
      (b) => b.Domain.toLowerCase() === domain.toLowerCase() && !b.IsRetired && !b.IsFabricated,
    );
  } catch (error) {
    log.error("Failed to check domain breaches", { error: String(error) });
    return [];
  }
}

/**
 * Map HIBP breach severity based on data classes exposed.
 */
export function assessBreachSeverity(breach: HibpBreach): "critical" | "high" | "medium" | "low" {
  const criticalData = ["Passwords", "Credit cards", "Bank account numbers", "Social security numbers"];
  const highData = ["Email addresses", "Phone numbers", "Physical addresses", "Dates of birth"];

  const hasCritical = breach.DataClasses.some((dc) => criticalData.includes(dc));
  const hasHigh = breach.DataClasses.some((dc) => highData.includes(dc));

  if (hasCritical && breach.PwnCount > 1_000_000) return "critical";
  if (hasCritical) return "high";
  if (hasHigh && breach.PwnCount > 500_000) return "high";
  if (hasHigh) return "medium";
  return "low";
}

/**
 * Map HIBP paste to a severity level.
 */
export function assessPasteSeverity(paste: HibpPaste): "high" | "medium" | "low" {
  if (paste.EmailCount > 10_000) return "high";
  if (paste.EmailCount > 1_000) return "medium";
  return "low";
}

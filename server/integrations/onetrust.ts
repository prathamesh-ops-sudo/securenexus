/**
 * OneTrust Consent Management Integration
 *
 * Provides connectivity to OneTrust and Cookiebot consent management platforms.
 * Syncs consent records, manages consent preferences, and tracks consent lifecycle.
 */

import { logger } from "../logger";

const log = logger.child("onetrust-integration");

// ── Types ───────────────────────────────────────────────────────────

export interface OneTrustConfig {
  apiKey: string;
  baseUrl: string; // e.g. https://app.onetrust.com/api
  orgExternalId?: string;
}

export interface CookiebotConfig {
  apiKey: string;
  domainGroupId: string;
}

export interface ConsentPreference {
  subjectId: string;
  email?: string;
  purpose: string;
  granted: boolean;
  source: string;
  consentVersion?: string;
  grantedAt?: Date;
  withdrawnAt?: Date;
  expiresAt?: Date;
  metadata?: Record<string, unknown>;
}

export interface ConsentSyncResult {
  synced: number;
  created: number;
  updated: number;
  errors: string[];
}

// ── OneTrust Client ─────────────────────────────────────────────────

export class OneTrustClient {
  private config: OneTrustConfig;

  constructor(config: OneTrustConfig) {
    this.config = config;
  }

  /**
   * Fetch consent records from OneTrust for a given purpose
   */
  async fetchConsents(purpose: string, page = 0, size = 100): Promise<ConsentPreference[]> {
    try {
      const url = `${this.config.baseUrl}/consentmanager/v2/consent-receipts?purpose=${encodeURIComponent(purpose)}&page=${page}&size=${size}`;
      const response = await fetch(url, {
        headers: {
          Authorization: `Bearer ${this.config.apiKey}`,
          "Content-Type": "application/json",
        },
      });

      if (!response.ok) {
        log.error("OneTrust API error", { status: response.status, statusText: response.statusText });
        return [];
      }

      const data = (await response.json()) as {
        content?: Array<{
          identifier: string;
          email?: string;
          purposeId: string;
          consentStatus: string;
          consentVersion?: string;
          lastTransactionDate?: string;
          expiryDate?: string;
        }>;
      };

      return (data.content || []).map((record) => ({
        subjectId: record.identifier,
        email: record.email,
        purpose,
        granted: record.consentStatus === "ACTIVE" || record.consentStatus === "OPT_IN",
        source: "onetrust",
        consentVersion: record.consentVersion,
        grantedAt: record.lastTransactionDate ? new Date(record.lastTransactionDate) : undefined,
        withdrawnAt:
          record.consentStatus === "WITHDRAWN" && record.lastTransactionDate
            ? new Date(record.lastTransactionDate)
            : undefined,
        expiresAt: record.expiryDate ? new Date(record.expiryDate) : undefined,
      }));
    } catch (err) {
      log.error("Failed to fetch OneTrust consents", { error: String(err), purpose });
      return [];
    }
  }

  /**
   * Submit a consent withdrawal to OneTrust
   */
  async withdrawConsent(subjectId: string, purpose: string): Promise<boolean> {
    try {
      const url = `${this.config.baseUrl}/consentmanager/v2/consent-receipts/withdraw`;
      const response = await fetch(url, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${this.config.apiKey}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          identifier: subjectId,
          purposeId: purpose,
          status: "WITHDRAWN",
        }),
      });
      return response.ok;
    } catch (err) {
      log.error("Failed to withdraw consent in OneTrust", { error: String(err), subjectId, purpose });
      return false;
    }
  }

  /**
   * Check connection health
   */
  async healthCheck(): Promise<{ connected: boolean; version?: string; error?: string }> {
    try {
      const url = `${this.config.baseUrl}/consentmanager/v2/health`;
      const response = await fetch(url, {
        headers: { Authorization: `Bearer ${this.config.apiKey}` },
      });
      if (response.ok) {
        return { connected: true, version: "v2" };
      }
      return { connected: false, error: `HTTP ${response.status}` };
    } catch (err) {
      return { connected: false, error: String(err) };
    }
  }
}

// ── Cookiebot Client ────────────────────────────────────────────────

export class CookiebotClient {
  private config: CookiebotConfig;

  constructor(config: CookiebotConfig) {
    this.config = config;
  }

  /**
   * Fetch consent statistics from Cookiebot
   */
  async fetchConsentStats(): Promise<{
    totalConsents: number;
    acceptAll: number;
    rejectAll: number;
    customized: number;
  }> {
    try {
      const url = `https://consent.cookiebot.com/api/v1/${this.config.domainGroupId}/consent-statistics`;
      const response = await fetch(url, {
        headers: {
          Authorization: `Bearer ${this.config.apiKey}`,
          "Content-Type": "application/json",
        },
      });

      if (!response.ok) {
        log.error("Cookiebot API error", { status: response.status });
        return { totalConsents: 0, acceptAll: 0, rejectAll: 0, customized: 0 };
      }

      const data = (await response.json()) as {
        totalConsents?: number;
        acceptAll?: number;
        rejectAll?: number;
        customized?: number;
      };
      return {
        totalConsents: data.totalConsents ?? 0,
        acceptAll: data.acceptAll ?? 0,
        rejectAll: data.rejectAll ?? 0,
        customized: data.customized ?? 0,
      };
    } catch (err) {
      log.error("Failed to fetch Cookiebot stats", { error: String(err) });
      return { totalConsents: 0, acceptAll: 0, rejectAll: 0, customized: 0 };
    }
  }

  /**
   * Check connection health
   */
  async healthCheck(): Promise<{ connected: boolean; error?: string }> {
    try {
      const url = `https://consent.cookiebot.com/api/v1/${this.config.domainGroupId}/status`;
      const response = await fetch(url, {
        headers: { Authorization: `Bearer ${this.config.apiKey}` },
      });
      return { connected: response.ok };
    } catch (err) {
      return { connected: false, error: String(err) };
    }
  }
}

// ── Consent Sync Helper ─────────────────────────────────────────────

/**
 * Sync consent records from an external provider into our consent_records table
 */
export async function syncConsentRecords(orgId: string, preferences: ConsentPreference[]): Promise<ConsentSyncResult> {
  const { db } = await import("../db");
  const { consentRecords } = await import("../../shared/schema");
  const { eq, and } = await import("drizzle-orm");

  const result: ConsentSyncResult = { synced: 0, created: 0, updated: 0, errors: [] };

  for (const pref of preferences) {
    try {
      // Check if record exists
      const [existing] = await db
        .select()
        .from(consentRecords)
        .where(
          and(
            eq(consentRecords.orgId, orgId),
            eq(consentRecords.dataSubjectId, pref.subjectId),
            eq(consentRecords.purpose, pref.purpose),
          ),
        )
        .limit(1);

      if (existing) {
        await db
          .update(consentRecords)
          .set({
            granted: pref.granted,
            source: pref.source,
            consentVersion: pref.consentVersion ?? existing.consentVersion,
            grantedAt: pref.grantedAt ?? existing.grantedAt,
            withdrawnAt: pref.withdrawnAt ?? existing.withdrawnAt,
            expiresAt: pref.expiresAt ?? existing.expiresAt,
            updatedAt: new Date(),
          })
          .where(eq(consentRecords.id, existing.id));
        result.updated++;
      } else {
        await db.insert(consentRecords).values({
          orgId,
          dataSubjectId: pref.subjectId,
          dataSubjectEmail: pref.email ?? null,
          purpose: pref.purpose,
          granted: pref.granted,
          source: pref.source,
          consentVersion: pref.consentVersion ?? null,
          grantedAt: pref.grantedAt ?? null,
          withdrawnAt: pref.withdrawnAt ?? null,
          expiresAt: pref.expiresAt ?? null,
        });
        result.created++;
      }
      result.synced++;
    } catch (err) {
      result.errors.push(`Failed to sync consent for ${pref.subjectId}/${pref.purpose}: ${String(err)}`);
    }
  }

  log.info("Consent sync completed", { orgId, ...result });
  return result;
}

import { pool } from "./db";
import { logger } from "./logger";
import { getPodId } from "./scaling-state";

const log = logger.child("distributed-concurrency");

const STALE_SLOT_TIMEOUT_MS = 5 * 60 * 1000;
const ENSURE_ROW_CACHE = new Set<string>();

async function ensureProviderRow(provider: string, maxConcurrency: number): Promise<void> {
  if (ENSURE_ROW_CACHE.has(provider)) return;
  await pool.query(
    `INSERT INTO connector_provider_state (provider, active_count, max_concurrency, backoff_factor, updated_at)
     VALUES ($1, 0, $2, 1, NOW())
     ON CONFLICT (provider) DO NOTHING`,
    [provider, maxConcurrency],
  );
  ENSURE_ROW_CACHE.add(provider);
}

export async function distributedAcquireSlot(provider: string, maxConcurrency: number): Promise<boolean> {
  await ensureProviderRow(provider, maxConcurrency);

  const result = await pool.query(
    `UPDATE connector_provider_state
     SET active_count = active_count + 1, updated_at = NOW()
     WHERE provider = $1
       AND active_count < max_concurrency
       AND (backoff_until IS NULL OR backoff_until <= NOW())
     RETURNING active_count`,
    [provider],
  );

  return result.rowCount !== null && result.rowCount > 0;
}

export async function distributedReleaseSlot(provider: string): Promise<void> {
  const result = await pool.query(
    `UPDATE connector_provider_state
     SET active_count = GREATEST(0, active_count - 1), updated_at = NOW()
     WHERE provider = $1
     RETURNING active_count`,
    [provider],
  );

  if (result.rowCount === 0) {
    log.warn("Release called for unknown provider", { provider, podId: getPodId() });
  }
}

export async function distributedCheckBackoff(provider: string): Promise<number> {
  const result = await pool.query(`SELECT backoff_until FROM connector_provider_state WHERE provider = $1`, [provider]);

  if (result.rows.length === 0) return 0;

  const row = result.rows[0] as { backoff_until: Date | null };
  if (!row.backoff_until) return 0;

  const remaining = new Date(row.backoff_until).getTime() - Date.now();
  return remaining > 0 ? remaining : 0;
}

export async function distributedApplyBackoff(provider: string): Promise<void> {
  await ensureProviderRow(provider, 3);

  const result = await pool.query(
    `UPDATE connector_provider_state
     SET backoff_factor = LEAST(backoff_factor * 2, 64),
         backoff_until = NOW() + (LEAST(backoff_factor * 2, 64) || ' seconds')::interval,
         updated_at = NOW()
     WHERE provider = $1
     RETURNING backoff_factor`,
    [provider],
  );

  const factor = (result.rows[0] as { backoff_factor: number } | undefined)?.backoff_factor ?? 2;
  log.warn("Provider backoff applied (distributed)", {
    provider,
    factor,
    podId: getPodId(),
  });
}

export async function distributedClearBackoff(provider: string): Promise<void> {
  await pool.query(
    `UPDATE connector_provider_state
     SET backoff_until = NULL, backoff_factor = 1, updated_at = NOW()
     WHERE provider = $1`,
    [provider],
  );
}

export async function distributedSetMaxConcurrency(provider: string, max: number): Promise<void> {
  await ensureProviderRow(provider, max);

  await pool.query(
    `UPDATE connector_provider_state
     SET max_concurrency = $2, updated_at = NOW()
     WHERE provider = $1`,
    [provider, max],
  );
}

export async function distributedGetProviderStats(): Promise<
  Record<string, { active: number; maxConcurrency: number; backoffMs: number; waiting: number }>
> {
  const result = await pool.query(
    `SELECT provider, active_count, max_concurrency, backoff_until
     FROM connector_provider_state`,
  );

  const stats: Record<string, { active: number; maxConcurrency: number; backoffMs: number; waiting: number }> = {};

  for (const row of result.rows as Array<{
    provider: string;
    active_count: number;
    max_concurrency: number;
    backoff_until: Date | null;
  }>) {
    let backoffMs = 0;
    if (row.backoff_until) {
      const remaining = new Date(row.backoff_until).getTime() - Date.now();
      if (remaining > 0) backoffMs = remaining;
    }
    stats[row.provider] = {
      active: row.active_count,
      maxConcurrency: row.max_concurrency,
      backoffMs,
      waiting: 0,
    };
  }

  return stats;
}

export async function reapStaleSlots(): Promise<number> {
  const threshold = new Date(Date.now() - STALE_SLOT_TIMEOUT_MS);

  const result = await pool.query(
    `UPDATE connector_provider_state
     SET active_count = 0, updated_at = NOW()
     WHERE active_count > 0
       AND updated_at < $1
     RETURNING provider, active_count`,
    [threshold],
  );

  const reaped = result.rowCount ?? 0;
  if (reaped > 0) {
    log.warn("Reaped stale provider slots", {
      count: reaped,
      providers: (result.rows as Array<{ provider: string }>).map((r) => r.provider),
      podId: getPodId(),
    });
  }

  return reaped;
}

let reapInterval: ReturnType<typeof setInterval> | null = null;

export function startStaleSlotReaper(intervalMs: number = 60_000): void {
  if (reapInterval) return;
  reapInterval = setInterval(() => {
    reapStaleSlots().catch((err) => {
      log.error("Stale slot reaper failed", { error: String(err) });
    });
  }, intervalMs);
  log.info("Stale slot reaper started", { intervalMs, podId: getPodId() });
}

export function stopStaleSlotReaper(): void {
  if (reapInterval) {
    clearInterval(reapInterval);
    reapInterval = null;
  }
}

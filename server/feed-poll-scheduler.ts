import { scheduleJob } from "./job-queue";
import { logger } from "./logger";

const SCHEDULER_INTERVAL_MS = 5 * 60 * 1000; // Check every 5 minutes
let schedulerTimer: NodeJS.Timeout | null = null;

function parseScheduleToMs(schedule: string): number {
  const map: Record<string, number> = {
    "1h": 60 * 60 * 1000,
    "6h": 6 * 60 * 60 * 1000,
    "12h": 12 * 60 * 60 * 1000,
    "24h": 24 * 60 * 60 * 1000,
    daily: 24 * 60 * 60 * 1000,
    hourly: 60 * 60 * 1000,
  };
  return map[schedule] || 0;
}

async function checkFeedsDueForPoll(): Promise<void> {
  try {
    const { db } = await import("./db");
    const { iocFeeds } = await import("@shared/schema");
    const { eq, and, sql } = await import("drizzle-orm");

    // Find all enabled feeds with a non-manual schedule
    const feeds = await db
      .select()
      .from(iocFeeds)
      .where(
        and(eq(iocFeeds.enabled, true), sql`${iocFeeds.schedule} IS NOT NULL AND ${iocFeeds.schedule} != 'manual'`),
      );

    for (const feed of feeds) {
      const schedule = feed.schedule || "manual";
      const intervalMs = parseScheduleToMs(schedule);
      if (intervalMs <= 0) continue;

      // Check if feed is due for polling
      const lastFetch = feed.lastFetchAt ? new Date(feed.lastFetchAt).getTime() : 0;
      const now = Date.now();
      const timeSinceLastFetch = now - lastFetch;

      if (timeSinceLastFetch >= intervalMs) {
        // Feed is overdue — enqueue a poll job
        const orgId = feed.orgId;
        if (!orgId) continue;

        try {
          await scheduleJob("ioc_feed_poll", orgId, { feedId: feed.id }, new Date());
          logger.child("feed-poll-scheduler").info(`Enqueued poll for feed ${feed.name} (${schedule})`, {
            feedId: feed.id,
            lastFetchAt: feed.lastFetchAt?.toISOString() ?? "never",
          });
        } catch (err) {
          // Dedup in scheduleJob will handle already-queued jobs
          logger.child("feed-poll-scheduler").debug(`Feed ${feed.name} already queued or dedup hit`, {
            error: String(err),
          });
        }
      }
    }
  } catch (err) {
    logger.child("feed-poll-scheduler").error("Error checking feeds due for poll", { error: String(err) });
  }
}

export function startFeedPollScheduler(): void {
  logger.child("feed-poll-scheduler").info("Started — checks every 5 minutes");
  schedulerTimer = setInterval(checkFeedsDueForPoll, SCHEDULER_INTERVAL_MS);
  // Initial check after 30 seconds (give server time to start)
  setTimeout(checkFeedsDueForPoll, 30_000);
}

export function stopFeedPollScheduler(): void {
  if (schedulerTimer) {
    clearInterval(schedulerTimer);
    schedulerTimer = null;
  }
  logger.child("feed-poll-scheduler").info("Stopped");
}

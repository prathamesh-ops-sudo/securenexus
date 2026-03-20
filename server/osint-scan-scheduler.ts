import { logger } from "./logger";

const SCHEDULER_INTERVAL_MS = 5 * 60 * 1000; // Check every 5 minutes
let schedulerTimer: NodeJS.Timeout | null = null;

/**
 * 5.4: OSINT Scan Scheduler
 *
 * Polls osintScheduledScans for scans that are due (nextRunAt <= now, enabled = true)
 * and executes them with change detection (5.5) and quota tracking (5.6).
 *
 * Follows the same pattern as feed-poll-scheduler.ts.
 */
async function checkOsintScansDueForRun(): Promise<void> {
  try {
    const { db } = await import("./db");
    const { osintScheduledScans } = await import("@shared/schema");
    const { eq, and, sql } = await import("drizzle-orm");
    const { executeScheduledScan } = await import("./routes/osint");

    const log = logger.child("osint-scan-scheduler");

    // Find all enabled scheduled scans that are due
    const dueScans = await db
      .select()
      .from(osintScheduledScans)
      .where(
        and(
          eq(osintScheduledScans.enabled, true),
          sql`${osintScheduledScans.nextRunAt} IS NOT NULL AND ${osintScheduledScans.nextRunAt} <= NOW()`,
        ),
      );

    if (dueScans.length === 0) return;

    log.info(`Found ${dueScans.length} OSINT scan(s) due for execution`);

    for (const scan of dueScans) {
      const orgId = scan.orgId;
      if (!orgId) continue;

      try {
        const result = await executeScheduledScan(scan, orgId, log);
        if (result.success) {
          log.info(`Scheduled scan "${scan.name}" completed successfully`, {
            scanId: scan.id,
            resultCount: result.resultCount,
            newFindings: result.newFindings,
            resolvedFindings: result.resolvedFindings,
          });
        } else {
          log.warn(`Scheduled scan "${scan.name}" failed`, {
            scanId: scan.id,
            error: result.error,
          });
        }
      } catch (err) {
        log.error(`Error executing scheduled scan "${scan.name}"`, {
          scanId: scan.id,
          error: String(err),
        });

        // Mark scan as errored but don't disable it
        await db
          .update(osintScheduledScans)
          .set({
            lastRunAt: new Date(),
            lastRunStatus: "error",
            updatedAt: new Date(),
          })
          .where(eq(osintScheduledScans.id, scan.id));
      }
    }
  } catch (err) {
    logger.child("osint-scan-scheduler").error("Error checking OSINT scans due for run", { error: String(err) });
  }
}

export function startOsintScanScheduler(): void {
  logger.child("osint-scan-scheduler").info("Started -- checks every 5 minutes");
  schedulerTimer = setInterval(checkOsintScansDueForRun, SCHEDULER_INTERVAL_MS);
  // Initial check after 45 seconds (give server time to start, stagger from feed-poll-scheduler)
  setTimeout(checkOsintScansDueForRun, 45_000);
}

export function stopOsintScanScheduler(): void {
  if (schedulerTimer) {
    clearInterval(schedulerTimer);
    schedulerTimer = null;
  }
  logger.child("osint-scan-scheduler").info("Stopped");
}

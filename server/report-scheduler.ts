import { storage } from "./storage";
import { generateReportData, formatAsCSV } from "./report-engine";
import { uploadFile } from "./s3";

const SCHEDULER_INTERVAL_MS = 60 * 60 * 1000;
let schedulerTimer: NodeJS.Timeout | null = null;

export function startReportScheduler() {
  console.log("[ReportScheduler] Started - checks every hour");
  schedulerTimer = setInterval(checkDueSchedules, SCHEDULER_INTERVAL_MS);
  setTimeout(checkDueSchedules, 10000);
}

export function stopReportScheduler() {
  if (schedulerTimer) {
    clearInterval(schedulerTimer);
    schedulerTimer = null;
  }
}

async function checkDueSchedules() {
  try {
    const dueSchedules = await storage.getDueSchedules();
    for (const schedule of dueSchedules) {
      try {
        await executeScheduledReport(schedule);
      } catch (err) {
        console.error(`[ReportScheduler] Failed to execute schedule ${schedule.id}:`, err);
      }
    }
  } catch (err) {
    console.error("[ReportScheduler] Error checking schedules:", err);
  }
}

async function executeScheduledReport(schedule: any) {
  const template = await storage.getReportTemplate(schedule.templateId);
  if (!template) return;

  const run = await storage.createReportRun({
    orgId: schedule.orgId,
    templateId: template.id,
    scheduleId: schedule.id,
    status: "running",
    format: template.format || "csv",
  });

  try {
    await storage.updateReportRun(run.id, { startedAt: new Date() });

    const data = await generateReportData(template.reportType, template.orgId || undefined);
    const content = template.format === "csv" ? formatAsCSV(data) : JSON.stringify(data, null, 2);
    const contentType = template.format === "csv" ? "text/csv" : "application/json";
    const ext = template.format === "csv" ? "csv" : "json";

    const s3Key = `reports/${schedule.orgId || "global"}/${template.reportType}_${new Date().toISOString().replace(/[:.]/g, "-")}.${ext}`;

    const targets = schedule.deliveryTargets ? JSON.parse(schedule.deliveryTargets) : [];
    let outputLocation = "";

    for (const target of targets) {
      if (target.type === "s3") {
        try {
          const result = await uploadFile(s3Key, content, contentType);
          outputLocation = `s3://${result.bucket}/${result.key}`;
        } catch (err: any) {
          console.log(`[ReportScheduler] S3 delivery for schedule ${schedule.id}: ${err.message}`);
          outputLocation = `local://${s3Key}`;
        }
      } else if (target.type === "webhook" && target.url) {
        try {
          await fetch(target.url, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ report: data, scheduleName: schedule.name, template: template.name }),
          });
          console.log(`[ReportScheduler] Webhook delivered for schedule ${schedule.id} to ${target.url}`);
        } catch (err: any) {
          console.log(`[ReportScheduler] Webhook delivery failed for schedule ${schedule.id}: ${err.message}`);
        }
      } else if (target.type === "email" && target.address) {
        console.log(`[ReportScheduler] Email delivery simulated for schedule ${schedule.id} to ${target.address}`);
        console.log(`[ReportScheduler] Subject: ${template.name} - ${new Date().toLocaleDateString()}`);
      }
    }

    if (!outputLocation) outputLocation = `generated://${template.reportType}`;

    await storage.updateReportRun(run.id, {
      status: "completed",
      completedAt: new Date(),
      outputLocation,
      fileSize: Buffer.byteLength(content),
    });

    const nextRun = calculateNextRunTime(schedule.cadence);
    await storage.updateReportSchedule(schedule.id, { lastRunAt: new Date(), nextRunAt: nextRun });

    console.log(`[ReportScheduler] Completed report run ${run.id} for schedule ${schedule.id}`);
  } catch (err: any) {
    await storage.updateReportRun(run.id, {
      status: "failed",
      completedAt: new Date(),
      error: err.message,
    });
  }
}

function calculateNextRunTime(cadence: string): Date {
  const now = new Date();
  switch (cadence) {
    case "daily": return new Date(now.getTime() + 24 * 60 * 60 * 1000);
    case "weekly": return new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
    case "biweekly": return new Date(now.getTime() + 14 * 24 * 60 * 60 * 1000);
    case "monthly": { const d = new Date(now); d.setMonth(d.getMonth() + 1); return d; }
    case "quarterly": { const d = new Date(now); d.setMonth(d.getMonth() + 3); return d; }
    default: return new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
  }
}

export async function runReportOnDemand(templateId: string, orgId?: string, createdBy?: string): Promise<any> {
  const template = await storage.getReportTemplate(templateId);
  if (!template) throw new Error("Template not found");

  const run = await storage.createReportRun({
    orgId: orgId || template.orgId || null,
    templateId: template.id,
    status: "running",
    format: template.format || "csv",
    createdBy: createdBy || null,
  });

  try {
    await storage.updateReportRun(run.id, { startedAt: new Date() });
    const data = await generateReportData(template.reportType, orgId || template.orgId || undefined);
    const content = template.format === "csv" ? formatAsCSV(data) : JSON.stringify(data, null, 2);

    await storage.updateReportRun(run.id, {
      status: "completed",
      completedAt: new Date(),
      outputLocation: `generated://${template.reportType}`,
      fileSize: Buffer.byteLength(content),
    });

    return { run: await storage.getReportRun(run.id), data, content };
  } catch (err: any) {
    await storage.updateReportRun(run.id, {
      status: "failed",
      completedAt: new Date(),
      error: err.message,
    });
    throw err;
  }
}

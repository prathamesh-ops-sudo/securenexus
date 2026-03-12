import { storage } from "./storage";
import { generateReportData, formatAsCSV } from "./report-engine";
import { generatePdfReport, CONFIDENTIAL_REPORT_TYPES } from "./report-pdf";
import { uploadFile } from "./s3";
import { logger } from "./logger";
import { calculateNextRunTimeInTimezone, safeTimezone, formatInTimezone } from "./timezone-utils";
import { sendEmail, isEmailEnabled } from "./email-service";

const SCHEDULER_INTERVAL_MS = 60 * 60 * 1000;
let schedulerTimer: NodeJS.Timeout | null = null;

export function startReportScheduler() {
  logger.child("report-scheduler").info("Started - checks every hour");
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
        logger.child("report-scheduler").error(`Failed to execute schedule ${schedule.id}:`, { error: String(err) });
      }
    }
  } catch (err) {
    logger.child("report-scheduler").error("Error checking schedules:", { error: String(err) });
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
    let content: string | Buffer;
    let contentType: string;
    let ext: string;
    if (template.format === "pdf") {
      const isConfidential = CONFIDENTIAL_REPORT_TYPES.includes(template.reportType);
      content = await generatePdfReport(data, { confidential: isConfidential, orgName: "Arica Tech Solutions" });
      contentType = "application/pdf";
      ext = "pdf";
    } else if (template.format === "csv") {
      content = formatAsCSV(data);
      contentType = "text/csv";
      ext = "csv";
    } else {
      content = JSON.stringify(data, null, 2);
      contentType = "application/json";
      ext = "json";
    }

    const s3Key = `reports/${schedule.orgId ?? "_global"}/${template.reportType}_${new Date().toISOString().replace(/[:.]/g, "-")}.${ext}`;

    const targets = schedule.deliveryTargets ? JSON.parse(schedule.deliveryTargets) : [];
    let outputLocation = "";

    for (const target of targets) {
      if (target.type === "s3") {
        try {
          const result = await uploadFile(s3Key, content, contentType);
          outputLocation = `s3://${result.bucket}/${result.key}`;
        } catch (err: any) {
          logger
            .child("report-scheduler")
            .warn(`S3 delivery failed for schedule ${schedule.id}`, { error: err.message });
          outputLocation = `local://${s3Key}`;
        }
      } else if (target.type === "webhook" && target.url) {
        try {
          await fetch(target.url, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ report: data, scheduleName: schedule.name, template: template.name }),
          });
          logger.child("report-scheduler").info(`Webhook delivered for schedule ${schedule.id} to ${target.url}`);
        } catch (err: any) {
          logger
            .child("report-scheduler")
            .warn(`Webhook delivery failed for schedule ${schedule.id}`, { url: target.url, error: err.message });
        }
      } else if (target.type === "email" && target.address) {
        const tz = safeTimezone(schedule.timezone);
        const subject = `${template.name} — ${formatInTimezone(new Date(), tz)}`;
        if (isEmailEnabled()) {
          try {
            const isConfidentialReport = CONFIDENTIAL_REPORT_TYPES.includes(template.reportType);
            await sendEmail({
              to: target.address,
              subject,
              html:
                `<p>Your scheduled report <strong>${template.name}</strong> is ready.</p>` +
                (isConfidentialReport ? `<p style="color:red;"><strong>CONFIDENTIAL</strong></p>` : "") +
                `<p>Report type: ${template.reportType}<br/>Generated: ${formatInTimezone(new Date(), tz)}</p>` +
                (outputLocation ? `<p>Download: ${outputLocation}</p>` : ""),
              text: `Your scheduled report "${template.name}" is ready.\nReport type: ${template.reportType}\nGenerated: ${formatInTimezone(new Date(), tz)}${outputLocation ? `\nDownload: ${outputLocation}` : ""}`,
            });
            logger.child("report-scheduler").info(`Email delivered for schedule ${schedule.id} to ${target.address}`);
          } catch (emailErr: any) {
            logger.child("report-scheduler").warn(`Email delivery failed for schedule ${schedule.id}`, {
              to: target.address,
              error: emailErr.message,
            });
          }
        } else {
          logger
            .child("report-scheduler")
            .info(`Email delivery skipped (non-production) for schedule ${schedule.id} to ${target.address}`);
        }
      }
    }

    if (!outputLocation) outputLocation = `generated://${template.reportType}`;

    await storage.updateReportRun(run.id, {
      status: "completed",
      completedAt: new Date(),
      outputLocation,
      fileSize: Buffer.byteLength(content),
    });

    const tz = safeTimezone(schedule.timezone);
    const nextRun = calculateNextRunTimeInTimezone(schedule.cadence, tz);
    await storage.updateReportSchedule(schedule.id, { lastRunAt: new Date(), nextRunAt: nextRun });

    logger.child("report-scheduler").info(`Completed report run ${run.id} for schedule ${schedule.id}`);
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
    case "daily":
      return new Date(now.getTime() + 24 * 60 * 60 * 1000);
    case "weekly":
      return new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
    case "biweekly":
      return new Date(now.getTime() + 14 * 24 * 60 * 60 * 1000);
    case "monthly": {
      const d = new Date(now);
      d.setMonth(d.getMonth() + 1);
      return d;
    }
    case "quarterly": {
      const d = new Date(now);
      d.setMonth(d.getMonth() + 3);
      return d;
    }
    default:
      return new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
  }
}

export async function runReportOnDemand(templateId: string, orgId?: string, createdBy?: string): Promise<any> {
  const template = await storage.getReportTemplate(templateId);
  if (!template) throw new Error("Template not found");

  const run = await storage.createReportRun({
    orgId: orgId ?? template.orgId ?? null,
    templateId: template.id,
    status: "running",
    format: template.format || "csv",
    createdBy: createdBy || null,
  });

  try {
    await storage.updateReportRun(run.id, { startedAt: new Date() });
    const data = await generateReportData(template.reportType, orgId ?? template.orgId ?? undefined);
    let content: string | Buffer;
    if (template.format === "pdf") {
      const isConfidential = CONFIDENTIAL_REPORT_TYPES.includes(template.reportType);
      content = await generatePdfReport(data, { confidential: isConfidential, orgName: "Arica Tech Solutions" });
    } else {
      content = template.format === "csv" ? formatAsCSV(data) : JSON.stringify(data, null, 2);
    }

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

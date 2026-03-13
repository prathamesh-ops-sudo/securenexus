/**
 * Phishing Simulation Engine
 * Handles campaign execution, click tracking, and adaptive training enrollment.
 */

import { db } from "./db";
import {
  phishingCampaigns,
  phishingResults,
  employeeRiskScores,
  trainingAssignments,
  trainingModules,
  securityAwarenessConfig,
} from "../shared/schema";
import { eq, and, sql } from "drizzle-orm";
import { logger } from "./routes/shared";

const log = logger.child("phishing-engine");

/**
 * Launch a phishing campaign — mark it as running and create result entries for each recipient.
 */
export async function launchCampaign(campaignId: string, orgId: string): Promise<{ sent: number }> {
  const [campaign] = await db
    .select()
    .from(phishingCampaigns)
    .where(and(eq(phishingCampaigns.id, campaignId), eq(phishingCampaigns.orgId, orgId)));

  if (!campaign) throw new Error("Campaign not found");
  if (campaign.status !== "draft" && campaign.status !== "scheduled") {
    throw new Error(`Campaign cannot be launched from status: ${campaign.status}`);
  }

  const targetEmails = (campaign.targetEmails as string[]) || [];
  if (targetEmails.length === 0) {
    throw new Error("No target emails configured for this campaign");
  }

  // Create result entries for each recipient
  const now = new Date();
  const resultValues = targetEmails.map((email) => ({
    orgId,
    campaignId,
    recipientEmail: email,
    emailSentAt: now,
  }));

  await db.insert(phishingResults).values(resultValues);

  // Update campaign status
  await db
    .update(phishingCampaigns)
    .set({
      status: "running",
      startedAt: now,
      emailsSent: targetEmails.length,
      totalRecipients: targetEmails.length,
      updatedAt: now,
    })
    .where(eq(phishingCampaigns.id, campaignId));

  log.info("Campaign launched", { campaignId, recipients: targetEmails.length });

  // In production: integrate with email delivery service (SES, SendGrid, etc.)
  // For now, we track the simulated sends in the results table

  return { sent: targetEmails.length };
}

/**
 * Record a phishing event (open, click, credential submission, report).
 */
export async function recordPhishingEvent(
  resultId: string,
  orgId: string,
  eventType: "opened" | "clicked" | "submitted" | "reported",
  metadata?: { userAgent?: string; ipAddress?: string },
): Promise<void> {
  const now = new Date();
  const updates: Record<string, unknown> = {};

  switch (eventType) {
    case "opened":
      updates.emailOpenedAt = now;
      break;
    case "clicked":
      updates.linkClickedAt = now;
      if (metadata?.userAgent) updates.userAgent = metadata.userAgent;
      if (metadata?.ipAddress) updates.ipAddress = metadata.ipAddress;
      break;
    case "submitted":
      updates.credentialSubmittedAt = now;
      break;
    case "reported":
      updates.reportedAt = now;
      break;
  }

  // Check if this event was already recorded (prevent duplicate counter inflation)
  const [existingResult] = await db
    .select()
    .from(phishingResults)
    .where(and(eq(phishingResults.id, resultId), eq(phishingResults.orgId, orgId)));

  if (!existingResult) return;

  const timestampField =
    eventType === "opened"
      ? "emailOpenedAt"
      : eventType === "clicked"
        ? "linkClickedAt"
        : eventType === "submitted"
          ? "credentialSubmittedAt"
          : "reportedAt";

  const alreadyRecorded = existingResult[timestampField] != null;

  await db
    .update(phishingResults)
    .set(updates)
    .where(and(eq(phishingResults.id, resultId), eq(phishingResults.orgId, orgId)));

  // Only increment campaign counter if this is the first time this event type was recorded
  if (!alreadyRecorded) {
    const counterField =
      eventType === "opened"
        ? "emailsOpened"
        : eventType === "clicked"
          ? "linksClicked"
          : eventType === "submitted"
            ? "credentialsSubmitted"
            : "reported";

    await db
      .update(phishingCampaigns)
      .set({
        [counterField]: sql`${phishingCampaigns[counterField]} + 1`,
        updatedAt: now,
      })
      .where(eq(phishingCampaigns.id, existingResult.campaignId));

    // If clicked or submitted, check auto-enroll setting
    if (eventType === "clicked" || eventType === "submitted") {
      await maybeAutoEnrollTraining(orgId, existingResult.recipientEmail, existingResult.recipientName);
    }
  }
}

/**
 * Auto-enroll an employee in training after they clicked a phishing link.
 */
async function maybeAutoEnrollTraining(orgId: string, email: string, name: string | null): Promise<void> {
  try {
    const [config] = await db.select().from(securityAwarenessConfig).where(eq(securityAwarenessConfig.orgId, orgId));

    if (!config?.autoEnrollOnClick) return;

    // Find a suitable training module
    const moduleId = config.defaultTrainingModuleId;
    if (!moduleId) {
      // Find first active phishing awareness module
      const [module] = await db
        .select()
        .from(trainingModules)
        .where(
          and(
            eq(trainingModules.orgId, orgId),
            eq(trainingModules.category, "phishing_awareness"),
            eq(trainingModules.isActive, true),
          ),
        )
        .limit(1);

      if (!module) return;

      await db.insert(trainingAssignments).values({
        orgId,
        moduleId: module.id,
        employeeEmail: email,
        employeeName: name,
        assignedReason: "phishing_click",
        dueAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
      });
    } else {
      await db.insert(trainingAssignments).values({
        orgId,
        moduleId,
        employeeEmail: email,
        employeeName: name,
        assignedReason: "phishing_click",
        dueAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      });
    }

    log.info("Auto-enrolled employee in training after phishing click", { email, orgId });
  } catch (err) {
    log.error("Failed to auto-enroll training", { error: String(err) });
  }
}

/**
 * Recalculate the human risk score for an employee based on their phishing + training history.
 */
export async function recalculateRiskScore(orgId: string, email: string): Promise<void> {
  try {
    // Get all phishing results for this employee
    const results = await db
      .select()
      .from(phishingResults)
      .where(and(eq(phishingResults.orgId, orgId), eq(phishingResults.recipientEmail, email)));

    const campaignsReceived = results.length;
    const campaignsClicked = results.filter((r) => r.linkClickedAt != null).length;
    const campaignsReported = results.filter((r) => r.reportedAt != null).length;
    const clickRate = campaignsReceived > 0 ? (campaignsClicked / campaignsReceived) * 100 : 0;
    const reportRate = campaignsReceived > 0 ? (campaignsReported / campaignsReceived) * 100 : 0;

    // Get training assignments
    const assignments = await db
      .select()
      .from(trainingAssignments)
      .where(and(eq(trainingAssignments.orgId, orgId), eq(trainingAssignments.employeeEmail, email)));

    const trainingsAssigned = assignments.length;
    const trainingsCompleted = assignments.filter((a) => a.completedAt != null).length;
    const trainingCompletionRate = trainingsAssigned > 0 ? (trainingsCompleted / trainingsAssigned) * 100 : 0;

    // Calculate risk score (0-100, higher = riskier)
    let riskScore = 50; // baseline
    riskScore += clickRate * 0.3; // high click rate increases risk
    riskScore -= reportRate * 0.2; // high report rate decreases risk
    riskScore -= trainingCompletionRate * 0.15; // training completion decreases risk
    riskScore = Math.max(0, Math.min(100, riskScore));

    // Determine trend
    const [existing] = await db
      .select()
      .from(employeeRiskScores)
      .where(and(eq(employeeRiskScores.orgId, orgId), eq(employeeRiskScores.email, email)));

    const riskTrend = existing
      ? riskScore < existing.riskScore
        ? "improving"
        : riskScore > existing.riskScore
          ? "worsening"
          : "stable"
      : "stable";

    const lastPhishingTest =
      results.length > 0
        ? results.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())[0].createdAt
        : null;

    const lastTrainingCompleted =
      assignments.filter((a) => a.completedAt != null).length > 0
        ? assignments
            .filter((a) => a.completedAt != null)
            .sort((a, b) => new Date(b.completedAt!).getTime() - new Date(a.completedAt!).getTime())[0].completedAt
        : null;

    const scoreData = {
      orgId,
      email,
      name: results[0]?.recipientName || existing?.name || null,
      department: results[0]?.department || existing?.department || null,
      riskScore,
      phishingClickRate: clickRate,
      reportRate,
      trainingCompletionRate,
      campaignsReceived,
      campaignsClicked,
      campaignsReported,
      trainingsCompleted,
      trainingsAssigned,
      lastPhishingTestAt: lastPhishingTest,
      lastTrainingCompletedAt: lastTrainingCompleted,
      riskTrend,
      updatedAt: new Date(),
    };

    if (existing) {
      await db.update(employeeRiskScores).set(scoreData).where(eq(employeeRiskScores.id, existing.id));
    } else {
      await db.insert(employeeRiskScores).values(scoreData);
    }

    log.info("Recalculated risk score", { email, riskScore, riskTrend });
  } catch (err) {
    log.error("Failed to recalculate risk score", { email, error: String(err) });
  }
}

/**
 * Complete a campaign — finalize stats and recalculate risk scores for all recipients.
 */
export async function completeCampaign(campaignId: string, orgId: string): Promise<void> {
  const results = await db
    .select()
    .from(phishingResults)
    .where(and(eq(phishingResults.orgId, orgId), eq(phishingResults.campaignId, campaignId)));

  await db
    .update(phishingCampaigns)
    .set({
      status: "completed",
      completedAt: new Date(),
      updatedAt: new Date(),
    })
    .where(and(eq(phishingCampaigns.id, campaignId), eq(phishingCampaigns.orgId, orgId)));

  // Recalculate risk scores for all recipients
  const uniqueEmails = Array.from(new Set(results.map((r) => r.recipientEmail)));
  for (const email of uniqueEmails) {
    await recalculateRiskScore(orgId, email);
  }

  log.info("Campaign completed", { campaignId, recipientsScored: uniqueEmails.length });
}

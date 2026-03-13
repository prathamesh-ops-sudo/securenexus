/**
 * Physical-Digital Event Correlation Engine
 * Correlates physical badge events with digital security events to detect insider threats.
 */

import { db } from "./db";
import { badgeEvents, alerts, physicalIncidents } from "../shared/schema";
import { eq, and, gte, lte, sql, desc } from "drizzle-orm";
import { logger } from "./routes/shared";

const log = logger.child("physical-correlation");

export interface CorrelationRule {
  name: string;
  description: string;
  physicalCondition: string;
  digitalCondition: string;
  severity: string;
  windowMinutes: number;
}

const BUILT_IN_RULES: CorrelationRule[] = [
  {
    name: "After-Hours Access + Mass File Download",
    description: "Badge access outside business hours combined with large file downloads detected by DLP",
    physicalCondition: "after_hours_access",
    digitalCondition: "mass_file_download",
    severity: "critical",
    windowMinutes: 60,
  },
  {
    name: "Server Room Access + Privileged Escalation",
    description: "Badge into server room combined with privilege escalation alert within the time window",
    physicalCondition: "server_room_access",
    digitalCondition: "privilege_escalation",
    severity: "critical",
    windowMinutes: 30,
  },
  {
    name: "Failed Badge + Brute Force Login",
    description: "Multiple failed badge attempts at same time as brute force login attempts",
    physicalCondition: "repeated_badge_failure",
    digitalCondition: "brute_force_login",
    severity: "high",
    windowMinutes: 15,
  },
  {
    name: "Visitor Badge + Network Access",
    description: "Visitor badge used in restricted area while unauthorized network device detected",
    physicalCondition: "visitor_restricted_area",
    digitalCondition: "rogue_device_detected",
    severity: "high",
    windowMinutes: 30,
  },
  {
    name: "Tailgate + VPN from Same Badge Owner",
    description: "Tailgate detected at entrance while the same employee's VPN session is active from remote location",
    physicalCondition: "tailgate_detected",
    digitalCondition: "vpn_active_same_user",
    severity: "high",
    windowMinutes: 5,
  },
  {
    name: "Badge Clone Detection",
    description: "Same badge used at two physically distant locations within impossible travel time",
    physicalCondition: "impossible_travel",
    digitalCondition: "any",
    severity: "critical",
    windowMinutes: 10,
  },
];

/**
 * Check if a badge event occurred outside business hours.
 */
function isAfterHours(eventTime: Date, afterHoursStart: string = "20:00", afterHoursEnd: string = "06:00"): boolean {
  const hours = eventTime.getHours();
  const minutes = eventTime.getMinutes();
  const timeStr = `${hours.toString().padStart(2, "0")}:${minutes.toString().padStart(2, "0")}`;

  // Handle overnight ranges (e.g., 20:00 - 06:00)
  if (afterHoursStart > afterHoursEnd) {
    return timeStr >= afterHoursStart || timeStr < afterHoursEnd;
  }
  return timeStr >= afterHoursStart && timeStr < afterHoursEnd;
}

/**
 * Run correlation analysis for a specific org's recent badge events.
 * Looks for patterns that match built-in rules by checking digital alerts
 * within the correlation time window.
 */
export async function runCorrelationAnalysis(
  orgId: string,
  lookbackMinutes: number = 60,
): Promise<Array<{ rule: CorrelationRule; badgeEventId: string; alertId?: string; details: string }>> {
  const correlations: Array<{ rule: CorrelationRule; badgeEventId: string; alertId?: string; details: string }> = [];
  const since = new Date(Date.now() - lookbackMinutes * 60 * 1000);

  try {
    // Get recent badge events
    const recentBadgeEvents = await db
      .select()
      .from(badgeEvents)
      .where(and(eq(badgeEvents.orgId, orgId), gte(badgeEvents.occurredAt, since)))
      .orderBy(desc(badgeEvents.occurredAt))
      .limit(500);

    for (const event of recentBadgeEvents) {
      // Check after-hours access
      if (isAfterHours(new Date(event.occurredAt)) && event.eventType === "access_granted") {
        // Look for digital alerts in the same time window
        const windowStart = new Date(new Date(event.occurredAt).getTime() - 60 * 60 * 1000);
        const windowEnd = new Date(new Date(event.occurredAt).getTime() + 60 * 60 * 1000);

        const digitalAlerts = await db
          .select()
          .from(alerts)
          .where(and(eq(alerts.orgId, orgId), gte(alerts.createdAt, windowStart), lte(alerts.createdAt, windowEnd)))
          .limit(10);

        if (digitalAlerts.length > 0) {
          correlations.push({
            rule: BUILT_IN_RULES[0],
            badgeEventId: event.id,
            alertId: digitalAlerts[0].id,
            details: `After-hours badge access by ${event.employeeName || event.badgeNumber} at ${event.location} correlated with ${digitalAlerts.length} digital alert(s)`,
          });
        }
      }

      // Check tailgate events
      if (event.eventType === "tailgate_detected") {
        correlations.push({
          rule: BUILT_IN_RULES[4],
          badgeEventId: event.id,
          details: `Tailgate detected at ${event.doorName || event.location}`,
        });
      }

      // Check forced door events
      if (event.eventType === "door_forced") {
        correlations.push({
          rule: {
            name: "Forced Entry Detection",
            description: "Door forced open without valid badge",
            physicalCondition: "door_forced",
            digitalCondition: "any",
            severity: "critical",
            windowMinutes: 5,
          },
          badgeEventId: event.id,
          details: `Door forced open at ${event.doorName || event.location}`,
        });
      }

      // Check duress alarms
      if (event.eventType === "duress_alarm") {
        correlations.push({
          rule: {
            name: "Duress Alarm",
            description: "Employee triggered duress code during badge scan",
            physicalCondition: "duress_alarm",
            digitalCondition: "any",
            severity: "critical",
            windowMinutes: 0,
          },
          badgeEventId: event.id,
          details: `Duress alarm triggered by ${event.employeeName || event.badgeNumber} at ${event.location}`,
        });
      }
    }

    // Check for impossible travel (same badge at distant locations within short time)
    const badgeGroups = new Map<string, typeof recentBadgeEvents>();
    for (const event of recentBadgeEvents) {
      if (!event.badgeNumber) continue;
      const existing = badgeGroups.get(event.badgeNumber) || [];
      existing.push(event);
      badgeGroups.set(event.badgeNumber, existing);
    }

    for (const [badge, events] of Array.from(badgeGroups.entries())) {
      if (events.length < 2) continue;
      for (let i = 0; i < events.length - 1; i++) {
        const timeDiff = Math.abs(
          new Date(events[i].occurredAt).getTime() - new Date(events[i + 1].occurredAt).getTime(),
        );
        if (timeDiff < 10 * 60 * 1000 && events[i].location !== events[i + 1].location) {
          correlations.push({
            rule: BUILT_IN_RULES[5],
            badgeEventId: events[i].id,
            details: `Badge ${badge} used at ${events[i].location} and ${events[i + 1].location} within ${Math.round(timeDiff / 60000)} minutes`,
          });
        }
      }
    }

    log.info("Correlation analysis complete", {
      orgId,
      eventsAnalyzed: recentBadgeEvents.length,
      correlationsFound: correlations.length,
    });
  } catch (err) {
    log.error("Failed to run correlation analysis", { orgId, error: String(err) });
  }

  return correlations;
}

/**
 * Auto-create physical incidents from detected correlations.
 */
export async function createPhysicalIncidentsFromCorrelations(
  orgId: string,
  correlationResults: Array<{ rule: CorrelationRule; badgeEventId: string; alertId?: string; details: string }>,
): Promise<number> {
  let created = 0;

  for (const result of correlationResults) {
    try {
      await db.insert(physicalIncidents).values({
        orgId,
        title: result.rule.name,
        description: result.details,
        incidentType: result.rule.physicalCondition,
        severity: result.rule.severity,
        status: "open",
        badgeEventIds: [result.badgeEventId],
        correlatedAlertIds: result.alertId ? [result.alertId] : [],
      });
      created++;
    } catch (err) {
      log.error("Failed to create physical incident", { error: String(err) });
    }
  }

  return created;
}

export { BUILT_IN_RULES };

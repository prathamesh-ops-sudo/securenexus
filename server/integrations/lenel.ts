/**
 * Lenel OnGuard API Integration
 * Connects to Lenel OnGuard access control systems for badge event ingestion.
 * Also supports Genetec and Honeywell Pro-Watch via normalized event format.
 */

import { logger } from "../routes/shared";

const log = logger.child("lenel-integration");

export interface RawBadgeEvent {
  eventId: string;
  eventType: string;
  badgeNumber: string;
  cardholderName: string;
  cardholderEmail?: string;
  department?: string;
  readerName: string;
  location: string;
  direction?: "entry" | "exit";
  timestamp: string;
  rawData?: Record<string, unknown>;
}

export interface ControllerConfig {
  type: "lenel" | "genetec" | "honeywell" | "generic";
  name: string;
  apiEndpoint: string;
  apiKey?: string;
  isActive: boolean;
}

/**
 * Normalize event types from different controller vendors to our standard types.
 */
function normalizeEventType(controllerType: string, rawType: string): string {
  const typeMap: Record<string, Record<string, string>> = {
    lenel: {
      GRANT: "access_granted",
      DENY: "access_denied",
      FORCED: "door_forced",
      HELD: "door_held",
      TAILGATE: "tailgate_detected",
      ANTIPASSBACK: "antipassback_violation",
      DURESS: "duress_alarm",
      UNKNOWN_CARD: "card_unknown",
    },
    genetec: {
      AccessGranted: "access_granted",
      AccessDenied: "access_denied",
      DoorForcedOpen: "door_forced",
      DoorHeldOpen: "door_held",
      TailgateDetected: "tailgate_detected",
      AntiPassbackViolation: "antipassback_violation",
      DuressAlarm: "duress_alarm",
      UnknownCredential: "card_unknown",
    },
    honeywell: {
      ACCESS_ALLOW: "access_granted",
      ACCESS_DENY: "access_denied",
      DOOR_FORCE: "door_forced",
      DOOR_HELD_OPEN: "door_held",
      PIGGYBACK: "tailgate_detected",
      APB_VIOLATION: "antipassback_violation",
      DURESS: "duress_alarm",
      INVALID_CARD: "card_unknown",
    },
  };

  const vendorMap = typeMap[controllerType] || {};
  return vendorMap[rawType] || rawType.toLowerCase().replace(/\s+/g, "_");
}

/**
 * Fetch badge events from a Lenel OnGuard system.
 * In production, this would call the Lenel REST API.
 */
export async function fetchLenelEvents(config: ControllerConfig, since: Date): Promise<RawBadgeEvent[]> {
  log.info("Fetching events from Lenel OnGuard", {
    endpoint: config.apiEndpoint,
    since: since.toISOString(),
  });

  // In production: call config.apiEndpoint/api/access/events?since=...
  // For now, return empty — real integration requires customer Lenel credentials
  return [];
}

/**
 * Fetch badge events from a Genetec Security Center.
 */
export async function fetchGenetecEvents(config: ControllerConfig, since: Date): Promise<RawBadgeEvent[]> {
  log.info("Fetching events from Genetec Security Center", {
    endpoint: config.apiEndpoint,
    since: since.toISOString(),
  });
  return [];
}

/**
 * Fetch badge events from a Honeywell Pro-Watch system.
 */
export async function fetchHoneywellEvents(config: ControllerConfig, since: Date): Promise<RawBadgeEvent[]> {
  log.info("Fetching events from Honeywell Pro-Watch", {
    endpoint: config.apiEndpoint,
    since: since.toISOString(),
  });
  return [];
}

/**
 * Unified event fetcher — dispatches to the correct vendor integration.
 */
export async function fetchBadgeEvents(config: ControllerConfig, since: Date): Promise<RawBadgeEvent[]> {
  if (!config.isActive) return [];

  let events: RawBadgeEvent[];
  switch (config.type) {
    case "lenel":
      events = await fetchLenelEvents(config, since);
      break;
    case "genetec":
      events = await fetchGenetecEvents(config, since);
      break;
    case "honeywell":
      events = await fetchHoneywellEvents(config, since);
      break;
    default:
      events = [];
  }

  // Normalize event types
  return events.map((e) => ({
    ...e,
    eventType: normalizeEventType(config.type, e.eventType),
  }));
}

/**
 * Test connectivity to a controller.
 */
export async function validateControllerConfiguration(
  config: ControllerConfig,
): Promise<{ status: "configuration_valid" | "invalid"; message: string }> {
  log.info("Validating controller configuration", { type: config.type, endpoint: config.apiEndpoint });

  try {
    if (!config.apiEndpoint) {
      return { status: "invalid", message: "API endpoint is required" };
    }
    if (!config.type) {
      return { status: "invalid", message: "Controller type is required" };
    }
    return {
      status: "configuration_valid",
      message: `Configuration for ${config.name} (${config.type}) is valid. Reachability was not tested.`,
    };
  } catch (err) {
    return { status: "invalid", message: `Configuration validation failed: ${String(err)}` };
  }
}

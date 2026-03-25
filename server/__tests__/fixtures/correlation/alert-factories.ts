/**
 * Alert factory functions for correlation engine tests.
 * Provides typed Alert objects for CrowdStrike, Splunk, and GuardDuty sources.
 */
import type { Alert } from "@shared/schema";

let alertCounter = 0;

function nextId(): string {
  alertCounter++;
  return `alert-factory-${alertCounter}`;
}

/** Reset counter between test suites if needed */
export function resetAlertCounter(): void {
  alertCounter = 0;
}

export function makeBaseAlert(overrides: Partial<Alert> = {}): Alert {
  const id = nextId();
  return {
    id,
    orgId: "org-test-1",
    source: "Generic Source",
    sourceEventId: `evt-${id}`,
    category: "other",
    severity: "medium",
    title: `Test Alert ${id}`,
    description: "Base test alert for correlation testing",
    rawData: {},
    normalizedData: {},
    ocsfData: null,
    sourceIp: "10.0.0.1",
    destIp: "192.168.1.1",
    sourcePort: null,
    destPort: null,
    protocol: null,
    userId: null,
    hostname: "workstation-1",
    fileHash: null,
    url: null,
    domain: null,
    mitreTactic: null,
    mitreTechnique: null,
    status: "new",
    incidentId: null,
    correlationScore: null,
    correlationReason: null,
    correlationClusterId: null,
    suppressed: false,
    suppressedBy: null,
    suppressionRuleId: null,
    confidenceScore: null,
    confidenceSource: null,
    confidenceNotes: null,
    dedupClusterId: null,
    analystNotes: null,
    assignedTo: null,
    detectedAt: new Date("2026-03-25T10:00:00Z"),
    ingestedAt: new Date("2026-03-25T10:00:01Z"),
    createdAt: new Date("2026-03-25T10:00:01Z"),
    ...overrides,
  } as Alert;
}

export function makeCrowdStrikeAlert(overrides: Partial<Alert> = {}): Alert {
  return makeBaseAlert({
    source: "CrowdStrike EDR",
    category: "malware",
    severity: "high",
    title: "CrowdStrike: Malicious Process Detected",
    description: "Falcon detected execution of malicious binary on endpoint",
    sourceIp: "10.0.1.50",
    hostname: "ws-finance-01",
    mitreTactic: "execution",
    mitreTechnique: "T1059",
    ...overrides,
  });
}

export function makeSplunkAlert(overrides: Partial<Alert> = {}): Alert {
  return makeBaseAlert({
    source: "Splunk SIEM",
    category: "intrusion",
    severity: "medium",
    title: "Splunk: Anomalous Login Pattern",
    description: "Multiple failed logins followed by successful authentication from unusual geography",
    sourceIp: "203.0.113.42",
    destIp: "10.0.0.5",
    hostname: "dc-primary",
    mitreTactic: "credential-access",
    mitreTechnique: "T1110",
    ...overrides,
  });
}

export function makeGuardDutyAlert(overrides: Partial<Alert> = {}): Alert {
  return makeBaseAlert({
    source: "AWS GuardDuty",
    category: "credential_access",
    severity: "medium",
    title: "GuardDuty: Unusual API Call from Known Malicious IP",
    description: "API call detected from IP address associated with known malicious activity",
    sourceIp: "198.51.100.77",
    hostname: null,
    domain: "api.amazonaws.com",
    mitreTactic: "discovery",
    mitreTechnique: "T1087",
    ...overrides,
  });
}

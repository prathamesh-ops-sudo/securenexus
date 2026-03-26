/**
 * Lateral Movement Campaign Scenario Fixture
 *
 * Simulates a 12-alert attack campaign across 3 sources (CrowdStrike EDR,
 * Splunk SIEM, AWS GuardDuty) covering 6 MITRE ATT&CK phases:
 *   initial-access -> execution -> persistence -> privilege-escalation
 *   -> lateral-movement -> collection
 *
 * Shared entities link the alerts into a single correlated incident:
 *   - User: "john.doe" (phases 1-4)
 *   - Host: "workstation-42" (phases 2-4)
 *   - Host: "server-db-01" (phases 4-5)
 *   - IP: "10.0.1.42" (workstation-42, phases 2-4)
 *   - IP: "203.0.113.77" (attacker external IP, phase 1)
 */

import type { Alert } from "@shared/schema";

const ORG_ID = "test-org-integration";
const BASE_TIME = new Date("2026-03-01T08:00:00Z");

function timeOffset(minutes: number): Date {
  return new Date(BASE_TIME.getTime() + minutes * 60 * 1000);
}

function makeAlert(overrides: Partial<Alert>): Alert {
  return {
    id: overrides.id ?? "alert-unknown",
    orgId: ORG_ID,
    source: overrides.source ?? "Unknown",
    sourceEventId: overrides.sourceEventId ?? `evt-${overrides.id}`,
    category: overrides.category ?? "unknown",
    severity: overrides.severity ?? "medium",
    title: overrides.title ?? "Test alert",
    description: overrides.description ?? "",
    rawData: {},
    normalizedData: overrides.normalizedData ?? {},
    ocsfData: null,
    sourceIp: overrides.sourceIp ?? null,
    destIp: overrides.destIp ?? null,
    sourcePort: null,
    destPort: null,
    protocol: null,
    userId: overrides.userId ?? null,
    hostname: overrides.hostname ?? null,
    fileHash: overrides.fileHash ?? null,
    url: overrides.url ?? null,
    domain: overrides.domain ?? null,
    mitreTactic: overrides.mitreTactic ?? null,
    mitreTechnique: overrides.mitreTechnique ?? null,
    status: "new",
    correlationScore: null,
    correlationClusterId: null,
    correlationReason: null,
    incidentId: null,
    detectedAt: overrides.createdAt ?? BASE_TIME,
    createdAt: overrides.createdAt ?? BASE_TIME,
    updatedAt: null,
    assignedTo: null,
    suppressed: false,
    suppressedBy: null,
    suppressionRuleId: null,
    duplicateOf: null,
    duplicateCount: 0,
    firstSeenAt: overrides.createdAt ?? BASE_TIME,
    lastSeenAt: overrides.createdAt ?? BASE_TIME,
    enrichmentStatus: null,
    enrichedAt: null,
    confidenceScore: null,
    confidenceSource: null,
    confidenceNotes: null,
    dedupClusterId: null,
    occurrenceCount: 1,
    ingestionPipeline: null,
    ingestionLatencyMs: null,
    analystNotes: null,
    ingestedAt: overrides.createdAt ?? BASE_TIME,
  } as unknown as Alert;
}

export interface ExpectedEntityLink {
  entity: string;
  alertIds: string[];
}

/**
 * Build the lateral movement campaign scenario.
 * Returns 12 alerts that should correlate into a single incident.
 */
export function buildLateralMovementScenario(): Alert[] {
  return [
    // ---- Phase 1: Phishing / Initial Access (AWS GuardDuty, 2 alerts) ----
    makeAlert({
      id: "lm-01",
      source: "AWS GuardDuty",
      sourceEventId: "gd-001",
      category: "credential_access",
      severity: "high",
      title: "Unusual login from foreign IP for john.doe",
      description: "Console login from 203.0.113.77 (Tor exit node)",
      userId: "john.doe",
      sourceIp: "203.0.113.77",
      mitreTactic: "initial-access",
      mitreTechnique: "T1078",
      createdAt: timeOffset(0),
    }),
    makeAlert({
      id: "lm-02",
      source: "AWS GuardDuty",
      sourceEventId: "gd-002",
      category: "credential_access",
      severity: "high",
      title: "Credential access alert for john.doe",
      description: "GetSecretValue calls from unusual IP",
      userId: "john.doe",
      sourceIp: "203.0.113.77",
      mitreTactic: "credential-access",
      mitreTechnique: "T1552",
      createdAt: timeOffset(10),
    }),

    // ---- Phase 2: Host Compromise (CrowdStrike EDR, 3 alerts) ----
    makeAlert({
      id: "lm-03",
      source: "CrowdStrike EDR",
      sourceEventId: "cs-001",
      category: "malware",
      severity: "critical",
      title: "Malware execution on workstation-42",
      description: "Suspicious binary launched by john.doe",
      userId: "john.doe",
      hostname: "workstation-42",
      sourceIp: "10.0.1.42",
      mitreTactic: "execution",
      mitreTechnique: "T1059",
      createdAt: timeOffset(30),
    }),
    makeAlert({
      id: "lm-04",
      source: "CrowdStrike EDR",
      sourceEventId: "cs-002",
      category: "malware",
      severity: "critical",
      title: "Process injection detected on workstation-42",
      description: "DLL injection into explorer.exe",
      hostname: "workstation-42",
      sourceIp: "10.0.1.42",
      mitreTactic: "defense-evasion",
      mitreTechnique: "T1055",
      createdAt: timeOffset(35),
    }),
    makeAlert({
      id: "lm-05",
      source: "CrowdStrike EDR",
      sourceEventId: "cs-003",
      category: "malware",
      severity: "high",
      title: "Persistence mechanism installed on workstation-42",
      description: "Registry run key added",
      hostname: "workstation-42",
      sourceIp: "10.0.1.42",
      mitreTactic: "persistence",
      mitreTechnique: "T1547",
      createdAt: timeOffset(45),
    }),

    // ---- Phase 3: Privilege Escalation (CrowdStrike + Splunk, 2 alerts) ----
    makeAlert({
      id: "lm-06",
      source: "CrowdStrike EDR",
      sourceEventId: "cs-004",
      category: "privilege_escalation",
      severity: "critical",
      title: "Local admin exploit on workstation-42",
      description: "UAC bypass via fodhelper",
      userId: "john.doe",
      hostname: "workstation-42",
      sourceIp: "10.0.1.42",
      mitreTactic: "privilege-escalation",
      mitreTechnique: "T1548",
      createdAt: timeOffset(60),
    }),
    makeAlert({
      id: "lm-07",
      source: "Splunk SIEM",
      sourceEventId: "sp-001",
      category: "privilege_escalation",
      severity: "high",
      title: "Suspicious service creation on workstation-42",
      description: "New service installed via sc.exe",
      hostname: "workstation-42",
      sourceIp: "10.0.1.42",
      mitreTactic: "privilege-escalation",
      mitreTechnique: "T1543",
      createdAt: timeOffset(65),
    }),

    // ---- Phase 4: Lateral Movement (Splunk + CrowdStrike, 3 alerts) ----
    makeAlert({
      id: "lm-08",
      source: "Splunk SIEM",
      sourceEventId: "sp-002",
      category: "lateral_movement",
      severity: "high",
      title: "RDP to server-db-01 from workstation-42",
      description: "Inbound RDP session from 10.0.1.42",
      userId: "john.doe",
      hostname: "server-db-01",
      sourceIp: "10.0.1.42",
      destIp: "10.0.2.10",
      mitreTactic: "lateral-movement",
      mitreTechnique: "T1021",
      createdAt: timeOffset(120),
    }),
    makeAlert({
      id: "lm-09",
      source: "CrowdStrike EDR",
      sourceEventId: "cs-005",
      category: "credential_access",
      severity: "critical",
      title: "Pass-the-Hash detected from workstation-42",
      description: "NTLM hash reuse targeting server-db-01",
      userId: "john.doe",
      hostname: "workstation-42",
      sourceIp: "10.0.1.42",
      mitreTactic: "lateral-movement",
      mitreTechnique: "T1550",
      createdAt: timeOffset(125),
    }),
    makeAlert({
      id: "lm-10",
      source: "CrowdStrike EDR",
      sourceEventId: "cs-006",
      category: "malware",
      severity: "high",
      title: "New process execution on server-db-01",
      description: "cmd.exe spawned by RDP session",
      hostname: "server-db-01",
      sourceIp: "10.0.2.10",
      mitreTactic: "execution",
      mitreTechnique: "T1059",
      createdAt: timeOffset(130),
    }),

    // ---- Phase 5: Data Staging / Collection (Splunk, 2 alerts) ----
    makeAlert({
      id: "lm-11",
      source: "Splunk SIEM",
      sourceEventId: "sp-003",
      category: "data_exfiltration",
      severity: "high",
      title: "Large file access on server-db-01",
      description: "Bulk read of customer_data table exports",
      hostname: "server-db-01",
      sourceIp: "10.0.2.10",
      mitreTactic: "collection",
      mitreTechnique: "T1005",
      createdAt: timeOffset(180),
    }),
    makeAlert({
      id: "lm-12",
      source: "Splunk SIEM",
      sourceEventId: "sp-004",
      category: "data_exfiltration",
      severity: "high",
      title: "Archive creation on server-db-01",
      description: "7z archive created in temp directory",
      hostname: "server-db-01",
      sourceIp: "10.0.2.10",
      mitreTactic: "collection",
      mitreTechnique: "T1560",
      createdAt: timeOffset(200),
    }),
  ];
}

/**
 * Expected entity links across alerts.
 * Used by tests to verify correct entity-based correlation.
 */
export const expectedEntityLinks: ExpectedEntityLink[] = [
  { entity: "user:john.doe", alertIds: ["lm-01", "lm-02", "lm-03", "lm-06", "lm-08", "lm-09"] },
  { entity: "host:workstation-42", alertIds: ["lm-03", "lm-04", "lm-05", "lm-06", "lm-07", "lm-09"] },
  { entity: "host:server-db-01", alertIds: ["lm-08", "lm-10", "lm-11", "lm-12"] },
  { entity: "ip:10.0.1.42", alertIds: ["lm-03", "lm-04", "lm-05", "lm-06", "lm-07", "lm-08", "lm-09"] },
  { entity: "ip:203.0.113.77", alertIds: ["lm-01", "lm-02"] },
  { entity: "ip:10.0.2.10", alertIds: ["lm-08", "lm-10", "lm-11", "lm-12"] },
];

/**
 * All 12 alerts should group into 1 incident (they share overlapping entity chains).
 */
export const expectedIncidentCount = 1;

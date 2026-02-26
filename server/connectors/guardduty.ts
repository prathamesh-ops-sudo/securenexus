import type { InsertAlert } from "@shared/schema";
import type { ConnectorPlugin, ConnectorConfig, ConnectorTestResult } from "./connector-plugin";

function mapSeverity(sev?: number): string {
  if (!sev) return "medium";
  if (sev >= 7) return "critical";
  if (sev >= 5) return "high";
  if (sev >= 3) return "medium";
  if (sev >= 1) return "low";
  return "informational";
}

function mapCategory(type?: string): string {
  if (!type) return "other";
  const t = type.toLowerCase();
  if (t.includes("trojan") || t.includes("malware")) return "malware";
  if (t.includes("unauthorized")) return "intrusion";
  if (t.includes("recon")) return "reconnaissance";
  if (t.includes("exfiltration")) return "data_exfiltration";
  if (t.includes("cryptomining") || t.includes("bitcoin")) return "policy_violation";
  if (t.includes("persistence")) return "persistence";
  return "other";
}

export const guarddutyPlugin: ConnectorPlugin = {
  type: "guardduty",
  alertSource: "AWS GuardDuty",
  normalizerKey: "guardduty",
  metadata: {
    name: "AWS GuardDuty",
    description: "Cloud Threat Detection - Pulls findings via AWS SDK with severity filtering",
    authType: "aws_credentials",
    requiredFields: [
      { key: "region", label: "AWS Region", type: "text", placeholder: "us-east-1" },
    ],
    optionalFields: [
      { key: "accessKeyId", label: "AWS Access Key ID (uses default if empty)", type: "text", placeholder: "AKIA..." },
      { key: "secretAccessKey", label: "AWS Secret Access Key", type: "password", placeholder: "Override default AWS credentials" },
    ],
    icon: "CloudLightning",
    docsUrl: "https://docs.aws.amazon.com/guardduty/latest/APIReference/",
  },

  async test(config: ConnectorConfig): Promise<ConnectorTestResult> {
    const start = Date.now();
    try {
      const { GuardDutyClient, ListDetectorsCommand } = await import("@aws-sdk/client-guardduty");
      const { getConnectorAwsClientConfig } = await import("../aws-credentials");
      const client = new GuardDutyClient(
        getConnectorAwsClientConfig(config.region, config.accessKeyId, config.secretAccessKey) as any,
      );
      const res = await client.send(new ListDetectorsCommand({}));
      if (!res.DetectorIds?.length) throw new Error("No GuardDuty detectors found");
      return { success: true, message: "Successfully connected to guardduty", latencyMs: Date.now() - start };
    } catch (err: unknown) {
      return { success: false, message: (err as Error).message || "Connection failed", latencyMs: Date.now() - start };
    }
  },

  async fetch(config: ConnectorConfig, since?: Date): Promise<unknown[]> {
    const { GuardDutyClient, ListDetectorsCommand, ListFindingsCommand, GetFindingsCommand } = await import("@aws-sdk/client-guardduty");
    const { getConnectorAwsClientConfig } = await import("../aws-credentials");
    const client = new GuardDutyClient(
      getConnectorAwsClientConfig(config.region, config.accessKeyId, config.secretAccessKey) as any,
    );
    const detectorsRes = await client.send(new ListDetectorsCommand({}));
    const detectorId = detectorsRes.DetectorIds?.[0];
    if (!detectorId) return [];
    const criterion: Record<string, Record<string, number>> = { severity: { Gte: 4 } };
    if (since) {
      criterion.updatedAt = { Gte: since.getTime() };
    }
    const findingsRes = await client.send(new ListFindingsCommand({
      DetectorId: detectorId,
      FindingCriteria: { Criterion: criterion },
      MaxResults: 50,
    }));
    if (!findingsRes.FindingIds?.length) return [];
    const detailsRes = await client.send(new GetFindingsCommand({
      DetectorId: detectorId,
      FindingIds: findingsRes.FindingIds,
    }));
    return detailsRes.Findings || [];
  },

  normalize(raw: unknown): Partial<InsertAlert> {
    const r = raw as Record<string, any>;
    const resource = r.Resource || {};
    const service = r.Service || {};
    const action = service.Action || {};
    return {
      source: "AWS GuardDuty",
      sourceEventId: r.Id || r.id,
      title: r.Title || r.Type || "GuardDuty Finding",
      description: r.Description || "",
      severity: mapSeverity(r.Severity),
      category: mapCategory(r.Type),
      sourceIp: action.NetworkConnectionAction?.RemoteIpDetails?.IpAddressV4 ||
                action.AwsApiCallAction?.RemoteIpDetails?.IpAddressV4,
      hostname: resource.InstanceDetails?.InstanceId,
      domain: action.DnsRequestAction?.Domain,
      detectedAt: r.CreatedAt ? new Date(r.CreatedAt) : new Date(),
      rawData: r,
      normalizedData: {
        accountId: r.AccountId,
        region: r.Region,
        resourceType: r.Resource?.ResourceType,
      },
    };
  },
};

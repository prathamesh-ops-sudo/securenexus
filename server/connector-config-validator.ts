import { z } from "zod";
import { CONNECTOR_TYPES } from "@shared/schema";
import { logger } from "./logger";

const httpsUrl = z.string().url().max(2048).refine(
  (url) => {
    try {
      const parsed = new URL(url);
      return parsed.protocol === "https:" || parsed.protocol === "http:";
    } catch {
      return false;
    }
  },
  { message: "URL must use http or https protocol" },
).refine(
  (url) => {
    try {
      const parsed = new URL(url);
      const host = parsed.hostname.toLowerCase();
      if (host === "localhost" || host === "127.0.0.1" || host === "0.0.0.0" || host === "[::1]") return false;
      if (host.startsWith("10.") || host.startsWith("192.168.") || host.startsWith("169.254.")) return false;
      if (/^172\.(1[6-9]|2\d|3[01])\./.test(host)) return false;
      if (host.startsWith("fc") || host.startsWith("fd")) return false;
      return true;
    } catch {
      return false;
    }
  },
  { message: "URL must not target private or internal networks" },
);

const nonEmptyString = z.string().min(1).max(2048);
const optionalString = z.string().max(2048).optional();

const oauthCredentials = z.object({
  baseUrl: httpsUrl,
  clientId: nonEmptyString,
  clientSecret: nonEmptyString,
});

const apiKeyCredentials = z.object({
  baseUrl: httpsUrl,
  apiKey: nonEmptyString,
});

const basicCredentials = z.object({
  baseUrl: httpsUrl,
  username: nonEmptyString,
  password: nonEmptyString,
});

const awsCredentials = z.object({
  region: nonEmptyString,
  accessKeyId: z.string().min(16).max(128),
  secretAccessKey: nonEmptyString,
});

const tokenCredentials = z.object({
  baseUrl: httpsUrl,
  token: nonEmptyString,
});

const connectorConfigSchemas: Partial<Record<string, z.ZodType>> = {
  crowdstrike: oauthCredentials.extend({
    clientId: nonEmptyString,
    clientSecret: nonEmptyString,
  }),

  splunk: z.object({
    baseUrl: httpsUrl,
    token: nonEmptyString,
    searchQuery: optionalString,
    indexPattern: optionalString,
  }),

  wiz: oauthCredentials.extend({
    clientId: nonEmptyString,
    clientSecret: nonEmptyString,
  }),

  wazuh: basicCredentials,

  paloalto: apiKeyCredentials,

  guardduty: awsCredentials.extend({
    baseUrl: z.string().max(2048).optional(),
  }),

  defender: z.object({
    baseUrl: httpsUrl,
    tenantId: nonEmptyString,
    clientId: nonEmptyString,
    clientSecret: nonEmptyString,
  }),

  sentinelone: apiKeyCredentials,

  elastic: z.object({
    baseUrl: httpsUrl,
    username: optionalString,
    password: optionalString,
    apiKey: optionalString,
    indexPattern: optionalString,
  }),

  qradar: z.object({
    baseUrl: httpsUrl,
    token: nonEmptyString,
  }),

  fortigate: apiKeyCredentials,

  carbonblack: z.object({
    baseUrl: httpsUrl,
    apiKey: nonEmptyString,
    orgKey: nonEmptyString,
  }),

  qualys: z.object({
    baseUrl: httpsUrl,
    username: nonEmptyString,
    password: nonEmptyString,
  }),

  tenable: z.object({
    baseUrl: httpsUrl,
    accessKeyId: nonEmptyString,
    secretAccessKey: nonEmptyString,
  }),

  umbrella: z.object({
    baseUrl: httpsUrl,
    apiKey: nonEmptyString,
    apiSecret: optionalString,
  }),

  darktrace: z.object({
    baseUrl: httpsUrl,
    token: nonEmptyString,
    siteToken: optionalString,
  }),

  rapid7: apiKeyCredentials,

  trendmicro: tokenCredentials,

  okta: z.object({
    baseUrl: httpsUrl,
    apiKey: nonEmptyString,
  }),

  proofpoint: basicCredentials,

  snort: z.object({
    baseUrl: httpsUrl,
    apiKey: optionalString,
    username: optionalString,
    password: optionalString,
  }),

  zscaler: z.object({
    baseUrl: httpsUrl,
    username: nonEmptyString,
    password: nonEmptyString,
    apiKey: nonEmptyString,
  }),

  checkpoint: z.object({
    baseUrl: httpsUrl,
    username: nonEmptyString,
    password: nonEmptyString,
    datacenter: optionalString,
  }),
};

export interface ConnectorValidationResult {
  valid: boolean;
  errors: string[];
}

export function validateConnectorConfig(
  connectorType: string,
  config: Record<string, unknown>,
): ConnectorValidationResult {
  const schema = connectorConfigSchemas[connectorType];
  if (!schema) {
    if (!(CONNECTOR_TYPES as readonly string[]).includes(connectorType)) {
      return { valid: false, errors: [`Unknown connector type: ${connectorType}`] };
    }
    return { valid: true, errors: [] };
  }

  const result = schema.safeParse(config);
  if (!result.success) {
    const errors = result.error.issues.map(
      (issue) => `${issue.path.join(".")}: ${issue.message}`,
    );
    logger.child("connector-validator").warn("Connector config validation failed", {
      connectorType,
      errorCount: errors.length,
    });
    return { valid: false, errors };
  }

  return { valid: true, errors: [] };
}

export function getRequiredFields(connectorType: string): string[] {
  const fieldMap: Record<string, string[]> = {
    crowdstrike: ["baseUrl", "clientId", "clientSecret"],
    splunk: ["baseUrl", "token"],
    wiz: ["baseUrl", "clientId", "clientSecret"],
    wazuh: ["baseUrl", "username", "password"],
    paloalto: ["baseUrl", "apiKey"],
    guardduty: ["region", "accessKeyId", "secretAccessKey"],
    defender: ["baseUrl", "tenantId", "clientId", "clientSecret"],
    sentinelone: ["baseUrl", "apiKey"],
    elastic: ["baseUrl"],
    qradar: ["baseUrl", "token"],
    fortigate: ["baseUrl", "apiKey"],
    carbonblack: ["baseUrl", "apiKey", "orgKey"],
    qualys: ["baseUrl", "username", "password"],
    tenable: ["baseUrl", "accessKeyId", "secretAccessKey"],
    umbrella: ["baseUrl", "apiKey"],
    darktrace: ["baseUrl", "token"],
    rapid7: ["baseUrl", "apiKey"],
    trendmicro: ["baseUrl", "token"],
    okta: ["baseUrl", "apiKey"],
    proofpoint: ["baseUrl", "username", "password"],
    snort: ["baseUrl"],
    zscaler: ["baseUrl", "username", "password", "apiKey"],
    checkpoint: ["baseUrl", "username", "password"],
  };
  return fieldMap[connectorType] ?? ["baseUrl"];
}

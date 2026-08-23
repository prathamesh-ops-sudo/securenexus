import type { InsertAlert } from "@shared/schema";

export interface ConnectorConfig {
  baseUrl: string;
  clientId?: string;
  clientSecret?: string;
  apiKey?: string;
  username?: string;
  password?: string;
  region?: string;
  accessKeyId?: string;
  secretAccessKey?: string;
  token?: string;
  tenantId?: string;
  searchQuery?: string;
  indexPattern?: string;
  datacenter?: string;
  siteToken?: string;
  orgKey?: string;
}

export interface ConnectorTestResult {
  success: boolean;
  message: string;
  latencyMs: number;
  details?: unknown;
  preview?: Array<{ timestamp: string; title: string; description: string }>;
}

export interface SyncResult {
  alertsReceived: number;
  alertsCreated: number;
  alertsDeduped: number;
  alertsFailed: number;
  errors: string[];
  rawAlerts: Partial<InsertAlert>[];
  errorStatus?: number;
}

export type AuthType = "oauth2" | "basic" | "api_key" | "token" | "aws_credentials";

export interface ConnectorFieldMeta {
  key: string;
  label: string;
  type: "url" | "text" | "password";
  placeholder: string;
}

export interface ConnectorMetadata {
  name: string;
  description: string;
  authType: AuthType;
  requiredFields: ConnectorFieldMeta[];
  optionalFields: ConnectorFieldMeta[];
  icon: string;
  docsUrl: string;
}

export interface ConnectorPlugin {
  readonly type: string;
  readonly alertSource: string;
  readonly normalizerKey: string;
  readonly metadata: ConnectorMetadata;

  test(config: ConnectorConfig): Promise<ConnectorTestResult>;
  fetch(config: ConnectorConfig, since?: Date): Promise<unknown[]>;
  normalize(raw: unknown): Partial<InsertAlert>;
}

const MAX_ERROR_BODY_LENGTH = 1_000;

export class ConnectorHttpError extends Error {
  readonly status: number;
  readonly responseBody: string;
  readonly retryAfter: string | null;

  constructor(status: number, url: string, responseBody: string, retryAfter: string | null) {
    super(`Connector upstream returned HTTP ${status} for ${url}`);
    this.name = "ConnectorHttpError";
    this.status = status;
    this.responseBody = responseBody.slice(0, MAX_ERROR_BODY_LENGTH);
    this.retryAfter = retryAfter;
  }
}

export function getConnectorTestErrorMessage(error: unknown): string {
  if (error instanceof ConnectorHttpError) {
    if (error.status === 401 || error.status === 403) return "Authentication failed — verify vendor credentials.";
    if (error.status === 429) return "Vendor rate limit reached. Try again later.";
    return `Vendor returned HTTP ${error.status}.`;
  }
  if (error instanceof Error && error.message) return error.message;
  return "Connection failed";
}

const registry = new Map<string, ConnectorPlugin>();

export function registerPlugin(plugin: ConnectorPlugin): void {
  if (registry.has(plugin.type)) {
    throw new Error(`Connector plugin "${plugin.type}" is already registered.`);
  }
  registry.set(plugin.type, plugin);
}

export function getPlugin(type: string): ConnectorPlugin | undefined {
  return registry.get(type);
}

export function getAllPlugins(): ConnectorPlugin[] {
  return Array.from(registry.values());
}

export function getAllPluginTypes(): string[] {
  return Array.from(registry.keys());
}

export function getPluginMetadata(type: string): ConnectorMetadata | null {
  const plugin = registry.get(type);
  return plugin ? plugin.metadata : null;
}

export function httpRequest(
  url: string,
  options: {
    method?: string;
    headers?: Record<string, string>;
    body?: unknown;
    timeout?: number;
  },
): Promise<{ status: number; data: unknown }> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), options.timeout || 30000);
  return fetch(url, {
    method: options.method || "GET",
    headers: options.headers,
    body: options.body ? JSON.stringify(options.body) : undefined,
    signal: controller.signal,
  })
    .then(async (res) => {
      clearTimeout(timeoutId);
      const text = await res.text();
      if (!res.ok) {
        throw new ConnectorHttpError(res.status, url, text, res.headers.get("retry-after"));
      }
      let data: unknown;
      try {
        data = JSON.parse(text);
      } catch {
        data = text;
      }
      return { status: res.status, data };
    })
    .catch((err: Error) => {
      clearTimeout(timeoutId);
      if (err.name === "AbortError") throw new Error("Request timed out");
      throw err;
    });
}

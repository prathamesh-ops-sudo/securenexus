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
}

export interface SyncResult {
  alertsReceived: number;
  alertsCreated: number;
  alertsDeduped: number;
  alertsFailed: number;
  errors: string[];
  rawAlerts: Partial<InsertAlert>[];
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

export function httpRequest(url: string, options: {
  method?: string;
  headers?: Record<string, string>;
  body?: unknown;
  timeout?: number;
}): Promise<{ status: number; data: unknown }> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), options.timeout || 30000);
  return fetch(url, {
    method: options.method || "GET",
    headers: options.headers,
    body: options.body ? JSON.stringify(options.body) : undefined,
    signal: controller.signal,
  }).then(async (res) => {
    clearTimeout(timeoutId);
    const text = await res.text();
    let data: unknown;
    try { data = JSON.parse(text); } catch { data = text; }
    return { status: res.status, data };
  }).catch((err: Error) => {
    clearTimeout(timeoutId);
    if (err.name === "AbortError") throw new Error("Request timed out");
    throw err;
  });
}

/**
 * Agent Configuration — persistent config stored on disk
 */

import * as fs from "fs";
import * as path from "path";
import * as os from "os";

export interface AgentConfig {
  serverUrl: string;
  sensorId: string;
  apiKey: string;
  hostname: string;
  platform: string;
  heartbeatInterval: number; // seconds
  eventBatchSize: number;
  eventFlushInterval: number; // seconds
  autoStart: boolean;
  collectors: {
    process: boolean;
    network: boolean;
    file: boolean;
    auth: boolean;
    usb: boolean;
    dns: boolean;
    syslog: boolean;
  };
}

const DEFAULT_CONFIG: AgentConfig = {
  serverUrl: "",
  sensorId: "",
  apiKey: "",
  hostname: os.hostname(),
  platform: process.platform,
  heartbeatInterval: 30,
  eventBatchSize: 100,
  eventFlushInterval: 10,
  autoStart: true,
  collectors: {
    process: true,
    network: true,
    file: true,
    auth: true,
    usb: true,
    dns: true,
    syslog: true,
  },
};

function getConfigDir(): string {
  const configDir =
    process.platform === "win32"
      ? path.join(process.env.PROGRAMDATA || "C:\\ProgramData", "ATS-Sensor")
      : process.platform === "darwin"
        ? path.join(os.homedir(), "Library", "Application Support", "ATS-Sensor")
        : path.join("/etc", "ats-sensor");

  if (!fs.existsSync(configDir)) {
    fs.mkdirSync(configDir, { recursive: true, mode: 0o700 });
  }
  return configDir;
}

function getConfigPath(): string {
  return path.join(getConfigDir(), "config.json");
}

export function loadConfig(): AgentConfig {
  const configPath = getConfigPath();
  try {
    if (fs.existsSync(configPath)) {
      const raw = fs.readFileSync(configPath, "utf-8");
      const parsed = JSON.parse(raw);
      return {
        ...DEFAULT_CONFIG,
        ...parsed,
        collectors: { ...DEFAULT_CONFIG.collectors, ...(parsed.collectors || {}) },
      };
    }
  } catch {
    // Fall through to default
  }
  return { ...DEFAULT_CONFIG };
}

export function saveConfig(partial: Partial<AgentConfig>): void {
  const current = loadConfig();
  const merged = { ...current, ...partial, collectors: { ...current.collectors, ...(partial.collectors || {}) } };
  const configPath = getConfigPath();
  fs.writeFileSync(configPath, JSON.stringify(merged, null, 2), { mode: 0o600 });
}

export function isConfigured(): boolean {
  const config = loadConfig();
  return !!(config.serverUrl && config.sensorId && config.apiKey);
}

export function getConfigDir_public(): string {
  return getConfigDir();
}

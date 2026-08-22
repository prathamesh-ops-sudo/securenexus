/**
 * API Client — communicates with SecureNexus backend
 */

import { AgentConfig } from "./config";
import { AgentLogger } from "./logger";
import * as os from "os";
import { randomUUID } from "crypto";
import { execFile } from "child_process";
import { promisify } from "util";

const execFileAsync = promisify(execFile);

const log = new AgentLogger("api-client");

interface SensorEvent {
  eventType: string;
  timestamp: string;
  [key: string]: unknown;
}

interface PackageInventoryItem {
  packageManager: "apt" | "rpm" | "apk" | "brew" | "windows" | "windows-registry";
  packageName: string;
  installedVersion: string;
  source: string;
}

interface HostMetrics {
  cpuUsage?: number;
  memoryUsage?: number;
  diskUsage?: number;
  ipAddress?: string;
  arch?: string;
  cpuCount?: number;
  memoryGb?: number;
}

export class ApiClient {
  private config: AgentConfig;
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;
  private packageTimer: ReturnType<typeof setInterval> | null = null;
  private connected = false;
  private stats = { eventsSent: 0, lastHeartbeat: null as string | null, errors: 0 };

  constructor(config: AgentConfig) {
    this.config = config;
  }

  async testConnection(): Promise<boolean> {
    try {
      const resp = await fetch(`${this.config.serverUrl}/api/agent/v1/sensors/${this.config.sensorId}/heartbeat`, {
        method: "POST",
        headers: this.getHeaders(),
        body: JSON.stringify({ ...this.getHostMetrics(), agentVersion: "1.0.0" }),
        signal: AbortSignal.timeout(10000),
      });
      this.connected = resp.ok;
      if (resp.ok) {
        this.stats.lastHeartbeat = new Date().toISOString();
        log.info("Connection test successful");
      } else {
        log.error(`Connection test failed: HTTP ${resp.status}`);
      }
      return resp.ok;
    } catch (err) {
      log.error(`Connection test failed: ${err}`);
      this.connected = false;
      return false;
    }
  }

  startHeartbeat(): void {
    if (this.heartbeatTimer) return;

    const interval = (this.config.heartbeatInterval || 30) * 1000;
    this.heartbeatTimer = setInterval(() => this.sendHeartbeat(), interval);
    void this.sendPackageInventory();
    this.packageTimer = setInterval(() => this.sendPackageInventory(), 6 * 60 * 60 * 1000);
    log.info(`Heartbeat started (every ${this.config.heartbeatInterval}s)`);
  }

  stopHeartbeat(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
      log.info("Heartbeat stopped");
    }
    if (this.packageTimer) {
      clearInterval(this.packageTimer);
      this.packageTimer = null;
    }
  }

  private async sendHeartbeat(): Promise<void> {
    try {
      const resp = await fetch(`${this.config.serverUrl}/api/agent/v1/sensors/${this.config.sensorId}/heartbeat`, {
        method: "POST",
        headers: this.getHeaders(),
        body: JSON.stringify({
          ...this.getHostMetrics(),
          agentVersion: "1.0.0",
        }),
        signal: AbortSignal.timeout(10000),
      });

      if (resp.ok) {
        this.connected = true;
        this.stats.lastHeartbeat = new Date().toISOString();
      } else {
        this.connected = false;
        this.stats.errors++;
        log.warn(`Heartbeat failed: HTTP ${resp.status}`);
      }
    } catch (err) {
      this.connected = false;
      this.stats.errors++;
      log.warn(`Heartbeat error: ${err}`);
    }
  }

  private async sendPackageInventory(): Promise<void> {
    try {
      const packages = await this.collectPackageInventory();
      if (packages.length === 0) return;
      const resp = await fetch(`${this.config.serverUrl}/api/agent/v1/sensors/${this.config.sensorId}/packages`, {
        method: "POST",
        headers: this.getHeaders(),
        body: JSON.stringify({
          batchId: `agent-${randomUUID()}`,
          packages,
        }),
        signal: AbortSignal.timeout(30000),
      });
      if (!resp.ok) {
        this.stats.errors++;
        log.error(`Package inventory upload failed: HTTP ${resp.status}`);
        return;
      }
      log.info(`Package inventory uploaded: ${packages.length} packages`);
    } catch (err) {
      this.stats.errors++;
      log.error(`Package inventory collection failed: ${err}`);
    }
  }

  private async collectPackageInventory(): Promise<PackageInventoryItem[]> {
    if (process.platform === "win32") {
      const packageResult = await this.runOptionalCommand("powershell", [
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "Get-Package | Select-Object Name,Version | ConvertTo-Json -Compress",
      ]);
      const registryResult = await this.runOptionalCommand("powershell", [
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "$paths=@('HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'); Get-ItemProperty $paths | Where-Object { $_.DisplayName -and $_.DisplayVersion } | Select-Object @{Name='Name';Expression={$_.DisplayName}},@{Name='Version';Expression={$_.DisplayVersion}} | ConvertTo-Json -Compress",
      ]);
      const packages: PackageInventoryItem[] = [];
      for (const [result, packageManager, source] of [
        [packageResult, "windows", "Get-Package"],
        [registryResult, "windows-registry", "Windows uninstall registry"],
      ] as const) {
        if (!result) continue;
        try {
          const parsed = JSON.parse(result) as
            | Array<{ Name?: string; Version?: string }>
            | { Name?: string; Version?: string };
          const rows = Array.isArray(parsed) ? parsed : [parsed];
          packages.push(
            ...rows
              .filter((row) => row.Name && row.Version)
              .map((row) => ({
                packageManager,
                packageName: row.Name as string,
                installedVersion: row.Version as string,
                source,
              })),
          );
        } catch (err) {
          log.error(`Windows package inventory parse failed (${source}): ${err}`);
        }
      }
      return packages;
    }

    const commands: Array<{
      packageManager: PackageInventoryItem["packageManager"];
      command: string;
      args: string[];
      source: string;
      parse: (output: string) => PackageInventoryItem[];
    }> = [
      {
        packageManager: "apt",
        command: "dpkg-query",
        args: ["-W", "-f=${binary:Package}\\t${Version}\\n"],
        source: "dpkg-query",
        parse: (output) =>
          output
            .split("\n")
            .filter(Boolean)
            .flatMap((line) => {
              const [packageName, installedVersion] = line.split("\t");
              return packageName && installedVersion
                ? [{ packageManager: "apt", packageName, installedVersion, source: "dpkg-query" }]
                : [];
            }),
      },
      {
        packageManager: "rpm",
        command: "rpm",
        args: ["-qa", "--qf", "%{NAME}\\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\\n"],
        source: "rpm",
        parse: (output) =>
          output
            .split("\n")
            .filter(Boolean)
            .flatMap((line) => {
              const [packageName, installedVersion] = line.split("\t");
              return packageName && installedVersion
                ? [{ packageManager: "rpm", packageName, installedVersion, source: "rpm" }]
                : [];
            }),
      },
      {
        packageManager: "apk",
        command: "apk",
        args: ["info", "-v"],
        source: "apk",
        parse: (output) =>
          output
            .split("\n")
            .filter(Boolean)
            .flatMap((line) => {
              const separator = line.lastIndexOf("-");
              if (separator <= 0) return [];
              return [
                {
                  packageManager: "apk",
                  packageName: line.slice(0, separator),
                  installedVersion: line.slice(separator + 1),
                  source: "apk",
                },
              ];
            }),
      },
      {
        packageManager: "brew",
        command: "brew",
        args: ["list", "--versions"],
        source: "brew",
        parse: (output) =>
          output
            .split("\n")
            .filter(Boolean)
            .flatMap((line) => {
              const [packageName, installedVersion] = line.trim().split(/\s+/, 2);
              return packageName && installedVersion
                ? [{ packageManager: "brew", packageName, installedVersion, source: "brew" }]
                : [];
            }),
      },
    ];
    const collected: PackageInventoryItem[] = [];
    for (const entry of commands) {
      const output = await this.runOptionalCommand(entry.command, entry.args);
      if (output) collected.push(...entry.parse(output));
    }
    return collected;
  }

  private async runOptionalCommand(command: string, args: string[]): Promise<string | null> {
    try {
      const result = await execFileAsync(command, args, { maxBuffer: 10 * 1024 * 1024 });
      return result.stdout;
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === "ENOENT") return null;
      log.error(`Optional inventory command failed (${command}): ${err}`);
      return null;
    }
  }

  private getHostMetrics(): HostMetrics {
    const metrics: HostMetrics = {};
    const load = os.loadavg()[0];
    const cpuCount = os.cpus().length;
    if (Number.isFinite(load) && cpuCount > 0) metrics.cpuUsage = Math.min(100, Math.max(0, (load / cpuCount) * 100));
    const totalMemory = os.totalmem();
    const freeMemory = os.freemem();
    if (totalMemory > 0) metrics.memoryUsage = ((totalMemory - freeMemory) / totalMemory) * 100;
    metrics.arch = os.arch();
    if (cpuCount > 0) metrics.cpuCount = cpuCount;
    if (totalMemory > 0) metrics.memoryGb = totalMemory / 1024 ** 3;
    const interfaces = Object.values(os.networkInterfaces()).flatMap((items) => items ?? []);
    const address = interfaces.find((item) => !item.internal && item.family === "IPv4")?.address;
    if (address) metrics.ipAddress = address;
    return metrics;
  }

  async sendEvents(events: SensorEvent[]): Promise<{ accepted: number; alertsCreated: number }> {
    if (events.length === 0) return { accepted: 0, alertsCreated: 0 };

    try {
      const resp = await fetch(`${this.config.serverUrl}/api/agent/v1/sensors/${this.config.sensorId}/events`, {
        method: "POST",
        headers: this.getHeaders(),
        body: JSON.stringify({ events }),
        signal: AbortSignal.timeout(30000),
      });

      if (!resp.ok) {
        this.stats.errors++;
        log.warn(`Event send failed: HTTP ${resp.status}`);
        return { accepted: 0, alertsCreated: 0 };
      }

      const result = (await resp.json()) as { accepted?: number; alertsCreated?: number };
      const accepted = result.accepted ?? events.length;
      const alertsCreated = result.alertsCreated ?? 0;
      this.stats.eventsSent += accepted;

      log.info(`Events sent: ${accepted} accepted, ${alertsCreated} alerts`);
      return { accepted, alertsCreated };
    } catch (err) {
      this.stats.errors++;
      log.error(`Event send error: ${err}`);
      return { accepted: 0, alertsCreated: 0 };
    }
  }

  isConnected(): boolean {
    return this.connected;
  }

  getStats(): { eventsSent: number; lastHeartbeat: string | null; errors: number } {
    return { ...this.stats };
  }

  private getHeaders(): Record<string, string> {
    return {
      "Content-Type": "application/json",
      "X-API-Key": this.config.apiKey,
    };
  }
}

/**
 * API Client — communicates with SecureNexus backend
 */

import { AgentConfig } from "./config";
import { AgentLogger } from "./logger";
import * as os from "os";

const log = new AgentLogger("api-client");

interface SensorEvent {
  eventType: string;
  timestamp: string;
  [key: string]: unknown;
}

export class ApiClient {
  private config: AgentConfig;
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;
  private connected = false;
  private stats = { eventsSent: 0, lastHeartbeat: null as string | null, errors: 0 };

  constructor(config: AgentConfig) {
    this.config = config;
  }

  async testConnection(): Promise<boolean> {
    try {
      const resp = await fetch(`${this.config.serverUrl}/api/native-sensors/${this.config.sensorId}/heartbeat`, {
        method: "POST",
        headers: this.getHeaders(),
        body: JSON.stringify({
          cpuUsage: 0,
          memoryUsage: 0,
          diskUsage: 0,
          agentVersion: "1.0.0",
        }),
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
    log.info(`Heartbeat started (every ${this.config.heartbeatInterval}s)`);
  }

  stopHeartbeat(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
      log.info("Heartbeat stopped");
    }
  }

  private async sendHeartbeat(): Promise<void> {
    try {
      const cpuUsage = os.loadavg()[0]; // 1-min load average
      const totalMem = os.totalmem();
      const freeMem = os.freemem();
      const memoryUsage = ((totalMem - freeMem) / totalMem) * 100;

      const resp = await fetch(`${this.config.serverUrl}/api/native-sensors/${this.config.sensorId}/heartbeat`, {
        method: "POST",
        headers: this.getHeaders(),
        body: JSON.stringify({
          cpuUsage: Math.round(cpuUsage * 10) / 10,
          memoryUsage: Math.round(memoryUsage * 10) / 10,
          diskUsage: 0,
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

  async sendEvents(events: SensorEvent[]): Promise<{ accepted: number; alertsCreated: number }> {
    if (events.length === 0) return { accepted: 0, alertsCreated: 0 };

    try {
      const resp = await fetch(`${this.config.serverUrl}/api/native-sensors/${this.config.sensorId}/events`, {
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

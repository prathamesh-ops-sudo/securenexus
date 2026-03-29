/**
 * Collector Manager — orchestrates all system event collectors
 */

import { AgentConfig } from "../config";
import { ApiClient } from "../api-client";
import { AgentLogger } from "../logger";
import { ProcessCollector } from "./process-collector";
import { NetworkCollector } from "./network-collector";
import { FileCollector } from "./file-collector";
import { AuthCollector } from "./auth-collector";
import { UsbCollector } from "./usb-collector";
import { DnsCollector } from "./dns-collector";
import { SyslogCollector } from "./syslog-collector";

const log = new AgentLogger("collector-manager");

export interface SensorEvent {
  eventType: string;
  timestamp: string;
  [key: string]: unknown;
}

export interface Collector {
  name: string;
  collect(): Promise<SensorEvent[]>;
  start?(): Promise<void>;
  stop?(): void;
}

export class CollectorManager {
  private apiClient: ApiClient;
  private config: AgentConfig;
  private collectors: Collector[] = [];
  private flushTimer: ReturnType<typeof setInterval> | null = null;
  private collectTimer: ReturnType<typeof setInterval> | null = null;
  private eventBuffer: SensorEvent[] = [];
  private running = false;
  private stats = { totalEvents: 0, totalAlerts: 0 };

  constructor(apiClient: ApiClient, config: AgentConfig) {
    this.apiClient = apiClient;
    this.config = config;
  }

  async start(): Promise<void> {
    if (this.running) return;

    log.info("Starting collectors...");

    // Initialize enabled collectors
    if (this.config.collectors.process) {
      this.collectors.push(new ProcessCollector());
    }
    if (this.config.collectors.network) {
      this.collectors.push(new NetworkCollector());
    }
    if (this.config.collectors.file) {
      this.collectors.push(new FileCollector());
    }
    if (this.config.collectors.auth) {
      this.collectors.push(new AuthCollector());
    }
    if (this.config.collectors.usb) {
      this.collectors.push(new UsbCollector());
    }
    if (this.config.collectors.dns) {
      this.collectors.push(new DnsCollector());
    }
    if (this.config.collectors.syslog) {
      this.collectors.push(new SyslogCollector());
    }

    // Start any collectors that need initialization
    for (const collector of this.collectors) {
      try {
        if (collector.start) {
          await collector.start();
        }
        log.info(`Collector started: ${collector.name}`);
      } catch (err) {
        log.error(`Failed to start collector ${collector.name}: ${err}`);
      }
    }

    // Collection interval — run every 5 seconds
    this.collectTimer = setInterval(() => this.runCollection(), 5000);

    // Flush interval — send events to server
    const flushMs = (this.config.eventFlushInterval || 10) * 1000;
    this.flushTimer = setInterval(() => this.flushEvents(), flushMs);

    this.running = true;
    log.info(`${this.collectors.length} collectors active`);
  }

  async stop(): Promise<void> {
    if (!this.running) return;

    if (this.collectTimer) {
      clearInterval(this.collectTimer);
      this.collectTimer = null;
    }
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }

    for (const collector of this.collectors) {
      try {
        collector.stop?.();
      } catch {
        // Ignore stop errors
      }
    }

    // Final flush
    await this.flushEvents();

    this.collectors = [];
    this.running = false;
    log.info("All collectors stopped");
  }

  isRunning(): boolean {
    return this.running;
  }

  getStats(): { totalEvents: number; totalAlerts: number } {
    return { ...this.stats };
  }

  private async runCollection(): Promise<void> {
    for (const collector of this.collectors) {
      try {
        const events = await collector.collect();
        if (events.length > 0) {
          this.eventBuffer.push(...events);
          this.stats.totalEvents += events.length;
        }
      } catch (err) {
        log.warn(`Collector ${collector.name} error: ${err}`);
      }
    }

    // Auto-flush if buffer exceeds batch size
    if (this.eventBuffer.length >= (this.config.eventBatchSize || 100)) {
      await this.flushEvents();
    }
  }

  private async flushEvents(): Promise<void> {
    if (this.eventBuffer.length === 0) return;

    const batch = this.eventBuffer.splice(0, this.config.eventBatchSize || 100);
    const result = await this.apiClient.sendEvents(batch);

    if (result.accepted === 0 && batch.length > 0) {
      // Re-queue failed events (up to 500 max buffer)
      if (this.eventBuffer.length < 500) {
        this.eventBuffer.unshift(...batch);
      } else {
        log.warn(`Dropping ${batch.length} events — buffer full`);
      }
    }

    this.stats.totalAlerts += result.alertsCreated;
  }
}

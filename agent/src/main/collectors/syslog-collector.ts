/**
 * Syslog Collector — monitors system logs for security-relevant events
 */

import { execSync } from "child_process";
import { AgentLogger } from "../logger";
import type { Collector, SensorEvent } from "./index";

const log = new AgentLogger("syslog-collector");

const SECURITY_KEYWORDS = [
  "segfault",
  "kernel panic",
  "oom-killer",
  "firewall",
  "iptables",
  "nftables",
  "ufw",
  "apparmor",
  "selinux",
  "denied",
  "failed",
  "error",
  "warning",
  "critical",
  "cron",
  "systemd",
  "service",
  "mount",
  "umount",
];

export class SyslogCollector implements Collector {
  name = "syslog";

  async collect(): Promise<SensorEvent[]> {
    const events: SensorEvent[] = [];
    const now = new Date().toISOString();

    try {
      if (process.platform === "linux") {
        events.push(...this.collectLinux(now));
      } else if (process.platform === "darwin") {
        events.push(...this.collectMacOS(now));
      } else if (process.platform === "win32") {
        events.push(...this.collectWindows(now));
      }
    } catch (err) {
      log.warn(`Syslog collection error: ${err}`);
    }

    return events;
  }

  private collectLinux(now: string): SensorEvent[] {
    const events: SensorEvent[] = [];

    try {
      // Use journalctl for recent security-relevant entries
      const output = execSync("journalctl --since '30 seconds ago' --no-pager -q -p warning 2>/dev/null | head -30", {
        timeout: 5000,
        encoding: "utf-8",
      });

      for (const line of output.trim().split("\n")) {
        if (!line.trim()) continue;
        const lower = line.toLowerCase();
        const isRelevant = SECURITY_KEYWORDS.some((kw) => lower.includes(kw));
        if (isRelevant) {
          events.push({
            eventType: "syslog",
            timestamp: now,
            logSource: "journalctl",
            logMessage: line.trim().substring(0, 1000),
          });
        }
      }
    } catch {
      // Try /var/log/syslog or /var/log/messages
      try {
        const output = execSync("tail -30 /var/log/syslog 2>/dev/null || tail -30 /var/log/messages 2>/dev/null", {
          timeout: 5000,
          encoding: "utf-8",
        });
        for (const line of output.trim().split("\n")) {
          if (!line.trim()) continue;
          const lower = line.toLowerCase();
          const isRelevant = SECURITY_KEYWORDS.some((kw) => lower.includes(kw));
          if (isRelevant) {
            events.push({
              eventType: "syslog",
              timestamp: now,
              logSource: "syslog",
              logMessage: line.trim().substring(0, 1000),
            });
          }
        }
      } catch {
        // Ignore
      }
    }

    return events;
  }

  private collectMacOS(now: string): SensorEvent[] {
    const events: SensorEvent[] = [];
    try {
      const output = execSync(
        "log show --last 30s --predicate 'messageType == error OR messageType == fault' 2>/dev/null | head -20",
        { timeout: 10000, encoding: "utf-8" },
      );
      for (const line of output.trim().split("\n")) {
        if (!line.trim() || line.startsWith("Timestamp") || line.startsWith("---")) continue;
        events.push({
          eventType: "syslog",
          timestamp: now,
          logSource: "unified_log",
          logMessage: line.trim().substring(0, 1000),
        });
      }
    } catch {
      // Ignore
    }
    return events;
  }

  private collectWindows(now: string): SensorEvent[] {
    const events: SensorEvent[] = [];
    try {
      // Query System and Application event logs for errors/warnings
      const output = execSync(
        'wevtutil qe System /c:10 /q:"*[System[Level<=3 and TimeCreated[timediff(@SystemTime) <= 30000]]]" /f:text 2>nul',
        { timeout: 10000, encoding: "utf-8" },
      );
      const entries = output.split("Event[").filter((e) => e.trim());
      for (const entry of entries.slice(0, 10)) {
        events.push({
          eventType: "syslog",
          timestamp: now,
          logSource: "windows_system",
          logMessage: entry.trim().substring(0, 1000),
        });
      }
    } catch {
      // Ignore
    }
    return events;
  }
}

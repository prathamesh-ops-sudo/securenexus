/**
 * Auth Collector — monitors authentication events (login, logout, privilege escalation)
 */

import { execSync } from "child_process";
import { AgentLogger } from "../logger";
import type { Collector, SensorEvent } from "./index";

const log = new AgentLogger("auth-collector");

export class AuthCollector implements Collector {
  name = "auth";
  private lastCheckTime = new Date(Date.now() - 60000); // Start from 1 min ago
  private seenLines = new Set<string>(); // Deduplication: track already-reported lines

  async collect(): Promise<SensorEvent[]> {
    const events: SensorEvent[] = [];
    const since = this.lastCheckTime;
    this.lastCheckTime = new Date();

    try {
      if (process.platform === "win32") {
        events.push(...this.collectWindows(since));
      } else if (process.platform === "darwin") {
        events.push(...this.collectMacOS(since));
      } else {
        events.push(...this.collectLinux(since));
      }
    } catch (err) {
      log.warn(`Auth collection error: ${err}`);
    }

    return events;
  }

  private collectLinux(since: Date): SensorEvent[] {
    const events: SensorEvent[] = [];
    const now = new Date().toISOString();

    try {
      // Use journalctl for time-based filtering (avoids re-scanning static files)
      try {
        const sinceStr = since.toISOString();
        const output = execSync(
          `journalctl _COMM=sshd _COMM=sudo _COMM=su _COMM=login --since "${sinceStr}" --no-pager -o short-iso 2>/dev/null | tail -50`,
          { timeout: 5000, encoding: "utf-8" },
        );

        for (const line of output.trim().split("\n")) {
          if (!line.trim()) continue;
          if (this.seenLines.has(line)) continue;
          this.seenLines.add(line);

          const event = this.parseAuthLogLine(line, now);
          if (event) events.push(event);
        }
      } catch {
        // journalctl not available — fallback to grepping log files with dedup
        const logFiles = ["/var/log/auth.log", "/var/log/secure"];
        for (const logFile of logFiles) {
          try {
            const output = execSync(`grep -E '(sshd|sudo|su|login|pam)' ${logFile} 2>/dev/null | tail -50`, {
              timeout: 5000,
              encoding: "utf-8",
            });

            for (const line of output.trim().split("\n")) {
              if (!line.trim()) continue;
              if (this.seenLines.has(line)) continue;
              this.seenLines.add(line);

              const event = this.parseAuthLogLine(line, now);
              if (event) events.push(event);
            }
          } catch {
            // File may not exist or not readable
          }
        }
      }

      // Check lastlog for recent logins (with deduplication)
      try {
        const output = execSync("last -n 10 -F 2>/dev/null | head -10", {
          timeout: 5000,
          encoding: "utf-8",
        });
        for (const line of output.trim().split("\n")) {
          if (!line.trim() || line.includes("wtmp begins") || line.includes("reboot")) continue;
          if (this.seenLines.has(line)) continue;
          this.seenLines.add(line);

          const parts = line.trim().split(/\s+/);
          if (parts.length < 3) continue;

          events.push({
            eventType: "auth_event",
            timestamp: now,
            authAction: "login_success",
            authResult: "success",
            authMethod: "system",
            userName: parts[0],
            srcIp: parts[2] || "",
            logSource: "lastlog",
            logMessage: line.trim().substring(0, 500),
          });
        }
      } catch {
        // Ignore
      }

      // Prune seen-lines set to prevent unbounded memory growth (keep last 5000)
      if (this.seenLines.size > 5000) {
        const entries = Array.from(this.seenLines);
        this.seenLines = new Set(entries.slice(entries.length - 2500));
      }
    } catch (err) {
      log.warn(`Linux auth collection error: ${err}`);
    }

    return events;
  }

  private collectMacOS(since: Date): SensorEvent[] {
    const events: SensorEvent[] = [];
    const now = new Date().toISOString();

    try {
      // Use log show for macOS unified logging
      const sinceStr = since.toISOString().replace("T", " ").split(".")[0];
      const output = execSync(
        `log show --predicate 'subsystem == "com.apple.securityd" OR subsystem == "com.apple.Authorization"' --start "${sinceStr}" 2>/dev/null | head -20`,
        { timeout: 10000, encoding: "utf-8" },
      );

      for (const line of output.trim().split("\n")) {
        if (!line.trim() || line.startsWith("Timestamp")) continue;
        if (this.seenLines.has(line)) continue;
        this.seenLines.add(line);

        events.push({
          eventType: "auth_event",
          timestamp: now,
          authAction: "auth_check",
          authResult: "success",
          authMethod: "macos_unified_log",
          logSource: "unified_log",
          logMessage: line.trim().substring(0, 500),
        });
      }
    } catch {
      // Ignore
    }

    return events;
  }

  private collectWindows(since: Date): SensorEvent[] {
    const events: SensorEvent[] = [];
    const now = new Date().toISOString();

    try {
      // Windows: use wevtutil to query Security event log
      const timeDiffMs = Date.now() - since.getTime();
      const output = execSync(
        `wevtutil qe Security /c:20 /q:"*[System[(EventID=4624 or EventID=4625 or EventID=4634 or EventID=4648 or EventID=4672) and TimeCreated[timediff(@SystemTime) <= ${timeDiffMs}]]]" /f:text 2>nul`,
        { timeout: 10000, encoding: "utf-8" },
      );

      const entries = output.split("Event[").filter((e) => e.trim());
      for (const entry of entries.slice(0, 20)) {
        const eventIdMatch = entry.match(/EventID:\s*(\d+)/i);
        const userMatch = entry.match(/Account Name:\s*(.+)/i);
        const srcIpMatch = entry.match(/Source Network Address:\s*(.+)/i);

        if (!eventIdMatch) continue;

        const eventId = parseInt(eventIdMatch[1]);
        const actionMap: Record<number, string> = {
          4624: "login_success",
          4625: "login_failure",
          4634: "logoff",
          4648: "explicit_credential",
          4672: "privilege_escalation",
        };

        events.push({
          eventType: "auth_event",
          timestamp: now,
          authAction: actionMap[eventId] || "unknown",
          authResult: eventId === 4625 ? "failure" : "success",
          authMethod: "windows_security",
          userName: userMatch?.[1]?.trim() || "unknown",
          srcIp: srcIpMatch?.[1]?.trim() || "",
          logSource: "windows_security_log",
          logMessage: entry.substring(0, 500),
        });
      }
    } catch {
      // Ignore — likely not running as admin
    }

    return events;
  }

  private parseAuthLogLine(line: string, timestamp: string): SensorEvent | null {
    const lower = line.toLowerCase();

    if (lower.includes("accepted") && lower.includes("ssh")) {
      const userMatch = line.match(/for (\S+) from/);
      const ipMatch = line.match(/from (\S+)/);
      return {
        eventType: "auth_event",
        timestamp,
        authAction: "login_success",
        authResult: "success",
        authMethod: "ssh",
        userName: userMatch?.[1] || "unknown",
        srcIp: ipMatch?.[1] || "",
        logSource: "auth.log",
        logMessage: line.substring(0, 500),
      };
    }

    if (lower.includes("failed") && lower.includes("ssh")) {
      const userMatch = line.match(/for (?:invalid user )?(\S+) from/);
      const ipMatch = line.match(/from (\S+)/);
      return {
        eventType: "auth_event",
        timestamp,
        authAction: "login_failure",
        authResult: "failure",
        authMethod: "ssh",
        userName: userMatch?.[1] || "unknown",
        srcIp: ipMatch?.[1] || "",
        logSource: "auth.log",
        logMessage: line.substring(0, 500),
      };
    }

    if (lower.includes("sudo") && lower.includes("command=")) {
      const userMatch = line.match(/:\s+(\S+)\s+:/);
      return {
        eventType: "auth_event",
        timestamp,
        authAction: "privilege_escalation",
        authResult: "success",
        authMethod: "sudo",
        userName: userMatch?.[1] || "unknown",
        logSource: "auth.log",
        logMessage: line.substring(0, 500),
      };
    }

    return null;
  }
}

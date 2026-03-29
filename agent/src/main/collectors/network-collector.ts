/**
 * Network Collector — monitors active network connections and detects suspicious traffic
 */

import { execSync } from "child_process";
import { AgentLogger } from "../logger";
import type { Collector, SensorEvent } from "./index";

const log = new AgentLogger("network-collector");

const SUSPICIOUS_PORTS = new Set([
  4444,
  5555,
  6666,
  1337,
  31337,
  8888,
  9999, // Common backdoor ports
  1234,
  1337,
  3389,
  5900,
  5800, // RDP/VNC if unexpected
]);

const IGNORED_LOCAL_ADDRS = new Set(["127.0.0.1", "::1", "0.0.0.0", "*", ""]);

interface Connection {
  proto: string;
  srcIp: string;
  srcPort: number;
  dstIp: string;
  dstPort: number;
  state: string;
  pid: number;
}

export class NetworkCollector implements Collector {
  name = "network";
  private lastConnections = new Map<string, Connection>();

  async collect(): Promise<SensorEvent[]> {
    const events: SensorEvent[] = [];
    const now = new Date().toISOString();

    try {
      const connections = this.getActiveConnections();
      const currentKeys = new Set<string>();

      for (const conn of connections) {
        const key = `${conn.proto}:${conn.srcIp}:${conn.srcPort}-${conn.dstIp}:${conn.dstPort}`;
        currentKeys.add(key);

        // Skip local/loopback
        if (IGNORED_LOCAL_ADDRS.has(conn.dstIp)) continue;

        const isNew = !this.lastConnections.has(key);
        const isSuspicious = SUSPICIOUS_PORTS.has(conn.dstPort);

        if (isNew || isSuspicious) {
          events.push({
            eventType: "network_connection",
            timestamp: now,
            srcIp: conn.srcIp,
            srcPort: conn.srcPort,
            dstIp: conn.dstIp,
            dstPort: conn.dstPort,
            protocol: conn.proto,
            pid: conn.pid || undefined,
          });
        }
      }

      // Update tracking
      this.lastConnections.clear();
      for (const conn of connections) {
        const key = `${conn.proto}:${conn.srcIp}:${conn.srcPort}-${conn.dstIp}:${conn.dstPort}`;
        this.lastConnections.set(key, conn);
      }
    } catch (err) {
      log.warn(`Network collection error: ${err}`);
    }

    return events;
  }

  private getActiveConnections(): Connection[] {
    try {
      if (process.platform === "win32") {
        return this.parseNetstatWindows();
      } else if (process.platform === "linux") {
        return this.parseSsLinux();
      } else {
        return this.parseNetstatMac();
      }
    } catch {
      return [];
    }
  }

  private parseSsLinux(): Connection[] {
    const results: Connection[] = [];
    try {
      const output = execSync("ss -tunapH 2>/dev/null | head -100", {
        timeout: 5000,
        encoding: "utf-8",
      });
      for (const line of output.trim().split("\n")) {
        if (!line.trim()) continue;
        const parts = line.trim().split(/\s+/);
        if (parts.length < 6) continue;

        const proto = parts[0];
        const state = parts[1];
        const local = parts[4];
        const remote = parts[5];
        const pidInfo = parts[6] || "";

        const [srcIp, srcPortStr] = this.splitAddress(local);
        const [dstIp, dstPortStr] = this.splitAddress(remote);

        const pidMatch = pidInfo.match(/pid=(\d+)/);
        const pid = pidMatch ? parseInt(pidMatch[1]) : 0;

        results.push({
          proto,
          srcIp,
          srcPort: parseInt(srcPortStr) || 0,
          dstIp,
          dstPort: parseInt(dstPortStr) || 0,
          state,
          pid,
        });
      }
    } catch {
      // Fallback to netstat
      return this.parseNetstatLinux();
    }
    return results;
  }

  private parseNetstatLinux(): Connection[] {
    const results: Connection[] = [];
    try {
      const output = execSync("netstat -tunaW 2>/dev/null | tail -n +3 | head -100", {
        timeout: 5000,
        encoding: "utf-8",
      });
      for (const line of output.trim().split("\n")) {
        if (!line.trim()) continue;
        const parts = line.trim().split(/\s+/);
        if (parts.length < 6) continue;

        const proto = parts[0];
        const [srcIp, srcPortStr] = this.splitAddress(parts[3]);
        const [dstIp, dstPortStr] = this.splitAddress(parts[4]);
        const state = parts[5] || "";

        results.push({
          proto,
          srcIp,
          srcPort: parseInt(srcPortStr) || 0,
          dstIp,
          dstPort: parseInt(dstPortStr) || 0,
          state,
          pid: 0,
        });
      }
    } catch {
      // Ignore
    }
    return results;
  }

  private parseNetstatMac(): Connection[] {
    const results: Connection[] = [];
    try {
      const output = execSync("netstat -an -f inet 2>/dev/null | grep -E 'ESTABLISHED|LISTEN' | head -100", {
        timeout: 5000,
        encoding: "utf-8",
      });
      for (const line of output.trim().split("\n")) {
        if (!line.trim()) continue;
        const parts = line.trim().split(/\s+/);
        if (parts.length < 5) continue;

        const proto = parts[0];
        const [srcIp, srcPortStr] = this.splitAddressDot(parts[3]);
        const [dstIp, dstPortStr] = this.splitAddressDot(parts[4]);
        const state = parts[5] || "";

        results.push({
          proto,
          srcIp,
          srcPort: parseInt(srcPortStr) || 0,
          dstIp,
          dstPort: parseInt(dstPortStr) || 0,
          state,
          pid: 0,
        });
      }
    } catch {
      // Ignore
    }
    return results;
  }

  private parseNetstatWindows(): Connection[] {
    const results: Connection[] = [];
    try {
      const output = execSync("netstat -ano 2>nul | findstr ESTABLISHED", {
        timeout: 5000,
        encoding: "utf-8",
      });
      for (const line of output.trim().split("\n")) {
        if (!line.trim()) continue;
        const parts = line.trim().split(/\s+/);
        if (parts.length < 5) continue;

        const proto = parts[0];
        const [srcIp, srcPortStr] = this.splitAddress(parts[1]);
        const [dstIp, dstPortStr] = this.splitAddress(parts[2]);
        const state = parts[3] || "";
        const pid = parseInt(parts[4]) || 0;

        results.push({
          proto,
          srcIp,
          srcPort: parseInt(srcPortStr) || 0,
          dstIp,
          dstPort: parseInt(dstPortStr) || 0,
          state,
          pid,
        });
      }
    } catch {
      // Ignore
    }
    return results;
  }

  private splitAddress(addr: string): [string, string] {
    const lastColon = addr.lastIndexOf(":");
    if (lastColon === -1) return [addr, "0"];
    return [addr.substring(0, lastColon), addr.substring(lastColon + 1)];
  }

  private splitAddressDot(addr: string): [string, string] {
    const lastDot = addr.lastIndexOf(".");
    if (lastDot === -1) return [addr, "0"];
    return [addr.substring(0, lastDot), addr.substring(lastDot + 1)];
  }
}

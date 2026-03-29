/**
 * DNS Collector — monitors DNS queries for suspicious domain lookups
 */

import { execSync } from "child_process";
import * as fs from "fs";
import { AgentLogger } from "../logger";
import type { Collector, SensorEvent } from "./index";

const log = new AgentLogger("dns-collector");

const SUSPICIOUS_TLDS = new Set([
  ".tk",
  ".ml",
  ".ga",
  ".cf",
  ".gq", // Free TLDs used by malware
  ".onion",
  ".bit",
  ".bazar",
  ".xyz",
  ".top",
  ".club",
  ".work",
  ".date",
  ".stream",
]);

const SUSPICIOUS_PATTERNS = [
  /[a-z0-9]{30,}\./i, // Very long random subdomain (DGA)
  /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\.in-addr\.arpa/i, // Reverse DNS (recon)
  /pastebin|paste\.ee|hastebin/i,
  /ngrok|serveo|localtunnel/i, // Tunneling services
  /dnscat|iodine|dns2tcp/i, // DNS tunneling tools
];

export class DnsCollector implements Collector {
  name = "dns";
  private lastPosition = 0;
  private initialized = false;

  async collect(): Promise<SensorEvent[]> {
    const events: SensorEvent[] = [];
    const now = new Date().toISOString();

    try {
      if (process.platform === "linux") {
        events.push(...this.collectLinuxDns(now));
      } else if (process.platform === "darwin") {
        events.push(...this.collectMacDns(now));
      } else if (process.platform === "win32") {
        events.push(...this.collectWindowsDns(now));
      }
    } catch (err) {
      log.warn(`DNS collection error: ${err}`);
    }

    if (!this.initialized) {
      this.initialized = true;
    }

    return events;
  }

  private collectLinuxDns(now: string): SensorEvent[] {
    const events: SensorEvent[] = [];

    // Check systemd-resolved logs
    try {
      const output = execSync(
        "journalctl -u systemd-resolved --since '1 minute ago' --no-pager -q 2>/dev/null | head -50",
        { timeout: 5000, encoding: "utf-8" },
      );
      for (const line of output.trim().split("\n")) {
        if (!line.trim()) continue;
        const domainMatch = line.match(/(?:query|lookup|resolve)\s+(\S+)/i);
        if (domainMatch) {
          const domain = domainMatch[1];
          if (this.isSuspiciousDomain(domain)) {
            events.push({
              eventType: "dns_query",
              timestamp: now,
              dnsQuery: domain,
              dnsType: "A",
              logSource: "systemd-resolved",
              logMessage: `Suspicious DNS query: ${domain}`,
            });
          }
        }
      }
    } catch {
      // May not have systemd-resolved
    }

    // Check /var/log/dnsmasq.log if exists
    try {
      if (fs.existsSync("/var/log/dnsmasq.log")) {
        const output = execSync("tail -50 /var/log/dnsmasq.log 2>/dev/null", {
          timeout: 5000,
          encoding: "utf-8",
        });
        for (const line of output.trim().split("\n")) {
          const match = line.match(/query\[\w+\]\s+(\S+)\s+from/);
          if (match && this.isSuspiciousDomain(match[1])) {
            events.push({
              eventType: "dns_query",
              timestamp: now,
              dnsQuery: match[1],
              dnsType: "A",
              logSource: "dnsmasq",
              logMessage: `Suspicious DNS query: ${match[1]}`,
            });
          }
        }
      }
    } catch {
      // Ignore
    }

    return events;
  }

  private collectMacDns(now: string): SensorEvent[] {
    const events: SensorEvent[] = [];
    try {
      const output = execSync(
        "log show --predicate 'subsystem == \"com.apple.mDNSResponder\"' --last 1m 2>/dev/null | head -20",
        { timeout: 10000, encoding: "utf-8" },
      );
      for (const line of output.trim().split("\n")) {
        const domainMatch = line.match(/query\s+(\S+)/i);
        if (domainMatch && this.isSuspiciousDomain(domainMatch[1])) {
          events.push({
            eventType: "dns_query",
            timestamp: now,
            dnsQuery: domainMatch[1],
            dnsType: "A",
            logSource: "mDNSResponder",
            logMessage: `Suspicious DNS query: ${domainMatch[1]}`,
          });
        }
      }
    } catch {
      // Ignore
    }
    return events;
  }

  private collectWindowsDns(now: string): SensorEvent[] {
    const events: SensorEvent[] = [];
    try {
      // Windows DNS Client events (ETW)
      const output = execSync(
        'wevtutil qe "Microsoft-Windows-DNS-Client/Operational" /c:20 /q:"*[System[TimeCreated[timediff(@SystemTime) <= 60000]]]" /f:text 2>nul',
        { timeout: 10000, encoding: "utf-8" },
      );
      const entries = output.split("Event[").filter((e) => e.trim());
      for (const entry of entries.slice(0, 20)) {
        const domainMatch = entry.match(/Query Name:\s*(\S+)/i);
        if (domainMatch && this.isSuspiciousDomain(domainMatch[1])) {
          events.push({
            eventType: "dns_query",
            timestamp: now,
            dnsQuery: domainMatch[1],
            dnsType: "A",
            logSource: "windows_dns_client",
            logMessage: `Suspicious DNS query: ${domainMatch[1]}`,
          });
        }
      }
    } catch {
      // Ignore
    }
    return events;
  }

  private isSuspiciousDomain(domain: string): boolean {
    const lower = domain.toLowerCase();

    // Check suspicious TLDs
    for (const tld of SUSPICIOUS_TLDS) {
      if (lower.endsWith(tld)) return true;
    }

    // Check suspicious patterns
    for (const pattern of SUSPICIOUS_PATTERNS) {
      if (pattern.test(lower)) return true;
    }

    return false;
  }
}

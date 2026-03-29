/**
 * Process Collector — monitors process creation, termination, and suspicious activity
 */

import { execSync } from "child_process";
import { AgentLogger } from "../logger";
import type { Collector, SensorEvent } from "./index";

const log = new AgentLogger("process-collector");

const SUSPICIOUS_PROCESS_NAMES = new Set([
  "nc",
  "ncat",
  "netcat",
  "socat",
  "nmap",
  "masscan",
  "sqlmap",
  "hydra",
  "john",
  "hashcat",
  "mimikatz",
  "psexec",
  "rubeus",
  "sharphound",
  "bloodhound",
  "lazagne",
  "procdump",
  "certutil",
  "bitsadmin",
  "mshta",
  "rundll32",
  "wscript",
  "cscript",
  "regsvr32",
  "base64",
  "xxd",
]);

const SUSPICIOUS_ARGS_PATTERNS = [
  /reverse.?shell/i,
  /bind.?shell/i,
  /\b(\/dev\/shm|\/tmp\/\.)/i,
  /powershell.*-enc/i,
  /powershell.*downloadstring/i,
  /curl.*\|.*sh/i,
  /wget.*\|.*sh/i,
  /python.*-c.*import.*socket/i,
  /perl.*-e.*socket/i,
  /base64.*-d/i,
  /shadow|passwd/i,
];

export class ProcessCollector implements Collector {
  name = "process";
  private knownPids = new Set<number>();
  private initialized = false;

  async collect(): Promise<SensorEvent[]> {
    const events: SensorEvent[] = [];
    const now = new Date().toISOString();

    try {
      const processes = this.getRunningProcesses();

      for (const proc of processes) {
        if (!proc.pid || proc.pid === process.pid) continue;

        const isNew = !this.knownPids.has(proc.pid);
        const isSuspicious = this.isSuspiciousProcess(proc);

        // On first run, just populate knownPids without generating events
        if (!this.initialized) {
          this.knownPids.add(proc.pid);
          continue;
        }

        if (isNew || isSuspicious) {
          events.push({
            eventType: "process_start",
            timestamp: now,
            processName: proc.name,
            processPath: proc.path || proc.name,
            processArgs: proc.args || "",
            pid: proc.pid,
            ppid: proc.ppid || 0,
            userName: proc.user || "unknown",
          });
          this.knownPids.add(proc.pid);
        }
      }

      // Detect terminated processes
      const currentPids = new Set(processes.map((p) => p.pid));
      for (const oldPid of this.knownPids) {
        if (!currentPids.has(oldPid)) {
          this.knownPids.delete(oldPid);
        }
      }

      if (!this.initialized) {
        this.initialized = true;
        log.info(`Baseline: ${this.knownPids.size} processes tracked`);
      }
    } catch (err) {
      log.warn(`Process collection error: ${err}`);
    }

    return events;
  }

  private getRunningProcesses(): Array<{
    pid: number;
    ppid: number;
    name: string;
    path: string;
    args: string;
    user: string;
  }> {
    try {
      if (process.platform === "win32") {
        const output = execSync(
          "wmic process get ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,Owner /format:csv 2>nul",
          { timeout: 5000, encoding: "utf-8", maxBuffer: 10 * 1024 * 1024 },
        );
        return this.parseWmicOutput(output);
      } else {
        const output = execSync("ps -eo pid,ppid,user,comm,args --no-headers 2>/dev/null", {
          timeout: 5000,
          encoding: "utf-8",
          maxBuffer: 10 * 1024 * 1024,
        });
        return this.parsePsOutput(output);
      }
    } catch {
      return [];
    }
  }

  private parsePsOutput(
    output: string,
  ): Array<{ pid: number; ppid: number; name: string; path: string; args: string; user: string }> {
    const results: Array<{ pid: number; ppid: number; name: string; path: string; args: string; user: string }> = [];
    for (const line of output.trim().split("\n")) {
      if (!line.trim()) continue;
      const parts = line.trim().split(/\s+/);
      if (parts.length < 4) continue;
      const pid = parseInt(parts[0]);
      const ppid = parseInt(parts[1]);
      const user = parts[2];
      const name = parts[3];
      const args = parts.slice(4).join(" ");
      if (isNaN(pid)) continue;
      results.push({ pid, ppid: isNaN(ppid) ? 0 : ppid, name, path: name, args, user });
    }
    return results;
  }

  private parseWmicOutput(
    output: string,
  ): Array<{ pid: number; ppid: number; name: string; path: string; args: string; user: string }> {
    const results: Array<{ pid: number; ppid: number; name: string; path: string; args: string; user: string }> = [];
    const lines = output
      .trim()
      .split("\n")
      .filter((l) => l.trim());
    // WMIC CSV: Node,CommandLine,ExecutablePath,Name,Owner,ParentProcessId,ProcessId
    for (let i = 1; i < lines.length; i++) {
      const parts = lines[i].split(",");
      if (parts.length < 7) continue;
      const pid = parseInt(parts[6]);
      const ppid = parseInt(parts[5]);
      const name = parts[3] || "";
      const path = parts[2] || name;
      const args = parts[1] || "";
      const user = parts[4] || "SYSTEM";
      if (isNaN(pid)) continue;
      results.push({ pid, ppid: isNaN(ppid) ? 0 : ppid, name, path, args, user });
    }
    return results;
  }

  private isSuspiciousProcess(proc: { name: string; args: string }): boolean {
    const nameLower = proc.name.toLowerCase();
    if (SUSPICIOUS_PROCESS_NAMES.has(nameLower)) return true;

    const fullCmd = `${proc.name} ${proc.args}`;
    return SUSPICIOUS_ARGS_PATTERNS.some((pattern) => pattern.test(fullCmd));
  }
}

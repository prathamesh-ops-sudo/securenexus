/**
 * File Collector — monitors sensitive file modifications and suspicious file activity
 */

import * as fs from "fs";
import * as crypto from "crypto";
import { AgentLogger } from "../logger";
import type { Collector, SensorEvent } from "./index";

const log = new AgentLogger("file-collector");

const WATCHED_PATHS_LINUX = [
  "/etc/passwd",
  "/etc/shadow",
  "/etc/sudoers",
  "/etc/ssh/sshd_config",
  "/etc/crontab",
  "/etc/hosts",
  "/root/.ssh/authorized_keys",
  "/etc/pam.d/common-auth",
  "/etc/ld.so.preload",
  "/etc/profile",
  "/etc/bashrc",
];

const WATCHED_PATHS_MACOS = [
  "/etc/hosts",
  "/etc/sudoers",
  "/etc/ssh/sshd_config",
  "/etc/pam.d/sudo",
  "/Library/LaunchDaemons",
  "/Library/LaunchAgents",
];

const WATCHED_PATHS_WINDOWS = [
  "C:\\Windows\\System32\\drivers\\etc\\hosts",
  "C:\\Windows\\System32\\config\\SAM",
  "C:\\Windows\\System32\\config\\SYSTEM",
];

const SUSPICIOUS_TEMP_DIRS_LINUX = ["/tmp", "/dev/shm", "/var/tmp"];
const SUSPICIOUS_TEMP_DIRS_WINDOWS = ["C:\\Windows\\Temp", "C:\\Users\\Public"];
const SUSPICIOUS_EXTENSIONS = new Set([".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".sh", ".py", ".elf"]);

export class FileCollector implements Collector {
  name = "file";
  private fileChecksums = new Map<string, string>();
  private initialized = false;

  async collect(): Promise<SensorEvent[]> {
    const events: SensorEvent[] = [];
    const now = new Date().toISOString();

    // Check watched sensitive files for modifications
    const watchedPaths = this.getWatchedPaths();
    for (const fpath of watchedPaths) {
      try {
        if (!fs.existsSync(fpath)) continue;
        const stat = fs.statSync(fpath);
        if (!stat.isFile()) continue;

        const hash = this.hashFile(fpath);
        if (!hash) continue;

        const prevHash = this.fileChecksums.get(fpath);
        if (prevHash && hash !== prevHash) {
          events.push({
            eventType: "file_modification",
            timestamp: now,
            filePath: fpath,
            fileAction: "modified",
            fileHash: hash,
            fileSize: stat.size,
          });
          log.warn(`Sensitive file modified: ${fpath}`);
        }
        this.fileChecksums.set(fpath, hash);
      } catch {
        // Skip files we can't read
      }
    }

    // Check temp directories for suspicious new files
    if (this.initialized) {
      const tempDirs = this.getTempDirs();
      for (const dir of tempDirs) {
        try {
          if (!fs.existsSync(dir)) continue;
          const files = fs.readdirSync(dir);
          for (const file of files.slice(0, 50)) {
            const fullPath = `${dir}/${file}`;
            try {
              const stat = fs.statSync(fullPath);
              if (!stat.isFile()) continue;

              // Check if created in last minute
              const age = Date.now() - stat.mtimeMs;
              if (age > 60000) continue;

              const ext = file.substring(file.lastIndexOf(".")).toLowerCase();
              if (SUSPICIOUS_EXTENSIONS.has(ext)) {
                events.push({
                  eventType: "file_creation",
                  timestamp: now,
                  filePath: fullPath,
                  fileAction: "created",
                  fileSize: stat.size,
                  logMessage: `Suspicious file in temp directory: ${file}`,
                });
              }
            } catch {
              // Skip
            }
          }
        } catch {
          // Skip
        }
      }
    }

    if (!this.initialized) {
      this.initialized = true;
      log.info(`Baseline: ${this.fileChecksums.size} files tracked`);
    }

    return events;
  }

  private getWatchedPaths(): string[] {
    switch (process.platform) {
      case "win32":
        return WATCHED_PATHS_WINDOWS;
      case "darwin":
        return WATCHED_PATHS_MACOS;
      default:
        return WATCHED_PATHS_LINUX;
    }
  }

  private getTempDirs(): string[] {
    return process.platform === "win32" ? SUSPICIOUS_TEMP_DIRS_WINDOWS : SUSPICIOUS_TEMP_DIRS_LINUX;
  }

  private hashFile(fpath: string): string | null {
    try {
      const content = fs.readFileSync(fpath);
      return crypto.createHash("sha256").update(content).digest("hex");
    } catch {
      return null;
    }
  }
}

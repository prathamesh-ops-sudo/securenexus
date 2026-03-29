/**
 * Agent Logger — writes to file + console
 */

import * as fs from "fs";
import * as path from "path";
import * as os from "os";

export class AgentLogger {
  private module: string;
  private static logDir: string | null = null;

  constructor(module: string) {
    this.module = module;
  }

  static getLogDir(): string {
    if (!AgentLogger.logDir) {
      const dir =
        process.platform === "win32"
          ? path.join(process.env.PROGRAMDATA || "C:\\ProgramData", "ATS-Sensor", "logs")
          : process.platform === "darwin"
            ? path.join(os.homedir(), "Library", "Logs", "ATS-Sensor")
            : "/var/log/ats-sensor";

      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      AgentLogger.logDir = dir;
    }
    return AgentLogger.logDir;
  }

  private write(level: string, message: string): void {
    const ts = new Date().toISOString();
    const line = `${ts} [${level}] [${this.module}] ${message}\n`;

    // Console
    if (level === "ERROR") {
      process.stderr.write(line);
    } else {
      process.stdout.write(line);
    }

    // File
    try {
      const logFile = path.join(AgentLogger.getLogDir(), "agent.log");
      fs.appendFileSync(logFile, line);

      // Rotate if > 10MB
      const stat = fs.statSync(logFile);
      if (stat.size > 10 * 1024 * 1024) {
        const rotated = path.join(AgentLogger.getLogDir(), `agent.${Date.now()}.log`);
        fs.renameSync(logFile, rotated);
      }
    } catch {
      // Swallow file write errors
    }
  }

  info(msg: string): void {
    this.write("INFO", msg);
  }
  warn(msg: string): void {
    this.write("WARN", msg);
  }
  error(msg: string): void {
    this.write("ERROR", msg);
  }
  debug(msg: string): void {
    if (process.env.ATS_DEBUG) {
      this.write("DEBUG", msg);
    }
  }
}

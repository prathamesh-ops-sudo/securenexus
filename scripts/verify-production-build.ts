import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { resolve } from "node:path";

const PORT = Number(process.env.VERIFY_PRODUCTION_BUILD_PORT || 5515);
const HEALTH_URL = `http://127.0.0.1:${PORT}/api/health`;
const STARTUP_TIMEOUT_MS = 30_000;
const SHUTDOWN_TIMEOUT_MS = 10_000;

function delay(ms: number): Promise<void> {
  return new Promise((resolveDelay) => setTimeout(resolveDelay, ms));
}

async function waitForHealth(child: ReturnType<typeof spawn>): Promise<number> {
  const deadline = Date.now() + STARTUP_TIMEOUT_MS;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(`dist/index.cjs exited with code ${child.exitCode} before serving health`);
    }

    try {
      const response = await fetch(HEALTH_URL, { signal: AbortSignal.timeout(1_000) });
      if (response.ok) return response.status;
    } catch {
      // The server may still be running startup migrations and initialization.
    }

    await delay(200);
  }

  throw new Error(`dist/index.cjs did not serve ${HEALTH_URL} within ${STARTUP_TIMEOUT_MS}ms`);
}

async function stopChild(child: ReturnType<typeof spawn>): Promise<void> {
  if (child.exitCode !== null) return;

  await new Promise<void>((resolveStop) => {
    const timeout = setTimeout(() => {
      child.kill("SIGKILL");
      resolveStop();
    }, SHUTDOWN_TIMEOUT_MS);
    child.once("close", () => {
      clearTimeout(timeout);
      resolveStop();
    });
    child.kill("SIGTERM");
  });
}

async function main(): Promise<void> {
  const bundlePath = resolve("dist/index.cjs");
  if (!existsSync(bundlePath)) {
    throw new Error(`Missing ${bundlePath}; run npm run build first`);
  }

  const child = spawn(process.execPath, [bundlePath], {
    env: {
      ...process.env,
      NODE_ENV: "production",
      MIGRATE_ON_STARTUP: "true",
      PORT: String(PORT),
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  child.stdout.on("data", (chunk: Buffer) => {
    output += chunk.toString();
  });
  child.stderr.on("data", (chunk: Buffer) => {
    output += chunk.toString();
  });

  try {
    const status = await waitForHealth(child);
    process.stdout.write(`Production bundle served ${HEALTH_URL} with HTTP ${status}\n`);
  } catch (error) {
    throw new Error(`${error instanceof Error ? error.message : String(error)}\n${output}`);
  } finally {
    await stopChild(child);
  }
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});

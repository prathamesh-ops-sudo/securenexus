import type { NextFunction, Request, Response } from "express";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { and, eq, isNull } from "drizzle-orm";
import { db } from "./db";
import { collectorInstances, nativeSensors } from "../shared/schema";
import { hashApiKey } from "./routes/shared";
import { replyUnauthenticated, ERROR_CODES } from "./api-response";

export interface AgentContext {
  sensorId: string;
  orgId: string;
}

export interface CollectorAgentContext {
  collectorId: string;
  orgId: string;
}

declare module "express-serve-static-core" {
  interface Request {
    agentContext?: AgentContext;
    collectorAgentContext?: CollectorAgentContext;
  }
}

function safeHashEqual(storedHash: string | null | undefined, presentedHash: string): boolean {
  if (!storedHash) return false;
  try {
    const stored = Buffer.from(storedHash, "hex");
    const presented = Buffer.from(presentedHash, "hex");
    return stored.length === presented.length && timingSafeEqual(stored, presented);
  } catch {
    return false;
  }
}

function presentedCredential(req: Request): string | null {
  const apiKey = req.headers["x-api-key"];
  if (typeof apiKey === "string" && apiKey.length > 0) return apiKey;

  const authorization = req.headers.authorization;
  if (!authorization) return null;
  const match = /^Bearer\s+(.+)$/i.exec(authorization);
  return match?.[1] ?? null;
}

function sensorIdFromCredential(credential: string): string | null {
  const match = /^snx_agent_([0-9a-f-]{36})_[a-f0-9]{64}$/i.exec(credential);
  return match?.[1] ?? null;
}

function collectorIdFromCredential(credential: string): string | null {
  const match = /^snx_collector_([0-9a-f-]{36})_[a-f0-9]{64}$/i.exec(credential);
  return match?.[1] ?? null;
}

export async function agentAuth(req: Request, res: Response, next: NextFunction): Promise<void> {
  const credential = presentedCredential(req);
  const sensorId = credential ? sensorIdFromCredential(credential) : null;
  if (!credential || !sensorId) {
    replyUnauthenticated(res, "Missing or malformed sensor credential.", ERROR_CODES.API_KEY_INVALID);
    return;
  }

  const [sensor] = await db
    .select({
      id: nativeSensors.id,
      orgId: nativeSensors.orgId,
      apiKey: nativeSensors.apiKey,
      revokedAt: nativeSensors.revokedAt,
    })
    .from(nativeSensors)
    .where(and(eq(nativeSensors.id, sensorId), isNull(nativeSensors.revokedAt)))
    .limit(1);

  if (!sensor || !safeHashEqual(sensor.apiKey, hashApiKey(credential))) {
    replyUnauthenticated(res, "Invalid or revoked sensor credential.", ERROR_CODES.API_KEY_INVALID);
    return;
  }

  req.agentContext = { sensorId: sensor.id, orgId: sensor.orgId };
  next();
}

export async function collectorAgentAuth(req: Request, res: Response, next: NextFunction): Promise<void> {
  const credential = presentedCredential(req);
  const collectorId = credential ? collectorIdFromCredential(credential) : null;
  if (!credential || !collectorId) {
    replyUnauthenticated(res, "Missing or malformed collector credential.", ERROR_CODES.API_KEY_INVALID);
    return;
  }

  const [collector] = await db
    .select({
      id: collectorInstances.id,
      orgId: collectorInstances.orgId,
      apiKey: collectorInstances.apiKey,
      revokedAt: collectorInstances.revokedAt,
    })
    .from(collectorInstances)
    .where(and(eq(collectorInstances.id, collectorId), isNull(collectorInstances.revokedAt)))
    .limit(1);

  if (!collector || !safeHashEqual(collector.apiKey, hashApiKey(credential))) {
    replyUnauthenticated(res, "Invalid or revoked collector credential.", ERROR_CODES.API_KEY_INVALID);
    return;
  }

  req.collectorAgentContext = { collectorId: collector.id, orgId: collector.orgId };
  next();
}

export function createSensorAgentKey(sensorId: string): { key: string; hash: string } {
  const key = `snx_agent_${sensorId}_${randomBytes(32).toString("hex")}`;
  return { key, hash: hashApiKey(key) };
}

export function createCollectorAgentKey(collectorId: string): { key: string; hash: string; prefix: string } {
  const key = `snx_collector_${collectorId}_${randomBytes(32).toString("hex")}`;
  return { key, hash: hashApiKey(key), prefix: key.slice(0, 24) };
}

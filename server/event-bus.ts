import { EventEmitter } from "events";
import type { Response } from "express";
import { randomBytes } from "crypto";
import { logger } from "./logger";
import { getPodId, registerShutdownHandler, isDraining } from "./scaling-state";

export type EventType =
  | "alert:created"
  | "alert:updated"
  | "incident:created"
  | "incident:updated"
  | "correlation:found"
  | "entity:resolved"
  | "system:health";

export interface BusEvent {
  type: EventType;
  orgId: string | null;
  timestamp: string;
  podId: string;
  data: Record<string, any>;
}

const MAX_BUFFER_SIZE = 64;
const SLOW_CLIENT_THRESHOLD_MS = 5000;
const KEEP_ALIVE_INTERVAL_MS = 30000;
const DRAIN_BATCH_SIZE = 16;

interface ManagedClient {
  id: string;
  orgId: string | null;
  res: Response;
  connectedAt: Date;
  subscriptions: Set<EventType> | null;
  buffer: string[];
  draining: boolean;
  lastWriteAt: number;
  dropped: number;
}

export interface SSEClient {
  id: string;
  orgId: string | null;
  res: Response;
  connectedAt: Date;
  subscriptions?: EventType[];
}

class EventBus extends EventEmitter {
  private clients: Map<string, ManagedClient> = new Map();
  private orgIndex: Map<string, Set<string>> = new Map();
  private keepAliveInterval: ReturnType<typeof setInterval>;

  constructor() {
    super();
    this.setMaxListeners(500);

    this.keepAliveInterval = setInterval(() => {
      Array.from(this.clients.entries()).forEach(([id, client]) => {
        this.sendToClient(client, ":ping\n\n");
      });
    }, KEEP_ALIVE_INTERVAL_MS);
  }

  addClient(client: SSEClient): void {
    const subs = client.subscriptions && client.subscriptions.length > 0
      ? new Set(client.subscriptions)
      : null;

    const managed: ManagedClient = {
      id: client.id,
      orgId: client.orgId,
      res: client.res,
      connectedAt: client.connectedAt,
      subscriptions: subs,
      buffer: [],
      draining: false,
      lastWriteAt: Date.now(),
      dropped: 0,
    };

    this.clients.set(client.id, managed);

    if (client.orgId) {
      let orgSet = this.orgIndex.get(client.orgId);
      if (!orgSet) {
        orgSet = new Set();
        this.orgIndex.set(client.orgId, orgSet);
      }
      orgSet.add(client.id);
    }

    client.res.on("close", () => {
      this.removeClient(client.id);
    });
  }

  removeClient(id: string): void {
    const client = this.clients.get(id);
    if (!client) return;

    if (client.orgId) {
      const orgSet = this.orgIndex.get(client.orgId);
      if (orgSet) {
        orgSet.delete(id);
        if (orgSet.size === 0) this.orgIndex.delete(client.orgId);
      }
    }

    if (client.dropped > 0) {
      logger.child("sse").warn("Slow client disconnected with dropped events", {
        clientId: id,
        orgId: client.orgId,
        dropped: client.dropped,
      });
    }

    this.clients.delete(id);
  }

  private sendToClient(client: ManagedClient, payload: string): void {
    if (client.draining) {
      if (client.buffer.length >= MAX_BUFFER_SIZE) {
        client.dropped++;
        client.buffer.shift();
      }
      client.buffer.push(payload);
      return;
    }

    try {
      const ok = client.res.write(payload);
      client.lastWriteAt = Date.now();
      if (!ok) {
        client.draining = true;
        client.res.once("drain", () => {
          this.flushBuffer(client);
        });
      }
    } catch {
      this.removeClient(client.id);
    }
  }

  private flushBuffer(client: ManagedClient): void {
    let flushed = 0;
    while (client.buffer.length > 0 && flushed < DRAIN_BATCH_SIZE) {
      const msg = client.buffer.shift();
      if (!msg) break;
      try {
        const ok = client.res.write(msg);
        client.lastWriteAt = Date.now();
        flushed++;
        if (!ok) {
          client.res.once("drain", () => {
            this.flushBuffer(client);
          });
          return;
        }
      } catch {
        this.removeClient(client.id);
        return;
      }
    }
    if (client.buffer.length === 0) {
      client.draining = false;
    } else {
      setImmediate(() => this.flushBuffer(client));
    }
  }

  private formatSSE(event: BusEvent): string {
    return `event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`;
  }

  private clientAcceptsEvent(client: ManagedClient, eventType: EventType): boolean {
    if (!client.subscriptions) return true;
    return client.subscriptions.has(eventType);
  }

  broadcastToOrg(orgId: string, event: BusEvent): void {
    const payload = this.formatSSE(event);
    const orgClients = this.orgIndex.get(orgId);
    if (!orgClients) return;

    Array.from(orgClients).forEach((clientId) => {
      const client = this.clients.get(clientId);
      if (client && this.clientAcceptsEvent(client, event.type)) {
        this.sendToClient(client, payload);
      }
    });
  }

  broadcastToAll(event: BusEvent): void {
    const payload = this.formatSSE(event);
    Array.from(this.clients.values()).forEach((client) => {
      if (this.clientAcceptsEvent(client, event.type)) {
        this.sendToClient(client, payload);
      }
    });
  }

  drainAllClients(): void {
    const count = this.clients.size;
    if (count === 0) return;
    logger.child("sse").info("Draining all SSE clients for shutdown", { count });
    for (const [id, client] of Array.from(this.clients.entries())) {
      try {
        client.res.write("event: system:shutdown\ndata: {\"reason\":\"pod_shutdown\"}\n\n");
        client.res.end();
      } catch { /* client already gone */ }
      this.clients.delete(id);
    }
    this.orgIndex.clear();
    clearInterval(this.keepAliveInterval);
  }

  getClientCount(): number {
    return this.clients.size;
  }

  getOrgClientCount(orgId: string): number {
    return this.orgIndex.get(orgId)?.size ?? 0;
  }

  generateClientId(): string {
    return randomBytes(16).toString("hex");
  }

  getStats(): {
    totalClients: number;
    orgCounts: Record<string, number>;
    slowClients: number;
    totalDropped: number;
    totalBuffered: number;
  } {
    let slowClients = 0;
    let totalDropped = 0;
    let totalBuffered = 0;
    const now = Date.now();
    const orgCounts: Record<string, number> = {};

    Array.from(this.clients.values()).forEach((client) => {
      if (now - client.lastWriteAt > SLOW_CLIENT_THRESHOLD_MS && client.draining) {
        slowClients++;
      }
      totalDropped += client.dropped;
      totalBuffered += client.buffer.length;
      const key = client.orgId || "__global__";
      orgCounts[key] = (orgCounts[key] || 0) + 1;
    });

    return {
      totalClients: this.clients.size,
      orgCounts,
      slowClients,
      totalDropped,
      totalBuffered,
    };
  }
}

export const eventBus = new EventBus();

registerShutdownHandler("sse-clients", () => {
  eventBus.drainAllClients();
});

export function broadcastEvent(event: { type: EventType; orgId: string | null; data: Record<string, any> }): void {
  if (isDraining()) return;

  const fullEvent: BusEvent = {
    type: event.type,
    orgId: event.orgId,
    timestamp: new Date().toISOString(),
    podId: getPodId(),
    data: event.data,
  };

  eventBus.emit(event.type, fullEvent);

  if (event.orgId) {
    eventBus.broadcastToOrg(event.orgId, fullEvent);
  } else {
    eventBus.broadcastToAll(fullEvent);
  }
}

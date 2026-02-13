import { EventEmitter } from "events";
import type { Response } from "express";
import { randomBytes } from "crypto";

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
  data: Record<string, any>;
}

export interface SSEClient {
  id: string;
  orgId: string | null;
  res: Response;
  connectedAt: Date;
}

class EventBus extends EventEmitter {
  private clients: Map<string, SSEClient> = new Map();
  private keepAliveInterval: ReturnType<typeof setInterval>;

  constructor() {
    super();
    this.setMaxListeners(100);

    this.keepAliveInterval = setInterval(() => {
      Array.from(this.clients.entries()).forEach(([id, client]) => {
        try {
          client.res.write(":ping\n\n");
        } catch {
          this.removeClient(id);
        }
      });
    }, 30000);
  }

  addClient(client: SSEClient): void {
    this.clients.set(client.id, client);

    client.res.on("close", () => {
      this.removeClient(client.id);
    });
  }

  removeClient(id: string): void {
    this.clients.delete(id);
  }

  broadcastToOrg(orgId: string, event: BusEvent): void {
    Array.from(this.clients.entries()).forEach(([id, client]) => {
      if (client.orgId === orgId) {
        try {
          client.res.write(`event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`);
        } catch {
          this.removeClient(id);
        }
      }
    });
  }

  broadcastToAll(event: BusEvent): void {
    Array.from(this.clients.entries()).forEach(([id, client]) => {
      try {
        client.res.write(`event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`);
      } catch {
        this.removeClient(id);
      }
    });
  }

  getClientCount(): number {
    return this.clients.size;
  }

  getOrgClientCount(orgId: string): number {
    let count = 0;
    Array.from(this.clients.values()).forEach((client) => {
      if (client.orgId === orgId) count++;
    });
    return count;
  }

  generateClientId(): string {
    return randomBytes(16).toString("hex");
  }
}

export const eventBus = new EventBus();

export function broadcastEvent(event: { type: EventType; orgId: string | null; data: Record<string, any> }): void {
  const fullEvent: BusEvent = {
    type: event.type,
    orgId: event.orgId,
    timestamp: new Date().toISOString(),
    data: event.data,
  };

  eventBus.emit(event.type, fullEvent);

  if (event.orgId) {
    eventBus.broadcastToOrg(event.orgId, fullEvent);
  } else {
    eventBus.broadcastToAll(fullEvent);
  }
}

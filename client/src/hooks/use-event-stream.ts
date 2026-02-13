import { useState, useEffect, useRef, useCallback } from "react";
import { queryClient } from "@/lib/queryClient";

export interface StreamEvent {
  type: string;
  orgId: string | null;
  timestamp: string;
  data: Record<string, any>;
}

type ConnectionState = "connected" | "connecting" | "disconnected";

const EVENT_TYPES = [
  "alert:created",
  "alert:updated",
  "incident:created",
  "incident:updated",
  "correlation:found",
  "entity:resolved",
] as const;

const INVALIDATION_MAP: Record<string, string[][]> = {
  "alert:created": [["/api/alerts"], ["/api/dashboard/stats"], ["/api/dashboard/analytics"]],
  "alert:updated": [["/api/alerts"], ["/api/dashboard/stats"]],
  "incident:created": [["/api/incidents"], ["/api/dashboard/stats"]],
  "incident:updated": [["/api/incidents"], ["/api/dashboard/stats"]],
  "correlation:found": [["/api/correlation/clusters"], ["/api/dashboard/stats"]],
  "entity:resolved": [["/api/entities"]],
};

const MAX_EVENTS = 50;
const MAX_BACKOFF = 30000;

interface UseEventStreamOptions {
  enabled: boolean;
}

export function useEventStream({ enabled }: UseEventStreamOptions) {
  const [connectionState, setConnectionState] = useState<ConnectionState>("disconnected");
  const [eventCount, setEventCount] = useState(0);
  const [lastEvent, setLastEvent] = useState<StreamEvent | null>(null);
  const [events, setEvents] = useState<StreamEvent[]>([]);

  const eventSourceRef = useRef<EventSource | null>(null);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const backoffRef = useRef(1000);

  const cleanup = useCallback(() => {
    if (reconnectTimerRef.current) {
      clearTimeout(reconnectTimerRef.current);
      reconnectTimerRef.current = null;
    }
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
  }, []);

  const handleEvent = useCallback((event: MessageEvent) => {
    try {
      const parsed: StreamEvent = JSON.parse(event.data);
      setLastEvent(parsed);
      setEventCount((c) => c + 1);
      setEvents((prev) => {
        const next = [parsed, ...prev];
        return next.length > MAX_EVENTS ? next.slice(0, MAX_EVENTS) : next;
      });

      const keys = INVALIDATION_MAP[parsed.type];
      if (keys) {
        for (const queryKey of keys) {
          queryClient.invalidateQueries({ queryKey });
        }
      }
    } catch {
      // ignore malformed events
    }
  }, []);

  const connect = useCallback(() => {
    cleanup();
    setConnectionState("connecting");

    const es = new EventSource("/api/events/stream");
    eventSourceRef.current = es;

    es.onopen = () => {
      setConnectionState("connected");
      backoffRef.current = 1000;
    };

    es.onerror = () => {
      es.close();
      eventSourceRef.current = null;
      setConnectionState("disconnected");

      const delay = backoffRef.current;
      backoffRef.current = Math.min(delay * 2, MAX_BACKOFF);
      reconnectTimerRef.current = setTimeout(() => {
        connect();
      }, delay);
    };

    for (const eventType of EVENT_TYPES) {
      es.addEventListener(eventType, handleEvent);
    }
  }, [cleanup, handleEvent]);

  useEffect(() => {
    if (enabled) {
      connect();
    } else {
      cleanup();
      setConnectionState("disconnected");
    }

    return cleanup;
  }, [enabled, connect, cleanup]);

  return {
    connected: connectionState === "connected",
    connectionState,
    eventCount,
    lastEvent,
    events,
  };
}

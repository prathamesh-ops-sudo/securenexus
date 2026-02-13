import { useRef, useEffect } from "react";
import { useEventStreamContext } from "@/App";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { AlertTriangle, FileWarning, Network, Shield, Radio, Zap } from "lucide-react";
import type { StreamEvent } from "@/hooks/use-event-stream";

function formatRelativeTime(timestamp: string): string {
  const diff = Date.now() - new Date(timestamp).getTime();
  const seconds = Math.floor(diff / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  return `${hours}h ago`;
}

const EVENT_TYPE_MAP: Record<string, { label: string; icon: typeof AlertTriangle }> = {
  "alert:created": { label: "New Alert", icon: AlertTriangle },
  "alert:updated": { label: "Alert Updated", icon: AlertTriangle },
  "incident:created": { label: "New Incident", icon: FileWarning },
  "incident:updated": { label: "Incident Updated", icon: FileWarning },
  "correlation:found": { label: "Correlation Detected", icon: Network },
  "entity:resolved": { label: "Entity Resolved", icon: Shield },
  "system:health": { label: "System Health", icon: Radio },
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "text-red-500",
  high: "text-orange-500",
  medium: "text-yellow-500",
  low: "text-blue-400",
  info: "text-gray-400",
  informational: "text-gray-400",
};

const SEVERITY_BADGE_VARIANTS: Record<string, string> = {
  critical: "bg-red-500/15 text-red-500 border-red-500/30",
  high: "bg-orange-500/15 text-orange-500 border-orange-500/30",
  medium: "bg-yellow-500/15 text-yellow-500 border-yellow-500/30",
  low: "bg-blue-400/15 text-blue-400 border-blue-400/30",
  info: "bg-gray-400/15 text-gray-400 border-gray-400/30",
  informational: "bg-gray-400/15 text-gray-400 border-gray-400/30",
};

function getEventTitle(event: StreamEvent): string {
  const mapping = EVENT_TYPE_MAP[event.type];
  const label = mapping?.label || event.type;
  const title = event.data?.title || event.data?.name || "";
  return title ? `${label}: ${title}` : label;
}

function getEventSeverity(event: StreamEvent): string | null {
  return event.data?.severity || null;
}

function getEventSource(event: StreamEvent): string | null {
  return event.data?.source || event.data?.sourceTool || null;
}

export function LiveActivityFeed() {
  const { connected, events, eventCount } = useEventStreamContext();
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = 0;
    }
  }, [events.length]);

  return (
    <Card className="gradient-card" data-testid="live-activity-feed">
      <CardHeader className="flex flex-row items-center justify-between gap-1 pb-3">
        <div className="flex items-center gap-2">
          <Zap className="h-4 w-4 text-muted-foreground" />
          <CardTitle className="text-sm font-medium">Live Activity Feed</CardTitle>
          {eventCount > 0 && (
            <Badge variant="secondary" className="text-[10px]" data-testid="badge-event-count">
              {eventCount}
            </Badge>
          )}
        </div>
        <div className="flex items-center gap-1.5">
          <div
            className={`w-2 h-2 rounded-full ${connected ? "bg-green-500" : "bg-red-500"}`}
            data-testid="indicator-feed-connection"
          />
          <span className="text-[10px] text-muted-foreground">
            {connected ? "Live" : "Offline"}
          </span>
        </div>
      </CardHeader>
      <CardContent>
        <div
          ref={scrollRef}
          className="max-h-[400px] overflow-auto space-y-1.5"
          data-testid="activity-feed-list"
        >
          {events.length === 0 ? (
            <div className="flex items-center justify-center gap-2 py-8 text-sm text-muted-foreground">
              <div className="w-2 h-2 rounded-full bg-muted-foreground animate-pulse" />
              <span>Listening for events...</span>
            </div>
          ) : (
            events.map((event, index) => {
              const mapping = EVENT_TYPE_MAP[event.type] || { label: event.type, icon: Zap };
              const Icon = mapping.icon;
              const severity = getEventSeverity(event);
              const source = getEventSource(event);
              const colorClass = severity ? SEVERITY_COLORS[severity] || "text-muted-foreground" : "text-muted-foreground";

              return (
                <div
                  key={`${event.timestamp}-${index}`}
                  className="flex items-start gap-3 p-2 rounded-md hover-elevate"
                  data-testid={`activity-event-${index}`}
                >
                  <div className={`flex items-center justify-center w-8 h-8 rounded-md bg-muted/50 flex-shrink-0`}>
                    <Icon className={`h-3.5 w-3.5 ${colorClass}`} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="text-xs font-medium truncate">{getEventTitle(event)}</div>
                    <div className="flex items-center gap-2 mt-0.5 flex-wrap">
                      {severity && (
                        <Badge
                          variant="outline"
                          className={`text-[10px] px-1.5 py-0 ${SEVERITY_BADGE_VARIANTS[severity] || ""}`}
                          data-testid={`badge-severity-${index}`}
                        >
                          {severity}
                        </Badge>
                      )}
                      {source && (
                        <span className="text-[10px] text-muted-foreground truncate">{source}</span>
                      )}
                    </div>
                  </div>
                  <span className="text-[10px] text-muted-foreground whitespace-nowrap flex-shrink-0">
                    {formatRelativeTime(event.timestamp)}
                  </span>
                </div>
              );
            })
          )}
        </div>
      </CardContent>
    </Card>
  );
}

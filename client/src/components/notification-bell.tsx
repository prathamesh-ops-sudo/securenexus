import { useState, useEffect, useCallback, useRef, useContext } from "react";
import {
  AlertTriangle,
  Shield,
  FileWarning,
  ArrowUpRight,
  X,
  Bell,
  BellRing,
  CheckCircle2,
  Volume2,
  VolumeX,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Link } from "wouter";
import { EventStreamContext } from "@/App";

// ── Types ────────────────────────────────────────────────────────────

interface CriticalNotification {
  id: string;
  title: string;
  severity: string;
  source: string;
  timestamp: Date;
  read: boolean;
  alertId?: string;
}

// ── Push Notification helpers ────────────────────────────────────────

function isPushSupported(): boolean {
  return "Notification" in window && "serviceWorker" in navigator;
}

function getPushPermission(): NotificationPermission | "unsupported" {
  if (!isPushSupported()) return "unsupported";
  return Notification.permission;
}

async function requestPushPermission(): Promise<boolean> {
  if (!isPushSupported()) return false;
  const result = await Notification.requestPermission();
  return result === "granted";
}

function sendBrowserNotification(title: string, body: string, tag: string) {
  if (getPushPermission() !== "granted") return;
  if (document.hasFocus()) return; // only push when tab is not focused
  try {
    new Notification(title, {
      body,
      icon: "/favicon.ico",
      tag, // dedup by tag
      requireInteraction: false,
    });
  } catch {
    // Notification constructor may fail in some contexts
  }
}

// ── Storage helpers ─────────────────────────────────────────────────

const PUSH_OPT_IN_KEY = "notifications.push.optIn";
const NOTIFICATIONS_KEY = "notifications.critical.v1";
const MAX_NOTIFICATIONS = 50;

function loadPushOptIn(): boolean {
  try {
    return localStorage.getItem(PUSH_OPT_IN_KEY) === "true";
  } catch {
    return false;
  }
}

function savePushOptIn(value: boolean) {
  try {
    localStorage.setItem(PUSH_OPT_IN_KEY, String(value));
  } catch {
    // ignore
  }
}

function loadNotifications(): CriticalNotification[] {
  try {
    const raw = localStorage.getItem(NOTIFICATIONS_KEY);
    if (raw) {
      const parsed = JSON.parse(raw);
      return parsed.map((n: any) => ({ ...n, timestamp: new Date(n.timestamp) }));
    }
  } catch {
    // ignore
  }
  return [];
}

function saveNotifications(notifications: CriticalNotification[]) {
  try {
    localStorage.setItem(NOTIFICATIONS_KEY, JSON.stringify(notifications.slice(0, MAX_NOTIFICATIONS)));
  } catch {
    // ignore
  }
}

// ── Component ───────────────────────────────────────────────────────

export function NotificationBell() {
  const { lastEvent } = useContext(EventStreamContext);
  const [notifications, setNotifications] = useState<CriticalNotification[]>(loadNotifications);
  const [isOpen, setIsOpen] = useState(false);
  const [pushOptIn, setPushOptIn] = useState(loadPushOptIn);
  const panelRef = useRef<HTMLDivElement>(null);
  const processedRef = useRef<Set<string>>(new Set());

  const unreadCount = notifications.filter((n) => !n.read).length;

  // Process incoming SSE events for critical alerts
  useEffect(() => {
    if (!lastEvent) return;
    if (lastEvent.type !== "alert:created") return;

    const data = lastEvent.data as Record<string, any>;
    const severity = data.severity as string;
    if (severity !== "critical" && severity !== "high") return;

    const alertId = data.alertId as string;
    if (!alertId || processedRef.current.has(alertId)) return;
    processedRef.current.add(alertId);

    const notification: CriticalNotification = {
      id: `${alertId}-${Date.now()}`,
      title: (data.title as string) || "Critical alert detected",
      severity,
      source: (data.source as string) || "unknown",
      timestamp: new Date(),
      read: false,
      alertId,
    };

    setNotifications((prev) => {
      const updated = [notification, ...prev].slice(0, MAX_NOTIFICATIONS);
      saveNotifications(updated);
      return updated;
    });

    // Browser push notification when tab is unfocused
    if (pushOptIn) {
      const urgency = severity === "critical" ? "CRITICAL" : "HIGH";
      sendBrowserNotification(
        `[${urgency}] ${notification.title}`,
        `Source: ${notification.source} — Click to investigate`,
        alertId,
      );
    }
  }, [lastEvent, pushOptIn]);

  // Close panel when clicking outside
  useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (panelRef.current && !panelRef.current.contains(e.target as Node)) {
        setIsOpen(false);
      }
    }
    if (isOpen) {
      document.addEventListener("mousedown", handleClickOutside);
      return () => document.removeEventListener("mousedown", handleClickOutside);
    }
  }, [isOpen]);

  const markAllRead = useCallback(() => {
    setNotifications((prev) => {
      const updated = prev.map((n) => ({ ...n, read: true }));
      saveNotifications(updated);
      return updated;
    });
  }, []);

  const clearAll = useCallback(() => {
    setNotifications([]);
    saveNotifications([]);
    processedRef.current.clear();
  }, []);

  const togglePushOptIn = useCallback(async () => {
    if (!pushOptIn) {
      const granted = await requestPushPermission();
      if (granted) {
        setPushOptIn(true);
        savePushOptIn(true);
      }
    } else {
      setPushOptIn(false);
      savePushOptIn(false);
    }
  }, [pushOptIn]);

  const severityIcon = (severity: string) => {
    switch (severity) {
      case "critical":
        return <Shield className="h-3.5 w-3.5 text-red-500" />;
      case "high":
        return <AlertTriangle className="h-3.5 w-3.5 text-orange-500" />;
      default:
        return <FileWarning className="h-3.5 w-3.5 text-amber-500" />;
    }
  };

  const formatTimeAgo = (date: Date) => {
    const seconds = Math.floor((Date.now() - date.getTime()) / 1000);
    if (seconds < 60) return "just now";
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return `${minutes}m ago`;
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours}h ago`;
    return `${Math.floor(hours / 24)}d ago`;
  };

  return (
    <div className="relative" ref={panelRef}>
      <Button
        size="icon"
        variant="ghost"
        className="h-8 w-8 hover:bg-muted/60 active:scale-95 transition-all duration-150 relative"
        onClick={() => setIsOpen(!isOpen)}
        aria-label={`Notifications${unreadCount > 0 ? ` (${unreadCount} unread)` : ""}`}
        aria-expanded={isOpen}
        title="Critical alert notifications"
      >
        {unreadCount > 0 ? (
          <BellRing className="h-4 w-4 animate-pulse" aria-hidden="true" />
        ) : (
          <Bell className="h-4 w-4" aria-hidden="true" />
        )}
        {unreadCount > 0 && (
          <span className="absolute -top-0.5 -right-0.5 flex h-4 w-4 items-center justify-center rounded-full bg-red-500 text-[9px] font-bold text-white ring-2 ring-background">
            {unreadCount > 9 ? "9+" : unreadCount}
          </span>
        )}
      </Button>

      {isOpen && (
        <div className="absolute right-0 top-10 w-80 bg-popover border border-border rounded-lg shadow-xl z-50 overflow-hidden">
          {/* Header */}
          <div className="px-3 py-2 border-b border-border bg-muted/30 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="text-xs font-semibold">Critical Alerts</span>
              {unreadCount > 0 && (
                <Badge variant="destructive" className="h-4 px-1.5 text-[9px]">
                  {unreadCount}
                </Badge>
              )}
            </div>
            <div className="flex items-center gap-1">
              {notifications.length > 0 && (
                <>
                  <Button
                    size="sm"
                    variant="ghost"
                    className="h-6 px-2 text-[10px]"
                    onClick={markAllRead}
                    title="Mark all as read"
                  >
                    <CheckCircle2 className="h-3 w-3" />
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    className="h-6 px-2 text-[10px]"
                    onClick={clearAll}
                    title="Clear all"
                  >
                    <X className="h-3 w-3" />
                  </Button>
                </>
              )}
            </div>
          </div>

          {/* Notification list */}
          <div className="max-h-72 overflow-y-auto">
            {notifications.length === 0 ? (
              <div className="px-3 py-8 text-center">
                <div className="flex justify-center mb-2">
                  <CheckCircle2 className="h-6 w-6 text-emerald-500" />
                </div>
                <p className="text-xs font-medium text-muted-foreground">No critical alerts</p>
                <p className="text-[10px] text-muted-foreground mt-1">
                  Critical and high-severity alerts will appear here in real time
                </p>
              </div>
            ) : (
              notifications.map((n) => (
                <Link
                  key={n.id}
                  href={n.alertId ? `/alerts/${n.alertId}` : "/alerts?severity=critical"}
                  onClick={() => {
                    setNotifications((prev) => {
                      const updated = prev.map((x) => (x.id === n.id ? { ...x, read: true } : x));
                      saveNotifications(updated);
                      return updated;
                    });
                    setIsOpen(false);
                  }}
                >
                  <div
                    className={`px-3 py-2.5 hover:bg-muted/50 transition-colors cursor-pointer border-b border-border/50 ${!n.read ? "bg-red-500/5" : ""}`}
                  >
                    <div className="flex items-start gap-2">
                      <div className="mt-0.5">{severityIcon(n.severity)}</div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-1.5">
                          <span className="text-xs font-medium truncate">{n.title}</span>
                          {!n.read && <span className="flex h-1.5 w-1.5 rounded-full bg-red-500 shrink-0" />}
                        </div>
                        <div className="flex items-center gap-2 mt-0.5">
                          <Badge
                            variant="outline"
                            className={`text-[9px] h-4 px-1 ${n.severity === "critical" ? "border-red-500/30 text-red-400" : "border-orange-500/30 text-orange-400"}`}
                          >
                            {n.severity}
                          </Badge>
                          <span className="text-[10px] text-muted-foreground">{n.source}</span>
                          <span className="text-[10px] text-muted-foreground ml-auto">
                            {formatTimeAgo(n.timestamp)}
                          </span>
                        </div>
                      </div>
                      <ArrowUpRight className="h-3 w-3 text-muted-foreground shrink-0 mt-1" />
                    </div>
                  </div>
                </Link>
              ))
            )}
          </div>

          {/* Footer — Push notification opt-in */}
          <div className="px-3 py-2 border-t border-border bg-muted/20 flex items-center justify-between">
            <div className="flex items-center gap-1.5">
              {pushOptIn ? (
                <Volume2 className="h-3 w-3 text-emerald-500" />
              ) : (
                <VolumeX className="h-3 w-3 text-muted-foreground" />
              )}
              <span className="text-[10px] text-muted-foreground">
                {pushOptIn ? "Push notifications on" : "Push notifications off"}
              </span>
            </div>
            <Button
              size="sm"
              variant={pushOptIn ? "secondary" : "outline"}
              className="h-5 px-2 text-[9px]"
              onClick={togglePushOptIn}
            >
              {pushOptIn ? "Disable" : "Enable"}
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}

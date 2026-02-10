import { useQuery } from "@tanstack/react-query";
import { Activity, User, Shield, AlertTriangle, FileWarning } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import type { AuditLog } from "@shared/schema";

const ACTION_ICONS: Record<string, any> = {
  "incident.escalate": FileWarning,
  "incident.contain": Shield,
  "alert.triage": AlertTriangle,
  "alert.correlate": Shield,
  "alert.dismiss": AlertTriangle,
};

const ACTION_LABELS: Record<string, string> = {
  "incident.escalate": "Escalated incident",
  "incident.contain": "Contained incident",
  "alert.triage": "Triaged alert",
  "alert.correlate": "Correlated alerts",
  "alert.dismiss": "Dismissed alert",
};

export default function AuditLogPage() {
  const { data: logs, isLoading } = useQuery<AuditLog[]>({
    queryKey: ["/api/audit-logs"],
  });

  return (
    <div className="p-4 md:p-6 space-y-6 max-w-7xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold tracking-tight" data-testid="text-page-title">Audit Log</h1>
        <p className="text-sm text-muted-foreground mt-1">All platform activities and changes</p>
      </div>

      <Card>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="space-y-0">
              {Array.from({ length: 5 }).map((_, i) => (
                <div key={i} className="flex items-center gap-3 p-4 border-b last:border-0">
                  <Skeleton className="h-8 w-8 rounded-full flex-shrink-0" />
                  <div className="flex-1 space-y-1">
                    <Skeleton className="h-4 w-3/4" />
                    <Skeleton className="h-3 w-1/2" />
                  </div>
                </div>
              ))}
            </div>
          ) : logs && logs.length > 0 ? (
            <div className="space-y-0">
              {logs.map((log) => {
                const Icon = ACTION_ICONS[log.action] || Activity;
                const label = ACTION_LABELS[log.action] || log.action;
                const details = log.details ? (typeof log.details === "string" ? JSON.parse(log.details) : log.details) as Record<string, any> : null;

                return (
                  <div key={log.id} className="flex items-start gap-3 p-4 border-b last:border-0" data-testid={`log-${log.id}`}>
                    <div className="flex items-center justify-center w-8 h-8 rounded-full bg-muted flex-shrink-0 mt-0.5">
                      <Icon className="h-3 w-3 text-muted-foreground" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-sm font-medium">{label}</span>
                        {log.resourceType && (
                          <span className="px-1.5 py-0.5 rounded bg-muted text-[10px] font-mono">{log.resourceType}</span>
                        )}
                      </div>
                      <div className="flex items-center gap-2 text-xs text-muted-foreground mt-0.5 flex-wrap">
                        {log.userName && (
                          <span className="flex items-center gap-1">
                            <User className="h-3 w-3" />
                            {log.userName}
                          </span>
                        )}
                        {log.createdAt && (
                          <span>{new Date(log.createdAt).toLocaleString()}</span>
                        )}
                      </div>
                      {details && (
                        <div className="mt-1.5 text-xs text-muted-foreground/80">
                          {details.reason && <span>{details.reason}</span>}
                          {details.action && <span>{details.action}</span>}
                          {details.newStatus && <span>Status changed to: {details.newStatus}</span>}
                          {details.alertsCorrelated && <span>{details.alertsCorrelated} alerts correlated via {details.method}</span>}
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="text-center py-16 text-sm text-muted-foreground">
              <Activity className="h-8 w-8 mx-auto mb-3 text-muted-foreground/50" />
              <p>No audit log entries yet</p>
              <p className="text-xs mt-1">Activities will appear here as you use the platform</p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

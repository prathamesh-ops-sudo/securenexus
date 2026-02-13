const severityVariants: Record<string, string> = {
  critical: "bg-red-500/10 text-red-500 border-red-500/20",
  high: "bg-orange-500/10 text-orange-500 border-orange-500/20",
  medium: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20",
  low: "bg-green-500/10 text-green-500 border-green-500/20",
  informational: "bg-muted text-muted-foreground border-muted",
};

const alertStatusVariants: Record<string, string> = {
  new: "bg-red-500/10 text-red-500 border-red-500/20",
  triaged: "bg-red-500/10 text-red-500 border-red-500/20",
  correlated: "bg-purple-500/10 text-purple-500 border-purple-500/20",
  investigating: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20",
  resolved: "bg-green-500/10 text-green-500 border-green-500/20",
  dismissed: "bg-muted text-muted-foreground border-muted",
  false_positive: "bg-muted text-muted-foreground border-muted",
};

const incidentStatusVariants: Record<string, string> = {
  open: "bg-red-500/10 text-red-500 border-red-500/20",
  investigating: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20",
  contained: "bg-orange-500/10 text-orange-500 border-orange-500/20",
  eradicated: "bg-purple-500/10 text-purple-500 border-purple-500/20",
  recovered: "bg-emerald-500/10 text-emerald-500 border-emerald-500/20",
  resolved: "bg-green-500/10 text-green-500 border-green-500/20",
  closed: "bg-muted text-muted-foreground border-muted",
};

const priorityVariants: Record<number, string> = {
  1: "bg-red-500/10 text-red-500 border-red-500/20",
  2: "bg-orange-500/10 text-orange-500 border-orange-500/20",
  3: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20",
  4: "bg-green-500/10 text-green-500 border-green-500/20",
  5: "bg-muted text-muted-foreground border-muted",
};

export function SeverityBadge({ severity, className }: { severity: string; className?: string }) {
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium uppercase tracking-wider border ${severityVariants[severity] || severityVariants.medium} ${className || ""}`}
      data-testid={`badge-severity-${severity}`}
    >
      {severity}
    </span>
  );
}

export function AlertStatusBadge({ status, className }: { status: string; className?: string }) {
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium uppercase tracking-wider border ${alertStatusVariants[status] || alertStatusVariants.new} ${className || ""}`}
      data-testid={`badge-alert-status-${status}`}
    >
      {status.replace(/_/g, " ")}
    </span>
  );
}

export function IncidentStatusBadge({ status, className }: { status: string; className?: string }) {
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium uppercase tracking-wider border ${incidentStatusVariants[status] || incidentStatusVariants.open} ${className || ""}`}
      data-testid={`badge-incident-status-${status}`}
    >
      {status}
    </span>
  );
}

export function PriorityBadge({ priority, className }: { priority: number; className?: string }) {
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium uppercase tracking-wider border ${priorityVariants[priority] || priorityVariants[3]} ${className || ""}`}
      data-testid={`badge-priority-${priority}`}
    >
      P{priority}
    </span>
  );
}

export function formatTimestamp(date: string | Date | null | undefined) {
  if (!date) return "N/A";
  return new Date(date).toLocaleString();
}

export function formatRelativeTime(date: string | Date | null | undefined) {
  if (!date) return "N/A";
  const d = new Date(date);
  const now = new Date();
  const diffMs = now.getTime() - d.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);

  if (diffMins < 1) return "just now";
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  if (diffDays < 7) return `${diffDays}d ago`;
  return d.toLocaleDateString("en-US", { month: "short", day: "numeric" });
}

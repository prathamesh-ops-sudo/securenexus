import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { usePageTitle } from "@/hooks/use-page-title";
import {
  GitBranch,
  Clock,
  ArrowRight,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Info,
  Code2,
  FileText,
  Shield,
  Layers,
  ChevronRight,
  ChevronDown,
  Copy,
  Search,
  Tag,
  CalendarClock,
  Megaphone,
  Rocket,
  BookOpen,
  Server,
  Lock,
  Zap,
  RefreshCw,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Input } from "@/components/ui/input";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { Separator } from "@/components/ui/separator";
import { useToast } from "@/hooks/use-toast";

interface VersionPolicy {
  currentVersion: string;
  stabilityLevel: string;
  stabilityGuarantees: {
    breakingChanges: string;
    deprecationNotice: string;
    sunsetDate: string;
    supportedUntil: string;
  };
  v2Roadmap: {
    status: string;
    breakingChanges: string[];
    migrationPath: string;
  };
  headers: Record<string, string>;
  endpoints: Record<string, string>;
  publishedAt: string;
}

interface MigrationSection {
  id: string;
  title: string;
  legacy: { method: string; path: string; description: string } | null;
  v1: { method: string; path: string; description: string };
  changes: string[];
  example?: {
    request: string;
    responseShape: Record<string, unknown>;
  };
}

interface MigrationGuide {
  title: string;
  version: string;
  lastUpdated: string;
  overview: string;
  sections: MigrationSection[];
  generalChanges: string[];
  authentication: {
    current: string;
    v2planned: string;
  };
}

const STABILITY_CONFIG: Record<string, { label: string; color: string; icon: typeof CheckCircle2; bgClass: string }> = {
  stable: {
    label: "Stable",
    color: "text-emerald-500",
    icon: CheckCircle2,
    bgClass: "bg-emerald-500/10 border-emerald-500/20",
  },
  beta: {
    label: "Beta",
    color: "text-amber-500",
    icon: AlertTriangle,
    bgClass: "bg-amber-500/10 border-amber-500/20",
  },
  deprecated: {
    label: "Deprecated",
    color: "text-red-500",
    icon: XCircle,
    bgClass: "bg-red-500/10 border-red-500/20",
  },
  planning: {
    label: "Planning",
    color: "text-blue-500",
    icon: Info,
    bgClass: "bg-blue-500/10 border-blue-500/20",
  },
};

function formatDate(iso: string | null | undefined): string {
  if (!iso) return "\u2014";
  try {
    return new Date(iso).toLocaleDateString("en-US", {
      month: "long",
      day: "numeric",
      year: "numeric",
    });
  } catch {
    return "\u2014";
  }
}

function daysUntil(iso: string): number {
  const target = new Date(iso).getTime();
  const now = Date.now();
  return Math.max(0, Math.ceil((target - now) / (1000 * 60 * 60 * 24)));
}

function StabilityBadge({ level }: { level: string }) {
  const config = STABILITY_CONFIG[level] || STABILITY_CONFIG.stable;
  const Icon = config.icon;
  return (
    <Badge variant="outline" className={`text-xs gap-1.5 ${config.bgClass} ${config.color} border px-2.5 py-0.5`}>
      <Icon className="h-3.5 w-3.5" />
      {config.label}
    </Badge>
  );
}

function MethodBadge({ method }: { method: string }) {
  const colors: Record<string, string> = {
    GET: "bg-emerald-500/15 text-emerald-400 border-emerald-500/25",
    POST: "bg-blue-500/15 text-blue-400 border-blue-500/25",
    PUT: "bg-amber-500/15 text-amber-400 border-amber-500/25",
    PATCH: "bg-orange-500/15 text-orange-400 border-orange-500/25",
    DELETE: "bg-red-500/15 text-red-400 border-red-500/25",
  };
  return (
    <Badge
      variant="outline"
      className={`text-[10px] font-mono font-bold ${colors[method] || "bg-muted/50 text-muted-foreground"}`}
    >
      {method}
    </Badge>
  );
}

function CopyButton({ text }: { text: string }) {
  const { toast } = useToast();
  return (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger asChild>
          <Button
            variant="ghost"
            size="icon"
            className="h-6 w-6 shrink-0"
            onClick={() => {
              navigator.clipboard.writeText(text);
              toast({ title: "Copied", description: "Copied to clipboard" });
            }}
          >
            <Copy className="h-3 w-3" />
          </Button>
        </TooltipTrigger>
        <TooltipContent side="top" className="text-xs">
          Copy
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}

function VersionTimelineCard({ policy }: { policy: VersionPolicy }) {
  const sunsetDays = daysUntil(policy.stabilityGuarantees.sunsetDate);

  return (
    <Card className="glass-card">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm flex items-center gap-2">
            <CalendarClock className="h-4 w-4 text-cyan-400" />
            Version Timeline
          </CardTitle>
          <StabilityBadge level={policy.stabilityLevel} />
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="relative">
          <div className="absolute left-[11px] top-0 bottom-0 w-px bg-border/50" />
          <div className="space-y-5">
            <div className="flex items-start gap-3 relative">
              <div className="h-6 w-6 rounded-full bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center shrink-0 z-10">
                <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500" />
              </div>
              <div>
                <p className="text-sm font-medium">v1 Published</p>
                <p className="text-xs text-muted-foreground">{formatDate(policy.publishedAt)}</p>
              </div>
            </div>
            <div className="flex items-start gap-3 relative">
              <div className="h-6 w-6 rounded-full bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center shrink-0 z-10">
                <Shield className="h-3.5 w-3.5 text-cyan-500" />
              </div>
              <div>
                <p className="text-sm font-medium">Stability Guarantee Active</p>
                <p className="text-xs text-muted-foreground">{policy.stabilityGuarantees.breakingChanges}</p>
              </div>
            </div>
            <div className="flex items-start gap-3 relative">
              <div className="h-6 w-6 rounded-full bg-blue-500/20 border border-blue-500/40 flex items-center justify-center shrink-0 z-10">
                <Rocket className="h-3.5 w-3.5 text-blue-500" />
              </div>
              <div>
                <p className="text-sm font-medium">v2 Roadmap</p>
                <p className="text-xs text-muted-foreground capitalize">Status: {policy.v2Roadmap.status}</p>
              </div>
            </div>
            <div className="flex items-start gap-3 relative">
              <div
                className={`h-6 w-6 rounded-full ${sunsetDays < 365 ? "bg-amber-500/20 border-amber-500/40" : "bg-muted/30 border-border/50"} border flex items-center justify-center shrink-0 z-10`}
              >
                <Clock className={`h-3.5 w-3.5 ${sunsetDays < 365 ? "text-amber-500" : "text-muted-foreground"}`} />
              </div>
              <div>
                <p className="text-sm font-medium">v1 Sunset</p>
                <p className="text-xs text-muted-foreground">
                  {formatDate(policy.stabilityGuarantees.sunsetDate)} ({sunsetDays} days remaining)
                </p>
              </div>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function HeadersReferenceCard({ headers }: { headers: Record<string, string> }) {
  return (
    <Card className="glass-card">
      <CardHeader className="pb-3">
        <CardTitle className="text-sm flex items-center gap-2">
          <Server className="h-4 w-4 text-cyan-400" />
          Response Headers
        </CardTitle>
        <CardDescription className="text-xs">Headers included in all API v1 responses</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-2">
          {Object.entries(headers).map(([header, description]) => (
            <div key={header} className="flex items-start gap-3 p-2.5 rounded-lg border border-border/30 bg-card/30">
              <code className="text-xs font-mono text-cyan-400 bg-cyan-500/10 px-2 py-0.5 rounded shrink-0">
                {header}
              </code>
              <p className="text-xs text-muted-foreground flex-1">{description}</p>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

function V2RoadmapCard({ roadmap, migrationPath }: { roadmap: VersionPolicy["v2Roadmap"]; migrationPath: string }) {
  const statusConfig = STABILITY_CONFIG[roadmap.status] || STABILITY_CONFIG.planning;

  return (
    <Card className="glass-card border-blue-500/20">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm flex items-center gap-2">
            <Rocket className="h-4 w-4 text-blue-400" />
            v2 Roadmap
          </CardTitle>
          <Badge
            variant="outline"
            className={`text-xs gap-1.5 ${statusConfig.bgClass} ${statusConfig.color} capitalize`}
          >
            {roadmap.status}
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <div>
          <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2">Breaking Changes</p>
          <ul className="space-y-1.5">
            {roadmap.breakingChanges.map((change, i) => (
              <li key={i} className="flex items-start gap-2 text-xs">
                <AlertTriangle className="h-3.5 w-3.5 text-amber-500 mt-0.5 shrink-0" />
                <span>{change}</span>
              </li>
            ))}
          </ul>
        </div>
        <Separator />
        <div>
          <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-1.5">Migration Path</p>
          <p className="text-xs">{migrationPath}</p>
        </div>
      </CardContent>
    </Card>
  );
}

function EndpointCard({
  section,
  isExpanded,
  onToggle,
}: {
  section: MigrationSection;
  isExpanded: boolean;
  onToggle: () => void;
}) {
  const isNew = section.legacy === null;

  return (
    <div className="border border-border/40 rounded-lg overflow-hidden bg-card/30">
      <button
        className="w-full flex items-center gap-3 p-3.5 hover:bg-muted/30 transition-colors text-left"
        onClick={onToggle}
        aria-expanded={isExpanded}
        aria-label={`Toggle ${section.title} details`}
      >
        {isExpanded ? (
          <ChevronDown className="h-4 w-4 text-muted-foreground shrink-0" />
        ) : (
          <ChevronRight className="h-4 w-4 text-muted-foreground shrink-0" />
        )}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <p className="text-sm font-medium">{section.title}</p>
            {isNew && (
              <Badge variant="outline" className="text-[10px] bg-cyan-500/10 text-cyan-400 border-cyan-500/20">
                NEW IN v1
              </Badge>
            )}
          </div>
          <p className="text-xs text-muted-foreground mt-0.5 truncate">{section.v1.description}</p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <MethodBadge method={section.v1.method} />
          <code className="text-[11px] font-mono text-muted-foreground hidden sm:inline">{section.v1.path}</code>
        </div>
      </button>

      {isExpanded && (
        <div className="border-t border-border/30 p-4 space-y-4 bg-muted/5">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {section.legacy && (
              <div className="space-y-1.5">
                <p className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider flex items-center gap-1.5">
                  <XCircle className="h-3 w-3 text-red-400" />
                  Legacy Endpoint
                </p>
                <div className="flex items-center gap-2 p-2 rounded border border-red-500/20 bg-red-500/5">
                  <MethodBadge method={section.legacy.method} />
                  <code className="text-xs font-mono flex-1">{section.legacy.path}</code>
                  <CopyButton text={section.legacy.path} />
                </div>
                <p className="text-xs text-muted-foreground">{section.legacy.description}</p>
              </div>
            )}
            <div className="space-y-1.5">
              <p className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider flex items-center gap-1.5">
                <CheckCircle2 className="h-3 w-3 text-emerald-400" />
                v1 Endpoint
              </p>
              <div className="flex items-center gap-2 p-2 rounded border border-emerald-500/20 bg-emerald-500/5">
                <MethodBadge method={section.v1.method} />
                <code className="text-xs font-mono flex-1">{section.v1.path}</code>
                <CopyButton text={section.v1.path} />
              </div>
              <p className="text-xs text-muted-foreground">{section.v1.description}</p>
            </div>
          </div>

          {section.legacy && (
            <div className="flex items-center gap-2 p-2 rounded bg-muted/20 border border-border/30">
              <ArrowRight className="h-4 w-4 text-cyan-400 shrink-0" />
              <p className="text-xs text-muted-foreground">
                Migration: <code className="font-mono text-red-400">{section.legacy.path}</code>
                {" \u2192 "}
                <code className="font-mono text-emerald-400">{section.v1.path}</code>
              </p>
            </div>
          )}

          <div>
            <p className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider mb-2">Changes</p>
            <ul className="space-y-1.5">
              {section.changes.map((change, i) => (
                <li key={i} className="flex items-start gap-2 text-xs">
                  <Zap className="h-3.5 w-3.5 text-cyan-400 mt-0.5 shrink-0" />
                  <span>{change}</span>
                </li>
              ))}
            </ul>
          </div>

          {section.example && (
            <div>
              <p className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider mb-2">Example</p>
              <div className="space-y-2">
                <div className="flex items-center gap-2 p-2 rounded border border-border/30 bg-muted/10">
                  <code className="text-[11px] font-mono flex-1 break-all">{section.example.request}</code>
                  <CopyButton text={section.example.request} />
                </div>
                <div className="p-2.5 rounded border border-border/30 bg-muted/10">
                  <pre className="text-[11px] font-mono whitespace-pre-wrap break-all leading-relaxed text-muted-foreground">
                    {JSON.stringify(section.example.responseShape, null, 2)}
                  </pre>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function EndpointCatalog({ sections, search }: { sections: MigrationSection[]; search: string }) {
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());

  const filtered = sections.filter((s) => {
    if (!search) return true;
    const q = search.toLowerCase();
    return (
      s.title.toLowerCase().includes(q) ||
      s.id.toLowerCase().includes(q) ||
      s.v1.path.toLowerCase().includes(q) ||
      s.v1.description.toLowerCase().includes(q) ||
      (s.legacy?.path.toLowerCase().includes(q) ?? false)
    );
  });

  const toggleExpand = (id: string) => {
    setExpandedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const expandAll = () => {
    setExpandedIds(new Set(filtered.map((s) => s.id)));
  };

  const collapseAll = () => {
    setExpandedIds(new Set());
  };

  if (filtered.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-16 text-muted-foreground">
        <Search className="h-10 w-10 mb-3 opacity-30" />
        <p className="text-sm font-medium">No endpoints match your search</p>
        <p className="text-xs mt-1">Try a different search term</p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <p className="text-xs text-muted-foreground">
          {filtered.length} endpoint{filtered.length !== 1 ? "s" : ""}
          {search && ` matching "${search}"`}
        </p>
        <div className="flex gap-1">
          <Button variant="ghost" size="sm" className="text-xs h-7" onClick={expandAll}>
            Expand All
          </Button>
          <Button variant="ghost" size="sm" className="text-xs h-7" onClick={collapseAll}>
            Collapse All
          </Button>
        </div>
      </div>
      {filtered.map((section) => (
        <EndpointCard
          key={section.id}
          section={section}
          isExpanded={expandedIds.has(section.id)}
          onToggle={() => toggleExpand(section.id)}
        />
      ))}
    </div>
  );
}

function GeneralChangesCard({ changes }: { changes: string[] }) {
  return (
    <Card className="glass-card">
      <CardHeader className="pb-3">
        <CardTitle className="text-sm flex items-center gap-2">
          <Megaphone className="h-4 w-4 text-cyan-400" />
          General v1 Changes
        </CardTitle>
        <CardDescription className="text-xs">Changes that apply to all v1 endpoints</CardDescription>
      </CardHeader>
      <CardContent>
        <ul className="space-y-2">
          {changes.map((change, i) => (
            <li key={i} className="flex items-start gap-2.5 text-xs">
              <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400 mt-0.5 shrink-0" />
              <span>{change}</span>
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}

function AuthenticationCard({ auth }: { auth: MigrationGuide["authentication"] }) {
  return (
    <Card className="glass-card">
      <CardHeader className="pb-3">
        <CardTitle className="text-sm flex items-center gap-2">
          <Lock className="h-4 w-4 text-cyan-400" />
          Authentication
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="flex items-start gap-3 p-2.5 rounded-lg border border-emerald-500/20 bg-emerald-500/5">
          <CheckCircle2 className="h-4 w-4 text-emerald-400 mt-0.5 shrink-0" />
          <div>
            <p className="text-xs font-medium">Current (v1)</p>
            <p className="text-xs text-muted-foreground">{auth.current}</p>
          </div>
        </div>
        <div className="flex items-start gap-3 p-2.5 rounded-lg border border-blue-500/20 bg-blue-500/5">
          <Rocket className="h-4 w-4 text-blue-400 mt-0.5 shrink-0" />
          <div>
            <p className="text-xs font-medium">Planned (v2)</p>
            <p className="text-xs text-muted-foreground">{auth.v2planned}</p>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function EnvelopeFormatCard() {
  const exampleEnvelope = {
    ok: true,
    data: ["...payload..."],
    meta: { offset: 0, limit: 50, total: 142 },
    errors: null,
  };

  return (
    <Card className="glass-card">
      <CardHeader className="pb-3">
        <CardTitle className="text-sm flex items-center gap-2">
          <Layers className="h-4 w-4 text-cyan-400" />
          Response Envelope Format
        </CardTitle>
        <CardDescription className="text-xs">All v1 endpoints wrap responses in a standard envelope</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="p-3 rounded-lg border border-border/30 bg-muted/10">
          <pre className="text-[11px] font-mono whitespace-pre-wrap leading-relaxed">
            {JSON.stringify(exampleEnvelope, null, 2)}
          </pre>
        </div>
        <div className="mt-3 grid grid-cols-1 sm:grid-cols-3 gap-2">
          <div className="p-2 rounded border border-border/30 bg-card/30">
            <code className="text-[10px] font-mono text-cyan-400">data</code>
            <p className="text-[10px] text-muted-foreground mt-0.5">The response payload (array or object)</p>
          </div>
          <div className="p-2 rounded border border-border/30 bg-card/30">
            <code className="text-[10px] font-mono text-cyan-400">meta</code>
            <p className="text-[10px] text-muted-foreground mt-0.5">Pagination info, totals, filters</p>
          </div>
          <div className="p-2 rounded border border-border/30 bg-card/30">
            <code className="text-[10px] font-mono text-cyan-400">errors</code>
            <p className="text-[10px] text-muted-foreground mt-0.5">null on success, array of error objects</p>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function LoadingSkeleton() {
  return (
    <div className="p-6 space-y-6" role="status" aria-label="Loading API versioning dashboard">
      <Skeleton className="h-8 w-72" />
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={`stat-${i}`} className="h-24" />
        ))}
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Skeleton className="h-64" />
        <Skeleton className="h-64" />
      </div>
      <Skeleton className="h-96" />
      <span className="sr-only">Loading API versioning dashboard content...</span>
    </div>
  );
}

export default function ApiVersioningPage() {
  usePageTitle("API Versioning");
  const { toast } = useToast();
  const [activeTab, setActiveTab] = useState("overview");
  const [endpointSearch, setEndpointSearch] = useState("");

  const {
    data: policy,
    isLoading: policyLoading,
    isError: policyError,
    refetch: refetchPolicy,
  } = useQuery<VersionPolicy>({
    queryKey: ["/api/v1/version-policy"],
  });

  const {
    data: guide,
    isLoading: guideLoading,
    isError: guideError,
    refetch: refetchGuide,
  } = useQuery<MigrationGuide>({
    queryKey: ["/api/v1/migration-guide"],
  });

  const isLoading = policyLoading || guideLoading;
  const isError = policyError || guideError;

  const handleRefresh = () => {
    refetchPolicy();
    refetchGuide();
    toast({ title: "Refreshed", description: "API versioning data refreshed" });
  };

  if (isLoading) return <LoadingSkeleton />;

  if (isError || !policy) {
    return (
      <div className="flex flex-col items-center justify-center h-[60vh] text-muted-foreground">
        <AlertTriangle className="h-12 w-12 mb-4 text-amber-500/60" />
        <p className="text-lg font-medium">Failed to load API versioning data</p>
        <p className="text-sm mt-1 mb-4">Check your connection and try again</p>
        <Button onClick={handleRefresh} variant="outline" className="gap-2">
          <RefreshCw className="h-4 w-4" />
          Retry
        </Button>
      </div>
    );
  }

  const sunsetDays = daysUntil(policy.stabilityGuarantees.sunsetDate);
  const legacyCount = guide?.sections.filter((s) => s.legacy !== null).length ?? 0;
  const newCount = guide?.sections.filter((s) => s.legacy === null).length ?? 0;

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold flex items-center gap-2">
            <GitBranch className="h-5 w-5 text-cyan-400" />
            API Versioning & Lifecycle
          </h1>
          <p className="text-sm text-muted-foreground mt-1">Version policy, migration guides, and endpoint catalog</p>
        </div>
        <div className="flex items-center gap-2">
          <StabilityBadge level={policy.stabilityLevel} />
          <Badge variant="outline" className="text-xs font-mono">
            {policy.currentVersion}
          </Badge>
          <Button variant="outline" size="sm" onClick={handleRefresh} className="gap-1.5">
            <RefreshCw className="h-3.5 w-3.5" />
            Refresh
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <Card className="glass-card">
          <CardContent className="pt-4 pb-3 px-4">
            <div className="flex items-center gap-2 mb-2">
              <Tag className="h-4 w-4 text-cyan-400" />
              <span className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">Version</span>
            </div>
            <p className="text-2xl font-bold">{policy.currentVersion}</p>
            <p className="text-[10px] text-muted-foreground mt-1">Current stable release</p>
          </CardContent>
        </Card>
        <Card className="glass-card">
          <CardContent className="pt-4 pb-3 px-4">
            <div className="flex items-center gap-2 mb-2">
              <Clock className="h-4 w-4 text-amber-400" />
              <span className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">Sunset In</span>
            </div>
            <p className="text-2xl font-bold tabular-nums">{sunsetDays}d</p>
            <p className="text-[10px] text-muted-foreground mt-1">
              {formatDate(policy.stabilityGuarantees.sunsetDate)}
            </p>
          </CardContent>
        </Card>
        <Card className="glass-card">
          <CardContent className="pt-4 pb-3 px-4">
            <div className="flex items-center gap-2 mb-2">
              <Layers className="h-4 w-4 text-emerald-400" />
              <span className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">Endpoints</span>
            </div>
            <p className="text-2xl font-bold tabular-nums">{guide?.sections.length ?? 0}</p>
            <p className="text-[10px] text-muted-foreground mt-1">
              {legacyCount} migrated, {newCount} new
            </p>
          </CardContent>
        </Card>
        <Card className="glass-card">
          <CardContent className="pt-4 pb-3 px-4">
            <div className="flex items-center gap-2 mb-2">
              <Rocket className="h-4 w-4 text-blue-400" />
              <span className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">v2 Status</span>
            </div>
            <p className="text-2xl font-bold capitalize">{policy.v2Roadmap.status}</p>
            <p className="text-[10px] text-muted-foreground mt-1">
              {policy.v2Roadmap.breakingChanges.length} breaking changes planned
            </p>
          </CardContent>
        </Card>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="grid w-full grid-cols-4 max-w-xl">
          <TabsTrigger value="overview" className="gap-1.5 text-xs">
            <Info className="h-3.5 w-3.5" />
            Overview
          </TabsTrigger>
          <TabsTrigger value="endpoints" className="gap-1.5 text-xs">
            <Code2 className="h-3.5 w-3.5" />
            Endpoints
          </TabsTrigger>
          <TabsTrigger value="migration" className="gap-1.5 text-xs">
            <ArrowRight className="h-3.5 w-3.5" />
            Migration
          </TabsTrigger>
          <TabsTrigger value="reference" className="gap-1.5 text-xs">
            <BookOpen className="h-3.5 w-3.5" />
            Reference
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-6 mt-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <VersionTimelineCard policy={policy} />
            <V2RoadmapCard roadmap={policy.v2Roadmap} migrationPath={policy.v2Roadmap.migrationPath} />
          </div>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <EnvelopeFormatCard />
            {guide && <AuthenticationCard auth={guide.authentication} />}
          </div>
          {guide && <GeneralChangesCard changes={guide.generalChanges} />}
        </TabsContent>

        <TabsContent value="endpoints" className="space-y-4 mt-4">
          <div className="flex items-center gap-3">
            <div className="relative flex-1 max-w-sm">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search endpoints..."
                value={endpointSearch}
                onChange={(e) => setEndpointSearch(e.target.value)}
                className="pl-9 h-9"
              />
            </div>
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <Badge variant="outline" className="text-[10px] bg-cyan-500/10 text-cyan-400 border-cyan-500/20">
                {newCount} new
              </Badge>
              <Badge variant="outline" className="text-[10px] bg-amber-500/10 text-amber-400 border-amber-500/20">
                {legacyCount} migrated
              </Badge>
            </div>
          </div>
          {guide && (
            <ScrollArea className="h-[600px]">
              <EndpointCatalog sections={guide.sections} search={endpointSearch} />
            </ScrollArea>
          )}
        </TabsContent>

        <TabsContent value="migration" className="space-y-6 mt-4">
          {guide && (
            <>
              <Card className="glass-card border-amber-500/20">
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <FileText className="h-4 w-4 text-amber-400" />
                    {guide.title}
                  </CardTitle>
                  <CardDescription className="text-xs">{guide.overview}</CardDescription>
                </CardHeader>
                <CardContent className="space-y-2">
                  <div className="flex items-center gap-4 text-xs text-muted-foreground">
                    <span>
                      Version: <strong className="text-foreground">{guide.version}</strong>
                    </span>
                    <span>
                      Last updated: <strong className="text-foreground">{formatDate(guide.lastUpdated)}</strong>
                    </span>
                  </div>
                </CardContent>
              </Card>
              <GeneralChangesCard changes={guide.generalChanges} />
              <Card className="glass-card">
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <ArrowRight className="h-4 w-4 text-cyan-400" />
                    Endpoint Migration Details
                  </CardTitle>
                  <CardDescription className="text-xs">
                    {legacyCount} endpoints have migration paths from legacy to v1
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <ScrollArea className="h-[500px]">
                    <EndpointCatalog sections={guide.sections.filter((s) => s.legacy !== null)} search="" />
                  </ScrollArea>
                </CardContent>
              </Card>
              <AuthenticationCard auth={guide.authentication} />
            </>
          )}
        </TabsContent>

        <TabsContent value="reference" className="space-y-6 mt-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <HeadersReferenceCard headers={policy.headers} />
            <EnvelopeFormatCard />
          </div>
          <Card className="glass-card">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm flex items-center gap-2">
                <Code2 className="h-4 w-4 text-cyan-400" />
                Endpoint Namespaces
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                {Object.entries(policy.endpoints).map(([namespace, description]) => (
                  <div
                    key={namespace}
                    className="flex items-start gap-3 p-2.5 rounded-lg border border-border/30 bg-card/30"
                  >
                    <Badge variant="outline" className="text-[10px] font-mono capitalize shrink-0">
                      {namespace}
                    </Badge>
                    <p className="text-xs text-muted-foreground">{description}</p>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
          <Card className="glass-card">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm flex items-center gap-2">
                <Shield className="h-4 w-4 text-cyan-400" />
                Stability Guarantees
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                <div className="flex items-start gap-3 p-2.5 rounded-lg border border-emerald-500/20 bg-emerald-500/5">
                  <CheckCircle2 className="h-4 w-4 text-emerald-400 mt-0.5 shrink-0" />
                  <div>
                    <p className="text-xs font-medium">No Breaking Changes</p>
                    <p className="text-xs text-muted-foreground">{policy.stabilityGuarantees.breakingChanges}</p>
                  </div>
                </div>
                <div className="flex items-start gap-3 p-2.5 rounded-lg border border-amber-500/20 bg-amber-500/5">
                  <Megaphone className="h-4 w-4 text-amber-400 mt-0.5 shrink-0" />
                  <div>
                    <p className="text-xs font-medium">Deprecation Notice</p>
                    <p className="text-xs text-muted-foreground">{policy.stabilityGuarantees.deprecationNotice}</p>
                  </div>
                </div>
                <div className="flex items-start gap-3 p-2.5 rounded-lg border border-blue-500/20 bg-blue-500/5">
                  <CalendarClock className="h-4 w-4 text-blue-400 mt-0.5 shrink-0" />
                  <div>
                    <p className="text-xs font-medium">Supported Until</p>
                    <p className="text-xs text-muted-foreground">
                      {formatDate(policy.stabilityGuarantees.supportedUntil)} ({sunsetDays} days remaining)
                    </p>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}

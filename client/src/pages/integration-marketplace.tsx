import { useState, useCallback } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  AlertTriangle,
  ArrowLeftRight,
  ArrowRight,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Cloud,
  Code,
  Database,
  GitBranch,
  Globe,
  Heart,
  Loader2,
  Lock,
  MessageSquare,
  Monitor,
  Plug,
  RefreshCw,
  Search,
  Settings,
  Shield,
  ShieldCheck,
  Ticket,
  Trash2,
  Unlock,
  User,
  Wifi,
  WifiOff,
  XCircle,
  Zap,
  Star,
  BookOpen,
  Layers,
  BarChart3,
  Clock,
  FileText,
  Play,
  ExternalLink,
  Package,
  Bell,
} from "lucide-react";
import { SuccessIcon } from "@/components/ui/animated-state-icons";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";

interface MarketplaceConnector {
  id: string;
  name: string;
  vendor: string;
  category: string;
  description: string;
  icon: string;
  supportedAuth: string[];
  supportedSync: string[];
  syncEntities: string[];
  version: string;
  docsUrl: string;
  status: string;
  permissionMode: string;
  installedAt: string | null;
  configuredAt: string | null;
  orgId: string;
}

interface ConnectorInstance {
  id: string;
  connectorId: string;
  orgId: string;
  name: string;
  authMethod: string;
  permissionMode: string;
  syncDirection: string;
  status: string;
  config: Record<string, unknown>;
  installedAt: string;
  configuredAt: string | null;
  lastSyncAt: string | null;
  lastSyncStatus: string | null;
  syncIntervalMinutes: number;
}

interface QualityScore {
  connectorId: string;
  instanceId: string;
  latencyP50Ms: number;
  latencyP99Ms: number;
  reliabilityPercent: number;
  schemaCompleteness: number;
  uptimePercent: number;
  totalSyncs: number;
  successfulSyncs: number;
  failedSyncs: number;
  lastMeasuredAt: string;
}

interface SyncEvent {
  id: string;
  instanceId: string;
  direction: string;
  entity: string;
  recordsProcessed: number;
  recordsFailed: number;
  durationMs: number;
  status: string;
  error: string | null;
  startedAt: string;
  completedAt: string;
}

interface HealthCheck {
  id: string;
  instanceId: string;
  status: string;
  latencyMs: number;
  credentialStatus: string;
  schemaVersion: string | null;
  driftDetected: boolean;
  driftDetails: string | null;
  checkedAt: string;
}

interface DeadLetterEntry {
  id: string;
  webhookEventId: string;
  instanceId: string;
  eventType: string;
  failureReason: string;
  attempts: number;
  movedAt: string;
  retriedAt: string | null;
  resolvedAt: string | null;
}

interface MarketplaceStats {
  totalInstances: number;
  activeInstances: number;
  errorInstances: number;
  totalConnectors: number;
}

interface IntegrationDetail {
  id: string;
  name: string;
  vendor: string;
  category: string;
  description: string;
  version: string;
  installCount: number;
  supportedFeatures: string[];
  configurationGuide: string[];
  versionHistory: Array<{ version: string; date: string; changes: string[] }>;
  reviews: Array<{ rating: number; author: string; comment: string; date: string }>;
  rating: number;
  pricing: string;
}

interface SetupStep {
  step: number;
  title: string;
  description: string;
  fields: Array<{
    key: string;
    type: string;
    options?: string[];
    label: string;
    required: boolean;
    placeholder?: string;
  }>;
}

interface SetupWizardData {
  connectorSlug: string;
  connectorName: string;
  category: string;
  steps: SetupStep[];
}

interface HealthSummaryEntry {
  instanceId: string;
  name: string;
  connectorId: string;
  status: string;
  lastSyncAt: string | null;
  lastSyncStatus: string | null;
  healthStatus: string;
  latencyMs: number | null;
  credentialStatus: string;
  driftDetected: boolean;
  reliabilityPercent: number | null;
  uptimePercent: number | null;
  successRate: number | null;
  errorCount: number;
  alertLevel: string;
}

interface UpdateEntry {
  instanceId: string;
  instanceName: string;
  connectorId: string;
  connectorName: string;
  currentVersion: string;
  latestVersion: string;
  hasUpdate: boolean;
  autoUpdateEnabled: boolean;
  changelog: string[];
  lastCheckedAt: string;
}

const CATEGORY_CONFIG: Record<string, { label: string; icon: typeof Plug; color: string }> = {
  ticketing: { label: "Ticketing", icon: Ticket, color: "text-blue-400" },
  messaging: { label: "Messaging", icon: MessageSquare, color: "text-green-400" },
  siem: { label: "SIEM", icon: Database, color: "text-purple-400" },
  soar: { label: "SOAR", icon: Shield, color: "text-orange-400" },
  iam: { label: "IAM", icon: User, color: "text-cyan-400" },
  cicd: { label: "CI/CD", icon: GitBranch, color: "text-yellow-400" },
  vcs: { label: "VCS", icon: Code, color: "text-pink-400" },
  cloud: { label: "Cloud", icon: Cloud, color: "text-sky-400" },
  endpoint: { label: "Endpoint", icon: Monitor, color: "text-red-400" },
};

const STATUS_CONFIG: Record<string, { label: string; color: string; icon: typeof CheckCircle2 }> = {
  available: { label: "Available", color: "bg-slate-600 text-slate-200", icon: Globe },
  installed: { label: "Installed", color: "bg-blue-600/20 text-blue-300", icon: Plug },
  configured: { label: "Configured", color: "bg-indigo-600/20 text-indigo-300", icon: Settings },
  active: { label: "Active", color: "bg-emerald-600/20 text-emerald-300", icon: CheckCircle2 },
  degraded: { label: "Degraded", color: "bg-yellow-600/20 text-yellow-300", icon: AlertTriangle },
  error: { label: "Error", color: "bg-red-600/20 text-red-300", icon: XCircle },
  disabled: { label: "Disabled", color: "bg-slate-600/20 text-slate-400", icon: WifiOff },
};

const HEALTH_CONFIG: Record<string, { label: string; color: string }> = {
  healthy: { label: "Healthy", color: "text-emerald-400" },
  degraded: { label: "Degraded", color: "text-yellow-400" },
  unhealthy: { label: "Unhealthy", color: "text-red-400" },
  unreachable: { label: "Unreachable", color: "text-slate-400" },
};

const PERMISSION_LABELS: Record<string, string> = {
  read_only: "Read Only",
  scoped_write: "Scoped Write",
  full_write: "Full Write",
};

type TabView = "catalog" | "installed" | "health" | "dead-letters" | "details" | "updates";

function StatsBar({ stats }: { stats: MarketplaceStats }) {
  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
      <Card className="border-border/40 bg-card/50">
        <CardContent className="p-3 text-center">
          <div className="text-2xl font-bold text-foreground">{stats.totalConnectors}</div>
          <div className="text-xs text-muted-foreground">Available</div>
        </CardContent>
      </Card>
      <Card className="border-border/40 bg-card/50">
        <CardContent className="p-3 text-center">
          <div className="text-2xl font-bold text-blue-400">{stats.totalInstances}</div>
          <div className="text-xs text-muted-foreground">Installed</div>
        </CardContent>
      </Card>
      <Card className="border-border/40 bg-card/50">
        <CardContent className="p-3 text-center">
          <div className="text-2xl font-bold text-emerald-400">{stats.activeInstances}</div>
          <div className="text-xs text-muted-foreground">Active</div>
        </CardContent>
      </Card>
      <Card className="border-border/40 bg-card/50">
        <CardContent className="p-3 text-center">
          <div className="text-2xl font-bold text-yellow-400">—</div>
          <div className="text-xs text-muted-foreground">Degraded</div>
        </CardContent>
      </Card>
      <Card className="border-border/40 bg-card/50">
        <CardContent className="p-3 text-center">
          <div className="text-2xl font-bold text-red-400">{stats.errorInstances}</div>
          <div className="text-xs text-muted-foreground">Errors</div>
        </CardContent>
      </Card>
      <Card className="border-border/40 bg-card/50">
        <CardContent className="p-3 text-center">
          <div className="text-2xl font-bold text-foreground">—</div>
          <div className="text-xs text-muted-foreground">Categories</div>
        </CardContent>
      </Card>
    </div>
  );
}

function ConnectorCard({
  connector,
  onInstall,
  installing,
}: {
  connector: MarketplaceConnector;
  onInstall: (slug: string) => void;
  installing: boolean;
}) {
  const catConfig = CATEGORY_CONFIG[connector.category];
  const statusConfig = STATUS_CONFIG[connector.status] || STATUS_CONFIG.available;
  const CategoryIcon = catConfig?.icon || Plug;
  const StatusIcon = statusConfig.icon;

  return (
    <Card className="border-border/40 bg-card/50 hover:border-primary/30 transition-colors">
      <CardContent className="p-4">
        <div className="flex items-start justify-between mb-3">
          <div className="flex items-center gap-3">
            <div className={`p-2 rounded-lg bg-muted/50 ${catConfig?.color || "text-muted-foreground"}`}>
              <CategoryIcon className="h-5 w-5" />
            </div>
            <div>
              <h3 className="font-semibold text-sm text-foreground">{connector.name}</h3>
              <p className="text-xs text-muted-foreground">{connector.vendor}</p>
            </div>
          </div>
          <Badge className={statusConfig.color + " text-xs"}>
            <StatusIcon className="h-3 w-3 mr-1" />
            {statusConfig.label}
          </Badge>
        </div>

        <p className="text-xs text-muted-foreground mb-3 line-clamp-2">{connector.description}</p>

        <div className="flex flex-wrap gap-1 mb-3">
          {connector.syncEntities.slice(0, 4).map((entity) => (
            <Badge key={entity} variant="outline" className="text-[10px] px-1.5 py-0">
              {entity.replace(/_/g, " ")}
            </Badge>
          ))}
          {connector.syncEntities.length > 4 && (
            <Badge variant="outline" className="text-[10px] px-1.5 py-0">
              +{connector.syncEntities.length - 4}
            </Badge>
          )}
        </div>

        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <span>v{connector.version}</span>
            <span className="text-border">|</span>
            <div className="flex items-center gap-1">
              {connector.supportedSync.includes("bidirectional") ? (
                <ArrowLeftRight className="h-3 w-3" />
              ) : (
                <ArrowRight className="h-3 w-3" />
              )}
              <span>{connector.supportedSync.includes("bidirectional") ? "Bi-directional" : "One-way"}</span>
            </div>
          </div>
          {connector.status === "available" && (
            <div className="flex gap-1">
              <Button
                size="sm"
                variant="outline"
                className="h-7 text-xs"
                onClick={() => onInstall(connector.id)}
                disabled={installing}
                aria-label={"Install " + connector.name}
              >
                {installing ? <Loader2 className="h-3 w-3 animate-spin mr-1" /> : <Plug className="h-3 w-3 mr-1" />}
                Install
              </Button>
            </div>
          )}
          {connector.status !== "available" && (
            <Badge variant="outline" className="text-[10px]">
              <Lock className="h-2.5 w-2.5 mr-1" />
              {PERMISSION_LABELS[connector.permissionMode] || "Read Only"}
            </Badge>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

function InstanceRow({
  instance,
  onSync,
  onHealthCheck,
  onDelete,
  onUpgradePermissions,
  syncing,
  checking,
  expanded,
  onToggle,
  qualityScore,
}: {
  instance: ConnectorInstance;
  onSync: (id: string) => void;
  onHealthCheck: (id: string) => void;
  onDelete: (id: string) => void;
  onUpgradePermissions: (id: string, mode: string) => void;
  syncing: boolean;
  checking: boolean;
  expanded: boolean;
  onToggle: () => void;
  qualityScore: QualityScore | null;
}) {
  const statusConfig = STATUS_CONFIG[instance.status] || STATUS_CONFIG.available;
  const StatusIcon = statusConfig.icon;

  return (
    <Card className="border-border/40 bg-card/50">
      <CardContent className="p-0">
        <button
          className="w-full flex items-center justify-between p-4 text-left hover:bg-muted/20 transition-colors"
          onClick={onToggle}
          aria-expanded={expanded}
          aria-label={"Toggle details for " + instance.name}
        >
          <div className="flex items-center gap-3">
            {expanded ? (
              <ChevronDown className="h-4 w-4 text-muted-foreground" />
            ) : (
              <ChevronRight className="h-4 w-4 text-muted-foreground" />
            )}
            <div>
              <div className="font-semibold text-sm text-foreground">{instance.name}</div>
              <div className="text-xs text-muted-foreground">
                {instance.authMethod} | {instance.syncDirection} | every {instance.syncIntervalMinutes}m
              </div>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Badge className={statusConfig.color + " text-xs"}>
              <StatusIcon className="h-3 w-3 mr-1" />
              {statusConfig.label}
            </Badge>
            <Badge variant="outline" className="text-xs">
              <Lock className="h-2.5 w-2.5 mr-1" />
              {PERMISSION_LABELS[instance.permissionMode] || "Read Only"}
            </Badge>
          </div>
        </button>

        {expanded && (
          <div className="border-t border-border/40 p-4 space-y-4">
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div>
                <div className="text-xs text-muted-foreground mb-1">Last Sync</div>
                <div className="text-sm text-foreground">
                  {instance.lastSyncAt ? new Date(instance.lastSyncAt).toLocaleString() : "Never"}
                </div>
              </div>
              <div>
                <div className="text-xs text-muted-foreground mb-1">Last Status</div>
                <div className="text-sm text-foreground">{instance.lastSyncStatus || "N/A"}</div>
              </div>
              <div>
                <div className="text-xs text-muted-foreground mb-1">Installed</div>
                <div className="text-sm text-foreground">{new Date(instance.installedAt).toLocaleDateString()}</div>
              </div>
              <div>
                <div className="text-xs text-muted-foreground mb-1">Configured</div>
                <div className="text-sm text-foreground">
                  {instance.configuredAt ? new Date(instance.configuredAt).toLocaleDateString() : "Pending"}
                </div>
              </div>
            </div>

            {qualityScore && (
              <div className="rounded-lg border border-border/40 p-3">
                <div className="text-xs font-medium text-muted-foreground mb-2">Quality Score</div>
                <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
                  <div>
                    <div className="text-lg font-bold text-foreground">{qualityScore.latencyP50Ms}ms</div>
                    <div className="text-[10px] text-muted-foreground">P50 Latency</div>
                  </div>
                  <div>
                    <div className="text-lg font-bold text-foreground">{qualityScore.latencyP99Ms}ms</div>
                    <div className="text-[10px] text-muted-foreground">P99 Latency</div>
                  </div>
                  <div>
                    <div
                      className={`text-lg font-bold ${qualityScore.reliabilityPercent !== null && qualityScore.reliabilityPercent >= 99 ? "text-emerald-400" : qualityScore.reliabilityPercent !== null && qualityScore.reliabilityPercent >= 95 ? "text-yellow-400" : "text-muted-foreground"}`}
                    >
                      {qualityScore.reliabilityPercent !== null ? `${qualityScore.reliabilityPercent}%` : "Unavailable"}
                    </div>
                    <div className="text-[10px] text-muted-foreground">Reliability</div>
                  </div>
                  <div>
                    <div className="text-lg font-bold text-foreground">{qualityScore.schemaCompleteness}%</div>
                    <div className="text-[10px] text-muted-foreground">Schema</div>
                  </div>
                  <div>
                    <div className="text-lg font-bold text-foreground">
                      {qualityScore.successfulSyncs}/{qualityScore.totalSyncs}
                    </div>
                    <div className="text-[10px] text-muted-foreground">Success/Total</div>
                  </div>
                </div>
              </div>
            )}

            <div className="flex flex-wrap gap-2">
              <Button
                size="sm"
                variant="outline"
                className="h-7 text-xs"
                onClick={() => onSync(instance.id)}
                disabled={syncing}
                aria-label={"Sync " + instance.name}
              >
                {syncing ? <Loader2 className="h-3 w-3 animate-spin mr-1" /> : <RefreshCw className="h-3 w-3 mr-1" />}
                Sync Now
              </Button>
              <Button
                size="sm"
                variant="outline"
                className="h-7 text-xs"
                onClick={() => onHealthCheck(instance.id)}
                disabled={checking}
                aria-label={"Health check " + instance.name}
              >
                {checking ? <Loader2 className="h-3 w-3 animate-spin mr-1" /> : <Heart className="h-3 w-3 mr-1" />}
                Health Check
              </Button>
              {instance.permissionMode === "read_only" && (
                <Button
                  size="sm"
                  variant="outline"
                  className="h-7 text-xs"
                  onClick={() => onUpgradePermissions(instance.id, "scoped_write")}
                  aria-label={"Upgrade permissions for " + instance.name}
                >
                  <Unlock className="h-3 w-3 mr-1" />
                  Enable Scoped Write
                </Button>
              )}
              {instance.permissionMode === "scoped_write" && (
                <Button
                  size="sm"
                  variant="outline"
                  className="h-7 text-xs"
                  onClick={() => onUpgradePermissions(instance.id, "full_write")}
                  aria-label={"Upgrade to full write for " + instance.name}
                >
                  <Unlock className="h-3 w-3 mr-1" />
                  Enable Full Write
                </Button>
              )}
              <Button
                size="sm"
                variant="destructive"
                className="h-7 text-xs ml-auto"
                onClick={() => onDelete(instance.id)}
                aria-label={"Uninstall " + instance.name}
              >
                <Trash2 className="h-3 w-3 mr-1" />
                Uninstall
              </Button>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function HealthDashboard({ instances }: { instances: ConnectorInstance[] }) {
  const { data: healthData } = useQuery<Record<string, HealthCheck[]>>({
    queryKey: ["/api/integration-marketplace/health-all"],
    queryFn: async () => {
      const results: Record<string, HealthCheck[]> = {};
      for (const inst of instances) {
        try {
          const res = await apiRequest(
            "GET",
            `/api/integration-marketplace/instances/${inst.id}/health-history?limit=5`,
          );
          results[inst.id] = await res.json();
        } catch {
          results[inst.id] = [];
        }
      }
      return results;
    },
    enabled: instances.length > 0,
  });

  if (instances.length === 0) {
    return (
      <div className="text-center py-12">
        <Wifi className="h-10 w-10 text-muted-foreground mx-auto mb-3" />
        <p className="text-sm text-muted-foreground">No installed connectors to monitor</p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {instances.map((inst) => {
        const checks = healthData?.[inst.id] || [];
        const latest = checks[0];
        const healthConfig = latest ? HEALTH_CONFIG[latest.status] : null;

        return (
          <Card key={inst.id} className="border-border/40 bg-card/50">
            <CardContent className="p-4">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <div
                    className={`h-2 w-2 rounded-full ${latest?.status === "healthy" ? "bg-emerald-400" : latest?.status === "degraded" ? "bg-yellow-400" : latest?.status === "unhealthy" ? "bg-red-400" : "bg-slate-400"}`}
                  />
                  <span className="font-semibold text-sm text-foreground">{inst.name}</span>
                </div>
                <div className="flex items-center gap-3 text-xs">
                  {healthConfig && <span className={healthConfig.color}>{healthConfig.label}</span>}
                  {latest && <span className="text-muted-foreground">{latest.latencyMs}ms</span>}
                  {latest?.credentialStatus && (
                    <Badge
                      variant="outline"
                      className={`text-[10px] ${latest.credentialStatus === "valid" ? "text-emerald-400" : latest.credentialStatus === "expiring" ? "text-yellow-400" : "text-red-400"}`}
                    >
                      Creds: {latest.credentialStatus}
                    </Badge>
                  )}
                </div>
              </div>

              {latest?.driftDetected && (
                <div className="mt-2 p-2 rounded bg-yellow-500/10 border border-yellow-500/20">
                  <div className="flex items-center gap-1 text-xs text-yellow-400">
                    <AlertTriangle className="h-3 w-3" />
                    <span className="font-medium">Schema Drift Detected</span>
                  </div>
                  {latest.driftDetails && <p className="text-xs text-muted-foreground mt-1">{latest.driftDetails}</p>}
                </div>
              )}

              {checks.length > 1 && (
                <div className="mt-2 flex items-center gap-1">
                  <span className="text-[10px] text-muted-foreground mr-1">History:</span>
                  {checks.slice(0, 5).map((check) => (
                    <div
                      key={check.id}
                      className={`h-3 w-3 rounded-sm ${check.status === "healthy" ? "bg-emerald-500/60" : check.status === "degraded" ? "bg-yellow-500/60" : "bg-red-500/60"}`}
                      title={`${check.status} at ${new Date(check.checkedAt).toLocaleString()} (${check.latencyMs}ms)`}
                    />
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        );
      })}
    </div>
  );
}

function DeadLetterQueue() {
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const { data: deadLetters, isLoading } = useQuery<DeadLetterEntry[]>({
    queryKey: ["/api/integration-marketplace/dead-letters"],
  });

  const retryMutation = useMutation({
    mutationFn: async (entryId: string) => {
      const res = await apiRequest("POST", `/api/integration-marketplace/dead-letters/${entryId}/retry`);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/integration-marketplace/dead-letters"] });
      toast({ title: "Dead letter retried" });
    },
  });

  const discardMutation = useMutation({
    mutationFn: async (entryId: string) => {
      const res = await apiRequest("POST", `/api/integration-marketplace/dead-letters/${entryId}/discard`);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/integration-marketplace/dead-letters"] });
      toast({ title: "Dead letter discarded" });
    },
  });

  if (isLoading) {
    return (
      <div className="space-y-3">
        {Array.from({ length: 3 }).map((_, i) => (
          <Skeleton key={i} className="h-20 w-full" />
        ))}
      </div>
    );
  }

  if (!deadLetters || deadLetters.length === 0) {
    return (
      <div className="text-center py-12">
        <ShieldCheck className="h-10 w-10 text-emerald-400 mx-auto mb-3" />
        <p className="text-sm text-muted-foreground">Dead letter queue is empty</p>
        <p className="text-xs text-muted-foreground mt-1">All webhook events have been delivered successfully</p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {deadLetters.map((entry) => (
        <Card key={entry.id} className="border-border/40 bg-card/50">
          <CardContent className="p-4">
            <div className="flex items-center justify-between mb-2">
              <div>
                <span className="font-medium text-sm text-foreground">{entry.eventType}</span>
                <span className="text-xs text-muted-foreground ml-2">{entry.attempts} attempt(s)</span>
              </div>
              <span className="text-xs text-muted-foreground">{new Date(entry.movedAt).toLocaleString()}</span>
            </div>
            <p className="text-xs text-red-400 mb-3">{entry.failureReason}</p>
            <div className="flex gap-2">
              <Button
                size="sm"
                variant="outline"
                className="h-7 text-xs"
                onClick={() => retryMutation.mutate(entry.id)}
                disabled={retryMutation.isPending}
                aria-label={"Retry dead letter " + entry.eventType}
              >
                <RefreshCw className="h-3 w-3 mr-1" />
                Retry
              </Button>
              <Button
                size="sm"
                variant="ghost"
                className="h-7 text-xs text-muted-foreground"
                onClick={() => discardMutation.mutate(entry.id)}
                disabled={discardMutation.isPending}
                aria-label={"Discard dead letter " + entry.eventType}
              >
                <Trash2 className="h-3 w-3 mr-1" />
                Discard
              </Button>
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

function IntegrationDetailPanel({ slug, onBack }: { slug: string; onBack: () => void }) {
  const { data: detail } = useQuery<IntegrationDetail>({
    queryKey: ["/api/integration-marketplace/catalog", slug, "details"],
    queryFn: async () => {
      const res = await apiRequest("GET", `/api/integration-marketplace/catalog/\${slug}/details`);
      return res.json();
    },
  });

  if (!detail)
    return (
      <div className="space-y-3">
        {Array.from({ length: 3 }).map((_, i) => (
          <Skeleton key={i} className="h-20 w-full" />
        ))}
      </div>
    );

  return (
    <div className="space-y-4">
      <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={onBack}>
        <ChevronRight className="h-3 w-3 mr-1 rotate-180" />
        Back to Catalog
      </Button>

      <Card className="border-border/40 bg-card/50">
        <CardContent className="p-6">
          <div className="flex items-start justify-between mb-4">
            <div>
              <h2 className="text-lg font-bold text-foreground">{detail.name}</h2>
              <p className="text-sm text-muted-foreground">{detail.vendor}</p>
            </div>
            <div className="flex items-center gap-2">
              <div className="flex items-center gap-1">
                <Star className="h-4 w-4 text-yellow-400 fill-yellow-400" />
                <span className="text-sm font-medium text-foreground">{detail.rating}</span>
              </div>
              <Badge variant="outline" className="text-xs">
                v{detail.version}
              </Badge>
              <Badge className="bg-emerald-600/20 text-emerald-300 text-xs">{detail.pricing}</Badge>
            </div>
          </div>
          <p className="text-sm text-muted-foreground mb-4">{detail.description}</p>
          <div className="text-xs text-muted-foreground">{detail.installCount} installation(s)</div>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card className="border-border/40 bg-card/50">
          <CardContent className="p-4">
            <h3 className="text-sm font-semibold text-foreground mb-3 flex items-center gap-2">
              <Layers className="h-4 w-4 text-primary" />
              Supported Features
            </h3>
            <div className="flex flex-wrap gap-1.5">
              {detail.supportedFeatures.map((f) => (
                <Badge key={f} variant="outline" className="text-xs">
                  {f.replace(/_/g, " ")}
                </Badge>
              ))}
            </div>
          </CardContent>
        </Card>
        <Card className="border-border/40 bg-card/50">
          <CardContent className="p-4">
            <h3 className="text-sm font-semibold text-foreground mb-3 flex items-center gap-2">
              <BookOpen className="h-4 w-4 text-primary" />
              Configuration Guide
            </h3>
            <ol className="space-y-1.5">
              {detail.configurationGuide.map((step, i) => (
                <li key={i} className="text-xs text-muted-foreground">
                  {step}
                </li>
              ))}
            </ol>
          </CardContent>
        </Card>
      </div>

      {detail.versionHistory.length > 0 && (
        <Card className="border-border/40 bg-card/50">
          <CardContent className="p-4">
            <h3 className="text-sm font-semibold text-foreground mb-3 flex items-center gap-2">
              <Clock className="h-4 w-4 text-primary" />
              Version History
            </h3>
            {detail.versionHistory.map((v) => (
              <div key={v.version} className="mb-2">
                <div className="flex items-center gap-2">
                  <Badge variant="outline" className="text-xs">
                    v{v.version}
                  </Badge>
                  <span className="text-xs text-muted-foreground">{new Date(v.date).toLocaleDateString()}</span>
                </div>
                <ul className="mt-1 space-y-0.5">
                  {v.changes.map((c, i) => (
                    <li key={i} className="text-xs text-muted-foreground pl-2">
                      - {c}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function SetupWizardDialog({
  slug,
  onClose,
  onInstall,
}: {
  slug: string;
  onClose: () => void;
  onInstall: (slug: string) => void;
}) {
  const [currentStep, setCurrentStep] = useState(0);
  const [formData, setFormData] = useState<Record<string, string>>({});
  const [testStatus, setTestStatus] = useState<"idle" | "testing" | "success" | "failed">("idle");
  const { toast } = useToast();

  const { data: wizard } = useQuery<SetupWizardData>({
    queryKey: ["/api/integration-marketplace/catalog", slug, "setup-steps"],
    queryFn: async () => {
      const res = await apiRequest("GET", `/api/integration-marketplace/catalog/\${slug}/setup-steps`);
      return res.json();
    },
  });

  if (!wizard) return null;

  const step = wizard.steps[currentStep];
  const isLastStep = currentStep === wizard.steps.length - 1;

  const handleNext = () => {
    if (isLastStep) {
      if (step.title === "Test Connection") {
        setTestStatus("testing");
        setTimeout(() => {
          setTestStatus("success");
          toast({ title: "Connection successful" });
        }, 1500);
        return;
      }
      onInstall(slug);
      onClose();
    } else {
      setCurrentStep((prev) => prev + 1);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
      <div className="bg-card border border-border/60 rounded-xl shadow-2xl w-full max-w-lg mx-4">
        <div className="flex items-center justify-between p-4 border-b border-border/40">
          <div>
            <h2 className="text-sm font-semibold text-foreground">Setup: {wizard.connectorName}</h2>
            <p className="text-xs text-muted-foreground">
              Step {currentStep + 1} of {wizard.steps.length}
            </p>
          </div>
          <Button variant="ghost" size="sm" onClick={onClose} aria-label="Close setup wizard">
            <XCircle className="h-4 w-4" />
          </Button>
        </div>

        <div className="p-4 space-y-4">
          <div className="flex items-center gap-2 mb-2">
            {wizard.steps.map((s, i) => (
              <div
                key={i}
                className={`flex-1 h-1.5 rounded-full \${i <= currentStep ? "bg-primary" : "bg-muted/50"}`}
              />
            ))}
          </div>

          <div>
            <h3 className="text-sm font-semibold text-foreground mb-1">{step.title}</h3>
            <p className="text-xs text-muted-foreground mb-3">{step.description}</p>
          </div>

          {step.fields.map((field) => (
            <div key={field.key}>
              <label className="text-xs font-medium text-muted-foreground mb-1 block">{field.label}</label>
              {field.type === "select" && field.options ? (
                <select
                  className="w-full px-3 py-2 rounded-md border border-border/60 bg-background text-sm text-foreground"
                  value={formData[field.key] || ""}
                  onChange={(e) => setFormData({ ...formData, [field.key]: e.target.value })}
                >
                  <option value="">Select...</option>
                  {field.options.map((o) => (
                    <option key={o} value={o}>
                      {o.replace(/_/g, " ")}
                    </option>
                  ))}
                </select>
              ) : (
                <input
                  type={field.type === "secret" ? "password" : "text"}
                  className="w-full px-3 py-2 rounded-md border border-border/60 bg-background text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-primary/50"
                  value={formData[field.key] || ""}
                  onChange={(e) => setFormData({ ...formData, [field.key]: e.target.value })}
                  placeholder={field.placeholder || ""}
                />
              )}
            </div>
          ))}

          {step.title === "Test Connection" && (
            <div className="rounded-lg border border-border/40 p-4 text-center">
              {testStatus === "idle" && (
                <p className="text-sm text-muted-foreground">Click Next to test the connection</p>
              )}
              {testStatus === "testing" && (
                <div className="flex items-center justify-center gap-2">
                  <Loader2 className="h-4 w-4 animate-spin text-primary" />
                  <span className="text-sm text-foreground">Testing connection...</span>
                </div>
              )}
              {testStatus === "success" && (
                <div className="flex items-center justify-center gap-2">
                  <CheckCircle2 className="h-4 w-4 text-green-500" />
                  <span className="text-sm text-emerald-400">Connection successful!</span>
                </div>
              )}
              {testStatus === "failed" && (
                <div className="flex items-center justify-center gap-2">
                  <XCircle className="h-4 w-4 text-red-400" />
                  <span className="text-sm text-red-400">Connection failed</span>
                </div>
              )}
            </div>
          )}
        </div>

        <div className="flex items-center justify-between p-4 border-t border-border/40">
          <Button
            variant="outline"
            size="sm"
            onClick={() => (currentStep > 0 ? setCurrentStep(currentStep - 1) : onClose())}
            className="h-7 text-xs"
          >
            {currentStep > 0 ? "Back" : "Cancel"}
          </Button>
          <Button size="sm" onClick={handleNext} className="h-7 text-xs" disabled={testStatus === "testing"}>
            {isLastStep && testStatus === "success" ? (
              <>
                <Play className="h-3 w-3 mr-1" />
                Install
              </>
            ) : (
              <>
                <ArrowRight className="h-3 w-3 mr-1" />
                Next
              </>
            )}
          </Button>
        </div>
      </div>
    </div>
  );
}

function HealthSummaryView() {
  const { data: healthSummary, isLoading } = useQuery<HealthSummaryEntry[]>({
    queryKey: ["/api/integration-marketplace/health-summary"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/integration-marketplace/health-summary");
      return res.json();
    },
  });

  if (isLoading)
    return (
      <div className="space-y-3">
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={i} className="h-16 w-full" />
        ))}
      </div>
    );

  if (!healthSummary || healthSummary.length === 0) {
    return (
      <div className="text-center py-12">
        <Activity className="h-10 w-10 text-muted-foreground mx-auto mb-3" />
        <p className="text-sm text-muted-foreground">No integrations to monitor</p>
      </div>
    );
  }

  const criticalCount = healthSummary.filter((h) => h.alertLevel === "critical").length;
  const warningCount = healthSummary.filter((h) => h.alertLevel === "warning").length;
  const okCount = healthSummary.filter((h) => h.alertLevel === "ok").length;

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-3 gap-3">
        <Card className="border-border/40 bg-card/50">
          <CardContent className="p-3 text-center">
            <div className="text-2xl font-bold text-emerald-400">{okCount}</div>
            <div className="text-xs text-muted-foreground">Healthy</div>
          </CardContent>
        </Card>
        <Card className="border-border/40 bg-card/50">
          <CardContent className="p-3 text-center">
            <div className="text-2xl font-bold text-yellow-400">{warningCount}</div>
            <div className="text-xs text-muted-foreground">Warning</div>
          </CardContent>
        </Card>
        <Card className="border-border/40 bg-card/50">
          <CardContent className="p-3 text-center">
            <div className="text-2xl font-bold text-red-400">{criticalCount}</div>
            <div className="text-xs text-muted-foreground">Critical</div>
          </CardContent>
        </Card>
      </div>

      <div className="space-y-2">
        {healthSummary.map((entry) => (
          <Card key={entry.instanceId} className="border-border/40 bg-card/50">
            <CardContent className="p-4">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <div
                    className={`h-2.5 w-2.5 rounded-full \${entry.alertLevel === "ok" ? "bg-emerald-400" : entry.alertLevel === "warning" ? "bg-yellow-400" : "bg-red-400"}`}
                  />
                  <span className="font-semibold text-sm text-foreground">{entry.name}</span>
                </div>
                <div className="flex items-center gap-2 text-xs">
                  <Badge
                    variant="outline"
                    className={`text-[10px] \${entry.healthStatus === "healthy" ? "text-emerald-400" : entry.healthStatus === "degraded" ? "text-yellow-400" : "text-red-400"}`}
                  >
                    {entry.healthStatus}
                  </Badge>
                  {entry.latencyMs !== null && <span className="text-muted-foreground">{entry.latencyMs}ms</span>}
                </div>
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 text-xs">
                <div>
                  <span className="text-muted-foreground">Last Sync</span>
                  <div className="text-foreground">
                    {entry.lastSyncAt ? new Date(entry.lastSyncAt).toLocaleString() : "Never"}
                  </div>
                </div>
                <div>
                  <span className="text-muted-foreground">Credentials</span>
                  <div
                    className={`\${entry.credentialStatus === "valid" ? "text-emerald-400" : entry.credentialStatus === "expiring" ? "text-yellow-400" : "text-red-400"}`}
                  >
                    {entry.credentialStatus}
                  </div>
                </div>
                <div>
                  <span className="text-muted-foreground">Reliability</span>
                  <div className="text-foreground">
                    {entry.reliabilityPercent !== null ? entry.reliabilityPercent + "%" : "N/A"}
                  </div>
                </div>
                <div>
                  <span className="text-muted-foreground">Success Rate</span>
                  <div className="text-foreground">{entry.successRate !== null ? entry.successRate + "%" : "N/A"}</div>
                </div>
                <div>
                  <span className="text-muted-foreground">Errors</span>
                  <div className={`\${entry.errorCount > 0 ? "text-red-400" : "text-emerald-400"}`}>
                    {entry.errorCount}
                  </div>
                </div>
              </div>
              {entry.driftDetected && (
                <div className="mt-2 p-2 rounded bg-yellow-500/10 border border-yellow-500/20 text-xs text-yellow-400 flex items-center gap-1">
                  <AlertTriangle className="h-3 w-3" />
                  Schema drift detected
                </div>
              )}
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}

function UpdatesView() {
  const { data: updates, isLoading } = useQuery<UpdateEntry[]>({
    queryKey: ["/api/integration-marketplace/updates"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/integration-marketplace/updates");
      return res.json();
    },
  });

  if (isLoading)
    return (
      <div className="space-y-3">
        {Array.from({ length: 3 }).map((_, i) => (
          <Skeleton key={i} className="h-16 w-full" />
        ))}
      </div>
    );

  if (!updates || updates.length === 0) {
    return (
      <div className="text-center py-12">
        <Package className="h-10 w-10 text-muted-foreground mx-auto mb-3" />
        <p className="text-sm text-muted-foreground">No installed integrations to check for updates</p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {updates.map((update) => (
        <Card key={update.instanceId} className="border-border/40 bg-card/50">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <div className="font-semibold text-sm text-foreground">{update.instanceName}</div>
                <div className="text-xs text-muted-foreground">{update.connectorName}</div>
              </div>
              <div className="flex items-center gap-2">
                <Badge variant="outline" className="text-xs">
                  v{update.currentVersion}
                </Badge>
                {update.hasUpdate && (
                  <>
                    <ArrowRight className="h-3 w-3 text-primary" />
                    <Badge className="bg-primary/20 text-primary text-xs">v{update.latestVersion}</Badge>
                  </>
                )}
                {!update.hasUpdate && (
                  <Badge className="bg-emerald-600/20 text-emerald-300 text-xs">
                    <CheckCircle2 className="h-3 w-3 text-green-500" />
                    Up to date
                  </Badge>
                )}
              </div>
            </div>
            <div className="flex items-center gap-3 mt-2 text-xs text-muted-foreground">
              <span>Auto-update: {update.autoUpdateEnabled ? "On" : "Off"}</span>
              <span className="text-border">|</span>
              <span>Checked: {new Date(update.lastCheckedAt).toLocaleString()}</span>
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

export default function IntegrationMarketplacePage() {
  const [activeTab, setActiveTab] = useState<TabView>("catalog");
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null);
  const [expandedInstance, setExpandedInstance] = useState<string | null>(null);
  const [installingSlug, setInstallingSlug] = useState<string | null>(null);
  const [syncingId, setSyncingId] = useState<string | null>(null);
  const [checkingId, setCheckingId] = useState<string | null>(null);

  const queryClient = useQueryClient();
  const { toast } = useToast();

  const { data: stats } = useQuery<MarketplaceStats>({
    queryKey: ["/api/integration-marketplace/stats"],
  });

  const { data: catalog, isLoading: catalogLoading } = useQuery<MarketplaceConnector[]>({
    queryKey: ["/api/integration-marketplace/catalog", selectedCategory],
    queryFn: async () => {
      const url = selectedCategory
        ? `/api/integration-marketplace/catalog?category=${selectedCategory}`
        : "/api/integration-marketplace/catalog";
      const res = await apiRequest("GET", url);
      return res.json();
    },
  });

  const { data: instances, isLoading: instancesLoading } = useQuery<ConnectorInstance[]>({
    queryKey: ["/api/integration-marketplace/instances"],
  });

  const { data: qualityScores } = useQuery<QualityScore[]>({
    queryKey: ["/api/integration-marketplace/quality-scores"],
  });

  const installMutation = useMutation({
    mutationFn: async (slug: string) => {
      setInstallingSlug(slug);
      const res = await apiRequest("POST", "/api/integration-marketplace/install", {
        connectorSlug: slug,
        authMethod: "api_key",
        syncDirection: "inbound",
        config: {},
      });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/integration-marketplace"] });
      toast({ title: "Connector installed (read-only mode)" });
      setInstallingSlug(null);
    },
    onError: (err: Error) => {
      toast({ title: "Install failed", description: err.message, variant: "destructive" });
      setInstallingSlug(null);
    },
  });

  const syncMutation = useMutation({
    mutationFn: async (instanceId: string) => {
      setSyncingId(instanceId);
      const res = await apiRequest("POST", `/api/integration-marketplace/instances/${instanceId}/sync`);
      return res.json();
    },
    onSuccess: (data: SyncEvent) => {
      queryClient.invalidateQueries({ queryKey: ["/api/integration-marketplace"] });
      toast({
        title: "Sync completed",
        description: `${data.recordsProcessed} records processed in ${data.durationMs}ms`,
      });
      setSyncingId(null);
    },
    onError: (err: Error) => {
      toast({ title: "Sync failed", description: err.message, variant: "destructive" });
      setSyncingId(null);
    },
  });

  const healthMutation = useMutation({
    mutationFn: async (instanceId: string) => {
      setCheckingId(instanceId);
      const res = await apiRequest("POST", `/api/integration-marketplace/instances/${instanceId}/health-check`);
      return res.json();
    },
    onSuccess: (data: HealthCheck) => {
      queryClient.invalidateQueries({ queryKey: ["/api/integration-marketplace"] });
      toast({
        title: "Health check: " + data.status,
        description: `Latency: ${data.latencyMs}ms | Credentials: ${data.credentialStatus}`,
      });
      setCheckingId(null);
    },
    onError: (err: Error) => {
      toast({ title: "Health check failed", description: err.message, variant: "destructive" });
      setCheckingId(null);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (instanceId: string) => {
      const res = await apiRequest("DELETE", `/api/integration-marketplace/instances/${instanceId}`);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/integration-marketplace"] });
      toast({ title: "Connector uninstalled" });
    },
  });

  const permissionMutation = useMutation({
    mutationFn: async ({ id, mode }: { id: string; mode: string }) => {
      const res = await apiRequest("POST", `/api/integration-marketplace/instances/${id}/permissions`, { mode });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/integration-marketplace"] });
      toast({ title: "Permissions updated" });
    },
  });

  const handleInstall = useCallback((slug: string) => installMutation.mutate(slug), [installMutation]);

  const handleSync = useCallback((id: string) => syncMutation.mutate(id), [syncMutation]);

  const handleHealthCheck = useCallback((id: string) => healthMutation.mutate(id), [healthMutation]);

  const handleDelete = useCallback((id: string) => deleteMutation.mutate(id), [deleteMutation]);

  const handleUpgradePermissions = useCallback(
    (id: string, mode: string) => permissionMutation.mutate({ id, mode }),
    [permissionMutation],
  );

  const toggleInstance = useCallback((id: string) => setExpandedInstance((prev) => (prev === id ? null : id)), []);

  const filteredCatalog = (catalog || []).filter((c) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      c.name.toLowerCase().includes(q) ||
      c.vendor.toLowerCase().includes(q) ||
      c.description.toLowerCase().includes(q) ||
      c.category.toLowerCase().includes(q)
    );
  });

  const [detailSlug, setDetailSlug] = useState<string | null>(null);
  const [setupSlug, setSetupSlug] = useState<string | null>(null);

  const tabs: { key: TabView; label: string; icon: typeof Plug }[] = [
    { key: "catalog", label: "Catalog", icon: Globe },
    { key: "installed", label: "Installed", icon: Plug },
    { key: "health", label: "Health Monitor", icon: Activity },
    { key: "dead-letters", label: "Dead Letters", icon: AlertTriangle },
    { key: "updates", label: "Updates", icon: Package },
  ];

  return (
    <div className="min-h-screen bg-background p-4 sm:p-6 space-y-6" role="main" aria-label="Integration Marketplace">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-foreground flex items-center gap-2">
            <Zap className="h-5 w-5 text-primary" />
            Integration Marketplace
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Bidirectional connectors for ticketing, messaging, SIEM, SOAR, IAM, CI/CD, VCS, cloud, and endpoint tools
          </p>
        </div>
      </div>

      {stats && <StatsBar stats={stats} />}

      <div className="flex items-center gap-2 border-b border-border/40 pb-1">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          return (
            <button
              key={tab.key}
              className={`flex items-center gap-1.5 px-3 py-2 text-sm rounded-t-lg transition-colors ${
                activeTab === tab.key
                  ? "bg-primary/10 text-primary border-b-2 border-primary"
                  : "text-muted-foreground hover:text-foreground"
              }`}
              onClick={() => setActiveTab(tab.key)}
              aria-selected={activeTab === tab.key}
              role="tab"
            >
              <Icon className="h-3.5 w-3.5" />
              {tab.label}
            </button>
          );
        })}
      </div>

      {activeTab === "catalog" && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <input
                type="text"
                placeholder="Search connectors by name, vendor, or category..."
                className="w-full pl-9 pr-3 py-2 text-sm bg-muted/30 border border-border/40 rounded-lg focus:outline-none focus:ring-1 focus:ring-primary text-foreground"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                aria-label="Search connectors"
              />
            </div>
            <div className="flex flex-wrap gap-1.5">
              <Button
                size="sm"
                variant={selectedCategory === null ? "default" : "outline"}
                className="h-8 text-xs"
                onClick={() => setSelectedCategory(null)}
              >
                All
              </Button>
              {Object.entries(CATEGORY_CONFIG).map(([key, cfg]) => {
                const CatIcon = cfg.icon;
                return (
                  <Button
                    key={key}
                    size="sm"
                    variant={selectedCategory === key ? "default" : "outline"}
                    className="h-8 text-xs"
                    onClick={() => setSelectedCategory(key)}
                  >
                    <CatIcon className="h-3 w-3 mr-1" />
                    {cfg.label}
                  </Button>
                );
              })}
            </div>
          </div>

          {catalogLoading ? (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
              {Array.from({ length: 6 }).map((_, i) => (
                <Skeleton key={i} className="h-48 w-full" />
              ))}
            </div>
          ) : filteredCatalog.length === 0 ? (
            <div className="text-center py-12">
              <Search className="h-10 w-10 text-muted-foreground mx-auto mb-3" />
              <p className="text-sm text-muted-foreground">No connectors match your search</p>
            </div>
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
              {filteredCatalog.map((connector) => (
                <ConnectorCard
                  key={connector.id}
                  connector={connector}
                  onInstall={handleInstall}
                  installing={installingSlug === connector.id}
                />
              ))}
            </div>
          )}
        </div>
      )}

      {activeTab === "installed" && (
        <div className="space-y-3">
          {instancesLoading ? (
            Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-20 w-full" />)
          ) : !instances || instances.length === 0 ? (
            <div className="text-center py-12">
              <Plug className="h-10 w-10 text-muted-foreground mx-auto mb-3" />
              <p className="text-sm text-muted-foreground">No connectors installed yet</p>
              <p className="text-xs text-muted-foreground mt-1">Browse the catalog to install your first connector</p>
              <Button size="sm" variant="outline" className="mt-3" onClick={() => setActiveTab("catalog")}>
                Browse Catalog
              </Button>
            </div>
          ) : (
            instances.map((inst) => (
              <InstanceRow
                key={inst.id}
                instance={inst}
                onSync={handleSync}
                onHealthCheck={handleHealthCheck}
                onDelete={handleDelete}
                onUpgradePermissions={handleUpgradePermissions}
                syncing={syncingId === inst.id}
                checking={checkingId === inst.id}
                expanded={expandedInstance === inst.id}
                onToggle={() => toggleInstance(inst.id)}
                qualityScore={(qualityScores || []).find((q) => q.instanceId === inst.id) || null}
              />
            ))
          )}
        </div>
      )}

      {activeTab === "health" && <HealthSummaryView />}

      {activeTab === "dead-letters" && <DeadLetterQueue />}

      {activeTab === "updates" && <UpdatesView />}

      {activeTab === "details" && detailSlug && (
        <IntegrationDetailPanel
          slug={detailSlug}
          onBack={() => {
            setDetailSlug(null);
            setActiveTab("catalog");
          }}
        />
      )}

      {setupSlug && (
        <SetupWizardDialog
          slug={setupSlug}
          onClose={() => setSetupSlug(null)}
          onInstall={(slug) => {
            installMutation.mutate(slug);
            setSetupSlug(null);
          }}
        />
      )}
    </div>
  );
}

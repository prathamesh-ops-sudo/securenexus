import { useState, useCallback } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  AlertTriangle,
  Ban,
  ArrowDownToLine,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Cloud,
  Copy,
  Download,
  HardDrive,
  Key,
  Loader2,
  Monitor,
  Network,
  Plus,
  RefreshCw,
  ScanSearch,
  Search,
  Server,
  Shield,
  Terminal,
  Trash2,
  Upload,
  Wifi,
  WifiOff,
  X,
  Zap,
  Map,
  FileCode,
  Lock,
  RotateCcw,
  BarChart3,
  Eye,
  Layers,
  GitBranch,
  CheckSquare,
  ArrowRight,
  Play,
} from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";

interface CollectorTemplate {
  slug: string;
  name: string;
  type: string;
  description: string;
  icon: string;
  platforms: string[];
  deploymentMethods: string[];
  dataTypes: string[];
  estimatedSetupMinutes: number;
  requiresAgent: boolean;
  configSchema: ConfigField[];
}

interface ConfigField {
  key: string;
  label: string;
  type: "string" | "number" | "boolean" | "select" | "secret";
  required: boolean;
  defaultValue?: string | number | boolean;
  options?: string[];
  placeholder?: string;
}

interface CollectorInstance {
  id: string;
  templateSlug: string;
  orgId: string;
  name: string;
  status: string;
  platform: string;
  deploymentMethod: string;
  config: Record<string, unknown>;
  hostInfo: {
    hostname: string;
    ipAddress: string;
    os: string;
    arch: string;
    cpuCount: number;
    memoryGb: number;
    agentVersion: string;
  } | null;
  metrics: {
    eventsPerSecond: number;
    bytesIngested: number;
    errorsLast24h: number;
    latencyP50Ms: number;
    latencyP99Ms: number;
    lastEventCount: number;
    totalEventsIngested: number;
  };
  installedAt: string;
  lastHeartbeatAt: string | null;
  lastDataAt: string | null;
  lifecycleState: string;
  version: string;
  tags: string[];
}

interface IngestedEvent {
  id: string;
  collectorId: string;
  eventType: string;
  severity: string;
  source: string;
  timestamp: string;
  rawData: Record<string, unknown>;
  parsedFields: Record<string, unknown>;
  tags: string[];
  processed: boolean;
}

interface PipelineStats {
  totalCollectors: number;
  activeCollectors: number;
  degradedCollectors: number;
  offlineCollectors: number;
  eventsPerSecond: number;
  totalEventsToday: number;
  totalBytesToday: number;
  storageUsedGb: number;
  storageQuotaGb: number;
  retentionDays: number;
  topEventTypes: Array<{ type: string; count: number; percentage: number }>;
  collectorsByType: Record<string, number>;
}

interface CollectorHealth {
  collectorId: string;
  name: string;
  status: string;
  lifecycleState: string;
  eventsPerSecond: number;
  lastReceivedEvent: string | null;
  lastHeartbeat: string | null;
  heartbeatStale: boolean;
  dataStale: boolean;
  parsingErrors: number;
  dataVolumeBytes: number;
  latencyP50Ms: number;
  latencyP99Ms: number;
  alerts: Array<{ level: string; message: string; timestamp: string }>;
}

interface CoverageEntry {
  templateSlug: string;
  templateName: string;
  type: string;
  platforms: string[];
  dataTypes: string[];
  deployed: number;
  active: number;
  covered: boolean;
}

interface CoverageMap {
  coverage: CoverageEntry[];
  gaps: CoverageEntry[];
  totalTemplates: number;
  coveredTemplates: number;
  coveragePercent: number;
}

interface ParserInfo {
  id: string;
  name: string;
  patternType: string;
  builtIn: boolean;
  fieldCount: number;
}

interface CertificateInfo {
  id: string;
  collectorId: string;
  subject: string;
  issuer: string;
  serialNumber: string;
  notBefore: string;
  notAfter: string;
  daysUntilExpiry: number;
  status: string;
  autoRenew: boolean;
  fingerprint: string;
  keyType: string;
}

interface DeployWizardData {
  templateSlug: string;
  templateName: string;
  requiresAgent: boolean;
  estimatedMinutes: number;
  steps: Array<{
    step: number;
    title: string;
    description: string;
    status: string;
    fields: Array<{ key: string; type: string; options?: string[]; label: string; required: boolean }>;
    instructions?: string[];
  }>;
}

const TYPE_CONFIG: Record<string, { label: string; icon: typeof Monitor; color: string }> = {
  agent_endpoint: { label: "Endpoint Agent", icon: Monitor, color: "text-blue-400" },
  agent_network: { label: "Network Monitor", icon: Network, color: "text-purple-400" },
  agent_cloud: { label: "Cloud Agent", icon: Cloud, color: "text-sky-400" },
  agentless_cloud: { label: "Cloud (Agentless)", icon: Cloud, color: "text-cyan-400" },
  syslog_receiver: { label: "Syslog Receiver", icon: ArrowDownToLine, color: "text-green-400" },
  log_file_upload: { label: "Log Upload", icon: Upload, color: "text-orange-400" },
  api_push: { label: "API Push", icon: Zap, color: "text-yellow-400" },
  vulnerability_scanner: { label: "Vuln Scanner", icon: Shield, color: "text-red-400" },
  asset_discovery: { label: "Asset Discovery", icon: ScanSearch, color: "text-pink-400" },
};

const STATUS_CONFIG: Record<string, { label: string; color: string; icon: typeof CheckCircle2 }> = {
  active: { label: "Active", color: "bg-emerald-600/20 text-emerald-300", icon: CheckCircle2 },
  "online-but-zero-telemetry": {
    label: "Online — No Telemetry",
    color: "bg-yellow-600/20 text-yellow-300",
    icon: AlertTriangle,
  },
  "receiving-telemetry": {
    label: "Receiving Telemetry",
    color: "bg-emerald-600/20 text-emerald-300",
    icon: CheckCircle2,
  },
  "enrolled-but-never-heartbeated": {
    label: "Enrolled — Awaiting Heartbeat",
    color: "bg-blue-600/20 text-blue-300",
    icon: Download,
  },
  "never-enrolled": { label: "Never Enrolled", color: "bg-slate-600/20 text-slate-400", icon: Download },
  revoked: { label: "Revoked", color: "bg-red-600/20 text-red-300", icon: Ban },
  degraded: { label: "Degraded", color: "bg-yellow-600/20 text-yellow-300", icon: AlertTriangle },
  offline: { label: "Offline", color: "bg-red-600/20 text-red-300", icon: WifiOff },
  pending_install: { label: "Pending Install", color: "bg-blue-600/20 text-blue-300", icon: Download },
  disabled: { label: "Disabled", color: "bg-slate-600/20 text-slate-400", icon: WifiOff },
  unknown: { label: "Unknown", color: "bg-slate-600/20 text-slate-400", icon: AlertTriangle },
};

const PLATFORM_LABELS: Record<string, string> = {
  linux: "Linux",
  windows: "Windows",
  macos: "macOS",
  docker: "Docker",
  kubernetes: "Kubernetes",
  aws: "AWS",
  azure: "Azure",
  gcp: "GCP",
  any: "Any",
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-600/20 text-red-300",
  high: "bg-orange-600/20 text-orange-300",
  medium: "bg-yellow-600/20 text-yellow-300",
  low: "bg-blue-600/20 text-blue-300",
  info: "bg-slate-600/20 text-slate-300",
};

type TabView = "catalog" | "deployed" | "events" | "pipeline" | "health" | "coverage" | "parsers" | "certs";

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${units[i]}`;
}

function PipelineOverview({ stats }: { stats: PipelineStats }) {
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <Card className="border-border/40 bg-card/50">
          <CardContent className="p-3 text-center">
            <div className="text-2xl font-bold text-foreground">{stats.totalCollectors}</div>
            <div className="text-xs text-muted-foreground">Total Collectors</div>
          </CardContent>
        </Card>
        <Card className="border-border/40 bg-card/50">
          <CardContent className="p-3 text-center">
            <div className="text-2xl font-bold text-emerald-400">{stats.activeCollectors}</div>
            <div className="text-xs text-muted-foreground">Active</div>
          </CardContent>
        </Card>
        <Card className="border-border/40 bg-card/50">
          <CardContent className="p-3 text-center">
            <div className="text-2xl font-bold text-yellow-400">{stats.degradedCollectors}</div>
            <div className="text-xs text-muted-foreground">Degraded</div>
          </CardContent>
        </Card>
        <Card className="border-border/40 bg-card/50">
          <CardContent className="p-3 text-center">
            <div className="text-2xl font-bold text-cyan-400">{stats.eventsPerSecond}</div>
            <div className="text-xs text-muted-foreground">Events/sec</div>
          </CardContent>
        </Card>
        <Card className="border-border/40 bg-card/50">
          <CardContent className="p-3 text-center">
            <div className="text-2xl font-bold text-foreground">{stats.totalEventsToday.toLocaleString()}</div>
            <div className="text-xs text-muted-foreground">Events Today</div>
          </CardContent>
        </Card>
        <Card className="border-border/40 bg-card/50">
          <CardContent className="p-3 text-center">
            <div className="text-2xl font-bold text-foreground">{stats.activeCollectors}</div>
            <div className="text-xs text-muted-foreground">Reporting Collectors</div>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card className="border-border/40 bg-card/50">
          <CardContent className="p-4">
            <h3 className="text-sm font-semibold mb-3 text-foreground">Storage & Retention</h3>
            <div className="space-y-3">
              <div className="flex justify-between text-sm">
                <span className="text-muted-foreground">Storage Used</span>
                <span className="text-foreground font-medium">
                  {stats.storageUsedGb} / {stats.storageQuotaGb} GB
                </span>
              </div>
              <div className="w-full bg-muted/50 rounded-full h-2">
                <div
                  className="bg-gradient-to-r from-cyan-500 to-blue-500 h-2 rounded-full transition-all"
                  style={{ width: `${Math.min((stats.storageUsedGb / stats.storageQuotaGb) * 100, 100)}%` }}
                />
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-muted-foreground">Data Ingested Today</span>
                <span className="text-foreground font-medium">{formatBytes(stats.totalBytesToday)}</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-muted-foreground">Retention Period</span>
                <span className="text-foreground font-medium">{stats.retentionDays} days</span>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="border-border/40 bg-card/50">
          <CardContent className="p-4">
            <h3 className="text-sm font-semibold mb-3 text-foreground">Collectors by Type</h3>
            {Object.entries(stats.collectorsByType).filter(([, count]) => count > 0).length === 0 ? (
              <div className="flex flex-col items-center justify-center py-6 text-muted-foreground">
                <Server className="h-8 w-8 mb-2 opacity-40" />
                <p className="text-sm">No collectors deployed yet</p>
                <p className="text-xs mt-1">Deploy your first collector from the catalog</p>
              </div>
            ) : (
              <div className="space-y-2">
                {Object.entries(stats.collectorsByType)
                  .filter(([, count]) => count > 0)
                  .sort(([, a], [, b]) => b - a)
                  .map(([type, count]) => {
                    const cfg = TYPE_CONFIG[type];
                    const Icon = cfg?.icon || Server;
                    return (
                      <div key={type} className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <Icon className={`h-4 w-4 ${cfg?.color || "text-muted-foreground"}`} />
                          <span className="text-sm text-foreground">{cfg?.label || type}</span>
                        </div>
                        <Badge variant="outline" className="text-xs">
                          {count}
                        </Badge>
                      </div>
                    );
                  })}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {stats.topEventTypes.length > 0 && (
        <Card className="border-border/40 bg-card/50">
          <CardContent className="p-4">
            <h3 className="text-sm font-semibold mb-3 text-foreground">Top Event Types</h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-2">
              {stats.topEventTypes.slice(0, 10).map((et) => (
                <div key={et.type} className="flex items-center justify-between p-2 rounded-lg bg-muted/30">
                  <span className="text-xs text-foreground truncate mr-2">{et.type.replace(/_/g, " ")}</span>
                  <Badge variant="outline" className="text-[10px] shrink-0">
                    {et.count} ({et.percentage}%)
                  </Badge>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function DeployDialog({
  template,
  onDeploy,
  onClose,
  deploying,
}: {
  template: CollectorTemplate;
  onDeploy: (data: {
    templateSlug: string;
    name: string;
    platform: string;
    deploymentMethod: string;
    config: Record<string, unknown>;
    tags: string[];
  }) => void;
  onClose: () => void;
  deploying: boolean;
}) {
  const [name, setName] = useState(`${template.name} — Instance 1`);
  const [platform, setPlatform] = useState(template.platforms[0]);
  const [method, setMethod] = useState(template.deploymentMethods[0]);
  const [config, setConfig] = useState<Record<string, unknown>>(() => {
    const defaults: Record<string, unknown> = {};
    for (const f of template.configSchema) {
      if (f.defaultValue !== undefined) defaults[f.key] = f.defaultValue;
    }
    return defaults;
  });
  const [tags, setTags] = useState("");
  const [errors, setErrors] = useState<Record<string, string>>({});

  const validate = (): boolean => {
    const e: Record<string, string> = {};
    if (!name.trim()) e.name = "Name is required";
    for (const f of template.configSchema) {
      if (f.required && (config[f.key] === undefined || config[f.key] === "")) {
        e[f.key] = `${f.label} is required`;
      }
    }
    setErrors(e);
    return Object.keys(e).length === 0;
  };

  const handleSubmit = () => {
    if (!validate()) return;
    onDeploy({
      templateSlug: template.slug,
      name: name.trim(),
      platform,
      deploymentMethod: method,
      config,
      tags: tags
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean),
    });
  };

  const typeConfig = TYPE_CONFIG[template.type];
  const TypeIcon = typeConfig?.icon || Server;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
      <div className="bg-card border border-border/60 rounded-xl shadow-2xl w-full max-w-lg mx-4 max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between p-4 border-b border-border/40">
          <div className="flex items-center gap-3">
            <div className={`p-2 rounded-lg bg-muted/50 ${typeConfig?.color || "text-muted-foreground"}`}>
              <TypeIcon className="h-5 w-5" />
            </div>
            <div>
              <h2 className="text-sm font-semibold text-foreground">Deploy {template.name}</h2>
              <p className="text-xs text-muted-foreground">~{template.estimatedSetupMinutes} min setup</p>
            </div>
          </div>
          <Button variant="ghost" size="sm" onClick={onClose} aria-label="Close deploy dialog">
            <X className="h-4 w-4" />
          </Button>
        </div>

        <div className="p-4 space-y-4">
          <div>
            <label className="text-xs font-medium text-muted-foreground mb-1 block">Instance Name</label>
            <input
              className="w-full px-3 py-2 rounded-md border border-border/60 bg-background text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-primary/50"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="My Collector"
            />
            {errors.name && <p className="text-xs text-red-400 mt-1">{errors.name}</p>}
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs font-medium text-muted-foreground mb-1 block">Platform</label>
              <select
                className="w-full px-3 py-2 rounded-md border border-border/60 bg-background text-sm text-foreground"
                value={platform}
                onChange={(e) => setPlatform(e.target.value)}
              >
                {template.platforms.map((p) => (
                  <option key={p} value={p}>
                    {PLATFORM_LABELS[p] || p}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="text-xs font-medium text-muted-foreground mb-1 block">Deployment Method</label>
              <select
                className="w-full px-3 py-2 rounded-md border border-border/60 bg-background text-sm text-foreground"
                value={method}
                onChange={(e) => setMethod(e.target.value)}
              >
                {template.deploymentMethods.map((m) => (
                  <option key={m} value={m}>
                    {m.replace(/_/g, " ")}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {template.configSchema.length > 0 && (
            <div className="space-y-3">
              <h3 className="text-xs font-medium text-muted-foreground">Configuration</h3>
              {template.configSchema.map((field) => (
                <div key={field.key}>
                  <label className="text-xs text-muted-foreground mb-1 block">
                    {field.label}
                    {field.required && <span className="text-red-400 ml-0.5">*</span>}
                  </label>
                  {field.type === "boolean" ? (
                    <label className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={!!config[field.key]}
                        onChange={(e) => setConfig({ ...config, [field.key]: e.target.checked })}
                        className="rounded border-border"
                      />
                      <span className="text-sm text-foreground">Enabled</span>
                    </label>
                  ) : field.type === "select" ? (
                    <select
                      className="w-full px-3 py-2 rounded-md border border-border/60 bg-background text-sm text-foreground"
                      value={String(config[field.key] ?? field.defaultValue ?? "")}
                      onChange={(e) => setConfig({ ...config, [field.key]: e.target.value })}
                    >
                      {field.options?.map((o) => (
                        <option key={o} value={o}>
                          {o}
                        </option>
                      ))}
                    </select>
                  ) : field.type === "number" ? (
                    <input
                      type="number"
                      className="w-full px-3 py-2 rounded-md border border-border/60 bg-background text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-primary/50"
                      value={String(config[field.key] ?? field.defaultValue ?? "")}
                      onChange={(e) => setConfig({ ...config, [field.key]: parseFloat(e.target.value) || 0 })}
                      placeholder={field.placeholder}
                    />
                  ) : (
                    <input
                      type={field.type === "secret" ? "password" : "text"}
                      className="w-full px-3 py-2 rounded-md border border-border/60 bg-background text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-primary/50"
                      value={String(config[field.key] ?? "")}
                      onChange={(e) => setConfig({ ...config, [field.key]: e.target.value })}
                      placeholder={field.placeholder}
                    />
                  )}
                  {errors[field.key] && <p className="text-xs text-red-400 mt-1">{errors[field.key]}</p>}
                </div>
              ))}
            </div>
          )}

          <div>
            <label className="text-xs font-medium text-muted-foreground mb-1 block">Tags (comma-separated)</label>
            <input
              className="w-full px-3 py-2 rounded-md border border-border/60 bg-background text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-primary/50"
              value={tags}
              onChange={(e) => setTags(e.target.value)}
              placeholder="production, us-east-1, web-tier"
            />
          </div>
        </div>

        <div className="flex items-center justify-end gap-2 p-4 border-t border-border/40">
          <Button variant="outline" size="sm" onClick={onClose}>
            Cancel
          </Button>
          <Button size="sm" onClick={handleSubmit} disabled={deploying}>
            {deploying ? <Loader2 className="h-3 w-3 animate-spin mr-1" /> : <Plus className="h-3 w-3 mr-1" />}
            Deploy Collector
          </Button>
        </div>
      </div>
    </div>
  );
}

function TemplateCard({
  template,
  onDeploy,
}: {
  template: CollectorTemplate;
  onDeploy: (t: CollectorTemplate) => void;
}) {
  const typeConfig = TYPE_CONFIG[template.type];
  const TypeIcon = typeConfig?.icon || Server;

  return (
    <Card className="border-border/40 bg-card/50 hover:border-primary/30 transition-colors group">
      <CardContent className="p-4">
        <div className="flex items-start justify-between mb-3">
          <div className="flex items-center gap-3">
            <div
              className={`p-2.5 rounded-lg bg-muted/50 ${typeConfig?.color || "text-muted-foreground"} group-hover:scale-105 transition-transform`}
            >
              <TypeIcon className="h-5 w-5" />
            </div>
            <div>
              <h3 className="font-semibold text-sm text-foreground">{template.name}</h3>
              <p className="text-xs text-muted-foreground">{typeConfig?.label || template.type}</p>
            </div>
          </div>
          {template.requiresAgent ? (
            <Badge className="bg-blue-600/20 text-blue-300 text-[10px]">Agent</Badge>
          ) : (
            <Badge className="bg-emerald-600/20 text-emerald-300 text-[10px]">Agentless</Badge>
          )}
        </div>

        <p className="text-xs text-muted-foreground mb-3 line-clamp-2">{template.description}</p>

        <div className="flex flex-wrap gap-1 mb-3">
          {template.dataTypes.slice(0, 4).map((dt) => (
            <Badge key={dt} variant="outline" className="text-[10px] px-1.5 py-0">
              {dt.replace(/_/g, " ")}
            </Badge>
          ))}
          {template.dataTypes.length > 4 && (
            <Badge variant="outline" className="text-[10px] px-1.5 py-0">
              +{template.dataTypes.length - 4}
            </Badge>
          )}
        </div>

        <div className="flex items-center justify-between">
          <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
            {template.platforms.slice(0, 3).map((p) => (
              <Badge key={p} variant="outline" className="text-[10px] px-1 py-0">
                {PLATFORM_LABELS[p] || p}
              </Badge>
            ))}
            <span className="text-border">|</span>
            <span>~{template.estimatedSetupMinutes}m setup</span>
          </div>
          <Button
            size="sm"
            variant="outline"
            className="h-7 text-xs hover:bg-primary/10 hover:border-primary/40 transition-colors"
            onClick={() => onDeploy(template)}
            aria-label={`Deploy ${template.name}`}
          >
            <Plus className="h-3 w-3 mr-1" />
            Deploy
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

function InstanceRow({
  instance,
  templateSlug,
  onDelete,
  onViewScript,
  onGenerateKey,
  onRevoke,
  expanded,
  onToggle,
  deleting,
}: {
  instance: CollectorInstance;
  templateSlug: string;
  onDelete: (id: string) => void;
  onViewScript: (id: string) => void;
  onGenerateKey: (id: string) => void;
  onRevoke: (id: string) => void;
  expanded: boolean;
  onToggle: () => void;
  deleting: boolean;
}) {
  const statusConfig = STATUS_CONFIG[instance.lifecycleState] || STATUS_CONFIG.unknown;
  const StatusIcon = statusConfig.icon;
  const typeConfig =
    TYPE_CONFIG[
      Object.keys(TYPE_CONFIG).find((k) =>
        instance.templateSlug.includes(k.replace("agent_", "").replace("agentless_", "")),
      ) || ""
    ];

  return (
    <Card className="border-border/40 bg-card/50">
      <CardContent className="p-0">
        <button
          className="w-full flex items-center justify-between p-4 text-left hover:bg-muted/20 transition-colors"
          onClick={onToggle}
          aria-expanded={expanded}
          aria-label={`Toggle details for ${instance.name}`}
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
                {PLATFORM_LABELS[instance.platform] || instance.platform} |{" "}
                {instance.deploymentMethod.replace(/_/g, " ")} | v{instance.version}
              </div>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Badge className={statusConfig.color + " text-xs"}>
              <StatusIcon className="h-3 w-3 mr-1" />
              {statusConfig.label}
            </Badge>
            {instance.tags.slice(0, 2).map((tag) => (
              <Badge key={tag} variant="outline" className="text-[10px] px-1.5 py-0 hidden sm:inline-flex">
                {tag}
              </Badge>
            ))}
          </div>
        </button>

        {expanded && (
          <div className="border-t border-border/40 p-4 space-y-4">
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div>
                <div className="text-xs text-muted-foreground mb-1">Events/sec</div>
                <div className="text-sm font-medium text-foreground">{instance.metrics.eventsPerSecond}</div>
              </div>
              <div>
                <div className="text-xs text-muted-foreground mb-1">Total Ingested</div>
                <div className="text-sm font-medium text-foreground">
                  {instance.metrics.totalEventsIngested.toLocaleString()}
                </div>
              </div>
              <div>
                <div className="text-xs text-muted-foreground mb-1">Data Volume</div>
                <div className="text-sm font-medium text-foreground">{formatBytes(instance.metrics.bytesIngested)}</div>
              </div>
              <div>
                <div className="text-xs text-muted-foreground mb-1">Errors (24h)</div>
                <div
                  className={`text-sm font-medium ${instance.metrics.errorsLast24h > 0 ? "text-red-400" : "text-emerald-400"}`}
                >
                  {instance.metrics.errorsLast24h}
                </div>
              </div>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div>
                <div className="text-xs text-muted-foreground mb-1">Lifecycle</div>
                <div className="text-sm font-medium text-foreground">{instance.lifecycleState}</div>
              </div>
              <div>
                <div className="text-xs text-muted-foreground mb-1">Latency (P50)</div>
                <div className="text-sm font-medium text-foreground">{instance.metrics.latencyP50Ms}ms</div>
              </div>
              <div>
                <div className="text-xs text-muted-foreground mb-1">Last Heartbeat</div>
                <div className="text-sm text-foreground">
                  {instance.lastHeartbeatAt ? new Date(instance.lastHeartbeatAt).toLocaleString() : "Never"}
                </div>
              </div>
              <div>
                <div className="text-xs text-muted-foreground mb-1">Last Data</div>
                <div className="text-sm text-foreground">
                  {instance.lastDataAt ? new Date(instance.lastDataAt).toLocaleString() : "Never"}
                </div>
              </div>
            </div>
            <div className="flex gap-2">
              <Button variant="outline" size="sm" onClick={() => onGenerateKey(instance.id)}>
                <RotateCcw className="h-3 w-3 mr-1" /> Rotate Key
              </Button>
              <Button variant="outline" size="sm" onClick={() => onRevoke(instance.id)}>
                <Ban className="h-3 w-3 mr-1" /> Revoke
              </Button>
            </div>

            {instance.hostInfo && (
              <div className="rounded-lg border border-border/40 p-3">
                <div className="text-xs font-medium text-muted-foreground mb-2">Host Information</div>
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-xs">
                  <div>
                    <span className="text-muted-foreground">Hostname:</span>{" "}
                    <span className="text-foreground">{instance.hostInfo.hostname}</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">IP:</span>{" "}
                    <span className="text-foreground">{instance.hostInfo.ipAddress}</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">OS:</span>{" "}
                    <span className="text-foreground">{instance.hostInfo.os}</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">CPU:</span>{" "}
                    <span className="text-foreground">{instance.hostInfo.cpuCount} cores</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Memory:</span>{" "}
                    <span className="text-foreground">{instance.hostInfo.memoryGb} GB</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Agent:</span>{" "}
                    <span className="text-foreground">v{instance.hostInfo.agentVersion}</span>
                  </div>
                </div>
              </div>
            )}

            <div className="flex flex-wrap gap-2">
              <Button
                size="sm"
                variant="outline"
                className="h-7 text-xs"
                onClick={() => onViewScript(instance.id)}
                aria-label={`View deploy script for ${instance.name}`}
              >
                <Terminal className="h-3 w-3 mr-1" />
                Deploy Script
              </Button>
              <Button
                size="sm"
                variant="outline"
                className="h-7 text-xs"
                onClick={() => onGenerateKey(instance.id)}
                aria-label={`Generate API key for ${instance.name}`}
              >
                <Key className="h-3 w-3 mr-1" />
                API Key
              </Button>
              <Button
                size="sm"
                variant="outline"
                className="h-7 text-xs text-red-400 hover:text-red-300 hover:border-red-400/40"
                onClick={() => onDelete(instance.id)}
                disabled={deleting}
                aria-label={`Delete ${instance.name}`}
              >
                {deleting ? <Loader2 className="h-3 w-3 animate-spin mr-1" /> : <Trash2 className="h-3 w-3 mr-1" />}
                Remove
              </Button>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function EventsView() {
  const { data: events, isLoading } = useQuery<IngestedEvent[]>({
    queryKey: ["/api/native-collectors/events"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/native-collectors/events?limit=100");
      return res.json();
    },
  });

  if (isLoading) {
    return (
      <div className="space-y-2">
        {Array.from({ length: 5 }).map((_, i) => (
          <Skeleton key={i} className="h-16 w-full" />
        ))}
      </div>
    );
  }

  if (!events || events.length === 0) {
    return (
      <Card className="border-border/40 bg-card/50">
        <CardContent className="p-8 text-center">
          <Activity className="h-10 w-10 mx-auto mb-3 text-muted-foreground/40" />
          <p className="text-sm text-muted-foreground">No events ingested yet</p>
          <p className="text-xs text-muted-foreground mt-1">Deploy a collector and start sending data</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-2">
      <div className="text-xs text-muted-foreground mb-2">{events.length} recent events</div>
      {events.map((event) => (
        <Card key={event.id} className="border-border/40 bg-card/50">
          <CardContent className="p-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Badge className={(SEVERITY_COLORS[event.severity] || SEVERITY_COLORS.info) + " text-[10px]"}>
                  {event.severity}
                </Badge>
                <span className="text-sm font-medium text-foreground">{event.eventType.replace(/_/g, " ")}</span>
              </div>
              <span className="text-xs text-muted-foreground">{new Date(event.timestamp).toLocaleString()}</span>
            </div>
            <div className="mt-1 flex items-center gap-2 text-xs text-muted-foreground">
              <span>Source: {event.source}</span>
              {event.tags.length > 0 && (
                <>
                  <span className="text-border">|</span>
                  {event.tags.map((t) => (
                    <Badge key={t} variant="outline" className="text-[10px] px-1 py-0">
                      {t}
                    </Badge>
                  ))}
                </>
              )}
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

function ScriptDialog({
  script,
  templateSlug,
  onClose,
}: {
  script: string;
  templateSlug: string;
  onClose: () => void;
}) {
  const { toast } = useToast();

  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText(script).then(() => {
      toast({ title: "Copied to clipboard" });
    });
  }, [script, toast]);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
      <div className="bg-card border border-border/60 rounded-xl shadow-2xl w-full max-w-2xl mx-4 max-h-[80vh] overflow-y-auto">
        <div className="flex items-center justify-between p-4 border-b border-border/40">
          <div className="flex items-center gap-2">
            <Terminal className="h-4 w-4 text-cyan-400" />
            <h2 className="text-sm font-semibold text-foreground">Deployment Script</h2>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={handleCopy} className="h-7 text-xs">
              <Copy className="h-3 w-3 mr-1" />
              Copy
            </Button>
            <Button variant="ghost" size="sm" onClick={onClose} aria-label="Close script dialog">
              <X className="h-4 w-4" />
            </Button>
          </div>
        </div>
        <div className="p-4">
          <pre className="bg-muted/30 rounded-lg p-4 text-xs text-foreground font-mono whitespace-pre-wrap overflow-x-auto">
            {script}
          </pre>
        </div>
      </div>
    </div>
  );
}

function CollectorHealthView() {
  const { data: instances } = useQuery<CollectorInstance[]>({
    queryKey: ["/api/native-collectors/instances"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/native-collectors/instances");
      return res.json();
    },
  });

  const healthQueries = (instances || []).map((inst) => ({
    queryKey: ["/api/native-collectors/instances", inst.id, "health"],
    queryFn: async () => {
      const res = await apiRequest("GET", `/api/native-collectors/instances/\${inst.id}/health`);
      return res.json() as Promise<CollectorHealth>;
    },
    enabled: true,
  }));

  // Use individual queries instead of batch
  const { data: healthList } = useQuery<CollectorHealth[]>({
    queryKey: ["/api/native-collectors/health-all", instances?.length],
    queryFn: async () => {
      if (!instances || instances.length === 0) return [];
      const results: CollectorHealth[] = [];
      for (const inst of instances) {
        try {
          const res = await apiRequest("GET", `/api/native-collectors/instances/\${inst.id}/health`);
          results.push(await res.json());
        } catch {
          // skip failed health checks
        }
      }
      return results;
    },
    enabled: (instances?.length ?? 0) > 0,
  });

  if (!instances || instances.length === 0) {
    return (
      <div className="text-center py-12">
        <Activity className="h-10 w-10 text-muted-foreground mx-auto mb-3" />
        <p className="text-sm text-muted-foreground">No collectors deployed to monitor</p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {(healthList || []).map((health) => (
        <Card key={health.collectorId} className="border-border/40 bg-card/50">
          <CardContent className="p-4">
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2">
                <div
                  className={`h-2.5 w-2.5 rounded-full \${health.lifecycleState === "receiving-telemetry" ? "bg-emerald-400" : health.lifecycleState === "degraded" ? "bg-yellow-400" : "bg-red-400"}`}
                />
                <span className="font-semibold text-sm text-foreground">{health.name}</span>
              </div>
              <div className="flex items-center gap-2">
                <Badge
                  className={`text-xs \${health.lifecycleState === "receiving-telemetry" ? "bg-emerald-600/20 text-emerald-300" : health.lifecycleState === "degraded" ? "bg-yellow-600/20 text-yellow-300" : "bg-red-600/20 text-red-300"}`}
                >
                  {health.lifecycleState}
                </Badge>
                <span className="text-xs text-muted-foreground">{health.eventsPerSecond} evt/s</span>
              </div>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs mb-2">
              <div>
                <span className="text-muted-foreground">Last Event</span>
                <div className="text-foreground">
                  {health.lastReceivedEvent ? new Date(health.lastReceivedEvent).toLocaleString() : "Never"}
                </div>
              </div>
              <div>
                <span className="text-muted-foreground">Parsing Errors</span>
                <div className={`\${health.parsingErrors > 0 ? "text-red-400" : "text-emerald-400"}`}>
                  {health.parsingErrors}
                </div>
              </div>
              <div>
                <span className="text-muted-foreground">Volume</span>
                <div className="text-foreground">{formatBytes(health.dataVolumeBytes)}</div>
              </div>
              <div>
                <span className="text-muted-foreground">Lifecycle</span>
                <div className="text-foreground">{health.lifecycleState}</div>
              </div>
            </div>
            {health.alerts.length > 0 && (
              <div className="space-y-1 mt-2">
                {health.alerts.map((alert, i) => (
                  <div
                    key={i}
                    className={`p-2 rounded text-xs flex items-center gap-1 \${alert.level === "critical" ? "bg-red-500/10 border border-red-500/20 text-red-400" : "bg-yellow-500/10 border border-yellow-500/20 text-yellow-400"}`}
                  >
                    <AlertTriangle className="h-3 w-3" />
                    {alert.message}
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

function CoverageMapView() {
  const { data: coverageData, isLoading } = useQuery<CoverageMap>({
    queryKey: ["/api/native-collectors/coverage-map"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/native-collectors/coverage-map");
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

  if (!coverageData) return null;

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-3 gap-3">
        <Card className="border-border/40 bg-card/50">
          <CardContent className="p-3 text-center">
            <div className="text-2xl font-bold text-foreground">{coverageData.coveragePercent}%</div>
            <div className="text-xs text-muted-foreground">Coverage</div>
          </CardContent>
        </Card>
        <Card className="border-border/40 bg-card/50">
          <CardContent className="p-3 text-center">
            <div className="text-2xl font-bold text-emerald-400">{coverageData.coveredTemplates}</div>
            <div className="text-xs text-muted-foreground">Covered</div>
          </CardContent>
        </Card>
        <Card className="border-border/40 bg-card/50">
          <CardContent className="p-3 text-center">
            <div className="text-2xl font-bold text-red-400">{coverageData.gaps.length}</div>
            <div className="text-xs text-muted-foreground">Gaps</div>
          </CardContent>
        </Card>
      </div>

      {coverageData.gaps.length > 0 && (
        <Card className="border-border/40 bg-card/50">
          <CardContent className="p-4">
            <h3 className="text-sm font-semibold text-foreground mb-3 flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-yellow-400" />
              Coverage Gaps
            </h3>
            <div className="space-y-2">
              {coverageData.gaps.map((gap) => {
                const cfg = TYPE_CONFIG[gap.type];
                const Icon = cfg?.icon || Server;
                return (
                  <div key={gap.templateSlug} className="flex items-center justify-between p-2 rounded-lg bg-muted/30">
                    <div className="flex items-center gap-2">
                      <Icon className={`h-4 w-4 \${cfg?.color || "text-muted-foreground"}`} />
                      <span className="text-sm text-foreground">{gap.templateName}</span>
                    </div>
                    <Badge variant="outline" className="text-xs text-red-400">
                      No collection
                    </Badge>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>
      )}

      <Card className="border-border/40 bg-card/50">
        <CardContent className="p-4">
          <h3 className="text-sm font-semibold text-foreground mb-3">All Log Sources</h3>
          <div className="space-y-2">
            {coverageData.coverage.map((entry) => {
              const cfg = TYPE_CONFIG[entry.type];
              const Icon = cfg?.icon || Server;
              return (
                <div key={entry.templateSlug} className="flex items-center justify-between p-2 rounded-lg bg-muted/20">
                  <div className="flex items-center gap-2">
                    <Icon className={`h-4 w-4 \${cfg?.color || "text-muted-foreground"}`} />
                    <div>
                      <span className="text-sm text-foreground">{entry.templateName}</span>
                      <div className="text-[10px] text-muted-foreground">{entry.platforms.join(", ")}</div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    {entry.covered ? (
                      <Badge className="bg-emerald-600/20 text-emerald-300 text-[10px]">
                        {entry.active}/{entry.deployed} active
                      </Badge>
                    ) : (
                      <Badge className="bg-slate-600/20 text-slate-400 text-[10px]">Not deployed</Badge>
                    )}
                    {entry.covered && (
                      <span className="text-xs text-muted-foreground">
                        {entry.active}/{entry.deployed} reporting
                      </span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function ParsersView() {
  const { data: parsers, isLoading } = useQuery<ParserInfo[]>({
    queryKey: ["/api/native-collectors/parsers"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/native-collectors/parsers");
      return res.json();
    },
  });

  const [testPattern, setTestPattern] = useState("");
  const [testType, setTestType] = useState("regex");
  const [testSample, setTestSample] = useState("");
  const [testResult, setTestResult] = useState<{
    success: boolean;
    extractedFields: Record<string, string>;
    fieldCount: number;
  } | null>(null);
  const [testing, setTesting] = useState(false);
  const { toast } = useToast();

  const handleTest = async () => {
    if (!testPattern || !testSample) return;
    setTesting(true);
    try {
      const res = await apiRequest("POST", "/api/native-collectors/parsers/test", {
        pattern: testPattern,
        patternType: testType,
        sampleLog: testSample,
      });
      setTestResult(await res.json());
    } catch {
      toast({ title: "Parser test failed", variant: "destructive" });
    } finally {
      setTesting(false);
    }
  };

  return (
    <div className="space-y-4">
      <Card className="border-border/40 bg-card/50">
        <CardContent className="p-4">
          <h3 className="text-sm font-semibold text-foreground mb-3 flex items-center gap-2">
            <FileCode className="h-4 w-4 text-primary" />
            Test Custom Parser
          </h3>
          <div className="space-y-3">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div className="sm:col-span-2">
                <label className="text-xs font-medium text-muted-foreground mb-1 block">Pattern</label>
                <input
                  className="w-full px-3 py-2 rounded-md border border-border/60 bg-background text-sm text-foreground font-mono focus:outline-none focus:ring-2 focus:ring-primary/50"
                  value={testPattern}
                  onChange={(e) => setTestPattern(e.target.value)}
                  placeholder="Enter regex, JSON path, or KV pattern..."
                />
              </div>
              <div>
                <label className="text-xs font-medium text-muted-foreground mb-1 block">Type</label>
                <select
                  className="w-full px-3 py-2 rounded-md border border-border/60 bg-background text-sm text-foreground"
                  value={testType}
                  onChange={(e) => setTestType(e.target.value)}
                >
                  <option value="regex">Regex</option>
                  <option value="json_path">JSON Path</option>
                  <option value="kv">Key-Value</option>
                </select>
              </div>
            </div>
            <div>
              <label className="text-xs font-medium text-muted-foreground mb-1 block">Sample Log</label>
              <textarea
                className="w-full px-3 py-2 rounded-md border border-border/60 bg-background text-sm text-foreground font-mono focus:outline-none focus:ring-2 focus:ring-primary/50 min-h-[80px]"
                value={testSample}
                onChange={(e) => setTestSample(e.target.value)}
                placeholder="Paste a sample log line..."
                rows={3}
              />
            </div>
            <Button
              size="sm"
              onClick={handleTest}
              disabled={testing || !testPattern || !testSample}
              className="h-7 text-xs"
            >
              {testing ? <Loader2 className="h-3 w-3 animate-spin mr-1" /> : <Play className="h-3 w-3 mr-1" />}
              Test Parser
            </Button>
          </div>

          {testResult && (
            <div className="mt-4 rounded-lg border border-border/40 p-3">
              <div className="flex items-center gap-2 mb-2">
                <CheckCircle2
                  className={`h-4 w-4 \${testResult.fieldCount > 0 ? "text-emerald-400" : "text-yellow-400"}`}
                />
                <span className="text-sm font-medium text-foreground">{testResult.fieldCount} field(s) extracted</span>
              </div>
              {Object.entries(testResult.extractedFields).length > 0 && (
                <div className="space-y-1">
                  {Object.entries(testResult.extractedFields).map(([key, value]) => (
                    <div key={key} className="flex items-center gap-2 text-xs">
                      <Badge variant="outline" className="text-[10px] font-mono">
                        {key}
                      </Badge>
                      <span className="text-foreground font-mono">{value}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      <Card className="border-border/40 bg-card/50">
        <CardContent className="p-4">
          <h3 className="text-sm font-semibold text-foreground mb-3">Built-in Parsers</h3>
          {isLoading ? (
            <div className="space-y-2">
              {Array.from({ length: 4 }).map((_, i) => (
                <Skeleton key={i} className="h-10 w-full" />
              ))}
            </div>
          ) : (
            <div className="space-y-2">
              {(parsers || []).map((parser) => (
                <div key={parser.id} className="flex items-center justify-between p-2 rounded-lg bg-muted/20">
                  <div className="flex items-center gap-2">
                    <FileCode className="h-4 w-4 text-cyan-400" />
                    <span className="text-sm text-foreground">{parser.name}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant="outline" className="text-[10px]">
                      {parser.patternType}
                    </Badge>
                    {parser.fieldCount > 0 && (
                      <span className="text-xs text-muted-foreground">{parser.fieldCount} fields</span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function CertificatesView() {
  const { data: instances } = useQuery<CollectorInstance[]>({
    queryKey: ["/api/native-collectors/instances"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/native-collectors/instances");
      return res.json();
    },
  });

  const { data: allCerts } = useQuery<CertificateInfo[]>({
    queryKey: ["/api/native-collectors/certificates-all", instances?.length],
    queryFn: async () => {
      if (!instances || instances.length === 0) return [];
      const results: CertificateInfo[] = [];
      for (const inst of instances) {
        try {
          const res = await apiRequest("GET", `/api/native-collectors/instances/\${inst.id}/certificates`);
          const certs: CertificateInfo[] = await res.json();
          results.push(...certs);
        } catch {
          // skip
        }
      }
      return results;
    },
    enabled: (instances?.length ?? 0) > 0,
  });

  if (!instances || instances.length === 0) {
    return (
      <div className="text-center py-12">
        <Lock className="h-10 w-10 text-muted-foreground mx-auto mb-3" />
        <p className="text-sm text-muted-foreground">No collectors deployed for certificate management</p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {(allCerts || []).map((cert) => (
        <Card key={cert.id} className="border-border/40 bg-card/50">
          <CardContent className="p-4">
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2">
                <Lock
                  className={`h-4 w-4 \${cert.status === "valid" ? "text-emerald-400" : cert.status === "expiring_soon" ? "text-yellow-400" : "text-red-400"}`}
                />
                <span className="font-semibold text-sm text-foreground">{cert.subject}</span>
              </div>
              <Badge
                className={`text-xs \${cert.status === "valid" ? "bg-emerald-600/20 text-emerald-300" : cert.status === "expiring_soon" ? "bg-yellow-600/20 text-yellow-300" : "bg-red-600/20 text-red-300"}`}
              >
                {cert.status.replace(/_/g, " ")}
              </Badge>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
              <div>
                <span className="text-muted-foreground">Issuer</span>
                <div className="text-foreground">{cert.issuer}</div>
              </div>
              <div>
                <span className="text-muted-foreground">Expires</span>
                <div
                  className={`\${cert.daysUntilExpiry > 30 ? "text-foreground" : cert.daysUntilExpiry > 7 ? "text-yellow-400" : "text-red-400"}`}
                >
                  {new Date(cert.notAfter).toLocaleDateString()} ({cert.daysUntilExpiry}d)
                </div>
              </div>
              <div>
                <span className="text-muted-foreground">Key Type</span>
                <div className="text-foreground">{cert.keyType}</div>
              </div>
              <div>
                <span className="text-muted-foreground">Auto-Renew</span>
                <div className={`\${cert.autoRenew ? "text-emerald-400" : "text-muted-foreground"}`}>
                  {cert.autoRenew ? "Enabled" : "Disabled"}
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

export default function NativeCollectorsPage() {
  const [tab, setTab] = useState<TabView>("catalog");
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState<string>("all");
  const [deployTemplate, setDeployTemplate] = useState<CollectorTemplate | null>(null);
  const [expandedInstance, setExpandedInstance] = useState<string | null>(null);
  const [scriptDialog, setScriptDialog] = useState<{ script: string; slug: string } | null>(null);
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const { data: stats } = useQuery<PipelineStats>({
    queryKey: ["/api/native-collectors/stats"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/native-collectors/stats");
      return res.json();
    },
  });

  const { data: templates, isLoading: templatesLoading } = useQuery<CollectorTemplate[]>({
    queryKey: ["/api/native-collectors/templates"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/native-collectors/templates");
      return res.json();
    },
  });

  const { data: instances, isLoading: instancesLoading } = useQuery<CollectorInstance[]>({
    queryKey: ["/api/native-collectors/instances"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/native-collectors/instances");
      return res.json();
    },
  });

  const deployMutation = useMutation({
    mutationFn: async (data: {
      templateSlug: string;
      name: string;
      platform: string;
      deploymentMethod: string;
      config: Record<string, unknown>;
      tags: string[];
    }) => {
      const res = await apiRequest("POST", "/api/native-collectors/deploy", data);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/native-collectors/instances"] });
      queryClient.invalidateQueries({ queryKey: ["/api/native-collectors/stats"] });
      toast({ title: "Collector deployed successfully" });
      setDeployTemplate(null);
    },
    onError: (err: Error) => {
      toast({ title: "Deploy failed", description: err.message, variant: "destructive" });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("DELETE", `/api/native-collectors/instances/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/native-collectors/instances"] });
      queryClient.invalidateQueries({ queryKey: ["/api/native-collectors/stats"] });
      toast({ title: "Collector removed" });
    },
    onError: (err: Error) => {
      toast({ title: "Delete failed", description: err.message, variant: "destructive" });
    },
  });

  const revokeMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("POST", `/api/native-collectors/instances/${id}/revoke`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/native-collectors/instances"] });
      toast({ title: "Collector revoked" });
    },
    onError: (err: Error) => {
      toast({ title: "Revoke failed", description: err.message, variant: "destructive" });
    },
  });

  const handleViewScript = useCallback(
    async (instanceId: string) => {
      try {
        const instance = instances?.find((candidate) => candidate.id === instanceId);
        if (!instance) return;
        const tokenResponse = await apiRequest("POST", "/api/native-sensors/enrollment-tokens", {
          label: `${instance.name} collector bootstrap`,
          maxUses: 1,
          expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
          platformHint: instance.platform,
        });
        const tokenData = await tokenResponse.json();
        const enrollmentToken = tokenData.enrollmentToken;
        if (!enrollmentToken) throw new Error("Enrollment token was not returned.");
        const res = await apiRequest("POST", `/api/native-collectors/instances/${instanceId}/deploy-script`, {
          enrollmentToken,
        });
        const data = await res.json();
        setScriptDialog({ script: data.script, slug: data.templateSlug });
      } catch {
        toast({ title: "Failed to fetch script", variant: "destructive" });
      }
    },
    [instances, toast],
  );

  const handleGenerateKey = useCallback(
    async (instanceId: string) => {
      try {
        const res = await apiRequest("POST", `/api/native-collectors/instances/${instanceId}/api-key`);
        const data = await res.json();
        await navigator.clipboard.writeText(data.apiKey);
        toast({
          title: "API key generated and copied",
          description: `Expires: ${new Date(data.expiresAt).toLocaleDateString()}`,
        });
      } catch {
        toast({ title: "Failed to generate API key", variant: "destructive" });
      }
    },
    [toast],
  );

  const filteredTemplates = (templates || []).filter((t) => {
    const matchesSearch =
      !search ||
      t.name.toLowerCase().includes(search.toLowerCase()) ||
      t.description.toLowerCase().includes(search.toLowerCase());
    const matchesType = typeFilter === "all" || t.type === typeFilter;
    return matchesSearch && matchesType;
  });

  const tabs: { id: TabView; label: string; icon: typeof Monitor }[] = [
    { id: "catalog", label: "Catalog", icon: HardDrive },
    { id: "deployed", label: `Deployed (\${instances?.length || 0})`, icon: Server },
    { id: "health", label: "Health", icon: Activity },
    { id: "coverage", label: "Coverage Map", icon: Map },
    { id: "events", label: "Events", icon: Activity },
    { id: "parsers", label: "Parsers", icon: FileCode },
    { id: "certs", label: "Certificates", icon: Lock },
    { id: "pipeline", label: "Pipeline", icon: Wifi },
  ];

  return (
    <div className="p-4 sm:p-6 space-y-4 max-w-[1400px] mx-auto">
      <div className="gradient-page-header pb-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h1 className="text-xl font-bold text-foreground flex items-center gap-2">
              <div className="p-1.5 rounded-lg gradient-icon-bg">
                <HardDrive className="h-5 w-5 text-cyan-400" />
              </div>
              Native Data Collection
            </h1>
            <p className="text-sm text-muted-foreground mt-1">
              Deploy lightweight collectors to start securing in minutes — no existing tools required
            </p>
          </div>
          <Button size="sm" className="h-8 text-xs" onClick={() => setTab("catalog")} aria-label="Deploy new collector">
            <Plus className="h-3.5 w-3.5 mr-1" />
            Deploy Collector
          </Button>
        </div>
      </div>

      <div className="flex gap-1 border-b border-border/40 overflow-x-auto">
        {tabs.map((t) => {
          const Icon = t.icon;
          return (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={`flex items-center gap-1.5 px-3 py-2 text-xs font-medium border-b-2 transition-colors whitespace-nowrap ${
                tab === t.id
                  ? "border-primary text-primary"
                  : "border-transparent text-muted-foreground hover:text-foreground hover:border-border"
              }`}
              aria-label={`Switch to ${t.label} tab`}
            >
              <Icon className="h-3.5 w-3.5" />
              {t.label}
            </button>
          );
        })}
      </div>

      {tab === "catalog" && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <input
                className="w-full pl-9 pr-3 py-2 rounded-md border border-border/60 bg-background text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-primary/50"
                placeholder="Search collectors..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                aria-label="Search collector templates"
              />
            </div>
            <select
              className="px-3 py-2 rounded-md border border-border/60 bg-background text-sm text-foreground"
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              aria-label="Filter by collector type"
            >
              <option value="all">All Types</option>
              {Object.entries(TYPE_CONFIG).map(([key, cfg]) => (
                <option key={key} value={key}>
                  {cfg.label}
                </option>
              ))}
            </select>
          </div>

          {templatesLoading ? (
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
              {Array.from({ length: 6 }).map((_, i) => (
                <Skeleton key={i} className="h-48" />
              ))}
            </div>
          ) : filteredTemplates.length === 0 ? (
            <Card className="border-border/40 bg-card/50">
              <CardContent className="p-8 text-center">
                <Search className="h-10 w-10 mx-auto mb-3 text-muted-foreground/40" />
                <p className="text-sm text-muted-foreground">No collectors match your search</p>
              </CardContent>
            </Card>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
              {filteredTemplates.map((t) => (
                <TemplateCard key={t.slug} template={t} onDeploy={setDeployTemplate} />
              ))}
            </div>
          )}
        </div>
      )}

      {tab === "deployed" && (
        <div className="space-y-3">
          {instancesLoading ? (
            Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-20 w-full" />)
          ) : !instances || instances.length === 0 ? (
            <Card className="border-border/40 bg-card/50">
              <CardContent className="p-8 text-center">
                <Server className="h-10 w-10 mx-auto mb-3 text-muted-foreground/40" />
                <p className="text-sm text-muted-foreground">No collectors deployed</p>
                <p className="text-xs text-muted-foreground mt-1">Go to Catalog to deploy your first collector</p>
                <Button variant="outline" size="sm" className="mt-3 h-7 text-xs" onClick={() => setTab("catalog")}>
                  <Plus className="h-3 w-3 mr-1" />
                  Browse Catalog
                </Button>
              </CardContent>
            </Card>
          ) : (
            instances.map((inst) => (
              <InstanceRow
                key={inst.id}
                instance={inst}
                templateSlug={inst.templateSlug}
                onDelete={(id) => deleteMutation.mutate(id)}
                onViewScript={handleViewScript}
                onGenerateKey={handleGenerateKey}
                onRevoke={(id) => revokeMutation.mutate(id)}
                expanded={expandedInstance === inst.id}
                onToggle={() => setExpandedInstance(expandedInstance === inst.id ? null : inst.id)}
                deleting={deleteMutation.isPending}
              />
            ))
          )}
        </div>
      )}

      {tab === "health" && <CollectorHealthView />}
      {tab === "coverage" && <CoverageMapView />}
      {tab === "parsers" && <ParsersView />}
      {tab === "certs" && <CertificatesView />}
      {tab === "events" && <EventsView />}
      {tab === "pipeline" && stats && <PipelineOverview stats={stats} />}
      {tab === "pipeline" && !stats && (
        <div className="space-y-3">
          <Skeleton className="h-24 w-full" />
          <div className="grid grid-cols-2 gap-3">
            <Skeleton className="h-48" />
            <Skeleton className="h-48" />
          </div>
        </div>
      )}

      {deployTemplate && (
        <DeployDialog
          template={deployTemplate}
          onDeploy={(data) => deployMutation.mutate(data)}
          onClose={() => setDeployTemplate(null)}
          deploying={deployMutation.isPending}
        />
      )}

      {scriptDialog && (
        <ScriptDialog
          script={scriptDialog.script}
          templateSlug={scriptDialog.slug}
          onClose={() => setScriptDialog(null)}
        />
      )}
    </div>
  );
}

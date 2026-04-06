import { useState, useMemo, useCallback } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import {
  Shield,
  AlertTriangle,
  ArrowRight,
  ChevronDown,
  ChevronRight,
  Cloud,
  Code2,
  Database,
  Fingerprint,
  Globe,
  Loader2,
  Monitor,
  Network,
  Server,
  Box,
  Filter,
  Search,
  X,
  ExternalLink,
  Target,
  Zap,
  TrendingUp,
  Plus,
  Send,
  Route,
  Crosshair,
  Laptop,
  CloudCog,
  Bug,
  Wrench,
  Activity,
} from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Progress } from "@/components/ui/progress";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";

interface SecurityAsset {
  id: string;
  orgId: string | null;
  name: string;
  type: string;
  subType: string;
  environment: string;
  riskScore: number;
  metadata: Record<string, unknown>;
  tags: string[];
  owner: string | null;
  lastScannedAt: string | null;
  createdAt: string;
}

interface SecurityRelationship {
  id: string;
  sourceId: string;
  targetId: string;
  relationship: string;
  weight: number;
  metadata: Record<string, unknown>;
  bidirectional: boolean;
}

interface RankedAttackPath {
  id: string;
  name: string;
  description: string;
  nodes: SecurityAsset[];
  edges: SecurityRelationship[];
  riskScore: number;
  blastRadius: number;
  exploitability: number;
  hopCount: number;
  entryPoint: SecurityAsset;
  target: SecurityAsset;
  mitigations: string[];
  mitreTactics: string[];
}

interface GraphStats {
  totalAssets: number;
  totalRelationships: number;
  criticalPaths: number;
  highRiskAssets: number;
  avgRiskScore: number;
  byType: Record<string, number>;
  byEnvironment: Record<string, number>;
  internetExposed: number;
  overPrivileged: number;
}

interface SecurityGraphData {
  assets: SecurityAsset[];
  relationships: SecurityRelationship[];
  attackPaths: RankedAttackPath[];
  stats: GraphStats;
}

const ASSET_TYPE_CONFIG: Record<string, { icon: typeof Shield; color: string; label: string }> = {
  code: { icon: Code2, color: "text-blue-400 bg-blue-500/10 border-blue-500/20", label: "Code" },
  cloud: { icon: Cloud, color: "text-sky-400 bg-sky-500/10 border-sky-500/20", label: "Cloud" },
  identity: { icon: Fingerprint, color: "text-purple-400 bg-purple-500/10 border-purple-500/20", label: "Identity" },
  data: { icon: Database, color: "text-amber-400 bg-amber-500/10 border-amber-500/20", label: "Data" },
  network: { icon: Globe, color: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20", label: "Network" },
  compute: { icon: Server, color: "text-orange-400 bg-orange-500/10 border-orange-500/20", label: "Compute" },
  container: { icon: Box, color: "text-cyan-400 bg-cyan-500/10 border-cyan-500/20", label: "Container" },
  endpoint: { icon: Laptop, color: "text-pink-400 bg-pink-500/10 border-pink-500/20", label: "Endpoint" },
  saas: { icon: CloudCog, color: "text-indigo-400 bg-indigo-500/10 border-indigo-500/20", label: "SaaS" },
  runtime: { icon: Activity, color: "text-lime-400 bg-lime-500/10 border-lime-500/20", label: "Runtime" },
  remediation: { icon: Wrench, color: "text-teal-400 bg-teal-500/10 border-teal-500/20", label: "Remediation" },
  vulnerability: { icon: Bug, color: "text-rose-400 bg-rose-500/10 border-rose-500/20", label: "Vulnerability" },
};

const ENVIRONMENT_COLORS: Record<string, string> = {
  production: "text-red-400 bg-red-500/10 border-red-500/20",
  staging: "text-yellow-400 bg-yellow-500/10 border-yellow-500/20",
  development: "text-blue-400 bg-blue-500/10 border-blue-500/20",
  shared: "text-purple-400 bg-purple-500/10 border-purple-500/20",
};

function riskColor(score: number): string {
  if (score >= 0.8) return "text-red-400";
  if (score >= 0.6) return "text-orange-400";
  if (score >= 0.4) return "text-yellow-400";
  return "text-emerald-400";
}

function riskBgColor(score: number): string {
  if (score >= 0.8) return "bg-red-500/10 border-red-500/20";
  if (score >= 0.6) return "bg-orange-500/10 border-orange-500/20";
  if (score >= 0.4) return "bg-yellow-500/10 border-yellow-500/20";
  return "bg-emerald-500/10 border-emerald-500/20";
}

function riskProgressColor(score: number): string {
  if (score >= 0.8) return "[&>div]:bg-red-500";
  if (score >= 0.6) return "[&>div]:bg-orange-500";
  if (score >= 0.4) return "[&>div]:bg-yellow-500";
  return "[&>div]:bg-emerald-500";
}

function formatTimeAgo(date: string | null): string {
  if (!date) return "Never";
  const diff = Date.now() - new Date(date).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function AssetTypeIcon({ type, className }: { type: string; className?: string }) {
  const config = ASSET_TYPE_CONFIG[type];
  if (!config) return <Shield className={className || "h-4 w-4"} />;
  const Icon = config.icon;
  return <Icon className={className || "h-4 w-4"} />;
}

function StatCard({
  icon: Icon,
  label,
  value,
  color,
  testId,
}: {
  icon: typeof Shield;
  label: string;
  value: string | number;
  color: string;
  testId: string;
}) {
  return (
    <Card data-testid={testId}>
      <CardContent className="p-4">
        <div className="flex items-center gap-3">
          <div className={`p-2 rounded-md border ${color}`}>
            <Icon className="h-4 w-4" />
          </div>
          <div>
            <p className="text-2xl font-bold">{value}</p>
            <p className="text-xs text-muted-foreground">{label}</p>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function AssetDetailPanel({
  asset,
  relationships,
  allAssets,
  onClose,
}: {
  asset: SecurityAsset;
  relationships: SecurityRelationship[];
  allAssets: SecurityAsset[];
  onClose: () => void;
}) {
  const assetMap = useMemo(() => new Map(allAssets.map((a) => [a.id, a])), [allAssets]);
  const config = ASSET_TYPE_CONFIG[asset.type];

  const connected = useMemo(() => {
    const results: { asset: SecurityAsset; relationship: string; direction: string }[] = [];
    for (const rel of relationships) {
      if (rel.sourceId === asset.id) {
        const target = assetMap.get(rel.targetId);
        if (target) results.push({ asset: target, relationship: rel.relationship, direction: "outbound" });
      }
      if (rel.targetId === asset.id) {
        const source = assetMap.get(rel.sourceId);
        if (source) results.push({ asset: source, relationship: rel.relationship, direction: "inbound" });
      }
    }
    return results;
  }, [asset.id, relationships, assetMap]);

  const meta = asset.metadata as Record<string, unknown>;
  const metaEntries = Object.entries(meta).filter(
    ([, v]) => typeof v === "string" || typeof v === "number" || typeof v === "boolean",
  );

  return (
    <div
      className="fixed inset-y-0 right-0 w-[420px] z-50 border-l border-border/50 glass-strong overflow-y-auto"
      role="dialog"
      aria-label={`Asset details: ${asset.name}`}
    >
      <div className="p-4 border-b border-border/50 flex items-center justify-between sticky top-0 z-10 glass-strong">
        <div className="flex items-center gap-2">
          <div className={`p-1.5 rounded-md border ${config?.color || "bg-muted"}`}>
            <AssetTypeIcon type={asset.type} className="h-4 w-4" />
          </div>
          <div>
            <h2 className="text-sm font-bold">{asset.name}</h2>
            <p className="text-[10px] text-muted-foreground">{asset.subType.replace(/_/g, " ")}</p>
          </div>
        </div>
        <Button variant="ghost" size="icon" onClick={onClose} aria-label="Close panel">
          <X className="h-4 w-4" />
        </Button>
      </div>

      <div className="p-4 space-y-4">
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs text-muted-foreground">Risk Score</span>
            <span className={`text-sm font-bold ${riskColor(asset.riskScore)}`}>
              {(asset.riskScore * 100).toFixed(0)}%
            </span>
          </div>
          <Progress value={asset.riskScore * 100} className={`h-2 ${riskProgressColor(asset.riskScore)}`} />
        </div>

        <div className="grid grid-cols-2 gap-2">
          <div className="rounded-md border p-2 text-center">
            <p className="text-[10px] text-muted-foreground">Environment</p>
            <Badge variant="outline" className={`text-[10px] mt-1 ${ENVIRONMENT_COLORS[asset.environment] || ""}`}>
              {asset.environment}
            </Badge>
          </div>
          <div className="rounded-md border p-2 text-center">
            <p className="text-[10px] text-muted-foreground">Owner</p>
            <p className="text-xs font-medium mt-1">{asset.owner || "Unassigned"}</p>
          </div>
          <div className="rounded-md border p-2 text-center">
            <p className="text-[10px] text-muted-foreground">Last Scanned</p>
            <p className="text-xs font-medium mt-1">{formatTimeAgo(asset.lastScannedAt)}</p>
          </div>
          <div className="rounded-md border p-2 text-center">
            <p className="text-[10px] text-muted-foreground">Connections</p>
            <p className="text-xs font-medium mt-1">{connected.length}</p>
          </div>
        </div>

        {asset.tags.length > 0 && (
          <div>
            <p className="text-xs text-muted-foreground mb-1.5">Tags</p>
            <div className="flex flex-wrap gap-1">
              {asset.tags.map((tag) => (
                <Badge key={tag} variant="outline" className="text-[10px]">
                  {tag}
                </Badge>
              ))}
            </div>
          </div>
        )}

        {metaEntries.length > 0 && (
          <div>
            <p className="text-xs text-muted-foreground mb-1.5">Properties</p>
            <div className="space-y-1">
              {metaEntries.map(([key, value]) => (
                <div key={key} className="flex items-center justify-between text-xs py-0.5">
                  <span className="text-muted-foreground">{key}</span>
                  <span className="font-mono text-[11px]">
                    {typeof value === "boolean" ? (value ? "Yes" : "No") : String(value)}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {connected.length > 0 && (
          <div>
            <p className="text-xs text-muted-foreground mb-1.5">Connections ({connected.length})</p>
            <div className="space-y-1.5">
              {connected.map((conn, i) => {
                const connConfig = ASSET_TYPE_CONFIG[conn.asset.type];
                return (
                  <div
                    key={`${conn.asset.id}-${conn.direction}-${i}`}
                    className="flex items-center gap-2 p-1.5 rounded-md border text-xs"
                  >
                    <div className={`p-1 rounded border ${connConfig?.color || "bg-muted"}`}>
                      <AssetTypeIcon type={conn.asset.type} className="h-3 w-3" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="font-medium truncate">{conn.asset.name}</p>
                      <p className="text-[10px] text-muted-foreground">
                        {conn.direction === "outbound" ? "→" : "←"} {conn.relationship.replace(/_/g, " ")}
                      </p>
                    </div>
                    <span className={`text-[10px] font-bold ${riskColor(conn.asset.riskScore)}`}>
                      {(conn.asset.riskScore * 100).toFixed(0)}%
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function AttackPathCard({
  path,
  isExpanded,
  onToggle,
}: {
  path: RankedAttackPath;
  isExpanded: boolean;
  onToggle: () => void;
}) {
  return (
    <Card className="overflow-hidden" data-testid={`attack-path-${path.id}`}>
      <div className="flex items-start gap-3 p-4 cursor-pointer hover-elevate" onClick={onToggle}>
        <div className={`p-2 rounded-md border shrink-0 ${riskBgColor(path.riskScore)}`}>
          <Target className={`h-4 w-4 ${riskColor(path.riskScore)}`} />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-bold truncate">{path.name}</h3>
            <Badge
              variant="outline"
              className={`text-[10px] shrink-0 border ${riskBgColor(path.riskScore)} ${riskColor(path.riskScore)}`}
            >
              Risk: {(path.riskScore * 100).toFixed(0)}%
            </Badge>
          </div>
          <p className="text-xs text-muted-foreground mt-0.5">{path.description}</p>
          <div className="flex items-center gap-3 mt-2 text-[10px] text-muted-foreground">
            <span>{path.hopCount} hops</span>
            <span>Blast radius: {(path.blastRadius * 100).toFixed(0)}%</span>
            <span>Exploitability: {(path.exploitability * 100).toFixed(0)}%</span>
          </div>
        </div>
        <div className="shrink-0">
          {isExpanded ? (
            <ChevronDown className="h-4 w-4 text-muted-foreground" />
          ) : (
            <ChevronRight className="h-4 w-4 text-muted-foreground" />
          )}
        </div>
      </div>

      {isExpanded && (
        <div className="border-t border-border/50 p-4 space-y-4">
          <div>
            <p className="text-xs font-medium mb-2">Attack Chain</p>
            <div className="flex items-center gap-1 flex-wrap">
              {path.nodes.map((node, idx) => {
                const nodeConfig = ASSET_TYPE_CONFIG[node.type];
                return (
                  <div key={node.id} className="flex items-center gap-1">
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <div
                          className={`flex items-center gap-1 px-2 py-1 rounded-md border ${nodeConfig?.color || "bg-muted"}`}
                        >
                          <AssetTypeIcon type={node.type} className="h-3 w-3" />
                          <span className="text-[10px] font-mono">
                            {node.name.length > 18 ? node.name.substring(0, 18) + "..." : node.name}
                          </span>
                        </div>
                      </TooltipTrigger>
                      <TooltipContent>
                        <p className="text-xs">
                          {node.name} ({node.subType.replace(/_/g, " ")})
                        </p>
                        <p className="text-[10px] text-muted-foreground">Risk: {(node.riskScore * 100).toFixed(0)}%</p>
                      </TooltipContent>
                    </Tooltip>
                    {idx < path.nodes.length - 1 && <ArrowRight className="h-3 w-3 text-muted-foreground shrink-0" />}
                  </div>
                );
              })}
            </div>
          </div>

          {path.mitreTactics.length > 0 && (
            <div>
              <p className="text-xs font-medium mb-1.5">MITRE ATT&CK Tactics</p>
              <div className="flex flex-wrap gap-1">
                {path.mitreTactics.map((tactic) => (
                  <Badge
                    key={tactic}
                    variant="outline"
                    className="text-[10px] text-red-400 bg-red-500/10 border-red-500/20"
                  >
                    {tactic}
                  </Badge>
                ))}
              </div>
            </div>
          )}

          {path.mitigations.length > 0 && (
            <div>
              <p className="text-xs font-medium mb-1.5">Recommended Mitigations</p>
              <div className="space-y-1">
                {path.mitigations.map((mitigation, i) => (
                  <div key={i} className="flex items-start gap-2 text-xs">
                    <Shield className="h-3 w-3 text-emerald-400 mt-0.5 shrink-0" />
                    <span className="text-muted-foreground">{mitigation}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="grid grid-cols-3 gap-2">
            <div className="rounded-md border p-2 text-center">
              <p className="text-[10px] text-muted-foreground">Risk Score</p>
              <p className={`text-sm font-bold ${riskColor(path.riskScore)}`}>{(path.riskScore * 100).toFixed(0)}%</p>
            </div>
            <div className="rounded-md border p-2 text-center">
              <p className="text-[10px] text-muted-foreground">Blast Radius</p>
              <p className={`text-sm font-bold ${riskColor(path.blastRadius)}`}>
                {(path.blastRadius * 100).toFixed(0)}%
              </p>
            </div>
            <div className="rounded-md border p-2 text-center">
              <p className="text-[10px] text-muted-foreground">Exploitability</p>
              <p className={`text-sm font-bold ${riskColor(path.exploitability)}`}>
                {(path.exploitability * 100).toFixed(0)}%
              </p>
            </div>
          </div>
        </div>
      )}
    </Card>
  );
}

function VisualGraphView({
  assets,
  relationships,
  onSelectAsset,
  selectedAssetId,
  typeFilter,
}: {
  assets: SecurityAsset[];
  relationships: SecurityRelationship[];
  onSelectAsset: (id: string) => void;
  selectedAssetId: string | null;
  typeFilter: string | null;
}) {
  const filtered = useMemo(() => {
    if (!typeFilter) return assets;
    return assets.filter((a) => a.type === typeFilter);
  }, [assets, typeFilter]);

  const filteredIds = useMemo(() => new Set(filtered.map((a) => a.id)), [filtered]);

  const visibleRelationships = useMemo(
    () => relationships.filter((r) => filteredIds.has(r.sourceId) && filteredIds.has(r.targetId)),
    [relationships, filteredIds],
  );

  const positions = useMemo(() => {
    const pos = new Map<string, { x: number; y: number }>();
    const typeGroups = new Map<string, SecurityAsset[]>();
    for (const asset of filtered) {
      const group = typeGroups.get(asset.type) || [];
      group.push(asset);
      typeGroups.set(asset.type, group);
    }

    const types = Array.from(typeGroups.keys());
    const cx = 450;
    const cy = 300;
    const typeRadius = 220;

    types.forEach((type, typeIdx) => {
      const typeAngle = (typeIdx / types.length) * 2 * Math.PI - Math.PI / 2;
      const groupCx = cx + typeRadius * Math.cos(typeAngle);
      const groupCy = cy + typeRadius * Math.sin(typeAngle);

      const groupAssets = typeGroups.get(type) || [];
      const itemRadius = Math.min(80, 30 + groupAssets.length * 15);

      groupAssets.forEach((asset, i) => {
        const itemAngle = (i / Math.max(groupAssets.length, 1)) * 2 * Math.PI - Math.PI / 2;
        pos.set(asset.id, {
          x: groupCx + itemRadius * Math.cos(itemAngle),
          y: groupCy + itemRadius * Math.sin(itemAngle),
        });
      });
    });

    return pos;
  }, [filtered]);

  return (
    <div className="relative w-full overflow-hidden rounded-lg border" style={{ height: 600 }}>
      <svg width="100%" height="100%" viewBox="0 0 900 600" className="bg-background/50">
        <defs>
          <marker id="arrowhead" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
            <polygon points="0 0, 8 3, 0 6" className="fill-muted-foreground/30" />
          </marker>
        </defs>

        {visibleRelationships.map((rel) => {
          const from = positions.get(rel.sourceId);
          const to = positions.get(rel.targetId);
          if (!from || !to) return null;

          const isHighlighted = selectedAssetId === rel.sourceId || selectedAssetId === rel.targetId;

          return (
            <line
              key={rel.id}
              x1={from.x}
              y1={from.y}
              x2={to.x}
              y2={to.y}
              className={isHighlighted ? "stroke-cyan-400/60" : "stroke-muted-foreground/15"}
              strokeWidth={isHighlighted ? 2 : 1}
              markerEnd="url(#arrowhead)"
            />
          );
        })}

        {filtered.map((asset) => {
          const pos = positions.get(asset.id);
          if (!pos) return null;

          const config = ASSET_TYPE_CONFIG[asset.type];
          const isSelected = selectedAssetId === asset.id;
          const r = isSelected ? 24 : 20;

          let fillColor = "rgba(100,100,100,0.3)";
          if (asset.riskScore >= 0.8) fillColor = "rgba(239,68,68,0.2)";
          else if (asset.riskScore >= 0.6) fillColor = "rgba(249,115,22,0.2)";
          else if (asset.riskScore >= 0.4) fillColor = "rgba(234,179,8,0.2)";
          else fillColor = "rgba(16,185,129,0.2)";

          let strokeColor = "rgba(100,100,100,0.4)";
          if (asset.riskScore >= 0.8) strokeColor = "rgba(239,68,68,0.5)";
          else if (asset.riskScore >= 0.6) strokeColor = "rgba(249,115,22,0.5)";
          else if (asset.riskScore >= 0.4) strokeColor = "rgba(234,179,8,0.5)";
          else strokeColor = "rgba(16,185,129,0.5)";

          if (isSelected) strokeColor = "rgba(6,182,212,0.8)";

          return (
            <g
              key={asset.id}
              className="cursor-pointer"
              onClick={() => onSelectAsset(asset.id)}
              role="button"
              tabIndex={0}
              aria-label={`${asset.name}: ${asset.type}, risk ${(asset.riskScore * 100).toFixed(0)}%`}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  onSelectAsset(asset.id);
                }
              }}
            >
              <circle
                cx={pos.x}
                cy={pos.y}
                r={r}
                fill={fillColor}
                stroke={strokeColor}
                strokeWidth={isSelected ? 3 : 1.5}
              />
              <text
                x={pos.x}
                y={pos.y - r - 6}
                textAnchor="middle"
                className="fill-foreground text-[9px] font-medium"
                style={{ pointerEvents: "none" }}
              >
                {asset.name.length > 20 ? asset.name.substring(0, 20) + "..." : asset.name}
              </text>
              <text
                x={pos.x}
                y={pos.y + 4}
                textAnchor="middle"
                className="fill-foreground/70 text-[8px]"
                style={{ pointerEvents: "none" }}
              >
                {(asset.riskScore * 100).toFixed(0)}%
              </text>
            </g>
          );
        })}
      </svg>

      <div className="absolute top-3 left-3 flex flex-wrap gap-1.5">
        {Object.entries(ASSET_TYPE_CONFIG).map(([type, config]) => (
          <div
            key={type}
            className={`flex items-center gap-1 px-2 py-0.5 rounded-full border text-[10px] ${config.color}`}
          >
            <config.icon className="h-2.5 w-2.5" />
            {config.label}
          </div>
        ))}
      </div>
    </div>
  );
}

interface IngestionResult {
  assetsUpserted: number;
  relationshipsUpserted: number;
  assetsSkipped: number;
  relationshipsSkipped: number;
  errors: string[];
}

const ASSET_TYPE_OPTIONS = [
  "code",
  "cloud",
  "identity",
  "data",
  "network",
  "compute",
  "container",
  "endpoint",
  "saas",
  "runtime",
  "remediation",
  "vulnerability",
];

const RELATIONSHIP_TYPE_OPTIONS = [
  "accesses",
  "authenticates_with",
  "contains",
  "deploys_to",
  "exposes",
  "has_permission",
  "reads_from",
  "writes_to",
  "connects_to",
  "inherits_from",
  "manages",
  "depends_on",
  "runs_on",
  "can_access",
  "exposed_to",
  "owned_by",
  "fixed_by",
  "triggers",
  "mitigates",
  "scans",
];

const ENV_OPTIONS = ["production", "staging", "development", "shared"];

function IngestionPanel() {
  const queryClient = useQueryClient();
  const [assetName, setAssetName] = useState("");
  const [assetType, setAssetType] = useState("code");
  const [assetSubType, setAssetSubType] = useState("");
  const [assetEnv, setAssetEnv] = useState("production");
  const [assetRisk, setAssetRisk] = useState("0.5");
  const [assetOwner, setAssetOwner] = useState("");
  const [assetTags, setAssetTags] = useState("");
  const [lastResult, setLastResult] = useState<IngestionResult | null>(null);

  const ingestMutation = useMutation({
    mutationFn: async (payload: Record<string, unknown>) => {
      const res = await apiRequest("POST", "/api/security-graph/ingest", payload);
      return res.json() as Promise<IngestionResult>;
    },
    onSuccess: (data) => {
      setLastResult(data);
      queryClient.invalidateQueries({ queryKey: ["/api/security-graph"] });
    },
  });

  const handleIngest = () => {
    const riskScore = Math.max(0, Math.min(1, parseFloat(assetRisk) || 0.5));
    const tags = assetTags
      .split(",")
      .map((t) => t.trim())
      .filter(Boolean);
    ingestMutation.mutate({
      assets: [
        {
          name: assetName,
          type: assetType,
          subType: assetSubType || assetType + "_asset",
          environment: assetEnv,
          riskScore,
          owner: assetOwner || null,
          tags,
          metadata: {},
        },
      ],
    });
  };

  const nameValid = assetName.trim().length > 0;
  const subTypeValid = assetSubType.trim().length > 0;
  const riskValid = !isNaN(parseFloat(assetRisk)) && parseFloat(assetRisk) >= 0 && parseFloat(assetRisk) <= 1;

  return (
    <Card>
      <CardContent className="p-4 space-y-4">
        <div className="flex items-center gap-2 mb-2">
          <Plus className="h-4 w-4 text-cyan-400" />
          <h3 className="text-sm font-bold">Ingest New Entity</h3>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          <div>
            <label className="text-xs text-muted-foreground block mb-1">Asset Name *</label>
            <Input
              value={assetName}
              onChange={(e) => setAssetName(e.target.value)}
              placeholder="e.g. my-api-server"
              className={`text-xs h-8 ${!nameValid && assetName ? "border-red-500" : ""}`}
            />
            {!nameValid && assetName && <p className="text-[10px] text-red-400 mt-0.5">Name is required</p>}
          </div>
          <div>
            <label className="text-xs text-muted-foreground block mb-1">Type *</label>
            <select
              value={assetType}
              onChange={(e) => setAssetType(e.target.value)}
              className="w-full h-8 text-xs rounded-md border bg-background px-2"
            >
              {ASSET_TYPE_OPTIONS.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="text-xs text-muted-foreground block mb-1">Sub Type *</label>
            <Input
              value={assetSubType}
              onChange={(e) => setAssetSubType(e.target.value)}
              placeholder="e.g. repository, s3_bucket"
              className={`text-xs h-8 ${!subTypeValid && assetSubType ? "border-red-500" : ""}`}
            />
          </div>
          <div>
            <label className="text-xs text-muted-foreground block mb-1">Environment</label>
            <select
              value={assetEnv}
              onChange={(e) => setAssetEnv(e.target.value)}
              className="w-full h-8 text-xs rounded-md border bg-background px-2"
            >
              {ENV_OPTIONS.map((e) => (
                <option key={e} value={e}>
                  {e}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="text-xs text-muted-foreground block mb-1">Risk Score (0-1)</label>
            <Input
              value={assetRisk}
              onChange={(e) => setAssetRisk(e.target.value)}
              type="number"
              min={0}
              max={1}
              step={0.05}
              className={`text-xs h-8 ${!riskValid ? "border-red-500" : ""}`}
            />
            {!riskValid && <p className="text-[10px] text-red-400 mt-0.5">Must be 0-1</p>}
          </div>
          <div>
            <label className="text-xs text-muted-foreground block mb-1">Owner</label>
            <Input
              value={assetOwner}
              onChange={(e) => setAssetOwner(e.target.value)}
              placeholder="e.g. platform-team"
              className="text-xs h-8"
            />
          </div>
          <div className="md:col-span-2 lg:col-span-3">
            <label className="text-xs text-muted-foreground block mb-1">Tags (comma-separated)</label>
            <Input
              value={assetTags}
              onChange={(e) => setAssetTags(e.target.value)}
              placeholder="e.g. backend, api, nodejs"
              className="text-xs h-8"
            />
          </div>
        </div>
        <div className="flex items-center gap-3">
          <Button
            size="sm"
            onClick={handleIngest}
            disabled={!nameValid || !riskValid || ingestMutation.isPending}
            className="h-8"
          >
            {ingestMutation.isPending ? (
              <Loader2 className="h-3 w-3 mr-1 animate-spin" />
            ) : (
              <Send className="h-3 w-3 mr-1" />
            )}
            Ingest Entity
          </Button>
          {lastResult && (
            <div className="text-xs text-muted-foreground">
              Upserted: {lastResult.assetsUpserted} assets
              {lastResult.errors.length > 0 && (
                <span className="text-red-400 ml-2">{lastResult.errors.length} errors</span>
              )}
            </div>
          )}
          {ingestMutation.isError && <span className="text-xs text-red-400">Ingestion failed. Try again.</span>}
        </div>
        {lastResult && lastResult.errors.length > 0 && (
          <div className="rounded-md border border-red-500/20 bg-red-500/5 p-2">
            <p className="text-[10px] font-medium text-red-400 mb-1">Ingestion Errors</p>
            {lastResult.errors.map((err, i) => (
              <p key={i} className="text-[10px] text-muted-foreground">
                {err}
              </p>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function QueryBuilderPanel({ onApplyQuery }: { onApplyQuery: (q: Record<string, unknown>) => void }) {
  const [selectedTypes, setSelectedTypes] = useState<string[]>([]);
  const [selectedEnvs, setSelectedEnvs] = useState<string[]>([]);
  const [minRisk, setMinRisk] = useState("");
  const [maxRisk, setMaxRisk] = useState("");
  const [ownerFilter, setOwnerFilter] = useState("");
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedRelTypes, setSelectedRelTypes] = useState<string[]>([]);

  const toggleArrayItem = (arr: string[], item: string): string[] =>
    arr.includes(item) ? arr.filter((x) => x !== item) : [...arr, item];

  const handleApply = () => {
    const query: Record<string, unknown> = {};
    if (selectedTypes.length > 0) query.assetTypes = selectedTypes;
    if (selectedEnvs.length > 0) query.environments = selectedEnvs;
    if (selectedRelTypes.length > 0) query.relationshipTypes = selectedRelTypes;
    if (minRisk) query.minRiskScore = parseFloat(minRisk);
    if (maxRisk) query.maxRiskScore = parseFloat(maxRisk);
    if (ownerFilter) query.ownerFilter = ownerFilter;
    if (searchTerm) query.searchTerm = searchTerm;
    onApplyQuery(query);
  };

  const handleClear = () => {
    setSelectedTypes([]);
    setSelectedEnvs([]);
    setMinRisk("");
    setMaxRisk("");
    setOwnerFilter("");
    setSearchTerm("");
    setSelectedRelTypes([]);
    onApplyQuery({});
  };

  return (
    <Card>
      <CardContent className="p-4 space-y-4">
        <div className="flex items-center gap-2 mb-2">
          <Crosshair className="h-4 w-4 text-cyan-400" />
          <h3 className="text-sm font-bold">Query Builder</h3>
        </div>
        <div className="space-y-3">
          <div>
            <label className="text-xs text-muted-foreground block mb-1">Asset Types</label>
            <div className="flex flex-wrap gap-1">
              {ASSET_TYPE_OPTIONS.map((t) => (
                <Badge
                  key={t}
                  variant={selectedTypes.includes(t) ? "default" : "outline"}
                  className="text-[10px] cursor-pointer hover:opacity-80 transition-opacity"
                  onClick={() => setSelectedTypes(toggleArrayItem(selectedTypes, t))}
                >
                  {t}
                </Badge>
              ))}
            </div>
          </div>
          <div>
            <label className="text-xs text-muted-foreground block mb-1">Environments</label>
            <div className="flex flex-wrap gap-1">
              {ENV_OPTIONS.map((e) => (
                <Badge
                  key={e}
                  variant={selectedEnvs.includes(e) ? "default" : "outline"}
                  className={`text-[10px] cursor-pointer hover:opacity-80 transition-opacity ${ENVIRONMENT_COLORS[e] || ""}`}
                  onClick={() => setSelectedEnvs(toggleArrayItem(selectedEnvs, e))}
                >
                  {e}
                </Badge>
              ))}
            </div>
          </div>
          <div>
            <label className="text-xs text-muted-foreground block mb-1">Relationship Types</label>
            <div className="flex flex-wrap gap-1">
              {RELATIONSHIP_TYPE_OPTIONS.map((r) => (
                <Badge
                  key={r}
                  variant={selectedRelTypes.includes(r) ? "default" : "outline"}
                  className="text-[10px] cursor-pointer hover:opacity-80 transition-opacity"
                  onClick={() => setSelectedRelTypes(toggleArrayItem(selectedRelTypes, r))}
                >
                  {r.replace(/_/g, " ")}
                </Badge>
              ))}
            </div>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div>
              <label className="text-xs text-muted-foreground block mb-1">Min Risk</label>
              <Input
                value={minRisk}
                onChange={(e) => setMinRisk(e.target.value)}
                type="number"
                min={0}
                max={1}
                step={0.1}
                placeholder="0.0"
                className="text-xs h-8"
              />
            </div>
            <div>
              <label className="text-xs text-muted-foreground block mb-1">Max Risk</label>
              <Input
                value={maxRisk}
                onChange={(e) => setMaxRisk(e.target.value)}
                type="number"
                min={0}
                max={1}
                step={0.1}
                placeholder="1.0"
                className="text-xs h-8"
              />
            </div>
            <div>
              <label className="text-xs text-muted-foreground block mb-1">Owner</label>
              <Input
                value={ownerFilter}
                onChange={(e) => setOwnerFilter(e.target.value)}
                placeholder="e.g. devops-team"
                className="text-xs h-8"
              />
            </div>
            <div>
              <label className="text-xs text-muted-foreground block mb-1">Search Term</label>
              <Input
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="e.g. securenexus"
                className="text-xs h-8"
              />
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button size="sm" onClick={handleApply} className="h-8">
            <Filter className="h-3 w-3 mr-1" />
            Apply Query
          </Button>
          <Button size="sm" variant="outline" onClick={handleClear} className="h-8">
            <X className="h-3 w-3 mr-1" />
            Clear
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

function PathFinderPanel({ assets }: { assets: SecurityAsset[] }) {
  const [sourceId, setSourceId] = useState("");
  const [targetId, setTargetId] = useState("");
  const [maxDepth, setMaxDepth] = useState("6");
  const [paths, setPaths] = useState<RankedAttackPath[]>([]);
  const [expandedPathIds, setExpandedPathIds] = useState<Set<string>>(new Set());

  const findPathsMutation = useMutation({
    mutationFn: async (payload: { sourceId: string; targetId: string; maxDepth: number }) => {
      const res = await apiRequest("POST", "/api/security-graph/find-paths", payload);
      return res.json() as Promise<RankedAttackPath[]>;
    },
    onSuccess: (data) => setPaths(data),
  });

  const handleFindPaths = () => {
    if (!sourceId || !targetId) return;
    findPathsMutation.mutate({
      sourceId,
      targetId,
      maxDepth: Math.max(1, Math.min(10, parseInt(maxDepth, 10) || 6)),
    });
  };

  const togglePathExpansion = useCallback((id: string) => {
    setExpandedPathIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  return (
    <div className="space-y-4">
      <Card>
        <CardContent className="p-4 space-y-4">
          <div className="flex items-center gap-2 mb-2">
            <Route className="h-4 w-4 text-cyan-400" />
            <h3 className="text-sm font-bold">Path Finder</h3>
          </div>
          <p className="text-xs text-muted-foreground">Find all attack paths between any two assets in the graph.</p>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div>
              <label className="text-xs text-muted-foreground block mb-1">Source Asset</label>
              <select
                value={sourceId}
                onChange={(e) => setSourceId(e.target.value)}
                className="w-full h-8 text-xs rounded-md border bg-background px-2"
              >
                <option value="">Select source...</option>
                {assets.map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.name} ({a.type})
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="text-xs text-muted-foreground block mb-1">Target Asset</label>
              <select
                value={targetId}
                onChange={(e) => setTargetId(e.target.value)}
                className="w-full h-8 text-xs rounded-md border bg-background px-2"
              >
                <option value="">Select target...</option>
                {assets.map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.name} ({a.type})
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="text-xs text-muted-foreground block mb-1">Max Depth (1-10)</label>
              <Input
                value={maxDepth}
                onChange={(e) => setMaxDepth(e.target.value)}
                type="number"
                min={1}
                max={10}
                className="text-xs h-8"
              />
            </div>
          </div>
          <Button
            size="sm"
            onClick={handleFindPaths}
            disabled={!sourceId || !targetId || sourceId === targetId || findPathsMutation.isPending}
            className="h-8"
          >
            {findPathsMutation.isPending ? (
              <Loader2 className="h-3 w-3 mr-1 animate-spin" />
            ) : (
              <Route className="h-3 w-3 mr-1" />
            )}
            Find Paths
          </Button>
          {sourceId === targetId && sourceId && (
            <p className="text-[10px] text-red-400">Source and target must be different.</p>
          )}
        </CardContent>
      </Card>

      {findPathsMutation.isError && (
        <Card>
          <CardContent className="p-4 text-center">
            <AlertTriangle className="h-8 w-8 text-red-400 mx-auto mb-2" />
            <p className="text-xs text-red-400">Failed to find paths. Try again.</p>
          </CardContent>
        </Card>
      )}

      {paths.length === 0 && !findPathsMutation.isPending && findPathsMutation.isSuccess && (
        <Card>
          <CardContent className="p-8 text-center">
            <Route className="h-12 w-12 text-muted-foreground mx-auto mb-3 opacity-50" />
            <p className="text-sm text-muted-foreground">No paths found between the selected assets.</p>
          </CardContent>
        </Card>
      )}

      {paths.length > 0 && (
        <div className="space-y-3">
          <p className="text-xs text-muted-foreground">{paths.length} path(s) found</p>
          {paths.map((path) => (
            <AttackPathCard
              key={path.id}
              path={path}
              isExpanded={expandedPathIds.has(path.id)}
              onToggle={() => togglePathExpansion(path.id)}
            />
          ))}
        </div>
      )}
    </div>
  );
}

export default function UnifiedSecurityGraphPage() {
  const queryClient = useQueryClient();
  const [selectedAssetId, setSelectedAssetId] = useState<string | null>(null);
  const [typeFilter, setTypeFilter] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [expandedPaths, setExpandedPaths] = useState<Set<string>>(new Set());
  const [queryFilteredData, setQueryFilteredData] = useState<SecurityGraphData | null>(null);

  const {
    data: graphData,
    isLoading,
    isError,
    refetch,
  } = useQuery<SecurityGraphData>({
    queryKey: ["/api/security-graph"],
  });

  const queryMutation = useMutation({
    mutationFn: async (query: Record<string, unknown>) => {
      const res = await apiRequest("POST", "/api/security-graph/query", query);
      return res.json() as Promise<SecurityGraphData>;
    },
    onSuccess: (data) => setQueryFilteredData(data),
  });

  const handleApplyQuery = useCallback(
    (query: Record<string, unknown>) => {
      if (Object.keys(query).length === 0) {
        setQueryFilteredData(null);
        return;
      }
      queryMutation.mutate(query);
    },
    [queryMutation],
  );

  const selectedAsset = useMemo(() => {
    if (!selectedAssetId || !graphData) return null;
    return graphData.assets.find((a) => a.id === selectedAssetId) || null;
  }, [selectedAssetId, graphData]);

  const filteredAssets = useMemo(() => {
    if (!graphData) return [];
    let result = graphData.assets;
    if (typeFilter) result = result.filter((a) => a.type === typeFilter);
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      result = result.filter(
        (a) =>
          a.name.toLowerCase().includes(q) ||
          a.subType.toLowerCase().includes(q) ||
          a.tags.some((t) => t.toLowerCase().includes(q)) ||
          (a.owner && a.owner.toLowerCase().includes(q)),
      );
    }
    return result;
  }, [graphData, typeFilter, searchQuery]);

  const togglePath = useCallback((id: string) => {
    setExpandedPaths((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  if (isLoading) {
    return (
      <div className="w-full p-4 md:p-6 space-y-6">
        <div className="flex items-center justify-between gap-4 flex-wrap">
          <div className="space-y-1">
            <Skeleton className="h-7 w-64" />
            <Skeleton className="h-4 w-96" />
          </div>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          {[1, 2, 3, 4, 5].map((i) => (
            <Card key={i}>
              <CardContent className="p-4">
                <Skeleton className="h-12 w-full" />
              </CardContent>
            </Card>
          ))}
        </div>
        <Skeleton className="h-[400px] w-full" />
      </div>
    );
  }

  if (isError || !graphData) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-center" role="alert">
        <div className="rounded-full bg-destructive/10 p-3 ring-1 ring-destructive/20 mb-3">
          <AlertTriangle className="h-6 w-6 text-destructive" />
        </div>
        <p className="text-sm font-medium">Failed to load security graph</p>
        <p className="text-xs text-muted-foreground mt-1">An error occurred while fetching data.</p>
        <Button variant="outline" size="sm" className="mt-3" onClick={() => refetch()}>
          Try Again
        </Button>
      </div>
    );
  }

  const activeData = queryFilteredData || graphData;
  const { stats, relationships, attackPaths } = activeData;

  return (
    <div className="w-full p-4 md:p-6 space-y-6">
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <div className="p-2 rounded-md bg-cyan-500/10 border border-cyan-500/20">
              <Shield className="h-5 w-5 text-cyan-400" />
            </div>
            <h1 className="text-xl font-bold" data-testid="text-page-title">
              Unified Security Graph
            </h1>
          </div>
          <p className="text-sm text-muted-foreground" data-testid="text-page-description">
            Code, cloud, identity, and data relationships with attack-path ranking
          </p>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <StatCard
          icon={Network}
          label="Total Assets"
          value={stats.totalAssets}
          color="text-cyan-400 bg-cyan-500/10 border-cyan-500/20"
          testId="stat-total-assets"
        />
        <StatCard
          icon={ExternalLink}
          label="Relationships"
          value={stats.totalRelationships}
          color="text-blue-400 bg-blue-500/10 border-blue-500/20"
          testId="stat-relationships"
        />
        <StatCard
          icon={Target}
          label="Critical Paths"
          value={stats.criticalPaths}
          color="text-red-400 bg-red-500/10 border-red-500/20"
          testId="stat-critical-paths"
        />
        <StatCard
          icon={AlertTriangle}
          label="High Risk Assets"
          value={stats.highRiskAssets}
          color="text-orange-400 bg-orange-500/10 border-orange-500/20"
          testId="stat-high-risk"
        />
        <StatCard
          icon={TrendingUp}
          label="Avg Risk"
          value={`${(stats.avgRiskScore * 100).toFixed(0)}%`}
          color="text-yellow-400 bg-yellow-500/10 border-yellow-500/20"
          testId="stat-avg-risk"
        />
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <Card>
          <CardContent className="p-3">
            <p className="text-[10px] text-muted-foreground mb-1.5">Asset Distribution</p>
            <div className="space-y-1">
              {Object.entries(stats.byType || {}).map(([type, count]) => {
                const config = ASSET_TYPE_CONFIG[type];
                return (
                  <div key={type} className="flex items-center justify-between text-xs">
                    <div className="flex items-center gap-1.5">
                      {config && <config.icon className={`h-3 w-3 ${config.color.split(" ")[0]}`} />}
                      <span className="capitalize">{config?.label || type}</span>
                    </div>
                    <span className="font-bold">{count}</span>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-3">
            <p className="text-[10px] text-muted-foreground mb-1.5">By Environment</p>
            <div className="space-y-1">
              {Object.entries(stats.byEnvironment).map(([env, count]) => (
                <div key={env} className="flex items-center justify-between text-xs">
                  <Badge variant="outline" className={`text-[10px] ${ENVIRONMENT_COLORS[env] || ""}`}>
                    {env}
                  </Badge>
                  <span className="font-bold">{count}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-3">
            <p className="text-[10px] text-muted-foreground mb-1.5">Exposure</p>
            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs">
                <span className="text-muted-foreground">Internet Exposed</span>
                <span className="font-bold text-orange-400">{stats.internetExposed}</span>
              </div>
              <div className="flex items-center justify-between text-xs">
                <span className="text-muted-foreground">Over-Privileged</span>
                <span className="font-bold text-red-400">{stats.overPrivileged}</span>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-3">
            <p className="text-[10px] text-muted-foreground mb-1.5">Attack Paths</p>
            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs">
                <span className="text-muted-foreground">Total Paths</span>
                <span className="font-bold">{attackPaths.length}</span>
              </div>
              <div className="flex items-center justify-between text-xs">
                <span className="text-muted-foreground">Critical (70%+)</span>
                <span className="font-bold text-red-400">{stats.criticalPaths}</span>
              </div>
              <div className="flex items-center justify-between text-xs">
                <span className="text-muted-foreground">Avg Hops</span>
                <span className="font-bold">
                  {attackPaths.length > 0
                    ? (attackPaths.reduce((s, p) => s + p.hopCount, 0) / attackPaths.length).toFixed(1)
                    : "0"}
                </span>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="graph" className="space-y-4">
        <div className="flex items-center justify-between gap-4 flex-wrap">
          <TabsList data-testid="tabs-security-graph">
            <TabsTrigger value="graph" data-testid="tab-graph">
              Graph View
            </TabsTrigger>
            <TabsTrigger value="assets" data-testid="tab-assets">
              Assets
            </TabsTrigger>
            <TabsTrigger value="attack-paths" data-testid="tab-attack-paths">
              Attack Paths
            </TabsTrigger>
            <TabsTrigger value="ingest" data-testid="tab-ingest">
              <Plus className="h-3 w-3 mr-1" />
              Ingest
            </TabsTrigger>
            <TabsTrigger value="query" data-testid="tab-query">
              <Crosshair className="h-3 w-3 mr-1" />
              Query
            </TabsTrigger>
            <TabsTrigger value="path-finder" data-testid="tab-path-finder">
              <Route className="h-3 w-3 mr-1" />
              Path Finder
            </TabsTrigger>
          </TabsList>

          <div className="flex items-center gap-2">
            <div className="relative">
              <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-muted-foreground" />
              <Input
                placeholder="Search assets..."
                className="pl-8 h-9 w-48 text-xs"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                data-testid="input-search"
              />
            </div>
            <div className="flex items-center gap-1">
              <Filter className="h-3.5 w-3.5 text-muted-foreground" />
              {Object.entries(ASSET_TYPE_CONFIG).map(([type, config]) => (
                <Tooltip key={type}>
                  <TooltipTrigger asChild>
                    <Button
                      variant={typeFilter === type ? "default" : "outline"}
                      size="icon"
                      className="h-7 w-7"
                      onClick={() => setTypeFilter(typeFilter === type ? null : type)}
                      aria-label={`Filter by ${config.label}`}
                    >
                      <config.icon className="h-3.5 w-3.5" />
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent>{config.label}</TooltipContent>
                </Tooltip>
              ))}
              {typeFilter && (
                <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={() => setTypeFilter(null)}>
                  <X className="h-3 w-3 mr-1" />
                  Clear
                </Button>
              )}
            </div>
          </div>
        </div>

        <TabsContent value="graph">
          <VisualGraphView
            assets={filteredAssets}
            relationships={relationships}
            onSelectAsset={setSelectedAssetId}
            selectedAssetId={selectedAssetId}
            typeFilter={typeFilter}
          />
        </TabsContent>

        <TabsContent value="assets">
          {filteredAssets.length === 0 ? (
            <Card>
              <CardContent className="p-8 text-center">
                <Network className="h-12 w-12 text-muted-foreground mx-auto mb-3 opacity-50" />
                <p className="text-sm text-muted-foreground">No assets match the current filters.</p>
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardContent className="p-0">
                <Table data-testid="table-assets">
                  <TableHeader>
                    <TableRow>
                      <TableHead>Asset</TableHead>
                      <TableHead>Type</TableHead>
                      <TableHead>Environment</TableHead>
                      <TableHead>Risk</TableHead>
                      <TableHead>Owner</TableHead>
                      <TableHead>Last Scanned</TableHead>
                      <TableHead>Tags</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredAssets.map((asset) => {
                      const config = ASSET_TYPE_CONFIG[asset.type];
                      return (
                        <TableRow
                          key={asset.id}
                          className="cursor-pointer"
                          onClick={() => setSelectedAssetId(asset.id)}
                          data-testid={`row-asset-${asset.id}`}
                        >
                          <TableCell>
                            <div className="flex items-center gap-2">
                              <div className={`p-1 rounded border ${config?.color || "bg-muted"}`}>
                                <AssetTypeIcon type={asset.type} className="h-3 w-3" />
                              </div>
                              <div>
                                <p className="text-xs font-medium">{asset.name}</p>
                                <p className="text-[10px] text-muted-foreground">{asset.subType.replace(/_/g, " ")}</p>
                              </div>
                            </div>
                          </TableCell>
                          <TableCell>
                            <Badge variant="outline" className={`text-[10px] ${config?.color || ""}`}>
                              {config?.label || asset.type}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            <Badge
                              variant="outline"
                              className={`text-[10px] ${ENVIRONMENT_COLORS[asset.environment] || ""}`}
                            >
                              {asset.environment}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            <div className="flex items-center gap-2">
                              <Progress
                                value={asset.riskScore * 100}
                                className={`h-1.5 w-16 ${riskProgressColor(asset.riskScore)}`}
                              />
                              <span className={`text-xs font-bold ${riskColor(asset.riskScore)}`}>
                                {(asset.riskScore * 100).toFixed(0)}%
                              </span>
                            </div>
                          </TableCell>
                          <TableCell>
                            <span className="text-xs text-muted-foreground">{asset.owner || "—"}</span>
                          </TableCell>
                          <TableCell>
                            <span className="text-xs text-muted-foreground">{formatTimeAgo(asset.lastScannedAt)}</span>
                          </TableCell>
                          <TableCell>
                            <div className="flex gap-1 flex-wrap">
                              {asset.tags.slice(0, 2).map((tag) => (
                                <Badge key={tag} variant="outline" className="text-[9px]">
                                  {tag}
                                </Badge>
                              ))}
                              {asset.tags.length > 2 && (
                                <Badge variant="outline" className="text-[9px]">
                                  +{asset.tags.length - 2}
                                </Badge>
                              )}
                            </div>
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="attack-paths">
          {attackPaths.length === 0 ? (
            <Card>
              <CardContent className="p-8 text-center">
                <Target className="h-12 w-12 text-muted-foreground mx-auto mb-3 opacity-50" />
                <p className="text-sm text-muted-foreground">No attack paths detected.</p>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-3">
              {attackPaths.map((path) => (
                <AttackPathCard
                  key={path.id}
                  path={path}
                  isExpanded={expandedPaths.has(path.id)}
                  onToggle={() => togglePath(path.id)}
                />
              ))}
            </div>
          )}
        </TabsContent>

        <TabsContent value="ingest">
          <IngestionPanel />
        </TabsContent>

        <TabsContent value="query">
          <div className="space-y-4">
            <QueryBuilderPanel onApplyQuery={handleApplyQuery} />
            {queryMutation.isPending && (
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <Loader2 className="h-3 w-3 animate-spin" />
                Querying graph...
              </div>
            )}
            {queryMutation.isError && (
              <Card>
                <CardContent className="p-4 text-center">
                  <AlertTriangle className="h-8 w-8 text-red-400 mx-auto mb-2" />
                  <p className="text-xs text-red-400">Query failed. Try again.</p>
                </CardContent>
              </Card>
            )}
            {queryFilteredData && (
              <Card>
                <CardContent className="p-3">
                  <p className="text-xs text-muted-foreground mb-2">
                    Query returned {queryFilteredData.assets.length} assets, {queryFilteredData.relationships.length}{" "}
                    relationships
                  </p>
                  <Button
                    variant="outline"
                    size="sm"
                    className="h-7 text-xs"
                    onClick={() => setQueryFilteredData(null)}
                  >
                    <X className="h-3 w-3 mr-1" />
                    Clear Query Results
                  </Button>
                </CardContent>
              </Card>
            )}
          </div>
        </TabsContent>

        <TabsContent value="path-finder">
          <PathFinderPanel assets={graphData.assets} />
        </TabsContent>
      </Tabs>

      {selectedAsset && (
        <AssetDetailPanel
          asset={selectedAsset}
          relationships={relationships}
          allAssets={graphData.assets}
          onClose={() => setSelectedAssetId(null)}
        />
      )}
    </div>
  );
}

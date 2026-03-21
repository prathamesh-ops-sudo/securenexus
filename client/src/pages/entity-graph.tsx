import { useState, useMemo, useCallback, useEffect, useRef } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Link } from "wouter";
import {
  Network,
  Search,
  User,
  Server,
  Globe,
  Hash,
  Mail,
  Link2,
  Terminal,
  Shield,
  AlertTriangle,
  Activity,
  Merge,
  Plus,
  Trash2,
  Loader2,
  Tag,
  Layout,
  Filter,
  Route,
  Camera,
  GitCompare,
  Code2,
  Wifi,
  Crosshair,
  Eye,
  EyeOff,
  ChevronDown,
  ChevronRight,
  Zap,
  Save,
  RotateCcw,
  ZoomIn,
  ZoomOut,
  Maximize2,
  Grid3X3,
  Circle,
  ArrowRight,
  Brain,
  X,
  Play,
  Pause,
  RefreshCw,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Progress } from "@/components/ui/progress";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
  DialogDescription,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuTrigger,
  ContextMenuSeparator,
} from "@/components/ui/context-menu";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { formatRelativeTime } from "@/components/security-badges";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { usePageTitle } from "@/hooks/use-page-title";
import type { Entity } from "@shared/schema";

// ═══════════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════════

interface GraphNode extends Entity {
  connections: number;
}

interface GraphEdge {
  source: string;
  target: string;
  weight: number;
  relationship: string;
}

interface EntityGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

interface EntityRelationship {
  relatedEntityId: string;
  relatedEntityType: string;
  relatedEntityValue: string;
  relatedEntityRiskScore: number;
  sharedAlertCount: number;
  relationship: string;
}

interface PathResult {
  found: boolean;
  path: { entityId: string; type: string; value: string; displayName: string | null; riskScore: number }[];
  edges: { source: string; target: string; relationship: string; sharedAlertCount: number }[];
  hops: number;
  allPaths: {
    path: { entityId: string; type: string; value: string; displayName: string | null; riskScore: number }[];
    edges: { source: string; target: string; relationship: string; sharedAlertCount: number }[];
    hops: number;
  }[];
}

interface SnapshotMeta {
  id: string;
  name: string;
  description: string | null;
  nodeCount: number;
  edgeCount: number;
  createdBy: string;
  createdAt: string;
}

interface SnapshotComparison {
  snapshotId: string;
  snapshotName: string;
  snapshotDate: string;
  summary: {
    nodesAdded: number;
    nodesRemoved: number;
    edgesAdded: number;
    edgesRemoved: number;
    riskChanges: number;
  };
  addedNodes: { id: string; type: string; value: string; riskScore: number }[];
  removedNodes: { id: string; type: string; value: string; riskScore: number }[];
  riskChanges: { entityId: string; value: string; type: string; oldRisk: number; newRisk: number; change: number }[];
}

interface UebaOverlay {
  overlay: Record<string, { uebaRiskScore: number; uebaRiskLevel: string; anomalyCount: number }>;
  totalScored: number;
}

interface GraphQueryResult {
  entities: {
    id: string;
    type: string;
    value: string;
    displayName: string | null;
    riskScore: number;
    alertCount: number;
    connections: number;
  }[];
  totalMatched: number;
  query: string;
}

type LayoutType = "force-directed" | "hierarchical" | "radial" | "circular" | "grid";

// ═══════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════

const ENTITY_TYPE_CONFIG: Record<
  string,
  {
    icon: typeof User;
    color: string;
    bgColor: string;
    borderColor: string;
    label: string;
    svgFill: string;
  }
> = {
  user: {
    icon: User,
    color: "text-blue-400",
    bgColor: "bg-blue-500/10",
    borderColor: "border-blue-500/20",
    label: "User",
    svgFill: "#60a5fa",
  },
  host: {
    icon: Server,
    color: "text-emerald-400",
    bgColor: "bg-emerald-500/10",
    borderColor: "border-emerald-500/20",
    label: "Host",
    svgFill: "#34d399",
  },
  ip: {
    icon: Globe,
    color: "text-purple-400",
    bgColor: "bg-purple-500/10",
    borderColor: "border-purple-500/20",
    label: "IP Address",
    svgFill: "#a78bfa",
  },
  domain: {
    icon: Globe,
    color: "text-cyan-400",
    bgColor: "bg-cyan-500/10",
    borderColor: "border-cyan-500/20",
    label: "Domain",
    svgFill: "#22d3ee",
  },
  file_hash: {
    icon: Hash,
    color: "text-orange-400",
    bgColor: "bg-orange-500/10",
    borderColor: "border-orange-500/20",
    label: "File Hash",
    svgFill: "#fb923c",
  },
  email: {
    icon: Mail,
    color: "text-pink-400",
    bgColor: "bg-pink-500/10",
    borderColor: "border-pink-500/20",
    label: "Email",
    svgFill: "#f472b6",
  },
  url: {
    icon: Link2,
    color: "text-yellow-400",
    bgColor: "bg-yellow-500/10",
    borderColor: "border-yellow-500/20",
    label: "URL",
    svgFill: "#facc15",
  },
  process: {
    icon: Terminal,
    color: "text-red-400",
    bgColor: "bg-red-500/10",
    borderColor: "border-red-500/20",
    label: "Process",
    svgFill: "#f87171",
  },
};

const RELATIONSHIP_LABELS: Record<string, string> = {
  attack_path: "Attack Path",
  uses: "Uses",
  targeted_by: "Targeted By",
  associated_with: "Associated",
  co_occurred: "Co-occurred",
};

const LAYOUT_OPTIONS: { value: LayoutType; label: string; icon: typeof Layout }[] = [
  { value: "force-directed", label: "Force-Directed", icon: Network },
  { value: "hierarchical", label: "Hierarchical", icon: GitCompare },
  { value: "radial", label: "Radial", icon: Circle },
  { value: "circular", label: "Circular", icon: RotateCcw },
  { value: "grid", label: "Grid", icon: Grid3X3 },
];

const QUERY_EXAMPLES = [
  "FIND User WHERE riskScore > 60",
  "FIND Host WHERE alertCount >= 5",
  "FIND IP WHERE riskScore > 80 CONNECTED_TO Host",
  'FIND Domain WHERE value CONTAINS "malware"',
  "FIND User WHERE lastSeen < 7d",
];

// ═══════════════════════════════════════════════════════════════════════════════
// Utility Functions
// ═══════════════════════════════════════════════════════════════════════════════

function getRiskColor(risk: number): string {
  if (risk >= 0.8) return "text-red-400";
  if (risk >= 0.6) return "text-orange-400";
  if (risk >= 0.4) return "text-yellow-400";
  return "text-emerald-400";
}

function getRiskBgColor(risk: number): string {
  if (risk >= 0.8) return "bg-red-500/10 border-red-500/20";
  if (risk >= 0.6) return "bg-orange-500/10 border-orange-500/20";
  if (risk >= 0.4) return "bg-yellow-500/10 border-yellow-500/20";
  return "bg-emerald-500/10 border-emerald-500/20";
}

function getRiskLabel(risk: number): string {
  if (risk >= 0.8) return "Critical";
  if (risk >= 0.6) return "High";
  if (risk >= 0.4) return "Medium";
  return "Low";
}

function getRiskSvgColor(risk: number): string {
  if (risk >= 0.8) return "#ef4444";
  if (risk >= 0.6) return "#f97316";
  if (risk >= 0.4) return "#eab308";
  return "#22c55e";
}

function EntityTypeIcon({ type, className }: { type: string; className?: string }) {
  const config = ENTITY_TYPE_CONFIG[type];
  if (!config) return <Network className={className} />;
  const IconComp = config.icon;
  return <IconComp className={`${config.color} ${className || ""}`} />;
}

// ═══════════════════════════════════════════════════════════════════════════════
// 11.2: Layout Algorithms
// ═══════════════════════════════════════════════════════════════════════════════

function computeLayout(
  nodes: GraphNode[],
  edges: GraphEdge[],
  layoutType: LayoutType,
  width: number,
  height: number,
): Map<string, { x: number; y: number }> {
  const positions = new Map<string, { x: number; y: number }>();
  if (nodes.length === 0) return positions;

  const centerX = width / 2;
  const centerY = height / 2;

  switch (layoutType) {
    case "force-directed": {
      // Type-clustered force-directed layout
      const sorted = [...nodes].sort((a, b) => (b.riskScore || 0) - (a.riskScore || 0));
      const typeGroups: Record<string, GraphNode[]> = {};
      for (const node of sorted) {
        if (!typeGroups[node.type]) typeGroups[node.type] = [];
        typeGroups[node.type].push(node);
      }
      const types = Object.keys(typeGroups);
      const angleStep = (2 * Math.PI) / Math.max(types.length, 1);

      types.forEach((type, typeIdx) => {
        const baseAngle = typeIdx * angleStep - Math.PI / 2;
        const group = typeGroups[type];
        const clusterRadius = 120 + group.length * 8;
        group.forEach((node, nodeIdx) => {
          const nodeAngle = baseAngle + (nodeIdx / Math.max(group.length, 1) - 0.5) * 0.8;
          const r = clusterRadius * (0.6 + (node.riskScore || 0) * 0.4);
          positions.set(node.id, {
            x: centerX + r * Math.cos(nodeAngle),
            y: centerY + r * Math.sin(nodeAngle),
          });
        });
      });
      break;
    }

    case "hierarchical": {
      // Sort by risk score to create hierarchy levels
      const sorted = [...nodes].sort((a, b) => (b.riskScore || 0) - (a.riskScore || 0));
      const levels = [
        sorted.filter((n) => (n.riskScore || 0) >= 0.8),
        sorted.filter((n) => (n.riskScore || 0) >= 0.6 && (n.riskScore || 0) < 0.8),
        sorted.filter((n) => (n.riskScore || 0) >= 0.4 && (n.riskScore || 0) < 0.6),
        sorted.filter((n) => (n.riskScore || 0) < 0.4),
      ].filter((l) => l.length > 0);

      const levelHeight = height / (levels.length + 1);
      levels.forEach((level, li) => {
        const y = (li + 1) * levelHeight;
        const spacing = width / (level.length + 1);
        level.forEach((node, ni) => {
          positions.set(node.id, { x: (ni + 1) * spacing, y });
        });
      });
      break;
    }

    case "radial": {
      // Radial layout: high risk at center, lower risk further out
      const sorted = [...nodes].sort((a, b) => (b.riskScore || 0) - (a.riskScore || 0));
      const rings = [
        sorted.filter((n) => (n.riskScore || 0) >= 0.7),
        sorted.filter((n) => (n.riskScore || 0) >= 0.4 && (n.riskScore || 0) < 0.7),
        sorted.filter((n) => (n.riskScore || 0) < 0.4),
      ].filter((r) => r.length > 0);

      const maxRadius = Math.min(width, height) * 0.4;
      rings.forEach((ring, ri) => {
        const radius = ri === 0 ? maxRadius * 0.2 : maxRadius * (0.3 + (ri / rings.length) * 0.7);
        ring.forEach((node, ni) => {
          const angle = (ni / ring.length) * 2 * Math.PI - Math.PI / 2;
          positions.set(node.id, {
            x: centerX + radius * Math.cos(angle),
            y: centerY + radius * Math.sin(angle),
          });
        });
      });
      break;
    }

    case "circular": {
      // Simple circle layout
      const radius = Math.min(width, height) * 0.38;
      nodes.forEach((node, i) => {
        const angle = (i / nodes.length) * 2 * Math.PI - Math.PI / 2;
        positions.set(node.id, {
          x: centerX + radius * Math.cos(angle),
          y: centerY + radius * Math.sin(angle),
        });
      });
      break;
    }

    case "grid": {
      // Grid layout sorted by type then risk
      const sorted = [...nodes].sort((a, b) => {
        if (a.type !== b.type) return a.type.localeCompare(b.type);
        return (b.riskScore || 0) - (a.riskScore || 0);
      });
      const cols = Math.ceil(Math.sqrt(sorted.length));
      const cellW = width / (cols + 1);
      const cellH = height / (Math.ceil(sorted.length / cols) + 1);
      sorted.forEach((node, i) => {
        const col = i % cols;
        const row = Math.floor(i / cols);
        positions.set(node.id, {
          x: (col + 1) * cellW,
          y: (row + 1) * cellH,
        });
      });
      break;
    }
  }

  return positions;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Sub-Components
// ═══════════════════════════════════════════════════════════════════════════════

function EntityGraphStats({ graph }: { graph: EntityGraph }) {
  const stats = useMemo(() => {
    const typeCounts: Record<string, number> = {};
    let highRiskCount = 0;
    let totalRisk = 0;

    for (const node of graph.nodes) {
      typeCounts[node.type] = (typeCounts[node.type] || 0) + 1;
      if ((node.riskScore || 0) >= 0.7) highRiskCount++;
      totalRisk += node.riskScore || 0;
    }

    return {
      totalEntities: graph.nodes.length,
      totalEdges: graph.edges.length,
      highRiskCount,
      avgRisk: graph.nodes.length > 0 ? totalRisk / graph.nodes.length : 0,
      typeCounts,
    };
  }, [graph]);

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
      <Card data-testid="stat-total-entities">
        <CardContent className="p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-md bg-blue-500/10 border border-blue-500/20">
              <Network className="h-4 w-4 text-blue-400" />
            </div>
            <div>
              <p className="text-2xl font-bold">{stats.totalEntities}</p>
              <p className="text-xs text-muted-foreground">Total Entities</p>
            </div>
          </div>
        </CardContent>
      </Card>
      <Card data-testid="stat-relationships">
        <CardContent className="p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-md bg-purple-500/10 border border-purple-500/20">
              <Activity className="h-4 w-4 text-purple-400" />
            </div>
            <div>
              <p className="text-2xl font-bold">{stats.totalEdges}</p>
              <p className="text-xs text-muted-foreground">Relationships</p>
            </div>
          </div>
        </CardContent>
      </Card>
      <Card data-testid="stat-high-risk">
        <CardContent className="p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-md bg-red-500/10 border border-red-500/20">
              <AlertTriangle className="h-4 w-4 text-red-400" />
            </div>
            <div>
              <p className="text-2xl font-bold">{stats.highRiskCount}</p>
              <p className="text-xs text-muted-foreground">High Risk</p>
            </div>
          </div>
        </CardContent>
      </Card>
      <Card data-testid="stat-avg-risk">
        <CardContent className="p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-md bg-yellow-500/10 border border-yellow-500/20">
              <Shield className="h-4 w-4 text-yellow-400" />
            </div>
            <div>
              <p className="text-2xl font-bold">{(stats.avgRisk * 100).toFixed(0)}%</p>
              <p className="text-xs text-muted-foreground">Avg Risk Score</p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function EntityCard({
  entity,
  onSelect,
  isSelected,
}: {
  entity: GraphNode;
  onSelect: (id: string) => void;
  isSelected: boolean;
}) {
  const config = ENTITY_TYPE_CONFIG[entity.type] || ENTITY_TYPE_CONFIG.ip;
  const risk = entity.riskScore || 0;

  return (
    <Card
      className={`hover-elevate active-elevate-2 cursor-pointer smooth-all ${isSelected ? "ring-1 ring-red-500/50" : ""}`}
      onClick={() => onSelect(entity.id)}
      data-testid={`entity-card-${entity.id}`}
    >
      <CardContent className="p-3">
        <div className="flex items-start gap-3">
          <div className={`p-2 rounded-md ${config.bgColor} border ${config.borderColor} shrink-0`}>
            <EntityTypeIcon type={entity.type} className="h-4 w-4" />
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-sm font-mono font-medium truncate" data-testid={`entity-value-${entity.id}`}>
                {entity.displayName || entity.value}
              </span>
              <Badge
                variant="outline"
                className={`text-[9px] shrink-0 ${config.bgColor} ${config.color} border ${config.borderColor}`}
              >
                {config.label}
              </Badge>
            </div>
            {entity.displayName && entity.displayName !== entity.value && (
              <p className="text-xs text-muted-foreground font-mono truncate mt-0.5">{entity.value}</p>
            )}
            <div className="flex items-center gap-3 mt-2 flex-wrap">
              <div className="flex items-center gap-1.5">
                <span className={`text-xs font-semibold ${getRiskColor(risk)}`}>{(risk * 100).toFixed(0)}%</span>
                <Progress value={risk * 100} className="h-1 w-12" />
              </div>
              <span className="text-[10px] text-muted-foreground">{entity.alertCount || 0} alerts</span>
              <span className="text-[10px] text-muted-foreground">{entity.connections || 0} links</span>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Entity Alias Manager (unchanged)
// ═══════════════════════════════════════════════════════════════════════════════

interface EntityAlias {
  id: string;
  aliasType: string;
  aliasValue: string;
  source: string;
}

const ALIAS_TYPES = ["ip", "domain", "hostname", "email", "url", "file_hash", "user", "process"];

function EntityAliasManager({ entityId }: { entityId: string }) {
  const { toast } = useToast();
  const [showAddForm, setShowAddForm] = useState(false);
  const [aliasType, setAliasType] = useState("");
  const [aliasValue, setAliasValue] = useState("");

  const { data: aliases, isLoading } = useQuery<EntityAlias[]>({
    queryKey: ["/api/entities", entityId, "aliases"],
    enabled: !!entityId,
  });

  const addAliasMutation = useMutation({
    mutationFn: async (data: { aliasType: string; aliasValue: string }) => {
      const res = await apiRequest("POST", `/api/entities/${encodeURIComponent(entityId)}/aliases`, {
        aliasType: data.aliasType.trim(),
        aliasValue: data.aliasValue.trim(),
        source: "manual",
      });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/entities", entityId, "aliases"] });
      toast({ title: "Alias added", description: "Entity alias created successfully" });
      setAliasType("");
      setAliasValue("");
      setShowAddForm(false);
    },
    onError: (error: Error) => {
      toast({ title: "Failed to add alias", description: error.message, variant: "destructive" });
    },
  });

  const handleAddAlias = () => {
    const trimmedType = aliasType.trim();
    const trimmedValue = aliasValue.trim();
    if (!trimmedType || !trimmedValue) return;
    if (trimmedValue.length > 500) {
      toast({
        title: "Validation error",
        description: "Alias value must be under 500 characters",
        variant: "destructive",
      });
      return;
    }
    addAliasMutation.mutate({ aliasType: trimmedType, aliasValue: trimmedValue });
  };

  return (
    <Card data-testid="entity-aliases-panel">
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm flex items-center gap-1.5">
            <Tag className="h-3.5 w-3.5 text-muted-foreground" aria-hidden="true" />
            Aliases ({aliases?.length || 0})
          </CardTitle>
          <Button
            variant="ghost"
            size="sm"
            className="h-6 px-2 text-[10px]"
            onClick={() => setShowAddForm(!showAddForm)}
            data-testid="button-toggle-add-alias"
            aria-label="Add alias"
          >
            <Plus className="h-3 w-3 mr-1" />
            Add
          </Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-2">
        {showAddForm && (
          <div
            className="space-y-2 p-2 rounded-md border border-dashed border-cyan-500/30 bg-cyan-500/5"
            data-testid="add-alias-form"
          >
            <div>
              <Label className="text-[10px] text-muted-foreground">Type</Label>
              <Select value={aliasType} onValueChange={setAliasType}>
                <SelectTrigger className="h-7 text-xs" data-testid="select-alias-type">
                  <SelectValue placeholder="Select type" />
                </SelectTrigger>
                <SelectContent>
                  {ALIAS_TYPES.map((t) => (
                    <SelectItem key={t} value={t}>
                      {ENTITY_TYPE_CONFIG[t]?.label || t}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label className="text-[10px] text-muted-foreground">Value</Label>
              <Input
                value={aliasValue}
                onChange={(e) => setAliasValue(e.target.value)}
                placeholder="e.g. 192.168.1.100"
                className="h-7 text-xs"
                maxLength={500}
                data-testid="input-alias-value"
              />
            </div>
            <div className="flex gap-1.5">
              <Button
                size="sm"
                className="h-6 text-[10px] flex-1"
                onClick={handleAddAlias}
                disabled={!aliasType.trim() || !aliasValue.trim() || addAliasMutation.isPending}
                data-testid="button-submit-alias"
              >
                {addAliasMutation.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : "Add Alias"}
              </Button>
              <Button
                variant="ghost"
                size="sm"
                className="h-6 text-[10px]"
                onClick={() => {
                  setShowAddForm(false);
                  setAliasType("");
                  setAliasValue("");
                }}
              >
                Cancel
              </Button>
            </div>
          </div>
        )}
        {isLoading ? (
          <div className="space-y-1.5">
            <Skeleton className="h-7 w-full" />
            <Skeleton className="h-7 w-full" />
          </div>
        ) : aliases && aliases.length > 0 ? (
          <div className="space-y-1.5">
            {aliases.map((alias) => (
              <div key={alias.id} className="flex items-center justify-between gap-2 text-xs p-1.5 rounded bg-muted/20">
                <span className="font-mono truncate flex-1">{alias.aliasValue}</span>
                <Badge variant="outline" className="text-[9px] shrink-0">
                  {alias.aliasType}
                </Badge>
                <Badge variant="secondary" className="text-[8px] shrink-0 opacity-60">
                  {alias.source}
                </Badge>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-[10px] text-muted-foreground text-center py-2">
            No aliases. Add one to link alternate identifiers.
          </p>
        )}
      </CardContent>
    </Card>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Entity Merge Dialog (unchanged)
// ═══════════════════════════════════════════════════════════════════════════════

function EntityMergeDialog({
  open,
  onOpenChange,
  allNodes,
  selectedEntityId,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  allNodes: GraphNode[];
  selectedEntityId: string | null;
}) {
  const { toast } = useToast();
  const [targetId, setTargetId] = useState("");
  const [sourceId, setSourceId] = useState("");
  const [confirmText, setConfirmText] = useState("");
  const [mergeSearch, setMergeSearch] = useState("");

  useEffect(() => {
    if (open) {
      setTargetId(selectedEntityId || "");
      setSourceId("");
      setConfirmText("");
      setMergeSearch("");
    }
  }, [open, selectedEntityId]);

  const mergeMutation = useMutation({
    mutationFn: async (data: { targetId: string; sourceId: string }) => {
      const res = await apiRequest("POST", "/api/entities/merge", data);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/entity-graph"] });
      queryClient.invalidateQueries({ queryKey: ["/api/entities"] });
      toast({ title: "Entities merged", description: "Source entity absorbed into target successfully" });
      onOpenChange(false);
    },
    onError: (error: Error) => {
      toast({ title: "Merge failed", description: error.message, variant: "destructive" });
    },
  });

  const suggestions = useMemo(() => {
    if (!selectedEntityId || allNodes.length < 2) return [];
    const selected = allNodes.find((n) => n.id === selectedEntityId);
    if (!selected) return [];
    return allNodes
      .filter((n) => {
        if (n.id === selectedEntityId) return false;
        if (n.type !== selected.type) return false;
        const selVal = (selected.displayName || selected.value).toLowerCase();
        const nVal = (n.displayName || n.value).toLowerCase();
        return (
          selVal.includes(nVal.substring(0, Math.min(8, nVal.length))) ||
          nVal.includes(selVal.substring(0, Math.min(8, selVal.length)))
        );
      })
      .slice(0, 5);
  }, [allNodes, selectedEntityId]);

  const filteredNodes = useMemo(() => {
    if (!mergeSearch.trim()) return allNodes.slice(0, 20);
    const q = mergeSearch.toLowerCase();
    return allNodes
      .filter((n) => n.value.toLowerCase().includes(q) || (n.displayName || "").toLowerCase().includes(q))
      .slice(0, 20);
  }, [allNodes, mergeSearch]);

  const targetEntity = allNodes.find((n) => n.id === targetId);
  const sourceEntity = allNodes.find((n) => n.id === sourceId);
  const canMerge = targetId && sourceId && targetId !== sourceId && confirmText === "MERGE";

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Merge className="h-4 w-4 text-cyan-400" />
            Merge Entities
          </DialogTitle>
          <DialogDescription>
            Merge a source entity into a target. The source will be deleted and its alerts, aliases, and relationships
            transferred to the target.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          {suggestions.length > 0 && (
            <div className="space-y-1.5">
              <p className="text-[10px] text-muted-foreground uppercase tracking-wider font-semibold">
                Merge Suggestions
              </p>
              <div className="space-y-1">
                {suggestions.map((s) => {
                  const cfg = ENTITY_TYPE_CONFIG[s.type] || ENTITY_TYPE_CONFIG.ip;
                  return (
                    <div
                      key={s.id}
                      className="flex items-center gap-2 text-xs p-2 rounded-md border border-dashed border-amber-500/30 bg-amber-500/5 cursor-pointer hover:bg-amber-500/10 transition-colors"
                      onClick={() => {
                        setSourceId(s.id);
                        setTargetId(selectedEntityId || "");
                      }}
                      data-testid={`merge-suggestion-${s.id}`}
                    >
                      <EntityTypeIcon type={s.type} className="h-3.5 w-3.5 shrink-0" />
                      <span className="font-mono truncate flex-1">{s.displayName || s.value}</span>
                      <Badge variant="outline" className={`text-[8px] ${cfg.bgColor} ${cfg.color}`}>
                        {cfg.label}
                      </Badge>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
          <div className="space-y-2">
            <Label className="text-xs font-medium">Target Entity (keep)</Label>
            <div className="relative">
              <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3 w-3 text-muted-foreground" />
              <Input
                value={mergeSearch}
                onChange={(e) => setMergeSearch(e.target.value)}
                placeholder="Search entities..."
                className="h-8 text-xs pl-7"
              />
            </div>
            <div className="max-h-32 overflow-y-auto space-y-1 border rounded-md p-1.5">
              {filteredNodes.map((n) => (
                <div
                  key={`target-${n.id}`}
                  className={`flex items-center gap-2 text-xs p-1.5 rounded cursor-pointer transition-colors ${targetId === n.id ? "bg-cyan-500/15 border border-cyan-500/30" : "hover:bg-muted/40"}`}
                  onClick={() => setTargetId(n.id)}
                  data-testid={`merge-target-${n.id}`}
                >
                  <EntityTypeIcon type={n.type} className="h-3 w-3 shrink-0" />
                  <span className="font-mono truncate">{n.displayName || n.value}</span>
                </div>
              ))}
            </div>
            {targetEntity && (
              <div className="flex items-center gap-2 text-xs p-2 rounded-md bg-cyan-500/10 border border-cyan-500/20">
                <EntityTypeIcon type={targetEntity.type} className="h-3.5 w-3.5" />
                <span className="font-mono font-medium">{targetEntity.displayName || targetEntity.value}</span>
                <Badge variant="outline" className="text-[8px] ml-auto">
                  Target
                </Badge>
              </div>
            )}
          </div>
          <div className="space-y-2">
            <Label className="text-xs font-medium">Source Entity (will be deleted)</Label>
            <div className="max-h-32 overflow-y-auto space-y-1 border rounded-md p-1.5">
              {filteredNodes
                .filter((n) => n.id !== targetId)
                .map((n) => (
                  <div
                    key={`source-${n.id}`}
                    className={`flex items-center gap-2 text-xs p-1.5 rounded cursor-pointer transition-colors ${sourceId === n.id ? "bg-red-500/15 border border-red-500/30" : "hover:bg-muted/40"}`}
                    onClick={() => setSourceId(n.id)}
                    data-testid={`merge-source-${n.id}`}
                  >
                    <EntityTypeIcon type={n.type} className="h-3 w-3 shrink-0" />
                    <span className="font-mono truncate">{n.displayName || n.value}</span>
                  </div>
                ))}
            </div>
            {sourceEntity && (
              <div className="flex items-center gap-2 text-xs p-2 rounded-md bg-red-500/10 border border-red-500/20">
                <EntityTypeIcon type={sourceEntity.type} className="h-3.5 w-3.5" />
                <span className="font-mono font-medium">{sourceEntity.displayName || sourceEntity.value}</span>
                <Badge variant="destructive" className="text-[8px] ml-auto">
                  Source (deleted)
                </Badge>
              </div>
            )}
          </div>
          {targetId && sourceId && targetId !== sourceId && (
            <div className="space-y-2 p-3 rounded-md border border-destructive/30 bg-destructive/5">
              <div className="flex items-center gap-2 text-xs">
                <AlertTriangle className="h-3.5 w-3.5 text-destructive shrink-0" />
                <span className="font-medium text-destructive">This action is irreversible</span>
              </div>
              <p className="text-[10px] text-muted-foreground">
                All alerts, aliases, and relationships from the source entity will be transferred to the target.
              </p>
              <div>
                <Label className="text-[10px] text-muted-foreground">
                  Type <span className="font-bold text-foreground">MERGE</span> to confirm
                </Label>
                <Input
                  value={confirmText}
                  onChange={(e) => setConfirmText(e.target.value)}
                  placeholder="Type MERGE"
                  className="h-7 text-xs mt-1"
                  data-testid="input-merge-confirm"
                />
              </div>
            </div>
          )}
        </div>
        <DialogFooter>
          <Button variant="outline" size="sm" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            variant="destructive"
            size="sm"
            onClick={() => mergeMutation.mutate({ targetId, sourceId })}
            disabled={!canMerge || mergeMutation.isPending}
            data-testid="button-confirm-merge"
          >
            {mergeMutation.isPending ? (
              <>
                <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />
                Merging...
              </>
            ) : (
              <>
                <Merge className="h-3.5 w-3.5 mr-1.5" />
                Merge Entities
              </>
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Entity Detail Panel (unchanged)
// ═══════════════════════════════════════════════════════════════════════════════

function EntityDetailPanel({ entityId, allNodes }: { entityId: string; allNodes: GraphNode[] }) {
  const { toast } = useToast();
  const [showMergeDialog, setShowMergeDialog] = useState(false);

  const {
    data: entity,
    isLoading: entityLoading,
    isError: _entityError,
    refetch: _refetchEntity,
  } = useQuery<Entity>({
    queryKey: ["/api/entities", entityId],
    enabled: !!entityId,
  });

  const {
    data: relationships,
    isLoading: relLoading,
    isError: _relError,
    refetch: _refetchRelationships,
  } = useQuery<EntityRelationship[]>({
    queryKey: ["/api/entities", entityId, "relationships"],
    enabled: !!entityId,
  });

  const { data: entityAlerts } = useQuery<{ id: string; title: string; severity: string }[]>({
    queryKey: ["/api/entities", entityId, "alerts"],
    enabled: !!entityId,
  });

  if (entityLoading || relLoading) {
    return (
      <Card>
        <CardContent className="p-4 space-y-3">
          <Skeleton className="h-6 w-48" />
          <Skeleton className="h-4 w-32" />
          <Skeleton className="h-20 w-full" />
        </CardContent>
      </Card>
    );
  }

  if (!entity) return null;

  const config = ENTITY_TYPE_CONFIG[entity.type] || ENTITY_TYPE_CONFIG.ip;
  const risk = entity.riskScore || 0;

  return (
    <div className="space-y-3">
      <Card data-testid="entity-detail-panel">
        <CardHeader className="pb-3">
          <div className="flex items-center gap-3">
            <div className={`p-2.5 rounded-md ${config.bgColor} border ${config.borderColor}`}>
              <EntityTypeIcon type={entity.type} className="h-5 w-5" />
            </div>
            <div className="min-w-0 flex-1">
              <CardTitle className="text-base font-mono truncate">{entity.displayName || entity.value}</CardTitle>
              <p className="text-xs text-muted-foreground mt-0.5">{config.label}</p>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <div className={`p-2.5 rounded-md border ${getRiskBgColor(risk)}`}>
              <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Risk Score</p>
              <div className="flex items-center gap-2 mt-1">
                <span className={`text-lg font-bold ${getRiskColor(risk)}`}>{(risk * 100).toFixed(0)}%</span>
                <Badge variant="outline" className={`text-[9px] ${getRiskBgColor(risk)}`}>
                  {getRiskLabel(risk)}
                </Badge>
              </div>
            </div>
            <div className="p-2.5 rounded-md border bg-muted/30">
              <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Alert Count</p>
              <p className="text-lg font-bold mt-1">{entity.alertCount || 0}</p>
            </div>
          </div>
          <div className="space-y-1.5">
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Timeline</p>
            <div className="text-xs space-y-1">
              <div className="flex justify-between">
                <span className="text-muted-foreground">First Seen</span>
                <span>{formatRelativeTime(entity.firstSeenAt)}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Last Seen</span>
                <span>{formatRelativeTime(entity.lastSeenAt)}</span>
              </div>
            </div>
          </div>
          {entity.value !== (entity.displayName || entity.value) && (
            <div className="space-y-1.5">
              <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Raw Value</p>
              <p className="text-xs font-mono break-all bg-muted/30 p-2 rounded-md">{entity.value}</p>
            </div>
          )}
          <Button
            variant="outline"
            size="sm"
            className="w-full text-xs"
            onClick={() => setShowMergeDialog(true)}
            data-testid="button-open-merge"
          >
            <Merge className="h-3.5 w-3.5 mr-1.5" />
            Merge with Another Entity
          </Button>
        </CardContent>
      </Card>

      <EntityAliasManager entityId={entityId} />

      {relationships && relationships.length > 0 && (
        <Card data-testid="entity-relationships-panel">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Relationships ({relationships.length})</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-1.5 max-h-64 overflow-y-auto">
              {relationships.slice(0, 20).map((rel) => (
                <div
                  key={rel.relatedEntityId}
                  className="flex items-center gap-2 text-xs p-2 rounded-md bg-muted/20 hover-elevate"
                  data-testid={`relationship-${rel.relatedEntityId}`}
                >
                  <EntityTypeIcon type={rel.relatedEntityType} className="h-3.5 w-3.5 shrink-0" />
                  <span className="font-mono truncate flex-1">{rel.relatedEntityValue}</span>
                  <Badge variant="outline" className="text-[9px] shrink-0">
                    {RELATIONSHIP_LABELS[rel.relationship] || rel.relationship}
                  </Badge>
                  <span className="text-muted-foreground shrink-0">{rel.sharedAlertCount}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {entityAlerts && entityAlerts.length > 0 && (
        <Card data-testid="entity-alerts-panel">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Linked Alerts ({entityAlerts.length})</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-1.5 max-h-48 overflow-y-auto">
              {entityAlerts.slice(0, 10).map((alert) => (
                <Link key={alert.id} href={`/alerts/${alert.id}`}>
                  <div className="flex items-center gap-2 text-xs p-2 rounded-md bg-muted/20 hover-elevate cursor-pointer">
                    <AlertTriangle className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                    <span className="truncate flex-1">{alert.title}</span>
                    <span
                      className={`text-[9px] font-medium uppercase ${alert.severity === "critical" ? "text-red-400" : alert.severity === "high" ? "text-orange-400" : alert.severity === "medium" ? "text-yellow-400" : "text-emerald-400"}`}
                    >
                      {alert.severity}
                    </span>
                  </div>
                </Link>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      <EntityMergeDialog
        open={showMergeDialog}
        onOpenChange={setShowMergeDialog}
        allNodes={allNodes}
        selectedEntityId={entityId}
      />
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// 11.1: Canvas-based graph rendering with level-of-detail + zoom/pan
// 11.2: Multiple layout algorithms
// 11.9: UEBA anomaly overlay (pulsing nodes)
// ═══════════════════════════════════════════════════════════════════════════════

function VisualGraph({
  graph,
  selectedId,
  onSelectEntity,
  layoutType,
  uebaOverlay,
  pathHighlight,
  visibleNodeTypes,
  visibleEdgeTypes,
  onContextMenu,
}: {
  graph: EntityGraph;
  selectedId: string | null;
  onSelectEntity: (id: string) => void;
  layoutType: LayoutType;
  uebaOverlay?: UebaOverlay | null;
  pathHighlight?: Set<string> | null;
  visibleNodeTypes: Set<string>;
  visibleEdgeTypes: Set<string>;
  onContextMenu?: (entityId: string, x: number, y: number) => void;
}) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const animFrameRef = useRef<number>(0);
  const pulseRef = useRef(0);

  const WIDTH = 800;
  const HEIGHT = 500;

  // Filter nodes/edges by visibility
  const visibleNodes = useMemo(() => {
    return graph.nodes.filter((n) => visibleNodeTypes.has(n.type));
  }, [graph.nodes, visibleNodeTypes]);

  const visibleEdges = useMemo(() => {
    const nodeIdSet = new Set(visibleNodes.map((n) => n.id));
    return graph.edges.filter(
      (e) => nodeIdSet.has(e.source) && nodeIdSet.has(e.target) && visibleEdgeTypes.has(e.relationship),
    );
  }, [graph.edges, visibleNodes, visibleEdgeTypes]);

  const layout = useMemo(() => {
    return computeLayout(visibleNodes, visibleEdges, layoutType, WIDTH, HEIGHT);
  }, [visibleNodes, visibleEdges, layoutType]);

  // 11.1: Level-of-detail — cluster nodes when zoomed out with many nodes
  const useClusterMode = visibleNodes.length > 100 && zoom < 0.6;

  const clusters = useMemo(() => {
    if (!useClusterMode) return null;
    const typeGroups: Record<string, { nodes: GraphNode[]; cx: number; cy: number; count: number }> = {};
    for (const node of visibleNodes) {
      if (!typeGroups[node.type]) typeGroups[node.type] = { nodes: [], cx: 0, cy: 0, count: 0 };
      typeGroups[node.type].nodes.push(node);
      const pos = layout.get(node.id);
      if (pos) {
        typeGroups[node.type].cx += pos.x;
        typeGroups[node.type].cy += pos.y;
        typeGroups[node.type].count++;
      }
    }
    for (const key of Object.keys(typeGroups)) {
      if (typeGroups[key].count > 0) {
        typeGroups[key].cx /= typeGroups[key].count;
        typeGroups[key].cy /= typeGroups[key].count;
      }
    }
    return typeGroups;
  }, [useClusterMode, visibleNodes, layout]);

  // 11.1: Canvas rendering for performance with large datasets
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const dpr = window.devicePixelRatio || 1;
    canvas.width = WIDTH * dpr;
    canvas.height = HEIGHT * dpr;
    ctx.scale(dpr, dpr);

    const render = () => {
      pulseRef.current = (pulseRef.current + 0.02) % (2 * Math.PI);
      const pulseScale = 0.5 + Math.sin(pulseRef.current) * 0.5;

      ctx.clearRect(0, 0, WIDTH, HEIGHT);
      ctx.save();
      ctx.translate(pan.x, pan.y);
      ctx.scale(zoom, zoom);

      if (useClusterMode && clusters) {
        // Render clusters instead of individual nodes
        for (const [type, cluster] of Object.entries(clusters)) {
          const config = ENTITY_TYPE_CONFIG[type];
          const fill = config?.svgFill || "#888";
          const radius = 15 + Math.sqrt(cluster.count) * 5;
          ctx.beginPath();
          ctx.arc(cluster.cx, cluster.cy, radius, 0, Math.PI * 2);
          ctx.fillStyle = fill + "30";
          ctx.fill();
          ctx.strokeStyle = fill;
          ctx.lineWidth = 2;
          ctx.stroke();
          ctx.fillStyle = "#e5e7eb";
          ctx.font = "bold 11px system-ui";
          ctx.textAlign = "center";
          ctx.fillText(`${config?.label || type} (${cluster.count})`, cluster.cx, cluster.cy + 4);
        }
      } else {
        // Render edges
        for (const edge of visibleEdges) {
          const from = layout.get(edge.source);
          const to = layout.get(edge.target);
          if (!from || !to) continue;

          const isHighlighted = selectedId === edge.source || selectedId === edge.target;
          const isPathEdge = pathHighlight && pathHighlight.has(edge.source) && pathHighlight.has(edge.target);

          ctx.beginPath();
          ctx.moveTo(from.x, from.y);
          ctx.lineTo(to.x, to.y);

          if (isPathEdge) {
            ctx.strokeStyle = "#f59e0b";
            ctx.lineWidth = 3;
            ctx.globalAlpha = 0.9;
          } else if (isHighlighted) {
            ctx.strokeStyle = "#ef4444";
            ctx.lineWidth = 1.5;
            ctx.globalAlpha = 0.8;
          } else {
            ctx.strokeStyle = "#374151";
            ctx.lineWidth = 0.5 + Math.min(edge.weight, 3) * 0.3;
            ctx.globalAlpha = selectedId ? 0.1 : 0.25;
          }

          ctx.stroke();
          ctx.globalAlpha = 1;
        }

        // Render nodes
        for (const node of visibleNodes) {
          const pos = layout.get(node.id);
          if (!pos) continue;

          const risk = node.riskScore || 0;
          const fillColor = getRiskSvgColor(risk);
          const isSelected = selectedId === node.id;
          const isHovered = hoveredNode === node.id;
          const isPathNode = pathHighlight?.has(node.id);
          const radius = 6 + risk * 10;

          const connectedToSelected =
            selectedId &&
            visibleEdges.some(
              (e) =>
                (e.source === selectedId && e.target === node.id) || (e.target === selectedId && e.source === node.id),
            );
          const dimmed = selectedId && !isSelected && !connectedToSelected && !isPathNode;

          // 11.9: UEBA pulsing glow
          const uebaData = uebaOverlay?.overlay?.[node.id];
          if (uebaData && uebaData.uebaRiskScore >= 40) {
            const glowRadius = radius + 8 + pulseScale * 6;
            ctx.beginPath();
            ctx.arc(pos.x, pos.y, glowRadius, 0, Math.PI * 2);
            const uebaColor =
              uebaData.uebaRiskScore >= 80 ? "#ef4444" : uebaData.uebaRiskScore >= 60 ? "#f97316" : "#eab308";
            ctx.fillStyle =
              uebaColor +
              Math.round(30 + pulseScale * 40)
                .toString(16)
                .padStart(2, "0");
            ctx.fill();
          }

          ctx.globalAlpha = dimmed ? 0.2 : 1;

          // Outer glow
          if (isSelected || isPathNode) {
            ctx.beginPath();
            ctx.arc(pos.x, pos.y, radius + 4, 0, Math.PI * 2);
            ctx.fillStyle = isPathNode ? "#f59e0b30" : fillColor + "30";
            ctx.fill();
          }

          // Main circle
          ctx.beginPath();
          ctx.arc(pos.x, pos.y, radius, 0, Math.PI * 2);
          ctx.fillStyle = fillColor;
          ctx.globalAlpha = dimmed ? 0.15 : isSelected ? 1 : 0.7;
          ctx.fill();

          if (isSelected || isHovered) {
            ctx.strokeStyle = "#ffffff";
            ctx.lineWidth = 1.5;
            ctx.stroke();
          }

          if (isPathNode) {
            ctx.strokeStyle = "#f59e0b";
            ctx.lineWidth = 2;
            ctx.stroke();
          }

          ctx.globalAlpha = 1;

          // Label
          if (!dimmed || isPathNode) {
            const label = (node.displayName || node.value).substring(0, 20);
            ctx.fillStyle = "#d1d5db";
            ctx.font = `${isSelected || isHovered ? "bold " : ""}9px system-ui`;
            ctx.textAlign = "center";
            ctx.globalAlpha = isSelected || connectedToSelected || isPathNode ? 1 : 0.5;
            ctx.fillText(label, pos.x, pos.y + radius + 12);
            ctx.globalAlpha = 1;
          }

          // 11.9: UEBA badge
          if (uebaData && uebaData.uebaRiskScore >= 20) {
            const badgeX = pos.x + radius;
            const badgeY = pos.y - radius;
            ctx.beginPath();
            ctx.arc(badgeX, badgeY, 5, 0, Math.PI * 2);
            ctx.fillStyle =
              uebaData.uebaRiskScore >= 80
                ? "#ef4444"
                : uebaData.uebaRiskScore >= 60
                  ? "#f97316"
                  : uebaData.uebaRiskScore >= 40
                    ? "#eab308"
                    : "#6b7280";
            ctx.fill();
            ctx.strokeStyle = "#111827";
            ctx.lineWidth = 1;
            ctx.stroke();
          }
        }
      }

      ctx.restore();

      // Request animation if UEBA overlay active (for pulsing)
      if (uebaOverlay && uebaOverlay.totalScored > 0) {
        animFrameRef.current = requestAnimationFrame(render);
      }
    };

    render();

    return () => {
      if (animFrameRef.current) cancelAnimationFrame(animFrameRef.current);
    };
  }, [
    visibleNodes,
    visibleEdges,
    layout,
    selectedId,
    hoveredNode,
    zoom,
    pan,
    useClusterMode,
    clusters,
    uebaOverlay,
    pathHighlight,
  ]);

  // Mouse interaction handlers
  const getNodeAtPosition = useCallback(
    (clientX: number, clientY: number): string | null => {
      const canvas = canvasRef.current;
      if (!canvas) return null;
      const rect = canvas.getBoundingClientRect();
      const scaleX = WIDTH / rect.width;
      const scaleY = HEIGHT / rect.height;
      const x = (clientX - rect.left) * scaleX;
      const y = (clientY - rect.top) * scaleY;

      const graphX = (x - pan.x) / zoom;
      const graphY = (y - pan.y) / zoom;

      for (const node of visibleNodes) {
        const pos = layout.get(node.id);
        if (!pos) continue;
        const radius = 6 + (node.riskScore || 0) * 10 + 3;
        const dx = graphX - pos.x;
        const dy = graphY - pos.y;
        if (dx * dx + dy * dy <= radius * radius) return node.id;
      }
      return null;
    },
    [visibleNodes, layout, zoom, pan],
  );

  const handleCanvasClick = useCallback(
    (e: React.MouseEvent<HTMLCanvasElement>) => {
      const nodeId = getNodeAtPosition(e.clientX, e.clientY);
      if (nodeId) onSelectEntity(nodeId);
    },
    [getNodeAtPosition, onSelectEntity],
  );

  const handleCanvasMouseMove = useCallback(
    (e: React.MouseEvent<HTMLCanvasElement>) => {
      if (isDragging) {
        const dx = e.clientX - dragStart.x;
        const dy = e.clientY - dragStart.y;
        const canvas = canvasRef.current;
        if (!canvas) return;
        const rect = canvas.getBoundingClientRect();
        const scaleX = WIDTH / rect.width;
        const scaleY = HEIGHT / rect.height;
        setPan((prev) => ({ x: prev.x + dx * scaleX, y: prev.y + dy * scaleY }));
        setDragStart({ x: e.clientX, y: e.clientY });
        return;
      }
      const nodeId = getNodeAtPosition(e.clientX, e.clientY);
      setHoveredNode(nodeId);
      const canvas = canvasRef.current;
      if (canvas) canvas.style.cursor = nodeId ? "pointer" : isDragging ? "grabbing" : "grab";
    },
    [getNodeAtPosition, isDragging, dragStart],
  );

  const handleWheel = useCallback((e: React.WheelEvent<HTMLCanvasElement>) => {
    e.preventDefault();
    const delta = e.deltaY > 0 ? 0.9 : 1.1;
    setZoom((prev) => Math.max(0.2, Math.min(5, prev * delta)));
  }, []);

  const handleMouseDown = useCallback(
    (e: React.MouseEvent<HTMLCanvasElement>) => {
      const nodeId = getNodeAtPosition(e.clientX, e.clientY);
      if (!nodeId) {
        setIsDragging(true);
        setDragStart({ x: e.clientX, y: e.clientY });
      }
    },
    [getNodeAtPosition],
  );

  const handleMouseUp = useCallback(() => {
    setIsDragging(false);
  }, []);

  const handleContextMenuEvent = useCallback(
    (e: React.MouseEvent<HTMLCanvasElement>) => {
      e.preventDefault();
      const nodeId = getNodeAtPosition(e.clientX, e.clientY);
      if (nodeId && onContextMenu) {
        onContextMenu(nodeId, e.clientX, e.clientY);
      }
    },
    [getNodeAtPosition, onContextMenu],
  );

  if (graph.nodes.length === 0) {
    return (
      <Card>
        <CardContent className="p-8 text-center">
          <Network className="h-12 w-12 text-muted-foreground mx-auto mb-3 opacity-50" />
          <p className="text-sm text-muted-foreground">No entities discovered yet.</p>
          <p className="text-xs text-muted-foreground mt-1">Ingest alerts to populate the entity graph.</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card data-testid="visual-graph">
      <CardContent className="p-0 overflow-hidden relative">
        {/* Zoom controls */}
        <div className="absolute top-2 right-2 z-10 flex flex-col gap-1">
          <Button
            variant="outline"
            size="icon"
            className="h-7 w-7"
            onClick={() => setZoom((z) => Math.min(5, z * 1.2))}
          >
            <ZoomIn className="h-3.5 w-3.5" />
          </Button>
          <Button
            variant="outline"
            size="icon"
            className="h-7 w-7"
            onClick={() => setZoom((z) => Math.max(0.2, z * 0.8))}
          >
            <ZoomOut className="h-3.5 w-3.5" />
          </Button>
          <Button
            variant="outline"
            size="icon"
            className="h-7 w-7"
            onClick={() => {
              setZoom(1);
              setPan({ x: 0, y: 0 });
            }}
          >
            <Maximize2 className="h-3.5 w-3.5" />
          </Button>
        </div>
        {/* LOD indicator */}
        {useClusterMode && (
          <div className="absolute top-2 left-2 z-10">
            <Badge variant="outline" className="text-[9px] bg-background/80 backdrop-blur">
              Cluster View ({visibleNodes.length} nodes) — Zoom in for detail
            </Badge>
          </div>
        )}
        {/* Zoom level indicator */}
        <div className="absolute bottom-2 right-2 z-10">
          <Badge variant="outline" className="text-[9px] bg-background/80 backdrop-blur">
            {(zoom * 100).toFixed(0)}%
          </Badge>
        </div>
        <canvas
          ref={canvasRef}
          className="w-full"
          style={{ minHeight: 300, maxHeight: 500, aspectRatio: `${WIDTH}/${HEIGHT}` }}
          onClick={handleCanvasClick}
          onMouseMove={handleCanvasMouseMove}
          onWheel={handleWheel}
          onMouseDown={handleMouseDown}
          onMouseUp={handleMouseUp}
          onMouseLeave={handleMouseUp}
          onContextMenu={handleContextMenuEvent}
        />
      </CardContent>
    </Card>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// 11.3: Filter Panel
// ═══════════════════════════════════════════════════════════════════════════════

function FilterPanel({
  allTypes,
  allEdgeTypes,
  visibleNodeTypes,
  visibleEdgeTypes,
  onToggleNodeType,
  onToggleEdgeType,
  onShowAll,
  onHideAll,
}: {
  allTypes: string[];
  allEdgeTypes: string[];
  visibleNodeTypes: Set<string>;
  visibleEdgeTypes: Set<string>;
  onToggleNodeType: (type: string) => void;
  onToggleEdgeType: (type: string) => void;
  onShowAll: () => void;
  onHideAll: () => void;
}) {
  const [expanded, setExpanded] = useState(true);

  return (
    <Card data-testid="filter-panel">
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between cursor-pointer" onClick={() => setExpanded(!expanded)}>
          <CardTitle className="text-sm flex items-center gap-1.5">
            <Filter className="h-3.5 w-3.5 text-muted-foreground" />
            Filters
          </CardTitle>
          {expanded ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
        </div>
      </CardHeader>
      {expanded && (
        <CardContent className="space-y-3">
          <div className="flex gap-1.5">
            <Button variant="ghost" size="sm" className="h-6 text-[10px]" onClick={onShowAll}>
              Show All
            </Button>
            <Button variant="ghost" size="sm" className="h-6 text-[10px]" onClick={onHideAll}>
              Hide All
            </Button>
          </div>
          <div>
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1.5">Node Types</p>
            <div className="space-y-1">
              {allTypes.map((type) => {
                const config = ENTITY_TYPE_CONFIG[type];
                return (
                  <div key={type} className="flex items-center gap-2">
                    <Switch
                      checked={visibleNodeTypes.has(type)}
                      onCheckedChange={() => onToggleNodeType(type)}
                      className="scale-75"
                    />
                    <EntityTypeIcon type={type} className="h-3 w-3" />
                    <span className="text-xs">{config?.label || type}</span>
                  </div>
                );
              })}
            </div>
          </div>
          <div>
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1.5">Edge Types</p>
            <div className="space-y-1">
              {allEdgeTypes.map((type) => (
                <div key={type} className="flex items-center gap-2">
                  <Switch
                    checked={visibleEdgeTypes.has(type)}
                    onCheckedChange={() => onToggleEdgeType(type)}
                    className="scale-75"
                  />
                  <span className="text-xs">{RELATIONSHIP_LABELS[type] || type}</span>
                </div>
              ))}
            </div>
          </div>
        </CardContent>
      )}
    </Card>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// 11.4: Path Finding Panel
// ═══════════════════════════════════════════════════════════════════════════════

function PathFindingPanel({
  allNodes,
  onPathFound,
}: {
  allNodes: GraphNode[];
  onPathFound: (nodeIds: Set<string> | null) => void;
}) {
  const { toast } = useToast();
  const [sourceSearch, setSourceSearch] = useState("");
  const [targetSearch, setTargetSearch] = useState("");
  const [sourceId, setSourceId] = useState("");
  const [targetId, setTargetId] = useState("");
  const [expanded, setExpanded] = useState(false);

  const pathQuery = useQuery<PathResult>({
    queryKey: ["/api/entity-graph/path", sourceId, targetId],
    queryFn: async () => {
      const res = await apiRequest(
        "GET",
        `/api/entity-graph/path?source=${encodeURIComponent(sourceId)}&target=${encodeURIComponent(targetId)}`,
      );
      return res.json();
    },
    enabled: !!sourceId && !!targetId && sourceId !== targetId,
  });

  useEffect(() => {
    if (pathQuery.data?.found) {
      const ids = new Set(pathQuery.data.path.map((n) => n.entityId));
      onPathFound(ids);
    } else {
      onPathFound(null);
    }
  }, [pathQuery.data, onPathFound]);

  const filteredSource = useMemo(() => {
    if (!sourceSearch.trim()) return allNodes.slice(0, 10);
    const q = sourceSearch.toLowerCase();
    return allNodes
      .filter((n) => n.value.toLowerCase().includes(q) || (n.displayName || "").toLowerCase().includes(q))
      .slice(0, 10);
  }, [allNodes, sourceSearch]);

  const filteredTarget = useMemo(() => {
    if (!targetSearch.trim()) return allNodes.filter((n) => n.id !== sourceId).slice(0, 10);
    const q = targetSearch.toLowerCase();
    return allNodes
      .filter(
        (n) =>
          n.id !== sourceId && (n.value.toLowerCase().includes(q) || (n.displayName || "").toLowerCase().includes(q)),
      )
      .slice(0, 10);
  }, [allNodes, targetSearch, sourceId]);

  return (
    <Card data-testid="path-finding-panel">
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between cursor-pointer" onClick={() => setExpanded(!expanded)}>
          <CardTitle className="text-sm flex items-center gap-1.5">
            <Route className="h-3.5 w-3.5 text-muted-foreground" />
            Path Finding
          </CardTitle>
          {expanded ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
        </div>
      </CardHeader>
      {expanded && (
        <CardContent className="space-y-3">
          <div>
            <Label className="text-[10px]">Source Entity</Label>
            <Input
              value={sourceSearch}
              onChange={(e) => setSourceSearch(e.target.value)}
              placeholder="Search source..."
              className="h-7 text-xs"
            />
            <div className="max-h-24 overflow-y-auto space-y-0.5 mt-1">
              {filteredSource.map((n) => (
                <div
                  key={n.id}
                  className={`flex items-center gap-1.5 text-[10px] p-1 rounded cursor-pointer ${sourceId === n.id ? "bg-cyan-500/15" : "hover:bg-muted/40"}`}
                  onClick={() => {
                    setSourceId(n.id);
                    setSourceSearch(n.displayName || n.value);
                  }}
                >
                  <EntityTypeIcon type={n.type} className="h-2.5 w-2.5" />
                  <span className="font-mono truncate">{n.displayName || n.value}</span>
                </div>
              ))}
            </div>
          </div>
          <div className="flex items-center justify-center">
            <ArrowRight className="h-3 w-3 text-muted-foreground" />
          </div>
          <div>
            <Label className="text-[10px]">Target Entity</Label>
            <Input
              value={targetSearch}
              onChange={(e) => setTargetSearch(e.target.value)}
              placeholder="Search target..."
              className="h-7 text-xs"
            />
            <div className="max-h-24 overflow-y-auto space-y-0.5 mt-1">
              {filteredTarget.map((n) => (
                <div
                  key={n.id}
                  className={`flex items-center gap-1.5 text-[10px] p-1 rounded cursor-pointer ${targetId === n.id ? "bg-cyan-500/15" : "hover:bg-muted/40"}`}
                  onClick={() => {
                    setTargetId(n.id);
                    setTargetSearch(n.displayName || n.value);
                  }}
                >
                  <EntityTypeIcon type={n.type} className="h-2.5 w-2.5" />
                  <span className="font-mono truncate">{n.displayName || n.value}</span>
                </div>
              ))}
            </div>
          </div>
          {sourceId && targetId && sourceId !== targetId && (
            <div className="text-xs space-y-1.5">
              {pathQuery.isLoading && (
                <div className="flex items-center gap-1.5 text-muted-foreground">
                  <Loader2 className="h-3 w-3 animate-spin" />
                  Finding path...
                </div>
              )}
              {pathQuery.data?.found && (
                <div className="p-2 rounded-md bg-emerald-500/10 border border-emerald-500/20">
                  <p className="font-medium text-emerald-400">Path found: {pathQuery.data.hops} hops</p>
                  <div className="flex items-center gap-1 mt-1 flex-wrap">
                    {pathQuery.data.path.map((p, i) => (
                      <span key={p.entityId} className="flex items-center gap-0.5">
                        <Badge variant="outline" className="text-[8px]">
                          {(p.displayName || p.value).slice(0, 15)}
                        </Badge>
                        {i < pathQuery.data!.path.length - 1 && (
                          <ArrowRight className="h-2.5 w-2.5 text-muted-foreground" />
                        )}
                      </span>
                    ))}
                  </div>
                  {pathQuery.data.allPaths.length > 1 && (
                    <p className="text-[10px] text-muted-foreground mt-1">
                      {pathQuery.data.allPaths.length} total paths found
                    </p>
                  )}
                </div>
              )}
              {pathQuery.data && !pathQuery.data.found && (
                <div className="p-2 rounded-md bg-red-500/10 border border-red-500/20">
                  <p className="text-red-400">No path found between these entities</p>
                </div>
              )}
            </div>
          )}
          <Button
            variant="ghost"
            size="sm"
            className="w-full h-6 text-[10px]"
            onClick={() => {
              setSourceId("");
              setTargetId("");
              setSourceSearch("");
              setTargetSearch("");
              onPathFound(null);
            }}
          >
            Clear Path
          </Button>
        </CardContent>
      )}
    </Card>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// 11.5: Snapshot Panel
// ═══════════════════════════════════════════════════════════════════════════════

function SnapshotPanel() {
  const { toast } = useToast();
  const [expanded, setExpanded] = useState(false);
  const [snapshotName, setSnapshotName] = useState("");
  const [compareId, setCompareId] = useState<string | null>(null);

  const { data: snapshots, refetch: refetchSnapshots } = useQuery<SnapshotMeta[]>({
    queryKey: ["/api/entity-graph/snapshots"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/entity-graph/snapshots");
      return res.json();
    },
  });

  const { data: comparison } = useQuery<SnapshotComparison>({
    queryKey: ["/api/entity-graph/snapshots", compareId, "compare"],
    queryFn: async () => {
      const res = await apiRequest("GET", `/api/entity-graph/snapshots/${compareId}/compare`);
      return res.json();
    },
    enabled: !!compareId,
  });

  const saveMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/entity-graph/snapshots", {
        name: snapshotName.trim(),
        description: `Snapshot taken on ${new Date().toLocaleString()}`,
      });
      return res.json();
    },
    onSuccess: () => {
      toast({ title: "Snapshot saved" });
      setSnapshotName("");
      refetchSnapshots();
    },
    onError: (error: Error) => {
      toast({ title: "Failed to save snapshot", description: error.message, variant: "destructive" });
    },
  });

  return (
    <Card data-testid="snapshot-panel">
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between cursor-pointer" onClick={() => setExpanded(!expanded)}>
          <CardTitle className="text-sm flex items-center gap-1.5">
            <Camera className="h-3.5 w-3.5 text-muted-foreground" />
            Snapshots
          </CardTitle>
          {expanded ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
        </div>
      </CardHeader>
      {expanded && (
        <CardContent className="space-y-3">
          <div className="flex gap-1.5">
            <Input
              value={snapshotName}
              onChange={(e) => setSnapshotName(e.target.value)}
              placeholder="Snapshot name..."
              className="h-7 text-xs flex-1"
              maxLength={200}
            />
            <Button
              size="sm"
              className="h-7 text-xs"
              onClick={() => saveMutation.mutate()}
              disabled={!snapshotName.trim() || saveMutation.isPending}
            >
              {saveMutation.isPending ? (
                <Loader2 className="h-3 w-3 animate-spin" />
              ) : (
                <>
                  <Save className="h-3 w-3 mr-1" />
                  Save
                </>
              )}
            </Button>
          </div>
          {snapshots && snapshots.length > 0 && (
            <div className="space-y-1">
              <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Saved Snapshots</p>
              {snapshots.map((s) => (
                <div
                  key={s.id}
                  className={`flex items-center gap-2 text-xs p-1.5 rounded cursor-pointer ${compareId === s.id ? "bg-amber-500/15 border border-amber-500/30" : "hover:bg-muted/40"}`}
                  onClick={() => setCompareId(compareId === s.id ? null : s.id)}
                >
                  <Camera className="h-3 w-3 text-muted-foreground shrink-0" />
                  <span className="truncate flex-1">{s.name}</span>
                  <span className="text-[9px] text-muted-foreground">{s.nodeCount}n</span>
                  <span className="text-[9px] text-muted-foreground">{formatRelativeTime(s.createdAt)}</span>
                </div>
              ))}
            </div>
          )}
          {comparison && (
            <div className="p-2 rounded-md border bg-muted/20 space-y-2">
              <p className="text-xs font-medium flex items-center gap-1.5">
                <GitCompare className="h-3 w-3" />
                Comparison: {comparison.snapshotName}
              </p>
              <div className="grid grid-cols-2 gap-1.5 text-[10px]">
                <div className="p-1.5 rounded bg-emerald-500/10">
                  <span className="text-emerald-400 font-medium">+{comparison.summary.nodesAdded}</span> nodes added
                </div>
                <div className="p-1.5 rounded bg-red-500/10">
                  <span className="text-red-400 font-medium">-{comparison.summary.nodesRemoved}</span> nodes removed
                </div>
                <div className="p-1.5 rounded bg-blue-500/10">
                  <span className="text-blue-400 font-medium">+{comparison.summary.edgesAdded}</span> edges added
                </div>
                <div className="p-1.5 rounded bg-orange-500/10">
                  <span className="text-orange-400 font-medium">{comparison.summary.riskChanges}</span> risk changes
                </div>
              </div>
              {comparison.riskChanges.length > 0 && (
                <div className="space-y-0.5">
                  <p className="text-[9px] text-muted-foreground">Top Risk Changes:</p>
                  {comparison.riskChanges.slice(0, 5).map((rc) => (
                    <div key={rc.entityId} className="flex items-center gap-1.5 text-[10px]">
                      <EntityTypeIcon type={rc.type} className="h-2.5 w-2.5" />
                      <span className="font-mono truncate flex-1">{rc.value}</span>
                      <span className={rc.change > 0 ? "text-red-400" : "text-emerald-400"}>
                        {rc.change > 0 ? "+" : ""}
                        {(rc.change * 100).toFixed(0)}%
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </CardContent>
      )}
    </Card>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// 11.6: Graph Query Language Panel
// ═══════════════════════════════════════════════════════════════════════════════

function GraphQueryPanel() {
  const { toast } = useToast();
  const [queryStr, setQueryStr] = useState("");
  const [expanded, setExpanded] = useState(false);
  const [showExamples, setShowExamples] = useState(false);

  const queryMutation = useMutation({
    mutationFn: async (query: string) => {
      const res = await apiRequest("POST", "/api/entity-graph/query", { query });
      return res.json() as Promise<GraphQueryResult>;
    },
    onError: (error: Error) => {
      toast({ title: "Query failed", description: error.message, variant: "destructive" });
    },
  });

  return (
    <Card data-testid="graph-query-panel">
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between cursor-pointer" onClick={() => setExpanded(!expanded)}>
          <CardTitle className="text-sm flex items-center gap-1.5">
            <Code2 className="h-3.5 w-3.5 text-muted-foreground" />
            Graph Query
          </CardTitle>
          {expanded ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
        </div>
      </CardHeader>
      {expanded && (
        <CardContent className="space-y-3">
          <div className="relative">
            <Textarea
              value={queryStr}
              onChange={(e) => setQueryStr(e.target.value)}
              placeholder="FIND User WHERE riskScore > 60 CONNECTED_TO Host"
              className="text-xs font-mono min-h-[60px] resize-none"
            />
          </div>
          <div className="flex gap-1.5">
            <Button
              size="sm"
              className="h-7 text-xs flex-1"
              onClick={() => queryMutation.mutate(queryStr)}
              disabled={!queryStr.trim() || queryMutation.isPending}
            >
              {queryMutation.isPending ? (
                <Loader2 className="h-3 w-3 animate-spin mr-1" />
              ) : (
                <Play className="h-3 w-3 mr-1" />
              )}
              Run Query
            </Button>
            <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={() => setShowExamples(!showExamples)}>
              Examples
            </Button>
          </div>
          {showExamples && (
            <div className="space-y-0.5">
              {QUERY_EXAMPLES.map((ex) => (
                <div
                  key={ex}
                  className="text-[10px] font-mono p-1.5 rounded bg-muted/30 cursor-pointer hover:bg-muted/50"
                  onClick={() => {
                    setQueryStr(ex);
                    setShowExamples(false);
                  }}
                >
                  {ex}
                </div>
              ))}
            </div>
          )}
          {queryMutation.data && (
            <div className="space-y-2">
              <p className="text-xs text-muted-foreground">{queryMutation.data.totalMatched} entities matched</p>
              <div className="max-h-48 overflow-y-auto space-y-1">
                {queryMutation.data.entities.map((e) => (
                  <div key={e.id} className="flex items-center gap-2 text-xs p-1.5 rounded bg-muted/20">
                    <EntityTypeIcon type={e.type} className="h-3 w-3 shrink-0" />
                    <span className="font-mono truncate flex-1">{e.displayName || e.value}</span>
                    <span className={`text-[9px] font-medium ${getRiskColor(e.riskScore)}`}>
                      {(e.riskScore * 100).toFixed(0)}%
                    </span>
                    <span className="text-[9px] text-muted-foreground">{e.alertCount}a</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </CardContent>
      )}
    </Card>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// 11.8: Create Incident from Graph Dialog
// ═══════════════════════════════════════════════════════════════════════════════

function CreateIncidentDialog({
  open,
  onOpenChange,
  entityIds,
  allNodes,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  entityIds: string[];
  allNodes: GraphNode[];
}) {
  const { toast } = useToast();
  const [title, setTitle] = useState("");
  const [severity, setSeverity] = useState("high");
  const [description, setDescription] = useState("");

  useEffect(() => {
    if (open && entityIds.length > 0) {
      const selectedNodes = allNodes.filter((n) => entityIds.includes(n.id));
      const autoTitle = `Suspicious activity: ${selectedNodes
        .map((n) => n.displayName || n.value)
        .slice(0, 3)
        .join(", ")}${selectedNodes.length > 3 ? ` +${selectedNodes.length - 3} more` : ""}`;
      setTitle(autoTitle);
      const maxRisk = Math.max(...selectedNodes.map((n) => n.riskScore || 0));
      setSeverity(maxRisk >= 0.8 ? "critical" : maxRisk >= 0.6 ? "high" : maxRisk >= 0.4 ? "medium" : "low");
    }
  }, [open, entityIds, allNodes]);

  const createMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/entity-graph/create-incident", {
        title: title.trim(),
        severity,
        entityIds,
        description: description.trim(),
      });
      return res.json();
    },
    onSuccess: (data: { incident: { id: string }; linkedAlertCount: number }) => {
      toast({ title: "Incident created", description: `Incident created with ${data.linkedAlertCount} linked alerts` });
      queryClient.invalidateQueries({ queryKey: ["/api/incidents"] });
      onOpenChange(false);
      setTitle("");
      setDescription("");
    },
    onError: (error: Error) => {
      toast({ title: "Failed to create incident", description: error.message, variant: "destructive" });
    },
  });

  const selectedEntities = allNodes.filter((n) => entityIds.includes(n.id));

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Crosshair className="h-4 w-4 text-red-400" />
            Create Incident from Graph
          </DialogTitle>
          <DialogDescription>Create an incident from {entityIds.length} selected entities.</DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <div>
            <Label className="text-xs">Title</Label>
            <Input value={title} onChange={(e) => setTitle(e.target.value)} className="text-xs" maxLength={500} />
          </div>
          <div>
            <Label className="text-xs">Severity</Label>
            <Select value={severity} onValueChange={setSeverity}>
              <SelectTrigger className="h-8 text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="critical">Critical</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="low">Low</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div>
            <Label className="text-xs">Description (optional)</Label>
            <Textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              className="text-xs min-h-[60px]"
              maxLength={2000}
            />
          </div>
          <div>
            <Label className="text-xs">Selected Entities ({selectedEntities.length})</Label>
            <div className="max-h-24 overflow-y-auto space-y-0.5 mt-1 border rounded-md p-1.5">
              {selectedEntities.map((n) => (
                <div key={n.id} className="flex items-center gap-1.5 text-[10px]">
                  <EntityTypeIcon type={n.type} className="h-2.5 w-2.5" />
                  <span className="font-mono truncate">{n.displayName || n.value}</span>
                  <span className={`ml-auto ${getRiskColor(n.riskScore || 0)}`}>
                    {((n.riskScore || 0) * 100).toFixed(0)}%
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" size="sm" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            size="sm"
            onClick={() => createMutation.mutate()}
            disabled={!title.trim() || createMutation.isPending}
          >
            {createMutation.isPending ? (
              <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />
            ) : (
              <Crosshair className="h-3.5 w-3.5 mr-1.5" />
            )}
            Create Incident
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Main Page Component
// ═══════════════════════════════════════════════════════════════════════════════

export default function EntityGraphPage() {
  usePageTitle("Entity Graph");
  const { toast } = useToast();
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState<string>("all");
  const [riskFilter, setRiskFilter] = useState<string>("all");
  const [selectedEntityId, setSelectedEntityId] = useState<string | null>(null);
  const [viewMode, setViewMode] = useState<"graph" | "table">("graph");
  const [layoutType, setLayoutType] = useState<LayoutType>("force-directed");
  const [showUebaOverlay, setShowUebaOverlay] = useState(false);
  const [pathHighlight, setPathHighlight] = useState<Set<string> | null>(null);
  const [incidentDialogOpen, setIncidentDialogOpen] = useState(false);
  const [incidentEntityIds, setIncidentEntityIds] = useState<string[]>([]);
  const [showSidebar, setShowSidebar] = useState(true);
  const [activeToolTab, setActiveToolTab] = useState<string>("filter");

  // 11.7: Real-time graph updates via SSE
  const [sseConnected, setSseConnected] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);

  // Node/edge type visibility (11.3)
  const [visibleNodeTypes, setVisibleNodeTypes] = useState<Set<string>>(new Set(Object.keys(ENTITY_TYPE_CONFIG)));
  const [visibleEdgeTypes, setVisibleEdgeTypes] = useState<Set<string>>(new Set(Object.keys(RELATIONSHIP_LABELS)));

  const {
    data: graph,
    isLoading,
    refetch: refetchGraph,
  } = useQuery<EntityGraph>({
    queryKey: ["/api/entity-graph"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/entity-graph");
      return res.json();
    },
  });

  // 11.9: UEBA anomaly overlay
  const { data: uebaOverlay } = useQuery<UebaOverlay>({
    queryKey: ["/api/entity-graph/ueba-overlay"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/entity-graph/ueba-overlay");
      return res.json();
    },
    enabled: showUebaOverlay,
  });

  // 11.7: Real-time SSE updates
  useEffect(() => {
    if (!autoRefresh) return;
    const eventSource = new EventSource("/api/events/stream", { withCredentials: true });

    eventSource.addEventListener("entity:resolved", () => {
      refetchGraph();
    });

    eventSource.addEventListener("alert:created", () => {
      refetchGraph();
    });

    eventSource.addEventListener("correlation:found", () => {
      refetchGraph();
    });

    eventSource.onopen = () => setSseConnected(true);
    eventSource.onerror = () => setSseConnected(false);

    return () => {
      eventSource.close();
      setSseConnected(false);
    };
  }, [autoRefresh, refetchGraph]);

  const filteredNodes = useMemo(() => {
    if (!graph) return [];
    let nodes = graph.nodes;

    if (search) {
      const q = search.toLowerCase();
      nodes = nodes.filter((n) => n.value.toLowerCase().includes(q) || (n.displayName || "").toLowerCase().includes(q));
    }

    if (typeFilter !== "all") {
      nodes = nodes.filter((n) => n.type === typeFilter);
    }

    if (riskFilter === "critical") nodes = nodes.filter((n) => (n.riskScore || 0) >= 0.8);
    else if (riskFilter === "high") nodes = nodes.filter((n) => (n.riskScore || 0) >= 0.6 && (n.riskScore || 0) < 0.8);
    else if (riskFilter === "medium")
      nodes = nodes.filter((n) => (n.riskScore || 0) >= 0.4 && (n.riskScore || 0) < 0.6);
    else if (riskFilter === "low") nodes = nodes.filter((n) => (n.riskScore || 0) < 0.4);

    return nodes;
  }, [graph, search, typeFilter, riskFilter]);

  const filteredGraph = useMemo((): EntityGraph => {
    if (!graph) return { nodes: [], edges: [] };
    const nodeIds = new Set(filteredNodes.map((n) => n.id));
    return {
      nodes: filteredNodes,
      edges: graph.edges.filter((e) => nodeIds.has(e.source) && nodeIds.has(e.target)),
    };
  }, [graph, filteredNodes]);

  const allEdgeTypes = useMemo(() => {
    if (!graph) return [];
    return Array.from(new Set(graph.edges.map((e) => e.relationship)));
  }, [graph]);

  const handleSelectEntity = useCallback((id: string) => {
    setSelectedEntityId((prev) => (prev === id ? null : id));
  }, []);

  const handleToggleNodeType = useCallback((type: string) => {
    setVisibleNodeTypes((prev) => {
      const next = new Set(prev);
      if (next.has(type)) next.delete(type);
      else next.add(type);
      return next;
    });
  }, []);

  const handleToggleEdgeType = useCallback((type: string) => {
    setVisibleEdgeTypes((prev) => {
      const next = new Set(prev);
      if (next.has(type)) next.delete(type);
      else next.add(type);
      return next;
    });
  }, []);

  const handleShowAll = useCallback(() => {
    setVisibleNodeTypes(new Set(Object.keys(ENTITY_TYPE_CONFIG)));
    setVisibleEdgeTypes(new Set([...Object.keys(RELATIONSHIP_LABELS), ...allEdgeTypes]));
  }, [allEdgeTypes]);

  const handleHideAll = useCallback(() => {
    setVisibleNodeTypes(new Set());
    setVisibleEdgeTypes(new Set());
  }, []);

  // 11.8: Context menu for creating incidents
  const handleGraphContextMenu = useCallback(
    (entityId: string, _x: number, _y: number) => {
      const ids = selectedEntityId ? [selectedEntityId, entityId] : [entityId];
      const uniqueIds = Array.from(new Set(ids));
      setIncidentEntityIds(uniqueIds);
      setIncidentDialogOpen(true);
    },
    [selectedEntityId],
  );

  const entityTypes = useMemo(() => {
    return Array.from(new Set(graph?.nodes.map((n) => n.type) || []));
  }, [graph]);

  if (isLoading) {
    return (
      <div className="p-6 space-y-4">
        <Skeleton className="h-8 w-64" />
        <div className="grid grid-cols-4 gap-3">
          {[1, 2, 3, 4].map((i) => (
            <Skeleton key={i} className="h-24" />
          ))}
        </div>
        <Skeleton className="h-96" />
      </div>
    );
  }

  if (!graph && !isLoading) {
    return (
      <div className="p-6 space-y-4 animate-fade-in" data-testid="entity-graph-page">
        <div>
          <h1 className="text-xl font-bold tracking-tight flex items-center gap-2">
            <Network className="h-5 w-5 text-red-400" />
            <span className="gradient-text-red">Entity Graph</span>
          </h1>
          <p className="text-sm text-muted-foreground mt-0.5">Identity resolution and entity relationship mapping</p>
          <div className="gradient-accent-line w-24 mt-2" />
        </div>
        <Card>
          <CardContent className="py-12">
            <div className="flex flex-col items-center justify-center text-center" role="alert">
              <Network className="h-10 w-10 text-muted-foreground mb-3" />
              <p className="text-sm font-medium">No entity graph data available</p>
              <p className="text-xs text-muted-foreground mt-1">
                Entity relationships will appear here once alerts and incidents generate entity data.
              </p>
              <Button variant="outline" size="sm" className="mt-3" onClick={() => window.location.reload()}>
                Refresh
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-4 animate-fade-in" data-testid="entity-graph-page">
      {/* Header */}
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-xl font-bold tracking-tight flex items-center gap-2">
            <Network className="h-5 w-5 text-red-400" />
            <span className="gradient-text-red">Entity Graph</span>
          </h1>
          <p className="text-sm text-muted-foreground mt-0.5">Identity resolution and entity relationship mapping</p>
          <div className="gradient-accent-line w-24 mt-2" />
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          {/* 11.7: SSE connection status */}
          <TooltipProvider>
            <Tooltip>
              <TooltipTrigger asChild>
                <div className="flex items-center gap-1.5 cursor-pointer" onClick={() => setAutoRefresh(!autoRefresh)}>
                  <div
                    className={`h-2 w-2 rounded-full ${sseConnected ? "bg-emerald-400 animate-pulse" : autoRefresh ? "bg-yellow-400" : "bg-muted-foreground"}`}
                  />
                  <span className="text-[10px] text-muted-foreground">
                    {sseConnected ? "Live" : autoRefresh ? "Connecting..." : "Paused"}
                  </span>
                </div>
              </TooltipTrigger>
              <TooltipContent>
                <p className="text-xs">Real-time updates: {autoRefresh ? "On" : "Off"}. Click to toggle.</p>
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>

          {/* 11.9: UEBA overlay toggle */}
          <TooltipProvider>
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant={showUebaOverlay ? "default" : "outline"}
                  size="sm"
                  className="h-8"
                  onClick={() => setShowUebaOverlay(!showUebaOverlay)}
                >
                  <Brain className="h-3.5 w-3.5 mr-1" />
                  UEBA
                  {uebaOverlay && showUebaOverlay && (
                    <Badge variant="secondary" className="ml-1 text-[8px] h-4">
                      {uebaOverlay.totalScored}
                    </Badge>
                  )}
                </Button>
              </TooltipTrigger>
              <TooltipContent>
                <p className="text-xs">Toggle UEBA anomaly overlay on graph nodes</p>
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>

          {/* 11.2: Layout selector */}
          <Select value={layoutType} onValueChange={(v) => setLayoutType(v as LayoutType)}>
            <SelectTrigger className="w-40 h-8 text-xs">
              <Layout className="h-3 w-3 mr-1" />
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {LAYOUT_OPTIONS.map((opt) => (
                <SelectItem key={opt.value} value={opt.value}>
                  {opt.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          {/* View mode */}
          <Button
            variant={viewMode === "graph" ? "default" : "outline"}
            size="sm"
            onClick={() => setViewMode("graph")}
            data-testid="button-view-graph"
          >
            <Network className="h-3.5 w-3.5 mr-1.5" />
            Graph
          </Button>
          <Button
            variant={viewMode === "table" ? "default" : "outline"}
            size="sm"
            onClick={() => setViewMode("table")}
            data-testid="button-view-table"
          >
            <Activity className="h-3.5 w-3.5 mr-1.5" />
            Table
          </Button>

          <Button variant="outline" size="sm" className="h-8" onClick={() => setShowSidebar(!showSidebar)}>
            {showSidebar ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
          </Button>
        </div>
      </div>

      {graph && <EntityGraphStats graph={graph} />}

      {/* Search and filters */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="relative flex-1 min-w-[200px] max-w-sm">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
          <Input
            placeholder="Search entities..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-8 h-9"
            data-testid="input-entity-search"
          />
        </div>
        <Select value={typeFilter} onValueChange={setTypeFilter}>
          <SelectTrigger className="w-36 h-9" data-testid="select-type-filter">
            <SelectValue placeholder="Entity Type" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Types</SelectItem>
            {entityTypes.map((t) => (
              <SelectItem key={t} value={t}>
                {ENTITY_TYPE_CONFIG[t]?.label || t}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={riskFilter} onValueChange={setRiskFilter}>
          <SelectTrigger className="w-32 h-9" data-testid="select-risk-filter">
            <SelectValue placeholder="Risk Level" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Risk</SelectItem>
            <SelectItem value="critical">Critical</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="low">Low</SelectItem>
          </SelectContent>
        </Select>
        <Badge variant="outline" className="text-xs">
          {filteredNodes.length} / {graph?.nodes.length || 0} entities
        </Badge>
      </div>

      {/* Main content */}
      <div className="flex gap-4">
        {/* Tools sidebar */}
        {showSidebar && (
          <div className="w-64 shrink-0 hidden md:block space-y-3">
            <Tabs value={activeToolTab} onValueChange={setActiveToolTab}>
              <TabsList className="w-full grid grid-cols-4 h-8">
                <TabsTrigger value="filter" className="text-[10px] px-1">
                  <Filter className="h-3 w-3" />
                </TabsTrigger>
                <TabsTrigger value="path" className="text-[10px] px-1">
                  <Route className="h-3 w-3" />
                </TabsTrigger>
                <TabsTrigger value="snapshot" className="text-[10px] px-1">
                  <Camera className="h-3 w-3" />
                </TabsTrigger>
                <TabsTrigger value="query" className="text-[10px] px-1">
                  <Code2 className="h-3 w-3" />
                </TabsTrigger>
              </TabsList>

              <TabsContent value="filter" className="mt-2">
                <FilterPanel
                  allTypes={entityTypes}
                  allEdgeTypes={allEdgeTypes}
                  visibleNodeTypes={visibleNodeTypes}
                  visibleEdgeTypes={visibleEdgeTypes}
                  onToggleNodeType={handleToggleNodeType}
                  onToggleEdgeType={handleToggleEdgeType}
                  onShowAll={handleShowAll}
                  onHideAll={handleHideAll}
                />
              </TabsContent>
              <TabsContent value="path" className="mt-2">
                <PathFindingPanel allNodes={graph?.nodes || []} onPathFound={setPathHighlight} />
              </TabsContent>
              <TabsContent value="snapshot" className="mt-2">
                <SnapshotPanel />
              </TabsContent>
              <TabsContent value="query" className="mt-2">
                <GraphQueryPanel />
              </TabsContent>
            </Tabs>
          </div>
        )}

        {/* Graph or Table */}
        <div className="flex-1 min-w-0">
          {viewMode === "graph" ? (
            <div className="space-y-3">
              <VisualGraph
                graph={filteredGraph}
                selectedId={selectedEntityId}
                onSelectEntity={handleSelectEntity}
                layoutType={layoutType}
                uebaOverlay={showUebaOverlay ? uebaOverlay : null}
                pathHighlight={pathHighlight}
                visibleNodeTypes={visibleNodeTypes}
                visibleEdgeTypes={visibleEdgeTypes}
                onContextMenu={handleGraphContextMenu}
              />
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
                {filteredNodes.slice(0, 30).map((node) => (
                  <EntityCard
                    key={node.id}
                    entity={node}
                    onSelect={handleSelectEntity}
                    isSelected={selectedEntityId === node.id}
                  />
                ))}
              </div>
            </div>
          ) : (
            <Card>
              <CardContent className="p-0">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-10">Type</TableHead>
                      <TableHead>Value</TableHead>
                      <TableHead className="w-24">Risk</TableHead>
                      <TableHead className="w-20">Alerts</TableHead>
                      <TableHead className="w-24">Links</TableHead>
                      <TableHead className="w-28">Last Seen</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredNodes.map((node) => {
                      const risk = node.riskScore || 0;
                      const uebaData = showUebaOverlay ? uebaOverlay?.overlay?.[node.id] : null;
                      return (
                        <TableRow
                          key={node.id}
                          className="cursor-pointer hover-elevate"
                          onClick={() => handleSelectEntity(node.id)}
                          data-testid={`entity-row-${node.id}`}
                        >
                          <TableCell>
                            <EntityTypeIcon type={node.type} className="h-4 w-4" />
                          </TableCell>
                          <TableCell>
                            <div className="flex items-center gap-2">
                              <div>
                                <span className="text-sm font-mono">{node.displayName || node.value}</span>
                                {node.displayName && node.displayName !== node.value && (
                                  <p className="text-[10px] text-muted-foreground font-mono truncate">{node.value}</p>
                                )}
                              </div>
                              {uebaData && uebaData.uebaRiskScore >= 40 && (
                                <Badge
                                  variant="outline"
                                  className={`text-[8px] ${uebaData.uebaRiskScore >= 80 ? "border-red-500/30 text-red-400" : uebaData.uebaRiskScore >= 60 ? "border-orange-500/30 text-orange-400" : "border-yellow-500/30 text-yellow-400"}`}
                                >
                                  UEBA {uebaData.uebaRiskScore}
                                </Badge>
                              )}
                            </div>
                          </TableCell>
                          <TableCell>
                            <div className="flex items-center gap-1.5">
                              <span className={`text-xs font-semibold ${getRiskColor(risk)}`}>
                                {(risk * 100).toFixed(0)}%
                              </span>
                              <Progress value={risk * 100} className="h-1 w-10" />
                            </div>
                          </TableCell>
                          <TableCell className="text-sm">{node.alertCount || 0}</TableCell>
                          <TableCell className="text-sm">{node.connections || 0}</TableCell>
                          <TableCell className="text-xs text-muted-foreground">
                            {formatRelativeTime(node.lastSeenAt)}
                          </TableCell>
                        </TableRow>
                      );
                    })}
                    {filteredNodes.length === 0 && (
                      <TableRow>
                        <TableCell colSpan={6} className="text-center text-sm text-muted-foreground py-8">
                          No entities found matching filters.
                        </TableCell>
                      </TableRow>
                    )}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          )}
        </div>

        {/* Entity detail panel */}
        {selectedEntityId && (
          <div className="w-80 shrink-0 hidden lg:block">
            <EntityDetailPanel entityId={selectedEntityId} allNodes={graph?.nodes || []} />
          </div>
        )}
      </div>

      {/* 11.8: Incident creation dialog */}
      <CreateIncidentDialog
        open={incidentDialogOpen}
        onOpenChange={setIncidentDialogOpen}
        entityIds={incidentEntityIds}
        allNodes={graph?.nodes || []}
      />
    </div>
  );
}

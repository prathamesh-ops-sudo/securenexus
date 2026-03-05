import { useState, useMemo, useCallback, useEffect } from "react";
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
import { formatRelativeTime } from "@/components/security-badges";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { usePageTitle } from "@/hooks/use-page-title";
import type { Entity } from "@shared/schema";

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

const ENTITY_TYPE_CONFIG: Record<
  string,
  {
    icon: typeof User;
    color: string;
    bgColor: string;
    borderColor: string;
    label: string;
  }
> = {
  user: {
    icon: User,
    color: "text-blue-400",
    bgColor: "bg-blue-500/10",
    borderColor: "border-blue-500/20",
    label: "User",
  },
  host: {
    icon: Server,
    color: "text-emerald-400",
    bgColor: "bg-emerald-500/10",
    borderColor: "border-emerald-500/20",
    label: "Host",
  },
  ip: {
    icon: Globe,
    color: "text-purple-400",
    bgColor: "bg-purple-500/10",
    borderColor: "border-purple-500/20",
    label: "IP Address",
  },
  domain: {
    icon: Globe,
    color: "text-cyan-400",
    bgColor: "bg-cyan-500/10",
    borderColor: "border-cyan-500/20",
    label: "Domain",
  },
  file_hash: {
    icon: Hash,
    color: "text-orange-400",
    bgColor: "bg-orange-500/10",
    borderColor: "border-orange-500/20",
    label: "File Hash",
  },
  email: {
    icon: Mail,
    color: "text-pink-400",
    bgColor: "bg-pink-500/10",
    borderColor: "border-pink-500/20",
    label: "Email",
  },
  url: {
    icon: Link2,
    color: "text-yellow-400",
    bgColor: "bg-yellow-500/10",
    borderColor: "border-yellow-500/20",
    label: "URL",
  },
  process: {
    icon: Terminal,
    color: "text-red-400",
    bgColor: "bg-red-500/10",
    borderColor: "border-red-500/20",
    label: "Process",
  },
};

const RELATIONSHIP_LABELS: Record<string, string> = {
  attack_path: "Attack Path",
  uses: "Uses",
  targeted_by: "Targeted By",
  associated_with: "Associated",
  co_occurred: "Co-occurred",
};

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

function EntityTypeIcon({ type, className }: { type: string; className?: string }) {
  const config = ENTITY_TYPE_CONFIG[type];
  if (!config) return <Network className={className} />;
  const IconComp = config.icon;
  return <IconComp className={`${config.color} ${className || ""}`} />;
}

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
      setTargetId("");
      setSourceId("");
      setConfirmText("");
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
                Merge Suggestions (similar to selected)
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
                  className={`flex items-center gap-2 text-xs p-1.5 rounded cursor-pointer transition-colors ${
                    targetId === n.id ? "bg-cyan-500/15 border border-cyan-500/30" : "hover:bg-muted/40"
                  }`}
                  onClick={() => setTargetId(n.id)}
                  data-testid={`merge-target-${n.id}`}
                >
                  <EntityTypeIcon type={n.type} className="h-3 w-3 shrink-0" />
                  <span className="font-mono truncate">{n.displayName || n.value}</span>
                </div>
              ))}
              {filteredNodes.length === 0 && (
                <p className="text-[10px] text-muted-foreground text-center py-2">No entities found</p>
              )}
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
                    className={`flex items-center gap-2 text-xs p-1.5 rounded cursor-pointer transition-colors ${
                      sourceId === n.id ? "bg-red-500/15 border border-red-500/30" : "hover:bg-muted/40"
                    }`}
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
                All alerts, aliases, and relationships from the source entity will be transferred to the target. The
                source entity will be permanently deleted.
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
              {relationships.slice(0, 20).map((rel) => {
                const _relConfig = ENTITY_TYPE_CONFIG[rel.relatedEntityType] || ENTITY_TYPE_CONFIG.ip;
                return (
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
                );
              })}
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
                      className={`text-[9px] font-medium uppercase ${
                        alert.severity === "critical"
                          ? "text-red-400"
                          : alert.severity === "high"
                            ? "text-orange-400"
                            : alert.severity === "medium"
                              ? "text-yellow-400"
                              : "text-emerald-400"
                      }`}
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

function VisualGraph({
  graph,
  selectedId,
  onSelectEntity,
}: {
  graph: EntityGraph;
  selectedId: string | null;
  onSelectEntity: (id: string) => void;
}) {
  const layout = useMemo(() => {
    if (graph.nodes.length === 0) return { positions: new Map<string, { x: number; y: number }>() };

    const positions = new Map<string, { x: number; y: number }>();
    const width = 800;
    const height = 500;
    const centerX = width / 2;
    const centerY = height / 2;

    const sorted = [...graph.nodes].sort((a, b) => (b.riskScore || 0) - (a.riskScore || 0));

    const typeGroups: Record<string, GraphNode[]> = {};
    for (const node of sorted) {
      if (!typeGroups[node.type]) typeGroups[node.type] = [];
      typeGroups[node.type].push(node);
    }

    const types = Object.keys(typeGroups);
    const angleStep = (2 * Math.PI) / Math.max(types.length, 1);

    types.forEach((type, typeIdx) => {
      const baseAngle = typeIdx * angleStep - Math.PI / 2;
      const nodes = typeGroups[type];
      const clusterRadius = 120 + nodes.length * 8;

      nodes.forEach((node, nodeIdx) => {
        const nodeAngle = baseAngle + (nodeIdx / Math.max(nodes.length, 1) - 0.5) * 0.8;
        const r = clusterRadius * (0.6 + (node.riskScore || 0) * 0.4);
        positions.set(node.id, {
          x: centerX + r * Math.cos(nodeAngle),
          y: centerY + r * Math.sin(nodeAngle),
        });
      });
    });

    return { positions };
  }, [graph]);

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
      <CardContent className="p-0 overflow-hidden">
        <svg viewBox="0 0 800 500" className="w-full h-auto" style={{ minHeight: 300, maxHeight: 500 }}>
          <defs>
            <filter id="glow">
              <feGaussianBlur stdDeviation="2" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>

          {graph.edges.map((edge, i) => {
            const from = layout.positions.get(edge.source);
            const to = layout.positions.get(edge.target);
            if (!from || !to) return null;
            const isHighlighted = selectedId === edge.source || selectedId === edge.target;
            return (
              <line
                key={`edge-${i}`}
                x1={from.x}
                y1={from.y}
                x2={to.x}
                y2={to.y}
                stroke={isHighlighted ? "hsl(var(--destructive))" : "hsl(var(--border))"}
                strokeWidth={isHighlighted ? 1.5 : 0.5 + Math.min(edge.weight, 3) * 0.3}
                opacity={selectedId ? (isHighlighted ? 0.8 : 0.15) : 0.3}
                className="smooth-all"
              />
            );
          })}

          {graph.nodes.map((node) => {
            const pos = layout.positions.get(node.id);
            if (!pos) return null;
            const risk = node.riskScore || 0;
            const isSelected = selectedId === node.id;
            const radius = 6 + risk * 10;

            const fillColor = risk >= 0.8 ? "#ef4444" : risk >= 0.6 ? "#f97316" : risk >= 0.4 ? "#eab308" : "#22c55e";

            const connectedToSelected =
              selectedId &&
              graph.edges.some(
                (e) =>
                  (e.source === selectedId && e.target === node.id) ||
                  (e.target === selectedId && e.source === node.id),
              );

            const dimmed = selectedId && !isSelected && !connectedToSelected;

            return (
              <g
                key={node.id}
                onClick={() => onSelectEntity(node.id)}
                className="cursor-pointer"
                opacity={dimmed ? 0.2 : 1}
                data-testid={`graph-node-${node.id}`}
              >
                <circle
                  cx={pos.x}
                  cy={pos.y}
                  r={radius + 3}
                  fill={fillColor}
                  opacity={isSelected ? 0.3 : 0.1}
                  filter={isSelected ? "url(#glow)" : undefined}
                  className="smooth-all"
                />
                <circle
                  cx={pos.x}
                  cy={pos.y}
                  r={radius}
                  fill={fillColor}
                  opacity={isSelected ? 1 : 0.7}
                  stroke={isSelected ? "#fff" : "none"}
                  strokeWidth={isSelected ? 1.5 : 0}
                  className="smooth-all"
                />
                <text
                  x={pos.x}
                  y={pos.y + radius + 12}
                  textAnchor="middle"
                  className="fill-foreground"
                  fontSize={9}
                  opacity={isSelected || connectedToSelected ? 1 : 0.5}
                >
                  {(node.displayName || node.value).substring(0, 20)}
                </text>
              </g>
            );
          })}
        </svg>
      </CardContent>
    </Card>
  );
}

export default function EntityGraphPage() {
  usePageTitle("Entity Graph");
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState<string>("all");
  const [riskFilter, setRiskFilter] = useState<string>("all");
  const [selectedEntityId, setSelectedEntityId] = useState<string | null>(null);
  const [viewMode, setViewMode] = useState<"graph" | "table">("graph");

  const { data: graph, isLoading } = useQuery<EntityGraph>({
    queryKey: ["/api/entity-graph"],
  });

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

  const handleSelectEntity = useCallback((id: string) => {
    setSelectedEntityId((prev) => (prev === id ? null : id));
  }, []);

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
      <div className="flex flex-col items-center justify-center py-12 text-center" role="alert">
        <div className="rounded-full bg-destructive/10 p-3 ring-1 ring-destructive/20 mb-3">
          <AlertTriangle className="h-6 w-6 text-destructive" />
        </div>
        <p className="text-sm font-medium">Failed to load entity graph</p>
        <p className="text-xs text-muted-foreground mt-1">An error occurred while fetching data.</p>
        <Button variant="outline" size="sm" className="mt-3" onClick={() => window.location.reload()}>
          Try Again
        </Button>
      </div>
    );
  }

  const entityTypes = Array.from(new Set(graph?.nodes.map((n) => n.type) || []));

  return (
    <div className="p-6 space-y-4 animate-fade-in" data-testid="entity-graph-page">
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-xl font-bold tracking-tight flex items-center gap-2">
            <Network className="h-5 w-5 text-red-400" />
            <span className="gradient-text-red">Entity Graph</span>
          </h1>
          <p className="text-sm text-muted-foreground mt-0.5">Identity resolution and entity relationship mapping</p>
          <div className="gradient-accent-line w-24 mt-2" />
        </div>
        <div className="flex items-center gap-2">
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
        </div>
      </div>

      {graph && <EntityGraphStats graph={graph} />}

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

      <div className="flex gap-4">
        <div className="flex-1 min-w-0">
          {viewMode === "graph" ? (
            <div className="space-y-3">
              <VisualGraph graph={filteredGraph} selectedId={selectedEntityId} onSelectEntity={handleSelectEntity} />
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
                            <div>
                              <span className="text-sm font-mono">{node.displayName || node.value}</span>
                              {node.displayName && node.displayName !== node.value && (
                                <p className="text-[10px] text-muted-foreground font-mono truncate">{node.value}</p>
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

        {selectedEntityId && (
          <div className="w-80 shrink-0 hidden lg:block">
            <EntityDetailPanel entityId={selectedEntityId} allNodes={graph?.nodes || []} />
          </div>
        )}
      </div>
    </div>
  );
}

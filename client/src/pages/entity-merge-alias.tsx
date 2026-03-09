import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { usePageTitle } from "@/hooks/use-page-title";
import { apiRequest } from "@/lib/queryClient";
import {
  GitMerge,
  RefreshCw,
  AlertTriangle,
  Loader2,
  Search,
  Shield,
  Hash,
  Network,
  Plus,
  Trash2,
  ArrowRight,
  CheckCircle2,
  XCircle,
  Globe,
  Server,
  User,
  FileText,
  Link2,
  ChevronDown,
  ChevronRight,
  Info,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { useToast } from "@/hooks/use-toast";

interface Entity {
  id: string;
  orgId: string | null;
  type: string;
  value: string;
  displayName: string | null;
  metadata: Record<string, unknown> | null;
  firstSeenAt: string | null;
  lastSeenAt: string | null;
  alertCount: number;
  riskScore: number;
  createdAt: string | null;
}

interface EntityAlias {
  id: string;
  entityId: string;
  aliasType: string;
  aliasValue: string;
  source: string | null;
  createdAt: string | null;
}

interface EntityRelationship {
  relatedEntityId: string;
  relatedEntityType: string;
  relatedEntityValue: string;
  relatedEntityRiskScore: number;
  sharedAlertCount: number;
  relationship: string;
}

const ENTITY_TYPE_META: Record<string, { label: string; color: string; icon: typeof Shield }> = {
  ip: { label: "IP Address", color: "text-cyan-400", icon: Globe },
  domain: { label: "Domain", color: "text-blue-400", icon: Globe },
  host: { label: "Hostname", color: "text-emerald-400", icon: Server },
  user: { label: "User", color: "text-purple-400", icon: User },
  email: { label: "Email", color: "text-amber-400", icon: FileText },
  file_hash: { label: "File Hash", color: "text-red-400", icon: Hash },
  url: { label: "URL", color: "text-indigo-400", icon: Link2 },
  process: { label: "Process", color: "text-orange-400", icon: Server },
};

const RELATIONSHIP_LABELS: Record<string, string> = {
  attack_path: "Attack Path",
  uses: "Uses",
  targeted_by: "Targeted By",
  associated_with: "Associated With",
  co_occurred: "Co-occurred",
};

function getEntityMeta(type: string) {
  return ENTITY_TYPE_META[type] || { label: type, color: "text-muted-foreground", icon: Hash };
}

function formatDate(ts: string | null): string {
  if (!ts) return "\u2014";
  return new Date(ts).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
  });
}

function riskBadge(score: number) {
  if (score >= 0.8) return { label: "Critical", variant: "destructive" as const };
  if (score >= 0.6) return { label: "High", variant: "destructive" as const };
  if (score >= 0.4) return { label: "Medium", variant: "default" as const };
  if (score >= 0.2) return { label: "Low", variant: "secondary" as const };
  return { label: "Info", variant: "outline" as const };
}

export default function EntityMergeAliasPage() {
  usePageTitle("Entity Merge & Alias Management");
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const [searchTerm, setSearchTerm] = useState("");
  const [typeFilter, setTypeFilter] = useState<string>("all");
  const [selectedEntity, setSelectedEntity] = useState<Entity | null>(null);
  const [mergeTarget, setMergeTarget] = useState<Entity | null>(null);
  const [mergeSource, setMergeSource] = useState<Entity | null>(null);
  const [showMergeConfirm, setShowMergeConfirm] = useState(false);
  const [showAddAlias, setShowAddAlias] = useState(false);
  const [newAliasType, setNewAliasType] = useState("ip");
  const [newAliasValue, setNewAliasValue] = useState("");
  const [expandedEntity, setExpandedEntity] = useState<string | null>(null);

  const {
    data: entitiesData,
    isLoading,
    isError,
    refetch,
    isFetching,
  } = useQuery<Entity[]>({
    queryKey: ["/api/entities"],
  });

  const { data: aliases, isLoading: aliasesLoading } = useQuery<EntityAlias[]>({
    queryKey: ["/api/entities", selectedEntity?.id, "aliases"],
    enabled: !!selectedEntity,
  });

  const { data: relationships, isLoading: relationshipsLoading } = useQuery<EntityRelationship[]>({
    queryKey: ["/api/entities", selectedEntity?.id, "relationships"],
    enabled: !!selectedEntity,
  });

  const addAliasMutation = useMutation({
    mutationFn: async ({
      entityId,
      aliasType,
      aliasValue,
    }: {
      entityId: string;
      aliasType: string;
      aliasValue: string;
    }) => {
      const res = await apiRequest("POST", `/api/entities/${entityId}/aliases`, {
        aliasType,
        aliasValue,
        source: "manual",
      });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/entities", selectedEntity?.id, "aliases"] });
      setShowAddAlias(false);
      setNewAliasValue("");
      toast({ title: "Alias added", description: "Entity alias has been created." });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to add alias", description: error.message, variant: "destructive" });
    },
  });

  const mergeMutation = useMutation({
    mutationFn: async ({ targetId, sourceId }: { targetId: string; sourceId: string }) => {
      const res = await apiRequest("POST", "/api/entities/merge", { targetId, sourceId });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/entities"] });
      setShowMergeConfirm(false);
      setMergeTarget(null);
      setMergeSource(null);
      setSelectedEntity(null);
      toast({ title: "Entities merged", description: "Source entity has been merged into the target." });
    },
    onError: (error: Error) => {
      toast({ title: "Merge failed", description: error.message, variant: "destructive" });
    },
  });

  const entities = entitiesData ?? [];

  const filteredEntities = entities.filter((entity) => {
    const matchesSearch =
      !searchTerm ||
      entity.value.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (entity.displayName || "").toLowerCase().includes(searchTerm.toLowerCase());
    const matchesType = typeFilter === "all" || entity.type === typeFilter;
    return matchesSearch && matchesType;
  });

  const entityTypes = Array.from(new Set(entities.map((e) => e.type))).sort();

  const handleStartMerge = (target: Entity) => {
    setMergeTarget(target);
    setMergeSource(null);
  };

  const handleSelectMergeSource = (source: Entity) => {
    if (source.id === mergeTarget?.id) return;
    setMergeSource(source);
  };

  const handleConfirmMerge = () => {
    if (!mergeTarget || !mergeSource) return;
    mergeMutation.mutate({ targetId: mergeTarget.id, sourceId: mergeSource.id });
  };

  const handleAddAlias = () => {
    if (!selectedEntity || !newAliasValue.trim()) return;
    addAliasMutation.mutate({
      entityId: selectedEntity.id,
      aliasType: newAliasType,
      aliasValue: newAliasValue.trim(),
    });
  };

  return (
    <div className="p-4 md:p-6 space-y-6 max-w-[1400px] mx-auto">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-500/10 border border-cyan-500/20">
            <GitMerge className="h-5 w-5 text-cyan-400" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight">Entity Merge & Alias Management</h1>
            <p className="text-xs text-muted-foreground">
              Merge duplicate entities, manage aliases, and view entity relationships
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {mergeTarget && (
            <Button
              size="sm"
              variant="outline"
              onClick={() => {
                setMergeTarget(null);
                setMergeSource(null);
              }}
              className="h-8"
            >
              <XCircle className="h-3.5 w-3.5 mr-1.5" />
              Cancel Merge
            </Button>
          )}
          <Button size="sm" variant="outline" onClick={() => refetch()} disabled={isFetching} className="h-8">
            {isFetching ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
            <span className="ml-1.5 hidden sm:inline">Refresh</span>
          </Button>
        </div>
      </div>

      {mergeTarget && (
        <Card className="border-cyan-500/30 bg-cyan-500/5">
          <CardContent className="p-4">
            <div className="flex items-center gap-3 flex-wrap">
              <GitMerge className="h-5 w-5 text-cyan-400 shrink-0" />
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium">Merge Mode Active</p>
                <p className="text-xs text-muted-foreground">
                  Target: <span className="text-cyan-400 font-mono">{mergeTarget.value}</span>
                  {mergeSource ? (
                    <>
                      {" "}
                      &larr; Source: <span className="text-orange-400 font-mono">{mergeSource.value}</span>
                    </>
                  ) : (
                    " \u2014 Select a source entity to merge into this target"
                  )}
                </p>
              </div>
              {mergeSource && (
                <Button
                  size="sm"
                  onClick={() => setShowMergeConfirm(true)}
                  className="h-8 bg-cyan-600 hover:bg-cyan-700"
                >
                  <GitMerge className="h-3.5 w-3.5 mr-1.5" />
                  Confirm Merge
                </Button>
              )}
            </div>
          </CardContent>
        </Card>
      )}

      <div className="flex items-center gap-3 flex-wrap">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search entities by value or display name..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="pl-9 h-9 text-sm"
          />
        </div>
        <Select value={typeFilter} onValueChange={setTypeFilter}>
          <SelectTrigger className="w-[160px] h-9 text-sm">
            <SelectValue placeholder="All Types" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Types</SelectItem>
            {entityTypes.map((t) => {
              const meta = getEntityMeta(t);
              return (
                <SelectItem key={t} value={t}>
                  {meta.label}
                </SelectItem>
              );
            })}
          </SelectContent>
        </Select>
        <Badge variant="outline" className="text-xs h-9 px-3 flex items-center">
          {filteredEntities.length} entities
        </Badge>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-3">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm flex items-center gap-2">
                <Network className="h-4 w-4 text-muted-foreground" />
                Entity List
              </CardTitle>
              <CardDescription className="text-xs">
                Click an entity to view details. Use merge to combine duplicates.
              </CardDescription>
            </CardHeader>
            <CardContent className="p-0">
              {isLoading ? (
                <div className="p-4 space-y-3">
                  {Array.from({ length: 8 }).map((_, i) => (
                    <div key={i} className="flex items-center gap-3">
                      <Skeleton className="h-8 w-8 rounded-full" />
                      <div className="flex-1 space-y-1.5">
                        <Skeleton className="h-4 w-48" />
                        <Skeleton className="h-3 w-32" />
                      </div>
                    </div>
                  ))}
                </div>
              ) : isError ? (
                <div className="p-8 text-center">
                  <AlertTriangle className="h-8 w-8 text-destructive mx-auto mb-2" />
                  <p className="text-sm font-medium">Failed to load entities</p>
                  <Button size="sm" variant="outline" onClick={() => refetch()} className="mt-3">
                    Retry
                  </Button>
                </div>
              ) : filteredEntities.length === 0 ? (
                <div className="p-8 text-center">
                  <Network className="h-8 w-8 text-muted-foreground/30 mx-auto mb-2" />
                  <p className="text-sm font-medium">No entities found</p>
                  <p className="text-xs text-muted-foreground mt-1">
                    {searchTerm || typeFilter !== "all"
                      ? "Try adjusting your filters"
                      : "Entities are created automatically when alerts are ingested"}
                  </p>
                </div>
              ) : (
                <ScrollArea className="max-h-[600px]">
                  <div className="divide-y divide-border">
                    {filteredEntities.map((entity) => {
                      const meta = getEntityMeta(entity.type);
                      const Icon = meta.icon;
                      const risk = riskBadge(entity.riskScore);
                      const isSelected = selectedEntity?.id === entity.id;
                      const isExpanded = expandedEntity === entity.id;
                      const isMergeTarget = mergeTarget?.id === entity.id;
                      const isMergeSource = mergeSource?.id === entity.id;

                      return (
                        <div
                          key={entity.id}
                          className={`p-3 transition-colors cursor-pointer hover:bg-muted/30
                            ${isSelected ? "bg-muted/40 border-l-2 border-l-cyan-500" : ""}
                            ${isMergeTarget ? "bg-cyan-500/10 border-l-2 border-l-cyan-500" : ""}
                            ${isMergeSource ? "bg-orange-500/10 border-l-2 border-l-orange-500" : ""}`}
                          onClick={() => {
                            if (mergeTarget && !isMergeTarget) {
                              handleSelectMergeSource(entity);
                            } else {
                              setSelectedEntity(entity);
                              setExpandedEntity(isExpanded ? null : entity.id);
                            }
                          }}
                          role="button"
                          tabIndex={0}
                          onKeyDown={(e) => {
                            if (e.key === "Enter" || e.key === " ") {
                              e.preventDefault();
                              if (mergeTarget && !isMergeTarget) {
                                handleSelectMergeSource(entity);
                              } else {
                                setSelectedEntity(entity);
                                setExpandedEntity(isExpanded ? null : entity.id);
                              }
                            }
                          }}
                          aria-label={`Entity ${entity.value}, type ${meta.label}`}
                        >
                          <div className="flex items-center gap-3">
                            <div className="w-8 h-8 rounded-full flex items-center justify-center bg-muted/50 border border-border shrink-0">
                              <Icon className={`h-4 w-4 ${meta.color}`} />
                            </div>
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2 flex-wrap">
                                <span className="text-sm font-mono font-medium truncate">{entity.value}</span>
                                <Badge variant="outline" className={`text-[10px] ${meta.color}`}>
                                  {meta.label}
                                </Badge>
                                <Badge variant={risk.variant} className="text-[10px]">
                                  {risk.label} ({Math.round(entity.riskScore * 100)}%)
                                </Badge>
                                {isMergeTarget && <Badge className="text-[10px] bg-cyan-600">TARGET</Badge>}
                                {isMergeSource && <Badge className="text-[10px] bg-orange-600">SOURCE</Badge>}
                              </div>
                              <div className="flex items-center gap-3 mt-1 text-[10px] text-muted-foreground">
                                <span>{entity.alertCount} alerts</span>
                                <span>First: {formatDate(entity.firstSeenAt)}</span>
                                <span>Last: {formatDate(entity.lastSeenAt)}</span>
                              </div>
                            </div>
                            <div className="flex items-center gap-1 shrink-0">
                              {!mergeTarget && (
                                <TooltipProvider>
                                  <Tooltip>
                                    <TooltipTrigger asChild>
                                      <Button
                                        size="sm"
                                        variant="ghost"
                                        className="h-7 w-7 p-0"
                                        onClick={(e) => {
                                          e.stopPropagation();
                                          handleStartMerge(entity);
                                        }}
                                      >
                                        <GitMerge className="h-3.5 w-3.5" />
                                      </Button>
                                    </TooltipTrigger>
                                    <TooltipContent className="text-xs">Merge into this entity</TooltipContent>
                                  </Tooltip>
                                </TooltipProvider>
                              )}
                              {isExpanded ? (
                                <ChevronDown className="h-4 w-4 text-muted-foreground" />
                              ) : (
                                <ChevronRight className="h-4 w-4 text-muted-foreground" />
                              )}
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </ScrollArea>
              )}
            </CardContent>
          </Card>
        </div>

        <div className="space-y-4">
          {selectedEntity ? (
            <>
              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm flex items-center gap-2">
                    {(() => {
                      const meta = getEntityMeta(selectedEntity.type);
                      const Icon = meta.icon;
                      return <Icon className={`h-4 w-4 ${meta.color}`} />;
                    })()}
                    Entity Details
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div>
                    <Label className="text-[10px] text-muted-foreground uppercase tracking-wider">Value</Label>
                    <p className="text-sm font-mono mt-0.5 break-all">{selectedEntity.value}</p>
                  </div>
                  {selectedEntity.displayName && selectedEntity.displayName !== selectedEntity.value && (
                    <div>
                      <Label className="text-[10px] text-muted-foreground uppercase tracking-wider">Display Name</Label>
                      <p className="text-sm mt-0.5">{selectedEntity.displayName}</p>
                    </div>
                  )}
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <Label className="text-[10px] text-muted-foreground uppercase tracking-wider">Type</Label>
                      <p className="text-sm mt-0.5">{getEntityMeta(selectedEntity.type).label}</p>
                    </div>
                    <div>
                      <Label className="text-[10px] text-muted-foreground uppercase tracking-wider">Risk</Label>
                      <p className="text-sm mt-0.5">{Math.round(selectedEntity.riskScore * 100)}%</p>
                    </div>
                    <div>
                      <Label className="text-[10px] text-muted-foreground uppercase tracking-wider">Alerts</Label>
                      <p className="text-sm mt-0.5">{selectedEntity.alertCount}</p>
                    </div>
                    <div>
                      <Label className="text-[10px] text-muted-foreground uppercase tracking-wider">ID</Label>
                      <p className="text-[10px] font-mono mt-0.5 text-muted-foreground truncate">{selectedEntity.id}</p>
                    </div>
                  </div>
                  <Separator />
                  <div className="flex items-center gap-2">
                    <Button
                      size="sm"
                      variant="outline"
                      className="h-7 text-xs flex-1"
                      onClick={() => handleStartMerge(selectedEntity)}
                      disabled={!!mergeTarget}
                    >
                      <GitMerge className="h-3 w-3 mr-1" />
                      Merge Into This
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      className="h-7 text-xs flex-1"
                      onClick={() => setShowAddAlias(true)}
                    >
                      <Plus className="h-3 w-3 mr-1" />
                      Add Alias
                    </Button>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Link2 className="h-4 w-4 text-muted-foreground" />
                    Aliases
                    {aliases && (
                      <Badge variant="outline" className="text-[10px] ml-auto">
                        {aliases.length}
                      </Badge>
                    )}
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  {aliasesLoading ? (
                    <div className="space-y-2">
                      {Array.from({ length: 3 }).map((_, i) => (
                        <Skeleton key={i} className="h-8 w-full" />
                      ))}
                    </div>
                  ) : !aliases || aliases.length === 0 ? (
                    <div className="text-center py-4">
                      <Link2 className="h-6 w-6 text-muted-foreground/30 mx-auto mb-1" />
                      <p className="text-xs text-muted-foreground">No aliases configured</p>
                    </div>
                  ) : (
                    <div className="space-y-2">
                      {aliases.map((alias) => (
                        <div
                          key={alias.id}
                          className="flex items-center gap-2 p-2 rounded-md bg-muted/30 border border-border/50"
                        >
                          <Badge variant="outline" className="text-[10px] shrink-0">
                            {alias.aliasType}
                          </Badge>
                          <span className="text-xs font-mono truncate flex-1">{alias.aliasValue}</span>
                          <span className="text-[10px] text-muted-foreground shrink-0">{alias.source}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </CardContent>
              </Card>

              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Network className="h-4 w-4 text-muted-foreground" />
                    Relationships
                    {relationships && (
                      <Badge variant="outline" className="text-[10px] ml-auto">
                        {relationships.length}
                      </Badge>
                    )}
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  {relationshipsLoading ? (
                    <div className="space-y-2">
                      {Array.from({ length: 3 }).map((_, i) => (
                        <Skeleton key={i} className="h-10 w-full" />
                      ))}
                    </div>
                  ) : !relationships || relationships.length === 0 ? (
                    <div className="text-center py-4">
                      <Network className="h-6 w-6 text-muted-foreground/30 mx-auto mb-1" />
                      <p className="text-xs text-muted-foreground">No relationships found</p>
                    </div>
                  ) : (
                    <ScrollArea className="max-h-[300px]">
                      <div className="space-y-2">
                        {relationships.map((rel) => {
                          const relMeta = getEntityMeta(rel.relatedEntityType);
                          const RelIcon = relMeta.icon;
                          return (
                            <div
                              key={rel.relatedEntityId}
                              className="flex items-center gap-2 p-2 rounded-md bg-muted/30 border border-border/50 cursor-pointer hover:bg-muted/50 transition-colors"
                              onClick={() => {
                                const found = entities.find((e) => e.id === rel.relatedEntityId);
                                if (found) setSelectedEntity(found);
                              }}
                              role="button"
                              tabIndex={0}
                              onKeyDown={(e) => {
                                if (e.key === "Enter" || e.key === " ") {
                                  const found = entities.find((en) => en.id === rel.relatedEntityId);
                                  if (found) setSelectedEntity(found);
                                }
                              }}
                            >
                              <RelIcon className={`h-3.5 w-3.5 ${relMeta.color} shrink-0`} />
                              <div className="flex-1 min-w-0">
                                <span className="text-xs font-mono truncate block">{rel.relatedEntityValue}</span>
                                <span className="text-[10px] text-muted-foreground">
                                  {RELATIONSHIP_LABELS[rel.relationship] || rel.relationship}
                                  {" \u00b7 "}
                                  {rel.sharedAlertCount} shared alerts
                                </span>
                              </div>
                              <Badge
                                variant={riskBadge(rel.relatedEntityRiskScore).variant}
                                className="text-[10px] shrink-0"
                              >
                                {Math.round(rel.relatedEntityRiskScore * 100)}%
                              </Badge>
                            </div>
                          );
                        })}
                      </div>
                    </ScrollArea>
                  )}
                </CardContent>
              </Card>
            </>
          ) : (
            <Card>
              <CardContent className="p-8 text-center">
                <Info className="h-8 w-8 text-muted-foreground/30 mx-auto mb-2" />
                <p className="text-sm font-medium">Select an entity</p>
                <p className="text-xs text-muted-foreground mt-1">
                  Click on an entity from the list to view its details, aliases, and relationships.
                </p>
              </CardContent>
            </Card>
          )}
        </div>
      </div>

      <Dialog open={showAddAlias} onOpenChange={setShowAddAlias}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle className="text-sm flex items-center gap-2">
              <Plus className="h-4 w-4" />
              Add Alias
            </DialogTitle>
            <DialogDescription className="text-xs">
              Add an alternative identifier for{" "}
              <span className="font-mono text-foreground">{selectedEntity?.value}</span>
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-1.5">
              <Label className="text-xs">Alias Type</Label>
              <Select value={newAliasType} onValueChange={setNewAliasType}>
                <SelectTrigger className="h-9 text-sm">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {Object.entries(ENTITY_TYPE_META).map(([key, meta]) => (
                    <SelectItem key={key} value={key}>
                      {meta.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">Alias Value</Label>
              <Input
                placeholder="e.g. 192.168.1.100, malware.example.com"
                value={newAliasValue}
                onChange={(e) => setNewAliasValue(e.target.value)}
                className="h-9 text-sm font-mono"
                onKeyDown={(e) => {
                  if (e.key === "Enter") handleAddAlias();
                }}
              />
            </div>
          </div>
          <DialogFooter>
            <Button size="sm" variant="outline" onClick={() => setShowAddAlias(false)}>
              Cancel
            </Button>
            <Button size="sm" onClick={handleAddAlias} disabled={!newAliasValue.trim() || addAliasMutation.isPending}>
              {addAliasMutation.isPending && <Loader2 className="h-3.5 w-3.5 animate-spin mr-1.5" />}
              Add Alias
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <AlertDialog open={showMergeConfirm} onOpenChange={setShowMergeConfirm}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2 text-sm">
              <GitMerge className="h-4 w-4 text-cyan-400" />
              Confirm Entity Merge
            </AlertDialogTitle>
            <AlertDialogDescription className="text-xs space-y-2">
              <p>This will merge the source entity into the target entity. This action is irreversible.</p>
              {mergeTarget && mergeSource && (
                <div className="mt-3 space-y-2">
                  <div className="flex items-center gap-2 p-2 rounded bg-cyan-500/10 border border-cyan-500/20">
                    <Badge className="text-[10px] bg-cyan-600 shrink-0">TARGET</Badge>
                    <span className="text-xs font-mono">{mergeTarget.value}</span>
                    <Badge variant="outline" className="text-[10px]">
                      {getEntityMeta(mergeTarget.type).label}
                    </Badge>
                  </div>
                  <div className="flex items-center justify-center">
                    <ArrowRight className="h-4 w-4 text-muted-foreground rotate-[-90deg]" />
                  </div>
                  <div className="flex items-center gap-2 p-2 rounded bg-orange-500/10 border border-orange-500/20">
                    <Badge className="text-[10px] bg-orange-600 shrink-0">SOURCE</Badge>
                    <span className="text-xs font-mono">{mergeSource.value}</span>
                    <Badge variant="outline" className="text-[10px]">
                      {getEntityMeta(mergeSource.type).label}
                    </Badge>
                  </div>
                  <div className="mt-2 p-2 rounded bg-muted/50 border text-[10px] text-muted-foreground space-y-1">
                    <p>What happens on merge:</p>
                    <ul className="list-disc list-inside space-y-0.5">
                      <li>All alerts from source will be re-linked to target</li>
                      <li>All aliases from source will transfer to target</li>
                      <li>Source value becomes an alias of target</li>
                      <li>Risk score takes the higher of both</li>
                      <li>Source entity is permanently deleted</li>
                    </ul>
                  </div>
                </div>
              )}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel className="text-xs h-8">Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleConfirmMerge}
              disabled={mergeMutation.isPending}
              className="text-xs h-8 bg-cyan-600 hover:bg-cyan-700"
            >
              {mergeMutation.isPending && <Loader2 className="h-3.5 w-3.5 animate-spin mr-1.5" />}
              Merge Entities
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

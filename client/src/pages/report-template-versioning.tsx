import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { usePageTitle } from "@/hooks/use-page-title";
import { useToast } from "@/hooks/use-toast";
import {
  FileText,
  GitBranch,
  Clock,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Search,
  Loader2,
  Eye,
  RotateCcw,
  ArrowRight,
  History,
  Shield,
  Archive,
  FilePlus,
  ChevronRight,
  RefreshCw,
  User,
  Calendar,
} from "lucide-react";
import { SuccessIcon } from "@/components/ui/animated-state-icons";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Input } from "@/components/ui/input";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";

interface ReportTemplate {
  id: string;
  orgId: string;
  name: string;
  description: string | null;
  reportType: string;
  format: string;
  dashboardRole: string | null;
  isBuiltIn: boolean;
  createdBy: string | null;
  createdAt: string;
  updatedAt: string | null;
}

interface TemplateVersion {
  id: string;
  orgId: string;
  templateId: string;
  version: number;
  changeDescription: string;
  config: string | null;
  format: string | null;
  status: string;
  approvedBy: string | null;
  approvedAt: string | null;
  createdBy: string | null;
  createdAt: string;
}

function LoadingSkeleton() {
  return (
    <div className="p-6 space-y-6" role="status" aria-label="Loading report template versioning">
      <Skeleton className="h-8 w-80" />
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={i} className="h-24" />
        ))}
      </div>
      <Skeleton className="h-96" />
      <span className="sr-only">Loading report template versioning...</span>
    </div>
  );
}

function ErrorState({ onRetry }: { onRetry: () => void }) {
  return (
    <div className="p-6">
      <Card className="glass-card border-red-500/30">
        <CardContent className="flex flex-col items-center justify-center py-12">
          <AlertTriangle className="h-12 w-12 text-red-400 mb-4" />
          <p className="text-lg font-semibold mb-2">Failed to Load Report Templates</p>
          <p className="text-sm text-muted-foreground mb-4">Could not retrieve template data from the server.</p>
          <Button onClick={onRetry} variant="outline" size="sm">
            <RefreshCw className="h-4 w-4 mr-1" /> Retry
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  const config: Record<string, { color: string; icon: typeof CheckCircle2 }> = {
    active: { color: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30", icon: CheckCircle2 },
    draft: { color: "bg-amber-500/15 text-amber-400 border-amber-500/30", icon: Clock },
    deprecated: { color: "bg-red-500/15 text-red-400 border-red-500/30", icon: XCircle },
    archived: { color: "bg-slate-500/15 text-slate-400 border-slate-500/30", icon: Archive },
  };
  const c = config[status] || config.draft;
  const Icon = c.icon;
  return (
    <Badge variant="outline" className={`${c.color} text-xs`}>
      <Icon className="h-3 w-3 mr-1" />
      {status.charAt(0).toUpperCase() + status.slice(1)}
    </Badge>
  );
}

function VersionDiffViewer({ current, previous }: { current: TemplateVersion; previous: TemplateVersion | null }) {
  if (!previous) {
    return (
      <div className="text-xs text-muted-foreground p-3 bg-muted/30 rounded-md">
        Initial version — no previous version to compare
      </div>
    );
  }

  const changes: { field: string; from: string; to: string }[] = [];
  if (current.format !== previous.format) {
    changes.push({ field: "Format", from: previous.format || "—", to: current.format || "—" });
  }
  if (current.status !== previous.status) {
    changes.push({ field: "Status", from: previous.status, to: current.status });
  }
  if (current.config !== previous.config) {
    changes.push({ field: "Config", from: "Modified", to: "Updated" });
  }

  if (changes.length === 0) {
    return (
      <div className="text-xs text-muted-foreground p-3 bg-muted/30 rounded-md">
        Only the change description differs from v{previous.version}
      </div>
    );
  }

  return (
    <div className="space-y-1">
      {changes.map((c) => (
        <div key={c.field} className="flex items-center gap-2 text-xs">
          <span className="text-muted-foreground w-16">{c.field}:</span>
          <span className="text-red-400 line-through">{c.from}</span>
          <ArrowRight className="h-3 w-3 text-muted-foreground" />
          <span className="text-emerald-400">{c.to}</span>
        </div>
      ))}
    </div>
  );
}

function TemplateDetailPanel({
  template,
  versions,
  isLoadingVersions,
  onCreateVersion,
  onApproveVersion,
  onRollback,
}: {
  template: ReportTemplate;
  versions: TemplateVersion[];
  isLoadingVersions: boolean;
  onCreateVersion: () => void;
  onApproveVersion: (versionId: string) => void;
  onRollback: (versionId: string) => void;
}) {
  const [activeDetailTab, setActiveDetailTab] = useState("versions");
  const activeVersion = versions.find((v) => v.status === "active");
  const draftVersions = versions.filter((v) => v.status === "draft");
  const sortedVersions = [...versions].sort((a, b) => b.version - a.version);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-semibold">{template.name}</h3>
          <p className="text-sm text-muted-foreground">{template.description || "No description"}</p>
        </div>
        <Button size="sm" onClick={onCreateVersion} className="gap-1">
          <FilePlus className="h-4 w-4" /> New Version
        </Button>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="p-3 rounded-md bg-muted/30 border border-border/50">
          <p className="text-xs text-muted-foreground">Total Versions</p>
          <p className="text-xl font-bold">{versions.length}</p>
        </div>
        <div className="p-3 rounded-md bg-muted/30 border border-border/50">
          <p className="text-xs text-muted-foreground">Active Version</p>
          <p className="text-xl font-bold">{activeVersion ? `v${activeVersion.version}` : "None"}</p>
        </div>
        <div className="p-3 rounded-md bg-muted/30 border border-border/50">
          <p className="text-xs text-muted-foreground">Draft Versions</p>
          <p className="text-xl font-bold">{draftVersions.length}</p>
        </div>
        <div className="p-3 rounded-md bg-muted/30 border border-border/50">
          <p className="text-xs text-muted-foreground">Format</p>
          <p className="text-xl font-bold uppercase">{template.format}</p>
        </div>
      </div>

      <Tabs value={activeDetailTab} onValueChange={setActiveDetailTab}>
        <TabsList className="w-full">
          <TabsTrigger value="versions" className="flex-1">
            <History className="h-4 w-4 mr-1" /> Version History
          </TabsTrigger>
          <TabsTrigger value="approval" className="flex-1">
            <Shield className="h-4 w-4 mr-1" /> Approval Queue
          </TabsTrigger>
        </TabsList>

        <TabsContent value="versions" className="mt-3">
          {isLoadingVersions ? (
            <div className="space-y-2">
              {Array.from({ length: 3 }).map((_, i) => (
                <Skeleton key={i} className="h-20" />
              ))}
            </div>
          ) : sortedVersions.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
              <History className="h-10 w-10 mb-3 opacity-40" />
              <p className="text-sm">No versions yet</p>
              <p className="text-xs mt-1">Create the first version to start tracking changes</p>
            </div>
          ) : (
            <ScrollArea className="h-[400px]">
              <div className="space-y-3 pr-3">
                {sortedVersions.map((version, idx) => {
                  const prevVersion = sortedVersions[idx + 1] || null;
                  return (
                    <Card key={version.id} className="glass-card border-border/40">
                      <CardContent className="p-4">
                        <div className="flex items-start justify-between mb-2">
                          <div className="flex items-center gap-2">
                            <span className="text-sm font-semibold">v{version.version}</span>
                            <StatusBadge status={version.status} />
                          </div>
                          <div className="flex items-center gap-1">
                            {version.status === "draft" && (
                              <TooltipProvider>
                                <Tooltip>
                                  <TooltipTrigger asChild>
                                    <Button
                                      variant="ghost"
                                      size="icon"
                                      className="h-7 w-7"
                                      onClick={() => onApproveVersion(version.id)}
                                    >
                                      <SuccessIcon size={16} color="#22c55e" />
                                    </Button>
                                  </TooltipTrigger>
                                  <TooltipContent>Approve &amp; Activate</TooltipContent>
                                </Tooltip>
                              </TooltipProvider>
                            )}
                            {version.status !== "active" && version.status !== "draft" && (
                              <TooltipProvider>
                                <Tooltip>
                                  <TooltipTrigger asChild>
                                    <Button
                                      variant="ghost"
                                      size="icon"
                                      className="h-7 w-7"
                                      onClick={() => onRollback(version.id)}
                                    >
                                      <RotateCcw className="h-4 w-4 text-amber-400" />
                                    </Button>
                                  </TooltipTrigger>
                                  <TooltipContent>Rollback to this version</TooltipContent>
                                </Tooltip>
                              </TooltipProvider>
                            )}
                          </div>
                        </div>
                        <p className="text-sm text-muted-foreground mb-2">{version.changeDescription}</p>
                        <VersionDiffViewer current={version} previous={prevVersion} />
                        <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
                          <span className="flex items-center gap-1">
                            <Calendar className="h-3 w-3" />
                            {new Date(version.createdAt).toLocaleDateString()}
                          </span>
                          {version.approvedBy && (
                            <span className="flex items-center gap-1">
                              <User className="h-3 w-3" />
                              Approved
                              {version.approvedAt && ` on ${new Date(version.approvedAt).toLocaleDateString()}`}
                            </span>
                          )}
                        </div>
                      </CardContent>
                    </Card>
                  );
                })}
              </div>
            </ScrollArea>
          )}
        </TabsContent>

        <TabsContent value="approval" className="mt-3">
          {draftVersions.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
              <Shield className="h-10 w-10 mb-3 opacity-40" />
              <p className="text-sm">No versions pending approval</p>
              <p className="text-xs mt-1">All versions have been reviewed</p>
            </div>
          ) : (
            <div className="space-y-3">
              {draftVersions
                .sort((a, b) => b.version - a.version)
                .map((v) => (
                  <Card key={v.id} className="glass-card border-amber-500/20">
                    <CardContent className="p-4">
                      <div className="flex items-center justify-between">
                        <div>
                          <span className="text-sm font-semibold">v{v.version}</span>
                          <p className="text-xs text-muted-foreground mt-1">{v.changeDescription}</p>
                        </div>
                        <Button size="sm" onClick={() => onApproveVersion(v.id)} className="gap-1">
                          <SuccessIcon size={16} color="#22c55e" /> Approve
                        </Button>
                      </div>
                    </CardContent>
                  </Card>
                ))}
            </div>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}

export default function ReportTemplateVersioningPage() {
  usePageTitle("Report Template Versioning");
  const { toast } = useToast();
  const [selectedTemplateId, setSelectedTemplateId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [typeFilter, setTypeFilter] = useState<string>("all");
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [newVersionDesc, setNewVersionDesc] = useState("");
  const [newVersionFormat, setNewVersionFormat] = useState("");
  const [newVersionConfig, setNewVersionConfig] = useState("");

  const {
    data: templates,
    isLoading: isLoadingTemplates,
    isError: isErrorTemplates,
    refetch: refetchTemplates,
  } = useQuery<ReportTemplate[]>({
    queryKey: ["/api/report-templates"],
  });

  const { data: versions, isLoading: isLoadingVersions } = useQuery<TemplateVersion[]>({
    queryKey: ["/api/report-templates", String(selectedTemplateId), "versions"],
    queryFn: async () => {
      const headers: Record<string, string> = {};
      try {
        const activeOrgId = localStorage.getItem("securenexus.activeOrgId");
        if (activeOrgId) headers["X-Org-Id"] = activeOrgId;
      } catch {
        /* privacy mode */
      }
      const res = await fetch(`/api/report-templates/${selectedTemplateId}/versions`, {
        credentials: "include",
        headers,
      });
      if (!res.ok) return [];
      const body = await res.json();
      return body && typeof body === "object" && "data" in body && "meta" in body && "errors" in body
        ? body.data
        : body;
    },
    enabled: !!selectedTemplateId,
  });

  const createVersionMutation = useMutation({
    mutationFn: async (data: { changeDescription: string; config?: string; format?: string }) => {
      const res = await apiRequest("POST", `/api/report-templates/${selectedTemplateId}/versions`, data);
      return res.json();
    },
    onSuccess: () => {
      toast({ title: "Version Created", description: "New template version has been created" });
      queryClient.invalidateQueries({ queryKey: ["/api/report-templates", String(selectedTemplateId), "versions"] });
      setShowCreateDialog(false);
      setNewVersionDesc("");
      setNewVersionFormat("");
      setNewVersionConfig("");
    },
    onError: (err: Error) => {
      toast({ title: "Error", description: err.message, variant: "destructive" });
    },
  });

  const approveVersionMutation = useMutation({
    mutationFn: async ({
      versionId,
      currentActiveVersionId,
    }: {
      versionId: string;
      currentActiveVersionId?: string;
    }) => {
      if (currentActiveVersionId) {
        await apiRequest("PATCH", `/api/report-template-versions/${currentActiveVersionId}`, {
          status: "deprecated",
        });
      }
      const res = await apiRequest("PATCH", `/api/report-template-versions/${versionId}`, { status: "active" });
      return res.json();
    },
    onSuccess: () => {
      toast({ title: "Version Approved", description: "Version is now active" });
      queryClient.invalidateQueries({ queryKey: ["/api/report-templates", String(selectedTemplateId), "versions"] });
    },
    onError: (err: Error) => {
      toast({ title: "Error", description: err.message, variant: "destructive" });
    },
  });

  const rollbackMutation = useMutation({
    mutationFn: async ({
      targetVersionId,
      currentActiveVersionId,
    }: {
      targetVersionId: string;
      currentActiveVersionId?: string;
    }) => {
      if (currentActiveVersionId) {
        await apiRequest("PATCH", `/api/report-template-versions/${currentActiveVersionId}`, {
          status: "deprecated",
        });
      }
      const res = await apiRequest("PATCH", `/api/report-template-versions/${targetVersionId}`, { status: "active" });
      return res.json();
    },
    onSuccess: () => {
      toast({ title: "Rollback Complete", description: "Template has been rolled back to the selected version" });
      queryClient.invalidateQueries({ queryKey: ["/api/report-templates", String(selectedTemplateId), "versions"] });
    },
    onError: (err: Error) => {
      toast({ title: "Error", description: err.message, variant: "destructive" });
    },
  });

  if (isLoadingTemplates) return <LoadingSkeleton />;
  if (isErrorTemplates) return <ErrorState onRetry={() => refetchTemplates()} />;

  const allTemplates = Array.isArray(templates) ? templates : [];
  const reportTypes = Array.from(new Set(allTemplates.map((t) => t.reportType)));

  const filteredTemplates = allTemplates.filter((t) => {
    const matchesSearch =
      !searchQuery ||
      t.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (t.description || "").toLowerCase().includes(searchQuery.toLowerCase());
    const matchesType = typeFilter === "all" || t.reportType === typeFilter;
    return matchesSearch && matchesType;
  });

  const selectedTemplate = allTemplates.find((t) => t.id === selectedTemplateId) || null;
  const builtInCount = allTemplates.filter((t) => t.isBuiltIn).length;
  const customCount = allTemplates.length - builtInCount;
  const formatDistribution = allTemplates.reduce(
    (acc, t) => {
      const fmt = (t.format || "other").toUpperCase();
      acc[fmt] = (acc[fmt] || 0) + 1;
      return acc;
    },
    {} as Record<string, number>,
  );

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Report Template Versioning</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Manage template versions, view diffs, approve changes, and rollback
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card className="glass-card">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground">Total Templates</p>
                <p className="text-2xl font-bold">{allTemplates.length}</p>
              </div>
              <FileText className="h-8 w-8 text-cyan-400 opacity-60" />
            </div>
          </CardContent>
        </Card>
        <Card className="glass-card">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground">Built-in</p>
                <p className="text-2xl font-bold">{builtInCount}</p>
              </div>
              <Shield className="h-8 w-8 text-emerald-400 opacity-60" />
            </div>
          </CardContent>
        </Card>
        <Card className="glass-card">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground">Custom</p>
                <p className="text-2xl font-bold">{customCount}</p>
              </div>
              <FilePlus className="h-8 w-8 text-amber-400 opacity-60" />
            </div>
          </CardContent>
        </Card>
        <Card className="glass-card">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground">Report Types</p>
                <p className="text-2xl font-bold">{reportTypes.length}</p>
              </div>
              <GitBranch className="h-8 w-8 text-purple-400 opacity-60" />
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search templates..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-10"
          />
        </div>
        <Select value={typeFilter} onValueChange={setTypeFilter}>
          <SelectTrigger className="w-[180px]">
            <SelectValue placeholder="All types" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Types</SelectItem>
            {reportTypes.map((t) => (
              <SelectItem key={t} value={t}>
                {t.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase())}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-1">
          <Card className="glass-card">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">Templates ({filteredTemplates.length})</CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              {filteredTemplates.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-12 text-muted-foreground px-4">
                  <FileText className="h-10 w-10 mb-3 opacity-40" />
                  <p className="text-sm">No templates found</p>
                  {searchQuery && <p className="text-xs mt-1">Try adjusting your search</p>}
                </div>
              ) : (
                <ScrollArea className="h-[500px]">
                  <div className="space-y-1 p-2">
                    {filteredTemplates.map((t) => (
                      <button
                        key={t.id}
                        onClick={() => setSelectedTemplateId(t.id)}
                        className={`w-full text-left p-3 rounded-md transition-colors hover:bg-accent/50 ${
                          selectedTemplateId === t.id ? "bg-accent border border-accent-foreground/10" : ""
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <span className="text-sm font-medium truncate">{t.name}</span>
                          <ChevronRight className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                        </div>
                        <div className="flex items-center gap-2 mt-1">
                          <Badge variant="outline" className="text-[10px] px-1.5 py-0">
                            {t.reportType.replace(/_/g, " ")}
                          </Badge>
                          <Badge variant="outline" className="text-[10px] px-1.5 py-0 uppercase">
                            {t.format}
                          </Badge>
                          {t.isBuiltIn && (
                            <Badge
                              variant="outline"
                              className="text-[10px] px-1.5 py-0 bg-cyan-500/10 text-cyan-400 border-cyan-500/30"
                            >
                              built-in
                            </Badge>
                          )}
                        </div>
                        <p className="text-xs text-muted-foreground mt-1 line-clamp-1">
                          {t.description || "No description"}
                        </p>
                      </button>
                    ))}
                  </div>
                </ScrollArea>
              )}
            </CardContent>
          </Card>

          {Object.keys(formatDistribution).length > 0 && (
            <Card className="glass-card mt-4">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">Format Breakdown</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {Object.entries(formatDistribution).map(([fmt, count]) => (
                    <div key={fmt} className="flex items-center justify-between">
                      <span className="text-xs text-muted-foreground">{fmt}</span>
                      <div className="flex items-center gap-2">
                        <div className="w-24 h-1.5 bg-muted rounded-full overflow-hidden">
                          <div
                            className="h-full bg-cyan-500 rounded-full"
                            style={{ width: `${(count / allTemplates.length) * 100}%` }}
                          />
                        </div>
                        <span className="text-xs font-medium w-6 text-right">{count}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </div>

        <div className="lg:col-span-2">
          {selectedTemplate ? (
            <Card className="glass-card">
              <CardContent className="p-4">
                <TemplateDetailPanel
                  template={selectedTemplate}
                  versions={Array.isArray(versions) ? versions : []}
                  isLoadingVersions={isLoadingVersions}
                  onCreateVersion={() => setShowCreateDialog(true)}
                  onApproveVersion={(id) => {
                    const currentActive = (Array.isArray(versions) ? versions : []).find((v) => v.status === "active");
                    approveVersionMutation.mutate({
                      versionId: id,
                      currentActiveVersionId: currentActive?.id,
                    });
                  }}
                  onRollback={(id) => {
                    const currentActive = (Array.isArray(versions) ? versions : []).find((v) => v.status === "active");
                    rollbackMutation.mutate({
                      targetVersionId: id,
                      currentActiveVersionId: currentActive?.id,
                    });
                  }}
                />
              </CardContent>
            </Card>
          ) : (
            <Card className="glass-card">
              <CardContent className="flex flex-col items-center justify-center py-24">
                <Eye className="h-12 w-12 text-muted-foreground/30 mb-4" />
                <p className="text-sm text-muted-foreground">Select a template to view version history</p>
                <p className="text-xs text-muted-foreground mt-1">
                  Click on any template from the list to inspect its versions
                </p>
              </CardContent>
            </Card>
          )}
        </div>
      </div>

      <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create New Version</DialogTitle>
            <DialogDescription>Create a new version for &ldquo;{selectedTemplate?.name}&rdquo;</DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div>
              <Label htmlFor="change-desc">Change Description</Label>
              <Textarea
                id="change-desc"
                placeholder="Describe what changed in this version..."
                value={newVersionDesc}
                onChange={(e) => setNewVersionDesc(e.target.value)}
                className="mt-1"
              />
            </div>
            <div>
              <Label htmlFor="version-format">Format (optional)</Label>
              <Select value={newVersionFormat} onValueChange={setNewVersionFormat}>
                <SelectTrigger id="version-format" className="mt-1">
                  <SelectValue placeholder="Same as template" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="csv">CSV</SelectItem>
                  <SelectItem value="json">JSON</SelectItem>
                  <SelectItem value="pdf">PDF</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label htmlFor="version-config">Config JSON (optional)</Label>
              <Textarea
                id="version-config"
                placeholder='{"columns": [...], "filters": {...}}'
                value={newVersionConfig}
                onChange={(e) => setNewVersionConfig(e.target.value)}
                className="mt-1 font-mono text-xs"
                rows={3}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowCreateDialog(false)}>
              Cancel
            </Button>
            <Button
              onClick={() => {
                if (!newVersionDesc.trim()) {
                  toast({
                    title: "Validation Error",
                    description: "Change description is required",
                    variant: "destructive",
                  });
                  return;
                }
                createVersionMutation.mutate({
                  changeDescription: newVersionDesc.trim(),
                  format: newVersionFormat || undefined,
                  config: newVersionConfig || undefined,
                });
              }}
              disabled={createVersionMutation.isPending}
            >
              {createVersionMutation.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              ) : (
                <FilePlus className="h-4 w-4 mr-1" />
              )}
              Create
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

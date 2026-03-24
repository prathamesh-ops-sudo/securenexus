import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import {
  BookOpen,
  Search,
  Star,
  Download,
  Layers,
  Shield,
  Zap,
  Bug,
  Cloud,
  UserX,
  Target,
  Loader2,
  Eye,
  BarChart3,
  ArrowUpCircle,
  Clock,
  CheckCircle2,
  FileText,
  RefreshCw,
  AlertTriangle,
  Crosshair,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { useToast } from "@/hooks/use-toast";
import { usePageTitle } from "@/hooks/use-page-title";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

export default function PlaybookTemplatesPage() {
  usePageTitle("Playbook Templates");
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [search, setSearch] = useState("");
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null);
  const [selectedTemplate, setSelectedTemplate] = useState<string | null>(null);
  const [previewId, setPreviewId] = useState<string | null>(null);
  const [statsId, setStatsId] = useState<string | null>(null);
  const [versionsId, setVersionsId] = useState<string | null>(null);

  const { data: templates, isLoading } = useQuery({
    queryKey: ["/api/playbook-templates", search, selectedCategory],
    queryFn: async () => {
      const params = new URLSearchParams();
      if (search) params.set("search", search);
      if (selectedCategory) params.set("category", selectedCategory);
      const r = await apiRequest("GET", `/api/playbook-templates?${params.toString()}`);
      return r.json();
    },
  });

  const { data: categories } = useQuery({
    queryKey: ["/api/playbook-templates/categories"],
    queryFn: async () => {
      const r = await apiRequest("GET", "/api/playbook-templates/categories");
      return r.json();
    },
  });

  const { data: detail } = useQuery({
    queryKey: ["/api/playbook-templates", selectedTemplate],
    queryFn: async () => {
      const r = await apiRequest("GET", `/api/playbook-templates/${selectedTemplate}`);
      return r.json();
    },
    enabled: !!selectedTemplate,
  });

  // 23.2: Preview query
  const { data: previewData } = useQuery({
    queryKey: ["/api/playbook-templates", previewId, "preview"],
    queryFn: async () => {
      const r = await apiRequest("GET", `/api/playbook-templates/${previewId}/preview`);
      return r.json();
    },
    enabled: !!previewId,
  });

  // 23.3: Stats query
  const { data: statsData } = useQuery({
    queryKey: ["/api/playbook-templates", statsId, "stats"],
    queryFn: async () => {
      const r = await apiRequest("GET", `/api/playbook-templates/${statsId}/stats`);
      return r.json();
    },
    enabled: !!statsId,
  });

  // 23.5: Versions query
  const { data: versionsData } = useQuery({
    queryKey: ["/api/playbook-templates", versionsId, "versions"],
    queryFn: async () => {
      const r = await apiRequest("GET", `/api/playbook-templates/${versionsId}/versions`);
      return r.json();
    },
    enabled: !!versionsId,
  });

  // 23.5: Check for updates
  const { data: updatesData } = useQuery({
    queryKey: ["/api/playbook-templates/check-updates"],
    queryFn: async () => {
      const r = await apiRequest("GET", "/api/playbook-templates/check-updates");
      return r.json();
    },
  });

  // 23.3: Rate mutation
  const rateMutation = useMutation({
    mutationFn: async ({ id, rating }: { id: string; rating: number }) => {
      const r = await apiRequest("POST", `/api/playbook-templates/${id}/rate`, { rating });
      return r.json();
    },
    onSuccess: () => {
      toast({ title: "Rating submitted" });
      queryClient.invalidateQueries({ queryKey: ["/api/playbook-templates"] });
    },
    onError: () => toast({ title: "Failed to submit rating", variant: "destructive" }),
  });

  const deployMutation = useMutation({
    mutationFn: async (id: string) => {
      const r = await apiRequest("POST", `/api/playbook-templates/${id}/deploy`);
      return r.json();
    },
    onSuccess: () => {
      toast({ title: "Template Deployed", description: "Playbook created from template." });
      queryClient.invalidateQueries({ queryKey: ["/api/playbook-templates"] });
    },
    onError: () => toast({ title: "Deploy Failed", variant: "destructive" }),
  });

  const templateList = Array.isArray(templates) ? templates : (templates as any)?.data || [];
  const categoryList = Array.isArray(categories) ? categories : [];
  const templateDetail = detail as any;
  const preview = previewData as any;
  const stats = statsData as any;
  const versions = versionsData as any;
  const updates = (updatesData as any)?.updates || [];

  if (isLoading) {
    return (
      <div className="p-6 space-y-4">
        <Skeleton className="h-8 w-64" />
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {[1, 2, 3, 4, 5, 6].map((i) => (
            <Skeleton key={i} className="h-48" />
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <BookOpen className="h-6 w-6" />
            Playbook Templates
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Pre-built response playbooks for common security scenarios
          </p>
        </div>
        {updates.length > 0 && (
          <Badge variant="outline" className="gap-1">
            <ArrowUpCircle className="h-3 w-3" />
            {updates.length} update{updates.length !== 1 ? "s" : ""} available
          </Badge>
        )}
      </div>

      {/* 23.5: Update notification banner */}
      {updates.length > 0 && (
        <Card className="border-blue-500/20 bg-blue-500/5">
          <CardContent className="py-3">
            <div className="flex items-center gap-2">
              <ArrowUpCircle className="h-4 w-4 text-blue-400" />
              <span className="text-sm font-medium">Template Updates Available</span>
            </div>
            <div className="mt-2 space-y-1">
              {updates.map((u: any, i: number) => (
                <div key={i} className="flex items-center justify-between text-xs">
                  <span>
                    <span className="font-medium">{u.templateName}</span>{" "}
                    <span className="text-muted-foreground">
                      v{u.deployedVersion} → v{u.latestVersion}
                    </span>
                  </span>
                  <span className="text-muted-foreground truncate max-w-[300px]">{u.changelog}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* 23.1: Enhanced search and category filter */}
      <div className="flex flex-wrap gap-3">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search templates by name, description, or tags..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-10"
          />
        </div>
        <div className="flex gap-2 flex-wrap">
          <Button
            size="sm"
            variant={selectedCategory === null ? "default" : "outline"}
            onClick={() => setSelectedCategory(null)}
          >
            All
          </Button>
          {categoryList.map((cat: string) => (
            <Button
              key={cat}
              size="sm"
              variant={selectedCategory === cat ? "default" : "outline"}
              onClick={() => setSelectedCategory(cat)}
            >
              <CategoryIcon category={cat} />
              <span className="ml-1">{cat}</span>
            </Button>
          ))}
        </div>
      </div>

      {/* Stats bar */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="pt-4 flex items-center gap-2">
            <BookOpen className="h-5 w-5 text-primary" />
            <div>
              <p className="text-2xl font-bold">{templateList.length}</p>
              <p className="text-xs text-muted-foreground">Templates</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 flex items-center gap-2">
            <Layers className="h-5 w-5 text-purple-400" />
            <div>
              <p className="text-2xl font-bold">{categoryList.length}</p>
              <p className="text-xs text-muted-foreground">Categories</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 flex items-center gap-2">
            <Download className="h-5 w-5 text-green-500" />
            <div>
              <p className="text-2xl font-bold">
                {templateList.reduce((sum: number, t: any) => sum + (t.usageCount || 0), 0)}
              </p>
              <p className="text-xs text-muted-foreground">Total Deployments</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 flex items-center gap-2">
            <Star className="h-5 w-5 text-yellow-400" />
            <div>
              <p className="text-2xl font-bold">
                {templateList.length > 0
                  ? (
                      templateList.reduce((sum: number, t: any) => sum + (t.rating || 0), 0) / templateList.length
                    ).toFixed(1)
                  : "0"}
              </p>
              <p className="text-xs text-muted-foreground">Avg Rating</p>
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-4">
          {templateList.length === 0 && (
            <Card className="border-dashed border-border bg-card/30">
              <CardContent className="py-12 text-center">
                <BookOpen className="h-12 w-12 text-muted-foreground mx-auto mb-3" />
                <p className="text-muted-foreground">No templates match your search</p>
              </CardContent>
            </Card>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {templateList.map((tpl: any) => (
              <Card
                key={tpl.id}
                onClick={() => setSelectedTemplate(tpl.id)}
                className={`cursor-pointer transition-all hover:shadow-sm ${selectedTemplate === tpl.id ? "border-primary bg-primary/5" : ""}`}
              >
                <CardContent className="p-4">
                  <div className="flex items-start justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <CategoryIcon category={tpl.category} />
                      <span className="text-sm font-medium">{tpl.name}</span>
                    </div>
                    <SeverityBadge severity={tpl.severity} />
                  </div>
                  <p className="text-xs text-muted-foreground line-clamp-2 mb-3">{tpl.description}</p>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      {/* 23.3: Interactive rating stars */}
                      <div className="flex items-center gap-0.5">
                        {[1, 2, 3, 4, 5].map((s) => (
                          <Star
                            key={s}
                            className={`h-3 w-3 cursor-pointer ${
                              s <= Math.round(tpl.rating || 0)
                                ? "text-yellow-400 fill-yellow-400"
                                : "text-muted-foreground"
                            }`}
                            onClick={(e) => {
                              e.stopPropagation();
                              rateMutation.mutate({ id: tpl.id, rating: s });
                            }}
                          />
                        ))}
                        <span className="text-xs ml-1">{tpl.rating}</span>
                      </div>
                      <span className="text-xs text-muted-foreground">{tpl.usageCount} uses</span>
                    </div>
                    <Badge variant="outline" className="text-xs">
                      {tpl.category}
                    </Badge>
                  </div>
                  <div className="flex gap-1 mt-2">
                    {(tpl.tags || []).slice(0, 3).map((tag: string) => (
                      <Badge key={tag} variant="outline" className="text-xs">
                        {tag}
                      </Badge>
                    ))}
                    {(tpl.tags || []).length > 3 && (
                      <Badge variant="outline" className="text-xs">
                        +{tpl.tags.length - 3}
                      </Badge>
                    )}
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>

        {/* Right sidebar - template detail */}
        <div>
          {!selectedTemplate && (
            <Card className="border-dashed border-border bg-card/30">
              <CardContent className="py-12 text-center">
                <Layers className="h-10 w-10 text-muted-foreground mx-auto mb-2" />
                <p className="text-sm text-muted-foreground">Select a template to view details</p>
              </CardContent>
            </Card>
          )}

          {selectedTemplate && templateDetail && (
            <Card className="sticky top-6">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <CardTitle className="text-lg">{templateDetail.name}</CardTitle>
                  <Badge variant="outline">v{templateDetail.version}</Badge>
                </div>
                <p className="text-sm text-muted-foreground">{templateDetail.description}</p>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center gap-2 text-sm">
                  <span className="text-muted-foreground">By:</span>
                  <span>{templateDetail.author}</span>
                  <span className="text-muted-foreground">|</span>
                  <span className="text-muted-foreground">{templateDetail.usageCount} deployments</span>
                </div>

                <div>
                  <h3 className="text-sm font-semibold mb-2">Steps ({templateDetail.steps?.length || 0})</h3>
                  <div className="space-y-2">
                    {(templateDetail.steps || []).map((step: any, i: number) => (
                      <div key={step.id || i} className="flex items-center gap-2 p-2 rounded bg-muted/50 text-sm">
                        <span className="flex items-center justify-center w-5 h-5 rounded-full bg-primary/20 text-primary text-xs font-bold">
                          {step.order || i + 1}
                        </span>
                        <span className="flex-1 text-xs">{step.name}</span>
                        <StepTypeBadge type={step.type} />
                      </div>
                    ))}
                  </div>
                </div>

                <div className="flex flex-wrap gap-1">
                  {(templateDetail.tags || []).map((tag: string) => (
                    <Badge key={tag} variant="outline" className="text-xs">
                      {tag}
                    </Badge>
                  ))}
                </div>

                {/* Action buttons */}
                <div className="space-y-2">
                  <Button
                    className="w-full"
                    onClick={() => deployMutation.mutate(templateDetail.id)}
                    disabled={deployMutation.isPending}
                  >
                    {deployMutation.isPending ? (
                      <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                    ) : (
                      <Download className="h-4 w-4 mr-2" />
                    )}
                    Deploy as Playbook
                  </Button>

                  {/* 23.2, 23.3, 23.5 action buttons */}
                  <div className="flex gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      className="flex-1"
                      onClick={() => setPreviewId(templateDetail.id)}
                    >
                      <Eye className="mr-1 h-3 w-3" />
                      Preview
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      className="flex-1"
                      onClick={() => setStatsId(templateDetail.id)}
                    >
                      <BarChart3 className="mr-1 h-3 w-3" />
                      Stats
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      className="flex-1"
                      onClick={() => setVersionsId(templateDetail.id)}
                    >
                      <FileText className="mr-1 h-3 w-3" />
                      Versions
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      </div>

      {/* 23.2: PREVIEW DIALOG */}
      <Dialog open={!!previewId} onOpenChange={() => setPreviewId(null)}>
        <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Eye className="h-5 w-5" />
              Template Preview — {preview?.name}
            </DialogTitle>
          </DialogHeader>
          {preview ? (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <p className="text-xs text-muted-foreground">Category</p>
                  <p className="text-sm font-medium">{preview.category}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Severity</p>
                  <SeverityBadge severity={preview.severity} />
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Author</p>
                  <p className="text-sm">{preview.author}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Version</p>
                  <p className="text-sm">v{preview.version}</p>
                </div>
              </div>

              <p className="text-sm text-muted-foreground">{preview.description}</p>

              {/* Workflow summary */}
              {preview.workflow && (
                <>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                    <Card>
                      <CardContent className="pt-3 text-center">
                        <p className="text-lg font-bold">{preview.workflow.totalSteps}</p>
                        <p className="text-xs text-muted-foreground">Total Steps</p>
                      </CardContent>
                    </Card>
                    <Card>
                      <CardContent className="pt-3 text-center">
                        <p className="text-lg font-bold">{preview.workflow.automationPercentage}%</p>
                        <p className="text-xs text-muted-foreground">Automated</p>
                      </CardContent>
                    </Card>
                    <Card>
                      <CardContent className="pt-3 text-center">
                        <Clock className="h-4 w-4 mx-auto mb-1 text-primary" />
                        <p className="text-lg font-bold">{preview.workflow.estimatedDurationFormatted}</p>
                        <p className="text-xs text-muted-foreground">Est. Duration</p>
                      </CardContent>
                    </Card>
                    <Card>
                      <CardContent className="pt-3 text-center">
                        <p className="text-lg font-bold">{preview.workflow.approvalSteps}</p>
                        <p className="text-xs text-muted-foreground">Approvals</p>
                      </CardContent>
                    </Card>
                  </div>

                  {/* Step breakdown by type */}
                  <div className="flex gap-4 text-xs">
                    <span className="text-muted-foreground">
                      <Badge variant="outline" className="mr-1">
                        Automated
                      </Badge>
                      {preview.workflow.automatedSteps}
                    </span>
                    <span className="text-muted-foreground">
                      <Badge variant="outline" className="mr-1">
                        Manual
                      </Badge>
                      {preview.workflow.manualSteps}
                    </span>
                    <span className="text-muted-foreground">
                      <Badge variant="outline" className="mr-1">
                        Approval
                      </Badge>
                      {preview.workflow.approvalSteps}
                    </span>
                    <span className="text-muted-foreground">
                      <Badge variant="outline" className="mr-1">
                        Notification
                      </Badge>
                      {preview.workflow.notificationSteps}
                    </span>
                  </div>

                  {/* Workflow steps visualization */}
                  <div>
                    <h3 className="text-sm font-semibold mb-2">Workflow Steps</h3>
                    <div className="space-y-1">
                      {(preview.workflow.steps || []).map((step: any, i: number) => (
                        <div key={step.id || i} className="flex items-center gap-3 p-2 rounded bg-muted/50">
                          <div className="flex flex-col items-center">
                            <span className="flex items-center justify-center w-6 h-6 rounded-full bg-primary/20 text-primary text-xs font-bold">
                              {step.order}
                            </span>
                            {!step.isLast && <div className="w-px h-4 bg-border" />}
                          </div>
                          <div className="flex-1 min-w-0">
                            <p className="text-sm font-medium">{step.name}</p>
                            <p className="text-xs text-muted-foreground">{step.description}</p>
                          </div>
                          <StepTypeBadge type={step.type} />
                        </div>
                      ))}
                    </div>
                  </div>
                </>
              )}

              <div className="flex flex-wrap gap-1">
                {(preview.tags || []).map((tag: string) => (
                  <Badge key={tag} variant="outline" className="text-xs">
                    {tag}
                  </Badge>
                ))}
              </div>
            </div>
          ) : (
            <div className="flex justify-center py-8">
              <Loader2 className="h-6 w-6 animate-spin" />
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* 23.3: STATS DIALOG */}
      <Dialog open={!!statsId} onOpenChange={() => setStatsId(null)}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <BarChart3 className="h-5 w-5" />
              Template Statistics — {stats?.name}
            </DialogTitle>
          </DialogHeader>
          {stats ? (
            <div className="space-y-4">
              <div className="grid grid-cols-3 gap-3">
                <Card>
                  <CardContent className="pt-3 text-center">
                    <Star className="h-4 w-4 mx-auto mb-1 text-yellow-400" />
                    <p className="text-lg font-bold">{stats.averageRating}</p>
                    <p className="text-xs text-muted-foreground">Avg Rating</p>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent className="pt-3 text-center">
                    <p className="text-lg font-bold">{stats.totalRatings}</p>
                    <p className="text-xs text-muted-foreground">Total Ratings</p>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent className="pt-3 text-center">
                    <Download className="h-4 w-4 mx-auto mb-1 text-green-500" />
                    <p className="text-lg font-bold">{stats.usageCount}</p>
                    <p className="text-xs text-muted-foreground">Deployments</p>
                  </CardContent>
                </Card>
              </div>

              {/* Rating distribution */}
              <div>
                <h3 className="text-sm font-semibold mb-2">Rating Distribution</h3>
                {[5, 4, 3, 2, 1].map((star) => {
                  const count = stats.ratingDistribution?.[star] || 0;
                  const total = stats.totalRatings || 1;
                  const pct = Math.round((count / total) * 100) || 0;
                  return (
                    <div key={star} className="flex items-center gap-2 mb-1">
                      <span className="text-xs w-4">{star}</span>
                      <Star className="h-3 w-3 text-yellow-400" />
                      <div className="flex-1 bg-muted rounded h-2">
                        <div className="bg-yellow-400 h-2 rounded" style={{ width: `${pct}%` }} />
                      </div>
                      <span className="text-xs text-muted-foreground w-8">{count}</span>
                    </div>
                  );
                })}
              </div>

              {/* Recent reviews */}
              {(stats.recentReviews || []).length > 0 && (
                <div>
                  <h3 className="text-sm font-semibold mb-2">Recent Reviews</h3>
                  <div className="space-y-2">
                    {stats.recentReviews.map((r: any, i: number) => (
                      <div key={i} className="p-2 rounded bg-muted/50">
                        <div className="flex items-center gap-1 mb-1">
                          {[1, 2, 3, 4, 5].map((s) => (
                            <Star
                              key={s}
                              className={`h-3 w-3 ${s <= r.rating ? "text-yellow-400 fill-yellow-400" : "text-muted-foreground"}`}
                            />
                          ))}
                          <span className="text-xs text-muted-foreground ml-2">
                            {new Date(r.createdAt).toLocaleDateString()}
                          </span>
                        </div>
                        {r.comment && <p className="text-xs">{r.comment}</p>}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="flex justify-center py-8">
              <Loader2 className="h-6 w-6 animate-spin" />
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* 23.5: VERSIONS DIALOG */}
      <Dialog open={!!versionsId} onOpenChange={() => setVersionsId(null)}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <FileText className="h-5 w-5" />
              Version History
            </DialogTitle>
          </DialogHeader>
          {versions ? (
            <div className="space-y-4">
              <div className="flex items-center gap-2">
                <span className="text-sm text-muted-foreground">Current Version:</span>
                <Badge>v{versions.currentVersion}</Badge>
              </div>
              <div className="space-y-2">
                {(versions.versions || []).map((v: any, i: number) => (
                  <div key={i} className="flex items-start gap-3 p-2 rounded bg-muted/50">
                    <div className="flex flex-col items-center">
                      <div
                        className={`w-2 h-2 rounded-full mt-1.5 ${i === (versions.versions || []).length - 1 ? "bg-primary" : "bg-muted-foreground"}`}
                      />
                      {i < (versions.versions || []).length - 1 && <div className="w-px h-6 bg-border" />}
                    </div>
                    <div>
                      <p className="text-sm font-medium">v{v.version}</p>
                      <p className="text-xs text-muted-foreground">{v.changelog}</p>
                      <p className="text-xs text-muted-foreground">
                        {v.publishedAt ? new Date(v.publishedAt).toLocaleDateString() : "N/A"}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="flex justify-center py-8">
              <Loader2 className="h-6 w-6 animate-spin" />
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}

function CategoryIcon({ category }: { category: string }) {
  switch (category) {
    case "Incident Response":
      return <Shield className="h-4 w-4 text-red-400" />;
    case "Email Security":
      return <Zap className="h-4 w-4 text-yellow-400" />;
    case "Cloud Security":
      return <Cloud className="h-4 w-4 text-blue-400" />;
    case "Insider Threat":
      return <UserX className="h-4 w-4 text-orange-400" />;
    case "Vulnerability Management":
      return <Bug className="h-4 w-4 text-green-400" />;
    case "Compliance":
      return <CheckCircle2 className="h-4 w-4 text-emerald-400" />;
    case "Remediation":
      return <RefreshCw className="h-4 w-4 text-indigo-400" />;
    case "Threat Hunting":
      return <Crosshair className="h-4 w-4 text-purple-400" />;
    default:
      return <Target className="h-4 w-4 text-cyan-400" />;
  }
}

function SeverityBadge({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    critical: "bg-red-500/20 text-red-400",
    high: "bg-orange-500/20 text-orange-400",
    medium: "bg-yellow-500/20 text-yellow-400",
    low: "bg-green-500/20 text-green-400",
  };
  return <Badge className={`text-xs ${colors[severity] || colors.medium}`}>{severity}</Badge>;
}

function StepTypeBadge({ type }: { type: string }) {
  const colors: Record<string, string> = {
    automated: "bg-cyan-500/20 text-cyan-400",
    manual: "bg-yellow-500/20 text-yellow-400",
    approval: "bg-purple-500/20 text-purple-400",
    notification: "bg-blue-500/20 text-blue-400",
  };
  return <Badge className={`text-xs ${colors[type] || "bg-gray-500/20 text-gray-400"}`}>{type}</Badge>;
}

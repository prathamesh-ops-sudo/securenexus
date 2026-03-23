import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { usePageTitle } from "@/hooks/use-page-title";
import {
  Brain,
  RefreshCw,
  Loader2,
  Star,
  Send,
  MessageSquare,
  ThumbsUp,
  ThumbsDown,
  AlertTriangle,
  CheckCircle2,
  Filter,
  TrendingUp,
  TrendingDown,
  BarChart3,
  Lightbulb,
  Zap,
  Target,
  ArrowUpRight,
  Activity,
  PieChart,
  ShieldAlert,
} from "lucide-react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { useToast } from "@/hooks/use-toast";

interface AiFeedback {
  id: string;
  orgId: string | null;
  userId: string | null;
  userName: string | null;
  resourceType: string;
  resourceId: string | null;
  rating: number;
  comment: string | null;
  correctionReason: string | null;
  correctedSeverity: string | null;
  correctedCategory: string | null;
  aiOutput: unknown;
  createdAt: string | null;
}

interface FeedbackMetric {
  date: string;
  avgRating: number;
  totalFeedback: number;
  negativeFeedback: number;
  positiveFeedback: number;
}

interface FeedbackAnalytics {
  summary: {
    totalFeedback: number;
    totalPositive: number;
    totalNegative: number;
    avgRating: number;
    positiveRate: number;
  };
  trends: FeedbackMetric[];
  categoryBreakdown: Record<string, { count: number; avgRating: number; topIssues: string[] }>;
  topCorrectionReasons: Array<{ reason: string; count: number }>;
  promptImprovementSuggestions: Array<{ category: string; issue: string; suggestedFix: string; confidence: string }>;
  period: string;
}

const RESOURCE_TYPES = [
  { value: "alert", label: "Alert" },
  { value: "incident", label: "Incident" },
  { value: "threat_intel", label: "Threat Intel" },
  { value: "playbook", label: "Playbook" },
  { value: "detection_rule", label: "Detection Rule" },
  { value: "correlation", label: "Correlation" },
  { value: "recommendation", label: "Recommendation" },
  { value: "other", label: "Other" },
];

const SEVERITY_OPTIONS = ["critical", "high", "medium", "low", "informational"];

function formatDate(dateStr: string | null): string {
  if (!dateStr) return "—";
  return new Date(dateStr).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function RatingStars({
  value,
  onChange,
  readonly = false,
}: {
  value: number;
  onChange?: (v: number) => void;
  readonly?: boolean;
}) {
  const [hovered, setHovered] = useState(0);
  return (
    <div className="flex items-center gap-0.5">
      {[1, 2, 3, 4, 5].map((star) => (
        <button
          key={star}
          type="button"
          disabled={readonly}
          className={`p-0.5 transition-colors ${readonly ? "cursor-default" : "cursor-pointer hover:scale-110"}`}
          onMouseEnter={() => !readonly && setHovered(star)}
          onMouseLeave={() => !readonly && setHovered(0)}
          onClick={() => onChange?.(star)}
        >
          <Star
            className={`h-5 w-5 ${
              star <= (hovered || value) ? "text-yellow-400 fill-yellow-400" : "text-muted-foreground/30"
            }`}
          />
        </button>
      ))}
    </div>
  );
}

export default function AiFeedbackFormPage() {
  usePageTitle("AI Feedback");
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const [resourceType, setResourceType] = useState("alert");
  const [resourceId, setResourceId] = useState("");
  const [rating, setRating] = useState(0);
  const [comment, setComment] = useState("");
  const [correctionReason, setCorrectionReason] = useState("");
  const [correctedSeverity, setCorrectedSeverity] = useState("");
  const [correctedCategory, setCorrectedCategory] = useState("");
  const [filterType, setFilterType] = useState("all");

  const [ratingError, setRatingError] = useState("");
  const [resourceTypeError, setResourceTypeError] = useState("");

  const {
    data: feedbackList,
    isPending: listPending,
    isError: listError,
    refetch: refetchList,
    isFetching: listFetching,
  } = useQuery<AiFeedback[]>({
    queryKey: ["/api/ai/feedback", filterType],
    queryFn: async () => {
      const params = new URLSearchParams();
      if (filterType !== "all") params.set("resourceType", filterType);
      const res = await apiRequest("GET", `/api/ai/feedback?${params.toString()}`);
      const data = await res.json();
      return Array.isArray(data) ? data : [];
    },
  });

  const { data: metrics, isPending: metricsPending } = useQuery<FeedbackMetric[]>({
    queryKey: ["/api/ai/feedback/metrics"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/ai/feedback/metrics?days=30");
      const data = await res.json();
      return Array.isArray(data) ? data : [];
    },
  });

  const submitMutation = useMutation({
    mutationFn: async (data: {
      resourceType: string;
      resourceId?: string;
      rating: number;
      comment?: string;
      correctionReason?: string;
      correctedSeverity?: string;
      correctedCategory?: string;
    }) => {
      const res = await apiRequest("POST", "/api/ai/feedback", data);
      return res.json();
    },
    onSuccess: () => {
      toast({ title: "Feedback submitted", description: "Your AI feedback has been recorded." });
      setRating(0);
      setComment("");
      setResourceId("");
      setCorrectionReason("");
      setCorrectedSeverity("");
      setCorrectedCategory("");
      setRatingError("");
      setResourceTypeError("");
      queryClient.invalidateQueries({ queryKey: ["/api/ai/feedback"] });
      queryClient.invalidateQueries({ queryKey: ["/api/ai/feedback/metrics"] });
    },
    onError: (err: Error) => {
      toast({ title: "Submission failed", description: err.message, variant: "destructive" });
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    let valid = true;
    if (rating < 1) {
      setRatingError("Please select a rating");
      valid = false;
    } else {
      setRatingError("");
    }
    if (!resourceType) {
      setResourceTypeError("Please select a resource type");
      valid = false;
    } else {
      setResourceTypeError("");
    }
    if (!valid) return;

    const payload: Record<string, unknown> = { resourceType, rating };
    if (resourceId.trim()) payload.resourceId = resourceId.trim();
    if (comment.trim()) payload.comment = comment.trim();
    if (correctionReason.trim()) payload.correctionReason = correctionReason.trim();
    if (correctedSeverity && correctedSeverity !== "none") payload.correctedSeverity = correctedSeverity;
    if (correctedCategory.trim()) payload.correctedCategory = correctedCategory.trim();
    submitMutation.mutate(payload as Parameters<typeof submitMutation.mutate>[0]);
  };

  const totalFeedback = metrics?.reduce((sum, m) => sum + m.totalFeedback, 0) ?? 0;
  const totalPositive = metrics?.reduce((sum, m) => sum + m.positiveFeedback, 0) ?? 0;
  const totalNegative = metrics?.reduce((sum, m) => sum + m.negativeFeedback, 0) ?? 0;
  const avgRating =
    metrics && metrics.length > 0
      ? metrics.reduce((sum, m) => sum + m.avgRating * m.totalFeedback, 0) / Math.max(totalFeedback, 1)
      : 0;

  return (
    <div className="p-4 md:p-6 space-y-6 max-w-[1400px] mx-auto">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-gradient-to-br from-purple-500/20 to-blue-500/10 border border-purple-500/20">
            <Brain className="h-5 w-5 text-purple-400" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight">AI Feedback & Learning</h1>
            <p className="text-xs text-muted-foreground">
              Rate AI outputs, track improvement trends, and view prompt improvement suggestions
            </p>
          </div>
        </div>
        <Button size="sm" variant="outline" onClick={() => refetchList()} disabled={listFetching} className="h-8">
          {listFetching ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
          <span className="ml-1.5 hidden sm:inline">Refresh</span>
        </Button>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
        <Card>
          <CardContent className="p-4 flex items-center gap-3">
            <div className="p-2 rounded-lg bg-blue-500/10 border border-blue-500/20">
              <MessageSquare className="h-4 w-4 text-blue-400" />
            </div>
            <div>
              <p className="text-2xl font-bold tabular-nums">
                {metricsPending ? <Skeleton className="h-7 w-8 inline-block" /> : totalFeedback}
              </p>
              <p className="text-[11px] text-muted-foreground">Total (30d)</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 flex items-center gap-3">
            <div className="p-2 rounded-lg bg-yellow-500/10 border border-yellow-500/20">
              <Star className="h-4 w-4 text-yellow-400" />
            </div>
            <div>
              <p className="text-2xl font-bold tabular-nums">
                {metricsPending ? <Skeleton className="h-7 w-8 inline-block" /> : avgRating.toFixed(1)}
              </p>
              <p className="text-[11px] text-muted-foreground">Avg Rating</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 flex items-center gap-3">
            <div className="p-2 rounded-lg bg-emerald-500/10 border border-emerald-500/20">
              <ThumbsUp className="h-4 w-4 text-emerald-400" />
            </div>
            <div>
              <p className="text-2xl font-bold tabular-nums text-emerald-400">
                {metricsPending ? <Skeleton className="h-7 w-8 inline-block" /> : totalPositive}
              </p>
              <p className="text-[11px] text-muted-foreground">Positive</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 flex items-center gap-3">
            <div className="p-2 rounded-lg bg-red-500/10 border border-red-500/20">
              <ThumbsDown className="h-4 w-4 text-red-400" />
            </div>
            <div>
              <p className="text-2xl font-bold tabular-nums text-red-400">
                {metricsPending ? <Skeleton className="h-7 w-8 inline-block" /> : totalNegative}
              </p>
              <p className="text-[11px] text-muted-foreground">Negative</p>
            </div>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="feedback" className="w-full">
        <TabsList>
          <TabsTrigger value="feedback">Submit & Review</TabsTrigger>
          <TabsTrigger value="analytics">Analytics Dashboard</TabsTrigger>
          <TabsTrigger value="suggestions">Improvement Suggestions</TabsTrigger>
          <TabsTrigger value="inline-guide">Inline Feedback</TabsTrigger>
        </TabsList>

        <TabsContent value="feedback" className="mt-4">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <Card className="lg:col-span-1">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Send className="h-4 w-4 text-muted-foreground" />
                  Submit Feedback
                </CardTitle>
                <CardDescription className="text-xs">
                  Rate an AI output and optionally provide corrections
                </CardDescription>
              </CardHeader>
              <CardContent>
                <form onSubmit={handleSubmit} className="space-y-4">
                  <div className="space-y-1.5">
                    <Label className="text-xs">Resource Type *</Label>
                    <Select
                      value={resourceType}
                      onValueChange={(v) => {
                        setResourceType(v);
                        setResourceTypeError("");
                      }}
                    >
                      <SelectTrigger className="h-8 text-xs">
                        <SelectValue placeholder="Select type" />
                      </SelectTrigger>
                      <SelectContent>
                        {RESOURCE_TYPES.map((t) => (
                          <SelectItem key={t.value} value={t.value}>
                            {t.label}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    {resourceTypeError && <p className="text-[11px] text-destructive">{resourceTypeError}</p>}
                  </div>

                  <div className="space-y-1.5">
                    <Label className="text-xs">Resource ID (optional)</Label>
                    <Input
                      className="h-8 text-xs"
                      placeholder="e.g. alert UUID or incident ID"
                      value={resourceId}
                      onChange={(e) => setResourceId(e.target.value)}
                    />
                  </div>

                  <div className="space-y-1.5">
                    <Label className="text-xs">Rating *</Label>
                    <RatingStars
                      value={rating}
                      onChange={(v) => {
                        setRating(v);
                        setRatingError("");
                      }}
                    />
                    {ratingError && <p className="text-[11px] text-destructive">{ratingError}</p>}
                  </div>

                  <div className="space-y-1.5">
                    <Label className="text-xs">Comment</Label>
                    <Textarea
                      className="text-xs min-h-[60px]"
                      placeholder="Describe what was good or what went wrong..."
                      value={comment}
                      onChange={(e) => setComment(e.target.value)}
                    />
                  </div>

                  <div className="space-y-1.5">
                    <Label className="text-xs">Correction Reason</Label>
                    <Input
                      className="h-8 text-xs"
                      placeholder="Why is the AI output incorrect?"
                      value={correctionReason}
                      onChange={(e) => setCorrectionReason(e.target.value)}
                    />
                  </div>

                  <div className="grid grid-cols-2 gap-3">
                    <div className="space-y-1.5">
                      <Label className="text-xs">Corrected Severity</Label>
                      <Select
                        value={correctedSeverity}
                        onValueChange={(v) => setCorrectedSeverity(v === "none" ? "" : v)}
                      >
                        <SelectTrigger className="h-8 text-xs">
                          <SelectValue placeholder="Select" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="none">None</SelectItem>
                          {SEVERITY_OPTIONS.map((s) => (
                            <SelectItem key={s} value={s}>
                              {s.charAt(0).toUpperCase() + s.slice(1)}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="space-y-1.5">
                      <Label className="text-xs">Corrected Category</Label>
                      <Input
                        className="h-8 text-xs"
                        placeholder="e.g. malware"
                        value={correctedCategory}
                        onChange={(e) => setCorrectedCategory(e.target.value)}
                      />
                    </div>
                  </div>

                  <Button type="submit" size="sm" className="w-full h-8" disabled={submitMutation.isPending}>
                    {submitMutation.isPending ? (
                      <Loader2 className="h-3.5 w-3.5 animate-spin mr-1.5" />
                    ) : (
                      <Send className="h-3.5 w-3.5 mr-1.5" />
                    )}
                    Submit Feedback
                  </Button>
                </form>
              </CardContent>
            </Card>

            <Card className="lg:col-span-2">
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between flex-wrap gap-2">
                  <div>
                    <CardTitle className="text-sm flex items-center gap-2">
                      <MessageSquare className="h-4 w-4 text-muted-foreground" />
                      Recent Feedback
                    </CardTitle>
                    <CardDescription className="text-xs mt-1">
                      {(feedbackList ?? []).length} feedback entries
                    </CardDescription>
                  </div>
                  <div className="flex items-center gap-2">
                    <Filter className="h-3.5 w-3.5 text-muted-foreground" />
                    <Select value={filterType} onValueChange={setFilterType}>
                      <SelectTrigger className="w-[120px] h-7 text-xs">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="all">All Types</SelectItem>
                        {RESOURCE_TYPES.map((t) => (
                          <SelectItem key={t.value} value={t.value}>
                            {t.label}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="p-0">
                {listPending ? (
                  <div className="p-4 space-y-3">
                    {Array.from({ length: 5 }).map((_, i) => (
                      <Skeleton key={i} className="h-12 w-full" />
                    ))}
                  </div>
                ) : listError ? (
                  <div className="p-8 text-center">
                    <AlertTriangle className="h-8 w-8 text-destructive mx-auto mb-2" />
                    <p className="text-sm text-muted-foreground">Failed to load feedback</p>
                    <Button size="sm" variant="outline" onClick={() => refetchList()} className="mt-3">
                      Retry
                    </Button>
                  </div>
                ) : (feedbackList ?? []).length === 0 ? (
                  <div className="p-8 text-center">
                    <MessageSquare className="h-8 w-8 text-muted-foreground/50 mx-auto mb-2" />
                    <p className="text-sm font-medium">No feedback submitted yet</p>
                    <p className="text-xs text-muted-foreground mt-1">
                      Use the form to submit your first AI feedback entry.
                    </p>
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead className="text-xs">Rating</TableHead>
                          <TableHead className="text-xs">Type</TableHead>
                          <TableHead className="text-xs">Resource</TableHead>
                          <TableHead className="text-xs">Comment</TableHead>
                          <TableHead className="text-xs">Correction</TableHead>
                          <TableHead className="text-xs">User</TableHead>
                          <TableHead className="text-xs">Date</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {(feedbackList ?? []).map((fb) => (
                          <TableRow key={fb.id}>
                            <TableCell>
                              <RatingStars value={fb.rating} readonly />
                            </TableCell>
                            <TableCell>
                              <Badge variant="outline" className="text-[10px]">
                                {fb.resourceType}
                              </Badge>
                            </TableCell>
                            <TableCell className="font-mono text-xs">
                              {fb.resourceId ? `${fb.resourceId.slice(0, 8)}...` : "—"}
                            </TableCell>
                            <TableCell className="text-xs max-w-[200px] truncate">
                              <TooltipProvider>
                                <Tooltip>
                                  <TooltipTrigger asChild>
                                    <span>{fb.comment || "—"}</span>
                                  </TooltipTrigger>
                                  {fb.comment && (
                                    <TooltipContent className="text-xs max-w-[300px]">{fb.comment}</TooltipContent>
                                  )}
                                </Tooltip>
                              </TooltipProvider>
                            </TableCell>
                            <TableCell className="text-xs">
                              {fb.correctedSeverity || fb.correctedCategory ? (
                                <div className="flex flex-col gap-0.5">
                                  {fb.correctedSeverity && (
                                    <Badge
                                      variant="outline"
                                      className="text-[10px] text-orange-400 border-orange-500/30 bg-orange-500/10"
                                    >
                                      {fb.correctedSeverity}
                                    </Badge>
                                  )}
                                  {fb.correctedCategory && (
                                    <span className="text-[10px] text-muted-foreground">{fb.correctedCategory}</span>
                                  )}
                                </div>
                              ) : (
                                "—"
                              )}
                            </TableCell>
                            <TableCell className="text-xs text-muted-foreground">{fb.userName || "—"}</TableCell>
                            <TableCell className="text-xs text-muted-foreground">{formatDate(fb.createdAt)}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* 35.2: Feedback Analytics Dashboard */}
        <TabsContent value="analytics" className="mt-4">
          <FeedbackAnalyticsDashboard />
        </TabsContent>

        {/* 35.3: Prompt Improvement Suggestions */}
        <TabsContent value="suggestions" className="mt-4">
          <PromptImprovementSuggestions />
        </TabsContent>

        {/* 35.1: Inline Feedback Guide */}
        <TabsContent value="inline-guide" className="mt-4">
          <InlineFeedbackGuide />
        </TabsContent>
      </Tabs>
    </div>
  );
}

/* ── 35.2: Feedback Analytics Dashboard ── */
function FeedbackAnalyticsDashboard() {
  const { data: analytics, isLoading } = useQuery<FeedbackAnalytics>({
    queryKey: ["/api/ai/feedback/analytics"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/ai/feedback/analytics?days=30");
      return res.json();
    },
  });

  if (isLoading) {
    return (
      <div className="space-y-4">
        {Array.from({ length: 3 }).map((_, i) => (
          <Skeleton key={i} className="h-32 w-full" />
        ))}
      </div>
    );
  }

  if (!analytics) {
    return (
      <Card>
        <CardContent className="flex flex-col items-center justify-center py-16 text-muted-foreground">
          <BarChart3 className="h-10 w-10 mb-3 opacity-30" />
          <p className="text-sm font-medium">No analytics data available</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      {/* Summary Row */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        <Card>
          <CardContent className="p-4 text-center">
            <p className="text-2xl font-bold tabular-nums">{analytics.summary.totalFeedback}</p>
            <p className="text-[11px] text-muted-foreground">Total Feedback</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 text-center">
            <p className="text-2xl font-bold tabular-nums">{analytics.summary.avgRating.toFixed(1)}</p>
            <p className="text-[11px] text-muted-foreground">Avg Rating</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 text-center">
            <p className="text-2xl font-bold tabular-nums text-emerald-400">{analytics.summary.positiveRate}%</p>
            <p className="text-[11px] text-muted-foreground">Positive Rate</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 text-center">
            <p className="text-2xl font-bold tabular-nums text-emerald-400">{analytics.summary.totalPositive}</p>
            <p className="text-[11px] text-muted-foreground">Positive</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 text-center">
            <p className="text-2xl font-bold tabular-nums text-red-400">{analytics.summary.totalNegative}</p>
            <p className="text-[11px] text-muted-foreground">Negative</p>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Accuracy Trend */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm flex items-center gap-2">
              <Activity className="h-4 w-4" /> Rating Trend ({analytics.period})
            </CardTitle>
          </CardHeader>
          <CardContent>
            {analytics.trends.length === 0 ? (
              <p className="text-sm text-muted-foreground text-center py-8">No trend data yet</p>
            ) : (
              <ScrollArea className="h-[200px]">
                <div className="space-y-1">
                  {analytics.trends.slice(-14).map((m, i) => (
                    <div
                      key={`${m.date}-${i}`}
                      className="flex items-center justify-between text-xs py-1 border-b border-border/30"
                    >
                      <span className="text-muted-foreground tabular-nums">{m.date}</span>
                      <div className="flex items-center gap-3">
                        <span className="tabular-nums">{m.avgRating.toFixed(1)} avg</span>
                        <span className="text-emerald-400 tabular-nums">{m.positiveFeedback} pos</span>
                        <span className="text-red-400 tabular-nums">{m.negativeFeedback} neg</span>
                      </div>
                    </div>
                  ))}
                </div>
              </ScrollArea>
            )}
          </CardContent>
        </Card>

        {/* Category Breakdown */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm flex items-center gap-2">
              <PieChart className="h-4 w-4" /> Feedback by Category
            </CardTitle>
          </CardHeader>
          <CardContent>
            {Object.keys(analytics.categoryBreakdown).length === 0 ? (
              <p className="text-sm text-muted-foreground text-center py-8">No category data yet</p>
            ) : (
              <div className="space-y-2">
                {Object.entries(analytics.categoryBreakdown).map(([cat, data]) => (
                  <div key={cat} className="flex items-center justify-between p-2 rounded-lg border border-border/30">
                    <div className="flex items-center gap-2">
                      <Badge variant="outline" className="text-[10px]">
                        {cat}
                      </Badge>
                      <span className="text-xs text-muted-foreground">{data.count} feedback</span>
                    </div>
                    <span
                      className={`text-sm font-bold tabular-nums ${data.avgRating >= 4 ? "text-emerald-400" : data.avgRating >= 3 ? "text-amber-400" : "text-red-400"}`}
                    >
                      {data.avgRating}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Top Correction Reasons (FP reduction tracking) */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm flex items-center gap-2">
            <ShieldAlert className="h-4 w-4" /> Top Correction Reasons
          </CardTitle>
          <CardDescription className="text-xs">
            Most common reasons analysts correct AI outputs - tracks false positive patterns
          </CardDescription>
        </CardHeader>
        <CardContent>
          {analytics.topCorrectionReasons.length === 0 ? (
            <p className="text-sm text-muted-foreground text-center py-8">No corrections recorded yet</p>
          ) : (
            <div className="space-y-2">
              {analytics.topCorrectionReasons.map((r, i) => (
                <div
                  key={`${r.reason}-${i}`}
                  className="flex items-center justify-between p-2 rounded-lg border border-border/30"
                >
                  <span className="text-xs truncate max-w-[400px]">{r.reason}</span>
                  <Badge variant="outline" className="text-xs tabular-nums shrink-0">
                    {r.count}x
                  </Badge>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

/* ── 35.3: Prompt Improvement Suggestions ── */
function PromptImprovementSuggestions() {
  const { data: analytics, isLoading } = useQuery<FeedbackAnalytics>({
    queryKey: ["/api/ai/feedback/analytics", "suggestions"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/ai/feedback/analytics?days=90");
      return res.json();
    },
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base flex items-center gap-2">
          <Lightbulb className="h-4 w-4 text-amber-400" />
          Prompt Improvement Suggestions
        </CardTitle>
        <CardDescription>
          When negative feedback patterns emerge, specific prompt modifications are suggested
        </CardDescription>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
          </div>
        ) : !analytics?.promptImprovementSuggestions || analytics.promptImprovementSuggestions.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-muted-foreground">
            <Lightbulb className="h-10 w-10 mb-3 opacity-30" />
            <p className="text-sm font-medium">No improvement suggestions yet</p>
            <p className="text-xs mt-1">
              Suggestions appear when negative feedback patterns are detected (3+ similar corrections)
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            {analytics.promptImprovementSuggestions.map((s, i) => (
              <div key={`${s.category}-${i}`} className="border border-border/50 rounded-lg p-4 space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Badge variant="outline" className="text-xs">
                      {s.category}
                    </Badge>
                    <Badge
                      variant="outline"
                      className={`text-[10px] ${
                        s.confidence === "high"
                          ? "bg-red-500/15 text-red-400 border-red-500/30"
                          : "bg-amber-500/15 text-amber-400 border-amber-500/30"
                      }`}
                    >
                      {s.confidence} confidence
                    </Badge>
                  </div>
                  <ArrowUpRight className="h-3.5 w-3.5 text-muted-foreground" />
                </div>
                <p className="text-xs text-red-400 flex items-center gap-1.5">
                  <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
                  {s.issue}
                </p>
                <p className="text-xs text-emerald-400 flex items-center gap-1.5">
                  <Target className="h-3.5 w-3.5 shrink-0" />
                  {s.suggestedFix}
                </p>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

/* ── 35.1: Inline Feedback Guide ── */
function InlineFeedbackGuide() {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base flex items-center gap-2">
          <Zap className="h-4 w-4 text-cyan-400" />
          Inline Feedback on AI Responses
        </CardTitle>
        <CardDescription>
          Thumbs up/down feedback is available directly on AI responses throughout the platform
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="p-4 rounded-lg border border-cyan-500/20 bg-cyan-500/5">
          <h4 className="text-sm font-semibold mb-2">How Inline Feedback Works</h4>
          <div className="space-y-3 text-xs text-muted-foreground">
            <div className="flex items-start gap-3">
              <div className="p-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 shrink-0 mt-0.5">
                <ThumbsUp className="h-3.5 w-3.5 text-emerald-400" />
              </div>
              <div>
                <p className="font-medium text-foreground">Thumbs Up</p>
                <p>
                  Marks the AI response as helpful and accurate. Positive examples may be automatically added to the
                  prompt&apos;s few-shot examples to reinforce good behavior.
                </p>
              </div>
            </div>
            <div className="flex items-start gap-3">
              <div className="p-1.5 rounded-lg bg-red-500/10 border border-red-500/20 shrink-0 mt-0.5">
                <ThumbsDown className="h-3.5 w-3.5 text-red-400" />
              </div>
              <div>
                <p className="font-medium text-foreground">Thumbs Down</p>
                <p>
                  Marks the AI response as incorrect or unhelpful. The system tracks which data sources and categories
                  generate the most false positives and can automatically adjust alert scoring or add suppression rules.
                </p>
              </div>
            </div>
          </div>
        </div>

        <Separator />

        <div>
          <h4 className="text-sm font-semibold mb-3">Feedback Pipeline</h4>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div className="p-3 rounded-lg border border-border/50 text-center">
              <div className="p-2 rounded-lg bg-blue-500/10 border border-blue-500/20 w-fit mx-auto mb-2">
                <MessageSquare className="h-4 w-4 text-blue-400" />
              </div>
              <p className="text-xs font-medium">1. Collect</p>
              <p className="text-[10px] text-muted-foreground">Inline thumbs up/down on every AI response</p>
            </div>
            <div className="p-3 rounded-lg border border-border/50 text-center">
              <div className="p-2 rounded-lg bg-purple-500/10 border border-purple-500/20 w-fit mx-auto mb-2">
                <Brain className="h-4 w-4 text-purple-400" />
              </div>
              <p className="text-xs font-medium">2. Learn</p>
              <p className="text-[10px] text-muted-foreground">Auto-inject few-shot examples from positive feedback</p>
            </div>
            <div className="p-3 rounded-lg border border-border/50 text-center">
              <div className="p-2 rounded-lg bg-emerald-500/10 border border-emerald-500/20 w-fit mx-auto mb-2">
                <Target className="h-4 w-4 text-emerald-400" />
              </div>
              <p className="text-xs font-medium">3. Improve</p>
              <p className="text-[10px] text-muted-foreground">Suppress high-FP sources, suggest prompt fixes</p>
            </div>
          </div>
        </div>

        <div className="p-3 rounded-lg border border-amber-500/20 bg-amber-500/5">
          <p className="text-xs flex items-start gap-2">
            <AlertTriangle className="h-3.5 w-3.5 text-amber-400 shrink-0 mt-0.5" />
            <span>
              <strong>API Endpoint:</strong> <code className="text-cyan-400">POST /api/ai/feedback/inline</code> with{" "}
              <code>{'{ thumbs: "up"|"down", resourceType, resourceId, comment? }'}</code>. This endpoint is used by all
              AI response components across the platform for zero-friction feedback collection.
            </span>
          </p>
        </div>
      </CardContent>
    </Card>
  );
}

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
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
} from "lucide-react";
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
    isLoading: listLoading,
    isError: listError,
    refetch: refetchList,
    isFetching: listFetching,
  } = useQuery<AiFeedback[]>({
    queryKey: ["/api/ai/feedback", filterType],
    queryFn: async () => {
      const params = new URLSearchParams();
      if (filterType !== "all") params.set("resourceType", filterType);
      const res = await fetch(`/api/ai/feedback?${params.toString()}`, { credentials: "include" });
      if (!res.ok) throw new Error("Failed to fetch feedback");
      const body = await res.json();
      if (body && typeof body === "object" && "data" in body && "meta" in body && "errors" in body) {
        return (body.data ?? []) as AiFeedback[];
      }
      return Array.isArray(body) ? body : [];
    },
  });

  const { data: metrics, isLoading: metricsLoading } = useQuery<FeedbackMetric[]>({
    queryKey: ["/api/ai/feedback/metrics"],
    queryFn: async () => {
      const res = await fetch("/api/ai/feedback/metrics?days=30", { credentials: "include" });
      if (!res.ok) throw new Error("Failed to fetch metrics");
      const body = await res.json();
      if (body && typeof body === "object" && "data" in body && "meta" in body && "errors" in body) {
        return (body.data ?? []) as FeedbackMetric[];
      }
      return Array.isArray(body) ? body : [];
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
      const res = await fetch("/api/ai/feedback", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify(data),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({ message: "Failed to submit feedback" }));
        throw new Error(err.message || "Failed to submit feedback");
      }
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
            <h1 className="text-xl font-bold tracking-tight">AI Feedback</h1>
            <p className="text-xs text-muted-foreground">
              Rate AI outputs and submit corrections to improve model accuracy
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
                {metricsLoading ? <Skeleton className="h-7 w-8 inline-block" /> : totalFeedback}
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
                {metricsLoading ? <Skeleton className="h-7 w-8 inline-block" /> : avgRating.toFixed(1)}
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
                {metricsLoading ? <Skeleton className="h-7 w-8 inline-block" /> : totalPositive}
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
                {metricsLoading ? <Skeleton className="h-7 w-8 inline-block" /> : totalNegative}
              </p>
              <p className="text-[11px] text-muted-foreground">Negative</p>
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="lg:col-span-1">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm flex items-center gap-2">
              <Send className="h-4 w-4 text-muted-foreground" />
              Submit Feedback
            </CardTitle>
            <CardDescription className="text-xs">Rate an AI output and optionally provide corrections</CardDescription>
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
                  <Select value={correctedSeverity} onValueChange={(v) => setCorrectedSeverity(v === "none" ? "" : v)}>
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
            {listLoading ? (
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
    </div>
  );
}

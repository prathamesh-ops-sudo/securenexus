import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { usePageTitle } from "@/hooks/use-page-title";
import {
  FileText,
  AlertTriangle,
  RefreshCw,
  Search,
  CheckCircle2,
  Clock,
  Plus,
  Loader2,
  ChevronDown,
  ChevronUp,
  Users,
  Calendar,
  ListChecks,
  Trash2,
} from "lucide-react";
import { SuccessIcon } from "@/components/ui/animated-state-icons";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Skeleton } from "@/components/ui/skeleton";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";

interface ActionItem {
  id: string;
  title: string;
  assignee: string;
  status: "open" | "in_progress" | "done";
  dueDate: string;
}

interface PIR {
  id: string;
  incidentId: string;
  incidentTitle: string;
  status: "draft" | "in_review" | "published";
  summary: string;
  timeline: string;
  rootCause: string;
  lessonsLearned: string;
  actionItems: ActionItem[];
  createdAt: string;
  updatedAt: string;
  author: string;
}

export default function PostIncidentReviewPage() {
  usePageTitle("Post-Incident Reviews");
  const { toast } = useToast();
  const [search, setSearch] = useState("");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState("all");

  const {
    data: pirs,
    isLoading,
    isError,
    error,
    refetch,
  } = useQuery<PIR[]>({
    queryKey: ["/api/pir"],
    queryFn: () => apiRequest("GET", "/api/pir").then((r) => r.json()),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiRequest("DELETE", `/api/pir/${id}`),
    onSuccess: () => {
      toast({ title: "PIR deleted" });
      queryClient.invalidateQueries({ queryKey: ["/api/pir"] });
    },
    onError: () => toast({ title: "Failed to delete PIR", variant: "destructive" }),
  });

  const list = Array.isArray(pirs) ? pirs : [];
  const filtered = list.filter((p) => {
    if (
      search &&
      !p.incidentTitle?.toLowerCase().includes(search.toLowerCase()) &&
      !p.summary?.toLowerCase().includes(search.toLowerCase())
    )
      return false;
    if (statusFilter !== "all" && p.status !== statusFilter) return false;
    return true;
  });

  if (isLoading) {
    return (
      <div className="p-6 space-y-4">
        <Skeleton className="h-8 w-64" />
        <div className="space-y-3">
          {[1, 2, 3].map((i) => (
            <Skeleton key={i} className="h-28" />
          ))}
        </div>
      </div>
    );
  }

  if (isError) {
    return (
      <div className="p-6">
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12 gap-3">
            <AlertTriangle className="h-8 w-8 text-destructive" />
            <p className="text-muted-foreground">Failed to load post-incident reviews</p>
            <Button variant="outline" onClick={() => refetch()}>
              <RefreshCw className="mr-2 h-4 w-4" /> Retry
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <FileText className="h-6 w-6" /> Post-Incident Reviews
          </h1>
          <p className="text-muted-foreground text-sm mt-1">
            Blameless post-mortems with root cause analysis, lessons learned, and action items
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={() => refetch()}>
          <RefreshCw className="mr-2 h-4 w-4" /> Refresh
        </Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="pt-4 flex items-center gap-2">
            <FileText className="h-5 w-5 text-primary" />
            <div>
              <p className="text-2xl font-bold">{list.length}</p>
              <p className="text-xs text-muted-foreground">Total PIRs</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 flex items-center gap-2">
            <Clock className="h-5 w-5 text-yellow-500" />
            <div>
              <p className="text-2xl font-bold">{list.filter((p) => p.status === "draft").length}</p>
              <p className="text-xs text-muted-foreground">Drafts</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 flex items-center gap-2">
            <SuccessIcon size={20} color="#22c55e" />
            <div>
              <p className="text-2xl font-bold">{list.filter((p) => p.status === "published").length}</p>
              <p className="text-xs text-muted-foreground">Published</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 flex items-center gap-2">
            <ListChecks className="h-5 w-5 text-blue-500" />
            <div>
              <p className="text-2xl font-bold">
                {list.reduce((s, p) => s + (p.actionItems?.filter((a) => a.status !== "done").length || 0), 0)}
              </p>
              <p className="text-xs text-muted-foreground">Open Actions</p>
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="flex gap-2">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search PIRs..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
          />
        </div>
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-40">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Status</SelectItem>
            <SelectItem value="draft">Draft</SelectItem>
            <SelectItem value="in_review">In Review</SelectItem>
            <SelectItem value="published">Published</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {filtered.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center py-12 gap-3">
            <FileText className="h-8 w-8 text-muted-foreground" />
            <p className="text-muted-foreground">No post-incident reviews found</p>
            <p className="text-xs text-muted-foreground">Create a PIR from the incident detail page</p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {filtered.map((pir) => (
            <Card
              key={pir.id}
              className="transition-all hover:shadow-md cursor-pointer"
              onClick={() => setExpandedId(expandedId === pir.id ? null : pir.id)}
            >
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <FileText className="h-5 w-5 text-primary" />
                    <div>
                      <CardTitle className="text-base">{pir.incidentTitle || `PIR-${pir.id.slice(0, 8)}`}</CardTitle>
                      <CardDescription className="text-xs">
                        <Users className="inline h-3 w-3 mr-1" />
                        {pir.author} &middot; <Calendar className="inline h-3 w-3 mr-1" />
                        {new Date(pir.createdAt).toLocaleDateString()}
                      </CardDescription>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge
                      variant={
                        pir.status === "published" ? "default" : pir.status === "in_review" ? "secondary" : "outline"
                      }
                    >
                      {pir.status.replace("_", " ")}
                    </Badge>
                    {pir.actionItems && (
                      <Badge variant="outline">
                        {pir.actionItems.filter((a) => a.status === "done").length}/{pir.actionItems.length} actions
                        done
                      </Badge>
                    )}
                    <Button
                      variant="ghost"
                      size="icon"
                      className="text-destructive"
                      onClick={(e) => {
                        e.stopPropagation();
                        deleteMutation.mutate(pir.id);
                      }}
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                    {expandedId === pir.id ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                  </div>
                </div>
              </CardHeader>
              {expandedId === pir.id && (
                <CardContent className="space-y-4">
                  {pir.summary && (
                    <div>
                      <p className="text-xs font-medium text-muted-foreground mb-1">Summary</p>
                      <p className="text-sm">{pir.summary}</p>
                    </div>
                  )}
                  {pir.rootCause && (
                    <div>
                      <p className="text-xs font-medium text-muted-foreground mb-1">Root Cause</p>
                      <p className="text-sm">{pir.rootCause}</p>
                    </div>
                  )}
                  {pir.lessonsLearned && (
                    <div>
                      <p className="text-xs font-medium text-muted-foreground mb-1">Lessons Learned</p>
                      <p className="text-sm">{pir.lessonsLearned}</p>
                    </div>
                  )}
                  {pir.actionItems && pir.actionItems.length > 0 && (
                    <div>
                      <p className="text-xs font-medium text-muted-foreground mb-2">Action Items</p>
                      <div className="space-y-1">
                        {pir.actionItems.map((a) => (
                          <div key={a.id} className="flex items-center gap-2 text-sm p-2 border rounded">
                            {a.status === "done" ? (
                              <SuccessIcon size={12} color="#22c55e" />
                            ) : (
                              <Clock className="h-3 w-3 text-yellow-500" />
                            )}
                            <span className="flex-1">{a.title}</span>
                            <Badge variant="outline" className="text-xs">
                              {a.assignee}
                            </Badge>
                            <Badge variant={a.status === "done" ? "default" : "secondary"} className="text-xs">
                              {a.status.replace("_", " ")}
                            </Badge>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </CardContent>
              )}
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

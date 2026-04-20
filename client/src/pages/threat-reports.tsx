import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { usePageTitle } from "@/hooks/use-page-title";
import { useToast } from "@/hooks/use-toast";
import {
  Flag,
  Plus,
  Search,
  RefreshCw,
  AlertTriangle,
  Shield,
  Mail,
  Phone,
  Globe,
  User,
  Clock,
  ExternalLink,
  Filter,
  ChevronRight,
  Eye,
  EyeOff,
  Send,
  ArrowUpRight,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Skeleton } from "@/components/ui/skeleton";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";

interface ThreatReport {
  id: string;
  title: string;
  description: string;
  category: string;
  severity: string;
  status: string;
  reporterName: string | null;
  reporterEmail: string | null;
  reporterDepartment: string | null;
  isAnonymous: boolean;
  suspectedTarget: string | null;
  dateObserved: string | null;
  evidenceDescription: string | null;
  linkedAlertId: string | null;
  linkedIncidentId: string | null;
  assignedTo: string | null;
  resolution: string | null;
  createdAt: string;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-500/10 text-red-500 border-red-500/20",
  high: "bg-orange-500/10 text-orange-500 border-orange-500/20",
  medium: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20",
  low: "bg-green-500/10 text-green-500 border-green-500/20",
  informational: "bg-blue-500/10 text-blue-500 border-blue-500/20",
};

const STATUS_COLORS: Record<string, string> = {
  submitted: "bg-blue-500/10 text-blue-500",
  reviewing: "bg-yellow-500/10 text-yellow-500",
  investigating: "bg-orange-500/10 text-orange-500",
  resolved: "bg-green-500/10 text-green-500",
  dismissed: "bg-zinc-500/10 text-zinc-500",
};

const CATEGORY_ICONS: Record<string, React.ElementType> = {
  phishing: Mail,
  social_engineering: Phone,
  suspicious_website: Globe,
  malware: Shield,
  unauthorized_access: AlertTriangle,
  data_leak: Eye,
  insider_threat: User,
  physical_security: Shield,
  policy_violation: Flag,
  other: Flag,
};

function SubmitReportDialog({ onSubmitted }: { onSubmitted: () => void }) {
  const { toast } = useToast();
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({
    title: "",
    description: "",
    category: "phishing",
    severity: "medium",
    isAnonymous: false,
    reporterName: "",
    reporterEmail: "",
    reporterDepartment: "",
    suspectedTarget: "",
    dateObserved: "",
    evidenceDescription: "",
  });

  const submitMutation = useMutation({
    mutationFn: async () => {
      const body: Record<string, unknown> = {
        title: form.title,
        description: form.description,
        category: form.category,
        severity: form.severity,
        isAnonymous: form.isAnonymous,
      };
      if (!form.isAnonymous) {
        if (form.reporterName) body.reporterName = form.reporterName;
        if (form.reporterEmail) body.reporterEmail = form.reporterEmail;
        if (form.reporterDepartment) body.reporterDepartment = form.reporterDepartment;
      }
      if (form.suspectedTarget) body.suspectedTarget = form.suspectedTarget;
      if (form.dateObserved) body.dateObserved = form.dateObserved;
      if (form.evidenceDescription) body.evidenceDescription = form.evidenceDescription;
      const res = await apiRequest("POST", "/api/threat-reports", body);
      if (!res.ok) throw new Error("Failed to submit report");
      return res.json();
    },
    onSuccess: () => {
      toast({ title: "Threat report submitted", description: "Your report will be reviewed by the security team" });
      setOpen(false);
      setForm({
        title: "",
        description: "",
        category: "phishing",
        severity: "medium",
        isAnonymous: false,
        reporterName: "",
        reporterEmail: "",
        reporterDepartment: "",
        suspectedTarget: "",
        dateObserved: "",
        evidenceDescription: "",
      });
      onSubmitted();
    },
    onError: () => toast({ title: "Error", description: "Failed to submit report", variant: "destructive" }),
  });

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm">
          <Plus className="mr-2 h-4 w-4" /> Report Threat
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Report a Security Threat</DialogTitle>
          <DialogDescription>
            If you've observed something suspicious, report it here. Your report will be reviewed by the security team.
          </DialogDescription>
        </DialogHeader>
        <div className="grid grid-cols-2 gap-4">
          <div className="col-span-2">
            <Label>What happened? *</Label>
            <Input
              value={form.title}
              onChange={(e) => setForm({ ...form, title: e.target.value })}
              placeholder="Brief description of the threat (e.g., Suspicious email from CEO)"
            />
          </div>
          <div className="col-span-2">
            <Label>Details *</Label>
            <Textarea
              value={form.description}
              onChange={(e) => setForm({ ...form, description: e.target.value })}
              placeholder="Provide as much detail as possible: what you saw, when, where, who was involved..."
              rows={4}
            />
          </div>
          <div>
            <Label>Category</Label>
            <Select value={form.category} onValueChange={(v) => setForm({ ...form, category: v })}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="phishing">Phishing Email</SelectItem>
                <SelectItem value="social_engineering">Social Engineering</SelectItem>
                <SelectItem value="suspicious_website">Suspicious Website</SelectItem>
                <SelectItem value="malware">Malware / Virus</SelectItem>
                <SelectItem value="unauthorized_access">Unauthorized Access</SelectItem>
                <SelectItem value="data_leak">Data Leak</SelectItem>
                <SelectItem value="insider_threat">Insider Threat</SelectItem>
                <SelectItem value="physical_security">Physical Security</SelectItem>
                <SelectItem value="policy_violation">Policy Violation</SelectItem>
                <SelectItem value="other">Other</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div>
            <Label>Severity</Label>
            <Select value={form.severity} onValueChange={(v) => setForm({ ...form, severity: v })}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="critical">Critical - Active breach</SelectItem>
                <SelectItem value="high">High - Immediate risk</SelectItem>
                <SelectItem value="medium">Medium - Potential risk</SelectItem>
                <SelectItem value="low">Low - Informational</SelectItem>
                <SelectItem value="informational">Informational</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="col-span-2 border rounded-lg p-3">
            <div className="flex items-center justify-between">
              <div>
                <Label>Submit Anonymously</Label>
                <p className="text-xs text-muted-foreground">Your identity will not be stored with this report</p>
              </div>
              <Switch checked={form.isAnonymous} onCheckedChange={(v) => setForm({ ...form, isAnonymous: v })} />
            </div>
          </div>
          {!form.isAnonymous && (
            <>
              <div>
                <Label>Your Name</Label>
                <Input
                  value={form.reporterName}
                  onChange={(e) => setForm({ ...form, reporterName: e.target.value })}
                  placeholder="Your name"
                />
              </div>
              <div>
                <Label>Your Email</Label>
                <Input
                  value={form.reporterEmail}
                  onChange={(e) => setForm({ ...form, reporterEmail: e.target.value })}
                  placeholder="your@email.com"
                  type="email"
                />
              </div>
              <div>
                <Label>Department</Label>
                <Input
                  value={form.reporterDepartment}
                  onChange={(e) => setForm({ ...form, reporterDepartment: e.target.value })}
                  placeholder="e.g., Finance, HR, Engineering"
                />
              </div>
            </>
          )}
          <div className={form.isAnonymous ? "col-span-2" : ""}>
            <Label>Suspected Target</Label>
            <Input
              value={form.suspectedTarget}
              onChange={(e) => setForm({ ...form, suspectedTarget: e.target.value })}
              placeholder="Who or what was targeted?"
            />
          </div>
          <div>
            <Label>When did you observe this?</Label>
            <Input
              value={form.dateObserved}
              onChange={(e) => setForm({ ...form, dateObserved: e.target.value })}
              type="datetime-local"
            />
          </div>
          <div>
            <Label>Evidence</Label>
            <Input
              value={form.evidenceDescription}
              onChange={(e) => setForm({ ...form, evidenceDescription: e.target.value })}
              placeholder="Screenshots, email headers, URLs..."
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)}>
            Cancel
          </Button>
          <Button
            onClick={() => submitMutation.mutate()}
            disabled={!form.title || !form.description || submitMutation.isPending}
          >
            <Send className="mr-2 h-4 w-4" />
            {submitMutation.isPending ? "Submitting..." : "Submit Report"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default function ThreatReportsPage() {
  usePageTitle("Threat Reports");
  const { toast } = useToast();
  const [statusFilter, setStatusFilter] = useState("all");
  const [categoryFilter, setCategoryFilter] = useState("all");

  const {
    data: reports,
    isLoading,
    refetch,
  } = useQuery<{ reports: ThreatReport[]; stats: any }>({
    queryKey: ["/api/threat-reports", statusFilter, categoryFilter],
    queryFn: async () => {
      const params = new URLSearchParams();
      if (statusFilter !== "all") params.set("status", statusFilter);
      if (categoryFilter !== "all") params.set("category", categoryFilter);
      const res = await apiRequest("GET", `/api/threat-reports?${params}`);
      return res.json();
    },
  });

  const escalateMutation = useMutation({
    mutationFn: async (id: string) => {
      const res = await apiRequest("POST", `/api/threat-reports/${id}/escalate`);
      if (!res.ok) throw new Error("Failed to escalate");
      return res.json();
    },
    onSuccess: () => {
      toast({ title: "Report escalated to incident" });
      refetch();
    },
    onError: () => toast({ title: "Error", description: "Failed to escalate", variant: "destructive" }),
  });

  const updateStatusMutation = useMutation({
    mutationFn: async ({ id, status }: { id: string; status: string }) => {
      const res = await apiRequest("PATCH", `/api/threat-reports/${id}`, { status });
      if (!res.ok) throw new Error("Failed to update");
      return res.json();
    },
    onSuccess: () => {
      toast({ title: "Status updated" });
      refetch();
    },
  });

  const list = reports?.reports || [];

  const stats = {
    total: list.length,
    critical: list.filter((r) => r.severity === "critical").length,
    high: list.filter((r) => r.severity === "high").length,
    pending: list.filter((r) => r.status === "submitted" || r.status === "reviewing").length,
    resolved: list.filter((r) => r.status === "resolved").length,
    anonymous: list.filter((r) => r.isAnonymous).length,
  };

  if (isLoading) {
    return (
      <div className="p-6 space-y-4">
        <Skeleton className="h-8 w-64" />
        <div className="grid grid-cols-4 gap-4">
          {[1, 2, 3, 4].map((i) => (
            <Skeleton key={i} className="h-24" />
          ))}
        </div>
        <Skeleton className="h-96" />
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Flag className="h-6 w-6" /> Employee Threat Reporting
          </h1>
          <p className="text-muted-foreground text-sm mt-1">
            Report suspicious activity, phishing attempts, and security concerns
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="mr-2 h-4 w-4" /> Refresh
          </Button>
          <SubmitReportDialog onSubmitted={() => refetch()} />
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center gap-2">
              <Flag className="h-5 w-5 text-primary" />
              <div>
                <p className="text-2xl font-bold">{stats.total}</p>
                <p className="text-xs text-muted-foreground">Total Reports</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-red-500" />
              <div>
                <p className="text-2xl font-bold">{stats.critical}</p>
                <p className="text-xs text-muted-foreground">Critical</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center gap-2">
              <Shield className="h-5 w-5 text-orange-500" />
              <div>
                <p className="text-2xl font-bold">{stats.high}</p>
                <p className="text-xs text-muted-foreground">High</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center gap-2">
              <Clock className="h-5 w-5 text-yellow-500" />
              <div>
                <p className="text-2xl font-bold">{stats.pending}</p>
                <p className="text-xs text-muted-foreground">Pending</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center gap-2">
              <Eye className="h-5 w-5 text-green-500" />
              <div>
                <p className="text-2xl font-bold">{stats.resolved}</p>
                <p className="text-xs text-muted-foreground">Resolved</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center gap-2">
              <EyeOff className="h-5 w-5 text-zinc-500" />
              <div>
                <p className="text-2xl font-bold">{stats.anonymous}</p>
                <p className="text-xs text-muted-foreground">Anonymous</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Threat Category Breakdown */}
      {list.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base flex items-center gap-2">
              <Shield className="h-4 w-4" /> Threat Category Distribution
            </CardTitle>
            <CardDescription>Breakdown of reported threats by category and severity</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
              {Object.entries(
                list.reduce<Record<string, number>>((acc, r) => {
                  acc[r.category] = (acc[r.category] || 0) + 1;
                  return acc;
                }, {}),
              )
                .sort((a, b) => b[1] - a[1])
                .slice(0, 10)
                .map(([cat, count]) => {
                  const CatIcon = CATEGORY_ICONS[cat] || Flag;
                  return (
                    <div key={cat} className="flex items-center gap-2 p-2 border rounded-lg">
                      <CatIcon className="h-4 w-4 text-muted-foreground shrink-0" />
                      <div className="min-w-0">
                        <p className="text-sm font-medium truncate">
                          {cat.replace(/_/g, " ").replace(/\b\w/g, (l) => l.toUpperCase())}
                        </p>
                        <p className="text-xs text-muted-foreground">
                          {count} report{count !== 1 ? "s" : ""}
                        </p>
                      </div>
                    </div>
                  );
                })}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Response Time Metrics */}
      {list.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base flex items-center gap-2">
              <Clock className="h-4 w-4" /> Response Metrics
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="text-center p-3 border rounded-lg">
                <p className="text-2xl font-bold">{stats.total}</p>
                <p className="text-xs text-muted-foreground">Total Reports</p>
              </div>
              <div className="text-center p-3 border rounded-lg">
                <p className="text-2xl font-bold">{stats.pending}</p>
                <p className="text-xs text-muted-foreground">Awaiting Review</p>
              </div>
              <div className="text-center p-3 border rounded-lg">
                <p className="text-2xl font-bold">
                  {stats.total > 0 ? Math.round((stats.resolved / stats.total) * 100) : 0}%
                </p>
                <p className="text-xs text-muted-foreground">Resolution Rate</p>
              </div>
              <div className="text-center p-3 border rounded-lg">
                <p className="text-2xl font-bold">{list.filter((r) => r.linkedIncidentId).length}</p>
                <p className="text-xs text-muted-foreground">Escalated to Incidents</p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Filters */}
      <div className="flex gap-2">
        <Select value={categoryFilter} onValueChange={setCategoryFilter}>
          <SelectTrigger className="w-48">
            <Filter className="mr-2 h-4 w-4" />
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Categories</SelectItem>
            {[
              "phishing",
              "social_engineering",
              "suspicious_website",
              "malware",
              "unauthorized_access",
              "data_leak",
              "insider_threat",
              "physical_security",
              "policy_violation",
              "other",
            ].map((c) => (
              <SelectItem key={c} value={c}>
                {c.replace(/_/g, " ").replace(/\b\w/g, (l) => l.toUpperCase())}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-40">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Statuses</SelectItem>
            {["submitted", "reviewing", "investigating", "resolved", "dismissed"].map((s) => (
              <SelectItem key={s} value={s}>
                {s.replace(/\b\w/g, (l) => l.toUpperCase())}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {/* Reports List */}
      {list.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center py-16 gap-4">
            <Flag className="h-12 w-12 text-muted-foreground/40" />
            <div className="text-center">
              <h3 className="font-semibold">No threat reports</h3>
              <p className="text-sm text-muted-foreground mt-1">
                No reports have been submitted yet. Encourage employees to report suspicious activity.
              </p>
            </div>
            <SubmitReportDialog onSubmitted={() => refetch()} />
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-2">
          {list.map((report) => {
            const CatIcon = CATEGORY_ICONS[report.category] || Flag;
            return (
              <Card key={report.id} className="transition-all hover:shadow-sm">
                <CardContent className="py-3">
                  <div className="flex items-start gap-4">
                    <div className="flex items-center justify-center w-10 h-10 rounded-lg bg-muted shrink-0">
                      <CatIcon className="h-5 w-5 text-muted-foreground" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-0.5 flex-wrap">
                        <span className="font-semibold text-sm">{report.title}</span>
                        <Badge className={SEVERITY_COLORS[report.severity] || ""} variant="outline">
                          {report.severity}
                        </Badge>
                        <Badge className={STATUS_COLORS[report.status] || ""} variant="outline">
                          {report.status}
                        </Badge>
                        <Badge variant="outline">{report.category.replace(/_/g, " ")}</Badge>
                        {report.isAnonymous && (
                          <Badge variant="outline" className="text-zinc-500">
                            <EyeOff className="h-3 w-3 mr-1" /> Anonymous
                          </Badge>
                        )}
                      </div>
                      <p className="text-xs text-muted-foreground line-clamp-2 mt-1">{report.description}</p>
                      <div className="flex items-center gap-4 text-xs text-muted-foreground mt-1.5">
                        {report.reporterName && (
                          <span className="flex items-center gap-1">
                            <User className="h-3 w-3" /> {report.reporterName}
                          </span>
                        )}
                        {report.reporterDepartment && <span>{report.reporterDepartment}</span>}
                        <span className="flex items-center gap-1">
                          <Clock className="h-3 w-3" /> {new Date(report.createdAt).toLocaleString()}
                        </span>
                        {report.linkedAlertId && (
                          <Badge variant="outline" className="text-[10px]">
                            Alert linked
                          </Badge>
                        )}
                        {report.linkedIncidentId && (
                          <Badge variant="outline" className="text-[10px]">
                            Incident linked
                          </Badge>
                        )}
                      </div>
                    </div>
                    <div className="flex items-center gap-1 shrink-0">
                      {report.status !== "resolved" && report.status !== "dismissed" && (
                        <>
                          <Select
                            value={report.status}
                            onValueChange={(v) => updateStatusMutation.mutate({ id: report.id, status: v })}
                          >
                            <SelectTrigger className="h-7 w-28 text-[10px]">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="submitted">Submitted</SelectItem>
                              <SelectItem value="reviewing">Reviewing</SelectItem>
                              <SelectItem value="investigating">Investigating</SelectItem>
                              <SelectItem value="resolved">Resolved</SelectItem>
                              <SelectItem value="dismissed">Dismissed</SelectItem>
                            </SelectContent>
                          </Select>
                          {!report.linkedIncidentId && (
                            <Button
                              variant="outline"
                              size="sm"
                              className="h-7 text-[10px]"
                              onClick={() => escalateMutation.mutate(report.id)}
                              disabled={escalateMutation.isPending}
                            >
                              <ArrowUpRight className="h-3 w-3 mr-1" /> Escalate
                            </Button>
                          )}
                        </>
                      )}
                    </div>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}

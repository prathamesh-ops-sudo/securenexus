import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { formatDateTime } from "@/lib/i18n";
import { useToast } from "@/hooks/use-toast";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
  DialogDescription,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Skeleton } from "@/components/ui/skeleton";
import {
  FileText,
  Calendar,
  Clock,
  Download,
  Plus,
  Trash2,
  Play,
  BarChart3,
  Shield,
  Monitor,
  CheckCircle2,
  XCircle,
  Loader2,
  RefreshCw,
  Users,
  AlertTriangle,
  GitBranch,
  History,
} from "lucide-react";
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip as RechartsTooltip,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  AreaChart,
  Area,
} from "recharts";

const REPORT_TYPE_LABELS: Record<string, string> = {
  soc_kpi: "SOC KPIs",
  incidents: "Incidents",
  attack_coverage: "ATT&CK Coverage",
  connector_health: "Connector Health",
  executive_summary: "Executive Summary",
  compliance: "Compliance",
};

const CADENCE_LABELS: Record<string, string> = {
  daily: "Daily",
  weekly: "Weekly",
  biweekly: "Bi-Weekly",
  monthly: "Monthly",
  quarterly: "Quarterly",
};

const ROLE_LABELS: Record<string, string> = {
  ciso: "CISO",
  soc_manager: "SOC Manager",
  analyst: "Analyst",
};

const CHART_COLORS = ["#ef4444", "#f97316", "#eab308", "#22c55e", "#3b82f6", "#8b5cf6", "#ec4899", "#14b8a6"];

const VERSION_STATUS_COLORS: Record<string, string> = {
  draft: "border-yellow-500/30 text-yellow-400",
  active: "border-green-500/30 text-green-400",
  deprecated: "border-orange-500/30 text-orange-400",
  archived: "border-gray-500/30 text-gray-400",
};

export default function ReportsPage() {
  const { toast } = useToast();
  const [activeTab, setActiveTab] = useState("templates");

  const [showCreateTemplate, setShowCreateTemplate] = useState(false);
  const [templateName, setTemplateName] = useState("");
  const [templateDescription, setTemplateDescription] = useState("");
  const [templateType, setTemplateType] = useState("soc_kpi");
  const [templateFormat, setTemplateFormat] = useState("csv");
  const [templateRole, setTemplateRole] = useState("soc_manager");

  const [showCreateSchedule, setShowCreateSchedule] = useState(false);
  const [scheduleName, setScheduleName] = useState("");
  const [scheduleTemplateId, setScheduleTemplateId] = useState("");
  const [scheduleCadence, setScheduleCadence] = useState("weekly");
  const [scheduleDeliveryType, setScheduleDeliveryType] = useState("email");
  const [scheduleDeliveryTarget, setScheduleDeliveryTarget] = useState("");
  const [scheduleEnabled, setScheduleEnabled] = useState(true);

  const [dashboardRole, setDashboardRole] = useState("ciso");

  const {
    data: templates,
    isLoading: templatesLoading,
    isError: templatesError,
    refetch: refetchTemplates,
  } = useQuery<any[]>({
    queryKey: ["/api/report-templates"],
  });

  const {
    data: schedules,
    isLoading: schedulesLoading,
    isError: schedulesError,
    refetch: refetchSchedules,
  } = useQuery<any[]>({
    queryKey: ["/api/report-schedules"],
  });

  const {
    data: runs,
    isLoading: runsLoading,
    isError: _runsError,
    refetch: _refetchRuns,
  } = useQuery<any[]>({
    queryKey: ["/api/report-runs"],
  });

  const {
    data: dashboardData,
    isLoading: dashboardLoading,
    isError: _dashboardError,
    refetch: _refetchDashboard,
  } = useQuery<any>({
    queryKey: ["/api/dashboard", dashboardRole],
  });

  const seedTemplates = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/report-templates/seed", {});
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/report-templates"] });
      toast({ title: "Templates Loaded" });
    },
    onError: (e: Error) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const createTemplate = useMutation({
    mutationFn: async (data: any) => {
      const res = await apiRequest("POST", "/api/report-templates", data);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/report-templates"] });
      setShowCreateTemplate(false);
      setTemplateName("");
      setTemplateDescription("");
      setTemplateType("soc_kpi");
      setTemplateFormat("csv");
      setTemplateRole("soc_manager");
      toast({ title: "Template Created" });
    },
    onError: (e: Error) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const deleteTemplate = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("DELETE", `/api/report-templates/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/report-templates"] });
      toast({ title: "Template Deleted" });
    },
  });

  const generateReport = useMutation({
    mutationFn: async (templateId: string) => {
      const res = await apiRequest("POST", "/api/reports/generate", { templateId });
      return res.json();
    },
    onSuccess: (data: any) => {
      queryClient.invalidateQueries({ queryKey: ["/api/report-runs"] });
      if (data.content) {
        const format = data.run?.format || "json";
        const blob = new Blob([data.content], { type: format === "csv" ? "text/csv" : "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `report.${format}`;
        a.click();
        URL.revokeObjectURL(url);
      }
      toast({ title: "Report Generated", description: "Download started" });
    },
    onError: (e: Error) => toast({ title: "Generation Failed", description: e.message, variant: "destructive" }),
  });

  const createSchedule = useMutation({
    mutationFn: async (data: any) => {
      const res = await apiRequest("POST", "/api/report-schedules", data);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/report-schedules"] });
      setShowCreateSchedule(false);
      setScheduleName("");
      setScheduleTemplateId("");
      setScheduleCadence("weekly");
      setScheduleDeliveryType("email");
      setScheduleDeliveryTarget("");
      setScheduleEnabled(true);
      toast({ title: "Schedule Created" });
    },
    onError: (e: Error) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const updateSchedule = useMutation({
    mutationFn: async ({ id, data }: { id: string; data: any }) => {
      const res = await apiRequest("PATCH", `/api/report-schedules/${id}`, data);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/report-schedules"] });
      toast({ title: "Schedule Updated" });
    },
  });

  const deleteSchedule = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("DELETE", `/api/report-schedules/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/report-schedules"] });
      toast({ title: "Schedule Deleted" });
    },
  });

  function formatDate(d: string | null) {
    if (!d) return "Never";
    return formatDateTime(d);
  }

  function formatFileSize(bytes: number | null) {
    if (!bytes) return "-";
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  }

  return (
    <div className="p-4 md:p-6 space-y-6 max-w-7xl mx-auto">
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold" data-testid="text-reports-title">
            Reports & Executive Briefs
          </h1>
          <p className="text-sm text-muted-foreground">Generate, schedule, and download security reports</p>
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList data-testid="tabs-reports">
          <TabsTrigger value="templates" data-testid="tab-templates">
            <FileText className="h-3.5 w-3.5 mr-1.5" />
            Templates
          </TabsTrigger>
          <TabsTrigger value="schedules" data-testid="tab-schedules">
            <Calendar className="h-3.5 w-3.5 mr-1.5" />
            Schedules
          </TabsTrigger>
          <TabsTrigger value="history" data-testid="tab-history">
            <Clock className="h-3.5 w-3.5 mr-1.5" />
            History
          </TabsTrigger>
          <TabsTrigger value="dashboards" data-testid="tab-dashboards">
            <BarChart3 className="h-3.5 w-3.5 mr-1.5" />
            Dashboards
          </TabsTrigger>
          <TabsTrigger value="versioning" data-testid="tab-versioning">
            <GitBranch className="h-3.5 w-3.5 mr-1.5" />
            Versioning
          </TabsTrigger>
        </TabsList>

        <TabsContent value="templates" className="space-y-4 mt-4">
          <div className="flex items-center justify-between gap-2 flex-wrap">
            <h2 className="text-lg font-semibold">Report Templates</h2>
            <div className="flex items-center gap-2 flex-wrap">
              <Button
                variant="outline"
                size="sm"
                onClick={() => seedTemplates.mutate()}
                disabled={seedTemplates.isPending}
                data-testid="button-seed-templates"
              >
                <RefreshCw className="h-3.5 w-3.5 mr-1.5" />
                Load Built-in Templates
              </Button>
              <Button size="sm" onClick={() => setShowCreateTemplate(true)} data-testid="button-create-template">
                <Plus className="h-3.5 w-3.5 mr-1.5" />
                Create Template
              </Button>
            </div>
          </div>

          {templatesLoading ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {[1, 2, 3].map((i) => (
                <Skeleton key={i} className="h-48" />
              ))}
            </div>
          ) : templatesError ? (
            <Card>
              <CardContent className="flex flex-col items-center justify-center py-12" role="alert">
                <div className="rounded-full bg-destructive/10 p-3 ring-1 ring-destructive/20 mb-3">
                  <AlertTriangle className="h-6 w-6 text-destructive" />
                </div>
                <p className="text-sm font-medium">Failed to load templates</p>
                <p className="text-xs text-muted-foreground mt-1">An error occurred while fetching report templates.</p>
                <Button variant="outline" size="sm" className="mt-3" onClick={() => refetchTemplates()}>
                  Try Again
                </Button>
              </CardContent>
            </Card>
          ) : !templates?.length ? (
            <Card>
              <CardContent className="py-12 text-center text-muted-foreground" data-testid="text-no-templates">
                <FileText className="h-10 w-10 mx-auto mb-3 opacity-40" />
                <p>No report templates configured</p>
                <p className="text-xs mt-1">Load built-in templates or create a custom one</p>
              </CardContent>
            </Card>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {templates.map((t: any) => (
                <Card key={t.id} data-testid={`card-template-${t.id}`}>
                  <CardHeader className="flex flex-row items-start justify-between gap-2">
                    <div className="space-y-1 min-w-0">
                      <CardTitle className="text-sm font-medium truncate" data-testid={`text-template-name-${t.id}`}>
                        {t.name}
                      </CardTitle>
                      <p className="text-xs text-muted-foreground line-clamp-2">{t.description}</p>
                    </div>
                    {t.isBuiltIn && (
                      <Badge
                        variant="secondary"
                        className="no-default-hover-elevate no-default-active-elevate shrink-0"
                      >
                        Built-in
                      </Badge>
                    )}
                  </CardHeader>
                  <CardContent className="space-y-3">
                    <div className="flex items-center gap-1.5 flex-wrap">
                      <Badge variant="outline" className="no-default-hover-elevate no-default-active-elevate">
                        {REPORT_TYPE_LABELS[t.reportType] || t.reportType}
                      </Badge>
                      <Badge variant="outline" className="no-default-hover-elevate no-default-active-elevate">
                        {(t.format || "csv").toUpperCase()}
                      </Badge>
                      {t.dashboardRole && (
                        <Badge variant="outline" className="no-default-hover-elevate no-default-active-elevate">
                          {ROLE_LABELS[t.dashboardRole] || t.dashboardRole}
                        </Badge>
                      )}
                    </div>
                    <div className="flex items-center gap-2 flex-wrap">
                      <Button
                        size="sm"
                        onClick={() => generateReport.mutate(t.id)}
                        disabled={generateReport.isPending}
                        data-testid={`button-generate-${t.id}`}
                      >
                        {generateReport.isPending ? (
                          <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />
                        ) : (
                          <Play className="h-3.5 w-3.5 mr-1.5" />
                        )}
                        Generate
                      </Button>
                      {!t.isBuiltIn && (
                        <Button
                          size="icon"
                          variant="ghost"
                          onClick={() => deleteTemplate.mutate(t.id)}
                          data-testid={`button-delete-template-${t.id}`}
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </Button>
                      )}
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>

        <TabsContent value="schedules" className="space-y-4 mt-4">
          <div className="flex items-center justify-between gap-2 flex-wrap">
            <h2 className="text-lg font-semibold">Scheduled Reports</h2>
            <Button size="sm" onClick={() => setShowCreateSchedule(true)} data-testid="button-create-schedule">
              <Plus className="h-3.5 w-3.5 mr-1.5" />
              Create Schedule
            </Button>
          </div>

          {schedulesLoading ? (
            <div className="space-y-3">
              {[1, 2].map((i) => (
                <Skeleton key={i} className="h-24" />
              ))}
            </div>
          ) : schedulesError ? (
            <Card>
              <CardContent className="flex flex-col items-center justify-center py-12" role="alert">
                <div className="rounded-full bg-destructive/10 p-3 ring-1 ring-destructive/20 mb-3">
                  <AlertTriangle className="h-6 w-6 text-destructive" />
                </div>
                <p className="text-sm font-medium">Failed to load schedules</p>
                <p className="text-xs text-muted-foreground mt-1">An error occurred while fetching report schedules.</p>
                <Button variant="outline" size="sm" className="mt-3" onClick={() => refetchSchedules()}>
                  Try Again
                </Button>
              </CardContent>
            </Card>
          ) : !schedules?.length ? (
            <Card>
              <CardContent className="py-12 text-center text-muted-foreground" data-testid="text-no-schedules">
                <Calendar className="h-10 w-10 mx-auto mb-3 opacity-40" />
                <p>No scheduled reports</p>
                <p className="text-xs mt-1">Create a schedule to automate report delivery</p>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-3">
              {schedules.map((s: any) => {
                const tplName = templates?.find((t: any) => t.id === s.templateId)?.name || "Unknown Template";
                let deliveryTargets: any[] = [];
                try {
                  deliveryTargets = s.deliveryTargets ? JSON.parse(s.deliveryTargets) : [];
                } catch (_parseErr) {
                  console.warn("Failed to parse delivery targets", _parseErr);
                }
                return (
                  <Card key={s.id} data-testid={`card-schedule-${s.id}`}>
                    <CardContent className="py-4">
                      <div className="flex items-center justify-between gap-2 flex-wrap">
                        <div className="space-y-1 min-w-0">
                          <p className="font-medium text-sm" data-testid={`text-schedule-name-${s.id}`}>
                            {s.name}
                          </p>
                          <p className="text-xs text-muted-foreground">Template: {tplName}</p>
                          <div className="flex items-center gap-1.5 flex-wrap mt-1">
                            <Badge variant="outline" className="no-default-hover-elevate no-default-active-elevate">
                              {CADENCE_LABELS[s.cadence] || s.cadence}
                            </Badge>
                            {deliveryTargets.map((dt: any, i: number) => (
                              <Badge
                                key={i}
                                variant="secondary"
                                className="no-default-hover-elevate no-default-active-elevate"
                              >
                                {dt.type}: {dt.address || dt.url || dt.path || "configured"}
                              </Badge>
                            ))}
                          </div>
                          <div className="flex items-center gap-3 mt-1 text-xs text-muted-foreground">
                            <span>Last: {formatDate(s.lastRunAt)}</span>
                            <span>Next: {formatDate(s.nextRunAt)}</span>
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          <div className="flex items-center gap-1.5">
                            <Switch
                              checked={s.enabled}
                              onCheckedChange={(checked) =>
                                updateSchedule.mutate({ id: s.id, data: { enabled: checked } })
                              }
                              data-testid={`switch-schedule-enabled-${s.id}`}
                            />
                            <span className="text-xs text-muted-foreground">{s.enabled ? "Active" : "Paused"}</span>
                          </div>
                          <Button
                            size="icon"
                            variant="ghost"
                            onClick={() => deleteSchedule.mutate(s.id)}
                            data-testid={`button-delete-schedule-${s.id}`}
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </Button>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          )}
        </TabsContent>

        <TabsContent value="history" className="space-y-4 mt-4">
          <h2 className="text-lg font-semibold">Report History</h2>

          {runsLoading ? (
            <div className="space-y-3">
              {[1, 2, 3].map((i) => (
                <Skeleton key={i} className="h-16" />
              ))}
            </div>
          ) : !runs?.length ? (
            <Card>
              <CardContent className="py-12 text-center text-muted-foreground" data-testid="text-no-runs">
                <Clock className="h-10 w-10 mx-auto mb-3 opacity-40" />
                <p>No reports generated yet</p>
                <p className="text-xs mt-1">Generate a report from a template to see history</p>
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardContent className="p-0">
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b">
                        <th className="text-left p-3 font-medium text-muted-foreground">Report</th>
                        <th className="text-left p-3 font-medium text-muted-foreground">Format</th>
                        <th className="text-left p-3 font-medium text-muted-foreground">Status</th>
                        <th className="text-left p-3 font-medium text-muted-foreground">Started</th>
                        <th className="text-left p-3 font-medium text-muted-foreground">Completed</th>
                        <th className="text-left p-3 font-medium text-muted-foreground">Size</th>
                        <th className="text-left p-3 font-medium text-muted-foreground">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {runs.map((r: any) => {
                        const tpl = templates?.find((t: any) => t.id === r.templateId);
                        return (
                          <tr key={r.id} className="border-b last:border-0" data-testid={`row-run-${r.id}`}>
                            <td className="p-3" data-testid={`text-run-template-${r.id}`}>
                              {tpl?.name || r.templateId}
                            </td>
                            <td className="p-3">
                              <Badge variant="outline" className="no-default-hover-elevate no-default-active-elevate">
                                {(r.format || "csv").toUpperCase()}
                              </Badge>
                            </td>
                            <td className="p-3">
                              {r.status === "completed" ? (
                                <Badge className="bg-emerald-500/10 text-emerald-500 border-emerald-500/20 no-default-hover-elevate no-default-active-elevate">
                                  <CheckCircle2 className="h-3 w-3 mr-1" />
                                  Completed
                                </Badge>
                              ) : r.status === "failed" ? (
                                <Badge
                                  variant="destructive"
                                  className="no-default-hover-elevate no-default-active-elevate"
                                >
                                  <XCircle className="h-3 w-3 mr-1" />
                                  Failed
                                </Badge>
                              ) : r.status === "running" ? (
                                <Badge className="no-default-hover-elevate no-default-active-elevate">
                                  <Loader2 className="h-3 w-3 mr-1 animate-spin" />
                                  Running
                                </Badge>
                              ) : (
                                <Badge
                                  variant="secondary"
                                  className="no-default-hover-elevate no-default-active-elevate"
                                >
                                  {r.status}
                                </Badge>
                              )}
                            </td>
                            <td className="p-3 text-muted-foreground text-xs">{formatDate(r.startedAt)}</td>
                            <td className="p-3 text-muted-foreground text-xs">{formatDate(r.completedAt)}</td>
                            <td className="p-3 text-muted-foreground text-xs">{formatFileSize(r.fileSize)}</td>
                            <td className="p-3">
                              {r.status === "completed" && (
                                <Button
                                  size="sm"
                                  variant="ghost"
                                  onClick={async () => {
                                    try {
                                      const res = await fetch(`/api/reports/${r.id}/download`, {
                                        credentials: "include",
                                      });
                                      if (!res.ok) throw new Error("Download failed");
                                      const contentType = res.headers.get("content-type") || "";
                                      const isCSV = contentType.includes("csv");
                                      const text = await res.text();
                                      const blob = new Blob([text], { type: isCSV ? "text/csv" : "application/json" });
                                      const url = URL.createObjectURL(blob);
                                      const a = document.createElement("a");
                                      a.href = url;
                                      a.download = `report-${r.id}.${isCSV ? "csv" : "json"}`;
                                      a.click();
                                      URL.revokeObjectURL(url);
                                    } catch (e: any) {
                                      toast({
                                        title: "Download Failed",
                                        description: e.message,
                                        variant: "destructive",
                                      });
                                    }
                                  }}
                                  data-testid={`button-download-${r.id}`}
                                >
                                  <Download className="h-3.5 w-3.5 mr-1" />
                                  Download
                                </Button>
                              )}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="dashboards" className="space-y-4 mt-4">
          <div className="flex items-center justify-between gap-2 flex-wrap">
            <h2 className="text-lg font-semibold">Role-Specific Dashboards</h2>
            <div className="flex items-center gap-1">
              {(["ciso", "soc_manager", "analyst"] as const).map((role) => (
                <Button
                  key={role}
                  size="sm"
                  variant={dashboardRole === role ? "default" : "outline"}
                  className="toggle-elevate"
                  onClick={() => setDashboardRole(role)}
                  data-testid={`button-role-${role}`}
                >
                  {role === "ciso" ? (
                    <Shield className="h-3.5 w-3.5 mr-1.5" />
                  ) : role === "soc_manager" ? (
                    <Monitor className="h-3.5 w-3.5 mr-1.5" />
                  ) : (
                    <Users className="h-3.5 w-3.5 mr-1.5" />
                  )}
                  {ROLE_LABELS[role]}
                </Button>
              ))}
            </div>
          </div>

          {dashboardLoading ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              {[1, 2, 3, 4].map((i) => (
                <Skeleton key={i} className="h-24" />
              ))}
            </div>
          ) : dashboardData ? (
            <div className="space-y-4">
              <h3 className="text-sm font-medium text-muted-foreground" data-testid="text-dashboard-title">
                {dashboardData.title}
              </h3>

              <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3">
                {dashboardData.kpis &&
                  Object.entries(dashboardData.kpis).map(([key, value]) => (
                    <Card key={key} data-testid={`stat-${key}`}>
                      <CardContent className="py-3 px-4">
                        <p className="text-xs text-muted-foreground capitalize">
                          {key.replace(/([A-Z])/g, " $1").trim()}
                        </p>
                        <p className="text-xl font-bold tabular-nums mt-1" data-testid={`value-${key}`}>
                          {(value as any) ?? "N/A"}
                        </p>
                      </CardContent>
                    </Card>
                  ))}
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {dashboardData.severityDistribution && (
                  <Card>
                    <CardHeader>
                      <CardTitle className="text-sm">Severity Distribution</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <ResponsiveContainer width="100%" height={200}>
                        <PieChart>
                          <Pie
                            data={dashboardData.severityDistribution}
                            dataKey="value"
                            nameKey="name"
                            cx="50%"
                            cy="50%"
                            outerRadius={70}
                            label={({ name, value }: any) => `${name}: ${value}`}
                          >
                            {dashboardData.severityDistribution.map((_: any, i: number) => (
                              <Cell key={i} fill={CHART_COLORS[i % CHART_COLORS.length]} />
                            ))}
                          </Pie>
                          <RechartsTooltip />
                        </PieChart>
                      </ResponsiveContainer>
                    </CardContent>
                  </Card>
                )}

                {dashboardData.riskPosture && (
                  <Card>
                    <CardHeader>
                      <CardTitle className="text-sm">Risk Posture</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <ResponsiveContainer width="100%" height={200}>
                        <PieChart>
                          <Pie
                            data={dashboardData.riskPosture}
                            dataKey="value"
                            nameKey="name"
                            cx="50%"
                            cy="50%"
                            outerRadius={70}
                            label={({ name, value }: any) => `${name}: ${value}`}
                          >
                            {dashboardData.riskPosture.map((_: any, i: number) => (
                              <Cell key={i} fill={CHART_COLORS[i % CHART_COLORS.length]} />
                            ))}
                          </Pie>
                          <RechartsTooltip />
                        </PieChart>
                      </ResponsiveContainer>
                    </CardContent>
                  </Card>
                )}

                {dashboardData.topMitreTactics && dashboardData.topMitreTactics.length > 0 && (
                  <Card>
                    <CardHeader>
                      <CardTitle className="text-sm">Top MITRE Tactics</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <ResponsiveContainer width="100%" height={200}>
                        <BarChart data={dashboardData.topMitreTactics}>
                          <CartesianGrid strokeDasharray="3 3" className="opacity-30" />
                          <XAxis dataKey="name" tick={{ fontSize: 10 }} />
                          <YAxis tick={{ fontSize: 10 }} />
                          <RechartsTooltip />
                          <Bar dataKey="value" fill="#3b82f6" radius={[4, 4, 0, 0]} />
                        </BarChart>
                      </ResponsiveContainer>
                    </CardContent>
                  </Card>
                )}

                {dashboardData.alertTrend && dashboardData.alertTrend.length > 0 && (
                  <Card>
                    <CardHeader>
                      <CardTitle className="text-sm">Alert Trend</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <ResponsiveContainer width="100%" height={200}>
                        <AreaChart data={dashboardData.alertTrend}>
                          <CartesianGrid strokeDasharray="3 3" className="opacity-30" />
                          <XAxis dataKey="date" tick={{ fontSize: 10 }} />
                          <YAxis tick={{ fontSize: 10 }} />
                          <RechartsTooltip />
                          <Area type="monotone" dataKey="count" stroke="#3b82f6" fill="#3b82f6" fillOpacity={0.1} />
                        </AreaChart>
                      </ResponsiveContainer>
                    </CardContent>
                  </Card>
                )}

                {dashboardData.categoryDistribution && dashboardData.categoryDistribution.length > 0 && (
                  <Card>
                    <CardHeader>
                      <CardTitle className="text-sm">Category Distribution</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <ResponsiveContainer width="100%" height={200}>
                        <BarChart data={dashboardData.categoryDistribution}>
                          <CartesianGrid strokeDasharray="3 3" className="opacity-30" />
                          <XAxis dataKey="name" tick={{ fontSize: 10 }} angle={-45} textAnchor="end" height={60} />
                          <YAxis tick={{ fontSize: 10 }} />
                          <RechartsTooltip />
                          <Bar dataKey="value" fill="#f97316" radius={[4, 4, 0, 0]} />
                        </BarChart>
                      </ResponsiveContainer>
                    </CardContent>
                  </Card>
                )}

                {dashboardData.sourceDistribution && dashboardData.sourceDistribution.length > 0 && (
                  <Card>
                    <CardHeader>
                      <CardTitle className="text-sm">Source Distribution</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <ResponsiveContainer width="100%" height={200}>
                        <PieChart>
                          <Pie
                            data={dashboardData.sourceDistribution}
                            dataKey="value"
                            nameKey="name"
                            cx="50%"
                            cy="50%"
                            outerRadius={70}
                            label={({ name, value }: any) => `${name}: ${value}`}
                          >
                            {dashboardData.sourceDistribution.map((_: any, i: number) => (
                              <Cell key={i} fill={CHART_COLORS[i % CHART_COLORS.length]} />
                            ))}
                          </Pie>
                          <RechartsTooltip />
                        </PieChart>
                      </ResponsiveContainer>
                    </CardContent>
                  </Card>
                )}

                {dashboardData.connectorHealth && dashboardData.connectorHealth.length > 0 && (
                  <Card className="md:col-span-2">
                    <CardHeader>
                      <CardTitle className="text-sm">Connector Health</CardTitle>
                    </CardHeader>
                    <CardContent className="p-0">
                      <div className="overflow-x-auto">
                        <table className="w-full text-xs">
                          <thead>
                            <tr className="border-b">
                              <th className="p-2 text-left font-medium text-muted-foreground">Name</th>
                              <th className="p-2 text-left font-medium text-muted-foreground">Type</th>
                              <th className="p-2 text-left font-medium text-muted-foreground">Status</th>
                              <th className="p-2 text-left font-medium text-muted-foreground">Last Sync</th>
                            </tr>
                          </thead>
                          <tbody>
                            {dashboardData.connectorHealth.map((c: any, i: number) => (
                              <tr key={i} className="border-b last:border-0">
                                <td className="p-2">{c.name}</td>
                                <td className="p-2">{c.type}</td>
                                <td className="p-2">
                                  <Badge
                                    variant={c.status === "active" ? "default" : "secondary"}
                                    className="no-default-hover-elevate no-default-active-elevate"
                                  >
                                    {c.status}
                                  </Badge>
                                </td>
                                <td className="p-2 text-muted-foreground">
                                  {c.lastSyncAt ? formatDateTime(c.lastSyncAt) : "Never"}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </CardContent>
                  </Card>
                )}
              </div>

              {(dashboardData.recentCriticalIncidents || dashboardData.recentIncidents) && (
                <Card>
                  <CardHeader>
                    <CardTitle className="text-sm">
                      {dashboardRole === "ciso" ? "Critical Incidents" : "Recent Incidents"}
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="p-0">
                    <div className="overflow-x-auto">
                      <table className="w-full text-xs">
                        <thead>
                          <tr className="border-b">
                            <th className="p-2 text-left font-medium text-muted-foreground">Title</th>
                            <th className="p-2 text-left font-medium text-muted-foreground">Severity</th>
                            <th className="p-2 text-left font-medium text-muted-foreground">Status</th>
                            <th className="p-2 text-left font-medium text-muted-foreground">Created</th>
                          </tr>
                        </thead>
                        <tbody>
                          {(dashboardData.recentCriticalIncidents || dashboardData.recentIncidents || []).map(
                            (inc: any) => (
                              <tr key={inc.id} className="border-b last:border-0">
                                <td className="p-2 font-medium">{inc.title}</td>
                                <td className="p-2">
                                  <Badge
                                    variant={inc.severity === "critical" ? "destructive" : "outline"}
                                    className="no-default-hover-elevate no-default-active-elevate"
                                  >
                                    {inc.severity}
                                  </Badge>
                                </td>
                                <td className="p-2">{inc.status}</td>
                                <td className="p-2 text-muted-foreground">{formatDate(inc.createdAt)}</td>
                              </tr>
                            ),
                          )}
                        </tbody>
                      </table>
                    </div>
                  </CardContent>
                </Card>
              )}
            </div>
          ) : null}
        </TabsContent>

        <TemplateVersioningTab templates={templates || []} />
      </Tabs>

      <Dialog open={showCreateTemplate} onOpenChange={setShowCreateTemplate}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create Report Template</DialogTitle>
            <DialogDescription>Configure a new report template</DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-1.5">
              <Label htmlFor="tmpl-name">Name</Label>
              <Input
                id="tmpl-name"
                value={templateName}
                onChange={(e) => setTemplateName(e.target.value)}
                placeholder="Weekly Security Brief"
                data-testid="input-template-name"
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="tmpl-desc">Description</Label>
              <Textarea
                id="tmpl-desc"
                value={templateDescription}
                onChange={(e) => setTemplateDescription(e.target.value)}
                placeholder="Description of the report..."
                data-testid="input-template-description"
              />
            </div>
            <div className="grid grid-cols-3 gap-3">
              <div className="space-y-1.5">
                <Label>Report Type</Label>
                <Select value={templateType} onValueChange={setTemplateType}>
                  <SelectTrigger data-testid="select-template-type">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {Object.entries(REPORT_TYPE_LABELS).map(([k, v]) => (
                      <SelectItem key={k} value={k}>
                        {v}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label>Format</Label>
                <Select value={templateFormat} onValueChange={setTemplateFormat}>
                  <SelectTrigger data-testid="select-template-format">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="csv">CSV</SelectItem>
                    <SelectItem value="json">JSON</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label>Dashboard Role</Label>
                <Select value={templateRole} onValueChange={setTemplateRole}>
                  <SelectTrigger data-testid="select-template-role">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {Object.entries(ROLE_LABELS).map(([k, v]) => (
                      <SelectItem key={k} value={k}>
                        {v}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowCreateTemplate(false)}>
              Cancel
            </Button>
            <Button
              onClick={() =>
                createTemplate.mutate({
                  name: templateName,
                  description: templateDescription,
                  reportType: templateType,
                  format: templateFormat,
                  dashboardRole: templateRole,
                })
              }
              disabled={!templateName || createTemplate.isPending}
              data-testid="button-submit-template"
            >
              {createTemplate.isPending ? <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" /> : null}Create Template
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={showCreateSchedule} onOpenChange={setShowCreateSchedule}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create Report Schedule</DialogTitle>
            <DialogDescription>Set up automated report delivery</DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-1.5">
              <Label htmlFor="sched-name">Schedule Name</Label>
              <Input
                id="sched-name"
                value={scheduleName}
                onChange={(e) => setScheduleName(e.target.value)}
                placeholder="Weekly SOC Brief"
                data-testid="input-schedule-name"
              />
            </div>
            <div className="space-y-1.5">
              <Label>Report Template</Label>
              <Select value={scheduleTemplateId} onValueChange={setScheduleTemplateId}>
                <SelectTrigger data-testid="select-schedule-template">
                  <SelectValue placeholder="Select template..." />
                </SelectTrigger>
                <SelectContent>
                  {templates?.map((t: any) => (
                    <SelectItem key={t.id} value={t.id}>
                      {t.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label>Cadence</Label>
                <Select value={scheduleCadence} onValueChange={setScheduleCadence}>
                  <SelectTrigger data-testid="select-schedule-cadence">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {Object.entries(CADENCE_LABELS).map(([k, v]) => (
                      <SelectItem key={k} value={k}>
                        {v}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label>Delivery Type</Label>
                <Select value={scheduleDeliveryType} onValueChange={setScheduleDeliveryType}>
                  <SelectTrigger data-testid="select-schedule-delivery-type">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="email">Email</SelectItem>
                    <SelectItem value="s3">S3 Bucket</SelectItem>
                    <SelectItem value="webhook">Webhook</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="sched-target">
                {scheduleDeliveryType === "email"
                  ? "Email Address"
                  : scheduleDeliveryType === "webhook"
                    ? "Webhook URL"
                    : "S3 Path"}
              </Label>
              <Input
                id="sched-target"
                value={scheduleDeliveryTarget}
                onChange={(e) => setScheduleDeliveryTarget(e.target.value)}
                placeholder={
                  scheduleDeliveryType === "email"
                    ? "soc-team@company.com"
                    : scheduleDeliveryType === "webhook"
                      ? "https://hooks.example.com/reports"
                      : "s3://bucket/reports/"
                }
                data-testid="input-schedule-target"
              />
            </div>
            <div className="flex items-center gap-2">
              <Switch
                checked={scheduleEnabled}
                onCheckedChange={setScheduleEnabled}
                data-testid="switch-schedule-enabled"
              />
              <Label>Enable schedule immediately</Label>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowCreateSchedule(false)}>
              Cancel
            </Button>
            <Button
              onClick={() =>
                createSchedule.mutate({
                  name: scheduleName,
                  templateId: scheduleTemplateId,
                  cadence: scheduleCadence,
                  deliveryTargets: JSON.stringify([
                    {
                      type: scheduleDeliveryType,
                      [scheduleDeliveryType === "email"
                        ? "address"
                        : scheduleDeliveryType === "webhook"
                          ? "url"
                          : "path"]: scheduleDeliveryTarget,
                    },
                  ]),
                  enabled: scheduleEnabled,
                })
              }
              disabled={!scheduleName || !scheduleTemplateId || createSchedule.isPending}
              data-testid="button-submit-schedule"
            >
              {createSchedule.isPending ? <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" /> : null}Create Schedule
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function TemplateVersioningTab({ templates }: { templates: any[] }) {
  const { toast } = useToast();
  const [selectedTemplate, setSelectedTemplate] = useState<string>("");
  const [showCreateVersion, setShowCreateVersion] = useState(false);
  const [changeDescription, setChangeDescription] = useState("");

  const {
    data: versions,
    isLoading: versionsLoading,
    refetch: refetchVersions,
  } = useQuery<any[]>({
    queryKey: ["/api/report-templates", selectedTemplate, "versions"],
    queryFn: async () => {
      if (!selectedTemplate) return [];
      const res = await fetch(`/api/report-templates/${selectedTemplate}/versions`, { credentials: "include" });
      if (!res.ok) return [];
      return res.json();
    },
    enabled: !!selectedTemplate,
  });

  const createVersion = useMutation({
    mutationFn: async (data: { changeDescription: string }) => {
      const res = await apiRequest("POST", `/api/report-templates/${selectedTemplate}/versions`, data);
      return res.json();
    },
    onSuccess: () => {
      refetchVersions();
      setShowCreateVersion(false);
      setChangeDescription("");
      toast({ title: "Version Created" });
    },
    onError: (e: Error) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const approveVersion = useMutation({
    mutationFn: async (id: string) => {
      const res = await apiRequest("PATCH", `/api/report-template-versions/${id}`, { status: "active" });
      return res.json();
    },
    onSuccess: () => {
      refetchVersions();
      toast({ title: "Version Approved" });
    },
  });

  const deprecateVersion = useMutation({
    mutationFn: async (id: string) => {
      const res = await apiRequest("PATCH", `/api/report-template-versions/${id}`, { status: "deprecated" });
      return res.json();
    },
    onSuccess: () => {
      refetchVersions();
      toast({ title: "Version Deprecated" });
    },
  });

  return (
    <TabsContent value="versioning" className="space-y-4 mt-4">
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <h2 className="text-lg font-semibold">Template Version History</h2>
        <div className="flex items-center gap-2">
          <Select value={selectedTemplate} onValueChange={setSelectedTemplate}>
            <SelectTrigger className="w-[220px]" data-testid="select-version-template">
              <SelectValue placeholder="Select template" />
            </SelectTrigger>
            <SelectContent>
              {templates.map((t: any) => (
                <SelectItem key={t.id} value={t.id}>
                  {t.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          {selectedTemplate && (
            <Button size="sm" onClick={() => setShowCreateVersion(true)} data-testid="button-create-version">
              <Plus className="h-3.5 w-3.5 mr-1.5" />
              New Version
            </Button>
          )}
        </div>
      </div>

      {!selectedTemplate ? (
        <Card>
          <CardContent className="py-12 text-center text-muted-foreground">
            <GitBranch className="h-10 w-10 mx-auto mb-3 opacity-40" />
            <p>Select a template to view its version history</p>
          </CardContent>
        </Card>
      ) : versionsLoading ? (
        <div className="space-y-3">
          {[1, 2].map((i) => (
            <Skeleton key={i} className="h-20" />
          ))}
        </div>
      ) : !versions?.length ? (
        <Card>
          <CardContent className="py-12 text-center text-muted-foreground">
            <History className="h-10 w-10 mx-auto mb-3 opacity-40" />
            <p>No versions yet</p>
            <p className="text-xs mt-1">Create a version to start tracking changes</p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {versions.map((v: any) => (
            <Card key={v.id} data-testid={`card-version-${v.id}`}>
              <CardContent className="py-4">
                <div className="flex items-center justify-between gap-3 flex-wrap">
                  <div className="space-y-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-sm font-semibold">v{v.version}</span>
                      <Badge
                        variant="outline"
                        className={`no-default-hover-elevate no-default-active-elevate ${VERSION_STATUS_COLORS[v.status] || ""}`}
                      >
                        {v.status}
                      </Badge>
                    </div>
                    <p className="text-sm text-muted-foreground">{v.changeDescription}</p>
                    <p className="text-xs text-muted-foreground">
                      Created: {formatDateTime(v.createdAt)}
                      {v.approvedAt && ` | Approved: ${formatDateTime(v.approvedAt)}`}
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    {v.status === "draft" && (
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => approveVersion.mutate(v.id)}
                        disabled={approveVersion.isPending}
                      >
                        <CheckCircle2 className="h-3.5 w-3.5 mr-1.5" />
                        Approve
                      </Button>
                    )}
                    {v.status === "active" && (
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => deprecateVersion.mutate(v.id)}
                        disabled={deprecateVersion.isPending}
                      >
                        Deprecate
                      </Button>
                    )}
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      <Dialog open={showCreateVersion} onOpenChange={setShowCreateVersion}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create New Version</DialogTitle>
            <DialogDescription>
              Create a new version of this report template with a description of changes.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-1.5">
              <Label htmlFor="version-desc">Change Description</Label>
              <Textarea
                id="version-desc"
                value={changeDescription}
                onChange={(e) => setChangeDescription(e.target.value)}
                placeholder="Describe what changed in this version..."
                data-testid="input-version-description"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowCreateVersion(false)}>
              Cancel
            </Button>
            <Button
              onClick={() => createVersion.mutate({ changeDescription })}
              disabled={!changeDescription.trim() || createVersion.isPending}
              data-testid="button-submit-version"
            >
              {createVersion.isPending ? <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" /> : null}
              Create Version
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </TabsContent>
  );
}

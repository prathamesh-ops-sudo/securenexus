import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import {
  Calendar,
  Plus,
  Play,
  Pause,
  Trash2,
  Clock,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  BarChart3,
  FileText,
  Mail,
  Timer,
  TrendingUp,
  Loader2,
  RefreshCw,
  Settings,
} from "lucide-react";
import { SuccessIcon } from "@/components/ui/animated-state-icons";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { useToast } from "@/hooks/use-toast";

export default function ReportSchedulingPage() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [selectedSchedule, setSelectedSchedule] = useState<string | null>(null);
  const [newSchedule, setNewSchedule] = useState({
    reportType: "compliance",
    name: "",
    cadence: "weekly",
    recipients: "",
    format: "pdf",
    slaMinutes: 60,
  });

  const { data: schedules, isLoading } = useQuery({
    queryKey: ["/api/report-schedules"],
    queryFn: async () => {
      const r = await apiRequest("GET", "/api/report-schedules");
      return r.json();
    },
  });

  const { data: slaSummary } = useQuery({
    queryKey: ["/api/report-schedules/sla/summary"],
    queryFn: async () => {
      const r = await apiRequest("GET", "/api/report-schedules/sla/summary");
      return r.json();
    },
  });

  const { data: deliveries } = useQuery({
    queryKey: ["/api/report-schedules", selectedSchedule, "deliveries"],
    queryFn: async () => {
      const r = await apiRequest("GET", `/api/report-schedules/${selectedSchedule}/deliveries`);
      return r.json();
    },
    enabled: !!selectedSchedule,
  });

  const createMutation = useMutation({
    mutationFn: async (data: any) => {
      const r = await apiRequest("POST", "/api/report-schedules", {
        ...data,
        recipients: data.recipients
          .split(",")
          .map((r: string) => r.trim())
          .filter(Boolean),
        slaMinutes: Number(data.slaMinutes),
      });
      return r.json();
    },
    onSuccess: () => {
      toast({ title: "Schedule Created" });
      queryClient.invalidateQueries({ queryKey: ["/api/report-schedules"] });
      setShowCreate(false);
      setNewSchedule({
        reportType: "compliance",
        name: "",
        cadence: "weekly",
        recipients: "",
        format: "pdf",
        slaMinutes: 60,
      });
    },
    onError: () => toast({ title: "Failed to create schedule", variant: "destructive" }),
  });

  const triggerMutation = useMutation({
    mutationFn: async (id: string) => {
      const r = await apiRequest("POST", `/api/report-schedules/${id}/trigger`);
      return r.json();
    },
    onSuccess: (data: any) => {
      const slaMet = data?.slaMet;
      toast({
        title: "Report Generated",
        description: slaMet ? "Delivered within SLA" : "SLA breached",
        variant: slaMet ? "default" : "destructive",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/report-schedules"] });
      queryClient.invalidateQueries({ queryKey: ["/api/report-schedules", selectedSchedule, "deliveries"] });
    },
    onError: () => toast({ title: "Trigger Failed", variant: "destructive" }),
  });

  const toggleMutation = useMutation({
    mutationFn: async ({ id, isActive }: { id: string; isActive: boolean }) => {
      const r = await apiRequest("PATCH", `/api/report-schedules/${id}`, { isActive });
      return r.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/report-schedules"] });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("DELETE", `/api/report-schedules/${id}`);
    },
    onSuccess: () => {
      toast({ title: "Schedule Deleted" });
      queryClient.invalidateQueries({ queryKey: ["/api/report-schedules"] });
      if (selectedSchedule) setSelectedSchedule(null);
    },
  });

  const scheduleList = Array.isArray(schedules) ? schedules : (schedules as any)?.data || [];
  const sla = slaSummary as any;
  const deliveryList = Array.isArray(deliveries) ? deliveries : (deliveries as any)?.data || [];

  if (isLoading) {
    return (
      <div className="p-6 space-y-4">
        <Skeleton className="h-8 w-64" />
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {[1, 2, 3, 4].map((i) => (
            <Skeleton key={i} className="h-32" />
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
            <Calendar className="h-6 w-6 text-indigo-400" />
            Report Scheduling & SLA
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Automated report delivery with SLA tracking and compliance
          </p>
        </div>
        <Button onClick={() => setShowCreate(true)} className="bg-indigo-600 hover:bg-indigo-700">
          <Plus className="h-4 w-4 mr-2" />
          New Schedule
        </Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="border-indigo-500/20 bg-card/50">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Calendar className="h-4 w-4 text-indigo-400" />
              Active Schedules
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{sla?.activeSchedules || 0}</div>
            <p className="text-xs text-muted-foreground">of {sla?.totalSchedules || 0} total</p>
          </CardContent>
        </Card>
        <Card className="border-indigo-500/20 bg-card/50">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <TrendingUp className="h-4 w-4 text-green-400" />
              SLA Compliance
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div
              className={`text-2xl font-bold ${(sla?.slaComplianceRate || 100) >= 95 ? "text-green-400" : (sla?.slaComplianceRate || 100) >= 80 ? "text-yellow-400" : "text-red-400"}`}
            >
              {sla?.slaComplianceRate || 100}%
            </div>
            <p className="text-xs text-muted-foreground">{sla?.totalRuns || 0} total runs</p>
          </CardContent>
        </Card>
        <Card className="border-indigo-500/20 bg-card/50">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-orange-400" />
              SLA Breaches
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-orange-400">{sla?.totalBreaches || 0}</div>
            <p className="text-xs text-muted-foreground">{sla?.atRiskSchedules || 0} at risk</p>
          </CardContent>
        </Card>
        <Card className="border-indigo-500/20 bg-card/50">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <FileText className="h-4 w-4 text-cyan-400" />
              Total Deliveries
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{sla?.totalRuns || 0}</div>
          </CardContent>
        </Card>
      </div>

      {showCreate && (
        <Card className="border-indigo-500/20 bg-card/50">
          <CardHeader>
            <CardTitle className="text-lg">Create Report Schedule</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <Input
              placeholder="Schedule name"
              value={newSchedule.name}
              onChange={(e) => setNewSchedule({ ...newSchedule, name: e.target.value })}
            />
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <select
                value={newSchedule.reportType}
                onChange={(e) => setNewSchedule({ ...newSchedule, reportType: e.target.value })}
                className="px-3 py-2 text-sm bg-background border border-border rounded"
              >
                <option value="compliance">Compliance Report</option>
                <option value="security_posture">Security Posture</option>
                <option value="incident_summary">Incident Summary</option>
                <option value="vulnerability">Vulnerability Report</option>
                <option value="executive">Executive Dashboard</option>
              </select>
              <select
                value={newSchedule.cadence}
                onChange={(e) => setNewSchedule({ ...newSchedule, cadence: e.target.value })}
                className="px-3 py-2 text-sm bg-background border border-border rounded"
              >
                <option value="daily">Daily</option>
                <option value="weekly">Weekly</option>
                <option value="biweekly">Biweekly</option>
                <option value="monthly">Monthly</option>
                <option value="quarterly">Quarterly</option>
              </select>
              <select
                value={newSchedule.format}
                onChange={(e) => setNewSchedule({ ...newSchedule, format: e.target.value })}
                className="px-3 py-2 text-sm bg-background border border-border rounded"
              >
                <option value="pdf">PDF</option>
                <option value="csv">CSV</option>
                <option value="html">HTML</option>
              </select>
              <Input
                type="number"
                placeholder="SLA (minutes)"
                value={newSchedule.slaMinutes}
                onChange={(e) => setNewSchedule({ ...newSchedule, slaMinutes: Number(e.target.value) })}
              />
            </div>
            <Input
              placeholder="Recipients (comma-separated emails)"
              value={newSchedule.recipients}
              onChange={(e) => setNewSchedule({ ...newSchedule, recipients: e.target.value })}
            />
            <div className="flex gap-2">
              <Button
                onClick={() => createMutation.mutate(newSchedule)}
                disabled={!newSchedule.name || createMutation.isPending}
                className="bg-indigo-600 hover:bg-indigo-700"
              >
                {createMutation.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                Create Schedule
              </Button>
              <Button variant="outline" onClick={() => setShowCreate(false)}>
                Cancel
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="space-y-3">
          <h2 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider">Schedules</h2>
          {scheduleList.length === 0 && (
            <Card className="border-dashed border-border bg-card/30">
              <CardContent className="py-8 text-center">
                <Calendar className="h-10 w-10 text-muted-foreground mx-auto mb-2" />
                <p className="text-sm text-muted-foreground">No schedules created yet</p>
              </CardContent>
            </Card>
          )}
          {scheduleList.map((s: any) => (
            <Card
              key={s.id}
              onClick={() => setSelectedSchedule(s.id)}
              className={`cursor-pointer transition-all hover:border-indigo-500/30 ${selectedSchedule === s.id ? "border-indigo-400 bg-indigo-500/5" : "border-border bg-card/50"}`}
            >
              <CardContent className="p-4">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm font-medium">{s.name}</span>
                  <Badge
                    className={`text-xs ${s.isActive ? "bg-green-500/20 text-green-400" : "bg-gray-500/20 text-gray-400"}`}
                  >
                    {s.isActive ? "Active" : "Paused"}
                  </Badge>
                </div>
                <div className="flex items-center gap-3 text-xs text-muted-foreground">
                  <span className="capitalize">{s.cadence}</span>
                  <span>{s.format?.toUpperCase()}</span>
                  <span>SLA: {s.slaMinutes}m</span>
                </div>
                {s.slaMet !== null && (
                  <div className="flex items-center gap-1 mt-1">
                    {s.slaMet ? (
                      <SuccessIcon size={12} color="#22c55e" />
                    ) : (
                      <AlertTriangle className="h-3 w-3 text-red-400" />
                    )}
                    <span className="text-xs text-muted-foreground">
                      Last: {s.slaMet ? "SLA met" : `SLA breached (${s.consecutiveSlaBreaches} consecutive)`}
                    </span>
                  </div>
                )}
              </CardContent>
            </Card>
          ))}
        </div>

        <div className="lg:col-span-2">
          {!selectedSchedule && (
            <Card className="border-dashed border-border bg-card/30 h-full">
              <CardContent className="py-20 text-center">
                <Calendar className="h-12 w-12 text-muted-foreground mx-auto mb-3" />
                <p className="text-muted-foreground">Select a schedule to view delivery history</p>
              </CardContent>
            </Card>
          )}

          {selectedSchedule && (
            <div className="space-y-4">
              {(() => {
                const s = scheduleList.find((s: any) => s.id === selectedSchedule);
                if (!s) return null;
                return (
                  <Card className="border-indigo-500/20 bg-card/50">
                    <CardHeader className="pb-2">
                      <div className="flex items-center justify-between">
                        <CardTitle className="text-lg">{s.name}</CardTitle>
                        <div className="flex gap-2">
                          <Button
                            size="sm"
                            onClick={() => triggerMutation.mutate(s.id)}
                            disabled={triggerMutation.isPending}
                          >
                            {triggerMutation.isPending ? (
                              <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                            ) : (
                              <Play className="h-4 w-4 mr-2" />
                            )}
                            Trigger Now
                          </Button>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => toggleMutation.mutate({ id: s.id, isActive: !s.isActive })}
                          >
                            {s.isActive ? <Pause className="h-4 w-4 mr-1" /> : <Play className="h-4 w-4 mr-1" />}
                            {s.isActive ? "Pause" : "Resume"}
                          </Button>
                          <Button size="sm" variant="destructive" onClick={() => deleteMutation.mutate(s.id)}>
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </div>
                      </div>
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs mt-2">
                        <div>
                          <span className="text-muted-foreground">Type:</span> {s.reportType}
                        </div>
                        <div>
                          <span className="text-muted-foreground">Cadence:</span> {s.cadence}
                        </div>
                        <div>
                          <span className="text-muted-foreground">Format:</span> {s.format?.toUpperCase()}
                        </div>
                        <div>
                          <span className="text-muted-foreground">SLA:</span> {s.slaMinutes} min
                        </div>
                        <div>
                          <span className="text-muted-foreground">Runs:</span> {s.totalRuns}
                        </div>
                        <div>
                          <span className="text-muted-foreground">Breaches:</span> {s.totalSlaBreaches}
                        </div>
                        <div>
                          <span className="text-muted-foreground">Recipients:</span> {s.recipients?.length || 0}
                        </div>
                        <div>
                          <span className="text-muted-foreground">Next:</span>{" "}
                          {s.nextRunAt ? new Date(s.nextRunAt).toLocaleDateString() : "-"}
                        </div>
                      </div>
                    </CardHeader>
                  </Card>
                );
              })()}

              <Card className="border-indigo-500/20 bg-card/50">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm">Delivery History</CardTitle>
                </CardHeader>
                <CardContent>
                  {deliveryList.length === 0 && (
                    <div className="py-8 text-center">
                      <Timer className="h-8 w-8 text-muted-foreground mx-auto mb-2" />
                      <p className="text-sm text-muted-foreground">No deliveries yet. Trigger a run above.</p>
                    </div>
                  )}
                  <div className="space-y-2">
                    {deliveryList.map((d: any) => (
                      <div
                        key={d.id}
                        className="flex items-center justify-between p-3 rounded-lg bg-background/50 border border-border"
                      >
                        <div className="flex items-center gap-3">
                          {d.slaMet ? (
                            <SuccessIcon size={20} color="#22c55e" />
                          ) : (
                            <XCircle className="h-5 w-5 text-red-400" />
                          )}
                          <div>
                            <div className="text-sm font-medium">{new Date(d.startedAt).toLocaleString()}</div>
                            <div className="text-xs text-muted-foreground">
                              Duration: {d.durationMs ? `${(d.durationMs / 1000).toFixed(1)}s` : "-"} | SLA:{" "}
                              {d.slaMinutes}m
                            </div>
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          <Badge
                            className={`text-xs ${d.status === "delivered" ? "bg-green-500/20 text-green-400" : "bg-red-500/20 text-red-400"}`}
                          >
                            {d.status}
                          </Badge>
                          <Badge
                            className={`text-xs ${d.slaMet ? "bg-green-500/20 text-green-400" : "bg-red-500/20 text-red-400"}`}
                          >
                            {d.slaMet ? "SLA Met" : "SLA Breached"}
                          </Badge>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

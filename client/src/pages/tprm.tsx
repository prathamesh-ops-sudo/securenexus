import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
  DialogFooter,
  DialogDescription,
} from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks/use-toast";
import {
  Building2,
  Plus,
  Search,
  Shield,
  AlertTriangle,
  Activity,
  FileText,
  Network,
  RefreshCw,
  ChevronRight,
  Globe,
  ExternalLink,
  Clock,
  ShieldAlert,
  CheckCircle2,
  XCircle,
  BarChart3,
  TrendingUp,
  Users,
  Loader2,
} from "lucide-react";
import { apiRequest } from "@/lib/queryClient";

// ── Types ─────────────────────────────────────────────────────────

interface Vendor {
  id: string;
  name: string;
  domain: string | null;
  website: string | null;
  category: string;
  description: string | null;
  status: string;
  riskTier: string;
  overallRiskScore: number | null;
  securityScore: number | null;
  complianceCertifications: string[] | null;
  dataAccessLevel: string | null;
  dataTypes: string[] | null;
  contractStartDate: string | null;
  contractEndDate: string | null;
  contractValue: number | null;
  primaryContact: string | null;
  primaryContactEmail: string | null;
  securityContact: string | null;
  securityContactEmail: string | null;
  fourthPartyVendors: unknown;
  reviewCadence: string;
  lastReviewDate: string | null;
  nextReviewDate: string | null;
  notes: string | null;
  createdAt: string;
  updatedAt: string;
}

interface VendorAssessment {
  id: string;
  vendorId: string;
  questionnaireType: string;
  title: string;
  status: string;
  sentAt: string | null;
  dueDate: string | null;
  completedAt: string | null;
  totalQuestions: number;
  answeredQuestions: number;
  score: number | null;
  riskRating: string | null;
  createdAt: string;
}

interface VendorRisk {
  id: string;
  vendorId: string;
  category: string;
  title: string;
  description: string;
  severity: string;
  status: string;
  source: string;
  createdAt: string;
}

interface MonitoringEvent {
  id: string;
  vendorId: string;
  checkType: string;
  status: string;
  details: string | null;
  severity: string;
  checkedAt: string;
}

interface BreachAlert {
  id: string;
  vendorId: string;
  title: string;
  description: string;
  source: string;
  severity: string;
  status: string;
  createdAt: string;
}

interface TprmSummary {
  vendors: {
    total: number;
    active: number;
    critical: number;
    highRisk: number;
    overdueReviews: number;
    avgSecurityScore: number;
  };
  assessments: {
    total: number;
    pending: number;
    completed: number;
    overdue: number;
    avgScore: number;
  };
  risks: {
    total: number;
    open: number;
    critical: number;
    high: number;
  };
  breachAlerts: {
    total: number;
    new: number;
    investigating: number;
  };
}

interface FourthPartyRisk {
  totalFourthParties: number;
  uniqueFourthParties: number;
  highRiskCount: number;
  byVendor: Array<{ vendorId: string; vendorName: string; fourthPartyCount: number }>;
}

// ── Helpers ───────────────────────────────────────────────────────

function riskTierColor(tier: string): string {
  switch (tier) {
    case "critical":
      return "bg-red-500/10 text-red-500 border-red-500/20";
    case "high":
      return "bg-orange-500/10 text-orange-500 border-orange-500/20";
    case "medium":
      return "bg-yellow-500/10 text-yellow-500 border-yellow-500/20";
    case "low":
      return "bg-blue-500/10 text-blue-500 border-blue-500/20";
    case "minimal":
      return "bg-green-500/10 text-green-500 border-green-500/20";
    default:
      return "bg-muted text-muted-foreground";
  }
}

function statusColor(status: string): string {
  switch (status) {
    case "active":
      return "bg-green-500/10 text-green-500";
    case "under_review":
      return "bg-yellow-500/10 text-yellow-500";
    case "probation":
      return "bg-orange-500/10 text-orange-500";
    case "offboarded":
      return "bg-muted text-muted-foreground";
    case "pending_onboard":
      return "bg-blue-500/10 text-blue-500";
    default:
      return "bg-muted text-muted-foreground";
  }
}

function severityColor(sev: string): string {
  switch (sev) {
    case "critical":
      return "bg-red-500/10 text-red-500";
    case "high":
      return "bg-orange-500/10 text-orange-500";
    case "medium":
      return "bg-yellow-500/10 text-yellow-500";
    case "low":
      return "bg-blue-500/10 text-blue-500";
    default:
      return "bg-muted text-muted-foreground";
  }
}

function formatDate(d: string | null): string {
  if (!d) return "—";
  return new Date(d).toLocaleDateString();
}

const CATEGORIES = [
  { value: "saas", label: "SaaS" },
  { value: "infrastructure", label: "Infrastructure" },
  { value: "payment_processing", label: "Payment Processing" },
  { value: "cloud_hosting", label: "Cloud Hosting" },
  { value: "identity_provider", label: "Identity Provider" },
  { value: "analytics", label: "Analytics" },
  { value: "communications", label: "Communications" },
  { value: "development_tools", label: "Development Tools" },
  { value: "security", label: "Security" },
  { value: "data_processing", label: "Data Processing" },
  { value: "consulting", label: "Consulting" },
  { value: "staffing", label: "Staffing" },
  { value: "hardware", label: "Hardware" },
  { value: "other", label: "Other" },
];

const RISK_TIERS = [
  { value: "critical", label: "Critical" },
  { value: "high", label: "High" },
  { value: "medium", label: "Medium" },
  { value: "low", label: "Low" },
  { value: "minimal", label: "Minimal" },
];

// ── Main Component ────────────────────────────────────────────────

export default function TprmPage() {
  const [search, setSearch] = useState("");
  const [riskFilter, setRiskFilter] = useState("all");
  const [categoryFilter, setCategoryFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [selectedVendor, setSelectedVendor] = useState<string | null>(null);
  const [addVendorOpen, setAddVendorOpen] = useState(false);
  const [sendQuestionnaireOpen, setSendQuestionnaireOpen] = useState(false);
  const { toast } = useToast();
  const qc = useQueryClient();

  // ── Data Fetching ───────────────────────────────────────────────

  const { data: summaryData } = useQuery<TprmSummary>({
    queryKey: ["/api/tprm/summary"],
  });

  const { data: vendorsData, isLoading: vendorsLoading } = useQuery<{
    vendors: Vendor[];
    total: number;
    stats: Record<string, number>;
  }>({
    queryKey: ["/api/tprm/vendors", search, riskFilter, categoryFilter, statusFilter],
    queryFn: () => {
      const params = new URLSearchParams();
      if (search) params.set("q", search);
      if (riskFilter !== "all") params.set("riskTier", riskFilter);
      if (categoryFilter !== "all") params.set("category", categoryFilter);
      if (statusFilter !== "all") params.set("status", statusFilter);
      return apiRequest("GET", `/api/tprm/vendors?${params.toString()}`).then((r) => r.json());
    },
  });

  const { data: vendorDetail } = useQuery<{
    vendor: Vendor;
    assessments: VendorAssessment[];
    risks: VendorRisk[];
    monitoringEvents: MonitoringEvent[];
    breachAlerts: BreachAlert[];
  }>({
    queryKey: ["/api/tprm/vendors", selectedVendor],
    queryFn: () => apiRequest("GET", `/api/tprm/vendors/${selectedVendor}`).then((r) => r.json()),
    enabled: !!selectedVendor,
  });

  const { data: breachAlerts } = useQuery<{ alerts: BreachAlert[] }>({
    queryKey: ["/api/tprm/breach-alerts"],
  });

  const { data: monitoringStatus } = useQuery<{
    vendorsMonitored: number;
    totalChecks: number;
    alertCount: number;
    warningCount: number;
    okCount: number;
    lastCheckAt: string | null;
    unacknowledgedCount: number;
    recentAlerts: MonitoringEvent[];
  }>({
    queryKey: ["/api/tprm/monitoring/status"],
  });

  const { data: fourthPartyData } = useQuery<FourthPartyRisk>({
    queryKey: ["/api/tprm/fourth-party-risk"],
  });

  const { data: contractRiskMap } = useQuery<{
    vendors: Vendor[];
    byAccessLevel: Record<string, number>;
    byCategory: Record<string, number>;
    totalContractValue: number;
  }>({
    queryKey: ["/api/tprm/contract-risk-map"],
  });

  // ── Mutations ───────────────────────────────────────────────────

  const createVendorMutation = useMutation({
    mutationFn: (data: Record<string, unknown>) => apiRequest("POST", "/api/tprm/vendors", data).then((r) => r.json()),
    onSuccess: () => {
      toast({ title: "Vendor created" });
      qc.invalidateQueries({ queryKey: ["/api/tprm/vendors"] });
      qc.invalidateQueries({ queryKey: ["/api/tprm/summary"] });
      setAddVendorOpen(false);
    },
    onError: (err: Error) => {
      toast({ title: "Failed to create vendor", description: err.message, variant: "destructive" });
    },
  });

  const runMonitoringMutation = useMutation({
    mutationFn: () => apiRequest("POST", "/api/tprm/monitoring/run").then((r) => r.json()),
    onSuccess: (data) => {
      toast({
        title: "Monitoring sweep complete",
        description: `Checked ${data.vendorsChecked} vendors, ${data.totalAlerts} alerts found`,
      });
      qc.invalidateQueries({ queryKey: ["/api/tprm/vendors"] });
      qc.invalidateQueries({ queryKey: ["/api/tprm/summary"] });
      qc.invalidateQueries({ queryKey: ["/api/tprm/monitoring/status"] });
      qc.invalidateQueries({ queryKey: ["/api/tprm/breach-alerts"] });
      qc.invalidateQueries({ queryKey: ["/api/tprm/contract-risk-map"] });
      qc.invalidateQueries({ queryKey: ["/api/tprm/fourth-party-risk"] });
    },
    onError: (err: Error) => {
      toast({ title: "Monitoring failed", description: err.message, variant: "destructive" });
    },
  });

  const sendQuestionnaireMutation = useMutation({
    mutationFn: ({ vendorId, ...data }: Record<string, unknown>) =>
      apiRequest("POST", `/api/tprm/vendors/${vendorId}/send-questionnaire`, data).then((r) => r.json()),
    onSuccess: () => {
      toast({ title: "Questionnaire sent" });
      qc.invalidateQueries({ queryKey: ["/api/tprm/vendors"] });
      setSendQuestionnaireOpen(false);
    },
    onError: (err: Error) => {
      toast({ title: "Failed to send questionnaire", description: err.message, variant: "destructive" });
    },
  });

  const summary = summaryData;
  const vendorsList = vendorsData?.vendors || [];

  // ── Render ──────────────────────────────────────────────────────

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Third-Party Risk Management</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Manage vendor inventory, security assessments, continuous monitoring, and breach alerting
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => runMonitoringMutation.mutate()}
            disabled={runMonitoringMutation.isPending}
          >
            {runMonitoringMutation.isPending ? (
              <Loader2 className="h-4 w-4 mr-1 animate-spin" />
            ) : (
              <RefreshCw className="h-4 w-4 mr-1" />
            )}
            Run Monitoring Sweep
          </Button>
          <Dialog open={addVendorOpen} onOpenChange={setAddVendorOpen}>
            <DialogTrigger asChild>
              <Button size="sm">
                <Plus className="h-4 w-4 mr-1" />
                Add Vendor
              </Button>
            </DialogTrigger>
            <DialogContent className="max-w-lg">
              <DialogHeader>
                <DialogTitle>Add Vendor</DialogTitle>
                <DialogDescription>Register a new third-party vendor for risk management</DialogDescription>
              </DialogHeader>
              <AddVendorForm
                onSubmit={(data) => createVendorMutation.mutate(data)}
                isPending={createVendorMutation.isPending}
              />
            </DialogContent>
          </Dialog>
        </div>
      </div>

      {/* Summary Cards */}
      {summary && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <Card>
            <CardContent className="pt-4 pb-3">
              <div className="flex items-center gap-2 mb-1">
                <Building2 className="h-4 w-4 text-muted-foreground" />
                <span className="text-xs text-muted-foreground">Total Vendors</span>
              </div>
              <div className="text-2xl font-semibold">{summary.vendors.total}</div>
              <div className="text-xs text-muted-foreground mt-1">
                {summary.vendors.active} active
                {summary.vendors.overdueReviews > 0 && (
                  <span className="text-yellow-500 ml-1">({summary.vendors.overdueReviews} overdue reviews)</span>
                )}
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4 pb-3">
              <div className="flex items-center gap-2 mb-1">
                <ShieldAlert className="h-4 w-4 text-red-500" />
                <span className="text-xs text-muted-foreground">High Risk Vendors</span>
              </div>
              <div className="text-2xl font-semibold text-red-500">
                {summary.vendors.critical + summary.vendors.highRisk}
              </div>
              <div className="text-xs text-muted-foreground mt-1">
                {summary.vendors.critical} critical, {summary.vendors.highRisk} high
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4 pb-3">
              <div className="flex items-center gap-2 mb-1">
                <FileText className="h-4 w-4 text-blue-500" />
                <span className="text-xs text-muted-foreground">Assessments</span>
              </div>
              <div className="text-2xl font-semibold">{summary.assessments.completed}</div>
              <div className="text-xs text-muted-foreground mt-1">
                {summary.assessments.pending} pending
                {summary.assessments.overdue > 0 && (
                  <span className="text-orange-500 ml-1">({summary.assessments.overdue} overdue)</span>
                )}
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4 pb-3">
              <div className="flex items-center gap-2 mb-1">
                <AlertTriangle className="h-4 w-4 text-orange-500" />
                <span className="text-xs text-muted-foreground">Active Risks</span>
              </div>
              <div className="text-2xl font-semibold">{summary.risks.open}</div>
              <div className="text-xs text-muted-foreground mt-1">
                {summary.risks.critical} critical, {summary.risks.high} high
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Main Tabs */}
      <Tabs defaultValue="inventory">
        <TabsList>
          <TabsTrigger value="inventory">Vendor Inventory</TabsTrigger>
          <TabsTrigger value="assessments">Assessments</TabsTrigger>
          <TabsTrigger value="monitoring">Monitoring</TabsTrigger>
          <TabsTrigger value="breaches">Breach Alerts</TabsTrigger>
          <TabsTrigger value="contracts">Contract Risk Map</TabsTrigger>
          <TabsTrigger value="fourth-party">Fourth-Party Risk</TabsTrigger>
        </TabsList>

        {/* ── Vendor Inventory Tab ──────────────────────────────────── */}
        <TabsContent value="inventory" className="space-y-4">
          <div className="flex items-center gap-2">
            <div className="relative flex-1">
              <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search vendors..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-8"
              />
            </div>
            <Select value={riskFilter} onValueChange={setRiskFilter}>
              <SelectTrigger className="w-[140px]">
                <SelectValue placeholder="Risk Tier" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Tiers</SelectItem>
                {RISK_TIERS.map((t) => (
                  <SelectItem key={t.value} value={t.value}>
                    {t.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={categoryFilter} onValueChange={setCategoryFilter}>
              <SelectTrigger className="w-[160px]">
                <SelectValue placeholder="Category" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Categories</SelectItem>
                {CATEGORIES.map((c) => (
                  <SelectItem key={c.value} value={c.value}>
                    {c.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="w-[160px]">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Statuses</SelectItem>
                <SelectItem value="active">Active</SelectItem>
                <SelectItem value="under_review">Under Review</SelectItem>
                <SelectItem value="probation">Probation</SelectItem>
                <SelectItem value="offboarded">Offboarded</SelectItem>
                <SelectItem value="pending_onboard">Pending Onboard</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {vendorsLoading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : vendorsList.length === 0 ? (
            <Card>
              <CardContent className="flex flex-col items-center justify-center py-12">
                <Building2 className="h-10 w-10 text-muted-foreground mb-3" />
                <p className="text-sm text-muted-foreground">No vendors found</p>
                <Button size="sm" className="mt-3" onClick={() => setAddVendorOpen(true)}>
                  <Plus className="h-4 w-4 mr-1" />
                  Add your first vendor
                </Button>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-2">
              {vendorsList.map((vendor) => (
                <Card
                  key={vendor.id}
                  className="cursor-pointer hover:bg-accent/50 transition-colors"
                  onClick={() => setSelectedVendor(vendor.id)}
                >
                  <CardContent className="flex items-center justify-between py-3 px-4">
                    <div className="flex items-center gap-3 min-w-0">
                      <div className="h-9 w-9 rounded-md bg-muted flex items-center justify-center shrink-0">
                        <Building2 className="h-4 w-4" />
                      </div>
                      <div className="min-w-0">
                        <div className="font-medium text-sm truncate">{vendor.name}</div>
                        <div className="flex items-center gap-2 mt-0.5">
                          {vendor.domain && (
                            <span className="text-xs text-muted-foreground flex items-center gap-1">
                              <Globe className="h-3 w-3" />
                              {vendor.domain}
                            </span>
                          )}
                          <span className="text-xs text-muted-foreground">
                            {CATEGORIES.find((c) => c.value === vendor.category)?.label || vendor.category}
                          </span>
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      {vendor.securityScore !== null && (
                        <span className="text-xs font-mono">{vendor.securityScore}/100</span>
                      )}
                      <Badge variant="outline" className={riskTierColor(vendor.riskTier)}>
                        {vendor.riskTier}
                      </Badge>
                      <Badge variant="outline" className={statusColor(vendor.status)}>
                        {vendor.status.replace(/_/g, " ")}
                      </Badge>
                      {vendor.nextReviewDate && new Date(vendor.nextReviewDate) < new Date() && (
                        <Badge variant="outline" className="bg-red-500/10 text-red-500">
                          <Clock className="h-3 w-3 mr-1" />
                          Overdue
                        </Badge>
                      )}
                      <ChevronRight className="h-4 w-4 text-muted-foreground" />
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>

        {/* ── Assessments Tab ──────────────────────────────────────── */}
        <TabsContent value="assessments" className="space-y-4">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="text-base">Security Questionnaires</CardTitle>
                  <CardDescription>CAIQ, SIG, and custom assessments sent to vendors</CardDescription>
                </div>
                <Dialog open={sendQuestionnaireOpen} onOpenChange={setSendQuestionnaireOpen}>
                  <DialogTrigger asChild>
                    <Button size="sm" variant="outline">
                      <FileText className="h-4 w-4 mr-1" />
                      Send Questionnaire
                    </Button>
                  </DialogTrigger>
                  <DialogContent className="max-w-lg">
                    <DialogHeader>
                      <DialogTitle>Send Security Questionnaire</DialogTitle>
                      <DialogDescription>Select a vendor and questionnaire type to send</DialogDescription>
                    </DialogHeader>
                    <SendQuestionnaireForm
                      vendors={vendorsList}
                      onSubmit={(data) => sendQuestionnaireMutation.mutate(data)}
                      isPending={sendQuestionnaireMutation.isPending}
                    />
                  </DialogContent>
                </Dialog>
              </div>
            </CardHeader>
            <CardContent>
              {summary && summary.assessments.total === 0 ? (
                <div className="text-center py-8 text-sm text-muted-foreground">
                  No assessments yet. Send a questionnaire to get started.
                </div>
              ) : (
                <div className="text-sm text-muted-foreground">
                  {summary?.assessments.total} total assessments
                  {summary && summary.assessments.pending > 0 && ` (${summary.assessments.pending} pending)`}
                  {summary && summary.assessments.overdue > 0 && (
                    <span className="text-orange-500 ml-1">({summary.assessments.overdue} overdue)</span>
                  )}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ── Monitoring Tab ───────────────────────────────────────── */}
        <TabsContent value="monitoring" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Card>
              <CardContent className="pt-4 pb-3">
                <div className="flex items-center gap-2 mb-1">
                  <Activity className="h-4 w-4 text-green-500" />
                  <span className="text-xs text-muted-foreground">Vendors Monitored</span>
                </div>
                <div className="text-2xl font-semibold">{monitoringStatus?.vendorsMonitored || 0}</div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-4 pb-3">
                <div className="flex items-center gap-2 mb-1">
                  <AlertTriangle className="h-4 w-4 text-red-500" />
                  <span className="text-xs text-muted-foreground">Active Alerts</span>
                </div>
                <div className="text-2xl font-semibold text-red-500">{monitoringStatus?.alertCount || 0}</div>
                <div className="text-xs text-muted-foreground mt-1">
                  {monitoringStatus?.unacknowledgedCount || 0} unacknowledged
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-4 pb-3">
                <div className="flex items-center gap-2 mb-1">
                  <Clock className="h-4 w-4 text-muted-foreground" />
                  <span className="text-xs text-muted-foreground">Last Check</span>
                </div>
                <div className="text-sm font-medium">
                  {monitoringStatus?.lastCheckAt ? formatDate(monitoringStatus.lastCheckAt) : "Never"}
                </div>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">Recent Monitoring Alerts</CardTitle>
              <CardDescription>Domain, SSL, HTTP, and security header checks</CardDescription>
            </CardHeader>
            <CardContent>
              {!monitoringStatus?.recentAlerts || monitoringStatus.recentAlerts.length === 0 ? (
                <div className="text-center py-8 text-sm text-muted-foreground">
                  No monitoring alerts. Run a monitoring sweep to check vendor attack surfaces.
                </div>
              ) : (
                <div className="space-y-2">
                  {monitoringStatus.recentAlerts.map((alert) => (
                    <div key={alert.id} className="flex items-center justify-between py-2 border-b last:border-0">
                      <div>
                        <div className="text-sm font-medium">{alert.checkType.replace(/_/g, " ")}</div>
                        <div className="text-xs text-muted-foreground">{alert.details}</div>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge variant="outline" className={severityColor(alert.severity)}>
                          {alert.severity}
                        </Badge>
                        <span className="text-xs text-muted-foreground">{formatDate(alert.checkedAt)}</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ── Breach Alerts Tab ────────────────────────────────────── */}
        <TabsContent value="breaches" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Vendor Breach Alerts</CardTitle>
              <CardDescription>Alerts when vendors in your supply chain are breached</CardDescription>
            </CardHeader>
            <CardContent>
              {!breachAlerts?.alerts || breachAlerts.alerts.length === 0 ? (
                <div className="text-center py-8 text-sm text-muted-foreground">
                  <ShieldAlert className="h-8 w-8 mx-auto mb-2 text-muted-foreground/50" />
                  No breach alerts. Vendor breach monitoring is active.
                </div>
              ) : (
                <div className="space-y-3">
                  {breachAlerts.alerts.map((alert) => (
                    <div key={alert.id} className="border rounded-md p-3">
                      <div className="flex items-start justify-between">
                        <div>
                          <div className="font-medium text-sm flex items-center gap-2">
                            <AlertTriangle className="h-4 w-4 text-red-500" />
                            {alert.title}
                          </div>
                          <div className="text-xs text-muted-foreground mt-1">{alert.description}</div>
                        </div>
                        <div className="flex items-center gap-2">
                          <Badge variant="outline" className={severityColor(alert.severity)}>
                            {alert.severity}
                          </Badge>
                          <Badge variant="outline">{alert.status}</Badge>
                        </div>
                      </div>
                      <div className="flex items-center gap-3 mt-2 text-xs text-muted-foreground">
                        <span>Source: {alert.source}</span>
                        <span>{formatDate(alert.createdAt)}</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ── Contract Risk Map Tab ────────────────────────────────── */}
        <TabsContent value="contracts" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Card>
              <CardContent className="pt-4 pb-3">
                <div className="text-xs text-muted-foreground mb-1">Total Contract Value</div>
                <div className="text-2xl font-semibold">
                  ${((contractRiskMap?.totalContractValue || 0) / 100).toLocaleString()}
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-4 pb-3">
                <div className="text-xs text-muted-foreground mb-1">By Access Level</div>
                <div className="space-y-1 mt-1">
                  {contractRiskMap &&
                    Object.entries(contractRiskMap.byAccessLevel).map(([level, cnt]) => (
                      <div key={level} className="flex justify-between text-xs">
                        <span>{level}</span>
                        <span className="font-mono">{cnt}</span>
                      </div>
                    ))}
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-4 pb-3">
                <div className="text-xs text-muted-foreground mb-1">By Category</div>
                <div className="space-y-1 mt-1">
                  {contractRiskMap &&
                    Object.entries(contractRiskMap.byCategory)
                      .slice(0, 5)
                      .map(([cat, cnt]) => (
                        <div key={cat} className="flex justify-between text-xs">
                          <span>{CATEGORIES.find((c) => c.value === cat)?.label || cat}</span>
                          <span className="font-mono">{cnt}</span>
                        </div>
                      ))}
                </div>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">Vendor Data Access Mapping</CardTitle>
              <CardDescription>Which vendors have access to what data</CardDescription>
            </CardHeader>
            <CardContent>
              {!contractRiskMap?.vendors || contractRiskMap.vendors.length === 0 ? (
                <div className="text-center py-8 text-sm text-muted-foreground">
                  No vendors with contract data. Add vendors and map their data access.
                </div>
              ) : (
                <div className="space-y-2">
                  {contractRiskMap.vendors.map((v) => (
                    <div key={v.id} className="flex items-center justify-between py-2 border-b last:border-0">
                      <div>
                        <div className="text-sm font-medium">{v.name}</div>
                        <div className="flex items-center gap-2 mt-0.5">
                          <span className="text-xs text-muted-foreground">{v.dataAccessLevel || "Not mapped"}</span>
                          {v.dataTypes && v.dataTypes.length > 0 && (
                            <span className="text-xs text-muted-foreground">— {v.dataTypes.join(", ")}</span>
                          )}
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge variant="outline" className={riskTierColor(v.riskTier)}>
                          {v.riskTier}
                        </Badge>
                        {v.contractValue && (
                          <span className="text-xs font-mono">${(v.contractValue / 100).toLocaleString()}</span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ── Fourth-Party Risk Tab ────────────────────────────────── */}
        <TabsContent value="fourth-party" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Card>
              <CardContent className="pt-4 pb-3">
                <div className="flex items-center gap-2 mb-1">
                  <Network className="h-4 w-4 text-muted-foreground" />
                  <span className="text-xs text-muted-foreground">Total 4th Parties</span>
                </div>
                <div className="text-2xl font-semibold">{fourthPartyData?.totalFourthParties || 0}</div>
                <div className="text-xs text-muted-foreground mt-1">
                  {fourthPartyData?.uniqueFourthParties || 0} unique
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-4 pb-3">
                <div className="flex items-center gap-2 mb-1">
                  <AlertTriangle className="h-4 w-4 text-orange-500" />
                  <span className="text-xs text-muted-foreground">High Risk 4th Parties</span>
                </div>
                <div className="text-2xl font-semibold text-orange-500">{fourthPartyData?.highRiskCount || 0}</div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-4 pb-3">
                <div className="flex items-center gap-2 mb-1">
                  <Users className="h-4 w-4 text-muted-foreground" />
                  <span className="text-xs text-muted-foreground">Vendors with Sub-vendors</span>
                </div>
                <div className="text-2xl font-semibold">{fourthPartyData?.byVendor?.length || 0}</div>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">Fourth-Party Vendor Map</CardTitle>
              <CardDescription>Who are your vendors{"'"} vendors?</CardDescription>
            </CardHeader>
            <CardContent>
              {!fourthPartyData?.byVendor || fourthPartyData.byVendor.length === 0 ? (
                <div className="text-center py-8 text-sm text-muted-foreground">
                  No fourth-party data. Update vendor records with their sub-vendors.
                </div>
              ) : (
                <div className="space-y-2">
                  {fourthPartyData.byVendor.map((v) => (
                    <div key={v.vendorId} className="flex items-center justify-between py-2 border-b last:border-0">
                      <div className="text-sm font-medium">{v.vendorName}</div>
                      <Badge variant="outline">{v.fourthPartyCount} sub-vendors</Badge>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* ── Vendor Detail Dialog ────────────────────────────────────── */}
      <Dialog open={!!selectedVendor} onOpenChange={(open) => !open && setSelectedVendor(null)}>
        <DialogContent className="max-w-3xl max-h-[80vh] overflow-y-auto">
          {vendorDetail && (
            <>
              <DialogHeader>
                <DialogTitle className="flex items-center gap-2">
                  <Building2 className="h-5 w-5" />
                  {vendorDetail.vendor.name}
                </DialogTitle>
                <DialogDescription>
                  {vendorDetail.vendor.domain && (
                    <a
                      href={vendorDetail.vendor.website || `https://${vendorDetail.vendor.domain}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-blue-500 hover:underline flex items-center gap-1"
                    >
                      {vendorDetail.vendor.domain}
                      <ExternalLink className="h-3 w-3" />
                    </a>
                  )}
                </DialogDescription>
              </DialogHeader>

              <div className="space-y-4">
                {/* Vendor metadata */}
                <div className="grid grid-cols-3 gap-3">
                  <div>
                    <div className="text-xs text-muted-foreground">Risk Tier</div>
                    <Badge variant="outline" className={riskTierColor(vendorDetail.vendor.riskTier)}>
                      {vendorDetail.vendor.riskTier}
                    </Badge>
                  </div>
                  <div>
                    <div className="text-xs text-muted-foreground">Status</div>
                    <Badge variant="outline" className={statusColor(vendorDetail.vendor.status)}>
                      {vendorDetail.vendor.status.replace(/_/g, " ")}
                    </Badge>
                  </div>
                  <div>
                    <div className="text-xs text-muted-foreground">Security Score</div>
                    <div className="text-sm font-mono">
                      {vendorDetail.vendor.securityScore !== null ? `${vendorDetail.vendor.securityScore}/100` : "—"}
                    </div>
                  </div>
                  <div>
                    <div className="text-xs text-muted-foreground">Category</div>
                    <div className="text-sm">
                      {CATEGORIES.find((c) => c.value === vendorDetail.vendor.category)?.label ||
                        vendorDetail.vendor.category}
                    </div>
                  </div>
                  <div>
                    <div className="text-xs text-muted-foreground">Review Cadence</div>
                    <div className="text-sm">{vendorDetail.vendor.reviewCadence.replace(/_/g, " ")}</div>
                  </div>
                  <div>
                    <div className="text-xs text-muted-foreground">Next Review</div>
                    <div className="text-sm">{formatDate(vendorDetail.vendor.nextReviewDate)}</div>
                  </div>
                </div>

                {/* Data access */}
                {vendorDetail.vendor.dataAccessLevel && (
                  <div>
                    <div className="text-xs text-muted-foreground mb-1">Data Access</div>
                    <div className="text-sm">
                      Level: {vendorDetail.vendor.dataAccessLevel}
                      {vendorDetail.vendor.dataTypes && vendorDetail.vendor.dataTypes.length > 0 && (
                        <span className="ml-2">— {vendorDetail.vendor.dataTypes.join(", ")}</span>
                      )}
                    </div>
                  </div>
                )}

                {/* Assessments */}
                <div>
                  <h4 className="text-sm font-medium mb-2">Assessments ({vendorDetail.assessments.length})</h4>
                  {vendorDetail.assessments.length === 0 ? (
                    <div className="text-xs text-muted-foreground">No assessments yet</div>
                  ) : (
                    <div className="space-y-1">
                      {vendorDetail.assessments.map((a) => (
                        <div
                          key={a.id}
                          className="flex items-center justify-between py-1.5 text-sm border-b last:border-0"
                        >
                          <div>
                            <span className="font-medium">{a.title}</span>
                            <span className="text-xs text-muted-foreground ml-2">{a.questionnaireType}</span>
                          </div>
                          <div className="flex items-center gap-2">
                            {a.score !== null && <span className="text-xs font-mono">{a.score}%</span>}
                            <Badge
                              variant="outline"
                              className={
                                a.status === "completed"
                                  ? "bg-green-500/10 text-green-500"
                                  : "bg-yellow-500/10 text-yellow-500"
                              }
                            >
                              {a.status}
                            </Badge>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Active Risks */}
                <div>
                  <h4 className="text-sm font-medium mb-2">Active Risks ({vendorDetail.risks.length})</h4>
                  {vendorDetail.risks.length === 0 ? (
                    <div className="text-xs text-muted-foreground">No active risks</div>
                  ) : (
                    <div className="space-y-1">
                      {vendorDetail.risks.map((r) => (
                        <div
                          key={r.id}
                          className="flex items-center justify-between py-1.5 text-sm border-b last:border-0"
                        >
                          <div>
                            <span className="font-medium">{r.title}</span>
                            <span className="text-xs text-muted-foreground ml-2">{r.category}</span>
                          </div>
                          <div className="flex items-center gap-2">
                            <Badge variant="outline" className={severityColor(r.severity)}>
                              {r.severity}
                            </Badge>
                            <Badge variant="outline">{r.status}</Badge>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Breach Alerts */}
                {vendorDetail.breachAlerts.length > 0 && (
                  <div>
                    <h4 className="text-sm font-medium mb-2 text-red-500">
                      Breach Alerts ({vendorDetail.breachAlerts.length})
                    </h4>
                    <div className="space-y-1">
                      {vendorDetail.breachAlerts.map((b) => (
                        <div
                          key={b.id}
                          className="flex items-center justify-between py-1.5 text-sm border-b last:border-0"
                        >
                          <div className="flex items-center gap-2">
                            <AlertTriangle className="h-3.5 w-3.5 text-red-500" />
                            <span className="font-medium">{b.title}</span>
                          </div>
                          <div className="flex items-center gap-2">
                            <Badge variant="outline" className={severityColor(b.severity)}>
                              {b.severity}
                            </Badge>
                            <span className="text-xs text-muted-foreground">{formatDate(b.createdAt)}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Recent Monitoring */}
                <div>
                  <h4 className="text-sm font-medium mb-2">
                    Recent Monitoring ({vendorDetail.monitoringEvents.length})
                  </h4>
                  {vendorDetail.monitoringEvents.length === 0 ? (
                    <div className="text-xs text-muted-foreground">No monitoring data yet</div>
                  ) : (
                    <div className="space-y-1">
                      {vendorDetail.monitoringEvents.slice(0, 5).map((m) => (
                        <div
                          key={m.id}
                          className="flex items-center justify-between py-1.5 text-sm border-b last:border-0"
                        >
                          <div className="flex items-center gap-2">
                            {m.status === "ok" ? (
                              <CheckCircle2 className="h-3.5 w-3.5 text-green-500" />
                            ) : m.status === "alert" ? (
                              <XCircle className="h-3.5 w-3.5 text-red-500" />
                            ) : (
                              <AlertTriangle className="h-3.5 w-3.5 text-yellow-500" />
                            )}
                            <span>{m.checkType.replace(/_/g, " ")}</span>
                          </div>
                          <span className="text-xs text-muted-foreground">{formatDate(m.checkedAt)}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}

// ── Add Vendor Form ───────────────────────────────────────────────

function AddVendorForm({
  onSubmit,
  isPending,
}: {
  onSubmit: (data: Record<string, unknown>) => void;
  isPending: boolean;
}) {
  const [name, setName] = useState("");
  const [domain, setDomain] = useState("");
  const [website, setWebsite] = useState("");
  const [category, setCategory] = useState("other");
  const [riskTier, setRiskTier] = useState("medium");
  const [description, setDescription] = useState("");
  const [dataAccessLevel, setDataAccessLevel] = useState("");

  return (
    <div className="space-y-3">
      <div>
        <Label>Vendor Name *</Label>
        <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Acme Corp" />
      </div>
      <div className="grid grid-cols-2 gap-3">
        <div>
          <Label>Domain</Label>
          <Input value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="acme.com" />
        </div>
        <div>
          <Label>Website</Label>
          <Input value={website} onChange={(e) => setWebsite(e.target.value)} placeholder="https://acme.com" />
        </div>
      </div>
      <div className="grid grid-cols-2 gap-3">
        <div>
          <Label>Category</Label>
          <Select value={category} onValueChange={setCategory}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {CATEGORIES.map((c) => (
                <SelectItem key={c.value} value={c.value}>
                  {c.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div>
          <Label>Initial Risk Tier</Label>
          <Select value={riskTier} onValueChange={setRiskTier}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {RISK_TIERS.map((t) => (
                <SelectItem key={t.value} value={t.value}>
                  {t.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>
      <div>
        <Label>Data Access Level</Label>
        <Select value={dataAccessLevel} onValueChange={setDataAccessLevel}>
          <SelectTrigger>
            <SelectValue placeholder="Select access level" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="none">None</SelectItem>
            <SelectItem value="metadata_only">Metadata Only</SelectItem>
            <SelectItem value="limited_pii">Limited PII</SelectItem>
            <SelectItem value="full_pii">Full PII</SelectItem>
            <SelectItem value="financial">Financial Data</SelectItem>
            <SelectItem value="credentials">Credentials/Secrets</SelectItem>
            <SelectItem value="full_access">Full Data Access</SelectItem>
          </SelectContent>
        </Select>
      </div>
      <div>
        <Label>Description</Label>
        <Textarea
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          placeholder="What does this vendor do for your organization?"
          rows={2}
        />
      </div>
      <DialogFooter>
        <Button
          onClick={() =>
            onSubmit({
              name,
              domain: domain || undefined,
              website: website || undefined,
              category,
              riskTier,
              description: description || undefined,
              dataAccessLevel: dataAccessLevel || undefined,
            })
          }
          disabled={!name.trim() || isPending}
        >
          {isPending ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <Plus className="h-4 w-4 mr-1" />}
          Add Vendor
        </Button>
      </DialogFooter>
    </div>
  );
}

// ── Send Questionnaire Form ───────────────────────────────────────

function SendQuestionnaireForm({
  vendors: vendorList,
  onSubmit,
  isPending,
}: {
  vendors: Vendor[];
  onSubmit: (data: Record<string, unknown>) => void;
  isPending: boolean;
}) {
  const [vendorId, setVendorId] = useState("");
  const [questionnaireType, setQuestionnaireType] = useState("caiq");
  const [title, setTitle] = useState("");
  const [respondentEmail, setRespondentEmail] = useState("");

  return (
    <div className="space-y-3">
      <div>
        <Label>Vendor *</Label>
        <Select value={vendorId} onValueChange={setVendorId}>
          <SelectTrigger>
            <SelectValue placeholder="Select vendor" />
          </SelectTrigger>
          <SelectContent>
            {vendorList.map((v) => (
              <SelectItem key={v.id} value={v.id}>
                {v.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <div>
        <Label>Questionnaire Type *</Label>
        <Select value={questionnaireType} onValueChange={setQuestionnaireType}>
          <SelectTrigger>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="caiq">CAIQ (Cloud Security Alliance)</SelectItem>
            <SelectItem value="sig_lite">SIG Lite</SelectItem>
            <SelectItem value="sig_full">SIG Full</SelectItem>
            <SelectItem value="custom">Custom</SelectItem>
            <SelectItem value="iso27001">ISO 27001</SelectItem>
            <SelectItem value="soc2">SOC 2</SelectItem>
            <SelectItem value="nist">NIST</SelectItem>
          </SelectContent>
        </Select>
      </div>
      <div>
        <Label>Assessment Title</Label>
        <Input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Q1 2026 Security Assessment" />
      </div>
      <div>
        <Label>Respondent Email</Label>
        <Input
          value={respondentEmail}
          onChange={(e) => setRespondentEmail(e.target.value)}
          placeholder="security@vendor.com"
        />
      </div>
      <DialogFooter>
        <Button
          onClick={() =>
            onSubmit({
              vendorId,
              questionnaireType,
              title: title || undefined,
              respondentEmail: respondentEmail || undefined,
            })
          }
          disabled={!vendorId || isPending}
        >
          {isPending ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <FileText className="h-4 w-4 mr-1" />}
          Send Questionnaire
        </Button>
      </DialogFooter>
    </div>
  );
}

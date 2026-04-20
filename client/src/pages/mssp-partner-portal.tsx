import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { useOrgContext } from "@/hooks/use-org-context";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
  DialogFooter,
  DialogClose,
} from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  Building2,
  Palette,
  Clock,
  AlertTriangle,
  DollarSign,
  FileCheck2,
  BarChart3,
  Plus,
  Check,
  RefreshCw,
  Shield,
  Trash2,
  Send,
  CheckCircle2,
  XCircle,
  ChevronRight,
  Globe,
  Mail,
  Paintbrush,
  Users,
  TrendingUp,
} from "lucide-react";

// ── Types ───────────────────────────────────────────────────────────

interface PortalStats {
  clientCount: number;
  activeSlas: number;
  activeBreaches: number;
  onboardingPending: number;
  onboardingCompleted: number;
  billingDraftInvoices: number;
  billingTotalRevenue: number;
  billingOverdueCount: number;
  whiteLabelConfigured: boolean;
  whiteLabelActive: boolean;
}

interface WhiteLabelConfig {
  id: string;
  orgId: string;
  customLogoUrl: string | null;
  customFaviconUrl: string | null;
  primaryColor: string;
  secondaryColor: string;
  accentColor: string;
  customDomain: string | null;
  customAppName: string | null;
  customSupportEmail: string | null;
  customSupportUrl: string | null;
  hidePoweredBy: boolean;
  customCss: string | null;
  isActive: boolean;
}

interface ClientSla {
  id: string;
  parentOrgId: string;
  childOrgId: string;
  name: string;
  priority: string;
  responseTimeMinutes: number;
  resolutionTimeMinutes: number;
  escalationContactEmail: string | null;
  escalationContactPhone: string | null;
  autoEscalateOnBreach: boolean;
  businessHoursOnly: boolean;
  businessHoursStart: string;
  businessHoursEnd: string;
  businessTimezone: string;
  isActive: boolean;
  createdAt: string;
}

interface SlaBreach {
  id: string;
  slaId: string;
  parentOrgId: string;
  childOrgId: string;
  incidentId: string | null;
  alertId: string | null;
  breachType: string;
  targetMinutes: number;
  actualMinutes: number;
  status: string;
  resolvedAt: string | null;
  resolvedBy: string | null;
  notes: string | null;
  createdAt: string;
}

interface BillingRecord {
  id: string;
  parentOrgId: string;
  childOrgId: string;
  periodStart: string;
  periodEnd: string;
  baseFee: number;
  markupPercent: number;
  alertsIngested: number;
  alertsCost: number;
  aiAnalyses: number;
  aiCost: number;
  storageGb: number;
  storageCost: number;
  userCount: number;
  userCost: number;
  subtotal: number;
  markupAmount: number;
  totalAmount: number;
  currency: string;
  status: string;
  createdAt: string;
}

interface OnboardingRecord {
  id: string;
  parentOrgId: string;
  childOrgId: string;
  status: string;
  steps: Array<{ key: string; label: string; done: boolean }>;
  assignedTo: string | null;
  targetGoLiveDate: string | null;
  actualGoLiveDate: string | null;
  notes: string | null;
  createdAt: string;
}

interface ChildOrg {
  id: string;
  name: string;
  slug: string;
  industry: string | null;
}

interface ReportData {
  parentOrgId: string;
  childCount: number;
  clients: Array<{
    orgId: string;
    orgName: string;
    orgSlug: string;
    industry: string | null;
    alertCount: number;
    criticalAlerts: number;
    openIncidents: number;
    connectorCount: number;
    activeSlaBreaches: number;
  }>;
  totals: {
    totalAlerts: number;
    criticalAlerts: number;
    openIncidents: number;
    totalConnectors: number;
    slaBreaches: number;
    revenue: number;
  };
}

// ── Helpers ──────────────────────────────────────────────────────────

function unwrap<T>(data: unknown): T {
  if (data && typeof data === "object" && "data" in data) {
    return (data as { data: T }).data;
  }
  return data as T;
}

function formatCurrency(cents: number): string {
  return `$${(cents / 100).toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
}

function formatMinutes(mins: number): string {
  if (mins < 60) return `${mins}m`;
  const h = Math.floor(mins / 60);
  const m = mins % 60;
  return m > 0 ? `${h}h ${m}m` : `${h}h`;
}

function StatCard({
  title,
  value,
  icon: Icon,
  variant = "default",
}: {
  title: string;
  value: string | number;
  icon: React.ComponentType<{ className?: string }>;
  variant?: "default" | "critical" | "warning" | "success";
}) {
  const colorMap = {
    default: "text-cyan-400",
    critical: "text-red-400",
    warning: "text-amber-400",
    success: "text-emerald-400",
  };
  return (
    <Card className="glass-subtle hover:glass-strong transition-all duration-200">
      <CardContent className="p-4">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-xs text-muted-foreground font-medium">{title}</p>
            <p className="text-2xl font-bold mt-1">{value}</p>
          </div>
          <div className={`p-2 rounded-lg bg-background/50 ${colorMap[variant]}`}>
            <Icon className="h-5 w-5" />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// ── Tab Components ──────────────────────────────────────────────────

type PortalTab = "overview" | "whitelabel" | "onboarding" | "sla" | "billing" | "reporting";

// ── White-Label Tab ─────────────────────────────────────────────────

function WhiteLabelTab() {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: configRaw, isLoading } = useQuery({
    queryKey: ["/api/mssp-portal/white-label"],
  });
  const config = unwrap<WhiteLabelConfig | null>(configRaw);

  const [formData, setFormData] = useState<Partial<WhiteLabelConfig>>({});

  const saveMutation = useMutation({
    mutationFn: async (data: Partial<WhiteLabelConfig>) => {
      await apiRequest("PUT", "/api/mssp-portal/white-label", data);
    },
    onSuccess: () => {
      toast({ title: "White-label configuration saved" });
      queryClient.invalidateQueries({ queryKey: ["/api/mssp-portal/white-label"] });
    },
    onError: (err: Error) => {
      toast({ title: "Failed to save", description: err.message, variant: "destructive" });
    },
  });

  const getValue = (key: keyof WhiteLabelConfig): string => {
    if (key in formData) return String(formData[key] || "");
    if (config && key in config) return String(config[key] || "");
    return "";
  };

  const setField = (key: keyof WhiteLabelConfig, value: string | boolean) => {
    setFormData((prev) => ({ ...prev, [key]: value }));
  };

  const handleSave = () => {
    saveMutation.mutate(formData);
  };

  if (isLoading) {
    return (
      <div className="space-y-4">
        {Array.from({ length: 3 }).map((_, i) => (
          <Skeleton key={`wl-skel-${i}`} className="h-24 w-full" />
        ))}
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Branding Colors */}
      <Card className="glass-subtle">
        <CardHeader className="pb-3">
          <CardTitle className="text-base flex items-center gap-2">
            <Paintbrush className="h-4 w-4 text-violet-400" />
            Brand Colors
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="space-y-1.5">
              <Label>Primary Color</Label>
              <div className="flex gap-2">
                <input
                  type="color"
                  value={getValue("primaryColor") || "#0ea5e9"}
                  onChange={(e) => setField("primaryColor", e.target.value)}
                  className="h-9 w-12 rounded border border-border cursor-pointer"
                />
                <Input
                  value={getValue("primaryColor") || "#0ea5e9"}
                  onChange={(e) => setField("primaryColor", e.target.value)}
                  placeholder="#0ea5e9"
                  maxLength={7}
                  className="font-mono"
                />
              </div>
            </div>
            <div className="space-y-1.5">
              <Label>Secondary Color</Label>
              <div className="flex gap-2">
                <input
                  type="color"
                  value={getValue("secondaryColor") || "#6366f1"}
                  onChange={(e) => setField("secondaryColor", e.target.value)}
                  className="h-9 w-12 rounded border border-border cursor-pointer"
                />
                <Input
                  value={getValue("secondaryColor") || "#6366f1"}
                  onChange={(e) => setField("secondaryColor", e.target.value)}
                  placeholder="#6366f1"
                  maxLength={7}
                  className="font-mono"
                />
              </div>
            </div>
            <div className="space-y-1.5">
              <Label>Accent Color</Label>
              <div className="flex gap-2">
                <input
                  type="color"
                  value={getValue("accentColor") || "#10b981"}
                  onChange={(e) => setField("accentColor", e.target.value)}
                  className="h-9 w-12 rounded border border-border cursor-pointer"
                />
                <Input
                  value={getValue("accentColor") || "#10b981"}
                  onChange={(e) => setField("accentColor", e.target.value)}
                  placeholder="#10b981"
                  maxLength={7}
                  className="font-mono"
                />
              </div>
            </div>
          </div>
          {/* Color preview */}
          <div className="flex gap-3 pt-2">
            <div className="h-8 flex-1 rounded" style={{ backgroundColor: getValue("primaryColor") || "#0ea5e9" }} />
            <div className="h-8 flex-1 rounded" style={{ backgroundColor: getValue("secondaryColor") || "#6366f1" }} />
            <div className="h-8 flex-1 rounded" style={{ backgroundColor: getValue("accentColor") || "#10b981" }} />
          </div>
        </CardContent>
      </Card>

      {/* Logo & Domain */}
      <Card className="glass-subtle">
        <CardHeader className="pb-3">
          <CardTitle className="text-base flex items-center gap-2">
            <Globe className="h-4 w-4 text-cyan-400" />
            Logo, Domain & Identity
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-1.5">
              <Label>Custom Logo URL</Label>
              <Input
                value={getValue("customLogoUrl")}
                onChange={(e) => setField("customLogoUrl", e.target.value)}
                placeholder="https://cdn.example.com/logo.svg"
                maxLength={2000}
              />
            </div>
            <div className="space-y-1.5">
              <Label>Custom Favicon URL</Label>
              <Input
                value={getValue("customFaviconUrl")}
                onChange={(e) => setField("customFaviconUrl", e.target.value)}
                placeholder="https://cdn.example.com/favicon.ico"
                maxLength={2000}
              />
            </div>
            <div className="space-y-1.5">
              <Label>Custom App Name</Label>
              <Input
                value={getValue("customAppName")}
                onChange={(e) => setField("customAppName", e.target.value)}
                placeholder="YourBrand Security"
                maxLength={100}
              />
            </div>
            <div className="space-y-1.5">
              <Label>Custom Domain</Label>
              <Input
                value={getValue("customDomain")}
                onChange={(e) => setField("customDomain", e.target.value)}
                placeholder="security.yourbrand.com"
                maxLength={255}
              />
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Support & Customization */}
      <Card className="glass-subtle">
        <CardHeader className="pb-3">
          <CardTitle className="text-base flex items-center gap-2">
            <Mail className="h-4 w-4 text-emerald-400" />
            Support & Customization
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-1.5">
              <Label>Support Email</Label>
              <Input
                type="email"
                value={getValue("customSupportEmail")}
                onChange={(e) => setField("customSupportEmail", e.target.value)}
                placeholder="support@yourbrand.com"
                maxLength={255}
              />
            </div>
            <div className="space-y-1.5">
              <Label>Support URL</Label>
              <Input
                value={getValue("customSupportUrl")}
                onChange={(e) => setField("customSupportUrl", e.target.value)}
                placeholder="https://support.yourbrand.com"
                maxLength={2000}
              />
            </div>
          </div>
          <div className="flex items-center gap-3 pt-2">
            <input
              type="checkbox"
              id="hide-powered-by"
              checked={"hidePoweredBy" in formData ? !!formData.hidePoweredBy : config?.hidePoweredBy || false}
              onChange={(e) => setField("hidePoweredBy", e.target.checked)}
              className="h-4 w-4 rounded border-border"
            />
            <Label htmlFor="hide-powered-by" className="text-sm cursor-pointer">
              Hide &ldquo;Powered by SecureNexus&rdquo; branding
            </Label>
          </div>
          <div className="space-y-1.5">
            <Label>Custom CSS (advanced)</Label>
            <Textarea
              value={getValue("customCss")}
              onChange={(e) => setField("customCss", e.target.value)}
              placeholder=":root { --primary: #0ea5e9; }"
              rows={4}
              className="font-mono text-xs"
            />
          </div>
        </CardContent>
      </Card>

      <div className="flex justify-end">
        <Button onClick={handleSave} disabled={saveMutation.isPending || Object.keys(formData).length === 0}>
          {saveMutation.isPending ? "Saving..." : "Save White-Label Config"}
        </Button>
      </div>
    </div>
  );
}

// ── Onboarding Tab ──────────────────────────────────────────────────

function OnboardingTab({ children: childOrgs }: { children: ChildOrg[] }) {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: onboardingRaw, isLoading } = useQuery({
    queryKey: ["/api/mssp-portal/onboarding"],
  });
  const records = unwrap<OnboardingRecord[]>(onboardingRaw) || [];

  const [createOpen, setCreateOpen] = useState(false);
  const [selectedChild, setSelectedChild] = useState("");
  const [assignedTo, setAssignedTo] = useState("");
  const [targetDate, setTargetDate] = useState("");

  const createMutation = useMutation({
    mutationFn: async () => {
      await apiRequest("POST", "/api/mssp-portal/onboarding", {
        childOrgId: selectedChild,
        assignedTo: assignedTo || undefined,
        targetGoLiveDate: targetDate || undefined,
      });
    },
    onSuccess: () => {
      toast({ title: "Onboarding record created" });
      setCreateOpen(false);
      setSelectedChild("");
      setAssignedTo("");
      setTargetDate("");
      queryClient.invalidateQueries({ queryKey: ["/api/mssp-portal/onboarding"] });
    },
    onError: (err: Error) => {
      toast({ title: "Failed to create", description: err.message, variant: "destructive" });
    },
  });

  const stepMutation = useMutation({
    mutationFn: async ({ recordId, key, done }: { recordId: string; key: string; done: boolean }) => {
      await apiRequest("PATCH", `/api/mssp-portal/onboarding/${recordId}/steps`, { key, done });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/mssp-portal/onboarding"] });
    },
    onError: (err: Error) => {
      toast({ title: "Failed to update step", description: err.message, variant: "destructive" });
    },
  });

  const getOrgName = (orgId: string) => {
    const org = childOrgs.find((c) => c.id === orgId);
    return org?.name || orgId;
  };

  if (isLoading) {
    return (
      <div className="space-y-4">
        {Array.from({ length: 3 }).map((_, i) => (
          <Skeleton key={`ob-skel-${i}`} className="h-32 w-full" />
        ))}
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">
          Track onboarding progress for each client organization. Complete all steps for rapid go-live.
        </p>
        <Dialog open={createOpen} onOpenChange={setCreateOpen}>
          <DialogTrigger asChild>
            <Button size="sm" className="gap-1.5">
              <Plus className="h-4 w-4" />
              New Onboarding
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Start Client Onboarding</DialogTitle>
            </DialogHeader>
            <div className="space-y-4 py-2">
              <div className="space-y-1.5">
                <Label>Client Organization</Label>
                <Select value={selectedChild} onValueChange={setSelectedChild}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select client org" />
                  </SelectTrigger>
                  <SelectContent>
                    {childOrgs.map((org) => (
                      <SelectItem key={org.id} value={org.id}>
                        {org.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label>Assigned To (optional)</Label>
                <Input
                  value={assignedTo}
                  onChange={(e) => setAssignedTo(e.target.value)}
                  placeholder="engineer@yourbrand.com"
                  maxLength={255}
                />
              </div>
              <div className="space-y-1.5">
                <Label>Target Go-Live Date (optional)</Label>
                <Input type="date" value={targetDate} onChange={(e) => setTargetDate(e.target.value)} />
              </div>
            </div>
            <DialogFooter>
              <DialogClose asChild>
                <Button variant="outline">Cancel</Button>
              </DialogClose>
              <Button onClick={() => createMutation.mutate()} disabled={!selectedChild || createMutation.isPending}>
                {createMutation.isPending ? "Creating..." : "Start Onboarding"}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {records.length === 0 ? (
        <Card className="glass-subtle">
          <CardContent className="p-8 text-center text-sm text-muted-foreground">
            <FileCheck2 className="h-12 w-12 mx-auto mb-4 text-muted-foreground/50" />
            <p>No onboarding records yet. Start onboarding a client organization.</p>
          </CardContent>
        </Card>
      ) : (
        records.map((record) => {
          const steps = record.steps || [];
          const completedSteps = steps.filter((s) => s.done).length;
          const progress = steps.length > 0 ? Math.round((completedSteps / steps.length) * 100) : 0;

          return (
            <Card key={record.id} className="glass-subtle">
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-base">{getOrgName(record.childOrgId)}</CardTitle>
                  <Badge
                    variant="outline"
                    className={
                      record.status === "completed"
                        ? "text-emerald-400 border-emerald-400/30"
                        : record.status === "in_progress"
                          ? "text-cyan-400 border-cyan-400/30"
                          : "text-amber-400 border-amber-400/30"
                    }
                  >
                    {record.status === "completed"
                      ? "Go Live"
                      : record.status === "in_progress"
                        ? "In Progress"
                        : "Pending"}
                  </Badge>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                {/* Progress bar */}
                <div>
                  <div className="flex items-center justify-between text-xs text-muted-foreground mb-1">
                    <span>
                      {completedSteps} of {steps.length} steps
                    </span>
                    <span>{progress}%</span>
                  </div>
                  <div className="h-2 rounded-full bg-muted overflow-hidden">
                    <div
                      className="h-full rounded-full bg-cyan-500 transition-all duration-500"
                      style={{ width: `${progress}%` }}
                    />
                  </div>
                </div>

                {/* Steps */}
                <div className="space-y-2">
                  {steps.map((step) => (
                    <div
                      key={step.key}
                      className="flex items-center gap-3 p-2 rounded-md hover:bg-muted/30 transition-colors cursor-pointer"
                      onClick={() => stepMutation.mutate({ recordId: record.id, key: step.key, done: !step.done })}
                    >
                      <div
                        className={`h-5 w-5 rounded-full border-2 flex items-center justify-center transition-colors ${
                          step.done ? "bg-emerald-500 border-emerald-500" : "border-muted-foreground/40"
                        }`}
                      >
                        {step.done && <Check className="h-3 w-3 text-white" />}
                      </div>
                      <span
                        className={`text-sm ${step.done ? "text-muted-foreground line-through" : "text-foreground"}`}
                      >
                        {step.label}
                      </span>
                    </div>
                  ))}
                </div>

                {record.assignedTo && (
                  <p className="text-xs text-muted-foreground">
                    Assigned to: <span className="text-foreground">{record.assignedTo}</span>
                  </p>
                )}
                {record.targetGoLiveDate && (
                  <p className="text-xs text-muted-foreground">
                    Target go-live:{" "}
                    <span className="text-foreground">{new Date(record.targetGoLiveDate).toLocaleDateString()}</span>
                  </p>
                )}
              </CardContent>
            </Card>
          );
        })
      )}
    </div>
  );
}

// ── SLA Management Tab ──────────────────────────────────────────────

function SlaTab({ children: childOrgs }: { children: ChildOrg[] }) {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: slasRaw, isLoading } = useQuery({ queryKey: ["/api/mssp-portal/slas"] });
  const slas = unwrap<ClientSla[]>(slasRaw) || [];

  const { data: breachesRaw } = useQuery({ queryKey: ["/api/mssp-portal/sla-breaches"] });
  const breaches = unwrap<SlaBreach[]>(breachesRaw) || [];

  const [createOpen, setCreateOpen] = useState(false);
  const [slaForm, setSlaForm] = useState({
    childOrgId: "",
    name: "",
    priority: "medium" as string,
    responseTimeMinutes: 60,
    resolutionTimeMinutes: 480,
    escalationContactEmail: "",
    autoEscalateOnBreach: true,
  });

  const createSla = useMutation({
    mutationFn: async () => {
      await apiRequest("POST", "/api/mssp-portal/slas", {
        ...slaForm,
        escalationContactEmail: slaForm.escalationContactEmail || undefined,
      });
    },
    onSuccess: () => {
      toast({ title: "SLA policy created" });
      setCreateOpen(false);
      setSlaForm({
        childOrgId: "",
        name: "",
        priority: "medium",
        responseTimeMinutes: 60,
        resolutionTimeMinutes: 480,
        escalationContactEmail: "",
        autoEscalateOnBreach: true,
      });
      queryClient.invalidateQueries({ queryKey: ["/api/mssp-portal/slas"] });
    },
    onError: (err: Error) => {
      toast({ title: "Failed to create SLA", description: err.message, variant: "destructive" });
    },
  });

  const deleteSla = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("DELETE", `/api/mssp-portal/slas/${id}`);
    },
    onSuccess: () => {
      toast({ title: "SLA deleted" });
      queryClient.invalidateQueries({ queryKey: ["/api/mssp-portal/slas"] });
    },
    onError: (err: Error) => {
      toast({ title: "Failed to delete SLA", description: err.message, variant: "destructive" });
    },
  });

  const resolveBreach = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("PATCH", `/api/mssp-portal/sla-breaches/${id}/resolve`, {
        notes: "Resolved from partner portal",
      });
    },
    onSuccess: () => {
      toast({ title: "Breach resolved" });
      queryClient.invalidateQueries({ queryKey: ["/api/mssp-portal/sla-breaches"] });
    },
    onError: (err: Error) => {
      toast({ title: "Failed to resolve", description: err.message, variant: "destructive" });
    },
  });

  const getOrgName = (orgId: string) => {
    const org = childOrgs.find((c) => c.id === orgId);
    return org?.name || orgId;
  };

  const priorityColors: Record<string, string> = {
    critical: "text-red-400 border-red-400/30",
    high: "text-orange-400 border-orange-400/30",
    medium: "text-amber-400 border-amber-400/30",
    low: "text-emerald-400 border-emerald-400/30",
  };

  if (isLoading) {
    return (
      <div className="space-y-4">
        {Array.from({ length: 3 }).map((_, i) => (
          <Skeleton key={`sla-skel-${i}`} className="h-24 w-full" />
        ))}
      </div>
    );
  }

  const activeBreaches = breaches.filter((b) => b.status === "breached");

  return (
    <div className="space-y-6">
      {/* Active Breaches */}
      {activeBreaches.length > 0 && (
        <Card className="glass-subtle border-red-500/30">
          <CardHeader className="pb-3">
            <CardTitle className="text-base flex items-center gap-2 text-red-400">
              <AlertTriangle className="h-4 w-4" />
              Active SLA Breaches ({activeBreaches.length})
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {activeBreaches.map((breach) => (
                <div
                  key={breach.id}
                  className="flex items-center justify-between p-3 rounded-md bg-red-500/5 border border-red-500/20"
                >
                  <div>
                    <p className="text-sm font-medium">{getOrgName(breach.childOrgId)}</p>
                    <p className="text-xs text-muted-foreground">
                      {breach.breachType === "response" ? "Response time" : "Resolution time"} breach — Target:{" "}
                      {formatMinutes(breach.targetMinutes)}, Actual: {formatMinutes(breach.actualMinutes)}
                    </p>
                    {breach.incidentId && (
                      <p className="text-xs text-muted-foreground mt-0.5">Incident: {breach.incidentId}</p>
                    )}
                  </div>
                  <Button
                    size="sm"
                    variant="outline"
                    className="text-red-400 border-red-400/30 hover:bg-red-500/10"
                    onClick={() => resolveBreach.mutate(breach.id)}
                    disabled={resolveBreach.isPending}
                  >
                    <CheckCircle2 className="h-3.5 w-3.5 mr-1" />
                    Resolve
                  </Button>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* SLA Policies */}
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-medium text-muted-foreground">SLA Policies ({slas.length})</h3>
        <Dialog open={createOpen} onOpenChange={setCreateOpen}>
          <DialogTrigger asChild>
            <Button size="sm" className="gap-1.5">
              <Plus className="h-4 w-4" />
              New SLA Policy
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-lg">
            <DialogHeader>
              <DialogTitle>Create SLA Policy</DialogTitle>
            </DialogHeader>
            <div className="space-y-4 py-2">
              <div className="space-y-1.5">
                <Label>Client Organization</Label>
                <Select value={slaForm.childOrgId} onValueChange={(v) => setSlaForm((p) => ({ ...p, childOrgId: v }))}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select client" />
                  </SelectTrigger>
                  <SelectContent>
                    {childOrgs.map((org) => (
                      <SelectItem key={org.id} value={org.id}>
                        {org.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label>SLA Name</Label>
                <Input
                  value={slaForm.name}
                  onChange={(e) => setSlaForm((p) => ({ ...p, name: e.target.value }))}
                  placeholder="Standard Support SLA"
                  maxLength={200}
                />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <Label>Priority</Label>
                  <Select value={slaForm.priority} onValueChange={(v) => setSlaForm((p) => ({ ...p, priority: v }))}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="critical">Critical</SelectItem>
                      <SelectItem value="high">High</SelectItem>
                      <SelectItem value="medium">Medium</SelectItem>
                      <SelectItem value="low">Low</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-1.5">
                  <Label>Response Time (minutes)</Label>
                  <Input
                    type="number"
                    value={slaForm.responseTimeMinutes}
                    onChange={(e) => setSlaForm((p) => ({ ...p, responseTimeMinutes: parseInt(e.target.value) || 60 }))}
                    min={1}
                    max={43200}
                  />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <Label>Resolution Time (minutes)</Label>
                  <Input
                    type="number"
                    value={slaForm.resolutionTimeMinutes}
                    onChange={(e) =>
                      setSlaForm((p) => ({ ...p, resolutionTimeMinutes: parseInt(e.target.value) || 480 }))
                    }
                    min={1}
                    max={43200}
                  />
                </div>
                <div className="space-y-1.5">
                  <Label>Escalation Email</Label>
                  <Input
                    type="email"
                    value={slaForm.escalationContactEmail}
                    onChange={(e) => setSlaForm((p) => ({ ...p, escalationContactEmail: e.target.value }))}
                    placeholder="escalation@yourbrand.com"
                    maxLength={255}
                  />
                </div>
              </div>
              <div className="flex items-center gap-3">
                <input
                  type="checkbox"
                  id="auto-escalate"
                  checked={slaForm.autoEscalateOnBreach}
                  onChange={(e) => setSlaForm((p) => ({ ...p, autoEscalateOnBreach: e.target.checked }))}
                  className="h-4 w-4 rounded border-border"
                />
                <Label htmlFor="auto-escalate" className="text-sm cursor-pointer">
                  Auto-escalate on breach
                </Label>
              </div>
            </div>
            <DialogFooter>
              <DialogClose asChild>
                <Button variant="outline">Cancel</Button>
              </DialogClose>
              <Button
                onClick={() => createSla.mutate()}
                disabled={!slaForm.childOrgId || !slaForm.name.trim() || createSla.isPending}
              >
                {createSla.isPending ? "Creating..." : "Create SLA"}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {slas.length === 0 ? (
        <Card className="glass-subtle">
          <CardContent className="p-8 text-center text-sm text-muted-foreground">
            <Shield className="h-12 w-12 mx-auto mb-4 text-muted-foreground/50" />
            <p>No SLA policies defined yet. Create one to set response time expectations.</p>
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {slas.map((sla) => (
            <Card key={sla.id} className="glass-subtle">
              <CardContent className="p-4">
                <div className="flex items-start justify-between">
                  <div>
                    <h4 className="font-medium text-sm">{sla.name}</h4>
                    <p className="text-xs text-muted-foreground mt-0.5">{getOrgName(sla.childOrgId)}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant="outline" className={priorityColors[sla.priority] || ""}>
                      {sla.priority}
                    </Badge>
                    <Button
                      size="icon"
                      variant="ghost"
                      className="h-7 w-7 text-muted-foreground hover:text-red-400"
                      onClick={() => deleteSla.mutate(sla.id)}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-3 mt-3">
                  <div className="text-xs">
                    <span className="text-muted-foreground">Response: </span>
                    <span className="font-medium">{formatMinutes(sla.responseTimeMinutes)}</span>
                  </div>
                  <div className="text-xs">
                    <span className="text-muted-foreground">Resolution: </span>
                    <span className="font-medium">{formatMinutes(sla.resolutionTimeMinutes)}</span>
                  </div>
                </div>
                {sla.autoEscalateOnBreach && (
                  <p className="text-[10px] text-amber-400 mt-2">Auto-escalation enabled on breach</p>
                )}
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Billing Tab ─────────────────────────────────────────────────────

function BillingTab({ children: childOrgs }: { children: ChildOrg[] }) {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: billingRaw, isLoading } = useQuery({ queryKey: ["/api/mssp-portal/billing"] });
  const records = unwrap<BillingRecord[]>(billingRaw) || [];

  const [generateOpen, setGenerateOpen] = useState(false);
  const [billForm, setBillForm] = useState({
    childOrgId: "",
    periodStart: "",
    periodEnd: "",
    baseFee: 0,
    markupPercent: 20,
  });

  const generateBilling = useMutation({
    mutationFn: async () => {
      await apiRequest("POST", "/api/mssp-portal/billing/generate", {
        childOrgId: billForm.childOrgId,
        periodStart: new Date(billForm.periodStart).toISOString(),
        periodEnd: new Date(billForm.periodEnd).toISOString(),
        baseFee: Math.round(billForm.baseFee * 100),
        markupPercent: billForm.markupPercent,
      });
    },
    onSuccess: () => {
      toast({ title: "Billing record generated" });
      setGenerateOpen(false);
      queryClient.invalidateQueries({ queryKey: ["/api/mssp-portal/billing"] });
      queryClient.invalidateQueries({ queryKey: ["/api/mssp-portal/stats"] });
    },
    onError: (err: Error) => {
      toast({ title: "Failed to generate billing", description: err.message, variant: "destructive" });
    },
  });

  const updateStatus = useMutation({
    mutationFn: async ({ id, status }: { id: string; status: string }) => {
      await apiRequest("PATCH", `/api/mssp-portal/billing/${id}/status`, { status });
    },
    onSuccess: () => {
      toast({ title: "Billing status updated" });
      queryClient.invalidateQueries({ queryKey: ["/api/mssp-portal/billing"] });
      queryClient.invalidateQueries({ queryKey: ["/api/mssp-portal/stats"] });
    },
    onError: (err: Error) => {
      toast({ title: "Failed to update status", description: err.message, variant: "destructive" });
    },
  });

  const getOrgName = (orgId: string) => {
    const org = childOrgs.find((c) => c.id === orgId);
    return org?.name || orgId;
  };

  const statusColors: Record<string, string> = {
    draft: "text-muted-foreground border-muted-foreground/30",
    sent: "text-cyan-400 border-cyan-400/30",
    paid: "text-emerald-400 border-emerald-400/30",
    overdue: "text-red-400 border-red-400/30",
    cancelled: "text-muted-foreground/50 border-muted-foreground/20",
  };

  if (isLoading) {
    return (
      <div className="space-y-4">
        {Array.from({ length: 3 }).map((_, i) => (
          <Skeleton key={`bill-skel-${i}`} className="h-24 w-full" />
        ))}
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">
          Generate invoices with usage-based billing and configurable markup.
        </p>
        <Dialog open={generateOpen} onOpenChange={setGenerateOpen}>
          <DialogTrigger asChild>
            <Button size="sm" className="gap-1.5">
              <DollarSign className="h-4 w-4" />
              Generate Invoice
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Generate Client Invoice</DialogTitle>
            </DialogHeader>
            <div className="space-y-4 py-2">
              <div className="space-y-1.5">
                <Label>Client Organization</Label>
                <Select
                  value={billForm.childOrgId}
                  onValueChange={(v) => setBillForm((p) => ({ ...p, childOrgId: v }))}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Select client" />
                  </SelectTrigger>
                  <SelectContent>
                    {childOrgs.map((org) => (
                      <SelectItem key={org.id} value={org.id}>
                        {org.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <Label>Period Start</Label>
                  <Input
                    type="date"
                    value={billForm.periodStart}
                    onChange={(e) => setBillForm((p) => ({ ...p, periodStart: e.target.value }))}
                  />
                </div>
                <div className="space-y-1.5">
                  <Label>Period End</Label>
                  <Input
                    type="date"
                    value={billForm.periodEnd}
                    onChange={(e) => setBillForm((p) => ({ ...p, periodEnd: e.target.value }))}
                  />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <Label>Base Fee ($)</Label>
                  <Input
                    type="number"
                    value={billForm.baseFee}
                    onChange={(e) => setBillForm((p) => ({ ...p, baseFee: parseFloat(e.target.value) || 0 }))}
                    min={0}
                    step={0.01}
                  />
                </div>
                <div className="space-y-1.5">
                  <Label>Markup %</Label>
                  <Input
                    type="number"
                    value={billForm.markupPercent}
                    onChange={(e) => setBillForm((p) => ({ ...p, markupPercent: parseFloat(e.target.value) || 0 }))}
                    min={0}
                    max={100}
                    step={0.1}
                  />
                </div>
              </div>
              <p className="text-xs text-muted-foreground">
                Usage (alerts ingested, users, AI analyses, storage) is calculated automatically from the client&apos;s
                actual data.
              </p>
            </div>
            <DialogFooter>
              <DialogClose asChild>
                <Button variant="outline">Cancel</Button>
              </DialogClose>
              <Button
                onClick={() => generateBilling.mutate()}
                disabled={
                  !billForm.childOrgId || !billForm.periodStart || !billForm.periodEnd || generateBilling.isPending
                }
              >
                {generateBilling.isPending ? "Generating..." : "Generate Invoice"}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {records.length === 0 ? (
        <Card className="glass-subtle">
          <CardContent className="p-8 text-center text-sm text-muted-foreground">
            <DollarSign className="h-12 w-12 mx-auto mb-4 text-muted-foreground/50" />
            <p>No billing records yet. Generate an invoice for a client.</p>
          </CardContent>
        </Card>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm" role="table">
            <thead>
              <tr className="border-b border-border/50 text-muted-foreground">
                <th className="text-left py-2 px-3 font-medium">Client</th>
                <th className="text-left py-2 px-3 font-medium">Period</th>
                <th className="text-right py-2 px-3 font-medium">Alerts</th>
                <th className="text-right py-2 px-3 font-medium">Users</th>
                <th className="text-right py-2 px-3 font-medium">Subtotal</th>
                <th className="text-right py-2 px-3 font-medium">Markup</th>
                <th className="text-right py-2 px-3 font-medium">Total</th>
                <th className="text-center py-2 px-3 font-medium">Status</th>
                <th className="text-right py-2 px-3 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {records.map((record) => (
                <tr key={record.id} className="border-b border-border/30 hover:bg-muted/30 transition-colors">
                  <td className="py-2.5 px-3 font-medium">{getOrgName(record.childOrgId)}</td>
                  <td className="py-2.5 px-3 text-xs text-muted-foreground">
                    {new Date(record.periodStart).toLocaleDateString()} –{" "}
                    {new Date(record.periodEnd).toLocaleDateString()}
                  </td>
                  <td className="py-2.5 px-3 text-right">{record.alertsIngested.toLocaleString()}</td>
                  <td className="py-2.5 px-3 text-right">{record.userCount}</td>
                  <td className="py-2.5 px-3 text-right">{formatCurrency(record.subtotal)}</td>
                  <td className="py-2.5 px-3 text-right text-emerald-400">
                    +{record.markupPercent}% ({formatCurrency(record.markupAmount)})
                  </td>
                  <td className="py-2.5 px-3 text-right font-medium">{formatCurrency(record.totalAmount)}</td>
                  <td className="py-2.5 px-3 text-center">
                    <Badge variant="outline" className={statusColors[record.status] || ""}>
                      {record.status}
                    </Badge>
                  </td>
                  <td className="py-2.5 px-3 text-right">
                    <div className="flex items-center justify-end gap-1">
                      {record.status === "draft" && (
                        <Button
                          size="icon"
                          variant="ghost"
                          className="h-7 w-7"
                          title="Send invoice"
                          onClick={() => updateStatus.mutate({ id: record.id, status: "sent" })}
                        >
                          <Send className="h-3.5 w-3.5" />
                        </Button>
                      )}
                      {(record.status === "sent" || record.status === "overdue") && (
                        <Button
                          size="icon"
                          variant="ghost"
                          className="h-7 w-7 text-emerald-400"
                          title="Mark as paid"
                          onClick={() => updateStatus.mutate({ id: record.id, status: "paid" })}
                        >
                          <CheckCircle2 className="h-3.5 w-3.5" />
                        </Button>
                      )}
                      {record.status !== "paid" && record.status !== "cancelled" && (
                        <Button
                          size="icon"
                          variant="ghost"
                          className="h-7 w-7 text-red-400"
                          title="Cancel"
                          onClick={() => updateStatus.mutate({ id: record.id, status: "cancelled" })}
                        >
                          <XCircle className="h-3.5 w-3.5" />
                        </Button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ── Reporting Tab ───────────────────────────────────────────────────

function ReportingTab() {
  const { data: reportRaw, isLoading } = useQuery({ queryKey: ["/api/mssp-portal/report"] });
  const report = unwrap<ReportData | null>(reportRaw);

  if (isLoading) {
    return (
      <div className="space-y-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={`rpt-skel-${i}`} className="h-24 w-full" />
        ))}
      </div>
    );
  }

  if (!report || report.childCount === 0) {
    return (
      <Card className="glass-subtle">
        <CardContent className="p-8 text-center text-sm text-muted-foreground">
          <BarChart3 className="h-12 w-12 mx-auto mb-4 text-muted-foreground/50" />
          <p>No client data available for reporting. Add client organizations first.</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      {/* Totals */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        <StatCard title="Client Orgs" value={report.childCount} icon={Building2} />
        <StatCard
          title="Total Alerts"
          value={report.totals.totalAlerts.toLocaleString()}
          icon={AlertTriangle}
          variant="warning"
        />
        <StatCard title="Critical Alerts" value={report.totals.criticalAlerts} icon={Shield} variant="critical" />
        <StatCard title="Open Incidents" value={report.totals.openIncidents} icon={Clock} variant="warning" />
        <StatCard title="SLA Breaches" value={report.totals.slaBreaches} icon={XCircle} variant="critical" />
        <StatCard
          title="Total Revenue"
          value={formatCurrency(report.totals.revenue)}
          icon={TrendingUp}
          variant="success"
        />
      </div>

      {/* Per-Client Breakdown */}
      <Card className="glass-subtle">
        <CardHeader className="pb-3">
          <CardTitle className="text-base flex items-center gap-2">
            <BarChart3 className="h-4 w-4 text-cyan-400" />
            Per-Client Breakdown
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full text-sm" role="table">
              <thead>
                <tr className="border-b border-border/50 text-muted-foreground">
                  <th className="text-left py-2 px-3 font-medium">Organization</th>
                  <th className="text-left py-2 px-3 font-medium">Industry</th>
                  <th className="text-right py-2 px-3 font-medium">Alerts</th>
                  <th className="text-right py-2 px-3 font-medium">Critical</th>
                  <th className="text-right py-2 px-3 font-medium">Open Incidents</th>
                  <th className="text-right py-2 px-3 font-medium">Connectors</th>
                  <th className="text-right py-2 px-3 font-medium">SLA Breaches</th>
                  <th className="text-right py-2 px-3 font-medium">Health</th>
                </tr>
              </thead>
              <tbody>
                {report.clients.map((client) => {
                  const health =
                    Number(client.activeSlaBreaches) > 0
                      ? "breached"
                      : Number(client.criticalAlerts) > 5
                        ? "critical"
                        : Number(client.openIncidents) > 0
                          ? "warning"
                          : "healthy";
                  const healthBadge: Record<string, React.ReactNode> = {
                    healthy: (
                      <Badge variant="outline" className="text-emerald-400 border-emerald-400/30">
                        Healthy
                      </Badge>
                    ),
                    warning: (
                      <Badge variant="outline" className="text-amber-400 border-amber-400/30">
                        Warning
                      </Badge>
                    ),
                    critical: (
                      <Badge variant="outline" className="text-red-400 border-red-400/30">
                        Critical
                      </Badge>
                    ),
                    breached: (
                      <Badge variant="outline" className="text-red-400 border-red-400/30 bg-red-500/10">
                        SLA Breach
                      </Badge>
                    ),
                  };
                  return (
                    <tr key={client.orgId} className="border-b border-border/30 hover:bg-muted/30 transition-colors">
                      <td className="py-2.5 px-3 font-medium">{client.orgName}</td>
                      <td className="py-2.5 px-3 text-muted-foreground">{client.industry || "—"}</td>
                      <td className="py-2.5 px-3 text-right">{Number(client.alertCount).toLocaleString()}</td>
                      <td className="py-2.5 px-3 text-right text-red-400">{client.criticalAlerts}</td>
                      <td className="py-2.5 px-3 text-right">{client.openIncidents}</td>
                      <td className="py-2.5 px-3 text-right">{client.connectorCount}</td>
                      <td className="py-2.5 px-3 text-right">{client.activeSlaBreaches}</td>
                      <td className="py-2.5 px-3 text-right">{healthBadge[health]}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

// ── Main Page ───────────────────────────────────────────────────────

export default function MsspPartnerPortalPage() {
  const [activeTab, setActiveTab] = useState<PortalTab>("overview");
  const { currentOrg } = useOrgContext();
  const queryClient = useQueryClient();

  const isMsspParent = currentOrg?.orgType === "mssp_parent";

  const { data: statsRaw, isLoading: statsLoading } = useQuery({
    queryKey: ["/api/mssp-portal/stats"],
    enabled: isMsspParent,
  });
  const stats = unwrap<PortalStats | null>(statsRaw);

  const { data: childrenRaw } = useQuery<ChildOrg[]>({
    queryKey: ["/api/mssp/children"],
    enabled: isMsspParent,
  });
  const childOrgs: ChildOrg[] = (
    Array.isArray(childrenRaw)
      ? childrenRaw
      : childrenRaw && typeof childrenRaw === "object" && "data" in childrenRaw
        ? (childrenRaw as { data: ChildOrg[] }).data
        : []
  ) as ChildOrg[];

  const refreshAll = () => {
    queryClient.invalidateQueries({ queryKey: ["/api/mssp-portal/stats"] });
    queryClient.invalidateQueries({ queryKey: ["/api/mssp-portal/white-label"] });
    queryClient.invalidateQueries({ queryKey: ["/api/mssp-portal/slas"] });
    queryClient.invalidateQueries({ queryKey: ["/api/mssp-portal/sla-breaches"] });
    queryClient.invalidateQueries({ queryKey: ["/api/mssp-portal/billing"] });
    queryClient.invalidateQueries({ queryKey: ["/api/mssp-portal/onboarding"] });
    queryClient.invalidateQueries({ queryKey: ["/api/mssp-portal/report"] });
  };

  if (!isMsspParent) {
    return (
      <div className="p-6">
        <Card className="glass-subtle">
          <CardContent className="p-8 text-center">
            <Building2 className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
            <h2 className="text-lg font-semibold mb-2">MSSP Partner Portal</h2>
            <p className="text-sm text-muted-foreground max-w-md mx-auto">
              Your organization is not configured as an MSSP parent. Contact your administrator to enable MSSP features
              for white-label branding, client management, SLA policies, and usage-based billing.
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  const TABS: { key: PortalTab; label: string; icon: React.ComponentType<{ className?: string }> }[] = [
    { key: "overview", label: "Overview", icon: BarChart3 },
    { key: "whitelabel", label: "White-Label", icon: Palette },
    { key: "onboarding", label: "Onboarding", icon: FileCheck2 },
    { key: "sla", label: "SLA Management", icon: Clock },
    { key: "billing", label: "Billing", icon: DollarSign },
    { key: "reporting", label: "Reporting", icon: TrendingUp },
  ];

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">MSSP Partner Portal</h1>
          <p className="text-sm text-muted-foreground mt-0.5">
            White-label branding, client management, SLA policies, and billing
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={refreshAll} className="gap-1.5">
          <RefreshCw className="h-4 w-4" />
          Refresh
        </Button>
      </div>

      {/* Tab bar */}
      <div className="flex gap-1 border-b border-border/50 pb-px overflow-x-auto">
        {TABS.map((tab) => {
          const TabIcon = tab.icon;
          return (
            <button
              key={tab.key}
              onClick={() => setActiveTab(tab.key)}
              className={`flex items-center gap-1.5 px-4 py-2 text-sm font-medium rounded-t-md transition-colors whitespace-nowrap ${
                activeTab === tab.key
                  ? "bg-background border border-b-0 border-border/50 text-foreground"
                  : "text-muted-foreground hover:text-foreground hover:bg-muted/50"
              }`}
            >
              <TabIcon className="h-3.5 w-3.5" />
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* Overview tab */}
      {activeTab === "overview" && (
        <div className="space-y-6">
          {statsLoading ? (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {Array.from({ length: 8 }).map((_, i) => (
                <Card key={`stat-skel-${i}`} className="glass-subtle">
                  <CardContent className="p-4">
                    <Skeleton className="h-3 w-20 mb-2" />
                    <Skeleton className="h-8 w-16" />
                  </CardContent>
                </Card>
              ))}
            </div>
          ) : stats ? (
            <>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <StatCard title="Client Organizations" value={stats.clientCount} icon={Building2} />
                <StatCard title="Active SLAs" value={stats.activeSlas} icon={Shield} variant="success" />
                <StatCard
                  title="SLA Breaches"
                  value={stats.activeBreaches}
                  icon={AlertTriangle}
                  variant={stats.activeBreaches > 0 ? "critical" : "success"}
                />
                <StatCard
                  title="Onboarding Pending"
                  value={stats.onboardingPending}
                  icon={FileCheck2}
                  variant={stats.onboardingPending > 0 ? "warning" : "success"}
                />
                <StatCard title="Clients Onboarded" value={stats.onboardingCompleted} icon={Users} variant="success" />
                <StatCard
                  title="Draft Invoices"
                  value={stats.billingDraftInvoices}
                  icon={DollarSign}
                  variant="warning"
                />
                <StatCard
                  title="Total Revenue"
                  value={formatCurrency(stats.billingTotalRevenue)}
                  icon={TrendingUp}
                  variant="success"
                />
                <StatCard
                  title="Overdue Invoices"
                  value={stats.billingOverdueCount}
                  icon={XCircle}
                  variant={stats.billingOverdueCount > 0 ? "critical" : "success"}
                />
              </div>

              {/* Usage and Billing Dashboard Summary */}
              <Card className="glass-subtle">
                <CardHeader className="pb-3">
                  <CardTitle className="text-base flex items-center gap-2">
                    <DollarSign className="h-4 w-4 text-emerald-400" />
                    Usage & Billing Summary
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
                    <div className="text-center p-3 border rounded-lg">
                      <p className="text-2xl font-bold">{formatCurrency(stats.billingTotalRevenue)}</p>
                      <p className="text-xs text-muted-foreground">Total Revenue</p>
                    </div>
                    <div className="text-center p-3 border rounded-lg">
                      <p className="text-2xl font-bold">{stats.clientCount}</p>
                      <p className="text-xs text-muted-foreground">Active Tenants</p>
                    </div>
                    <div className="text-center p-3 border rounded-lg">
                      <p className="text-2xl font-bold">{stats.billingDraftInvoices}</p>
                      <p className="text-xs text-muted-foreground">Draft Invoices</p>
                    </div>
                    <div className="text-center p-3 border rounded-lg">
                      <p className="text-2xl font-bold">
                        {stats.clientCount > 0
                          ? formatCurrency(Math.round(stats.billingTotalRevenue / stats.clientCount))
                          : "$0"}
                      </p>
                      <p className="text-xs text-muted-foreground">Avg Revenue/Tenant</p>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* Partner Onboarding Wizard Quick Actions */}
              <Card className="glass-subtle">
                <CardHeader className="pb-3">
                  <CardTitle className="text-base">Quick Actions</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                    <Button
                      variant="outline"
                      className="h-auto py-3 flex-col gap-1.5"
                      onClick={() => setActiveTab("whitelabel")}
                    >
                      <Palette className="h-5 w-5 text-violet-400" />
                      <span className="text-xs">{stats.whiteLabelConfigured ? "Edit Branding" : "Setup Branding"}</span>
                    </Button>
                    <Button
                      variant="outline"
                      className="h-auto py-3 flex-col gap-1.5"
                      onClick={() => setActiveTab("onboarding")}
                    >
                      <FileCheck2 className="h-5 w-5 text-cyan-400" />
                      <span className="text-xs">Client Onboarding</span>
                    </Button>
                    <Button
                      variant="outline"
                      className="h-auto py-3 flex-col gap-1.5"
                      onClick={() => setActiveTab("sla")}
                    >
                      <Clock className="h-5 w-5 text-amber-400" />
                      <span className="text-xs">Manage SLAs</span>
                    </Button>
                    <Button
                      variant="outline"
                      className="h-auto py-3 flex-col gap-1.5"
                      onClick={() => setActiveTab("billing")}
                    >
                      <DollarSign className="h-5 w-5 text-emerald-400" />
                      <span className="text-xs">Generate Invoice</span>
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </>
          ) : (
            <Card className="glass-subtle">
              <CardContent className="p-6 text-center text-sm text-muted-foreground">
                No stats available yet.
              </CardContent>
            </Card>
          )}
        </div>
      )}

      {activeTab === "whitelabel" && <WhiteLabelTab />}
      {activeTab === "onboarding" && <OnboardingTab>{childOrgs}</OnboardingTab>}
      {activeTab === "sla" && <SlaTab>{childOrgs}</SlaTab>}
      {activeTab === "billing" && <BillingTab>{childOrgs}</BillingTab>}
      {activeTab === "reporting" && <ReportingTab />}
    </div>
  );
}

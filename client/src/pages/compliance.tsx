import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import {
  Shield, FileText, Users, CheckCircle2, XCircle, AlertTriangle,
  Loader2, Download, Play, Clock, Hash, Mail, Calendar,
  Lock, Eye, EyeOff, Database, RefreshCw, Plus, ChevronRight,
  ScrollText, Scale, ShieldCheck, Trash2, Upload, Gavel, Ban,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger, DialogFooter, DialogClose,
} from "@/components/ui/dialog";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";

interface CompliancePolicy {
  id: string;
  orgId: string;
  alertRetentionDays: number;
  incidentRetentionDays: number;
  auditLogRetentionDays: number;
  piiMaskingEnabled: boolean;
  pseudonymizeExports: boolean;
  enabledFrameworks: string[];
  dataProcessingBasis: string;
  dpoEmail: string | null;
  dsarSlaDays: number;
  retentionLastRunAt: string | null;
  retentionLastDeletedCount: number;
}

interface DsarRequest {
  id: string;
  orgId: string;
  requestorEmail: string;
  requestType: string;
  subjectIdentifiers: any;
  status: string;
  dueDate: string | null;
  notes: string | null;
  resultSummary: any;
  fulfilledAt: string | null;
  fulfilledBy: string | null;
  createdAt: string;
}

interface AuditVerifyResult {
  verified: boolean;
  totalEntries: number;
  lastVerifiedSeq: number;
  errors: string[];
}

interface RetentionReport {
  alertRetentionDays: number;
  incidentRetentionDays: number;
  auditLogRetentionDays: number;
  oldestAlert: string | null;
  oldestIncident: string | null;
  oldestAuditLog: string | null;
  alertsWithinPolicy: boolean;
  incidentsWithinPolicy: boolean;
  auditLogsWithinPolicy: boolean;
  totalAlerts: number;
  totalIncidents: number;
  totalAuditLogs: number;
  lastCleanupAt: string | null;
  lastDeletedCount: number;
}

interface ComplianceControl {
  id: string;
  framework: string;
  controlId: string;
  title: string;
  description: string | null;
  category: string | null;
  parentControlId: string | null;
  createdAt: string;
}

interface ComplianceControlMapping {
  id: string;
  orgId: string;
  controlId: string;
  resourceType: string;
  resourceId: string;
  status: string;
  evidenceNotes: string | null;
  lastAssessedAt: string | null;
  assessedBy: string | null;
  createdAt: string;
}

interface EvidenceLockerItem {
  id: string;
  orgId: string;
  title: string;
  description: string | null;
  artifactType: string;
  framework: string | null;
  controlId: string | null;
  storageKey: string | null;
  url: string | null;
  mimeType: string | null;
  fileSize: number | null;
  checksum: string | null;
  retentionDays: number;
  expiresAt: string | null;
  status: string;
  metadata: any;
  tags: string[];
  uploadedBy: string | null;
  uploadedByName: string | null;
  createdAt: string;
}

const ARTIFACT_TYPE_LABELS: Record<string, string> = {
  screenshot: "Screenshot",
  log: "Log File",
  config_snapshot: "Config Snapshot",
  report: "Report",
  policy_result: "Policy Result",
  scan_result: "Scan Result",
  communication: "Communication",
  other: "Other",
};

const ARTIFACT_TYPE_COLORS: Record<string, string> = {
  screenshot: "border-cyan-500/30 text-cyan-400",
  log: "border-amber-500/30 text-amber-400",
  config_snapshot: "border-indigo-500/30 text-indigo-400",
  report: "border-blue-500/30 text-blue-400",
  policy_result: "border-green-500/30 text-green-400",
  scan_result: "border-purple-500/30 text-purple-400",
  communication: "border-pink-500/30 text-pink-400",
  other: "border-gray-500/30 text-gray-400",
};

const EVIDENCE_STATUS_COLORS: Record<string, string> = {
  active: "border-green-500/30 text-green-400",
  archived: "border-gray-500/30 text-gray-400",
  expired: "border-red-500/30 text-red-400",
};

const CONTROL_FRAMEWORK_LABELS: Record<string, string> = {
  nist_csf: "NIST CSF",
  iso_27001: "ISO 27001",
  cis: "CIS",
  soc2: "SOC 2",
};

const CONTROL_FRAMEWORK_COLORS: Record<string, string> = {
  nist_csf: "border-blue-500/30 text-blue-400",
  iso_27001: "border-purple-500/30 text-purple-400",
  cis: "border-green-500/30 text-green-400",
  soc2: "border-orange-500/30 text-orange-400",
};

const MAPPING_STATUS_COLORS: Record<string, string> = {
  compliant: "border-green-500/30 text-green-400",
  non_compliant: "border-red-500/30 text-red-400",
  not_assessed: "border-gray-500/30 text-gray-400",
  partial: "border-yellow-500/30 text-yellow-400",
};

const FRAMEWORKS = ["GDPR", "DPDP", "HIPAA", "SOX", "PCI-DSS", "ISO27001", "NIST"];

const PROCESSING_BASES = [
  { value: "legitimate_interest", label: "Legitimate Interest" },
  { value: "consent", label: "Consent" },
  { value: "contract", label: "Contract" },
  { value: "legal_obligation", label: "Legal Obligation" },
  { value: "vital_interest", label: "Vital Interest" },
  { value: "public_interest", label: "Public Interest" },
];

const DSAR_STATUS_COLORS: Record<string, string> = {
  pending: "border-yellow-500/30 text-yellow-400",
  in_progress: "border-blue-500/30 text-blue-400",
  fulfilled: "border-green-500/30 text-green-400",
  rejected: "border-red-500/30 text-red-400",
  expired: "border-gray-500/30 text-gray-400",
};

const REQUEST_TYPES = ["access", "erasure", "portability", "rectification"];

function formatDate(date: string | null | undefined): string {
  if (!date) return "N/A";
  return new Date(date).toLocaleDateString("en-US", {
    year: "numeric", month: "short", day: "numeric",
  });
}

function formatDateTime(date: string | null | undefined): string {
  if (!date) return "Never";
  return new Date(date).toLocaleString("en-US", {
    year: "numeric", month: "short", day: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
}

function PoliciesTab() {
  const { toast } = useToast();
  const { data: policy, isLoading } = useQuery<CompliancePolicy>({
    queryKey: ["/api/compliance/policy"],
  });

  const [alertRetention, setAlertRetention] = useState<number>(365);
  const [incidentRetention, setIncidentRetention] = useState<number>(730);
  const [auditLogRetention, setAuditLogRetention] = useState<number>(2555);
  const [piiMasking, setPiiMasking] = useState(false);
  const [pseudonymize, setPseudonymize] = useState(false);
  const [frameworks, setFrameworks] = useState<string[]>([]);
  const [processingBasis, setProcessingBasis] = useState("legitimate_interest");
  const [dpoEmail, setDpoEmail] = useState("");
  const [dsarSla, setDsarSla] = useState<number>(30);
  const [initialized, setInitialized] = useState(false);

  if (policy && !initialized) {
    setAlertRetention(policy.alertRetentionDays);
    setIncidentRetention(policy.incidentRetentionDays);
    setAuditLogRetention(policy.auditLogRetentionDays);
    setPiiMasking(policy.piiMaskingEnabled);
    setPseudonymize(policy.pseudonymizeExports);
    setFrameworks(policy.enabledFrameworks || []);
    setProcessingBasis(policy.dataProcessingBasis || "legitimate_interest");
    setDpoEmail(policy.dpoEmail || "");
    setDsarSla(policy.dsarSlaDays);
    setInitialized(true);
  }

  const savePolicy = useMutation({
    mutationFn: async () => {
      await apiRequest("PUT", "/api/compliance/policy", {
        alertRetentionDays: alertRetention,
        incidentRetentionDays: incidentRetention,
        auditLogRetentionDays: auditLogRetention,
        piiMaskingEnabled: piiMasking,
        pseudonymizeExports: pseudonymize,
        enabledFrameworks: frameworks,
        dataProcessingBasis: processingBasis,
        dpoEmail: dpoEmail || null,
        dsarSlaDays: dsarSla,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/compliance/policy"] });
      toast({ title: "Policy saved", description: "Compliance policy updated successfully." });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to save policy", description: error.message, variant: "destructive" });
    },
  });

  const toggleFramework = (fw: string) => {
    setFrameworks((prev) =>
      prev.includes(fw) ? prev.filter((f) => f !== fw) : [...prev, fw]
    );
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2 flex-wrap">
            <Scale className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
            Data Governance Policy
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="space-y-4">
            <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Retention Periods</h3>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div className="space-y-1.5">
                <label className="text-xs text-muted-foreground">Alert Retention (days)</label>
                <Input
                  type="number"
                  value={alertRetention}
                  onChange={(e) => setAlertRetention(Number(e.target.value))}
                  data-testid="input-alert-retention"
                />
              </div>
              <div className="space-y-1.5">
                <label className="text-xs text-muted-foreground">Incident Retention (days)</label>
                <Input
                  type="number"
                  value={incidentRetention}
                  onChange={(e) => setIncidentRetention(Number(e.target.value))}
                  data-testid="input-incident-retention"
                />
              </div>
              <div className="space-y-1.5">
                <label className="text-xs text-muted-foreground">Audit Log Retention (days)</label>
                <Input
                  type="number"
                  value={auditLogRetention}
                  onChange={(e) => setAuditLogRetention(Number(e.target.value))}
                  data-testid="input-audit-log-retention"
                />
              </div>
            </div>
          </div>

          <div className="space-y-4">
            <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Privacy Controls</h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="flex items-center justify-between gap-2 p-3 rounded-md bg-muted/30">
                <div className="flex items-center gap-2">
                  <EyeOff className="h-4 w-4 text-muted-foreground flex-shrink-0" aria-hidden="true" />
                  <div>
                    <div className="text-sm font-medium">PII Masking</div>
                    <div className="text-xs text-muted-foreground">Mask personally identifiable information</div>
                  </div>
                </div>
                <Switch
                  checked={piiMasking}
                  onCheckedChange={setPiiMasking}
                  data-testid="switch-pii-masking"
                />
              </div>
              <div className="flex items-center justify-between gap-2 p-3 rounded-md bg-muted/30">
                <div className="flex items-center gap-2">
                  <Lock className="h-4 w-4 text-muted-foreground flex-shrink-0" aria-hidden="true" />
                  <div>
                    <div className="text-sm font-medium">Pseudonymize Exports</div>
                    <div className="text-xs text-muted-foreground">Replace identifiers in exported data</div>
                  </div>
                </div>
                <Switch
                  checked={pseudonymize}
                  onCheckedChange={setPseudonymize}
                  data-testid="switch-pseudonymize"
                />
              </div>
            </div>
          </div>

          <div className="space-y-3">
            <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Compliance Frameworks</h3>
            <div className="flex flex-wrap gap-2">
              {FRAMEWORKS.map((fw) => (
                <Badge
                  key={fw}
                  variant="outline"
                  className={`cursor-pointer toggle-elevate ${frameworks.includes(fw) ? "toggle-elevated border-red-500/40 text-red-400" : ""}`}
                  onClick={() => toggleFramework(fw)}
                  data-testid={`badge-framework-${fw}`}
                >
                  {frameworks.includes(fw) && <CheckCircle2 className="h-3 w-3 mr-1" />}
                  {fw}
                </Badge>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div className="space-y-1.5">
              <label className="text-xs text-muted-foreground">Data Processing Basis</label>
              <Select value={processingBasis} onValueChange={setProcessingBasis}>
                <SelectTrigger data-testid="select-processing-basis">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {PROCESSING_BASES.map((b) => (
                    <SelectItem key={b.value} value={b.value}>{b.label}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <label className="text-xs text-muted-foreground">DPO Email</label>
              <Input
                type="email"
                placeholder="dpo@example.com"
                value={dpoEmail}
                onChange={(e) => setDpoEmail(e.target.value)}
                data-testid="input-dpo-email"
              />
            </div>
            <div className="space-y-1.5">
              <label className="text-xs text-muted-foreground">DSAR SLA (days)</label>
              <Input
                type="number"
                value={dsarSla}
                onChange={(e) => setDsarSla(Number(e.target.value))}
                data-testid="input-dsar-sla"
              />
            </div>
          </div>

          <div className="flex items-center justify-between gap-4 pt-2 flex-wrap">
            <div className="text-xs text-muted-foreground space-y-0.5">
              {policy?.retentionLastRunAt && (
                <div data-testid="text-last-retention-run">
                  Last retention run: {formatDateTime(policy.retentionLastRunAt)}
                  {policy.retentionLastDeletedCount > 0 && (
                    <span className="ml-1 text-red-400">({policy.retentionLastDeletedCount} records deleted)</span>
                  )}
                </div>
              )}
            </div>
            <Button
              onClick={() => savePolicy.mutate()}
              disabled={savePolicy.isPending}
              data-testid="button-save-policy"
            >
              {savePolicy.isPending ? (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              ) : (
                <Shield className="h-4 w-4 mr-2" />
              )}
              Save Policy
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function DsarTab() {
  const { toast } = useToast();
  const [showCreate, setShowCreate] = useState(false);
  const [newEmail, setNewEmail] = useState("");
  const [newType, setNewType] = useState("access");
  const [newSubjectEmail, setNewSubjectEmail] = useState("");
  const [newSubjectIp, setNewSubjectIp] = useState("");
  const [newSubjectUserId, setNewSubjectUserId] = useState("");
  const [newNotes, setNewNotes] = useState("");
  const [statusUpdateId, setStatusUpdateId] = useState<string | null>(null);
  const [statusUpdateValue, setStatusUpdateValue] = useState("in_progress");

  const { data: dsarRequests, isLoading } = useQuery<DsarRequest[]>({
    queryKey: ["/api/compliance/dsar"],
  });

  const createDsar = useMutation({
    mutationFn: async () => {
      const subjectIdentifiers: Record<string, string> = {};
      if (newSubjectEmail) subjectIdentifiers.email = newSubjectEmail;
      if (newSubjectIp) subjectIdentifiers.ip = newSubjectIp;
      if (newSubjectUserId) subjectIdentifiers.userId = newSubjectUserId;
      await apiRequest("POST", "/api/compliance/dsar", {
        requestorEmail: newEmail,
        requestType: newType,
        subjectIdentifiers,
        notes: newNotes || null,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/compliance/dsar"] });
      setShowCreate(false);
      setNewEmail("");
      setNewType("access");
      setNewSubjectEmail("");
      setNewSubjectIp("");
      setNewSubjectUserId("");
      setNewNotes("");
      toast({ title: "DSAR created", description: "Data subject request submitted successfully." });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to create DSAR", description: error.message, variant: "destructive" });
    },
  });

  const fulfillDsar = useMutation({
    mutationFn: async (id: string) => {
      const res = await apiRequest("POST", `/api/compliance/dsar/${id}/fulfill`);
      return res.json();
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["/api/compliance/dsar"] });
      toast({
        title: "DSAR fulfilled",
        description: data?.summary || "Request has been fulfilled successfully.",
      });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to fulfill DSAR", description: error.message, variant: "destructive" });
    },
  });

  const updateStatus = useMutation({
    mutationFn: async ({ id, status }: { id: string; status: string }) => {
      await apiRequest("PATCH", `/api/compliance/dsar/${id}`, { status });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/compliance/dsar"] });
      setStatusUpdateId(null);
      toast({ title: "Status updated", description: "DSAR status has been updated." });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to update status", description: error.message, variant: "destructive" });
    },
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2 flex-wrap">
            <Users className="h-4 w-4 text-muted-foreground" />
            Data Subject Access Requests
          </CardTitle>
          <Dialog open={showCreate} onOpenChange={setShowCreate}>
            <DialogTrigger asChild>
              <Button size="sm" data-testid="button-create-dsar">
                <Plus className="h-4 w-4 mr-1" />
                New Request
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Create DSAR Request</DialogTitle>
              </DialogHeader>
              <div className="space-y-4 py-2">
                <div className="space-y-1.5">
                  <label className="text-xs text-muted-foreground">Requestor Email</label>
                  <Input
                    type="email"
                    placeholder="requestor@example.com"
                    value={newEmail}
                    onChange={(e) => setNewEmail(e.target.value)}
                    data-testid="input-dsar-email"
                  />
                </div>
                <div className="space-y-1.5">
                  <label className="text-xs text-muted-foreground">Request Type</label>
                  <Select value={newType} onValueChange={setNewType}>
                    <SelectTrigger data-testid="select-dsar-type">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {REQUEST_TYPES.map((t) => (
                        <SelectItem key={t} value={t}>{t.charAt(0).toUpperCase() + t.slice(1)}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-1.5">
                  <label className="text-xs text-muted-foreground">Subject Identifiers</label>
                  <div className="space-y-2">
                    <Input
                      placeholder="Subject email"
                      value={newSubjectEmail}
                      onChange={(e) => setNewSubjectEmail(e.target.value)}
                      data-testid="input-dsar-subject-email"
                    />
                    <Input
                      placeholder="Subject IP address"
                      value={newSubjectIp}
                      onChange={(e) => setNewSubjectIp(e.target.value)}
                      data-testid="input-dsar-subject-ip"
                    />
                    <Input
                      placeholder="Subject User ID"
                      value={newSubjectUserId}
                      onChange={(e) => setNewSubjectUserId(e.target.value)}
                      data-testid="input-dsar-subject-userid"
                    />
                  </div>
                </div>
                <div className="space-y-1.5">
                  <label className="text-xs text-muted-foreground">Notes</label>
                  <Input
                    placeholder="Additional notes..."
                    value={newNotes}
                    onChange={(e) => setNewNotes(e.target.value)}
                    data-testid="input-dsar-notes"
                  />
                </div>
              </div>
              <DialogFooter>
                <DialogClose asChild>
                  <Button variant="outline" data-testid="button-cancel-dsar">Cancel</Button>
                </DialogClose>
                <Button
                  onClick={() => createDsar.mutate()}
                  disabled={!newEmail || createDsar.isPending}
                  data-testid="button-submit-dsar"
                >
                  {createDsar.isPending ? (
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  ) : (
                    <Plus className="h-4 w-4 mr-2" />
                  )}
                  Create Request
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto border rounded-md">
            <Table data-testid="table-dsar">
              <TableHeader>
                <TableRow>
                  <TableHead className="text-xs">ID</TableHead>
                  <TableHead className="text-xs">Requestor</TableHead>
                  <TableHead className="text-xs">Type</TableHead>
                  <TableHead className="text-xs">Status</TableHead>
                  <TableHead className="text-xs">Due Date</TableHead>
                  <TableHead className="text-xs">Created</TableHead>
                  <TableHead className="text-xs">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {dsarRequests && dsarRequests.length > 0 ? (
                  dsarRequests.map((req) => (
                    <TableRow key={req.id} data-testid={`row-dsar-${req.id}`}>
                      <TableCell>
                        <span className="text-xs font-mono" data-testid={`text-dsar-id-${req.id}`}>
                          {req.id.slice(0, 8)}...
                        </span>
                      </TableCell>
                      <TableCell>
                        <span className="text-xs" data-testid={`text-dsar-email-${req.id}`}>{req.requestorEmail}</span>
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className="no-default-hover-elevate no-default-active-elevate text-[10px] uppercase" data-testid={`badge-dsar-type-${req.id}`}>
                          {req.requestType}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant="outline"
                          className={`no-default-hover-elevate no-default-active-elevate text-[10px] ${DSAR_STATUS_COLORS[req.status] || ""}`}
                          data-testid={`badge-dsar-status-${req.id}`}
                        >
                          {req.status.replace("_", " ")}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <span className="text-xs text-muted-foreground" data-testid={`text-dsar-due-${req.id}`}>
                          {formatDate(req.dueDate)}
                        </span>
                      </TableCell>
                      <TableCell>
                        <span className="text-xs text-muted-foreground" data-testid={`text-dsar-created-${req.id}`}>
                          {formatDate(req.createdAt)}
                        </span>
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-1 flex-wrap">
                          {req.status === "pending" || req.status === "in_progress" ? (
                            <>
                              <Button
                                size="sm"
                                variant="outline"
                                onClick={() => fulfillDsar.mutate(req.id)}
                                disabled={fulfillDsar.isPending && fulfillDsar.variables === req.id}
                                data-testid={`button-fulfill-dsar-${req.id}`}
                              >
                                {fulfillDsar.isPending && fulfillDsar.variables === req.id ? (
                                  <Loader2 className="h-3 w-3 animate-spin" />
                                ) : (
                                  <CheckCircle2 className="h-3 w-3" />
                                )}
                              </Button>
                              {statusUpdateId === req.id ? (
                                <div className="flex items-center gap-1 flex-wrap">
                                  <Select value={statusUpdateValue} onValueChange={setStatusUpdateValue}>
                                    <SelectTrigger className="text-xs w-28" data-testid={`select-status-update-${req.id}`}>
                                      <SelectValue />
                                    </SelectTrigger>
                                    <SelectContent>
                                      <SelectItem value="pending">Pending</SelectItem>
                                      <SelectItem value="in_progress">In Progress</SelectItem>
                                      <SelectItem value="rejected">Rejected</SelectItem>
                                      <SelectItem value="expired">Expired</SelectItem>
                                    </SelectContent>
                                  </Select>
                                  <Button
                                    size="sm"
                                    onClick={() => updateStatus.mutate({ id: req.id, status: statusUpdateValue })}
                                    disabled={updateStatus.isPending}
                                    data-testid={`button-confirm-status-${req.id}`}
                                  >
                                    {updateStatus.isPending ? (
                                      <Loader2 className="h-3 w-3 animate-spin" />
                                    ) : (
                                      <CheckCircle2 className="h-3 w-3" />
                                    )}
                                  </Button>
                                </div>
                              ) : (
                                <Button
                                  size="sm"
                                  variant="outline"
                                  onClick={() => { setStatusUpdateId(req.id); setStatusUpdateValue(req.status); }}
                                  data-testid={`button-update-status-${req.id}`}
                                >
                                  <RefreshCw className="h-3 w-3" />
                                </Button>
                              )}
                            </>
                          ) : (
                            <span className="text-xs text-muted-foreground">
                              {req.fulfilledAt ? `Fulfilled ${formatDate(req.fulfilledAt)}` : "Closed"}
                            </span>
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                  ))
                ) : (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center py-8">
                      <Users className="h-8 w-8 mx-auto mb-2 text-muted-foreground/50" />
                      <p className="text-sm text-muted-foreground" data-testid="text-no-dsar">No DSAR requests found</p>
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function ReportsTab() {
  const { toast } = useToast();
  const [activeReport, setActiveReport] = useState<string | null>(null);
  const [reportData, setReportData] = useState<any>(null);

  const generateReport = useMutation({
    mutationFn: async (reportType: string) => {
      const res = await apiRequest("GET", `/api/compliance/report/${reportType}`);
      return res.json();
    },
    onSuccess: (data, reportType) => {
      setActiveReport(reportType);
      setReportData(data);
      toast({ title: "Report generated", description: `${reportType} report generated successfully.` });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to generate report", description: error.message, variant: "destructive" });
    },
  });

  const reports = [
    {
      key: "gdpr_article30",
      title: "GDPR Article 30 Report",
      description: "Record of Processing Activities as required by GDPR Article 30",
      icon: ScrollText,
    },
    {
      key: "retention_status",
      title: "Data Retention Status",
      description: "Current retention compliance metrics and data lifecycle status",
      icon: Database,
    },
    {
      key: "dpdp_compliance",
      title: "DPDP Act Compliance",
      description: "Digital Personal Data Protection Act compliance summary",
      icon: ShieldCheck,
    },
  ];

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {reports.map((report) => (
          <Card key={report.key} data-testid={`card-report-${report.key}`}>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-semibold flex items-center gap-2 flex-wrap">
                <report.icon className="h-4 w-4 text-muted-foreground" />
                {report.title}
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <p className="text-xs text-muted-foreground">{report.description}</p>
              <Button
                size="sm"
                variant="outline"
                className="w-full"
                onClick={() => generateReport.mutate(report.key)}
                disabled={generateReport.isPending && generateReport.variables === report.key}
                data-testid={`button-generate-${report.key}`}
              >
                {generateReport.isPending && generateReport.variables === report.key ? (
                  <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />
                ) : (
                  <FileText className="h-3.5 w-3.5 mr-1.5" />
                )}
                Generate Report
              </Button>
            </CardContent>
          </Card>
        ))}
      </div>

      {activeReport && reportData && (
        <Card data-testid="card-report-result">
          <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-3">
            <CardTitle className="text-sm font-semibold" data-testid="text-report-title">
              {reports.find((r) => r.key === activeReport)?.title || activeReport}
            </CardTitle>
            <Button
              size="sm"
              variant="outline"
              onClick={() => {
                const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: "application/json" });
                const url = URL.createObjectURL(blob);
                const a = document.createElement("a");
                a.href = url;
                a.download = `${activeReport}_report.json`;
                a.click();
                URL.revokeObjectURL(url);
              }}
              data-testid="button-download-report"
            >
              <Download className="h-3.5 w-3.5 mr-1.5" />
              Download
            </Button>
          </CardHeader>
          <CardContent>
            <pre className="text-xs bg-muted/30 rounded-md p-4 overflow-auto max-h-96 whitespace-pre-wrap" data-testid="text-report-data">
              {JSON.stringify(reportData, null, 2)}
            </pre>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function AuditIntegrityTab() {
  const { toast } = useToast();
  const [verifyResult, setVerifyResult] = useState<AuditVerifyResult | null>(null);

  const verifyIntegrity = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("GET", "/api/compliance/audit/verify");
      return res.json() as Promise<AuditVerifyResult>;
    },
    onSuccess: (data) => {
      setVerifyResult(data);
      toast({
        title: data.verified ? "Audit trail verified" : "Integrity issues detected",
        description: data.verified
          ? `${data.totalEntries} entries verified successfully.`
          : `${data.errors.length} integrity errors found.`,
        variant: data.verified ? undefined : "destructive",
      });
    },
    onError: (error: Error) => {
      toast({ title: "Verification failed", description: error.message, variant: "destructive" });
    },
  });

  const exportAudit = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("GET", "/api/compliance/audit/export");
      return res.json();
    },
    onSuccess: (data) => {
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "audit_trail_export.json";
      a.click();
      URL.revokeObjectURL(url);
      toast({ title: "Audit trail exported", description: "JSON export downloaded successfully." });
    },
    onError: (error: Error) => {
      toast({ title: "Export failed", description: error.message, variant: "destructive" });
    },
  });

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2 flex-wrap">
            <Hash className="h-4 w-4 text-muted-foreground" />
            Immutable Audit Trail Verification
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center gap-2 flex-wrap">
            <Button
              onClick={() => verifyIntegrity.mutate()}
              disabled={verifyIntegrity.isPending}
              data-testid="button-verify-integrity"
            >
              {verifyIntegrity.isPending ? (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              ) : (
                <ShieldCheck className="h-4 w-4 mr-2" />
              )}
              Verify Integrity
            </Button>
            <Button
              variant="outline"
              onClick={() => exportAudit.mutate()}
              disabled={exportAudit.isPending}
              data-testid="button-export-audit"
            >
              {exportAudit.isPending ? (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              ) : (
                <Download className="h-4 w-4 mr-2" />
              )}
              Export Audit Trail
            </Button>
          </div>

          {verifyResult && (
            <div className="space-y-3 pt-2" data-testid="section-verify-result">
              <div className="flex items-center gap-3 p-4 rounded-md bg-muted/30">
                {verifyResult.verified ? (
                  <CheckCircle2 className="h-8 w-8 text-green-500 flex-shrink-0" />
                ) : (
                  <XCircle className="h-8 w-8 text-red-500 flex-shrink-0" />
                )}
                <div>
                  <div className={`text-sm font-semibold ${verifyResult.verified ? "text-green-400" : "text-red-400"}`} data-testid="text-verify-status">
                    {verifyResult.verified ? "Audit Chain Verified" : "Integrity Issues Detected"}
                  </div>
                  <div className="text-xs text-muted-foreground mt-0.5" data-testid="text-verify-details">
                    {verifyResult.totalEntries} total entries | Last verified sequence: {verifyResult.lastVerifiedSeq}
                  </div>
                </div>
              </div>
              {verifyResult.errors.length > 0 && (
                <div className="space-y-1" data-testid="section-verify-errors">
                  <h4 className="text-xs font-semibold text-red-400">Integrity Errors:</h4>
                  {verifyResult.errors.map((err, idx) => (
                    <div key={idx} className="flex items-start gap-2 text-xs text-red-300 p-2 rounded bg-red-500/10">
                      <AlertTriangle className="h-3 w-3 mt-0.5 flex-shrink-0" />
                      <span data-testid={`text-verify-error-${idx}`}>{err}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <Card data-testid="card-audit-total">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <Database className="h-4 w-4 text-muted-foreground flex-shrink-0" />
              <div>
                <div className="text-xs text-muted-foreground">Total Entries</div>
                <div className="text-lg font-bold tabular-nums" data-testid="text-audit-total">
                  {verifyResult?.totalEntries ?? "—"}
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card data-testid="card-audit-sequence">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <Hash className="h-4 w-4 text-muted-foreground flex-shrink-0" />
              <div>
                <div className="text-xs text-muted-foreground">Last Sequence</div>
                <div className="text-lg font-bold tabular-nums" data-testid="text-audit-sequence">
                  {verifyResult?.lastVerifiedSeq ?? "—"}
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card data-testid="card-audit-chain-status">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              {verifyResult ? (
                verifyResult.verified ? (
                  <CheckCircle2 className="h-4 w-4 text-green-500 flex-shrink-0" />
                ) : (
                  <XCircle className="h-4 w-4 text-red-500 flex-shrink-0" />
                )
              ) : (
                <Shield className="h-4 w-4 text-muted-foreground flex-shrink-0" />
              )}
              <div>
                <div className="text-xs text-muted-foreground">Chain Status</div>
                <div className={`text-sm font-semibold ${verifyResult ? (verifyResult.verified ? "text-green-400" : "text-red-400") : ""}`} data-testid="text-chain-status">
                  {verifyResult ? (verifyResult.verified ? "Valid" : "Compromised") : "Not Verified"}
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function RetentionTab() {
  const { toast } = useToast();
  const [confirmRun, setConfirmRun] = useState(false);

  const { data: policy } = useQuery<CompliancePolicy>({
    queryKey: ["/api/compliance/policy"],
  });

  const [retentionData, setRetentionData] = useState<RetentionReport | null>(null);

  const fetchRetention = useQuery<RetentionReport>({
    queryKey: ["/api/compliance/report/retention_status"],
    enabled: false,
  });

  const runRetention = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/compliance/retention/run");
      return res.json();
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["/api/compliance/policy"] });
      setConfirmRun(false);
      setRetentionData(null);
      toast({
        title: "Retention cleanup completed",
        description: `${data?.deletedCount ?? 0} records removed.`,
      });
    },
    onError: (error: Error) => {
      toast({ title: "Retention cleanup failed", description: error.message, variant: "destructive" });
    },
  });

  const loadRetention = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("GET", "/api/compliance/report/retention_status");
      return res.json() as Promise<RetentionReport>;
    },
    onSuccess: (data) => {
      setRetentionData(data);
    },
    onError: (error: Error) => {
      toast({ title: "Failed to load retention data", description: error.message, variant: "destructive" });
    },
  });

  const retentionItems = [
    {
      label: "Alerts",
      days: policy?.alertRetentionDays ?? 365,
      oldest: retentionData?.oldestAlert,
      withinPolicy: retentionData?.alertsWithinPolicy,
      total: retentionData?.totalAlerts,
    },
    {
      label: "Incidents",
      days: policy?.incidentRetentionDays ?? 730,
      oldest: retentionData?.oldestIncident,
      withinPolicy: retentionData?.incidentsWithinPolicy,
      total: retentionData?.totalIncidents,
    },
    {
      label: "Audit Logs",
      days: policy?.auditLogRetentionDays ?? 2555,
      oldest: retentionData?.oldestAuditLog,
      withinPolicy: retentionData?.auditLogsWithinPolicy,
      total: retentionData?.totalAuditLogs,
    },
  ];

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2 flex-wrap">
            <Clock className="h-4 w-4 text-muted-foreground" />
            Data Retention Dashboard
          </CardTitle>
          <div className="flex items-center gap-2 flex-wrap">
            <Button
              size="sm"
              variant="outline"
              onClick={() => loadRetention.mutate()}
              disabled={loadRetention.isPending}
              data-testid="button-refresh-retention"
            >
              {loadRetention.isPending ? (
                <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />
              ) : (
                <RefreshCw className="h-3.5 w-3.5 mr-1.5" />
              )}
              Refresh
            </Button>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {retentionItems.map((item) => (
              <div key={item.label} className="p-4 rounded-md bg-muted/30 space-y-2" data-testid={`retention-card-${item.label.toLowerCase().replace(/\s/g, "-")}`}>
                <div className="flex items-center justify-between gap-2 flex-wrap">
                  <span className="text-sm font-medium">{item.label}</span>
                  {item.withinPolicy !== undefined && (
                    item.withinPolicy ? (
                      <Badge variant="outline" className="no-default-hover-elevate no-default-active-elevate text-[10px] border-green-500/30 text-green-400" data-testid={`badge-retention-status-${item.label.toLowerCase()}`}>
                        <CheckCircle2 className="h-2.5 w-2.5 mr-0.5" />
                        Compliant
                      </Badge>
                    ) : (
                      <Badge variant="outline" className="no-default-hover-elevate no-default-active-elevate text-[10px] border-red-500/30 text-red-400" data-testid={`badge-retention-status-${item.label.toLowerCase()}`}>
                        <AlertTriangle className="h-2.5 w-2.5 mr-0.5" />
                        Non-compliant
                      </Badge>
                    )
                  )}
                </div>
                <div className="text-xs text-muted-foreground space-y-0.5">
                  <div>Retention: {item.days} days</div>
                  <div>Oldest record: {item.oldest ? formatDate(item.oldest) : "N/A"}</div>
                  {item.total !== undefined && <div>Total records: {item.total.toLocaleString()}</div>}
                </div>
              </div>
            ))}
          </div>

          <div className="flex items-center justify-between gap-4 pt-2 border-t border-border/50 flex-wrap">
            <div className="text-xs text-muted-foreground" data-testid="text-retention-last-cleanup">
              {policy?.retentionLastRunAt ? (
                <span>
                  Last cleanup: {formatDateTime(policy.retentionLastRunAt)}
                  {policy.retentionLastDeletedCount > 0 && (
                    <span className="ml-1 text-red-400">({policy.retentionLastDeletedCount} deleted)</span>
                  )}
                </span>
              ) : (
                "No cleanup has been run yet"
              )}
            </div>
            <Dialog open={confirmRun} onOpenChange={setConfirmRun}>
              <DialogTrigger asChild>
                <Button variant="destructive" size="sm" data-testid="button-run-retention">
                  <Trash2 className="h-3.5 w-3.5 mr-1.5" />
                  Run Retention Cleanup
                </Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>Confirm Retention Cleanup</DialogTitle>
                </DialogHeader>
                <p className="text-sm text-muted-foreground py-4">
                  This will permanently delete records that exceed the configured retention periods.
                  This action cannot be undone. Are you sure you want to proceed?
                </p>
                <DialogFooter>
                  <DialogClose asChild>
                    <Button variant="outline" data-testid="button-cancel-retention">Cancel</Button>
                  </DialogClose>
                  <Button
                    variant="destructive"
                    onClick={() => runRetention.mutate()}
                    disabled={runRetention.isPending}
                    data-testid="button-confirm-retention"
                  >
                    {runRetention.isPending ? (
                      <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                    ) : (
                      <Trash2 className="h-4 w-4 mr-2" />
                    )}
                    Run Cleanup
                  </Button>
                </DialogFooter>
              </DialogContent>
            </Dialog>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function ControlsTab() {
  const { toast } = useToast();
  const [frameworkFilter, setFrameworkFilter] = useState("all");
  const [showAddMapping, setShowAddMapping] = useState(false);
  const [mappingControlId, setMappingControlId] = useState("");
  const [mappingResourceType, setMappingResourceType] = useState("");
  const [mappingResourceId, setMappingResourceId] = useState("");
  const [mappingStatus, setMappingStatus] = useState("not_assessed");
  const [mappingEvidenceNotes, setMappingEvidenceNotes] = useState("");

  const controlsQueryKey = frameworkFilter === "all"
    ? ["/api/compliance-controls"]
    : ["/api/compliance-controls", { framework: frameworkFilter }];

  const { data: controls, isLoading: controlsLoading } = useQuery<ComplianceControl[]>({
    queryKey: controlsQueryKey,
    queryFn: async () => {
      const url = frameworkFilter === "all"
        ? "/api/compliance-controls"
        : `/api/compliance-controls?framework=${frameworkFilter}`;
      const res = await fetch(url, { credentials: "include" });
      if (!res.ok) throw new Error("Failed to fetch controls");
      return res.json();
    },
  });

  const { data: mappings, isLoading: mappingsLoading } = useQuery<ComplianceControlMapping[]>({
    queryKey: ["/api/compliance-control-mappings"],
  });

  const seedControls = useMutation({
    mutationFn: async () => {
      await apiRequest("POST", "/api/compliance-controls/seed");
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/compliance-controls"] });
      toast({ title: "Controls seeded", description: "Built-in compliance controls have been loaded." });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to seed controls", description: error.message, variant: "destructive" });
    },
  });

  const createMapping = useMutation({
    mutationFn: async () => {
      await apiRequest("POST", "/api/compliance-control-mappings", {
        controlId: mappingControlId,
        resourceType: mappingResourceType,
        resourceId: mappingResourceId,
        status: mappingStatus,
        evidenceNotes: mappingEvidenceNotes || null,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/compliance-control-mappings"] });
      setShowAddMapping(false);
      setMappingControlId("");
      setMappingResourceType("");
      setMappingResourceId("");
      setMappingStatus("not_assessed");
      setMappingEvidenceNotes("");
      toast({ title: "Mapping created", description: "Control mapping has been added." });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to create mapping", description: error.message, variant: "destructive" });
    },
  });

  const groupedControls = (controls || []).reduce<Record<string, ComplianceControl[]>>((acc, ctrl) => {
    const key = ctrl.category || "Uncategorized";
    if (!acc[key]) acc[key] = [];
    acc[key].push(ctrl);
    return acc;
  }, {});

  if (controlsLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2 flex-wrap">
            <ShieldCheck className="h-4 w-4 text-muted-foreground" />
            Compliance Control Mappings
          </CardTitle>
          <Button
            size="sm"
            onClick={() => seedControls.mutate()}
            disabled={seedControls.isPending}
            data-testid="button-seed-controls"
          >
            {seedControls.isPending ? (
              <Loader2 className="h-4 w-4 mr-1 animate-spin" />
            ) : (
              <Database className="h-4 w-4 mr-1" />
            )}
            Seed Controls
          </Button>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-1.5">
            <label className="text-xs text-muted-foreground">Framework Filter</label>
            <Select value={frameworkFilter} onValueChange={setFrameworkFilter}>
              <SelectTrigger className="w-48" data-testid="select-framework-filter">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Frameworks</SelectItem>
                <SelectItem value="nist_csf">NIST CSF</SelectItem>
                <SelectItem value="iso_27001">ISO 27001</SelectItem>
                <SelectItem value="cis">CIS</SelectItem>
                <SelectItem value="soc2">SOC 2</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {Object.keys(groupedControls).length === 0 ? (
            <div className="text-center py-8 text-sm text-muted-foreground" data-testid="text-no-controls">
              No controls found. Click "Seed Controls" to load built-in compliance controls.
            </div>
          ) : (
            Object.entries(groupedControls).map(([category, categoryControls]) => (
              <div key={category} className="space-y-2" data-testid={`control-group-${category.toLowerCase().replace(/\s/g, "-")}`}>
                <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">{category}</h3>
                <div className="overflow-x-auto border rounded-md">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="text-xs">Framework</TableHead>
                        <TableHead className="text-xs">Control ID</TableHead>
                        <TableHead className="text-xs">Title</TableHead>
                        <TableHead className="text-xs">Description</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {categoryControls.map((ctrl) => (
                        <TableRow key={ctrl.id} data-testid={`row-control-${ctrl.id}`}>
                          <TableCell>
                            <Badge
                              variant="outline"
                              className={`no-default-hover-elevate no-default-active-elevate text-[10px] ${CONTROL_FRAMEWORK_COLORS[ctrl.framework] || ""}`}
                              data-testid={`badge-framework-${ctrl.id}`}
                            >
                              {CONTROL_FRAMEWORK_LABELS[ctrl.framework] || ctrl.framework}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            <span className="text-xs font-mono" data-testid={`text-control-id-${ctrl.id}`}>{ctrl.controlId}</span>
                          </TableCell>
                          <TableCell>
                            <span className="text-sm" data-testid={`text-control-title-${ctrl.id}`}>{ctrl.title}</span>
                          </TableCell>
                          <TableCell>
                            <span className="text-xs text-muted-foreground" data-testid={`text-control-desc-${ctrl.id}`}>
                              {ctrl.description || "—"}
                            </span>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              </div>
            ))
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2 flex-wrap">
            <ScrollText className="h-4 w-4 text-muted-foreground" />
            Control Mappings
          </CardTitle>
          <Dialog open={showAddMapping} onOpenChange={setShowAddMapping}>
            <DialogTrigger asChild>
              <Button size="sm" data-testid="button-add-mapping">
                <Plus className="h-4 w-4 mr-1" />
                Add Mapping
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Create Control Mapping</DialogTitle>
              </DialogHeader>
              <div className="space-y-4 py-2">
                <div className="space-y-1.5">
                  <label className="text-xs text-muted-foreground">Control</label>
                  <Select value={mappingControlId} onValueChange={setMappingControlId}>
                    <SelectTrigger data-testid="select-mapping-control">
                      <SelectValue placeholder="Select a control" />
                    </SelectTrigger>
                    <SelectContent>
                      {(controls || []).map((ctrl) => (
                        <SelectItem key={ctrl.id} value={ctrl.id}>
                          {ctrl.controlId} - {ctrl.title}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-1.5">
                  <label className="text-xs text-muted-foreground">Resource Type</label>
                  <Input
                    placeholder="e.g., server, application, policy"
                    value={mappingResourceType}
                    onChange={(e) => setMappingResourceType(e.target.value)}
                    data-testid="input-mapping-resource-type"
                  />
                </div>
                <div className="space-y-1.5">
                  <label className="text-xs text-muted-foreground">Resource ID</label>
                  <Input
                    placeholder="e.g., web-server-01"
                    value={mappingResourceId}
                    onChange={(e) => setMappingResourceId(e.target.value)}
                    data-testid="input-mapping-resource-id"
                  />
                </div>
                <div className="space-y-1.5">
                  <label className="text-xs text-muted-foreground">Status</label>
                  <Select value={mappingStatus} onValueChange={setMappingStatus}>
                    <SelectTrigger data-testid="select-mapping-status">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="compliant">Compliant</SelectItem>
                      <SelectItem value="non_compliant">Non-Compliant</SelectItem>
                      <SelectItem value="not_assessed">Not Assessed</SelectItem>
                      <SelectItem value="partial">Partial</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-1.5">
                  <label className="text-xs text-muted-foreground">Evidence Notes</label>
                  <Input
                    placeholder="Evidence or notes..."
                    value={mappingEvidenceNotes}
                    onChange={(e) => setMappingEvidenceNotes(e.target.value)}
                    data-testid="input-mapping-evidence"
                  />
                </div>
              </div>
              <DialogFooter>
                <DialogClose asChild>
                  <Button variant="outline" data-testid="button-cancel-mapping">Cancel</Button>
                </DialogClose>
                <Button
                  onClick={() => createMapping.mutate()}
                  disabled={!mappingControlId || !mappingResourceType || !mappingResourceId || createMapping.isPending}
                  data-testid="button-submit-mapping"
                >
                  {createMapping.isPending ? (
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  ) : (
                    <Plus className="h-4 w-4 mr-2" />
                  )}
                  Create Mapping
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </CardHeader>
        <CardContent>
          {mappingsLoading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : mappings && mappings.length > 0 ? (
            <div className="overflow-x-auto border rounded-md">
              <Table data-testid="table-mappings">
                <TableHeader>
                  <TableRow>
                    <TableHead className="text-xs">Control ID</TableHead>
                    <TableHead className="text-xs">Resource</TableHead>
                    <TableHead className="text-xs">Status</TableHead>
                    <TableHead className="text-xs">Evidence</TableHead>
                    <TableHead className="text-xs">Last Assessed</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {mappings.map((mapping) => (
                    <TableRow key={mapping.id} data-testid={`row-mapping-${mapping.id}`}>
                      <TableCell>
                        <span className="text-xs font-mono" data-testid={`text-mapping-control-${mapping.id}`}>
                          {mapping.controlId.slice(0, 8)}...
                        </span>
                      </TableCell>
                      <TableCell>
                        <span className="text-xs" data-testid={`text-mapping-resource-${mapping.id}`}>
                          {mapping.resourceType} / {mapping.resourceId}
                        </span>
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant="outline"
                          className={`no-default-hover-elevate no-default-active-elevate text-[10px] ${MAPPING_STATUS_COLORS[mapping.status] || ""}`}
                          data-testid={`badge-mapping-status-${mapping.id}`}
                        >
                          {mapping.status.replace(/_/g, " ")}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <span className="text-xs text-muted-foreground" data-testid={`text-mapping-evidence-${mapping.id}`}>
                          {mapping.evidenceNotes || "—"}
                        </span>
                      </TableCell>
                      <TableCell>
                        <span className="text-xs text-muted-foreground" data-testid={`text-mapping-assessed-${mapping.id}`}>
                          {formatDateTime(mapping.lastAssessedAt)}
                        </span>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          ) : (
            <div className="text-center py-8 text-sm text-muted-foreground" data-testid="text-no-mappings">
              No control mappings found. Add a mapping to track compliance status.
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function formatFileSize(bytes: number | null): string {
  if (bytes === null || bytes === undefined) return "—";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function EvidenceLockerTab() {
  const { toast } = useToast();
  const [frameworkFilter, setFrameworkFilter] = useState("all");
  const [artifactTypeFilter, setArtifactTypeFilter] = useState("all");
  const [showUpload, setShowUpload] = useState(false);
  const [newTitle, setNewTitle] = useState("");
  const [newDescription, setNewDescription] = useState("");
  const [newArtifactType, setNewArtifactType] = useState("screenshot");
  const [newFramework, setNewFramework] = useState("nist_csf");
  const [newControlId, setNewControlId] = useState("");
  const [newUrl, setNewUrl] = useState("");
  const [newRetentionDays, setNewRetentionDays] = useState<number>(365);
  const [newTags, setNewTags] = useState("");

  const evidenceQueryKey = ["/api/evidence-locker", { framework: frameworkFilter, artifactType: artifactTypeFilter }];

  const { data: evidenceItems, isLoading } = useQuery<EvidenceLockerItem[]>({
    queryKey: evidenceQueryKey,
    queryFn: async () => {
      const params = new URLSearchParams();
      if (frameworkFilter !== "all") params.set("framework", frameworkFilter);
      if (artifactTypeFilter !== "all") params.set("artifactType", artifactTypeFilter);
      const url = `/api/evidence-locker${params.toString() ? `?${params.toString()}` : ""}`;
      const res = await fetch(url, { credentials: "include" });
      if (!res.ok) throw new Error("Failed to fetch evidence");
      return res.json();
    },
  });

  const createEvidence = useMutation({
    mutationFn: async () => {
      const tags = newTags.split(",").map((t) => t.trim()).filter(Boolean);
      await apiRequest("POST", "/api/evidence-locker", {
        title: newTitle,
        description: newDescription || null,
        artifactType: newArtifactType,
        framework: newFramework,
        controlId: newControlId || null,
        url: newUrl || null,
        retentionDays: newRetentionDays,
        tags,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/evidence-locker"] });
      setShowUpload(false);
      setNewTitle("");
      setNewDescription("");
      setNewArtifactType("screenshot");
      setNewFramework("nist_csf");
      setNewControlId("");
      setNewUrl("");
      setNewRetentionDays(365);
      setNewTags("");
      toast({ title: "Evidence uploaded", description: "Evidence artifact has been added to the locker." });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to upload evidence", description: error.message, variant: "destructive" });
    },
  });

  const deleteEvidence = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("DELETE", `/api/evidence-locker/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/evidence-locker"] });
      toast({ title: "Evidence deleted", description: "Evidence artifact has been removed." });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to delete evidence", description: error.message, variant: "destructive" });
    },
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-3">
          <div>
            <CardTitle className="text-sm font-semibold flex items-center gap-2 flex-wrap">
              <Lock className="h-4 w-4 text-muted-foreground" />
              Evidence Locker
            </CardTitle>
            <p className="text-xs text-muted-foreground mt-1">Audit-ready artifacts for compliance evidence</p>
          </div>
          <Dialog open={showUpload} onOpenChange={setShowUpload}>
            <DialogTrigger asChild>
              <Button size="sm" data-testid="button-upload-evidence">
                <Upload className="h-4 w-4 mr-1" />
                Upload Evidence
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Upload Evidence</DialogTitle>
              </DialogHeader>
              <div className="space-y-4 py-2">
                <div className="space-y-1.5">
                  <label className="text-xs text-muted-foreground">Title</label>
                  <Input
                    placeholder="Evidence title"
                    value={newTitle}
                    onChange={(e) => setNewTitle(e.target.value)}
                    data-testid="input-evidence-title"
                  />
                </div>
                <div className="space-y-1.5">
                  <label className="text-xs text-muted-foreground">Description</label>
                  <Input
                    placeholder="Brief description..."
                    value={newDescription}
                    onChange={(e) => setNewDescription(e.target.value)}
                    data-testid="input-evidence-description"
                  />
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-1.5">
                    <label className="text-xs text-muted-foreground">Artifact Type</label>
                    <Select value={newArtifactType} onValueChange={setNewArtifactType}>
                      <SelectTrigger data-testid="select-evidence-artifact-type">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {Object.entries(ARTIFACT_TYPE_LABELS).map(([value, label]) => (
                          <SelectItem key={value} value={value}>{label}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-1.5">
                    <label className="text-xs text-muted-foreground">Framework</label>
                    <Select value={newFramework} onValueChange={setNewFramework}>
                      <SelectTrigger data-testid="select-evidence-framework">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="nist_csf">NIST CSF</SelectItem>
                        <SelectItem value="iso_27001">ISO 27001</SelectItem>
                        <SelectItem value="cis">CIS</SelectItem>
                        <SelectItem value="soc2">SOC 2</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>
                <div className="space-y-1.5">
                  <label className="text-xs text-muted-foreground">Control ID</label>
                  <Input
                    placeholder="e.g., PR.AC-1"
                    value={newControlId}
                    onChange={(e) => setNewControlId(e.target.value)}
                    data-testid="input-evidence-control-id"
                  />
                </div>
                <div className="space-y-1.5">
                  <label className="text-xs text-muted-foreground">URL</label>
                  <Input
                    placeholder="https://..."
                    value={newUrl}
                    onChange={(e) => setNewUrl(e.target.value)}
                    data-testid="input-evidence-url"
                  />
                </div>
                <div className="space-y-1.5">
                  <label className="text-xs text-muted-foreground">Retention Days</label>
                  <Input
                    type="number"
                    value={newRetentionDays}
                    onChange={(e) => setNewRetentionDays(Number(e.target.value))}
                    data-testid="input-evidence-retention-days"
                  />
                </div>
                <div className="space-y-1.5">
                  <label className="text-xs text-muted-foreground">Tags (comma-separated)</label>
                  <Input
                    placeholder="audit, q1-2026, access-control"
                    value={newTags}
                    onChange={(e) => setNewTags(e.target.value)}
                    data-testid="input-evidence-tags"
                  />
                </div>
              </div>
              <DialogFooter>
                <DialogClose asChild>
                  <Button variant="outline" data-testid="button-cancel-evidence">Cancel</Button>
                </DialogClose>
                <Button
                  onClick={() => createEvidence.mutate()}
                  disabled={!newTitle || createEvidence.isPending}
                  data-testid="button-submit-evidence"
                >
                  {createEvidence.isPending ? (
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  ) : (
                    <Upload className="h-4 w-4 mr-2" />
                  )}
                  Upload
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center gap-4 flex-wrap">
            <div className="space-y-1.5">
              <label className="text-xs text-muted-foreground">Framework</label>
              <Select value={frameworkFilter} onValueChange={setFrameworkFilter}>
                <SelectTrigger className="w-48" data-testid="select-evidence-framework-filter">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Frameworks</SelectItem>
                  <SelectItem value="nist_csf">NIST CSF</SelectItem>
                  <SelectItem value="iso_27001">ISO 27001</SelectItem>
                  <SelectItem value="cis">CIS</SelectItem>
                  <SelectItem value="soc2">SOC 2</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <label className="text-xs text-muted-foreground">Artifact Type</label>
              <Select value={artifactTypeFilter} onValueChange={setArtifactTypeFilter}>
                <SelectTrigger className="w-48" data-testid="select-evidence-artifact-type-filter">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Types</SelectItem>
                  {Object.entries(ARTIFACT_TYPE_LABELS).map(([value, label]) => (
                    <SelectItem key={value} value={value}>{label}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          {evidenceItems && evidenceItems.length > 0 ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {evidenceItems.map((item) => (
                <Card key={item.id} data-testid={`card-evidence-${item.id}`}>
                  <CardContent className="p-4 space-y-3">
                    <div className="flex items-start justify-between gap-2">
                      <div className="space-y-1 min-w-0 flex-1">
                        <div className="text-sm font-medium truncate" data-testid={`text-evidence-title-${item.id}`}>{item.title}</div>
                        {item.description && (
                          <div className="text-xs text-muted-foreground" data-testid={`text-evidence-desc-${item.id}`}>{item.description}</div>
                        )}
                      </div>
                      <Button
                        size="icon"
                        variant="ghost"
                        onClick={() => deleteEvidence.mutate(item.id)}
                        disabled={deleteEvidence.isPending && deleteEvidence.variables === item.id}
                        data-testid={`button-delete-evidence-${item.id}`}
                      >
                        {deleteEvidence.isPending && deleteEvidence.variables === item.id ? (
                          <Loader2 className="h-4 w-4 animate-spin" />
                        ) : (
                          <Trash2 className="h-4 w-4" />
                        )}
                      </Button>
                    </div>
                    <div className="flex items-center gap-2 flex-wrap">
                      <Badge
                        variant="outline"
                        className={`no-default-hover-elevate no-default-active-elevate text-[10px] ${ARTIFACT_TYPE_COLORS[item.artifactType] || ""}`}
                        data-testid={`badge-evidence-type-${item.id}`}
                      >
                        {ARTIFACT_TYPE_LABELS[item.artifactType] || item.artifactType}
                      </Badge>
                      {item.framework && (
                        <Badge
                          variant="outline"
                          className={`no-default-hover-elevate no-default-active-elevate text-[10px] ${CONTROL_FRAMEWORK_COLORS[item.framework] || ""}`}
                          data-testid={`badge-evidence-framework-${item.id}`}
                        >
                          {CONTROL_FRAMEWORK_LABELS[item.framework] || item.framework}
                        </Badge>
                      )}
                      <Badge
                        variant="outline"
                        className={`no-default-hover-elevate no-default-active-elevate text-[10px] ${EVIDENCE_STATUS_COLORS[item.status] || ""}`}
                        data-testid={`badge-evidence-status-${item.id}`}
                      >
                        {item.status}
                      </Badge>
                    </div>
                    <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs text-muted-foreground">
                      {item.controlId && (
                        <div data-testid={`text-evidence-control-${item.id}`}>
                          Control: <span className="font-mono">{item.controlId}</span>
                        </div>
                      )}
                      <div data-testid={`text-evidence-size-${item.id}`}>
                        Size: {formatFileSize(item.fileSize)}
                      </div>
                      {item.checksum && (
                        <div className="truncate" data-testid={`text-evidence-checksum-${item.id}`}>
                          Checksum: <span className="font-mono">{item.checksum.slice(0, 12)}...</span>
                        </div>
                      )}
                      <div data-testid={`text-evidence-retention-${item.id}`}>
                        Retention: {item.retentionDays} days
                      </div>
                      {item.expiresAt && (
                        <div data-testid={`text-evidence-expiry-${item.id}`}>
                          Expires: {formatDate(item.expiresAt)}
                        </div>
                      )}
                      {item.uploadedByName && (
                        <div data-testid={`text-evidence-uploader-${item.id}`}>
                          By: {item.uploadedByName}
                        </div>
                      )}
                      <div data-testid={`text-evidence-created-${item.id}`}>
                        Created: {formatDate(item.createdAt)}
                      </div>
                    </div>
                    {item.tags && item.tags.length > 0 && (
                      <div className="flex items-center gap-1 flex-wrap" data-testid={`tags-evidence-${item.id}`}>
                        {item.tags.map((tag) => (
                          <Badge key={tag} variant="outline" className="no-default-hover-elevate no-default-active-elevate text-[10px]">
                            {tag}
                          </Badge>
                        ))}
                      </div>
                    )}
                  </CardContent>
                </Card>
              ))}
            </div>
          ) : (
            <div className="text-center py-8 text-sm text-muted-foreground" data-testid="text-no-evidence">
              <FileText className="h-8 w-8 mx-auto mb-2 text-muted-foreground/50" />
              No evidence artifacts found. Upload evidence to get started.
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

interface LegalHold {
  id: string;
  orgId: string | null;
  name: string;
  description: string | null;
  holdType: string;
  tableScope: string[];
  filterCriteria: any;
  reason: string | null;
  caseReference: string | null;
  isActive: boolean;
  activatedByName: string | null;
  deactivatedBy: string | null;
  deactivatedAt: string | null;
  activatedAt: string;
  createdAt: string;
}

function LegalHoldsTab() {
  const [showCreate, setShowCreate] = useState(false);
  const [newName, setNewName] = useState("");
  const [newDescription, setNewDescription] = useState("");
  const [newReason, setNewReason] = useState("");
  const [newCaseRef, setNewCaseRef] = useState("");
  const [newHoldType, setNewHoldType] = useState("full");
  const [newTableScope, setNewTableScope] = useState(["alerts", "incidents", "audit_logs"]);
  const { toast } = useToast();

  const { data: holds, isLoading } = useQuery<LegalHold[]>({
    queryKey: ["/api/legal-holds"],
  });

  const createMutation = useMutation({
    mutationFn: async () => {
      const res = await fetch("/api/legal-holds", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          name: newName, description: newDescription, reason: newReason,
          caseReference: newCaseRef, holdType: newHoldType, tableScope: newTableScope,
        }),
      });
      if (!res.ok) throw new Error("Failed to create legal hold");
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/legal-holds"] });
      setShowCreate(false);
      setNewName(""); setNewDescription(""); setNewReason(""); setNewCaseRef("");
      toast({ title: "Legal hold created" });
    },
  });

  const deactivateMutation = useMutation({
    mutationFn: async (id: string) => {
      const res = await fetch(`/api/legal-holds/${id}/deactivate`, {
        method: "POST", credentials: "include",
      });
      if (!res.ok) throw new Error("Failed to deactivate");
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/legal-holds"] });
      toast({ title: "Legal hold deactivated" });
    },
  });

  const toggleScope = (table: string) => {
    setNewTableScope(prev =>
      prev.includes(table) ? prev.filter(t => t !== table) : [...prev, table]
    );
  };

  if (isLoading) return <div className="flex items-center justify-center py-12"><Loader2 className="h-6 w-6 animate-spin text-muted-foreground" /></div>;

  const activeHolds = (holds || []).filter(h => h.isActive);
  const inactiveHolds = (holds || []).filter(h => !h.isActive);

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Gavel className="h-4 w-4 text-muted-foreground" />
            Legal Holds
            {activeHolds.length > 0 && (
              <Badge variant="default" className="border-yellow-500/30 text-yellow-400 ml-2">
                {activeHolds.length} Active
              </Badge>
            )}
          </CardTitle>
          <Button size="sm" onClick={() => setShowCreate(true)}>
            <Plus className="h-3.5 w-3.5 mr-1.5" />New Hold
          </Button>
        </CardHeader>
        <CardContent>
          {!holds?.length ? (
            <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
              <Gavel className="h-10 w-10 mb-3" />
              <p className="text-sm">No legal holds configured</p>
              <p className="text-xs mt-1">Legal holds prevent data from being deleted by retention policies</p>
            </div>
          ) : (
            <div className="space-y-3">
              {activeHolds.length > 0 && (
                <div>
                  <h4 className="text-xs font-semibold text-muted-foreground mb-2 uppercase tracking-wider">Active Holds</h4>
                  <div className="space-y-2">
                    {activeHolds.map(hold => (
                      <div key={hold.id} className="border rounded-md p-3 bg-yellow-500/5 border-yellow-500/20">
                        <div className="flex items-center justify-between">
                          <div>
                            <div className="flex items-center gap-2">
                              <span className="text-sm font-medium">{hold.name}</span>
                              <Badge variant="outline" className="no-default-hover-elevate no-default-active-elevate text-[10px]">{hold.holdType}</Badge>
                            </div>
                            {hold.description && <p className="text-xs text-muted-foreground mt-1">{hold.description}</p>}
                            <div className="flex gap-2 mt-1 flex-wrap">
                              {(hold.tableScope || []).map(t => (
                                <Badge key={t} variant="secondary" className="text-[10px]"><Database className="h-2.5 w-2.5 mr-1" />{t}</Badge>
                              ))}
                            </div>
                            <div className="flex gap-3 mt-1.5 text-xs text-muted-foreground">
                              {hold.reason && <span>Reason: {hold.reason}</span>}
                              {hold.caseReference && <span>Case: {hold.caseReference}</span>}
                              <span>Activated: {formatDateTime(hold.activatedAt)}</span>
                              {hold.activatedByName && <span>By: {hold.activatedByName}</span>}
                            </div>
                          </div>
                          <Button size="sm" variant="outline" className="text-red-400 h-7 px-2" onClick={() => deactivateMutation.mutate(hold.id)} disabled={deactivateMutation.isPending}>
                            <Ban className="h-3 w-3 mr-1" />Deactivate
                          </Button>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
              {inactiveHolds.length > 0 && (
                <div>
                  <h4 className="text-xs font-semibold text-muted-foreground mb-2 uppercase tracking-wider">Inactive Holds</h4>
                  <div className="space-y-2">
                    {inactiveHolds.map(hold => (
                      <div key={hold.id} className="border rounded-md p-3 opacity-60">
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-medium line-through">{hold.name}</span>
                          <Badge variant="secondary" className="text-[10px]">Deactivated</Badge>
                        </div>
                        <div className="text-xs text-muted-foreground mt-1">
                          Deactivated: {formatDateTime(hold.deactivatedAt)} | Originally for: {(hold.tableScope || []).join(", ")}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      <Dialog open={showCreate} onOpenChange={setShowCreate}>
        <DialogContent>
          <DialogHeader><DialogTitle>Create Legal Hold</DialogTitle></DialogHeader>
          <div className="space-y-3">
            <div>
              <Label className="text-xs">Name</Label>
              <Input value={newName} onChange={e => setNewName(e.target.value)} placeholder="e.g. SEC Investigation Q1 2026" />
            </div>
            <div>
              <Label className="text-xs">Description</Label>
              <Input value={newDescription} onChange={e => setNewDescription(e.target.value)} placeholder="Brief description of the hold" />
            </div>
            <div>
              <Label className="text-xs">Hold Type</Label>
              <Select value={newHoldType} onValueChange={setNewHoldType}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="full">Full (all data)</SelectItem>
                  <SelectItem value="partial">Partial (scoped to tables)</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label className="text-xs">Table Scope</Label>
              <div className="flex gap-2 flex-wrap mt-1">
                {["alerts", "incidents", "audit_logs", "entities", "ioc_entries"].map(table => (
                  <Button key={table} size="sm" variant={newTableScope.includes(table) ? "default" : "outline"}
                    className="h-7 text-[10px]" onClick={() => toggleScope(table)}>
                    {table}
                  </Button>
                ))}
              </div>
            </div>
            <div>
              <Label className="text-xs">Reason</Label>
              <Input value={newReason} onChange={e => setNewReason(e.target.value)} placeholder="Legal or regulatory reason" />
            </div>
            <div>
              <Label className="text-xs">Case Reference</Label>
              <Input value={newCaseRef} onChange={e => setNewCaseRef(e.target.value)} placeholder="e.g. CASE-2026-001" />
            </div>
          </div>
          <DialogFooter>
            <DialogClose asChild><Button variant="outline">Cancel</Button></DialogClose>
            <Button onClick={() => createMutation.mutate()} disabled={!newName || createMutation.isPending}>
              {createMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : null}
              Activate Hold
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

export default function CompliancePage() {
  return (
    <div className="p-4 md:p-6 space-y-6 max-w-7xl mx-auto" role="main" aria-label="Compliance & Governance" data-testid="page-compliance">
      <div>
        <h1 className="text-2xl font-bold tracking-tight" data-testid="text-page-title">
          <span className="gradient-text-red">Compliance & Governance</span>
        </h1>
        <p className="text-sm text-muted-foreground mt-1" data-testid="text-page-description">
          Data governance, privacy controls, legal holds, and regulatory compliance management
        </p>
        <div className="gradient-accent-line w-24 mt-2" />
      </div>

      <Tabs defaultValue="policies" data-testid="tabs-compliance">
        <TabsList className="flex-wrap" data-testid="tabs-list">
          <TabsTrigger value="policies" data-testid="tab-policies">
            <Scale className="h-3.5 w-3.5 mr-1.5" aria-hidden="true" />
            Policies
          </TabsTrigger>
          <TabsTrigger value="dsar" data-testid="tab-dsar">
            <Users className="h-3.5 w-3.5 mr-1.5" aria-hidden="true" />
            DSAR
          </TabsTrigger>
          <TabsTrigger value="legal-holds" data-testid="tab-legal-holds">
            <Gavel className="h-3.5 w-3.5 mr-1.5" aria-hidden="true" />
            Legal Holds
          </TabsTrigger>
          <TabsTrigger value="reports" data-testid="tab-reports">
            <FileText className="h-3.5 w-3.5 mr-1.5" aria-hidden="true" />
            Reports
          </TabsTrigger>
          <TabsTrigger value="audit-integrity" data-testid="tab-audit-integrity">
            <Hash className="h-3.5 w-3.5 mr-1.5" aria-hidden="true" />
            Audit Integrity
          </TabsTrigger>
          <TabsTrigger value="retention" data-testid="tab-retention">
            <Clock className="h-3.5 w-3.5 mr-1.5" aria-hidden="true" />
            Retention
          </TabsTrigger>
          <TabsTrigger value="controls" data-testid="tab-controls">
            <ShieldCheck className="h-3.5 w-3.5 mr-1.5" aria-hidden="true" />
            Controls
          </TabsTrigger>
          <TabsTrigger value="evidence-locker" data-testid="tab-evidence-locker">
            <Lock className="h-3.5 w-3.5 mr-1.5" aria-hidden="true" />
            Evidence Locker
          </TabsTrigger>
        </TabsList>

        <TabsContent value="policies">
          <PoliciesTab />
        </TabsContent>
        <TabsContent value="dsar">
          <DsarTab />
        </TabsContent>
        <TabsContent value="legal-holds">
          <LegalHoldsTab />
        </TabsContent>
        <TabsContent value="reports">
          <ReportsTab />
        </TabsContent>
        <TabsContent value="audit-integrity">
          <AuditIntegrityTab />
        </TabsContent>
        <TabsContent value="retention">
          <RetentionTab />
        </TabsContent>
        <TabsContent value="controls">
          <ControlsTab />
        </TabsContent>
        <TabsContent value="evidence-locker">
          <EvidenceLockerTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}

import { useState, useMemo } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { usePageTitle } from "@/hooks/use-page-title";
import { useToast } from "@/hooks/use-toast";
import {
  Link2,
  Plus,
  Shield,
  ShieldCheck,
  ShieldAlert,
  Lock,
  Unlock,
  FileText,
  Camera,
  HardDrive,
  Globe,
  Package,
  Database,
  ArrowRight,
  CheckCircle2,
  XCircle,
  Loader2,
  Eye,
  Search,
  Download,
  Copy,
  Tag,
  AlertTriangle,
  Clock,
  User,
  Hash,
  Columns,
  RefreshCw,
  ChevronRight,
  FileImage,
  FileCode,
  Binary,
  ScrollText,
  Send,
  MessageSquare,
  Trash2,
  Filter,
  Activity,
} from "lucide-react";
import { SuccessIcon } from "@/components/ui/animated-state-icons";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";

// ─── Types ──────────────────────────────────────────────────────────────────

interface AccessRequest {
  id: string;
  evidenceId: string;
  requestedBy: string;
  requestedAt: string;
  reason: string;
  accessType: string;
  status: string;
  decidedBy: string | null;
  decidedAt: string | null;
  decisionNote: string | null;
}

interface AccessLogEntry {
  id: string;
  evidenceId: string;
  action: string;
  actor: string;
  ip: string;
  timestamp: string;
  userAgent: string;
  metadata: Record<string, unknown>;
}

interface EvidencePreview {
  evidenceId: string;
  previewType: string;
  content: string;
  mimeType: string;
  sizeBytes: number;
  truncated: boolean;
}

interface CoCReport {
  exportedAt: string;
  exportedBy: string;
  evidence: any;
  chainOfCustody: any[];
  integrityVerification: any;
  accessLog: any[];
  tags: any[];
  files: any[];
  legalNotice: string;
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function formatTimestamp(ts: string | null): string {
  if (!ts) return "\u2014";
  return new Date(ts).toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function truncateHash(hash: string | null): string {
  if (!hash) return "\u2014";
  if (hash === "GENESIS" || hash === "genesis") return "GENESIS";
  return `${hash.slice(0, 8)}\u2026${hash.slice(-6)}`;
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
}

// ─── 19.1 Evidence Preview Panel ────────────────────────────────────────────

function EvidencePreviewPanel({ evidenceId }: { evidenceId: string }) {
  const {
    data: preview,
    isLoading,
    refetch,
  } = useQuery<EvidencePreview>({
    queryKey: ["/api/evidence-custody", evidenceId, "preview"],
    queryFn: async () => {
      const r = await apiRequest("GET", `/api/evidence-custody/${evidenceId}/preview`);
      return r.json();
    },
  });

  if (isLoading) {
    return (
      <Card>
        <CardContent className="p-4">
          <Skeleton className="h-40" />
        </CardContent>
      </Card>
    );
  }

  if (!preview) {
    return (
      <Card>
        <CardContent className="p-4 text-center text-xs text-muted-foreground">No preview available</CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm flex items-center gap-2">
            {preview.previewType === "image" && <FileImage className="h-4 w-4 text-purple-400" />}
            {preview.previewType === "json" && <FileCode className="h-4 w-4 text-blue-400" />}
            {preview.previewType === "hex" && <Binary className="h-4 w-4 text-orange-400" />}
            {preview.previewType === "text" && <ScrollText className="h-4 w-4 text-cyan-400" />}
            Evidence Preview
          </CardTitle>
          <div className="flex items-center gap-1">
            <Badge variant="outline" className="text-[10px]">
              {preview.previewType.toUpperCase()}
            </Badge>
            {preview.truncated && (
              <Badge variant="secondary" className="text-[10px]">
                Truncated
              </Badge>
            )}
            <Button size="sm" variant="ghost" className="h-6 w-6 p-0" onClick={() => refetch()}>
              <RefreshCw className="h-3 w-3" />
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        {preview.previewType === "image" ? (
          <div className="flex items-center justify-center bg-muted/20 rounded p-4">
            <img src={preview.content} alt="Evidence preview" className="max-w-full max-h-64 rounded" />
          </div>
        ) : preview.previewType === "hex" ? (
          <ScrollArea className="h-48">
            <pre className="text-[10px] font-mono text-emerald-400 bg-black/40 p-3 rounded leading-relaxed whitespace-pre overflow-x-auto">
              {preview.content}
            </pre>
          </ScrollArea>
        ) : preview.previewType === "json" ? (
          <ScrollArea className="h-48">
            <pre className="text-[10px] font-mono text-foreground/80 bg-muted/20 p-3 rounded leading-relaxed whitespace-pre overflow-x-auto">
              {preview.content}
            </pre>
          </ScrollArea>
        ) : (
          <ScrollArea className="h-48">
            <pre className="text-xs font-mono text-foreground/80 bg-muted/20 p-3 rounded leading-relaxed whitespace-pre-wrap">
              {preview.content}
            </pre>
          </ScrollArea>
        )}
        <div className="flex items-center gap-3 mt-2 text-[10px] text-muted-foreground">
          <span>{formatBytes(preview.sizeBytes)}</span>
          <span>{preview.mimeType}</span>
        </div>
      </CardContent>
    </Card>
  );
}

// ─── 19.2 Access Request Workflow ───────────────────────────────────────────

function AccessRequestPanel({ evidenceId, classification }: { evidenceId: string; classification: string }) {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [showRequest, setShowRequest] = useState(false);
  const [reason, setReason] = useState("");
  const [accessType, setAccessType] = useState("view");
  const [decisionNote, setDecisionNote] = useState("");

  const { data: requestsData } = useQuery<AccessRequest[]>({
    queryKey: ["/api/evidence-custody", evidenceId, "access-requests"],
    queryFn: async () => {
      const r = await apiRequest("GET", `/api/evidence-custody/${evidenceId}/access-requests`);
      const d = await r.json();
      return Array.isArray(d) ? d : (d as any)?.data || [];
    },
  });

  const requestMutation = useMutation({
    mutationFn: async (data: { reason: string; accessType: string }) => {
      const r = await apiRequest("POST", `/api/evidence-custody/${evidenceId}/access-requests`, data);
      return r.json();
    },
    onSuccess: () => {
      toast({ title: "Access request submitted" });
      queryClient.invalidateQueries({ queryKey: ["/api/evidence-custody", evidenceId, "access-requests"] });
      setShowRequest(false);
      setReason("");
    },
    onError: () => toast({ title: "Failed to submit request", variant: "destructive" }),
  });

  const decideMutation = useMutation({
    mutationFn: async ({ requestId, decision, note }: { requestId: string; decision: string; note: string }) => {
      const r = await apiRequest("POST", `/api/evidence-custody/${evidenceId}/access-requests/${requestId}/decide`, {
        decision,
        note,
      });
      return r.json();
    },
    onSuccess: () => {
      toast({ title: "Decision recorded" });
      queryClient.invalidateQueries({ queryKey: ["/api/evidence-custody", evidenceId, "access-requests"] });
      setDecisionNote("");
    },
    onError: () => toast({ title: "Failed to record decision", variant: "destructive" }),
  });

  const requests = requestsData || [];
  const needsApproval = classification === "confidential" || classification === "restricted";

  return (
    <Card className={needsApproval ? "border-yellow-500/20" : ""}>
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm flex items-center gap-2">
            <Shield className="h-4 w-4 text-yellow-400" />
            Access Control
            {needsApproval && (
              <Badge variant="outline" className="text-[10px] border-yellow-500/40 text-yellow-400">
                Approval Required
              </Badge>
            )}
          </CardTitle>
          <Button size="sm" variant="outline" className="h-7 text-xs" onClick={() => setShowRequest(true)}>
            <Send className="h-3 w-3 mr-1" />
            Request Access
          </Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        {showRequest && (
          <div className="p-3 bg-muted/20 rounded border border-border space-y-2">
            <Label className="text-xs">Reason for access</Label>
            <Textarea
              placeholder="Explain why you need access to this evidence..."
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              className="text-xs resize-none"
              rows={2}
            />
            <div className="flex items-center gap-2">
              <Select value={accessType} onValueChange={setAccessType}>
                <SelectTrigger className="h-7 w-32 text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="view" className="text-xs">
                    View
                  </SelectItem>
                  <SelectItem value="download" className="text-xs">
                    Download
                  </SelectItem>
                  <SelectItem value="analyze" className="text-xs">
                    Analyze
                  </SelectItem>
                  <SelectItem value="export" className="text-xs">
                    Export
                  </SelectItem>
                </SelectContent>
              </Select>
              <Button
                size="sm"
                className="h-7 text-xs"
                onClick={() => requestMutation.mutate({ reason, accessType })}
                disabled={!reason || requestMutation.isPending}
              >
                {requestMutation.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : "Submit"}
              </Button>
              <Button size="sm" variant="ghost" className="h-7 text-xs" onClick={() => setShowRequest(false)}>
                Cancel
              </Button>
            </div>
          </div>
        )}

        {requests.length === 0 ? (
          <p className="text-xs text-muted-foreground py-2">No access requests</p>
        ) : (
          <div className="space-y-2">
            {requests.map((req) => (
              <div key={req.id} className="p-2 bg-muted/10 rounded border border-border">
                <div className="flex items-center gap-2 mb-1 flex-wrap">
                  <Badge
                    variant={
                      req.status === "approved" ? "default" : req.status === "denied" ? "destructive" : "secondary"
                    }
                    className="text-[10px]"
                  >
                    {req.status}
                  </Badge>
                  <span className="text-[10px] text-muted-foreground flex items-center gap-0.5">
                    <User className="h-2.5 w-2.5" />
                    {req.requestedBy}
                  </span>
                  <Badge variant="outline" className="text-[10px]">
                    {req.accessType}
                  </Badge>
                  <span className="text-[10px] text-muted-foreground">{formatTimestamp(req.requestedAt)}</span>
                </div>
                <p className="text-xs text-foreground/70 mb-1">{req.reason}</p>
                {req.status === "pending" && (
                  <div className="flex items-center gap-2 mt-2">
                    <Input
                      placeholder="Decision note..."
                      value={decisionNote}
                      onChange={(e) => setDecisionNote(e.target.value)}
                      className="h-6 text-[10px] flex-1"
                    />
                    <Button
                      size="sm"
                      className="h-6 text-[10px] bg-emerald-600 hover:bg-emerald-700"
                      onClick={() =>
                        decideMutation.mutate({ requestId: req.id, decision: "approved", note: decisionNote })
                      }
                      disabled={decideMutation.isPending}
                    >
                      Approve
                    </Button>
                    <Button
                      size="sm"
                      variant="destructive"
                      className="h-6 text-[10px]"
                      onClick={() =>
                        decideMutation.mutate({ requestId: req.id, decision: "denied", note: decisionNote })
                      }
                      disabled={decideMutation.isPending}
                    >
                      Deny
                    </Button>
                  </div>
                )}
                {req.decidedBy && (
                  <div className="text-[10px] text-muted-foreground mt-1">
                    Decided by {req.decidedBy} at {formatTimestamp(req.decidedAt)}
                    {req.decisionNote && <span className="italic"> \u2014 {req.decisionNote}</span>}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ─── 19.3 Evidence Comparison ───────────────────────────────────────────────

function EvidenceComparisonDialog({
  open,
  onClose,
  evidenceList,
}: {
  open: boolean;
  onClose: () => void;
  evidenceList: any[];
}) {
  const [leftId, setLeftId] = useState("");
  const [rightId, setRightId] = useState("");

  const { data: leftDetail } = useQuery({
    queryKey: ["/api/evidence-custody", leftId, "compare"],
    queryFn: async () => {
      const r = await apiRequest("GET", `/api/evidence-custody/${leftId}`);
      return r.json();
    },
    enabled: !!leftId,
  });

  const { data: rightDetail } = useQuery({
    queryKey: ["/api/evidence-custody", rightId, "compare"],
    queryFn: async () => {
      const r = await apiRequest("GET", `/api/evidence-custody/${rightId}`);
      return r.json();
    },
    enabled: !!rightId,
  });

  const left = leftDetail as any;
  const right = rightDetail as any;

  const compareFields = [
    { key: "name", label: "Name" },
    { key: "type", label: "Type" },
    { key: "sourceSystem", label: "Source" },
    { key: "classification", label: "Classification" },
    { key: "caseId", label: "Case ID" },
    { key: "collectedBy", label: "Collected By" },
    { key: "collectedAt", label: "Collected At" },
    { key: "sha256Hash", label: "SHA-256" },
    { key: "sizeBytes", label: "Size" },
    { key: "isSealed", label: "Sealed" },
  ];

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-4xl max-h-[80vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Columns className="h-5 w-5 text-blue-400" />
            Evidence Comparison
          </DialogTitle>
          <DialogDescription>Side-by-side comparison of two evidence items</DialogDescription>
        </DialogHeader>

        <div className="grid grid-cols-2 gap-4 mb-4">
          <div>
            <Label className="text-xs mb-1 block">Left Evidence</Label>
            <Select value={leftId} onValueChange={setLeftId}>
              <SelectTrigger className="h-8 text-xs">
                <SelectValue placeholder="Select evidence..." />
              </SelectTrigger>
              <SelectContent>
                {evidenceList.map((e: any) => (
                  <SelectItem key={e.id} value={e.id} className="text-xs">
                    {e.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div>
            <Label className="text-xs mb-1 block">Right Evidence</Label>
            <Select value={rightId} onValueChange={setRightId}>
              <SelectTrigger className="h-8 text-xs">
                <SelectValue placeholder="Select evidence..." />
              </SelectTrigger>
              <SelectContent>
                {evidenceList.map((e: any) => (
                  <SelectItem key={e.id} value={e.id} className="text-xs">
                    {e.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>

        {left && right && (
          <div className="space-y-1">
            {compareFields.map(({ key, label }) => {
              const lVal = String(left[key] ?? "\u2014");
              const rVal = String(right[key] ?? "\u2014");
              const isDiff = lVal !== rVal;
              return (
                <div
                  key={key}
                  className={`grid grid-cols-[120px_1fr_1fr] gap-2 p-2 rounded text-xs ${isDiff ? "bg-yellow-500/5 border border-yellow-500/20" : "bg-muted/10"}`}
                >
                  <span className="text-muted-foreground font-medium">{label}</span>
                  <span className={`font-mono truncate ${isDiff ? "text-red-400" : ""}`}>
                    {key === "sizeBytes" ? formatBytes(Number(lVal)) : key === "sha256Hash" ? truncateHash(lVal) : lVal}
                  </span>
                  <span className={`font-mono truncate ${isDiff ? "text-emerald-400" : ""}`}>
                    {key === "sizeBytes" ? formatBytes(Number(rVal)) : key === "sha256Hash" ? truncateHash(rVal) : rVal}
                  </span>
                </div>
              );
            })}
            <Separator className="my-3" />
            <div className="grid grid-cols-2 gap-4 text-xs">
              <div>
                <h4 className="font-semibold mb-1">Custody Chain ({(left.integrityChain || []).length} entries)</h4>
                {(left.integrityChain || []).slice(0, 5).map((e: any, i: number) => (
                  <div key={i} className="text-[10px] text-muted-foreground py-0.5">
                    {e.action} by {e.actor} \u2014 {formatTimestamp(e.timestamp)}
                  </div>
                ))}
              </div>
              <div>
                <h4 className="font-semibold mb-1">Custody Chain ({(right.integrityChain || []).length} entries)</h4>
                {(right.integrityChain || []).slice(0, 5).map((e: any, i: number) => (
                  <div key={i} className="text-[10px] text-muted-foreground py-0.5">
                    {e.action} by {e.actor} \u2014 {formatTimestamp(e.timestamp)}
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            Close
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── 19.4 Access Audit Log Panel ────────────────────────────────────────────

function AccessAuditLogPanel({ evidenceId }: { evidenceId: string }) {
  const { data: logData, isLoading } = useQuery<AccessLogEntry[]>({
    queryKey: ["/api/evidence-custody", evidenceId, "access-log"],
    queryFn: async () => {
      const r = await apiRequest("GET", `/api/evidence-custody/${evidenceId}/access-log`);
      const d = await r.json();
      return Array.isArray(d) ? d : (d as any)?.data || [];
    },
  });

  const entries = logData || [];

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm flex items-center gap-2">
          <Activity className="h-4 w-4 text-cyan-400" />
          Access Audit Log ({entries.length})
        </CardTitle>
        <CardDescription className="text-[10px]">
          Every access to this evidence is logged for legal admissibility
        </CardDescription>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="space-y-2">
            {[1, 2, 3].map((i) => (
              <Skeleton key={i} className="h-6" />
            ))}
          </div>
        ) : entries.length === 0 ? (
          <p className="text-xs text-muted-foreground py-2">No access records</p>
        ) : (
          <ScrollArea className="h-48">
            <div className="space-y-1">
              {entries.map((entry) => (
                <div key={entry.id} className="flex items-center gap-2 p-1.5 bg-muted/10 rounded text-[10px]">
                  <Badge variant="outline" className="text-[9px] shrink-0">
                    {entry.action}
                  </Badge>
                  <span className="text-muted-foreground flex items-center gap-0.5">
                    <User className="h-2 w-2" />
                    {entry.actor}
                  </span>
                  <span className="text-muted-foreground">{entry.ip}</span>
                  <span className="text-muted-foreground ml-auto">{formatTimestamp(entry.timestamp)}</span>
                </div>
              ))}
            </div>
          </ScrollArea>
        )}
      </CardContent>
    </Card>
  );
}

// ─── 19.5 Evidence Export with CoC Report ───────────────────────────────────

function EvidenceExportPanel({ evidenceId }: { evidenceId: string }) {
  const { toast } = useToast();
  const [showReport, setShowReport] = useState(false);

  const {
    data: report,
    refetch: fetchReport,
    isFetching,
  } = useQuery<CoCReport>({
    queryKey: ["/api/evidence-custody", evidenceId, "export"],
    queryFn: async () => {
      const r = await apiRequest("GET", `/api/evidence-custody/${evidenceId}/export`);
      return r.json();
    },
    enabled: false,
  });

  const handleExport = async (format: string) => {
    if (format === "json") {
      const result = await fetchReport();
      if (result.data) {
        const blob = new Blob([JSON.stringify(result.data, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `coc-report-${evidenceId}.json`;
        a.click();
        URL.revokeObjectURL(url);
        toast({ title: "CoC report exported (JSON)" });
      }
    } else if (format === "csv") {
      try {
        const r = await apiRequest("GET", `/api/evidence-custody/${evidenceId}/export?format=csv`);
        const text = await r.text();
        const blob = new Blob([text], { type: "text/csv" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `coc-report-${evidenceId}.csv`;
        a.click();
        URL.revokeObjectURL(url);
        toast({ title: "CoC report exported (CSV)" });
      } catch {
        toast({ title: "Export failed", variant: "destructive" });
      }
    } else {
      const result = await fetchReport();
      if (result.data) {
        setShowReport(true);
      }
    }
  };

  return (
    <>
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm flex items-center gap-2">
            <Download className="h-4 w-4 text-emerald-400" />
            Chain of Custody Export
          </CardTitle>
          <CardDescription className="text-[10px]">
            Export evidence with full chain of custody report for court submissions
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap gap-2">
            <Button
              size="sm"
              variant="outline"
              className="h-7 text-xs"
              onClick={() => handleExport("json")}
              disabled={isFetching}
            >
              {isFetching ? <Loader2 className="h-3 w-3 animate-spin mr-1" /> : <FileCode className="h-3 w-3 mr-1" />}
              Export JSON
            </Button>
            <Button
              size="sm"
              variant="outline"
              className="h-7 text-xs"
              onClick={() => handleExport("csv")}
              disabled={isFetching}
            >
              <ScrollText className="h-3 w-3 mr-1" />
              Export CSV
            </Button>
            <Button
              size="sm"
              variant="outline"
              className="h-7 text-xs"
              onClick={() => handleExport("preview")}
              disabled={isFetching}
            >
              <Eye className="h-3 w-3 mr-1" />
              Preview Report
            </Button>
          </div>
        </CardContent>
      </Card>

      <Dialog open={showReport} onOpenChange={setShowReport}>
        <DialogContent className="max-w-3xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Chain of Custody Report</DialogTitle>
            <DialogDescription>Official report for legal proceedings</DialogDescription>
          </DialogHeader>
          {report && (
            <div className="space-y-4 text-xs">
              <div className="p-3 bg-red-500/5 border border-red-500/20 rounded">
                <p className="text-red-400 font-semibold text-[10px]">LEGAL NOTICE</p>
                <p className="text-[10px] text-muted-foreground mt-1">{report.legalNotice}</p>
              </div>

              <div className="grid grid-cols-2 gap-2">
                <div>
                  <span className="text-muted-foreground">Evidence ID:</span> {report.evidence?.id}
                </div>
                <div>
                  <span className="text-muted-foreground">Name:</span> {report.evidence?.name}
                </div>
                <div>
                  <span className="text-muted-foreground">Type:</span> {report.evidence?.type}
                </div>
                <div>
                  <span className="text-muted-foreground">Classification:</span> {report.evidence?.classification}
                </div>
                <div>
                  <span className="text-muted-foreground">Case:</span> {report.evidence?.caseId}
                </div>
                <div>
                  <span className="text-muted-foreground">Sealed:</span> {report.evidence?.isSealed ? "Yes" : "No"}
                </div>
                <div className="col-span-2">
                  <span className="text-muted-foreground">SHA-256:</span>{" "}
                  <code className="font-mono text-[10px]">{report.evidence?.sha256Hash}</code>
                </div>
              </div>

              <Separator />

              <div>
                <h4 className="font-semibold mb-2">Integrity Verification</h4>
                <div className="flex items-center gap-2">
                  {report.integrityVerification?.chainValid ? (
                    <SuccessIcon size={16} color="#22c55e" />
                  ) : (
                    <XCircle className="h-4 w-4 text-red-400" />
                  )}
                  <span>{report.integrityVerification?.chainValid ? "Chain Valid" : "Chain Broken"}</span>
                  <span className="text-muted-foreground">
                    ({report.integrityVerification?.totalEntries} entries, verified{" "}
                    {formatTimestamp(report.integrityVerification?.verifiedAt)})
                  </span>
                </div>
              </div>

              <Separator />

              <div>
                <h4 className="font-semibold mb-2">Chain of Custody ({report.chainOfCustody?.length || 0} entries)</h4>
                <div className="space-y-1">
                  {(report.chainOfCustody || []).map((entry: any, i: number) => (
                    <div
                      key={i}
                      className="grid grid-cols-[80px_100px_1fr_120px] gap-2 p-1.5 bg-muted/10 rounded text-[10px]"
                    >
                      <Badge variant="outline" className="text-[9px] justify-center">
                        {entry.action}
                      </Badge>
                      <span>{entry.actor}</span>
                      <span className="text-muted-foreground truncate font-mono">{truncateHash(entry.entryHash)}</span>
                      <span className="text-muted-foreground">{formatTimestamp(entry.timestamp)}</span>
                    </div>
                  ))}
                </div>
              </div>

              {report.accessLog && report.accessLog.length > 0 && (
                <>
                  <Separator />
                  <div>
                    <h4 className="font-semibold mb-2">Access Log ({report.accessLog.length} entries)</h4>
                    <div className="space-y-1">
                      {report.accessLog.map((entry: any, i: number) => (
                        <div
                          key={i}
                          className="grid grid-cols-[80px_100px_120px_1fr] gap-2 p-1.5 bg-muted/10 rounded text-[10px]"
                        >
                          <Badge variant="outline" className="text-[9px] justify-center">
                            {entry.action}
                          </Badge>
                          <span>{entry.actor}</span>
                          <span className="text-muted-foreground">{entry.ip}</span>
                          <span className="text-muted-foreground">{formatTimestamp(entry.timestamp)}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </>
              )}

              <div className="text-[10px] text-muted-foreground mt-4">
                Report generated: {formatTimestamp(report.exportedAt)} by {report.exportedBy}
              </div>
            </div>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowReport(false)}>
              Close
            </Button>
            <Button onClick={() => handleExport("json")}>Download JSON</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

// ─── Helper Components ──────────────────────────────────────────────────────

function EvidenceTypeIcon({ type }: { type: string }) {
  switch (type) {
    case "file":
      return <FileText className="h-4 w-4 text-blue-400" />;
    case "log":
      return <Database className="h-4 w-4 text-cyan-400" />;
    case "screenshot":
      return <Camera className="h-4 w-4 text-purple-400" />;
    case "memory_dump":
      return <HardDrive className="h-4 w-4 text-orange-400" />;
    case "network_capture":
      return <Globe className="h-4 w-4 text-green-400" />;
    default:
      return <Package className="h-4 w-4 text-emerald-400" />;
  }
}

function CustodyActionIcon({ action }: { action: string }) {
  switch (action) {
    case "collected":
      return <Plus className="h-4 w-4 text-cyan-400" />;
    case "transferred":
      return <ArrowRight className="h-4 w-4 text-blue-400" />;
    case "accessed":
      return <Eye className="h-4 w-4 text-yellow-400" />;
    case "analyzed":
      return <Search className="h-4 w-4 text-purple-400" />;
    case "exported":
      return <Download className="h-4 w-4 text-emerald-400" />;
    case "sealed":
      return <Lock className="h-4 w-4 text-red-400" />;
    case "unsealed":
      return <Unlock className="h-4 w-4 text-orange-400" />;
    default:
      return <ChevronRight className="h-4 w-4 text-muted-foreground" />;
  }
}

function ClassBadge({ classification }: { classification: string }) {
  const styles: Record<string, string> = {
    public: "bg-green-500/10 text-green-400 border-green-500/30",
    internal: "bg-blue-500/10 text-blue-400 border-blue-500/30",
    confidential: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
    restricted: "bg-red-500/10 text-red-400 border-red-500/30",
  };
  return (
    <Badge variant="outline" className={`text-[10px] ${styles[classification] || ""}`}>
      {classification}
    </Badge>
  );
}

// ─── Main Page ──────────────────────────────────────────────────────────────

export default function EvidenceCustodyPage() {
  usePageTitle("Evidence Locker");
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [showCollect, setShowCollect] = useState(false);
  const [showCompare, setShowCompare] = useState(false);
  const [caseFilter, setCaseFilter] = useState("");
  const [detailTab, setDetailTab] = useState("overview");
  const [newEvidence, setNewEvidence] = useState({
    name: "",
    type: "artifact",
    sourceSystem: "",
    classification: "internal",
    caseId: "",
  });
  const [transferReason, setTransferReason] = useState("");

  const { data: evidence, isLoading } = useQuery({
    queryKey: ["/api/evidence-custody", caseFilter],
    queryFn: async () => {
      const params = new URLSearchParams();
      if (caseFilter) params.set("caseId", caseFilter);
      const r = await apiRequest("GET", `/api/evidence-custody?${params.toString()}`);
      return r.json();
    },
  });

  const { data: detail } = useQuery({
    queryKey: ["/api/evidence-custody", selectedId],
    queryFn: async () => {
      const r = await apiRequest("GET", `/api/evidence-custody/${selectedId}`);
      return r.json();
    },
    enabled: !!selectedId,
  });

  const { data: verification } = useQuery({
    queryKey: ["/api/evidence-custody", selectedId, "verify"],
    queryFn: async () => {
      const r = await apiRequest("GET", `/api/evidence-custody/${selectedId}/verify`);
      return r.json();
    },
    enabled: !!selectedId,
  });

  const collectMutation = useMutation({
    mutationFn: async (data: typeof newEvidence) => {
      const r = await apiRequest("POST", "/api/evidence-custody", data);
      return r.json();
    },
    onSuccess: () => {
      toast({ title: "Evidence Collected" });
      queryClient.invalidateQueries({ queryKey: ["/api/evidence-custody"] });
      setShowCollect(false);
      setNewEvidence({ name: "", type: "artifact", sourceSystem: "", classification: "internal", caseId: "" });
    },
    onError: () => toast({ title: "Collection Failed", variant: "destructive" }),
  });

  const transferMutation = useMutation({
    mutationFn: async ({ action, reason }: { action: string; reason: string }) => {
      const r = await apiRequest("POST", `/api/evidence-custody/${selectedId}/transfer`, { action, reason });
      return r.json();
    },
    onSuccess: () => {
      toast({ title: "Custody Transfer Recorded" });
      setTransferReason("");
      queryClient.invalidateQueries({ queryKey: ["/api/evidence-custody", selectedId] });
      queryClient.invalidateQueries({ queryKey: ["/api/evidence-custody", selectedId, "verify"] });
    },
    onError: () => toast({ title: "Transfer Failed", variant: "destructive" }),
  });

  const sealMutation = useMutation({
    mutationFn: async () => {
      const r = await apiRequest("POST", `/api/evidence-custody/${selectedId}/seal`);
      return r.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/evidence-custody", selectedId] });
      queryClient.invalidateQueries({ queryKey: ["/api/evidence-custody"] });
    },
  });

  const evidenceList = Array.isArray(evidence) ? evidence : (evidence as any)?.data || [];
  const evidenceDetail = detail as any;
  const verifyResult = verification as any;

  if (isLoading) {
    return (
      <div className="p-6 space-y-4">
        <Skeleton className="h-8 w-64" />
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {[1, 2, 3, 4].map((i) => (
            <Skeleton key={i} className="h-24" />
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
            <Link2 className="h-6 w-6 text-emerald-400" />
            Evidence Locker
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Cryptographically verified evidence integrity tracking with audit trail
          </p>
        </div>
        <div className="flex gap-2">
          <Button size="sm" variant="outline" onClick={() => setShowCompare(true)}>
            <Columns className="h-4 w-4 mr-1" />
            Compare
          </Button>
          <Button onClick={() => setShowCollect(true)} className="bg-emerald-600 hover:bg-emerald-700">
            <Plus className="h-4 w-4 mr-2" />
            Collect Evidence
          </Button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="border-emerald-500/20 bg-card/50">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Package className="h-4 w-4 text-emerald-400" />
              Total Evidence
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{evidenceList.length}</div>
          </CardContent>
        </Card>
        <Card className="border-emerald-500/20 bg-card/50">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <ShieldCheck className="h-4 w-4 text-green-400" />
              Integrity Valid
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-400">
              {evidenceList.filter((e: any) => e.integrityValid).length}
            </div>
          </CardContent>
        </Card>
        <Card className="border-emerald-500/20 bg-card/50">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Lock className="h-4 w-4 text-yellow-400" />
              Sealed
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{evidenceList.filter((e: any) => e.isSealed).length}</div>
          </CardContent>
        </Card>
        <Card className="border-emerald-500/20 bg-card/50">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-red-400" />
              Integrity Broken
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-400">
              {evidenceList.filter((e: any) => !e.integrityValid).length}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Collect form */}
      {showCollect && (
        <Card className="border-emerald-500/20 bg-card/50">
          <CardHeader>
            <CardTitle className="text-lg">Collect New Evidence</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <Input
              placeholder="Evidence name"
              value={newEvidence.name}
              onChange={(e) => setNewEvidence({ ...newEvidence, name: e.target.value })}
            />
            <Input
              placeholder="Case ID (e.g., CASE-2024-001)"
              value={newEvidence.caseId}
              onChange={(e) => setNewEvidence({ ...newEvidence, caseId: e.target.value })}
            />
            <Input
              placeholder="Source system"
              value={newEvidence.sourceSystem}
              onChange={(e) => setNewEvidence({ ...newEvidence, sourceSystem: e.target.value })}
            />
            <div className="flex gap-2">
              <select
                value={newEvidence.type}
                onChange={(e) => setNewEvidence({ ...newEvidence, type: e.target.value })}
                className="px-3 py-2 text-sm bg-background border border-border rounded"
              >
                <option value="file">File</option>
                <option value="log">Log</option>
                <option value="screenshot">Screenshot</option>
                <option value="memory_dump">Memory Dump</option>
                <option value="network_capture">Network Capture</option>
                <option value="artifact">Artifact</option>
              </select>
              <select
                value={newEvidence.classification}
                onChange={(e) => setNewEvidence({ ...newEvidence, classification: e.target.value })}
                className="px-3 py-2 text-sm bg-background border border-border rounded"
              >
                <option value="public">Public</option>
                <option value="internal">Internal</option>
                <option value="confidential">Confidential</option>
                <option value="restricted">Restricted</option>
              </select>
            </div>
            <div className="flex gap-2">
              <Button
                onClick={() => collectMutation.mutate(newEvidence)}
                disabled={!newEvidence.name || !newEvidence.caseId || collectMutation.isPending}
                className="bg-emerald-600 hover:bg-emerald-700"
              >
                {collectMutation.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                Collect
              </Button>
              <Button variant="outline" onClick={() => setShowCollect(false)}>
                Cancel
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Filter */}
      <div className="flex gap-2">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Filter by Case ID..."
            value={caseFilter}
            onChange={(e) => setCaseFilter(e.target.value)}
            className="pl-10"
          />
        </div>
      </div>

      {/* Main content */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Evidence list */}
        <div className="space-y-3">
          <h2 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider">Evidence Items</h2>
          {evidenceList.length === 0 && (
            <Card className="border-dashed border-border bg-card/30">
              <CardContent className="py-8 text-center">
                <Package className="h-10 w-10 text-muted-foreground mx-auto mb-2" />
                <p className="text-sm text-muted-foreground">No evidence collected yet</p>
              </CardContent>
            </Card>
          )}
          {evidenceList.map((item: any) => (
            <Card
              key={item.id}
              onClick={() => {
                setSelectedId(item.id);
                setDetailTab("overview");
              }}
              className={`cursor-pointer transition-all hover:border-emerald-500/30 ${selectedId === item.id ? "border-emerald-400 bg-emerald-500/5" : "border-border bg-card/50"}`}
            >
              <CardContent className="p-4">
                <div className="flex items-center justify-between mb-1">
                  <div className="flex items-center gap-2">
                    <EvidenceTypeIcon type={item.type} />
                    <span className="text-sm font-medium">{item.name}</span>
                  </div>
                  {item.integrityValid ? (
                    <ShieldCheck className="h-4 w-4 text-green-400" />
                  ) : (
                    <ShieldAlert className="h-4 w-4 text-red-400" />
                  )}
                </div>
                <div className="flex items-center gap-2 text-xs text-muted-foreground flex-wrap">
                  <span>{item.caseId}</span>
                  <ClassBadge classification={item.classification} />
                  <span>{item.custodyEntries} transfers</span>
                  {item.isSealed && <Lock className="h-3 w-3 text-yellow-400" />}
                </div>
              </CardContent>
            </Card>
          ))}
        </div>

        {/* Detail panel */}
        <div className="lg:col-span-2">
          {!selectedId && (
            <Card className="border-dashed border-border bg-card/30 h-full">
              <CardContent className="py-20 text-center">
                <Link2 className="h-12 w-12 text-muted-foreground mx-auto mb-3" />
                <p className="text-muted-foreground">Select evidence to view details</p>
              </CardContent>
            </Card>
          )}

          {selectedId && evidenceDetail && (
            <div className="space-y-4">
              {/* Header card */}
              <Card className="border-emerald-500/20 bg-card/50">
                <CardHeader className="pb-2">
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-lg">{evidenceDetail.name}</CardTitle>
                    <div className="flex gap-2">
                      <Button size="sm" variant="outline" onClick={() => sealMutation.mutate()}>
                        {evidenceDetail.isSealed ? (
                          <Unlock className="h-4 w-4 mr-1" />
                        ) : (
                          <Lock className="h-4 w-4 mr-1" />
                        )}
                        {evidenceDetail.isSealed ? "Unseal" : "Seal"}
                      </Button>
                    </div>
                  </div>
                  <div className="grid grid-cols-2 gap-2 mt-2 text-xs">
                    <div>
                      <span className="text-muted-foreground">Type:</span> {evidenceDetail.type}
                    </div>
                    <div>
                      <span className="text-muted-foreground">Source:</span> {evidenceDetail.sourceSystem}
                    </div>
                    <div>
                      <span className="text-muted-foreground">Classification:</span>{" "}
                      <ClassBadge classification={evidenceDetail.classification} />
                    </div>
                    <div>
                      <span className="text-muted-foreground">Case:</span> {evidenceDetail.caseId}
                    </div>
                    <div className="col-span-2">
                      <span className="text-muted-foreground">SHA-256:</span>{" "}
                      <code className="text-[10px] break-all font-mono">{evidenceDetail.sha256Hash}</code>
                    </div>
                  </div>
                </CardHeader>
              </Card>

              {/* Verification */}
              {verifyResult && (
                <Card className={`border-${verifyResult.integrityValid ? "green" : "red"}-500/20 bg-card/50`}>
                  <CardContent className="p-4">
                    <div className="flex items-center gap-3">
                      {verifyResult.integrityValid ? (
                        <SuccessIcon size={20} color="#22c55e" />
                      ) : (
                        <XCircle className="h-5 w-5 text-red-400" />
                      )}
                      <div>
                        <div className="text-sm font-medium">
                          {verifyResult.integrityValid ? "Chain Integrity Verified" : "Chain Integrity Broken"}
                        </div>
                        <div className="text-xs text-muted-foreground">
                          {verifyResult.chainLength} entries | Last verified:{" "}
                          {new Date(verifyResult.lastVerified).toLocaleString()}
                        </div>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              )}

              {/* Tabbed detail view */}
              <Tabs value={detailTab} onValueChange={setDetailTab}>
                <TabsList className="grid grid-cols-5">
                  <TabsTrigger value="overview" className="text-xs">
                    Chain
                  </TabsTrigger>
                  <TabsTrigger value="preview" className="text-xs">
                    Preview
                  </TabsTrigger>
                  <TabsTrigger value="access" className="text-xs">
                    Access
                  </TabsTrigger>
                  <TabsTrigger value="audit" className="text-xs">
                    Audit Log
                  </TabsTrigger>
                  <TabsTrigger value="export" className="text-xs">
                    Export
                  </TabsTrigger>
                </TabsList>

                <TabsContent value="overview" className="space-y-4">
                  <Card className="border-emerald-500/20 bg-card/50">
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm">Custody Chain</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-3">
                        {(evidenceDetail.integrityChain || []).map((entry: any, i: number) => (
                          <div
                            key={entry.id || i}
                            className="flex gap-3 p-3 rounded-lg bg-background/50 border border-border"
                          >
                            <CustodyActionIcon action={entry.action} />
                            <div className="flex-1">
                              <div className="flex items-center gap-2">
                                <span className="text-sm font-medium capitalize">{entry.action}</span>
                                <span className="text-xs text-muted-foreground">{entry.actor}</span>
                                <span className="text-xs text-muted-foreground">
                                  {new Date(entry.timestamp).toLocaleString()}
                                </span>
                              </div>
                              <p className="text-xs text-muted-foreground mt-1">{entry.reason}</p>
                              <code className="text-[10px] text-muted-foreground/60 block mt-1 truncate font-mono">
                                {entry.entryHash}
                              </code>
                            </div>
                          </div>
                        ))}
                      </div>

                      {!evidenceDetail.isSealed && (
                        <div className="mt-4 pt-4 border-t border-border space-y-2">
                          <h3 className="text-sm font-semibold">Record Custody Transfer</h3>
                          <Input
                            placeholder="Reason for transfer"
                            value={transferReason}
                            onChange={(e) => setTransferReason(e.target.value)}
                          />
                          <div className="flex gap-2">
                            {["transferred", "accessed", "analyzed", "exported"].map((action) => (
                              <Button
                                key={action}
                                size="sm"
                                variant="outline"
                                onClick={() => transferMutation.mutate({ action, reason: transferReason })}
                                disabled={!transferReason || transferMutation.isPending}
                              >
                                {action}
                              </Button>
                            ))}
                          </div>
                        </div>
                      )}
                    </CardContent>
                  </Card>
                </TabsContent>

                <TabsContent value="preview" className="space-y-4">
                  <EvidencePreviewPanel evidenceId={selectedId} />
                </TabsContent>

                <TabsContent value="access" className="space-y-4">
                  <AccessRequestPanel evidenceId={selectedId} classification={evidenceDetail.classification} />
                </TabsContent>

                <TabsContent value="audit" className="space-y-4">
                  <AccessAuditLogPanel evidenceId={selectedId} />
                </TabsContent>

                <TabsContent value="export" className="space-y-4">
                  <EvidenceExportPanel evidenceId={selectedId} />
                </TabsContent>
              </Tabs>
            </div>
          )}
        </div>
      </div>

      {/* 19.3 Compare dialog */}
      <EvidenceComparisonDialog open={showCompare} onClose={() => setShowCompare(false)} evidenceList={evidenceList} />
    </div>
  );
}

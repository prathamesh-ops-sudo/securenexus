import { useRef, useState, useMemo } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { usePageTitle } from "@/hooks/use-page-title";
import { useToast } from "@/hooks/use-toast";
import {
  Fingerprint,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  Loader2,
  ChevronRight,
  Search,
  Shield,
  Hash,
  User,
  Clock,
  FileText,
  XCircle,
  Info,
  Link2,
  ArrowLeft,
  Tag,
  Plus,
  Trash2,
  Upload,
  Download,
  Archive,
  Settings,
  Eye,
  Lock,
  Unlock,
  ArrowRight,
  Filter,
  Copy,
  Play,
} from "lucide-react";
import { SuccessIcon } from "@/components/ui/animated-state-icons";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Link } from "wouter";
import { Progress } from "@/components/ui/progress";

// ─── Types ──────────────────────────────────────────────────────────────────

interface EvidenceChainEntry {
  id: string;
  orgId: string | null;
  incidentId: string;
  sequenceNum: number;
  entryType: string;
  actorId: string | null;
  actorName: string | null;
  summary: string;
  details: Record<string, unknown> | null;
  relatedResourceType: string | null;
  relatedResourceId: string | null;
  entryHash: string;
  previousHash: string | null;
  createdAt: string | null;
}

interface ChainVerification {
  valid: boolean;
  entryCount: number;
  firstEntry: string | null;
  lastEntry: string | null;
  violations: { sequenceNum: number; reason: string }[];
}

interface EvidenceItem {
  id: string;
  name: string;
  type: string;
  sourceSystem: string;
  collectedBy: string;
  collectedAt: string;
  sha256Hash: string;
  classification: string;
  caseId: string;
  custodyEntries: number;
  isSealed: boolean;
  integrityValid: boolean;
  tags?: TagEntry[];
  files?: FileRef[];
}

interface CustodyEntry {
  id: string;
  action: string;
  actor: string;
  timestamp: string;
  previousHash: string;
  entryHash: string;
  reason: string;
  metadata: Record<string, unknown>;
}

interface EvidenceDetail extends EvidenceItem {
  integrityChain: CustodyEntry[];
  retentionUntil: string;
  sizeBytes: number;
}

interface TagEntry {
  id: string;
  tag: string;
  category: string;
  addedBy: string;
  addedAt: string;
}

interface FileRef {
  fileName: string;
  fileSize: number;
  mimeType: string;
  sha256: string;
  uploadedAt: string;
  uploadedBy: string;
  storageKey: string;
}

interface RetentionPolicy {
  evidenceType: string;
  retentionDays: number;
  action: string;
  autoApply: boolean;
}

// ─── Helpers ────────────────────────────────────────────────────────────────

const ENTRY_TYPE_META: Record<string, { label: string; color: string; icon: typeof Shield }> = {
  evidence_added: { label: "Evidence Added", color: "text-cyan-400", icon: FileText },
  evidence_removed: { label: "Evidence Removed", color: "text-red-400", icon: XCircle },
  status_change: { label: "Status Change", color: "text-blue-400", icon: RefreshCw },
  assignment_change: { label: "Assignment Change", color: "text-purple-400", icon: User },
  escalation: { label: "Escalation", color: "text-orange-400", icon: AlertTriangle },
  containment: { label: "Containment", color: "text-emerald-400", icon: Shield },
  approval_requested: { label: "Approval Requested", color: "text-yellow-400", icon: Clock },
  approval_granted: { label: "Approved", color: "text-green-400", icon: CheckCircle2 },
  approval_denied: { label: "Denied", color: "text-red-400", icon: XCircle },
  response_action: { label: "Response Action", color: "text-amber-400", icon: Shield },
  comment: { label: "Comment", color: "text-muted-foreground", icon: FileText },
  attachment: { label: "Attachment", color: "text-indigo-400", icon: Link2 },
  external_update: { label: "External Update", color: "text-teal-400", icon: Info },
  collected: { label: "Collected", color: "text-cyan-400", icon: FileText },
  transferred: { label: "Transferred", color: "text-blue-400", icon: ArrowRight },
  accessed: { label: "Accessed", color: "text-yellow-400", icon: Eye },
  analyzed: { label: "Analyzed", color: "text-purple-400", icon: Search },
  exported: { label: "Exported", color: "text-emerald-400", icon: Download },
  sealed: { label: "Sealed", color: "text-red-400", icon: Lock },
  unsealed: { label: "Unsealed", color: "text-orange-400", icon: Unlock },
};

const EVIDENCE_CATEGORIES = [
  "malware_sample",
  "network_capture",
  "memory_dump",
  "log_file",
  "screenshot",
  "disk_image",
  "registry",
  "email",
  "document",
  "other",
];

function getEntryMeta(type: string) {
  return ENTRY_TYPE_META[type] || { label: type, color: "text-muted-foreground", icon: FileText };
}

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

// ─── 18.1 Visual Chain of Custody Graph ─────────────────────────────────────

function CustodyFlowGraph({ chain }: { chain: CustodyEntry[] }) {
  if (chain.length === 0) {
    return <div className="text-center py-6 text-xs text-muted-foreground">No custody entries</div>;
  }

  return (
    <div className="space-y-0">
      {chain.map((entry, index) => {
        const meta = getEntryMeta(entry.action);
        const Icon = meta.icon;
        const isLast = index === chain.length - 1;
        return (
          <div key={entry.id} className="flex items-start gap-3 relative">
            {/* Connector */}
            <div className="flex flex-col items-center">
              <div
                className={`w-8 h-8 rounded-full flex items-center justify-center border-2 shrink-0 ${
                  entry.action === "sealed"
                    ? "bg-red-500/10 border-red-500/30"
                    : entry.action === "collected"
                      ? "bg-cyan-500/10 border-cyan-500/30"
                      : entry.action === "analyzed"
                        ? "bg-purple-500/10 border-purple-500/30"
                        : entry.action === "transferred"
                          ? "bg-blue-500/10 border-blue-500/30"
                          : "bg-muted/50 border-border"
                }`}
              >
                <Icon className={`h-3.5 w-3.5 ${meta.color}`} />
              </div>
              {!isLast && (
                <div className="w-px flex-1 bg-border min-h-[24px]">
                  <div className="w-0 h-0 border-l-[4px] border-r-[4px] border-t-[6px] border-l-transparent border-r-transparent border-t-border mx-auto mt-auto" />
                </div>
              )}
            </div>
            {/* Content */}
            <div className="flex-1 min-w-0 pb-4">
              <div className="p-3 rounded-lg bg-muted/20 border border-border">
                <div className="flex items-center gap-2 flex-wrap mb-1">
                  <Badge variant="outline" className={`text-[10px] ${meta.color}`}>
                    {meta.label}
                  </Badge>
                  <span className="text-[10px] text-muted-foreground flex items-center gap-1">
                    <User className="h-2.5 w-2.5" />
                    {entry.actor}
                  </span>
                  <span className="text-[10px] text-muted-foreground flex items-center gap-1">
                    <Clock className="h-2.5 w-2.5" />
                    {formatTimestamp(entry.timestamp)}
                  </span>
                </div>
                <p className="text-xs text-foreground/80">{entry.reason}</p>
                <div className="flex items-center gap-2 mt-2 flex-wrap">
                  <TooltipProvider>
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <span className="text-[9px] font-mono text-muted-foreground/60 flex items-center gap-0.5 cursor-help">
                          <Hash className="h-2 w-2" />
                          {truncateHash(entry.entryHash)}
                        </span>
                      </TooltipTrigger>
                      <TooltipContent className="text-xs font-mono max-w-xs break-all">
                        {entry.entryHash}
                      </TooltipContent>
                    </Tooltip>
                  </TooltipProvider>
                  {entry.previousHash && entry.previousHash !== "genesis" && (
                    <TooltipProvider>
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <span className="text-[9px] font-mono text-muted-foreground/40 flex items-center gap-0.5 cursor-help">
                            \u2190 {truncateHash(entry.previousHash)}
                          </span>
                        </TooltipTrigger>
                        <TooltipContent className="text-xs font-mono max-w-xs break-all">
                          Previous: {entry.previousHash}
                        </TooltipContent>
                      </Tooltip>
                    </TooltipProvider>
                  )}
                </div>
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ─── 18.2 Evidence Integrity Verification ───────────────────────────────────

function IntegrityVerificationPanel({
  evidenceId,
  integrityValid,
  sha256Hash,
}: {
  evidenceId: string;
  integrityValid: boolean;
  sha256Hash: string;
}) {
  const { toast } = useToast();

  const {
    data: verifyResult,
    refetch: verify,
    isFetching: verifying,
  } = useQuery<{
    evidenceId: string;
    chainLength: number;
    integrityValid: boolean;
    brokenLinks: number[];
    lastVerified: string;
  }>({
    queryKey: ["/api/evidence-custody", evidenceId, "verify"],
    queryFn: async () => {
      const r = await apiRequest("GET", `/api/evidence-custody/${evidenceId}/verify`);
      return r.json();
    },
    enabled: false,
  });

  const copyHash = () => {
    navigator.clipboard.writeText(sha256Hash);
    toast({ title: "Hash copied to clipboard" });
  };

  return (
    <Card className={integrityValid ? "border-emerald-500/20" : "border-red-500/20"}>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm flex items-center gap-2">
          {integrityValid ? (
            <CheckCircle2 className="h-4 w-4 text-green-500" />
          ) : (
            <AlertTriangle className="h-4 w-4 text-red-400" />
          )}
          Integrity Verification
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="flex items-center gap-2">
          <Badge variant={integrityValid ? "default" : "destructive"} className="text-[10px]">
            {integrityValid ? "CHAIN VALID" : "CHAIN BROKEN"}
          </Badge>
          <Button size="sm" variant="outline" className="h-6 text-[10px]" onClick={() => verify()} disabled={verifying}>
            {verifying ? <Loader2 className="h-3 w-3 animate-spin" /> : <RefreshCw className="h-3 w-3" />}
            <span className="ml-1">Re-verify</span>
          </Button>
        </div>

        <div className="text-xs space-y-1">
          <div className="flex items-center gap-2">
            <span className="text-muted-foreground">SHA-256:</span>
            <code className="text-[10px] font-mono text-foreground/70 truncate flex-1">{sha256Hash}</code>
            <Button size="sm" variant="ghost" className="h-5 w-5 p-0" onClick={copyHash}>
              <Copy className="h-3 w-3" />
            </Button>
          </div>
        </div>

        {verifyResult && (
          <div className="space-y-2 pt-2 border-t border-border">
            <div className="flex items-center gap-3 text-xs text-muted-foreground">
              <span>{verifyResult.chainLength} entries</span>
              <span>Last verified: {formatTimestamp(verifyResult.lastVerified)}</span>
            </div>
            {verifyResult.brokenLinks.length > 0 && (
              <div className="space-y-1">
                {verifyResult.brokenLinks.map((link) => (
                  <div key={link} className="flex items-center gap-1 text-xs text-red-400">
                    <XCircle className="h-3 w-3" />
                    <span>Broken link at chain position #{link}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ─── 18.3 Evidence Tagging and Categorization ───────────────────────────────

function EvidenceTagsPanel({ evidenceId }: { evidenceId: string }) {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [showAdd, setShowAdd] = useState(false);
  const [tag, setTag] = useState("");
  const [category, setCategory] = useState("other");

  const { data: tagsData } = useQuery<TagEntry[]>({
    queryKey: ["/api/evidence-custody", evidenceId, "tags"],
    queryFn: async () => {
      const r = await apiRequest("GET", `/api/evidence-custody/${evidenceId}/tags`);
      const data = await r.json();
      return Array.isArray(data) ? data : (data as any)?.data || [];
    },
  });

  const addTagMutation = useMutation({
    mutationFn: async (data: { tag: string; category: string }) => {
      const r = await apiRequest("POST", `/api/evidence-custody/${evidenceId}/tags`, data);
      return r.json();
    },
    onSuccess: () => {
      toast({ title: "Tag added" });
      queryClient.invalidateQueries({ queryKey: ["/api/evidence-custody", evidenceId, "tags"] });
      setTag("");
      setShowAdd(false);
    },
    onError: () => toast({ title: "Failed to add tag", variant: "destructive" }),
  });

  const deleteTagMutation = useMutation({
    mutationFn: async (tagId: string) => {
      const r = await apiRequest("DELETE", `/api/evidence-custody/${evidenceId}/tags/${tagId}`);
      return r.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/evidence-custody", evidenceId, "tags"] });
    },
  });

  const tags = tagsData || [];

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <Label className="text-xs flex items-center gap-1">
          <Tag className="h-3 w-3" /> Tags
        </Label>
        <Button size="sm" variant="ghost" className="h-5 text-[10px]" onClick={() => setShowAdd(!showAdd)}>
          <Plus className="h-3 w-3" />
        </Button>
      </div>

      {showAdd && (
        <div className="flex items-center gap-2 p-2 bg-muted/20 rounded">
          <Input
            placeholder="Tag name"
            value={tag}
            onChange={(e) => setTag(e.target.value)}
            className="h-7 text-xs flex-1"
          />
          <Select value={category} onValueChange={setCategory}>
            <SelectTrigger className="h-7 w-36 text-xs">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {EVIDENCE_CATEGORIES.map((c) => (
                <SelectItem key={c} value={c} className="text-xs">
                  {c.replace(/_/g, " ")}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Button
            size="sm"
            className="h-7 text-xs"
            onClick={() => addTagMutation.mutate({ tag, category })}
            disabled={!tag || addTagMutation.isPending}
          >
            Add
          </Button>
        </div>
      )}

      <div className="flex flex-wrap gap-1">
        {tags.map((t) => (
          <Badge key={t.id} variant="secondary" className="text-[10px] gap-1">
            {t.tag}
            <span className="text-muted-foreground">({t.category.replace(/_/g, " ")})</span>
            <button onClick={() => deleteTagMutation.mutate(t.id)} className="ml-0.5 hover:text-destructive">
              <XCircle className="h-2.5 w-2.5" />
            </button>
          </Badge>
        ))}
        {tags.length === 0 && !showAdd && <span className="text-[10px] text-muted-foreground">No tags yet</span>}
      </div>
    </div>
  );
}

// ─── Evidence Custody Manager (new standalone evidence management) ───────────

function EvidenceCustodyManager() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [selectedEvidence, setSelectedEvidence] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [newEvidence, setNewEvidence] = useState({
    name: "",
    type: "artifact",
    sourceSystem: "",
    classification: "internal",
    caseId: "",
  });
  const [typeFilter, setTypeFilter] = useState<string>("all");
  const [uploadProgress, setUploadProgress] = useState(0);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const { data: evidenceListData, isLoading: loadingList } = useQuery<EvidenceItem[]>({
    queryKey: ["/api/evidence-custody"],
    queryFn: async () => {
      const r = await apiRequest("GET", "/api/evidence-custody");
      const data = await r.json();
      return Array.isArray(data) ? data : (data as any)?.data || [];
    },
  });

  const { data: evidenceDetail } = useQuery<EvidenceDetail>({
    queryKey: ["/api/evidence-custody", selectedEvidence],
    queryFn: async () => {
      const r = await apiRequest("GET", `/api/evidence-custody/${selectedEvidence}`);
      return r.json();
    },
    enabled: !!selectedEvidence,
  });

  const createMutation = useMutation({
    mutationFn: async (data: typeof newEvidence) => {
      const r = await apiRequest("POST", "/api/evidence-custody", data);
      return r.json();
    },
    onSuccess: () => {
      toast({ title: "Evidence collected" });
      queryClient.invalidateQueries({ queryKey: ["/api/evidence-custody"] });
      setShowCreate(false);
      setNewEvidence({ name: "", type: "artifact", sourceSystem: "", classification: "internal", caseId: "" });
    },
    onError: () => toast({ title: "Failed to collect evidence", variant: "destructive" }),
  });

  const transferMutation = useMutation({
    mutationFn: async ({ id, action, reason }: { id: string; action: string; reason: string }) => {
      const r = await apiRequest("POST", `/api/evidence-custody/${id}/transfer`, { action, reason });
      return r.json();
    },
    onSuccess: () => {
      toast({ title: "Custody transferred" });
      queryClient.invalidateQueries({ queryKey: ["/api/evidence-custody", selectedEvidence] });
    },
    onError: () => toast({ title: "Failed to transfer custody", variant: "destructive" }),
  });

  const sealMutation = useMutation({
    mutationFn: async (id: string) => {
      const r = await apiRequest("POST", `/api/evidence-custody/${id}/seal`);
      return r.json();
    },
    onSuccess: () => {
      toast({ title: "Evidence seal toggled" });
      queryClient.invalidateQueries({ queryKey: ["/api/evidence-custody"] });
      queryClient.invalidateQueries({ queryKey: ["/api/evidence-custody", selectedEvidence] });
    },
  });

  const uploadMutation = useMutation({
    mutationFn: async ({ id, file }: { id: string; file: File }) => {
      const digest = await crypto.subtle.digest("SHA-256", await file.arrayBuffer());
      const checksumSha256 = btoa(String.fromCharCode(...Array.from(new Uint8Array(digest))));
      const presignResponse = await apiRequest("POST", `/api/evidence-custody/${id}/upload`, {
        fileName: file.name,
        fileSize: file.size,
        mimeType: file.type || "application/octet-stream",
        checksumSha256,
      });
      const grant = await presignResponse.json();
      await new Promise<void>((resolve, reject) => {
        const request = new XMLHttpRequest();
        request.open("PUT", grant.uploadUrl);
        request.setRequestHeader("Content-Type", grant.requiredHeaders["Content-Type"]);
        request.setRequestHeader("x-amz-checksum-sha256", grant.requiredHeaders["x-amz-checksum-sha256"]);
        request.upload.onprogress = (event) => {
          if (event.lengthComputable) setUploadProgress(Math.round((event.loaded / event.total) * 100));
        };
        request.onload = () =>
          request.status >= 200 && request.status < 300 ? resolve() : reject(new Error("S3 upload failed"));
        request.onerror = () => reject(new Error("S3 upload failed"));
        request.send(file);
      });
      const confirmResponse = await apiRequest("POST", `/api/evidence-custody/${id}/upload/confirm`, {
        key: grant.key,
        fileName: file.name,
        fileSize: file.size,
        mimeType: file.type || "application/octet-stream",
        checksumSha256,
      });
      return confirmResponse.json();
    },
    onSuccess: () => {
      setUploadProgress(100);
      toast({ title: "File uploaded and verified" });
      queryClient.invalidateQueries({ queryKey: ["/api/evidence-custody", selectedEvidence] });
    },
    onError: (error) => {
      setUploadProgress(0);
      toast({ title: error instanceof Error ? error.message : "Failed to upload", variant: "destructive" });
    },
  });

  const evidenceList = evidenceListData || [];
  const filteredList = typeFilter === "all" ? evidenceList : evidenceList.filter((e) => e.type === typeFilter);

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div className="flex items-center gap-2">
          <Select value={typeFilter} onValueChange={setTypeFilter}>
            <SelectTrigger className="h-8 w-40 text-xs">
              <SelectValue placeholder="Filter by type" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all" className="text-xs">
                All Types
              </SelectItem>
              {["file", "log", "screenshot", "memory_dump", "network_capture", "artifact"].map((t) => (
                <SelectItem key={t} value={t} className="text-xs">
                  {t.replace(/_/g, " ")}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <span className="text-xs text-muted-foreground">{filteredList.length} items</span>
        </div>
        <Button size="sm" onClick={() => setShowCreate(true)} className="h-8 text-xs">
          <Plus className="h-3 w-3 mr-1" /> Collect Evidence
        </Button>
      </div>

      {showCreate && (
        <Card className="border-cyan-500/20">
          <CardContent className="p-4 space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <div>
                <Label className="text-xs">Name</Label>
                <Input
                  placeholder="Evidence name"
                  value={newEvidence.name}
                  onChange={(e) => setNewEvidence({ ...newEvidence, name: e.target.value })}
                  className="h-8 text-xs"
                />
              </div>
              <div>
                <Label className="text-xs">Case ID</Label>
                <Input
                  placeholder="CASE-001"
                  value={newEvidence.caseId}
                  onChange={(e) => setNewEvidence({ ...newEvidence, caseId: e.target.value })}
                  className="h-8 text-xs"
                />
              </div>
              <div>
                <Label className="text-xs">Type</Label>
                <Select value={newEvidence.type} onValueChange={(v) => setNewEvidence({ ...newEvidence, type: v })}>
                  <SelectTrigger className="h-8 text-xs">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {["file", "log", "screenshot", "memory_dump", "network_capture", "artifact"].map((t) => (
                      <SelectItem key={t} value={t} className="text-xs">
                        {t.replace(/_/g, " ")}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label className="text-xs">Classification</Label>
                <Select
                  value={newEvidence.classification}
                  onValueChange={(v) => setNewEvidence({ ...newEvidence, classification: v })}
                >
                  <SelectTrigger className="h-8 text-xs">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {["public", "internal", "confidential", "restricted"].map((c) => (
                      <SelectItem key={c} value={c} className="text-xs">
                        {c}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
            <Input
              placeholder="Source system"
              value={newEvidence.sourceSystem}
              onChange={(e) => setNewEvidence({ ...newEvidence, sourceSystem: e.target.value })}
              className="h-8 text-xs"
            />
            <div className="flex gap-2">
              <Button
                size="sm"
                className="h-7 text-xs"
                onClick={() => createMutation.mutate(newEvidence)}
                disabled={!newEvidence.name || !newEvidence.caseId || createMutation.isPending}
              >
                {createMutation.isPending && <Loader2 className="h-3 w-3 animate-spin mr-1" />} Collect
              </Button>
              <Button size="sm" variant="outline" className="h-7 text-xs" onClick={() => setShowCreate(false)}>
                Cancel
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Evidence List */}
        <div className="space-y-2">
          {loadingList ? (
            <div className="space-y-2">
              {[1, 2, 3].map((i) => (
                <Skeleton key={i} className="h-20" />
              ))}
            </div>
          ) : filteredList.length === 0 ? (
            <Card className="border-dashed">
              <CardContent className="py-8 text-center">
                <Fingerprint className="h-8 w-8 text-muted-foreground mx-auto mb-2" />
                <p className="text-xs text-muted-foreground">No evidence items</p>
              </CardContent>
            </Card>
          ) : (
            filteredList.map((item) => (
              <Card
                key={item.id}
                onClick={() => setSelectedEvidence(item.id)}
                className={`cursor-pointer transition-all hover:border-cyan-500/30 ${selectedEvidence === item.id ? "border-cyan-400 bg-cyan-500/5" : ""}`}
              >
                <CardContent className="p-3">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-medium truncate">{item.name}</span>
                    <div className="flex items-center gap-1">
                      {item.integrityValid ? (
                        <CheckCircle2 className="h-3 w-3 text-green-500" />
                      ) : (
                        <AlertTriangle className="h-3 w-3 text-red-400" />
                      )}
                      {item.isSealed && <Lock className="h-3 w-3 text-red-400" />}
                    </div>
                  </div>
                  <div className="flex items-center gap-2 text-[10px] text-muted-foreground">
                    <Badge variant="outline" className="text-[9px]">
                      {item.type.replace(/_/g, " ")}
                    </Badge>
                    <Badge variant="outline" className="text-[9px]">
                      {item.classification}
                    </Badge>
                    <span>{item.custodyEntries} entries</span>
                  </div>
                  <div className="text-[10px] text-muted-foreground mt-1">
                    {item.collectedBy} \u00b7 {formatTimestamp(item.collectedAt)}
                  </div>
                </CardContent>
              </Card>
            ))
          )}
        </div>

        {/* Evidence Detail */}
        <div className="lg:col-span-2">
          {!selectedEvidence ? (
            <Card className="border-dashed h-full">
              <CardContent className="py-16 text-center">
                <Fingerprint className="h-10 w-10 text-muted-foreground mx-auto mb-2" />
                <p className="text-sm text-muted-foreground">Select evidence to view chain of custody</p>
              </CardContent>
            </Card>
          ) : evidenceDetail ? (
            <div className="space-y-4">
              {/* Evidence header */}
              <Card>
                <CardContent className="p-4">
                  <div className="flex items-center justify-between mb-2">
                    <h3 className="text-sm font-medium">{evidenceDetail.name}</h3>
                    <div className="flex items-center gap-2">
                      <Button
                        size="sm"
                        variant="outline"
                        className="h-7 text-xs"
                        onClick={() => sealMutation.mutate(evidenceDetail.id)}
                        disabled={sealMutation.isPending}
                      >
                        {evidenceDetail.isSealed ? (
                          <Unlock className="h-3 w-3 mr-1" />
                        ) : (
                          <Lock className="h-3 w-3 mr-1" />
                        )}
                        {evidenceDetail.isSealed ? "Unseal" : "Seal"}
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        className="h-7 text-xs"
                        onClick={() => {
                          const reason = prompt("Transfer reason:");
                          if (reason) transferMutation.mutate({ id: evidenceDetail.id, action: "accessed", reason });
                        }}
                        disabled={evidenceDetail.isSealed}
                      >
                        <ArrowRight className="h-3 w-3 mr-1" /> Transfer
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        className="h-7 text-xs"
                        onClick={() => fileInputRef.current?.click()}
                        disabled={evidenceDetail.isSealed || uploadMutation.isPending}
                      >
                        <Upload className="h-3 w-3 mr-1" /> Upload File
                      </Button>
                      <input
                        ref={fileInputRef}
                        type="file"
                        className="hidden"
                        onChange={(event) => {
                          const file = event.target.files?.[0];
                          if (file) uploadMutation.mutate({ id: evidenceDetail.id, file });
                          event.target.value = "";
                        }}
                      />
                    </div>
                  </div>
                  {uploadMutation.isPending && (
                    <div className="mt-3 space-y-1">
                      <div className="flex justify-between text-[10px] text-muted-foreground">
                        <span>Uploading and verifying object</span>
                        <span>{uploadProgress}%</span>
                      </div>
                      <Progress value={uploadProgress} className="h-1.5" />
                    </div>
                  )}
                  <div className="grid grid-cols-3 gap-3 text-xs">
                    <div>
                      <span className="text-muted-foreground">Type:</span>{" "}
                      <Badge variant="outline" className="text-[10px] ml-1">
                        {evidenceDetail.type}
                      </Badge>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Classification:</span>{" "}
                      <span className="ml-1">{evidenceDetail.classification}</span>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Size:</span>{" "}
                      <span className="ml-1">{formatBytes(evidenceDetail.sizeBytes)}</span>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Case:</span>{" "}
                      <span className="ml-1 font-mono">{evidenceDetail.caseId}</span>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Retention:</span>{" "}
                      <span className="ml-1">{formatTimestamp(evidenceDetail.retentionUntil)}</span>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Source:</span>{" "}
                      <span className="ml-1">{evidenceDetail.sourceSystem}</span>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* 18.2 Integrity verification */}
              <IntegrityVerificationPanel
                evidenceId={evidenceDetail.id}
                integrityValid={!!(evidenceDetail as any).integrityValid}
                sha256Hash={evidenceDetail.sha256Hash}
              />

              {/* 18.3 Tags */}
              <Card>
                <CardContent className="p-4">
                  <EvidenceTagsPanel evidenceId={evidenceDetail.id} />
                </CardContent>
              </Card>

              {/* 18.1 Visual chain of custody graph */}
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Fingerprint className="h-4 w-4 text-violet-400" />
                    Chain of Custody ({evidenceDetail.integrityChain.length} entries)
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <CustodyFlowGraph chain={evidenceDetail.integrityChain} />
                </CardContent>
              </Card>

              {/* Uploaded files */}
              {(evidenceDetail as any).files?.length > 0 && (
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm flex items-center gap-2">
                      <FileText className="h-4 w-4 text-blue-400" />
                      Uploaded Files ({(evidenceDetail as any).files.length})
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-1.5">
                      {(evidenceDetail as any).files.map((f: FileRef, idx: number) => (
                        <div key={idx} className="flex items-center gap-2 p-2 bg-muted/20 rounded text-xs">
                          <FileText className="h-3 w-3 text-muted-foreground" />
                          <span className="font-medium">{f.fileName}</span>
                          <span className="text-muted-foreground">{formatBytes(f.fileSize)}</span>
                          <TooltipProvider>
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <span className="text-[9px] font-mono text-muted-foreground/60 cursor-help">
                                  {truncateHash(f.sha256)}
                                </span>
                              </TooltipTrigger>
                              <TooltipContent className="text-xs font-mono">{f.sha256}</TooltipContent>
                            </Tooltip>
                          </TooltipProvider>
                          <span className="text-muted-foreground ml-auto">{f.uploadedBy}</span>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}
            </div>
          ) : (
            <Card>
              <CardContent className="p-8 text-center">
                <Loader2 className="h-6 w-6 animate-spin mx-auto" />
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── 18.5 Retention Policies Panel ──────────────────────────────────────────

function RetentionPoliciesPanel() {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: policiesData, isLoading } = useQuery<RetentionPolicy[]>({
    queryKey: ["/api/evidence-custody/retention-policies"],
    queryFn: async () => {
      const r = await apiRequest("GET", "/api/evidence-custody/retention-policies");
      const data = await r.json();
      return Array.isArray(data) ? data : (data as any)?.data || [];
    },
  });

  const applyMutation = useMutation({
    mutationFn: async () => {
      const r = await apiRequest("POST", "/api/evidence-custody/retention-policies/apply");
      return r.json();
    },
    onSuccess: (data: any) => {
      toast({
        title: `Retention preview: ${data.wouldArchive} would archive, ${data.wouldDelete} would delete`,
      });
      queryClient.invalidateQueries({ queryKey: ["/api/evidence-custody"] });
    },
    onError: () => toast({ title: "Failed to preview retention", variant: "destructive" }),
  });

  const policies = policiesData || [];

  return (
    <Card>
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm flex items-center gap-2">
            <Archive className="h-4 w-4 text-amber-400" />
            Retention Policies
          </CardTitle>
          <Button
            size="sm"
            variant="outline"
            className="h-7 text-xs"
            onClick={() => applyMutation.mutate()}
            disabled={applyMutation.isPending}
          >
            {applyMutation.isPending ? (
              <Loader2 className="h-3 w-3 animate-spin mr-1" />
            ) : (
              <Play className="h-3 w-3 mr-1" />
            )}
            Preview Retention
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="space-y-2">
            {[1, 2, 3].map((i) => (
              <Skeleton key={i} className="h-8" />
            ))}
          </div>
        ) : policies.length === 0 ? (
          <p className="text-xs text-muted-foreground py-2">No retention policies configured</p>
        ) : (
          <div className="space-y-1.5">
            {policies.map((p, i) => (
              <div key={i} className="flex items-center gap-3 p-2 bg-muted/20 rounded text-xs">
                <Badge variant="outline" className="text-[10px]">
                  {p.evidenceType.replace(/_/g, " ")}
                </Badge>
                <span>{p.retentionDays} days</span>
                <Badge variant={p.action === "delete" ? "destructive" : "secondary"} className="text-[10px]">
                  {p.action}
                </Badge>
                {p.autoApply && (
                  <Badge variant="outline" className="text-[10px] text-emerald-400">
                    auto
                  </Badge>
                )}
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ─── Main Page ──────────────────────────────────────────────────────────────

export default function EvidenceChainViewerPage() {
  usePageTitle("Evidence Chain Viewer");
  const [incidentId, setIncidentId] = useState("");
  const [activeIncidentId, setActiveIncidentId] = useState<string | null>(null);
  const [selectedEntry, setSelectedEntry] = useState<EvidenceChainEntry | null>(null);
  const [activeTab, setActiveTab] = useState("chain");

  const {
    data: rawEntries,
    isLoading,
    isError,
    error,
    refetch,
    isFetching,
  } = useQuery<EvidenceChainEntry[]>({
    queryKey: ["/api/incidents", activeIncidentId, "evidence-chain"],
    queryFn: async () => {
      const res = await apiRequest("GET", `/api/incidents/${activeIncidentId}/evidence-chain`);
      const data = await res.json();
      return Array.isArray(data) ? data : [];
    },
    enabled: !!activeIncidentId,
  });

  const entries = Array.isArray(rawEntries) ? rawEntries : [];
  const isNotFound = isError && error instanceof Error && error.message.startsWith("404");

  const {
    data: verification,
    refetch: verifyChain,
    isFetching: verifying,
  } = useQuery<ChainVerification>({
    queryKey: ["/api/incidents", activeIncidentId, "evidence-chain", "verify"],
    queryFn: async () => {
      const res = await apiRequest("GET", `/api/incidents/${activeIncidentId}/evidence-chain/verify`);
      return res.json();
    },
    enabled: false,
  });

  const handleSearch = () => {
    const trimmed = incidentId.trim();
    if (trimmed) {
      setActiveIncidentId(trimmed);
    }
  };

  const sortedEntries = [...entries].sort((a, b) => a.sequenceNum - b.sequenceNum);

  return (
    <div className="p-4 md:p-6 space-y-6 max-w-[1400px] mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-violet-500/10 border border-violet-500/20">
            <Fingerprint className="h-5 w-5 text-violet-400" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight">Evidence Chain & Custody</h1>
            <p className="text-xs text-muted-foreground">
              Immutable chain-of-custody, integrity verification, tagging, and retention management
            </p>
          </div>
        </div>
      </div>

      {/* Tabs: Chain Viewer | Evidence Manager | Retention */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="chain" className="text-xs">
            <Fingerprint className="h-3 w-3 mr-1" /> Incident Chain
          </TabsTrigger>
          <TabsTrigger value="custody" className="text-xs">
            <Shield className="h-3 w-3 mr-1" /> Evidence Custody
          </TabsTrigger>
          <TabsTrigger value="retention" className="text-xs">
            <Archive className="h-3 w-3 mr-1" /> Retention
          </TabsTrigger>
        </TabsList>

        <TabsContent value="chain" className="mt-4">
          {/* Original chain viewer with improvements */}
          <div className="space-y-4">
            <Card>
              <CardContent className="p-4">
                <div className="flex items-center gap-2">
                  <Search className="h-4 w-4 text-muted-foreground shrink-0" />
                  <Input
                    placeholder="Enter Incident ID to view evidence chain..."
                    value={incidentId}
                    onChange={(e) => setIncidentId(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") handleSearch();
                    }}
                    className="h-9 text-sm"
                  />
                  <Button size="sm" onClick={handleSearch} disabled={!incidentId.trim()} className="h-9 px-4">
                    View Chain
                  </Button>
                </div>
                {activeIncidentId && (
                  <div className="flex items-center gap-2 mt-3">
                    <Badge variant="outline" className="text-xs">
                      <Hash className="h-3 w-3 mr-1" />
                      {activeIncidentId}
                    </Badge>
                    <Link
                      href={`/incidents/${activeIncidentId}`}
                      className="text-xs text-cyan-400 hover:underline flex items-center gap-1"
                    >
                      View Incident <ChevronRight className="h-3 w-3" />
                    </Link>
                    <div className="ml-auto flex items-center gap-2">
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => verifyChain()}
                        disabled={verifying || !entries?.length}
                        className="h-8"
                      >
                        {verifying ? (
                          <Loader2 className="h-3.5 w-3.5 animate-spin" />
                        ) : (
                          <Shield className="h-3.5 w-3.5" />
                        )}
                        <span className="ml-1.5">Verify Chain</span>
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => refetch()}
                        disabled={isFetching}
                        className="h-8"
                      >
                        {isFetching ? (
                          <Loader2 className="h-3.5 w-3.5 animate-spin" />
                        ) : (
                          <RefreshCw className="h-3.5 w-3.5" />
                        )}
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        className="h-8 text-xs"
                        onClick={() => {
                          setActiveIncidentId(null);
                          setIncidentId("");
                        }}
                      >
                        <ArrowLeft className="h-3 w-3 mr-1" /> Clear
                      </Button>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Verification result */}
            {verification && (
              <Card className={verification.valid ? "border-emerald-500/30" : "border-red-500/30"}>
                <CardContent className="p-4">
                  <div className="flex items-center gap-3">
                    {verification.valid ? (
                      <CheckCircle2 className="h-5 w-5 text-green-500" />
                    ) : (
                      <AlertTriangle className="h-5 w-5 text-red-400 shrink-0" />
                    )}
                    <div className="flex-1">
                      <p className="text-sm font-medium">
                        Chain Integrity: {verification.valid ? "Valid" : "Violations Detected"}
                      </p>
                      <p className="text-xs text-muted-foreground">
                        {verification.entryCount} entries
                        {verification.firstEntry && ` \u00b7 First: ${formatTimestamp(verification.firstEntry)}`}
                        {verification.lastEntry && ` \u00b7 Last: ${formatTimestamp(verification.lastEntry)}`}
                      </p>
                    </div>
                    <Badge variant={verification.valid ? "default" : "destructive"} className="text-[10px]">
                      {verification.valid
                        ? "VERIFIED"
                        : `${verification.violations.length} VIOLATION${verification.violations.length !== 1 ? "S" : ""}`}
                    </Badge>
                  </div>
                  {verification.violations.length > 0 && (
                    <div className="mt-3 space-y-1.5">
                      <Separator />
                      {verification.violations.map((v, i) => (
                        <div key={i} className="flex items-start gap-2 text-xs text-red-400 py-1">
                          <XCircle className="h-3.5 w-3.5 shrink-0 mt-0.5" />
                          <span>
                            Sequence #{v.sequenceNum}: {v.reason}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </CardContent>
              </Card>
            )}

            {/* Chain entries */}
            {!activeIncidentId ? (
              <Card>
                <CardContent className="p-12 text-center">
                  <Fingerprint className="h-12 w-12 text-muted-foreground/30 mx-auto mb-3" />
                  <p className="text-sm font-medium">Enter an Incident ID to view its evidence chain</p>
                  <p className="text-xs text-muted-foreground mt-1">
                    The evidence chain provides an immutable, SHA-256 hash-linked audit trail.
                  </p>
                </CardContent>
              </Card>
            ) : isLoading ? (
              <Card>
                <CardContent className="p-4 space-y-4">
                  {Array.from({ length: 5 }).map((_, i) => (
                    <div key={i} className="flex items-start gap-3">
                      <Skeleton className="h-6 w-6 rounded-full shrink-0" />
                      <div className="flex-1 space-y-2">
                        <Skeleton className="h-4 w-48" />
                        <Skeleton className="h-3 w-full" />
                      </div>
                    </div>
                  ))}
                </CardContent>
              </Card>
            ) : isNotFound ? (
              <Card>
                <CardContent className="p-8 text-center">
                  <AlertTriangle className="h-8 w-8 text-amber-400 mx-auto mb-2" />
                  <p className="text-sm font-medium">Incident not found</p>
                </CardContent>
              </Card>
            ) : isError ? (
              <Card>
                <CardContent className="p-8 text-center">
                  <AlertTriangle className="h-8 w-8 text-destructive mx-auto mb-2" />
                  <p className="text-sm font-medium">Failed to load evidence chain</p>
                  <Button size="sm" variant="outline" onClick={() => refetch()} className="mt-3">
                    Retry
                  </Button>
                </CardContent>
              </Card>
            ) : sortedEntries.length === 0 ? (
              <Card>
                <CardContent className="p-8 text-center">
                  <Fingerprint className="h-8 w-8 text-muted-foreground/30 mx-auto mb-2" />
                  <p className="text-sm font-medium">No evidence chain entries</p>
                </CardContent>
              </Card>
            ) : (
              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Fingerprint className="h-4 w-4 text-muted-foreground" />
                    Chain Timeline
                  </CardTitle>
                  <CardDescription className="text-xs">
                    {sortedEntries.length} entries \u00b7 Click any entry to view full details
                  </CardDescription>
                </CardHeader>
                <CardContent className="p-4 pt-0">
                  <div className="relative space-y-0">
                    {sortedEntries.map((entry, index) => {
                      const meta = getEntryMeta(entry.entryType);
                      const Icon = meta.icon;
                      return (
                        <div
                          key={entry.id}
                          className="flex items-start gap-3 relative pb-4 cursor-pointer group"
                          onClick={() => setSelectedEntry(entry)}
                          role="button"
                          tabIndex={0}
                          onKeyDown={(e) => {
                            if (e.key === "Enter" || e.key === " ") setSelectedEntry(entry);
                          }}
                        >
                          <div className="flex flex-col items-center">
                            <div
                              className={`w-7 h-7 rounded-full flex items-center justify-center border shrink-0 transition-colors ${entry.entryType === "approval_granted" ? "bg-green-500/10 border-green-500/30" : entry.entryType === "approval_denied" ? "bg-red-500/10 border-red-500/30" : "bg-muted/50 border-border"} group-hover:border-cyan-500/40`}
                            >
                              <Icon className={`h-3.5 w-3.5 ${meta.color}`} />
                            </div>
                            {index < sortedEntries.length - 1 && (
                              <div className="w-px flex-1 bg-border mt-1 min-h-[16px]" />
                            )}
                          </div>
                          <div className="flex-1 min-w-0 pt-0.5">
                            <div className="flex items-center gap-2 flex-wrap">
                              <Badge variant="outline" className={`text-[10px] ${meta.color}`}>
                                {meta.label}
                              </Badge>
                              <span className="text-[10px] text-muted-foreground">#{entry.sequenceNum}</span>
                              {entry.actorName && (
                                <span className="text-[10px] text-muted-foreground flex items-center gap-1">
                                  <User className="h-2.5 w-2.5" />
                                  {entry.actorName}
                                </span>
                              )}
                            </div>
                            <p className="text-xs mt-1 text-foreground/80 group-hover:text-foreground transition-colors">
                              {entry.summary}
                            </p>
                            <div className="flex items-center gap-3 mt-1.5 flex-wrap">
                              <span className="text-[10px] text-muted-foreground flex items-center gap-1">
                                <Clock className="h-2.5 w-2.5" />
                                {formatTimestamp(entry.createdAt)}
                              </span>
                              <TooltipProvider>
                                <Tooltip>
                                  <TooltipTrigger asChild>
                                    <span className="text-[10px] font-mono text-muted-foreground/60 flex items-center gap-1 cursor-help">
                                      <Hash className="h-2.5 w-2.5" />
                                      {truncateHash(entry.entryHash)}
                                    </span>
                                  </TooltipTrigger>
                                  <TooltipContent className="text-xs font-mono max-w-xs break-all">
                                    {entry.entryHash}
                                  </TooltipContent>
                                </Tooltip>
                              </TooltipProvider>
                              {entry.previousHash && (
                                <TooltipProvider>
                                  <Tooltip>
                                    <TooltipTrigger asChild>
                                      <span className="text-[10px] font-mono text-muted-foreground/40 flex items-center gap-1 cursor-help">
                                        \u2190 {truncateHash(entry.previousHash)}
                                      </span>
                                    </TooltipTrigger>
                                    <TooltipContent className="text-xs font-mono max-w-xs break-all">
                                      Previous: {entry.previousHash}
                                    </TooltipContent>
                                  </Tooltip>
                                </TooltipProvider>
                              )}
                            </div>
                          </div>
                          <ChevronRight className="h-4 w-4 text-muted-foreground/30 group-hover:text-muted-foreground transition-colors shrink-0 mt-1" />
                        </div>
                      );
                    })}
                  </div>
                </CardContent>
              </Card>
            )}
          </div>
        </TabsContent>

        <TabsContent value="custody" className="mt-4">
          <EvidenceCustodyManager />
        </TabsContent>

        <TabsContent value="retention" className="mt-4">
          <RetentionPoliciesPanel />
        </TabsContent>
      </Tabs>

      {/* Entry detail dialog */}
      <Dialog open={!!selectedEntry} onOpenChange={() => setSelectedEntry(null)}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-sm">
              {selectedEntry &&
                (() => {
                  const meta = getEntryMeta(selectedEntry.entryType);
                  const Icon = meta.icon;
                  return (
                    <>
                      <Icon className={`h-4 w-4 ${meta.color}`} />
                      {meta.label}
                      <Badge variant="outline" className="text-[10px] ml-auto">
                        #{selectedEntry.sequenceNum}
                      </Badge>
                    </>
                  );
                })()}
            </DialogTitle>
            <DialogDescription className="text-xs">Full details for this evidence chain entry</DialogDescription>
          </DialogHeader>
          {selectedEntry && (
            <ScrollArea className="max-h-[60vh]">
              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-3 text-xs">
                  <div>
                    <p className="text-muted-foreground mb-0.5">Entry ID</p>
                    <p className="font-mono text-[11px] break-all">{selectedEntry.id}</p>
                  </div>
                  <div>
                    <p className="text-muted-foreground mb-0.5">Incident ID</p>
                    <Link
                      href={`/incidents/${selectedEntry.incidentId}`}
                      className="font-mono text-[11px] text-cyan-400 hover:underline break-all"
                    >
                      {selectedEntry.incidentId}
                    </Link>
                  </div>
                  <div>
                    <p className="text-muted-foreground mb-0.5">Actor</p>
                    <p>{selectedEntry.actorName || "System"}</p>
                  </div>
                  <div>
                    <p className="text-muted-foreground mb-0.5">Timestamp</p>
                    <p>{formatTimestamp(selectedEntry.createdAt)}</p>
                  </div>
                </div>
                <Separator />
                <div className="text-xs">
                  <p className="text-muted-foreground mb-1">Summary</p>
                  <p className="text-foreground">{selectedEntry.summary}</p>
                </div>
                <Separator />
                <div className="text-xs space-y-2">
                  <p className="text-muted-foreground">Hash Chain</p>
                  <div className="space-y-1.5">
                    <div className="flex items-center gap-2">
                      <Badge variant="outline" className="text-[9px] shrink-0">
                        CURRENT
                      </Badge>
                      <code className="text-[10px] font-mono text-foreground/70 break-all">
                        {selectedEntry.entryHash}
                      </code>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge variant="outline" className="text-[9px] shrink-0">
                        PREVIOUS
                      </Badge>
                      <code className="text-[10px] font-mono text-foreground/70 break-all">
                        {selectedEntry.previousHash || "GENESIS"}
                      </code>
                    </div>
                  </div>
                </div>
                {selectedEntry.details && Object.keys(selectedEntry.details).length > 0 && (
                  <>
                    <Separator />
                    <div className="text-xs">
                      <p className="text-muted-foreground mb-1">Details (JSON)</p>
                      <pre className="text-[10px] font-mono bg-muted/30 rounded-md p-3 overflow-x-auto whitespace-pre-wrap break-all">
                        {JSON.stringify(selectedEntry.details, null, 2)}
                      </pre>
                    </div>
                  </>
                )}
                {(selectedEntry.relatedResourceType || selectedEntry.relatedResourceId) && (
                  <>
                    <Separator />
                    <div className="grid grid-cols-2 gap-3 text-xs">
                      {selectedEntry.relatedResourceType && (
                        <div>
                          <p className="text-muted-foreground mb-0.5">Related Resource Type</p>
                          <p>{selectedEntry.relatedResourceType}</p>
                        </div>
                      )}
                      {selectedEntry.relatedResourceId && (
                        <div>
                          <p className="text-muted-foreground mb-0.5">Related Resource ID</p>
                          <p className="font-mono text-[11px] break-all">{selectedEntry.relatedResourceId}</p>
                        </div>
                      )}
                    </div>
                  </>
                )}
              </div>
            </ScrollArea>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}

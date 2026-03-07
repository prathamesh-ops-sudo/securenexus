import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { usePageTitle } from "@/hooks/use-page-title";
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
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Input } from "@/components/ui/input";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from "@/components/ui/dialog";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { Link } from "wouter";

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
};

function getEntryMeta(type: string) {
  return ENTRY_TYPE_META[type] || { label: type, color: "text-muted-foreground", icon: FileText };
}

function formatTimestamp(ts: string | null): string {
  if (!ts) return "—";
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
  if (!hash) return "—";
  if (hash === "GENESIS") return "GENESIS";
  return `${hash.slice(0, 8)}…${hash.slice(-6)}`;
}

export default function EvidenceChainViewerPage() {
  usePageTitle("Evidence Chain Viewer");
  const [incidentId, setIncidentId] = useState("");
  const [activeIncidentId, setActiveIncidentId] = useState<string | null>(null);
  const [selectedEntry, setSelectedEntry] = useState<EvidenceChainEntry | null>(null);

  const {
    data: entries,
    isLoading,
    isError,
    refetch,
    isFetching,
  } = useQuery<EvidenceChainEntry[]>({
    queryKey: ["/api/incidents", activeIncidentId, "evidence-chain"],
    queryFn: async () => {
      const res = await apiRequest("GET", `/api/incidents/${activeIncidentId}/evidence-chain`);
      return res.json();
    },
    enabled: !!activeIncidentId,
  });

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

  const sortedEntries = [...(entries ?? [])].sort((a, b) => a.sequenceNum - b.sequenceNum);

  return (
    <div className="p-4 md:p-6 space-y-6 max-w-[1400px] mx-auto">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-gradient-to-br from-violet-500/20 to-purple-500/10 border border-violet-500/20">
            <Fingerprint className="h-5 w-5 text-violet-400" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight">Evidence Chain Viewer</h1>
            <p className="text-xs text-muted-foreground">Immutable chain-of-custody audit trail for incidents</p>
          </div>
        </div>
        {activeIncidentId && (
          <div className="flex items-center gap-2">
            <Button
              size="sm"
              variant="outline"
              onClick={() => verifyChain()}
              disabled={verifying || !entries?.length}
              className="h-8"
            >
              {verifying ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Shield className="h-3.5 w-3.5" />}
              <span className="ml-1.5">Verify Chain</span>
            </Button>
            <Button size="sm" variant="outline" onClick={() => refetch()} disabled={isFetching} className="h-8">
              {isFetching ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
              <span className="ml-1.5 hidden sm:inline">Refresh</span>
            </Button>
          </div>
        )}
      </div>

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
              <Button
                variant="ghost"
                size="sm"
                className="h-6 px-2 text-xs ml-auto"
                onClick={() => {
                  setActiveIncidentId(null);
                  setIncidentId("");
                }}
              >
                <ArrowLeft className="h-3 w-3 mr-1" />
                Clear
              </Button>
            </div>
          )}
        </CardContent>
      </Card>

      {verification && (
        <Card className={verification.valid ? "border-emerald-500/30" : "border-red-500/30"}>
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              {verification.valid ? (
                <CheckCircle2 className="h-5 w-5 text-emerald-400 shrink-0" />
              ) : (
                <AlertTriangle className="h-5 w-5 text-red-400 shrink-0" />
              )}
              <div className="flex-1">
                <p className="text-sm font-medium">
                  Chain Integrity: {verification.valid ? "Valid" : "Violations Detected"}
                </p>
                <p className="text-xs text-muted-foreground">
                  {verification.entryCount} entries
                  {verification.firstEntry && ` · First: ${formatTimestamp(verification.firstEntry)}`}
                  {verification.lastEntry && ` · Last: ${formatTimestamp(verification.lastEntry)}`}
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

      {!activeIncidentId ? (
        <Card>
          <CardContent className="p-12 text-center">
            <Fingerprint className="h-12 w-12 text-muted-foreground/30 mx-auto mb-3" />
            <p className="text-sm font-medium">Enter an Incident ID to view its evidence chain</p>
            <p className="text-xs text-muted-foreground mt-1">
              The evidence chain provides an immutable, SHA-256 hash-linked audit trail of all actions taken on an
              incident.
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
                  <Skeleton className="h-3 w-32" />
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      ) : isError ? (
        <Card>
          <CardContent className="p-8 text-center">
            <AlertTriangle className="h-8 w-8 text-destructive mx-auto mb-2" />
            <p className="text-sm font-medium">Failed to load evidence chain</p>
            <p className="text-xs text-muted-foreground mt-1">The incident may not exist or you may not have access.</p>
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
            <p className="text-xs text-muted-foreground mt-1">This incident has no chain-of-custody entries yet.</p>
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
              {sortedEntries.length} entries · Click any entry to view full details
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
                        className={`w-7 h-7 rounded-full flex items-center justify-center border shrink-0 transition-colors
                          ${entry.entryType === "approval_granted" ? "bg-green-500/10 border-green-500/30" : entry.entryType === "approval_denied" ? "bg-red-500/10 border-red-500/30" : "bg-muted/50 border-border"}
                          group-hover:border-cyan-500/40`}
                      >
                        <Icon className={`h-3.5 w-3.5 ${meta.color}`} />
                      </div>
                      {index < sortedEntries.length - 1 && <div className="w-px flex-1 bg-border mt-1 min-h-[16px]" />}
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
                                  ← {truncateHash(entry.previousHash)}
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

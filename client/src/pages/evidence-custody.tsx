import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
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
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { useToast } from "@/hooks/use-toast";

export default function EvidenceCustodyPage() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [showCollect, setShowCollect] = useState(false);
  const [caseFilter, setCaseFilter] = useState("");
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
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {[1, 2, 3].map((i) => (
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
            <Link2 className="h-6 w-6 text-emerald-400" />
            Evidence Chain of Custody
          </h1>
          <p className="text-sm text-muted-foreground mt-1">Cryptographically verified evidence integrity tracking</p>
        </div>
        <Button onClick={() => setShowCollect(true)} className="bg-emerald-600 hover:bg-emerald-700">
          <Plus className="h-4 w-4 mr-2" />
          Collect Evidence
        </Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
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
      </div>

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

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
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
              onClick={() => setSelectedId(item.id)}
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
                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                  <span>{item.caseId}</span>
                  <span>{item.custodyEntries} transfers</span>
                  {item.isSealed && <Lock className="h-3 w-3 text-yellow-400" />}
                </div>
              </CardContent>
            </Card>
          ))}
        </div>

        <div className="lg:col-span-2">
          {!selectedId && (
            <Card className="border-dashed border-border bg-card/30 h-full">
              <CardContent className="py-20 text-center">
                <Link2 className="h-12 w-12 text-muted-foreground mx-auto mb-3" />
                <p className="text-muted-foreground">Select evidence to view custody chain</p>
              </CardContent>
            </Card>
          )}

          {selectedId && evidenceDetail && (
            <div className="space-y-4">
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
                      <code className="text-xs break-all">{evidenceDetail.sha256Hash}</code>
                    </div>
                  </div>
                </CardHeader>
              </Card>

              {verifyResult && (
                <Card className={`border-${verifyResult.integrityValid ? "green" : "red"}-500/20 bg-card/50`}>
                  <CardContent className="p-4">
                    <div className="flex items-center gap-3">
                      {verifyResult.integrityValid ? (
                        <CheckCircle2 className="h-5 w-5 text-green-400" />
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
                          <code className="text-xs text-muted-foreground/60 block mt-1 truncate">
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
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

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
      return <Plus className="h-4 w-4 text-green-400 mt-1" />;
    case "transferred":
      return <ArrowRight className="h-4 w-4 text-blue-400 mt-1" />;
    case "accessed":
      return <Eye className="h-4 w-4 text-cyan-400 mt-1" />;
    case "analyzed":
      return <Search className="h-4 w-4 text-purple-400 mt-1" />;
    case "exported":
      return <Database className="h-4 w-4 text-orange-400 mt-1" />;
    case "sealed":
      return <Lock className="h-4 w-4 text-yellow-400 mt-1" />;
    case "unsealed":
      return <Unlock className="h-4 w-4 text-yellow-400 mt-1" />;
    default:
      return <Shield className="h-4 w-4 text-muted-foreground mt-1" />;
  }
}

function ClassBadge({ classification }: { classification: string }) {
  const styles: Record<string, string> = {
    public: "bg-green-500/20 text-green-400",
    internal: "bg-blue-500/20 text-blue-400",
    confidential: "bg-orange-500/20 text-orange-400",
    restricted: "bg-red-500/20 text-red-400",
  };
  return <Badge className={`text-xs ${styles[classification] || styles.internal}`}>{classification}</Badge>;
}

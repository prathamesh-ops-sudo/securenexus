import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import {
  Download,
  Trash2,
  RefreshCw,
  Database,
  Shield,
  AlertTriangle,
  CheckCircle2,
  Clock,
  HardDrive,
  FileDown,
  ShieldAlert,
  Loader2,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { useToast } from "@/hooks/use-toast";

export default function TenantDataPage() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<"export" | "deletion">("export");
  const [confirmToken, setConfirmToken] = useState("");
  const [pendingDeletion, setPendingDeletion] = useState<{ jobId: string; token: string } | null>(null);

  const { data: summary, isLoading: summaryLoading } = useQuery({
    queryKey: ["/api/tenant-data/summary"],
    queryFn: async () => {
      const r = await apiRequest("GET", "/api/tenant-data/summary");
      return r.json();
    },
  });

  const { data: exports, isLoading: exportsLoading } = useQuery({
    queryKey: ["/api/tenant-data/exports"],
    queryFn: async () => {
      const r = await apiRequest("GET", "/api/tenant-data/exports");
      return r.json();
    },
  });

  const exportMutation = useMutation({
    mutationFn: async (format: string) => {
      const r = await apiRequest("POST", "/api/tenant-data/export", { format });
      return r.json();
    },
    onSuccess: (data: any) => {
      toast({ title: "Export Started", description: `Job ${data?.jobId || "created"}. Check progress below.` });
      queryClient.invalidateQueries({ queryKey: ["/api/tenant-data/exports"] });
    },
    onError: () => toast({ title: "Export Failed", variant: "destructive" }),
  });

  const deletionMutation = useMutation({
    mutationFn: async (retentionDays: number) => {
      const r = await apiRequest("POST", "/api/tenant-data/deletion", { retentionDays });
      return r.json();
    },
    onSuccess: (data: any) => {
      setPendingDeletion({ jobId: data?.jobId || "", token: data?.confirmationToken || "" });
      toast({ title: "Deletion Request Created", description: "Confirm with the token below to proceed." });
    },
    onError: () => toast({ title: "Deletion Failed", variant: "destructive" }),
  });

  const confirmDeletionMutation = useMutation({
    mutationFn: async ({ jobId, token }: { jobId: string; token: string }) => {
      const r = await apiRequest("POST", `/api/tenant-data/deletion/${jobId}/confirm`, { confirmationToken: token });
      return r.json();
    },
    onSuccess: () => {
      setPendingDeletion(null);
      setConfirmToken("");
      toast({ title: "Deletion Confirmed", description: "Data deletion is now processing." });
    },
    onError: () => toast({ title: "Confirmation Failed", variant: "destructive" }),
  });

  const summaryData = summary as any;
  const exportList = Array.isArray(exports) ? exports : (exports as any)?.data || [];

  if (summaryLoading) {
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
            <Database className="h-6 w-6 text-cyan-400" />
            Tenant Data Management
          </h1>
          <p className="text-sm text-muted-foreground mt-1">GDPR-compliant data portability and erasure controls</p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card className="border-cyan-500/20 bg-card/50">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <HardDrive className="h-4 w-4 text-cyan-400" />
              Total Records
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{summaryData?.totalRecords?.toLocaleString() || 0}</div>
            <p className="text-xs text-muted-foreground">{Object.keys(summaryData?.tables || {}).length} data tables</p>
          </CardContent>
        </Card>
        <Card className="border-cyan-500/20 bg-card/50">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <FileDown className="h-4 w-4 text-green-400" />
              Estimated Size
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {summaryData?.estimatedSizeBytes
                ? `${(summaryData.estimatedSizeBytes / 1024 / 1024).toFixed(1)} MB`
                : "0 MB"}
            </div>
            <p className="text-xs text-muted-foreground">Across all org data</p>
          </CardContent>
        </Card>
        <Card className="border-cyan-500/20 bg-card/50">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Shield className="h-4 w-4 text-blue-400" />
              Exports
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{exportList.length}</div>
            <p className="text-xs text-muted-foreground">Historical export jobs</p>
          </CardContent>
        </Card>
      </div>

      <div className="flex gap-2 border-b border-border">
        <button
          onClick={() => setActiveTab("export")}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${activeTab === "export" ? "border-cyan-400 text-cyan-400" : "border-transparent text-muted-foreground hover:text-foreground"}`}
        >
          <Download className="h-4 w-4 inline mr-2" />
          Data Export
        </button>
        <button
          onClick={() => setActiveTab("deletion")}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${activeTab === "deletion" ? "border-red-400 text-red-400" : "border-transparent text-muted-foreground hover:text-foreground"}`}
        >
          <Trash2 className="h-4 w-4 inline mr-2" />
          Data Deletion
        </button>
      </div>

      {activeTab === "export" && (
        <div className="space-y-4">
          <Card className="border-cyan-500/20 bg-card/50">
            <CardHeader>
              <CardTitle className="text-lg">Export Organization Data</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <p className="text-sm text-muted-foreground">
                Export all organization data for GDPR portability compliance. Data is packaged as a downloadable
                archive.
              </p>
              <div className="flex gap-3">
                <Button
                  onClick={() => exportMutation.mutate("json")}
                  disabled={exportMutation.isPending}
                  className="bg-cyan-600 hover:bg-cyan-700"
                >
                  {exportMutation.isPending ? (
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  ) : (
                    <Download className="h-4 w-4 mr-2" />
                  )}
                  Export as JSON
                </Button>
                <Button
                  onClick={() => exportMutation.mutate("csv")}
                  disabled={exportMutation.isPending}
                  variant="outline"
                >
                  {exportMutation.isPending ? (
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  ) : (
                    <Download className="h-4 w-4 mr-2" />
                  )}
                  Export as CSV
                </Button>
              </div>
            </CardContent>
          </Card>

          {exportList.length > 0 && (
            <Card className="border-cyan-500/20 bg-card/50">
              <CardHeader>
                <CardTitle className="text-lg">Export History</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {exportList.map((job: any) => (
                    <div
                      key={job.id}
                      className="flex items-center justify-between p-3 rounded-lg bg-background/50 border border-border"
                    >
                      <div className="flex items-center gap-3">
                        <StatusIcon status={job.status} />
                        <div>
                          <div className="text-sm font-medium">Export #{job.id?.slice(-8)}</div>
                          <div className="text-xs text-muted-foreground">
                            {new Date(job.createdAt).toLocaleString()}
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-3">
                        <Badge variant={job.status === "completed" ? "default" : "secondary"}>{job.status}</Badge>
                        <span className="text-sm text-muted-foreground">{job.format?.toUpperCase()}</span>
                        {job.progress !== undefined && job.progress < 100 && (
                          <span className="text-sm">{job.progress}%</span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {exportList.length === 0 && !exportsLoading && (
            <Card className="border-dashed border-border bg-card/30">
              <CardContent className="py-12 text-center">
                <FileDown className="h-12 w-12 text-muted-foreground mx-auto mb-3" />
                <p className="text-muted-foreground">No exports yet. Start your first data export above.</p>
              </CardContent>
            </Card>
          )}
        </div>
      )}

      {activeTab === "deletion" && (
        <div className="space-y-4">
          <Card className="border-red-500/20 bg-card/50">
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <ShieldAlert className="h-5 w-5 text-red-400" />
                Request Data Deletion
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="p-4 bg-red-500/10 rounded-lg border border-red-500/20">
                <div className="flex items-start gap-3">
                  <AlertTriangle className="h-5 w-5 text-red-400 mt-0.5" />
                  <div>
                    <p className="text-sm font-medium text-red-400">Destructive Action</p>
                    <p className="text-sm text-muted-foreground mt-1">
                      This will permanently delete ALL organization data after a 30-day soft-delete retention period.
                      This action cannot be undone. We recommend exporting your data first.
                    </p>
                  </div>
                </div>
              </div>

              {!pendingDeletion && (
                <Button
                  onClick={() => deletionMutation.mutate(30)}
                  disabled={deletionMutation.isPending}
                  variant="destructive"
                >
                  {deletionMutation.isPending ? (
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  ) : (
                    <Trash2 className="h-4 w-4 mr-2" />
                  )}
                  Request Data Deletion
                </Button>
              )}

              {pendingDeletion && (
                <div className="space-y-3 p-4 bg-background/50 rounded-lg border border-border">
                  <p className="text-sm font-medium">Confirm deletion with the token below:</p>
                  <div className="flex gap-2">
                    <code className="flex-1 p-2 bg-muted rounded text-xs break-all">{pendingDeletion.token}</code>
                  </div>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      placeholder="Paste confirmation token"
                      value={confirmToken}
                      onChange={(e) => setConfirmToken(e.target.value)}
                      className="flex-1 px-3 py-2 text-sm bg-background border border-border rounded"
                    />
                    <Button
                      onClick={() =>
                        confirmDeletionMutation.mutate({ jobId: pendingDeletion.jobId, token: confirmToken })
                      }
                      disabled={confirmDeletionMutation.isPending || !confirmToken}
                      variant="destructive"
                    >
                      Confirm Delete
                    </Button>
                    <Button
                      variant="outline"
                      onClick={() => {
                        setPendingDeletion(null);
                        setConfirmToken("");
                      }}
                    >
                      Cancel
                    </Button>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

          {summaryData?.tables && (
            <Card className="border-cyan-500/20 bg-card/50">
              <CardHeader>
                <CardTitle className="text-lg">Data Inventory</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {Object.entries(summaryData.tables).map(([table, count]: [string, any]) => (
                    <div key={table} className="flex items-center justify-between p-2 rounded bg-background/50">
                      <span className="text-sm font-medium capitalize">{table.replace(/_/g, " ")}</span>
                      <span className="text-sm text-muted-foreground">{Number(count).toLocaleString()} records</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </div>
  );
}

function StatusIcon({ status }: { status: string }) {
  switch (status) {
    case "completed":
      return <CheckCircle2 className="h-5 w-5 text-green-400" />;
    case "running":
    case "pending":
      return <Clock className="h-5 w-5 text-yellow-400" />;
    case "failed":
      return <AlertTriangle className="h-5 w-5 text-red-400" />;
    default:
      return <RefreshCw className="h-5 w-5 text-muted-foreground" />;
  }
}

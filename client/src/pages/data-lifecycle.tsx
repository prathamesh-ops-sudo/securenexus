import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { usePageTitle } from "@/hooks/use-page-title";
import {
  Database,
  AlertTriangle,
  RefreshCw,
  Trash2,
  Archive,
  Clock,
  HardDrive,
  BarChart3,
  Shield,
  Loader2,
  CheckCircle2,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

interface RetentionPolicy {
  id: string;
  dataType: string;
  retentionDays: number;
  archiveAfterDays: number;
  deleteAfterDays: number;
  complianceHold: boolean;
  lastPurgeAt?: string;
  recordCount: number;
  sizeBytes: number;
}

interface LifecycleStats {
  totalStorageBytes: number;
  archivedBytes: number;
  pendingPurge: number;
  policies: RetentionPolicy[];
}

export default function DataLifecyclePage() {
  usePageTitle("Data Lifecycle Management");
  const { toast } = useToast();

  const {
    data: stats,
    isLoading,
    isError,
    refetch,
  } = useQuery<LifecycleStats>({
    queryKey: ["/api/data-lifecycle/status"],
    queryFn: () => apiRequest("GET", "/api/data-lifecycle/status").then((r) => r.json()),
  });

  const purgeMutation = useMutation({
    mutationFn: (policyId: string) => apiRequest("POST", `/api/data-lifecycle/purge/${policyId}`),
    onSuccess: () => {
      toast({ title: "Purge initiated" });
      queryClient.invalidateQueries({ queryKey: ["/api/data-lifecycle/status"] });
    },
    onError: () => toast({ title: "Purge failed", variant: "destructive" }),
  });

  if (isLoading) {
    return (
      <div className="p-6 space-y-4">
        <Skeleton className="h-8 w-64" />
        <div className="grid grid-cols-4 gap-4">
          {[1, 2, 3, 4].map((i) => (
            <Skeleton key={i} className="h-24" />
          ))}
        </div>
      </div>
    );
  }

  if (isError || !stats) {
    return (
      <div className="p-6">
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12 gap-3">
            <AlertTriangle className="h-8 w-8 text-destructive" />
            <p className="text-muted-foreground">Failed to load data lifecycle info</p>
            <Button variant="outline" onClick={() => refetch()}>
              <RefreshCw className="mr-2 h-4 w-4" /> Retry
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  const policies = Array.isArray(stats.policies) ? stats.policies : [];
  const formatBytes = (b: number) => {
    if (b >= 1e9) return `${(b / 1e9).toFixed(1)} GB`;
    if (b >= 1e6) return `${(b / 1e6).toFixed(1)} MB`;
    if (b >= 1e3) return `${(b / 1e3).toFixed(1)} KB`;
    return `${b} B`;
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Database className="h-6 w-6" /> Data Lifecycle Management
          </h1>
          <p className="text-muted-foreground text-sm mt-1">Retention policies, archival, and data purge management</p>
        </div>
        <Button variant="outline" size="sm" onClick={() => refetch()}>
          <RefreshCw className="mr-2 h-4 w-4" /> Refresh
        </Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="pt-4 flex items-center gap-2">
            <HardDrive className="h-5 w-5 text-primary" />
            <div>
              <p className="text-2xl font-bold">{formatBytes(stats.totalStorageBytes || 0)}</p>
              <p className="text-xs text-muted-foreground">Total Storage</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 flex items-center gap-2">
            <Archive className="h-5 w-5 text-blue-500" />
            <div>
              <p className="text-2xl font-bold">{formatBytes(stats.archivedBytes || 0)}</p>
              <p className="text-xs text-muted-foreground">Archived</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 flex items-center gap-2">
            <Trash2 className="h-5 w-5 text-red-500" />
            <div>
              <p className="text-2xl font-bold">{(stats.pendingPurge || 0).toLocaleString()}</p>
              <p className="text-xs text-muted-foreground">Pending Purge</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 flex items-center gap-2">
            <Shield className="h-5 w-5 text-green-500" />
            <div>
              <p className="text-2xl font-bold">{policies.length}</p>
              <p className="text-xs text-muted-foreground">Retention Policies</p>
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="space-y-3">
        <h2 className="text-lg font-semibold">Retention Policies</h2>
        {policies.length === 0 ? (
          <Card>
            <CardContent className="flex flex-col items-center py-12 gap-2">
              <Database className="h-8 w-8 text-muted-foreground" />
              <p className="text-muted-foreground">No retention policies configured</p>
            </CardContent>
          </Card>
        ) : (
          policies.map((p) => (
            <Card key={p.id}>
              <CardContent className="py-4">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-3">
                    <Database className="h-4 w-4 text-primary" />
                    <div>
                      <p className="font-medium text-sm capitalize">{p.dataType.replace(/_/g, " ")}</p>
                      <p className="text-xs text-muted-foreground">
                        {p.recordCount.toLocaleString()} records &middot; {formatBytes(p.sizeBytes)}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    {p.complianceHold && (
                      <Badge variant="outline">
                        <Shield className="mr-1 h-3 w-3" /> Compliance Hold
                      </Badge>
                    )}
                    <Badge variant="outline">
                      <Clock className="mr-1 h-3 w-3" /> Retain {p.retentionDays}d
                    </Badge>
                    <Badge variant="secondary">
                      <Archive className="mr-1 h-3 w-3" /> Archive {p.archiveAfterDays}d
                    </Badge>
                    <Badge variant="destructive">
                      <Trash2 className="mr-1 h-3 w-3" /> Delete {p.deleteAfterDays}d
                    </Badge>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => purgeMutation.mutate(p.id)}
                      disabled={purgeMutation.isPending || p.complianceHold}
                    >
                      {purgeMutation.isPending ? (
                        <Loader2 className="mr-1 h-3 w-3 animate-spin" />
                      ) : (
                        <Trash2 className="mr-1 h-3 w-3" />
                      )}
                      Purge
                    </Button>
                  </div>
                </div>
                {p.lastPurgeAt && (
                  <p className="text-xs text-muted-foreground">
                    Last purge: {new Date(p.lastPurgeAt).toLocaleString()}
                  </p>
                )}
              </CardContent>
            </Card>
          ))
        )}
      </div>
    </div>
  );
}

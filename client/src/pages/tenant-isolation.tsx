import { useQuery } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { usePageTitle } from "@/hooks/use-page-title";
import {
  Shield,
  AlertTriangle,
  RefreshCw,
  Server,
  Database,
  Gauge,
  CheckCircle2,
  XCircle,
  Users,
  BarChart3,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

interface QuotaStatus {
  category: string;
  used: number;
  limit: number;
  unit: string;
}

interface TenantInfo {
  orgId: string;
  plan: string;
  isolationLevel: string;
  quotas: QuotaStatus[];
  noisyNeighborScore: number;
  throttled: boolean;
}

export default function TenantIsolationPage() {
  usePageTitle("Tenant Isolation & Quotas");

  const {
    data: tenant,
    isLoading,
    isError,
    refetch,
  } = useQuery<TenantInfo>({
    queryKey: ["/api/tenant-quotas/status"],
    queryFn: () => apiRequest("GET", "/api/tenant-quotas/status").then((r) => r.json()),
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

  if (isError || !tenant) {
    return (
      <div className="p-6">
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12 gap-3">
            <AlertTriangle className="h-8 w-8 text-destructive" />
            <p className="text-muted-foreground">Failed to load tenant isolation data</p>
            <Button variant="outline" onClick={() => refetch()}>
              <RefreshCw className="mr-2 h-4 w-4" /> Retry
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  const quotas = Array.isArray(tenant.quotas) ? tenant.quotas : [];

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Shield className="h-6 w-6" /> Tenant Isolation & Quotas
          </h1>
          <p className="text-muted-foreground text-sm mt-1">
            Monitor resource isolation and quota usage for your organization
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={() => refetch()}>
          <RefreshCw className="mr-2 h-4 w-4" /> Refresh
        </Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center gap-2">
              <Server className="h-5 w-5 text-primary" />
              <div>
                <p className="text-lg font-bold capitalize">{tenant.isolationLevel || "shared"}</p>
                <p className="text-xs text-muted-foreground">Isolation Level</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center gap-2">
              <Users className="h-5 w-5 text-blue-500" />
              <div>
                <p className="text-lg font-bold capitalize">{tenant.plan || "free"}</p>
                <p className="text-xs text-muted-foreground">Plan Tier</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center gap-2">
              <Gauge className="h-5 w-5 text-yellow-500" />
              <div>
                <p className="text-lg font-bold">{tenant.noisyNeighborScore ?? 0}</p>
                <p className="text-xs text-muted-foreground">Noisy Neighbor Score</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center gap-2">
              {tenant.throttled ? (
                <XCircle className="h-5 w-5 text-red-500" />
              ) : (
                <CheckCircle2 className="h-5 w-5 text-green-500" />
              )}
              <div>
                <p className="text-lg font-bold">{tenant.throttled ? "Throttled" : "Active"}</p>
                <p className="text-xs text-muted-foreground">Status</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="quotas">
        <TabsList>
          <TabsTrigger value="quotas">Quota Usage</TabsTrigger>
          <TabsTrigger value="isolation">Isolation Details</TabsTrigger>
        </TabsList>

        <TabsContent value="quotas" className="space-y-3">
          {quotas.length === 0 ? (
            <Card>
              <CardContent className="flex flex-col items-center py-12 gap-2">
                <Database className="h-8 w-8 text-muted-foreground" />
                <p className="text-muted-foreground">No quota data available</p>
              </CardContent>
            </Card>
          ) : (
            quotas.map((q) => {
              const pct = q.limit > 0 ? Math.round((q.used / q.limit) * 100) : 0;
              return (
                <Card key={q.category}>
                  <CardContent className="py-4">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <BarChart3 className="h-4 w-4 text-primary" />
                        <span className="font-medium text-sm capitalize">{q.category.replace(/_/g, " ")}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-sm">
                          {q.used.toLocaleString()} / {q.limit.toLocaleString()} {q.unit}
                        </span>
                        <Badge variant={pct >= 90 ? "destructive" : pct >= 70 ? "secondary" : "outline"}>{pct}%</Badge>
                      </div>
                    </div>
                    <Progress value={Math.min(pct, 100)} />
                  </CardContent>
                </Card>
              );
            })
          )}
        </TabsContent>

        <TabsContent value="isolation">
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Isolation Configuration</CardTitle>
              <CardDescription>How your organization&apos;s data and compute are isolated</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="border rounded-lg p-4">
                  <p className="text-sm font-medium">Data Isolation</p>
                  <p className="text-xs text-muted-foreground mt-1">
                    All queries are scoped by orgId with row-level security
                  </p>
                  <Badge variant="outline" className="mt-2">
                    <CheckCircle2 className="mr-1 h-3 w-3 text-green-500" /> Active
                  </Badge>
                </div>
                <div className="border rounded-lg p-4">
                  <p className="text-sm font-medium">Compute Isolation</p>
                  <p className="text-xs text-muted-foreground mt-1">
                    {tenant.isolationLevel === "dedicated"
                      ? "Dedicated compute resources"
                      : "Shared compute with rate limiting"}
                  </p>
                  <Badge variant="outline" className="mt-2 capitalize">
                    {tenant.isolationLevel || "shared"}
                  </Badge>
                </div>
                <div className="border rounded-lg p-4">
                  <p className="text-sm font-medium">Network Isolation</p>
                  <p className="text-xs text-muted-foreground mt-1">VPC-scoped with security group enforcement</p>
                  <Badge variant="outline" className="mt-2">
                    <CheckCircle2 className="mr-1 h-3 w-3 text-green-500" /> Enforced
                  </Badge>
                </div>
                <div className="border rounded-lg p-4">
                  <p className="text-sm font-medium">Encryption</p>
                  <p className="text-xs text-muted-foreground mt-1">AES-256-GCM at rest, TLS 1.3 in transit</p>
                  <Badge variant="outline" className="mt-2">
                    <CheckCircle2 className="mr-1 h-3 w-3 text-green-500" /> Active
                  </Badge>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}

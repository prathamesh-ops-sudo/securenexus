import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { usePageTitle } from "@/hooks/use-page-title";
import {
  DollarSign,
  TrendingUp,
  AlertTriangle,
  RefreshCw,
  Settings2,
  BarChart3,
  Loader2,
  Zap,
  Clock,
  Shield,
  Construction,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Progress } from "@/components/ui/progress";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

interface BudgetUsage {
  totalSpent: number;
  monthlyLimit: number;
  dailySpend: number;
  requestCount: number;
  tokenCount: number;
  modelBreakdown: { model: string; cost: number; requests: number; tokens: number }[];
  featureBreakdown: { feature: string; cost: number; requests: number }[];
}

interface BudgetAlert {
  id: string;
  type: string;
  message: string;
  threshold: number;
  currentValue: number;
  createdAt: string;
}

export default function AiBudgetControlsPage() {
  usePageTitle("AI Budget Controls");
  const { toast } = useToast();
  const [newLimit, setNewLimit] = useState("");

  const {
    data: usage,
    isLoading,
    isError,
    error,
    refetch,
  } = useQuery<BudgetUsage>({
    queryKey: ["/api/ai/budget-usage"],
    queryFn: () => apiRequest("GET", "/api/ai/budget-usage").then((r) => r.json()),
  });

  const isNotImplemented = isError && error?.message?.startsWith("501:");

  const { data: alerts } = useQuery<BudgetAlert[]>({
    queryKey: ["/api/ai/budget-alerts"],
    queryFn: () => apiRequest("GET", "/api/ai/budget-alerts").then((r) => r.json()),
  });

  const updateLimitMutation = useMutation({
    mutationFn: (limit: number) => apiRequest("PATCH", "/api/ai/budget-config", { monthlyLimit: limit }),
    onSuccess: () => {
      toast({ title: "Budget limit updated" });
      queryClient.invalidateQueries({ queryKey: ["/api/ai/budget-usage"] });
      setNewLimit("");
    },
    onError: () => toast({ title: "Failed to update limit", variant: "destructive" }),
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
        <Skeleton className="h-64" />
      </div>
    );
  }

  if (isNotImplemented) {
    return (
      <div className="p-6 space-y-6">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <DollarSign className="h-6 w-6" /> AI Budget Controls
          </h1>
          <p className="text-muted-foreground text-sm mt-1">
            Monitor and control AI spending across models and features
          </p>
        </div>
        <Card className="border-dashed">
          <CardContent className="flex flex-col items-center justify-center py-16 gap-4">
            <Construction className="h-10 w-10 text-muted-foreground" />
            <div className="text-center">
              <p className="text-lg font-semibold">Coming Soon</p>
              <p className="text-sm text-muted-foreground mt-1 max-w-md">
                AI budget controls and usage tracking are under development. This will let you set spending limits,
                monitor token usage, and receive budget alerts.
              </p>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (isError || !usage) {
    return (
      <div className="p-6">
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12 gap-3">
            <AlertTriangle className="h-8 w-8 text-destructive" />
            <p className="text-muted-foreground">Failed to load AI budget data</p>
            <Button variant="outline" onClick={() => refetch()}>
              <RefreshCw className="mr-2 h-4 w-4" /> Retry
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  const pct = usage.monthlyLimit > 0 ? Math.round((usage.totalSpent / usage.monthlyLimit) * 100) : 0;
  const alertList = Array.isArray(alerts) ? alerts : [];

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <DollarSign className="h-6 w-6" /> AI Budget Controls
          </h1>
          <p className="text-muted-foreground text-sm mt-1">
            Monitor and control AI spending across models and features
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
              <DollarSign className="h-5 w-5 text-primary" />
              <div>
                <p className="text-2xl font-bold">${usage.totalSpent.toFixed(2)}</p>
                <p className="text-xs text-muted-foreground">Monthly Spend</p>
              </div>
            </div>
            <Progress value={Math.min(pct, 100)} className="mt-2" />
            <p className="text-xs text-muted-foreground mt-1">
              {pct}% of ${usage.monthlyLimit} limit
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center gap-2">
              <TrendingUp className="h-5 w-5 text-blue-500" />
              <div>
                <p className="text-2xl font-bold">${usage.dailySpend.toFixed(2)}</p>
                <p className="text-xs text-muted-foreground">Today&apos;s Spend</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center gap-2">
              <Zap className="h-5 w-5 text-yellow-500" />
              <div>
                <p className="text-2xl font-bold">{usage.requestCount.toLocaleString()}</p>
                <p className="text-xs text-muted-foreground">API Requests</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center gap-2">
              <BarChart3 className="h-5 w-5 text-green-500" />
              <div>
                <p className="text-2xl font-bold">{(usage.tokenCount / 1000).toFixed(0)}K</p>
                <p className="text-xs text-muted-foreground">Tokens Used</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="models">
        <TabsList>
          <TabsTrigger value="models">By Model</TabsTrigger>
          <TabsTrigger value="features">By Feature</TabsTrigger>
          <TabsTrigger value="alerts">Alerts ({alertList.length})</TabsTrigger>
          <TabsTrigger value="settings">Settings</TabsTrigger>
        </TabsList>

        <TabsContent value="models" className="space-y-3">
          {(usage.modelBreakdown || []).length === 0 ? (
            <Card>
              <CardContent className="flex flex-col items-center py-12 gap-2">
                <BarChart3 className="h-8 w-8 text-muted-foreground" />
                <p className="text-muted-foreground">No model usage data yet</p>
              </CardContent>
            </Card>
          ) : (
            (usage.modelBreakdown || []).map((m) => (
              <Card key={m.model}>
                <CardContent className="py-3 flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <Zap className="h-4 w-4 text-primary" />
                    <div>
                      <p className="font-medium text-sm">{m.model}</p>
                      <p className="text-xs text-muted-foreground">
                        {m.requests.toLocaleString()} requests &middot; {(m.tokens / 1000).toFixed(0)}K tokens
                      </p>
                    </div>
                  </div>
                  <div className="text-right">
                    <p className="font-bold">${m.cost.toFixed(2)}</p>
                    <p className="text-xs text-muted-foreground">
                      {usage.totalSpent > 0 ? Math.round((m.cost / usage.totalSpent) * 100) : 0}% of total
                    </p>
                  </div>
                </CardContent>
              </Card>
            ))
          )}
        </TabsContent>

        <TabsContent value="features" className="space-y-3">
          {(usage.featureBreakdown || []).length === 0 ? (
            <Card>
              <CardContent className="flex flex-col items-center py-12 gap-2">
                <Settings2 className="h-8 w-8 text-muted-foreground" />
                <p className="text-muted-foreground">No feature usage data yet</p>
              </CardContent>
            </Card>
          ) : (
            (usage.featureBreakdown || []).map((f) => (
              <Card key={f.feature}>
                <CardContent className="py-3 flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <Shield className="h-4 w-4 text-primary" />
                    <div>
                      <p className="font-medium text-sm">{f.feature}</p>
                      <p className="text-xs text-muted-foreground">{f.requests.toLocaleString()} requests</p>
                    </div>
                  </div>
                  <p className="font-bold">${f.cost.toFixed(2)}</p>
                </CardContent>
              </Card>
            ))
          )}
        </TabsContent>

        <TabsContent value="alerts" className="space-y-3">
          {alertList.length === 0 ? (
            <Card>
              <CardContent className="flex flex-col items-center py-12 gap-2">
                <AlertTriangle className="h-8 w-8 text-muted-foreground" />
                <p className="text-muted-foreground">No budget alerts</p>
              </CardContent>
            </Card>
          ) : (
            alertList.map((a) => (
              <Card key={a.id}>
                <CardContent className="py-3 flex items-center gap-3">
                  <AlertTriangle className="h-4 w-4 text-yellow-500" />
                  <div className="flex-1">
                    <p className="font-medium text-sm">{a.message}</p>
                    <p className="text-xs text-muted-foreground">
                      <Clock className="inline h-3 w-3 mr-1" />
                      {new Date(a.createdAt).toLocaleString()}
                    </p>
                  </div>
                  <Badge variant="outline">{a.type}</Badge>
                </CardContent>
              </Card>
            ))
          )}
        </TabsContent>

        <TabsContent value="settings">
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Budget Configuration</CardTitle>
              <CardDescription>Set monthly spending limits for AI features</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <Label>Monthly Spend Limit ($)</Label>
                <div className="flex gap-2 mt-1">
                  <Input
                    type="number"
                    placeholder={String(usage.monthlyLimit)}
                    value={newLimit}
                    onChange={(e) => setNewLimit(e.target.value)}
                    min={0}
                  />
                  <Button
                    onClick={() => {
                      const val = parseFloat(newLimit);
                      if (!isNaN(val) && val > 0) updateLimitMutation.mutate(val);
                    }}
                    disabled={!newLimit || updateLimitMutation.isPending}
                  >
                    {updateLimitMutation.isPending ? (
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    ) : (
                      <Settings2 className="mr-2 h-4 w-4" />
                    )}
                    Update
                  </Button>
                </div>
              </div>
              <div className="text-sm text-muted-foreground">
                Current limit: <span className="font-medium">${usage.monthlyLimit}</span> &middot; Current spend:{" "}
                <span className="font-medium">${usage.totalSpent.toFixed(2)}</span>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}

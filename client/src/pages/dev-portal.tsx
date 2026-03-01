import { useState, useCallback } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Textarea } from "@/components/ui/textarea";
import {
  Code2,
  Play,
  Webhook,
  Database,
  Settings2,
  Rocket,
  ChevronRight,
  Copy,
  Send,
  Table2,
  RefreshCw,
  CheckCircle2,
  XCircle,
  Clock,
  HardDrive,
  Cpu,
  MemoryStick,
  Activity,
  Search,
  Eye,
  ToggleLeft,
  ToggleRight,
  Server,
} from "lucide-react";

type DevTab = "api-docs" | "playground" | "webhooks" | "database" | "config" | "deployment";

interface ApiSummary {
  totalEndpoints: number;
  totalOperations: number;
  tags: { name: string; endpoints: number; methods: string[] }[];
}

interface TableInfo {
  table_name: string;
  total_size: string;
  size_bytes: number;
  estimated_rows: number;
}

interface TableSchema {
  tableName: string;
  columns: {
    column_name: string;
    data_type: string;
    is_nullable: string;
    column_default: string | null;
    character_maximum_length: number | null;
  }[];
  indexes: { indexname: string; indexdef: string }[];
}

interface ConfigData {
  config: Record<string, unknown>;
  featureFlags: { key: string; name: string; enabled: boolean; rollout_pct: number; created_at: string }[];
  pool: Record<string, unknown>;
  runtime: {
    nodeVersion: string;
    platform: string;
    arch: string;
    uptime: number;
    memoryUsage: Record<string, number>;
    pid: number;
  };
}

interface DeploymentData {
  application: {
    name: string;
    version: string;
    environment: string;
    uptime: number;
    startedAt: string;
    nodeVersion: string;
    pid: number;
  };
  database: { connected: boolean; version: string; tableCount: number; pool: Record<string, unknown> };
  memory: { rss: number; heapTotal: number; heapUsed: number; external: number };
  endpoints: { health: string; openapi: string; staging: string | null; production: string | null };
}

interface WebhookLog {
  id: string;
  webhook_id: string;
  event: string;
  response_status: number;
  success: boolean;
  created_at: string;
  url: string;
  org_id: string;
}

interface PlaygroundResult {
  status: number;
  statusText: string;
  headers: Record<string, string>;
  body: unknown;
  elapsed: number;
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

function formatUptime(seconds: number): string {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d}d ${h}h ${m}m`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

function ApiDocsTab() {
  const { data, isLoading } = useQuery<ApiSummary>({
    queryKey: ["/api/dev-portal/openapi/summary"],
  });

  const [expandedTag, setExpandedTag] = useState<string | null>(null);
  const [specVisible, setSpecVisible] = useState(false);
  const { toast } = useToast();

  const { data: fullSpec, isLoading: specLoading } = useQuery({
    queryKey: ["/api/dev-portal/openapi"],
    enabled: specVisible,
  });

  const copySpec = useCallback(() => {
    if (fullSpec) {
      navigator.clipboard.writeText(JSON.stringify(fullSpec, null, 2));
      toast({ title: "OpenAPI spec copied to clipboard" });
    }
  }, [fullSpec, toast]);

  if (isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-24" />
        <Skeleton className="h-64" />
      </div>
    );
  }

  if (!data) {
    return <p className="text-muted-foreground text-center py-8">Failed to load API documentation</p>;
  }

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card className="glass-card border-border/40">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground font-medium uppercase tracking-wider">Endpoints</p>
                <p className="text-2xl font-bold mt-1">{data.totalEndpoints}</p>
              </div>
              <Code2 className="h-8 w-8 text-cyan-400 opacity-60" />
            </div>
          </CardContent>
        </Card>
        <Card className="glass-card border-border/40">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground font-medium uppercase tracking-wider">Operations</p>
                <p className="text-2xl font-bold mt-1">{data.totalOperations}</p>
              </div>
              <Play className="h-8 w-8 text-emerald-400 opacity-60" />
            </div>
          </CardContent>
        </Card>
        <Card className="glass-card border-border/40">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground font-medium uppercase tracking-wider">API Groups</p>
                <p className="text-2xl font-bold mt-1">{data.tags.length}</p>
              </div>
              <Table2 className="h-8 w-8 text-violet-400 opacity-60" />
            </div>
          </CardContent>
        </Card>
      </div>

      <Card className="glass-card border-border/40">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-medium">API Groups</CardTitle>
            <div className="flex gap-2">
              <Button variant="outline" size="sm" onClick={() => setSpecVisible(!specVisible)}>
                <Eye className="h-3.5 w-3.5 mr-1" />
                {specVisible ? "Hide" : "View"} Raw Spec
              </Button>
              {fullSpec != null && (
                <Button variant="outline" size="sm" onClick={copySpec}>
                  <Copy className="h-3.5 w-3.5 mr-1" />
                  Copy JSON
                </Button>
              )}
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="space-y-1">
            {data.tags
              .sort((a, b) => b.endpoints - a.endpoints)
              .map((tag) => (
                <button
                  key={tag.name}
                  className="w-full flex items-center justify-between p-2.5 rounded-md hover:bg-muted/30 transition-colors text-left"
                  onClick={() => setExpandedTag(expandedTag === tag.name ? null : tag.name)}
                >
                  <div className="flex items-center gap-3">
                    <ChevronRight
                      className={`h-3.5 w-3.5 text-muted-foreground transition-transform ${expandedTag === tag.name ? "rotate-90" : ""}`}
                    />
                    <span className="text-sm font-medium">{tag.name}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    {tag.methods.map((m) => (
                      <Badge
                        key={m}
                        variant="outline"
                        className={`text-[10px] px-1.5 ${
                          m === "GET"
                            ? "border-emerald-500/50 text-emerald-400"
                            : m === "POST"
                              ? "border-blue-500/50 text-blue-400"
                              : m === "PUT" || m === "PATCH"
                                ? "border-amber-500/50 text-amber-400"
                                : "border-red-500/50 text-red-400"
                        }`}
                      >
                        {m}
                      </Badge>
                    ))}
                    <Badge variant="secondary" className="text-xs">
                      {tag.endpoints}
                    </Badge>
                  </div>
                </button>
              ))}
          </div>
        </CardContent>
      </Card>

      {specVisible && (
        <Card className="glass-card border-border/40">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">OpenAPI Specification</CardTitle>
          </CardHeader>
          <CardContent>
            {specLoading ? (
              <Skeleton className="h-64" />
            ) : (
              <pre className="text-xs bg-muted/30 p-4 rounded-lg overflow-auto max-h-96 font-mono">
                {JSON.stringify(fullSpec, null, 2)}
              </pre>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function PlaygroundTab() {
  const [method, setMethod] = useState("GET");
  const [path, setPath] = useState("/api/health");
  const [body, setBody] = useState("");
  const [result, setResult] = useState<PlaygroundResult | null>(null);
  const { toast } = useToast();

  const mutation = useMutation({
    mutationFn: async () => {
      let parsedBody: unknown = undefined;
      if (body.trim() && method !== "GET" && method !== "HEAD") {
        try {
          parsedBody = JSON.parse(body);
        } catch {
          throw new Error("Invalid JSON body");
        }
      }
      const res = await apiRequest("POST", "/api/dev-portal/api-playground", {
        method,
        path,
        body: parsedBody,
      });
      const json = await res.json();
      return json as PlaygroundResult;
    },
    onSuccess: (data) => setResult(data),
    onError: (err) => toast({ title: String(err), variant: "destructive" }),
  });

  const presets = [
    { label: "Health", method: "GET", path: "/api/health" },
    { label: "Dashboard Stats", method: "GET", path: "/api/dashboard/stats" },
    { label: "Alerts", method: "GET", path: "/api/alerts" },
    { label: "Incidents", method: "GET", path: "/api/incidents" },
    { label: "Connectors", method: "GET", path: "/api/connectors" },
    { label: "API Status", method: "GET", path: "/api/v1/status" },
  ];

  return (
    <div className="space-y-6">
      <Card className="glass-card border-border/40">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium">Quick Presets</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap gap-2">
            {presets.map((p) => (
              <Button
                key={p.path}
                variant="outline"
                size="sm"
                className="text-xs"
                onClick={() => {
                  setMethod(p.method);
                  setPath(p.path);
                  setBody("");
                }}
              >
                <Badge
                  variant="outline"
                  className={`text-[9px] mr-1.5 ${p.method === "GET" ? "border-emerald-500/50 text-emerald-400" : "border-blue-500/50 text-blue-400"}`}
                >
                  {p.method}
                </Badge>
                {p.label}
              </Button>
            ))}
          </div>
        </CardContent>
      </Card>

      <Card className="glass-card border-border/40">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium">Request</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex gap-2">
            <select
              className="h-9 rounded-md border border-border/40 bg-background px-3 text-sm font-medium min-w-[100px]"
              value={method}
              onChange={(e) => setMethod(e.target.value)}
            >
              {["GET", "POST", "PUT", "PATCH", "DELETE"].map((m) => (
                <option key={m} value={m}>
                  {m}
                </option>
              ))}
            </select>
            <Input
              value={path}
              onChange={(e) => setPath(e.target.value)}
              placeholder="/api/..."
              className="font-mono text-sm"
            />
            <Button onClick={() => mutation.mutate()} disabled={mutation.isPending}>
              <Send className="h-4 w-4 mr-1" />
              {mutation.isPending ? "Sending..." : "Send"}
            </Button>
          </div>

          {method !== "GET" && method !== "HEAD" && (
            <Textarea
              value={body}
              onChange={(e) => setBody(e.target.value)}
              placeholder='{"key": "value"}'
              className="font-mono text-sm min-h-[80px]"
            />
          )}
        </CardContent>
      </Card>

      {result && (
        <Card className="glass-card border-border/40">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-medium">Response</CardTitle>
              <div className="flex items-center gap-2">
                <Badge
                  variant={result.status < 300 ? "default" : result.status < 400 ? "secondary" : "destructive"}
                  className="text-xs"
                >
                  {result.status} {result.statusText}
                </Badge>
                <Badge variant="outline" className="text-xs">
                  <Clock className="h-3 w-3 mr-1" />
                  {result.elapsed}ms
                </Badge>
              </div>
            </div>
          </CardHeader>
          <CardContent>
            <pre className="text-xs bg-muted/30 p-4 rounded-lg overflow-auto max-h-96 font-mono">
              {typeof result.body === "string" ? result.body : JSON.stringify(result.body, null, 2)}
            </pre>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function WebhooksTab() {
  const {
    data: logs,
    isLoading,
    refetch,
  } = useQuery<WebhookLog[]>({
    queryKey: ["/api/dev-portal/webhooks/recent"],
  });

  const [testUrl, setTestUrl] = useState("");
  const [testEvent, setTestEvent] = useState("alert.created");
  const [testResult, setTestResult] = useState<{
    success: boolean;
    status: number;
    elapsed: number;
    responseBody: string;
  } | null>(null);
  const { toast } = useToast();

  const testMutation = useMutation({
    mutationFn: async () => {
      if (!testUrl) throw new Error("URL is required");
      const res = await apiRequest("POST", "/api/dev-portal/webhooks/test", {
        url: testUrl,
        event: testEvent,
      });
      return await res.json();
    },
    onSuccess: (data) => setTestResult(data as any),
    onError: (err) => toast({ title: String(err), variant: "destructive" }),
  });

  return (
    <div className="space-y-6">
      <Card className="glass-card border-border/40">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium">Test Webhook Delivery</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex gap-2">
            <Input
              value={testUrl}
              onChange={(e) => setTestUrl(e.target.value)}
              placeholder="https://webhook.site/..."
              className="font-mono text-sm flex-1"
            />
            <select
              className="h-9 rounded-md border border-border/40 bg-background px-3 text-sm min-w-[160px]"
              value={testEvent}
              onChange={(e) => setTestEvent(e.target.value)}
            >
              {[
                "alert.created",
                "alert.updated",
                "incident.created",
                "incident.resolved",
                "connector.synced",
                "user.invited",
              ].map((e) => (
                <option key={e} value={e}>
                  {e}
                </option>
              ))}
            </select>
            <Button onClick={() => testMutation.mutate()} disabled={testMutation.isPending}>
              <Send className="h-4 w-4 mr-1" />
              {testMutation.isPending ? "Sending..." : "Send Test"}
            </Button>
          </div>

          {testResult && (
            <div
              className={`p-3 rounded-md border text-sm ${testResult.success ? "border-emerald-500/30 bg-emerald-500/5" : "border-red-500/30 bg-red-500/5"}`}
            >
              <div className="flex items-center gap-2 mb-2">
                {testResult.success ? (
                  <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                ) : (
                  <XCircle className="h-4 w-4 text-red-400" />
                )}
                <span className="font-medium">{testResult.success ? "Delivered" : "Failed"}</span>
                <Badge variant="outline" className="text-xs">
                  {testResult.status}
                </Badge>
                <Badge variant="outline" className="text-xs">
                  {testResult.elapsed}ms
                </Badge>
              </div>
              {testResult.responseBody && (
                <pre className="text-xs text-muted-foreground font-mono truncate">
                  {testResult.responseBody.slice(0, 500)}
                </pre>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      <Card className="glass-card border-border/40">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-medium">Recent Webhook Deliveries</CardTitle>
            <Button variant="ghost" size="sm" onClick={() => refetch()}>
              <RefreshCw className="h-3.5 w-3.5" />
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="space-y-2">
              {Array.from({ length: 5 }).map((_, i) => (
                <Skeleton key={i} className="h-10" />
              ))}
            </div>
          ) : !logs?.length ? (
            <div className="text-center py-6 text-muted-foreground">
              <Webhook className="h-8 w-8 mx-auto mb-2 opacity-40" />
              <p className="text-sm">No webhook deliveries yet</p>
            </div>
          ) : (
            <div className="rounded-lg border border-border/40 overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border/40 bg-muted/30">
                    <th className="text-left p-2.5 font-medium text-xs">Event</th>
                    <th className="text-left p-2.5 font-medium text-xs">URL</th>
                    <th className="text-center p-2.5 font-medium text-xs">Status</th>
                    <th className="text-left p-2.5 font-medium text-xs">Time</th>
                  </tr>
                </thead>
                <tbody>
                  {logs.map((log) => (
                    <tr key={log.id} className="border-b border-border/20 hover:bg-muted/20 transition-colors">
                      <td className="p-2.5">
                        <Badge variant="outline" className="text-xs font-mono">
                          {log.event}
                        </Badge>
                      </td>
                      <td className="p-2.5 text-xs text-muted-foreground font-mono truncate max-w-[200px]">
                        {log.url}
                      </td>
                      <td className="p-2.5 text-center">
                        <Badge variant={log.success ? "default" : "destructive"} className="text-xs">
                          {log.response_status}
                        </Badge>
                      </td>
                      <td className="p-2.5 text-xs text-muted-foreground">
                        {new Date(log.created_at).toLocaleString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function DatabaseTab() {
  const { data: tables, isLoading } = useQuery<TableInfo[]>({
    queryKey: ["/api/dev-portal/db/tables"],
  });

  const [selectedTable, setSelectedTable] = useState<string | null>(null);
  const [limit, setLimit] = useState(100);
  const [offsetVal, setOffsetVal] = useState(0);
  const [orderBy, setOrderBy] = useState("");
  const [orderDir, setOrderDir] = useState<"asc" | "desc">("desc");
  const [filtersJson, setFiltersJson] = useState("[]");
  const [queryResult, setQueryResult] = useState<{
    rows: unknown[];
    rowCount: number;
    elapsed: number;
    truncated: boolean;
  } | null>(null);
  const [tableSearch, setTableSearch] = useState("");
  const { toast } = useToast();

  const { data: schema, isLoading: schemaLoading } = useQuery<TableSchema>({
    queryKey: ["/api/dev-portal/db/table", selectedTable, "schema"],
    queryFn: async () => {
      const res = await apiRequest("GET", `/api/dev-portal/db/table/${selectedTable}/schema`);
      const json = await res.json();
      return json as TableSchema;
    },
    enabled: !!selectedTable,
  });

  const queryMutation = useMutation({
    mutationFn: async () => {
      if (!selectedTable) {
        throw new Error("Select a table first");
      }

      let parsedFilters: unknown;
      try {
        parsedFilters = filtersJson ? JSON.parse(filtersJson) : [];
      } catch {
        throw new Error("Filters must be valid JSON");
      }

      if (!Array.isArray(parsedFilters)) {
        throw new Error("Filters JSON must be an array");
      }

      const res = await apiRequest("POST", "/api/dev-portal/db/query", {
        table: selectedTable,
        where: parsedFilters,
        limit,
        offset: offsetVal,
        orderBy: orderBy || undefined,
        orderDir,
      });
      return await res.json();
    },
    onSuccess: (data) => setQueryResult(data as any),
    onError: (err) => toast({ title: String(err), variant: "destructive" }),
  });

  const filteredTables = tables?.filter((t) => t.table_name.toLowerCase().includes(tableSearch.toLowerCase()));

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card className="glass-card border-border/40">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-medium">Tables ({tables?.length || 0})</CardTitle>
            </div>
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
              <Input
                placeholder="Filter tables..."
                className="pl-9 h-8 text-xs"
                value={tableSearch}
                onChange={(e) => setTableSearch(e.target.value)}
              />
            </div>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <div className="space-y-2">
                {Array.from({ length: 8 }).map((_, i) => (
                  <Skeleton key={i} className="h-8" />
                ))}
              </div>
            ) : (
              <div className="max-h-[400px] overflow-auto space-y-0.5">
                {filteredTables?.map((t) => (
                  <button
                    key={t.table_name}
                    className={`w-full flex items-center justify-between p-2 rounded-md text-left text-xs transition-colors ${
                      selectedTable === t.table_name ? "bg-primary/10 text-primary" : "hover:bg-muted/30"
                    }`}
                    onClick={() => setSelectedTable(t.table_name)}
                  >
                    <div className="flex items-center gap-2">
                      <Table2 className="h-3.5 w-3.5 shrink-0" />
                      <span className="font-mono">{t.table_name}</span>
                    </div>
                    <div className="flex items-center gap-2 text-muted-foreground">
                      <span>{Number(t.estimated_rows).toLocaleString()} rows</span>
                      <span>{t.total_size}</span>
                    </div>
                  </button>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        <Card className="glass-card border-border/40">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium">
              {selectedTable ? `Schema: ${selectedTable}` : "Select a table"}
            </CardTitle>
          </CardHeader>
          <CardContent>
            {!selectedTable ? (
              <div className="text-center py-8 text-muted-foreground">
                <Database className="h-8 w-8 mx-auto mb-2 opacity-40" />
                <p className="text-sm">Click a table to view its schema</p>
              </div>
            ) : schemaLoading ? (
              <Skeleton className="h-48" />
            ) : schema ? (
              <div className="space-y-4">
                <div className="max-h-[250px] overflow-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b border-border/40">
                        <th className="text-left p-1.5 font-medium">Column</th>
                        <th className="text-left p-1.5 font-medium">Type</th>
                        <th className="text-center p-1.5 font-medium">Nullable</th>
                      </tr>
                    </thead>
                    <tbody>
                      {schema.columns.map((col) => (
                        <tr key={col.column_name} className="border-b border-border/10 hover:bg-muted/20">
                          <td className="p-1.5 font-mono">{col.column_name}</td>
                          <td className="p-1.5 text-muted-foreground">{col.data_type}</td>
                          <td className="p-1.5 text-center">{col.is_nullable === "YES" ? "~" : "-"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {schema.indexes.length > 0 && (
                  <div>
                    <p className="text-xs font-medium mb-1 text-muted-foreground">Indexes ({schema.indexes.length})</p>
                    <div className="space-y-1 max-h-[100px] overflow-auto">
                      {schema.indexes.map((idx) => (
                        <div
                          key={idx.indexname}
                          className="text-[10px] font-mono text-muted-foreground bg-muted/20 px-2 py-1 rounded"
                        >
                          {idx.indexname}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ) : null}
          </CardContent>
        </Card>
      </div>

      <Card className="glass-card border-border/40">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium">
            Query Runner (Read-Only){selectedTable ? `: ${selectedTable}` : ""}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {!selectedTable ? (
            <div className="text-center py-4 text-muted-foreground text-sm">
              <Database className="h-6 w-6 mx-auto mb-1.5 opacity-40" />
              Select a table from the list above to query it
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-6 gap-2">
              <div className="lg:col-span-2">
                <label className="text-[11px] text-muted-foreground">Filters (JSON array)</label>
                <Textarea
                  value={filtersJson}
                  onChange={(e) => setFiltersJson(e.target.value)}
                  placeholder={'[{"column":"org_id","op":"=","value":"..."}]'}
                  className="font-mono text-xs min-h-[56px]"
                />
              </div>
              <div>
                <label className="text-[11px] text-muted-foreground">Limit</label>
                <Input
                  type="number"
                  value={limit}
                  onChange={(e) => setLimit(Number(e.target.value))}
                  className="h-9 text-xs"
                  min={1}
                  max={500}
                />
              </div>
              <div>
                <label className="text-[11px] text-muted-foreground">Offset</label>
                <Input
                  type="number"
                  value={offsetVal}
                  onChange={(e) => setOffsetVal(Number(e.target.value))}
                  className="h-9 text-xs"
                  min={0}
                />
              </div>
              <div>
                <label className="text-[11px] text-muted-foreground">Order By</label>
                <Input
                  value={orderBy}
                  onChange={(e) => setOrderBy(e.target.value)}
                  className="h-9 text-xs font-mono"
                  placeholder="created_at"
                />
              </div>
              <div className="flex items-end gap-2">
                <div className="flex gap-1">
                  <Button
                    type="button"
                    size="sm"
                    variant={orderDir === "desc" ? "default" : "outline"}
                    onClick={() => setOrderDir("desc")}
                  >
                    DESC
                  </Button>
                  <Button
                    type="button"
                    size="sm"
                    variant={orderDir === "asc" ? "default" : "outline"}
                    onClick={() => setOrderDir("asc")}
                  >
                    ASC
                  </Button>
                </div>
                <Button
                  onClick={() => queryMutation.mutate()}
                  disabled={queryMutation.isPending || !selectedTable}
                  className="ml-auto"
                >
                  <Play className="h-4 w-4 mr-1" />
                  {queryMutation.isPending ? "Running..." : "Run"}
                </Button>
              </div>
            </div>
          )}

          {queryResult && (
            <div>
              <div className="flex items-center gap-2 mb-2 text-xs text-muted-foreground">
                <span>
                  {queryResult.rowCount} row{queryResult.rowCount !== 1 ? "s" : ""}
                </span>
                <span>{queryResult.elapsed}ms</span>
                {queryResult.truncated && (
                  <Badge variant="secondary" className="text-[10px]">
                    Truncated to 500 rows
                  </Badge>
                )}
              </div>
              <div className="rounded-lg border border-border/40 overflow-auto max-h-[300px]">
                {queryResult.rows.length > 0 ? (
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b border-border/40 bg-muted/30 sticky top-0">
                        {Object.keys(queryResult.rows[0] as object).map((key) => (
                          <th key={key} className="text-left p-2 font-medium font-mono whitespace-nowrap">
                            {key}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {queryResult.rows.map((row, i) => (
                        <tr key={i} className="border-b border-border/10 hover:bg-muted/20">
                          {Object.values(row as object).map((val, j) => (
                            <td key={j} className="p-2 font-mono whitespace-nowrap max-w-[200px] truncate">
                              {val === null ? <span className="text-muted-foreground italic">null</span> : String(val)}
                            </td>
                          ))}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : (
                  <p className="p-4 text-center text-muted-foreground text-sm">No rows returned</p>
                )}
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function ConfigTab() {
  const { data, isLoading, refetch } = useQuery<ConfigData>({
    queryKey: ["/api/dev-portal/config"],
  });

  if (isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-48" />
        <Skeleton className="h-48" />
      </div>
    );
  }

  if (!data) {
    return <p className="text-muted-foreground text-center py-8">Failed to load configuration</p>;
  }

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card className="glass-card border-border/40">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium">Environment Configuration</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {Object.entries(data.config).map(([key, value]) => (
                <div key={key} className="flex items-center justify-between p-2 rounded-md hover:bg-muted/20 text-xs">
                  <span className="font-mono font-medium">{key}</span>
                  <span className="text-muted-foreground font-mono">
                    {typeof value === "string" ? value : JSON.stringify(value)}
                  </span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card className="glass-card border-border/40">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-medium">Runtime</CardTitle>
              <Button variant="ghost" size="sm" onClick={() => refetch()}>
                <RefreshCw className="h-3.5 w-3.5" />
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            <div className="space-y-2 text-xs">
              <div className="flex justify-between p-2 rounded-md hover:bg-muted/20">
                <span className="flex items-center gap-2">
                  <Server className="h-3.5 w-3.5" /> Node.js
                </span>
                <span className="font-mono text-muted-foreground">{data.runtime.nodeVersion}</span>
              </div>
              <div className="flex justify-between p-2 rounded-md hover:bg-muted/20">
                <span className="flex items-center gap-2">
                  <Cpu className="h-3.5 w-3.5" /> Platform
                </span>
                <span className="font-mono text-muted-foreground">
                  {data.runtime.platform}/{data.runtime.arch}
                </span>
              </div>
              <div className="flex justify-between p-2 rounded-md hover:bg-muted/20">
                <span className="flex items-center gap-2">
                  <Clock className="h-3.5 w-3.5" /> Uptime
                </span>
                <span className="font-mono text-muted-foreground">{formatUptime(data.runtime.uptime)}</span>
              </div>
              <div className="flex justify-between p-2 rounded-md hover:bg-muted/20">
                <span className="flex items-center gap-2">
                  <MemoryStick className="h-3.5 w-3.5" /> Heap Used
                </span>
                <span className="font-mono text-muted-foreground">
                  {formatBytes(data.runtime.memoryUsage.heapUsed)}
                </span>
              </div>
              <div className="flex justify-between p-2 rounded-md hover:bg-muted/20">
                <span className="flex items-center gap-2">
                  <HardDrive className="h-3.5 w-3.5" /> RSS
                </span>
                <span className="font-mono text-muted-foreground">{formatBytes(data.runtime.memoryUsage.rss)}</span>
              </div>
              <div className="flex justify-between p-2 rounded-md hover:bg-muted/20">
                <span className="flex items-center gap-2">
                  <Activity className="h-3.5 w-3.5" /> PID
                </span>
                <span className="font-mono text-muted-foreground">{data.runtime.pid}</span>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <Card className="glass-card border-border/40">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium">Feature Flags ({data.featureFlags.length})</CardTitle>
        </CardHeader>
        <CardContent>
          {data.featureFlags.length === 0 ? (
            <div className="text-center py-6 text-muted-foreground">
              <ToggleLeft className="h-8 w-8 mx-auto mb-2 opacity-40" />
              <p className="text-sm">No feature flags configured</p>
            </div>
          ) : (
            <div className="space-y-1">
              {data.featureFlags.map((ff) => (
                <div key={ff.key} className="flex items-center justify-between p-2.5 rounded-md hover:bg-muted/20">
                  <div className="flex items-center gap-3">
                    {ff.enabled ? (
                      <ToggleRight className="h-4 w-4 text-emerald-400" />
                    ) : (
                      <ToggleLeft className="h-4 w-4 text-muted-foreground" />
                    )}
                    <div>
                      <span className="text-sm font-medium">{ff.name}</span>
                      <span className="text-xs text-muted-foreground ml-2 font-mono">{ff.key}</span>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant="outline" className="text-xs">
                      {ff.rollout_pct}%
                    </Badge>
                    <Badge variant={ff.enabled ? "default" : "secondary"} className="text-xs">
                      {ff.enabled ? "ON" : "OFF"}
                    </Badge>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {Object.keys(data.pool).length > 0 && (
        <Card className="glass-card border-border/40">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium">Connection Pool</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              {Object.entries(data.pool).map(([key, value]) => (
                <div key={key} className="p-3 rounded-md bg-muted/20 text-center">
                  <p className="text-xs text-muted-foreground mb-1">{key}</p>
                  <p className="text-lg font-bold font-mono">{String(value)}</p>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function DeploymentTab() {
  const { data, isLoading, refetch } = useQuery<DeploymentData>({
    queryKey: ["/api/dev-portal/deployment"],
  });

  if (isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-32" />
        <Skeleton className="h-48" />
      </div>
    );
  }

  if (!data) {
    return <p className="text-muted-foreground text-center py-8">Failed to load deployment status</p>;
  }

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="glass-card border-border/40">
          <CardContent className="p-4">
            <p className="text-xs text-muted-foreground font-medium uppercase tracking-wider">Environment</p>
            <p className="text-xl font-bold mt-1 capitalize">{data.application.environment}</p>
            <p className="text-xs text-muted-foreground mt-1">v{data.application.version}</p>
          </CardContent>
        </Card>
        <Card className="glass-card border-border/40">
          <CardContent className="p-4">
            <p className="text-xs text-muted-foreground font-medium uppercase tracking-wider">Uptime</p>
            <p className="text-xl font-bold mt-1">{formatUptime(data.application.uptime)}</p>
            <p className="text-xs text-muted-foreground mt-1">
              Since {new Date(data.application.startedAt).toLocaleString()}
            </p>
          </CardContent>
        </Card>
        <Card className="glass-card border-border/40">
          <CardContent className="p-4">
            <p className="text-xs text-muted-foreground font-medium uppercase tracking-wider">Database</p>
            <p className="text-xl font-bold mt-1 flex items-center gap-2">
              {data.database.connected ? (
                <CheckCircle2 className="h-5 w-5 text-emerald-400" />
              ) : (
                <XCircle className="h-5 w-5 text-red-400" />
              )}
              {data.database.connected ? "Connected" : "Down"}
            </p>
            <p className="text-xs text-muted-foreground mt-1">{data.database.tableCount} tables</p>
          </CardContent>
        </Card>
        <Card className="glass-card border-border/40">
          <CardContent className="p-4">
            <p className="text-xs text-muted-foreground font-medium uppercase tracking-wider">Memory</p>
            <p className="text-xl font-bold mt-1">{formatBytes(data.memory.heapUsed)}</p>
            <p className="text-xs text-muted-foreground mt-1">of {formatBytes(data.memory.heapTotal)} heap</p>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card className="glass-card border-border/40">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-medium">Application Info</CardTitle>
              <Button variant="ghost" size="sm" onClick={() => refetch()}>
                <RefreshCw className="h-3.5 w-3.5" />
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            <div className="space-y-2 text-xs">
              {[
                ["App", data.application.name],
                ["Version", `v${data.application.version}`],
                ["Node.js", data.application.nodeVersion],
                ["PID", String(data.application.pid)],
                ["Environment", data.application.environment],
                ["Started", new Date(data.application.startedAt).toLocaleString()],
              ].map(([label, value]) => (
                <div key={label} className="flex justify-between p-2 rounded-md hover:bg-muted/20">
                  <span className="font-medium">{label}</span>
                  <span className="text-muted-foreground font-mono">{value}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card className="glass-card border-border/40">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium">Database Details</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2 text-xs">
              <div className="flex justify-between p-2 rounded-md hover:bg-muted/20">
                <span className="font-medium">Engine</span>
                <span className="text-muted-foreground font-mono truncate max-w-[250px]">{data.database.version}</span>
              </div>
              <div className="flex justify-between p-2 rounded-md hover:bg-muted/20">
                <span className="font-medium">Tables</span>
                <span className="text-muted-foreground font-mono">{data.database.tableCount}</span>
              </div>
              {Object.entries(data.database.pool).map(([key, value]) => (
                <div key={key} className="flex justify-between p-2 rounded-md hover:bg-muted/20">
                  <span className="font-medium">Pool: {key}</span>
                  <span className="text-muted-foreground font-mono">{String(value)}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      <Card className="glass-card border-border/40">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium">Memory Breakdown</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {[
              { label: "RSS", value: data.memory.rss },
              { label: "Heap Total", value: data.memory.heapTotal },
              { label: "Heap Used", value: data.memory.heapUsed },
              { label: "External", value: data.memory.external },
            ].map((m) => (
              <div key={m.label} className="p-3 rounded-md bg-muted/20 text-center">
                <p className="text-xs text-muted-foreground mb-1">{m.label}</p>
                <p className="text-lg font-bold font-mono">{formatBytes(m.value)}</p>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {(data.endpoints.staging || data.endpoints.production) && (
        <Card className="glass-card border-border/40">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium">Deployment URLs</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {data.endpoints.staging && (
                <div className="flex items-center justify-between p-2 rounded-md hover:bg-muted/20">
                  <div className="flex items-center gap-2">
                    <Badge variant="secondary" className="text-xs">
                      Staging
                    </Badge>
                    <span className="text-xs font-mono">{data.endpoints.staging}</span>
                  </div>
                  <a
                    href={data.endpoints.staging}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-xs text-primary hover:underline"
                  >
                    Open
                  </a>
                </div>
              )}
              {data.endpoints.production && (
                <div className="flex items-center justify-between p-2 rounded-md hover:bg-muted/20">
                  <div className="flex items-center gap-2">
                    <Badge className="text-xs">Production</Badge>
                    <span className="text-xs font-mono">{data.endpoints.production}</span>
                  </div>
                  <a
                    href={data.endpoints.production}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-xs text-primary hover:underline"
                  >
                    Open
                  </a>
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

const TABS: { id: DevTab; label: string; icon: React.ElementType }[] = [
  { id: "api-docs", label: "API Docs", icon: Code2 },
  { id: "playground", label: "Playground", icon: Play },
  { id: "webhooks", label: "Webhooks", icon: Webhook },
  { id: "database", label: "Database", icon: Database },
  { id: "config", label: "Config", icon: Settings2 },
  { id: "deployment", label: "Deployment", icon: Rocket },
];

export default function DevPortalPage() {
  const [activeTab, setActiveTab] = useState<DevTab>("api-docs");

  return (
    <div className="p-6 max-w-[1400px] mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Developer Portal</h1>
        <p className="text-sm text-muted-foreground mt-1">
          API documentation, testing tools, database explorer, and system configuration
        </p>
      </div>

      <div className="flex gap-1 p-1 rounded-lg bg-muted/30 border border-border/40 overflow-x-auto">
        {TABS.map((tab) => {
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-all whitespace-nowrap ${
                activeTab === tab.id
                  ? "bg-background shadow-sm text-foreground"
                  : "text-muted-foreground hover:text-foreground hover:bg-muted/50"
              }`}
            >
              <Icon className="h-4 w-4" />
              {tab.label}
            </button>
          );
        })}
      </div>

      {activeTab === "api-docs" && <ApiDocsTab />}
      {activeTab === "playground" && <PlaygroundTab />}
      {activeTab === "webhooks" && <WebhooksTab />}
      {activeTab === "database" && <DatabaseTab />}
      {activeTab === "config" && <ConfigTab />}
      {activeTab === "deployment" && <DeploymentTab />}
    </div>
  );
}

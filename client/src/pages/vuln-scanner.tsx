import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Progress } from "@/components/ui/progress";
import { useToast } from "@/hooks/use-toast";
import {
  Bug,
  ShieldAlert,
  Server,
  Package,
  ChevronDown,
  ChevronRight,
  CheckCircle2,
  AlertTriangle,
  Info,
  Search,
  RefreshCw,
  ExternalLink,
  Zap,
  BarChart3,
  ShieldCheck,
  AlertCircle,
} from "lucide-react";

// ─── Types ────────────────────────────────────────────────────────────────────

interface VulnFinding {
  id: string;
  cveId: string;
  severity: string;
  cvssScore?: number;
  title?: string;
  description?: string;
  publishedAt?: string;
  fixedInVersion?: string;
  status: string;
  packageName?: string;
  packageVersion?: string;
  hostname?: string;
  sensorId: string;
  references?: string[];
  createdAt: string;
}

interface VulnStats {
  bySeverity: Record<string, number>;
  affectedHosts: number;
  totalFindings: number;
  openFindings: number;
  topVulnerablePackages: Array<{ name: string; version: string; count: number }>;
}

interface PackageRow {
  id: string;
  name: string;
  version: string;
  ecosystem: string;
  hostname: string;
  vulnCount: number;
  criticalVulnCount: number;
  lastScannedAt?: string;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const SEV_CONFIG: Record<string, { color: string; bg: string; dot: string }> = {
  critical: { color: "text-red-400", bg: "bg-red-500/10 border-red-500/20", dot: "bg-red-500" },
  high: { color: "text-orange-400", bg: "bg-orange-500/10 border-orange-500/20", dot: "bg-orange-500" },
  medium: { color: "text-yellow-400", bg: "bg-yellow-500/10 border-yellow-500/20", dot: "bg-yellow-400" },
  low: { color: "text-blue-400", bg: "bg-blue-500/10 border-blue-500/20", dot: "bg-blue-400" },
  informational: { color: "text-slate-400", bg: "bg-slate-500/10 border-slate-500/20", dot: "bg-slate-500" },
};

function SevBadge({ severity }: { severity: string }) {
  const cfg = SEV_CONFIG[severity] ?? SEV_CONFIG.medium;
  return (
    <Badge variant="outline" className={`${cfg.bg} ${cfg.color} text-xs px-1.5 py-0 gap-1 uppercase`}>
      {severity}
    </Badge>
  );
}

function cvssBar(score?: number) {
  if (!score) return null;
  const pct = (score / 10) * 100;
  const color = score >= 9 ? "bg-red-500" : score >= 7 ? "bg-orange-500" : score >= 4 ? "bg-yellow-400" : "bg-blue-400";
  return (
    <div className="flex items-center gap-2">
      <div className="w-20 h-1.5 bg-slate-700 rounded-full overflow-hidden">
        <div className={`h-full ${color} rounded-full`} style={{ width: `${pct}%` }} />
      </div>
      <span className={`text-xs font-mono font-medium ${color.replace("bg-", "text-")}`}>{score.toFixed(1)}</span>
    </div>
  );
}

// ─── Finding Row ──────────────────────────────────────────────────────────────

function FindingRow({ finding, onAck, onRemediate }: {
  finding: VulnFinding;
  onAck: (id: string) => void;
  onRemediate: (id: string) => void;
}) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className={`rounded-lg border transition-colors ${
      finding.status === "open"
        ? "border-slate-700/50 bg-slate-800/40"
        : "border-slate-700/20 bg-slate-900/30 opacity-70"
    }`}>
      <div
        className="flex items-center gap-4 p-4 cursor-pointer"
        onClick={() => setExpanded((v) => !v)}
      >
        <span className="text-slate-500 shrink-0">
          {expanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
        </span>
        <div className="shrink-0"><SevBadge severity={finding.severity} /></div>

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono text-cyan-400">{finding.cveId}</span>
            {finding.title && (
              <span className="text-sm text-white truncate">{finding.title}</span>
            )}
          </div>
          <div className="flex items-center gap-3 text-xs text-slate-500 mt-0.5">
            <span className="flex items-center gap-1">
              <Package className="h-3 w-3" />
              {finding.packageName} {finding.packageVersion}
            </span>
            <span className="flex items-center gap-1">
              <Server className="h-3 w-3" />
              {finding.hostname}
            </span>
          </div>
        </div>

        {cvssBar(finding.cvssScore)}

        <Badge
          variant="outline"
          className={`text-xs px-1.5 py-0 shrink-0 ${
            finding.status === "open"
              ? "border-red-500/30 text-red-400"
              : finding.status === "remediated"
              ? "border-emerald-500/30 text-emerald-400"
              : "border-slate-600 text-slate-400"
          }`}
        >
          {finding.status}
        </Badge>

        {finding.status === "open" && (
          <div className="flex items-center gap-1" onClick={(e) => e.stopPropagation()}>
            <Button
              size="sm"
              variant="outline"
              className="h-6 text-xs border-slate-600 text-slate-400 hover:text-white px-2"
              onClick={() => onAck(finding.id)}
            >
              Ack
            </Button>
            <Button
              size="sm"
              className="h-6 text-xs bg-emerald-700/50 hover:bg-emerald-700 text-emerald-300 px-2"
              onClick={() => onRemediate(finding.id)}
            >
              Fixed
            </Button>
          </div>
        )}
      </div>

      {expanded && (
        <div className="px-4 pb-4 border-t border-slate-700/30 pt-3 space-y-2">
          {finding.description && (
            <p className="text-sm text-slate-400">{finding.description}</p>
          )}
          <div className="flex flex-wrap gap-4 text-xs">
            {finding.fixedInVersion && (
              <div>
                <span className="text-slate-500">Fix available in: </span>
                <span className="text-emerald-400 font-mono">{finding.fixedInVersion}</span>
              </div>
            )}
            {finding.publishedAt && (
              <div>
                <span className="text-slate-500">Published: </span>
                <span className="text-slate-300">{new Date(finding.publishedAt).toLocaleDateString()}</span>
              </div>
            )}
          </div>
          {(finding.references ?? []).length > 0 && (
            <div className="flex items-center gap-2 flex-wrap">
              {(finding.references ?? []).map((ref) => (
                <a
                  key={ref}
                  href={ref}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300"
                >
                  <ExternalLink className="h-3 w-3" />
                  {ref.replace(/^https?:\/\//, "").slice(0, 40)}
                </a>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Stats cards ──────────────────────────────────────────────────────────────

function StatsBar({ stats }: { stats?: VulnStats }) {
  if (!stats) return null;

  const sev = stats.bySeverity ?? {};
  const total = stats.totalFindings;

  return (
    <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
      {[
        { label: "Critical", value: sev.critical ?? 0, color: "text-red-400", bg: "bg-red-500/10" },
        { label: "High", value: sev.high ?? 0, color: "text-orange-400", bg: "bg-orange-500/10" },
        { label: "Medium", value: sev.medium ?? 0, color: "text-yellow-400", bg: "bg-yellow-500/10" },
        { label: "Low", value: sev.low ?? 0, color: "text-blue-400", bg: "bg-blue-500/10" },
        { label: "Hosts Affected", value: stats.affectedHosts, color: "text-violet-400", bg: "bg-violet-500/10" },
      ].map((s) => (
        <Card key={s.label} className="bg-slate-900/60 border-slate-700/50">
          <CardContent className="p-3">
            <div className={`text-2xl font-bold ${s.color}`}>{s.value}</div>
            <div className="text-xs text-slate-500 uppercase tracking-wider">{s.label}</div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

// ─── Main Page ─────────────────────────────────────────────────────────────────

export default function VulnScannerPage() {
  const [search, setSearch] = useState("");
  const [filterSev, setFilterSev] = useState("all");
  const [filterStatus, setFilterStatus] = useState("open");
  const [tab, setTab] = useState("findings");
  const { toast } = useToast();

  const { data: statsData } = useQuery<{ data: VulnStats }>({
    queryKey: ["/api/native/vuln/stats"],
  });

  const { data: findingsData, isLoading } = useQuery<{ data: VulnFinding[] }>({
    queryKey: ["/api/native/vuln/findings", filterSev, filterStatus],
    queryFn: () => {
      const params = new URLSearchParams();
      if (filterSev !== "all") params.set("severity", filterSev);
      if (filterStatus !== "all") params.set("status", filterStatus);
      return apiRequest("GET", `/api/native/vuln/findings?${params}`).then((r) => r.json());
    },
  });

  const { data: inventoryData } = useQuery<{ data: PackageRow[] }>({
    queryKey: ["/api/native/vuln/inventory"],
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) =>
      apiRequest("PATCH", `/api/native/vuln/findings/${id}`, { status }).then((r) => r.json()),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/native/vuln/findings"] });
      queryClient.invalidateQueries({ queryKey: ["/api/native/vuln/stats"] });
      toast({ title: "Finding updated" });
    },
  });

  const findings = (findingsData?.data ?? []).filter(
    (f) =>
      !search ||
      f.cveId.toLowerCase().includes(search.toLowerCase()) ||
      (f.packageName ?? "").toLowerCase().includes(search.toLowerCase()) ||
      (f.hostname ?? "").toLowerCase().includes(search.toLowerCase()),
  );

  const stats = statsData?.data;
  const inventory = inventoryData?.data ?? [];

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Bug className="h-6 w-6 text-orange-400" />
            Native Vulnerability Scanner
          </h1>
          <p className="text-slate-400 text-sm mt-1">
            Agent-based CVE detection — no Qualys or Tenable required.
          </p>
        </div>
        <Button
          variant="outline"
          className="border-slate-600 text-slate-300 hover:text-white gap-2"
          onClick={() => {
            queryClient.invalidateQueries({ queryKey: ["/api/native/vuln/findings"] });
            queryClient.invalidateQueries({ queryKey: ["/api/native/vuln/stats"] });
            toast({ title: "Refreshed" });
          }}
        >
          <RefreshCw className="h-4 w-4" />
          Refresh
        </Button>
      </div>

      {/* USP banner */}
      <div className="rounded-xl border border-orange-500/20 bg-orange-500/5 p-4">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {[
            { icon: <Package className="h-5 w-5 text-orange-400" />, title: "Package Inventory", desc: "Agents report every installed package — apt, rpm, pip, npm, gem, cargo, nuget" },
            { icon: <ShieldAlert className="h-5 w-5 text-red-400" />, title: "CVE Matching", desc: "Packages matched against NVD CVE database. Famous CVEs (Log4Shell, Heartbleed) detected instantly." },
            { icon: <ShieldCheck className="h-5 w-5 text-emerald-400" />, title: "Remediation Tracking", desc: "Track fix progress per CVE across all hosts. Know when you're actually patched." },
          ].map((item) => (
            <div key={item.title} className="flex items-start gap-3">
              {item.icon}
              <div>
                <p className="text-sm font-medium text-white">{item.title}</p>
                <p className="text-xs text-slate-400">{item.desc}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      <StatsBar stats={stats} />

      <Tabs value={tab} onValueChange={setTab}>
        <TabsList className="bg-slate-800 border-slate-700">
          <TabsTrigger value="findings" className="data-[state=active]:bg-slate-700 text-slate-300 data-[state=active]:text-white">
            Findings ({findings.length})
          </TabsTrigger>
          <TabsTrigger value="inventory" className="data-[state=active]:bg-slate-700 text-slate-300 data-[state=active]:text-white">
            Package Inventory
          </TabsTrigger>
        </TabsList>

        <TabsContent value="findings" className="mt-4 space-y-4">
          <div className="flex items-center gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500" />
              <Input
                placeholder="Search CVE, package, host..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-9 bg-slate-800 border-slate-600 text-white placeholder:text-slate-500"
              />
            </div>
            <Select value={filterSev} onValueChange={setFilterSev}>
              <SelectTrigger className="w-36 bg-slate-800 border-slate-600 text-slate-300">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="bg-slate-800 border-slate-600">
                <SelectItem value="all" className="text-slate-200">All severities</SelectItem>
                {["critical", "high", "medium", "low"].map((s) => (
                  <SelectItem key={s} value={s} className="text-slate-200 capitalize">{s}</SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={filterStatus} onValueChange={setFilterStatus}>
              <SelectTrigger className="w-32 bg-slate-800 border-slate-600 text-slate-300">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="bg-slate-800 border-slate-600">
                {["all", "open", "acknowledged", "remediated"].map((s) => (
                  <SelectItem key={s} value={s} className="text-slate-200 capitalize">{s}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {isLoading ? (
            <div className="space-y-2">{Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-14 w-full rounded-lg" />)}</div>
          ) : findings.length === 0 ? (
            <div className="text-center py-12 text-slate-500">
              <ShieldCheck className="h-10 w-10 mx-auto mb-3 opacity-40 text-emerald-500" />
              <p>No vulnerabilities found matching your filters.</p>
              <p className="text-sm mt-1">Deploy a sensor agent and submit package inventory to see CVE findings.</p>
            </div>
          ) : (
            <div className="space-y-2">
              {findings.map((f) => (
                <FindingRow
                  key={f.id}
                  finding={f}
                  onAck={(id) => updateMutation.mutate({ id, status: "acknowledged" })}
                  onRemediate={(id) => updateMutation.mutate({ id, status: "remediated" })}
                />
              ))}
            </div>
          )}
        </TabsContent>

        <TabsContent value="inventory" className="mt-4">
          {inventory.length === 0 ? (
            <div className="text-center py-12 text-slate-500">
              <Package className="h-10 w-10 mx-auto mb-3 opacity-40" />
              <p>No package inventory yet. Sensor agents report packages on first scan.</p>
            </div>
          ) : (
            <div className="space-y-2">
              {inventory.map((pkg) => (
                <div key={pkg.id} className="flex items-center gap-4 p-4 rounded-lg bg-slate-800/40 border border-slate-700/50">
                  <Package className="h-4 w-4 text-slate-500 shrink-0" />
                  <div className="flex-1">
                    <span className="text-sm font-medium text-white">{pkg.name}</span>
                    <span className="text-xs text-slate-500 ml-2 font-mono">{pkg.version}</span>
                    <span className="text-xs text-slate-600 ml-2">({pkg.ecosystem})</span>
                  </div>
                  <span className="text-xs text-slate-500">{pkg.hostname}</span>
                  {pkg.criticalVulnCount > 0 ? (
                    <Badge variant="outline" className="text-xs border-red-500/30 text-red-400">
                      {pkg.criticalVulnCount} critical
                    </Badge>
                  ) : pkg.vulnCount > 0 ? (
                    <Badge variant="outline" className="text-xs border-orange-500/30 text-orange-400">
                      {pkg.vulnCount} vulns
                    </Badge>
                  ) : (
                    <Badge variant="outline" className="text-xs border-emerald-500/20 text-emerald-500">clean</Badge>
                  )}
                </div>
              ))}
            </div>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}

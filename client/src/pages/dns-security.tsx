import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { useToast } from "@/hooks/use-toast";
import {
  Globe,
  Shield,
  AlertTriangle,
  Search,
  Plus,
  Activity,
  Eye,
  Ban,
  Network,
  Cpu,
  Zap,
  BarChart3,
  Clock,
} from "lucide-react";
import { fetchCsrfToken } from "@/lib/queryClient";
import { DashboardSkeleton } from "@/components/page-skeleton";
import { ReadOnlyActionNotice } from "@/components/read-only-action-notice";
import { useOrgContext } from "@/hooks/use-org-context";

type DnsEvent = {
  id: string;
  timestamp: string;
  eventType: string;
  queryName: string;
  queryType: string;
  sourceIp: string;
  entropy: number;
  isSuspicious: boolean;
};

type DnsFinding = {
  id: string;
  findingType: string;
  severity: string;
  domain: string;
  description: string;
  confidence: number;
  sourceIp: string;
  status: string;
  createdAt: string;
  mitreTechnique: string;
};

type Sinkhole = {
  id: string;
  domain: string;
  reason: string;
  status: string;
  hitCount: number;
  lastHitAt: string;
  createdAt: string;
};

type PassiveDnsRecord = {
  id: string;
  domain: string;
  recordType: string;
  resolvedValue: string;
  firstSeen: string;
  lastSeen: string;
  queryCount: number;
};

type DnsStats = {
  totalEvents: number;
  totalFindings: number;
  openFindings: number;
  sinkholedDomainCount: number;
  sinkholedHits: number;
  passiveDnsRecordCount: number;
  topQueriedDomains?: Array<{ domain: string; count: number }>;
  topNxdomains?: Array<{ domain: string; count: number }>;
  ingestionStatus?: {
    healthy: boolean;
    totalEventsLast24h: number;
    sources: Array<{ type: string; label: string; detected: boolean; eventCount: number }>;
  };
  policyStats?: {
    blockedQueries30d: number;
    activeRpzEntries: number;
    sinkholeHits30d: number;
    enforcementActive: boolean;
  };
};

type DgaResult = {
  isDga: boolean;
  confidence: number;
  entropy: number;
  features: Record<string, unknown>;
};

type NrdResult = {
  isNewlyRegistered: boolean;
  domainAgeDays: number | null;
  risk: string;
};

type TunnelingResult = {
  isTunneling: boolean;
  confidence: number;
  indicators: Record<string, unknown>;
};

type ExfiltrationResult = {
  isExfiltration: boolean;
  confidence: number;
  indicators: Record<string, unknown>;
};

async function apiFetch<T = unknown>(url: string, options?: RequestInit): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options?.headers as Record<string, string>),
  };
  const method = options?.method || "GET";
  if (method !== "GET" && method !== "HEAD") {
    const csrfToken = await fetchCsrfToken();
    if (csrfToken) headers["X-CSRF-Token"] = csrfToken;
  }
  try {
    const activeOrgId = localStorage.getItem("securenexus.activeOrgId");
    if (activeOrgId) headers["X-Org-Id"] = activeOrgId;
  } catch {
    /* SSR / privacy mode */
  }
  const res = await fetch(url, {
    ...options,
    credentials: "include",
    headers,
  });
  const body = await res.json();
  const errors = body?.errors;
  if (!res.ok) {
    throw new Error(errors?.[0]?.message || body?.error || res.statusText);
  }
  if (Array.isArray(errors) && errors.length > 0) {
    throw new Error(errors[0]?.message || "The server returned an error.");
  }
  return (body && typeof body === "object" && "data" in body ? body.data : body) as T;
}

function parseListResponse<T>(payload: unknown, label: string): { items: T[]; total: number } {
  if (
    !payload ||
    typeof payload !== "object" ||
    !Array.isArray((payload as { items?: unknown }).items) ||
    typeof (payload as { total?: unknown }).total !== "number"
  ) {
    throw new Error(`${label} returned an invalid response.`);
  }
  return payload as { items: T[]; total: number };
}

function severityColor(severity: string) {
  switch (severity) {
    case "critical":
      return "destructive";
    case "high":
      return "destructive";
    case "medium":
      return "secondary";
    default:
      return "outline";
  }
}

function StatCard({ label, value, icon: Icon }: { label: string; value: number | string; icon: React.ElementType }) {
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground">{label}</CardTitle>
        <Icon className="h-4 w-4 text-muted-foreground" />
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-bold">{value}</div>
      </CardContent>
    </Card>
  );
}

function DnsEventsTab() {
  const [eventType, setEventType] = useState("all");
  const [sourceIp, setSourceIp] = useState("");
  const [domainFilter, setDomainFilter] = useState("");

  const params = new URLSearchParams();
  if (eventType && eventType !== "all") params.set("eventType", eventType);
  if (sourceIp) params.set("sourceIp", sourceIp);
  if (domainFilter) params.set("domain", domainFilter);
  params.set("limit", "50");

  const { data, isLoading, isError } = useQuery<{ items: DnsEvent[]; total: number }>({
    queryKey: ["/api/dns-security/events", eventType, sourceIp, domainFilter],
    queryFn: async () =>
      parseListResponse<DnsEvent>(await apiFetch(`/api/dns-security/events?${params.toString()}`), "DNS events"),
    retry: false,
  });

  return (
    <div className="space-y-4">
      <div className="flex gap-2 items-end flex-wrap">
        <div>
          <Label className="text-xs">Event Type</Label>
          <Select value={eventType} onValueChange={setEventType}>
            <SelectTrigger className="w-40">
              <SelectValue placeholder="All types" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All types</SelectItem>
              <SelectItem value="query">Query</SelectItem>
              <SelectItem value="blocked">Blocked</SelectItem>
              <SelectItem value="sinkholed">Sinkholed</SelectItem>
              <SelectItem value="dga_detected">DGA Detected</SelectItem>
              <SelectItem value="tunneling_detected">Tunneling</SelectItem>
              <SelectItem value="exfiltration_detected">Exfiltration</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div>
          <Label className="text-xs">Source IP</Label>
          <Input
            className="w-36"
            placeholder="Filter by IP"
            value={sourceIp}
            onChange={(e) => setSourceIp(e.target.value)}
          />
        </div>
        <div>
          <Label className="text-xs">Domain</Label>
          <Input
            className="w-48"
            placeholder="Filter by domain"
            value={domainFilter}
            onChange={(e) => setDomainFilter(e.target.value)}
          />
        </div>
      </div>

      {isLoading && <p className="text-muted-foreground text-sm">Loading events...</p>}
      {isError && (
        <p className="text-sm text-destructive">DNS events are unavailable because the server returned an error.</p>
      )}

      {data && (
        <>
          <p className="text-sm text-muted-foreground">{data.total} total events</p>
          <div className="border rounded-md overflow-auto">
            <table className="w-full text-sm">
              <thead className="bg-muted/50">
                <tr>
                  <th className="text-left p-2 font-medium">Time</th>
                  <th className="text-left p-2 font-medium">Type</th>
                  <th className="text-left p-2 font-medium">Domain</th>
                  <th className="text-left p-2 font-medium">Query Type</th>
                  <th className="text-left p-2 font-medium">Source IP</th>
                  <th className="text-left p-2 font-medium">Entropy</th>
                  <th className="text-left p-2 font-medium">Suspicious</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map(
                  (e: {
                    id: string;
                    timestamp: string;
                    eventType: string;
                    queryName: string;
                    queryType: string;
                    sourceIp: string;
                    entropy: number;
                    isSuspicious: boolean;
                  }) => (
                    <tr key={e.id} className="border-t hover:bg-muted/30">
                      <td className="p-2 text-xs">{e.timestamp ? new Date(e.timestamp).toLocaleString() : "—"}</td>
                      <td className="p-2">
                        <Badge variant="outline" className="text-xs">
                          {e.eventType}
                        </Badge>
                      </td>
                      <td className="p-2 font-mono text-xs max-w-[200px] truncate">{e.queryName}</td>
                      <td className="p-2">{e.queryType}</td>
                      <td className="p-2 font-mono text-xs">{e.sourceIp || "—"}</td>
                      <td className="p-2">{e.entropy?.toFixed(2) || "—"}</td>
                      <td className="p-2">
                        {e.isSuspicious && (
                          <Badge variant="destructive" className="text-xs">
                            Suspicious
                          </Badge>
                        )}
                      </td>
                    </tr>
                  ),
                )}
                {data.items.length === 0 && (
                  <tr>
                    <td colSpan={7} className="p-4 text-center text-muted-foreground">
                      No DNS events found
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}

function DnsFindingsTab() {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [findingType, setFindingType] = useState("all");
  const [severity, setSeverity] = useState("all");
  const [status, setStatus] = useState("open");

  const params = new URLSearchParams();
  if (findingType && findingType !== "all") params.set("findingType", findingType);
  if (severity && severity !== "all") params.set("severity", severity);
  if (status && status !== "all") params.set("status", status);
  params.set("limit", "50");

  const { data, isLoading, isError } = useQuery<{ items: DnsFinding[]; total: number }>({
    queryKey: ["/api/dns-security/findings", findingType, severity, status],
    queryFn: async () =>
      parseListResponse<DnsFinding>(await apiFetch(`/api/dns-security/findings?${params.toString()}`), "DNS findings"),
    retry: false,
  });

  const resolveMut = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/dns-security/findings/${id}`, {
        method: "PATCH",
        body: JSON.stringify({ status: "resolved" }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/dns-security/findings"] });
      queryClient.invalidateQueries({ queryKey: ["/api/dns-security/dashboard"] });
      toast({ title: "Finding resolved" });
    },
  });

  return (
    <div className="space-y-4">
      <div className="flex gap-2 items-end flex-wrap">
        <div>
          <Label className="text-xs">Type</Label>
          <Select value={findingType} onValueChange={setFindingType}>
            <SelectTrigger className="w-44">
              <SelectValue placeholder="All types" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All types</SelectItem>
              <SelectItem value="dga_domain">DGA Domain</SelectItem>
              <SelectItem value="dns_tunneling">DNS Tunneling</SelectItem>
              <SelectItem value="dns_exfiltration">Exfiltration</SelectItem>
              <SelectItem value="newly_registered_domain">Newly Registered</SelectItem>
              <SelectItem value="sinkholed_hit">Sinkhole Hit</SelectItem>
              <SelectItem value="high_entropy_query">High Entropy</SelectItem>
              <SelectItem value="suspicious_txt_record">Suspicious TXT</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div>
          <Label className="text-xs">Severity</Label>
          <Select value={severity} onValueChange={setSeverity}>
            <SelectTrigger className="w-28">
              <SelectValue placeholder="All" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All</SelectItem>
              <SelectItem value="critical">Critical</SelectItem>
              <SelectItem value="high">High</SelectItem>
              <SelectItem value="medium">Medium</SelectItem>
              <SelectItem value="low">Low</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div>
          <Label className="text-xs">Status</Label>
          <Select value={status} onValueChange={setStatus}>
            <SelectTrigger className="w-28">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All</SelectItem>
              <SelectItem value="open">Open</SelectItem>
              <SelectItem value="resolved">Resolved</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      {isLoading && <p className="text-muted-foreground text-sm">Loading findings...</p>}
      {isError && (
        <p className="text-sm text-destructive">DNS findings are unavailable because the server returned an error.</p>
      )}

      {data && (
        <>
          <p className="text-sm text-muted-foreground">{data.total} total findings</p>
          <div className="space-y-2">
            {data.items.map(
              (f: {
                id: string;
                findingType: string;
                severity: string;
                domain: string;
                description: string;
                confidence: number;
                sourceIp: string;
                status: string;
                createdAt: string;
                mitreTechnique: string;
              }) => (
                <Card key={f.id}>
                  <CardContent className="p-4">
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-1">
                          <Badge variant={severityColor(f.severity)} className="text-xs capitalize">
                            {f.severity}
                          </Badge>
                          <Badge variant="outline" className="text-xs">
                            {f.findingType.replace(/_/g, " ")}
                          </Badge>
                          {f.mitreTechnique && (
                            <Badge variant="outline" className="text-xs">
                              {f.mitreTechnique}
                            </Badge>
                          )}
                          {f.confidence !== null && (
                            <span className="text-xs text-muted-foreground">
                              {Math.round(f.confidence * 100)}% confidence
                            </span>
                          )}
                        </div>
                        <p className="text-sm font-mono">{f.domain}</p>
                        <p className="text-xs text-muted-foreground mt-1">{f.description}</p>
                        <div className="flex gap-4 mt-2 text-xs text-muted-foreground">
                          <span>Source: {f.sourceIp || "—"}</span>
                          <span>{f.createdAt ? new Date(f.createdAt).toLocaleString() : ""}</span>
                        </div>
                      </div>
                      {f.status === "open" && (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => resolveMut.mutate(f.id)}
                          disabled={resolveMut.isPending}
                        >
                          Resolve
                        </Button>
                      )}
                      {f.status === "resolved" && (
                        <Badge variant="default" className="text-xs">
                          Resolved
                        </Badge>
                      )}
                    </div>
                  </CardContent>
                </Card>
              ),
            )}
            {data.items.length === 0 && <p className="text-center text-muted-foreground py-8">No findings found</p>}
          </div>
        </>
      )}
    </div>
  );
}

function SinkholesTab() {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [showAdd, setShowAdd] = useState(false);
  const [newDomain, setNewDomain] = useState("");
  const [newReason, setNewReason] = useState("");

  const { data, isLoading, isError } = useQuery<{ items: Sinkhole[]; total: number }>({
    queryKey: ["/api/dns-security/sinkholes"],
    queryFn: async () =>
      parseListResponse<Sinkhole>(await apiFetch("/api/dns-security/sinkholes?limit=100"), "DNS sinkholes"),
  });

  const addMut = useMutation({
    mutationFn: (body: { domain: string; reason: string }) =>
      apiFetch("/api/dns-security/sinkholes", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/dns-security/sinkholes"] });
      queryClient.invalidateQueries({ queryKey: ["/api/dns-security/dashboard"] });
      toast({ title: "Domain sinkholed" });
      setNewDomain("");
      setNewReason("");
      setShowAdd(false);
    },
  });

  const toggleMut = useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) =>
      apiFetch(`/api/dns-security/sinkholes/${id}`, {
        method: "PATCH",
        body: JSON.stringify({ status }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/dns-security/sinkholes"] });
      toast({ title: "Sinkhole updated" });
    },
  });

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <p className="text-sm text-muted-foreground">{data?.total || 0} sinkholed domains</p>
        <Dialog open={showAdd} onOpenChange={setShowAdd}>
          <DialogTrigger asChild>
            <Button size="sm">
              <Plus className="h-4 w-4 mr-1" />
              Add Domain
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Sinkhole Domain</DialogTitle>
            </DialogHeader>
            <div className="space-y-3">
              <div>
                <Label>Domain</Label>
                <Input
                  placeholder="malicious-domain.xyz"
                  value={newDomain}
                  onChange={(e) => setNewDomain(e.target.value)}
                />
              </div>
              <div>
                <Label>Reason</Label>
                <Textarea
                  placeholder="Why is this domain being sinkholed?"
                  value={newReason}
                  onChange={(e) => setNewReason(e.target.value)}
                />
              </div>
              <Button
                onClick={() => addMut.mutate({ domain: newDomain, reason: newReason })}
                disabled={!newDomain || addMut.isPending}
                className="w-full"
              >
                Sinkhole Domain
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      {isLoading && <p className="text-muted-foreground text-sm">Loading sinkholes...</p>}
      {isError && (
        <p className="text-sm text-destructive">DNS sinkholes are unavailable because the server returned an error.</p>
      )}

      {data && (
        <div className="border rounded-md overflow-auto">
          <table className="w-full text-sm">
            <thead className="bg-muted/50">
              <tr>
                <th className="text-left p-2 font-medium">Domain</th>
                <th className="text-left p-2 font-medium">Reason</th>
                <th className="text-left p-2 font-medium">Status</th>
                <th className="text-left p-2 font-medium">Hits</th>
                <th className="text-left p-2 font-medium">Last Hit</th>
                <th className="text-left p-2 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map(
                (s: {
                  id: string;
                  domain: string;
                  reason: string;
                  status: string;
                  hitCount: number;
                  lastHitAt: string;
                  createdAt: string;
                }) => (
                  <tr key={s.id} className="border-t hover:bg-muted/30">
                    <td className="p-2 font-mono">{s.domain}</td>
                    <td className="p-2 text-xs max-w-[200px] truncate">{s.reason || "—"}</td>
                    <td className="p-2">
                      <Badge variant={s.status === "active" ? "default" : "secondary"} className="text-xs capitalize">
                        {s.status}
                      </Badge>
                    </td>
                    <td className="p-2">{s.hitCount}</td>
                    <td className="p-2 text-xs">{s.lastHitAt ? new Date(s.lastHitAt).toLocaleString() : "Never"}</td>
                    <td className="p-2">
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() =>
                          toggleMut.mutate({
                            id: s.id,
                            status: s.status === "active" ? "inactive" : "active",
                          })
                        }
                      >
                        {s.status === "active" ? "Disable" : "Enable"}
                      </Button>
                    </td>
                  </tr>
                ),
              )}
              {data.items.length === 0 && (
                <tr>
                  <td colSpan={6} className="p-4 text-center text-muted-foreground">
                    No sinkholed domains
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function PassiveDnsTab() {
  const [domainFilter, setDomainFilter] = useState("");

  const params = new URLSearchParams();
  if (domainFilter) params.set("domain", domainFilter);
  params.set("limit", "50");

  const { data, isLoading, isError } = useQuery<{ items: PassiveDnsRecord[]; total: number }>({
    queryKey: ["/api/dns-security/passive-dns", domainFilter],
    queryFn: async () =>
      parseListResponse<PassiveDnsRecord>(
        await apiFetch(`/api/dns-security/passive-dns?${params.toString()}`),
        "Passive DNS",
      ),
  });

  return (
    <div className="space-y-4">
      <div>
        <Label className="text-xs">Search Domain</Label>
        <Input
          className="w-64"
          placeholder="Search passive DNS records..."
          value={domainFilter}
          onChange={(e) => setDomainFilter(e.target.value)}
        />
      </div>

      {isLoading && <p className="text-muted-foreground text-sm">Loading records...</p>}
      {isError && (
        <p className="text-sm text-destructive">
          Passive DNS data is unavailable because the server returned an error.
        </p>
      )}

      {data && (
        <>
          <p className="text-sm text-muted-foreground">{data.total} passive DNS records</p>
          <div className="border rounded-md overflow-auto">
            <table className="w-full text-sm">
              <thead className="bg-muted/50">
                <tr>
                  <th className="text-left p-2 font-medium">Domain</th>
                  <th className="text-left p-2 font-medium">Type</th>
                  <th className="text-left p-2 font-medium">Resolved Value</th>
                  <th className="text-left p-2 font-medium">First Seen</th>
                  <th className="text-left p-2 font-medium">Last Seen</th>
                  <th className="text-left p-2 font-medium">Queries</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map(
                  (r: {
                    id: string;
                    domain: string;
                    recordType: string;
                    resolvedValue: string;
                    firstSeen: string;
                    lastSeen: string;
                    queryCount: number;
                  }) => (
                    <tr key={r.id} className="border-t hover:bg-muted/30">
                      <td className="p-2 font-mono text-xs">{r.domain}</td>
                      <td className="p-2">
                        <Badge variant="outline" className="text-xs">
                          {r.recordType}
                        </Badge>
                      </td>
                      <td className="p-2 font-mono text-xs">{r.resolvedValue}</td>
                      <td className="p-2 text-xs">{r.firstSeen ? new Date(r.firstSeen).toLocaleDateString() : "—"}</td>
                      <td className="p-2 text-xs">{r.lastSeen ? new Date(r.lastSeen).toLocaleDateString() : "—"}</td>
                      <td className="p-2">{r.queryCount}</td>
                    </tr>
                  ),
                )}
                {data.items.length === 0 && (
                  <tr>
                    <td colSpan={6} className="p-4 text-center text-muted-foreground">
                      No passive DNS records
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}

function AnalysisToolsTab() {
  const { isPlatformAdminReadOnly } = useOrgContext();
  const { toast } = useToast();
  const [domain, setDomain] = useState("");
  const [dgaResult, setDgaResult] = useState<DgaResult | null>(null);
  const [nrdResult, setNrdResult] = useState<NrdResult | null>(null);
  const [tunnelingDomain, setTunnelingDomain] = useState("");
  const [tunnelingResult, setTunnelingResult] = useState<TunnelingResult | null>(null);
  const [exfilIp, setExfilIp] = useState("");
  const [exfilResult, setExfilResult] = useState<ExfiltrationResult | null>(null);

  const dgaMut = useMutation({
    mutationFn: (d: string) =>
      apiFetch<DgaResult>("/api/dns-security/analyze/dga", {
        method: "POST",
        body: JSON.stringify({ domain: d }),
      }),
    onSuccess: (data) => setDgaResult(data),
  });

  const nrdMut = useMutation({
    mutationFn: (d: string) =>
      apiFetch<NrdResult>("/api/dns-security/analyze/nrd", {
        method: "POST",
        body: JSON.stringify({ domain: d }),
      }),
    onSuccess: (data) => setNrdResult(data),
  });

  const tunnelingMut = useMutation({
    mutationFn: (d: string) =>
      apiFetch<TunnelingResult>("/api/dns-security/analyze/tunneling", {
        method: "POST",
        body: JSON.stringify({ domain: d }),
      }),
    onSuccess: (data) => setTunnelingResult(data),
  });

  const exfilMut = useMutation({
    mutationFn: (ip: string) =>
      apiFetch<ExfiltrationResult>("/api/dns-security/analyze/exfiltration", {
        method: "POST",
        body: JSON.stringify({ sourceIp: ip }),
      }),
    onSuccess: (data) => setExfilResult(data),
  });

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
      {/* DGA Detection */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">DGA Detection</CardTitle>
          <CardDescription>Analyze a domain for algorithmically generated patterns</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex gap-2">
            <Input placeholder="suspicious-domain.xyz" value={domain} onChange={(e) => setDomain(e.target.value)} />
            <Button
              size="sm"
              onClick={() => {
                dgaMut.mutate(domain);
                nrdMut.mutate(domain);
              }}
              disabled={!domain || dgaMut.isPending || isPlatformAdminReadOnly}
            >
              <Search className="h-4 w-4 mr-1" /> Analyze
            </Button>
          </div>
          <ReadOnlyActionNotice />
          {/* 71.2 — DGA Detection Visualization with confidence, entropy, lexical breakdown */}
          {dgaResult && (
            <div className="p-3 border rounded-md text-sm space-y-2">
              <div className="flex items-center gap-2">
                <Badge variant={dgaResult.isDga ? "destructive" : "default"}>
                  {dgaResult.isDga ? "DGA Detected" : "Legitimate"}
                </Badge>
                <span className="text-xs text-muted-foreground">
                  Confidence: {Math.round(dgaResult.confidence * 100)}%
                </span>
              </div>
              <div className="grid grid-cols-3 gap-2 mt-2">
                <div className="p-2 bg-muted/30 rounded text-center">
                  <p className="text-lg font-bold">
                    {typeof dgaResult.entropy === "number" ? dgaResult.entropy.toFixed(2) : dgaResult.entropy}
                  </p>
                  <p className="text-[10px] text-muted-foreground">Character Entropy</p>
                </div>
                <div className="p-2 bg-muted/30 rounded text-center">
                  <p className="text-lg font-bold">{Math.round(dgaResult.confidence * 100)}%</p>
                  <p className="text-[10px] text-muted-foreground">Confidence Score</p>
                </div>
                <div className="p-2 bg-muted/30 rounded text-center">
                  <p className="text-lg font-bold">{domain.length}</p>
                  <p className="text-[10px] text-muted-foreground">Domain Length</p>
                </div>
              </div>
              {dgaResult.features && Object.keys(dgaResult.features).length > 0 && (
                <div className="mt-2">
                  <p className="text-xs font-medium mb-1">Lexical Feature Breakdown</p>
                  <div className="grid grid-cols-2 gap-1">
                    {Object.entries(dgaResult.features).map(([key, val]) => (
                      <div key={key} className="flex justify-between text-xs py-0.5 px-2 bg-muted/20 rounded">
                        <span className="text-muted-foreground">{key.replace(/_/g, " ")}</span>
                        <span className="font-mono">
                          {typeof val === "number" ? (val as number).toFixed(2) : String(val)}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
          {nrdResult && (
            <div className="p-3 border rounded-md text-sm space-y-1">
              <div className="flex items-center gap-2">
                <Badge variant={nrdResult.isNewlyRegistered ? "destructive" : "outline"}>
                  {nrdResult.isNewlyRegistered ? "Newly Registered" : "Established"}
                </Badge>
                <Badge variant="outline" className="capitalize">
                  {nrdResult.risk} risk
                </Badge>
              </div>
              {nrdResult.domainAgeDays !== null && (
                <p className="text-xs">Domain age: {nrdResult.domainAgeDays} days</p>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* DNS Tunneling Detection */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">DNS Tunneling Detection</CardTitle>
          <CardDescription>Check for data tunneling through DNS queries to a domain</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex gap-2">
            <Input
              placeholder="base-domain.com"
              value={tunnelingDomain}
              onChange={(e) => setTunnelingDomain(e.target.value)}
            />
            <Button
              size="sm"
              onClick={() => tunnelingMut.mutate(tunnelingDomain)}
              disabled={!tunnelingDomain || tunnelingMut.isPending || isPlatformAdminReadOnly}
            >
              <Cpu className="h-4 w-4 mr-1" /> Check
            </Button>
          </div>
          <ReadOnlyActionNotice />
          {/* 71.3 — DNS Tunneling Detection Visualization */}
          {tunnelingResult && (
            <div className="p-3 border rounded-md text-sm space-y-2">
              <Badge variant={tunnelingResult.isTunneling ? "destructive" : "default"}>
                {tunnelingResult.isTunneling ? "Tunneling Detected" : "No Tunneling"}
              </Badge>
              <div className="grid grid-cols-2 gap-2 mt-2">
                <div className="p-2 bg-muted/30 rounded text-center">
                  <p className="text-lg font-bold">{Math.round(tunnelingResult.confidence * 100)}%</p>
                  <p className="text-[10px] text-muted-foreground">Confidence</p>
                </div>
                <div className="p-2 bg-muted/30 rounded text-center">
                  <p className="text-lg font-bold">
                    {tunnelingResult.indicators && typeof tunnelingResult.indicators === "object"
                      ? (tunnelingResult.indicators as Record<string, unknown>).estimatedBandwidthKB
                        ? `${(tunnelingResult.indicators as Record<string, unknown>).estimatedBandwidthKB} KB`
                        : "—"
                      : "—"}
                  </p>
                  <p className="text-[10px] text-muted-foreground">Est. Exfil Bandwidth</p>
                </div>
              </div>
              {tunnelingResult.indicators && Object.keys(tunnelingResult.indicators).length > 0 && (
                <div className="mt-1">
                  <p className="text-xs font-medium mb-1">Detection Indicators</p>
                  <div className="grid grid-cols-2 gap-1">
                    {Object.entries(tunnelingResult.indicators).map(([key, val]) => (
                      <div key={key} className="flex justify-between text-xs py-0.5 px-2 bg-muted/20 rounded">
                        <span className="text-muted-foreground">{key.replace(/_/g, " ")}</span>
                        <span className="font-mono">
                          {typeof val === "number" ? (val as number).toFixed(2) : String(val)}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* DNS Exfiltration Detection */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">DNS Exfiltration Detection</CardTitle>
          <CardDescription>Analyze a source IP for DNS-based data exfiltration patterns</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex gap-2">
            <Input placeholder="10.0.0.50" value={exfilIp} onChange={(e) => setExfilIp(e.target.value)} />
            <Button
              size="sm"
              onClick={() => exfilMut.mutate(exfilIp)}
              disabled={!exfilIp || exfilMut.isPending || isPlatformAdminReadOnly}
            >
              <Zap className="h-4 w-4 mr-1" /> Analyze
            </Button>
          </div>
          <ReadOnlyActionNotice />
          {exfilResult && (
            <div className="p-3 border rounded-md text-sm space-y-2">
              <Badge variant={exfilResult.isExfiltration ? "destructive" : "default"}>
                {exfilResult.isExfiltration ? "Exfiltration Detected" : "No Exfiltration"}
              </Badge>
              <div className="grid grid-cols-2 gap-2 mt-2">
                <div className="p-2 bg-muted/30 rounded text-center">
                  <p className="text-lg font-bold">{Math.round(exfilResult.confidence * 100)}%</p>
                  <p className="text-[10px] text-muted-foreground">Confidence</p>
                </div>
                <div className="p-2 bg-muted/30 rounded text-center">
                  <p className="text-lg font-bold">
                    {exfilResult.indicators && typeof exfilResult.indicators === "object"
                      ? (exfilResult.indicators as Record<string, unknown>).uniqueDomains
                        ? String((exfilResult.indicators as Record<string, unknown>).uniqueDomains)
                        : "—"
                      : "—"}
                  </p>
                  <p className="text-[10px] text-muted-foreground">Unique Domains</p>
                </div>
              </div>
              {exfilResult.indicators && Object.keys(exfilResult.indicators).length > 0 && (
                <div className="mt-1">
                  <p className="text-xs font-medium mb-1">Exfiltration Indicators</p>
                  <div className="grid grid-cols-2 gap-1">
                    {Object.entries(exfilResult.indicators).map(([key, val]) => (
                      <div key={key} className="flex justify-between text-xs py-0.5 px-2 bg-muted/20 rounded">
                        <span className="text-muted-foreground">{key.replace(/_/g, " ")}</span>
                        <span className="font-mono">
                          {typeof val === "number" ? (val as number).toFixed(2) : String(val)}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

export default function DnsSecurityPage() {
  const {
    data: stats,
    isLoading,
    isError: isStatsError,
  } = useQuery<DnsStats>({
    queryKey: ["/api/dns-security/dashboard"],
    queryFn: () => apiFetch<DnsStats>("/api/dns-security/dashboard"),
    retry: false,
  });

  if (isLoading) return <DashboardSkeleton />;

  return (
    <div className="p-6 space-y-6 max-w-[1400px] mx-auto">
      <div>
        <h1 className="text-2xl font-bold">DNS Security</h1>
        <p className="text-muted-foreground text-sm">
          Native DNS threat detection, sinkholing, and passive DNS intelligence
        </p>
      </div>
      {isStatsError && (
        <p className="text-sm text-destructive">
          DNS dashboard data is unavailable because the server returned an error.
        </p>
      )}

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4">
          <StatCard label="DNS Events (30d)" value={stats.totalEvents} icon={Activity} />
          <StatCard label="Total Findings" value={stats.totalFindings} icon={AlertTriangle} />
          <StatCard label="Open Findings" value={stats.openFindings} icon={Eye} />
          <StatCard label="Sinkholed Domains" value={stats.sinkholedDomainCount} icon={Ban} />
          <StatCard label="Sinkhole Hits" value={stats.sinkholedHits} icon={Shield} />
          <StatCard label="Passive DNS Records" value={stats.passiveDnsRecordCount} icon={Network} />
        </div>
      )}

      {/* 71.1 — DNS Query Dashboard: top queried domains, NXDomain, query volume */}
      {stats?.topQueriedDomains && stats.topQueriedDomains.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-base flex items-center gap-2">
                <BarChart3 className="h-4 w-4" /> Top Queried Domains
              </CardTitle>
              <CardDescription>Most frequently queried domains in the last 30 days</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                {stats.topQueriedDomains.slice(0, 10).map((d: { domain: string; count: number }, i: number) => (
                  <div
                    key={d.domain}
                    className="flex items-center justify-between py-1 border-b border-border/30 last:border-0"
                  >
                    <span className="text-sm font-mono truncate flex-1">
                      {i + 1}. {d.domain}
                    </span>
                    <Badge variant="outline" className="text-xs ml-2">
                      {d.count}
                    </Badge>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-base flex items-center gap-2">
                <AlertTriangle className="h-4 w-4" /> Top NXDomain Responses
              </CardTitle>
              <CardDescription>Domains returning NXDOMAIN — may indicate DGA or misconfig</CardDescription>
            </CardHeader>
            <CardContent>
              {stats.topNxdomains && stats.topNxdomains.length > 0 ? (
                <div className="space-y-2">
                  {stats.topNxdomains.slice(0, 10).map((d: { domain: string; count: number }, i: number) => (
                    <div
                      key={d.domain}
                      className="flex items-center justify-between py-1 border-b border-border/30 last:border-0"
                    >
                      <span className="text-sm font-mono truncate flex-1">
                        {i + 1}. {d.domain}
                      </span>
                      <Badge variant="destructive" className="text-xs ml-2">
                        {d.count}
                      </Badge>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-sm text-muted-foreground text-center py-4">No NXDomain responses recorded</p>
              )}
            </CardContent>
          </Card>
        </div>
      )}

      {/* 71.5 — DNS Log Ingestion Status */}
      {stats?.ingestionStatus && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base flex items-center gap-2">
              <Network className="h-4 w-4" /> DNS Log Ingestion Sources
            </CardTitle>
            <CardDescription>
              {stats.ingestionStatus.healthy
                ? `Receiving DNS data — ${stats.ingestionStatus.totalEventsLast24h} events in last 24h`
                : "No DNS events received in the last 24 hours — check your log sources"}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
              {stats.ingestionStatus.sources?.map(
                (s: { type: string; label: string; detected: boolean; eventCount: number }) => (
                  <div
                    key={s.type}
                    className={`p-3 border rounded-lg text-center ${s.detected ? "border-green-500/30 bg-green-500/5" : "border-border/50"}`}
                  >
                    <p className="text-xs font-medium">{s.label}</p>
                    <p className={`text-lg font-bold mt-1 ${s.detected ? "text-green-400" : "text-muted-foreground"}`}>
                      {s.detected ? s.eventCount : "—"}
                    </p>
                    <Badge variant={s.detected ? "default" : "secondary"} className="text-[10px] mt-1">
                      {s.detected ? "Active" : "Not Detected"}
                    </Badge>
                  </div>
                ),
              )}
            </div>
          </CardContent>
        </Card>
      )}

      {/* 71.6 — DNS Policy Enforcement Summary */}
      {stats?.policyStats && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base flex items-center gap-2">
              <Ban className="h-4 w-4" /> DNS Policy Enforcement
            </CardTitle>
            <CardDescription>Response Policy Zone (RPZ) status and blocked query volume</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="text-center">
                <p className="text-2xl font-bold">{stats.policyStats.blockedQueries30d}</p>
                <p className="text-xs text-muted-foreground">Blocked Queries (30d)</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-bold">{stats.policyStats.activeRpzEntries}</p>
                <p className="text-xs text-muted-foreground">Active RPZ Entries</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-bold">{stats.policyStats.sinkholeHits30d}</p>
                <p className="text-xs text-muted-foreground">Sinkhole Hits (30d)</p>
              </div>
              <div className="text-center">
                <Badge variant={stats.policyStats.enforcementActive ? "default" : "secondary"} className="text-xs">
                  {stats.policyStats.enforcementActive ? "Enforcement Active" : "No Active Policies"}
                </Badge>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      <Tabs defaultValue="findings" className="space-y-4">
        <TabsList>
          <TabsTrigger value="findings">Findings</TabsTrigger>
          <TabsTrigger value="events">Events</TabsTrigger>
          <TabsTrigger value="sinkholes">Sinkholes</TabsTrigger>
          <TabsTrigger value="passive-dns">Passive DNS</TabsTrigger>
          <TabsTrigger value="analysis">Analysis Tools</TabsTrigger>
        </TabsList>

        <TabsContent value="findings">
          <DnsFindingsTab />
        </TabsContent>

        <TabsContent value="events">
          <DnsEventsTab />
        </TabsContent>

        <TabsContent value="sinkholes">
          <SinkholesTab />
        </TabsContent>

        <TabsContent value="passive-dns">
          <PassiveDnsTab />
        </TabsContent>

        <TabsContent value="analysis">
          <AnalysisToolsTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}

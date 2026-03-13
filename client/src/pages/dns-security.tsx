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
import { Globe, Shield, AlertTriangle, Search, Plus, Activity, Eye, Ban, Network, Cpu, Zap } from "lucide-react";

function apiFetch(url: string, options?: RequestInit) {
  return fetch(url, {
    ...options,
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      ...options?.headers,
    },
  }).then(async (r) => {
    const data = await r.json();
    if (!r.ok) throw new Error(data?.error || r.statusText);
    return data;
  });
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
  const [eventType, setEventType] = useState("");
  const [sourceIp, setSourceIp] = useState("");
  const [domainFilter, setDomainFilter] = useState("");

  const params = new URLSearchParams();
  if (eventType) params.set("eventType", eventType);
  if (sourceIp) params.set("sourceIp", sourceIp);
  if (domainFilter) params.set("domain", domainFilter);
  params.set("limit", "50");

  const { data, isLoading } = useQuery({
    queryKey: ["/api/dns-security/events", eventType, sourceIp, domainFilter],
    queryFn: () => apiFetch(`/api/dns-security/events?${params.toString()}`),
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
              <SelectItem value="">All types</SelectItem>
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
  const [findingType, setFindingType] = useState("");
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("open");

  const params = new URLSearchParams();
  if (findingType) params.set("findingType", findingType);
  if (severity) params.set("severity", severity);
  if (status) params.set("status", status);
  params.set("limit", "50");

  const { data, isLoading } = useQuery({
    queryKey: ["/api/dns-security/findings", findingType, severity, status],
    queryFn: () => apiFetch(`/api/dns-security/findings?${params.toString()}`),
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
              <SelectItem value="">All types</SelectItem>
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
              <SelectItem value="">All</SelectItem>
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
              <SelectItem value="">All</SelectItem>
              <SelectItem value="open">Open</SelectItem>
              <SelectItem value="resolved">Resolved</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      {isLoading && <p className="text-muted-foreground text-sm">Loading findings...</p>}

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

  const { data, isLoading } = useQuery({
    queryKey: ["/api/dns-security/sinkholes"],
    queryFn: () => apiFetch("/api/dns-security/sinkholes?limit=100"),
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

  const { data, isLoading } = useQuery({
    queryKey: ["/api/dns-security/passive-dns", domainFilter],
    queryFn: () => apiFetch(`/api/dns-security/passive-dns?${params.toString()}`),
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
  const { toast } = useToast();
  const [domain, setDomain] = useState("");
  const [dgaResult, setDgaResult] = useState<{
    isDga: boolean;
    confidence: number;
    entropy: number;
    features: Record<string, unknown>;
  } | null>(null);
  const [nrdResult, setNrdResult] = useState<{
    isNewlyRegistered: boolean;
    domainAgeDays: number | null;
    risk: string;
  } | null>(null);
  const [tunnelingDomain, setTunnelingDomain] = useState("");
  const [tunnelingResult, setTunnelingResult] = useState<{
    isTunneling: boolean;
    confidence: number;
    indicators: Record<string, unknown>;
  } | null>(null);
  const [exfilIp, setExfilIp] = useState("");
  const [exfilResult, setExfilResult] = useState<{
    isExfiltration: boolean;
    confidence: number;
    indicators: Record<string, unknown>;
  } | null>(null);

  const dgaMut = useMutation({
    mutationFn: (d: string) =>
      apiFetch("/api/dns-security/analyze/dga", { method: "POST", body: JSON.stringify({ domain: d }) }),
    onSuccess: (data) => setDgaResult(data),
  });

  const nrdMut = useMutation({
    mutationFn: (d: string) =>
      apiFetch("/api/dns-security/analyze/nrd", { method: "POST", body: JSON.stringify({ domain: d }) }),
    onSuccess: (data) => setNrdResult(data),
  });

  const tunnelingMut = useMutation({
    mutationFn: (d: string) =>
      apiFetch("/api/dns-security/analyze/tunneling", { method: "POST", body: JSON.stringify({ domain: d }) }),
    onSuccess: (data) => setTunnelingResult(data),
  });

  const exfilMut = useMutation({
    mutationFn: (ip: string) =>
      apiFetch("/api/dns-security/analyze/exfiltration", { method: "POST", body: JSON.stringify({ sourceIp: ip }) }),
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
              disabled={!domain || dgaMut.isPending}
            >
              <Search className="h-4 w-4 mr-1" /> Analyze
            </Button>
          </div>
          {dgaResult && (
            <div className="p-3 border rounded-md text-sm space-y-1">
              <div className="flex items-center gap-2">
                <Badge variant={dgaResult.isDga ? "destructive" : "default"}>
                  {dgaResult.isDga ? "DGA Detected" : "Legitimate"}
                </Badge>
                <span className="text-xs text-muted-foreground">
                  Confidence: {Math.round(dgaResult.confidence * 100)}%
                </span>
              </div>
              <p className="text-xs">Entropy: {dgaResult.entropy}</p>
              <p className="text-xs text-muted-foreground">Features: {JSON.stringify(dgaResult.features)}</p>
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
              disabled={!tunnelingDomain || tunnelingMut.isPending}
            >
              <Cpu className="h-4 w-4 mr-1" /> Check
            </Button>
          </div>
          {tunnelingResult && (
            <div className="p-3 border rounded-md text-sm space-y-1">
              <Badge variant={tunnelingResult.isTunneling ? "destructive" : "default"}>
                {tunnelingResult.isTunneling ? "Tunneling Detected" : "No Tunneling"}
              </Badge>
              <p className="text-xs text-muted-foreground">
                Confidence: {Math.round(tunnelingResult.confidence * 100)}% | Indicators:{" "}
                {JSON.stringify(tunnelingResult.indicators)}
              </p>
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
            <Button size="sm" onClick={() => exfilMut.mutate(exfilIp)} disabled={!exfilIp || exfilMut.isPending}>
              <Zap className="h-4 w-4 mr-1" /> Analyze
            </Button>
          </div>
          {exfilResult && (
            <div className="p-3 border rounded-md text-sm space-y-1">
              <Badge variant={exfilResult.isExfiltration ? "destructive" : "default"}>
                {exfilResult.isExfiltration ? "Exfiltration Detected" : "No Exfiltration"}
              </Badge>
              <p className="text-xs text-muted-foreground">
                Confidence: {Math.round(exfilResult.confidence * 100)}% | Indicators:{" "}
                {JSON.stringify(exfilResult.indicators)}
              </p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

export default function DnsSecurityPage() {
  const { data: stats, isLoading } = useQuery({
    queryKey: ["/api/dns-security/dashboard"],
    queryFn: () => apiFetch("/api/dns-security/dashboard"),
  });

  return (
    <div className="p-6 space-y-6 max-w-[1400px] mx-auto">
      <div>
        <h1 className="text-2xl font-bold">DNS Security</h1>
        <p className="text-muted-foreground text-sm">
          Native DNS threat detection, sinkholing, and passive DNS intelligence
        </p>
      </div>

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

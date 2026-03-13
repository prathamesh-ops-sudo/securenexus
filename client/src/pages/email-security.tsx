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
  Mail,
  Shield,
  AlertTriangle,
  Search,
  Plus,
  Activity,
  Eye,
  Ban,
  Link2,
  UserX,
  Clock,
  RefreshCw,
  Cloud,
  Lock,
  FileWarning,
  Globe,
} from "lucide-react";

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

// ─── Findings Tab ───────────────────────────────────────────────────────────

function EmailFindingsTab() {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [findingType, setFindingType] = useState("");
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("open");
  const [senderFilter, setSenderFilter] = useState("");

  const params = new URLSearchParams();
  if (findingType) params.set("findingType", findingType);
  if (severity) params.set("severity", severity);
  if (status) params.set("status", status);
  if (senderFilter) params.set("sender", senderFilter);
  params.set("limit", "50");

  const { data, isLoading } = useQuery({
    queryKey: ["/api/email-security/findings", findingType, severity, status, senderFilter],
    queryFn: () => apiFetch(`/api/email-security/findings?${params.toString()}`),
  });

  const resolveMut = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/email-security/findings/${id}`, {
        method: "PATCH",
        body: JSON.stringify({ status: "resolved" }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/email-security/findings"] });
      queryClient.invalidateQueries({ queryKey: ["/api/email-security/dashboard"] });
      toast({ title: "Finding resolved" });
    },
  });

  return (
    <div className="space-y-4">
      <div className="flex gap-2 items-end flex-wrap">
        <div>
          <Label className="text-xs">Type</Label>
          <Select value={findingType} onValueChange={setFindingType}>
            <SelectTrigger className="w-48">
              <SelectValue placeholder="All types" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="">All types</SelectItem>
              <SelectItem value="spf_fail">SPF Fail</SelectItem>
              <SelectItem value="dkim_fail">DKIM Fail</SelectItem>
              <SelectItem value="dmarc_fail">DMARC Fail</SelectItem>
              <SelectItem value="bec_lookalike_domain">BEC Lookalike</SelectItem>
              <SelectItem value="bec_executive_impersonation">Executive Impersonation</SelectItem>
              <SelectItem value="bec_reply_to_mismatch">Reply-To Mismatch</SelectItem>
              <SelectItem value="malicious_url">Malicious URL</SelectItem>
              <SelectItem value="dangerous_attachment">Dangerous Attachment</SelectItem>
              <SelectItem value="thread_injection">Thread Injection</SelectItem>
              <SelectItem value="retroactive_ioc_match">Retroactive IOC</SelectItem>
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
              <SelectItem value="investigating">Investigating</SelectItem>
              <SelectItem value="resolved">Resolved</SelectItem>
              <SelectItem value="false_positive">False Positive</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div>
          <Label className="text-xs">Sender</Label>
          <Input
            className="w-48"
            placeholder="Filter by sender"
            value={senderFilter}
            onChange={(e) => setSenderFilter(e.target.value)}
          />
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
                title: string;
                description: string;
                confidence: number;
                senderAddress: string;
                domain: string;
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
                        <p className="text-sm font-medium">{f.title || f.findingType.replace(/_/g, " ")}</p>
                        <p className="text-xs text-muted-foreground mt-1">{f.description}</p>
                        <div className="flex gap-4 mt-2 text-xs text-muted-foreground">
                          <span>Sender: {f.senderAddress || "—"}</span>
                          <span>Domain: {f.domain || "—"}</span>
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

// ─── Policies Tab ───────────────────────────────────────────────────────────

function EmailPoliciesTab() {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [showAdd, setShowAdd] = useState(false);
  const [newName, setNewName] = useState("");
  const [newDescription, setNewDescription] = useState("");
  const [newType, setNewType] = useState("spf_enforcement");
  const [newAction, setNewAction] = useState("quarantine");

  const { data, isLoading } = useQuery({
    queryKey: ["/api/email-security/policies"],
    queryFn: () => apiFetch("/api/email-security/policies?limit=100"),
  });

  const addMut = useMutation({
    mutationFn: (body: { name: string; description: string; policyType: string; action: string }) =>
      apiFetch("/api/email-security/policies", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/email-security/policies"] });
      toast({ title: "Policy created" });
      setNewName("");
      setNewDescription("");
      setShowAdd(false);
    },
  });

  const toggleMut = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      apiFetch(`/api/email-security/policies/${id}`, {
        method: "PATCH",
        body: JSON.stringify({ enabled }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/email-security/policies"] });
      toast({ title: "Policy updated" });
    },
  });

  const deleteMut = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/email-security/policies/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/email-security/policies"] });
      toast({ title: "Policy deleted" });
    },
  });

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <p className="text-sm text-muted-foreground">{data?.total || 0} policies configured</p>
        <Dialog open={showAdd} onOpenChange={setShowAdd}>
          <DialogTrigger asChild>
            <Button size="sm">
              <Plus className="h-4 w-4 mr-1" />
              Add Policy
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Create Email Policy</DialogTitle>
            </DialogHeader>
            <div className="space-y-3">
              <div>
                <Label>Name</Label>
                <Input
                  placeholder="e.g. Block DMARC failures"
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                />
              </div>
              <div>
                <Label>Description</Label>
                <Textarea
                  placeholder="Policy description"
                  value={newDescription}
                  onChange={(e) => setNewDescription(e.target.value)}
                />
              </div>
              <div>
                <Label>Type</Label>
                <Select value={newType} onValueChange={setNewType}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="spf_enforcement">SPF Enforcement</SelectItem>
                    <SelectItem value="dkim_enforcement">DKIM Enforcement</SelectItem>
                    <SelectItem value="dmarc_enforcement">DMARC Enforcement</SelectItem>
                    <SelectItem value="bec_protection">BEC Protection</SelectItem>
                    <SelectItem value="attachment_scanning">Attachment Scanning</SelectItem>
                    <SelectItem value="url_rewriting">URL Rewriting</SelectItem>
                    <SelectItem value="sender_reputation">Sender Reputation</SelectItem>
                    <SelectItem value="thread_injection">Thread Injection</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label>Action</Label>
                <Select value={newAction} onValueChange={setNewAction}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="allow">Allow</SelectItem>
                    <SelectItem value="quarantine">Quarantine</SelectItem>
                    <SelectItem value="block">Block</SelectItem>
                    <SelectItem value="tag">Tag</SelectItem>
                    <SelectItem value="redirect">Redirect</SelectItem>
                    <SelectItem value="alert">Alert</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <Button
                onClick={() =>
                  addMut.mutate({
                    name: newName,
                    description: newDescription,
                    policyType: newType,
                    action: newAction,
                  })
                }
                disabled={!newName || addMut.isPending}
                className="w-full"
              >
                Create Policy
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      {isLoading && <p className="text-muted-foreground text-sm">Loading policies...</p>}

      {data && (
        <div className="border rounded-md overflow-auto">
          <table className="w-full text-sm">
            <thead className="bg-muted/50">
              <tr>
                <th className="text-left p-2 font-medium">Name</th>
                <th className="text-left p-2 font-medium">Type</th>
                <th className="text-left p-2 font-medium">Action</th>
                <th className="text-left p-2 font-medium">Priority</th>
                <th className="text-left p-2 font-medium">Status</th>
                <th className="text-left p-2 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map(
                (p: {
                  id: string;
                  name: string;
                  policyType: string;
                  action: string;
                  priority: number;
                  enabled: boolean;
                  matchCount: number;
                }) => (
                  <tr key={p.id} className="border-t hover:bg-muted/30">
                    <td className="p-2 font-medium">{p.name}</td>
                    <td className="p-2">
                      <Badge variant="outline" className="text-xs">
                        {p.policyType.replace(/_/g, " ")}
                      </Badge>
                    </td>
                    <td className="p-2">
                      <Badge
                        variant={
                          p.action === "block" ? "destructive" : p.action === "quarantine" ? "secondary" : "outline"
                        }
                        className="text-xs capitalize"
                      >
                        {p.action}
                      </Badge>
                    </td>
                    <td className="p-2">{p.priority}</td>
                    <td className="p-2">
                      <Badge variant={p.enabled ? "default" : "secondary"} className="text-xs">
                        {p.enabled ? "Active" : "Disabled"}
                      </Badge>
                    </td>
                    <td className="p-2 flex gap-1">
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => toggleMut.mutate({ id: p.id, enabled: !p.enabled })}
                      >
                        {p.enabled ? "Disable" : "Enable"}
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        className="text-destructive"
                        onClick={() => deleteMut.mutate(p.id)}
                      >
                        Delete
                      </Button>
                    </td>
                  </tr>
                ),
              )}
              {data.items.length === 0 && (
                <tr>
                  <td colSpan={6} className="p-4 text-center text-muted-foreground">
                    No policies configured
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

// ─── Integrations Tab ───────────────────────────────────────────────────────

function IntegrationsTab() {
  const { toast } = useToast();

  const m365Mut = useMutation({
    mutationFn: () => apiFetch("/api/email-security/m365/sync", { method: "POST" }),
    onSuccess: (data) => {
      toast({ title: "Microsoft 365", description: data.message });
    },
    onError: (err: Error) => {
      toast({ title: "Error", description: err.message, variant: "destructive" });
    },
  });

  const gmailMut = useMutation({
    mutationFn: () => apiFetch("/api/email-security/gmail/sync", { method: "POST" }),
    onSuccess: (data) => {
      toast({ title: "Google Workspace", description: data.message });
    },
    onError: (err: Error) => {
      toast({ title: "Error", description: err.message, variant: "destructive" });
    },
  });

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-semibold mb-4">Cloud Email Integrations</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Cloud className="h-5 w-5" />
                Microsoft 365
              </CardTitle>
              <CardDescription>Connect via Microsoft Graph API for native mailbox monitoring</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="text-sm space-y-1">
                <p className="text-muted-foreground">Required configuration:</p>
                <ul className="list-disc list-inside text-xs text-muted-foreground space-y-0.5">
                  <li>Azure AD Tenant ID</li>
                  <li>App Registration Client ID &amp; Secret</li>
                  <li>Mail.Read / Mail.ReadBasic application permissions</li>
                  <li>Target mailbox (e.g. security@company.com)</li>
                </ul>
              </div>
              <Button onClick={() => m365Mut.mutate()} disabled={m365Mut.isPending} className="w-full">
                <RefreshCw className={`h-4 w-4 mr-2 ${m365Mut.isPending ? "animate-spin" : ""}`} />
                Sync Microsoft 365
              </Button>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Globe className="h-5 w-5" />
                Google Workspace
              </CardTitle>
              <CardDescription>Connect via Gmail API with Pub/Sub push notifications</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="text-sm space-y-1">
                <p className="text-muted-foreground">Required configuration:</p>
                <ul className="list-disc list-inside text-xs text-muted-foreground space-y-0.5">
                  <li>OAuth2 Client ID &amp; Secret</li>
                  <li>Refresh Token (domain-wide delegation)</li>
                  <li>Cloud Pub/Sub topic for push notifications</li>
                  <li>Target Gmail user to monitor</li>
                </ul>
              </div>
              <Button onClick={() => gmailMut.mutate()} disabled={gmailMut.isPending} className="w-full">
                <RefreshCw className={`h-4 w-4 mr-2 ${gmailMut.isPending ? "animate-spin" : ""}`} />
                Sync Google Workspace
              </Button>
            </CardContent>
          </Card>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Integration Status</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-sm text-muted-foreground">
            <p>
              Configure API credentials in your organization's Integration Settings to enable native email monitoring.
              Once connected, emails are automatically ingested, analyzed for threats (SPF/DKIM/DMARC validation, BEC
              detection, URL scanning, attachment analysis), and findings are generated in real-time.
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Thread Injection Tab ───────────────────────────────────────────────────

function ThreadInjectionTab() {
  const [threadId, setThreadId] = useState("");
  const [senderAddress, setSenderAddress] = useState("");
  const [inReplyTo, setInReplyTo] = useState("");
  const [result, setResult] = useState<{
    isInjection: boolean;
    confidence: number;
    indicators: string[];
    newSender: boolean;
    timingAnomaly: boolean;
  } | null>(null);

  const analyzeMut = useMutation({
    mutationFn: () =>
      apiFetch("/api/email-security/analyze/thread-injection", {
        method: "POST",
        body: JSON.stringify({
          threadId,
          senderAddress,
          inReplyTo: inReplyTo || null,
        }),
      }),
    onSuccess: (data) => setResult(data),
  });

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <UserX className="h-5 w-5" />
            Thread Injection Detection
          </CardTitle>
          <CardDescription>
            Detect when attackers insert themselves into existing email threads by analyzing conversation patterns,
            sender history, and timing anomalies.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div>
              <Label>Thread / Conversation ID</Label>
              <Input placeholder="conversation-id-123" value={threadId} onChange={(e) => setThreadId(e.target.value)} />
            </div>
            <div>
              <Label>Sender Address</Label>
              <Input
                placeholder="suspicious@example.com"
                value={senderAddress}
                onChange={(e) => setSenderAddress(e.target.value)}
              />
            </div>
            <div>
              <Label>In-Reply-To (optional)</Label>
              <Input
                placeholder="<message-id@example.com>"
                value={inReplyTo}
                onChange={(e) => setInReplyTo(e.target.value)}
              />
            </div>
          </div>
          <Button onClick={() => analyzeMut.mutate()} disabled={!threadId || !senderAddress || analyzeMut.isPending}>
            <Search className="h-4 w-4 mr-2" />
            Analyze Thread
          </Button>

          {result && (
            <Card className={result.isInjection ? "border-destructive" : "border-green-500"}>
              <CardContent className="p-4">
                <div className="flex items-center gap-3 mb-3">
                  <Badge variant={result.isInjection ? "destructive" : "default"}>
                    {result.isInjection ? "Thread Injection Detected" : "No Injection Detected"}
                  </Badge>
                  <span className="text-sm text-muted-foreground">
                    Confidence: {Math.round(result.confidence * 100)}%
                  </span>
                </div>
                {result.indicators.length > 0 && (
                  <div className="space-y-1">
                    <p className="text-xs font-medium">Indicators:</p>
                    <ul className="list-disc list-inside text-xs text-muted-foreground space-y-0.5">
                      {result.indicators.map((ind, i) => (
                        <li key={i}>{ind}</li>
                      ))}
                    </ul>
                  </div>
                )}
                <div className="flex gap-4 mt-3 text-xs">
                  <span>New sender in thread: {result.newSender ? "Yes" : "No"}</span>
                  <span>Timing anomaly: {result.timingAnomaly ? "Yes" : "No"}</span>
                </div>
              </CardContent>
            </Card>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>How Thread Injection Works</CardTitle>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground space-y-2">
          <p>
            Attackers compromise one party in an email conversation, then inject fraudulent messages into the thread.
            Because the thread appears legitimate, recipients are more likely to trust the injected messages.
          </p>
          <p>Detection signals include:</p>
          <ul className="list-disc list-inside space-y-0.5">
            <li>New sender appearing in an established thread</li>
            <li>Broken In-Reply-To / References header chain</li>
            <li>Timing anomalies (messages arriving after extended gaps)</li>
            <li>Domain mismatches between thread participants</li>
          </ul>
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Retroactive IOC Scan Tab ───────────────────────────────────────────────

function RetroactiveScanTab() {
  const { toast } = useToast();
  const [iocValue, setIocValue] = useState("");
  const [iocType, setIocType] = useState("domain");
  const [lookbackDays, setLookbackDays] = useState("90");
  const [iocList, setIocList] = useState<Array<{ value: string; type: string }>>([]);
  const [scanResult, setScanResult] = useState<{
    totalScanned: number;
    matches: Array<{
      emailMessageId: string;
      senderAddress: string;
      subject: string;
      matchedIoc: string;
      matchType: string;
      receivedAt: string;
    }>;
    iocCount: number;
  } | null>(null);

  const scanMut = useMutation({
    mutationFn: () =>
      apiFetch("/api/email-security/retroactive-scan", {
        method: "POST",
        body: JSON.stringify({
          iocs: iocList,
          lookbackDays: Number(lookbackDays),
        }),
      }),
    onSuccess: (data) => {
      setScanResult(data);
      toast({ title: `Scan complete: ${data.matches.length} matches found` });
    },
    onError: (err: Error) => {
      toast({ title: "Scan failed", description: err.message, variant: "destructive" });
    },
  });

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Clock className="h-5 w-5" />
            Retroactive IOC Scanning
          </CardTitle>
          <CardDescription>
            When new IOCs are identified, scan all historical emails to find past exposure. Add IOCs below and scan your
            email corpus.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex gap-2 items-end">
            <div className="flex-1">
              <Label>IOC Value</Label>
              <Input
                placeholder="malicious-domain.com or attacker@evil.com"
                value={iocValue}
                onChange={(e) => setIocValue(e.target.value)}
              />
            </div>
            <div>
              <Label>Type</Label>
              <Select value={iocType} onValueChange={setIocType}>
                <SelectTrigger className="w-28">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="domain">Domain</SelectItem>
                  <SelectItem value="email">Email</SelectItem>
                  <SelectItem value="url">URL</SelectItem>
                  <SelectItem value="ip">IP</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <Button
              variant="outline"
              onClick={() => {
                if (iocValue.trim()) {
                  setIocList((prev) => [...prev, { value: iocValue.trim(), type: iocType }]);
                  setIocValue("");
                }
              }}
              disabled={!iocValue.trim()}
            >
              <Plus className="h-4 w-4 mr-1" />
              Add
            </Button>
          </div>

          {iocList.length > 0 && (
            <div className="space-y-2">
              <p className="text-sm font-medium">{iocList.length} IOCs queued</p>
              <div className="flex flex-wrap gap-2">
                {iocList.map((ioc, i) => (
                  <Badge key={i} variant="outline" className="text-xs">
                    {ioc.type}: {ioc.value}
                    <button
                      className="ml-1 hover:text-destructive"
                      onClick={() => setIocList((prev) => prev.filter((_, idx) => idx !== i))}
                    >
                      x
                    </button>
                  </Badge>
                ))}
              </div>
            </div>
          )}

          <div className="flex gap-3 items-end">
            <div>
              <Label>Lookback Days</Label>
              <Input
                type="number"
                className="w-24"
                value={lookbackDays}
                onChange={(e) => setLookbackDays(e.target.value)}
              />
            </div>
            <Button onClick={() => scanMut.mutate()} disabled={iocList.length === 0 || scanMut.isPending}>
              <Search className="h-4 w-4 mr-2" />
              {scanMut.isPending ? "Scanning..." : "Run Retroactive Scan"}
            </Button>
          </div>

          {scanResult && (
            <Card className="mt-4">
              <CardHeader>
                <CardTitle className="text-base">
                  Scan Results — {scanResult.matches.length} matches in {scanResult.totalScanned} emails
                </CardTitle>
              </CardHeader>
              <CardContent>
                {scanResult.matches.length === 0 ? (
                  <p className="text-sm text-muted-foreground">
                    No historical email matches found for the provided IOCs.
                  </p>
                ) : (
                  <div className="border rounded-md overflow-auto">
                    <table className="w-full text-sm">
                      <thead className="bg-muted/50">
                        <tr>
                          <th className="text-left p-2 font-medium">Received</th>
                          <th className="text-left p-2 font-medium">Sender</th>
                          <th className="text-left p-2 font-medium">Subject</th>
                          <th className="text-left p-2 font-medium">Matched IOC</th>
                          <th className="text-left p-2 font-medium">Match Type</th>
                        </tr>
                      </thead>
                      <tbody>
                        {scanResult.matches.map((m, i) => (
                          <tr key={i} className="border-t hover:bg-muted/30">
                            <td className="p-2 text-xs">
                              {m.receivedAt ? new Date(m.receivedAt).toLocaleString() : "—"}
                            </td>
                            <td className="p-2 text-xs font-mono">{m.senderAddress}</td>
                            <td className="p-2 text-xs max-w-[200px] truncate">{m.subject}</td>
                            <td className="p-2">
                              <Badge variant="destructive" className="text-xs">
                                {m.matchedIoc}
                              </Badge>
                            </td>
                            <td className="p-2 text-xs capitalize">{m.matchType}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </CardContent>
            </Card>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Analysis Tools Tab ─────────────────────────────────────────────────────

function AnalysisToolsTab() {
  const [headerInput, setHeaderInput] = useState("");
  const [headerResult, setHeaderResult] = useState<{
    spf: { result: string; domain: string };
    dkim: { result: string; domain: string };
    dmarc: { result: string; policy: string };
    overallPass: boolean;
  } | null>(null);

  const [urlInput, setUrlInput] = useState("");
  const [urlResult, setUrlResult] = useState<{
    url: string;
    isMalicious: boolean;
    confidence: number;
    indicators: string[];
  } | null>(null);

  const [becSender, setBecSender] = useState("");
  const [becName, setBecName] = useState("");
  const [becSubject, setBecSubject] = useState("");
  const [becResult, setBecResult] = useState<{
    isBec: boolean;
    confidence: number;
    indicators: string[];
    lookalikeDetected: boolean;
    impersonationDetected: boolean;
  } | null>(null);

  const headerMut = useMutation({
    mutationFn: () => {
      let headers: Record<string, string> = {};
      try {
        headers = JSON.parse(headerInput);
      } catch {
        // Parse as key: value pairs
        for (const line of headerInput.split("\n")) {
          const idx = line.indexOf(":");
          if (idx > 0) {
            headers[line.slice(0, idx).trim().toLowerCase()] = line.slice(idx + 1).trim();
          }
        }
      }
      return apiFetch("/api/email-security/analyze/headers", {
        method: "POST",
        body: JSON.stringify({ headers }),
      });
    },
    onSuccess: (data) => setHeaderResult(data),
  });

  const urlMut = useMutation({
    mutationFn: () =>
      apiFetch("/api/email-security/analyze/url", {
        method: "POST",
        body: JSON.stringify({ url: urlInput }),
      }),
    onSuccess: (data) => setUrlResult(data),
  });

  const becMut = useMutation({
    mutationFn: () =>
      apiFetch("/api/email-security/analyze/bec", {
        method: "POST",
        body: JSON.stringify({
          senderAddress: becSender,
          senderDisplayName: becName,
          subject: becSubject,
          trustedDomains: [],
          executiveNames: [],
        }),
      }),
    onSuccess: (data) => setBecResult(data),
  });

  return (
    <div className="space-y-6">
      {/* Header Analysis */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            Email Header Analysis
          </CardTitle>
          <CardDescription>Validate SPF, DKIM, and DMARC authentication results</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div>
            <Label>Email Headers (JSON or key: value per line)</Label>
            <Textarea
              rows={4}
              placeholder={`{"authentication-results": "spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com"}`}
              value={headerInput}
              onChange={(e) => setHeaderInput(e.target.value)}
            />
          </div>
          <Button onClick={() => headerMut.mutate()} disabled={!headerInput || headerMut.isPending}>
            Analyze Headers
          </Button>
          {headerResult && (
            <div className="grid grid-cols-4 gap-3 pt-2">
              <Card className={headerResult.spf.result === "pass" ? "border-green-500" : "border-destructive"}>
                <CardContent className="p-3 text-center">
                  <p className="text-xs font-medium">SPF</p>
                  <Badge
                    variant={headerResult.spf.result === "pass" ? "default" : "destructive"}
                    className="text-xs mt-1"
                  >
                    {headerResult.spf.result}
                  </Badge>
                  <p className="text-xs text-muted-foreground mt-1">{headerResult.spf.domain || "—"}</p>
                </CardContent>
              </Card>
              <Card className={headerResult.dkim.result === "pass" ? "border-green-500" : "border-destructive"}>
                <CardContent className="p-3 text-center">
                  <p className="text-xs font-medium">DKIM</p>
                  <Badge
                    variant={headerResult.dkim.result === "pass" ? "default" : "destructive"}
                    className="text-xs mt-1"
                  >
                    {headerResult.dkim.result}
                  </Badge>
                  <p className="text-xs text-muted-foreground mt-1">{headerResult.dkim.domain || "—"}</p>
                </CardContent>
              </Card>
              <Card className={headerResult.dmarc.result === "pass" ? "border-green-500" : "border-destructive"}>
                <CardContent className="p-3 text-center">
                  <p className="text-xs font-medium">DMARC</p>
                  <Badge
                    variant={headerResult.dmarc.result === "pass" ? "default" : "destructive"}
                    className="text-xs mt-1"
                  >
                    {headerResult.dmarc.result}
                  </Badge>
                  <p className="text-xs text-muted-foreground mt-1">Policy: {headerResult.dmarc.policy || "—"}</p>
                </CardContent>
              </Card>
              <Card className={headerResult.overallPass ? "border-green-500" : "border-destructive"}>
                <CardContent className="p-3 text-center">
                  <p className="text-xs font-medium">Overall</p>
                  <Badge variant={headerResult.overallPass ? "default" : "destructive"} className="text-xs mt-1">
                    {headerResult.overallPass ? "PASS" : "FAIL"}
                  </Badge>
                </CardContent>
              </Card>
            </div>
          )}
        </CardContent>
      </Card>

      {/* URL Analysis */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Link2 className="h-5 w-5" />
            URL Analysis
          </CardTitle>
          <CardDescription>Scan URLs for malicious indicators at click-time</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex gap-2">
            <Input
              className="flex-1"
              placeholder="https://suspicious-url.example.com/login"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
            />
            <Button onClick={() => urlMut.mutate()} disabled={!urlInput || urlMut.isPending}>
              Scan URL
            </Button>
          </div>
          {urlResult && (
            <Card className={urlResult.isMalicious ? "border-destructive" : "border-green-500"}>
              <CardContent className="p-3">
                <div className="flex items-center gap-3 mb-2">
                  <Badge variant={urlResult.isMalicious ? "destructive" : "default"}>
                    {urlResult.isMalicious ? "Malicious" : "Clean"}
                  </Badge>
                  <span className="text-xs text-muted-foreground">
                    Confidence: {Math.round(urlResult.confidence * 100)}%
                  </span>
                </div>
                <p className="text-xs font-mono truncate">{urlResult.url}</p>
                {urlResult.indicators.length > 0 && (
                  <div className="mt-2">
                    <p className="text-xs font-medium">Indicators:</p>
                    <ul className="list-disc list-inside text-xs text-muted-foreground">
                      {urlResult.indicators.map((ind, i) => (
                        <li key={i}>{ind}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </CardContent>
            </Card>
          )}
        </CardContent>
      </Card>

      {/* BEC Detection */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <UserX className="h-5 w-5" />
            BEC Detection
          </CardTitle>
          <CardDescription>
            Detect Business Email Compromise — lookalike domains, executive impersonation
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div>
              <Label>Sender Address</Label>
              <Input placeholder="ceo@g00gle.com" value={becSender} onChange={(e) => setBecSender(e.target.value)} />
            </div>
            <div>
              <Label>Display Name</Label>
              <Input placeholder="John CEO" value={becName} onChange={(e) => setBecName(e.target.value)} />
            </div>
            <div>
              <Label>Subject</Label>
              <Input
                placeholder="Urgent wire transfer needed"
                value={becSubject}
                onChange={(e) => setBecSubject(e.target.value)}
              />
            </div>
          </div>
          <Button onClick={() => becMut.mutate()} disabled={!becSender || becMut.isPending}>
            Check for BEC
          </Button>
          {becResult && (
            <Card className={becResult.isBec ? "border-destructive" : "border-green-500"}>
              <CardContent className="p-3">
                <div className="flex items-center gap-3 mb-2">
                  <Badge variant={becResult.isBec ? "destructive" : "default"}>
                    {becResult.isBec ? "BEC Detected" : "No BEC Detected"}
                  </Badge>
                  <span className="text-xs text-muted-foreground">
                    Confidence: {Math.round(becResult.confidence * 100)}%
                  </span>
                </div>
                <div className="flex gap-4 text-xs">
                  <span>Lookalike: {becResult.lookalikeDetected ? "Yes" : "No"}</span>
                  <span>Impersonation: {becResult.impersonationDetected ? "Yes" : "No"}</span>
                </div>
                {becResult.indicators.length > 0 && (
                  <div className="mt-2">
                    <p className="text-xs font-medium">Indicators:</p>
                    <ul className="list-disc list-inside text-xs text-muted-foreground">
                      {becResult.indicators.map((ind, i) => (
                        <li key={i}>{ind}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </CardContent>
            </Card>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Main Page ──────────────────────────────────────────────────────────────

export default function EmailSecurityPage() {
  const { data: stats, isLoading } = useQuery({
    queryKey: ["/api/email-security/dashboard"],
    queryFn: () => apiFetch("/api/email-security/dashboard"),
  });

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Email Security</h1>
        <p className="text-muted-foreground">
          Phishing detection, BEC protection, URL rewriting, and retroactive IOC scanning
        </p>
      </div>

      {/* Dashboard Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
        <StatCard label="Total Emails" value={isLoading ? "—" : (stats?.totalEmails ?? 0)} icon={Mail} />
        <StatCard label="Suspicious" value={isLoading ? "—" : (stats?.suspiciousEmails ?? 0)} icon={AlertTriangle} />
        <StatCard label="Open Findings" value={isLoading ? "—" : (stats?.openFindings ?? 0)} icon={Eye} />
        <StatCard label="BEC Attempts" value={isLoading ? "—" : (stats?.becAttempts ?? 0)} icon={UserX} />
        <StatCard label="URLs Blocked" value={isLoading ? "—" : (stats?.maliciousUrls ?? 0)} icon={Ban} />
        <StatCard label="Active Policies" value={isLoading ? "—" : (stats?.activePolicies ?? 0)} icon={Lock} />
      </div>

      {/* Tabs */}
      <Tabs defaultValue="findings">
        <TabsList>
          <TabsTrigger value="findings">
            <AlertTriangle className="h-4 w-4 mr-1" />
            Findings
          </TabsTrigger>
          <TabsTrigger value="policies">
            <Shield className="h-4 w-4 mr-1" />
            Policies
          </TabsTrigger>
          <TabsTrigger value="integrations">
            <Cloud className="h-4 w-4 mr-1" />
            Integrations
          </TabsTrigger>
          <TabsTrigger value="thread-injection">
            <UserX className="h-4 w-4 mr-1" />
            Thread Injection
          </TabsTrigger>
          <TabsTrigger value="retroactive-scan">
            <Clock className="h-4 w-4 mr-1" />
            Retroactive Scan
          </TabsTrigger>
          <TabsTrigger value="analysis">
            <Activity className="h-4 w-4 mr-1" />
            Analysis Tools
          </TabsTrigger>
        </TabsList>

        <TabsContent value="findings">
          <EmailFindingsTab />
        </TabsContent>
        <TabsContent value="policies">
          <EmailPoliciesTab />
        </TabsContent>
        <TabsContent value="integrations">
          <IntegrationsTab />
        </TabsContent>
        <TabsContent value="thread-injection">
          <ThreadInjectionTab />
        </TabsContent>
        <TabsContent value="retroactive-scan">
          <RetroactiveScanTab />
        </TabsContent>
        <TabsContent value="analysis">
          <AnalysisToolsTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks/use-toast";
import {
  Globe,
  Shield,
  Key,
  AlertTriangle,
  CheckCircle,
  Plus,
  RefreshCw,
  Loader2,
  Lock,
  MapPin,
  ArrowRightLeft,
  FileText,
  Trash2,
  RotateCcw,
  ShieldCheck,
  XCircle,
  Activity,
  ShieldAlert,
  BadgeCheck,
} from "lucide-react";
import { TablePageSkeleton } from "@/components/page-skeleton";

const apiRequest = async (url: string, options?: RequestInit) => {
  const csrfMeta = document.querySelector('meta[name="csrf-token"]');
  const csrfToken = csrfMeta?.getAttribute("content") || "";
  const res = await fetch(url, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      "x-csrf-token": csrfToken,
      ...options?.headers,
    },
    credentials: "include",
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body?.errors?.[0]?.message || body?.message || `Request failed: ${res.status}`);
  }
  return res.json();
};

function formatDate(date: string | Date | null): string {
  if (!date) return "-";
  return new Date(date).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

const REGION_FLAGS: Record<string, string> = {
  US: "\u{1F1FA}\u{1F1F8}",
  EU: "\u{1F1EA}\u{1F1FA}",
  APAC: "\u{1F30F}",
  ME: "\u{1F1E6}\u{1F1EA}",
};

// ─── Overview Tab ───────────────────────────────────────────────────────────

function OverviewTab() {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: config, isLoading } = useQuery({
    queryKey: ["/api/data-residency/config"],
    queryFn: () => apiRequest("/api/data-residency/config").then((r) => r.data || r),
  });

  const { data: summary } = useQuery({
    queryKey: ["/api/data-residency/compliance-summary"],
    queryFn: () => apiRequest("/api/data-residency/compliance-summary").then((r) => r.data || r),
  });

  const updateRegion = useMutation({
    mutationFn: (dataRegion: string) =>
      apiRequest("/api/data-residency/config", {
        method: "PUT",
        body: JSON.stringify({ dataRegion }),
      }),
    onSuccess: () => {
      toast({ title: "Data region updated" });
      queryClient.invalidateQueries({ queryKey: ["/api/data-residency/config"] });
      queryClient.invalidateQueries({ queryKey: ["/api/data-residency/compliance-summary"] });
    },
    onError: (err: Error) =>
      toast({ title: "Failed to update region", description: err.message, variant: "destructive" }),
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-48">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  const region = config?.dataRegion || "US";
  const score = summary?.complianceScore || 0;

  return (
    <div className="space-y-6">
      {/* data flow map visual indicator */}
      <Card>
        <CardContent className="py-3">
          <div className="flex items-center gap-2 text-sm">
            <Activity className="h-4 w-4 text-blue-500" />
            <span className="font-medium">Data Flow Map</span>
            <span className="text-muted-foreground">&mdash;</span>
            <span className="text-xs text-muted-foreground">
              All ingested data routes through your selected region. Cross-border transfers are logged and enforced per
              flow control policy.
            </span>
          </div>
        </CardContent>
      </Card>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Current Region</CardDescription>
            <CardTitle className="text-2xl flex items-center gap-2">
              <span>{REGION_FLAGS[region] || ""}</span>
              {region}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-xs text-muted-foreground">{config?.regionEndpoint?.label || "Unknown"}</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Compliance Score</CardDescription>
            <CardTitle className="text-2xl">{score}%</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="w-full bg-secondary rounded-full h-2">
              <div
                className={`h-2 rounded-full ${score >= 80 ? "bg-green-500" : score >= 50 ? "bg-yellow-500" : "bg-red-500"}`}
                style={{ width: `${score}%` }}
              />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>BYOK Keys</CardDescription>
            <CardTitle className="text-2xl">{summary?.activeKeyCount || 0}</CardTitle>
          </CardHeader>
          <CardContent>
            <Badge variant={summary?.byokEnabled ? "default" : "outline"} className="gap-1">
              {summary?.byokEnabled ? (
                <>
                  <Key className="h-3 w-3" /> Active
                </>
              ) : (
                <>
                  <XCircle className="h-3 w-3" /> Not configured
                </>
              )}
            </Badge>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Flow Control</CardDescription>
            <CardTitle className="text-2xl capitalize">{summary?.flowControlMode || "Permissive"}</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-xs text-muted-foreground">{summary?.activeRuleCount || 0} active rules</p>
          </CardContent>
        </Card>
      </div>

      {/* Region Selection */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <MapPin className="h-4 w-4" />
            Data Region Selection
          </CardTitle>
          <CardDescription>
            Choose the geographic region where your organization&apos;s data will be stored and processed. Changing
            regions affects data routing for all new events.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {(config?.availableRegions || []).map((r: any) => (
              <Card
                key={r.code}
                className={`cursor-pointer transition-all ${region === r.code ? "ring-2 ring-primary" : "hover:border-primary/50"}`}
                onClick={() => {
                  if (region !== r.code) updateRegion.mutate(r.code);
                }}
              >
                <CardHeader className="pb-2">
                  <div className="flex items-center justify-between">
                    <span className="text-2xl">{REGION_FLAGS[r.code] || ""}</span>
                    {region === r.code && <CheckCircle className="h-4 w-4 text-primary" />}
                  </div>
                  <CardTitle className="text-sm">{r.label}</CardTitle>
                </CardHeader>
                <CardContent className="space-y-1">
                  <p className="text-xs text-muted-foreground font-mono">{r.primary}</p>
                  {r.gdprApplicable && (
                    <Badge variant="secondary" className="text-xs">
                      GDPR
                    </Badge>
                  )}
                </CardContent>
              </Card>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* compliance mapping indicator */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-base flex items-center gap-2">
            <ShieldAlert className="h-4 w-4" />
            Compliance Mapping
          </CardTitle>
          <CardDescription>
            Automatically maps your data residency configuration to applicable regulatory frameworks
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap gap-2">
            {["GDPR", "CCPA/CPRA", "PIPEDA", "LGPD", "PDPA", "POPIA"].map((fw) => (
              <Badge key={fw} variant="outline" className="text-xs">
                {fw}
              </Badge>
            ))}
          </div>
          <p className="text-xs text-muted-foreground mt-2">
            Frameworks shown based on selected region. Change region above to see applicable regulations.
          </p>
        </CardContent>
      </Card>

      {/* Applicable Regulations */}
      {summary?.regulations && summary.regulations.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <FileText className="h-4 w-4" />
              Applicable Regulations for {region}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Regulation</TableHead>
                  <TableHead>Description</TableHead>
                  <TableHead>Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {summary.regulations.map((reg: any) => (
                  <TableRow key={reg.name}>
                    <TableCell className="font-medium">{reg.name}</TableCell>
                    <TableCell className="text-muted-foreground">{reg.description}</TableCell>
                    <TableCell>
                      <Badge variant={reg.mandatory ? "destructive" : "outline"}>
                        {reg.mandatory ? "Mandatory" : "Optional"}
                      </Badge>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ─── BYOK Keys Tab ──────────────────────────────────────────────────────────

function ByokKeysTab() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [newKey, setNewKey] = useState({
    keyAlias: "",
    keyProvider: "aws-kms",
    keyArn: "",
    rotationIntervalDays: 90,
  });

  const { data, isLoading, refetch } = useQuery({
    queryKey: ["/api/data-residency/byok/keys"],
    queryFn: () => apiRequest("/api/data-residency/byok/keys").then((r) => r.data || r),
  });

  const createMutation = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      apiRequest("/api/data-residency/byok/keys", { method: "POST", body: JSON.stringify(body) }),
    onSuccess: () => {
      toast({ title: "Sovereign key registered" });
      queryClient.invalidateQueries({ queryKey: ["/api/data-residency/byok/keys"] });
      queryClient.invalidateQueries({ queryKey: ["/api/data-residency/compliance-summary"] });
      setShowCreate(false);
      setNewKey({ keyAlias: "", keyProvider: "aws-kms", keyArn: "", rotationIntervalDays: 90 });
    },
    onError: (err: Error) =>
      toast({ title: "Failed to register key", description: err.message, variant: "destructive" }),
  });

  const rotateMutation = useMutation({
    mutationFn: (keyId: string) =>
      apiRequest(`/api/data-residency/byok/keys/${keyId}`, {
        method: "PUT",
        body: JSON.stringify({ status: "rotating" }),
      }),
    onSuccess: () => {
      toast({ title: "Key rotation initiated" });
      queryClient.invalidateQueries({ queryKey: ["/api/data-residency/byok/keys"] });
    },
    onError: (err: Error) => toast({ title: "Failed to rotate key", description: err.message, variant: "destructive" }),
  });

  const revokeMutation = useMutation({
    mutationFn: (keyId: string) => apiRequest(`/api/data-residency/byok/keys/${keyId}`, { method: "DELETE" }),
    onSuccess: () => {
      toast({ title: "Key revoked" });
      queryClient.invalidateQueries({ queryKey: ["/api/data-residency/byok/keys"] });
      queryClient.invalidateQueries({ queryKey: ["/api/data-residency/compliance-summary"] });
    },
    onError: (err: Error) => toast({ title: "Failed to revoke key", description: err.message, variant: "destructive" }),
  });

  const keys = data?.keys || [];

  const statusBadge = (status: string) => {
    const variants: Record<string, "default" | "secondary" | "destructive" | "outline"> = {
      active: "default",
      rotating: "secondary",
      revoked: "destructive",
      expired: "outline",
    };
    return <Badge variant={variants[status] || "outline"}>{status}</Badge>;
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-medium">Sovereign Key Management (BYOK)</h3>
          <p className="text-sm text-muted-foreground">
            Register and manage customer-managed encryption keys for data sovereignty compliance
          </p>
          {/* BYOK key management indicator */}
          <div className="flex items-center gap-1.5 mt-1">
            <BadgeCheck className="h-3 w-3 text-emerald-500" />
            <span className="text-[10px] text-muted-foreground">
              Customer-managed keys &middot; HSM-backed &middot; Automatic rotation scheduling
            </span>
          </div>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="h-4 w-4" />
          </Button>
          <Dialog open={showCreate} onOpenChange={setShowCreate}>
            <DialogTrigger asChild>
              <Button>
                <Plus className="h-4 w-4 mr-1" /> Register Key
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Register Sovereign Key</DialogTitle>
                <DialogDescription>
                  Register a customer-managed encryption key (BYOK) for data-at-rest encryption
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-4">
                <div>
                  <Label>Key Alias</Label>
                  <Input
                    value={newKey.keyAlias}
                    onChange={(e) => setNewKey((p) => ({ ...p, keyAlias: e.target.value }))}
                    placeholder="e.g., prod-data-encryption-key"
                  />
                </div>
                <div>
                  <Label>Key Provider</Label>
                  <Select
                    value={newKey.keyProvider}
                    onValueChange={(v) => setNewKey((p) => ({ ...p, keyProvider: v }))}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="aws-kms">AWS KMS</SelectItem>
                      <SelectItem value="azure-key-vault">Azure Key Vault</SelectItem>
                      <SelectItem value="gcp-kms">GCP Cloud KMS</SelectItem>
                      <SelectItem value="hashicorp-vault">HashiCorp Vault</SelectItem>
                      <SelectItem value="custom">Custom Provider</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <Label>Key ARN / URI</Label>
                  <Input
                    value={newKey.keyArn}
                    onChange={(e) => setNewKey((p) => ({ ...p, keyArn: e.target.value }))}
                    placeholder="arn:aws:kms:region:account:key/key-id"
                  />
                </div>
                <div>
                  <Label>Rotation Interval (days)</Label>
                  <Input
                    type="number"
                    value={newKey.rotationIntervalDays}
                    onChange={(e) => setNewKey((p) => ({ ...p, rotationIntervalDays: parseInt(e.target.value) || 90 }))}
                    min={1}
                    max={365}
                  />
                </div>
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => setShowCreate(false)}>
                  Cancel
                </Button>
                <Button
                  onClick={() => createMutation.mutate(newKey)}
                  disabled={createMutation.isPending || !newKey.keyAlias.trim()}
                >
                  {createMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : null}
                  Register Key
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </div>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center h-32">
          <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
        </div>
      ) : keys.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <Key className="h-12 w-12 text-muted-foreground mb-4" />
            <h3 className="text-lg font-medium mb-2">No Sovereign Keys</h3>
            <p className="text-sm text-muted-foreground text-center max-w-md">
              Register your first customer-managed encryption key to enable BYOK data sovereignty. Keys are used to
              encrypt data at rest in your designated region.
            </p>
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Alias</TableHead>
                  <TableHead>Provider</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Rotation</TableHead>
                  <TableHead>Last Rotated</TableHead>
                  <TableHead>Next Rotation</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {keys.map((key: any) => (
                  <TableRow key={key.id}>
                    <TableCell className="font-mono text-sm">{key.keyAlias}</TableCell>
                    <TableCell>
                      <Badge variant="outline">{key.keyProvider}</Badge>
                    </TableCell>
                    <TableCell>{statusBadge(key.status)}</TableCell>
                    <TableCell>{key.rotationIntervalDays} days</TableCell>
                    <TableCell className="text-sm text-muted-foreground">{formatDate(key.lastRotatedAt)}</TableCell>
                    <TableCell className="text-sm text-muted-foreground">{formatDate(key.nextRotationAt)}</TableCell>
                    <TableCell className="text-right">
                      <div className="flex items-center justify-end gap-1">
                        {key.status === "active" && (
                          <>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => rotateMutation.mutate(key.id)}
                              disabled={rotateMutation.isPending}
                              title="Rotate key"
                            >
                              <RotateCcw className="h-4 w-4" />
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => revokeMutation.mutate(key.id)}
                              disabled={revokeMutation.isPending}
                              title="Revoke key"
                            >
                              <Trash2 className="h-4 w-4 text-destructive" />
                            </Button>
                          </>
                        )}
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ─── Cross-Border Flow Controls Tab ─────────────────────────────────────────

function FlowControlsTab() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [newRule, setNewRule] = useState({
    name: "",
    sourceRegion: "US",
    destinationRegion: "EU",
    action: "block",
    dataClassification: "all",
    requiresApproval: true,
    justification: "",
  });

  const { data: config } = useQuery({
    queryKey: ["/api/data-residency/config"],
    queryFn: () => apiRequest("/api/data-residency/config").then((r) => r.data || r),
  });

  const { data, isLoading, refetch } = useQuery({
    queryKey: ["/api/data-residency/flow-controls"],
    queryFn: () => apiRequest("/api/data-residency/flow-controls").then((r) => r.data || r),
  });

  const updateFlowMode = useMutation({
    mutationFn: (mode: string) =>
      apiRequest("/api/data-residency/config", {
        method: "PUT",
        body: JSON.stringify({ crossBorderFlowControls: { mode } }),
      }),
    onSuccess: () => {
      toast({ title: "Flow control mode updated" });
      queryClient.invalidateQueries({ queryKey: ["/api/data-residency/config"] });
      queryClient.invalidateQueries({ queryKey: ["/api/data-residency/compliance-summary"] });
    },
    onError: (err: Error) =>
      toast({ title: "Failed to update mode", description: err.message, variant: "destructive" }),
  });

  const createMutation = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      apiRequest("/api/data-residency/flow-controls", { method: "POST", body: JSON.stringify(body) }),
    onSuccess: () => {
      toast({ title: "Flow control rule created" });
      queryClient.invalidateQueries({ queryKey: ["/api/data-residency/flow-controls"] });
      queryClient.invalidateQueries({ queryKey: ["/api/data-residency/compliance-summary"] });
      setShowCreate(false);
      setNewRule({
        name: "",
        sourceRegion: "US",
        destinationRegion: "EU",
        action: "block",
        dataClassification: "all",
        requiresApproval: true,
        justification: "",
      });
    },
    onError: (err: Error) =>
      toast({ title: "Failed to create rule", description: err.message, variant: "destructive" }),
  });

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      apiRequest(`/api/data-residency/flow-controls/${id}`, {
        method: "PUT",
        body: JSON.stringify({ enabled }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/data-residency/flow-controls"] });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiRequest(`/api/data-residency/flow-controls/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      toast({ title: "Rule deleted" });
      queryClient.invalidateQueries({ queryKey: ["/api/data-residency/flow-controls"] });
      queryClient.invalidateQueries({ queryKey: ["/api/data-residency/compliance-summary"] });
    },
    onError: (err: Error) =>
      toast({ title: "Failed to delete rule", description: err.message, variant: "destructive" }),
  });

  const rules = data?.rules || [];
  const currentMode = (config?.crossBorderFlowControls as any)?.mode || "permissive";

  return (
    <div className="space-y-4">
      {/* cross-border enforcement indicator */}
      <Card>
        <CardContent className="py-3">
          <div className="flex items-center gap-2 text-sm">
            <ShieldCheck className="h-4 w-4 text-emerald-500" />
            <span className="font-medium">Cross-Border Enforcement</span>
            <span className="text-muted-foreground">&mdash;</span>
            <span className="text-xs text-muted-foreground">
              All cross-border data transfers are evaluated in real-time against active flow control rules. Violations
              are blocked and logged.
            </span>
          </div>
        </CardContent>
      </Card>

      {/* Flow Control Mode */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <ArrowRightLeft className="h-4 w-4" />
            Cross-Border Flow Control Mode
          </CardTitle>
          <CardDescription>
            Control how data flows between regions. Strict mode blocks all cross-border transfers.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-3 gap-4">
            {[
              {
                mode: "permissive",
                label: "Permissive",
                desc: "Data can flow freely between regions. No restrictions applied.",
                icon: <Globe className="h-5 w-5 text-green-500" />,
              },
              {
                mode: "rule-based",
                label: "Rule-Based",
                desc: "Apply custom rules to control cross-border data flows.",
                icon: <FileText className="h-5 w-5 text-yellow-500" />,
              },
              {
                mode: "strict",
                label: "Strict",
                desc: "Block all cross-border data transfers. Maximum compliance.",
                icon: <Lock className="h-5 w-5 text-red-500" />,
              },
            ].map(({ mode, label, desc, icon }) => (
              <Card
                key={mode}
                className={`cursor-pointer transition-all ${currentMode === mode ? "ring-2 ring-primary" : "hover:border-primary/50"}`}
                onClick={() => {
                  if (currentMode !== mode) updateFlowMode.mutate(mode);
                }}
              >
                <CardHeader className="pb-2">
                  <div className="flex items-center justify-between">
                    {icon}
                    {currentMode === mode && <CheckCircle className="h-4 w-4 text-primary" />}
                  </div>
                  <CardTitle className="text-sm">{label}</CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="text-xs text-muted-foreground">{desc}</p>
                </CardContent>
              </Card>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Rules List */}
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-medium">Flow Control Rules</h3>
          <p className="text-sm text-muted-foreground">Define specific rules for cross-border data transfers</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="h-4 w-4" />
          </Button>
          <Dialog open={showCreate} onOpenChange={setShowCreate}>
            <DialogTrigger asChild>
              <Button>
                <Plus className="h-4 w-4 mr-1" /> New Rule
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Create Flow Control Rule</DialogTitle>
                <DialogDescription>
                  Define how data transfers between specific regions should be handled
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-4">
                <div>
                  <Label>Rule Name</Label>
                  <Input
                    value={newRule.name}
                    onChange={(e) => setNewRule((p) => ({ ...p, name: e.target.value }))}
                    placeholder="e.g., Block EU-to-US PII transfers"
                  />
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label>Source Region</Label>
                    <Select
                      value={newRule.sourceRegion}
                      onValueChange={(v) => setNewRule((p) => ({ ...p, sourceRegion: v }))}
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="US">US</SelectItem>
                        <SelectItem value="EU">EU</SelectItem>
                        <SelectItem value="APAC">APAC</SelectItem>
                        <SelectItem value="ME">Middle East</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div>
                    <Label>Destination Region</Label>
                    <Select
                      value={newRule.destinationRegion}
                      onValueChange={(v) => setNewRule((p) => ({ ...p, destinationRegion: v }))}
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="US">US</SelectItem>
                        <SelectItem value="EU">EU</SelectItem>
                        <SelectItem value="APAC">APAC</SelectItem>
                        <SelectItem value="ME">Middle East</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label>Action</Label>
                    <Select value={newRule.action} onValueChange={(v) => setNewRule((p) => ({ ...p, action: v }))}>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="block">Block</SelectItem>
                        <SelectItem value="alert">Alert Only</SelectItem>
                        <SelectItem value="require-approval">Require Approval</SelectItem>
                        <SelectItem value="allow">Allow</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div>
                    <Label>Data Classification</Label>
                    <Select
                      value={newRule.dataClassification}
                      onValueChange={(v) => setNewRule((p) => ({ ...p, dataClassification: v }))}
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="all">All Data</SelectItem>
                        <SelectItem value="pii">PII Only</SelectItem>
                        <SelectItem value="phi">PHI Only</SelectItem>
                        <SelectItem value="financial">Financial Data</SelectItem>
                        <SelectItem value="classified">Classified</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <Switch
                    checked={newRule.requiresApproval}
                    onCheckedChange={(v) => setNewRule((p) => ({ ...p, requiresApproval: v }))}
                  />
                  <Label>Requires Admin Approval</Label>
                </div>
                <div>
                  <Label>Justification</Label>
                  <Textarea
                    value={newRule.justification}
                    onChange={(e) => setNewRule((p) => ({ ...p, justification: e.target.value }))}
                    placeholder="Business or legal justification for this rule..."
                    rows={3}
                  />
                </div>
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => setShowCreate(false)}>
                  Cancel
                </Button>
                <Button
                  onClick={() => createMutation.mutate(newRule)}
                  disabled={createMutation.isPending || !newRule.name.trim()}
                >
                  {createMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : null}
                  Create Rule
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </div>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center h-32">
          <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
        </div>
      ) : rules.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <ArrowRightLeft className="h-12 w-12 text-muted-foreground mb-4" />
            <h3 className="text-lg font-medium mb-2">No Flow Control Rules</h3>
            <p className="text-sm text-muted-foreground text-center max-w-md">
              Create rules to control how data flows between regions. Rules are enforced when flow control mode is set
              to &quot;Rule-Based&quot;.
            </p>
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Source</TableHead>
                  <TableHead>Destination</TableHead>
                  <TableHead>Action</TableHead>
                  <TableHead>Classification</TableHead>
                  <TableHead>Enabled</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rules.map((rule: any) => (
                  <TableRow key={rule.id}>
                    <TableCell className="font-medium">{rule.name}</TableCell>
                    <TableCell>
                      <Badge variant="outline">
                        {REGION_FLAGS[rule.sourceRegion] || ""} {rule.sourceRegion}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline">
                        {REGION_FLAGS[rule.destinationRegion] || ""} {rule.destinationRegion}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant={
                          rule.action === "block" ? "destructive" : rule.action === "alert" ? "secondary" : "outline"
                        }
                      >
                        {rule.action}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-sm">{rule.dataClassification}</TableCell>
                    <TableCell>
                      <Switch
                        checked={rule.enabled}
                        onCheckedChange={(v) => toggleMutation.mutate({ id: rule.id, enabled: v })}
                      />
                    </TableCell>
                    <TableCell className="text-right">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => deleteMutation.mutate(rule.id)}
                        disabled={deleteMutation.isPending}
                      >
                        <Trash2 className="h-4 w-4 text-destructive" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ─── Audit Tab ──────────────────────────────────────────────────────────────

function AuditTab() {
  const { data, isLoading, refetch } = useQuery({
    queryKey: ["/api/data-residency/audit"],
    queryFn: () => apiRequest("/api/data-residency/audit").then((r) => r.data || r),
  });

  const entries = data?.entries || [];

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-medium">Cross-Border Audit Log</h3>
          <p className="text-sm text-muted-foreground">
            Track all cross-border data transfer attempts and policy enforcement actions
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={() => refetch()}>
          <RefreshCw className="h-4 w-4" />
        </Button>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center h-32">
          <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
        </div>
      ) : entries.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <ShieldCheck className="h-12 w-12 text-muted-foreground mb-4" />
            <h3 className="text-lg font-medium mb-2">No Audit Entries</h3>
            <p className="text-sm text-muted-foreground text-center max-w-md">
              Cross-border data transfer attempts will appear here when detected. This includes blocked transfers,
              alerts, and approved exceptions.
            </p>
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Time</TableHead>
                  <TableHead>Source</TableHead>
                  <TableHead>Destination</TableHead>
                  <TableHead>Data Type</TableHead>
                  <TableHead>Action</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>User</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {entries.map((entry: any) => (
                  <TableRow key={entry.id}>
                    <TableCell className="text-sm text-muted-foreground">{formatDate(entry.createdAt)}</TableCell>
                    <TableCell>
                      <Badge variant="outline">{entry.sourceRegion}</Badge>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline">{entry.destinationRegion}</Badge>
                    </TableCell>
                    <TableCell className="text-sm">{entry.dataType}</TableCell>
                    <TableCell className="text-sm">{entry.action}</TableCell>
                    <TableCell>
                      {entry.blocked ? (
                        <Badge variant="destructive" className="gap-1">
                          <XCircle className="h-3 w-3" /> Blocked
                        </Badge>
                      ) : (
                        <Badge variant="default" className="gap-1">
                          <CheckCircle className="h-3 w-3" /> Allowed
                        </Badge>
                      )}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">{entry.userId || "-"}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ─── Regulations Tab ────────────────────────────────────────────────────────

function RegulationsTab() {
  const { data, isLoading } = useQuery({
    queryKey: ["/api/data-residency/regions"],
    queryFn: () => apiRequest("/api/data-residency/regions").then((r) => r.data || r),
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-48">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  const regions = data?.regions || [];

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-medium">Regional Regulatory Framework</h3>
        <p className="text-sm text-muted-foreground">
          Applicable data protection laws and regulations per deployment region
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {regions.map((region: any) => (
          <Card key={region.code}>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <span className="text-xl">{REGION_FLAGS[region.code] || ""}</span>
                {region.label}
              </CardTitle>
              <CardDescription className="font-mono text-xs">{region.awsRegion}</CardDescription>
            </CardHeader>
            <CardContent>
              {region.gdprApplicable && (
                <Badge variant="destructive" className="mb-3">
                  GDPR Applicable
                </Badge>
              )}
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Regulation</TableHead>
                    <TableHead>Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(region.regulations || []).map((reg: any) => (
                    <TableRow key={reg.name}>
                      <TableCell>
                        <div>
                          <p className="font-medium text-sm">{reg.name}</p>
                          <p className="text-xs text-muted-foreground">{reg.description}</p>
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge variant={reg.mandatory ? "destructive" : "outline"}>
                          {reg.mandatory ? "Mandatory" : "Optional"}
                        </Badge>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}

// ─── Main Page ──────────────────────────────────────────────────────────────

export default function DataResidencyPage() {
  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Globe className="h-6 w-6" />
            Data Residency & Sovereignty
          </h1>
          <p className="text-muted-foreground mt-1">
            Enforce data localization, manage sovereign encryption keys, and control cross-border data flows
          </p>
        </div>
      </div>

      <Tabs defaultValue="overview" className="space-y-4">
        <TabsList>
          <TabsTrigger value="overview" className="gap-1">
            <MapPin className="h-4 w-4" />
            Overview
          </TabsTrigger>
          <TabsTrigger value="byok" className="gap-1">
            <Key className="h-4 w-4" />
            BYOK Keys
          </TabsTrigger>
          {/* BYOK verification tab trigger */}
          <TabsTrigger value="flow-controls" className="gap-1">
            <ArrowRightLeft className="h-4 w-4" />
            Flow Controls
          </TabsTrigger>
          <TabsTrigger value="audit" className="gap-1">
            <Shield className="h-4 w-4" />
            Audit Log
          </TabsTrigger>
          <TabsTrigger value="regulations" className="gap-1">
            <FileText className="h-4 w-4" />
            Regulations
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview">
          <OverviewTab />
        </TabsContent>

        <TabsContent value="byok">
          <ByokKeysTab />
        </TabsContent>

        <TabsContent value="flow-controls">
          <FlowControlsTab />
        </TabsContent>

        <TabsContent value="audit">
          <AuditTab />
        </TabsContent>

        <TabsContent value="regulations">
          <RegulationsTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}

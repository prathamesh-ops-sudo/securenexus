import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useToast } from "@/hooks/use-toast";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Plus,
  Trash2,
  RefreshCw,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Loader2,
  Plug,
  Unplug,
  TestTube,
  Shield,
  Database,
  Cloud,
  Eye,
  Flame,
  Radar,
  ShieldCheck,
  Zap,
  CloudLightning,
  Clock,
  Settings2,
  ExternalLink,
  BookOpen,
} from "lucide-react";

interface ConnectorType {
  type: string;
  name: string;
  description: string;
  authType: string;
  requiredFields: { key: string; label: string; type: string; placeholder: string }[];
  optionalFields: { key: string; label: string; type: string; placeholder: string }[];
  icon: string;
  docsUrl: string;
}

interface ConnectorItem {
  id: string;
  name: string;
  type: string;
  authType: string;
  config: Record<string, any>;
  status: string;
  pollingIntervalMin: number | null;
  lastSyncAt: string | null;
  lastSyncStatus: string | null;
  lastSyncAlerts: number | null;
  lastSyncError: string | null;
  totalAlertsSynced: number | null;
  createdAt: string | null;
  updatedAt: string | null;
}

const ICON_MAP: Record<string, any> = {
  Shield, Database, Cloud, Eye, Flame, Radar, ShieldCheck, CloudLightning, Zap,
};

function getIcon(name: string) {
  return ICON_MAP[name] || Plug;
}

function statusBadge(status: string) {
  switch (status) {
    case "active":
      return <Badge variant="default" data-testid="badge-status-active"><CheckCircle className="h-3 w-3 mr-1" />Active</Badge>;
    case "error":
      return <Badge variant="destructive" data-testid="badge-status-error"><XCircle className="h-3 w-3 mr-1" />Error</Badge>;
    case "syncing":
      return <Badge variant="secondary" data-testid="badge-status-syncing"><Loader2 className="h-3 w-3 mr-1 animate-spin" />Syncing</Badge>;
    case "inactive":
      return <Badge variant="outline" data-testid="badge-status-inactive"><Unplug className="h-3 w-3 mr-1" />Inactive</Badge>;
    default:
      return <Badge variant="outline" data-testid="badge-status-unknown"><AlertTriangle className="h-3 w-3 mr-1" />Unknown</Badge>;
  }
}

export default function ConnectorsPage() {
  const { toast } = useToast();
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [selectedType, setSelectedType] = useState<string>("");
  const [formData, setFormData] = useState<Record<string, string>>({});
  const [connectorName, setConnectorName] = useState("");
  const [pollingInterval, setPollingInterval] = useState("5");
  const [testingId, setTestingId] = useState<string | null>(null);
  const [syncingId, setSyncingId] = useState<string | null>(null);

  const { data: connectorTypes, isLoading: typesLoading } = useQuery<ConnectorType[]>({
    queryKey: ["/api/connectors/types"],
  });

  const { data: existingConnectors, isLoading: connectorsLoading } = useQuery<ConnectorItem[]>({
    queryKey: ["/api/connectors"],
  });

  const createMutation = useMutation({
    mutationFn: async (data: any) => {
      const res = await apiRequest("POST", "/api/connectors", data);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/connectors"] });
      setShowCreateDialog(false);
      resetForm();
      toast({ title: "Connector created", description: "Ready to test and sync." });
    },
    onError: (err: any) => {
      toast({ title: "Failed to create connector", description: err.message, variant: "destructive" });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("DELETE", `/api/connectors/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/connectors"] });
      toast({ title: "Connector deleted" });
    },
    onError: (err: any) => {
      toast({ title: "Failed to delete", description: err.message, variant: "destructive" });
    },
  });

  const testMutation = useMutation({
    mutationFn: async (id: string) => {
      setTestingId(id);
      const res = await apiRequest("POST", `/api/connectors/${id}/test`);
      return res.json();
    },
    onSuccess: (data: any) => {
      setTestingId(null);
      if (data.success) {
        toast({ title: "Connection successful", description: `Latency: ${data.latencyMs}ms` });
      } else {
        toast({ title: "Connection failed", description: data.message, variant: "destructive" });
      }
    },
    onError: (err: any) => {
      setTestingId(null);
      toast({ title: "Test failed", description: err.message, variant: "destructive" });
    },
  });

  const syncMutation = useMutation({
    mutationFn: async (id: string) => {
      setSyncingId(id);
      const res = await apiRequest("POST", `/api/connectors/${id}/sync`);
      return res.json();
    },
    onSuccess: (data: any) => {
      setSyncingId(null);
      queryClient.invalidateQueries({ queryKey: ["/api/connectors"] });
      queryClient.invalidateQueries({ queryKey: ["/api/alerts"] });
      queryClient.invalidateQueries({ queryKey: ["/api/ingestion/stats"] });
      if (data.success) {
        toast({
          title: "Sync complete",
          description: `Received: ${data.alertsReceived}, Created: ${data.alertsCreated}, Deduped: ${data.alertsDeduped}`,
        });
      } else {
        toast({ title: "Sync had errors", description: data.errors?.[0] || "Unknown error", variant: "destructive" });
      }
    },
    onError: (err: any) => {
      setSyncingId(null);
      queryClient.invalidateQueries({ queryKey: ["/api/connectors"] });
      toast({ title: "Sync failed", description: err.message, variant: "destructive" });
    },
  });

  const toggleMutation = useMutation({
    mutationFn: async ({ id, newStatus }: { id: string; newStatus: string }) => {
      const res = await apiRequest("PATCH", `/api/connectors/${id}`, { status: newStatus });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/connectors"] });
    },
  });

  function resetForm() {
    setSelectedType("");
    setFormData({});
    setConnectorName("");
    setPollingInterval("5");
  }

  function handleCreate() {
    if (!selectedType || !connectorName) return;
    const meta = connectorTypes?.find(t => t.type === selectedType);
    if (!meta) return;
    const config: Record<string, string> = {};
    for (const field of [...meta.requiredFields, ...meta.optionalFields]) {
      if (formData[field.key]) config[field.key] = formData[field.key];
    }
    const missingRequired = meta.requiredFields.filter(f => !config[f.key]);
    if (missingRequired.length > 0) {
      toast({ title: "Missing required fields", description: missingRequired.map(f => f.label).join(", "), variant: "destructive" });
      return;
    }
    createMutation.mutate({
      name: connectorName,
      type: selectedType,
      authType: meta.authType,
      config,
      pollingIntervalMin: parseInt(pollingInterval) || 5,
    });
  }

  const selectedMeta = connectorTypes?.find(t => t.type === selectedType);
  const activeCount = existingConnectors?.filter(c => c.status === "active").length || 0;
  const errorCount = existingConnectors?.filter(c => c.status === "error").length || 0;
  const totalSynced = existingConnectors?.reduce((sum, c) => sum + (c.totalAlertsSynced || 0), 0) || 0;

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold tracking-tight" data-testid="text-page-title"><span className="gradient-text-red">Connectors</span></h1>
          <p className="text-sm text-muted-foreground">Pull-based integrations that actively fetch alerts from your security tools</p>
          <div className="gradient-accent-line w-24 mt-2" />
        </div>
        <Button onClick={() => setShowCreateDialog(true)} data-testid="button-add-connector">
          <Plus className="h-4 w-4 mr-2" />
          Add Connector
        </Button>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Connectors</CardTitle>
            <Plug className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold" data-testid="text-total-connectors">{existingConnectors?.length || 0}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active</CardTitle>
            <CheckCircle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold" data-testid="text-active-count">{activeCount}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Errors</CardTitle>
            <XCircle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold" data-testid="text-error-count">{errorCount}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Alerts Synced</CardTitle>
            <Zap className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold" data-testid="text-total-synced">{totalSynced}</div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Configured Connectors</CardTitle>
          <CardDescription>Manage connections to your security tools</CardDescription>
        </CardHeader>
        <CardContent>
          {connectorsLoading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : !existingConnectors?.length ? (
            <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
              <Unplug className="h-10 w-10 mb-3" />
              <p className="text-sm">No connectors configured yet</p>
              <p className="text-xs mt-1">Add a connector to start pulling alerts from your security tools</p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Connector</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Last Sync</TableHead>
                  <TableHead>Alerts Synced</TableHead>
                  <TableHead>Interval</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {existingConnectors.map(connector => {
                  const meta = connectorTypes?.find(t => t.type === connector.type);
                  const IconComp = getIcon(meta?.icon || "");
                  return (
                    <TableRow key={connector.id} data-testid={`row-connector-${connector.id}`}>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <IconComp className="h-4 w-4 text-muted-foreground" />
                          <div>
                            <span className="font-medium" data-testid={`text-connector-name-${connector.id}`}>{connector.name}</span>
                            {connector.lastSyncError && connector.status === "error" && (
                              <p className="text-xs text-destructive mt-0.5 max-w-xs truncate">{connector.lastSyncError}</p>
                            )}
                          </div>
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <span className="text-sm text-muted-foreground">{meta?.name || connector.type}</span>
                          {meta?.docsUrl && (
                            <a
                              href={meta.docsUrl}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="inline-flex items-center text-primary hover:underline"
                              data-testid={`link-table-docs-${connector.id}`}
                            >
                              <ExternalLink className="h-3 w-3" />
                            </a>
                          )}
                        </div>
                      </TableCell>
                      <TableCell>{statusBadge(connector.status)}</TableCell>
                      <TableCell>
                        {connector.lastSyncAt ? (
                          <div className="flex items-center gap-1 text-sm text-muted-foreground">
                            <Clock className="h-3 w-3" />
                            {new Date(connector.lastSyncAt).toLocaleString()}
                          </div>
                        ) : (
                          <span className="text-sm text-muted-foreground">Never</span>
                        )}
                      </TableCell>
                      <TableCell>
                        <span className="text-sm font-mono" data-testid={`text-synced-${connector.id}`}>{connector.totalAlertsSynced || 0}</span>
                      </TableCell>
                      <TableCell>
                        <span className="text-sm text-muted-foreground">{connector.pollingIntervalMin || 5}m</span>
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center justify-end gap-1">
                          <Button
                            size="icon"
                            variant="ghost"
                            onClick={() => testMutation.mutate(connector.id)}
                            disabled={testingId === connector.id}
                            data-testid={`button-test-${connector.id}`}
                          >
                            {testingId === connector.id ? <Loader2 className="h-4 w-4 animate-spin" /> : <TestTube className="h-4 w-4" />}
                          </Button>
                          <Button
                            size="icon"
                            variant="ghost"
                            onClick={() => syncMutation.mutate(connector.id)}
                            disabled={syncingId === connector.id}
                            data-testid={`button-sync-${connector.id}`}
                          >
                            {syncingId === connector.id ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
                          </Button>
                          <Button
                            size="icon"
                            variant="ghost"
                            onClick={() => {
                              const newStatus = connector.status === "inactive" ? "active" : "inactive";
                              toggleMutation.mutate({ id: connector.id, newStatus });
                            }}
                            data-testid={`button-toggle-${connector.id}`}
                          >
                            {connector.status === "inactive" ? <Plug className="h-4 w-4" /> : <Settings2 className="h-4 w-4" />}
                          </Button>
                          <Button
                            size="icon"
                            variant="ghost"
                            onClick={() => {
                              if (confirm("Delete this connector? This cannot be undone.")) {
                                deleteMutation.mutate(connector.id);
                              }
                            }}
                            data-testid={`button-delete-${connector.id}`}
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {!typesLoading && connectorTypes && (
        <Card>
          <CardHeader>
            <CardTitle className="text-lg">Available Integrations</CardTitle>
            <CardDescription>Security tools you can connect to SecureNexus</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
              {connectorTypes.map(ct => {
                const IconComp = getIcon(ct.icon);
                const isConnected = existingConnectors?.some(c => c.type === ct.type);
                return (
                  <Card key={ct.type} className={isConnected ? "border-primary/30" : ""}>
                    <CardContent className="p-4">
                      <div className="flex items-start gap-3">
                        <div className="flex items-center justify-center w-9 h-9 rounded-md bg-muted flex-shrink-0">
                          <IconComp className="h-4 w-4" />
                        </div>
                        <div className="min-w-0 flex-1">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="font-medium text-sm" data-testid={`text-type-name-${ct.type}`}>{ct.name}</span>
                            {isConnected && <Badge variant="secondary" className="text-[10px]">Connected</Badge>}
                          </div>
                          <p className="text-xs text-muted-foreground mt-1 line-clamp-2">{ct.description}</p>
                          {ct.docsUrl && (
                            <a
                              href={ct.docsUrl}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="inline-flex items-center gap-1 text-xs text-primary mt-2 hover:underline"
                              data-testid={`link-docs-${ct.type}`}
                            >
                              <BookOpen className="h-3 w-3" />
                              API Docs
                              <ExternalLink className="h-2.5 w-2.5" />
                            </a>
                          )}
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          </CardContent>
        </Card>
      )}

      <Dialog open={showCreateDialog} onOpenChange={(open) => { if (!open) resetForm(); setShowCreateDialog(open); }}>
        <DialogContent className="max-w-lg max-h-[85vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Add Connector</DialogTitle>
            <DialogDescription>Connect a security tool to pull alerts automatically</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="connector-name">Connector Name</Label>
              <Input
                id="connector-name"
                placeholder="e.g. Production CrowdStrike"
                value={connectorName}
                onChange={e => setConnectorName(e.target.value)}
                data-testid="input-connector-name"
              />
            </div>
            <div className="space-y-2">
              <Label>Source Type</Label>
              <Select value={selectedType} onValueChange={(val) => { setSelectedType(val); setFormData({}); }}>
                <SelectTrigger data-testid="select-connector-type">
                  <SelectValue placeholder="Select a security tool..." />
                </SelectTrigger>
                <SelectContent>
                  {connectorTypes?.map(ct => (
                    <SelectItem key={ct.type} value={ct.type} data-testid={`option-type-${ct.type}`}>
                      {ct.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            {selectedMeta && (
              <>
                {selectedMeta.docsUrl && (
                  <div className="flex items-center gap-2 p-3 rounded-md bg-muted">
                    <BookOpen className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                    <div className="flex-1 min-w-0">
                      <p className="text-xs text-muted-foreground">
                        Refer to the official API documentation to find the required credentials and endpoint details.
                      </p>
                    </div>
                    <a
                      href={selectedMeta.docsUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      data-testid="link-docs-selected"
                    >
                      <Button variant="outline" size="sm" type="button">
                        <ExternalLink className="h-3.5 w-3.5 mr-1.5" />
                        View API Docs
                      </Button>
                    </a>
                  </div>
                )}
                {selectedMeta.requiredFields.map(field => (
                  <div key={field.key} className="space-y-2">
                    <Label htmlFor={`field-${field.key}`}>{field.label} <span className="text-destructive">*</span></Label>
                    <Input
                      id={`field-${field.key}`}
                      type={field.type === "password" ? "password" : "text"}
                      placeholder={field.placeholder}
                      value={formData[field.key] || ""}
                      onChange={e => setFormData(prev => ({ ...prev, [field.key]: e.target.value }))}
                      data-testid={`input-${field.key}`}
                    />
                  </div>
                ))}
                {selectedMeta.optionalFields.map(field => (
                  <div key={field.key} className="space-y-2">
                    <Label htmlFor={`field-${field.key}`}>{field.label}</Label>
                    <Input
                      id={`field-${field.key}`}
                      type={field.type === "password" ? "password" : "text"}
                      placeholder={field.placeholder}
                      value={formData[field.key] || ""}
                      onChange={e => setFormData(prev => ({ ...prev, [field.key]: e.target.value }))}
                      data-testid={`input-${field.key}`}
                    />
                  </div>
                ))}
                <div className="space-y-2">
                  <Label htmlFor="polling-interval">Polling Interval (minutes)</Label>
                  <Input
                    id="polling-interval"
                    type="number"
                    min="1"
                    max="1440"
                    value={pollingInterval}
                    onChange={e => setPollingInterval(e.target.value)}
                    data-testid="input-polling-interval"
                  />
                </div>
              </>
            )}
          </div>
          <DialogFooter className="gap-2">
            <Button variant="outline" onClick={() => { resetForm(); setShowCreateDialog(false); }} data-testid="button-cancel-create">
              Cancel
            </Button>
            <Button
              onClick={handleCreate}
              disabled={!selectedType || !connectorName || createMutation.isPending}
              data-testid="button-confirm-create"
            >
              {createMutation.isPending ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Plus className="h-4 w-4 mr-2" />}
              Create Connector
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

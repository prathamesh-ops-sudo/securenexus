import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import {
  Plug, Bell, Shield, Plus, Trash2, Pencil, TestTube, RefreshCw,
  Loader2, CheckCircle, XCircle, AlertTriangle, Clock, Zap,
  Mail, MessageSquare, Webhook, Star,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter, DialogClose,
} from "@/components/ui/dialog";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import type { IntegrationConfig, NotificationChannel, ResponseAction } from "@shared/schema";

const INTEGRATION_TYPES = [
  { value: "jira", label: "Jira" },
  { value: "servicenow", label: "ServiceNow" },
  { value: "slack", label: "Slack" },
  { value: "teams", label: "Teams" },
  { value: "pagerduty", label: "PagerDuty" },
  { value: "email", label: "Email" },
  { value: "webhook", label: "Webhook" },
] as const;

const CHANNEL_TYPES = [
  { value: "slack", label: "Slack" },
  { value: "teams", label: "Teams" },
  { value: "email", label: "Email" },
  { value: "webhook", label: "Webhook" },
  { value: "pagerduty", label: "PagerDuty" },
] as const;

const EVENT_OPTIONS = [
  { value: "incident_created", label: "Incident Created" },
  { value: "incident_escalated", label: "Incident Escalated" },
  { value: "alert_critical", label: "Alert Critical" },
  { value: "alert_created", label: "Alert Created" },
] as const;

const CONFIG_FIELDS: Record<string, { key: string; label: string; type: string; placeholder: string }[]> = {
  jira: [
    { key: "baseUrl", label: "Base URL", type: "text", placeholder: "https://your-domain.atlassian.net" },
    { key: "projectKey", label: "Project Key", type: "text", placeholder: "SEC" },
    { key: "apiToken", label: "API Token", type: "password", placeholder: "Your Jira API token" },
    { key: "email", label: "Email", type: "email", placeholder: "user@example.com" },
  ],
  servicenow: [
    { key: "instanceUrl", label: "Instance URL", type: "text", placeholder: "https://instance.service-now.com" },
    { key: "username", label: "Username", type: "text", placeholder: "admin" },
    { key: "password", label: "Password", type: "password", placeholder: "Password" },
  ],
  slack: [
    { key: "webhookUrl", label: "Webhook URL", type: "text", placeholder: "https://hooks.slack.com/services/..." },
    { key: "channel", label: "Channel", type: "text", placeholder: "#security-alerts" },
  ],
  teams: [
    { key: "webhookUrl", label: "Webhook URL", type: "text", placeholder: "https://outlook.office.com/webhook/..." },
  ],
  pagerduty: [
    { key: "routingKey", label: "Routing Key", type: "password", placeholder: "Integration routing key" },
    { key: "serviceId", label: "Service ID", type: "text", placeholder: "PXXXXXX" },
  ],
  email: [
    { key: "smtpHost", label: "SMTP Host", type: "text", placeholder: "smtp.example.com" },
    { key: "smtpPort", label: "SMTP Port", type: "text", placeholder: "587" },
    { key: "from", label: "From", type: "email", placeholder: "alerts@example.com" },
    { key: "to", label: "To", type: "email", placeholder: "team@example.com" },
  ],
  webhook: [
    { key: "url", label: "URL", type: "text", placeholder: "https://api.example.com/webhook" },
    { key: "secret", label: "Secret", type: "password", placeholder: "Webhook signing secret" },
    { key: "method", label: "Method", type: "text", placeholder: "POST" },
  ],
};

function formatDateTime(date: string | Date | null | undefined): string {
  if (!date) return "Never";
  return new Date(date).toLocaleString("en-US", {
    year: "numeric", month: "short", day: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
}

function typeBadge(type: string) {
  const colors: Record<string, string> = {
    jira: "border-blue-500/30 text-blue-400",
    servicenow: "border-green-500/30 text-green-400",
    slack: "border-purple-500/30 text-purple-400",
    teams: "border-indigo-500/30 text-indigo-400",
    pagerduty: "border-emerald-500/30 text-emerald-400",
    email: "border-yellow-500/30 text-yellow-400",
    webhook: "border-orange-500/30 text-orange-400",
  };
  return (
    <Badge variant="outline" className={`no-default-hover-elevate no-default-active-elevate text-[10px] uppercase ${colors[type] || ""}`}>
      {type}
    </Badge>
  );
}

function statusBadge(status: string) {
  switch (status) {
    case "active":
      return <Badge variant="default"><CheckCircle className="h-3 w-3 mr-1" />Active</Badge>;
    case "error":
      return <Badge variant="destructive"><XCircle className="h-3 w-3 mr-1" />Error</Badge>;
    case "inactive":
      return <Badge variant="outline"><AlertTriangle className="h-3 w-3 mr-1" />Inactive</Badge>;
    default:
      return <Badge variant="outline">{status}</Badge>;
  }
}

function IntegrationsTab() {
  const { toast } = useToast();
  const [showDialog, setShowDialog] = useState(false);
  const [editingItem, setEditingItem] = useState<IntegrationConfig | null>(null);
  const [formName, setFormName] = useState("");
  const [formType, setFormType] = useState("");
  const [formConfig, setFormConfig] = useState<Record<string, string>>({});
  const [testingId, setTestingId] = useState<string | null>(null);

  const { data: integrations, isLoading } = useQuery<IntegrationConfig[]>({
    queryKey: ["/api/integrations"],
  });

  const createMutation = useMutation({
    mutationFn: async (data: any) => {
      const res = await apiRequest("POST", "/api/integrations", data);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/integrations"] });
      closeDialog();
      toast({ title: "Integration created", description: "New integration has been configured." });
    },
    onError: (err: Error) => {
      toast({ title: "Failed to create integration", description: err.message, variant: "destructive" });
    },
  });

  const updateMutation = useMutation({
    mutationFn: async ({ id, data }: { id: string; data: any }) => {
      const res = await apiRequest("PATCH", `/api/integrations/${id}`, data);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/integrations"] });
      closeDialog();
      toast({ title: "Integration updated" });
    },
    onError: (err: Error) => {
      toast({ title: "Failed to update integration", description: err.message, variant: "destructive" });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("DELETE", `/api/integrations/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/integrations"] });
      toast({ title: "Integration deleted" });
    },
    onError: (err: Error) => {
      toast({ title: "Failed to delete", description: err.message, variant: "destructive" });
    },
  });

  const testMutation = useMutation({
    mutationFn: async (id: string) => {
      setTestingId(id);
      const res = await apiRequest("POST", `/api/integrations/${id}/test`);
      return res.json();
    },
    onSuccess: (data: any) => {
      setTestingId(null);
      queryClient.invalidateQueries({ queryKey: ["/api/integrations"] });
      if (data.success) {
        toast({ title: "Connection successful", description: data.message || "Integration is working." });
      } else {
        toast({ title: "Connection failed", description: data.message, variant: "destructive" });
      }
    },
    onError: (err: Error) => {
      setTestingId(null);
      toast({ title: "Test failed", description: err.message, variant: "destructive" });
    },
  });

  function closeDialog() {
    setShowDialog(false);
    setEditingItem(null);
    setFormName("");
    setFormType("");
    setFormConfig({});
  }

  function openCreate() {
    closeDialog();
    setShowDialog(true);
  }

  function openEdit(item: IntegrationConfig) {
    setEditingItem(item);
    setFormName(item.name);
    setFormType(item.type);
    setFormConfig((item.config as Record<string, string>) || {});
    setShowDialog(true);
  }

  function handleSubmit() {
    if (!formName || !formType) {
      toast({ title: "Missing fields", description: "Name and type are required.", variant: "destructive" });
      return;
    }
    const payload = { name: formName, type: formType, config: formConfig, status: "active" };
    if (editingItem) {
      updateMutation.mutate({ id: editingItem.id, data: payload });
    } else {
      createMutation.mutate(payload);
    }
  }

  const fields = formType ? (CONFIG_FIELDS[formType] || []) : [];

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2 flex-wrap">
            <Plug className="h-4 w-4 text-muted-foreground" />
            Configured Integrations
          </CardTitle>
          <Button size="sm" onClick={openCreate} data-testid="button-add-integration">
            <Plus className="h-4 w-4 mr-1" />
            Add Integration
          </Button>
        </CardHeader>
        <CardContent>
          {!integrations?.length ? (
            <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
              <Plug className="h-10 w-10 mb-3" />
              <p className="text-sm">No integrations configured yet</p>
              <p className="text-xs mt-1">Add an integration to connect with external tools</p>
            </div>
          ) : (
            <div className="overflow-x-auto border rounded-md">
              <Table data-testid="table-integrations">
                <TableHeader>
                  <TableRow>
                    <TableHead className="text-xs">Name</TableHead>
                    <TableHead className="text-xs">Type</TableHead>
                    <TableHead className="text-xs">Status</TableHead>
                    <TableHead className="text-xs">Last Tested</TableHead>
                    <TableHead className="text-xs">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {integrations.map((item) => (
                    <TableRow key={item.id} data-testid={`row-integration-${item.id}`}>
                      <TableCell>
                        <span className="text-sm font-medium" data-testid={`text-integration-name-${item.id}`}>{item.name}</span>
                      </TableCell>
                      <TableCell data-testid={`badge-integration-type-${item.id}`}>
                        {typeBadge(item.type)}
                      </TableCell>
                      <TableCell data-testid={`badge-integration-status-${item.id}`}>
                        {statusBadge(item.status)}
                      </TableCell>
                      <TableCell>
                        <span className="text-xs text-muted-foreground" data-testid={`text-integration-tested-${item.id}`}>
                          {formatDateTime(item.lastTestedAt)}
                        </span>
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-1">
                          <Button
                            size="icon"
                            variant="ghost"
                            onClick={() => testMutation.mutate(item.id)}
                            disabled={testingId === item.id}
                            data-testid={`button-test-integration-${item.id}`}
                          >
                            {testingId === item.id ? <Loader2 className="h-4 w-4 animate-spin" /> : <TestTube className="h-4 w-4" />}
                          </Button>
                          <Button
                            size="icon"
                            variant="ghost"
                            onClick={() => openEdit(item)}
                            data-testid={`button-edit-integration-${item.id}`}
                          >
                            <Pencil className="h-4 w-4" />
                          </Button>
                          <Button
                            size="icon"
                            variant="ghost"
                            onClick={() => {
                              if (confirm("Delete this integration?")) {
                                deleteMutation.mutate(item.id);
                              }
                            }}
                            data-testid={`button-delete-integration-${item.id}`}
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      <Dialog open={showDialog} onOpenChange={(open) => { if (!open) closeDialog(); else setShowDialog(true); }}>
        <DialogContent className="max-w-lg max-h-[85vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>{editingItem ? "Edit Integration" : "Add Integration"}</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-2">
              <Label htmlFor="integration-name">Name</Label>
              <Input
                id="integration-name"
                placeholder="e.g. Production Slack"
                value={formName}
                onChange={(e) => setFormName(e.target.value)}
                data-testid="input-integration-name"
              />
            </div>
            <div className="space-y-2">
              <Label>Type</Label>
              <Select value={formType} onValueChange={(val) => { setFormType(val); if (!editingItem) setFormConfig({}); }}>
                <SelectTrigger data-testid="select-integration-type">
                  <SelectValue placeholder="Select integration type..." />
                </SelectTrigger>
                <SelectContent>
                  {INTEGRATION_TYPES.map((t) => (
                    <SelectItem key={t.value} value={t.value} data-testid={`option-type-${t.value}`}>
                      {t.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            {fields.map((field) => (
              <div key={field.key} className="space-y-2">
                <Label htmlFor={`field-${field.key}`}>{field.label}</Label>
                <Input
                  id={`field-${field.key}`}
                  type={field.type === "password" ? "password" : "text"}
                  placeholder={field.placeholder}
                  value={formConfig[field.key] || ""}
                  onChange={(e) => setFormConfig((prev) => ({ ...prev, [field.key]: e.target.value }))}
                  data-testid={`input-integration-${field.key}`}
                />
              </div>
            ))}
          </div>
          <DialogFooter>
            <DialogClose asChild>
              <Button variant="outline" data-testid="button-cancel-integration">Cancel</Button>
            </DialogClose>
            <Button
              onClick={handleSubmit}
              disabled={!formName || !formType || createMutation.isPending || updateMutation.isPending}
              data-testid="button-submit-integration"
            >
              {(createMutation.isPending || updateMutation.isPending) ? (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              ) : (
                <Plus className="h-4 w-4 mr-2" />
              )}
              {editingItem ? "Update" : "Add"} Integration
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function NotificationChannelsTab() {
  const { toast } = useToast();
  const [showDialog, setShowDialog] = useState(false);
  const [formName, setFormName] = useState("");
  const [formType, setFormType] = useState("");
  const [formConfig, setFormConfig] = useState<Record<string, string>>({});
  const [formEvents, setFormEvents] = useState<string[]>([]);
  const [formIsDefault, setFormIsDefault] = useState(false);
  const [testingId, setTestingId] = useState<string | null>(null);

  const { data: channels, isLoading } = useQuery<NotificationChannel[]>({
    queryKey: ["/api/notification-channels"],
  });

  const createMutation = useMutation({
    mutationFn: async (data: any) => {
      const res = await apiRequest("POST", "/api/notification-channels", data);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/notification-channels"] });
      closeDialog();
      toast({ title: "Channel created", description: "Notification channel has been set up." });
    },
    onError: (err: Error) => {
      toast({ title: "Failed to create channel", description: err.message, variant: "destructive" });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("DELETE", `/api/notification-channels/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/notification-channels"] });
      toast({ title: "Channel deleted" });
    },
    onError: (err: Error) => {
      toast({ title: "Failed to delete", description: err.message, variant: "destructive" });
    },
  });

  const testMutation = useMutation({
    mutationFn: async (id: string) => {
      setTestingId(id);
      const res = await apiRequest("POST", `/api/notification-channels/${id}/test`);
      return res.json();
    },
    onSuccess: (data: any) => {
      setTestingId(null);
      if (data.success) {
        toast({ title: "Test notification sent", description: data.message || "Channel is working." });
      } else {
        toast({ title: "Test failed", description: data.message, variant: "destructive" });
      }
    },
    onError: (err: Error) => {
      setTestingId(null);
      toast({ title: "Test failed", description: err.message, variant: "destructive" });
    },
  });

  function closeDialog() {
    setShowDialog(false);
    setFormName("");
    setFormType("");
    setFormConfig({});
    setFormEvents([]);
    setFormIsDefault(false);
  }

  function toggleEvent(event: string) {
    setFormEvents((prev) =>
      prev.includes(event) ? prev.filter((e) => e !== event) : [...prev, event]
    );
  }

  function handleSubmit() {
    if (!formName || !formType) {
      toast({ title: "Missing fields", description: "Name and type are required.", variant: "destructive" });
      return;
    }
    createMutation.mutate({
      name: formName,
      type: formType,
      config: formConfig,
      events: formEvents,
      isDefault: formIsDefault,
      status: "active",
    });
  }

  const channelFields = formType ? (CONFIG_FIELDS[formType] || []) : [];

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2 flex-wrap">
            <Bell className="h-4 w-4 text-muted-foreground" />
            Notification Channels
          </CardTitle>
          <Button size="sm" onClick={() => setShowDialog(true)} data-testid="button-add-channel">
            <Plus className="h-4 w-4 mr-1" />
            Add Channel
          </Button>
        </CardHeader>
        <CardContent>
          {!channels?.length ? (
            <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
              <Bell className="h-10 w-10 mb-3" />
              <p className="text-sm">No notification channels configured</p>
              <p className="text-xs mt-1">Set up channels to receive security notifications</p>
            </div>
          ) : (
            <div className="overflow-x-auto border rounded-md">
              <Table data-testid="table-channels">
                <TableHeader>
                  <TableRow>
                    <TableHead className="text-xs">Name</TableHead>
                    <TableHead className="text-xs">Type</TableHead>
                    <TableHead className="text-xs">Events</TableHead>
                    <TableHead className="text-xs">Status</TableHead>
                    <TableHead className="text-xs">Default</TableHead>
                    <TableHead className="text-xs">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {channels.map((ch) => (
                    <TableRow key={ch.id} data-testid={`row-channel-${ch.id}`}>
                      <TableCell>
                        <span className="text-sm font-medium" data-testid={`text-channel-name-${ch.id}`}>{ch.name}</span>
                      </TableCell>
                      <TableCell data-testid={`badge-channel-type-${ch.id}`}>
                        {typeBadge(ch.type)}
                      </TableCell>
                      <TableCell>
                        <div className="flex flex-wrap gap-1">
                          {(ch.events || []).map((ev) => (
                            <Badge key={ev} variant="outline" className="no-default-hover-elevate no-default-active-elevate text-[10px]" data-testid={`badge-channel-event-${ch.id}-${ev}`}>
                              {ev.replace(/_/g, " ")}
                            </Badge>
                          ))}
                        </div>
                      </TableCell>
                      <TableCell data-testid={`badge-channel-status-${ch.id}`}>
                        {statusBadge(ch.status)}
                      </TableCell>
                      <TableCell>
                        {ch.isDefault && (
                          <Star className="h-4 w-4 text-yellow-400" data-testid={`icon-channel-default-${ch.id}`} />
                        )}
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-1">
                          <Button
                            size="icon"
                            variant="ghost"
                            onClick={() => testMutation.mutate(ch.id)}
                            disabled={testingId === ch.id}
                            data-testid={`button-test-channel-${ch.id}`}
                          >
                            {testingId === ch.id ? <Loader2 className="h-4 w-4 animate-spin" /> : <TestTube className="h-4 w-4" />}
                          </Button>
                          <Button
                            size="icon"
                            variant="ghost"
                            onClick={() => {
                              if (confirm("Delete this notification channel?")) {
                                deleteMutation.mutate(ch.id);
                              }
                            }}
                            data-testid={`button-delete-channel-${ch.id}`}
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      <Dialog open={showDialog} onOpenChange={(open) => { if (!open) closeDialog(); else setShowDialog(true); }}>
        <DialogContent className="max-w-lg max-h-[85vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Add Notification Channel</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-2">
              <Label htmlFor="channel-name">Name</Label>
              <Input
                id="channel-name"
                placeholder="e.g. Security Team Slack"
                value={formName}
                onChange={(e) => setFormName(e.target.value)}
                data-testid="input-channel-name"
              />
            </div>
            <div className="space-y-2">
              <Label>Type</Label>
              <Select value={formType} onValueChange={(val) => { setFormType(val); setFormConfig({}); }}>
                <SelectTrigger data-testid="select-channel-type">
                  <SelectValue placeholder="Select channel type..." />
                </SelectTrigger>
                <SelectContent>
                  {CHANNEL_TYPES.map((t) => (
                    <SelectItem key={t.value} value={t.value} data-testid={`option-channel-type-${t.value}`}>
                      {t.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            {channelFields.map((field) => (
              <div key={field.key} className="space-y-2">
                <Label htmlFor={`channel-field-${field.key}`}>{field.label}</Label>
                <Input
                  id={`channel-field-${field.key}`}
                  type={field.type === "password" ? "password" : "text"}
                  placeholder={field.placeholder}
                  value={formConfig[field.key] || ""}
                  onChange={(e) => setFormConfig((prev) => ({ ...prev, [field.key]: e.target.value }))}
                  data-testid={`input-channel-${field.key}`}
                />
              </div>
            ))}
            <div className="space-y-3">
              <Label>Events</Label>
              <div className="flex flex-wrap gap-2">
                {EVENT_OPTIONS.map((ev) => (
                  <Badge
                    key={ev.value}
                    variant="outline"
                    className={`cursor-pointer toggle-elevate ${formEvents.includes(ev.value) ? "toggle-elevated border-red-500/40 text-red-400" : ""}`}
                    onClick={() => toggleEvent(ev.value)}
                    data-testid={`badge-event-${ev.value}`}
                  >
                    {formEvents.includes(ev.value) && <CheckCircle className="h-3 w-3 mr-1" />}
                    {ev.label}
                  </Badge>
                ))}
              </div>
            </div>
            <div className="flex items-center justify-between gap-2 p-3 rounded-md bg-muted/30">
              <div className="flex items-center gap-2">
                <Star className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                <div>
                  <div className="text-sm font-medium">Default Channel</div>
                  <div className="text-xs text-muted-foreground">Use as default notification target</div>
                </div>
              </div>
              <Switch
                checked={formIsDefault}
                onCheckedChange={setFormIsDefault}
                data-testid="switch-channel-default"
              />
            </div>
          </div>
          <DialogFooter>
            <DialogClose asChild>
              <Button variant="outline" data-testid="button-cancel-channel">Cancel</Button>
            </DialogClose>
            <Button
              onClick={handleSubmit}
              disabled={!formName || !formType || createMutation.isPending}
              data-testid="button-submit-channel"
            >
              {createMutation.isPending ? (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              ) : (
                <Plus className="h-4 w-4 mr-2" />
              )}
              Add Channel
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function ResponseActionsTab() {
  const { data: actions, isLoading, refetch } = useQuery<ResponseAction[]>({
    queryKey: ["/api/response-actions"],
  });

  const actionStatusBadge = (status: string) => {
    switch (status) {
      case "completed":
        return <Badge variant="default" className="border-green-500/30 text-green-400"><CheckCircle className="h-3 w-3 mr-1" />Completed</Badge>;
      case "simulated":
        return <Badge variant="outline" className="no-default-hover-elevate no-default-active-elevate border-yellow-500/30 text-yellow-400"><AlertTriangle className="h-3 w-3 mr-1" />Simulated</Badge>;
      case "failed":
        return <Badge variant="destructive"><XCircle className="h-3 w-3 mr-1" />Failed</Badge>;
      case "pending":
        return <Badge variant="secondary"><Clock className="h-3 w-3 mr-1" />Pending</Badge>;
      case "executing":
        return <Badge variant="secondary"><Loader2 className="h-3 w-3 mr-1 animate-spin" />Executing</Badge>;
      default:
        return <Badge variant="outline">{status}</Badge>;
    }
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2 flex-wrap">
            <Zap className="h-4 w-4 text-muted-foreground" />
            Response Actions Log
          </CardTitle>
          <Button
            size="sm"
            variant="outline"
            onClick={() => refetch()}
            data-testid="button-refresh-actions"
          >
            <RefreshCw className="h-3.5 w-3.5 mr-1.5" />
            Refresh
          </Button>
        </CardHeader>
        <CardContent>
          {!actions?.length ? (
            <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
              <Shield className="h-10 w-10 mb-3" />
              <p className="text-sm">No response actions executed yet</p>
              <p className="text-xs mt-1">Response actions from incident handling will appear here</p>
            </div>
          ) : (
            <div className="overflow-x-auto border rounded-md">
              <Table data-testid="table-response-actions">
                <TableHeader>
                  <TableRow>
                    <TableHead className="text-xs">Action Type</TableHead>
                    <TableHead className="text-xs">Target</TableHead>
                    <TableHead className="text-xs">Incident</TableHead>
                    <TableHead className="text-xs">Status</TableHead>
                    <TableHead className="text-xs">Executed By</TableHead>
                    <TableHead className="text-xs">Executed At</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {actions.map((action) => (
                    <TableRow key={action.id} data-testid={`row-action-${action.id}`}>
                      <TableCell data-testid={`badge-action-type-${action.id}`}>
                        <Badge variant="outline" className="no-default-hover-elevate no-default-active-elevate text-[10px] uppercase">
                          {action.actionType.replace(/_/g, " ")}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className="text-sm" data-testid={`text-action-target-${action.id}`}>
                          {action.targetValue || "N/A"}
                          {action.targetType && (
                            <span className="text-xs text-muted-foreground ml-1">({action.targetType})</span>
                          )}
                        </div>
                      </TableCell>
                      <TableCell>
                        <span className="text-xs font-mono text-muted-foreground" data-testid={`text-action-incident-${action.id}`}>
                          {action.incidentId ? action.incidentId.slice(0, 8) + "..." : "N/A"}
                        </span>
                      </TableCell>
                      <TableCell data-testid={`badge-action-status-${action.id}`}>
                        {actionStatusBadge(action.status)}
                      </TableCell>
                      <TableCell>
                        <span className="text-xs text-muted-foreground" data-testid={`text-action-executor-${action.id}`}>
                          {action.executedBy || "System"}
                        </span>
                      </TableCell>
                      <TableCell>
                        <span className="text-xs text-muted-foreground" data-testid={`text-action-time-${action.id}`}>
                          {formatDateTime(action.executedAt)}
                        </span>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

export default function IntegrationsPage() {
  return (
    <div className="p-4 md:p-6 space-y-6 max-w-7xl mx-auto" data-testid="page-integrations">
      <div>
        <h1 className="text-2xl font-bold tracking-tight" data-testid="text-page-title">
          <span className="gradient-text-red">Integrations & Notifications</span>
        </h1>
        <p className="text-sm text-muted-foreground mt-1" data-testid="text-page-description">
          Configure external integrations, notification channels, and view response actions
        </p>
        <div className="gradient-accent-line w-24 mt-2" />
      </div>

      <Tabs defaultValue="integrations" data-testid="tabs-integrations">
        <TabsList className="flex-wrap" data-testid="tabs-list">
          <TabsTrigger value="integrations" data-testid="tab-integrations">
            <Plug className="h-3.5 w-3.5 mr-1.5" />
            Integrations
          </TabsTrigger>
          <TabsTrigger value="channels" data-testid="tab-channels">
            <Bell className="h-3.5 w-3.5 mr-1.5" />
            Notification Channels
          </TabsTrigger>
          <TabsTrigger value="response-actions" data-testid="tab-response-actions">
            <Zap className="h-3.5 w-3.5 mr-1.5" />
            Response Actions
          </TabsTrigger>
        </TabsList>

        <TabsContent value="integrations">
          <IntegrationsTab />
        </TabsContent>
        <TabsContent value="channels">
          <NotificationChannelsTab />
        </TabsContent>
        <TabsContent value="response-actions">
          <ResponseActionsTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}

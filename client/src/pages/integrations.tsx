import { useState, useEffect } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import {
  Plug,
  Bell,
  Shield,
  Plus,
  Trash2,
  Pencil,
  TestTube,
  RefreshCw,
  Loader2,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Clock,
  Zap,
  Star,
  ArrowLeftRight,
  ShieldCheck,
  Play,
  Eye,
  ThumbsUp,
  ThumbsDown,
  Link2,
  Settings2,
  ScrollText,
  ChevronLeft,
  ChevronRight,
  Moon,
  Mail,
  Save,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter, DialogClose } from "@/components/ui/dialog";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { formatDateTime } from "@/lib/i18n";
import { useToast } from "@/hooks/use-toast";
import type {
  IntegrationConfig,
  NotificationChannel,
  NotificationDeliveryLog,
  NotificationUserPreferences,
  ResponseAction,
} from "@shared/schema";

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
    <Badge
      variant="outline"
      className={`no-default-hover-elevate no-default-active-elevate text-[10px] uppercase ${colors[type] || ""}`}
    >
      {type}
    </Badge>
  );
}

function statusBadge(status: string) {
  switch (status) {
    case "active":
      return (
        <Badge variant="default">
          <CheckCircle className="h-3 w-3 mr-1" />
          Active
        </Badge>
      );
    case "error":
      return (
        <Badge variant="destructive">
          <XCircle className="h-3 w-3 mr-1" />
          Error
        </Badge>
      );
    case "inactive":
      return (
        <Badge variant="outline">
          <AlertTriangle className="h-3 w-3 mr-1" />
          Inactive
        </Badge>
      );
    default:
      return <Badge variant="outline">{status}</Badge>;
  }
}

function IntegrationTestResultCard({
  result,
  integrationType,
}: {
  result: { success: boolean; message?: string } | null;
  integrationType: string;
}) {
  if (!result) return null;
  if (result.success) {
    return (
      <div className="mt-2 p-3 rounded-lg border border-emerald-500/30 bg-emerald-500/5">
        <div className="flex items-center gap-2">
          <CheckCircle className="h-4 w-4 text-emerald-400" />
          <span className="text-sm font-medium text-emerald-400">Connection Successful</span>
        </div>
        <p className="text-xs text-muted-foreground mt-1">
          {result.message || `${integrationType} integration is responding correctly.`}
        </p>
      </div>
    );
  }
  const remediationSteps: Record<string, string[]> = {
    jira: [
      "Verify the Base URL includes https:// and your domain",
      "Check the API token hasn't expired",
      "Ensure the email matches the token owner",
    ],
    servicenow: [
      "Confirm the Instance URL is correct",
      "Verify username and password credentials",
      "Check instance is not in maintenance mode",
    ],
    slack: [
      "Verify the Webhook URL is a valid Slack incoming webhook",
      "Check the channel exists and bot has access",
      "Regenerate the webhook if it was revoked",
    ],
    teams: [
      "Verify the Webhook URL is a valid Teams connector URL",
      "Check the connector hasn't been removed from the channel",
    ],
    pagerduty: [
      "Verify the Routing Key is correct",
      "Check the Service ID matches an active service",
      "Ensure the integration key hasn't been rotated",
    ],
    email: [
      "Verify SMTP host and port are correct",
      "Check SMTP credentials and authentication method",
      "Ensure the SMTP server allows connections from your IP",
    ],
    webhook: [
      "Verify the URL is reachable from the server",
      "Check the signing secret matches",
      "Ensure the endpoint accepts the configured HTTP method",
    ],
  };
  const steps = remediationSteps[integrationType] || [
    "Check the integration configuration",
    "Verify network connectivity",
    "Review the service status page",
  ];
  return (
    <div className="mt-2 p-3 rounded-lg border border-destructive/30 bg-destructive/5">
      <div className="flex items-center gap-2">
        <XCircle className="h-4 w-4 text-destructive" />
        <span className="text-sm font-medium text-destructive">Connection Failed</span>
      </div>
      {result.message && (
        <p className="text-xs text-muted-foreground mt-1 font-mono bg-muted/30 p-2 rounded">{result.message}</p>
      )}
      <div className="mt-2">
        <p className="text-xs font-medium mb-1">Remediation Steps:</p>
        <ol className="text-xs text-muted-foreground space-y-1 list-decimal list-inside">
          {steps.map((step, i) => (
            <li key={i}>{step}</li>
          ))}
        </ol>
      </div>
    </div>
  );
}

function IntegrationsTab() {
  const { toast } = useToast();
  const [showDialog, setShowDialog] = useState(false);
  const [editingItem, setEditingItem] = useState<IntegrationConfig | null>(null);
  const [formName, setFormName] = useState("");
  const [formType, setFormType] = useState("");
  const [formConfig, setFormConfig] = useState<Record<string, string>>({});
  const [testingId, setTestingId] = useState<string | null>(null);
  const [testResults, setTestResults] = useState<Record<string, { success: boolean; message?: string }>>({});
  const [touchedFields, setTouchedFields] = useState<Record<string, boolean>>({});
  const [formErrors, setFormErrors] = useState<Record<string, string>>({});
  const [submitAttempted, setSubmitAttempted] = useState(false);

  const {
    data: integrations,
    isLoading,
    isError: integrationsError,
    refetch: refetchIntegrations,
  } = useQuery<IntegrationConfig[]>({
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
      return { id, data: await res.json() };
    },
    onSuccess: ({ id, data }: { id: string; data: { success: boolean; message?: string } }) => {
      setTestingId(null);
      setTestResults((prev) => ({ ...prev, [id]: data }));
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
    setTouchedFields({});
    setFormErrors({});
    setSubmitAttempted(false);
  }

  function validateConfigFields(): Record<string, string> {
    const errors: Record<string, string> = {};
    if (!formType) return errors;
    const fields = CONFIG_FIELDS[formType] || [];
    for (const field of fields) {
      const val = (formConfig[field.key] || "").trim();
      if (!val) {
        errors[field.key] = `${field.label} is required`;
        continue;
      }
      const isUrl = field.key.toLowerCase().includes("url");
      const isEmail = field.type === "email";
      const isPort = field.key.toLowerCase().includes("port");
      const isMethod = field.key === "method";
      if (isUrl && !/^https?:\/\/.+/.test(val)) {
        errors[field.key] = "Must be a valid URL starting with http:// or https://";
      } else if (isEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(val)) {
        errors[field.key] = "Must be a valid email address";
      } else if (isPort) {
        const port = Number(val);
        if (!Number.isInteger(port) || port < 1 || port > 65535) {
          errors[field.key] = "Must be a valid port number (1-65535)";
        }
      } else if (isMethod && !["POST", "PUT", "PATCH", "GET", "DELETE"].includes(val.toUpperCase())) {
        errors[field.key] = "Must be POST, PUT, PATCH, GET, or DELETE";
      }
    }
    return errors;
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
    setSubmitAttempted(true);
    if (!formName.trim() || !formType) {
      return;
    }
    const configErrors = validateConfigFields();
    setFormErrors(configErrors);
    if (Object.keys(configErrors).length > 0) {
      return;
    }
    const payload = { name: formName.trim(), type: formType, config: formConfig };
    if (editingItem) {
      updateMutation.reset();
      updateMutation.mutate({ id: editingItem.id, data: payload });
    } else {
      createMutation.reset();
      createMutation.mutate(payload);
    }
  }

  const fields = formType ? CONFIG_FIELDS[formType] || [] : [];

  if (isLoading) {
    return (
      <div className="space-y-3 py-6" role="status" aria-label="Loading integrations">
        {Array.from({ length: 4 }).map((_, i) => (
          <div key={i} className="flex items-center gap-4 px-4 py-3 border-b last:border-0">
            <Skeleton className="h-4 w-32" />
            <Skeleton className="h-5 w-20 rounded-full" />
            <Skeleton className="h-5 w-16 rounded-full" />
            <Skeleton className="h-4 w-28" />
            <Skeleton className="h-8 w-8 rounded" />
          </div>
        ))}
        <span className="sr-only">Loading integrations...</span>
      </div>
    );
  }

  if (integrationsError) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-center" role="alert">
        <div className="rounded-full bg-destructive/10 p-3 ring-1 ring-destructive/20 mb-3">
          <AlertTriangle className="h-6 w-6 text-destructive" />
        </div>
        <p className="text-sm font-medium">Failed to load integrations</p>
        <p className="text-xs text-muted-foreground mt-1">An error occurred while fetching data.</p>
        <Button
          variant="outline"
          size="sm"
          className="mt-3"
          onClick={() => {
            refetchIntegrations();
          }}
        >
          Try Again
        </Button>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2 flex-wrap">
            <Plug className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
            Configured Integrations
          </CardTitle>
          <Button size="sm" onClick={openCreate} aria-label="Add new integration" data-testid="button-add-integration">
            <Plus className="h-4 w-4 mr-1" aria-hidden="true" />
            Add Integration
          </Button>
        </CardHeader>
        <CardContent>
          {!integrations?.length ? (
            <div
              className="flex flex-col items-center justify-center py-12 text-muted-foreground"
              role="status"
              aria-label="No integrations"
            >
              <Plug className="h-10 w-10 mb-3" aria-hidden="true" />
              <p className="text-sm font-medium">No integrations configured yet</p>
              <p className="text-xs mt-1">Add an integration to connect with external tools</p>
              <Button className="mt-4" size="sm" onClick={openCreate} aria-label="Add your first integration">
                <Plus className="h-4 w-4 mr-1.5" aria-hidden="true" />
                Add First Integration
              </Button>
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
                        <div>
                          <span className="text-sm font-medium" data-testid={`text-integration-name-${item.id}`}>
                            {item.name}
                          </span>
                          <IntegrationTestResultCard
                            result={testResults[item.id] || null}
                            integrationType={item.type}
                          />
                        </div>
                      </TableCell>
                      <TableCell data-testid={`badge-integration-type-${item.id}`}>{typeBadge(item.type)}</TableCell>
                      <TableCell data-testid={`badge-integration-status-${item.id}`}>
                        {statusBadge(item.status)}
                      </TableCell>
                      <TableCell>
                        <span
                          className="text-xs text-muted-foreground"
                          data-testid={`text-integration-tested-${item.id}`}
                        >
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
                            {testingId === item.id ? (
                              <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
                            ) : (
                              <TestTube className="h-4 w-4" aria-hidden="true" />
                            )}
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

      <Dialog
        open={showDialog}
        onOpenChange={(open) => {
          if (!open) closeDialog();
          else setShowDialog(true);
        }}
      >
        <DialogContent className="max-w-lg max-h-[85vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>{editingItem ? "Edit Integration" : "Add Integration"}</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-2">
              <Label htmlFor="integration-name">
                Name <span className="text-destructive">*</span>
              </Label>
              <Input
                id="integration-name"
                placeholder="e.g. Production Slack"
                value={formName}
                onChange={(e) => setFormName(e.target.value)}
                className={submitAttempted && !formName.trim() ? "border-destructive" : ""}
                data-testid="input-integration-name"
              />
              {submitAttempted && !formName.trim() && <p className="text-xs text-destructive">Name is required</p>}
            </div>
            <div className="space-y-2">
              <Label>
                Type <span className="text-destructive">*</span>
              </Label>
              {submitAttempted && !formType && <p className="text-xs text-destructive">Integration type is required</p>}
              <Select
                value={formType}
                onValueChange={(val) => {
                  setFormType(val);
                  if (!editingItem) setFormConfig({});
                }}
              >
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
            {fields.map((field) => {
              const val = formConfig[field.key] || "";
              const fieldError = formErrors[field.key];
              const showError = fieldError && (touchedFields[field.key] || submitAttempted);
              return (
                <div key={field.key} className="space-y-1.5">
                  <Label htmlFor={`field-${field.key}`}>
                    {field.label} <span className="text-destructive">*</span>
                  </Label>
                  <Input
                    id={`field-${field.key}`}
                    type={field.type === "password" ? "password" : "text"}
                    placeholder={field.placeholder}
                    value={val}
                    onChange={(e) => {
                      const newConfig = { ...formConfig, [field.key]: e.target.value };
                      setFormConfig(newConfig);
                      if (formErrors[field.key]) {
                        const updated = { ...formErrors };
                        delete updated[field.key];
                        setFormErrors(updated);
                      }
                    }}
                    onBlur={() => {
                      setTouchedFields((prev) => ({ ...prev, [field.key]: true }));
                      const singleErrors = validateConfigFields();
                      if (singleErrors[field.key]) {
                        setFormErrors((prev) => ({ ...prev, [field.key]: singleErrors[field.key] }));
                      } else {
                        setFormErrors((prev) => {
                          const updated = { ...prev };
                          delete updated[field.key];
                          return updated;
                        });
                      }
                    }}
                    className={showError ? "border-destructive" : ""}
                    aria-invalid={!!showError}
                    aria-describedby={showError ? `error-${field.key}` : undefined}
                    data-testid={`input-integration-${field.key}`}
                  />
                  {showError && (
                    <p id={`error-${field.key}`} className="text-xs text-destructive" role="alert">
                      {fieldError}
                    </p>
                  )}
                </div>
              );
            })}
          </div>
          <DialogFooter>
            <DialogClose asChild>
              <Button variant="outline" data-testid="button-cancel-integration">
                Cancel
              </Button>
            </DialogClose>
            <Button
              onClick={handleSubmit}
              disabled={!formName || !formType || createMutation.isPending || updateMutation.isPending}
              data-testid="button-submit-integration"
            >
              {createMutation.isPending || updateMutation.isPending ? (
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

  const {
    data: channels,
    isLoading,
    isError: _channelsError,
    refetch: _refetchChannels,
  } = useQuery<NotificationChannel[]>({
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
    setFormEvents((prev) => (prev.includes(event) ? prev.filter((e) => e !== event) : [...prev, event]));
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

  const channelFields = formType ? CONFIG_FIELDS[formType] || [] : [];

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
                        <span className="text-sm font-medium" data-testid={`text-channel-name-${ch.id}`}>
                          {ch.name}
                        </span>
                      </TableCell>
                      <TableCell data-testid={`badge-channel-type-${ch.id}`}>{typeBadge(ch.type)}</TableCell>
                      <TableCell>
                        <div className="flex flex-wrap gap-1">
                          {(ch.events || []).map((ev) => (
                            <Badge
                              key={ev}
                              variant="outline"
                              className="no-default-hover-elevate no-default-active-elevate text-[10px]"
                              data-testid={`badge-channel-event-${ch.id}-${ev}`}
                            >
                              {ev.replace(/_/g, " ")}
                            </Badge>
                          ))}
                        </div>
                      </TableCell>
                      <TableCell data-testid={`badge-channel-status-${ch.id}`}>{statusBadge(ch.status)}</TableCell>
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
                            {testingId === ch.id ? (
                              <Loader2 className="h-4 w-4 animate-spin" />
                            ) : (
                              <TestTube className="h-4 w-4" />
                            )}
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

      <Dialog
        open={showDialog}
        onOpenChange={(open) => {
          if (!open) closeDialog();
          else setShowDialog(true);
        }}
      >
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
              <Select
                value={formType}
                onValueChange={(val) => {
                  setFormType(val);
                  setFormConfig({});
                }}
              >
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
            {channelFields.map((field) => {
              const val = formConfig[field.key] || "";
              const isUrl = field.key.toLowerCase().includes("url");
              const urlInvalid = isUrl && val.trim() && !/^https?:\/\/.+/.test(val.trim());
              return (
                <div key={field.key} className="space-y-2">
                  <Label htmlFor={`channel-field-${field.key}`}>{field.label}</Label>
                  <Input
                    id={`channel-field-${field.key}`}
                    type={field.type === "password" ? "password" : "text"}
                    placeholder={field.placeholder}
                    value={val}
                    onChange={(e) => setFormConfig((prev) => ({ ...prev, [field.key]: e.target.value }))}
                    className={urlInvalid ? "border-amber-500" : ""}
                    data-testid={`input-channel-${field.key}`}
                  />
                  {urlInvalid && <p className="text-xs text-amber-400">URL should start with http:// or https://</p>}
                </div>
              );
            })}
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
              <Switch checked={formIsDefault} onCheckedChange={setFormIsDefault} data-testid="switch-channel-default" />
            </div>
          </div>
          <DialogFooter>
            <DialogClose asChild>
              <Button variant="outline" data-testid="button-cancel-channel">
                Cancel
              </Button>
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
  const {
    data: actions,
    isLoading,
    refetch,
  } = useQuery<ResponseAction[]>({
    queryKey: ["/api/response-actions"],
  });

  const actionStatusBadge = (status: string) => {
    switch (status) {
      case "completed":
        return (
          <Badge variant="default" className="border-green-500/30 text-green-400">
            <CheckCircle className="h-3 w-3 mr-1" />
            Completed
          </Badge>
        );
      case "simulated":
        return (
          <Badge
            variant="outline"
            className="no-default-hover-elevate no-default-active-elevate border-yellow-500/30 text-yellow-400"
          >
            <AlertTriangle className="h-3 w-3 mr-1" />
            Simulated
          </Badge>
        );
      case "failed":
        return (
          <Badge variant="destructive">
            <XCircle className="h-3 w-3 mr-1" />
            Failed
          </Badge>
        );
      case "pending":
        return (
          <Badge variant="secondary">
            <Clock className="h-3 w-3 mr-1" />
            Pending
          </Badge>
        );
      case "executing":
        return (
          <Badge variant="secondary">
            <Loader2 className="h-3 w-3 mr-1 animate-spin" />
            Executing
          </Badge>
        );
      case "unavailable":
        return (
          <Badge variant="outline" className="border-yellow-500/30 text-yellow-400">
            <AlertTriangle className="h-3 w-3 mr-1" />
            Not configured
          </Badge>
        );
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
          <Button size="sm" variant="outline" onClick={() => refetch()} data-testid="button-refresh-actions">
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
                        <Badge
                          variant="outline"
                          className="no-default-hover-elevate no-default-active-elevate text-[10px] uppercase"
                        >
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
                        <span
                          className="text-xs font-mono text-muted-foreground"
                          data-testid={`text-action-incident-${action.id}`}
                        >
                          {action.incidentId ? action.incidentId.slice(0, 8) + "..." : "N/A"}
                        </span>
                      </TableCell>
                      <TableCell data-testid={`badge-action-status-${action.id}`}>
                        {actionStatusBadge(action.status)}
                      </TableCell>
                      <TableCell>
                        <span
                          className="text-xs text-muted-foreground"
                          data-testid={`text-action-executor-${action.id}`}
                        >
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

interface TicketSyncJob {
  id: string;
  orgId: string | null;
  integrationId: string;
  incidentId: string | null;
  externalTicketId: string | null;
  externalTicketUrl: string | null;
  direction: string;
  syncStatus: string;
  lastSyncedAt: string | null;
  lastSyncError: string | null;
  fieldMapping: any;
  statusMapping: any;
  commentsMirrored: number;
  statusSyncs: number;
  createdAt: string;
}

interface ResponseApproval {
  id: string;
  orgId: string | null;
  actionType: string;
  targetType: string | null;
  targetValue: string | null;
  incidentId: string | null;
  requestPayload: any;
  dryRunResult: any;
  status: string;
  requiredApprovers: number;
  currentApprovals: number;
  approvers: any[];
  requestedByName: string | null;
  decidedByName: string | null;
  decisionNote: string | null;
  expiresAt: string | null;
  requestedAt: string;
  decidedAt: string | null;
}

function TicketSyncTab() {
  const [showCreate, setShowCreate] = useState(false);
  const [newIntegrationId, setNewIntegrationId] = useState("");
  const [newIncidentId, setNewIncidentId] = useState("");
  const [newDirection, setNewDirection] = useState("bidirectional");

  const { data: syncJobs, isLoading } = useQuery<TicketSyncJob[]>({
    queryKey: ["/api/ticket-sync"],
  });

  const { data: integrations } = useQuery<IntegrationConfig[]>({
    queryKey: ["/api/integrations"],
  });

  const createMutation = useMutation({
    mutationFn: async () => {
      return apiRequest("POST", "/api/ticket-sync", {
        integrationId: newIntegrationId,
        incidentId: newIncidentId || undefined,
        direction: newDirection,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/ticket-sync"] });
      setShowCreate(false);
      setNewIntegrationId("");
      setNewIncidentId("");
    },
  });

  const syncMutation = useMutation({
    mutationFn: async (id: string) => apiRequest("POST", `/api/ticket-sync/${id}/sync`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["/api/ticket-sync"] }),
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => apiRequest("DELETE", `/api/ticket-sync/${id}`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["/api/ticket-sync"] }),
  });

  const syncStatusBadge = (status: string) => {
    switch (status) {
      case "synced":
        return (
          <Badge variant="default" className="border-green-500/30 text-green-400">
            <CheckCircle className="h-3 w-3 mr-1" />
            Synced
          </Badge>
        );
      case "syncing":
        return (
          <Badge variant="secondary">
            <Loader2 className="h-3 w-3 mr-1 animate-spin" />
            Syncing
          </Badge>
        );
      case "error":
        return (
          <Badge variant="destructive">
            <XCircle className="h-3 w-3 mr-1" />
            Error
          </Badge>
        );
      default:
        return (
          <Badge variant="outline">
            <Clock className="h-3 w-3 mr-1" />
            Pending
          </Badge>
        );
    }
  };

  if (isLoading)
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );

  const jiraSnIntegrations = (integrations || []).filter((i) => i.type === "jira" || i.type === "servicenow");

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <ArrowLeftRight className="h-4 w-4 text-muted-foreground" />
            Bi-Directional Ticket Sync
          </CardTitle>
          <Button size="sm" onClick={() => setShowCreate(true)} disabled={jiraSnIntegrations.length === 0}>
            <Plus className="h-3.5 w-3.5 mr-1.5" />
            New Sync
          </Button>
        </CardHeader>
        <CardContent>
          {jiraSnIntegrations.length === 0 && (
            <div className="text-xs text-muted-foreground mb-3 p-2 bg-muted/30 rounded">
              Add a Jira or ServiceNow integration first to enable ticket sync.
            </div>
          )}
          {!syncJobs?.length ? (
            <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
              <ArrowLeftRight className="h-10 w-10 mb-3" />
              <p className="text-sm">No ticket sync jobs configured</p>
              <p className="text-xs mt-1">
                Create a sync to mirror statuses and comments between SecureNexus and your ticketing system
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto border rounded-md">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="text-xs">Integration</TableHead>
                    <TableHead className="text-xs">Direction</TableHead>
                    <TableHead className="text-xs">External Ticket</TableHead>
                    <TableHead className="text-xs">Status</TableHead>
                    <TableHead className="text-xs">Comments</TableHead>
                    <TableHead className="text-xs">Status Syncs</TableHead>
                    <TableHead className="text-xs">Last Synced</TableHead>
                    <TableHead className="text-xs">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {syncJobs.map((job) => (
                    <TableRow key={job.id}>
                      <TableCell>
                        <span className="text-xs font-mono">{job.integrationId.slice(0, 8)}...</span>
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant="outline"
                          className="no-default-hover-elevate no-default-active-elevate text-[10px]"
                        >
                          {job.direction === "bidirectional"
                            ? "Bi-directional"
                            : job.direction === "outbound"
                              ? "Outbound"
                              : "Inbound"}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        {job.externalTicketUrl ? (
                          <a
                            href={job.externalTicketUrl}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-xs text-blue-400 hover:underline flex items-center gap-1"
                          >
                            <Link2 className="h-3 w-3" />
                            {job.externalTicketId || "View"}
                          </a>
                        ) : (
                          <span className="text-xs text-muted-foreground">{job.externalTicketId || "Not linked"}</span>
                        )}
                      </TableCell>
                      <TableCell>{syncStatusBadge(job.syncStatus)}</TableCell>
                      <TableCell>
                        <span className="text-xs">{job.commentsMirrored}</span>
                      </TableCell>
                      <TableCell>
                        <span className="text-xs">{job.statusSyncs}</span>
                      </TableCell>
                      <TableCell>
                        <span className="text-xs text-muted-foreground">{formatDateTime(job.lastSyncedAt)}</span>
                      </TableCell>
                      <TableCell>
                        <div className="flex gap-1">
                          <Button
                            size="sm"
                            variant="outline"
                            className="h-7 px-2"
                            onClick={() => syncMutation.mutate(job.id)}
                            disabled={syncMutation.isPending}
                          >
                            <RefreshCw className={`h-3 w-3 ${syncMutation.isPending ? "animate-spin" : ""}`} />
                          </Button>
                          <Button
                            size="sm"
                            variant="outline"
                            className="h-7 px-2 text-red-400"
                            onClick={() => deleteMutation.mutate(job.id)}
                          >
                            <Trash2 className="h-3 w-3" />
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

      <Dialog open={showCreate} onOpenChange={setShowCreate}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create Ticket Sync</DialogTitle>
          </DialogHeader>
          <div className="space-y-3">
            <div>
              <Label className="text-xs">Integration</Label>
              <Select value={newIntegrationId} onValueChange={setNewIntegrationId}>
                <SelectTrigger>
                  <SelectValue placeholder="Select integration" />
                </SelectTrigger>
                <SelectContent>
                  {jiraSnIntegrations.map((i) => (
                    <SelectItem key={i.id} value={i.id}>
                      {i.name} ({i.type})
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label className="text-xs">Direction</Label>
              <Select value={newDirection} onValueChange={setNewDirection}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="bidirectional">Bi-directional</SelectItem>
                  <SelectItem value="outbound">Outbound only</SelectItem>
                  <SelectItem value="inbound">Inbound only</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label className="text-xs">Incident ID (optional)</Label>
              <Input
                value={newIncidentId}
                onChange={(e) => setNewIncidentId(e.target.value)}
                placeholder="Link to specific incident"
              />
            </div>
          </div>
          <DialogFooter>
            <DialogClose asChild>
              <Button variant="outline">Cancel</Button>
            </DialogClose>
            <Button onClick={() => createMutation.mutate()} disabled={!newIntegrationId || createMutation.isPending}>
              {createMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : null}
              Create
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function ResponseApprovalsTab() {
  const [statusFilter, setStatusFilter] = useState("pending");
  const [showCreate, setShowCreate] = useState(false);
  const [showDryRun, setShowDryRun] = useState(false);
  const [dryRunResult, setDryRunResult] = useState<any>(null);
  const [newActionType, setNewActionType] = useState("block_ip");
  const [newTargetType, setNewTargetType] = useState("ip");
  const [newTargetValue, setNewTargetValue] = useState("");

  const { data: approvals, isLoading } = useQuery<ResponseApproval[]>({
    queryKey: ["/api/response-approvals", statusFilter],
    queryFn: async () => {
      const res = await fetch(`/api/response-approvals?status=${statusFilter}`, { credentials: "include" });
      if (!res.ok) throw new Error("Failed to fetch");
      return res.json();
    },
  });

  const createMutation = useMutation({
    mutationFn: async () =>
      apiRequest("POST", "/api/response-approvals", {
        actionType: newActionType,
        targetType: newTargetType,
        targetValue: newTargetValue,
        requiredApprovers: 1,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/response-approvals"] });
      setShowCreate(false);
      setNewTargetValue("");
    },
  });

  const decideMutation = useMutation({
    mutationFn: async ({ id, decision, note }: { id: string; decision: string; note?: string }) =>
      apiRequest("POST", `/api/response-approvals/${id}/decide`, { decision, note }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["/api/response-approvals"] }),
  });

  const dryRunMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/response-actions/dry-run", {
        actionType: newActionType,
        target: { targetType: newTargetType, targetValue: newTargetValue },
      });
      return res.json();
    },
    onSuccess: (data) => {
      setDryRunResult(data);
      setShowDryRun(true);
    },
  });

  const approvalStatusBadge = (status: string) => {
    switch (status) {
      case "approved":
        return (
          <Badge variant="default" className="border-green-500/30 text-green-400">
            <ThumbsUp className="h-3 w-3 mr-1" />
            Approved
          </Badge>
        );
      case "rejected":
        return (
          <Badge variant="destructive">
            <ThumbsDown className="h-3 w-3 mr-1" />
            Rejected
          </Badge>
        );
      case "expired":
        return (
          <Badge variant="secondary">
            <Clock className="h-3 w-3 mr-1" />
            Expired
          </Badge>
        );
      default:
        return (
          <Badge
            variant="outline"
            className="no-default-hover-elevate no-default-active-elevate border-yellow-500/30 text-yellow-400"
          >
            <Clock className="h-3 w-3 mr-1" />
            Pending
          </Badge>
        );
    }
  };

  if (isLoading)
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-muted-foreground" />
            Response Action Approvals
          </CardTitle>
          <div className="flex gap-2">
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="w-32 h-8 text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="pending">Pending</SelectItem>
                <SelectItem value="approved">Approved</SelectItem>
                <SelectItem value="rejected">Rejected</SelectItem>
                <SelectItem value="expired">Expired</SelectItem>
              </SelectContent>
            </Select>
            <Button size="sm" onClick={() => setShowCreate(true)}>
              <Plus className="h-3.5 w-3.5 mr-1.5" />
              Request Approval
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {!approvals?.length ? (
            <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
              <ShieldCheck className="h-10 w-10 mb-3" />
              <p className="text-sm">No {statusFilter} approval requests</p>
              <p className="text-xs mt-1">High-impact response actions require approval before execution</p>
            </div>
          ) : (
            <div className="overflow-x-auto border rounded-md">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="text-xs">Action</TableHead>
                    <TableHead className="text-xs">Target</TableHead>
                    <TableHead className="text-xs">Requested By</TableHead>
                    <TableHead className="text-xs">Status</TableHead>
                    <TableHead className="text-xs">Approvals</TableHead>
                    <TableHead className="text-xs">Expires</TableHead>
                    <TableHead className="text-xs">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {approvals.map((a) => (
                    <TableRow key={a.id}>
                      <TableCell>
                        <Badge
                          variant="outline"
                          className="no-default-hover-elevate no-default-active-elevate text-[10px] uppercase"
                        >
                          {a.actionType.replace(/_/g, " ")}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className="text-sm">
                          {a.targetValue || "N/A"}
                          {a.targetType && <span className="text-xs text-muted-foreground ml-1">({a.targetType})</span>}
                        </div>
                      </TableCell>
                      <TableCell>
                        <span className="text-xs">{a.requestedByName || "Unknown"}</span>
                      </TableCell>
                      <TableCell>{approvalStatusBadge(a.status)}</TableCell>
                      <TableCell>
                        <span className="text-xs">
                          {a.currentApprovals}/{a.requiredApprovers}
                        </span>
                      </TableCell>
                      <TableCell>
                        <span className="text-xs text-muted-foreground">
                          {a.expiresAt ? formatDateTime(a.expiresAt) : "Never"}
                        </span>
                      </TableCell>
                      <TableCell>
                        {a.status === "pending" ? (
                          <div className="flex gap-1">
                            {a.dryRunResult && (
                              <Button
                                size="sm"
                                variant="outline"
                                className="h-7 px-2"
                                onClick={() => {
                                  setDryRunResult(a.dryRunResult);
                                  setShowDryRun(true);
                                }}
                              >
                                <Eye className="h-3 w-3" />
                              </Button>
                            )}
                            <Button
                              size="sm"
                              variant="outline"
                              className="h-7 px-2 text-green-400"
                              onClick={() => decideMutation.mutate({ id: a.id, decision: "approved" })}
                            >
                              <ThumbsUp className="h-3 w-3" />
                            </Button>
                            <Button
                              size="sm"
                              variant="outline"
                              className="h-7 px-2 text-red-400"
                              onClick={() => decideMutation.mutate({ id: a.id, decision: "rejected" })}
                            >
                              <ThumbsDown className="h-3 w-3" />
                            </Button>
                          </div>
                        ) : (
                          <span className="text-xs text-muted-foreground">{a.decidedByName || "-"}</span>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      <Dialog open={showCreate} onOpenChange={setShowCreate}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Request Response Action Approval</DialogTitle>
          </DialogHeader>
          <div className="space-y-3">
            <div>
              <Label className="text-xs">Action Type</Label>
              <Select value={newActionType} onValueChange={setNewActionType}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="block_ip">Block IP</SelectItem>
                  <SelectItem value="isolate_endpoint">Isolate Endpoint</SelectItem>
                  <SelectItem value="disable_user">Disable User</SelectItem>
                  <SelectItem value="quarantine_file">Quarantine File</SelectItem>
                  <SelectItem value="create_jira_ticket">Create Jira Ticket</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label className="text-xs">Target Type</Label>
              <Select value={newTargetType} onValueChange={setNewTargetType}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="ip">IP Address</SelectItem>
                  <SelectItem value="hostname">Hostname</SelectItem>
                  <SelectItem value="user">User</SelectItem>
                  <SelectItem value="file">File Hash</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label className="text-xs">Target Value</Label>
              <Input
                value={newTargetValue}
                onChange={(e) => setNewTargetValue(e.target.value)}
                placeholder="e.g. 192.168.1.100"
              />
            </div>
          </div>
          <DialogFooter className="flex-col sm:flex-row gap-2">
            <Button
              variant="outline"
              onClick={() => dryRunMutation.mutate()}
              disabled={!newTargetValue || dryRunMutation.isPending}
            >
              {dryRunMutation.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              ) : (
                <Play className="h-4 w-4 mr-1" />
              )}
              Dry Run
            </Button>
            <Button onClick={() => createMutation.mutate()} disabled={!newTargetValue || createMutation.isPending}>
              {createMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : null}
              Request Approval
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={showDryRun} onOpenChange={setShowDryRun}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Dry Run Simulation Result</DialogTitle>
          </DialogHeader>
          {dryRunResult && (
            <div className="space-y-3 text-sm">
              <div className="grid grid-cols-2 gap-2 text-xs">
                <div className="bg-muted/30 p-2 rounded">
                  <span className="text-muted-foreground">Action:</span>
                  <p className="font-medium">{(dryRunResult.actionType || "").replace(/_/g, " ")}</p>
                </div>
                <div className="bg-muted/30 p-2 rounded">
                  <span className="text-muted-foreground">Reversible:</span>
                  <p className="font-medium">{dryRunResult.reversible ? "Yes" : "No"}</p>
                </div>
                <div className="bg-muted/30 p-2 rounded col-span-2">
                  <span className="text-muted-foreground">Estimated Impact:</span>
                  <p className="font-medium">{dryRunResult.estimatedImpact}</p>
                </div>
                {dryRunResult.affectedResources && (
                  <div className="bg-muted/30 p-2 rounded col-span-2">
                    <span className="text-muted-foreground">Affected Resources:</span>
                    {(dryRunResult.affectedResources as any[]).map((r: any, i: number) => (
                      <p key={i} className="font-medium">
                        {r.type}: {r.value}
                      </p>
                    ))}
                  </div>
                )}
                {dryRunResult.requiresApproval !== undefined && (
                  <div className="bg-muted/30 p-2 rounded">
                    <span className="text-muted-foreground">Requires Approval:</span>
                    <p className="font-medium">{dryRunResult.requiresApproval ? "Yes" : "No"}</p>
                  </div>
                )}
                <div className="bg-muted/30 p-2 rounded">
                  <span className="text-muted-foreground">Duration:</span>
                  <p className="font-medium">{dryRunResult.estimatedDuration || "N/A"}</p>
                </div>
              </div>
            </div>
          )}
          <DialogFooter>
            <DialogClose asChild>
              <Button variant="outline">Close</Button>
            </DialogClose>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

const SEVERITY_OPTIONS = [
  { value: "info", label: "Info", color: "border-blue-500/30 text-blue-400" },
  { value: "warning", label: "Warning", color: "border-yellow-500/30 text-yellow-400" },
  { value: "critical", label: "Critical", color: "border-red-500/30 text-red-400" },
] as const;

const PREFERENCE_EVENT_OPTIONS = [
  { value: "incident_created", label: "Incident Created" },
  { value: "incident_escalated", label: "Incident Escalated" },
  { value: "incident_closed", label: "Incident Closed" },
  { value: "alert_created", label: "Alert Created" },
  { value: "alert_critical", label: "Alert Critical" },
  { value: "playbook_completed", label: "Playbook Completed" },
  { value: "compliance_violation", label: "Compliance Violation" },
] as const;

const QUIET_HOURS = Array.from({ length: 24 }, (_, i) => ({
  value: i,
  label: `${i.toString().padStart(2, "0")}:00`,
}));

function NotificationPreferencesTab() {
  const { toast } = useToast();

  const { data: preferences, isLoading: prefsLoading } = useQuery<NotificationUserPreferences | null>({
    queryKey: ["/api/notification-preferences"],
  });

  const { data: channels } = useQuery<NotificationChannel[]>({
    queryKey: ["/api/notification-channels"],
  });

  const [selectedChannelIds, setSelectedChannelIds] = useState<string[]>([]);
  const [selectedEventTypes, setSelectedEventTypes] = useState<string[]>(["incident_created"]);
  const [minSeverity, setMinSeverity] = useState<string>("info");
  const [quietStart, setQuietStart] = useState<number | null>(null);
  const [quietEnd, setQuietEnd] = useState<number | null>(null);
  const [digestEnabled, setDigestEnabled] = useState(false);
  const [digestFrequency, setDigestFrequency] = useState(24);
  const [initialized, setInitialized] = useState(false);

  useEffect(() => {
    if (preferences && !initialized) {
      setSelectedChannelIds(preferences.channelIds ?? []);
      setSelectedEventTypes(preferences.eventTypes ?? ["incident_created"]);
      setMinSeverity(preferences.minSeverity ?? "info");
      setQuietStart(preferences.quietHoursStart ?? null);
      setQuietEnd(preferences.quietHoursEnd ?? null);
      setDigestEnabled(preferences.digestEnabled ?? false);
      setDigestFrequency(preferences.digestFrequencyHours ?? 24);
      setInitialized(true);
    }
  }, [preferences, initialized]);

  const saveMutation = useMutation({
    mutationFn: async () => {
      await apiRequest("PUT", "/api/notification-preferences", {
        channelIds: selectedChannelIds,
        eventTypes: selectedEventTypes,
        minSeverity,
        quietHoursStart: quietStart,
        quietHoursEnd: quietEnd,
        digestEnabled,
        digestFrequencyHours: digestFrequency,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/notification-preferences"] });
      toast({ title: "Preferences saved", description: "Notification preferences updated successfully." });
    },
    onError: (err: Error) => {
      toast({ title: "Failed to save preferences", description: err.message, variant: "destructive" });
    },
  });

  function toggleChannel(channelId: string) {
    setSelectedChannelIds((prev) =>
      prev.includes(channelId) ? prev.filter((id) => id !== channelId) : [...prev, channelId],
    );
  }

  function toggleEventType(event: string) {
    setSelectedEventTypes((prev) => (prev.includes(event) ? prev.filter((e) => e !== event) : [...prev, event]));
  }

  if (prefsLoading) {
    return (
      <div className="space-y-4" role="status" aria-label="Loading preferences">
        <Card>
          <CardContent className="py-6 space-y-4">
            {Array.from({ length: 4 }).map((_, i) => (
              <div key={i} className="flex items-center gap-4">
                <Skeleton className="h-4 w-32" />
                <Skeleton className="h-8 w-48" />
              </div>
            ))}
          </CardContent>
        </Card>
        <span className="sr-only">Loading notification preferences...</span>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2 flex-wrap">
            <Settings2 className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
            My Notification Preferences
          </CardTitle>
          <Button
            size="sm"
            onClick={() => saveMutation.mutate()}
            disabled={saveMutation.isPending}
            data-testid="button-save-preferences"
          >
            {saveMutation.isPending ? (
              <Loader2 className="h-4 w-4 mr-1.5 animate-spin" />
            ) : (
              <Save className="h-4 w-4 mr-1.5" />
            )}
            Save Preferences
          </Button>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="space-y-3">
            <Label className="text-sm font-medium">Preferred Channels</Label>
            <p className="text-xs text-muted-foreground">Select which channels you want to receive notifications on</p>
            {!channels?.length ? (
              <div className="p-3 rounded-md bg-muted/30 text-center">
                <p className="text-xs text-muted-foreground">
                  No channels configured yet. Add channels in the Notification Channels tab first.
                </p>
              </div>
            ) : (
              <div className="flex flex-wrap gap-2">
                {channels.map((ch) => (
                  <Badge
                    key={ch.id}
                    variant="outline"
                    className={`cursor-pointer toggle-elevate ${
                      selectedChannelIds.includes(ch.id) ? "toggle-elevated border-cyan-500/40 text-cyan-400" : ""
                    }`}
                    onClick={() => toggleChannel(ch.id)}
                    data-testid={`badge-pref-channel-${ch.id}`}
                  >
                    {selectedChannelIds.includes(ch.id) && <CheckCircle className="h-3 w-3 mr-1" />}
                    {ch.name}
                    <span className="ml-1 text-[9px] opacity-60">({ch.type})</span>
                  </Badge>
                ))}
              </div>
            )}
          </div>

          <div className="space-y-3">
            <Label className="text-sm font-medium">Event Types</Label>
            <p className="text-xs text-muted-foreground">Choose which events trigger notifications for you</p>
            <div className="flex flex-wrap gap-2">
              {PREFERENCE_EVENT_OPTIONS.map((ev) => (
                <Badge
                  key={ev.value}
                  variant="outline"
                  className={`cursor-pointer toggle-elevate ${
                    selectedEventTypes.includes(ev.value) ? "toggle-elevated border-cyan-500/40 text-cyan-400" : ""
                  }`}
                  onClick={() => toggleEventType(ev.value)}
                  data-testid={`badge-pref-event-${ev.value}`}
                >
                  {selectedEventTypes.includes(ev.value) && <CheckCircle className="h-3 w-3 mr-1" />}
                  {ev.label}
                </Badge>
              ))}
            </div>
          </div>

          <div className="space-y-3">
            <Label className="text-sm font-medium">Minimum Severity</Label>
            <p className="text-xs text-muted-foreground">Only receive notifications at or above this severity level</p>
            <div className="flex flex-wrap gap-2">
              {SEVERITY_OPTIONS.map((sev) => (
                <Badge
                  key={sev.value}
                  variant="outline"
                  className={`cursor-pointer toggle-elevate ${
                    minSeverity === sev.value ? `toggle-elevated ${sev.color}` : ""
                  }`}
                  onClick={() => setMinSeverity(sev.value)}
                  data-testid={`badge-pref-severity-${sev.value}`}
                >
                  {minSeverity === sev.value && <CheckCircle className="h-3 w-3 mr-1" />}
                  {sev.label}
                </Badge>
              ))}
            </div>
          </div>

          <div className="space-y-3">
            <Label className="text-sm font-medium flex items-center gap-2">
              <Moon className="h-4 w-4" aria-hidden="true" />
              Quiet Hours
            </Label>
            <p className="text-xs text-muted-foreground">Suppress notifications during these hours (UTC)</p>
            <div className="flex items-center gap-3 flex-wrap">
              <div className="flex items-center gap-2">
                <Label className="text-xs text-muted-foreground whitespace-nowrap">From</Label>
                <Select
                  value={quietStart !== null ? String(quietStart) : "none"}
                  onValueChange={(val) => setQuietStart(val === "none" ? null : Number(val))}
                >
                  <SelectTrigger className="w-[100px]" data-testid="select-quiet-start">
                    <SelectValue placeholder="Off" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="none">Off</SelectItem>
                    {QUIET_HOURS.map((h) => (
                      <SelectItem key={h.value} value={String(h.value)}>
                        {h.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="flex items-center gap-2">
                <Label className="text-xs text-muted-foreground whitespace-nowrap">To</Label>
                <Select
                  value={quietEnd !== null ? String(quietEnd) : "none"}
                  onValueChange={(val) => setQuietEnd(val === "none" ? null : Number(val))}
                >
                  <SelectTrigger className="w-[100px]" data-testid="select-quiet-end">
                    <SelectValue placeholder="Off" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="none">Off</SelectItem>
                    {QUIET_HOURS.map((h) => (
                      <SelectItem key={h.value} value={String(h.value)}>
                        {h.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
          </div>

          <div className="space-y-3">
            <div className="flex items-center justify-between gap-2 p-3 rounded-md bg-muted/30">
              <div className="flex items-center gap-2">
                <Mail className="h-4 w-4 text-muted-foreground flex-shrink-0" aria-hidden="true" />
                <div>
                  <div className="text-sm font-medium">Digest Mode</div>
                  <div className="text-xs text-muted-foreground">
                    Bundle notifications into periodic summaries instead of real-time delivery
                  </div>
                </div>
              </div>
              <Switch checked={digestEnabled} onCheckedChange={setDigestEnabled} data-testid="switch-digest" />
            </div>
            {digestEnabled && (
              <div className="flex items-center gap-3 pl-3">
                <Label className="text-xs text-muted-foreground whitespace-nowrap">Every</Label>
                <Select value={String(digestFrequency)} onValueChange={(val) => setDigestFrequency(Number(val))}>
                  <SelectTrigger className="w-[120px]" data-testid="select-digest-frequency">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="1">1 hour</SelectItem>
                    <SelectItem value="4">4 hours</SelectItem>
                    <SelectItem value="8">8 hours</SelectItem>
                    <SelectItem value="12">12 hours</SelectItem>
                    <SelectItem value="24">24 hours</SelectItem>
                    <SelectItem value="48">48 hours</SelectItem>
                    <SelectItem value="168">Weekly</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function DeliveryLogTab() {
  const [page, setPage] = useState(0);
  const [channelFilter, setChannelFilter] = useState<string>("");
  const pageSize = 25;

  const { data: channels } = useQuery<NotificationChannel[]>({
    queryKey: ["/api/notification-channels"],
  });

  const {
    data: logData,
    isLoading,
    isError,
    refetch,
  } = useQuery<{ items: NotificationDeliveryLog[]; total: number }>({
    queryKey: ["/api/notification-delivery-log", channelFilter, page],
    queryFn: async () => {
      const params = new URLSearchParams();
      if (channelFilter) params.set("channelId", channelFilter);
      params.set("offset", String(page * pageSize));
      params.set("limit", String(pageSize));
      const res = await apiRequest("GET", `/api/notification-delivery-log?${params.toString()}`);
      if (!res.ok) throw new Error("Failed to fetch delivery log");
      return res.json();
    },
  });

  const totalPages = logData ? Math.ceil(logData.total / pageSize) : 0;

  if (isLoading) {
    return (
      <div className="space-y-3 py-6" role="status" aria-label="Loading delivery log">
        {Array.from({ length: 6 }).map((_, i) => (
          <div key={i} className="flex items-center gap-4 px-4 py-3 border-b last:border-0">
            <Skeleton className="h-4 w-24" />
            <Skeleton className="h-5 w-16 rounded-full" />
            <Skeleton className="h-4 w-40" />
            <Skeleton className="h-5 w-16 rounded-full" />
            <Skeleton className="h-4 w-28" />
          </div>
        ))}
        <span className="sr-only">Loading delivery log...</span>
      </div>
    );
  }

  if (isError) {
    return (
      <Card>
        <CardContent className="flex flex-col items-center justify-center py-12 text-muted-foreground">
          <AlertTriangle className="h-10 w-10 mb-3 text-destructive" aria-hidden="true" />
          <p className="text-sm font-medium">Failed to load delivery log</p>
          <Button variant="outline" size="sm" className="mt-3" onClick={() => refetch()}>
            <RefreshCw className="h-3.5 w-3.5 mr-1.5" />
            Retry
          </Button>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2 flex-wrap">
            <ScrollText className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
            Delivery Log
          </CardTitle>
          <div className="flex items-center gap-2">
            <Select
              value={channelFilter || "all"}
              onValueChange={(val) => {
                setChannelFilter(val === "all" ? "" : val);
                setPage(0);
              }}
            >
              <SelectTrigger className="w-[180px] h-8 text-xs" data-testid="select-log-channel-filter">
                <SelectValue placeholder="All channels" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All channels</SelectItem>
                {channels?.map((ch) => (
                  <SelectItem key={ch.id} value={ch.id}>
                    {ch.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </CardHeader>
        <CardContent>
          {!logData?.items.length ? (
            <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
              <ScrollText className="h-10 w-10 mb-3" aria-hidden="true" />
              <p className="text-sm">No delivery log entries yet</p>
              <p className="text-xs mt-1">Notification dispatches will appear here once channels are active</p>
            </div>
          ) : (
            <>
              <div className="overflow-x-auto border rounded-md">
                <Table data-testid="table-delivery-log">
                  <TableHeader>
                    <TableRow>
                      <TableHead className="text-xs">Channel</TableHead>
                      <TableHead className="text-xs">Type</TableHead>
                      <TableHead className="text-xs">Event</TableHead>
                      <TableHead className="text-xs">Title</TableHead>
                      <TableHead className="text-xs">Severity</TableHead>
                      <TableHead className="text-xs">Status</TableHead>
                      <TableHead className="text-xs">Delivered</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {logData.items.map((entry) => (
                      <TableRow key={entry.id} data-testid={`row-log-${entry.id}`}>
                        <TableCell>
                          <span className="text-sm font-medium">{entry.channelName}</span>
                        </TableCell>
                        <TableCell>{typeBadge(entry.channelType)}</TableCell>
                        <TableCell>
                          <Badge
                            variant="outline"
                            className="no-default-hover-elevate no-default-active-elevate text-[10px]"
                          >
                            {entry.eventType.replace(/_/g, " ")}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <span className="text-sm max-w-[200px] truncate block" title={entry.title}>
                            {entry.title}
                          </span>
                        </TableCell>
                        <TableCell>
                          <Badge
                            variant="outline"
                            className={`no-default-hover-elevate no-default-active-elevate text-[10px] uppercase ${
                              entry.severity === "critical"
                                ? "border-red-500/30 text-red-400"
                                : entry.severity === "warning"
                                  ? "border-yellow-500/30 text-yellow-400"
                                  : "border-blue-500/30 text-blue-400"
                            }`}
                          >
                            {entry.severity}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          {entry.success ? (
                            <Badge variant="default" className="border-green-500/30 text-green-400">
                              <CheckCircle className="h-3 w-3 mr-1" />
                              Delivered
                            </Badge>
                          ) : (
                            <Badge variant="destructive" title={entry.errorMessage ?? undefined}>
                              <XCircle className="h-3 w-3 mr-1" />
                              Failed
                            </Badge>
                          )}
                        </TableCell>
                        <TableCell>
                          <span className="text-xs text-muted-foreground">{formatDateTime(entry.deliveredAt)}</span>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
              {totalPages > 1 && (
                <div className="flex items-center justify-between pt-3">
                  <span className="text-xs text-muted-foreground">
                    Showing {page * pageSize + 1}–{Math.min((page + 1) * pageSize, logData.total)} of {logData.total}
                  </span>
                  <div className="flex items-center gap-1">
                    <Button
                      size="icon"
                      variant="outline"
                      disabled={page === 0}
                      onClick={() => setPage((p) => Math.max(0, p - 1))}
                      aria-label="Previous page"
                      data-testid="button-log-prev"
                    >
                      <ChevronLeft className="h-4 w-4" />
                    </Button>
                    <span className="text-xs px-2">
                      Page {page + 1} of {totalPages}
                    </span>
                    <Button
                      size="icon"
                      variant="outline"
                      disabled={page >= totalPages - 1}
                      onClick={() => setPage((p) => p + 1)}
                      aria-label="Next page"
                      data-testid="button-log-next"
                    >
                      <ChevronRight className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
              )}
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

export default function IntegrationsPage() {
  return (
    <div
      className="p-4 md:p-6 space-y-6 max-w-7xl mx-auto"
      aria-label="Integrations & Response"
      data-testid="page-integrations"
    >
      <div>
        <h1 className="text-2xl font-bold tracking-tight" data-testid="text-page-title">
          <span className="gradient-text-red">Integrations & Response</span>
        </h1>
        <p className="text-sm text-muted-foreground mt-1" data-testid="text-page-description">
          Configure integrations, ticket sync, notification channels, response actions, and approvals
        </p>
        <div className="gradient-accent-line w-24 mt-2" />
      </div>

      <Tabs defaultValue="integrations" data-testid="tabs-integrations">
        <TabsList className="flex-wrap" data-testid="tabs-list">
          <TabsTrigger value="integrations" data-testid="tab-integrations">
            <Plug className="h-3.5 w-3.5 mr-1.5" aria-hidden="true" />
            Integrations
          </TabsTrigger>
          <TabsTrigger value="ticket-sync" data-testid="tab-ticket-sync">
            <ArrowLeftRight className="h-3.5 w-3.5 mr-1.5" aria-hidden="true" />
            Ticket Sync
          </TabsTrigger>
          <TabsTrigger value="channels" data-testid="tab-channels">
            <Bell className="h-3.5 w-3.5 mr-1.5" aria-hidden="true" />
            Notification Channels
          </TabsTrigger>
          <TabsTrigger value="response-actions" data-testid="tab-response-actions">
            <Zap className="h-3.5 w-3.5 mr-1.5" aria-hidden="true" />
            Response Actions
          </TabsTrigger>
          <TabsTrigger value="approvals" data-testid="tab-approvals">
            <ShieldCheck className="h-3.5 w-3.5 mr-1.5" aria-hidden="true" />
            Approvals
          </TabsTrigger>
          <TabsTrigger value="preferences" data-testid="tab-preferences">
            <Settings2 className="h-3.5 w-3.5 mr-1.5" aria-hidden="true" />
            My Preferences
          </TabsTrigger>
          <TabsTrigger value="delivery-log" data-testid="tab-delivery-log">
            <ScrollText className="h-3.5 w-3.5 mr-1.5" aria-hidden="true" />
            Delivery Log
          </TabsTrigger>
        </TabsList>

        <TabsContent value="integrations">
          <IntegrationsTab />
        </TabsContent>
        <TabsContent value="ticket-sync">
          <TicketSyncTab />
        </TabsContent>
        <TabsContent value="channels">
          <NotificationChannelsTab />
        </TabsContent>
        <TabsContent value="response-actions">
          <ResponseActionsTab />
        </TabsContent>
        <TabsContent value="approvals">
          <ResponseApprovalsTab />
        </TabsContent>
        <TabsContent value="preferences">
          <NotificationPreferencesTab />
        </TabsContent>
        <TabsContent value="delivery-log">
          <DeliveryLogTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}

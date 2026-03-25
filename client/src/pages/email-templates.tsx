import { useState, useEffect } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { usePageTitle } from "@/hooks/use-page-title";
import {
  Mail,
  Eye,
  Send,
  Copy,
  CheckCircle2,
  XCircle,
  Loader2,
  FileText,
  Code2,
  Users,
  CreditCard,
  Shield,
  RefreshCw,
  AlertTriangle,
  ChevronRight,
  Smartphone,
  Monitor,
  Info,
} from "lucide-react";
import { SuccessIcon, EyeToggleIcon } from "@/components/ui/animated-state-icons";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";

interface TemplateVariable {
  name: string;
  description: string;
  required: boolean;
}

interface TemplateDescriptor {
  id: string;
  name: string;
  description: string;
  category: "auth" | "billing" | "team" | "lifecycle";
  variables: TemplateVariable[];
}

interface TemplatePreview {
  subject: string;
  html: string;
  text: string;
}

interface EmailStatus {
  emailEnabled: boolean;
  fromAddress: string;
  templateCount: number;
  categories: string[];
}

const CATEGORY_META: Record<string, { label: string; icon: typeof Mail; color: string }> = {
  auth: { label: "Authentication", icon: Shield, color: "text-emerald-400" },
  billing: { label: "Billing", icon: CreditCard, color: "text-amber-400" },
  team: { label: "Team", icon: Users, color: "text-blue-400" },
  lifecycle: { label: "Lifecycle", icon: RefreshCw, color: "text-violet-400" },
};

function categoryBadge(category: string) {
  const meta = CATEGORY_META[category];
  if (!meta)
    return (
      <Badge variant="outline" className="text-[10px]">
        {category}
      </Badge>
    );
  const Icon = meta.icon;
  return (
    <Badge variant="outline" className={`text-[10px] ${meta.color} border-current/30`}>
      <Icon className="h-3 w-3 mr-1" />
      {meta.label}
    </Badge>
  );
}

function TemplateCard({
  template,
  isSelected,
  onSelect,
}: {
  template: TemplateDescriptor;
  isSelected: boolean;
  onSelect: () => void;
}) {
  return (
    <button
      onClick={onSelect}
      className={`w-full text-left p-3 rounded-lg border transition-all duration-150 ${
        isSelected
          ? "border-cyan-500/50 bg-cyan-500/5 shadow-sm"
          : "border-border/50 hover:border-border hover:bg-muted/30"
      }`}
      aria-pressed={isSelected}
      data-testid={`template-card-${template.id}`}
    >
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0">
          <Mail className={`h-4 w-4 shrink-0 ${isSelected ? "text-cyan-400" : "text-muted-foreground"}`} />
          <span className="text-sm font-medium truncate">{template.name}</span>
        </div>
        <ChevronRight
          className={`h-3.5 w-3.5 shrink-0 transition-colors ${isSelected ? "text-cyan-400" : "text-muted-foreground/50"}`}
        />
      </div>
      <p className="text-[11px] text-muted-foreground mt-1 line-clamp-2 pl-6">{template.description}</p>
      <div className="mt-2 pl-6">{categoryBadge(template.category)}</div>
    </button>
  );
}

function VariableEditor({
  variables,
  values,
  onChange,
}: {
  variables: TemplateVariable[];
  values: Record<string, string>;
  onChange: (key: string, value: string) => void;
}) {
  return (
    <div className="space-y-3">
      {variables.map((v) => (
        <div key={v.name} className="space-y-1">
          <div className="flex items-center gap-1.5">
            <Label className="text-xs font-medium">
              {v.name}
              {v.required && <span className="text-red-400 ml-0.5">*</span>}
            </Label>
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Info className="h-3 w-3 text-muted-foreground cursor-help" />
                </TooltipTrigger>
                <TooltipContent side="right" className="max-w-xs text-xs">
                  {v.description}
                </TooltipContent>
              </Tooltip>
            </TooltipProvider>
          </div>
          <Input
            value={values[v.name] ?? ""}
            onChange={(e) => onChange(v.name, e.target.value)}
            placeholder={v.description}
            className="h-8 text-xs"
            data-testid={`var-input-${v.name}`}
          />
        </div>
      ))}
    </div>
  );
}

function PreviewFrame({ html, viewMode }: { html: string; viewMode: "desktop" | "mobile" }) {
  return (
    <div
      className={`mx-auto border rounded-lg overflow-hidden bg-background transition-all duration-300 ${
        viewMode === "mobile" ? "max-w-[375px]" : "max-w-full"
      }`}
      data-testid="preview-frame"
    >
      <iframe
        srcDoc={html}
        title="Email preview"
        className="w-full border-0"
        style={{ height: viewMode === "mobile" ? "600px" : "500px" }}
        sandbox="allow-same-origin"
      />
    </div>
  );
}

function TemplateEditor({
  template,
  sampleData,
}: {
  template: TemplateDescriptor;
  sampleData: Record<string, string>;
}) {
  const { toast } = useToast();
  const [variables, setVariables] = useState<Record<string, string>>({});
  const [preview, setPreview] = useState<TemplatePreview | null>(null);
  const [viewMode, setViewMode] = useState<"desktop" | "mobile">("desktop");
  const [activeTab, setActiveTab] = useState("preview");
  const [testEmail, setTestEmail] = useState("");
  const [copiedSubject, setCopiedSubject] = useState(false);

  useEffect(() => {
    const initial: Record<string, string> = {};
    for (const v of template.variables) {
      initial[v.name] = sampleData[v.name] ?? "";
    }
    setVariables(initial);
    setPreview(null);
  }, [template.id]);

  const previewMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", `/api/email-templates/${template.id}/preview`, { variables });
      if (!res.ok) throw new Error("Preview failed");
      const json = await res.json();
      return (json.data ?? json) as TemplatePreview;
    },
    onSuccess: (data) => {
      setPreview(data);
      setActiveTab("preview");
    },
    onError: (err: Error) => {
      toast({ title: "Preview failed", description: err.message, variant: "destructive" });
    },
  });

  const testSendMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", `/api/email-templates/${template.id}/test-send`, {
        recipientEmail: testEmail,
        variables,
      });
      if (!res.ok) {
        const errData = await res.json().catch(() => null);
        const msg = errData?.errors?.[0]?.message ?? "Send failed";
        throw new Error(msg);
      }
      const json = await res.json();
      return json.data ?? json;
    },
    onSuccess: (data: { sent: boolean; simulated: boolean; message: string }) => {
      if (data.simulated) {
        toast({ title: "Simulated", description: data.message });
      } else {
        toast({ title: "Test email sent", description: data.message });
      }
    },
    onError: (err: Error) => {
      toast({ title: "Send failed", description: err.message, variant: "destructive" });
    },
  });

  const handleVariableChange = (key: string, value: string) => {
    setVariables((prev) => ({ ...prev, [key]: value }));
  };

  const handleCopySubject = () => {
    if (preview?.subject) {
      navigator.clipboard.writeText(preview.subject);
      setCopiedSubject(true);
      setTimeout(() => setCopiedSubject(false), 2000);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h2 className="text-lg font-semibold flex items-center gap-2">
            <Mail className="h-5 w-5 text-cyan-400" />
            {template.name}
          </h2>
          <p className="text-xs text-muted-foreground mt-0.5">{template.description}</p>
        </div>
        {categoryBadge(template.category)}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Card className="lg:col-span-1">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm flex items-center gap-2">
              <FileText className="h-4 w-4 text-muted-foreground" />
              Template Variables
            </CardTitle>
            <CardDescription className="text-xs">Edit variables to customize the preview</CardDescription>
          </CardHeader>
          <CardContent>
            <ScrollArea className="h-[380px] pr-3">
              <VariableEditor variables={template.variables} values={variables} onChange={handleVariableChange} />
            </ScrollArea>
            <div className="flex gap-2 mt-3 pt-3 border-t">
              <Button
                size="sm"
                onClick={() => previewMutation.mutate()}
                disabled={previewMutation.isPending}
                className="flex-1"
                data-testid="button-preview"
              >
                {previewMutation.isPending ? (
                  <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />
                ) : (
                  <Eye className="h-3.5 w-3.5 mr-1.5" />
                )}
                Preview
              </Button>
            </div>
          </CardContent>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between flex-wrap gap-2">
              <CardTitle className="text-sm flex items-center gap-2">
                <Eye className="h-4 w-4 text-muted-foreground" />
                Preview
              </CardTitle>
              <div className="flex items-center gap-1">
                <Button
                  size="icon"
                  variant={viewMode === "desktop" ? "default" : "ghost"}
                  className="h-7 w-7"
                  onClick={() => setViewMode("desktop")}
                  aria-label="Desktop view"
                >
                  <Monitor className="h-3.5 w-3.5" />
                </Button>
                <Button
                  size="icon"
                  variant={viewMode === "mobile" ? "default" : "ghost"}
                  className="h-7 w-7"
                  onClick={() => setViewMode("mobile")}
                  aria-label="Mobile view"
                >
                  <Smartphone className="h-3.5 w-3.5" />
                </Button>
              </div>
            </div>
          </CardHeader>
          <CardContent>
            {!preview ? (
              <div className="flex flex-col items-center justify-center py-16 text-muted-foreground">
                <Eye className="h-10 w-10 mb-3 opacity-30" />
                <p className="text-sm">Click Preview to render this template</p>
                <p className="text-xs mt-1">Edit variables on the left, then preview the result</p>
              </div>
            ) : (
              <Tabs value={activeTab} onValueChange={setActiveTab}>
                <TabsList className="mb-3">
                  <TabsTrigger value="preview" className="text-xs">
                    <Eye className="h-3 w-3 mr-1" /> HTML
                  </TabsTrigger>
                  <TabsTrigger value="text" className="text-xs">
                    <FileText className="h-3 w-3 mr-1" /> Plain Text
                  </TabsTrigger>
                  <TabsTrigger value="source" className="text-xs">
                    <Code2 className="h-3 w-3 mr-1" /> Source
                  </TabsTrigger>
                </TabsList>

                {preview.subject && (
                  <div className="flex items-center gap-2 mb-3 p-2 rounded-md bg-muted/30 border">
                    <span className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider shrink-0">
                      Subject:
                    </span>
                    <span className="text-xs font-medium truncate flex-1">{preview.subject}</span>
                    <Button size="icon" variant="ghost" className="h-6 w-6 shrink-0" onClick={handleCopySubject}>
                      {copiedSubject ? <SuccessIcon size={12} color="#22c55e" /> : <Copy className="h-3 w-3" />}
                    </Button>
                  </div>
                )}

                <TabsContent value="preview" className="mt-0">
                  <PreviewFrame html={preview.html} viewMode={viewMode} />
                </TabsContent>
                <TabsContent value="text" className="mt-0">
                  <div className="border rounded-lg p-4 bg-muted/20 font-mono text-xs whitespace-pre-wrap max-h-[500px] overflow-auto">
                    {preview.text}
                  </div>
                </TabsContent>
                <TabsContent value="source" className="mt-0">
                  <div className="border rounded-lg p-4 bg-muted/20 font-mono text-[11px] whitespace-pre-wrap max-h-[500px] overflow-auto">
                    {preview.html}
                  </div>
                </TabsContent>
              </Tabs>
            )}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm flex items-center gap-2">
            <Send className="h-4 w-4 text-muted-foreground" />
            Send Test Email
          </CardTitle>
          <CardDescription className="text-xs">Send a test email using the current variable values</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-end gap-3 flex-wrap">
            <div className="flex-1 min-w-[250px] space-y-1">
              <Label className="text-xs">Recipient Email</Label>
              <Input
                type="email"
                value={testEmail}
                onChange={(e) => setTestEmail(e.target.value)}
                placeholder="test@example.com"
                className="h-8 text-xs"
                data-testid="input-test-email"
              />
            </div>
            <Button
              size="sm"
              onClick={() => testSendMutation.mutate()}
              disabled={!testEmail || testSendMutation.isPending}
              data-testid="button-send-test"
            >
              {testSendMutation.isPending ? (
                <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />
              ) : (
                <Send className="h-3.5 w-3.5 mr-1.5" />
              )}
              Send Test
            </Button>
          </div>
          {testSendMutation.isSuccess && (
            <div className="mt-2 flex items-center gap-2 text-xs text-green-400">
              <CheckCircle2 className="h-3.5 w-3.5" />
              {(testSendMutation.data as { message?: string })?.message ?? "Test email processed"}
            </div>
          )}
          {testSendMutation.isError && (
            <div className="mt-2 flex items-center gap-2 text-xs text-red-400">
              <XCircle className="h-3.5 w-3.5" />
              {testSendMutation.error.message}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

export default function EmailTemplatesPage() {
  usePageTitle("Email Templates");

  const {
    data: templates,
    isLoading,
    isError,
    refetch,
  } = useQuery<TemplateDescriptor[]>({
    queryKey: ["/api/email-templates"],
  });

  const { data: emailStatus } = useQuery<EmailStatus>({
    queryKey: ["/api/email-templates/status"],
  });

  const [selectedId, setSelectedId] = useState<string | null>(null);

  const selectedTemplate = templates?.find((t) => t.id === selectedId) ?? null;

  const { data: templateDetail } = useQuery<{
    template: TemplateDescriptor;
    sampleData: Record<string, string>;
  }>({
    queryKey: [`/api/email-templates/${selectedId}`],
    enabled: !!selectedId,
  });

  useEffect(() => {
    if (templates?.length && !selectedId) {
      setSelectedId(templates[0].id);
    }
  }, [templates]);

  if (isLoading) {
    return (
      <div className="p-4 md:p-6 space-y-6 max-w-7xl mx-auto" role="status" aria-label="Loading email templates">
        <div className="space-y-2">
          <Skeleton className="h-8 w-64" />
          <Skeleton className="h-4 w-96" />
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
          <div className="space-y-3">
            {Array.from({ length: 6 }).map((_, i) => (
              <Skeleton key={i} className="h-20 w-full rounded-lg" />
            ))}
          </div>
          <div className="lg:col-span-3">
            <Skeleton className="h-[600px] w-full rounded-lg" />
          </div>
        </div>
      </div>
    );
  }

  if (isError) {
    return (
      <div className="p-4 md:p-6 max-w-7xl mx-auto">
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-16 text-muted-foreground">
            <AlertTriangle className="h-10 w-10 mb-3 text-destructive" />
            <p className="text-sm font-medium">Failed to load email templates</p>
            <Button variant="outline" size="sm" className="mt-3" onClick={() => refetch()}>
              <RefreshCw className="h-3.5 w-3.5 mr-1.5" />
              Retry
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  const grouped =
    templates?.reduce(
      (acc, t) => {
        const cat = t.category;
        if (!acc[cat]) acc[cat] = [];
        acc[cat].push(t);
        return acc;
      },
      {} as Record<string, TemplateDescriptor[]>,
    ) ?? {};

  const categoryOrder = ["auth", "billing", "team", "lifecycle"];

  return (
    <div
      className="p-4 md:p-6 space-y-6 max-w-7xl mx-auto"
      aria-label="Email Templates & Delivery"
      data-testid="page-email-templates"
    >
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-bold tracking-tight" data-testid="text-page-title">
            <span className="gradient-text-red">Email Templates</span>
          </h1>
          <p className="text-sm text-muted-foreground mt-1" data-testid="text-page-description">
            Preview, test, and manage email templates for transactional notifications
          </p>
          <div className="gradient-accent-line w-24 mt-2" />
        </div>
        <div className="flex items-center gap-3">
          {emailStatus && (
            <>
              <Badge variant={emailStatus.emailEnabled ? "default" : "secondary"} className="text-[10px]">
                {emailStatus.emailEnabled ? (
                  <>
                    <SuccessIcon size={12} color="#22c55e" />
                    SES Active
                  </>
                ) : (
                  <>
                    <XCircle className="h-3 w-3 mr-1" />
                    SES Disabled
                  </>
                )}
              </Badge>
              <Badge variant="outline" className="text-[10px]">
                <Mail className="h-3 w-3 mr-1" />
                {emailStatus.templateCount} templates
              </Badge>
            </>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        <div className="lg:col-span-1">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">Templates</CardTitle>
            </CardHeader>
            <CardContent className="p-2">
              <ScrollArea className="h-[calc(100vh-280px)] min-h-[400px]">
                <div className="space-y-4 p-1">
                  {categoryOrder.map((cat) => {
                    const items = grouped[cat];
                    if (!items?.length) return null;
                    const meta = CATEGORY_META[cat];
                    return (
                      <div key={cat}>
                        <div className="flex items-center gap-1.5 mb-2 px-1">
                          {meta && <meta.icon className={`h-3 w-3 ${meta.color}`} />}
                          <span className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                            {meta?.label ?? cat}
                          </span>
                        </div>
                        <div className="space-y-1.5">
                          {items.map((t) => (
                            <TemplateCard
                              key={t.id}
                              template={t}
                              isSelected={selectedId === t.id}
                              onSelect={() => setSelectedId(t.id)}
                            />
                          ))}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </div>

        <div className="lg:col-span-3">
          {selectedTemplate && templateDetail ? (
            <TemplateEditor template={selectedTemplate} sampleData={templateDetail.sampleData ?? {}} />
          ) : selectedTemplate ? (
            <div className="flex items-center justify-center py-20" role="status">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : (
            <Card>
              <CardContent className="flex flex-col items-center justify-center py-20 text-muted-foreground">
                <Mail className="h-10 w-10 mb-3 opacity-30" />
                <p className="text-sm">Select a template from the list to get started</p>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}

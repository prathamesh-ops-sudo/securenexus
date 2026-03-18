import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { usePageTitle } from "@/hooks/use-page-title";
import {
  BookOpen,
  Clock,
  Hash,
  Tag,
  ChevronDown,
  ChevronRight,
  AlertTriangle,
  CheckCircle2,
  History,
  Loader2,
  Search,
  Filter,
  Thermometer,
  Layers,
  Zap,
  FileText,
  Eye,
  Archive,
  GitCompareArrows,
  FlaskConical,
  X,
  ArrowRight,
  Minus,
  Plus,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Separator } from "@/components/ui/separator";
import { Textarea } from "@/components/ui/textarea";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { useToast } from "@/hooks/use-toast";

interface PromptTemplate {
  id: string;
  version: number;
  name: string;
  description: string;
  tier: string;
  systemPrompt: string;
  userTemplate: string;
  outputSchema?: Record<string, string>;
  maxTokens: number;
  temperature: number;
  deprecated?: boolean;
  deprecatedAt?: string;
  supersededBy?: string;
  createdAt: string;
  updatedAt: string;
  tags: string[];
}

interface PromptCatalogSummary {
  totalPrompts: number;
  byTier: Record<string, number>;
  deprecated: number;
  totalVersions: number;
  totalInvocations: number;
}

interface PromptAuditEntry {
  promptId: string;
  version: number;
  action: "registered" | "updated" | "deprecated" | "invoked";
  timestamp: string;
  metadata?: Record<string, unknown>;
}

interface PromptsResponse {
  prompts: PromptTemplate[];
  summary: PromptCatalogSummary;
}

const TIER_COLORS: Record<string, string> = {
  triage: "bg-amber-500/15 text-amber-400 border-amber-500/30",
  narrative: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  correlation: "bg-purple-500/15 text-purple-400 border-purple-500/30",
  health: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
  general: "bg-cyan-500/15 text-cyan-400 border-cyan-500/30",
};

interface TestPromptResult {
  output: string;
  latencyMs: number;
  model: string;
  inputTokens: number;
  outputTokens: number;
  cached: boolean;
  prompt: { id: string; version: number; name: string; tier: string };
}

/* ── Inline diff helper ── */
function computeLineDiff(
  oldText: string,
  newText: string,
): Array<{ type: "same" | "added" | "removed"; line: string }> {
  const oldLines = oldText.split("\n");
  const newLines = newText.split("\n");
  const result: Array<{ type: "same" | "added" | "removed"; line: string }> = [];

  let oi = 0;
  let ni = 0;
  while (oi < oldLines.length || ni < newLines.length) {
    if (oi < oldLines.length && ni < newLines.length && oldLines[oi] === newLines[ni]) {
      result.push({ type: "same", line: oldLines[oi] });
      oi++;
      ni++;
    } else if (oi < oldLines.length && (ni >= newLines.length || !newLines.includes(oldLines[oi]))) {
      result.push({ type: "removed", line: oldLines[oi] });
      oi++;
    } else if (ni < newLines.length) {
      result.push({ type: "added", line: newLines[ni] });
      ni++;
    }
  }
  return result;
}

const ACTION_COLORS: Record<string, string> = {
  registered: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
  updated: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  deprecated: "bg-amber-500/15 text-amber-400 border-amber-500/30",
  invoked: "bg-cyan-500/15 text-cyan-400 border-cyan-500/30",
};

function LoadingSkeleton() {
  return (
    <div className="p-6 space-y-6" role="status" aria-label="Loading prompt registry">
      <Skeleton className="h-8 w-72" />
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        {Array.from({ length: 5 }).map((_, i) => (
          <Skeleton key={i} className="h-24" />
        ))}
      </div>
      <Skeleton className="h-96" />
      <span className="sr-only">Loading prompt registry...</span>
    </div>
  );
}

function ErrorState({ onRetry }: { onRetry: () => void }) {
  return (
    <div className="p-6">
      <Card className="glass-card border-red-500/30">
        <CardContent className="flex flex-col items-center justify-center py-12">
          <AlertTriangle className="h-12 w-12 text-red-400 mb-4" />
          <p className="text-lg font-semibold mb-2">Failed to Load Prompt Registry</p>
          <p className="text-sm text-muted-foreground mb-4">Could not retrieve prompt data from the server.</p>
          <Button onClick={onRetry} variant="outline" size="sm">
            Retry
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}

function PromptDetailPanel({
  prompt,
  versionHistory,
  auditLog,
  isLoadingHistory,
  isLoadingAudit,
  onOpenDiff,
  onOpenTest,
}: {
  prompt: PromptTemplate;
  versionHistory: PromptTemplate[];
  auditLog: PromptAuditEntry[];
  isLoadingHistory: boolean;
  isLoadingAudit: boolean;
  onOpenDiff: (promptId: string) => void;
  onOpenTest: (promptId: string) => void;
}) {
  const [showSystemPrompt, setShowSystemPrompt] = useState(false);
  const [showUserTemplate, setShowUserTemplate] = useState(false);

  return (
    <div className="space-y-4">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h3 className="text-lg font-semibold">{prompt.name}</h3>
          <p className="text-sm text-muted-foreground mt-1">{prompt.description}</p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <Badge variant="outline" className={TIER_COLORS[prompt.tier] ?? TIER_COLORS.general}>
            {prompt.tier}
          </Badge>
          {prompt.deprecated && (
            <Badge variant="outline" className="bg-amber-500/15 text-amber-400 border-amber-500/30">
              Deprecated
            </Badge>
          )}
        </div>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="p-3 rounded-lg border border-border/50 bg-card/50">
          <p className="text-xs text-muted-foreground">Version</p>
          <p className="text-lg font-bold tabular-nums">v{prompt.version}</p>
        </div>
        <div className="p-3 rounded-lg border border-border/50 bg-card/50">
          <p className="text-xs text-muted-foreground">Max Tokens</p>
          <p className="text-lg font-bold tabular-nums">{prompt.maxTokens.toLocaleString()}</p>
        </div>
        <div className="p-3 rounded-lg border border-border/50 bg-card/50">
          <p className="text-xs text-muted-foreground">Temperature</p>
          <p className="text-lg font-bold tabular-nums">{prompt.temperature}</p>
        </div>
        <div className="p-3 rounded-lg border border-border/50 bg-card/50">
          <p className="text-xs text-muted-foreground">Tags</p>
          <p className="text-lg font-bold tabular-nums">{prompt.tags.length}</p>
        </div>
      </div>

      {prompt.tags.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {prompt.tags.map((tag) => (
            <Badge key={tag} variant="secondary" className="text-xs">
              <Tag className="h-3 w-3 mr-1" />
              {tag}
            </Badge>
          ))}
        </div>
      )}

      {prompt.supersededBy && (
        <div className="flex items-center gap-2 text-sm text-amber-400 p-2 rounded-md bg-amber-500/10 border border-amber-500/20">
          <AlertTriangle className="h-4 w-4 shrink-0" />
          <span>
            Superseded by: <strong>{prompt.supersededBy}</strong>
          </span>
        </div>
      )}

      <div className="flex items-center gap-2">
        <Button variant="outline" size="sm" className="gap-1.5" onClick={() => onOpenDiff(prompt.id)}>
          <GitCompareArrows className="h-3.5 w-3.5" />
          Compare Versions
        </Button>
        <Button variant="outline" size="sm" className="gap-1.5" onClick={() => onOpenTest(prompt.id)}>
          <FlaskConical className="h-3.5 w-3.5" />
          Test Prompt
        </Button>
      </div>

      <Separator />

      <div>
        <button
          onClick={() => setShowSystemPrompt(!showSystemPrompt)}
          className="flex items-center gap-2 text-sm font-medium hover:text-cyan-400 transition-colors w-full text-left py-1"
        >
          {showSystemPrompt ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
          System Prompt
          <span className="text-xs text-muted-foreground ml-auto">
            {prompt.systemPrompt.length.toLocaleString()} chars
          </span>
        </button>
        {showSystemPrompt && (
          <ScrollArea className="h-64 mt-2">
            <pre className="text-xs whitespace-pre-wrap p-3 rounded-lg border border-border/50 bg-card/50 font-mono leading-relaxed">
              {prompt.systemPrompt}
            </pre>
          </ScrollArea>
        )}
      </div>

      <div>
        <button
          onClick={() => setShowUserTemplate(!showUserTemplate)}
          className="flex items-center gap-2 text-sm font-medium hover:text-cyan-400 transition-colors w-full text-left py-1"
        >
          {showUserTemplate ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
          User Template
          <span className="text-xs text-muted-foreground ml-auto">
            {prompt.userTemplate.length.toLocaleString()} chars
          </span>
        </button>
        {showUserTemplate && (
          <ScrollArea className="h-64 mt-2">
            <pre className="text-xs whitespace-pre-wrap p-3 rounded-lg border border-border/50 bg-card/50 font-mono leading-relaxed">
              {prompt.userTemplate}
            </pre>
          </ScrollArea>
        )}
      </div>

      {prompt.outputSchema && Object.keys(prompt.outputSchema).length > 0 && (
        <>
          <Separator />
          <div>
            <p className="text-sm font-medium mb-2">Output Schema</p>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Field</TableHead>
                  <TableHead>Type</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {Object.entries(prompt.outputSchema).map(([field, type]) => (
                  <TableRow key={field}>
                    <TableCell className="font-mono text-xs">{field}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">{type}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </>
      )}

      <Separator />

      <Tabs defaultValue="history" className="w-full">
        <TabsList className="grid w-full grid-cols-2">
          <TabsTrigger value="history">Version History</TabsTrigger>
          <TabsTrigger value="audit">Audit Log</TabsTrigger>
        </TabsList>
        <TabsContent value="history" className="mt-3">
          {isLoadingHistory ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
            </div>
          ) : versionHistory.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
              <History className="h-8 w-8 mb-2 opacity-40" />
              <p className="text-sm">No version history available</p>
            </div>
          ) : (
            <ScrollArea className="h-48">
              <div className="space-y-2">
                {versionHistory
                  .slice()
                  .reverse()
                  .map((v) => (
                    <div
                      key={`${v.id}-v${v.version}`}
                      className="flex items-center justify-between p-2 rounded-lg border border-border/30 bg-card/30"
                    >
                      <div className="flex items-center gap-2">
                        <Badge variant="outline" className="text-xs tabular-nums">
                          v{v.version}
                        </Badge>
                        <span className="text-xs text-muted-foreground">
                          Tokens: {v.maxTokens} | Temp: {v.temperature}
                        </span>
                      </div>
                      <span className="text-xs text-muted-foreground">
                        {new Date(v.createdAt).toLocaleDateString()}
                      </span>
                    </div>
                  ))}
              </div>
            </ScrollArea>
          )}
        </TabsContent>
        <TabsContent value="audit" className="mt-3">
          {isLoadingAudit ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
            </div>
          ) : auditLog.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
              <FileText className="h-8 w-8 mb-2 opacity-40" />
              <p className="text-sm">No audit entries</p>
            </div>
          ) : (
            <ScrollArea className="h-48">
              <div className="space-y-2">
                {auditLog
                  .slice()
                  .reverse()
                  .map((entry, i) => (
                    <div
                      key={`${entry.promptId}-${entry.timestamp}-${i}`}
                      className="flex items-center justify-between p-2 rounded-lg border border-border/30 bg-card/30"
                    >
                      <div className="flex items-center gap-2">
                        <Badge variant="outline" className={`text-xs ${ACTION_COLORS[entry.action] ?? ""}`}>
                          {entry.action}
                        </Badge>
                        <span className="text-xs tabular-nums">v{entry.version}</span>
                      </div>
                      <span className="text-xs text-muted-foreground">
                        {new Date(entry.timestamp).toLocaleString()}
                      </span>
                    </div>
                  ))}
              </div>
            </ScrollArea>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}

/* ── Version Diff Dialog ── */
function VersionDiffDialog({
  open,
  onOpenChange,
  promptId,
  versionHistory,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  promptId: string;
  versionHistory: PromptTemplate[];
}) {
  const sorted = versionHistory.slice().sort((a, b) => a.version - b.version);
  const [leftVersion, setLeftVersion] = useState<string>("");
  const [rightVersion, setRightVersion] = useState<string>("");

  const leftPrompt = sorted.find((v) => String(v.version) === leftVersion);
  const rightPrompt = sorted.find((v) => String(v.version) === rightVersion);

  // Auto-select latest two versions when opened
  if (open && sorted.length >= 2 && !leftVersion && !rightVersion) {
    const prev = sorted[sorted.length - 2];
    const curr = sorted[sorted.length - 1];
    if (prev && curr) {
      setTimeout(() => {
        setLeftVersion(String(prev.version));
        setRightVersion(String(curr.version));
      }, 0);
    }
  }

  const systemDiff =
    leftPrompt && rightPrompt ? computeLineDiff(leftPrompt.systemPrompt, rightPrompt.systemPrompt) : [];
  const userDiff = leftPrompt && rightPrompt ? computeLineDiff(leftPrompt.userTemplate, rightPrompt.userTemplate) : [];

  const configChanges: Array<{ field: string; oldVal: string; newVal: string }> = [];
  if (leftPrompt && rightPrompt) {
    if (leftPrompt.maxTokens !== rightPrompt.maxTokens) {
      configChanges.push({
        field: "maxTokens",
        oldVal: String(leftPrompt.maxTokens),
        newVal: String(rightPrompt.maxTokens),
      });
    }
    if (leftPrompt.temperature !== rightPrompt.temperature) {
      configChanges.push({
        field: "temperature",
        oldVal: String(leftPrompt.temperature),
        newVal: String(rightPrompt.temperature),
      });
    }
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(v) => {
        onOpenChange(v);
        if (!v) {
          setLeftVersion("");
          setRightVersion("");
        }
      }}
    >
      <DialogContent className="max-w-4xl max-h-[85vh] overflow-hidden flex flex-col">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <GitCompareArrows className="h-5 w-5" /> Version Diff — {promptId}
          </DialogTitle>
          <DialogDescription>Compare any two versions of this prompt side-by-side</DialogDescription>
        </DialogHeader>

        <div className="flex items-center gap-3 mt-2">
          <div className="flex-1">
            <Label className="text-xs">Left (older)</Label>
            <Select value={leftVersion} onValueChange={setLeftVersion}>
              <SelectTrigger className="mt-1">
                <SelectValue placeholder="Select version" />
              </SelectTrigger>
              <SelectContent>
                {sorted.map((v) => (
                  <SelectItem key={v.version} value={String(v.version)}>
                    v{v.version} — {new Date(v.createdAt).toLocaleDateString()}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <ArrowRight className="h-4 w-4 text-muted-foreground mt-5" />
          <div className="flex-1">
            <Label className="text-xs">Right (newer)</Label>
            <Select value={rightVersion} onValueChange={setRightVersion}>
              <SelectTrigger className="mt-1">
                <SelectValue placeholder="Select version" />
              </SelectTrigger>
              <SelectContent>
                {sorted.map((v) => (
                  <SelectItem key={v.version} value={String(v.version)}>
                    v{v.version} — {new Date(v.createdAt).toLocaleDateString()}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>

        {sorted.length < 2 ? (
          <div className="flex flex-col items-center py-12 text-muted-foreground">
            <History className="h-8 w-8 mb-2 opacity-40" />
            <p className="text-sm">Need at least 2 versions to compare</p>
          </div>
        ) : !leftPrompt || !rightPrompt ? (
          <div className="flex flex-col items-center py-12 text-muted-foreground">
            <p className="text-sm">Select two versions above to compare</p>
          </div>
        ) : (
          <ScrollArea className="flex-1 mt-3">
            <div className="space-y-4">
              {/* Config changes */}
              {configChanges.length > 0 && (
                <div>
                  <p className="text-xs font-medium text-muted-foreground mb-2">Configuration Changes</p>
                  <div className="space-y-1">
                    {configChanges.map((c) => (
                      <div
                        key={c.field}
                        className="flex items-center gap-2 text-xs font-mono p-2 rounded border border-border/50 bg-card/50"
                      >
                        <span className="font-medium">{c.field}:</span>
                        <span className="text-red-400 line-through">{c.oldVal}</span>
                        <ArrowRight className="h-3 w-3" />
                        <span className="text-green-400">{c.newVal}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* System Prompt diff */}
              <div>
                <p className="text-xs font-medium text-muted-foreground mb-2">System Prompt</p>
                {systemDiff.every((d) => d.type === "same") ? (
                  <p className="text-xs text-muted-foreground italic p-2">No changes</p>
                ) : (
                  <div className="border border-border/50 rounded-lg overflow-hidden">
                    <pre className="text-xs font-mono leading-relaxed">
                      {systemDiff.map((d, i) => (
                        <div
                          key={i}
                          className={`px-3 py-0.5 ${
                            d.type === "added"
                              ? "bg-green-500/10 text-green-400"
                              : d.type === "removed"
                                ? "bg-red-500/10 text-red-400"
                                : ""
                          }`}
                        >
                          <span className="inline-block w-4 text-muted-foreground/50 select-none">
                            {d.type === "added" ? (
                              <Plus className="h-3 w-3 inline" />
                            ) : d.type === "removed" ? (
                              <Minus className="h-3 w-3 inline" />
                            ) : (
                              " "
                            )}
                          </span>
                          {d.line || " "}
                        </div>
                      ))}
                    </pre>
                  </div>
                )}
              </div>

              {/* User Template diff */}
              <div>
                <p className="text-xs font-medium text-muted-foreground mb-2">User Template</p>
                {userDiff.every((d) => d.type === "same") ? (
                  <p className="text-xs text-muted-foreground italic p-2">No changes</p>
                ) : (
                  <div className="border border-border/50 rounded-lg overflow-hidden">
                    <pre className="text-xs font-mono leading-relaxed">
                      {userDiff.map((d, i) => (
                        <div
                          key={i}
                          className={`px-3 py-0.5 ${
                            d.type === "added"
                              ? "bg-green-500/10 text-green-400"
                              : d.type === "removed"
                                ? "bg-red-500/10 text-red-400"
                                : ""
                          }`}
                        >
                          <span className="inline-block w-4 text-muted-foreground/50 select-none">
                            {d.type === "added" ? (
                              <Plus className="h-3 w-3 inline" />
                            ) : d.type === "removed" ? (
                              <Minus className="h-3 w-3 inline" />
                            ) : (
                              " "
                            )}
                          </span>
                          {d.line || " "}
                        </div>
                      ))}
                    </pre>
                  </div>
                )}
              </div>
            </div>
          </ScrollArea>
        )}
      </DialogContent>
    </Dialog>
  );
}

/* ── Test Prompt Dialog ── */
function TestPromptDialog({
  open,
  onOpenChange,
  promptId,
  promptName,
  versionHistory,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  promptId: string;
  promptName: string;
  versionHistory: PromptTemplate[];
}) {
  const { toast } = useToast();
  const [sampleInput, setSampleInput] = useState("");
  const [testVersion, setTestVersion] = useState<string>("current");
  const [result, setResult] = useState<TestPromptResult | null>(null);

  const sorted = versionHistory.slice().sort((a, b) => a.version - b.version);

  const testMutation = useMutation({
    mutationFn: async () => {
      const body: Record<string, unknown> = { promptId, sampleInput };
      if (testVersion !== "current") {
        body.version = parseInt(testVersion, 10);
      }
      const res = await apiRequest("POST", "/api/ai/test-prompt", body);
      return (await res.json()) as TestPromptResult;
    },
    onSuccess: (data) => {
      setResult(data);
    },
    onError: (err: Error) => {
      toast({ title: "Test failed", description: err.message, variant: "destructive" });
    },
  });

  const handleRun = () => {
    if (!sampleInput.trim()) {
      toast({ title: "Input required", description: "Paste a sample alert or input to test", variant: "destructive" });
      return;
    }
    setResult(null);
    testMutation.mutate();
  };

  return (
    <Dialog
      open={open}
      onOpenChange={(v) => {
        onOpenChange(v);
        if (!v) {
          setResult(null);
          setSampleInput("");
          setTestVersion("current");
        }
      }}
    >
      <DialogContent className="max-w-3xl max-h-[85vh] overflow-hidden flex flex-col">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <FlaskConical className="h-5 w-5" /> Test Prompt — {promptName}
          </DialogTitle>
          <DialogDescription>
            Paste a sample alert and see the raw model output. This does not trigger production triage or record
            metrics.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-3 mt-2">
          <div className="flex items-center gap-3">
            <div className="flex-1">
              <Label className="text-xs">Version</Label>
              <Select value={testVersion} onValueChange={setTestVersion}>
                <SelectTrigger className="mt-1">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="current">Current</SelectItem>
                  {sorted.map((v) => (
                    <SelectItem key={v.version} value={String(v.version)}>
                      v{v.version}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          <div>
            <Label className="text-xs">Sample Input</Label>
            <Textarea
              value={sampleInput}
              onChange={(e) => setSampleInput(e.target.value)}
              placeholder={`Paste a sample alert or input here...\n\nExample:\n{\n  "alertId": "ALERT-001",\n  "severity": "critical",\n  "source": "endpoint",\n  "description": "Suspicious PowerShell execution detected on WORKSTATION-42"\n}`}
              className="mt-1 font-mono text-xs min-h-[120px]"
            />
          </div>

          <Button onClick={handleRun} disabled={testMutation.isPending} className="gap-1.5">
            {testMutation.isPending ? (
              <>
                <Loader2 className="h-3.5 w-3.5 animate-spin" /> Running...
              </>
            ) : (
              <>
                <FlaskConical className="h-3.5 w-3.5" /> Run Test
              </>
            )}
          </Button>
        </div>

        {result && (
          <div className="mt-3 space-y-3 flex-1 overflow-hidden">
            <Separator />
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div className="p-2 rounded border border-border/50 bg-card/50">
                <p className="text-[10px] text-muted-foreground">Model</p>
                <p className="text-xs font-mono truncate">{result.model}</p>
              </div>
              <div className="p-2 rounded border border-border/50 bg-card/50">
                <p className="text-[10px] text-muted-foreground">Latency</p>
                <p className="text-xs font-bold tabular-nums">{result.latencyMs}ms</p>
              </div>
              <div className="p-2 rounded border border-border/50 bg-card/50">
                <p className="text-[10px] text-muted-foreground">In / Out Tokens</p>
                <p className="text-xs tabular-nums">
                  {result.inputTokens} / {result.outputTokens}
                </p>
              </div>
              <div className="p-2 rounded border border-border/50 bg-card/50">
                <p className="text-[10px] text-muted-foreground">Cached</p>
                <p className="text-xs">{result.cached ? "Yes" : "No"}</p>
              </div>
            </div>
            <div>
              <p className="text-xs font-medium text-muted-foreground mb-1">Raw Model Output</p>
              <ScrollArea className="h-[250px]">
                <pre className="text-xs whitespace-pre-wrap p-3 rounded-lg border border-border/50 bg-card/50 font-mono leading-relaxed">
                  {result.output}
                </pre>
              </ScrollArea>
            </div>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}

export default function AiPromptRegistryPage() {
  usePageTitle("AI Prompt Registry");
  const [selectedPromptId, setSelectedPromptId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [tierFilter, setTierFilter] = useState<string>("all");
  const [activeTab, setActiveTab] = useState("catalog");
  const [diffDialogOpen, setDiffDialogOpen] = useState(false);
  const [diffPromptId, setDiffPromptId] = useState<string | null>(null);
  const [testDialogOpen, setTestDialogOpen] = useState(false);
  const [testPromptId, setTestPromptId] = useState<string | null>(null);

  const {
    data: promptsData,
    isLoading,
    isError,
    refetch,
  } = useQuery<PromptsResponse>({
    queryKey: ["/api/ai/prompts"],
  });

  const selectedPrompt = promptsData?.prompts.find((p) => p.id === selectedPromptId) ?? null;

  const { data: versionHistory, isLoading: isLoadingHistory } = useQuery<PromptTemplate[]>({
    queryKey: ["/api/ai/prompts", selectedPromptId, "history"],
    queryFn: async () => {
      const res = await apiRequest("GET", `/api/ai/prompts/${selectedPromptId}/history`);
      const data = await res.json();
      return Array.isArray(data) ? data : [];
    },
    enabled: !!selectedPromptId,
  });

  const { data: auditLog, isLoading: isLoadingAudit } = useQuery<PromptAuditEntry[]>({
    queryKey: ["/api/ai/prompts", selectedPromptId, "audit"],
    queryFn: async () => {
      const res = await apiRequest("GET", `/api/ai/prompts/${selectedPromptId}/audit?limit=50`);
      const data = await res.json();
      return Array.isArray(data) ? data : [];
    },
    enabled: !!selectedPromptId,
  });

  const { data: globalAudit, isLoading: isLoadingGlobalAudit } = useQuery<PromptAuditEntry[]>({
    queryKey: ["/api/ai/audit"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/ai/audit?limit=100");
      const data = await res.json();
      return Array.isArray(data) ? data : [];
    },
    enabled: activeTab === "audit",
  });

  if (isLoading) return <LoadingSkeleton />;
  if (isError) return <ErrorState onRetry={refetch} />;

  const prompts = promptsData?.prompts ?? [];
  const summary = promptsData?.summary ?? {
    totalPrompts: 0,
    byTier: {},
    deprecated: 0,
    totalVersions: 0,
    totalInvocations: 0,
  };

  const filteredPrompts = prompts.filter((p) => {
    const matchesSearch =
      !searchQuery ||
      p.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      p.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      p.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      p.tags.some((t) => t.toLowerCase().includes(searchQuery.toLowerCase()));
    const matchesTier = tierFilter === "all" || p.tier === tierFilter;
    return matchesSearch && matchesTier;
  });

  const tiers = Array.from(new Set(prompts.map((p) => p.tier)));

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">AI Prompt Registry</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Versioned prompt catalog, performance metrics, and audit trail
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={() => refetch()} className="gap-1.5">
          <Zap className="h-3.5 w-3.5" />
          Refresh
        </Button>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4">
        <Card className="glass-card">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground font-medium uppercase tracking-wider">Active Prompts</p>
                <p className="text-2xl font-bold tabular-nums">{summary.totalPrompts}</p>
              </div>
              <BookOpen className="h-5 w-5 text-muted-foreground" />
            </div>
          </CardContent>
        </Card>
        <Card className="glass-card">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground font-medium uppercase tracking-wider">Total Versions</p>
                <p className="text-2xl font-bold tabular-nums">{summary.totalVersions}</p>
              </div>
              <Layers className="h-5 w-5 text-muted-foreground" />
            </div>
          </CardContent>
        </Card>
        <Card className="glass-card">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground font-medium uppercase tracking-wider">Invocations</p>
                <p className="text-2xl font-bold tabular-nums">{summary.totalInvocations.toLocaleString()}</p>
              </div>
              <Zap className="h-5 w-5 text-muted-foreground" />
            </div>
          </CardContent>
        </Card>
        <Card className="glass-card">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground font-medium uppercase tracking-wider">Tiers</p>
                <p className="text-2xl font-bold tabular-nums">{Object.keys(summary.byTier).length}</p>
              </div>
              <Hash className="h-5 w-5 text-muted-foreground" />
            </div>
          </CardContent>
        </Card>
        <Card className={`glass-card ${summary.deprecated > 0 ? "border-amber-500/30" : ""}`}>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground font-medium uppercase tracking-wider">Deprecated</p>
                <p className={`text-2xl font-bold tabular-nums ${summary.deprecated > 0 ? "text-amber-400" : ""}`}>
                  {summary.deprecated}
                </p>
              </div>
              <Archive className="h-5 w-5 text-muted-foreground" />
            </div>
          </CardContent>
        </Card>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="catalog">Prompt Catalog</TabsTrigger>
          <TabsTrigger value="audit">Global Audit Log</TabsTrigger>
          <TabsTrigger value="tiers">Tier Breakdown</TabsTrigger>
        </TabsList>

        <TabsContent value="catalog" className="mt-4 space-y-4">
          <div className="flex items-center gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search prompts by name, description, ID, or tag..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-9"
              />
            </div>
            <Select value={tierFilter} onValueChange={setTierFilter}>
              <SelectTrigger className="w-40">
                <Filter className="h-3.5 w-3.5 mr-1.5" />
                <SelectValue placeholder="Filter tier" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Tiers</SelectItem>
                {tiers.map((tier) => (
                  <SelectItem key={tier} value={tier}>
                    <span className="capitalize">{tier}</span>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-1">
              <Card className="glass-card">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm">Prompts ({filteredPrompts.length})</CardTitle>
                </CardHeader>
                <CardContent className="p-0">
                  {filteredPrompts.length === 0 ? (
                    <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                      <Search className="h-8 w-8 mb-2 opacity-40" />
                      <p className="text-sm">No prompts match your filters</p>
                    </div>
                  ) : (
                    <ScrollArea className="h-[500px]">
                      <div className="space-y-1 p-2">
                        {filteredPrompts.map((p) => (
                          <button
                            key={p.id}
                            onClick={() => setSelectedPromptId(p.id)}
                            className={`w-full text-left p-3 rounded-lg transition-colors ${
                              selectedPromptId === p.id
                                ? "bg-cyan-500/10 border border-cyan-500/30"
                                : "hover:bg-card/80 border border-transparent"
                            }`}
                          >
                            <div className="flex items-center justify-between mb-1">
                              <span className="text-sm font-medium truncate">{p.name}</span>
                              <Badge
                                variant="outline"
                                className={`text-[10px] shrink-0 ml-2 ${TIER_COLORS[p.tier] ?? TIER_COLORS.general}`}
                              >
                                {p.tier}
                              </Badge>
                            </div>
                            <p className="text-xs text-muted-foreground truncate">{p.description}</p>
                            <div className="flex items-center gap-3 mt-1.5 text-[10px] text-muted-foreground/70">
                              <span className="flex items-center gap-1">
                                <Hash className="h-3 w-3" />v{p.version}
                              </span>
                              <span className="flex items-center gap-1">
                                <Thermometer className="h-3 w-3" />
                                {p.temperature}
                              </span>
                              <span className="flex items-center gap-1">
                                <Layers className="h-3 w-3" />
                                {p.maxTokens}
                              </span>
                              {p.deprecated && (
                                <Badge
                                  variant="outline"
                                  className="text-[9px] px-1 py-0 h-3.5 text-amber-400 border-amber-500/30"
                                >
                                  deprecated
                                </Badge>
                              )}
                            </div>
                          </button>
                        ))}
                      </div>
                    </ScrollArea>
                  )}
                </CardContent>
              </Card>
            </div>

            <div className="lg:col-span-2">
              <Card className="glass-card">
                <CardContent className="p-4">
                  {selectedPrompt ? (
                    <PromptDetailPanel
                      prompt={selectedPrompt}
                      versionHistory={versionHistory ?? []}
                      auditLog={auditLog ?? []}
                      isLoadingHistory={isLoadingHistory}
                      isLoadingAudit={isLoadingAudit}
                      onOpenDiff={(id) => {
                        setDiffPromptId(id);
                        setDiffDialogOpen(true);
                      }}
                      onOpenTest={(id) => {
                        setTestPromptId(id);
                        setTestDialogOpen(true);
                      }}
                    />
                  ) : (
                    <div className="flex flex-col items-center justify-center py-24 text-muted-foreground">
                      <Eye className="h-12 w-12 mb-3 opacity-30" />
                      <p className="text-sm font-medium">Select a prompt to view details</p>
                      <p className="text-xs mt-1">Click any prompt in the catalog to inspect it</p>
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          </div>
        </TabsContent>

        <TabsContent value="audit" className="mt-4">
          <Card className="glass-card">
            <CardHeader>
              <CardTitle className="text-base">Global Audit Log</CardTitle>
              <CardDescription>All prompt registry events across the platform</CardDescription>
            </CardHeader>
            <CardContent>
              {isLoadingGlobalAudit ? (
                <div className="flex items-center justify-center py-12">
                  <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
                </div>
              ) : !globalAudit || globalAudit.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                  <FileText className="h-10 w-10 mb-3 opacity-40" />
                  <p className="text-sm font-medium">No audit entries yet</p>
                  <p className="text-xs mt-1">
                    Audit events will appear as prompts are registered, updated, or invoked
                  </p>
                </div>
              ) : (
                <ScrollArea className="h-[500px]">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Timestamp</TableHead>
                        <TableHead>Prompt ID</TableHead>
                        <TableHead>Version</TableHead>
                        <TableHead>Action</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {globalAudit
                        .slice()
                        .reverse()
                        .map((entry, i) => (
                          <TableRow
                            key={`${entry.promptId}-${entry.timestamp}-${i}`}
                            className="cursor-pointer hover:bg-card/50"
                            onClick={() => {
                              setSelectedPromptId(entry.promptId);
                              setActiveTab("catalog");
                            }}
                          >
                            <TableCell className="text-xs tabular-nums">
                              {new Date(entry.timestamp).toLocaleString()}
                            </TableCell>
                            <TableCell className="font-mono text-xs">{entry.promptId}</TableCell>
                            <TableCell className="text-xs tabular-nums">v{entry.version}</TableCell>
                            <TableCell>
                              <Badge variant="outline" className={`text-xs ${ACTION_COLORS[entry.action] ?? ""}`}>
                                {entry.action}
                              </Badge>
                            </TableCell>
                          </TableRow>
                        ))}
                    </TableBody>
                  </Table>
                </ScrollArea>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="tiers" className="mt-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {Object.entries(summary.byTier).map(([tier, count]) => {
              const tierPrompts = prompts.filter((p) => p.tier === tier);
              const activeCount = tierPrompts.filter((p) => !p.deprecated).length;
              const deprecatedCount = tierPrompts.filter((p) => p.deprecated).length;

              return (
                <Card key={tier} className="glass-card">
                  <CardHeader className="pb-2">
                    <div className="flex items-center justify-between">
                      <CardTitle className="text-base capitalize">{tier}</CardTitle>
                      <Badge variant="outline" className={TIER_COLORS[tier] ?? TIER_COLORS.general}>
                        {count} prompt{count !== 1 ? "s" : ""}
                      </Badge>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-3">
                      <div className="flex items-center justify-between text-sm">
                        <span className="flex items-center gap-1.5 text-muted-foreground">
                          <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500" />
                          Active
                        </span>
                        <span className="font-medium">{activeCount}</span>
                      </div>
                      {deprecatedCount > 0 && (
                        <div className="flex items-center justify-between text-sm">
                          <span className="flex items-center gap-1.5 text-muted-foreground">
                            <AlertTriangle className="h-3.5 w-3.5 text-amber-500" />
                            Deprecated
                          </span>
                          <span className="font-medium text-amber-400">{deprecatedCount}</span>
                        </div>
                      )}
                      <Separator />
                      <div className="space-y-1">
                        {tierPrompts.map((p) => (
                          <button
                            key={p.id}
                            onClick={() => {
                              setSelectedPromptId(p.id);
                              setActiveTab("catalog");
                            }}
                            className="w-full text-left text-xs hover:text-cyan-400 transition-colors py-0.5 truncate"
                          >
                            {p.name} <span className="text-muted-foreground">v{p.version}</span>
                          </button>
                        ))}
                      </div>
                    </div>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        </TabsContent>
      </Tabs>

      {/* Version Diff Dialog */}
      {diffPromptId && (
        <VersionDiffDialog
          open={diffDialogOpen}
          onOpenChange={setDiffDialogOpen}
          promptId={diffPromptId}
          versionHistory={versionHistory ?? []}
        />
      )}

      {/* Test Prompt Dialog */}
      {testPromptId && (
        <TestPromptDialog
          open={testDialogOpen}
          onOpenChange={setTestDialogOpen}
          promptId={testPromptId}
          promptName={prompts.find((p) => p.id === testPromptId)?.name ?? testPromptId}
          versionHistory={versionHistory ?? []}
        />
      )}
    </div>
  );
}

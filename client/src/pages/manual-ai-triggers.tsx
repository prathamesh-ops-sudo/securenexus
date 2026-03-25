import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { usePageTitle } from "@/hooks/use-page-title";
import {
  Wand2,
  Play,
  Loader2,
  Brain,
  Shield,
  Search,
  FileText,
  AlertTriangle,
  CheckCircle2,
  Zap,
  Bot,
} from "lucide-react";
import { SuccessIcon } from "@/components/ui/animated-state-icons";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";

interface TriggerResult {
  feature: string;
  status: string;
  output: string;
  timestamp: string;
}

const AI_FEATURES = [
  {
    id: "correlate",
    name: "Alert Correlation",
    description: "Run AI correlation engine on recent alerts",
    icon: Brain,
  },
  { id: "triage", name: "Incident Triage", description: "Auto-triage and prioritize open incidents", icon: Shield },
  { id: "narrative", name: "Incident Narrative", description: "Generate AI narrative for an incident", icon: FileText },
  { id: "enrich", name: "IOC Enrichment", description: "Enrich indicators with threat intelligence", icon: Search },
  { id: "posture", name: "Posture Assessment", description: "Run AI security posture assessment", icon: Zap },
  {
    id: "anomaly",
    name: "Anomaly Detection",
    description: "Detect anomalies in recent telemetry",
    icon: AlertTriangle,
  },
];

export default function ManualAiTriggersPage() {
  usePageTitle("Manual AI Feature Triggers");
  const { toast } = useToast();
  const [selectedFeature, setSelectedFeature] = useState("");
  const [inputText, setInputText] = useState("");
  const [results, setResults] = useState<TriggerResult[]>([]);

  const triggerMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", `/api/ai/trigger/${selectedFeature}`, {
        input: inputText || undefined,
      });
      return res.json();
    },
    onSuccess: (data) => {
      const result: TriggerResult = {
        feature: selectedFeature,
        status: "success",
        output: typeof data === "string" ? data : JSON.stringify(data, null, 2),
        timestamp: new Date().toISOString(),
      };
      setResults((prev) => [result, ...prev]);
      toast({ title: `${selectedFeature} completed successfully` });
    },
    onError: (err: Error) => {
      const result: TriggerResult = {
        feature: selectedFeature,
        status: "error",
        output: err.message,
        timestamp: new Date().toISOString(),
      };
      setResults((prev) => [result, ...prev]);
      toast({ title: "AI trigger failed", description: err.message, variant: "destructive" });
    },
  });

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <Wand2 className="h-6 w-6" /> Manual AI Feature Triggers
        </h1>
        <p className="text-muted-foreground text-sm mt-1">
          Manually invoke AI features on demand for testing and ad-hoc analysis
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {AI_FEATURES.map((f) => {
          const Icon = f.icon;
          return (
            <Card
              key={f.id}
              className={`cursor-pointer transition-all hover:shadow-md ${selectedFeature === f.id ? "ring-2 ring-primary" : ""}`}
              onClick={() => setSelectedFeature(f.id)}
            >
              <CardContent className="pt-4">
                <div className="flex items-center gap-3">
                  <Icon className="h-5 w-5 text-primary" />
                  <div>
                    <p className="font-medium text-sm">{f.name}</p>
                    <p className="text-xs text-muted-foreground">{f.description}</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {selectedFeature && (
        <Card>
          <CardHeader>
            <CardTitle className="text-lg flex items-center gap-2">
              <Bot className="h-5 w-5" /> Run {AI_FEATURES.find((f) => f.id === selectedFeature)?.name}
            </CardTitle>
            <CardDescription>Provide optional input context for the AI feature</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <Label>Input Context (optional)</Label>
              <Textarea
                value={inputText}
                onChange={(e) => setInputText(e.target.value)}
                placeholder="Provide additional context, alert IDs, incident IDs, or IOCs..."
                rows={3}
              />
            </div>
            <Button onClick={() => triggerMutation.mutate()} disabled={triggerMutation.isPending}>
              {triggerMutation.isPending ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <Play className="mr-2 h-4 w-4" />
              )}
              Run Feature
            </Button>
          </CardContent>
        </Card>
      )}

      {results.length > 0 && (
        <div className="space-y-3">
          <h2 className="text-lg font-semibold">Results</h2>
          {results.map((r, i) => (
            <Card key={i}>
              <CardContent className="py-3">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    {r.status === "success" ? (
                      <CheckCircle2 className="h-4 w-4 text-green-500" />
                    ) : (
                      <AlertTriangle className="h-4 w-4 text-red-500" />
                    )}
                    <span className="font-medium text-sm capitalize">{r.feature}</span>
                    <Badge variant={r.status === "success" ? "default" : "destructive"}>{r.status}</Badge>
                  </div>
                  <span className="text-xs text-muted-foreground">{new Date(r.timestamp).toLocaleTimeString()}</span>
                </div>
                <pre className="text-xs bg-muted p-3 rounded overflow-auto max-h-48 whitespace-pre-wrap">
                  {r.output}
                </pre>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

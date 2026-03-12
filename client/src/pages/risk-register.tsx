import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { usePageTitle } from "@/hooks/use-page-title";
import { useToast } from "@/hooks/use-toast";
import {
  ShieldAlert,
  Plus,
  Search,
  RefreshCw,
  Trash2,
  AlertTriangle,
  TrendingUp,
  BarChart3,
  Filter,
  ArrowUpRight,
  ArrowDownRight,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Skeleton } from "@/components/ui/skeleton";
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

interface RiskEntry {
  id: string;
  title: string;
  description: string | null;
  category: string;
  likelihood: number;
  impact: number;
  inherentRiskScore: number;
  residualLikelihood: number | null;
  residualImpact: number | null;
  residualRiskScore: number | null;
  treatment: string;
  treatmentPlan: string | null;
  riskOwner: string | null;
  status: string;
  tags: string[];
  createdAt: string;
}

interface RiskStats {
  total: number;
  criticalRisks: number;
  highRisks: number;
  mediumRisks: number;
  lowRisks: number;
  inTreatment: number;
}

const HEATMAP_COLORS = [
  ["bg-green-900/60", "bg-green-700/60", "bg-yellow-700/60", "bg-orange-700/60", "bg-red-700/60"],
  ["bg-green-700/60", "bg-yellow-800/60", "bg-yellow-600/60", "bg-orange-600/60", "bg-red-600/60"],
  ["bg-yellow-700/60", "bg-yellow-600/60", "bg-orange-500/60", "bg-red-500/60", "bg-red-500/80"],
  ["bg-orange-700/60", "bg-orange-500/60", "bg-red-500/60", "bg-red-600/80", "bg-red-700/80"],
  ["bg-red-700/60", "bg-red-600/60", "bg-red-500/80", "bg-red-700/80", "bg-red-900/90"],
];

const RISK_LEVEL_BADGE: Record<string, string> = {
  critical: "bg-red-500/10 text-red-500 border-red-500/20",
  high: "bg-orange-500/10 text-orange-500 border-orange-500/20",
  medium: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20",
  low: "bg-green-500/10 text-green-500 border-green-500/20",
};

function riskLevel(score: number): string {
  if (score >= 20) return "critical";
  if (score >= 12) return "high";
  if (score >= 6) return "medium";
  return "low";
}

function CreateRiskDialog({ onCreated }: { onCreated: () => void }) {
  const { toast } = useToast();
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({
    title: "",
    description: "",
    category: "operational",
    likelihood: 3,
    impact: 3,
    treatment: "mitigate",
    treatmentPlan: "",
    riskOwner: "",
  });

  const createMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/risks", form);
      if (!res.ok) throw new Error("Failed to create risk");
      return res.json();
    },
    onSuccess: () => {
      toast({ title: "Risk created" });
      setOpen(false);
      setForm({
        title: "",
        description: "",
        category: "operational",
        likelihood: 3,
        impact: 3,
        treatment: "mitigate",
        treatmentPlan: "",
        riskOwner: "",
      });
      onCreated();
    },
    onError: () => toast({ title: "Error", description: "Failed to create risk", variant: "destructive" }),
  });

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm">
          <Plus className="mr-2 h-4 w-4" /> Add Risk
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-xl max-h-[80vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Register New Risk</DialogTitle>
          <DialogDescription>Add a new risk to the register with likelihood and impact scoring</DialogDescription>
        </DialogHeader>
        <div className="grid grid-cols-2 gap-4">
          <div className="col-span-2">
            <Label>Risk Title *</Label>
            <Input
              value={form.title}
              onChange={(e) => setForm({ ...form, title: e.target.value })}
              placeholder="e.g., Ransomware attack on production systems"
            />
          </div>
          <div className="col-span-2">
            <Label>Description</Label>
            <Textarea
              value={form.description}
              onChange={(e) => setForm({ ...form, description: e.target.value })}
              placeholder="Detailed description of the risk..."
              rows={3}
            />
          </div>
          <div>
            <Label>Category</Label>
            <Select value={form.category} onValueChange={(v) => setForm({ ...form, category: v })}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {[
                  "operational",
                  "technical",
                  "compliance",
                  "strategic",
                  "financial",
                  "reputational",
                  "third_party",
                  "physical",
                ].map((c) => (
                  <SelectItem key={c} value={c}>
                    {c.replace(/_/g, " ").replace(/\b\w/g, (l) => l.toUpperCase())}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div>
            <Label>Treatment</Label>
            <Select value={form.treatment} onValueChange={(v) => setForm({ ...form, treatment: v })}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="mitigate">Mitigate</SelectItem>
                <SelectItem value="accept">Accept</SelectItem>
                <SelectItem value="transfer">Transfer</SelectItem>
                <SelectItem value="avoid">Avoid</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div>
            <Label>Likelihood (1-5)</Label>
            <Select
              value={String(form.likelihood)}
              onValueChange={(v) => setForm({ ...form, likelihood: parseInt(v) })}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="1">1 - Rare</SelectItem>
                <SelectItem value="2">2 - Unlikely</SelectItem>
                <SelectItem value="3">3 - Possible</SelectItem>
                <SelectItem value="4">4 - Likely</SelectItem>
                <SelectItem value="5">5 - Almost Certain</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div>
            <Label>Impact (1-5)</Label>
            <Select value={String(form.impact)} onValueChange={(v) => setForm({ ...form, impact: parseInt(v) })}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="1">1 - Insignificant</SelectItem>
                <SelectItem value="2">2 - Minor</SelectItem>
                <SelectItem value="3">3 - Moderate</SelectItem>
                <SelectItem value="4">4 - Major</SelectItem>
                <SelectItem value="5">5 - Catastrophic</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="col-span-2 p-3 rounded-lg bg-muted text-center">
            <span className="text-sm text-muted-foreground">Inherent Risk Score: </span>
            <span className="text-lg font-bold">{form.likelihood * form.impact}</span>
            <Badge className={`ml-2 ${RISK_LEVEL_BADGE[riskLevel(form.likelihood * form.impact)]}`} variant="outline">
              {riskLevel(form.likelihood * form.impact)}
            </Badge>
          </div>
          <div>
            <Label>Risk Owner</Label>
            <Input
              value={form.riskOwner}
              onChange={(e) => setForm({ ...form, riskOwner: e.target.value })}
              placeholder="Name or team"
            />
          </div>
          <div>
            <Label>Treatment Plan</Label>
            <Input
              value={form.treatmentPlan}
              onChange={(e) => setForm({ ...form, treatmentPlan: e.target.value })}
              placeholder="How to address this risk"
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)}>
            Cancel
          </Button>
          <Button onClick={() => createMutation.mutate()} disabled={!form.title || createMutation.isPending}>
            {createMutation.isPending ? "Creating..." : "Create Risk"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default function RiskRegisterPage() {
  usePageTitle("Risk Register");
  const { toast } = useToast();
  const [categoryFilter, setCategoryFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");

  const { data, isLoading, refetch } = useQuery<{ risks: RiskEntry[]; heatmap: number[][]; stats: RiskStats }>({
    queryKey: ["/api/risks", categoryFilter, statusFilter],
    queryFn: async () => {
      const params = new URLSearchParams();
      if (categoryFilter !== "all") params.set("category", categoryFilter);
      if (statusFilter !== "all") params.set("status", statusFilter);
      const res = await apiRequest("GET", `/api/risks?${params}`);
      return res.json();
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      const res = await apiRequest("DELETE", `/api/risks/${id}`);
      if (!res.ok) throw new Error("Failed to delete");
    },
    onSuccess: () => {
      toast({ title: "Risk deleted" });
      refetch();
    },
  });

  const risks = data?.risks || [];
  const heatmap = data?.heatmap || Array.from({ length: 5 }, () => Array(5).fill(0));
  const stats = data?.stats || {
    total: 0,
    criticalRisks: 0,
    highRisks: 0,
    mediumRisks: 0,
    lowRisks: 0,
    inTreatment: 0,
  };

  if (isLoading) {
    return (
      <div className="p-6 space-y-4">
        <Skeleton className="h-8 w-64" />
        <div className="grid grid-cols-4 gap-4">
          {[1, 2, 3, 4].map((i) => (
            <Skeleton key={i} className="h-24" />
          ))}
        </div>
        <Skeleton className="h-96" />
      </div>
    );
  }

  const impactLabels = ["Insignificant", "Minor", "Moderate", "Major", "Catastrophic"];
  const likelihoodLabels = ["Rare", "Unlikely", "Possible", "Likely", "Almost Certain"];

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <ShieldAlert className="h-6 w-6" /> Risk Register
          </h1>
          <p className="text-muted-foreground text-sm mt-1">
            Enterprise risk management with likelihood-impact assessment
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="mr-2 h-4 w-4" /> Refresh
          </Button>
          <CreateRiskDialog onCreated={() => refetch()} />
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center gap-2">
              <ShieldAlert className="h-5 w-5 text-primary" />
              <div>
                <p className="text-2xl font-bold">{stats.total}</p>
                <p className="text-xs text-muted-foreground">Total Risks</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-red-500" />
              <div>
                <p className="text-2xl font-bold">{stats.criticalRisks}</p>
                <p className="text-xs text-muted-foreground">Critical</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center gap-2">
              <ArrowUpRight className="h-5 w-5 text-orange-500" />
              <div>
                <p className="text-2xl font-bold">{stats.highRisks}</p>
                <p className="text-xs text-muted-foreground">High</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center gap-2">
              <BarChart3 className="h-5 w-5 text-yellow-500" />
              <div>
                <p className="text-2xl font-bold">{stats.mediumRisks}</p>
                <p className="text-xs text-muted-foreground">Medium</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center gap-2">
              <ArrowDownRight className="h-5 w-5 text-green-500" />
              <div>
                <p className="text-2xl font-bold">{stats.lowRisks}</p>
                <p className="text-xs text-muted-foreground">Low</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center gap-2">
              <TrendingUp className="h-5 w-5 text-blue-500" />
              <div>
                <p className="text-2xl font-bold">{stats.inTreatment}</p>
                <p className="text-xs text-muted-foreground">In Treatment</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Heatmap */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Risk Heatmap</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex gap-4">
            <div className="flex flex-col items-end gap-0 pt-0">
              <span className="text-[10px] text-muted-foreground -rotate-0 mb-1">Likelihood</span>
              {likelihoodLabels
                .slice()
                .reverse()
                .map((label, idx) => (
                  <div key={label} className="h-12 flex items-center">
                    <span className="text-[10px] text-muted-foreground whitespace-nowrap">
                      {5 - idx}. {label}
                    </span>
                  </div>
                ))}
            </div>
            <div className="flex-1">
              <div className="grid grid-cols-5 gap-1">
                {[4, 3, 2, 1, 0].map((l) =>
                  [0, 1, 2, 3, 4].map((i) => (
                    <div
                      key={`${l}-${i}`}
                      className={`h-12 rounded flex items-center justify-center text-sm font-bold text-white ${HEATMAP_COLORS[l][i]}`}
                    >
                      {heatmap[l][i] > 0 ? heatmap[l][i] : ""}
                    </div>
                  )),
                )}
              </div>
              <div className="grid grid-cols-5 gap-1 mt-1">
                {impactLabels.map((label, idx) => (
                  <div key={label} className="text-center text-[10px] text-muted-foreground">
                    {idx + 1}. {label}
                  </div>
                ))}
              </div>
              <div className="text-center mt-1">
                <span className="text-[10px] text-muted-foreground">Impact</span>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Filters */}
      <div className="flex gap-2">
        <Select value={categoryFilter} onValueChange={setCategoryFilter}>
          <SelectTrigger className="w-44">
            <Filter className="mr-2 h-4 w-4" />
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Categories</SelectItem>
            {[
              "operational",
              "technical",
              "compliance",
              "strategic",
              "financial",
              "reputational",
              "third_party",
              "physical",
            ].map((c) => (
              <SelectItem key={c} value={c}>
                {c.replace(/_/g, " ").replace(/\b\w/g, (l) => l.toUpperCase())}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-40">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Statuses</SelectItem>
            {["identified", "assessing", "treating", "monitoring", "closed"].map((s) => (
              <SelectItem key={s} value={s}>
                {s.replace(/\b\w/g, (l) => l.toUpperCase())}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {/* Risk List */}
      {risks.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center py-16 gap-4">
            <ShieldAlert className="h-12 w-12 text-muted-foreground/40" />
            <div className="text-center">
              <h3 className="font-semibold">No risks registered</h3>
              <p className="text-sm text-muted-foreground mt-1">
                Add your first risk to start building your risk register
              </p>
            </div>
            <CreateRiskDialog onCreated={() => refetch()} />
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-2">
          {risks.map((risk) => {
            const level = riskLevel(risk.inherentRiskScore);
            return (
              <Card key={risk.id} className="transition-all hover:shadow-sm">
                <CardContent className="py-3">
                  <div className="flex items-center gap-4">
                    <div className={`flex items-center justify-center w-10 h-10 rounded-lg ${RISK_LEVEL_BADGE[level]}`}>
                      <span className="text-lg font-bold">{risk.inherentRiskScore}</span>
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-0.5">
                        <span className="font-semibold text-sm truncate">{risk.title}</span>
                        <Badge className={RISK_LEVEL_BADGE[level]} variant="outline">
                          {level}
                        </Badge>
                        <Badge variant="outline">{risk.category.replace(/_/g, " ")}</Badge>
                        <Badge variant="outline">{risk.treatment}</Badge>
                      </div>
                      <div className="flex items-center gap-4 text-xs text-muted-foreground">
                        <span>
                          L:{risk.likelihood} x I:{risk.impact}
                        </span>
                        {risk.residualRiskScore !== null && <span>Residual: {risk.residualRiskScore}</span>}
                        {risk.riskOwner && <span>Owner: {risk.riskOwner}</span>}
                        <span>Status: {risk.status}</span>
                      </div>
                      {risk.description && (
                        <p className="text-xs text-muted-foreground mt-1 line-clamp-1">{risk.description}</p>
                      )}
                    </div>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-8 w-8 text-muted-foreground hover:text-destructive"
                      onClick={() => deleteMutation.mutate(risk.id)}
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}

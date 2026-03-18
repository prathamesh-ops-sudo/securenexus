import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Shield,
  Users,
  Clock,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Network,
  KeyRound,
  UserX,
  Activity,
  Target,
  Plus,
  Play,
  Eye,
  Search,
  RefreshCw,
  ChevronRight,
  FileText,
  Lock,
  Unlock,
  Server,
  ArrowRight,
  Zap,
} from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import { DashboardSkeleton } from "@/components/page-skeleton";

// ============================================================================
// Types
// ============================================================================

interface AccessReviewCampaign {
  id: string;
  orgId: string;
  name: string;
  description: string | null;
  cadence: string;
  status: string;
  reviewerName: string | null;
  totalEntitlements: number;
  reviewedCount: number;
  approvedCount: number;
  revokedCount: number;
  dueDate: string | null;
  startedAt: string | null;
  completedAt: string | null;
  createdAt: string;
}

interface AccessReviewEntitlement {
  id: string;
  campaignId: string;
  userId: string;
  userName: string;
  userEmail: string | null;
  entitlementType: string;
  entitlementName: string;
  entitlementDescription: string | null;
  riskLevel: string;
  status: string;
  decision: string | null;
  decisionReason: string | null;
  lastUsedAt: string | null;
  grantedAt: string | null;
}

interface PamSession {
  id: string;
  requesterName: string;
  requesterEmail: string | null;
  targetSystem: string;
  targetHost: string | null;
  targetAccount: string;
  accessLevel: string;
  justification: string;
  status: string;
  durationMinutes: number;
  riskScore: number | null;
  riskFactors: string[] | null;
  approvedBy: string | null;
  approvedAt: string | null;
  activatedAt: string | null;
  expiresAt: string | null;
  terminatedAt: string | null;
  commandCount: number | null;
  keystrokeCount: number | null;
  createdAt: string;
}

interface IdentityRiskProfile {
  id: string;
  userId: string;
  userName: string;
  userEmail: string | null;
  riskLevel: string;
  riskScore: number;
  isStale: boolean;
  daysSinceActivity: number | null;
  isServiceAccount: boolean;
  blastRadiusScore: number | null;
  accessibleSystems: number | null;
  lateralMovementPaths: number | null;
  canReachCritical: boolean;
  mfaEnabled: boolean;
  hasExcessivePermissions: boolean;
  failedLoginCount: number | null;
  lastAssessedAt: string | null;
}

interface ScimLog {
  id: string;
  provider: string;
  operationType: string;
  externalUserName: string | null;
  externalEmail: string | null;
  groupName: string | null;
  success: boolean;
  errorMessage: string | null;
  createdAt: string;
}

// ============================================================================
// Helpers
// ============================================================================

function riskBadge(level: string) {
  const colors: Record<string, string> = {
    critical: "bg-red-500/15 text-red-400 border-red-500/30",
    high: "bg-orange-500/15 text-orange-400 border-orange-500/30",
    medium: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
    low: "bg-green-500/15 text-green-400 border-green-500/30",
  };
  return (
    <Badge variant="outline" className={colors[level] || colors.low}>
      {level}
    </Badge>
  );
}

function statusBadge(status: string) {
  const colors: Record<string, string> = {
    active: "bg-green-500/15 text-green-400 border-green-500/30",
    approved: "bg-green-500/15 text-green-400 border-green-500/30",
    completed: "bg-blue-500/15 text-blue-400 border-blue-500/30",
    pending: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
    requested: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
    draft: "bg-zinc-500/15 text-zinc-400 border-zinc-500/30",
    denied: "bg-red-500/15 text-red-400 border-red-500/30",
    revoked: "bg-red-500/15 text-red-400 border-red-500/30",
    terminated: "bg-red-500/15 text-red-400 border-red-500/30",
    expired: "bg-zinc-500/15 text-zinc-400 border-zinc-500/30",
    cancelled: "bg-zinc-500/15 text-zinc-400 border-zinc-500/30",
  };
  return (
    <Badge variant="outline" className={colors[status] || colors.draft}>
      {status}
    </Badge>
  );
}

function timeAgo(dateStr: string | null): string {
  if (!dateStr) return "Never";
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function riskMeter(score: number) {
  const color =
    score >= 80 ? "bg-red-500" : score >= 60 ? "bg-orange-500" : score >= 30 ? "bg-yellow-500" : "bg-green-500";
  return (
    <div className="flex items-center gap-2">
      <div className="w-24 h-2 bg-muted rounded-full overflow-hidden">
        <div className={`h-full ${color} rounded-full`} style={{ width: `${score}%` }} />
      </div>
      <span className="text-xs text-muted-foreground">{score}</span>
    </div>
  );
}

// ============================================================================
// Sub-components
// ============================================================================

function SummaryCards() {
  const { data: summary } = useQuery({
    queryKey: ["/api/identity/summary"],
    queryFn: () => apiRequest("GET", "/api/identity/summary").then((r) => r.json()),
    refetchInterval: 30000,
  });

  const { data: pamSummary } = useQuery({
    queryKey: ["/api/pam/summary"],
    queryFn: () => apiRequest("GET", "/api/pam/summary").then((r) => r.json()),
    refetchInterval: 30000,
  });

  const cards = [
    {
      title: "Active Campaigns",
      value: summary?.campaigns?.active ?? 0,
      subtitle: `${summary?.campaigns?.total ?? 0} total`,
      icon: FileText,
      color: "text-blue-400",
    },
    {
      title: "Critical Identities",
      value: (summary?.identities?.critical ?? 0) + (summary?.identities?.high ?? 0),
      subtitle: `${summary?.identities?.total ?? 0} profiled`,
      icon: AlertTriangle,
      color: "text-red-400",
    },
    {
      title: "Active PAM Sessions",
      value: pamSummary?.active ?? 0,
      subtitle: `${pamSummary?.pending ?? 0} pending approval`,
      icon: KeyRound,
      color: "text-amber-400",
    },
    {
      title: "Stale Accounts",
      value: summary?.identities?.stale ?? 0,
      subtitle: `${summary?.scimEvents ?? 0} SCIM events`,
      icon: UserX,
      color: "text-orange-400",
    },
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
      {cards.map((card) => (
        <Card key={card.title}>
          <CardContent className="p-4">
            <div className="flex items-start justify-between">
              <div>
                <p className="text-sm text-muted-foreground">{card.title}</p>
                <p className="text-2xl font-bold mt-1">{card.value}</p>
                <p className="text-xs text-muted-foreground mt-1">{card.subtitle}</p>
              </div>
              <card.icon className={`h-5 w-5 ${card.color}`} />
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

function AccessReviewsTab() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [selectedCampaign, setSelectedCampaign] = useState<string | null>(null);
  const [newName, setNewName] = useState("");
  const [newDescription, setNewDescription] = useState("");
  const [newCadence, setNewCadence] = useState("quarterly");

  const { data: campaignsData, isLoading } = useQuery({
    queryKey: ["/api/identity/access-reviews"],
    queryFn: () => apiRequest("GET", "/api/identity/access-reviews").then((r) => r.json()),
  });

  const { data: campaignDetail } = useQuery({
    queryKey: ["/api/identity/access-reviews", selectedCampaign],
    queryFn: () => apiRequest("GET", `/api/identity/access-reviews/${selectedCampaign}`).then((r) => r.json()),
    enabled: !!selectedCampaign,
  });

  const createMutation = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      apiRequest("POST", "/api/identity/access-reviews", body).then((r) => r.json()),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/identity/access-reviews"] });
      setShowCreate(false);
      setNewName("");
      setNewDescription("");
      toast({ title: "Campaign created" });
    },
    onError: () => toast({ title: "Failed to create campaign", variant: "destructive" }),
  });

  const startMutation = useMutation({
    mutationFn: (id: string) => apiRequest("POST", `/api/identity/access-reviews/${id}/start`).then((r) => r.json()),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/identity/access-reviews"] });
      toast({ title: "Campaign started" });
    },
    onError: () => toast({ title: "Failed to start campaign", variant: "destructive" }),
  });

  const completeMutation = useMutation({
    mutationFn: (id: string) => apiRequest("POST", `/api/identity/access-reviews/${id}/complete`).then((r) => r.json()),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/identity/access-reviews"] });
      toast({ title: "Campaign completed" });
    },
    onError: () => toast({ title: "Failed to complete campaign", variant: "destructive" }),
  });

  const decideMutation = useMutation({
    mutationFn: (body: { id: string; decision: string; decisionReason?: string }) =>
      apiRequest("PATCH", `/api/identity/access-reviews/entitlements/${body.id}`, {
        decision: body.decision,
        decisionReason: body.decisionReason,
      }).then((r) => r.json()),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/identity/access-reviews"] });
      toast({ title: "Decision recorded" });
    },
    onError: () => toast({ title: "Failed to record decision", variant: "destructive" }),
  });

  const campaigns: AccessReviewCampaign[] = campaignsData?.campaigns || [];

  if (selectedCampaign && campaignDetail) {
    const campaign: AccessReviewCampaign = campaignDetail.campaign;
    const entitlements: AccessReviewEntitlement[] = campaignDetail.entitlements || [];

    return (
      <div className="space-y-4">
        <div className="flex items-center gap-2">
          <Button variant="ghost" size="sm" onClick={() => setSelectedCampaign(null)}>
            Back
          </Button>
          <ChevronRight className="h-4 w-4 text-muted-foreground" />
          <span className="text-sm font-medium">{campaign.name}</span>
          {statusBadge(campaign.status)}
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <Card>
            <CardContent className="p-4 text-center">
              <p className="text-2xl font-bold">{campaign.totalEntitlements}</p>
              <p className="text-xs text-muted-foreground">Total Entitlements</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-4 text-center">
              <p className="text-2xl font-bold">{campaign.reviewedCount}</p>
              <p className="text-xs text-muted-foreground">Reviewed</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-4 text-center">
              <p className="text-2xl font-bold text-green-400">{campaign.approvedCount}</p>
              <p className="text-xs text-muted-foreground">Approved</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-4 text-center">
              <p className="text-2xl font-bold text-red-400">{campaign.revokedCount}</p>
              <p className="text-xs text-muted-foreground">Revoked</p>
            </CardContent>
          </Card>
        </div>

        {campaign.status === "active" && (
          <div className="flex justify-end">
            <Button
              size="sm"
              onClick={() => completeMutation.mutate(campaign.id)}
              disabled={completeMutation.isPending}
            >
              <CheckCircle className="h-4 w-4 mr-1" /> Complete Campaign
            </Button>
          </div>
        )}

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Entitlements Under Review</CardTitle>
          </CardHeader>
          <CardContent>
            {entitlements.length === 0 ? (
              <p className="text-sm text-muted-foreground py-4 text-center">
                {campaign.status === "draft"
                  ? "Start the campaign to populate entitlements from org members."
                  : "No entitlements found."}
              </p>
            ) : (
              <div className="space-y-2">
                {entitlements.map((ent) => (
                  <div key={ent.id} className="flex items-center justify-between p-3 bg-muted/30 rounded-lg">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-medium truncate">{ent.userName}</span>
                        {ent.userEmail && (
                          <span className="text-xs text-muted-foreground truncate">{ent.userEmail}</span>
                        )}
                      </div>
                      <div className="flex items-center gap-2 mt-1">
                        <Badge variant="outline" className="text-xs">
                          {ent.entitlementType}: {ent.entitlementName}
                        </Badge>
                        {riskBadge(ent.riskLevel || "low")}
                        {statusBadge(ent.status)}
                      </div>
                    </div>
                    {ent.status === "pending" && campaign.status === "active" && (
                      <div className="flex items-center gap-1 ml-2">
                        <Button
                          size="sm"
                          variant="outline"
                          className="text-green-400 border-green-500/30 hover:bg-green-500/10"
                          onClick={() => decideMutation.mutate({ id: ent.id, decision: "approve" })}
                          disabled={decideMutation.isPending}
                        >
                          <CheckCircle className="h-3 w-3 mr-1" /> Approve
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          className="text-red-400 border-red-500/30 hover:bg-red-500/10"
                          onClick={() => decideMutation.mutate({ id: ent.id, decision: "revoke" })}
                          disabled={decideMutation.isPending}
                        >
                          <XCircle className="h-3 w-3 mr-1" /> Revoke
                        </Button>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-semibold">Access Review Campaigns</h3>
          <p className="text-sm text-muted-foreground">Automated attestation: does this user still need this role?</p>
        </div>
        <Dialog open={showCreate} onOpenChange={setShowCreate}>
          <DialogTrigger asChild>
            <Button size="sm">
              <Plus className="h-4 w-4 mr-1" /> New Campaign
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Create Access Review Campaign</DialogTitle>
              <DialogDescription>Define a new access review campaign to audit user entitlements.</DialogDescription>
            </DialogHeader>
            <div className="space-y-4 mt-4">
              <div>
                <Label>Campaign Name</Label>
                <Input
                  placeholder="Q1 2026 Access Review"
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                />
              </div>
              <div>
                <Label>Description</Label>
                <Textarea
                  placeholder="Quarterly review of all user entitlements..."
                  value={newDescription}
                  onChange={(e) => setNewDescription(e.target.value)}
                />
              </div>
              <div>
                <Label>Cadence</Label>
                <Select value={newCadence} onValueChange={setNewCadence}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="monthly">Monthly</SelectItem>
                    <SelectItem value="quarterly">Quarterly</SelectItem>
                    <SelectItem value="annual">Annual</SelectItem>
                    <SelectItem value="one_time">One-time</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <Button
                className="w-full"
                onClick={() =>
                  createMutation.mutate({
                    name: newName,
                    description: newDescription,
                    cadence: newCadence,
                  })
                }
                disabled={!newName.trim() || createMutation.isPending}
              >
                Create Campaign
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      {isLoading ? (
        <div className="text-center py-8 text-muted-foreground">Loading campaigns...</div>
      ) : campaigns.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center">
            <FileText className="h-12 w-12 mx-auto text-muted-foreground/30 mb-4" />
            <h3 className="text-lg font-semibold mb-2">No Access Review Campaigns</h3>
            <p className="text-sm text-muted-foreground mb-4">
              Create a campaign to start auditing user entitlements and roles.
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {campaigns.map((c) => (
            <Card
              key={c.id}
              className="cursor-pointer hover:bg-muted/30 transition-colors"
              onClick={() => setSelectedCampaign(c.id)}
            >
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-medium">{c.name}</span>
                      {statusBadge(c.status)}
                      <Badge variant="outline" className="text-xs">
                        {c.cadence}
                      </Badge>
                    </div>
                    {c.description && <p className="text-sm text-muted-foreground mt-1 truncate">{c.description}</p>}
                    <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
                      <span>{c.totalEntitlements} entitlements</span>
                      <span>{c.reviewedCount} reviewed</span>
                      <span className="text-green-400">{c.approvedCount} approved</span>
                      <span className="text-red-400">{c.revokedCount} revoked</span>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 ml-4">
                    {c.status === "draft" && (
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={(e) => {
                          e.stopPropagation();
                          startMutation.mutate(c.id);
                        }}
                        disabled={startMutation.isPending}
                      >
                        <Play className="h-3 w-3 mr-1" /> Start
                      </Button>
                    )}
                    <Eye className="h-4 w-4 text-muted-foreground" />
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

function PamTab() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [showRequest, setShowRequest] = useState(false);
  const [form, setForm] = useState({
    requesterName: "",
    requesterEmail: "",
    targetSystem: "",
    targetHost: "",
    targetAccount: "",
    accessLevel: "read",
    justification: "",
    durationMinutes: 60,
  });

  const { data, isLoading } = useQuery({
    queryKey: ["/api/pam/sessions"],
    queryFn: () => apiRequest("GET", "/api/pam/sessions").then((r) => r.json()),
    refetchInterval: 15000,
  });

  const requestMutation = useMutation({
    mutationFn: (body: Record<string, unknown>) => apiRequest("POST", "/api/pam/sessions", body).then((r) => r.json()),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/pam/sessions"] });
      queryClient.invalidateQueries({ queryKey: ["/api/pam/summary"] });
      setShowRequest(false);
      setForm({
        requesterName: "",
        requesterEmail: "",
        targetSystem: "",
        targetHost: "",
        targetAccount: "",
        accessLevel: "read",
        justification: "",
        durationMinutes: 60,
      });
      toast({ title: "Access request submitted" });
    },
    onError: () => toast({ title: "Failed to submit request", variant: "destructive" }),
  });

  const approveMutation = useMutation({
    mutationFn: (id: string) => apiRequest("POST", `/api/pam/sessions/${id}/approve`).then((r) => r.json()),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/pam/sessions"] });
      queryClient.invalidateQueries({ queryKey: ["/api/pam/summary"] });
      toast({ title: "Session approved" });
    },
    onError: () => toast({ title: "Failed to approve", variant: "destructive" }),
  });

  const denyMutation = useMutation({
    mutationFn: (id: string) =>
      apiRequest("POST", `/api/pam/sessions/${id}/deny`, { reason: "Access denied" }).then((r) => r.json()),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/pam/sessions"] });
      queryClient.invalidateQueries({ queryKey: ["/api/pam/summary"] });
      toast({ title: "Session denied" });
    },
    onError: () => toast({ title: "Failed to deny", variant: "destructive" }),
  });

  const terminateMutation = useMutation({
    mutationFn: (id: string) =>
      apiRequest("POST", `/api/pam/sessions/${id}/terminate`, { reason: "Terminated by admin" }).then((r) => r.json()),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/pam/sessions"] });
      queryClient.invalidateQueries({ queryKey: ["/api/pam/summary"] });
      toast({ title: "Session terminated" });
    },
    onError: () => toast({ title: "Failed to terminate", variant: "destructive" }),
  });

  const sessions: PamSession[] = data?.sessions || [];

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-semibold">Privileged Access Management</h3>
          <p className="text-sm text-muted-foreground">Time-limited elevated access with session recording</p>
        </div>
        <Dialog open={showRequest} onOpenChange={setShowRequest}>
          <DialogTrigger asChild>
            <Button size="sm">
              <KeyRound className="h-4 w-4 mr-1" /> Request Access
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-lg">
            <DialogHeader>
              <DialogTitle>Request Elevated Access</DialogTitle>
              <DialogDescription>Submit a time-limited elevated access request with justification.</DialogDescription>
            </DialogHeader>
            <div className="space-y-3 mt-4">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <Label>Your Name</Label>
                  <Input
                    placeholder="John Doe"
                    value={form.requesterName}
                    onChange={(e) => setForm({ ...form, requesterName: e.target.value })}
                  />
                </div>
                <div>
                  <Label>Email</Label>
                  <Input
                    placeholder="john@example.com"
                    value={form.requesterEmail}
                    onChange={(e) => setForm({ ...form, requesterEmail: e.target.value })}
                  />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <Label>Target System</Label>
                  <Input
                    placeholder="production-db"
                    value={form.targetSystem}
                    onChange={(e) => setForm({ ...form, targetSystem: e.target.value })}
                  />
                </div>
                <div>
                  <Label>Target Host</Label>
                  <Input
                    placeholder="10.0.1.50"
                    value={form.targetHost}
                    onChange={(e) => setForm({ ...form, targetHost: e.target.value })}
                  />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <Label>Target Account</Label>
                  <Input
                    placeholder="root"
                    value={form.targetAccount}
                    onChange={(e) => setForm({ ...form, targetAccount: e.target.value })}
                  />
                </div>
                <div>
                  <Label>Access Level</Label>
                  <Select value={form.accessLevel} onValueChange={(v) => setForm({ ...form, accessLevel: v })}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="read">Read</SelectItem>
                      <SelectItem value="write">Write</SelectItem>
                      <SelectItem value="admin">Admin</SelectItem>
                      <SelectItem value="superadmin">Superadmin</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <div>
                <Label>Duration (minutes)</Label>
                <Input
                  type="number"
                  min={5}
                  max={480}
                  value={form.durationMinutes}
                  onChange={(e) => setForm({ ...form, durationMinutes: parseInt(e.target.value) || 60 })}
                />
              </div>
              <div>
                <Label>Justification</Label>
                <Textarea
                  placeholder="Describe why you need this access (min 10 chars)..."
                  value={form.justification}
                  onChange={(e) => setForm({ ...form, justification: e.target.value })}
                  rows={3}
                />
              </div>
              <Button
                className="w-full"
                onClick={() => requestMutation.mutate(form)}
                disabled={
                  !form.requesterName ||
                  !form.targetSystem ||
                  !form.targetAccount ||
                  form.justification.length < 10 ||
                  requestMutation.isPending
                }
              >
                Submit Request
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      {isLoading ? (
        <div className="text-center py-8 text-muted-foreground">Loading sessions...</div>
      ) : sessions.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center">
            <KeyRound className="h-12 w-12 mx-auto text-muted-foreground/30 mb-4" />
            <h3 className="text-lg font-semibold mb-2">No PAM Sessions</h3>
            <p className="text-sm text-muted-foreground">
              Request elevated access to get started with privileged session management.
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {sessions.map((s) => (
            <Card key={s.id}>
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-medium">{s.requesterName}</span>
                      <ArrowRight className="h-3 w-3 text-muted-foreground" />
                      <span className="font-mono text-sm">
                        {s.targetAccount}@{s.targetSystem}
                      </span>
                      {statusBadge(s.status)}
                    </div>
                    <div className="flex items-center gap-3 mt-2 text-xs text-muted-foreground flex-wrap">
                      <span className="flex items-center gap-1">
                        <Lock className="h-3 w-3" /> {s.accessLevel}
                      </span>
                      <span className="flex items-center gap-1">
                        <Clock className="h-3 w-3" /> {s.durationMinutes}min
                      </span>
                      {s.riskScore !== null && riskMeter(s.riskScore)}
                      <span>{timeAgo(s.createdAt)}</span>
                      {s.expiresAt && (
                        <span className="text-amber-400">Expires: {new Date(s.expiresAt).toLocaleString()}</span>
                      )}
                    </div>
                    <p className="text-xs text-muted-foreground mt-1 truncate">{s.justification}</p>
                  </div>
                  <div className="flex items-center gap-1 ml-2">
                    {s.status === "requested" && (
                      <>
                        <Button
                          size="sm"
                          variant="outline"
                          className="text-green-400 border-green-500/30"
                          onClick={() => approveMutation.mutate(s.id)}
                          disabled={approveMutation.isPending}
                        >
                          <CheckCircle className="h-3 w-3 mr-1" /> Approve
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          className="text-red-400 border-red-500/30"
                          onClick={() => denyMutation.mutate(s.id)}
                          disabled={denyMutation.isPending}
                        >
                          <XCircle className="h-3 w-3 mr-1" /> Deny
                        </Button>
                      </>
                    )}
                    {(s.status === "active" || s.status === "approved") && (
                      <Button
                        size="sm"
                        variant="outline"
                        className="text-red-400 border-red-500/30"
                        onClick={() => terminateMutation.mutate(s.id)}
                        disabled={terminateMutation.isPending}
                      >
                        <XCircle className="h-3 w-3 mr-1" /> Terminate
                      </Button>
                    )}
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

function StaleAccountsTab() {
  const [days, setDays] = useState(90);
  const { data, isLoading } = useQuery({
    queryKey: ["/api/identity/stale-accounts", days],
    queryFn: () => apiRequest("GET", `/api/identity/stale-accounts?days=${days}`).then((r) => r.json()),
  });

  const staleUsers = data?.staleUsers || [];

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-semibold">Stale Account Detection</h3>
          <p className="text-sm text-muted-foreground">
            Accounts inactive &gt;{days} days, service accounts with no rotation
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Label className="text-xs">Threshold (days):</Label>
          <Input
            type="number"
            className="w-20"
            value={days}
            onChange={(e) => setDays(parseInt(e.target.value) || 90)}
            min={1}
          />
        </div>
      </div>

      {isLoading ? (
        <div className="text-center py-8 text-muted-foreground">Scanning accounts...</div>
      ) : staleUsers.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center">
            <CheckCircle className="h-12 w-12 mx-auto text-green-400/30 mb-4" />
            <h3 className="text-lg font-semibold mb-2">No Stale Accounts</h3>
            <p className="text-sm text-muted-foreground">All accounts have been active within the last {days} days.</p>
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">
              {staleUsers.length} Stale Account{staleUsers.length !== 1 ? "s" : ""} Found
            </CardTitle>
            <CardDescription>Accounts with no login activity in over {days} days</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {staleUsers.map((u: any) => (
                <div key={u.id} className="flex items-center justify-between p-3 bg-muted/30 rounded-lg">
                  <div className="flex items-center gap-3">
                    <UserX className="h-4 w-4 text-orange-400" />
                    <div>
                      <span className="text-sm font-medium">
                        {u.firstName} {u.lastName}
                      </span>
                      {u.email && <span className="text-xs text-muted-foreground ml-2">{u.email}</span>}
                      <div className="flex items-center gap-2 mt-1">
                        <Badge
                          variant="outline"
                          className="text-xs bg-orange-500/10 text-orange-400 border-orange-500/30"
                        >
                          {u.daysSinceActivity}d inactive
                        </Badge>
                        {u.isDisabled && (
                          <Badge variant="outline" className="text-xs">
                            Disabled
                          </Badge>
                        )}
                        {!u.mfaEnabled && (
                          <Badge variant="outline" className="text-xs bg-red-500/10 text-red-400 border-red-500/30">
                            No MFA
                          </Badge>
                        )}
                      </div>
                    </div>
                  </div>
                  <div className="text-xs text-muted-foreground">
                    Last login: {u.lastLoginAt ? new Date(u.lastLoginAt).toLocaleDateString() : "Never"}
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function BlastRadiusTab() {
  const [search, setSearch] = useState("");
  const [riskFilter, setRiskFilter] = useState<string>("all");

  const { data, isLoading } = useQuery({
    queryKey: ["/api/identity/risk-profiles", riskFilter, search],
    queryFn: () => {
      const params = new URLSearchParams();
      if (riskFilter !== "all") params.set("riskLevel", riskFilter);
      if (search) params.set("search", search);
      return apiRequest("GET", `/api/identity/risk-profiles?${params}`).then((r) => r.json());
    },
  });

  const profiles: IdentityRiskProfile[] = data?.profiles || [];
  const stats = data?.stats || {};

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div>
          <h3 className="text-lg font-semibold">Blast Radius Calculator</h3>
          <p className="text-sm text-muted-foreground">If this account is breached, what can they reach?</p>
        </div>
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input
              className="pl-8 w-48"
              placeholder="Search user..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
          <Select value={riskFilter} onValueChange={setRiskFilter}>
            <SelectTrigger className="w-32">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Risks</SelectItem>
              <SelectItem value="critical">Critical</SelectItem>
              <SelectItem value="high">High</SelectItem>
              <SelectItem value="medium">Medium</SelectItem>
              <SelectItem value="low">Low</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      {/* Risk Distribution */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <Card>
          <CardContent className="p-3 text-center">
            <p className="text-xl font-bold">{stats.total || 0}</p>
            <p className="text-xs text-muted-foreground">Total Profiled</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-3 text-center">
            <p className="text-xl font-bold text-red-400">{stats.critical || 0}</p>
            <p className="text-xs text-muted-foreground">Critical</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-3 text-center">
            <p className="text-xl font-bold text-orange-400">{stats.high || 0}</p>
            <p className="text-xs text-muted-foreground">High</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-3 text-center">
            <p className="text-xl font-bold text-orange-400">{stats.stale || 0}</p>
            <p className="text-xs text-muted-foreground">Stale</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-3 text-center">
            <p className="text-xl font-bold text-yellow-400">{stats.noMfa || 0}</p>
            <p className="text-xs text-muted-foreground">No MFA</p>
          </CardContent>
        </Card>
      </div>

      {isLoading ? (
        <div className="text-center py-8 text-muted-foreground">Loading profiles...</div>
      ) : profiles.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center">
            <Target className="h-12 w-12 mx-auto text-muted-foreground/30 mb-4" />
            <h3 className="text-lg font-semibold mb-2">No Identity Risk Profiles</h3>
            <p className="text-sm text-muted-foreground">
              Run an identity risk assessment to populate blast radius data.
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-2">
          {profiles.map((p) => (
            <Card key={p.id}>
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-medium">{p.userName}</span>
                      {p.userEmail && <span className="text-xs text-muted-foreground">{p.userEmail}</span>}
                      {riskBadge(p.riskLevel)}
                    </div>
                    <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground flex-wrap">
                      <span className="flex items-center gap-1">
                        <Target className="h-3 w-3" /> Blast Radius: {riskMeter(p.blastRadiusScore || 0)}
                      </span>
                      <span className="flex items-center gap-1">
                        <Server className="h-3 w-3" /> {p.accessibleSystems || 0} systems
                      </span>
                      <span className="flex items-center gap-1">
                        <Network className="h-3 w-3" /> {p.lateralMovementPaths || 0} paths
                      </span>
                      {p.canReachCritical && (
                        <Badge variant="outline" className="text-xs bg-red-500/10 text-red-400 border-red-500/30">
                          Can reach critical
                        </Badge>
                      )}
                      {p.isStale && (
                        <Badge
                          variant="outline"
                          className="text-xs bg-orange-500/10 text-orange-400 border-orange-500/30"
                        >
                          Stale ({p.daysSinceActivity}d)
                        </Badge>
                      )}
                      {!p.mfaEnabled && (
                        <Badge
                          variant="outline"
                          className="text-xs bg-yellow-500/10 text-yellow-400 border-yellow-500/30"
                        >
                          No MFA
                        </Badge>
                      )}
                      {p.hasExcessivePermissions && (
                        <Badge variant="outline" className="text-xs bg-red-500/10 text-red-400 border-red-500/30">
                          Excessive perms
                        </Badge>
                      )}
                    </div>
                  </div>
                  <div className="text-right ml-4">
                    <div className="text-lg font-bold">{p.riskScore}</div>
                    <div className="text-xs text-muted-foreground">Risk Score</div>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

function LateralMovementTab() {
  const { data, isLoading } = useQuery({
    queryKey: ["/api/identity/access-graph"],
    queryFn: () => apiRequest("GET", "/api/identity/access-graph").then((r) => r.json()),
  });

  const nodes = data?.nodes || [];
  const edges = data?.edges || [];

  const userNodes = nodes.filter((n: any) => n.type === "user");
  const systemNodes = nodes.filter((n: any) => n.type === "system");

  return (
    <div className="space-y-4">
      <div>
        <h3 className="text-lg font-semibold">Lateral Movement Risk Graph</h3>
        <p className="text-sm text-muted-foreground">Map which identities can pivot to which systems</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card>
          <CardContent className="p-4 text-center">
            <Users className="h-6 w-6 mx-auto text-blue-400 mb-2" />
            <p className="text-2xl font-bold">{data?.totalUsers || 0}</p>
            <p className="text-xs text-muted-foreground">Identities</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 text-center">
            <Server className="h-6 w-6 mx-auto text-green-400 mb-2" />
            <p className="text-2xl font-bold">{data?.totalSystems || 0}</p>
            <p className="text-xs text-muted-foreground">Systems</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 text-center">
            <Network className="h-6 w-6 mx-auto text-amber-400 mb-2" />
            <p className="text-2xl font-bold">{data?.totalEdges || 0}</p>
            <p className="text-xs text-muted-foreground">Access Paths</p>
          </CardContent>
        </Card>
      </div>

      {isLoading ? (
        <div className="text-center py-8 text-muted-foreground">Loading access graph...</div>
      ) : edges.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center">
            <Network className="h-12 w-12 mx-auto text-muted-foreground/30 mb-4" />
            <h3 className="text-lg font-semibold mb-2">No Access Graph Data</h3>
            <p className="text-sm text-muted-foreground">
              Add access graph entries to visualize lateral movement risk paths.
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* User nodes */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <Users className="h-4 w-4" /> Identity Nodes
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2 max-h-80 overflow-y-auto">
                {userNodes.map((node: any) => {
                  const userEdges = edges.filter((e: any) => e.source === node.id);
                  const hasAdmin = userEdges.some((e: any) => ["admin", "superadmin"].includes(e.permissionLevel));
                  return (
                    <div key={node.id} className="p-2 bg-muted/30 rounded-lg flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Shield className={`h-4 w-4 ${hasAdmin ? "text-red-400" : "text-blue-400"}`} />
                        <span className="text-sm">{node.name}</span>
                      </div>
                      <Badge variant="outline" className="text-xs">
                        {userEdges.length} path{userEdges.length !== 1 ? "s" : ""}
                      </Badge>
                    </div>
                  );
                })}
              </div>
            </CardContent>
          </Card>

          {/* System nodes */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <Server className="h-4 w-4" /> System Nodes
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2 max-h-80 overflow-y-auto">
                {systemNodes.map((node: any) => {
                  const systemEdges = edges.filter((e: any) => e.target === node.id);
                  const hasAdmin = systemEdges.some((e: any) => ["admin", "superadmin"].includes(e.permissionLevel));
                  return (
                    <div key={node.id} className="p-2 bg-muted/30 rounded-lg flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Server className={`h-4 w-4 ${hasAdmin ? "text-red-400" : "text-green-400"}`} />
                        <span className="text-sm font-mono">{node.name}</span>
                      </div>
                      <Badge variant="outline" className="text-xs">
                        {systemEdges.length} accessor{systemEdges.length !== 1 ? "s" : ""}
                      </Badge>
                    </div>
                  );
                })}
              </div>
            </CardContent>
          </Card>

          {/* Edge list */}
          <Card className="lg:col-span-2">
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <Network className="h-4 w-4" /> Access Paths (sorted by risk weight)
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2 max-h-96 overflow-y-auto">
                {edges.map((edge: any) => {
                  const sourceNode = userNodes.find((n: any) => n.id === edge.source);
                  return (
                    <div key={edge.id} className="flex items-center justify-between p-2 bg-muted/30 rounded-lg">
                      <div className="flex items-center gap-2 text-sm">
                        <span>{sourceNode?.name || edge.source}</span>
                        <ArrowRight className="h-3 w-3 text-muted-foreground" />
                        <span className="font-mono">{edge.target}</span>
                        <Badge variant="outline" className="text-xs">
                          {edge.permissionLevel}
                        </Badge>
                        <Badge variant="outline" className="text-xs">
                          {edge.accessType}
                        </Badge>
                        {edge.grantedVia && (
                          <span className="text-xs text-muted-foreground">via {edge.grantedVia}</span>
                        )}
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-muted-foreground">Risk: {edge.riskWeight}</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}

function ScimTab() {
  const { data, isLoading } = useQuery({
    queryKey: ["/api/identity/scim/logs"],
    queryFn: () => apiRequest("GET", "/api/identity/scim/logs").then((r) => r.json()),
  });

  const logs: ScimLog[] = data?.logs || [];
  const stats = data?.stats || {};

  const providerLabel: Record<string, string> = {
    azure_ad: "Azure AD",
    okta: "Okta",
    google_workspace: "Google Workspace",
    onelogin: "OneLogin",
    jumpcloud: "JumpCloud",
  };

  return (
    <div className="space-y-4">
      <div>
        <h3 className="text-lg font-semibold">SCIM 2.0 Provisioning</h3>
        <p className="text-sm text-muted-foreground">Auto-sync users from Azure AD, Okta, and Google Workspace</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card>
          <CardContent className="p-4 text-center">
            <p className="text-2xl font-bold">{stats.total || 0}</p>
            <p className="text-xs text-muted-foreground">Total Events</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 text-center">
            <p className="text-2xl font-bold text-green-400">{stats.successful || 0}</p>
            <p className="text-xs text-muted-foreground">Successful</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 text-center">
            <p className="text-2xl font-bold text-red-400">{stats.failed || 0}</p>
            <p className="text-xs text-muted-foreground">Failed</p>
          </CardContent>
        </Card>
      </div>

      {isLoading ? (
        <div className="text-center py-8 text-muted-foreground">Loading SCIM logs...</div>
      ) : logs.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center">
            <RefreshCw className="h-12 w-12 mx-auto text-muted-foreground/30 mb-4" />
            <h3 className="text-lg font-semibold mb-2">No SCIM Events</h3>
            <p className="text-sm text-muted-foreground max-w-md mx-auto">
              Configure your identity provider (Okta, Azure AD, or Google Workspace) to push SCIM provisioning events to
              the /api/identity/scim/provision endpoint.
            </p>
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Provisioning Events</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2 max-h-96 overflow-y-auto">
              {logs.map((log) => (
                <div key={log.id} className="flex items-center justify-between p-3 bg-muted/30 rounded-lg">
                  <div className="flex items-center gap-3">
                    {log.success ? (
                      <CheckCircle className="h-4 w-4 text-green-400" />
                    ) : (
                      <XCircle className="h-4 w-4 text-red-400" />
                    )}
                    <div>
                      <div className="flex items-center gap-2">
                        <Badge variant="outline" className="text-xs">
                          {providerLabel[log.provider] || log.provider}
                        </Badge>
                        <Badge variant="outline" className="text-xs">
                          {log.operationType}
                        </Badge>
                      </div>
                      <p className="text-sm mt-1">
                        {log.externalUserName || log.externalEmail || log.groupName || "Unknown target"}
                      </p>
                      {log.errorMessage && <p className="text-xs text-red-400 mt-1">{log.errorMessage}</p>}
                    </div>
                  </div>
                  <span className="text-xs text-muted-foreground">{timeAgo(log.createdAt)}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ============================================================================
// Main Page
// ============================================================================

export default function IdentityGovernancePage() {
  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      <div className="flex items-center gap-3">
        <Shield className="h-7 w-7 text-primary" />
        <div>
          <h1 className="text-2xl font-bold">Identity Threat Detection & PAM</h1>
          <p className="text-sm text-muted-foreground">
            Identity governance, privileged access management, and lateral movement risk analysis
          </p>
        </div>
      </div>

      <SummaryCards />

      <Tabs defaultValue="pam" className="space-y-4">
        <TabsList className="grid w-full grid-cols-6">
          <TabsTrigger value="pam" className="text-xs">
            <KeyRound className="h-3 w-3 mr-1" /> PAM
          </TabsTrigger>
          <TabsTrigger value="reviews" className="text-xs">
            <FileText className="h-3 w-3 mr-1" /> Access Reviews
          </TabsTrigger>
          <TabsTrigger value="stale" className="text-xs">
            <UserX className="h-3 w-3 mr-1" /> Stale Accounts
          </TabsTrigger>
          <TabsTrigger value="blast" className="text-xs">
            <Target className="h-3 w-3 mr-1" /> Blast Radius
          </TabsTrigger>
          <TabsTrigger value="lateral" className="text-xs">
            <Network className="h-3 w-3 mr-1" /> Lateral Movement
          </TabsTrigger>
          <TabsTrigger value="scim" className="text-xs">
            <RefreshCw className="h-3 w-3 mr-1" /> SCIM
          </TabsTrigger>
        </TabsList>

        <TabsContent value="pam">
          <PamTab />
        </TabsContent>
        <TabsContent value="reviews">
          <AccessReviewsTab />
        </TabsContent>
        <TabsContent value="stale">
          <StaleAccountsTab />
        </TabsContent>
        <TabsContent value="blast">
          <BlastRadiusTab />
        </TabsContent>
        <TabsContent value="lateral">
          <LateralMovementTab />
        </TabsContent>
        <TabsContent value="scim">
          <ScimTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import {
  Shield,
  ShieldCheck,
  FileText,
  Download,
  Clock,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  RefreshCw,
  Plus,
  Trash2,
  Eye,
  ArrowRight,
  Calendar,
  Users,
  Lock,
  Globe,
  Search,
  Filter,
  ExternalLink,
  Award,
  GitBranch,
  Activity,
  BarChart3,
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { Skeleton } from "@/components/ui/skeleton";

type TabId = "overview" | "artifacts" | "mappings" | "audit" | "freshness";

interface Framework {
  id: string;
  name: string;
  shortName: string;
  description: string;
  status: "certified" | "in_progress" | "planned" | "not_applicable";
  certificationDate: string | null;
  expirationDate: string | null;
  auditor: string | null;
  scopeDescription: string;
  controls: FrameworkControl[];
}

interface FrameworkControl {
  id: string;
  frameworkId: string;
  controlId: string;
  title: string;
  description: string;
  status: "implemented" | "partial" | "planned" | "not_applicable";
  evidence: string[];
  mappings: ControlMapping[];
}

interface ControlMapping {
  sourceFramework: string;
  sourceControlId: string;
  targetFramework: string;
  targetControlId: string;
  relationship: "equivalent" | "partial" | "related";
}

interface Artifact {
  id: string;
  orgId: string;
  category: string;
  title: string;
  description: string;
  version: string;
  fileName: string;
  fileSize: number;
  mimeType: string;
  uploadedBy: string;
  uploadedAt: string;
  lastReviewedAt: string | null;
  nextReviewDue: string | null;
  freshnessSlaDays: number;
  status: "current" | "expiring_soon" | "expired" | "under_review";
  accessLevel: "public" | "nda_required" | "customer_only" | "internal";
  downloadCount: number;
  tags: string[];
}

interface DownloadEntry {
  id: string;
  orgId: string;
  artifactId: string;
  artifactTitle: string;
  downloadedBy: string;
  downloadedByEmail: string;
  downloadedAt: string;
  ipAddress: string;
  userAgent: string;
  accessLevel: string;
}

interface FreshnessAlert {
  artifactId: string;
  artifactTitle: string;
  category: string;
  status: "current" | "expiring_soon" | "expired";
  lastReviewedAt: string | null;
  nextReviewDue: string | null;
  daysUntilExpiry: number | null;
  freshnessSlaDays: number;
}

interface Summary {
  totalFrameworks: number;
  certifiedFrameworks: number;
  inProgressFrameworks: number;
  totalArtifacts: number;
  currentArtifacts: number;
  expiringSoonArtifacts: number;
  expiredArtifacts: number;
  totalDownloads: number;
  totalControlMappings: number;
  /* 79.4 — auto-update from platform data */
  lastSyncedAt?: string | null;
  syncSource?: string;
  /* 79.5 — access analytics */
  uniqueVisitors?: number;
  avgSessionDuration?: number;
}

function unwrap(data: unknown): any {
  if (data && typeof data === "object" && "data" in data) return (data as any).data;
  return data;
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

function formatDate(iso: string | null): string {
  if (!iso) return "N/A";
  return new Date(iso).toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" });
}

function relativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  return `${days}d ago`;
}

const TABS: { id: TabId; label: string; icon: typeof Shield }[] = [
  { id: "overview", label: "Compliance Overview", icon: ShieldCheck },
  { id: "artifacts", label: "Security Artifacts", icon: FileText },
  { id: "mappings", label: "Control Mappings", icon: GitBranch },
  { id: "audit", label: "Download Audit Log", icon: Eye },
  { id: "freshness", label: "Freshness Management", icon: Clock },
];

const STATUS_COLORS: Record<string, string> = {
  certified: "text-emerald-400 bg-emerald-500/10 border-emerald-500/30",
  in_progress: "text-amber-400 bg-amber-500/10 border-amber-500/30",
  planned: "text-blue-400 bg-blue-500/10 border-blue-500/30",
  not_applicable: "text-gray-400 bg-gray-500/10 border-gray-500/30",
  implemented: "text-emerald-400 bg-emerald-500/10 border-emerald-500/30",
  partial: "text-amber-400 bg-amber-500/10 border-amber-500/30",
  current: "text-emerald-400 bg-emerald-500/10 border-emerald-500/30",
  expiring_soon: "text-amber-400 bg-amber-500/10 border-amber-500/30",
  expired: "text-red-400 bg-red-500/10 border-red-500/30",
  under_review: "text-blue-400 bg-blue-500/10 border-blue-500/30",
};

const ACCESS_ICONS: Record<string, typeof Globe> = {
  public: Globe,
  nda_required: Lock,
  customer_only: Users,
  internal: Shield,
};

const CATEGORY_LABELS: Record<string, string> = {
  soc2_report: "SOC 2 Report",
  iso27001_cert: "ISO 27001 Certificate",
  pentest_report: "Penetration Test Report",
  security_architecture: "Security Architecture",
  incident_response_plan: "Incident Response Plan",
  privacy_policy: "Privacy Policy",
  data_processing_agreement: "Data Processing Agreement",
  business_continuity_plan: "Business Continuity Plan",
  vulnerability_disclosure: "Vulnerability Disclosure",
  encryption_policy: "Encryption Policy",
  access_control_policy: "Access Control Policy",
  vendor_security_assessment: "Vendor Security Assessment",
  gdpr_dpia: "GDPR DPIA",
  hipaa_baa: "HIPAA BAA",
  other: "Other",
};

function OverviewTab() {
  const { data: frameworksRaw, isLoading: frameworksLoading } = useQuery({
    queryKey: ["/api/trust-center/frameworks"],
    queryFn: () => apiRequest("GET", "/api/trust-center/frameworks").then((r) => r.json()),
  });
  const { data: summaryRaw, isLoading: summaryLoading } = useQuery({
    queryKey: ["/api/trust-center/summary"],
    queryFn: () => apiRequest("GET", "/api/trust-center/summary").then((r) => r.json()),
  });

  const frameworks: Framework[] = unwrap(frameworksRaw) || [];
  const summary: Summary | null = unwrap(summaryRaw);

  if (frameworksLoading || summaryLoading) {
    return (
      <div className="space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-24 rounded-xl" />
          ))}
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} className="h-48 rounded-xl" />
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {summary && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="rounded-xl border border-border/50 bg-card/50 p-4">
            <div className="flex items-center gap-3 mb-2">
              <div className="p-2 rounded-lg bg-emerald-500/10">
                <Award className="h-5 w-5 text-emerald-400" />
              </div>
              <span className="text-sm text-muted-foreground">Certified Frameworks</span>
            </div>
            <p className="text-2xl font-bold">
              {summary.certifiedFrameworks}
              <span className="text-sm text-muted-foreground font-normal ml-1">/ {summary.totalFrameworks}</span>
            </p>
          </div>
          <div className="rounded-xl border border-border/50 bg-card/50 p-4">
            <div className="flex items-center gap-3 mb-2">
              <div className="p-2 rounded-lg bg-cyan-500/10">
                <FileText className="h-5 w-5 text-cyan-400" />
              </div>
              <span className="text-sm text-muted-foreground">Security Artifacts</span>
            </div>
            <p className="text-2xl font-bold">{summary.totalArtifacts}</p>
          </div>
          <div className="rounded-xl border border-border/50 bg-card/50 p-4">
            <div className="flex items-center gap-3 mb-2">
              <div className="p-2 rounded-lg bg-amber-500/10">
                <AlertTriangle className="h-5 w-5 text-amber-400" />
              </div>
              <span className="text-sm text-muted-foreground">Expiring Soon</span>
            </div>
            <p className="text-2xl font-bold text-amber-400">
              {summary.expiringSoonArtifacts}
              {summary.expiredArtifacts > 0 && (
                <span className="text-sm text-red-400 font-normal ml-2">+{summary.expiredArtifacts} expired</span>
              )}
            </p>
          </div>
          <div className="rounded-xl border border-border/50 bg-card/50 p-4">
            <div className="flex items-center gap-3 mb-2">
              <div className="p-2 rounded-lg bg-purple-500/10">
                <Download className="h-5 w-5 text-purple-400" />
              </div>
              <span className="text-sm text-muted-foreground">Total Downloads</span>
            </div>
            <p className="text-2xl font-bold">{summary.totalDownloads.toLocaleString()}</p>
          </div>
        </div>
      )}

      {/* 79.4 — auto-update sync status from platform data */}
      {summary?.lastSyncedAt && (
        <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-cyan-500/5 border border-cyan-500/20 text-xs text-muted-foreground">
          <Activity className="h-3.5 w-3.5 text-cyan-400" />
          <span>
            Last synced from {summary.syncSource || "platform"}: {formatDate(summary.lastSyncedAt)}
          </span>
        </div>
      )}

      {/* 79.5 — access analytics summary */}
      {(summary?.uniqueVisitors ?? 0) > 0 && (
        <div className="grid grid-cols-2 gap-4">
          <div className="rounded-xl border border-border/50 bg-card/50 p-4">
            <div className="flex items-center gap-2 mb-1">
              <Users className="h-4 w-4 text-indigo-400" />
              <span className="text-xs text-muted-foreground">Unique Visitors</span>
            </div>
            <p className="text-xl font-bold">{summary?.uniqueVisitors?.toLocaleString()}</p>
          </div>
          <div className="rounded-xl border border-border/50 bg-card/50 p-4">
            <div className="flex items-center gap-2 mb-1">
              <Clock className="h-4 w-4 text-indigo-400" />
              <span className="text-xs text-muted-foreground">Avg Session Duration</span>
            </div>
            <p className="text-xl font-bold">{summary?.avgSessionDuration ?? 0}s</p>
          </div>
        </div>
      )}

      <div>
        <h3 className="text-lg font-semibold mb-4">Compliance Frameworks</h3>
        {frameworks.length === 0 ? (
          <div className="text-center py-12 text-muted-foreground">
            <ShieldCheck className="h-12 w-12 mx-auto mb-3 opacity-30" />
            <p>No compliance frameworks configured</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {frameworks.map((fw) => (
              <div
                key={fw.id}
                className="rounded-xl border border-border/50 bg-card/50 p-5 hover:border-cyan-500/30 transition-colors"
              >
                <div className="flex items-start justify-between mb-3">
                  <div>
                    <h4 className="font-semibold">{fw.shortName}</h4>
                    <p className="text-xs text-muted-foreground mt-0.5">{fw.name}</p>
                  </div>
                  <span className={`text-xs px-2 py-1 rounded-full border ${STATUS_COLORS[fw.status] || ""}`}>
                    {fw.status.replace(/_/g, " ")}
                  </span>
                </div>
                <p className="text-xs text-muted-foreground mb-3 line-clamp-2">{fw.description}</p>
                <div className="space-y-1.5 text-xs">
                  {fw.certificationDate && (
                    <div className="flex items-center gap-2 text-muted-foreground">
                      <Calendar className="h-3.5 w-3.5" />
                      <span>Certified: {formatDate(fw.certificationDate)}</span>
                    </div>
                  )}
                  {fw.expirationDate && (
                    <div className="flex items-center gap-2 text-muted-foreground">
                      <Clock className="h-3.5 w-3.5" />
                      <span>Expires: {formatDate(fw.expirationDate)}</span>
                    </div>
                  )}
                  {fw.auditor && (
                    <div className="flex items-center gap-2 text-muted-foreground">
                      <Users className="h-3.5 w-3.5" />
                      <span>Auditor: {fw.auditor}</span>
                    </div>
                  )}
                  <div className="flex items-center gap-2 text-muted-foreground">
                    <Shield className="h-3.5 w-3.5" />
                    <span>{fw.controls.length} controls mapped</span>
                  </div>
                </div>
                {fw.controls.length > 0 && (
                  <div className="mt-3 pt-3 border-t border-border/30">
                    <div className="flex gap-2">
                      <span className="text-xs text-emerald-400">
                        {fw.controls.filter((c) => c.status === "implemented").length} implemented
                      </span>
                      {fw.controls.filter((c) => c.status === "partial").length > 0 && (
                        <span className="text-xs text-amber-400">
                          {fw.controls.filter((c) => c.status === "partial").length} partial
                        </span>
                      )}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function ArtifactsTab() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [searchQuery, setSearchQuery] = useState("");
  const [categoryFilter, setCategoryFilter] = useState<string>("all");

  const { data: artifactsRaw, isLoading } = useQuery({
    queryKey: ["/api/trust-center/artifacts"],
    queryFn: () => apiRequest("GET", "/api/trust-center/artifacts").then((r) => r.json()),
  });

  const downloadMutation = useMutation({
    mutationFn: (artifactId: string) =>
      apiRequest("POST", `/api/trust-center/artifacts/${artifactId}/download`).then((r) => r.json()),
    onSuccess: (_data, artifactId) => {
      toast({ title: "Download recorded", description: `Artifact ${artifactId} download logged` });
      queryClient.invalidateQueries({ queryKey: ["/api/trust-center/artifacts"] });
    },
    onError: () => {
      toast({ title: "Download failed", description: "Failed to record download", variant: "destructive" });
    },
  });

  const artifacts: Artifact[] = unwrap(artifactsRaw) || [];

  const filtered = artifacts.filter((a) => {
    if (categoryFilter !== "all" && a.category !== categoryFilter) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return (
        a.title.toLowerCase().includes(q) ||
        a.description.toLowerCase().includes(q) ||
        a.tags.some((t) => t.toLowerCase().includes(q))
      );
    }
    return true;
  });

  const categories = Array.from(new Set(artifacts.map((a) => a.category)));

  if (isLoading) {
    return (
      <div className="space-y-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={i} className="h-32 rounded-xl" />
        ))}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <input
            type="text"
            placeholder="Search artifacts..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-4 py-2 text-sm rounded-lg border border-border/50 bg-card/50 focus:outline-none focus:ring-1 focus:ring-cyan-500/50"
          />
        </div>
        <div className="relative">
          <Filter className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="pl-9 pr-8 py-2 text-sm rounded-lg border border-border/50 bg-card/50 focus:outline-none focus:ring-1 focus:ring-cyan-500/50 appearance-none"
          >
            <option value="all">All Categories</option>
            {categories.map((c) => (
              <option key={c} value={c}>
                {CATEGORY_LABELS[c] || c}
              </option>
            ))}
          </select>
        </div>
      </div>

      {filtered.length === 0 ? (
        <div className="text-center py-12 text-muted-foreground">
          <FileText className="h-12 w-12 mx-auto mb-3 opacity-30" />
          <p>{searchQuery ? "No artifacts match your search" : "No security artifacts available"}</p>
        </div>
      ) : (
        <div className="space-y-3">
          {filtered.map((artifact) => {
            const AccessIcon = ACCESS_ICONS[artifact.accessLevel] || Globe;
            return (
              <div
                key={artifact.id}
                className="rounded-xl border border-border/50 bg-card/50 p-4 hover:border-cyan-500/30 transition-colors"
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <h4 className="font-semibold truncate">{artifact.title}</h4>
                      <span
                        className={`text-xs px-2 py-0.5 rounded-full border shrink-0 ${STATUS_COLORS[artifact.status] || ""}`}
                      >
                        {artifact.status.replace(/_/g, " ")}
                      </span>
                    </div>
                    <p className="text-xs text-muted-foreground mb-2 line-clamp-1">{artifact.description}</p>
                    <div className="flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
                      <span className="flex items-center gap-1">
                        <FileText className="h-3.5 w-3.5" />
                        {CATEGORY_LABELS[artifact.category] || artifact.category}
                      </span>
                      <span className="flex items-center gap-1">
                        <AccessIcon className="h-3.5 w-3.5" />
                        {artifact.accessLevel.replace(/_/g, " ")}
                      </span>
                      <span>v{artifact.version}</span>
                      <span>{formatBytes(artifact.fileSize)}</span>
                      <span className="flex items-center gap-1">
                        <Download className="h-3.5 w-3.5" />
                        {artifact.downloadCount} downloads
                      </span>
                      {/* 79.2 — NDA gate indicator */}
                      {artifact.accessLevel === "nda_required" && (
                        <span className="flex items-center gap-1 text-amber-400">
                          <Lock className="h-3.5 w-3.5" />
                          NDA Required
                        </span>
                      )}
                      {/* 79.3 — expiration tracking */}
                      {artifact.nextReviewDue && (
                        <span className="flex items-center gap-1">
                          <Calendar className="h-3.5 w-3.5" />
                          Review by {formatDate(artifact.nextReviewDue)}
                        </span>
                      )}
                    </div>
                    {artifact.tags.length > 0 && (
                      <div className="flex flex-wrap gap-1 mt-2">
                        {artifact.tags.map((tag) => (
                          <span
                            key={tag}
                            className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20"
                          >
                            {tag}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                  <button
                    onClick={() => downloadMutation.mutate(artifact.id)}
                    disabled={downloadMutation.isPending}
                    className="ml-4 shrink-0 flex items-center gap-1.5 px-3 py-2 text-xs rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 hover:bg-cyan-500/20 active:bg-cyan-500/30 transition-colors disabled:opacity-50"
                    aria-label={`Download ${artifact.title}`}
                  >
                    <Download className="h-3.5 w-3.5" />
                    Download
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function MappingsTab() {
  const [selectedFramework, setSelectedFramework] = useState<string>("all");

  const { data: frameworksRaw, isLoading: frameworksLoading } = useQuery({
    queryKey: ["/api/trust-center/frameworks"],
    queryFn: () => apiRequest("GET", "/api/trust-center/frameworks").then((r) => r.json()),
  });

  const { data: mappingsRaw, isLoading: mappingsLoading } = useQuery({
    queryKey: ["/api/trust-center/control-mappings", selectedFramework],
    queryFn: () => {
      const url =
        selectedFramework !== "all"
          ? `/api/trust-center/control-mappings?frameworkId=${selectedFramework}`
          : "/api/trust-center/control-mappings";
      return apiRequest("GET", url).then((r) => r.json());
    },
  });

  const frameworks: Framework[] = unwrap(frameworksRaw) || [];
  const mappings: ControlMapping[] = unwrap(mappingsRaw) || [];

  if (frameworksLoading || mappingsLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-10 w-64 rounded-lg" />
        <Skeleton className="h-64 rounded-xl" />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <label className="text-sm text-muted-foreground">Filter by framework:</label>
        <select
          value={selectedFramework}
          onChange={(e) => setSelectedFramework(e.target.value)}
          className="px-3 py-2 text-sm rounded-lg border border-border/50 bg-card/50 focus:outline-none focus:ring-1 focus:ring-cyan-500/50"
        >
          <option value="all">All Frameworks</option>
          {frameworks.map((fw) => (
            <option key={fw.id} value={fw.id}>
              {fw.shortName}
            </option>
          ))}
        </select>
        <span className="text-xs text-muted-foreground">{mappings.length} mappings found</span>
      </div>

      {mappings.length === 0 ? (
        <div className="text-center py-12 text-muted-foreground">
          <GitBranch className="h-12 w-12 mx-auto mb-3 opacity-30" />
          <p>No control mappings found for this framework</p>
        </div>
      ) : (
        <div className="rounded-xl border border-border/50 overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border/50 bg-card/80">
                <th className="text-left p-3 font-medium text-muted-foreground">Source Framework</th>
                <th className="text-left p-3 font-medium text-muted-foreground">Source Control</th>
                <th className="text-center p-3 font-medium text-muted-foreground">Relationship</th>
                <th className="text-left p-3 font-medium text-muted-foreground">Target Framework</th>
                <th className="text-left p-3 font-medium text-muted-foreground">Target Control</th>
              </tr>
            </thead>
            <tbody>
              {mappings.map((m, idx) => (
                <tr key={idx} className="border-b border-border/30 hover:bg-card/50 transition-colors">
                  <td className="p-3 font-medium">{m.sourceFramework}</td>
                  <td className="p-3 font-mono text-xs">{m.sourceControlId}</td>
                  <td className="p-3 text-center">
                    <span
                      className={`inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full border ${
                        m.relationship === "equivalent"
                          ? "text-emerald-400 bg-emerald-500/10 border-emerald-500/30"
                          : m.relationship === "partial"
                            ? "text-amber-400 bg-amber-500/10 border-amber-500/30"
                            : "text-blue-400 bg-blue-500/10 border-blue-500/30"
                      }`}
                    >
                      <ArrowRight className="h-3 w-3" />
                      {m.relationship}
                    </span>
                  </td>
                  <td className="p-3 font-medium">{m.targetFramework}</td>
                  <td className="p-3 font-mono text-xs">{m.targetControlId}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {selectedFramework !== "all" && (
        <div className="mt-6">
          <h4 className="text-sm font-semibold mb-3">Framework Controls</h4>
          {(() => {
            const fw = frameworks.find((f) => f.id === selectedFramework);
            if (!fw || fw.controls.length === 0) {
              return <p className="text-sm text-muted-foreground">No controls defined for this framework.</p>;
            }
            return (
              <div className="space-y-2">
                {fw.controls.map((ctrl) => (
                  <div key={ctrl.id} className="rounded-lg border border-border/50 bg-card/50 p-3">
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-mono text-xs font-semibold">{ctrl.controlId}</span>
                      <span className={`text-xs px-2 py-0.5 rounded-full border ${STATUS_COLORS[ctrl.status] || ""}`}>
                        {ctrl.status}
                      </span>
                    </div>
                    <h5 className="text-sm font-medium">{ctrl.title}</h5>
                    <p className="text-xs text-muted-foreground mt-1">{ctrl.description}</p>
                    {ctrl.evidence.length > 0 && (
                      <div className="mt-2 flex flex-wrap gap-1">
                        {ctrl.evidence.map((e) => (
                          <span
                            key={e}
                            className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                          >
                            {e}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            );
          })()}
        </div>
      )}
    </div>
  );
}

function AuditLogTab() {
  const { data: entriesRaw, isLoading } = useQuery({
    queryKey: ["/api/trust-center/download-audit-log"],
    queryFn: () => apiRequest("GET", "/api/trust-center/download-audit-log?limit=200").then((r) => r.json()),
  });

  const entries: DownloadEntry[] = unwrap(entriesRaw) || [];

  if (isLoading) {
    return (
      <div className="space-y-3">
        {Array.from({ length: 5 }).map((_, i) => (
          <Skeleton key={i} className="h-16 rounded-xl" />
        ))}
      </div>
    );
  }

  if (entries.length === 0) {
    return (
      <div className="text-center py-12 text-muted-foreground">
        <Eye className="h-12 w-12 mx-auto mb-3 opacity-30" />
        <p>No download activity recorded yet</p>
        <p className="text-xs mt-1">Downloads will appear here when users access security artifacts</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* 79.5 — access analytics: download audit with summary */}
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">{entries.length} download records</p>
        <div className="flex items-center gap-3 text-xs text-muted-foreground">
          <span className="flex items-center gap-1">
            <BarChart3 className="h-3.5 w-3.5" />
            {new Set(entries.map((e) => e.downloadedByEmail)).size} unique downloaders
          </span>
          <span className="flex items-center gap-1">
            <FileText className="h-3.5 w-3.5" />
            {new Set(entries.map((e) => e.artifactId)).size} artifacts accessed
          </span>
        </div>
      </div>

      <div className="rounded-xl border border-border/50 overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border/50 bg-card/80">
              <th className="text-left p-3 font-medium text-muted-foreground">Artifact</th>
              <th className="text-left p-3 font-medium text-muted-foreground">Downloaded By</th>
              <th className="text-left p-3 font-medium text-muted-foreground">Time</th>
              <th className="text-left p-3 font-medium text-muted-foreground">Access Level</th>
              <th className="text-left p-3 font-medium text-muted-foreground">IP Address</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((entry) => (
              <tr key={entry.id} className="border-b border-border/30 hover:bg-card/50 transition-colors">
                <td className="p-3">
                  <span className="font-medium">{entry.artifactTitle}</span>
                </td>
                <td className="p-3 text-muted-foreground">{entry.downloadedByEmail}</td>
                <td className="p-3 text-muted-foreground">{relativeTime(entry.downloadedAt)}</td>
                <td className="p-3">
                  <span className="text-xs px-2 py-0.5 rounded-full border border-border/50 bg-card/50">
                    {entry.accessLevel.replace(/_/g, " ")}
                  </span>
                </td>
                <td className="p-3 font-mono text-xs text-muted-foreground">{entry.ipAddress}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function FreshnessTab() {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: alertsRaw, isLoading } = useQuery({
    queryKey: ["/api/trust-center/freshness"],
    queryFn: () => apiRequest("GET", "/api/trust-center/freshness").then((r) => r.json()),
  });

  const reviewMutation = useMutation({
    mutationFn: (artifactId: string) =>
      apiRequest("POST", `/api/trust-center/artifacts/${artifactId}/review`).then((r) => r.json()),
    onSuccess: () => {
      toast({ title: "Artifact reviewed", description: "Freshness SLA timer has been reset" });
      queryClient.invalidateQueries({ queryKey: ["/api/trust-center/freshness"] });
      queryClient.invalidateQueries({ queryKey: ["/api/trust-center/artifacts"] });
      queryClient.invalidateQueries({ queryKey: ["/api/trust-center/summary"] });
    },
    onError: () => {
      toast({ title: "Review failed", description: "Failed to mark artifact as reviewed", variant: "destructive" });
    },
  });

  const alerts: FreshnessAlert[] = unwrap(alertsRaw) || [];
  const expired = alerts.filter((a) => a.status === "expired");
  const expiringSoon = alerts.filter((a) => a.status === "expiring_soon");
  const current = alerts.filter((a) => a.status === "current");

  if (isLoading) {
    return (
      <div className="space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {Array.from({ length: 3 }).map((_, i) => (
            <Skeleton key={i} className="h-20 rounded-xl" />
          ))}
        </div>
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={i} className="h-24 rounded-xl" />
        ))}
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="rounded-xl border border-red-500/30 bg-red-500/5 p-4">
          <div className="flex items-center gap-2 mb-1">
            <XCircle className="h-5 w-5 text-red-400" />
            <span className="text-sm font-medium text-red-400">Expired</span>
          </div>
          <p className="text-2xl font-bold text-red-400">{expired.length}</p>
          <p className="text-xs text-muted-foreground">Require immediate review</p>
        </div>
        <div className="rounded-xl border border-amber-500/30 bg-amber-500/5 p-4">
          <div className="flex items-center gap-2 mb-1">
            <AlertTriangle className="h-5 w-5 text-amber-400" />
            <span className="text-sm font-medium text-amber-400">Expiring Soon</span>
          </div>
          <p className="text-2xl font-bold text-amber-400">{expiringSoon.length}</p>
          <p className="text-xs text-muted-foreground">Due within 30 days</p>
        </div>
        <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/5 p-4">
          <div className="flex items-center gap-2 mb-1">
            <CheckCircle2 className="h-5 w-5 text-emerald-400" />
            <span className="text-sm font-medium text-emerald-400">Current</span>
          </div>
          <p className="text-2xl font-bold text-emerald-400">{current.length}</p>
          <p className="text-xs text-muted-foreground">Within SLA window</p>
        </div>
      </div>

      {expired.length > 0 && (
        <div>
          <h4 className="text-sm font-semibold text-red-400 mb-3 flex items-center gap-2">
            <XCircle className="h-4 w-4" />
            Expired Artifacts ({expired.length})
          </h4>
          <div className="space-y-2">
            {expired.map((alert) => (
              <div key={alert.artifactId} className="rounded-lg border border-red-500/30 bg-red-500/5 p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h5 className="font-medium">{alert.artifactTitle}</h5>
                    <div className="flex items-center gap-3 mt-1 text-xs text-muted-foreground">
                      <span>{CATEGORY_LABELS[alert.category] || alert.category}</span>
                      <span>SLA: {alert.freshnessSlaDays} days</span>
                      <span>Last reviewed: {formatDate(alert.lastReviewedAt)}</span>
                      <span className="text-red-400 font-medium">
                        {alert.daysUntilExpiry !== null ? `${Math.abs(alert.daysUntilExpiry)} days overdue` : "Overdue"}
                      </span>
                    </div>
                  </div>
                  <button
                    onClick={() => reviewMutation.mutate(alert.artifactId)}
                    disabled={reviewMutation.isPending}
                    className="flex items-center gap-1.5 px-3 py-2 text-xs rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-500/20 active:bg-emerald-500/30 transition-colors disabled:opacity-50"
                    aria-label={`Mark ${alert.artifactTitle} as reviewed`}
                  >
                    <RefreshCw className="h-3.5 w-3.5" />
                    Mark Reviewed
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {expiringSoon.length > 0 && (
        <div>
          <h4 className="text-sm font-semibold text-amber-400 mb-3 flex items-center gap-2">
            <AlertTriangle className="h-4 w-4" />
            Expiring Soon ({expiringSoon.length})
          </h4>
          <div className="space-y-2">
            {expiringSoon.map((alert) => (
              <div key={alert.artifactId} className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h5 className="font-medium">{alert.artifactTitle}</h5>
                    <div className="flex items-center gap-3 mt-1 text-xs text-muted-foreground">
                      <span>{CATEGORY_LABELS[alert.category] || alert.category}</span>
                      <span>SLA: {alert.freshnessSlaDays} days</span>
                      <span>Last reviewed: {formatDate(alert.lastReviewedAt)}</span>
                      <span className="text-amber-400 font-medium">
                        {alert.daysUntilExpiry !== null ? `${alert.daysUntilExpiry} days remaining` : "Due soon"}
                      </span>
                    </div>
                  </div>
                  <button
                    onClick={() => reviewMutation.mutate(alert.artifactId)}
                    disabled={reviewMutation.isPending}
                    className="flex items-center gap-1.5 px-3 py-2 text-xs rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-500/20 active:bg-emerald-500/30 transition-colors disabled:opacity-50"
                    aria-label={`Mark ${alert.artifactTitle} as reviewed`}
                  >
                    <RefreshCw className="h-3.5 w-3.5" />
                    Mark Reviewed
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {current.length > 0 && (
        <div>
          <h4 className="text-sm font-semibold text-emerald-400 mb-3 flex items-center gap-2">
            <CheckCircle2 className="h-4 w-4" />
            Current ({current.length})
          </h4>
          <div className="space-y-2">
            {current.map((alert) => (
              <div key={alert.artifactId} className="rounded-lg border border-border/50 bg-card/50 p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h5 className="font-medium">{alert.artifactTitle}</h5>
                    <div className="flex items-center gap-3 mt-1 text-xs text-muted-foreground">
                      <span>{CATEGORY_LABELS[alert.category] || alert.category}</span>
                      <span>SLA: {alert.freshnessSlaDays} days</span>
                      <span>Next review: {formatDate(alert.nextReviewDue)}</span>
                      {alert.daysUntilExpiry !== null && (
                        <span className="text-emerald-400">{alert.daysUntilExpiry} days remaining</span>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export default function TrustCenterPage() {
  const [activeTab, setActiveTab] = useState<TabId>("overview");

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Trust Center</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Central portal for compliance status, security artifacts, and procurement acceleration
        </p>
      </div>

      <div className="flex gap-1 border-b border-border/50 overflow-x-auto">
        {TABS.map((tab) => {
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium whitespace-nowrap border-b-2 transition-colors hover:text-foreground ${
                activeTab === tab.id ? "border-cyan-500 text-cyan-400" : "border-transparent text-muted-foreground"
              }`}
              aria-label={`Switch to ${tab.label} tab`}
            >
              <Icon className="h-4 w-4" />
              {tab.label}
            </button>
          );
        })}
      </div>

      {activeTab === "overview" && <OverviewTab />}
      {activeTab === "artifacts" && <ArtifactsTab />}
      {activeTab === "mappings" && <MappingsTab />}
      {activeTab === "audit" && <AuditLogTab />}
      {activeTab === "freshness" && <FreshnessTab />}
    </div>
  );
}

import {
  LayoutDashboard,
  AlertTriangle,
  FileWarning,
  Activity,
  Settings,
  LogOut,
  ArrowDownToLine,
  Plug,
  Brain,
  Zap,
  ChevronRight,
  BarChart3,
  Shield,
  Crosshair,
  Workflow,
  Network,
  GitBranch,
  Swords,
  Scale,
  Link2,
  TrendingUp,
  Bot,
  Gauge,
  Cloud,
  Monitor,
  Users,
  FileText,
  History,
  CreditCard,
  Building2,
  Check,
  ChevronsUpDown,
  ShieldCheck,
  Code2,
  Mail,
  Rss,
  Send,
  FolderOpen,
  KeyRound,
  Fingerprint,
  MessageSquare,
  EyeOff,
  BookOpen,
  Webhook as WebhookIcon,
  Upload,
  Newspaper,
  GitMerge,
  ShieldBan,
  Lock,
  HardDrive,
  Package,
  BadgeCheck,
  Layers,
  ClipboardList,
  Search,
  DollarSign,
  Server,
  Microscope,
  Target,
  Bug,
  HeartPulse,
  Wand2,
  LayoutGrid,
  Database,
  Flame,
  ListTodo,
  RotateCcw,
  Globe,
  Cpu,
} from "lucide-react";
import atsLogo from "@/assets/logo.jpg";
import { useLocation, Link } from "wouter";
import { useAuth } from "@/hooks/use-auth";
import { useOrgContext } from "@/hooks/use-org-context";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";
import { useState, useEffect } from "react";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Collapsible, CollapsibleTrigger, CollapsibleContent } from "@/components/ui/collapsible";
import {
  Sidebar,
  SidebarContent,
  SidebarGroup,
  SidebarGroupContent,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarHeader,
  SidebarFooter,
  SidebarSeparator,
} from "@/components/ui/sidebar";

type NavItem = { title: string; url: string; icon: React.ElementType };

type NavGroup = {
  label: string;
  icon: React.ElementType;
  color: string;
  items: NavItem[];
};

const coreItems: NavItem[] = [
  { title: "Dashboard", url: "/", icon: LayoutDashboard },
  { title: "Alerts", url: "/alerts", icon: AlertTriangle },
  { title: "Incidents", url: "/incidents", icon: FileWarning },
];

const navGroups: NavGroup[] = [
  {
    label: "Threat Intelligence",
    icon: Shield,
    color: "text-red-400",
    items: [
      { title: "Threat Intel", url: "/threat-intel", icon: Shield },
      { title: "Intel Feeds", url: "/threat-intel-feeds", icon: Newspaper },
      { title: "OSINT Feeds", url: "/osint-feeds-config", icon: Rss },
      { title: "IOC Ingestion", url: "/ioc-ingestion-matching", icon: Upload },
      { title: "MITRE ATT&CK", url: "/mitre-attack", icon: Crosshair },
      { title: "Kill Chain", url: "/kill-chain", icon: Swords },
      { title: "CVE Browser", url: "/cve-browser", icon: Bug },
      { title: "Campaign Viewer", url: "/campaign-viewer", icon: Target },
    ],
  },
  {
    label: "Investigation",
    icon: Microscope,
    color: "text-violet-400",
    items: [
      { title: "Entity Graph", url: "/entity-graph", icon: Network },
      { title: "Entity Merge", url: "/entity-merge-alias", icon: GitMerge },
      { title: "Attack Graph", url: "/attack-graph", icon: GitBranch },
      { title: "Security Graph", url: "/security-graph", icon: Shield },
      { title: "Finding Lineage", url: "/finding-lineage", icon: Fingerprint },
      { title: "Evidence Chain", url: "/evidence-chain-viewer", icon: Fingerprint },
      { title: "Investigation Runs", url: "/investigation-runs", icon: Microscope },
      { title: "Suppressed Alerts", url: "/suppressed-alerts", icon: EyeOff },
    ],
  },
  {
    label: "Response & Automation",
    icon: Bot,
    color: "text-emerald-400",
    items: [
      { title: "Autonomous Response", url: "/autonomous-response", icon: Bot },
      { title: "Playbooks", url: "/playbooks", icon: Workflow },
      { title: "Runbook Templates", url: "/runbook-templates", icon: ClipboardList },
      { title: "Post-Incident Review", url: "/post-incident-review", icon: FileText },
      { title: "Rollback History", url: "/rollback-history", icon: RotateCcw },
      { title: "SOC Co-Pilot", url: "/soc-copilot", icon: Brain },
    ],
  },
  {
    label: "Analytics & Posture",
    icon: BarChart3,
    color: "text-cyan-400",
    items: [
      { title: "Analytics", url: "/analytics", icon: BarChart3 },
      { title: "Reports", url: "/reports", icon: FileText },
      { title: "Template Versioning", url: "/report-template-versioning", icon: GitBranch },
      { title: "Predictive Defense", url: "/predictive-defense", icon: TrendingUp },
      { title: "Security Posture", url: "/security-posture", icon: Gauge },
      { title: "Gap Analysis", url: "/gap-analysis", icon: Search },
      { title: "Executive Risk", url: "/executive-risk", icon: TrendingUp },
    ],
  },
  {
    label: "Cloud & Assets",
    icon: Cloud,
    color: "text-blue-400",
    items: [
      { title: "CSPM", url: "/cspm", icon: Cloud },
      { title: "Endpoint Telemetry", url: "/endpoint-telemetry", icon: Monitor },
      { title: "Connectors", url: "/connectors", icon: Plug },
      { title: "Integrations", url: "/integrations", icon: Link2 },
      { title: "Marketplace", url: "/integration-marketplace", icon: Zap },
      { title: "Native Collectors", url: "/native-collectors", icon: HardDrive },
      { title: "Ingestion", url: "/ingestion", icon: ArrowDownToLine },
      { title: "File Manager", url: "/file-manager", icon: FolderOpen },
    ],
  },
  {
    label: "Security Controls",
    icon: Lock,
    color: "text-amber-400",
    items: [
      { title: "Secret Rotations", url: "/secret-rotation-overview", icon: KeyRound },
      { title: "JIT Secret Access", url: "/jit-secret-access", icon: Lock },
      { title: "Webhook Security", url: "/webhook-security-center", icon: WebhookIcon },
      { title: "Runtime Guardrails", url: "/runtime-guardrails", icon: ShieldBan },
      { title: "Adversarial Testing", url: "/adversarial-testing", icon: Shield },
      { title: "Agent Tool Security", url: "/agent-tool-security", icon: ShieldCheck },
      { title: "Browser Defense", url: "/browser-defense", icon: ShieldBan },
      { title: "Cross-Cutting Controls", url: "/cross-cutting", icon: Layers },
      { title: "Prompt to Artifact", url: "/prompt-to-artifact", icon: Zap },
      { title: "Dev Remediation", url: "/developer-remediation", icon: Code2 },
    ],
  },
  {
    label: "AI Platform",
    icon: Brain,
    color: "text-fuchsia-400",
    items: [
      { title: "AI Engine", url: "/ai-engine", icon: Brain },
      { title: "AI Feedback", url: "/ai-feedback", icon: MessageSquare },
      { title: "Prompt Registry", url: "/ai-prompt-registry", icon: BookOpen },
      { title: "Engine Controls", url: "/engine-controls", icon: Settings },
      { title: "Model Gateway", url: "/model-gateway", icon: ShieldCheck },
      { title: "AI Budget Controls", url: "/ai-budget-controls", icon: DollarSign },
      { title: "AI Model Health", url: "/ai-model-health", icon: HeartPulse },
      { title: "Manual AI Triggers", url: "/manual-ai-triggers", icon: Wand2 },
    ],
  },
  {
    label: "Operations",
    icon: Activity,
    color: "text-orange-400",
    items: [
      { title: "Operations", url: "/operations", icon: Zap },
      { title: "Outbox Monitor", url: "/outbox-monitor", icon: Send },
      { title: "API Versioning", url: "/api-versioning", icon: GitBranch },
      { title: "Job Queue", url: "/job-queue-dashboard", icon: ListTodo },
      { title: "Metrics Rollup", url: "/metrics-rollup", icon: BarChart3 },
    ],
  },
];

const adminGroup: NavGroup = {
  label: "Administration",
  icon: Settings,
  color: "text-slate-400",
  items: [
    { title: "Onboarding", url: "/onboarding", icon: Activity },
    { title: "Team & Invites", url: "/team", icon: Users },
    { title: "Billing", url: "/billing", icon: CreditCard },
    { title: "Usage", url: "/usage-billing", icon: BarChart3 },
    { title: "Plans & Packaging", url: "/tiered-packaging", icon: Package },
    { title: "Audit Log", url: "/audit-log", icon: Activity },
    { title: "Compliance", url: "/compliance", icon: Scale },
    { title: "Trust Center", url: "/trust-center", icon: BadgeCheck },
    { title: "Policy Packs", url: "/policy-packs", icon: Shield },
    { title: "Settings", url: "/settings", icon: Settings },
    { title: "Org Settings", url: "/org-settings", icon: Building2 },
    { title: "MSSP Dashboard", url: "/mssp-dashboard", icon: Network },
    { title: "Role Dashboard", url: "/role-dashboard", icon: LayoutGrid },
    { title: "Tenant Isolation", url: "/tenant-isolation", icon: Server },
    { title: "Data Lifecycle", url: "/data-lifecycle", icon: Database },
    { title: "DR Drill Scheduler", url: "/dr-drill-scheduler", icon: Flame },
    { title: "Domain Auto-Join", url: "/domain-auto-join", icon: Globe },
    { title: "Usage Analytics", url: "/usage-metering-analytics", icon: Cpu },
  ],
};

const ADMIN_ONLY_URLS = ["/team", "/onboarding", "/settings", "/compliance"];
const ANALYST_HIDDEN_URLS = ["/team", "/onboarding"];

const ALL_NAV_ITEMS: NavItem[] = [...coreItems, ...navGroups.flatMap((g) => g.items), ...adminGroup.items];

const RECENT_PAGES_KEY = "securenexus.recentPages.v1";
const MAX_RECENT = 5;

function useRecentPages(currentPath: string) {
  const [recent, setRecent] = useState<string[]>([]);

  useEffect(() => {
    try {
      const raw = localStorage.getItem(RECENT_PAGES_KEY);
      if (raw) setRecent(JSON.parse(raw));
    } catch {
      setRecent([]);
    }
  }, []);

  useEffect(() => {
    if (!currentPath || currentPath.includes(":")) return;
    const match = ALL_NAV_ITEMS.find((i) => i.url === currentPath);
    if (!match) return;
    setRecent((prev) => {
      const next = [currentPath, ...prev.filter((p) => p !== currentPath)].slice(0, MAX_RECENT);
      localStorage.setItem(RECENT_PAGES_KEY, JSON.stringify(next));
      return next;
    });
  }, [currentPath]);

  return recent.slice(1);
}

export function AppSidebar() {
  const [location] = useLocation();
  const { user } = useAuth();
  const { currentOrg, currentOrgId, memberships, switchOrg } = useOrgContext();
  const [openGroups, setOpenGroups] = useState<Record<string, boolean>>({});
  const recentPages = useRecentPages(location);

  useEffect(() => {
    const initial: Record<string, boolean> = {};
    [...navGroups, adminGroup].forEach((g) => {
      if (g.items.some((i) => (i.url === "/" ? location === "/" : location.startsWith(i.url)))) {
        initial[g.label] = true;
      }
    });
    setOpenGroups((prev) => ({ ...prev, ...initial }));
  }, []);

  const toggleGroup = (label: string) => {
    setOpenGroups((prev) => ({ ...prev, [label]: !prev[label] }));
  };

  const userRole = (user as any)?.role || "analyst";

  const initials = user ? `${user.firstName?.[0] || ""}${user.lastName?.[0] || ""}`.toUpperCase() || "U" : "U";

  function filterItems(items: NavItem[]) {
    if (userRole === "owner" || userRole === "admin") return items;
    if (userRole === "read_only") return items.filter((i) => !ADMIN_ONLY_URLS.includes(i.url));
    return items.filter((i) => !ANALYST_HIDDEN_URLS.includes(i.url));
  }

  function renderItem(item: NavItem) {
    const isActive = item.url === "/" ? location === "/" : location.startsWith(item.url);
    return (
      <SidebarMenuItem key={item.title}>
        <SidebarMenuButton
          asChild
          isActive={isActive}
          aria-label={`Navigate to ${item.title}`}
          className="h-7 text-[12.5px] rounded-md transition-all duration-150"
        >
          <Link href={item.url}>
            <item.icon className="h-3.5 w-3.5 shrink-0 opacity-70" aria-hidden="true" />
            <span className="truncate">{item.title}</span>
          </Link>
        </SidebarMenuButton>
      </SidebarMenuItem>
    );
  }

  function renderCollapsibleGroup(group: NavGroup) {
    const filtered = filterItems(group.items);
    if (filtered.length === 0) return null;
    const isOpen = !!openGroups[group.label];
    const hasActive = filtered.some((i) => (i.url === "/" ? location === "/" : location.startsWith(i.url)));

    return (
      <SidebarMenuItem key={group.label}>
        <Collapsible open={isOpen} onOpenChange={() => toggleGroup(group.label)}>
          <CollapsibleTrigger asChild>
            <SidebarMenuButton
              className="w-full h-8 rounded-md group/trigger transition-all duration-150"
              data-active={hasActive || undefined}
            >
              <div
                className={`flex items-center justify-center w-5 h-5 rounded ${hasActive ? "bg-sidebar-accent" : ""}`}
              >
                <group.icon
                  className={`h-3.5 w-3.5 shrink-0 ${hasActive ? group.color : "opacity-60"}`}
                  aria-hidden="true"
                />
              </div>
              <span className="truncate text-[12.5px] font-medium">{group.label}</span>
              <div className="ml-auto flex items-center gap-1">
                <span className="text-[10px] text-muted-foreground/50 tabular-nums">{filtered.length}</span>
                <ChevronRight
                  className={`h-3 w-3 shrink-0 text-muted-foreground/40 transition-transform duration-200 ${
                    isOpen ? "rotate-90" : ""
                  }`}
                />
              </div>
            </SidebarMenuButton>
          </CollapsibleTrigger>
          <CollapsibleContent className="animate-fade-in">
            <SidebarMenu className="ml-5 border-l border-sidebar-border/50 pl-2.5 mt-0.5 space-y-0">
              {filtered.map(renderItem)}
            </SidebarMenu>
          </CollapsibleContent>
        </Collapsible>
      </SidebarMenuItem>
    );
  }

  return (
    <Sidebar>
      <SidebarHeader className="p-3 pb-2">
        <Link href="/" className="flex items-center gap-2.5 group/logo">
          <div className="relative flex items-center justify-center w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-500/20 via-blue-500/10 to-violet-500/5 border border-cyan-500/15 shadow-sm shadow-cyan-500/10 transition-all duration-300 group-hover/logo:border-cyan-500/30 group-hover/logo:shadow-cyan-500/20">
            <img src={atsLogo} alt="ATS" className="w-5 h-5 object-contain" />
          </div>
          <div className="flex flex-col">
            <span className="text-sm font-bold tracking-tight gradient-text-brand">SecureNexus</span>
            <span className="text-[9px] text-sidebar-foreground/35 leading-none font-medium tracking-wide uppercase">
              Agentic SOC
            </span>
          </div>
        </Link>

        {memberships.length > 0 && (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <button className="mt-2 w-full flex items-center gap-2 px-2 py-1.5 rounded-md bg-sidebar-accent/30 border border-sidebar-border/50 hover:bg-sidebar-accent/50 hover:border-sidebar-border transition-all duration-200 text-left">
                <Building2 className="h-3.5 w-3.5 text-cyan-400/70 shrink-0" aria-hidden="true" />
                <span className="text-[11px] font-medium truncate flex-1">{currentOrg?.name || "Select org"}</span>
                <ChevronsUpDown className="h-3 w-3 text-muted-foreground/40 shrink-0" aria-hidden="true" />
              </button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="start" className="w-56" sideOffset={4}>
              <DropdownMenuLabel className="text-[10px] text-muted-foreground">Organizations</DropdownMenuLabel>
              <DropdownMenuSeparator />
              {memberships.map((m) => (
                <DropdownMenuItem
                  key={m.orgId}
                  onClick={() => switchOrg(m.orgId)}
                  className="flex items-center gap-2 text-xs"
                >
                  <Building2 className="h-3.5 w-3.5 shrink-0" />
                  <span className="truncate flex-1">{m.organization?.name || m.orgId}</span>
                  {m.orgId === currentOrgId && <Check className="h-3.5 w-3.5 text-cyan-400 shrink-0" />}
                </DropdownMenuItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>
        )}

        <div className="mt-1.5 flex items-center gap-2 px-2.5 py-1.5 rounded-md bg-sidebar-accent/20 border border-sidebar-border/30">
          <div className="flex items-center gap-1.5">
            <span className="relative flex h-1.5 w-1.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
              <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-emerald-500" />
            </span>
            <span className="text-[10px] text-emerald-400/80 font-medium">Online</span>
          </div>
          <Badge
            variant="outline"
            className="text-[8px] px-1.5 py-0 h-3.5 ml-auto border-cyan-500/20 bg-cyan-500/5 text-cyan-400 font-bold tracking-wider"
          >
            PRO
          </Badge>
        </div>
      </SidebarHeader>

      <SidebarSeparator className="opacity-50" />

      <SidebarContent className="gap-0 [&>div]:py-0">
        <SidebarGroup className="px-2 py-1.5">
          <SidebarGroupContent>
            <SidebarMenu className="space-y-0.5">
              {coreItems.map((item) => {
                const isActive = item.url === "/" ? location === "/" : location.startsWith(item.url);
                return (
                  <SidebarMenuItem key={item.title}>
                    <SidebarMenuButton
                      asChild
                      isActive={isActive}
                      aria-label={`Navigate to ${item.title}`}
                      className="h-8 text-[13px] font-medium rounded-md transition-all duration-150"
                    >
                      <Link href={item.url}>
                        <item.icon
                          className={`h-4 w-4 shrink-0 ${isActive ? "text-cyan-400" : "opacity-60"}`}
                          aria-hidden="true"
                        />
                        <span className="truncate">{item.title}</span>
                        {item.url === "/alerts" && (
                          <span className="ml-auto flex h-4 min-w-4 items-center justify-center rounded-full bg-red-500/15 text-[9px] font-bold text-red-400 px-1 tabular-nums">
                            !
                          </span>
                        )}
                      </Link>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                );
              })}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>

        <div className="px-3 py-1">
          <div className="h-px bg-gradient-to-r from-transparent via-sidebar-border/60 to-transparent" />
        </div>

        <SidebarGroup className="px-2 py-0.5">
          <SidebarGroupContent>
            <SidebarMenu className="space-y-0">{navGroups.map(renderCollapsibleGroup)}</SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>

        <div className="px-3 py-1">
          <div className="h-px bg-gradient-to-r from-transparent via-sidebar-border/60 to-transparent" />
        </div>

        <SidebarGroup className="px-2 py-0.5">
          <SidebarGroupContent>
            <SidebarMenu className="space-y-0">{renderCollapsibleGroup(adminGroup)}</SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>

        {user?.isSuperAdmin && (
          <>
            <div className="px-3 py-1">
              <div className="h-px bg-gradient-to-r from-transparent via-sidebar-border/60 to-transparent" />
            </div>
            <SidebarGroup className="px-2 py-0.5">
              <SidebarGroupContent>
                <SidebarMenu>
                  <SidebarMenuItem>
                    <div className="flex items-center gap-1.5 px-2 py-1">
                      <ShieldCheck className="h-3 w-3 text-yellow-500/70" aria-hidden="true" />
                      <span className="text-[9px] font-semibold text-yellow-500/60 uppercase tracking-widest">
                        Super Admin
                      </span>
                    </div>
                  </SidebarMenuItem>
                  {[
                    { title: "Platform Admin", url: "/platform-admin", icon: ShieldCheck, color: "text-yellow-500" },
                    { title: "Account Lockout", url: "/account-lockout", icon: Lock, color: "text-red-400" },
                    { title: "Dev Portal", url: "/dev-portal", icon: Code2, color: "text-cyan-400" },
                    { title: "Email Templates", url: "/email-templates", icon: Mail, color: "text-cyan-400" },
                    { title: "Metrics Rollup", url: "/metrics-rollup", icon: BarChart3, color: "text-cyan-400" },
                  ].map((item) => (
                    <SidebarMenuItem key={item.title}>
                      <SidebarMenuButton
                        asChild
                        isActive={location === item.url}
                        aria-label={`Navigate to ${item.title}`}
                        className="h-7 text-[12px] rounded-md"
                      >
                        <Link href={item.url}>
                          <item.icon className={`h-3.5 w-3.5 shrink-0 ${item.color}`} aria-hidden="true" />
                          <span className={`truncate font-medium ${item.color}`}>{item.title}</span>
                        </Link>
                      </SidebarMenuButton>
                    </SidebarMenuItem>
                  ))}
                </SidebarMenu>
              </SidebarGroupContent>
            </SidebarGroup>
          </>
        )}

        {recentPages.length > 0 && (
          <>
            <div className="px-3 py-1">
              <div className="h-px bg-gradient-to-r from-transparent via-sidebar-border/60 to-transparent" />
            </div>
            <SidebarGroup className="px-2 py-0.5">
              <SidebarGroupContent>
                <SidebarMenu>
                  <SidebarMenuItem>
                    <div className="flex items-center gap-1.5 px-2 py-1">
                      <History className="h-3 w-3 text-muted-foreground/40" aria-hidden="true" />
                      <span className="text-[9px] font-semibold text-muted-foreground/40 uppercase tracking-widest">
                        Recent
                      </span>
                    </div>
                  </SidebarMenuItem>
                  {recentPages.map((path) => {
                    const item = ALL_NAV_ITEMS.find((i) => i.url === path);
                    if (!item) return null;
                    return renderItem(item);
                  })}
                </SidebarMenu>
              </SidebarGroupContent>
            </SidebarGroup>
          </>
        )}
      </SidebarContent>

      <SidebarSeparator className="opacity-50" />

      <SidebarFooter className="p-2.5">
        <div className="flex items-center gap-2.5 px-1.5 py-1.5 rounded-md hover:bg-sidebar-accent/30 transition-colors duration-200">
          <Avatar className="h-7 w-7 border border-sidebar-border/50 ring-1 ring-cyan-500/10">
            <AvatarImage src={user?.profileImageUrl || ""} />
            <AvatarFallback className="text-[10px] font-bold bg-gradient-to-br from-cyan-500/20 to-blue-500/10 text-cyan-400">
              {initials}
            </AvatarFallback>
          </Avatar>
          <div className="flex-1 min-w-0">
            <p className="text-[11px] font-semibold truncate leading-tight">
              {user?.firstName || "User"} {user?.lastName || ""}
            </p>
            <p className="text-[9px] text-sidebar-foreground/35 truncate leading-tight">Security Analyst</p>
          </div>
        </div>
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton
              asChild
              className="h-7 text-[12px] text-muted-foreground hover:text-red-400 transition-colors duration-200"
            >
              <a href="/api/logout">
                <LogOut className="h-3.5 w-3.5" aria-hidden="true" />
                <span>Sign out</span>
              </a>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarFooter>
    </Sidebar>
  );
}

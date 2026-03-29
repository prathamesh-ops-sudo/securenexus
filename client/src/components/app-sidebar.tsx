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
  Calendar,
  ClipboardCheck,
  Flag,
  ShieldAlert,
  Scan,
  UserCheck,
  Zap as ZapIcon,
  Terminal,
  Factory,
  Smartphone,
  Palette,
  DoorOpen,
  GraduationCap,
  Atom,
  Radar,
} from "lucide-react";
import atsLogo from "@/assets/logo.png";
import { useLocation, Link } from "wouter";
import { useAuth } from "@/hooks/use-auth";
import { useOrgContext } from "@/hooks/use-org-context";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";

import { useState, useEffect, useMemo, useCallback } from "react";
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

type NavSection = {
  label: string;
  items: NavItem[];
};

type NavGroup = {
  label: string;
  icon: React.ElementType;
  color: string;
  sections: NavSection[];
  /** If true, this group is always visible and cannot be disabled */
  core?: boolean;
};

const coreItems: NavItem[] = [
  { title: "Dashboard", url: "/", icon: LayoutDashboard },
  { title: "Alerts", url: "/alerts", icon: AlertTriangle },
  { title: "Incidents", url: "/incidents", icon: FileWarning },
];

/* ── Module visibility persistence ─────────────────────────────────── */
const ENABLED_MODULES_KEY = "securenexus.enabledModules.v1";

/** Groups shown by default for every new user */
const DEFAULT_ENABLED_MODULES = new Set(["Watch & Recon", "Investigate", "Respond", "Posture", "Data & Integrations"]);

function loadEnabledModules(): Set<string> {
  try {
    const raw = localStorage.getItem(ENABLED_MODULES_KEY);
    if (raw) return new Set(JSON.parse(raw) as string[]);
  } catch {
    /* use defaults */
  }
  return new Set(DEFAULT_ENABLED_MODULES);
}

function saveEnabledModules(modules: Set<string>) {
  localStorage.setItem(ENABLED_MODULES_KEY, JSON.stringify(Array.from(modules)));
}

const navGroups: NavGroup[] = [
  {
    label: "Watch & Recon",
    icon: Globe,
    color: "text-cyan-400",
    core: true,
    sections: [
      {
        label: "Intelligence Collection",
        items: [
          { title: "Threat Intel Feeds", url: "/threat-intel-feeds", icon: Newspaper },
          { title: "OSINT Monitoring", url: "/osint-feeds-config", icon: Rss },
          { title: "IOC Management", url: "/ioc-ingestion-matching", icon: Upload },
          { title: "CVE Database", url: "/cve-browser", icon: Bug },
        ],
      },
      {
        label: "Adversary Tracking",
        items: [
          { title: "Campaigns", url: "/campaign-viewer", icon: Target },
          { title: "MITRE ATT&CK", url: "/mitre-attack", icon: Crosshair },
          { title: "Kill Chain", url: "/kill-chain", icon: Swords },
        ],
      },
    ],
  },
  {
    label: "Investigate",
    icon: Microscope,
    color: "text-violet-400",
    core: true,
    sections: [
      {
        label: "Graph Analysis",
        items: [
          { title: "Security Graph", url: "/security-graph", icon: Network },
          { title: "Attack Paths", url: "/attack-graph", icon: GitBranch },
          { title: "Entity Explorer", url: "/entity-graph", icon: Search },
          { title: "Entity Resolution", url: "/entity-merge-alias", icon: GitMerge },
        ],
      },
      {
        label: "Case Management",
        items: [
          { title: "War Room", url: "/war-room", icon: Shield },
          { title: "Threat Hunting", url: "/threat-hunting", icon: Crosshair },
          { title: "Timeline", url: "/investigation-timeline", icon: History },
          { title: "Evidence Chain", url: "/evidence-chain-viewer", icon: Fingerprint },
          { title: "Evidence Locker", url: "/evidence-custody", icon: Link2 },
        ],
      },
    ],
  },
  {
    label: "Respond",
    icon: Zap,
    color: "text-emerald-400",
    core: true,
    sections: [
      {
        label: "Automation",
        items: [
          { title: "Playbooks", url: "/playbooks", icon: Workflow },
          { title: "Autonomous Response", url: "/autonomous-response", icon: Bot },
          { title: "Rollback History", url: "/rollback-history", icon: RotateCcw },
        ],
      },
      {
        label: "Templates",
        items: [
          { title: "Playbook Library", url: "/playbook-templates", icon: BookOpen },
          { title: "Runbook Library", url: "/runbook-templates", icon: ClipboardList },
        ],
      },
    ],
  },
  {
    label: "Posture",
    icon: ShieldCheck,
    color: "text-blue-400",
    core: true,
    sections: [
      {
        label: "Cloud & Infrastructure",
        items: [
          { title: "CSPM", url: "/cspm", icon: Cloud },
          { title: "Endpoint Telemetry", url: "/endpoint-telemetry", icon: Monitor },
          { title: "Vulnerability Mgmt", url: "/security-posture", icon: Gauge },
        ],
      },
      {
        label: "Identity & Access",
        items: [
          { title: "JIT Access", url: "/jit-secret-access", icon: KeyRound },
          { title: "Secret Rotation", url: "/secret-rotation-overview", icon: RotateCcw },
        ],
      },
    ],
  },
  {
    label: "AI Analyst",
    icon: Brain,
    color: "text-fuchsia-400",
    sections: [
      {
        label: "Capabilities",
        items: [
          { title: "AI Engine", url: "/ai-engine", icon: Brain },
          { title: "SOC Co-Pilot", url: "/soc-copilot", icon: MessageSquare },
          { title: "Prompt Builder", url: "/prompt-to-artifact", icon: Wand2 },
        ],
      },
      {
        label: "Governance",
        items: [
          { title: "Model Gateway", url: "/model-gateway", icon: Server },
          { title: "Prompt Registry", url: "/ai-prompt-registry", icon: BookOpen },
          { title: "Feedback Loop", url: "/ai-feedback", icon: MessageSquare },
          { title: "Budget & Limits", url: "/ai-budget-controls", icon: DollarSign },
        ],
      },
    ],
  },
  {
    label: "Data & Integrations",
    icon: Database,
    color: "text-sky-400",
    core: true,
    sections: [
      {
        label: "Connectivity",
        items: [
          { title: "Connectors", url: "/connectors", icon: Plug },
          { title: "Marketplace", url: "/integration-marketplace", icon: Package },
          { title: "Native Collectors", url: "/native-collectors", icon: HardDrive },
          { title: "Webhooks", url: "/webhook-security-center", icon: WebhookIcon },
        ],
      },
      {
        label: "Pipeline",
        items: [
          { title: "Ingestion Status", url: "/ingestion", icon: Activity },
          { title: "Job Queue", url: "/job-queue-dashboard", icon: ListTodo },
          { title: "Outbox Monitor", url: "/outbox-monitor", icon: Send },
        ],
      },
      {
        label: "Storage",
        items: [{ title: "Data Lake", url: "/data-lake", icon: Database }],
      },
    ],
  },
  {
    label: "Standalone Security",
    icon: Shield,
    color: "text-teal-400",
    sections: [
      {
        label: "Asset & Risk",
        items: [
          { title: "Asset Inventory", url: "/asset-inventory", icon: Server },
          { title: "Risk Register", url: "/risk-register", icon: ShieldAlert },
        ],
      },
      {
        label: "Agent & Detection",
        items: [
          { title: "Native Sensors", url: "/native-sensors", icon: Cpu },
          { title: "Detection Rules", url: "/detection-rules", icon: ShieldAlert },
          { title: "Vuln Scanner", url: "/vuln-scanner", icon: Scan },
          { title: "Agent Response", url: "/agent-response", icon: Terminal },
        ],
      },
      {
        label: "Behavioral Analytics",
        items: [{ title: "UEBA Analytics", url: "/ueba", icon: UserCheck }],
      },
      {
        label: "Supply Chain",
        items: [{ title: "Supply Chain Security", url: "/supply-chain", icon: GitBranch }],
      },
      {
        label: "Identity & PAM",
        items: [{ title: "Identity Governance", url: "/identity-governance", icon: Shield }],
      },
      {
        label: "Deception",
        items: [{ title: "Deception Technology", url: "/deception", icon: Crosshair }],
      },
      {
        label: "OT/ICS Security",
        items: [{ title: "OT/ICS Security", url: "/ot-security", icon: Factory }],
      },
      {
        label: "Mobile & Remote",
        items: [{ title: "Mobile Security", url: "/mobile-security", icon: Smartphone }],
      },
      {
        label: "API Security",
        items: [{ title: "API Security", url: "/api-security", icon: Globe }],
      },
      {
        label: "Ransomware Defense",
        items: [{ title: "Ransomware Defense", url: "/ransomware-defense", icon: ShieldAlert }],
      },
      {
        label: "Community Intel",
        items: [{ title: "Community Threat Intel", url: "/community-intel", icon: Network }],
      },
      {
        label: "Posture & Trust",
        items: [{ title: "Security Posture Score", url: "/posture-trust-center", icon: ShieldCheck }],
      },
      {
        label: "Chaos Engineering",
        items: [{ title: "Security Chaos Engineering", url: "/chaos-engineering", icon: ZapIcon }],
      },
      {
        label: "AI Rule Generation",
        items: [{ title: "AI Detection Rules", url: "/ai-detection-rules", icon: Wand2 }],
      },
      {
        label: "Autonomous SOC",
        items: [{ title: "Autonomous SOC", url: "/autonomous-soc", icon: Brain }],
      },
      {
        label: "Developer Security",
        items: [{ title: "Developer Security", url: "/developer-security", icon: Code2 }],
      },
      {
        label: "Third-Party Risk",
        items: [{ title: "TPRM", url: "/tprm", icon: Building2 }],
      },
      {
        label: "Dark Web Monitoring",
        items: [{ title: "Dark Web Monitoring", url: "/dark-web-monitoring", icon: EyeOff }],
      },
      {
        label: "Physical Security",
        items: [{ title: "Physical Security", url: "/physical-security", icon: DoorOpen }],
      },
      {
        label: "Security Awareness",
        items: [{ title: "Phishing & Awareness", url: "/security-awareness", icon: GraduationCap }],
      },
      {
        label: "Quantum Readiness",
        items: [{ title: "Quantum Readiness", url: "/quantum-readiness", icon: Atom }],
      },
      {
        label: "Privacy Engineering",
        items: [{ title: "Privacy Engineering", url: "/privacy-engineering", icon: Fingerprint }],
      },
      {
        label: "DNS Security",
        items: [{ title: "DNS Security", url: "/dns-security", icon: Radar }],
      },
      {
        label: "Email Security",
        items: [{ title: "Email Security", url: "/email-security", icon: Mail }],
      },
      {
        label: "MSSP Partner",
        items: [
          { title: "MSSP Dashboard", url: "/mssp-dashboard", icon: Building2 },
          { title: "Partner Portal", url: "/mssp-partner-portal", icon: Palette },
        ],
      },
      {
        label: "Compliance & Reporting",
        items: [
          { title: "Assessments", url: "/security-assessments", icon: ClipboardCheck },
          { title: "Threat Reports", url: "/threat-reports", icon: Flag },
          { title: "Advanced Reports", url: "/advanced-reporting", icon: BarChart3 },
        ],
      },
    ],
  },
  {
    label: "Governance",
    icon: Building2,
    color: "text-amber-400",
    sections: [
      {
        label: "Compliance",
        items: [
          { title: "Compliance Center", url: "/compliance", icon: Scale },
          { title: "Trust Center", url: "/trust-center", icon: BadgeCheck },
          { title: "Gap Analysis", url: "/compliance-gap", icon: Search },
        ],
      },
      {
        label: "Audit & Policy",
        items: [
          { title: "Audit Log", url: "/audit-log", icon: FileText },
          { title: "Policy Packs", url: "/policy-packs", icon: Shield },
          { title: "Reports", url: "/reports", icon: FileText },
        ],
      },
      {
        label: "Data Sovereignty",
        items: [{ title: "Data Residency", url: "/data-residency", icon: Globe }],
      },
      {
        label: "Executive Metrics",
        items: [{ title: "Board Dashboard", url: "/board-dashboard", icon: TrendingUp }],
      },
    ],
  },
];

const adminGroup: NavGroup = {
  label: "Admin & Settings",
  icon: Settings,
  color: "text-slate-400",
  sections: [
    {
      label: "Team & Org",
      items: [
        { title: "Onboarding", url: "/onboarding", icon: Activity },
        { title: "Team & Invites", url: "/team", icon: Users },
        { title: "Org Settings", url: "/org-settings", icon: Building2 },
      ],
    },
    {
      label: "Developer & Commercial",
      items: [
        { title: "Developer Portal", url: "/developer-portal", icon: Code2 },
        { title: "Billing", url: "/billing", icon: CreditCard },
        { title: "Usage", url: "/usage-billing", icon: BarChart3 },
        { title: "Plans & Packaging", url: "/tiered-packaging", icon: Package },
      ],
    },
    {
      label: "Governance",
      items: [
        { title: "Audit Log", url: "/audit-log", icon: Activity },
        { title: "Compliance", url: "/compliance", icon: Scale },
        { title: "Trust Center", url: "/trust-center", icon: BadgeCheck },
        { title: "Policy Packs", url: "/policy-packs", icon: Shield },
      ],
    },
    {
      label: "Account",
      items: [
        { title: "MFA Setup", url: "/mfa-setup", icon: Shield },
        { title: "Settings", url: "/settings", icon: Settings },
      ],
    },
  ],
};

const ADMIN_ONLY_URLS = ["/team", "/onboarding", "/settings", "/compliance"];
const ANALYST_HIDDEN_URLS = ["/team", "/onboarding"];

const ALL_NAV_ITEMS: NavItem[] = [
  ...coreItems,
  ...navGroups.flatMap((g) => g.sections.flatMap((s) => s.items)),
  ...adminGroup.sections.flatMap((s) => s.items),
];

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
  const { currentOrg, currentOrgId, memberships, switchOrg, currentRole, isLoading: orgLoading } = useOrgContext();
  const [openGroups, setOpenGroups] = useState<Record<string, boolean>>({});
  const recentPages = useRecentPages(location);
  const [enabledModules, setEnabledModules] = useState<Set<string>>(loadEnabledModules);
  const [showModuleManager, setShowModuleManager] = useState(false);

  /** Which nav groups to actually render (core groups + user-enabled groups) */
  const visibleNavGroups = useMemo(
    () => navGroups.filter((g) => g.core || enabledModules.has(g.label)),
    [enabledModules],
  );

  /** Advanced (non-core) groups the user can toggle on/off */
  const advancedGroups = useMemo(() => navGroups.filter((g) => !g.core), []);

  const toggleModule = useCallback((label: string) => {
    setEnabledModules((prev) => {
      const next = new Set(prev);
      if (next.has(label)) next.delete(label);
      else next.add(label);
      saveEnabledModules(next);
      return next;
    });
  }, []);

  const enableAllModules = useCallback(() => {
    const all = new Set(navGroups.map((g) => g.label));
    setEnabledModules(all);
    saveEnabledModules(all);
  }, []);

  const resetModulesToDefault = useCallback(() => {
    setEnabledModules(new Set(DEFAULT_ENABLED_MODULES));
    saveEnabledModules(new Set(DEFAULT_ENABLED_MODULES));
  }, []);

  useEffect(() => {
    const initial: Record<string, boolean> = {};
    [...visibleNavGroups, adminGroup].forEach((g) => {
      const flatItems = g.sections.flatMap((s) => s.items);
      if (flatItems.some((i) => (i.url === "/" ? location === "/" : location.startsWith(i.url)))) {
        initial[g.label] = true;
      }
    });
    setOpenGroups((prev) => ({ ...prev, ...initial }));
  }, []);

  /* Auto-enable a module if the user navigates directly to one of its pages */
  useEffect(() => {
    for (const g of navGroups) {
      if (g.core || enabledModules.has(g.label)) continue;
      const flatItems = g.sections.flatMap((s) => s.items);
      if (flatItems.some((i) => location.startsWith(i.url))) {
        setEnabledModules((prev) => {
          const next = new Set(prev);
          next.add(g.label);
          saveEnabledModules(next);
          return next;
        });
        setOpenGroups((prev) => ({ ...prev, [g.label]: true }));
        break;
      }
    }
  }, [location, enabledModules]);

  const toggleGroup = (label: string) => {
    setOpenGroups((prev) => ({ ...prev, [label]: !prev[label] }));
  };

  // Don't default to "analyst" while org context is still loading — this causes
  // a visible flicker ("Analyst" → "Owner") once the real role arrives.
  const userRole = orgLoading ? null : currentRole || "analyst";
  const roleLabel = !userRole
    ? ""
    : userRole === "read_only"
      ? "Read-only"
      : userRole[0].toUpperCase() + userRole.slice(1);

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
          className="h-7 text-[13px] rounded-md transition-colors duration-150"
        >
          <Link href={item.url}>
            <item.icon className="h-3.5 w-3.5 shrink-0 opacity-50" aria-hidden="true" />
            <span className="truncate">{item.title}</span>
          </Link>
        </SidebarMenuButton>
      </SidebarMenuItem>
    );
  }

  function renderCollapsibleGroup(group: NavGroup) {
    const filteredSections = group.sections
      .map((section) => ({ ...section, items: filterItems(section.items) }))
      .filter((section) => section.items.length > 0);

    const flatItems = filteredSections.flatMap((section) => section.items);
    if (flatItems.length === 0) return null;

    const isOpen = !!openGroups[group.label];
    const hasActive = flatItems.some((i) => (i.url === "/" ? location === "/" : location.startsWith(i.url)));

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
                  className={`h-3.5 w-3.5 shrink-0 ${hasActive ? group.color : group.color + " opacity-50"}`}
                  aria-hidden="true"
                />
              </div>
              <span className="truncate text-[13px] font-semibold">{group.label}</span>
              <div className="ml-auto flex items-center gap-1">
                <span className="text-[10px] text-muted-foreground/50 tabular-nums">{flatItems.length}</span>
                <ChevronRight
                  className={`h-3 w-3 shrink-0 text-muted-foreground/40 transition-transform duration-200 ${
                    isOpen ? "rotate-90" : ""
                  }`}
                />
              </div>
            </SidebarMenuButton>
          </CollapsibleTrigger>
          <CollapsibleContent
            className="animate-fade-in"
            style={{ transition: "height 200ms ease-out, opacity 200ms ease-out" }}
          >
            <div className="ml-5 border-l border-sidebar-border/50 pl-2.5 mt-0.5 space-y-2">
              {filteredSections.map((section) => (
                <div key={section.label}>
                  <div className="px-2 py-1 text-[10px] font-medium text-muted-foreground/50 uppercase tracking-wider">
                    {section.label}
                  </div>
                  <SidebarMenu className="space-y-0">{section.items.map(renderItem)}</SidebarMenu>
                </div>
              ))}
            </div>
          </CollapsibleContent>
        </Collapsible>
      </SidebarMenuItem>
    );
  }

  return (
    <Sidebar>
      <SidebarHeader className="p-3 pb-2">
        <Link href="/" className="flex items-center gap-2.5 group/logo">
          <div className="relative flex items-center justify-center w-8 h-8 rounded-md bg-sidebar-accent/40 border border-sidebar-border/60 shadow-sm transition-colors duration-200 group-hover/logo:bg-sidebar-accent/55">
            <img src={atsLogo} alt="SecureNexus" className="w-5 h-5 object-contain" />
          </div>
          <div className="flex flex-col">
            <span className="text-sm font-semibold tracking-tight text-sidebar-foreground">SecureNexus</span>
            <span className="text-[9px] text-sidebar-foreground/40 leading-none font-medium tracking-wide uppercase">
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

        <button
          type="button"
          onClick={() => {
            window.dispatchEvent(new KeyboardEvent("keydown", { key: "k", metaKey: true, ctrlKey: true }));
          }}
          className="mt-2 w-full flex items-center gap-2 px-2 py-1.5 rounded-md bg-sidebar-accent/20 border border-sidebar-border/40 hover:bg-sidebar-accent/45 hover:border-sidebar-border transition-all duration-200 text-left"
          aria-label="Open command palette"
        >
          <Search className="h-3.5 w-3.5 text-muted-foreground/70 shrink-0" aria-hidden="true" />
          <span className="text-[11px] font-medium truncate flex-1">Search</span>
          <kbd className="text-[9px] font-semibold text-muted-foreground/40 border border-sidebar-border/40 rounded px-1.5 py-0.5">
            ⌘K
          </kbd>
        </button>

        <div className="mt-1.5 flex items-center gap-2 px-2.5 py-1.5 rounded-md bg-sidebar-accent/20 border border-sidebar-border/30">
          <div className="flex items-center gap-1.5">
            <span className="relative flex h-1.5 w-1.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
              <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-emerald-500" />
            </span>
            <span className="text-[10px] text-emerald-400/80 font-medium">Connected</span>
          </div>
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
          <div className="h-px bg-sidebar-border/60" />
        </div>

        <SidebarGroup className="px-2 py-0.5">
          <SidebarGroupContent>
            <SidebarMenu className="space-y-0">{visibleNavGroups.map(renderCollapsibleGroup)}</SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>

        {/* Module manager toggle */}
        <div className="px-3 py-1.5">
          <button
            type="button"
            onClick={() => setShowModuleManager((v) => !v)}
            className="w-full flex items-center gap-2 px-2 py-1.5 rounded-md text-[11px] font-medium text-muted-foreground/60 hover:text-muted-foreground hover:bg-sidebar-accent/30 border border-dashed border-sidebar-border/40 hover:border-sidebar-border/60 transition-all duration-200"
          >
            <Layers className="h-3.5 w-3.5 shrink-0" />
            <span>Manage Modules</span>
            {advancedGroups.length -
              Array.from(enabledModules).filter((m) => advancedGroups.some((g) => g.label === m)).length >
              0 && (
              <span className="ml-auto text-[9px] bg-blue-500/15 text-blue-400 rounded-full px-1.5 py-0.5 tabular-nums">
                +
                {advancedGroups.length -
                  Array.from(enabledModules).filter((m) => advancedGroups.some((g) => g.label === m)).length}{" "}
                hidden
              </span>
            )}
          </button>
        </div>

        {showModuleManager && (
          <div className="px-3 pb-2 animate-fade-in">
            <div className="rounded-lg border border-sidebar-border/60 bg-sidebar-accent/20 p-3 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wider">
                  Security Modules
                </span>
                <div className="flex items-center gap-1.5">
                  <button
                    type="button"
                    onClick={enableAllModules}
                    className="text-[9px] font-medium text-blue-400 hover:text-blue-300 transition-colors"
                  >
                    Enable all
                  </button>
                  <span className="text-muted-foreground/30">|</span>
                  <button
                    type="button"
                    onClick={resetModulesToDefault}
                    className="text-[9px] font-medium text-muted-foreground/50 hover:text-muted-foreground transition-colors"
                  >
                    Reset
                  </button>
                </div>
              </div>
              <div className="space-y-1">
                {advancedGroups.map((g) => {
                  const itemCount = g.sections.reduce((sum, s) => sum + s.items.length, 0);
                  const enabled = enabledModules.has(g.label);
                  return (
                    <button
                      key={g.label}
                      type="button"
                      onClick={() => toggleModule(g.label)}
                      className={`w-full flex items-center gap-2 px-2 py-1.5 rounded-md text-[11px] transition-all duration-150 ${
                        enabled
                          ? "bg-sidebar-accent/40 text-sidebar-foreground"
                          : "text-muted-foreground/50 hover:text-muted-foreground hover:bg-sidebar-accent/20"
                      }`}
                    >
                      <g.icon className={`h-3.5 w-3.5 shrink-0 ${enabled ? g.color : "opacity-40"}`} />
                      <span className="truncate text-left flex-1">{g.label}</span>
                      <span className="text-[9px] text-muted-foreground/40 tabular-nums">{itemCount}</span>
                      <div
                        className={`w-6 h-3.5 rounded-full relative transition-colors duration-200 ${
                          enabled ? "bg-blue-500" : "bg-zinc-700"
                        }`}
                      >
                        <div
                          className={`absolute top-0.5 w-2.5 h-2.5 rounded-full bg-white transition-transform duration-200 ${
                            enabled ? "translate-x-3" : "translate-x-0.5"
                          }`}
                        />
                      </div>
                    </button>
                  );
                })}
              </div>
              <p className="text-[9px] text-muted-foreground/40 leading-relaxed">
                Enable modules as your team needs them. Core modules (Watch & Recon, Investigate, Respond, Posture, Data
                & Integrations) are always visible.
              </p>
            </div>
          </div>
        )}

        <div className="px-3 py-1">
          <div className="h-px bg-sidebar-border/60" />
        </div>

        <SidebarGroup className="px-2 py-0.5">
          <SidebarGroupContent>
            <SidebarMenu className="space-y-0">{renderCollapsibleGroup(adminGroup)}</SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>

        {user?.isSuperAdmin && (
          <>
            <div className="px-3 py-1">
              <div className="h-px bg-sidebar-border/60" />
            </div>
            <SidebarGroup className="px-2 py-0.5">
              <SidebarGroupContent>
                <SidebarMenu>
                  <SidebarMenuItem>
                    <div className="flex items-center gap-1.5 px-2 py-1">
                      <ShieldCheck className="h-3 w-3 text-yellow-500/70" aria-hidden="true" />
                      <span className="text-[10px] font-medium text-yellow-500/60 uppercase tracking-wider">
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
              <div className="h-px bg-sidebar-border/60" />
            </div>
            <SidebarGroup className="px-2 py-0.5">
              <SidebarGroupContent>
                <SidebarMenu>
                  <SidebarMenuItem>
                    <div className="flex items-center gap-1.5 px-2 py-1">
                      <History className="h-3 w-3 text-muted-foreground/40" aria-hidden="true" />
                      <span className="text-[10px] font-medium text-muted-foreground/40 uppercase tracking-wider">
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
          <Avatar className="h-7 w-7 border border-sidebar-border/50">
            <AvatarImage src={user?.profileImageUrl || ""} />
            <AvatarFallback className="text-[10px] font-bold bg-blue-600/15 text-blue-400">{initials}</AvatarFallback>
          </Avatar>
          <div className="flex-1 min-w-0">
            <p className="text-[11px] font-semibold truncate leading-tight">
              {user?.firstName || "User"} {user?.lastName || ""}
            </p>
            <p className="text-[9px] text-sidebar-foreground/35 truncate leading-tight">{roleLabel}</p>
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

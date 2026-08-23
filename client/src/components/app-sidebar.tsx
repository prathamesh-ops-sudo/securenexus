import {
  LayoutDashboard,
  AlertTriangle,
  FileWarning,
  Activity,
  Settings,
  LogOut,
  Brain,
  Zap,
  ChevronRight,
  BarChart3,
  Shield,
  Crosshair,
  Workflow,
  Network,
  GitBranch,
  Scale,
  Cloud,
  Users,
  History,
  CreditCard,
  Building2,
  ShieldCheck,
  Code2,
  Mail,
  Lock,
  KeyRound,
  Fingerprint,
  Package,
  Layers,
  Search,
  Server,
  Microscope,
  Database,
  Globe,
  ShieldAlert,
  FileText,
} from "lucide-react";
import atsLogo from "@/assets/logo.png";
import { useLocation, Link } from "wouter";
import { filterNavItems } from "./sidebar-nav";
import { useAuth } from "@/hooks/use-auth";
import { useOrgContext } from "@/hooks/use-org-context";
import { PlatformTenantPicker } from "@/components/platform-tenant-picker";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";

import { useState, useEffect, useMemo, useContext } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { EventStreamContext } from "@/App";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
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
  { title: "Assets", url: "/asset-inventory", icon: Server },
  { title: "Connectors", url: "/connectors", icon: Activity },
];

const MODULE_CACHE_KEY = "securenexus.enabledModules.v3";
const CORE_MODULES = new Set(["Dashboard", "Alerts", "Incidents", "Assets", "Connectors"]);

function loadCachedEnabledModules(): Set<string> {
  try {
    const raw = localStorage.getItem(MODULE_CACHE_KEY);
    if (raw) return new Set([...Array.from(CORE_MODULES), ...(JSON.parse(raw) as string[])]);
  } catch {
    /* fall through to core-only pre-hydration state */
  }
  return new Set(CORE_MODULES);
}

const navGroups: NavGroup[] = [
  {
    label: "Threat Intelligence",
    icon: Globe,
    color: "text-cyan-400",
    sections: [
      {
        label: "Threat Intelligence",
        items: [{ title: "Threat Intelligence", url: "/threat-intelligence", icon: Globe }],
      },
    ],
  },
  {
    label: "Investigate",
    icon: Microscope,
    color: "text-violet-400",
    sections: [
      {
        label: "Investigation Tools",
        items: [
          { title: "Security Graph", url: "/security-graph-hub", icon: Network },
          { title: "Investigations", url: "/investigations", icon: Microscope },
        ],
      },
    ],
  },
  {
    label: "Respond",
    icon: Zap,
    color: "text-emerald-400",
    sections: [
      {
        label: "Response",
        items: [{ title: "Playbooks & Response", url: "/response", icon: Workflow }],
      },
    ],
  },
  {
    label: "Posture",
    icon: ShieldCheck,
    color: "text-blue-400",
    sections: [
      {
        label: "Posture",
        items: [
          { title: "Cloud & Endpoint", url: "/cloud-endpoint", icon: Cloud },
          { title: "Identity & Access", url: "/identity-access", icon: KeyRound },
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
        label: "AI Platform",
        items: [
          { title: "AI Platform", url: "/ai-platform", icon: Brain },
          { title: "AI Security", url: "/ai-security", icon: ShieldCheck },
          { title: "AI Accuracy", url: "/ai-accuracy", icon: Brain },
          { title: "Historical Replay", url: "/ai-replay", icon: History },
          { title: "SOC Reality Report", url: "/soc-reality-report", icon: FileText },
        ],
      },
    ],
  },
  {
    label: "Data & Integrations",
    icon: Database,
    color: "text-sky-400",
    sections: [
      {
        label: "Data Platform",
        items: [{ title: "Data Platform", url: "/data-platform", icon: Database }],
      },
    ],
  },
  {
    label: "Security Modules",
    icon: Shield,
    color: "text-teal-400",
    sections: [
      {
        label: "Core Modules",
        items: [
          { title: "Detection Engineering", url: "/detection-engineering", icon: ShieldAlert },
          { title: "Asset & Risk", url: "/asset-risk", icon: Server },
          { title: "Advanced Threats", url: "/advanced-threats", icon: Crosshair },
          { title: "Comms Security", url: "/comms-security", icon: Mail },
          { title: "Specialized Security", url: "/specialized-security", icon: Shield },
        ],
      },
      {
        label: "Standalone",
        items: [
          { title: "Autonomous SOC", url: "/autonomous-soc", icon: Brain },
          { title: "Developer Security", url: "/developer-security", icon: Code2 },
          { title: "Supply Chain", url: "/supply-chain", icon: GitBranch },
          { title: "Community Intel", url: "/community-intel", icon: Network },
          { title: "Privacy Engineering", url: "/privacy-engineering", icon: Fingerprint },
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
        label: "Governance",
        items: [
          { title: "Compliance & Governance", url: "/compliance-governance", icon: Scale },
          { title: "Executive & Reporting", url: "/executive-reporting", icon: BarChart3 },
          { title: "MSSP & Partners", url: "/mssp", icon: Building2 },
        ],
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
        { title: "AI Security", url: "/ai-security", icon: ShieldCheck },
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
      label: "Account",
      items: [
        { title: "MFA Setup", url: "/mfa-setup", icon: Shield },
        { title: "Settings", url: "/settings", icon: Settings },
      ],
    },
  ],
};

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

/** Live alert count badge that pulses when new alerts arrive */
function LiveAlertBadge() {
  const { eventCount } = useContext(EventStreamContext);
  const { data: stats } = useQuery<{ openAlerts?: number }>({
    queryKey: ["/api/dashboard/stats"],
    refetchInterval: 30_000,
  });
  const count = stats?.openAlerts ?? 0;
  const [flash, setFlash] = useState(false);

  useEffect(() => {
    if (eventCount > 0) {
      setFlash(true);
      const t = setTimeout(() => setFlash(false), 2000);
      return () => clearTimeout(t);
    }
  }, [eventCount]);

  if (count === 0) return null;

  const display = count > 99 ? "99+" : String(count);
  return (
    <span
      className={`ml-auto flex h-4 min-w-4 items-center justify-center rounded-full text-[9px] font-bold px-1 tabular-nums transition-all duration-300 ${
        flash ? "bg-red-500/30 text-red-300 animate-pulse scale-110" : "bg-red-500/15 text-red-400"
      }`}
    >
      {display}
    </span>
  );
}

export function AppSidebar() {
  const [location] = useLocation();
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const { user } = useAuth();
  const {
    memberships,
    currentRole,
    hasTenantContext,
    isPlatformAdminReadOnly,
    isLoading: orgLoading,
  } = useOrgContext();
  const [openGroups, setOpenGroups] = useState<Record<string, boolean>>({});
  const recentPages = useRecentPages(location);
  const [enabledModules, setEnabledModules] = useState<Set<string>>(loadCachedEnabledModules);
  const [showModuleManager, setShowModuleManager] = useState(false);
  const {
    data: moduleSettings,
    isLoading: moduleSettingsLoading,
    isError: moduleSettingsError,
  } = useQuery<{
    enabledModules: string[];
    coreModules: string[];
    canManage: boolean;
    readOnly: boolean;
  }>({
    queryKey: ["/api/org/module-settings"],
    enabled: hasTenantContext,
    staleTime: 30_000,
  });
  const moduleMutation = useMutation({
    mutationFn: (change: { moduleKey: string; enabled: boolean }) =>
      apiRequest("PUT", "/api/org/module-settings", change).then((response) => response.json()),
    onSuccess: (data: { enabledModules: string[] }) => {
      setEnabledModules(new Set(data.enabledModules));
      localStorage.setItem(MODULE_CACHE_KEY, JSON.stringify(data.enabledModules));
      queryClient.invalidateQueries({ queryKey: ["/api/org/module-settings"] });
    },
    onError: (error: Error) => {
      toast({ title: "Module setting was not saved", description: error.message, variant: "destructive" });
    },
  });
  const activeEnabledModules = useMemo(
    () => new Set(moduleSettings?.enabledModules ?? enabledModules),
    [moduleSettings, enabledModules],
  );

  /** Which nav groups to actually render (core groups + user-enabled groups) */
  const visibleNavGroups = useMemo(
    () =>
      hasTenantContext
        ? navGroups.filter(
            (g) =>
              activeEnabledModules.has(g.label) ||
              g.sections.some((section) =>
                section.items.some((item) => item.url !== "/" && location.startsWith(item.url)),
              ),
          )
        : [],
    [activeEnabledModules, hasTenantContext, location],
  );

  /** Advanced (non-core) groups the user can toggle on/off */
  const advancedGroups = useMemo(() => navGroups.filter((g) => !g.core), []);

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

  const toggleGroup = (label: string) => {
    setOpenGroups((prev) => ({ ...prev, [label]: !prev[label] }));
  };

  // Don't default to "analyst" while org context is still loading — this causes
  // a visible flicker ("Analyst" → "Owner") once the real role arrives.
  const userRole = orgLoading
    ? null
    : user?.isSuperAdmin
      ? isPlatformAdminReadOnly
        ? "read_only"
        : "super_admin"
      : currentRole;
  const roleLabel = !userRole
    ? "No organization"
    : userRole === "super_admin"
      ? "Super Admin"
      : userRole === "read_only"
        ? "Read-only"
        : userRole[0].toUpperCase() + userRole.slice(1);

  const initials = user ? `${user.firstName?.[0] || ""}${user.lastName?.[0] || ""}`.toUpperCase() || "U" : "U";
  const displayName = [user?.firstName, user?.lastName].filter(Boolean).join(" ") || user?.email || "Signed-in user";

  function filterItems(items: NavItem[]) {
    return filterNavItems(items, userRole, hasTenantContext);
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

        {(user?.isSuperAdmin || memberships.length > 0) && <PlatformTenantPicker className="mt-2 w-full" />}

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
              {hasTenantContext &&
                coreItems.map((item) => {
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
                          {item.url === "/alerts" && <LiveAlertBadge />}
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
        {hasTenantContext && (
          <div className="px-3 py-1.5">
            <button
              type="button"
              onClick={() => setShowModuleManager((v) => !v)}
              className="w-full flex items-center gap-2 px-2 py-1.5 rounded-md text-[11px] font-medium text-muted-foreground/60 hover:text-muted-foreground hover:bg-sidebar-accent/30 border border-dashed border-sidebar-border/40 hover:border-sidebar-border/60 transition-all duration-200"
            >
              <Layers className="h-3.5 w-3.5 shrink-0" />
              <span>Manage Modules</span>
              {advancedGroups.length -
                Array.from(activeEnabledModules).filter((m) => advancedGroups.some((g) => g.label === m)).length >
                0 && (
                <span className="ml-auto text-[9px] bg-blue-500/15 text-blue-400 rounded-full px-1.5 py-0.5 tabular-nums">
                  +
                  {advancedGroups.length -
                    Array.from(activeEnabledModules).filter((m) => advancedGroups.some((g) => g.label === m))
                      .length}{" "}
                  hidden
                </span>
              )}
            </button>
          </div>
        )}

        {hasTenantContext && showModuleManager && (
          <div className="px-3 pb-2 animate-fade-in">
            <div className="rounded-lg border border-sidebar-border/60 bg-sidebar-accent/20 p-3 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wider">
                  Security Modules
                </span>
                <span className="text-[9px] text-muted-foreground/50">
                  {moduleSettingsLoading
                    ? "Loading…"
                    : `${Math.max(activeEnabledModules.size - CORE_MODULES.size, 0)} enabled`}
                </span>
              </div>
              {moduleSettingsError && (
                <p className="text-[10px] text-red-400">Module settings could not be loaded. Try again later.</p>
              )}
              <div className="space-y-1">
                {advancedGroups.map((g) => {
                  const itemCount = g.sections.reduce((sum, s) => sum + s.items.length, 0);
                  const enabled = activeEnabledModules.has(g.label);
                  return (
                    <button
                      key={g.label}
                      type="button"
                      disabled={!moduleSettings?.canManage || moduleMutation.isPending}
                      onClick={() => moduleMutation.mutate({ moduleKey: g.label, enabled: !enabled })}
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
              {!moduleSettings?.canManage && !moduleSettingsLoading && (
                <p className="text-[9px] text-muted-foreground/60 leading-relaxed">
                  Only organization owners and admins can change module visibility.
                  {moduleSettings?.readOnly ? " Platform-admin tenant views are read-only." : ""}
                </p>
              )}
              {moduleSettings?.canManage && (
                <p className="text-[9px] text-muted-foreground/40 leading-relaxed">
                  Core navigation is always available. Optional modules appear for every organization member after an
                  admin saves the setting.
                </p>
              )}
            </div>
          </div>
        )}

        <div className="px-3 py-1">
          <div className="h-px bg-sidebar-border/60" />
        </div>

        {hasTenantContext && (
          <SidebarGroup className="px-2 py-0.5">
            <SidebarGroupContent>
              <SidebarMenu className="space-y-0">{renderCollapsibleGroup(adminGroup)}</SidebarMenu>
            </SidebarGroupContent>
          </SidebarGroup>
        )}

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

        {recentPages.length > 0 && hasTenantContext && (
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
                    if (!hasTenantContext) return null;
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
            <p className="text-[11px] font-semibold truncate leading-tight">{displayName}</p>
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

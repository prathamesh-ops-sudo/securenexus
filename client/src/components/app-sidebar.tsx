import { LayoutDashboard, AlertTriangle, FileWarning, Activity, Settings, LogOut, ArrowDownToLine, Plug, Brain, Zap, ChevronDown, BarChart3, Shield, Crosshair, Workflow, Network, GitBranch, Swords, Scale, Link2, TrendingUp, Bot, Gauge, Cloud, Monitor, Users, FileText, History } from "lucide-react";
import atsLogo from "@/assets/logo.jpg";
import { useLocation, Link } from "wouter";
import { useAuth } from "@/hooks/use-auth";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";
import { useState, useEffect } from "react";
import {
  Collapsible,
  CollapsibleTrigger,
  CollapsibleContent,
} from "@/components/ui/collapsible";
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

type NavItem = { title: string; url: string; icon: any };

const coreItems: NavItem[] = [
  { title: "Dashboard", url: "/", icon: LayoutDashboard },
  { title: "Alerts", url: "/alerts", icon: AlertTriangle },
  { title: "Incidents", url: "/incidents", icon: FileWarning },
];

type NavGroup = { label: string; icon: any; items: NavItem[] };

const navGroups: NavGroup[] = [
  {
    label: "Investigation",
    icon: Crosshair,
    items: [
      { title: "Threat Intel", url: "/threat-intel", icon: Shield },
      { title: "MITRE ATT&CK", url: "/mitre-attack", icon: Crosshair },
      { title: "Entity Graph", url: "/entity-graph", icon: Network },
      { title: "Attack Graph", url: "/attack-graph", icon: GitBranch },
      { title: "Kill Chain", url: "/kill-chain", icon: Swords },
    ],
  },
  {
    label: "Analytics & Defense",
    icon: BarChart3,
    items: [
      { title: "Analytics", url: "/analytics", icon: BarChart3 },
      { title: "Reports", url: "/reports", icon: FileText },
      { title: "Predictive Defense", url: "/predictive-defense", icon: TrendingUp },
      { title: "Security Posture", url: "/security-posture", icon: Gauge },
    ],
  },
  {
    label: "Response",
    icon: Bot,
    items: [
      { title: "Autonomous Response", url: "/autonomous-response", icon: Bot },
      { title: "Playbooks", url: "/playbooks", icon: Workflow },
    ],
  },
  {
    label: "Assets & Data",
    icon: Monitor,
    items: [
      { title: "CSPM", url: "/cspm", icon: Cloud },
      { title: "Endpoint Telemetry", url: "/endpoint-telemetry", icon: Monitor },
      { title: "Connectors", url: "/connectors", icon: Plug },
      { title: "Integrations", url: "/integrations", icon: Link2 },
      { title: "Ingestion", url: "/ingestion", icon: ArrowDownToLine },
    ],
  },
  {
    label: "Platform",
    icon: Brain,
    items: [
      { title: "AI Engine", url: "/ai-engine", icon: Brain },
      { title: "Operations", url: "/operations", icon: Zap },
    ],
  },
];

const adminGroup: NavGroup = {
  label: "Admin",
  icon: Settings,
  items: [
    { title: "Onboarding", url: "/onboarding", icon: Activity },
    { title: "Team Management", url: "/team", icon: Users },
    { title: "Audit Log", url: "/audit-log", icon: Activity },
    { title: "Compliance", url: "/compliance", icon: Scale },
    { title: "Settings", url: "/settings", icon: Settings },
  ],
};

const ADMIN_ONLY_URLS = ["/team", "/onboarding", "/settings", "/compliance"];
const ANALYST_HIDDEN_URLS = ["/team", "/onboarding"];

const ALL_NAV_ITEMS: NavItem[] = [
  ...coreItems,
  ...navGroups.flatMap(g => g.items),
  ...adminGroup.items,
];

const RECENT_PAGES_KEY = "securenexus.recentPages.v1";
const MAX_RECENT = 5;

function useRecentPages(currentPath: string) {
  const [recent, setRecent] = useState<string[]>([]);

  useEffect(() => {
    try {
      const raw = localStorage.getItem(RECENT_PAGES_KEY);
      if (raw) setRecent(JSON.parse(raw));
    } catch { setRecent([]); }
  }, []);

  useEffect(() => {
    if (!currentPath || currentPath.includes(":")) return;
    const match = ALL_NAV_ITEMS.find(i => i.url === currentPath);
    if (!match) return;
    setRecent(prev => {
      const next = [currentPath, ...prev.filter(p => p !== currentPath)].slice(0, MAX_RECENT);
      localStorage.setItem(RECENT_PAGES_KEY, JSON.stringify(next));
      return next;
    });
  }, [currentPath]);

  return recent.slice(1);
}

export function AppSidebar() {
  const [location] = useLocation();
  const { user } = useAuth();
  const [openGroups, setOpenGroups] = useState<Record<string, boolean>>({});
  const recentPages = useRecentPages(location);

  useEffect(() => {
    const initial: Record<string, boolean> = {};
    [...navGroups, adminGroup].forEach(g => {
      if (g.items.some(i => i.url === "/" ? location === "/" : location.startsWith(i.url))) {
        initial[g.label] = true;
      }
    });
    setOpenGroups(prev => ({ ...prev, ...initial }));
  }, []);

  const toggleGroup = (label: string) => {
    setOpenGroups(prev => ({ ...prev, [label]: !prev[label] }));
  };

  const userRole = (user as any)?.role || "analyst";

  const initials = user
    ? `${user.firstName?.[0] || ""}${user.lastName?.[0] || ""}`.toUpperCase() || "U"
    : "U";

  function filterItems(items: NavItem[]) {
    if (userRole === "owner" || userRole === "admin") return items;
    if (userRole === "read_only") return items.filter(i => !ADMIN_ONLY_URLS.includes(i.url));
    return items.filter(i => !ANALYST_HIDDEN_URLS.includes(i.url));
  }

  function renderItem(item: NavItem) {
    const isActive = item.url === "/" ? location === "/" : location.startsWith(item.url);
    return (
      <SidebarMenuItem key={item.title}>
        <SidebarMenuButton asChild isActive={isActive} aria-label={`Navigate to ${item.title}`}>
          <Link href={item.url}>
            <item.icon className="h-4 w-4 shrink-0" aria-hidden="true" />
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
    const hasActive = filtered.some(i => i.url === "/" ? location === "/" : location.startsWith(i.url));

    return (
      <Collapsible key={group.label} open={isOpen} onOpenChange={() => toggleGroup(group.label)}>
        <SidebarMenuItem>
          <CollapsibleTrigger asChild>
            <SidebarMenuButton className="w-full" data-active={hasActive || undefined}>
              <group.icon className="h-4 w-4 shrink-0" />
              <span className="truncate font-medium">{group.label}</span>
              <ChevronDown className={`ml-auto h-3.5 w-3.5 shrink-0 text-muted-foreground transition-transform duration-200 ${isOpen ? "rotate-180" : ""}`} />
            </SidebarMenuButton>
          </CollapsibleTrigger>
          <CollapsibleContent>
            <SidebarMenu className="ml-4 border-l border-sidebar-border pl-2 mt-0.5">
              {filtered.map(renderItem)}
            </SidebarMenu>
          </CollapsibleContent>
        </SidebarMenuItem>
      </Collapsible>
    );
  }

  return (
    <Sidebar>
      <SidebarHeader className="p-3 pb-2">
        <Link href="/" className="flex items-center gap-2.5">
          <div className="relative flex items-center justify-center w-8 h-8 rounded-md bg-gradient-to-br from-red-600/20 to-red-500/5 border border-red-500/20">
            <img src={atsLogo} alt="ATS" className="w-6 h-6 object-contain" />
          </div>
          <div className="flex flex-col">
            <span className="text-sm font-bold tracking-tight gradient-text-red">SecureNexus</span>
            <span className="text-[10px] text-sidebar-foreground/40 leading-none font-medium">AI Security Platform</span>
          </div>
        </Link>
        <div className="mt-2 flex items-center gap-2 px-2 py-1 rounded-md glass-subtle">
          <div className="flex items-center gap-1.5">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500" />
            </span>
            <span className="text-[10px] text-sidebar-foreground/50 font-medium">System Online</span>
          </div>
          <Badge variant="outline" className="text-[9px] px-1.5 py-0 h-4 ml-auto gradient-badge glow-red-subtle">
            <Zap className="h-2.5 w-2.5 mr-0.5" />
            PRO
          </Badge>
        </div>
      </SidebarHeader>

      <SidebarSeparator />

      <SidebarContent className="gap-0 [&>div]:py-0">
        <SidebarGroup className="px-2 py-1">
          <SidebarGroupContent>
            <SidebarMenu>
              {coreItems.map(renderItem)}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>

        <SidebarSeparator className="my-0" />

        <SidebarGroup className="px-2 py-1">
          <SidebarGroupContent>
            <SidebarMenu>
              {navGroups.map(renderCollapsibleGroup)}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>

        <SidebarSeparator className="my-0" />

        <SidebarGroup className="px-2 py-1">
          <SidebarGroupContent>
            <SidebarMenu>
              {renderCollapsibleGroup(adminGroup)}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>

        {recentPages.length > 0 && (
          <>
            <SidebarSeparator className="my-0" />
            <SidebarGroup className="px-2 py-1">
              <SidebarGroupContent>
                <SidebarMenu>
                  <SidebarMenuItem>
                    <div className="flex items-center gap-1.5 px-2 py-1">
                      <History className="h-3 w-3 text-muted-foreground" aria-hidden="true" />
                      <span className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider">Recent</span>
                    </div>
                  </SidebarMenuItem>
                  {recentPages.map(path => {
                    const item = ALL_NAV_ITEMS.find(i => i.url === path);
                    if (!item) return null;
                    return renderItem(item);
                  })}
                </SidebarMenu>
              </SidebarGroupContent>
            </SidebarGroup>
          </>
        )}
      </SidebarContent>

      <SidebarSeparator />

      <SidebarFooter className="p-2.5">
        <div className="flex items-center gap-2.5 px-1 mb-1.5">
          <Avatar className="h-7 w-7 border border-sidebar-border">
            <AvatarImage src={user?.profileImageUrl || ""} />
            <AvatarFallback className="text-[10px] font-semibold bg-red-500/15 text-red-400">{initials}</AvatarFallback>
          </Avatar>
          <div className="flex-1 min-w-0">
            <p className="text-xs font-medium truncate">{user?.firstName || "User"} {user?.lastName || ""}</p>
            <p className="text-[10px] text-sidebar-foreground/40 truncate">Security Analyst</p>
          </div>
        </div>
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton asChild>
              <a href="/api/logout">
                <LogOut className="h-4 w-4" />
                <span>Log out</span>
              </a>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarFooter>
    </Sidebar>
  );
}

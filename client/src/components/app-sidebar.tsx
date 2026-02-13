import { LayoutDashboard, AlertTriangle, FileWarning, Activity, Settings, LogOut, ArrowDownToLine, Plug, Brain, Zap, ChevronRight, BarChart3, Shield, Crosshair, Workflow, Network, GitBranch, Swords, Scale, Link2 } from "lucide-react";
import atsLogo from "@assets/Screenshot_20260213_122029_Google_1770965513052.jpg";
import { useLocation, Link } from "wouter";
import { useAuth } from "@/hooks/use-auth";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";
import {
  Sidebar,
  SidebarContent,
  SidebarGroup,
  SidebarGroupLabel,
  SidebarGroupContent,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarHeader,
  SidebarFooter,
  SidebarSeparator,
} from "@/components/ui/sidebar";

const mainNavItems = [
  { title: "Dashboard", url: "/", icon: LayoutDashboard, description: "Overview & analytics" },
  { title: "Alerts", url: "/alerts", icon: AlertTriangle, description: "Threat alerts" },
  { title: "Incidents", url: "/incidents", icon: FileWarning, description: "Active incidents" },
  { title: "Analytics", url: "/analytics", icon: BarChart3, description: "Security metrics" },
  { title: "Threat Intel", url: "/threat-intel", icon: Shield, description: "IOC intelligence" },
  { title: "MITRE ATT&CK", url: "/mitre-attack", icon: Crosshair, description: "Attack framework" },
  { title: "Entity Graph", url: "/entity-graph", icon: Network, description: "Identity resolution" },
  { title: "Attack Graph", url: "/attack-graph", icon: GitBranch, description: "Attack path correlation" },
  { title: "Kill Chain", url: "/kill-chain", icon: Swords, description: "Attack progression" },
];

const systemNavItems = [
  { title: "Ingestion", url: "/ingestion", icon: ArrowDownToLine, description: "Data pipeline" },
  { title: "Connectors", url: "/connectors", icon: Plug, description: "Integrations" },
  { title: "AI Engine", url: "/ai-engine", icon: Brain, description: "Correlation engine" },
  { title: "Playbooks", url: "/playbooks", icon: Workflow, description: "Automation playbooks" },
  { title: "Integrations", url: "/integrations", icon: Link2, description: "External integrations" },
];

const adminNavItems = [
  { title: "Audit Log", url: "/audit-log", icon: Activity, description: "Activity history" },
  { title: "Compliance", url: "/compliance", icon: Scale, description: "Data governance" },
  { title: "Settings", url: "/settings", icon: Settings, description: "Configuration" },
];

export function AppSidebar() {
  const [location] = useLocation();
  const { user } = useAuth();

  const initials = user
    ? `${user.firstName?.[0] || ""}${user.lastName?.[0] || ""}`.toUpperCase() || "U"
    : "U";

  function renderNavGroup(items: typeof mainNavItems) {
    return (
      <SidebarMenu>
        {items.map((item) => {
          const isActive = item.url === "/" ? location === "/" : location.startsWith(item.url);
          return (
            <SidebarMenuItem key={item.title}>
              <SidebarMenuButton
                asChild
                isActive={isActive}
                data-testid={`nav-${item.title.toLowerCase().replace(/\s/g, "-")}`}
              >
                <Link href={item.url}>
                  <item.icon className="h-4 w-4" />
                  <span>{item.title}</span>
                  {isActive && <ChevronRight className="ml-auto h-3 w-3 opacity-50" />}
                </Link>
              </SidebarMenuButton>
            </SidebarMenuItem>
          );
        })}
      </SidebarMenu>
    );
  }

  return (
    <Sidebar>
      <SidebarHeader className="p-4 pb-3 animate-fade-in gradient-sidebar-header">
        <Link href="/" className="flex items-center gap-3">
          <div className="relative flex items-center justify-center w-9 h-9 rounded-md bg-gradient-to-br from-red-600/20 to-red-500/5 border border-red-500/20 glow-red-subtle">
            <img src={atsLogo} alt="ATS" className="w-7 h-7 object-contain" />
          </div>
          <div className="flex flex-col">
            <span className="text-sm font-bold tracking-tight gradient-text-red" data-testid="text-app-name">SecureNexus</span>
            <span className="text-[10px] text-sidebar-foreground/40 leading-none font-medium">AI Security Platform</span>
          </div>
        </Link>
        <div className="mt-3 flex items-center gap-2 px-2 py-1.5 rounded-md glass-subtle">
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

      <SidebarContent>
        <SidebarGroup>
          <SidebarGroupLabel className="text-[10px] uppercase tracking-widest text-sidebar-foreground/35 font-semibold">Threat Center</SidebarGroupLabel>
          <SidebarGroupContent>
            {renderNavGroup(mainNavItems)}
          </SidebarGroupContent>
        </SidebarGroup>

        <SidebarGroup>
          <SidebarGroupLabel className="text-[10px] uppercase tracking-widest text-sidebar-foreground/35 font-semibold">Intelligence</SidebarGroupLabel>
          <SidebarGroupContent>
            {renderNavGroup(systemNavItems)}
          </SidebarGroupContent>
        </SidebarGroup>

        <SidebarGroup>
          <SidebarGroupLabel className="text-[10px] uppercase tracking-widest text-sidebar-foreground/35 font-semibold">Administration</SidebarGroupLabel>
          <SidebarGroupContent>
            {renderNavGroup(adminNavItems)}
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>

      <SidebarSeparator />

      <SidebarFooter className="p-3">
        <div className="flex items-center gap-3 px-1 mb-2">
          <Avatar className="h-8 w-8 border border-sidebar-border smooth-all">
            <AvatarImage src={user?.profileImageUrl || ""} />
            <AvatarFallback className="text-xs font-semibold bg-red-500/15 text-red-400">{initials}</AvatarFallback>
          </Avatar>
          <div className="flex-1 min-w-0">
            <p className="text-sm font-medium truncate" data-testid="text-user-name">{user?.firstName || "User"} {user?.lastName || ""}</p>
            <p className="text-[10px] text-sidebar-foreground/40 truncate">Security Analyst</p>
          </div>
        </div>
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton asChild data-testid="button-logout">
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

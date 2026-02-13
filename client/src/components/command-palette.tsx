import { useState, useEffect, useCallback } from "react";
import { useLocation } from "wouter";
import { useQuery } from "@tanstack/react-query";
import {
  CommandDialog,
  CommandInput,
  CommandList,
  CommandEmpty,
  CommandGroup,
  CommandItem,
  CommandSeparator,
} from "@/components/ui/command";
import {
  LayoutDashboard,
  AlertTriangle,
  FileWarning,
  ArrowDownToLine,
  Plug,
  Brain,
  Activity,
  Settings,
  Zap,
  Key,
  Plus,
  Network,
  BarChart3,
  Shield,
  Crosshair,
  Workflow,
} from "lucide-react";
import { SeverityBadge } from "@/components/security-badges";
import type { Alert, Incident } from "@shared/schema";

const navigationItems = [
  { label: "Dashboard", icon: LayoutDashboard, path: "/" },
  { label: "Alerts", icon: AlertTriangle, path: "/alerts" },
  { label: "Incidents", icon: FileWarning, path: "/incidents" },
  { label: "Analytics", icon: BarChart3, path: "/analytics" },
  { label: "Threat Intel", icon: Shield, path: "/threat-intel" },
  { label: "MITRE ATT&CK", icon: Crosshair, path: "/mitre-attack" },
  { label: "Entity Graph", icon: Network, path: "/entity-graph" },
  { label: "Ingestion", icon: ArrowDownToLine, path: "/ingestion" },
  { label: "Connectors", icon: Plug, path: "/connectors" },
  { label: "AI Engine", icon: Brain, path: "/ai-engine" },
  { label: "Playbooks", icon: Workflow, path: "/playbooks" },
  { label: "Audit Log", icon: Activity, path: "/audit-log" },
  { label: "Settings", icon: Settings, path: "/settings" },
];

export function CommandPalette() {
  const [open, setOpen] = useState(false);
  const [, navigate] = useLocation();

  const { data: alerts } = useQuery<Alert[]>({
    queryKey: ["/api/alerts"],
  });

  const { data: incidents } = useQuery<Incident[]>({
    queryKey: ["/api/incidents"],
  });

  useEffect(() => {
    const down = (e: KeyboardEvent) => {
      if (e.key === "k" && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        setOpen((prev) => !prev);
      }
    };
    document.addEventListener("keydown", down);
    return () => document.removeEventListener("keydown", down);
  }, []);

  const runCommand = useCallback(
    (command: () => void) => {
      setOpen(false);
      command();
    },
    []
  );

  const recentAlerts = alerts?.slice(0, 5) ?? [];
  const recentIncidents = incidents?.slice(0, 5) ?? [];

  return (
    <CommandDialog open={open} onOpenChange={setOpen} data-testid="command-palette">
      <CommandInput placeholder="Type a command or search..." data-testid="input-command-search" />
      <CommandList>
        <CommandEmpty>No results found.</CommandEmpty>

        <CommandGroup heading="Navigation">
          {navigationItems.map((item) => (
            <CommandItem
              key={item.path}
              onSelect={() => runCommand(() => navigate(item.path))}
              data-testid={`command-nav-${item.label.toLowerCase().replace(/\s+/g, "-")}`}
            >
              <item.icon className="mr-2" />
              <span>{item.label}</span>
            </CommandItem>
          ))}
        </CommandGroup>

        <CommandSeparator />

        {recentAlerts.length > 0 && (
          <>
            <CommandGroup heading="Recent Alerts">
              {recentAlerts.map((alert) => (
                <CommandItem
                  key={alert.id}
                  onSelect={() => runCommand(() => navigate(`/alerts/${alert.id}`))}
                  data-testid={`command-alert-${alert.id}`}
                >
                  <AlertTriangle className="mr-2" />
                  <span className="flex-1 truncate">{alert.title}</span>
                  <SeverityBadge severity={alert.severity} />
                </CommandItem>
              ))}
            </CommandGroup>
            <CommandSeparator />
          </>
        )}

        {recentIncidents.length > 0 && (
          <>
            <CommandGroup heading="Recent Incidents">
              {recentIncidents.map((incident) => (
                <CommandItem
                  key={incident.id}
                  onSelect={() => runCommand(() => navigate(`/incidents/${incident.id}`))}
                  data-testid={`command-incident-${incident.id}`}
                >
                  <FileWarning className="mr-2" />
                  <span className="flex-1 truncate">{incident.title}</span>
                  <SeverityBadge severity={incident.severity} />
                </CommandItem>
              ))}
            </CommandGroup>
            <CommandSeparator />
          </>
        )}

        <CommandGroup heading="Quick Actions">
          <CommandItem
            onSelect={() =>
              runCommand(() => {
                navigate("/alerts");
                setTimeout(() => {
                  const btn = document.querySelector('[data-testid="button-ai-correlate"]') as HTMLButtonElement;
                  btn?.click();
                }, 500);
              })
            }
            data-testid="command-action-correlate"
          >
            <Zap className="mr-2" />
            <span>Run AI Correlation</span>
          </CommandItem>
          <CommandItem
            onSelect={() => runCommand(() => navigate("/settings"))}
            data-testid="command-action-create-api-key"
          >
            <Key className="mr-2" />
            <span>Create API Key</span>
          </CommandItem>
          <CommandItem
            onSelect={() => runCommand(() => navigate("/connectors"))}
            data-testid="command-action-add-connector"
          >
            <Plus className="mr-2" />
            <span>Add Connector</span>
          </CommandItem>
        </CommandGroup>
      </CommandList>
    </CommandDialog>
  );
}

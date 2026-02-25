import { useState, useEffect, useCallback, useMemo } from "react";
import { useLocation } from "wouter";
import { useQuery } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
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
  Download,
  Users,
  FileText,
  Bot,
  Scale,
  ShieldCheck,
  RefreshCw,
  History,
  UserPlus,
  Play,
  Search,
} from "lucide-react";
import { SeverityBadge } from "@/components/security-badges";
import type { Alert, Incident } from "@shared/schema";

const RECENT_RECORDS_KEY = "securenexus.recentRecords.v1";
const MAX_RECENT_RECORDS = 10;

type RecentRecord = {
  type: "alert" | "incident" | "entity" | "page";
  id: string;
  label: string;
  path: string;
  visitedAt: number;
};

function loadRecentRecords(): RecentRecord[] {
  try {
    const raw = localStorage.getItem(RECENT_RECORDS_KEY);
    if (raw) return JSON.parse(raw);
  } catch {}
  return [];
}

function saveRecentRecord(record: Omit<RecentRecord, "visitedAt">) {
  const records = loadRecentRecords();
  const updated = [
    { ...record, visitedAt: Date.now() },
    ...records.filter(r => !(r.type === record.type && r.id === record.id)),
  ].slice(0, MAX_RECENT_RECORDS);
  localStorage.setItem(RECENT_RECORDS_KEY, JSON.stringify(updated));
}

const navigationItems = [
  { label: "Dashboard", icon: LayoutDashboard, path: "/" },
  { label: "Alerts", icon: AlertTriangle, path: "/alerts" },
  { label: "Incidents", icon: FileWarning, path: "/incidents" },
  { label: "Analytics", icon: BarChart3, path: "/analytics" },
  { label: "Reports", icon: FileText, path: "/reports" },
  { label: "Threat Intel", icon: Shield, path: "/threat-intel" },
  { label: "MITRE ATT&CK", icon: Crosshair, path: "/mitre-attack" },
  { label: "Entity Graph", icon: Network, path: "/entity-graph" },
  { label: "Autonomous Response", icon: Bot, path: "/autonomous-response" },
  { label: "Ingestion", icon: ArrowDownToLine, path: "/ingestion" },
  { label: "Connectors", icon: Plug, path: "/connectors" },
  { label: "AI Engine", icon: Brain, path: "/ai-engine" },
  { label: "Playbooks", icon: Workflow, path: "/playbooks" },
  { label: "Operations", icon: Zap, path: "/operations" },
  { label: "Team Management", icon: Users, path: "/team" },
  { label: "Audit Log", icon: Activity, path: "/audit-log" },
  { label: "Compliance", icon: Scale, path: "/compliance" },
  { label: "Settings", icon: Settings, path: "/settings" },
];

export function CommandPalette() {
  const [open, setOpen] = useState(false);
  const [, navigate] = useLocation();
  const { toast } = useToast();

  const { data: alerts } = useQuery<Alert[]>({
    queryKey: ["/api/alerts"],
  });

  const { data: incidents } = useQuery<Incident[]>({
    queryKey: ["/api/incidents"],
  });

  const recentRecords = useMemo(() => loadRecentRecords(), [open]);

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

  const handleCreateIncident = useCallback(() => {
    const title = prompt("Incident title:");
    if (!title?.trim()) return;
    apiRequest("POST", "/api/incidents", {
      title: title.trim(),
      severity: "medium",
      status: "open",
    }).then(() => {
      queryClient.invalidateQueries({ queryKey: ["/api/incidents"] });
      toast({ title: "Incident created", description: title.trim() });
      navigate("/incidents");
    }).catch(() => {
      toast({ title: "Failed to create incident", variant: "destructive" });
    });
  }, [toast, navigate]);

  const handleAssignAlert = useCallback(() => {
    if (!alerts?.length) {
      toast({ title: "No alerts available", variant: "destructive" });
      return;
    }
    const alertTitle = alerts[0].title;
    const name = prompt(`Assign "${alertTitle}" to:`);
    if (!name?.trim()) return;
    apiRequest("PATCH", `/api/alerts/${alerts[0].id}`, { assignedTo: name.trim() }).then(() => {
      queryClient.invalidateQueries({ queryKey: ["/api/alerts"] });
      toast({ title: "Alert assigned", description: `Assigned to ${name.trim()}` });
    }).catch(() => {
      toast({ title: "Failed to assign", variant: "destructive" });
    });
  }, [alerts, toast]);

  const handleRunPlaybook = useCallback(() => {
    navigate("/playbooks");
    toast({ title: "Navigate to Playbooks", description: "Select a playbook to execute" });
  }, [navigate, toast]);

  const handleOpenEntity = useCallback(() => {
    const entity = prompt("Entity to search (IP, hostname, user, hash):");
    if (!entity?.trim()) return;
    navigate(`/entity-graph?search=${encodeURIComponent(entity.trim())}`);
    saveRecentRecord({ type: "entity", id: entity.trim(), label: entity.trim(), path: `/entity-graph?search=${encodeURIComponent(entity.trim())}` });
  }, [navigate]);

  const recentAlerts = alerts?.slice(0, 5) ?? [];
  const recentIncidents = incidents?.slice(0, 5) ?? [];

  return (
    <CommandDialog open={open} onOpenChange={setOpen} data-testid="command-palette">
      <CommandInput placeholder="Type a command or search..." data-testid="input-command-search" />
      <CommandList>
        <CommandEmpty>No results found.</CommandEmpty>

        {recentRecords.length > 0 && (
          <>
            <CommandGroup heading="Recently Viewed">
              {recentRecords.slice(0, 5).map((record) => (
                <CommandItem
                  key={`${record.type}-${record.id}`}
                  onSelect={() => runCommand(() => navigate(record.path))}
                >
                  <History className="mr-2 h-4 w-4 text-muted-foreground" />
                  <span className="flex-1 truncate">{record.label}</span>
                  <span className="text-[10px] text-muted-foreground uppercase">{record.type}</span>
                </CommandItem>
              ))}
            </CommandGroup>
            <CommandSeparator />
          </>
        )}

        <CommandGroup heading="Operations">
          <CommandItem
            onSelect={() => runCommand(handleCreateIncident)}
            data-testid="command-op-create-incident"
          >
            <Plus className="mr-2" />
            <span>Create Incident</span>
          </CommandItem>
          <CommandItem
            onSelect={() => runCommand(handleAssignAlert)}
            data-testid="command-op-assign-alert"
          >
            <UserPlus className="mr-2" />
            <span>Assign Latest Alert</span>
          </CommandItem>
          <CommandItem
            onSelect={() => runCommand(handleRunPlaybook)}
            data-testid="command-op-run-playbook"
          >
            <Play className="mr-2" />
            <span>Run Playbook</span>
          </CommandItem>
          <CommandItem
            onSelect={() => runCommand(handleOpenEntity)}
            data-testid="command-op-open-entity"
          >
            <Search className="mr-2" />
            <span>Open Entity (IP, Host, User)</span>
          </CommandItem>
        </CommandGroup>

        <CommandSeparator />

        <CommandGroup heading="Navigation">
          {navigationItems.map((item) => (
            <CommandItem
              key={item.path}
              onSelect={() => runCommand(() => {
                navigate(item.path);
                saveRecentRecord({ type: "page", id: item.path, label: item.label, path: item.path });
              })}
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
                  onSelect={() => runCommand(() => {
                    navigate(`/alerts/${alert.id}`);
                    saveRecentRecord({ type: "alert", id: alert.id, label: alert.title, path: `/alerts/${alert.id}` });
                  })}
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
                  onSelect={() => runCommand(() => {
                    navigate(`/incidents/${incident.id}`);
                    saveRecentRecord({ type: "incident", id: incident.id, label: incident.title, path: `/incidents/${incident.id}` });
                  })}
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
          <CommandItem
            onSelect={() => runCommand(() => window.open("/api/export/alerts", "_blank"))}
            data-testid="command-action-export-alerts"
          >
            <Download className="mr-2" />
            <span>Export Alerts (CSV)</span>
          </CommandItem>
          <CommandItem
            onSelect={() => runCommand(() => window.open("/api/export/incidents", "_blank"))}
            data-testid="command-action-export-incidents"
          >
            <Download className="mr-2" />
            <span>Export Incidents (CSV)</span>
          </CommandItem>
          <CommandItem
            onSelect={() =>
              runCommand(() => {
                navigate("/alerts");
                setTimeout(() => {
                  const btn = document.querySelector('[data-testid="button-scan-duplicates"]') as HTMLButtonElement;
                  btn?.click();
                }, 500);
              })
            }
            data-testid="command-action-scan-duplicates"
          >
            <RefreshCw className="mr-2" />
            <span>Scan for Duplicate Alerts</span>
          </CommandItem>
          <CommandItem
            onSelect={() => runCommand(() => navigate("/compliance"))}
            data-testid="command-action-audit-verify"
          >
            <ShieldCheck className="mr-2" />
            <span>Verify Audit Integrity</span>
          </CommandItem>
          <CommandItem
            onSelect={() => runCommand(() => navigate("/team"))}
            data-testid="command-action-manage-team"
          >
            <Users className="mr-2" />
            <span>Manage Team Members</span>
          </CommandItem>
        </CommandGroup>
      </CommandList>
    </CommandDialog>
  );
}

import { Switch, Route } from "wouter";
import { createContext, useContext } from "react";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { ThemeProvider } from "@/components/theme-provider";
import { ThemeToggle } from "@/components/theme-toggle";
import { useAuth } from "@/hooks/use-auth";
import { useEventStream } from "@/hooks/use-event-stream";
import type { StreamEvent } from "@/hooks/use-event-stream";
import { SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar";
import { AppSidebar } from "@/components/app-sidebar";
import LandingPage from "@/pages/landing";
import Dashboard from "@/pages/dashboard";
import AlertsPage from "@/pages/alerts";
import IncidentsPage from "@/pages/incidents";
import IncidentDetailPage from "@/pages/incident-detail";
import AuditLogPage from "@/pages/audit-log";
import SettingsPage from "@/pages/settings";
import IngestionPage from "@/pages/ingestion";
import ConnectorsPage from "@/pages/connectors";
import AIEnginePage from "@/pages/ai-engine";
import AlertDetailPage from "@/pages/alert-detail";
import AnalyticsPage from "@/pages/analytics";
import ThreatIntelPage from "@/pages/threat-intel";
import MitreAttackPage from "@/pages/mitre-attack";
import PlaybooksPage from "@/pages/playbooks";
import EntityGraphPage from "@/pages/entity-graph";
import AttackGraphPage from "@/pages/attack-graph";
import KillChainPage from "@/pages/kill-chain";
import CompliancePage from "@/pages/compliance";
import IntegrationsPage from "@/pages/integrations";
import PredictiveDefensePage from "@/pages/predictive-defense";
import AutonomousResponsePage from "@/pages/autonomous-response";
import SecurityPosturePage from "@/pages/security-posture";
import CspmPage from "@/pages/cspm";
import EndpointTelemetryPage from "@/pages/endpoint-telemetry";
import TeamManagementPage from "@/pages/team-management";
import ReportsPage from "@/pages/reports";
import OperationsPage from "@/pages/operations";
import OnboardingPage from "@/pages/onboarding";
import UsageBillingPage from "@/pages/usage-billing";
import NotFound from "@/pages/not-found";
import { CommandPalette } from "@/components/command-palette";
import { OnboardingChecklist } from "@/components/onboarding-checklist";
import { PlanLimitBanner } from "@/components/plan-limit-banner";
import { Skeleton } from "@/components/ui/skeleton";

interface EventStreamContextType {
  connected: boolean;
  connectionState: string;
  eventCount: number;
  events: StreamEvent[];
  lastEvent: StreamEvent | null;
}

const EventStreamContext = createContext<EventStreamContextType>({
  connected: false,
  connectionState: "disconnected",
  eventCount: 0,
  events: [],
  lastEvent: null,
});

export function useEventStreamContext() {
  return useContext(EventStreamContext);
}

function AuthenticatedApp() {
  const { connected, connectionState, eventCount, events, lastEvent } = useEventStream({ enabled: true });

  const style = {
    "--sidebar-width": "16rem",
    "--sidebar-width-icon": "3rem",
  };

  const dotColor =
    connectionState === "connected"
      ? "bg-green-500"
      : connectionState === "connecting"
        ? "bg-yellow-500"
        : "bg-red-500";

  return (
    <EventStreamContext.Provider value={{ connected, connectionState, eventCount, events, lastEvent }}>
      <SidebarProvider style={style as React.CSSProperties}>
        <div className="flex h-screen w-full relative">
          <div className="ambient-mesh" />
          <div className="noise-overlay" />
          <AppSidebar />
          <div className="flex flex-col flex-1 min-w-0 relative z-10">
            <PlanLimitBanner />
            <header className="flex items-center justify-between gap-4 px-3 py-2 border-b border-border/50 sticky top-0 z-40 glass-strong gradient-bg-red-subtle">
              <div className="flex items-center gap-2">
                <SidebarTrigger data-testid="button-sidebar-toggle" />
                <div
                  className={`w-2 h-2 rounded-full ${dotColor}`}
                  data-testid="indicator-sse-status"
                />
              </div>
              <ThemeToggle />
            </header>
            <main className="flex-1 overflow-auto">
              <Switch>
                <Route path="/" component={Dashboard} />
                <Route path="/alerts/:id" component={AlertDetailPage} />
                <Route path="/alerts" component={AlertsPage} />
                <Route path="/incidents" component={IncidentsPage} />
                <Route path="/incidents/:id" component={IncidentDetailPage} />
                <Route path="/ingestion" component={IngestionPage} />
                <Route path="/connectors" component={ConnectorsPage} />
                <Route path="/ai-engine" component={AIEnginePage} />
                <Route path="/analytics" component={AnalyticsPage} />
                <Route path="/threat-intel" component={ThreatIntelPage} />
                <Route path="/mitre-attack" component={MitreAttackPage} />
                <Route path="/entity-graph" component={EntityGraphPage} />
                <Route path="/attack-graph" component={AttackGraphPage} />
                <Route path="/kill-chain" component={KillChainPage} />
                <Route path="/playbooks" component={PlaybooksPage} />
                <Route path="/integrations" component={IntegrationsPage} />
                <Route path="/predictive-defense" component={PredictiveDefensePage} />
                <Route path="/autonomous-response" component={AutonomousResponsePage} />
                <Route path="/security-posture" component={SecurityPosturePage} />
                <Route path="/cspm" component={CspmPage} />
                <Route path="/endpoint-telemetry" component={EndpointTelemetryPage} />
                <Route path="/audit-log" component={AuditLogPage} />
                <Route path="/compliance" component={CompliancePage} />
                <Route path="/settings" component={SettingsPage} />
                <Route path="/team" component={TeamManagementPage} />
                <Route path="/reports" component={ReportsPage} />
                <Route path="/operations" component={OperationsPage} />
                <Route path="/onboarding" component={OnboardingPage} />
                <Route path="/usage-billing" component={UsageBillingPage} />
                <Route component={NotFound} />
              </Switch>
            </main>
          </div>
        </div>
        <CommandPalette />
        <OnboardingChecklist />
      </SidebarProvider>
    </EventStreamContext.Provider>
  );
}

function AppContent() {
  const { user, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="h-screen flex items-center justify-center">
        <div className="space-y-3 text-center">
          <Skeleton className="h-10 w-10 rounded-md mx-auto" />
          <Skeleton className="h-4 w-32" />
        </div>
      </div>
    );
  }

  if (!user) {
    return <LandingPage />;
  }

  return <AuthenticatedApp />;
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <TooltipProvider>
          <AppContent />
          <Toaster />
        </TooltipProvider>
      </ThemeProvider>
    </QueryClientProvider>
  );
}

export default App;

import { Switch, Route } from "wouter";
import { createContext, useContext, lazy, Suspense } from "react";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { ThemeProvider } from "@/components/theme-provider";
import { ThemeToggle } from "@/components/theme-toggle";
import { useAuth } from "@/hooks/use-auth";
import { useRoleLanding } from "@/hooks/use-role-landing";
import { useEventStream } from "@/hooks/use-event-stream";
import type { StreamEvent } from "@/hooks/use-event-stream";
import { SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar";
import { AppSidebar } from "@/components/app-sidebar";
import LandingPage from "@/pages/landing";
import NotFound from "@/pages/not-found";
import { CommandPalette } from "@/components/command-palette";
import { OnboardingChecklist } from "@/components/onboarding-checklist";
import { PlanLimitBanner } from "@/components/plan-limit-banner";
import { Skeleton } from "@/components/ui/skeleton";

const Dashboard = lazy(() => import("@/pages/dashboard"));
const AlertsPage = lazy(() => import("@/pages/alerts"));
const IncidentsPage = lazy(() => import("@/pages/incidents"));
const IncidentDetailPage = lazy(() => import("@/pages/incident-detail"));
const AuditLogPage = lazy(() => import("@/pages/audit-log"));
const SettingsPage = lazy(() => import("@/pages/settings"));
const IngestionPage = lazy(() => import("@/pages/ingestion"));
const ConnectorsPage = lazy(() => import("@/pages/connectors"));
const AIEnginePage = lazy(() => import("@/pages/ai-engine"));
const AlertDetailPage = lazy(() => import("@/pages/alert-detail"));
const AnalyticsPage = lazy(() => import("@/pages/analytics"));
const ThreatIntelPage = lazy(() => import("@/pages/threat-intel"));
const MitreAttackPage = lazy(() => import("@/pages/mitre-attack"));
const PlaybooksPage = lazy(() => import("@/pages/playbooks"));
const EntityGraphPage = lazy(() => import("@/pages/entity-graph"));
const AttackGraphPage = lazy(() => import("@/pages/attack-graph"));
const KillChainPage = lazy(() => import("@/pages/kill-chain"));
const CompliancePage = lazy(() => import("@/pages/compliance"));
const IntegrationsPage = lazy(() => import("@/pages/integrations"));
const PredictiveDefensePage = lazy(() => import("@/pages/predictive-defense"));
const AutonomousResponsePage = lazy(() => import("@/pages/autonomous-response"));
const SecurityPosturePage = lazy(() => import("@/pages/security-posture"));
const CspmPage = lazy(() => import("@/pages/cspm"));
const EndpointTelemetryPage = lazy(() => import("@/pages/endpoint-telemetry"));
const TeamManagementPage = lazy(() => import("@/pages/team-management"));
const ReportsPage = lazy(() => import("@/pages/reports"));
const OperationsPage = lazy(() => import("@/pages/operations"));
const OnboardingPage = lazy(() => import("@/pages/onboarding"));
const UsageBillingPage = lazy(() => import("@/pages/usage-billing"));

function PageSkeleton() {
  return (
    <div className="p-6 space-y-4" role="status" aria-label="Loading page">
      <Skeleton className="h-8 w-64" />
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Skeleton className="h-32" />
        <Skeleton className="h-32" />
        <Skeleton className="h-32" />
      </div>
      <Skeleton className="h-64 w-full" />
      <span className="sr-only">Loading page content...</span>
    </div>
  );
}

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
  useRoleLanding();
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
          <a
            href="#main-content"
            className="sr-only focus:not-sr-only focus:absolute focus:top-2 focus:left-2 focus:z-[100] focus:px-4 focus:py-2 focus:bg-primary focus:text-primary-foreground focus:rounded-md focus:outline-none"
          >
            Skip to main content
          </a>
          <div className="flex flex-col flex-1 min-w-0 relative z-10">
            <PlanLimitBanner />
            <header className="flex items-center justify-between gap-4 px-3 py-2 border-b border-border/50 sticky top-0 z-40 glass-strong gradient-bg-red-subtle">
              <div className="flex items-center gap-2">
                <SidebarTrigger data-testid="button-sidebar-toggle" />
                <div className={`w-2 h-2 rounded-full ${dotColor}`} data-testid="indicator-sse-status" />
              </div>
              <ThemeToggle />
            </header>
            <main id="main-content" className="flex-1 overflow-auto" tabIndex={-1}>
              <Suspense fallback={<PageSkeleton />}>
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
              </Suspense>
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

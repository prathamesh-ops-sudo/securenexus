import { Switch, Route, useLocation, useSearch } from "wouter";
import { createContext, useContext, lazy, Suspense, useEffect, useState } from "react";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { ThemeProvider } from "@/components/theme-provider";
import { ThemeToggle } from "@/components/theme-toggle";
import { useAuth } from "@/hooks/use-auth";
import { useRoleLanding } from "@/hooks/use-role-landing";
import { usePageTracking } from "@/hooks/use-page-tracking";
import { useEventStream } from "@/hooks/use-event-stream";
import type { StreamEvent } from "@/hooks/use-event-stream";
import { OrgContext, useOrgContextProvider } from "@/hooks/use-org-context";
import { SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar";
import { AppSidebar } from "@/components/app-sidebar";
import LandingPage from "@/pages/landing";
import NotFound from "@/pages/not-found";
import { CommandPalette } from "@/components/command-palette";
import { OnboardingChecklist } from "@/components/onboarding-checklist";
import { PlanLimitBanner } from "@/components/plan-limit-banner";
import { ImpersonationBanner } from "@/components/impersonation-banner";
import { NotificationBell } from "@/components/notification-bell";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorBoundary } from "@/components/error-boundary";
import { LoadingScreen } from "@/components/loading-screen";
import { Button } from "@/components/ui/button";
import { getOrglessDestination } from "@/lib/org-routing";
import { getAuthenticatedRouteDestination, hasPasswordResetToken, isPasswordRecoveryRoute } from "@/lib/auth-routing";

const Dashboard = lazy(() => import("@/pages/dashboard"));
const AlertsPage = lazy(() => import("@/pages/alerts"));
const IncidentsPage = lazy(() => import("@/pages/incidents"));
const IncidentDetailPage = lazy(() => import("@/pages/incident-detail"));
const AuditLogPage = lazy(() => import("@/pages/audit-log"));
const SettingsPage = lazy(() => import("@/pages/settings"));
const IngestionPage = lazy(() => import("@/pages/ingestion"));
const ConnectorsPage = lazy(() => import("@/pages/connectors"));
const AIEnginePage = lazy(() => import("@/pages/ai-engine"));
const AiSecurityPage = lazy(() => import("@/pages/ai-security"));
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
const OrgSettingsPage = lazy(() => import("@/pages/org-settings"));
const OnboardingWizardPage = lazy(() => import("@/pages/onboarding-wizard"));
const BillingPage = lazy(() => import("@/pages/billing"));
const ForgotPasswordPage = lazy(() => import("@/pages/forgot-password"));
const ResetPasswordPage = lazy(() => import("@/pages/reset-password"));
const ForcedPasswordChangePage = lazy(() => import("@/pages/forced-password-change"));
const AcceptInvitationPage = lazy(() => import("@/pages/accept-invitation"));
const PlatformAdminPage = lazy(() => import("@/pages/platform-admin"));
const MsspDashboardPage = lazy(() => import("@/pages/mssp-dashboard"));
const DevPortalPage = lazy(() => import("@/pages/dev-portal"));
const DeveloperPortalPage = lazy(() => import("@/pages/developer-portal"));
const ProductOverviewPage = lazy(() => import("@/pages/product-overview"));
const AgenticSocPage = lazy(() => import("@/pages/agentic-soc"));
const AiSocAnalystPage = lazy(() => import("@/pages/ai-soc-analyst"));
const AutomatedSecopsPage = lazy(() => import("@/pages/automated-secops"));
const SolutionsIndiaPage = lazy(() => import("@/pages/solutions-india"));
const SolutionsMsspPage = lazy(() => import("@/pages/solutions-mssp"));
const SolutionsCompliancePage = lazy(() => import("@/pages/solutions-compliance"));
const AboutPage = lazy(() => import("@/pages/about"));
const ProductComparisonPage = lazy(() => import("@/pages/product-comparison"));
const EngineControlsPage = lazy(() => import("@/pages/engine-controls"));
const EmailTemplatesPage = lazy(() => import("@/pages/email-templates"));
const MetricsRollupPage = lazy(() => import("@/pages/metrics-rollup"));
const ModelGatewayPage = lazy(() => import("@/pages/model-gateway"));
const OsintFeedsConfigPage = lazy(() => import("@/pages/osint-feeds-config"));
const OutboxMonitoringPage = lazy(() => import("@/pages/outbox-monitoring"));
const ApiVersioningPage = lazy(() => import("@/pages/api-versioning"));
const FileManagerPage = lazy(() => import("@/pages/file-manager"));
const SecretRotationOverviewPage = lazy(() => import("@/pages/secret-rotation-overview"));
const EvidenceChainViewerPage = lazy(() => import("@/pages/evidence-chain-viewer"));
const AiFeedbackFormPage = lazy(() => import("@/pages/ai-feedback-form"));
const SuppressedAlertsPage = lazy(() => import("@/pages/suppressed-alerts"));
const AiPromptRegistryPage = lazy(() => import("@/pages/ai-prompt-registry"));
const WebhookSecurityCenterPage = lazy(() => import("@/pages/webhook-security-center"));
const ReportTemplateVersioningPage = lazy(() => import("@/pages/report-template-versioning"));
const IocIngestionMatchingPage = lazy(() => import("@/pages/ioc-ingestion-matching"));
const UnifiedSecurityGraphPage = lazy(() => import("@/pages/unified-security-graph"));
const PromptToArtifactPage = lazy(() => import("@/pages/prompt-to-artifact"));
const DeveloperRemediationPage = lazy(() => import("@/pages/developer-remediation"));
const ThreatIntelFeedsPage = lazy(() => import("@/pages/threat-intel-feeds"));
const EntityMergeAliasPage = lazy(() => import("@/pages/entity-merge-alias"));
const FindingLineagePage = lazy(() => import("@/pages/finding-lineage"));
const RuntimeGuardrailsPage = lazy(() => import("@/pages/runtime-guardrails"));
const JitSecretAccessPage = lazy(() => import("@/pages/jit-secret-access"));
const IntegrationMarketplacePage = lazy(() => import("@/pages/integration-marketplace"));
const NativeCollectorsPage = lazy(() => import("@/pages/native-collectors"));
const AdversarialTestingPage = lazy(() => import("@/pages/adversarial-testing"));
const SocCopilotPage = lazy(() => import("@/pages/soc-copilot"));
const TieredPackagingPage = lazy(() => import("@/pages/tiered-packaging"));
const TrustCenterPage = lazy(() => import("@/pages/trust-center"));
const PolicyPacksPage = lazy(() => import("@/pages/policy-packs"));
const ExecutiveRiskPage = lazy(() => import("@/pages/executive-risk"));
const AgentToolSecurityPage = lazy(() => import("@/pages/agent-tool-security"));
const BrowserDefensePage = lazy(() => import("@/pages/browser-defense"));
const CrossCuttingPage = lazy(() => import("@/pages/cross-cutting"));
const RunbookTemplatesPage = lazy(() => import("@/pages/runbook-templates"));
const GapAnalysisPage = lazy(() => import("@/pages/gap-analysis"));
const AiBudgetControlsPage = lazy(() => import("@/pages/ai-budget-controls"));
const TenantIsolationPage = lazy(() => import("@/pages/tenant-isolation"));
const InvestigationRunsPage = lazy(() => import("@/pages/investigation-runs"));
const CampaignViewerPage = lazy(() => import("@/pages/campaign-viewer"));
const CveBrowserPage = lazy(() => import("@/pages/cve-browser"));
const PostIncidentReviewPage = lazy(() => import("@/pages/post-incident-review"));
const AiModelHealthPage = lazy(() => import("@/pages/ai-model-health"));
const ManualAiTriggersPage = lazy(() => import("@/pages/manual-ai-triggers"));
const RoleDashboardPage = lazy(() => import("@/pages/role-dashboard"));
const DataLifecyclePage = lazy(() => import("@/pages/data-lifecycle"));
const DrDrillSchedulerPage = lazy(() => import("@/pages/dr-drill-scheduler"));
const JobQueueDashboardPage = lazy(() => import("@/pages/job-queue-dashboard"));
const RollbackHistoryPage = lazy(() => import("@/pages/rollback-history"));
const DomainAutoJoinPage = lazy(() => import("@/pages/domain-auto-join"));
const UsageMeteringAnalyticsPage = lazy(() => import("@/pages/usage-metering-analytics"));
const StunningDashboardPage = lazy(() => import("@/pages/dashboard-stunning"));
const AccountLockoutPage = lazy(() => import("@/pages/account-lockout"));
const MfaSetupPage = lazy(() => import("@/pages/mfa-setup"));
const TenantDataPage = lazy(() => import("@/pages/tenant-data"));
const WarRoomPage = lazy(() => import("@/pages/war-room"));
const PlaybookTemplatesPage = lazy(() => import("@/pages/playbook-templates"));
const InvestigationTimelinePage = lazy(() => import("@/pages/investigation-timeline"));
const EvidenceCustodyPage = lazy(() => import("@/pages/evidence-custody"));
const ComplianceGapPage = lazy(() => import("@/pages/compliance-gap"));
const ReportSchedulingPage = lazy(() => import("@/pages/report-scheduling"));
const AssetInventoryPage = lazy(() => import("@/pages/asset-inventory"));
const RiskRegisterPage = lazy(() => import("@/pages/risk-register"));
const SecurityAssessmentsPage = lazy(() => import("@/pages/security-assessments"));
const ThreatReportsPage = lazy(() => import("@/pages/threat-reports"));
const NativeSensorsPage = lazy(() => import("@/pages/native-sensors"));
const DetectionRulesPage = lazy(() => import("@/pages/detection-rules"));
const VulnScannerPage = lazy(() => import("@/pages/vuln-scanner"));
const UebaPage = lazy(() => import("@/pages/ueba"));
const AgentResponsePage = lazy(() => import("@/pages/agent-response"));
const SupplyChainPage = lazy(() => import("@/pages/supply-chain"));
const IdentityGovernancePage = lazy(() => import("@/pages/identity-governance"));
const DeceptionPage = lazy(() => import("@/pages/deception"));
const OtSecurityPage = lazy(() => import("@/pages/ot-security"));
const ThreatHuntingPage = lazy(() => import("@/pages/threat-hunting"));
const DataLakePage = lazy(() => import("@/pages/data-lake"));
const AdvancedReportingPage = lazy(() => import("@/pages/advanced-reporting"));
const DataResidencyPage = lazy(() => import("@/pages/data-residency"));
const MobileSecurityPage = lazy(() => import("@/pages/mobile-security"));
const ApiSecurityPage = lazy(() => import("@/pages/api-security"));
const RansomwareDefensePage = lazy(() => import("@/pages/ransomware-defense"));
const CommunityIntelPage = lazy(() => import("@/pages/community-intel"));
const PostureTrustCenterPage = lazy(() => import("@/pages/posture-trust-center"));
const SecurityChaosEngineeringPage = lazy(() => import("@/pages/security-chaos-engineering"));
const AiDetectionRulesPage = lazy(() => import("@/pages/ai-detection-rules"));
const MsspPartnerPortalPage = lazy(() => import("@/pages/mssp-partner-portal"));
const AutonomousSOCPage = lazy(() => import("@/pages/autonomous-soc"));
const DeveloperSecurityPage = lazy(() => import("@/pages/developer-security"));
const TprmPage = lazy(() => import("@/pages/tprm"));
const DarkWebMonitoringPage = lazy(() => import("@/pages/dark-web-monitoring"));
const PhysicalSecurityPage = lazy(() => import("@/pages/physical-security"));
const SecurityAwarenessPage = lazy(() => import("@/pages/security-awareness"));
const QuantumReadinessPage = lazy(() => import("@/pages/quantum-readiness"));
const PrivacyEngineeringPage = lazy(() => import("@/pages/privacy-engineering"));
const BoardDashboardPage = lazy(() => import("@/pages/board-dashboard"));
const DnsSecurityPage = lazy(() => import("@/pages/dns-security"));
const EmailSecurityPage = lazy(() => import("@/pages/email-security"));

/* ── Hub pages (feature bundling) ─────────────────────────────────── */
const ThreatIntelligenceHubPage = lazy(() => import("@/pages/threat-intelligence-hub"));
const SecurityGraphHubPage = lazy(() => import("@/pages/security-graph-hub"));
const InvestigationsHubPage = lazy(() => import("@/pages/investigations-hub"));
const PlaybooksResponseHubPage = lazy(() => import("@/pages/playbooks-response-hub"));
const CloudEndpointHubPage = lazy(() => import("@/pages/cloud-endpoint-hub"));
const IdentityAccessHubPage = lazy(() => import("@/pages/identity-access-hub"));
const AiPlatformHubPage = lazy(() => import("@/pages/ai-platform-hub"));
const DataPlatformHubPage = lazy(() => import("@/pages/data-platform-hub"));
const DetectionEngineeringHubPage = lazy(() => import("@/pages/detection-engineering-hub"));
const AssetRiskHubPage = lazy(() => import("@/pages/asset-risk-hub"));
const AdvancedThreatHubPage = lazy(() => import("@/pages/advanced-threat-hub"));
const CommsSecurityHubPage = lazy(() => import("@/pages/comms-security-hub"));
const SpecializedSecurityHubPage = lazy(() => import("@/pages/specialized-security-hub"));
const ComplianceGovernanceHubPage = lazy(() => import("@/pages/compliance-governance-hub"));
const ExecutiveReportingHubPage = lazy(() => import("@/pages/executive-reporting-hub"));
const MsspHubPage = lazy(() => import("@/pages/mssp-hub"));

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

export const EventStreamContext = createContext<EventStreamContextType>({
  connected: false,
  connectionState: "disconnected",
  eventCount: 0,
  events: [],
  lastEvent: null,
});

const EVENT_STREAM_CONTEXT_DEFAULT = {
  connected: false,
  connectionState: "disconnected",
  eventCount: 0,
  events: [],
  lastEvent: null,
};

const CONTENT_PAGE_PREFIXES = ["/product", "/solutions", "/about", "/blog"];

function isContentPageRoute(path: string): boolean {
  return CONTENT_PAGE_PREFIXES.some((prefix) => path === prefix || path.startsWith(prefix + "/"));
}

function NoOrganizationState() {
  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-6">
      <div className="w-full max-w-md space-y-5 text-center">
        <h1 className="text-2xl font-semibold">No organization yet</h1>
        <p className="text-sm text-muted-foreground">
          Access to SecureNexus is provisioned by your administrator. Please contact them to be added to an
          organization.
        </p>
        <Button asChild variant="outline">
          <a href="/api/logout">Sign out</a>
        </Button>
      </div>
    </div>
  );
}

function NoTenantSelectedState() {
  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-6">
      <div className="w-full max-w-md space-y-5 text-center">
        <h1 className="text-2xl font-semibold">Select or provision a tenant</h1>
        <p className="text-sm text-muted-foreground">
          Platform administrators manage tenants from the platform administration page. Select a tenant after
          provisioning to use tenant-scoped features.
        </p>
        <Button asChild>
          <a href="/platform-admin">Open platform administration</a>
        </Button>
      </div>
    </div>
  );
}

function AuthenticatedApp() {
  useRoleLanding();
  const { connected, connectionState, eventCount, events, lastEvent } = useEventStream({ enabled: true });
  const { user } = useAuth();
  const orgContext = useOrgContextProvider();
  const [location, navigate] = useLocation();

  useEffect(() => {
    if (!orgContext.needsOnboarding || isContentPageRoute(location)) return;
    const destination = getOrglessDestination(!!user?.isSuperAdmin);
    if (location !== destination) navigate(destination);
  }, [orgContext.needsOnboarding, location, navigate, user?.isSuperAdmin]);

  if (orgContext.needsOnboarding && !user?.isSuperAdmin && !isContentPageRoute(location)) {
    return <NoOrganizationState />;
  }

  if (
    orgContext.needsOnboarding &&
    user?.isSuperAdmin &&
    location !== "/platform-admin" &&
    !isContentPageRoute(location)
  ) {
    return <NoTenantSelectedState />;
  }

  if (isContentPageRoute(location)) {
    return (
      <Suspense fallback={<PageSkeleton />}>
        <Switch>
          <Route path="/product/agentic-soc" component={AgenticSocPage} />
          <Route path="/product/ai-soc-analyst" component={AiSocAnalystPage} />
          <Route path="/blog/automated-secops" component={AutomatedSecopsPage} />
          <Route path="/product/comparison" component={ProductComparisonPage} />
          <Route path="/product" component={ProductOverviewPage} />
          <Route path="/solutions/india" component={SolutionsIndiaPage} />
          <Route path="/solutions/mssp" component={SolutionsMsspPage} />
          <Route path="/solutions/compliance" component={SolutionsCompliancePage} />
          <Route path="/about" component={AboutPage} />
          <Route component={NotFound} />
        </Switch>
      </Suspense>
    );
  }

  const style = {
    "--sidebar-width": "16rem",
    "--sidebar-width-icon": "3rem",
  };

  const dotColor =
    connectionState === "connected"
      ? "bg-green-500 animate-live-dot"
      : connectionState === "connecting"
        ? "bg-yellow-500 animate-pulse"
        : "bg-red-500";

  return (
    <EventStreamContext.Provider value={{ connected, connectionState, eventCount, events, lastEvent }}>
      <OrgContext.Provider value={orgContext}>
        <SidebarProvider style={style as React.CSSProperties}>
          <div className="flex h-screen w-full relative">
            <AppSidebar />
            <a
              href="#main-content"
              className="sr-only focus:not-sr-only focus:absolute focus:top-2 focus:left-2 focus:z-[100] focus:px-4 focus:py-2 focus:bg-primary focus:text-primary-foreground focus:rounded-md focus:outline-none"
            >
              Skip to main content
            </a>
            <div className="flex flex-col flex-1 min-w-0 relative z-10">
              <ImpersonationBanner />
              <PlanLimitBanner />
              <header className="flex items-center justify-between gap-4 px-3 py-2 border-b border-border/60 sticky top-0 z-40 bg-background/80 backdrop-blur-md">
                <div className="flex items-center gap-2">
                  <SidebarTrigger data-testid="button-sidebar-toggle" />
                  <div className="flex items-center gap-1.5" data-testid="indicator-sse-status">
                    <div className="relative">
                      <div className={`w-2 h-2 rounded-full ${dotColor}`} />
                      {connectionState === "connected" && (
                        <div className="absolute inset-0 w-2 h-2 rounded-full bg-green-500 animate-ping opacity-40" />
                      )}
                    </div>
                    <span className="text-[10px] font-medium text-muted-foreground hidden sm:inline tabular-nums">
                      {connectionState === "connected"
                        ? "LIVE"
                        : connectionState === "connecting"
                          ? "CONNECTING"
                          : "OFFLINE"}
                    </span>
                    {eventCount > 0 && connectionState === "connected" && (
                      <span className="text-[9px] font-mono text-muted-foreground/60 hidden md:inline tabular-nums">
                        {eventCount} events
                      </span>
                    )}
                  </div>
                </div>
                <div className="flex items-center gap-1">
                  <NotificationBell />
                  <ThemeToggle />
                </div>
              </header>
              <main id="main-content" className="flex-1 overflow-auto" tabIndex={0}>
                <div key={location} className="animate-fade-in">
                  <Suspense fallback={<PageSkeleton />}>
                    <Switch>
                      <Route path="/" component={Dashboard} />
                      <Route path="/alerts/:id" component={AlertDetailPage} />
                      <Route path="/alerts" component={AlertsPage} />
                      <Route path="/incidents" component={IncidentsPage} />
                      <Route path="/incidents/:id" component={IncidentDetailPage} />

                      {/* ── Hub pages (bundled features) ──────────────── */}
                      <Route path="/threat-intelligence" component={ThreatIntelligenceHubPage} />
                      <Route path="/security-graph-hub" component={SecurityGraphHubPage} />
                      <Route path="/investigations" component={InvestigationsHubPage} />
                      <Route path="/response" component={PlaybooksResponseHubPage} />
                      <Route path="/cloud-endpoint" component={CloudEndpointHubPage} />
                      <Route path="/identity-access" component={IdentityAccessHubPage} />
                      <Route path="/ai-platform" component={AiPlatformHubPage} />
                      <Route path="/data-platform" component={DataPlatformHubPage} />
                      <Route path="/detection-engineering" component={DetectionEngineeringHubPage} />
                      <Route path="/asset-risk" component={AssetRiskHubPage} />
                      <Route path="/advanced-threats" component={AdvancedThreatHubPage} />
                      <Route path="/comms-security" component={CommsSecurityHubPage} />
                      <Route path="/specialized-security" component={SpecializedSecurityHubPage} />
                      <Route path="/compliance-governance" component={ComplianceGovernanceHubPage} />
                      <Route path="/executive-reporting" component={ExecutiveReportingHubPage} />
                      <Route path="/mssp" component={MsspHubPage} />

                      {/* ── Standalone pages (not bundled) ────────────── */}
                      <Route path="/autonomous-soc" component={AutonomousSOCPage} />
                      <Route path="/developer-security" component={DeveloperSecurityPage} />
                      <Route path="/supply-chain" component={SupplyChainPage} />
                      <Route path="/community-intel" component={CommunityIntelPage} />
                      <Route path="/privacy-engineering" component={PrivacyEngineeringPage} />
                      <Route path="/cross-cutting" component={CrossCuttingPage} />

                      {/* ── Admin/settings pages ─────────────────────── */}
                      <Route path="/settings" component={SettingsPage} />
                      <Route path="/team" component={TeamManagementPage} />
                      <Route path="/onboarding" component={OnboardingPage} />
                      <Route path="/onboarding-wizard" component={OnboardingWizardPage} />
                      <Route path="/usage-billing" component={UsageBillingPage} />
                      <Route path="/billing" component={BillingPage} />
                      <Route path="/org-settings" component={OrgSettingsPage} />
                      <Route path="/accept-invitation" component={AcceptInvitationPage} />
                      <Route path="/forgot-password" component={ForgotPasswordPage} />
                      <Route path="/reset-password" component={ResetPasswordPage} />
                      <Route path="/change-password" component={ForcedPasswordChangePage} />
                      <Route path="/platform-admin" component={PlatformAdminPage} />
                      <Route path="/dev-portal" component={DevPortalPage} />
                      <Route path="/developer-portal" component={DeveloperPortalPage} />
                      <Route path="/tiered-packaging" component={TieredPackagingPage} />
                      <Route path="/mfa-setup" component={MfaSetupPage} />
                      <Route path="/account-lockout" component={AccountLockoutPage} />
                      <Route path="/domain-auto-join" component={DomainAutoJoinPage} />

                      {/* ── Utility/internal pages ───────────────────── */}
                      <Route path="/analytics" component={AnalyticsPage} />
                      <Route path="/operations" component={OperationsPage} />
                      <Route path="/engine-controls" component={EngineControlsPage} />
                      <Route path="/email-templates" component={EmailTemplatesPage} />
                      <Route path="/metrics-rollup" component={MetricsRollupPage} />
                      <Route path="/api-versioning" component={ApiVersioningPage} />
                      <Route path="/file-manager" component={FileManagerPage} />
                      <Route path="/suppressed-alerts" component={SuppressedAlertsPage} />
                      <Route path="/report-template-versioning" component={ReportTemplateVersioningPage} />
                      <Route path="/developer-remediation" component={DeveloperRemediationPage} />
                      <Route path="/finding-lineage" component={FindingLineagePage} />
                      <Route path="/runtime-guardrails" component={RuntimeGuardrailsPage} />
                      <Route path="/adversarial-testing" component={AdversarialTestingPage} />
                      <Route path="/agent-tool-security" component={AgentToolSecurityPage} />
                      <Route path="/browser-defense" component={BrowserDefensePage} />
                      <Route path="/gap-analysis" component={GapAnalysisPage} />
                      <Route path="/tenant-isolation" component={TenantIsolationPage} />
                      <Route path="/investigation-runs" component={InvestigationRunsPage} />
                      <Route path="/post-incident-review" component={PostIncidentReviewPage} />
                      <Route path="/ai-model-health" component={AiModelHealthPage} />
                      <Route path="/manual-ai-triggers" component={ManualAiTriggersPage} />
                      <Route path="/role-dashboard" component={RoleDashboardPage} />
                      <Route path="/data-lifecycle" component={DataLifecyclePage} />
                      <Route path="/dr-drill-scheduler" component={DrDrillSchedulerPage} />
                      <Route path="/usage-metering-analytics" component={UsageMeteringAnalyticsPage} />
                      <Route path="/stunning-dashboard" component={StunningDashboardPage} />
                      <Route path="/tenant-data" component={TenantDataPage} />
                      <Route path="/report-scheduling" component={ReportSchedulingPage} />
                      <Route path="/executive-risk" component={ExecutiveRiskPage} />
                      <Route path="/posture-trust-center" component={PostureTrustCenterPage} />
                      <Route path="/threat-intel" component={ThreatIntelPage} />
                      <Route path="/integrations" component={IntegrationsPage} />
                      <Route path="/predictive-defense" component={PredictiveDefensePage} />

                      {/* ── Legacy direct routes (still accessible via URL) ── */}
                      <Route path="/threat-intel-feeds" component={ThreatIntelFeedsPage} />
                      <Route path="/osint-feeds-config" component={OsintFeedsConfigPage} />
                      <Route path="/ioc-ingestion-matching" component={IocIngestionMatchingPage} />
                      <Route path="/cve-browser" component={CveBrowserPage} />
                      <Route path="/campaign-viewer" component={CampaignViewerPage} />
                      <Route path="/mitre-attack" component={MitreAttackPage} />
                      <Route path="/kill-chain" component={KillChainPage} />
                      <Route path="/security-graph" component={UnifiedSecurityGraphPage} />
                      <Route path="/attack-graph" component={AttackGraphPage} />
                      <Route path="/entity-graph" component={EntityGraphPage} />
                      <Route path="/entity-merge-alias" component={EntityMergeAliasPage} />
                      <Route path="/war-room" component={WarRoomPage} />
                      <Route path="/threat-hunting" component={ThreatHuntingPage} />
                      <Route path="/investigation-timeline" component={InvestigationTimelinePage} />
                      <Route path="/evidence-chain-viewer" component={EvidenceChainViewerPage} />
                      <Route path="/evidence-custody" component={EvidenceCustodyPage} />
                      <Route path="/playbooks" component={PlaybooksPage} />
                      <Route path="/autonomous-response" component={AutonomousResponsePage} />
                      <Route path="/rollback-history" component={RollbackHistoryPage} />
                      <Route path="/playbook-templates" component={PlaybookTemplatesPage} />
                      <Route path="/runbook-templates" component={RunbookTemplatesPage} />
                      <Route path="/cspm" component={CspmPage} />
                      <Route path="/endpoint-telemetry" component={EndpointTelemetryPage} />
                      <Route path="/security-posture" component={SecurityPosturePage} />
                      <Route path="/native-sensors" component={NativeSensorsPage} />
                      <Route path="/vuln-scanner" component={VulnScannerPage} />
                      <Route path="/identity-governance" component={IdentityGovernancePage} />
                      <Route path="/jit-secret-access" component={JitSecretAccessPage} />
                      <Route path="/secret-rotation-overview" component={SecretRotationOverviewPage} />
                      <Route path="/ai-engine" component={AIEnginePage} />
                      <Route path="/ai-security" component={AiSecurityPage} />
                      <Route path="/soc-copilot" component={SocCopilotPage} />
                      <Route path="/prompt-to-artifact" component={PromptToArtifactPage} />
                      <Route path="/model-gateway" component={ModelGatewayPage} />
                      <Route path="/ai-prompt-registry" component={AiPromptRegistryPage} />
                      <Route path="/ai-feedback" component={AiFeedbackFormPage} />
                      <Route path="/ai-budget-controls" component={AiBudgetControlsPage} />
                      <Route path="/connectors" component={ConnectorsPage} />
                      <Route path="/integration-marketplace" component={IntegrationMarketplacePage} />
                      <Route path="/native-collectors" component={NativeCollectorsPage} />
                      <Route path="/webhook-security-center" component={WebhookSecurityCenterPage} />
                      <Route path="/ingestion" component={IngestionPage} />
                      <Route path="/job-queue-dashboard" component={JobQueueDashboardPage} />
                      <Route path="/outbox-monitor" component={OutboxMonitoringPage} />
                      <Route path="/data-lake" component={DataLakePage} />
                      <Route path="/detection-rules" component={DetectionRulesPage} />
                      <Route path="/ai-detection-rules" component={AiDetectionRulesPage} />
                      <Route path="/ueba" component={UebaPage} />
                      <Route path="/agent-response" component={AgentResponsePage} />
                      <Route path="/asset-inventory" component={AssetInventoryPage} />
                      <Route path="/risk-register" component={RiskRegisterPage} />
                      <Route path="/tprm" component={TprmPage} />
                      <Route path="/deception" component={DeceptionPage} />
                      <Route path="/ransomware-defense" component={RansomwareDefensePage} />
                      <Route path="/dark-web-monitoring" component={DarkWebMonitoringPage} />
                      <Route path="/chaos-engineering" component={SecurityChaosEngineeringPage} />
                      <Route path="/dns-security" component={DnsSecurityPage} />
                      <Route path="/email-security" component={EmailSecurityPage} />
                      <Route path="/security-awareness" component={SecurityAwarenessPage} />
                      <Route path="/ot-security" component={OtSecurityPage} />
                      <Route path="/mobile-security" component={MobileSecurityPage} />
                      <Route path="/api-security" component={ApiSecurityPage} />
                      <Route path="/physical-security" component={PhysicalSecurityPage} />
                      <Route path="/quantum-readiness" component={QuantumReadinessPage} />
                      <Route path="/compliance" component={CompliancePage} />
                      <Route path="/trust-center" component={TrustCenterPage} />
                      <Route path="/compliance-gap" component={ComplianceGapPage} />
                      <Route path="/audit-log" component={AuditLogPage} />
                      <Route path="/policy-packs" component={PolicyPacksPage} />
                      <Route path="/data-residency" component={DataResidencyPage} />
                      <Route path="/reports" component={ReportsPage} />
                      <Route path="/board-dashboard" component={BoardDashboardPage} />
                      <Route path="/security-assessments" component={SecurityAssessmentsPage} />
                      <Route path="/threat-reports" component={ThreatReportsPage} />
                      <Route path="/advanced-reporting" component={AdvancedReportingPage} />
                      <Route path="/mssp-dashboard" component={MsspDashboardPage} />
                      <Route path="/mssp-partner-portal" component={MsspPartnerPortalPage} />

                      <Route component={NotFound} />
                    </Switch>
                  </Suspense>
                </div>
              </main>
            </div>
          </div>
          <CommandPalette />
          <OnboardingChecklist />
        </SidebarProvider>
      </OrgContext.Provider>
    </EventStreamContext.Provider>
  );
}

function AppContent() {
  usePageTracking();
  const { user, isLoading, logoutAsync } = useAuth();
  const [location, setLocation] = useLocation();
  const search = useSearch();
  const currentRoute = search ? `${location}?${search}` : location;
  const resetLinkRoute = hasPasswordResetToken(currentRoute);
  const [resetSessionError, setResetSessionError] = useState<{ route: string; message: string } | null>(null);

  useEffect(() => {
    if (!user || isLoading) return;
    const pendingToken = sessionStorage.getItem("pendingInvitationToken");
    if (pendingToken) {
      sessionStorage.removeItem("pendingInvitationToken");
      setLocation(`/accept-invitation?token=${pendingToken}`);
    }
  }, [user, isLoading, setLocation]);

  useEffect(() => {
    if (!user || isLoading) return;
    const destination = getAuthenticatedRouteDestination(currentRoute);
    if (destination && location !== destination) setLocation(destination);
  }, [currentRoute, location, setLocation, user, isLoading]);

  useEffect(() => {
    if (user?.passwordChangeRequired && !isPasswordRecoveryRoute(currentRoute) && location !== "/change-password") {
      setLocation("/change-password");
    }
  }, [currentRoute, location, setLocation, user?.passwordChangeRequired]);

  useEffect(() => {
    if (!resetLinkRoute || !user || isLoading) return;

    let cancelled = false;
    void logoutAsync().catch((error) => {
      if (!cancelled) {
        setResetSessionError({
          route: currentRoute,
          message: error instanceof Error ? error.message : "Unable to start password reset.",
        });
      }
    });

    return () => {
      cancelled = true;
    };
  }, [currentRoute, isLoading, logoutAsync, resetLinkRoute, user]);

  if (isLoading) {
    return <LoadingScreen />;
  }

  if (resetLinkRoute && user) {
    const sessionError = resetSessionError?.route === currentRoute ? resetSessionError.message : null;
    if (sessionError) {
      return (
        <div className="min-h-screen flex items-center justify-center p-4">
          <div className="max-w-md space-y-3 text-center">
            <p className="text-sm text-destructive">{sessionError}</p>
            <Button onClick={() => window.location.reload()}>Retry</Button>
          </div>
        </div>
      );
    }
    return <LoadingScreen />;
  }

  if (!user) {
    return (
      <Suspense fallback={<PageSkeleton />}>
        <Switch>
          <Route path="/forgot-password" component={ForgotPasswordPage} />
          <Route path="/reset-password" component={ResetPasswordPage} />
          <Route path="/accept-invitation" component={AcceptInvitationPage} />
          <Route path="/product/agentic-soc" component={AgenticSocPage} />
          <Route path="/product/ai-soc-analyst" component={AiSocAnalystPage} />
          <Route path="/blog/automated-secops" component={AutomatedSecopsPage} />
          <Route path="/product/comparison" component={ProductComparisonPage} />
          <Route path="/product" component={ProductOverviewPage} />
          <Route path="/solutions/india" component={SolutionsIndiaPage} />
          <Route path="/solutions/mssp" component={SolutionsMsspPage} />
          <Route path="/solutions/compliance" component={SolutionsCompliancePage} />
          <Route path="/about" component={AboutPage} />
          <Route>
            <LandingPage />
          </Route>
        </Switch>
      </Suspense>
    );
  }

  if (user.passwordChangeRequired && !isPasswordRecoveryRoute(currentRoute)) {
    return (
      <Suspense fallback={<LoadingScreen />}>
        <ForcedPasswordChangePage />
      </Suspense>
    );
  }

  const authenticatedRouteDestination = getAuthenticatedRouteDestination(location);
  if (authenticatedRouteDestination && location !== authenticatedRouteDestination) {
    return <LoadingScreen />;
  }

  return <AuthenticatedApp />;
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <ErrorBoundary>
        <ThemeProvider>
          <TooltipProvider>
            <AppContent />
            <Toaster />
          </TooltipProvider>
        </ThemeProvider>
      </ErrorBoundary>
    </QueryClientProvider>
  );
}

export default App;

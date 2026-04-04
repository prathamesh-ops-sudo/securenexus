import { useState, useEffect, lazy, Suspense } from "react";
import { useSearch } from "wouter";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";
import { FileText, TrendingUp, ClipboardCheck, Flag, BarChart3 } from "lucide-react";

const ReportsPage = lazy(() => import("./reports"));
const BoardDashboardPage = lazy(() => import("./board-dashboard"));
const SecurityAssessmentsPage = lazy(() => import("./security-assessments"));
const ThreatReportsPage = lazy(() => import("./threat-reports"));
const AdvancedReportingPage = lazy(() => import("./advanced-reporting"));

const TABS = [
  { id: "reports", label: "Reports", icon: FileText },
  { id: "board", label: "Board Dashboard", icon: TrendingUp },
  { id: "assessments", label: "Assessments", icon: ClipboardCheck },
  { id: "threat-reports", label: "Threat Reports", icon: Flag },
  { id: "advanced", label: "Advanced Reports", icon: BarChart3 },
] as const;

type TabId = (typeof TABS)[number]["id"];

function TabSkeleton() {
  return (
    <div className="space-y-4 p-4">
      <Skeleton className="h-8 w-64" />
      <Skeleton className="h-64 w-full" />
      <Skeleton className="h-32 w-full" />
    </div>
  );
}

export default function ExecutiveReportingHubPage() {
  const search = useSearch();
  const params = new URLSearchParams(search);
  const tabFromUrl = params.get("tab") as TabId | null;
  const [activeTab, setActiveTab] = useState<TabId>(
    tabFromUrl && TABS.some((t) => t.id === tabFromUrl) ? tabFromUrl : "reports",
  );

  useEffect(() => {
    if (tabFromUrl && TABS.some((t) => t.id === tabFromUrl)) {
      setActiveTab(tabFromUrl);
    }
  }, [tabFromUrl]);

  return (
    <div className="flex flex-col gap-6 p-6">
      <div className="flex items-center gap-3">
        <BarChart3 className="h-8 w-8 text-primary" />
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Executive & Reporting</h1>
          <p className="text-muted-foreground">
            Board-level dashboards, security assessments, threat reports, and advanced analytics
          </p>
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as TabId)}>
        <TabsList className="flex-wrap">
          {TABS.map((tab) => (
            <TabsTrigger key={tab.id} value={tab.id} className="gap-1.5">
              <tab.icon className="h-4 w-4" />
              {tab.label}
            </TabsTrigger>
          ))}
        </TabsList>

        <Suspense fallback={<TabSkeleton />}>
          <TabsContent value="reports" className="mt-4">
            <ReportsPage />
          </TabsContent>
          <TabsContent value="board" className="mt-4">
            <BoardDashboardPage />
          </TabsContent>
          <TabsContent value="assessments" className="mt-4">
            <SecurityAssessmentsPage />
          </TabsContent>
          <TabsContent value="threat-reports" className="mt-4">
            <ThreatReportsPage />
          </TabsContent>
          <TabsContent value="advanced" className="mt-4">
            <AdvancedReportingPage />
          </TabsContent>
        </Suspense>
      </Tabs>
    </div>
  );
}

import { useState, useEffect, lazy, Suspense } from "react";
import { useLocation } from "wouter";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";
import { Database, Plug, Package, HardDrive, Activity, ListTodo, Send } from "lucide-react";
import { WebhookIcon } from "lucide-react";

const ConnectorsPage = lazy(() => import("./connectors"));
const IntegrationMarketplacePage = lazy(() => import("./integration-marketplace"));
const NativeCollectorsPage = lazy(() => import("./native-collectors"));
const WebhookSecurityCenterPage = lazy(() => import("./webhook-security-center"));
const IngestionPage = lazy(() => import("./ingestion"));
const JobQueueDashboardPage = lazy(() => import("./job-queue-dashboard"));
const OutboxMonitoringPage = lazy(() => import("./outbox-monitoring"));
const DataLakePage = lazy(() => import("./data-lake"));

const TABS = [
  { id: "connectors", label: "Connectors", icon: Plug },
  { id: "marketplace", label: "Marketplace", icon: Package },
  { id: "collectors", label: "Native Collectors", icon: HardDrive },
  { id: "webhooks", label: "Webhooks", icon: WebhookIcon },
  { id: "ingestion", label: "Ingestion Status", icon: Activity },
  { id: "job-queue", label: "Job Queue", icon: ListTodo },
  { id: "outbox", label: "Outbox Monitor", icon: Send },
  { id: "data-lake", label: "Data Lake", icon: Database },
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

export default function DataPlatformHubPage() {
  const [location] = useLocation();
  const params = new URLSearchParams(location.split("?")[1] || "");
  const tabFromUrl = params.get("tab") as TabId | null;
  const [activeTab, setActiveTab] = useState<TabId>(
    tabFromUrl && TABS.some((t) => t.id === tabFromUrl) ? tabFromUrl : "connectors",
  );

  useEffect(() => {
    if (tabFromUrl && TABS.some((t) => t.id === tabFromUrl)) {
      setActiveTab(tabFromUrl);
    }
  }, [tabFromUrl]);

  return (
    <div className="flex flex-col gap-6 p-6">
      <div className="flex items-center gap-3">
        <Database className="h-8 w-8 text-primary" />
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Data Platform</h1>
          <p className="text-muted-foreground">Manage connectors, data ingestion pipelines, and storage</p>
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
          <TabsContent value="connectors" className="mt-4">
            <ConnectorsPage />
          </TabsContent>
          <TabsContent value="marketplace" className="mt-4">
            <IntegrationMarketplacePage />
          </TabsContent>
          <TabsContent value="collectors" className="mt-4">
            <NativeCollectorsPage />
          </TabsContent>
          <TabsContent value="webhooks" className="mt-4">
            <WebhookSecurityCenterPage />
          </TabsContent>
          <TabsContent value="ingestion" className="mt-4">
            <IngestionPage />
          </TabsContent>
          <TabsContent value="job-queue" className="mt-4">
            <JobQueueDashboardPage />
          </TabsContent>
          <TabsContent value="outbox" className="mt-4">
            <OutboxMonitoringPage />
          </TabsContent>
          <TabsContent value="data-lake" className="mt-4">
            <DataLakePage />
          </TabsContent>
        </Suspense>
      </Tabs>
    </div>
  );
}

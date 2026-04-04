import { useState, useEffect, lazy, Suspense } from "react";
import { useSearch } from "wouter";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";
import { ShieldCheck, Cloud, Monitor, Gauge, Cpu, Scan } from "lucide-react";

const CspmPage = lazy(() => import("./cspm"));
const EndpointTelemetryPage = lazy(() => import("./endpoint-telemetry"));
const SecurityPosturePage = lazy(() => import("./security-posture"));
const NativeSensorsPage = lazy(() => import("./native-sensors"));
const VulnScannerPage = lazy(() => import("./vuln-scanner"));

const TABS = [
  { id: "cspm", label: "CSPM", icon: Cloud },
  { id: "endpoint", label: "Endpoint Telemetry", icon: Monitor },
  { id: "vuln-mgmt", label: "Vulnerability Mgmt", icon: Gauge },
  { id: "sensors", label: "Native Sensors", icon: Cpu },
  { id: "scanner", label: "Vuln Scanner", icon: Scan },
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

export default function CloudEndpointHubPage() {
  const search = useSearch();
  const params = new URLSearchParams(search);
  const tabFromUrl = params.get("tab") as TabId | null;
  const [activeTab, setActiveTab] = useState<TabId>(
    tabFromUrl && TABS.some((t) => t.id === tabFromUrl) ? tabFromUrl : "cspm",
  );

  useEffect(() => {
    if (tabFromUrl && TABS.some((t) => t.id === tabFromUrl)) {
      setActiveTab(tabFromUrl);
    }
  }, [tabFromUrl]);

  return (
    <div className="flex flex-col gap-6 p-6">
      <div className="flex items-center gap-3">
        <ShieldCheck className="h-8 w-8 text-primary" />
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Cloud & Endpoint Security</h1>
          <p className="text-muted-foreground">Monitor cloud posture, endpoint health, and vulnerability management</p>
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
          <TabsContent value="cspm" className="mt-4">
            <CspmPage />
          </TabsContent>
          <TabsContent value="endpoint" className="mt-4">
            <EndpointTelemetryPage />
          </TabsContent>
          <TabsContent value="vuln-mgmt" className="mt-4">
            <SecurityPosturePage />
          </TabsContent>
          <TabsContent value="sensors" className="mt-4">
            <NativeSensorsPage />
          </TabsContent>
          <TabsContent value="scanner" className="mt-4">
            <VulnScannerPage />
          </TabsContent>
        </Suspense>
      </Tabs>
    </div>
  );
}

import { useState, useEffect, lazy, Suspense } from "react";
import { useLocation } from "wouter";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";
import { Shield, Crosshair, ShieldAlert, EyeOff, Zap as ZapIcon } from "lucide-react";

const DeceptionPage = lazy(() => import("./deception"));
const RansomwareDefensePage = lazy(() => import("./ransomware-defense"));
const DarkWebMonitoringPage = lazy(() => import("./dark-web-monitoring"));
const SecurityChaosEngineeringPage = lazy(() => import("./security-chaos-engineering"));

const TABS = [
  { id: "deception", label: "Deception Technology", icon: Crosshair },
  { id: "ransomware", label: "Ransomware Defense", icon: ShieldAlert },
  { id: "dark-web", label: "Dark Web Monitoring", icon: EyeOff },
  { id: "chaos", label: "Chaos Engineering", icon: ZapIcon },
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

export default function AdvancedThreatHubPage() {
  const [location] = useLocation();
  const params = new URLSearchParams(location.split("?")[1] || "");
  const tabFromUrl = params.get("tab") as TabId | null;
  const [activeTab, setActiveTab] = useState<TabId>(
    tabFromUrl && TABS.some((t) => t.id === tabFromUrl) ? tabFromUrl : "deception",
  );

  useEffect(() => {
    if (tabFromUrl && TABS.some((t) => t.id === tabFromUrl)) {
      setActiveTab(tabFromUrl);
    }
  }, [tabFromUrl]);

  return (
    <div className="flex flex-col gap-6 p-6">
      <div className="flex items-center gap-3">
        <Shield className="h-8 w-8 text-primary" />
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Advanced Threat Defense</h1>
          <p className="text-muted-foreground">
            Proactive defense with deception, ransomware protection, dark web monitoring, and chaos testing
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
          <TabsContent value="deception" className="mt-4">
            <DeceptionPage />
          </TabsContent>
          <TabsContent value="ransomware" className="mt-4">
            <RansomwareDefensePage />
          </TabsContent>
          <TabsContent value="dark-web" className="mt-4">
            <DarkWebMonitoringPage />
          </TabsContent>
          <TabsContent value="chaos" className="mt-4">
            <SecurityChaosEngineeringPage />
          </TabsContent>
        </Suspense>
      </Tabs>
    </div>
  );
}

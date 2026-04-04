import { useState, useEffect, lazy, Suspense } from "react";
import { useLocation } from "wouter";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";
import { Building2, Palette } from "lucide-react";

const MsspDashboardPage = lazy(() => import("./mssp-dashboard"));
const MsspPartnerPortalPage = lazy(() => import("./mssp-partner-portal"));

const TABS = [
  { id: "dashboard", label: "MSSP Dashboard", icon: Building2 },
  { id: "portal", label: "Partner Portal", icon: Palette },
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

export default function MsspHubPage() {
  const [location] = useLocation();
  const params = new URLSearchParams(location.split("?")[1] || "");
  const tabFromUrl = params.get("tab") as TabId | null;
  const [activeTab, setActiveTab] = useState<TabId>(
    tabFromUrl && TABS.some((t) => t.id === tabFromUrl) ? tabFromUrl : "dashboard",
  );

  useEffect(() => {
    if (tabFromUrl && TABS.some((t) => t.id === tabFromUrl)) {
      setActiveTab(tabFromUrl);
    }
  }, [tabFromUrl]);

  return (
    <div className="flex flex-col gap-6 p-6">
      <div className="flex items-center gap-3">
        <Building2 className="h-8 w-8 text-primary" />
        <div>
          <h1 className="text-3xl font-bold tracking-tight">MSSP & Partners</h1>
          <p className="text-muted-foreground">Manage multi-tenant MSSP operations and partner portal</p>
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
          <TabsContent value="dashboard" className="mt-4">
            <MsspDashboardPage />
          </TabsContent>
          <TabsContent value="portal" className="mt-4">
            <MsspPartnerPortalPage />
          </TabsContent>
        </Suspense>
      </Tabs>
    </div>
  );
}

import { useState, useEffect, lazy, Suspense } from "react";
import { useSearch } from "wouter";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";
import { Server, ShieldAlert, Building2 } from "lucide-react";

const AssetInventoryPage = lazy(() => import("./asset-inventory"));
const RiskRegisterPage = lazy(() => import("./risk-register"));
const TprmPage = lazy(() => import("./tprm"));

const TABS = [
  { id: "inventory", label: "Asset Inventory", icon: Server },
  { id: "risk", label: "Risk Register", icon: ShieldAlert },
  { id: "tprm", label: "Third-Party Risk", icon: Building2 },
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

export default function AssetRiskHubPage() {
  const search = useSearch();
  const params = new URLSearchParams(search);
  const tabFromUrl = params.get("tab") as TabId | null;
  const [activeTab, setActiveTab] = useState<TabId>(
    tabFromUrl && TABS.some((t) => t.id === tabFromUrl) ? tabFromUrl : "inventory",
  );

  useEffect(() => {
    if (tabFromUrl && TABS.some((t) => t.id === tabFromUrl)) {
      setActiveTab(tabFromUrl);
    }
  }, [tabFromUrl]);

  return (
    <div className="flex flex-col gap-6 p-6">
      <div className="flex items-center gap-3">
        <Server className="h-8 w-8 text-primary" />
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Asset & Risk Management</h1>
          <p className="text-muted-foreground">
            Track assets, manage risk registers, and assess third-party vendor risk
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
          <TabsContent value="inventory" className="mt-4">
            <AssetInventoryPage />
          </TabsContent>
          <TabsContent value="risk" className="mt-4">
            <RiskRegisterPage />
          </TabsContent>
          <TabsContent value="tprm" className="mt-4">
            <TprmPage />
          </TabsContent>
        </Suspense>
      </Tabs>
    </div>
  );
}

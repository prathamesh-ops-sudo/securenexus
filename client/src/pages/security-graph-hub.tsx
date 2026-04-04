import { useState, useEffect, lazy, Suspense } from "react";
import { useLocation } from "wouter";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";
import { Network, GitBranch, Search, GitMerge } from "lucide-react";

const UnifiedSecurityGraphPage = lazy(() => import("./unified-security-graph"));
const AttackGraphPage = lazy(() => import("./attack-graph"));
const EntityGraphPage = lazy(() => import("./entity-graph"));
const EntityMergeAliasPage = lazy(() => import("./entity-merge-alias"));

const TABS = [
  { id: "unified", label: "Unified Graph", icon: Network },
  { id: "attack-paths", label: "Attack Paths", icon: GitBranch },
  { id: "entity-explorer", label: "Entity Explorer", icon: Search },
  { id: "entity-resolution", label: "Entity Resolution", icon: GitMerge },
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

export default function SecurityGraphHubPage() {
  const [location] = useLocation();
  const params = new URLSearchParams(location.split("?")[1] || "");
  const tabFromUrl = params.get("tab") as TabId | null;
  const [activeTab, setActiveTab] = useState<TabId>(
    tabFromUrl && TABS.some((t) => t.id === tabFromUrl) ? tabFromUrl : "unified",
  );

  useEffect(() => {
    if (tabFromUrl && TABS.some((t) => t.id === tabFromUrl)) {
      setActiveTab(tabFromUrl);
    }
  }, [tabFromUrl]);

  return (
    <div className="flex flex-col gap-6 p-6">
      <div className="flex items-center gap-3">
        <Network className="h-8 w-8 text-primary" />
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Security Graph</h1>
          <p className="text-muted-foreground">
            Visualize and analyze security entities, relationships, and attack paths
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
          <TabsContent value="unified" className="mt-4">
            <UnifiedSecurityGraphPage />
          </TabsContent>
          <TabsContent value="attack-paths" className="mt-4">
            <AttackGraphPage />
          </TabsContent>
          <TabsContent value="entity-explorer" className="mt-4">
            <EntityGraphPage />
          </TabsContent>
          <TabsContent value="entity-resolution" className="mt-4">
            <EntityMergeAliasPage />
          </TabsContent>
        </Suspense>
      </Tabs>
    </div>
  );
}

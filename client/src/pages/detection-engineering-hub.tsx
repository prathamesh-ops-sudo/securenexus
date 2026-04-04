import { useState, useEffect, lazy, Suspense } from "react";
import { useSearch } from "wouter";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";
import { ShieldAlert, Wand2, UserCheck, Terminal } from "lucide-react";

const DetectionRulesPage = lazy(() => import("./detection-rules"));
const AiDetectionRulesPage = lazy(() => import("./ai-detection-rules"));
const UebaPage = lazy(() => import("./ueba"));
const AgentResponsePage = lazy(() => import("./agent-response"));

const TABS = [
  { id: "rules", label: "Detection Rules", icon: ShieldAlert },
  { id: "ai-rules", label: "AI Detection Rules", icon: Wand2 },
  { id: "ueba", label: "UEBA Analytics", icon: UserCheck },
  { id: "agent-response", label: "Agent Response", icon: Terminal },
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

export default function DetectionEngineeringHubPage() {
  const search = useSearch();
  const params = new URLSearchParams(search);
  const tabFromUrl = params.get("tab") as TabId | null;
  const [activeTab, setActiveTab] = useState<TabId>(
    tabFromUrl && TABS.some((t) => t.id === tabFromUrl) ? tabFromUrl : "rules",
  );

  useEffect(() => {
    if (tabFromUrl && TABS.some((t) => t.id === tabFromUrl)) {
      setActiveTab(tabFromUrl);
    }
  }, [tabFromUrl]);

  return (
    <div className="flex flex-col gap-6 p-6">
      <div className="flex items-center gap-3">
        <ShieldAlert className="h-8 w-8 text-primary" />
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Detection Engineering</h1>
          <p className="text-muted-foreground">
            Create, manage, and tune detection rules with AI assistance and behavioral analytics
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
          <TabsContent value="rules" className="mt-4">
            <DetectionRulesPage />
          </TabsContent>
          <TabsContent value="ai-rules" className="mt-4">
            <AiDetectionRulesPage />
          </TabsContent>
          <TabsContent value="ueba" className="mt-4">
            <UebaPage />
          </TabsContent>
          <TabsContent value="agent-response" className="mt-4">
            <AgentResponsePage />
          </TabsContent>
        </Suspense>
      </Tabs>
    </div>
  );
}

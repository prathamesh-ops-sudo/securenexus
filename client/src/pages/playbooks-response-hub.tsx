import { useState, useEffect, lazy, Suspense } from "react";
import { useLocation } from "wouter";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";
import { Zap, Workflow, Bot, RotateCcw, BookOpen, ClipboardList } from "lucide-react";

const PlaybooksPage = lazy(() => import("./playbooks"));
const AutonomousResponsePage = lazy(() => import("./autonomous-response"));
const RollbackHistoryPage = lazy(() => import("./rollback-history"));
const PlaybookTemplatesPage = lazy(() => import("./playbook-templates"));
const RunbookTemplatesPage = lazy(() => import("./runbook-templates"));

const TABS = [
  { id: "playbooks", label: "Playbooks", icon: Workflow },
  { id: "autonomous", label: "Autonomous Response", icon: Bot },
  { id: "rollback", label: "Rollback History", icon: RotateCcw },
  { id: "playbook-templates", label: "Playbook Library", icon: BookOpen },
  { id: "runbook-templates", label: "Runbook Library", icon: ClipboardList },
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

export default function PlaybooksResponseHubPage() {
  const [location] = useLocation();
  const params = new URLSearchParams(location.split("?")[1] || "");
  const tabFromUrl = params.get("tab") as TabId | null;
  const [activeTab, setActiveTab] = useState<TabId>(
    tabFromUrl && TABS.some((t) => t.id === tabFromUrl) ? tabFromUrl : "playbooks",
  );

  useEffect(() => {
    if (tabFromUrl && TABS.some((t) => t.id === tabFromUrl)) {
      setActiveTab(tabFromUrl);
    }
  }, [tabFromUrl]);

  return (
    <div className="flex flex-col gap-6 p-6">
      <div className="flex items-center gap-3">
        <Zap className="h-8 w-8 text-primary" />
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Response & Automation</h1>
          <p className="text-muted-foreground">
            Orchestrate incident response with playbooks, autonomous actions, and runbooks
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
          <TabsContent value="playbooks" className="mt-4">
            <PlaybooksPage />
          </TabsContent>
          <TabsContent value="autonomous" className="mt-4">
            <AutonomousResponsePage />
          </TabsContent>
          <TabsContent value="rollback" className="mt-4">
            <RollbackHistoryPage />
          </TabsContent>
          <TabsContent value="playbook-templates" className="mt-4">
            <PlaybookTemplatesPage />
          </TabsContent>
          <TabsContent value="runbook-templates" className="mt-4">
            <RunbookTemplatesPage />
          </TabsContent>
        </Suspense>
      </Tabs>
    </div>
  );
}

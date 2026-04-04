import { useState, useEffect, lazy, Suspense } from "react";
import { useSearch } from "wouter";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";
import { Brain, MessageSquare, Wand2, Server, BookOpen, DollarSign } from "lucide-react";

const AIEnginePage = lazy(() => import("./ai-engine"));
const SocCopilotPage = lazy(() => import("./soc-copilot"));
const PromptToArtifactPage = lazy(() => import("./prompt-to-artifact"));
const ModelGatewayPage = lazy(() => import("./model-gateway"));
const AiPromptRegistryPage = lazy(() => import("./ai-prompt-registry"));
const AiFeedbackFormPage = lazy(() => import("./ai-feedback-form"));
const AiBudgetControlsPage = lazy(() => import("./ai-budget-controls"));

const TABS = [
  { id: "engine", label: "AI Engine", icon: Brain },
  { id: "copilot", label: "SOC Co-Pilot", icon: MessageSquare },
  { id: "prompt-builder", label: "Prompt Builder", icon: Wand2 },
  { id: "gateway", label: "Model Gateway", icon: Server },
  { id: "registry", label: "Prompt Registry", icon: BookOpen },
  { id: "feedback", label: "Feedback Loop", icon: MessageSquare },
  { id: "budget", label: "Budget & Limits", icon: DollarSign },
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

export default function AiPlatformHubPage() {
  const search = useSearch();
  const params = new URLSearchParams(search);
  const tabFromUrl = params.get("tab") as TabId | null;
  const [activeTab, setActiveTab] = useState<TabId>(
    tabFromUrl && TABS.some((t) => t.id === tabFromUrl) ? tabFromUrl : "engine",
  );

  useEffect(() => {
    if (tabFromUrl && TABS.some((t) => t.id === tabFromUrl)) {
      setActiveTab(tabFromUrl);
    }
  }, [tabFromUrl]);

  return (
    <div className="flex flex-col gap-6 p-6">
      <div className="flex items-center gap-3">
        <Brain className="h-8 w-8 text-primary" />
        <div>
          <h1 className="text-3xl font-bold tracking-tight">AI Platform</h1>
          <p className="text-muted-foreground">
            AI-powered security analysis, co-pilot assistance, and model governance
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
          <TabsContent value="engine" className="mt-4">
            <AIEnginePage />
          </TabsContent>
          <TabsContent value="copilot" className="mt-4">
            <SocCopilotPage />
          </TabsContent>
          <TabsContent value="prompt-builder" className="mt-4">
            <PromptToArtifactPage />
          </TabsContent>
          <TabsContent value="gateway" className="mt-4">
            <ModelGatewayPage />
          </TabsContent>
          <TabsContent value="registry" className="mt-4">
            <AiPromptRegistryPage />
          </TabsContent>
          <TabsContent value="feedback" className="mt-4">
            <AiFeedbackFormPage />
          </TabsContent>
          <TabsContent value="budget" className="mt-4">
            <AiBudgetControlsPage />
          </TabsContent>
        </Suspense>
      </Tabs>
    </div>
  );
}

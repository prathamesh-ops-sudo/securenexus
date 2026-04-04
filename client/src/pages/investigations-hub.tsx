import { useState, useEffect, lazy, Suspense } from "react";
import { useLocation } from "wouter";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";
import { Microscope, Shield, Crosshair, History, Fingerprint, Link2 } from "lucide-react";

const WarRoomPage = lazy(() => import("./war-room"));
const ThreatHuntingPage = lazy(() => import("./threat-hunting"));
const InvestigationTimelinePage = lazy(() => import("./investigation-timeline"));
const EvidenceChainViewerPage = lazy(() => import("./evidence-chain-viewer"));
const EvidenceCustodyPage = lazy(() => import("./evidence-custody"));

const TABS = [
  { id: "war-room", label: "War Room", icon: Shield },
  { id: "threat-hunting", label: "Threat Hunting", icon: Crosshair },
  { id: "timeline", label: "Timeline", icon: History },
  { id: "evidence-chain", label: "Evidence Chain", icon: Fingerprint },
  { id: "evidence-locker", label: "Evidence Locker", icon: Link2 },
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

export default function InvestigationsHubPage() {
  const [location] = useLocation();
  const params = new URLSearchParams(location.split("?")[1] || "");
  const tabFromUrl = params.get("tab") as TabId | null;
  const [activeTab, setActiveTab] = useState<TabId>(
    tabFromUrl && TABS.some((t) => t.id === tabFromUrl) ? tabFromUrl : "war-room",
  );

  useEffect(() => {
    if (tabFromUrl && TABS.some((t) => t.id === tabFromUrl)) {
      setActiveTab(tabFromUrl);
    }
  }, [tabFromUrl]);

  return (
    <div className="flex flex-col gap-6 p-6">
      <div className="flex items-center gap-3">
        <Microscope className="h-8 w-8 text-primary" />
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Investigations</h1>
          <p className="text-muted-foreground">Investigate threats, hunt for adversaries, and manage evidence chains</p>
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
          <TabsContent value="war-room" className="mt-4">
            <WarRoomPage />
          </TabsContent>
          <TabsContent value="threat-hunting" className="mt-4">
            <ThreatHuntingPage />
          </TabsContent>
          <TabsContent value="timeline" className="mt-4">
            <InvestigationTimelinePage />
          </TabsContent>
          <TabsContent value="evidence-chain" className="mt-4">
            <EvidenceChainViewerPage />
          </TabsContent>
          <TabsContent value="evidence-locker" className="mt-4">
            <EvidenceCustodyPage />
          </TabsContent>
        </Suspense>
      </Tabs>
    </div>
  );
}

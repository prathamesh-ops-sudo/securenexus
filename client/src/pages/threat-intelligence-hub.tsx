import { useState, useEffect, lazy, Suspense } from "react";
import { useLocation } from "wouter";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";
import { Newspaper, Rss, Upload, Bug, Target, Crosshair, Swords, Globe } from "lucide-react";

const ThreatIntelFeedsPage = lazy(() => import("./threat-intel-feeds"));
const OsintFeedsConfigPage = lazy(() => import("./osint-feeds-config"));
const IocIngestionMatchingPage = lazy(() => import("./ioc-ingestion-matching"));
const CveBrowserPage = lazy(() => import("./cve-browser"));
const CampaignViewerPage = lazy(() => import("./campaign-viewer"));
const MitreAttackPage = lazy(() => import("./mitre-attack"));
const KillChainPage = lazy(() => import("./kill-chain"));

const TABS = [
  { id: "feeds", label: "Threat Feeds", icon: Newspaper },
  { id: "osint", label: "OSINT", icon: Rss },
  { id: "ioc", label: "IOC Management", icon: Upload },
  { id: "cve", label: "CVE Database", icon: Bug },
  { id: "campaigns", label: "Campaigns", icon: Target },
  { id: "mitre", label: "MITRE ATT&CK", icon: Crosshair },
  { id: "kill-chain", label: "Kill Chain", icon: Swords },
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

export default function ThreatIntelligenceHubPage() {
  const [location] = useLocation();
  const params = new URLSearchParams(location.split("?")[1] || "");
  const tabFromUrl = params.get("tab") as TabId | null;
  const [activeTab, setActiveTab] = useState<TabId>(
    tabFromUrl && TABS.some((t) => t.id === tabFromUrl) ? tabFromUrl : "feeds",
  );

  useEffect(() => {
    if (tabFromUrl && TABS.some((t) => t.id === tabFromUrl)) {
      setActiveTab(tabFromUrl);
    }
  }, [tabFromUrl]);

  return (
    <div className="flex flex-col gap-6 p-6">
      <div className="flex items-center gap-3">
        <Globe className="h-8 w-8 text-primary" />
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Threat Intelligence</h1>
          <p className="text-muted-foreground">Collect, analyze, and track threat intelligence from multiple sources</p>
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
          <TabsContent value="feeds" className="mt-4">
            <ThreatIntelFeedsPage />
          </TabsContent>
          <TabsContent value="osint" className="mt-4">
            <OsintFeedsConfigPage />
          </TabsContent>
          <TabsContent value="ioc" className="mt-4">
            <IocIngestionMatchingPage />
          </TabsContent>
          <TabsContent value="cve" className="mt-4">
            <CveBrowserPage />
          </TabsContent>
          <TabsContent value="campaigns" className="mt-4">
            <CampaignViewerPage />
          </TabsContent>
          <TabsContent value="mitre" className="mt-4">
            <MitreAttackPage />
          </TabsContent>
          <TabsContent value="kill-chain" className="mt-4">
            <KillChainPage />
          </TabsContent>
        </Suspense>
      </Tabs>
    </div>
  );
}

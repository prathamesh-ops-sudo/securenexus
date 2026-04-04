import { useState, useEffect, lazy, Suspense } from "react";
import { useLocation } from "wouter";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";
import { Radar, Mail, GraduationCap } from "lucide-react";

const DnsSecurityPage = lazy(() => import("./dns-security"));
const EmailSecurityPage = lazy(() => import("./email-security"));
const SecurityAwarenessPage = lazy(() => import("./security-awareness"));

const TABS = [
  { id: "dns", label: "DNS Security", icon: Radar },
  { id: "email", label: "Email Security", icon: Mail },
  { id: "awareness", label: "Phishing & Awareness", icon: GraduationCap },
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

export default function CommsSecurityHubPage() {
  const [location] = useLocation();
  const params = new URLSearchParams(location.split("?")[1] || "");
  const tabFromUrl = params.get("tab") as TabId | null;
  const [activeTab, setActiveTab] = useState<TabId>(
    tabFromUrl && TABS.some((t) => t.id === tabFromUrl) ? tabFromUrl : "dns",
  );

  useEffect(() => {
    if (tabFromUrl && TABS.some((t) => t.id === tabFromUrl)) {
      setActiveTab(tabFromUrl);
    }
  }, [tabFromUrl]);

  return (
    <div className="flex flex-col gap-6 p-6">
      <div className="flex items-center gap-3">
        <Mail className="h-8 w-8 text-primary" />
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Communications Security</h1>
          <p className="text-muted-foreground">Protect DNS, email, and train users against phishing threats</p>
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
          <TabsContent value="dns" className="mt-4">
            <DnsSecurityPage />
          </TabsContent>
          <TabsContent value="email" className="mt-4">
            <EmailSecurityPage />
          </TabsContent>
          <TabsContent value="awareness" className="mt-4">
            <SecurityAwarenessPage />
          </TabsContent>
        </Suspense>
      </Tabs>
    </div>
  );
}

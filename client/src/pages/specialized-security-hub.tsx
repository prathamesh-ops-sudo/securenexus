import { useState, useEffect, lazy, Suspense } from "react";
import { useLocation } from "wouter";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";
import { Shield, Factory, Smartphone, Globe, DoorOpen, Atom } from "lucide-react";

const OtSecurityPage = lazy(() => import("./ot-security"));
const MobileSecurityPage = lazy(() => import("./mobile-security"));
const ApiSecurityPage = lazy(() => import("./api-security"));
const PhysicalSecurityPage = lazy(() => import("./physical-security"));
const QuantumReadinessPage = lazy(() => import("./quantum-readiness"));

const TABS = [
  { id: "ot-ics", label: "OT/ICS Security", icon: Factory },
  { id: "mobile", label: "Mobile Security", icon: Smartphone },
  { id: "api", label: "API Security", icon: Globe },
  { id: "physical", label: "Physical Security", icon: DoorOpen },
  { id: "quantum", label: "Quantum Readiness", icon: Atom },
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

export default function SpecializedSecurityHubPage() {
  const [location] = useLocation();
  const params = new URLSearchParams(location.split("?")[1] || "");
  const tabFromUrl = params.get("tab") as TabId | null;
  const [activeTab, setActiveTab] = useState<TabId>(
    tabFromUrl && TABS.some((t) => t.id === tabFromUrl) ? tabFromUrl : "ot-ics",
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
          <h1 className="text-3xl font-bold tracking-tight">Specialized Security</h1>
          <p className="text-muted-foreground">
            Industry-specific security for OT/ICS, mobile, API, physical, and quantum readiness
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
          <TabsContent value="ot-ics" className="mt-4">
            <OtSecurityPage />
          </TabsContent>
          <TabsContent value="mobile" className="mt-4">
            <MobileSecurityPage />
          </TabsContent>
          <TabsContent value="api" className="mt-4">
            <ApiSecurityPage />
          </TabsContent>
          <TabsContent value="physical" className="mt-4">
            <PhysicalSecurityPage />
          </TabsContent>
          <TabsContent value="quantum" className="mt-4">
            <QuantumReadinessPage />
          </TabsContent>
        </Suspense>
      </Tabs>
    </div>
  );
}

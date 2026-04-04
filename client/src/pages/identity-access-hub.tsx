import { useState, useEffect, lazy, Suspense } from "react";
import { useLocation } from "wouter";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";
import { Shield, KeyRound, RotateCcw } from "lucide-react";

const IdentityGovernancePage = lazy(() => import("./identity-governance"));
const JitSecretAccessPage = lazy(() => import("./jit-secret-access"));
const SecretRotationOverviewPage = lazy(() => import("./secret-rotation-overview"));

const TABS = [
  { id: "governance", label: "Identity Governance", icon: Shield },
  { id: "jit-access", label: "JIT Access", icon: KeyRound },
  { id: "secret-rotation", label: "Secret Rotation", icon: RotateCcw },
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

export default function IdentityAccessHubPage() {
  const [location] = useLocation();
  const params = new URLSearchParams(location.split("?")[1] || "");
  const tabFromUrl = params.get("tab") as TabId | null;
  const [activeTab, setActiveTab] = useState<TabId>(
    tabFromUrl && TABS.some((t) => t.id === tabFromUrl) ? tabFromUrl : "governance",
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
          <h1 className="text-3xl font-bold tracking-tight">Identity & Access</h1>
          <p className="text-muted-foreground">Govern identities, manage just-in-time access, and rotate secrets</p>
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
          <TabsContent value="governance" className="mt-4">
            <IdentityGovernancePage />
          </TabsContent>
          <TabsContent value="jit-access" className="mt-4">
            <JitSecretAccessPage />
          </TabsContent>
          <TabsContent value="secret-rotation" className="mt-4">
            <SecretRotationOverviewPage />
          </TabsContent>
        </Suspense>
      </Tabs>
    </div>
  );
}

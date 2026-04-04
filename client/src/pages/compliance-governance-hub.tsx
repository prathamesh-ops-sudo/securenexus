import { useState, useEffect, lazy, Suspense } from "react";
import { useSearch } from "wouter";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";
import { Scale, BadgeCheck, Search, FileText, Shield, Globe } from "lucide-react";

const CompliancePage = lazy(() => import("./compliance"));
const TrustCenterPage = lazy(() => import("./trust-center"));
const ComplianceGapPage = lazy(() => import("./compliance-gap"));
const AuditLogPage = lazy(() => import("./audit-log"));
const PolicyPacksPage = lazy(() => import("./policy-packs"));
const DataResidencyPage = lazy(() => import("./data-residency"));

const TABS = [
  { id: "center", label: "Compliance Center", icon: Scale },
  { id: "trust", label: "Trust Center", icon: BadgeCheck },
  { id: "gap", label: "Gap Analysis", icon: Search },
  { id: "audit", label: "Audit Log", icon: FileText },
  { id: "policies", label: "Policy Packs", icon: Shield },
  { id: "residency", label: "Data Residency", icon: Globe },
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

export default function ComplianceGovernanceHubPage() {
  const search = useSearch();
  const params = new URLSearchParams(search);
  const tabFromUrl = params.get("tab") as TabId | null;
  const [activeTab, setActiveTab] = useState<TabId>(
    tabFromUrl && TABS.some((t) => t.id === tabFromUrl) ? tabFromUrl : "center",
  );

  useEffect(() => {
    if (tabFromUrl && TABS.some((t) => t.id === tabFromUrl)) {
      setActiveTab(tabFromUrl);
    }
  }, [tabFromUrl]);

  return (
    <div className="flex flex-col gap-6 p-6">
      <div className="flex items-center gap-3">
        <Scale className="h-8 w-8 text-primary" />
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Compliance & Governance</h1>
          <p className="text-muted-foreground">
            Manage compliance frameworks, audit trails, policy enforcement, and data sovereignty
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
          <TabsContent value="center" className="mt-4">
            <CompliancePage />
          </TabsContent>
          <TabsContent value="trust" className="mt-4">
            <TrustCenterPage />
          </TabsContent>
          <TabsContent value="gap" className="mt-4">
            <ComplianceGapPage />
          </TabsContent>
          <TabsContent value="audit" className="mt-4">
            <AuditLogPage />
          </TabsContent>
          <TabsContent value="policies" className="mt-4">
            <PolicyPacksPage />
          </TabsContent>
          <TabsContent value="residency" className="mt-4">
            <DataResidencyPage />
          </TabsContent>
        </Suspense>
      </Tabs>
    </div>
  );
}

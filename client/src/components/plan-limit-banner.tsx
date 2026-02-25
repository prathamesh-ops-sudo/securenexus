import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { useLocation } from "wouter";
import { AlertTriangle, X, ArrowRight } from "lucide-react";

interface UsageMetric {
  type: string;
  label: string;
  current: number;
  limit: number;
  pctUsed: number;
  status: string;
}

interface UsageData {
  planTier: string;
  warnings: UsageMetric[];
}

export function PlanLimitBanner() {
  const [, navigate] = useLocation();
  const [dismissed, setDismissed] = useState(false);

  const { data } = useQuery<UsageData>({
    queryKey: ["/api/usage-metering"],
    refetchInterval: 60000,
  });

  if (dismissed || !data || data.warnings.length === 0) return null;

  const criticalWarnings = data.warnings.filter(w => w.status === "critical");
  const softWarnings = data.warnings.filter(w => w.status === "warning");

  const isCritical = criticalWarnings.length > 0;
  const warningList = isCritical ? criticalWarnings : softWarnings;

  if (warningList.length === 0) return null;

  const labels = warningList.map(w => w.label).join(", ");

  return (
    <div className={`flex items-center gap-3 px-4 py-2 text-sm border-b ${
      isCritical
        ? "bg-red-500/10 border-red-500/20 text-red-400"
        : "bg-yellow-500/10 border-yellow-500/20 text-yellow-400"
    }`}>
      <AlertTriangle className="h-4 w-4 shrink-0" />
      <span className="flex-1 truncate">
        {isCritical
          ? `Plan limit reached for ${labels}. Upgrade to continue.`
          : `Approaching plan limit for ${labels} (${warningList[0].pctUsed}% used).`
        }
      </span>
      <button
        onClick={() => navigate("/usage-billing")}
        className="flex items-center gap-1 text-xs font-medium hover:underline shrink-0"
      >
        {isCritical ? "Upgrade Plan" : "View Usage"}
        <ArrowRight className="h-3 w-3" />
      </button>
      <button onClick={() => setDismissed(true)} className="p-0.5 rounded hover:bg-white/10 transition-colors shrink-0">
        <X className="h-3.5 w-3.5" />
      </button>
    </div>
  );
}

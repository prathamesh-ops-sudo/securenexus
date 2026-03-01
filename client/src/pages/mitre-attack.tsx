import { useQuery } from "@tanstack/react-query";
import { useMemo } from "react";
import { Shield, Crosshair, Grid3X3, AlertTriangle, Clock, Target } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import type { Alert } from "@shared/schema";
import { formatDateFull } from "@/lib/i18n";
import { usePageTitle } from "@/hooks/use-page-title";

const MITRE_TACTICS = [
  "Reconnaissance",
  "Resource Development",
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command and Control",
  "Exfiltration",
  "Impact",
] as const;

type TechniqueData = {
  tactic: string;
  technique: string;
  count: number;
  severities: string[];
  lastSeen: Date | null;
};

function getColorClass(count: number, maxCount: number): string {
  if (maxCount === 0) return "bg-red-500/10";
  const ratio = count / maxCount;
  if (ratio >= 0.75) return "bg-red-500/90";
  if (ratio >= 0.5) return "bg-red-500/60";
  if (ratio >= 0.25) return "bg-red-500/30";
  return "bg-red-500/10";
}

function getMostCommonSeverity(severities: string[]): string {
  if (severities.length === 0) return "unknown";
  const counts: Record<string, number> = {};
  for (const s of severities) {
    counts[s] = (counts[s] || 0) + 1;
  }
  return Object.entries(counts).sort((a, b) => b[1] - a[1])[0][0];
}

function severityVariant(severity: string): "destructive" | "secondary" | "outline" | "default" {
  switch (severity) {
    case "critical":
    case "high":
      return "destructive";
    case "medium":
      return "secondary";
    default:
      return "outline";
  }
}

function StatCard({
  title,
  value,
  icon: Icon,
  loading,
}: {
  title: string;
  value: string | number;
  icon: any;
  loading?: boolean;
}) {
  const testId = `stat-${title.toLowerCase().replace(/\s+/g, "-")}`;
  return (
    <Card data-testid={testId}>
      <CardHeader className="flex flex-row items-center justify-between gap-1 space-y-0 pb-2">
        <CardTitle className="text-xs font-medium text-muted-foreground uppercase tracking-wider">{title}</CardTitle>
        <div className="p-1.5 rounded-md bg-muted/50">
          <Icon className="h-3.5 w-3.5 text-muted-foreground" />
        </div>
      </CardHeader>
      <CardContent>
        {loading ? (
          <Skeleton className="h-7 w-16" />
        ) : (
          <div className="text-2xl font-bold tabular-nums" data-testid={`value-${testId}`}>
            {value}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export default function MitreAttackPage() {
  usePageTitle("MITRE ATT&CK Coverage");
  const {
    data: alerts,
    isLoading,
    isError: alertsError,
    refetch: refetchAlerts,
  } = useQuery<Alert[]>({
    queryKey: ["/api/alerts"],
  });

  const {
    techniqueMap: _techniqueMap,
    tacticTechniques,
    maxCount,
    topTechnique,
    allTechniques,
  } = useMemo(() => {
    const tMap = new Map<string, TechniqueData>();
    const tTechniques = new Map<string, TechniqueData[]>();

    MITRE_TACTICS.forEach((t) => tTechniques.set(t, []));

    if (!alerts)
      return {
        techniqueMap: tMap,
        tacticTechniques: tTechniques,
        maxCount: 0,
        topTechnique: "N/A",
        allTechniques: [] as TechniqueData[],
      };

    for (const alert of alerts) {
      if (!alert.mitreTactic || !alert.mitreTechnique) continue;

      const key = `${alert.mitreTactic}::${alert.mitreTechnique}`;
      const existing = tMap.get(key);

      if (existing) {
        existing.count += 1;
        existing.severities.push(alert.severity);
        const alertDate = alert.detectedAt
          ? new Date(alert.detectedAt)
          : alert.createdAt
            ? new Date(alert.createdAt)
            : null;
        if (alertDate && (!existing.lastSeen || alertDate > existing.lastSeen)) {
          existing.lastSeen = alertDate;
        }
      } else {
        const alertDate = alert.detectedAt
          ? new Date(alert.detectedAt)
          : alert.createdAt
            ? new Date(alert.createdAt)
            : null;
        const data: TechniqueData = {
          tactic: alert.mitreTactic,
          technique: alert.mitreTechnique,
          count: 1,
          severities: [alert.severity],
          lastSeen: alertDate,
        };
        tMap.set(key, data);
      }
    }

    let max = 0;
    let top = "N/A";
    let topCount = 0;

    for (const data of Array.from(tMap.values())) {
      if (data.count > max) max = data.count;
      if (data.count > topCount) {
        topCount = data.count;
        top = data.technique;
      }

      const tacticList = tTechniques.get(data.tactic);
      if (tacticList) {
        tacticList.push(data);
      }
    }

    Array.from(tTechniques.entries()).forEach(([, list]: [string, TechniqueData[]]) => {
      list.sort((a: TechniqueData, b: TechniqueData) => b.count - a.count);
    });

    const all = Array.from(tMap.values()).sort((a, b) => b.count - a.count);

    return { techniqueMap: tMap, tacticTechniques: tTechniques, maxCount: max, topTechnique: top, allTechniques: all };
  }, [alerts]);

  const coveredTactics = Array.from(tacticTechniques.entries()).filter(([, list]) => list.length > 0).length;
  const totalTechniques = allTechniques.length;
  const coveragePercent = Math.round((coveredTactics / MITRE_TACTICS.length) * 100);
  const hasData = totalTechniques > 0;

  if (isLoading) {
    return (
      <div className="p-4 md:p-6 space-y-6 max-w-[1400px] mx-auto">
        <div>
          <Skeleton className="h-8 w-64 mb-2" />
          <Skeleton className="h-4 w-96" />
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {Array.from({ length: 4 }).map((_, i) => (
            <Card key={i}>
              <CardHeader className="pb-2">
                <Skeleton className="h-4 w-24" />
              </CardHeader>
              <CardContent>
                <Skeleton className="h-7 w-16" />
              </CardContent>
            </Card>
          ))}
        </div>
        <Card>
          <CardContent className="p-6">
            <Skeleton className="h-[300px] w-full" />
          </CardContent>
        </Card>
      </div>
    );
  }

  if (alertsError) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-center" role="alert">
        <div className="rounded-full bg-destructive/10 p-3 ring-1 ring-destructive/20 mb-3">
          <AlertTriangle className="h-6 w-6 text-destructive" />
        </div>
        <p className="text-sm font-medium">Failed to load MITRE ATT&CK data</p>
        <p className="text-xs text-muted-foreground mt-1">An error occurred while fetching data.</p>
        <Button variant="outline" size="sm" className="mt-3" onClick={() => refetchAlerts()}>
          Try Again
        </Button>
      </div>
    );
  }

  return (
    <div className="p-4 md:p-6 space-y-6 max-w-[1400px] mx-auto" data-testid="page-mitre-attack">
      <div>
        <h1 className="text-2xl font-bold tracking-tight" data-testid="text-page-title">
          <span className="gradient-text-red">MITRE ATT&CK Coverage</span>
        </h1>
        <p className="text-sm text-muted-foreground mt-1" data-testid="text-page-description">
          Visualize alert coverage across the MITRE ATT&CK framework tactics and techniques
        </p>
        <div className="gradient-accent-line w-24 mt-2" />
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3" data-testid="stats-grid">
        <StatCard title="Tactics Covered" value={coveredTactics} icon={Shield} />
        <StatCard title="Techniques Detected" value={totalTechniques} icon={Crosshair} />
        <StatCard title="Coverage %" value={`${coveragePercent}%`} icon={Grid3X3} />
        <StatCard title="Top Technique" value={topTechnique} icon={Target} />
      </div>

      <Card data-testid="mitre-matrix">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium">ATT&CK Matrix</CardTitle>
        </CardHeader>
        <CardContent>
          {!hasData ? (
            <div className="flex flex-col items-center justify-center py-12 text-center" data-testid="empty-state">
              <AlertTriangle className="h-10 w-10 text-muted-foreground mb-3" />
              <p className="text-sm font-medium text-muted-foreground">No MITRE ATT&CK data found</p>
              <p className="text-xs text-muted-foreground mt-1">
                Alerts with MITRE tactic and technique mappings will appear here
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto -mx-4 px-4 pb-2" data-testid="matrix-scroll-container">
              <div className="flex gap-2" style={{ minWidth: `${MITRE_TACTICS.length * 140}px` }}>
                {MITRE_TACTICS.map((tactic) => {
                  const techniques = tacticTechniques.get(tactic) || [];
                  return (
                    <div
                      key={tactic}
                      className="flex-1 min-w-[130px]"
                      data-testid={`tactic-column-${tactic.toLowerCase().replace(/\s+/g, "-")}`}
                    >
                      <div className="mb-2">
                        <Badge
                          variant="outline"
                          className="text-[10px] w-full justify-center text-center whitespace-normal leading-tight py-1"
                          data-testid={`badge-tactic-${tactic.toLowerCase().replace(/\s+/g, "-")}`}
                        >
                          {tactic}
                        </Badge>
                      </div>
                      <div className="space-y-1">
                        {techniques.length === 0 ? (
                          <div
                            className="text-[10px] text-muted-foreground text-center py-3 rounded-md bg-muted/30"
                            data-testid={`empty-tactic-${tactic.toLowerCase().replace(/\s+/g, "-")}`}
                          >
                            No detections
                          </div>
                        ) : (
                          techniques.map((tech) => (
                            <div
                              key={tech.technique}
                              className={`rounded-md px-2 py-1.5 text-[10px] ${getColorClass(tech.count, maxCount)}`}
                              data-testid={`technique-cell-${tech.technique.toLowerCase().replace(/\s+/g, "-")}`}
                            >
                              <div className="font-medium truncate text-foreground">{tech.technique}</div>
                              <div className="text-muted-foreground tabular-nums">
                                {tech.count} alert{tech.count !== 1 ? "s" : ""}
                              </div>
                            </div>
                          ))
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {hasData && (
        <Card data-testid="technique-table">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium">Technique Details</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <table className="w-full text-sm" data-testid="table-techniques">
                <thead>
                  <tr className="border-b border-border">
                    <th className="text-left py-2 px-3 text-xs font-medium text-muted-foreground">Tactic</th>
                    <th className="text-left py-2 px-3 text-xs font-medium text-muted-foreground">Technique</th>
                    <th className="text-left py-2 px-3 text-xs font-medium text-muted-foreground">Alert Count</th>
                    <th className="text-left py-2 px-3 text-xs font-medium text-muted-foreground">Severity</th>
                    <th className="text-left py-2 px-3 text-xs font-medium text-muted-foreground">Last Seen</th>
                  </tr>
                </thead>
                <tbody>
                  {allTechniques.map((tech, i) => {
                    const severity = getMostCommonSeverity(tech.severities);
                    return (
                      <tr
                        key={`${tech.tactic}-${tech.technique}`}
                        className="border-b border-border/50"
                        data-testid={`row-technique-${i}`}
                      >
                        <td className="py-2 px-3 text-muted-foreground">{tech.tactic}</td>
                        <td className="py-2 px-3 font-medium">{tech.technique}</td>
                        <td className="py-2 px-3 tabular-nums">{tech.count}</td>
                        <td className="py-2 px-3">
                          <Badge
                            variant={severityVariant(severity)}
                            className="text-[10px] capitalize"
                            data-testid={`badge-severity-${i}`}
                          >
                            {severity}
                          </Badge>
                        </td>
                        <td className="py-2 px-3 text-muted-foreground">
                          <div className="flex items-center gap-1">
                            <Clock className="h-3 w-3" />
                            {tech.lastSeen ? formatDateFull(tech.lastSeen) : "Unknown"}
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

import { useQuery } from "@tanstack/react-query";
import { useParams } from "wouter";
import { ArrowLeft, Shield, AlertTriangle, Clock, TrendingDown, CheckCircle2 } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Link } from "wouter";
import type { Incident, Alert } from "@shared/schema";

function SeverityBadge({ severity }: { severity: string }) {
  const variants: Record<string, string> = {
    critical: "bg-red-500/10 text-red-500 border-red-500/20",
    high: "bg-orange-500/10 text-orange-500 border-orange-500/20",
    medium: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20",
    low: "bg-green-500/10 text-green-500 border-green-500/20",
  };
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium uppercase tracking-wider border ${variants[severity] || variants.medium}`}>
      {severity}
    </span>
  );
}

export default function IncidentDetailPage() {
  const params = useParams<{ id: string }>();

  const { data: incident, isLoading } = useQuery<Incident>({
    queryKey: ["/api/incidents", params.id],
    enabled: !!params.id,
  });

  const { data: allAlerts } = useQuery<Alert[]>({
    queryKey: ["/api/alerts"],
  });

  const relatedAlerts = allAlerts?.filter((a) => a.incidentId === params.id) ?? [];

  if (isLoading) {
    return (
      <div className="p-4 md:p-6 space-y-6 max-w-5xl mx-auto">
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-48 w-full" />
        <Skeleton className="h-96 w-full" />
      </div>
    );
  }

  if (!incident) {
    return (
      <div className="p-4 md:p-6 text-center py-20">
        <p className="text-muted-foreground">Incident not found</p>
        <Link href="/incidents">
          <Button variant="outline" className="mt-4">Back to Incidents</Button>
        </Link>
      </div>
    );
  }

  const mitigationSteps = incident.mitigationSteps
    ? (typeof incident.mitigationSteps === "string"
      ? JSON.parse(incident.mitigationSteps)
      : incident.mitigationSteps) as string[]
    : [];

  return (
    <div className="p-4 md:p-6 space-y-6 max-w-5xl mx-auto">
      <div className="flex items-center gap-3">
        <Link href="/incidents">
          <Button size="icon" variant="ghost" data-testid="button-back">
            <ArrowLeft className="h-4 w-4" />
          </Button>
        </Link>
        <div className="flex-1">
          <div className="flex items-center gap-2 flex-wrap">
            <h1 className="text-xl font-bold tracking-tight" data-testid="text-incident-title">{incident.title}</h1>
            <SeverityBadge severity={incident.severity} />
          </div>
          <p className="text-sm text-muted-foreground mt-1">{incident.summary}</p>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <Card>
          <CardContent className="p-3 text-center">
            <AlertTriangle className="h-4 w-4 mx-auto text-muted-foreground mb-1" />
            <div className="text-lg font-bold">{incident.alertCount}</div>
            <div className="text-[10px] text-muted-foreground">Correlated Alerts</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-3 text-center">
            <TrendingDown className="h-4 w-4 mx-auto text-muted-foreground mb-1" />
            <div className="text-lg font-bold">{incident.confidence ? `${Math.round(incident.confidence * 100)}%` : "N/A"}</div>
            <div className="text-[10px] text-muted-foreground">Confidence</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-3 text-center">
            <Clock className="h-4 w-4 mx-auto text-muted-foreground mb-1" />
            <div className="text-lg font-bold capitalize">{incident.status}</div>
            <div className="text-[10px] text-muted-foreground">Status</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-3 text-center">
            <Shield className="h-4 w-4 mx-auto text-muted-foreground mb-1" />
            <div className="text-lg font-bold">{incident.mitreTactics?.length || 0}</div>
            <div className="text-[10px] text-muted-foreground">MITRE Tactics</div>
          </CardContent>
        </Card>
      </div>

      {incident.aiNarrative && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Shield className="h-4 w-4 text-primary" />
              AI-Generated Narrative
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm leading-relaxed text-muted-foreground" data-testid="text-ai-narrative">{incident.aiNarrative}</p>
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {incident.mitreTactics && incident.mitreTactics.length > 0 && (
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-semibold">MITRE ATT&CK Mapping</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <div>
                <div className="text-xs text-muted-foreground mb-1.5">Tactics</div>
                <div className="flex flex-wrap gap-1.5">
                  {incident.mitreTactics.map((tactic, i) => (
                    <span key={i} className="px-2 py-1 rounded-md bg-primary/10 text-primary text-xs">{tactic}</span>
                  ))}
                </div>
              </div>
              {incident.mitreTechniques && incident.mitreTechniques.length > 0 && (
                <div>
                  <div className="text-xs text-muted-foreground mb-1.5">Techniques</div>
                  <div className="flex flex-wrap gap-1.5">
                    {incident.mitreTechniques.map((technique, i) => (
                      <span key={i} className="px-2 py-1 rounded-md bg-muted text-xs font-mono">{technique}</span>
                    ))}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        )}

        {mitigationSteps.length > 0 && (
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <CheckCircle2 className="h-4 w-4 text-green-500" />
                Mitigation Steps
              </CardTitle>
            </CardHeader>
            <CardContent>
              <ol className="space-y-2">
                {mitigationSteps.map((step: string, i: number) => (
                  <li key={i} className="flex items-start gap-2 text-sm">
                    <span className="flex items-center justify-center w-5 h-5 rounded-full bg-muted text-[10px] font-medium flex-shrink-0 mt-0.5">{i + 1}</span>
                    <span className="text-muted-foreground">{step}</span>
                  </li>
                ))}
              </ol>
            </CardContent>
          </Card>
        )}
      </div>

      {relatedAlerts.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-semibold">Related Alerts ({relatedAlerts.length})</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {relatedAlerts.map((alert) => (
                <div key={alert.id} className="flex items-center gap-3 p-2 rounded-md hover-elevate" data-testid={`related-alert-${alert.id}`}>
                  <AlertTriangle className="h-3 w-3 text-muted-foreground flex-shrink-0" />
                  <div className="flex-1 min-w-0">
                    <div className="text-xs font-medium">{alert.title}</div>
                    <div className="text-[10px] text-muted-foreground flex items-center gap-2 flex-wrap">
                      <span>{alert.source}</span>
                      <SeverityBadge severity={alert.severity} />
                      {alert.sourceIp && <span>IP: {alert.sourceIp}</span>}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

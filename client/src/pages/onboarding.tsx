import { useQuery } from "@tanstack/react-query";
import { CheckCircle2, AlertCircle, ArrowRight, Plug, ArrowDownToLine, Monitor, Cloud } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { useLocation } from "wouter";

type OnboardingStatus = {
  steps: {
    integrations: { completed: boolean; count: number };
    ingestion: { completed: boolean; totalIngested: number };
    endpoints: { completed: boolean; count: number };
    cspm: { completed: boolean; count: number };
  };
  completedCount: number;
  totalSteps: number;
};

export default function OnboardingPage() {
  const [, navigate] = useLocation();

  const { data, isLoading } = useQuery<OnboardingStatus>({
    queryKey: ["/api/v1/onboarding/status"],
  });

  const completed = data?.completedCount ?? 0;
  const total = data?.totalSteps ?? 4;
  const percent = total > 0 ? (completed / total) * 100 : 0;

  return (
    <div className="p-4 md:p-6 max-w-5xl mx-auto space-y-6" data-testid="page-onboarding">
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">
            <span className="gradient-text-red">Workspace Onboarding</span>
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Bring your data and assets into SecureNexus with a guided checklist.
          </p>
          <div className="gradient-accent-line w-24 mt-2" />
        </div>
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold">Onboarding progress</CardTitle>
          <CardDescription className="text-xs">
            {isLoading ? "Loading status..." : `${completed} of ${total} core steps completed`}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-3 mb-2">
            <Progress value={percent} className="h-2 flex-1" />
            <span className="text-xs text-muted-foreground w-12 text-right">
              {Math.round(percent)}%
            </span>
          </div>
        </CardContent>
      </Card>

      <div className="grid gap-4 md:grid-cols-2">
        {/* Step 1: Connect an integration */}
        <Card data-testid="card-onboarding-integrations" className="flex flex-col">
          <CardHeader className="pb-2 flex flex-row items-start gap-3">
            <div className="mt-1">
              <Plug className="h-5 w-5 text-muted-foreground" />
            </div>
            <div className="space-y-1">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                Connect your first integration
                {data?.steps.integrations.completed ? (
                  <CheckCircle2 className="h-4 w-4 text-emerald-500" />
                ) : (
                  <AlertCircle className="h-4 w-4 text-amber-500" />
                )}
              </CardTitle>
              <CardDescription className="text-xs">
                Configure a SIEM, EDR, or collaboration tool to start flowing security data into the platform.
              </CardDescription>
            </div>
          </CardHeader>
          <CardContent className="flex-1 flex flex-col justify-between space-y-3">
            <p className="text-xs text-muted-foreground">
              Current: {data?.steps.integrations.count ?? 0} integration
              {(data?.steps.integrations.count ?? 0) === 1 ? "" : "s"} configured.
            </p>
            <Button
              size="sm"
              variant="default"
              className="w-full justify-between"
              onClick={() => navigate("/integrations")}
            >
              Go to Integrations
              <ArrowRight className="h-3 w-3 ml-1" />
            </Button>
          </CardContent>
        </Card>

        {/* Step 2: Send data to ingestion */}
        <Card data-testid="card-onboarding-ingestion" className="flex flex-col">
          <CardHeader className="pb-2 flex flex-row items-start gap-3">
            <div className="mt-1">
              <ArrowDownToLine className="h-5 w-5 text-muted-foreground" />
            </div>
            <div className="space-y-1">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                Ingest alerts and events
                {data?.steps.ingestion.completed ? (
                  <CheckCircle2 className="h-4 w-4 text-emerald-500" />
                ) : (
                  <AlertCircle className="h-4 w-4 text-amber-500" />
                )}
              </CardTitle>
              <CardDescription className="text-xs">
                Use an API key and webhook to send alerts from your existing tools.
              </CardDescription>
            </div>
          </CardHeader>
          <CardContent className="flex-1 flex flex-col justify-between space-y-3">
            <p className="text-xs text-muted-foreground">
              Total ingested alerts: {data?.steps.ingestion.totalIngested ?? 0}.
            </p>
            <div className="flex flex-col gap-2">
              <Button
                size="sm"
                variant="default"
                className="w-full justify-between"
                onClick={() => navigate("/ingestion")}
              >
                View ingestion setup
                <ArrowRight className="h-3 w-3 ml-1" />
              </Button>
              <Button
                size="sm"
                variant="outline"
                className="w-full justify-between"
                onClick={() => navigate("/settings")}
              >
                Manage API keys
                <ArrowRight className="h-3 w-3 ml-1" />
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Step 3: Discover endpoint assets */}
        <Card data-testid="card-onboarding-endpoints" className="flex flex-col">
          <CardHeader className="pb-2 flex flex-row items-start gap-3">
            <div className="mt-1">
              <Monitor className="h-5 w-5 text-muted-foreground" />
            </div>
            <div className="space-y-1">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                Discover endpoint assets
                {data?.steps.endpoints.completed ? (
                  <CheckCircle2 className="h-4 w-4 text-emerald-500" />
                ) : (
                  <AlertCircle className="h-4 w-4 text-amber-500" />
                )}
              </CardTitle>
              <CardDescription className="text-xs">
                Inventory your critical servers and workstations and start collecting telemetry.
              </CardDescription>
            </div>
          </CardHeader>
          <CardContent className="flex-1 flex flex-col justify-between space-y-3">
            <p className="text-xs text-muted-foreground">
              Endpoint assets discovered: {data?.steps.endpoints.count ?? 0}.
            </p>
            <Button
              size="sm"
              variant="default"
              className="w-full justify-between"
              onClick={() => navigate("/endpoint-telemetry")}
            >
              Go to Endpoint Telemetry
              <ArrowRight className="h-3 w-3 ml-1" />
            </Button>
          </CardContent>
        </Card>

        {/* Step 4: Connect cloud accounts (CSPM) */}
        <Card data-testid="card-onboarding-cspm" className="flex flex-col">
          <CardHeader className="pb-2 flex flex-row items-start gap-3">
            <div className="mt-1">
              <Cloud className="h-5 w-5 text-muted-foreground" />
            </div>
            <div className="space-y-1">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                Connect cloud accounts
                {data?.steps.cspm.completed ? (
                  <CheckCircle2 className="h-4 w-4 text-emerald-500" />
                ) : (
                  <AlertCircle className="h-4 w-4 text-amber-500" />
                )}
              </CardTitle>
              <CardDescription className="text-xs">
                Add AWS, Azure, or GCP accounts to start CSPM scanning and posture analysis.
              </CardDescription>
            </div>
          </CardHeader>
          <CardContent className="flex-1 flex flex-col justify-between space-y-3">
            <p className="text-xs text-muted-foreground">
              Cloud accounts configured: {data?.steps.cspm.count ?? 0}.
            </p>
            <Button
              size="sm"
              variant="default"
              className="w-full justify-between"
              onClick={() => navigate("/cspm")}
            >
              Go to CSPM
              <ArrowRight className="h-3 w-3 ml-1" />
            </Button>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}


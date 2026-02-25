import { useMemo } from "react";
import { useLocation } from "wouter";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/hooks/use-auth";
import { StepCreateOrg } from "@/components/onboarding/step-create-org";
import { StepChoosePlan } from "@/components/onboarding/step-choose-plan";
import { StepInviteTeam } from "@/components/onboarding/step-invite-team";
import { StepConnectIntegration } from "@/components/onboarding/step-connect-integration";
import { StepDashboardTour } from "@/components/onboarding/step-dashboard-tour";

type WizardStatus = {
  shouldOnboard: boolean;
  organization: { id: string; name: string } | null;
  progress: {
    currentStep: number;
    completedAt: string | null;
    stepsCompleted: {
      createOrg: boolean;
      choosePlan: boolean;
      inviteTeam: boolean;
      connectIntegration: boolean;
      dashboardTour: boolean;
    };
  } | null;
};

function normalizeStep(status?: WizardStatus): number {
  if (!status?.progress) return 1;
  return Math.max(1, Math.min(5, status.progress.currentStep || 1));
}

export default function OnboardingWizardPage() {
  const { toast } = useToast();
  const [, navigate] = useLocation();
  const { user } = useAuth();

  const { data: status, isLoading } = useQuery<WizardStatus>({
    queryKey: ["/api/onboarding/wizard-status"],
    refetchInterval: 10_000,
  });

  const step = normalizeStep(status);
  const pct = useMemo(() => Math.round((step / 5) * 100), [step]);

  const createOrg = useMutation({
    mutationFn: async (payload: { name: string; industry: string; companySize: string; contactEmail?: string }) => {
      const res = await apiRequest("POST", "/api/onboarding/create-org", payload);
      return res.json();
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["/api/onboarding/wizard-status"] });
      await queryClient.invalidateQueries({ queryKey: ["/api/auth/me"] });
    },
  });

  const choosePlan = useMutation({
    mutationFn: async (plan: "free" | "pro" | "enterprise") => {
      const res = await apiRequest("POST", "/api/onboarding/select-plan", { plan });
      return res.json();
    },
    onSuccess: async (data) => {
      await queryClient.invalidateQueries({ queryKey: ["/api/onboarding/wizard-status"] });
      if (data?.checkoutUrl) {
        window.location.href = data.checkoutUrl;
      }
    },
  });

  const inviteTeam = useMutation({
    mutationFn: async (payload: { invites?: Array<{ email: string; role: string }>; skip?: boolean }) => {
      const res = await apiRequest("POST", "/api/onboarding/invite-team", payload);
      return res.json();
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["/api/onboarding/wizard-status"] });
    },
  });

  const connectIntegration = useMutation({
    mutationFn: async (connector: { type: string; name: string; authType: string }) => {
      const res = await apiRequest("POST", "/api/connectors", {
        name: `${connector.name} (Onboarding)`,
        type: connector.type,
        authType: connector.authType,
        config: {},
        pollingIntervalMin: 5,
      });
      return res.json();
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["/api/onboarding/wizard-status"] });
      toast({ title: "Integration connected", description: "Your first connector has been created." });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to connect integration", description: error.message, variant: "destructive" });
    },
  });

  const completeOnboarding = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/onboarding/complete", { tourCompleted: true });
      return res.json();
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["/api/onboarding/wizard-status"] });
      navigate("/");
    },
  });

  if (isLoading) {
    return (
      <div className="p-6 max-w-5xl mx-auto">
        <Card>
          <CardHeader>
            <CardTitle>Loading onboarding wizard...</CardTitle>
          </CardHeader>
        </Card>
      </div>
    );
  }

  if (!status?.shouldOnboard) {
    return (
      <div className="p-6 max-w-5xl mx-auto">
        <Card>
          <CardHeader>
            <CardTitle>Onboarding complete</CardTitle>
            <CardDescription>Your workspace is ready.</CardDescription>
          </CardHeader>
          <CardContent>
            <button className="underline text-sm" onClick={() => navigate("/")}>Go to dashboard</button>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="p-4 md:p-6 max-w-5xl mx-auto space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Business Onboarding Wizard</CardTitle>
          <CardDescription>Step {step} of 5</CardDescription>
        </CardHeader>
        <CardContent className="space-y-2">
          <Progress value={pct} />
          <p className="text-xs text-muted-foreground">{pct}% complete</p>
        </CardContent>
      </Card>

      {step === 1 ? (
        <StepCreateOrg
          defaultEmail={user?.email || ""}
          isSubmitting={createOrg.isPending}
          onSubmit={async (payload) => {
            try {
              await createOrg.mutateAsync(payload);
            } catch (error: any) {
              toast({ title: "Failed to create organization", description: error?.message || "Try again", variant: "destructive" });
            }
          }}
        />
      ) : null}

      {step === 2 ? (
        <StepChoosePlan
          isSubmitting={choosePlan.isPending}
          onSelectPlan={async (plan) => {
            try {
              await choosePlan.mutateAsync(plan);
            } catch (error: any) {
              toast({ title: "Failed to select plan", description: error?.message || "Try again", variant: "destructive" });
            }
          }}
        />
      ) : null}

      {step === 3 ? (
        <StepInviteTeam
          isSubmitting={inviteTeam.isPending}
          onInvite={async (invites) => {
            try {
              await inviteTeam.mutateAsync({ invites });
            } catch (error: any) {
              toast({ title: "Failed to invite team", description: error?.message || "Try again", variant: "destructive" });
            }
          }}
          onSkip={async () => {
            try {
              await inviteTeam.mutateAsync({ skip: true });
            } catch (error: any) {
              toast({ title: "Failed to skip step", description: error?.message || "Try again", variant: "destructive" });
            }
          }}
        />
      ) : null}

      {step === 4 ? (
        <StepConnectIntegration
          isSubmitting={connectIntegration.isPending}
          alreadyConnected={!!status.progress?.stepsCompleted.connectIntegration}
          onConnect={async (connector) => {
            await connectIntegration.mutateAsync(connector);
          }}
          onContinue={() => queryClient.invalidateQueries({ queryKey: ["/api/onboarding/wizard-status"] })}
        />
      ) : null}

      {step === 5 ? (
        <StepDashboardTour
          isSubmitting={completeOnboarding.isPending}
          onFinish={async () => {
            try {
              await completeOnboarding.mutateAsync();
            } catch (error: any) {
              toast({ title: "Failed to finish onboarding", description: error?.message || "Try again", variant: "destructive" });
            }
          }}
        />
      ) : null}
    </div>
  );
}

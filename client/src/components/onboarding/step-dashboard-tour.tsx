import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";

const TOUR_STOPS = [
  { title: "Sidebar Navigation", description: "Use the left navigation to move between dashboard, alerts, incidents, and operations pages." },
  { title: "Dashboard Metrics", description: "Track key posture and incident metrics at the top of your dashboard." },
  { title: "Alert Trend Chart", description: "Review alert volume trends and quickly identify spikes." },
  { title: "Command Palette", description: "Press Ctrl+K to instantly navigate and trigger common actions." },
  { title: "Notification Bell", description: "Stay updated on critical events and assignment changes." },
  { title: "Settings", description: "Manage organization, roles, integrations, and onboarding replay from settings." },
];

export function StepDashboardTour({
  isSubmitting,
  onFinish,
}: {
  isSubmitting: boolean;
  onFinish: () => Promise<void>;
}) {
  const [index, setIndex] = useState(0);
  const stop = TOUR_STOPS[index];
  const pct = Math.round(((index + 1) / TOUR_STOPS.length) * 100);

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>Dashboard tour</CardTitle>
          <CardDescription>Quick walkthrough of the key product surfaces.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Progress value={pct} />
          <div className="rounded-md border p-4 space-y-2 bg-muted/20">
            <p className="text-xs text-muted-foreground">Stop {index + 1} of {TOUR_STOPS.length}</p>
            <h3 className="font-semibold">{stop.title}</h3>
            <p className="text-sm text-muted-foreground">{stop.description}</p>
          </div>
          <div className="flex gap-2">
            <Button variant="outline" disabled={index === 0 || isSubmitting} onClick={() => setIndex((i) => Math.max(0, i - 1))}>
              Back
            </Button>
            {index < TOUR_STOPS.length - 1 ? (
              <Button disabled={isSubmitting} onClick={() => setIndex((i) => Math.min(TOUR_STOPS.length - 1, i + 1))}>
                Next
              </Button>
            ) : (
              <Button disabled={isSubmitting} onClick={onFinish}>
                {isSubmitting ? "Finishing..." : "Finish onboarding"}
              </Button>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

export function StepChoosePlan({
  isSubmitting,
  onSelectPlan,
}: {
  isSubmitting: boolean;
  onSelectPlan: (plan: "free" | "pro" | "enterprise") => Promise<void>;
}) {
  const plans: Array<{ key: "free" | "pro" | "enterprise"; title: string; price: string; details: string }> = [
    { key: "free", title: "Free", price: "$0", details: "Best for evaluation and small teams." },
    { key: "pro", title: "Pro", price: "$99/mo", details: "Advanced workflows and higher limits." },
    { key: "enterprise", title: "Enterprise", price: "Custom", details: "Large org controls and premium support." },
  ];

  return (
    <div className="grid gap-4 md:grid-cols-3">
      {plans.map((plan) => (
        <Card key={plan.key} className={plan.key === "pro" ? "border-primary/40" : ""}>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle>{plan.title}</CardTitle>
              {plan.key === "pro" ? <Badge>Popular</Badge> : null}
            </div>
            <CardDescription>{plan.details}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <p className="text-2xl font-semibold">{plan.price}</p>
            <Button className="w-full" disabled={isSubmitting} onClick={() => onSelectPlan(plan.key)}>
              {isSubmitting ? "Processing..." : `Choose ${plan.title}`}
            </Button>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

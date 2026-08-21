import { AlertTriangle } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";

export function ApiQueryError({ error, label }: { error: unknown; label: string }) {
  const message = error instanceof Error ? error.message : `Unable to load ${label}.`;

  return (
    <Card role="alert" className="border-red-500/30 bg-red-500/5">
      <CardContent className="flex items-start gap-3 p-4">
        <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-red-400" aria-hidden="true" />
        <div>
          <p className="text-sm font-medium">Unable to load {label}</p>
          <p className="mt-1 text-xs text-muted-foreground">{message}</p>
        </div>
      </CardContent>
    </Card>
  );
}

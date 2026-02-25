import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

type ConnectorType = {
  type: string;
  name: string;
  description?: string;
  authType: string;
};

export function StepConnectIntegration({
  isSubmitting,
  onConnect,
  alreadyConnected,
  onContinue,
}: {
  isSubmitting: boolean;
  onConnect: (connector: ConnectorType) => Promise<void>;
  alreadyConnected: boolean;
  onContinue: () => void;
}) {
  const { data, isLoading } = useQuery<ConnectorType[]>({
    queryKey: ["/api/connectors/types"],
  });

  if (alreadyConnected) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Integration connected</CardTitle>
          <CardDescription>Your first integration is ready.</CardDescription>
        </CardHeader>
        <CardContent>
          <Button onClick={onContinue}>Continue</Button>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>Connect your first integration</CardTitle>
          <CardDescription>Pick one connector to complete onboarding.</CardDescription>
        </CardHeader>
      </Card>
      <div className="grid gap-3 md:grid-cols-2">
        {(data || []).slice(0, 8).map((connector) => (
          <Card key={connector.type}>
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle className="text-base">{connector.name}</CardTitle>
                <Badge variant="outline">{connector.authType}</Badge>
              </div>
              <CardDescription>{connector.description || connector.type}</CardDescription>
            </CardHeader>
            <CardContent>
              <Button disabled={isSubmitting || isLoading} onClick={() => onConnect(connector)}>
                {isSubmitting ? "Connecting..." : "Connect"}
              </Button>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}

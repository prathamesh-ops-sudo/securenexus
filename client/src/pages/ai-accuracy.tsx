import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { usePageTitle } from "@/hooks/use-page-title";
import { apiQuery } from "@/lib/queryClient";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Link } from "wouter";

type Report = {
  window: { from: string; to: string };
  decisionsTotal: number;
  adjudicatedCount: number;
  finalCount: number;
  provisionalCount: number;
  adjudicationCoverage: number | null;
  insufficientData: boolean;
  minimumSample: { threshold: number; count: number; reason: string | null };
  matrix: Record<"truePositive" | "trueNegative" | "falsePositive" | "falseNegative", number>;
  rates: Record<"agreementRate" | "precision" | "recall", number | null> &
    Record<"agreementRateReason" | "precisionReason" | "recallReason", string | null>;
  inconclusiveCount: number;
  unmappedCount: number;
  calibration: {
    label: string;
    count: number;
    inconclusiveCount: number;
    observedMaliciousRate: number | null;
    bucketMidpoint: number;
    insufficientData: boolean;
  }[];
  disagreements: {
    decisionId: string;
    predictedClass: string;
    adjudicatedClass: string;
    confidenceScore: number | null;
  }[];
};

const toIso = (date: Date): string => date.toISOString();
const matrixLabels = {
  truePositive: {
    label: "True positive",
    definition: "AI called it malicious and the analyst agreed.",
  },
  trueNegative: {
    label: "True negative",
    definition: "AI called it benign and the analyst agreed.",
  },
  falsePositive: {
    label: "False positive",
    definition: "AI called it malicious, but the analyst found it benign.",
  },
  falseNegative: {
    label: "False negative",
    definition: "AI called it benign, but the analyst found it malicious.",
  },
} as const;

export default function AiAccuracyPage() {
  usePageTitle("AI Accuracy");
  const [{ from, to: now }] = useState(() => {
    const to = new Date();
    const from = new Date(to);
    from.setDate(from.getDate() - 30);
    return { from, to };
  });
  const { data, isLoading, isError } = useQuery<Report>({
    queryKey: ["/api/ai/accuracy", from.toISOString(), now.toISOString()],
    queryFn: () =>
      apiQuery(
        `/api/ai/accuracy?from=${encodeURIComponent(toIso(from))}&to=${encodeURIComponent(toIso(now))}`,
        (value): value is Report => !!value,
      ),
  });

  if (isLoading) return <div className="p-6 text-muted-foreground">Loading AI accuracy…</div>;
  if (isError || !data) return <div className="p-6 text-destructive">AI accuracy could not be loaded.</div>;
  const percentage = (value: number | null): string =>
    value == null ? "Not recorded" : `${(value * 100).toFixed(1)}%`;
  const rateLabel = (value: number | null): string =>
    value == null && data.insufficientData
      ? `Withheld until ${data.minimumSample.threshold} adjudicated decisions`
      : percentage(value);

  return (
    <main className="container mx-auto space-y-6 p-6">
      <div>
        <h1 className="text-2xl font-semibold">AI Accuracy</h1>
        <p className="text-sm text-muted-foreground">
          Explicit tenant adjudications only · {new Date(data.window.from).toLocaleDateString()}–
          {new Date(data.window.to).toLocaleDateString()}
        </p>
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Coverage and rates</CardTitle>
        </CardHeader>
        <CardContent className="grid gap-4 md:grid-cols-4">
          <div>
            <p className="text-sm text-muted-foreground">Coverage</p>
            <p className="text-2xl">{percentage(data.adjudicationCoverage)}</p>
            <p className="text-xs">
              {data.adjudicatedCount}/{data.decisionsTotal} decisions
            </p>
          </div>
          {(["agreementRate", "precision", "recall"] as const).map((key) => (
            <div key={key}>
              <p className="text-sm capitalize text-muted-foreground">{key.replace("Rate", " rate")}</p>
              <p className="text-2xl">{rateLabel(data.rates[key])}</p>
              {data.rates[`${key}Reason` as keyof Report["rates"]] && (
                <p className="text-xs">{data.rates[`${key}Reason` as keyof Report["rates"]]}</p>
              )}
            </div>
          ))}
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Confusion matrix</CardTitle>
          <p className="text-sm text-muted-foreground">
            Judgements may postdate the decision window; the window selects decisions.
          </p>
        </CardHeader>
        <CardContent className="grid grid-cols-2 gap-3 md:grid-cols-4">
          {(Object.keys(matrixLabels) as (keyof typeof matrixLabels)[]).map((key) => (
            <div key={key} className="rounded border p-3">
              <p className="text-xs text-muted-foreground">{matrixLabels[key].label}</p>
              <p className="text-xl">{data.matrix[key]}</p>
              <p className="text-xs text-muted-foreground">{matrixLabels[key].definition}</p>
            </div>
          ))}
          <p className="col-span-full text-sm text-muted-foreground">
            Inconclusive: {data.inconclusiveCount} · Unmapped: {data.unmappedCount} · Final: {data.finalCount} ·
            Provisional: {data.provisionalCount}
          </p>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Calibration</CardTitle>
          <p className="text-sm text-muted-foreground">
            Whether “80% confident” corresponds to being right about 80% of the time for this tenant.
          </p>
        </CardHeader>
        <CardContent className="grid gap-2 md:grid-cols-5">
          {data.calibration.map((bucket) => (
            <div key={bucket.label} className="rounded border p-2 text-sm">
              <div className="flex justify-between">
                <span>{bucket.label}</span>
                {bucket.insufficientData && <Badge variant="outline">Sparse</Badge>}
              </div>
              <p>{bucket.count} definitive adjudications</p>
              <p>Excluded inconclusive: {bucket.inconclusiveCount}</p>
              <p>{bucket.observedMaliciousRate == null ? "Not recorded" : percentage(bucket.observedMaliciousRate)}</p>
            </div>
          ))}
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Disagreements</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          {data.disagreements.length === 0 ? (
            <p className="text-muted-foreground">No disagreements recorded.</p>
          ) : (
            data.disagreements.map((item) => (
              <Link
                key={item.decisionId}
                href={`/autonomous-soc?decisionId=${encodeURIComponent(item.decisionId)}`}
                className="flex justify-between rounded border p-3 hover:bg-muted"
              >
                <span>
                  {item.predictedClass} predicted, {item.adjudicatedClass} adjudicated
                </span>
                <span className="text-sm text-muted-foreground">
                  {item.confidenceScore == null ? "Confidence not recorded" : item.confidenceScore}
                </span>
              </Link>
            ))
          )}
        </CardContent>
      </Card>
    </main>
  );
}

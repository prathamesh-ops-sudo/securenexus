import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Separator } from "@/components/ui/separator";
import { useToast } from "@/hooks/use-toast";
import {
  FileText,
  Download,
  BarChart3,
  PieChart,
  TrendingUp,
  Shield,
  DollarSign,
  Globe,
  Building2,
  Clock,
  CheckCircle2,
  AlertTriangle,
  Loader2,
  Calendar,
  History,
} from "lucide-react";
import { apiRequest } from "@/lib/queryClient";
import { DashboardSkeleton } from "@/components/page-skeleton";

interface ReportType {
  id: string;
  name: string;
  description: string;
  format: string[];
}

interface ComplianceTemplate {
  id: string;
  name: string;
  framework: string;
  description: string;
  sections: string[];
}

interface WhiteLabelConfig {
  companyName: string;
  companyTagline?: string;
  primaryColor?: string;
  confidential?: boolean;
  generatedBy?: string;
  footerText?: string;
}

function downloadBlob(data: Blob, filename: string) {
  const url = URL.createObjectURL(data);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => {
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, 100);
}

export default function AdvancedReportingPage() {
  const { toast } = useToast();
  const [activeTab, setActiveTab] = useState("dashboard");
  const [selectedCompliance, setSelectedCompliance] = useState("soc2_readiness");
  const [boardPeriod, setBoardPeriod] = useState<"weekly" | "monthly">("weekly");
  const [whiteLabelEnabled, setWhiteLabelEnabled] = useState(false);
  const [whiteLabel, setWhiteLabel] = useState<WhiteLabelConfig>({
    companyName: "",
    companyTagline: "",
    primaryColor: "#0040FF",
    confidential: true,
    generatedBy: "",
    footerText: "",
  });

  const { data: reportTypes, isLoading } = useQuery<{
    reportTypes: ReportType[];
    complianceTemplates: ComplianceTemplate[];
  }>({
    queryKey: ["/api/advanced-reports/types"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/advanced-reports/types");
      const json = await res.json();
      return json.data ?? json;
    },
  });

  const getWhiteLabelPayload = (): WhiteLabelConfig | undefined => {
    if (!whiteLabelEnabled) return undefined;
    return {
      ...whiteLabel,
      companyName: whiteLabel.companyName || "Arica Tech Solutions",
    };
  };

  const executiveDashboardMutation = useMutation({
    mutationFn: async (format: string) => {
      const res = await apiRequest("POST", "/api/advanced-reports/executive-dashboard", {
        format,
        whiteLabel: getWhiteLabelPayload(),
      });
      if (format === "html") {
        const html = await res.text();
        const blob = new Blob([html], { type: "text/html" });
        downloadBlob(blob, "executive-dashboard.html");
      } else {
        const blob = await res.blob();
        downloadBlob(blob, "executive-dashboard.pdf");
      }
    },
    onSuccess: () => {
      toast({ title: "Report Downloaded", description: "Executive dashboard report has been downloaded." });
    },
    onError: () => {
      toast({ title: "Error", description: "Failed to generate report. Please try again.", variant: "destructive" });
    },
  });

  const complianceMutation = useMutation({
    mutationFn: async (templateId: string) => {
      const res = await apiRequest("POST", `/api/advanced-reports/compliance/${templateId}`, {
        whiteLabel: getWhiteLabelPayload(),
      });
      const blob = await res.blob();
      downloadBlob(blob, `${templateId}-report.pdf`);
    },
    onSuccess: () => {
      toast({ title: "Report Downloaded", description: "Compliance report has been downloaded." });
    },
    onError: () => {
      toast({ title: "Error", description: "Failed to generate compliance report.", variant: "destructive" });
    },
  });

  const boardSummaryMutation = useMutation({
    mutationFn: async (period: "weekly" | "monthly") => {
      const res = await apiRequest("POST", "/api/advanced-reports/board-summary", {
        period,
        whiteLabel: getWhiteLabelPayload(),
      });
      const blob = await res.blob();
      downloadBlob(blob, `board-summary-${period}.pdf`);
    },
    onSuccess: () => {
      toast({ title: "Report Downloaded", description: "Board summary has been downloaded." });
    },
    onError: () => {
      toast({ title: "Error", description: "Failed to generate board summary.", variant: "destructive" });
    },
  });

  const financialImpactMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/advanced-reports/financial-impact", {
        whiteLabel: getWhiteLabelPayload(),
      });
      const blob = await res.blob();
      downloadBlob(blob, "financial-risk-impact.pdf");
    },
    onSuccess: () => {
      toast({ title: "Report Downloaded", description: "Financial impact report has been downloaded." });
    },
    onError: () => {
      toast({ title: "Error", description: "Failed to generate financial impact report.", variant: "destructive" });
    },
  });

  const socKpiMutation = useMutation({
    mutationFn: async (format: string) => {
      const res = await apiRequest("POST", "/api/advanced-reports/soc-kpi", {
        format,
        whiteLabel: getWhiteLabelPayload(),
      });
      if (format === "html") {
        const html = await res.text();
        const blob = new Blob([html], { type: "text/html" });
        downloadBlob(blob, "soc-kpi-report.html");
      } else {
        const blob = await res.blob();
        downloadBlob(blob, "soc-kpi-report.pdf");
      }
    },
    onSuccess: () => {
      toast({ title: "Report Downloaded", description: "SOC KPI report has been downloaded." });
    },
    onError: () => {
      toast({ title: "Error", description: "Failed to generate SOC KPI report.", variant: "destructive" });
    },
  });

  const whiteLabelMutation = useMutation({
    mutationFn: async (reportType: string) => {
      if (!whiteLabel.companyName) {
        throw new Error("Company name is required for white-label reports.");
      }
      const res = await apiRequest("POST", "/api/advanced-reports/white-label", {
        reportType,
        whiteLabel: {
          ...whiteLabel,
          confidential: whiteLabel.confidential ?? true,
        },
      });
      const blob = await res.blob();
      const safeName = whiteLabel.companyName.replace(/[^a-zA-Z0-9]/g, "_");
      downloadBlob(blob, `${safeName}-${reportType}.pdf`);
    },
    onSuccess: () => {
      toast({ title: "Report Downloaded", description: "White-label report has been downloaded." });
    },
    onError: (err: Error) => {
      toast({
        title: "Error",
        description: err.message || "Failed to generate white-label report.",
        variant: "destructive",
      });
    },
  });

  const templates = reportTypes?.complianceTemplates ?? [];
  const isAnyLoading =
    executiveDashboardMutation.isPending ||
    complianceMutation.isPending ||
    boardSummaryMutation.isPending ||
    financialImpactMutation.isPending ||
    socKpiMutation.isPending ||
    whiteLabelMutation.isPending;

  if (isLoading) return <DashboardSkeleton />;

  return (
    <div className="p-6 space-y-6 max-w-[1400px] mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Advanced Reporting Engine</h1>
          <p className="text-muted-foreground text-sm mt-1">
            Generate PDF reports with charts, compliance assessments, executive dashboards, and financial impact
            analysis
          </p>
        </div>
        <Badge variant="outline" className="flex items-center gap-1.5">
          <FileText className="h-3.5 w-3.5" />
          {reportTypes?.reportTypes?.length ?? 0} Report Types
        </Badge>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="grid grid-cols-6 w-full max-w-[900px]">
          <TabsTrigger value="dashboard" className="flex items-center gap-1.5">
            <BarChart3 className="h-3.5 w-3.5" /> Dashboard
          </TabsTrigger>
          <TabsTrigger value="compliance" className="flex items-center gap-1.5">
            <Shield className="h-3.5 w-3.5" /> Compliance
          </TabsTrigger>
          <TabsTrigger value="board" className="flex items-center gap-1.5">
            <Building2 className="h-3.5 w-3.5" /> Board
          </TabsTrigger>
          <TabsTrigger value="financial" className="flex items-center gap-1.5">
            <DollarSign className="h-3.5 w-3.5" /> Financial
          </TabsTrigger>
          <TabsTrigger value="interactive" className="flex items-center gap-1.5">
            <Globe className="h-3.5 w-3.5" /> Interactive
          </TabsTrigger>
          <TabsTrigger value="whitelabel" className="flex items-center gap-1.5">
            <Building2 className="h-3.5 w-3.5" /> MSSP
          </TabsTrigger>
        </TabsList>

        {/* ────── Executive Dashboard ────── */}
        <TabsContent value="dashboard" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <BarChart3 className="h-5 w-5 text-blue-600" />
                Executive Security Dashboard
              </CardTitle>
              <CardDescription>
                Comprehensive security posture report with KPI cards, trend charts, severity breakdown, MITRE ATT&CK
                coverage, connector health, and financial risk impact analysis.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
                <Card className="border-l-4 border-l-blue-500">
                  <CardContent className="p-4">
                    <p className="text-xs text-muted-foreground">KPI Cards</p>
                    <p className="text-lg font-bold">8 Metrics</p>
                  </CardContent>
                </Card>
                <Card className="border-l-4 border-l-indigo-500">
                  <CardContent className="p-4">
                    <p className="text-xs text-muted-foreground">Charts</p>
                    <p className="text-lg font-bold">4 Visualizations</p>
                  </CardContent>
                </Card>
                <Card className="border-l-4 border-l-green-500">
                  <CardContent className="p-4">
                    <p className="text-xs text-muted-foreground">Tables</p>
                    <p className="text-lg font-bold">2 Data Tables</p>
                  </CardContent>
                </Card>
                <Card className="border-l-4 border-l-orange-500">
                  <CardContent className="p-4">
                    <p className="text-xs text-muted-foreground">Financial</p>
                    <p className="text-lg font-bold">Risk Analysis</p>
                  </CardContent>
                </Card>
              </div>
              <div className="flex gap-3">
                <Button onClick={() => executiveDashboardMutation.mutate("pdf")} disabled={isAnyLoading}>
                  {executiveDashboardMutation.isPending ? (
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  ) : (
                    <Download className="h-4 w-4 mr-2" />
                  )}
                  Download PDF
                </Button>
                <Button
                  variant="outline"
                  onClick={() => executiveDashboardMutation.mutate("html")}
                  disabled={isAnyLoading}
                >
                  <Globe className="h-4 w-4 mr-2" />
                  Interactive HTML
                </Button>
              </div>
            </CardContent>
          </Card>

          {/* SOC KPI */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <TrendingUp className="h-5 w-5 text-indigo-600" />
                SOC KPI Report
              </CardTitle>
              <CardDescription>
                Security Operations Center performance metrics with alert trends, severity distribution, and MITRE
                ATT&CK coverage.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex gap-3">
                <Button onClick={() => socKpiMutation.mutate("pdf")} disabled={isAnyLoading}>
                  {socKpiMutation.isPending ? (
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  ) : (
                    <Download className="h-4 w-4 mr-2" />
                  )}
                  Download PDF
                </Button>
                <Button variant="outline" onClick={() => socKpiMutation.mutate("html")} disabled={isAnyLoading}>
                  <Globe className="h-4 w-4 mr-2" />
                  Interactive HTML
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* ────── Compliance Templates ────── */}
        <TabsContent value="compliance" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Shield className="h-5 w-5 text-green-600" />
                Compliance Report Templates
              </CardTitle>
              <CardDescription>
                Generate framework-specific compliance assessments with gap analysis, control coverage scores, and
                remediation recommendations.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {templates.map((tpl) => (
                  <Card key={tpl.id} className="hover:border-blue-300 transition-colors">
                    <CardHeader className="pb-2">
                      <div className="flex items-center justify-between">
                        <Badge variant="secondary">{tpl.framework}</Badge>
                        <CheckCircle2 className="h-4 w-4 text-green-500" />
                      </div>
                      <CardTitle className="text-sm">{tpl.name}</CardTitle>
                      <CardDescription className="text-xs">{tpl.description}</CardDescription>
                    </CardHeader>
                    <CardContent className="pt-0">
                      <div className="flex flex-wrap gap-1 mb-3">
                        {tpl.sections.map((s) => (
                          <Badge key={s} variant="outline" className="text-[10px]">
                            {s.replace(/_/g, " ")}
                          </Badge>
                        ))}
                      </div>
                      <Button
                        size="sm"
                        className="w-full"
                        onClick={() => complianceMutation.mutate(tpl.id)}
                        disabled={isAnyLoading}
                      >
                        {complianceMutation.isPending && selectedCompliance === tpl.id ? (
                          <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />
                        ) : (
                          <Download className="h-3.5 w-3.5 mr-1.5" />
                        )}
                        Generate PDF
                      </Button>
                    </CardContent>
                  </Card>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* ────── Board Summary ────── */}
        <TabsContent value="board" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Building2 className="h-5 w-5 text-amber-600" />
                Board Security Summary
              </CardTitle>
              <CardDescription>
                Automated security summaries for board review with executive-level KPIs, risk assessment, and trend
                analysis. Designed for non-technical stakeholders.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center gap-4">
                <div className="space-y-1">
                  <Label>Report Period</Label>
                  <Select value={boardPeriod} onValueChange={(v) => setBoardPeriod(v as "weekly" | "monthly")}>
                    <SelectTrigger className="w-48">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="weekly">Weekly Summary</SelectItem>
                      <SelectItem value="monthly">Monthly Summary</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <Card className="border-l-4 border-l-amber-500">
                  <CardContent className="p-3">
                    <div className="flex items-center gap-2 text-sm font-medium">
                      <Clock className="h-4 w-4 text-amber-500" />
                      Executive Summary
                    </div>
                    <p className="text-xs text-muted-foreground mt-1">High-level posture overview</p>
                  </CardContent>
                </Card>
                <Card className="border-l-4 border-l-blue-500">
                  <CardContent className="p-3">
                    <div className="flex items-center gap-2 text-sm font-medium">
                      <TrendingUp className="h-4 w-4 text-blue-500" />
                      Trend Analysis
                    </div>
                    <p className="text-xs text-muted-foreground mt-1">Alert trends & severity breakdown</p>
                  </CardContent>
                </Card>
                <Card className="border-l-4 border-l-red-500">
                  <CardContent className="p-3">
                    <div className="flex items-center gap-2 text-sm font-medium">
                      <AlertTriangle className="h-4 w-4 text-red-500" />
                      Risk Assessment
                    </div>
                    <p className="text-xs text-muted-foreground mt-1">Risk level & open vulnerabilities</p>
                  </CardContent>
                </Card>
              </div>
              <Button onClick={() => boardSummaryMutation.mutate(boardPeriod)} disabled={isAnyLoading}>
                {boardSummaryMutation.isPending ? (
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                ) : (
                  <Download className="h-4 w-4 mr-2" />
                )}
                Download {boardPeriod === "weekly" ? "Weekly" : "Monthly"} Board Summary
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        {/* ────── Financial Impact ────── */}
        <TabsContent value="financial" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <DollarSign className="h-5 w-5 text-green-600" />
                Financial Risk Impact Assessment
              </CardTitle>
              <CardDescription>
                Translate security risk scores into dollar exposure using FAIR methodology. Includes annual risk
                exposure, mitigated vs. residual risk, cost of breach estimates, and security ROI analysis.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                <Card className="border-l-4 border-l-red-500">
                  <CardContent className="p-4">
                    <p className="text-xs text-muted-foreground">Annual Risk Exposure</p>
                    <p className="text-lg font-bold text-red-600">Quantified</p>
                    <p className="text-xs text-muted-foreground">Based on incident data</p>
                  </CardContent>
                </Card>
                <Card className="border-l-4 border-l-green-500">
                  <CardContent className="p-4">
                    <p className="text-xs text-muted-foreground">Mitigated Risk</p>
                    <p className="text-lg font-bold text-green-600">72%</p>
                    <p className="text-xs text-muted-foreground">Control effectiveness</p>
                  </CardContent>
                </Card>
                <Card className="border-l-4 border-l-orange-500">
                  <CardContent className="p-4">
                    <p className="text-xs text-muted-foreground">Cost of Breach</p>
                    <p className="text-lg font-bold text-orange-600">$4.45M</p>
                    <p className="text-xs text-muted-foreground">IBM 2024 average</p>
                  </CardContent>
                </Card>
                <Card className="border-l-4 border-l-blue-500">
                  <CardContent className="p-4">
                    <p className="text-xs text-muted-foreground">Risk Categories</p>
                    <p className="text-lg font-bold">5 Categories</p>
                    <p className="text-xs text-muted-foreground">FAIR methodology</p>
                  </CardContent>
                </Card>
              </div>
              <Button onClick={() => financialImpactMutation.mutate()} disabled={isAnyLoading}>
                {financialImpactMutation.isPending ? (
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                ) : (
                  <Download className="h-4 w-4 mr-2" />
                )}
                Download Financial Impact PDF
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        {/* ────── Interactive HTML ────── */}
        <TabsContent value="interactive" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Globe className="h-5 w-5 text-cyan-600" />
                Interactive HTML Reports
              </CardTitle>
              <CardDescription>
                Self-contained HTML reports with drill-down capability, interactive charts, and responsive layouts. Open
                in any browser — no server required.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <Card
                  className="hover:border-cyan-300 transition-colors cursor-pointer"
                  onClick={() => executiveDashboardMutation.mutate("html")}
                >
                  <CardContent className="p-4 text-center">
                    <BarChart3 className="h-8 w-8 mx-auto mb-2 text-blue-500" />
                    <p className="font-medium text-sm">Executive Dashboard</p>
                    <p className="text-xs text-muted-foreground mt-1">KPIs, charts, drill-down</p>
                  </CardContent>
                </Card>
                <Card
                  className="hover:border-cyan-300 transition-colors cursor-pointer"
                  onClick={() => socKpiMutation.mutate("html")}
                >
                  <CardContent className="p-4 text-center">
                    <TrendingUp className="h-8 w-8 mx-auto mb-2 text-indigo-500" />
                    <p className="font-medium text-sm">SOC KPI</p>
                    <p className="text-xs text-muted-foreground mt-1">Operations metrics</p>
                  </CardContent>
                </Card>
                <Card className="border-dashed opacity-60">
                  <CardContent className="p-4 text-center">
                    <PieChart className="h-8 w-8 mx-auto mb-2 text-muted-foreground" />
                    <p className="font-medium text-sm">MITRE ATT&CK</p>
                    <p className="text-xs text-muted-foreground mt-1">Coverage analysis</p>
                  </CardContent>
                </Card>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* ────── White-Label / MSSP ────── */}
        <TabsContent value="whitelabel" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Building2 className="h-5 w-5 text-purple-600" />
                White-Label Reports (MSSP)
              </CardTitle>
              <CardDescription>
                Generate branded reports for your managed security clients. Customize company name, logo, colors,
                tagline, and footer text. Reports are fully white-labeled with no SecureNexus branding.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-4">
                  <div className="space-y-2">
                    <Label>Client Company Name *</Label>
                    <Input
                      placeholder="e.g. Acme Corp"
                      value={whiteLabel.companyName}
                      onChange={(e) => setWhiteLabel({ ...whiteLabel, companyName: e.target.value })}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label>Company Tagline</Label>
                    <Input
                      placeholder="e.g. Enterprise Security Solutions"
                      value={whiteLabel.companyTagline || ""}
                      onChange={(e) => setWhiteLabel({ ...whiteLabel, companyTagline: e.target.value })}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label>Generated By</Label>
                    <Input
                      placeholder="Analyst name or email"
                      value={whiteLabel.generatedBy || ""}
                      onChange={(e) => setWhiteLabel({ ...whiteLabel, generatedBy: e.target.value })}
                    />
                  </div>
                </div>
                <div className="space-y-4">
                  <div className="space-y-2">
                    <Label>Brand Color</Label>
                    <div className="flex items-center gap-2">
                      <Input
                        type="color"
                        value={whiteLabel.primaryColor || "#0040FF"}
                        onChange={(e) => setWhiteLabel({ ...whiteLabel, primaryColor: e.target.value })}
                        className="w-12 h-10 p-1 cursor-pointer"
                      />
                      <Input
                        value={whiteLabel.primaryColor || "#0040FF"}
                        onChange={(e) => setWhiteLabel({ ...whiteLabel, primaryColor: e.target.value })}
                        className="flex-1"
                      />
                    </div>
                  </div>
                  <div className="space-y-2">
                    <Label>Footer Text</Label>
                    <Input
                      placeholder="Custom footer disclaimer text"
                      value={whiteLabel.footerText || ""}
                      onChange={(e) => setWhiteLabel({ ...whiteLabel, footerText: e.target.value })}
                    />
                  </div>
                  <div className="flex items-center gap-2">
                    <Switch
                      checked={whiteLabel.confidential ?? true}
                      onCheckedChange={(checked) => setWhiteLabel({ ...whiteLabel, confidential: checked })}
                    />
                    <Label>Mark as Confidential</Label>
                  </div>
                </div>
              </div>

              <Separator />

              <div>
                <Label className="text-sm font-medium mb-3 block">Select Report to Generate</Label>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  <Button
                    variant="outline"
                    className="h-auto py-3 flex-col items-start"
                    onClick={() => whiteLabelMutation.mutate("executive_dashboard")}
                    disabled={isAnyLoading || !whiteLabel.companyName}
                  >
                    <div className="flex items-center gap-2 w-full">
                      <BarChart3 className="h-4 w-4 text-blue-500" />
                      <span className="font-medium text-sm">Executive Dashboard</span>
                    </div>
                    <span className="text-xs text-muted-foreground mt-1">Full security posture report</span>
                  </Button>
                  <Button
                    variant="outline"
                    className="h-auto py-3 flex-col items-start"
                    onClick={() => whiteLabelMutation.mutate("board_weekly")}
                    disabled={isAnyLoading || !whiteLabel.companyName}
                  >
                    <div className="flex items-center gap-2 w-full">
                      <Clock className="h-4 w-4 text-amber-500" />
                      <span className="font-medium text-sm">Weekly Board Summary</span>
                    </div>
                    <span className="text-xs text-muted-foreground mt-1">Board-ready weekly report</span>
                  </Button>
                  <Button
                    variant="outline"
                    className="h-auto py-3 flex-col items-start"
                    onClick={() => whiteLabelMutation.mutate("compliance_soc2_readiness")}
                    disabled={isAnyLoading || !whiteLabel.companyName}
                  >
                    <div className="flex items-center gap-2 w-full">
                      <Shield className="h-4 w-4 text-green-500" />
                      <span className="font-medium text-sm">SOC 2 Compliance</span>
                    </div>
                    <span className="text-xs text-muted-foreground mt-1">SOC 2 readiness assessment</span>
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* 77.1 — Report Generation Summary */}
      <Card>
        <CardContent className="p-4">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="text-center">
              <p className="text-2xl font-bold">{reportTypes?.reportTypes?.length ?? 0}</p>
              <p className="text-xs text-muted-foreground">Report Types</p>
            </div>
            <div className="text-center">
              <p className="text-2xl font-bold">{templates.length}</p>
              <p className="text-xs text-muted-foreground">Compliance Templates</p>
            </div>
            <div className="text-center">
              <p className="text-2xl font-bold">5</p>
              <p className="text-xs text-muted-foreground">Export Formats</p>
            </div>
            <div className="text-center">
              <div className="flex items-center justify-center gap-1">
                <CheckCircle2 className="h-4 w-4 text-green-500" />
                <p className="text-sm font-medium">Ready</p>
              </div>
              <p className="text-xs text-muted-foreground">Engine Status</p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* 77.4 — Financial Impact Analysis Summary */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-base flex items-center gap-2">
            <DollarSign className="h-4 w-4" /> Financial Impact Analysis
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="text-center p-3 border rounded-lg">
              <p className="text-xs text-muted-foreground">Methodology</p>
              <p className="text-sm font-bold">FAIR</p>
            </div>
            <div className="text-center p-3 border rounded-lg">
              <p className="text-xs text-muted-foreground">Risk Categories</p>
              <p className="text-sm font-bold">5</p>
            </div>
            <div className="text-center p-3 border rounded-lg">
              <p className="text-xs text-muted-foreground">Avg Breach Cost</p>
              <p className="text-sm font-bold">$4.45M</p>
            </div>
            <div className="text-center p-3 border rounded-lg">
              <p className="text-xs text-muted-foreground">Industry Benchmark</p>
              <p className="text-sm font-bold">IBM 2024</p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* White-label toggle */}
      <Card>
        <CardContent className="p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium">White-Label Mode</p>
              <p className="text-xs text-muted-foreground">Apply custom branding to all report downloads</p>
            </div>
            <Switch checked={whiteLabelEnabled} onCheckedChange={setWhiteLabelEnabled} />
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

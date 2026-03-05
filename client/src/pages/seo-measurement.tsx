import { useState } from "react";
import { usePageTitle } from "@/hooks/use-page-title";
import {
  BarChart3,
  TrendingUp,
  Search,
  Globe,
  ExternalLink,
  Target,
  Eye,
  MousePointerClick,
  MessageSquare,
  ArrowUpRight,
  Bot,
  CheckCircle2,
  Clock,
  AlertTriangle,
  Info,
  Copy,
  Check,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";

interface KpiRow {
  metric: string;
  baseline: string;
  target3m: string;
  target6m: string;
  icon: React.ElementType;
  color: string;
}

const KPI_DATA: KpiRow[] = [
  {
    metric: "Organic Impressions (GSC)",
    baseline: "TBD",
    target3m: "10K/mo",
    target6m: "50K/mo",
    icon: Eye,
    color: "text-cyan-400",
  },
  {
    metric: "Organic Clicks",
    baseline: "TBD",
    target3m: "500/mo",
    target6m: "3K/mo",
    icon: MousePointerClick,
    color: "text-blue-400",
  },
  {
    metric: '"Agentic SOC" Ranking',
    baseline: "Not ranked",
    target3m: "Top 20",
    target6m: "Top 5",
    icon: TrendingUp,
    color: "text-emerald-400",
  },
  {
    metric: '"AI SOC Analyst" Ranking',
    baseline: "Not ranked",
    target3m: "Top 20",
    target6m: "Top 10",
    icon: TrendingUp,
    color: "text-violet-400",
  },
  {
    metric: "LLM Mentions (Manual)",
    baseline: "0",
    target3m: "1+ LLM",
    target6m: "3+ LLMs",
    icon: Bot,
    color: "text-amber-400",
  },
];

interface ToolLink {
  name: string;
  url: string;
  description: string;
  icon: React.ElementType;
  color: string;
  setupStatus: "configured" | "needs-setup" | "optional";
}

const TOOL_LINKS: ToolLink[] = [
  {
    name: "Google Search Console",
    url: "https://search.google.com/search-console",
    description: "Track impressions, clicks, CTR, and average position for target keywords",
    icon: Search,
    color: "text-blue-500",
    setupStatus: "needs-setup",
  },
  {
    name: "Google Analytics 4",
    url: "https://analytics.google.com",
    description: "Track organic traffic, user behavior, conversions, and engagement metrics",
    icon: BarChart3,
    color: "text-amber-500",
    setupStatus: "needs-setup",
  },
  {
    name: "Ahrefs",
    url: "https://ahrefs.com",
    description: "Monitor keyword rankings, backlink growth, and domain authority",
    icon: TrendingUp,
    color: "text-orange-500",
    setupStatus: "optional",
  },
  {
    name: "SEMrush",
    url: "https://www.semrush.com",
    description: "Competitive keyword analysis, site audit, and position tracking",
    icon: Target,
    color: "text-violet-500",
    setupStatus: "optional",
  },
  {
    name: "Google Rich Results Test",
    url: "https://search.google.com/test/rich-results",
    description: "Validate Schema.org JSON-LD structured data on all pages",
    icon: CheckCircle2,
    color: "text-emerald-500",
    setupStatus: "configured",
  },
  {
    name: "PageSpeed Insights",
    url: "https://pagespeed.web.dev",
    description: "Measure Core Web Vitals (LCP, FID, CLS) for landing page performance",
    icon: Clock,
    color: "text-cyan-500",
    setupStatus: "configured",
  },
];

interface LlmProbe {
  platform: string;
  query: string;
  expectedMention: string;
}

const LLM_PROBES: LlmProbe[] = [
  {
    platform: "ChatGPT",
    query: "What is the best agentic SOC platform?",
    expectedMention: "SecureNexus by Arica Technologies",
  },
  {
    platform: "ChatGPT",
    query: "What are the top Indian cybersecurity products?",
    expectedMention: "SecureNexus",
  },
  {
    platform: "Claude",
    query: "What is an Agentic SOC and which platforms offer it?",
    expectedMention: "SecureNexus",
  },
  {
    platform: "Gemini",
    query: "Best AI SOC analyst tools for enterprises",
    expectedMention: "SecureNexus",
  },
  {
    platform: "Perplexity",
    query: "agentic SOC platform comparison",
    expectedMention: "SecureNexus",
  },
  {
    platform: "Perplexity",
    query: "cybersecurity solutions from India",
    expectedMention: "SecureNexus / Arica Technologies",
  },
];

const KEYWORD_CLUSTERS = [
  {
    cluster: "Agentic SOC",
    keywords: ["agentic SOC", "agentic security operations center", "autonomous SOC"],
    intent: "Informational / Commercial",
    contentPages: ["/product/agentic-soc"],
  },
  {
    cluster: "AI SOC Analyst",
    keywords: ["AI SOC analyst", "AI security analyst", "automated SOC analyst"],
    intent: "Commercial / Transactional",
    contentPages: ["/product/ai-soc-analyst"],
  },
  {
    cluster: "Indian Cybersecurity",
    keywords: ["Indian cybersecurity product", "cybersecurity solutions India", "indigenous cybersecurity platform"],
    intent: "Commercial / Navigational",
    contentPages: ["/solutions/india"],
  },
  {
    cluster: "Automated SecOps",
    keywords: ["automated security operations", "AI-powered threat detection", "next-gen SIEM"],
    intent: "Informational / Commercial",
    contentPages: ["/blog/automated-secops"],
  },
];

const IMPLEMENTATION_CHECKLIST = [
  { phase: 1, item: "Schema.org JSON-LD (SoftwareApplication, Organization, WebSite, FAQPage)", done: true },
  { phase: 1, item: "Meta tags optimization (title, description, OG, Twitter Card)", done: true },
  { phase: 1, item: "robots.txt with sitemap reference", done: true },
  { phase: 1, item: "XML sitemap (sitemap.xml)", done: true },
  { phase: 1, item: "Canonical URLs", done: true },
  { phase: 1, item: "Hreflang tags (en, en-IN)", done: true },
  { phase: 1, item: "Dynamic page titles per route", done: true },
  { phase: 2, item: 'Cornerstone: "What is Agentic SOC" page', done: true },
  { phase: 2, item: 'Cornerstone: "AI SOC Analyst" page', done: true },
  { phase: 2, item: 'Cornerstone: "Automated SecOps" guide', done: true },
  { phase: 2, item: "Topic cluster internal linking", done: true },
  { phase: 2, item: "FAQ sections on content pages", done: true },
  { phase: 2, item: "Solutions pages (India, MSSP, Compliance)", done: true },
  { phase: 3, item: "llms.txt file at domain root", done: true },
  { phase: 3, item: "Product comparison page with structured tables", done: true },
  { phase: 3, item: "Speakable schema markup", done: true },
  { phase: 3, item: "About page with product positioning", done: true },
  { phase: 3, item: "GitHub README keyword optimization", done: true },
  { phase: 4, item: "Social share buttons on content pages", done: true },
  { phase: 4, item: "LocalBusiness JSON-LD schema", done: true },
  { phase: 5, item: "Google Analytics 4 integration", done: true },
  { phase: 5, item: "SPA page view tracking hook", done: true },
  { phase: 5, item: "Google Search Console verification meta tag", done: true },
  { phase: 5, item: "SEO Measurement Dashboard (this page)", done: true },
  { phase: 5, item: "KPI targets defined and tracked", done: true },
];

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = () => {
    navigator.clipboard.writeText(text).then(
      () => {
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      },
      () => {},
    );
  };
  return (
    <Button variant="ghost" size="icon" className="h-6 w-6" onClick={handleCopy} aria-label="Copy to clipboard">
      {copied ? <Check className="h-3 w-3 text-green-500" /> : <Copy className="h-3 w-3" />}
    </Button>
  );
}

function KpiTargetCards() {
  return (
    <div className="space-y-3">
      <div className="grid grid-cols-5 gap-2 px-3 text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
        <span className="col-span-2">Metric</span>
        <span>Baseline</span>
        <span>3-Month Target</span>
        <span>6-Month Target</span>
      </div>
      {KPI_DATA.map((kpi) => {
        const Icon = kpi.icon;
        return (
          <div
            key={kpi.metric}
            className="grid grid-cols-5 gap-2 items-center p-3 rounded-lg border bg-card hover:bg-muted/30 transition-colors"
          >
            <div className="col-span-2 flex items-center gap-2">
              <Icon className={`h-4 w-4 ${kpi.color} shrink-0`} />
              <span className="text-xs font-medium">{kpi.metric}</span>
            </div>
            <Badge variant="outline" className="text-[10px] w-fit">
              {kpi.baseline}
            </Badge>
            <Badge variant="secondary" className="text-[10px] w-fit">
              {kpi.target3m}
            </Badge>
            <Badge className="text-[10px] w-fit bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
              {kpi.target6m}
            </Badge>
          </div>
        );
      })}
    </div>
  );
}

function ToolsGrid() {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
      {TOOL_LINKS.map((tool) => {
        const Icon = tool.icon;
        return (
          <a
            key={tool.name}
            href={tool.url}
            target="_blank"
            rel="noopener noreferrer"
            className="group flex items-start gap-3 p-4 rounded-lg border bg-card hover:bg-muted/30 hover:border-cyan-500/30 transition-all"
          >
            <div className="flex items-center justify-center w-9 h-9 rounded-lg bg-muted/50 shrink-0">
              <Icon className={`h-4.5 w-4.5 ${tool.color}`} />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-1">
                <span className="text-sm font-semibold">{tool.name}</span>
                <ExternalLink className="h-3 w-3 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity" />
                {tool.setupStatus === "configured" && (
                  <Badge variant="outline" className="text-[9px] text-emerald-400 border-emerald-500/30">
                    Ready
                  </Badge>
                )}
                {tool.setupStatus === "needs-setup" && (
                  <Badge variant="outline" className="text-[9px] text-amber-400 border-amber-500/30">
                    Setup Required
                  </Badge>
                )}
                {tool.setupStatus === "optional" && (
                  <Badge variant="outline" className="text-[9px] text-muted-foreground">
                    Optional
                  </Badge>
                )}
              </div>
              <p className="text-[11px] text-muted-foreground leading-snug">{tool.description}</p>
            </div>
          </a>
        );
      })}
    </div>
  );
}

function LlmVisibilityChecklist() {
  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2 mb-3">
        <Info className="h-4 w-4 text-muted-foreground" />
        <p className="text-xs text-muted-foreground">
          Manually query these prompts periodically to track LLM visibility. Copy each query and test on the respective
          platform.
        </p>
      </div>
      <ScrollArea className="h-[380px]">
        <div className="space-y-2">
          {LLM_PROBES.map((probe, i) => (
            <div key={i} className="flex items-start gap-3 p-3 rounded-lg border bg-card">
              <Badge
                variant="outline"
                className={`text-[10px] shrink-0 mt-0.5 ${
                  probe.platform === "ChatGPT"
                    ? "text-emerald-400 border-emerald-500/30"
                    : probe.platform === "Claude"
                      ? "text-orange-400 border-orange-500/30"
                      : probe.platform === "Gemini"
                        ? "text-blue-400 border-blue-500/30"
                        : "text-violet-400 border-violet-500/30"
                }`}
              >
                {probe.platform}
              </Badge>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-1.5">
                  <p className="text-xs font-medium">&ldquo;{probe.query}&rdquo;</p>
                  <CopyButton text={probe.query} />
                </div>
                <p className="text-[10px] text-muted-foreground mt-1">
                  Expected: <span className="font-medium text-foreground/70">{probe.expectedMention}</span>
                </p>
              </div>
            </div>
          ))}
        </div>
      </ScrollArea>
    </div>
  );
}

function KeywordTracker() {
  return (
    <div className="space-y-3">
      {KEYWORD_CLUSTERS.map((cluster) => (
        <div key={cluster.cluster} className="p-4 rounded-lg border bg-card">
          <div className="flex items-center justify-between mb-2">
            <h4 className="text-sm font-semibold">{cluster.cluster}</h4>
            <Badge variant="outline" className="text-[9px]">
              {cluster.intent}
            </Badge>
          </div>
          <div className="flex flex-wrap gap-1.5 mb-2">
            {cluster.keywords.map((kw) => (
              <Badge key={kw} variant="secondary" className="text-[10px] font-mono">
                {kw}
              </Badge>
            ))}
          </div>
          <div className="flex items-center gap-1.5 text-[10px] text-muted-foreground">
            <Globe className="h-3 w-3" />
            Content:{" "}
            {cluster.contentPages.map((p, i) => (
              <span key={p}>
                {i > 0 && ", "}
                <a href={p} className="text-cyan-400 hover:underline">
                  {p}
                </a>
              </span>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

function ImplementationProgress() {
  const phases = [1, 2, 3, 4, 5];
  return (
    <div className="space-y-4">
      {phases.map((phase) => {
        const items = IMPLEMENTATION_CHECKLIST.filter((c) => c.phase === phase);
        const completed = items.filter((c) => c.done).length;
        const total = items.length;
        const pct = total > 0 ? Math.round((completed / total) * 100) : 0;
        return (
          <div key={phase} className="p-4 rounded-lg border bg-card">
            <div className="flex items-center justify-between mb-3">
              <h4 className="text-sm font-semibold">Phase {phase}</h4>
              <div className="flex items-center gap-2">
                <span className="text-[10px] text-muted-foreground">
                  {completed}/{total}
                </span>
                <Badge
                  variant="outline"
                  className={`text-[10px] ${pct === 100 ? "text-emerald-400 border-emerald-500/30" : "text-amber-400 border-amber-500/30"}`}
                >
                  {pct}%
                </Badge>
              </div>
            </div>
            <div className="w-full h-1.5 rounded-full bg-muted mb-3">
              <div
                className={`h-full rounded-full transition-all ${pct === 100 ? "bg-emerald-500" : "bg-cyan-500"}`}
                style={{ width: `${pct}%` }}
              />
            </div>
            <div className="space-y-1.5">
              {items.map((item) => (
                <div key={item.item} className="flex items-center gap-2 text-xs">
                  {item.done ? (
                    <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500 shrink-0" />
                  ) : (
                    <AlertTriangle className="h-3.5 w-3.5 text-amber-400 shrink-0" />
                  )}
                  <span className={item.done ? "text-muted-foreground" : "font-medium"}>{item.item}</span>
                </div>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}

export default function SeoMeasurementPage() {
  usePageTitle("SEO Measurement — SecureNexus");

  return (
    <div className="p-4 md:p-6 space-y-6 max-w-[1400px] mx-auto" data-testid="page-seo-measurement">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight" data-testid="text-seo-title">
            SEO Measurement & Iteration
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Track keyword rankings, organic traffic, and LLM discoverability metrics
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Tooltip>
            <TooltipTrigger asChild>
              <a
                href="https://search.google.com/search-console"
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex"
              >
                <Button variant="outline" size="sm" className="gap-1.5 text-xs">
                  <Search className="h-3.5 w-3.5" />
                  Search Console
                  <ArrowUpRight className="h-3 w-3" />
                </Button>
              </a>
            </TooltipTrigger>
            <TooltipContent>Open Google Search Console</TooltipContent>
          </Tooltip>
          <Tooltip>
            <TooltipTrigger asChild>
              <a href="https://analytics.google.com" target="_blank" rel="noopener noreferrer" className="inline-flex">
                <Button variant="outline" size="sm" className="gap-1.5 text-xs">
                  <BarChart3 className="h-3.5 w-3.5" />
                  GA4
                  <ArrowUpRight className="h-3 w-3" />
                </Button>
              </a>
            </TooltipTrigger>
            <TooltipContent>Open Google Analytics 4</TooltipContent>
          </Tooltip>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {KPI_DATA.map((kpi) => {
          const Icon = kpi.icon;
          return (
            <Card key={kpi.metric}>
              <CardContent className="pt-4 pb-3 px-4">
                <div className="flex items-center gap-2 mb-2">
                  <Icon className={`h-4 w-4 ${kpi.color}`} />
                  <span className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground truncate">
                    {kpi.metric.replace(/"/g, "")}
                  </span>
                </div>
                <p className="text-lg font-bold tabular-nums">{kpi.baseline}</p>
                <p className="text-[10px] text-muted-foreground mt-1">Target: {kpi.target6m} (6mo)</p>
              </CardContent>
            </Card>
          );
        })}
      </div>

      <Tabs defaultValue="kpis" className="space-y-4">
        <TabsList>
          <TabsTrigger value="kpis" className="text-xs">
            <Target className="h-3.5 w-3.5 mr-1.5" />
            KPI Targets
          </TabsTrigger>
          <TabsTrigger value="tools" className="text-xs">
            <Globe className="h-3.5 w-3.5 mr-1.5" />
            Tools
          </TabsTrigger>
          <TabsTrigger value="keywords" className="text-xs">
            <Search className="h-3.5 w-3.5 mr-1.5" />
            Keywords
          </TabsTrigger>
          <TabsTrigger value="llm" className="text-xs">
            <Bot className="h-3.5 w-3.5 mr-1.5" />
            LLM Visibility
          </TabsTrigger>
          <TabsTrigger value="progress" className="text-xs">
            <CheckCircle2 className="h-3.5 w-3.5 mr-1.5" />
            Progress
          </TabsTrigger>
        </TabsList>

        <TabsContent value="kpis">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm flex items-center gap-2">
                <Target className="h-4 w-4 text-cyan-400" />
                SEO KPI Targets
              </CardTitle>
              <CardDescription className="text-xs">
                Baseline measurements and growth targets for organic search performance
              </CardDescription>
            </CardHeader>
            <CardContent>
              <KpiTargetCards />
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="tools">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm flex items-center gap-2">
                <Globe className="h-4 w-4 text-cyan-400" />
                Measurement Tools
              </CardTitle>
              <CardDescription className="text-xs">
                External tools for tracking SEO performance. Click to open each tool.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ToolsGrid />
              <div className="mt-4 p-3 rounded-lg bg-muted/30 border border-dashed">
                <h4 className="text-xs font-semibold mb-1.5 flex items-center gap-1.5">
                  <Info className="h-3.5 w-3.5 text-muted-foreground" />
                  Setup Instructions
                </h4>
                <ol className="text-[11px] text-muted-foreground space-y-1.5 list-decimal list-inside">
                  <li>
                    <strong>Google Search Console</strong>: Verify ownership of{" "}
                    <code className="text-[10px] bg-muted px-1 rounded">nexus.aricatech.xyz</code>, then set{" "}
                    <code className="text-[10px] bg-muted px-1 rounded">VITE_GSC_VERIFICATION_TOKEN</code> env var with
                    your verification token — the meta tag is injected dynamically at runtime
                  </li>
                  <li>
                    <strong>Google Analytics 4</strong>: Create a GA4 property, copy the Measurement ID (G-XXXXXXX), and
                    set <code className="text-[10px] bg-muted px-1 rounded">VITE_GA4_MEASUREMENT_ID</code> env var — the
                    gtag script is loaded dynamically only when this var is present
                  </li>
                  <li>
                    <strong>Ahrefs / SEMrush</strong>: Optional paid tools for competitive analysis — set up keyword
                    tracking for the target clusters listed in the Keywords tab
                  </li>
                </ol>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="keywords">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm flex items-center gap-2">
                <Search className="h-4 w-4 text-cyan-400" />
                Target Keyword Clusters
              </CardTitle>
              <CardDescription className="text-xs">
                Primary keyword groups mapped to content pages for ranking optimization
              </CardDescription>
            </CardHeader>
            <CardContent>
              <KeywordTracker />
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="llm">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm flex items-center gap-2">
                <Bot className="h-4 w-4 text-cyan-400" />
                LLM Visibility Checks
              </CardTitle>
              <CardDescription className="text-xs">
                Test these prompts on each LLM platform to track if SecureNexus is being cited in responses
              </CardDescription>
            </CardHeader>
            <CardContent>
              <LlmVisibilityChecklist />
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="progress">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm flex items-center gap-2">
                <CheckCircle2 className="h-4 w-4 text-cyan-400" />
                SEO Implementation Progress
              </CardTitle>
              <CardDescription className="text-xs">
                Tracking all 5 phases of the SEO & LLM discoverability strategy
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ImplementationProgress />
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      <Card className="border-dashed">
        <CardContent className="pt-4 pb-4 px-4">
          <div className="flex items-start gap-3">
            <MessageSquare className="h-5 w-5 text-muted-foreground mt-0.5 shrink-0" />
            <div>
              <h4 className="text-sm font-semibold mb-1">Measurement Cadence</h4>
              <div className="text-xs text-muted-foreground space-y-1">
                <p>
                  <strong>Weekly</strong>: Check Google Search Console for impressions/clicks on target keywords
                </p>
                <p>
                  <strong>Bi-weekly</strong>: Query LLM platforms with the prompts above, record results
                </p>
                <p>
                  <strong>Monthly</strong>: Review GA4 organic traffic trends, backlink growth (Ahrefs), and keyword
                  position changes
                </p>
                <p>
                  <strong>Quarterly</strong>: Full SEO audit — technical issues, content gaps, competitor analysis
                </p>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

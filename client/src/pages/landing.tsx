import { useState, useRef } from "react";
import {
  Zap, Brain, Eye, ArrowRight, Lock, Activity,
  Layers, Shield, ShieldCheck, Radar, Cloud, Search,
  AlertTriangle, Database, Clock, TrendingDown, Users,
  CheckCircle2, ChevronDown, ChevronUp, ArrowDown,
  Timer, BarChart3, Workflow, Target, Lightbulb,
} from "lucide-react";
import { FaGoogle, FaGithub } from "react-icons/fa";
import {
  SiSplunk, SiPaloaltosoftware, SiAmazon,
  SiElastic, SiFortinet,
  SiCisco, SiOkta, SiTrendmicro,
} from "react-icons/si";
import atsLogo from "@/assets/logo.jpg";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useAuth } from "@/hooks/use-auth";

const painPoints = [
  {
    stat: "4,000+",
    label: "alerts/day",
    description: "The average SOC drowns in thousands of alerts daily, most of them noise.",
    icon: AlertTriangle,
  },
  {
    stat: "45 min",
    label: "per triage",
    description: "Analysts spend 45 minutes manually triaging each alert across disconnected tools.",
    icon: Timer,
  },
  {
    stat: "70%",
    label: "false positives",
    description: "Most alerts are false positives, burning analyst hours that should go to real threats.",
    icon: Target,
  },
  {
    stat: "3.5x",
    label: "tool sprawl",
    description: "Security teams juggle 3-5 tools per investigation, losing context at every handoff.",
    icon: Layers,
  },
];

const howItWorks = [
  {
    step: "01",
    title: "Connect your tools",
    description: "Plug in your EDR, SIEM, and cloud security tools via read-only API keys. No agents, no infrastructure changes. Under 30 minutes.",
    icon: Workflow,
  },
  {
    step: "02",
    title: "AI correlates everything",
    description: "Our engine clusters alerts by attacker behavior, maps to MITRE ATT&CK, and scores each threat. What took your team hours happens in seconds.",
    icon: Brain,
  },
  {
    step: "03",
    title: "Respond with confidence",
    description: "Get actionable incident narratives, automated playbooks, and one-click response actions. Your analysts focus on decisions, not data wrangling.",
    icon: Zap,
  },
];

const features = [
  {
    icon: Brain,
    title: "Cut triage time by 90%",
    description: "AI clusters alerts by attacker behavior and generates incident narratives automatically. What took 45 minutes now takes under 5.",
    gradient: "from-cyan-500/20 to-blue-500/20",
    iconColor: "text-cyan-400",
  },
  {
    icon: Eye,
    title: "See the full attack story",
    description: "Map campaigns to MITRE ATT&CK techniques with confidence scores. Stop chasing individual alerts and start tracking adversaries.",
    gradient: "from-violet-500/20 to-indigo-500/20",
    iconColor: "text-violet-400",
  },
  {
    icon: TrendingDown,
    title: "Eliminate 70% of false positives",
    description: "Behavioral correlation separates real threats from noise. Your team stops wasting hours on alerts that don\'t matter.",
    gradient: "from-blue-500/20 to-cyan-500/20",
    iconColor: "text-blue-400",
  },
  {
    icon: Lock,
    title: "Deploy without disruption",
    description: "Read-only API connectors to your existing stack. No rip-and-replace, no new agents, no infrastructure changes. Live in 30 minutes.",
    gradient: "from-emerald-500/20 to-cyan-500/20",
    iconColor: "text-emerald-400",
  },
  {
    icon: BarChart3,
    title: "Prove compliance in minutes",
    description: "Automated evidence collection for SOC 2, ISO 27001, NIST CSF, and GDPR. Generate audit-ready reports instead of building them manually.",
    gradient: "from-purple-500/20 to-violet-500/20",
    iconColor: "text-purple-400",
  },
  {
    icon: Lightbulb,
    title: "Make every analyst a senior",
    description: "AI-generated investigation guides and response playbooks give junior analysts the decision-making capability of a 10-year veteran.",
    gradient: "from-indigo-500/20 to-blue-500/20",
    iconColor: "text-indigo-400",
  },
];

const metrics = [
  { value: "90%", label: "Faster triage", icon: Clock },
  { value: "70%", label: "Fewer false positives", icon: TrendingDown },
  { value: "35%", label: "Lower MTTR", icon: Activity },
  { value: "50+", label: "SOC teams onboarded", icon: Users },
];

const testimonials = [
  {
    quote: "SecureNexus cut our alert triage time from 45 minutes to under 5. The AI correlation is genuinely useful, not just a buzzword.",
    name: "Sarah Chen",
    role: "SOC Lead",
    company: "Series B Fintech",
  },
  {
    quote: "We replaced three separate tools with SecureNexus. The attacker-centric view changed how our team thinks about incidents.",
    name: "Marcus Rivera",
    role: "CISO",
    company: "Healthcare SaaS",
  },
  {
    quote: "The MITRE ATT&CK mapping and automated narratives save my analysts 2+ hours per incident. ROI was obvious in week one.",
    name: "David Kim",
    role: "Director of Security",
    company: "E-commerce Platform",
  },
];

const faqs = [
  {
    q: "How long does it take to deploy?",
    a: "Under 30 minutes. Connect your existing EDR/SIEM via read-only API keys, and SecureNexus starts correlating alerts immediately. No agents to install, no infrastructure changes required.",
  },
  {
    q: "Does this replace our SIEM?",
    a: "No. SecureNexus sits on top of your existing stack (Splunk, Elastic, QRadar, etc.) and adds AI-powered correlation and attacker-centric analysis. It enhances your SIEM, not replaces it.",
  },
  {
    q: "How does the AI correlation work?",
    a: "Our engine clusters alerts by attacker behavior patterns, not just static rules. It maps to MITRE ATT&CK techniques, assigns confidence scores, and generates incident narratives that mimic how a senior analyst would connect the dots.",
  },
  {
    q: "What compliance frameworks do you support?",
    a: "SOC 2 Type II, ISO 27001, NIST CSF, and GDPR. We provide automated evidence collection, control mapping, and audit-ready reports.",
  },
  {
    q: "Can I try it before committing?",
    a: "Yes. Start with a 14-day free trial \u2014 no credit card required. You get full access to all features including AI correlation, integrations, and reporting.",
  },
];

const integrations = [
  { name: "CrowdStrike", icon: Shield },
  { name: "Splunk", icon: SiSplunk },
  { name: "Palo Alto", icon: SiPaloaltosoftware },
  { name: "AWS GuardDuty", icon: SiAmazon },
  { name: "Microsoft Defender", icon: ShieldCheck },
  { name: "SentinelOne", icon: Radar },
  { name: "Wiz", icon: Cloud },
  { name: "Wazuh", icon: Eye },
  { name: "Elastic Security", icon: SiElastic },
  { name: "IBM QRadar", icon: Database },
  { name: "Fortinet FortiGate", icon: SiFortinet },
  { name: "Carbon Black", icon: Shield },
  { name: "Qualys", icon: Search },
  { name: "Tenable Nessus", icon: Search },
  { name: "Cisco Umbrella", icon: SiCisco },
  { name: "Darktrace", icon: Eye },
  { name: "Rapid7 InsightIDR", icon: Radar },
  { name: "Trend Micro", icon: SiTrendmicro },
  { name: "Okta", icon: SiOkta },
  { name: "Proofpoint", icon: Shield },
  { name: "Snort IDS", icon: AlertTriangle },
  { name: "Zscaler", icon: Cloud },
  { name: "Check Point", icon: ShieldCheck },
  { name: "Suricata", icon: AlertTriangle },
];

export default function LandingPage() {
  const { login, register, loginError, registerError, isLoggingIn, isRegistering } = useAuth();
  const [authMode, setAuthMode] = useState<"login" | "register" | null>(null);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [firstName, setFirstName] = useState("");
  const [lastName, setLastName] = useState("");
  const [oauthError, setOauthError] = useState<string | null>(null);
  const [oauthLoading, setOauthLoading] = useState<string | null>(null);
  const howItWorksRef = useRef<HTMLElement>(null);

  const handleOAuth = async (provider: "google" | "github") => {
    setOauthError(null);
    setOauthLoading(provider);
    try {
      const res = await fetch(`/api/auth/${provider}`, { redirect: "manual" });
      if (res.type === "opaqueredirect" || res.status === 302 || res.status === 301) {
        window.location.href = `/api/auth/${provider}`;
        return;
      }
      if (res.status === 501) {
        setOauthError(`${provider === "google" ? "Google" : "GitHub"} login is not configured yet. Please use email login.`);
      } else {
        window.location.href = `/api/auth/${provider}`;
      }
    } catch {
      window.location.href = `/api/auth/${provider}`;
    } finally {
      setOauthLoading(null);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (authMode === "register") {
      await register({ email, password, firstName, lastName });
    } else {
      await login({ email, password });
    }
  };

  const scrollToHowItWorks = () => {
    howItWorksRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  const authError = authMode === "register" ? registerError : loginError;
  const isSubmitting = authMode === "register" ? isRegistering : isLoggingIn;

  return (
    <div className="min-h-screen bg-background">
      {authMode && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center bg-background/80 backdrop-blur-sm" onClick={() => setAuthMode(null)}>
          <Card className="w-full max-w-md mx-4 shadow-2xl border-border/50" onClick={(e) => e.stopPropagation()}>
            <CardContent className="p-8">
              <div className="flex items-center gap-2.5 mb-6">
                <img src={atsLogo} alt="SecureNexus" className="w-8 h-8 object-contain" />
                <span className="font-semibold text-lg">SecureNexus</span>
              </div>
              <h2 className="text-xl font-bold mb-1">{authMode === "register" ? "Start your free trial" : "Welcome back"}</h2>
              <p className="text-sm text-muted-foreground mb-6">{authMode === "register" ? "14 days free. No credit card required." : "Log in to your account"}</p>
              {authError && (
                <div className="mb-4 p-3 rounded-md bg-destructive/10 text-destructive text-sm">
                  {authError.message}
                </div>
              )}
              <div className="space-y-2 mb-4">
                {oauthError && (
                  <div className="mb-2 p-2.5 rounded-md bg-amber-500/10 text-amber-500 text-xs">
                    {oauthError}
                  </div>
                )}
                <Button
                  variant="outline"
                  className="w-full h-10 gap-2 text-sm font-medium hover:bg-muted/50 transition-all"
                  disabled={oauthLoading === "google"}
                  onClick={() => handleOAuth("google")}
                >
                  <FaGoogle className="h-4 w-4 text-[#4285F4]" />
                  {oauthLoading === "google" ? "Connecting..." : "Continue with Google"}
                </Button>
                <Button
                  variant="outline"
                  className="w-full h-10 gap-2 text-sm font-medium hover:bg-muted/50 transition-all"
                  disabled={oauthLoading === "github"}
                  onClick={() => handleOAuth("github")}
                >
                  <FaGithub className="h-4 w-4" />
                  {oauthLoading === "github" ? "Connecting..." : "Continue with GitHub"}
                </Button>
                <div className="relative my-3">
                  <div className="absolute inset-0 flex items-center"><div className="w-full border-t border-border" /></div>
                  <div className="relative flex justify-center text-xs"><span className="bg-card px-2 text-muted-foreground">or continue with email</span></div>
                </div>
              </div>
              <form onSubmit={handleSubmit} className="space-y-4">
                {authMode === "register" && (
                  <div className="grid grid-cols-2 gap-3">
                    <div className="space-y-1.5">
                      <Label htmlFor="firstName">First name</Label>
                      <Input id="firstName" value={firstName} onChange={(e) => setFirstName(e.target.value)} placeholder="John" />
                    </div>
                    <div className="space-y-1.5">
                      <Label htmlFor="lastName">Last name</Label>
                      <Input id="lastName" value={lastName} onChange={(e) => setLastName(e.target.value)} placeholder="Doe" />
                    </div>
                  </div>
                )}
                <div className="space-y-1.5">
                  <Label htmlFor="email">Email</Label>
                  <Input id="email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@company.com" required />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="password">Password</Label>
                  <Input id="password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Min 6 characters" required minLength={6} />
                </div>
                <Button type="submit" className="w-full" disabled={isSubmitting}>
                  {isSubmitting ? "Please wait..." : authMode === "register" ? "Start Free Trial" : "Log In"}
                </Button>
              </form>
              <p className="text-sm text-center text-muted-foreground mt-4">
                {authMode === "register" ? (
                  <>Already have an account? <button onClick={() => setAuthMode("login")} className="text-primary underline-offset-4 hover:underline">Log in</button></>
                ) : (
                  <>Don&apos;t have an account? <button onClick={() => setAuthMode("register")} className="text-primary underline-offset-4 hover:underline">Sign up</button></>
                )}
              </p>
            </CardContent>
          </Card>
        </div>
      )}

      <nav className="fixed top-0 left-0 right-0 z-50 border-b border-border/30 glass-strong">
        <div className="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between gap-4">
          <div className="flex items-center gap-2.5">
            <img src={atsLogo} alt="SecureNexus" className="w-9 h-9 object-contain" />
            <span className="font-semibold text-lg tracking-tight">SecureNexus</span>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={() => setAuthMode("login")}
              className="text-sm text-muted-foreground hover:text-foreground transition-colors"
            >
              Log in
            </button>
            <Button size="sm" onClick={() => setAuthMode("register")}>
              Start Free Trial
            </Button>
          </div>
        </div>
      </nav>

      <section className="relative pt-36 pb-20 px-6 overflow-hidden">
        <div className="absolute inset-0 overflow-hidden pointer-events-none">
          <div className="absolute top-20 left-1/4 w-[500px] h-[500px] bg-primary/8 dark:bg-primary/12 rounded-full blur-[120px]" />
          <div className="absolute top-40 right-1/4 w-[400px] h-[400px] bg-primary/6 dark:bg-primary/10 rounded-full blur-[100px]" />
        </div>

        <div className="max-w-4xl mx-auto text-center relative z-10">
          <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full gradient-badge text-xs font-medium mb-8 tracking-wide animate-fade-in glow-cyan-subtle">
            <div className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse" />
            AI-Powered Security Operations
          </div>
          <h1 className="text-4xl md:text-5xl lg:text-6xl font-bold tracking-tight mb-6 leading-[1.1] animate-fade-in-up">
            Stop chasing alerts.
            <br />
            <span className="gradient-text-hero">Start stopping attackers.</span>
          </h1>
          <p className="text-base md:text-lg text-muted-foreground max-w-2xl mx-auto mb-10 leading-relaxed animate-fade-in-up">
            SecureNexus uses AI to correlate thousands of alerts into actionable incidents, cutting triage time by 90% and false positives by 70%.
          </p>
          <div className="flex flex-col items-center gap-4 animate-fade-in-up">
            <Button size="lg" onClick={() => setAuthMode("register")} className="px-10 h-12 text-base">
              Start Free Trial &mdash; No Credit Card
              <ArrowRight className="ml-2 h-4 w-4" />
            </Button>
            <button
              onClick={scrollToHowItWorks}
              className="flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground transition-colors"
            >
              See how it works
              <ArrowDown className="h-3.5 w-3.5" />
            </button>
          </div>
        </div>
      </section>

      <section className="py-12 px-6 border-t border-border/30">
        <div className="max-w-4xl mx-auto">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {metrics.map((metric) => (
              <div key={metric.label} className="flex flex-col items-center gap-1 p-5 rounded-lg gradient-card">
                <metric.icon className="h-4 w-4 text-muted-foreground mb-1" />
                <span className="text-2xl md:text-3xl font-bold tracking-tight">{metric.value}</span>
                <span className="text-xs text-muted-foreground">{metric.label}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="py-20 px-6 border-t border-border/30">
        <div className="max-w-5xl mx-auto">
          <div className="text-center mb-14">
            <p className="text-xs uppercase tracking-widest text-cyan-400 mb-3 font-medium">The problem</p>
            <h2 className="text-2xl md:text-3xl font-bold mb-3">Your SOC is drowning in noise</h2>
            <p className="text-muted-foreground max-w-xl mx-auto text-sm">
              Security teams spend more time managing tools than stopping threats. The result: burnout, missed attacks, and wasted budget.
            </p>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {painPoints.map((point) => (
              <Card key={point.label} className="gradient-card border-border/30">
                <CardContent className="p-6 text-center">
                  <point.icon className="h-6 w-6 text-cyan-400/70 mx-auto mb-3" />
                  <div className="text-3xl font-bold tracking-tight mb-0.5">{point.stat}</div>
                  <div className="text-xs font-medium text-primary mb-2">{point.label}</div>
                  <p className="text-xs text-muted-foreground leading-relaxed">{point.description}</p>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      </section>

      <section ref={howItWorksRef} className="py-20 px-6 border-t border-border/30">
        <div className="max-w-4xl mx-auto">
          <div className="text-center mb-14">
            <p className="text-xs uppercase tracking-widest text-primary mb-3 font-medium">How it works</p>
            <h2 className="text-2xl md:text-3xl font-bold mb-3">Three steps to a quieter SOC</h2>
            <p className="text-muted-foreground max-w-xl mx-auto text-sm">
              Go from alert overload to clear, actionable intelligence in under 30 minutes.
            </p>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {howItWorks.map((step) => (
              <div key={step.step} className="relative">
                <div className="gradient-card rounded-lg p-6">
                  <div className="flex items-center gap-3 mb-4">
                    <span className="text-3xl font-bold text-primary/20">{step.step}</span>
                    <div className="w-10 h-10 rounded-md bg-gradient-to-br from-primary/10 to-primary/5 flex items-center justify-center">
                      <step.icon className="h-5 w-5 text-primary" />
                    </div>
                  </div>
                  <h3 className="font-semibold mb-2">{step.title}</h3>
                  <p className="text-sm text-muted-foreground leading-relaxed">{step.description}</p>
                </div>
              </div>
            ))}
          </div>
          <div className="text-center mt-10">
            <Button size="lg" onClick={() => setAuthMode("register")} className="px-8">
              Start Free Trial
              <ArrowRight className="ml-2 h-4 w-4" />
            </Button>
          </div>
        </div>
      </section>

      <section className="py-16 border-t border-border/30 overflow-hidden">
        <div className="text-center mb-10 px-6">
          <p className="text-xs uppercase tracking-widest text-muted-foreground mb-3 font-medium">Integrations</p>
          <h2 className="text-xl md:text-2xl font-bold mb-2">Works with your existing stack</h2>
          <p className="text-sm text-muted-foreground">24+ connectors. Read-only. No agents required.</p>
        </div>
        <div className="relative">
          <div className="absolute left-0 top-0 bottom-0 w-24 bg-gradient-to-r from-background to-transparent z-10 pointer-events-none" />
          <div className="absolute right-0 top-0 bottom-0 w-24 bg-gradient-to-l from-background to-transparent z-10 pointer-events-none" />
          <div className="flex animate-marquee gap-6">
            {[...integrations, ...integrations].map((item, i) => (
              <div
                key={`${item.name}-${i}`}
                className="flex items-center gap-3 px-5 py-3 rounded-md gradient-card flex-shrink-0"
              >
                <item.icon className="h-5 w-5 text-muted-foreground flex-shrink-0" />
                <span className="text-sm font-medium text-muted-foreground whitespace-nowrap">{item.name}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="py-20 px-6 border-t border-border/30">
        <div className="max-w-5xl mx-auto">
          <div className="text-center mb-14">
            <p className="text-xs uppercase tracking-widest text-primary mb-3 font-medium">Capabilities</p>
            <h2 className="text-2xl md:text-3xl font-bold mb-3">Outcomes, not features</h2>
            <p className="text-muted-foreground max-w-xl mx-auto text-sm">
              Every capability is built to deliver a measurable result for your security team.
            </p>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {features.map((feature, index) => (
              <Card key={index} className="gradient-card group">
                <CardContent className="p-6">
                  <div className={`inline-flex items-center justify-center w-10 h-10 rounded-md bg-gradient-to-br ${feature.gradient} mb-4`}>
                    <feature.icon className={`h-5 w-5 ${feature.iconColor}`} />
                  </div>
                  <h3 className="font-semibold mb-2">{feature.title}</h3>
                  <p className="text-sm text-muted-foreground leading-relaxed">{feature.description}</p>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      </section>

      <section className="py-20 px-6 border-t border-border/30">
        <div className="max-w-5xl mx-auto">
          <div className="text-center mb-14">
            <p className="text-xs uppercase tracking-widest text-primary mb-3 font-medium">Results</p>
            <h2 className="text-2xl md:text-3xl font-bold mb-3">Trusted by security teams worldwide</h2>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {testimonials.map((t, i) => (
              <Card key={i} className="gradient-card">
                <CardContent className="p-6 flex flex-col h-full">
                  <p className="text-sm text-muted-foreground leading-relaxed flex-1 mb-4">&ldquo;{t.quote}&rdquo;</p>
                  <div className="flex items-center gap-3 pt-4 border-t border-border/30">
                    <div className="w-9 h-9 rounded-full bg-gradient-to-br from-cyan-500/20 to-blue-500/20 flex items-center justify-center text-sm font-semibold text-cyan-400">
                      {t.name.split(" ").map(n => n[0]).join("")}
                    </div>
                    <div>
                      <p className="text-sm font-medium">{t.name}</p>
                      <p className="text-xs text-muted-foreground">{t.role}, {t.company}</p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      </section>

      <section className="py-20 px-6 border-t border-border/30">
        <div className="max-w-3xl mx-auto">
          <div className="text-center mb-10">
            <p className="text-xs uppercase tracking-widest text-primary mb-3 font-medium">FAQ</p>
            <h2 className="text-2xl md:text-3xl font-bold mb-3">Common questions</h2>
          </div>
          <div className="space-y-2">
            {faqs.map((faq, i) => (
              <FaqItem key={i} question={faq.q} answer={faq.a} />
            ))}
          </div>
        </div>
      </section>

      <section className="py-20 px-6 border-t border-border/30">
        <div className="max-w-3xl mx-auto text-center relative">
          <div className="absolute inset-0 -z-10 overflow-hidden pointer-events-none">
            <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[400px] h-[200px] bg-cyan-500/8 dark:bg-cyan-500/12 rounded-full blur-[80px]" />
          </div>
          <h2 className="text-2xl md:text-3xl font-bold mb-4">Ready to transform your SOC?</h2>
          <p className="text-muted-foreground mb-8 text-sm max-w-lg mx-auto">
            Join 50+ security teams that cut triage time by 90% and false positives by 70%. See results in your first week.
          </p>
          <Button size="lg" onClick={() => setAuthMode("register")} className="px-10 h-12 text-base">
            Start Free Trial &mdash; No Credit Card
            <ArrowRight className="ml-2 h-4 w-4" />
          </Button>
          <div className="flex flex-wrap items-center justify-center gap-6 mt-6 text-xs text-muted-foreground">
            <span className="flex items-center gap-1"><CheckCircle2 className="h-3 w-3 text-emerald-500" />14-day free trial</span>
            <span className="w-1 h-1 rounded-full bg-muted-foreground/30 hidden sm:block" />
            <span className="flex items-center gap-1"><CheckCircle2 className="h-3 w-3 text-emerald-500" />No credit card required</span>
            <span className="w-1 h-1 rounded-full bg-muted-foreground/30 hidden sm:block" />
            <span className="flex items-center gap-1"><CheckCircle2 className="h-3 w-3 text-emerald-500" />SOC 2 compliant</span>
            <span className="w-1 h-1 rounded-full bg-muted-foreground/30 hidden sm:block" />
            <span className="flex items-center gap-1"><Clock className="h-3 w-3 text-emerald-500" />Live in 30 minutes</span>
          </div>
        </div>
      </section>

      <footer className="border-t py-10 px-6 relative">
        <div className="gradient-accent-line absolute top-0 left-0 right-0" />
        <div className="max-w-6xl mx-auto">
          <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
            <div className="flex items-center gap-2.5">
              <img src={atsLogo} alt="SecureNexus" className="w-7 h-7 object-contain" />
              <div>
                <span className="font-semibold text-sm">SecureNexus</span>
                <p className="text-xs text-muted-foreground">AI-Powered Security Operations</p>
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-6 text-xs text-muted-foreground">
              <span className="flex items-center gap-1"><Shield className="h-3 w-3" /> SOC 2 Type II</span>
              <span className="flex items-center gap-1"><Shield className="h-3 w-3" /> ISO 27001</span>
              <span className="flex items-center gap-1"><Shield className="h-3 w-3" /> GDPR</span>
            </div>
          </div>
          <div className="mt-6 pt-6 border-t border-border/30 flex flex-wrap items-center justify-between gap-4 text-xs text-muted-foreground">
            <span>&copy; {new Date().getFullYear()} Arica Technologies. All rights reserved.</span>
            <div className="flex items-center gap-4">
              <a href="mailto:security@aricatech.com" className="hover:text-foreground transition-colors">Contact</a>
              <a href="https://github.com/prathamesh-ops-sudo/securenexus" target="_blank" rel="noopener noreferrer" className="hover:text-foreground transition-colors">GitHub</a>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}

function FaqItem({ question, answer }: { question: string; answer: string }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="gradient-card rounded-lg">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between p-4 text-left"
        aria-expanded={open}
      >
        <span className="text-sm font-medium pr-4">{question}</span>
        {open ? <ChevronUp className="h-4 w-4 text-muted-foreground flex-shrink-0" /> : <ChevronDown className="h-4 w-4 text-muted-foreground flex-shrink-0" />}
      </button>
      {open && (
        <div className="px-4 pb-4">
          <p className="text-sm text-muted-foreground leading-relaxed">{answer}</p>
        </div>
      )}
    </div>
  );
}

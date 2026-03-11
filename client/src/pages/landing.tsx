import { useState, useRef } from "react";
import {
  Zap,
  Brain,
  Eye,
  ArrowRight,
  Lock,
  Activity,
  Layers,
  Shield,
  ShieldCheck,
  Radar,
  Cloud,
  Search,
  AlertTriangle,
  Database,
  Clock,
  TrendingDown,
  Users,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Timer,
  BarChart3,
  Workflow,
  Target,
  Lightbulb,
  Star,
} from "lucide-react";
import { FaGoogle, FaGithub } from "react-icons/fa";
import {
  SiSplunk,
  SiPaloaltosoftware,
  SiAmazon,
  SiElastic,
  SiFortinet,
  SiCisco,
  SiOkta,
  SiTrendmicro,
} from "react-icons/si";
import atsLogo from "@/assets/logo.jpg";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useAuth } from "@/hooks/use-auth";

const painPoints = [
  {
    stat: "4,000+",
    label: "alerts/day",
    description: "The average SOC drowns in thousands of alerts daily, most of them noise.",
    icon: AlertTriangle,
    color: "text-red-500/80",
  },
  {
    stat: "45 min",
    label: "per triage",
    description: "Analysts spend 45 minutes manually triaging each alert across disconnected tools.",
    icon: Timer,
    color: "text-amber-500/80",
  },
  {
    stat: "70%",
    label: "false positives",
    description: "Most alerts are false positives, burning analyst hours that should go to real threats.",
    icon: Target,
    color: "text-orange-500/80",
  },
  {
    stat: "3.5x",
    label: "tool sprawl",
    description: "Security teams juggle 3-5 tools per investigation, losing context at every handoff.",
    icon: Layers,
    color: "text-violet-500/80",
  },
];

const howItWorks = [
  {
    step: "01",
    title: "Connect your tools",
    description:
      "Plug in your EDR, SIEM, and cloud security tools via read-only API keys. No agents, no infrastructure changes. Under 30 minutes.",
    icon: Workflow,
  },
  {
    step: "02",
    title: "AI correlates everything",
    description:
      "Our engine clusters alerts by attacker behavior, maps to MITRE ATT&CK, and scores each threat. What took your team hours happens in seconds.",
    icon: Brain,
  },
  {
    step: "03",
    title: "Respond with confidence",
    description:
      "Get actionable incident narratives, automated playbooks, and one-click response actions. Your analysts focus on decisions, not data wrangling.",
    icon: Zap,
  },
];

const features = [
  {
    icon: Brain,
    title: "Cut triage time by 90%",
    description:
      "AI clusters alerts by attacker behavior and generates incident narratives automatically. What took 45 minutes now takes under 5.",
    accent: "border-l-cyan-500",
  },
  {
    icon: Eye,
    title: "See the full attack story",
    description:
      "Map campaigns to MITRE ATT&CK techniques with confidence scores. Stop chasing individual alerts and start tracking adversaries.",
    accent: "border-l-violet-500",
  },
  {
    icon: TrendingDown,
    title: "Eliminate 70% of false positives",
    description:
      "Behavioral correlation separates real threats from noise. Your team stops wasting hours on alerts that don\u0027t matter.",
    accent: "border-l-blue-500",
  },
  {
    icon: Lock,
    title: "Deploy without disruption",
    description:
      "Read-only API connectors to your existing stack. No rip-and-replace, no new agents, no infrastructure changes. Live in 30 minutes.",
    accent: "border-l-emerald-500",
  },
  {
    icon: BarChart3,
    title: "Prove compliance in minutes",
    description:
      "Automated evidence collection for SOC 2, ISO 27001, NIST CSF, and GDPR. Generate audit-ready reports instead of building them manually.",
    accent: "border-l-purple-500",
  },
  {
    icon: Lightbulb,
    title: "Make every analyst a senior",
    description:
      "AI-generated investigation guides and response playbooks give junior analysts the decision-making capability of a 10-year veteran.",
    accent: "border-l-indigo-500",
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
    quote:
      "SecureNexus cut our alert triage time from 45 minutes to under 5. The AI correlation is genuinely useful, not just a buzzword.",
    name: "Sarah Chen",
    role: "SOC Lead",
    company: "Series B Fintech",
    rating: 5,
  },
  {
    quote:
      "We replaced three separate tools with SecureNexus. The attacker-centric view changed how our team thinks about incidents.",
    name: "Marcus Rivera",
    role: "CISO",
    company: "Healthcare SaaS",
    rating: 5,
  },
  {
    quote:
      "The MITRE ATT&CK mapping and automated narratives save my analysts 2+ hours per incident. ROI was obvious in week one.",
    name: "David Kim",
    role: "Director of Security",
    company: "E-commerce Platform",
    rating: 5,
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
  const [ssoMode, setSsoMode] = useState(false);
  const [ssoSlug, setSsoSlug] = useState("");
  const [ssoLoading, setSsoLoading] = useState(false);
  const [ssoError, setSsoError] = useState<string | null>(null);
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
        setOauthError(
          `${provider === "google" ? "Google" : "GitHub"} login is not configured yet. Please use email login.`,
        );
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

  const handleSsoLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!ssoSlug.trim()) return;
    setSsoLoading(true);
    setSsoError(null);
    try {
      const res = await fetch(`/api/sso/check/${encodeURIComponent(ssoSlug.trim())}`);
      const data = await res.json();
      if (!data.ssoEnabled) {
        setSsoError("SSO is not enabled for this organization.");
        return;
      }
      window.location.href = `/api/sso/${encodeURIComponent(ssoSlug.trim())}/login`;
    } catch {
      setSsoError("Failed to check SSO configuration.");
    } finally {
      setSsoLoading(false);
    }
  };

  const scrollToHowItWorks = () => {
    howItWorksRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  const authError = authMode === "register" ? registerError : loginError;
  const isSubmitting = authMode === "register" ? isRegistering : isLoggingIn;

  return (
    <div data-testid="landing-page" className="min-h-screen bg-background text-foreground font-sans refined-ui">
      {/* Auth Modal */}
      {authMode && (
        <div
          className="fixed inset-0 z-[60] flex items-center justify-center bg-black/60 backdrop-blur-sm animate-fade-in"
          onClick={() => setAuthMode(null)}
        >
          <div
            className="w-full max-w-md mx-4 bg-card border border-border rounded-xl shadow-[0_8px_40px_rgba(0,0,0,0.4)] animate-fade-in-up"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="p-8">
              <div className="flex items-center gap-3 mb-6">
                <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center">
                  <img src={atsLogo} alt="SecureNexus" className="w-6 h-6 object-contain" />
                </div>
                <span className="font-semibold text-xl tracking-tight font-display">SecureNexus</span>
              </div>
              <h2 className="text-2xl font-bold mb-2 font-display tracking-[-0.02em]">
                {authMode === "register" ? "Start your free trial" : "Welcome back"}
              </h2>
              <p className="text-sm text-muted-foreground mb-6">
                {authMode === "register" ? "14 days free. No credit card required." : "Log in to your account"}
              </p>
              {authError && (
                <div className="mb-4 p-3 rounded-lg border border-destructive/30 bg-destructive/10 text-destructive text-sm">
                  {authError.message}
                </div>
              )}
              <div className="space-y-3 mb-6">
                {oauthError && (
                  <div className="mb-2 p-2.5 rounded-lg border border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-400 text-xs">
                    {oauthError}
                  </div>
                )}
                <button
                  className="w-full h-10 flex items-center justify-center gap-2 text-sm font-medium rounded-lg bg-white/5 hover:bg-white/10 border border-border transition-colors duration-150"
                  disabled={oauthLoading === "google"}
                  onClick={() => handleOAuth("google")}
                >
                  <FaGoogle className="h-4 w-4 text-[#4285F4]" />
                  {oauthLoading === "google" ? "Connecting..." : "Continue with Google"}
                </button>
                <button
                  className="w-full h-10 flex items-center justify-center gap-2 text-sm font-medium rounded-lg bg-white/5 hover:bg-white/10 border border-border transition-colors duration-150"
                  disabled={oauthLoading === "github"}
                  onClick={() => handleOAuth("github")}
                >
                  <FaGithub className="h-4 w-4" />
                  {oauthLoading === "github" ? "Connecting..." : "Continue with GitHub"}
                </button>
                <div className="relative my-3">
                  <div className="absolute inset-0 flex items-center">
                    <div className="w-full border-t border-border" />
                  </div>
                  <div className="relative flex justify-center text-xs">
                    <span className="bg-card px-3 text-muted-foreground">or continue with email</span>
                  </div>
                </div>
              </div>
              <form onSubmit={handleSubmit} className="space-y-4">
                {authMode === "register" && (
                  <div className="grid grid-cols-2 gap-3">
                    <div className="space-y-1.5">
                      <Label
                        htmlFor="firstName"
                        className="text-xs font-medium uppercase tracking-wider text-muted-foreground"
                      >
                        First name
                      </Label>
                      <Input
                        id="firstName"
                        value={firstName}
                        onChange={(e) => setFirstName(e.target.value)}
                        placeholder="John"
                        className="border border-border rounded-lg h-10 focus:border-blue-500 dark:focus:border-blue-400"
                      />
                    </div>
                    <div className="space-y-1.5">
                      <Label
                        htmlFor="lastName"
                        className="text-xs font-medium uppercase tracking-wider text-muted-foreground"
                      >
                        Last name
                      </Label>
                      <Input
                        id="lastName"
                        value={lastName}
                        onChange={(e) => setLastName(e.target.value)}
                        placeholder="Doe"
                        className="border border-border rounded-lg h-10 focus:border-blue-500 dark:focus:border-blue-400"
                      />
                    </div>
                  </div>
                )}
                <div className="space-y-1.5">
                  <Label htmlFor="email" className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                    Email
                  </Label>
                  <Input
                    id="email"
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="you@company.com"
                    required
                    className="border border-border rounded-lg h-10 focus:border-blue-500 dark:focus:border-blue-400"
                  />
                </div>
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <Label
                      htmlFor="password"
                      className="text-xs font-medium uppercase tracking-wider text-muted-foreground"
                    >
                      Password
                    </Label>
                    {authMode === "login" && (
                      <a
                        href="/forgot-password"
                        className="text-xs font-medium text-blue-500 hover:text-blue-400 hover:underline transition-colors"
                        onClick={(e) => {
                          e.preventDefault();
                          setAuthMode(null);
                          window.location.href = "/forgot-password";
                        }}
                      >
                        Forgot password?
                      </a>
                    )}
                  </div>
                  <Input
                    id="password"
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Min 6 characters"
                    required
                    minLength={6}
                    className="border border-border rounded-lg h-10 focus:border-blue-500 dark:focus:border-blue-400"
                  />
                </div>
                <button
                  type="submit"
                  className="w-full h-11 rounded-lg font-semibold text-white bg-blue-600 hover:bg-blue-700 shadow-[0_1px_2px_rgba(0,0,0,0.1),0_4px_12px_rgba(37,99,235,0.25)] hover:shadow-[0_1px_2px_rgba(0,0,0,0.1),0_8px_20px_rgba(37,99,235,0.3)] transition-all duration-150 disabled:opacity-50 disabled:pointer-events-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2"
                  disabled={isSubmitting}
                >
                  {isSubmitting ? "Please wait..." : authMode === "register" ? "Start Free Trial" : "Log In"}
                </button>
              </form>
              <p className="text-sm text-center text-muted-foreground mt-4">
                {authMode === "register" ? (
                  <>
                    Already have an account?{" "}
                    <button
                      onClick={() => setAuthMode("login")}
                      className="text-blue-500 font-semibold hover:underline"
                    >
                      Log in
                    </button>
                  </>
                ) : (
                  <>
                    Don&apos;t have an account?{" "}
                    <button
                      onClick={() => setAuthMode("register")}
                      className="text-blue-500 font-semibold hover:underline"
                    >
                      Sign up
                    </button>
                  </>
                )}
              </p>
              {authMode === "login" && !ssoMode && (
                <div className="mt-3 pt-3 border-t border-border">
                  <button
                    onClick={() => setSsoMode(true)}
                    className="w-full text-sm font-medium text-muted-foreground hover:text-blue-500 transition-colors duration-150 flex items-center justify-center gap-1.5"
                  >
                    <Lock className="h-3.5 w-3.5" />
                    Sign in with SSO
                  </button>
                </div>
              )}
              {ssoMode && (
                <div className="mt-3 pt-3 border-t border-border">
                  <form onSubmit={handleSsoLogin} className="space-y-2">
                    <Label className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                      Organization Slug
                    </Label>
                    <Input
                      value={ssoSlug}
                      onChange={(e) => setSsoSlug(e.target.value)}
                      placeholder="your-org-slug"
                      required
                      className="border border-border rounded-lg h-10 focus:border-blue-500 dark:focus:border-blue-400"
                    />
                    {ssoError && <p className="text-xs text-red-500">{ssoError}</p>}
                    <div className="flex gap-2">
                      <button
                        type="button"
                        onClick={() => {
                          setSsoMode(false);
                          setSsoError(null);
                        }}
                        className="flex-1 h-9 rounded-lg text-sm font-medium border border-border hover:bg-white/5 transition-colors duration-150"
                      >
                        Back
                      </button>
                      <button
                        type="submit"
                        disabled={ssoLoading || !ssoSlug.trim()}
                        className="flex-1 h-9 rounded-lg text-sm font-semibold text-white bg-blue-600 hover:bg-blue-700 transition-colors duration-150 disabled:opacity-50 disabled:pointer-events-none"
                      >
                        {ssoLoading ? "Checking..." : "Continue with SSO"}
                      </button>
                    </div>
                  </form>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      <a
        href="#landing-main"
        className="sr-only focus:not-sr-only focus:absolute focus:top-2 focus:left-2 focus:z-[100] focus:px-4 focus:py-2 focus:bg-white focus:text-slate-900 focus:rounded-md focus:outline-none focus:shadow-lg focus:ring-2 focus:ring-blue-500"
      >
        Skip to main content
      </a>

      {/* Navigation */}
      <header>
        <nav className="fixed top-4 left-4 right-4 z-50 max-w-6xl mx-auto">
          <div className="flex items-center justify-between h-14 px-5 bg-white/5 dark:bg-white/[0.03] backdrop-blur-2xl border border-white/[0.08] rounded-xl shadow-[0_8px_32px_rgba(0,0,0,0.3)]">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center">
                <img src={atsLogo} alt="SecureNexus" className="w-5 h-5 object-contain" />
              </div>
              <span className="font-bold text-base tracking-tight">SecureNexus</span>
            </div>
            <div className="hidden md:flex items-center gap-6">
              <button
                onClick={scrollToHowItWorks}
                className="text-sm font-medium text-slate-400 hover:text-white transition-colors duration-150"
              >
                How it works
              </button>
              <a
                href="#features"
                className="text-sm font-medium text-slate-400 hover:text-white transition-colors duration-150"
              >
                Features
              </a>
              <a
                href="#faq"
                className="text-sm font-medium text-slate-400 hover:text-white transition-colors duration-150"
              >
                FAQ
              </a>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setAuthMode("login")}
                className="text-sm font-medium text-slate-400 hover:text-white transition-colors duration-150 px-3 py-1.5"
              >
                Log In
              </button>
              <button
                onClick={() => setAuthMode("register")}
                className="text-sm font-semibold text-white bg-blue-600 hover:bg-blue-700 px-5 py-2 rounded-lg shadow-[0_1px_2px_rgba(0,0,0,0.1),0_4px_12px_rgba(37,99,235,0.25)] hover:shadow-[0_1px_2px_rgba(0,0,0,0.1),0_8px_20px_rgba(37,99,235,0.3)] transition-all duration-150 hover:-translate-y-px focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2"
              >
                Start Free
              </button>
            </div>
          </div>
        </nav>
      </header>

      <main id="landing-main">
        {/* Hero */}
        <section className="relative pt-[8.5rem] pb-28 px-6 overflow-hidden">
          <div className="max-w-6xl mx-auto">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
              <div className="relative z-10">
                <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full border border-blue-500/30 bg-blue-500/10 text-blue-400 text-xs font-medium mb-6 tracking-wide">
                  <div className="w-1.5 h-1.5 rounded-full bg-blue-500 animate-pulse" />
                  AI-Powered Security Operations
                </div>
                <h1 className="text-[2.75rem] md:text-[3.25rem] lg:text-[3.75rem] font-extrabold tracking-[-0.03em] mb-6 leading-[1.04] font-display">
                  Stop Chasing
                  <br />
                  <span className="text-blue-500">Alerts.</span>
                  <br />
                  Start Stopping
                  <br />
                  <span className="border-b-[3px] border-blue-500 pb-0.5">Attackers.</span>
                </h1>
                <p className="text-base md:text-lg text-slate-400 max-w-lg mb-8 leading-relaxed">
                  SecureNexus uses AI to correlate thousands of alerts into actionable incidents, cutting triage time by
                  90% and false positives by 70%.
                </p>
                <div className="flex flex-wrap items-center gap-3 mb-8">
                  <button
                    onClick={() => setAuthMode("register")}
                    className="inline-flex items-center gap-2 px-7 py-3 rounded-lg font-semibold text-white bg-blue-600 hover:bg-blue-700 text-base shadow-[0_1px_2px_rgba(0,0,0,0.1),0_4px_12px_rgba(37,99,235,0.25)] hover:shadow-[0_1px_2px_rgba(0,0,0,0.1),0_8px_20px_rgba(37,99,235,0.3)] transition-all duration-150 hover:-translate-y-px focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2"
                  >
                    Start Free Trial
                    <ArrowRight className="h-4 w-4" />
                  </button>
                  <button
                    onClick={scrollToHowItWorks}
                    className="inline-flex items-center gap-2 px-7 py-3 rounded-lg font-medium text-white bg-white/5 hover:bg-white/10 text-base border border-white/15 hover:border-white/25 transition-all duration-200"
                  >
                    How It Works
                  </button>
                </div>
                <div className="flex items-center gap-8">
                  {[
                    { val: "10K+", sub: "Alerts/Day" },
                    { val: "50+", sub: "SOC Teams" },
                    { val: "500+", sub: "Integrations" },
                  ].map((s) => (
                    <div key={s.sub}>
                      <div className="text-[2rem] font-bold tracking-tight font-mono">{s.val}</div>
                      <div className="text-xs text-slate-500 font-medium">{s.sub}</div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Dashboard mockup */}
              <div className="relative hidden lg:block">
                <div className="bg-card border border-border rounded-xl shadow-[0_4px_30px_rgba(0,0,0,0.4)] overflow-hidden">
                  <div className="flex items-center gap-2 px-4 py-2.5 border-b border-border bg-muted/30">
                    <div className="flex gap-1.5">
                      <div className="w-2.5 h-2.5 rounded-full bg-red-400/80" />
                      <div className="w-2.5 h-2.5 rounded-full bg-amber-400/80" />
                      <div className="w-2.5 h-2.5 rounded-full bg-emerald-400/80" />
                    </div>
                    <div className="flex-1 text-center">
                      <span className="text-[10px] font-medium text-muted-foreground">SecureNexus Dashboard</span>
                    </div>
                  </div>
                  <div className="p-4 space-y-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <div className="w-8 h-8 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center">
                          <Shield className="h-4 w-4 text-blue-400" />
                        </div>
                        <div>
                          <div className="text-xs font-semibold">Threat Detection</div>
                          <div className="text-[10px] text-muted-foreground">24 active alerts &bull; 3 incidents</div>
                        </div>
                      </div>
                      <div className="flex items-center gap-1 px-2 py-1 rounded-md bg-emerald-500/10 border border-emerald-500/20">
                        <div className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                        <span className="text-[10px] font-medium text-emerald-400">Protected</span>
                      </div>
                    </div>
                    <div className="bg-muted/30 rounded-lg border border-border p-3">
                      <div className="flex justify-between items-center mb-2">
                        <span className="text-[10px] font-medium text-muted-foreground">Threat Score</span>
                        <span className="text-sm font-bold font-mono text-blue-400">87%</span>
                      </div>
                      <div className="w-full h-2.5 rounded-full bg-muted/50 overflow-hidden">
                        <div
                          className="h-full rounded-full bg-gradient-to-r from-blue-600 to-blue-400"
                          style={{ width: "87%" }}
                        />
                      </div>
                    </div>
                    <div className="grid grid-cols-3 gap-2">
                      {[
                        { label: "Critical", val: "3", cls: "border-l-2 border-l-red-500 bg-red-500/5 text-red-400" },
                        {
                          label: "High",
                          val: "12",
                          cls: "border-l-2 border-l-amber-500 bg-amber-500/5 text-amber-400",
                        },
                        {
                          label: "Resolved",
                          val: "156",
                          cls: "border-l-2 border-l-emerald-500 bg-emerald-500/5 text-emerald-400",
                        },
                      ].map((item) => (
                        <div
                          key={item.label}
                          className={`flex flex-col items-center p-2 rounded-lg border border-border ${item.cls}`}
                        >
                          <span className="text-lg font-bold font-mono">{item.val}</span>
                          <span className="text-[9px] font-medium">{item.label}</span>
                        </div>
                      ))}
                    </div>
                    <button
                      onClick={() => setAuthMode("register")}
                      className="w-full py-2.5 rounded-lg font-semibold text-white bg-blue-600 hover:bg-blue-700 shadow-[0_1px_2px_rgba(0,0,0,0.1),0_4px_12px_rgba(37,99,235,0.2)] transition-all duration-150 text-sm"
                    >
                      View Full Dashboard
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* Metrics bar */}
        <section className="py-12 px-6">
          <div className="max-w-5xl mx-auto">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {metrics.map((metric, index) => (
                <div
                  key={metric.label}
                  className="flex flex-col items-center gap-1.5 p-5 rounded-xl bg-white/[0.02] border border-white/[0.06] hover:bg-white/[0.04] hover:border-white/[0.1] transition-[background,border-color,box-shadow] duration-200"
                  style={{ animationDelay: `${index * 75}ms` }}
                >
                  <div className="w-9 h-9 rounded-lg bg-blue-500/10 flex items-center justify-center mb-1">
                    <metric.icon className="h-4 w-4 text-blue-400" />
                  </div>
                  <span className="text-[2rem] font-bold tracking-tight font-mono">{metric.value}</span>
                  <span className="text-xs text-slate-500 font-medium">{metric.label}</span>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Problem section */}
        <section className="py-24 px-6 bg-gradient-to-b from-background to-[#020617]">
          <div className="max-w-5xl mx-auto">
            <div className="text-center mb-14">
              <div className="inline-flex items-center px-3.5 py-1.5 rounded-full border border-red-500/30 bg-red-500/10 text-red-400 text-xs font-medium mb-4">
                The Problem
              </div>
              <h2 className="text-[1.875rem] md:text-[2.25rem] font-bold tracking-[-0.02em] mb-3">
                Your SOC Is Drowning in Noise
              </h2>
              <p className="text-slate-400 max-w-xl mx-auto">
                Security teams spend more time managing tools than stopping threats.
              </p>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              {painPoints.map((point) => (
                <div
                  key={point.label}
                  className="bg-white/[0.02] border border-white/[0.06] rounded-xl p-6 text-center hover:bg-white/[0.04] hover:border-white/[0.1] transition-[background,border-color,box-shadow] duration-200"
                >
                  <point.icon className={`h-6 w-6 mx-auto mb-3 ${point.color}`} />
                  <div className="text-[2rem] font-bold tracking-tight font-mono mb-0.5">{point.stat}</div>
                  <div className="text-xs font-medium text-blue-400 mb-2 uppercase tracking-wider">{point.label}</div>
                  <p className="text-xs text-slate-500 leading-relaxed">{point.description}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* How It Works */}
        <section ref={howItWorksRef} id="how-it-works" className="py-20 px-6">
          <div className="max-w-5xl mx-auto">
            <div className="text-center mb-14">
              <div className="inline-flex items-center px-3.5 py-1.5 rounded-full border border-blue-500/30 bg-blue-500/10 text-blue-400 text-xs font-medium mb-4">
                How It Works
              </div>
              <h2 className="text-[1.75rem] md:text-[2rem] font-semibold tracking-[-0.02em] mb-3">
                Three Steps to a Quieter SOC
              </h2>
              <p className="text-slate-400 max-w-xl mx-auto">
                Go from alert overload to clear, actionable intelligence in under 30 minutes.
              </p>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              {howItWorks.map((step) => (
                <div key={step.step} className="relative">
                  <div className="absolute -top-3 -left-3 w-8 h-8 rounded-full bg-blue-600 text-white flex items-center justify-center font-bold text-sm z-10">
                    {step.step}
                  </div>
                  <div className="bg-white/[0.02] border border-white/[0.06] rounded-xl p-6 pt-8 h-full hover:bg-white/[0.04] hover:border-white/[0.1] transition-[background,border-color] duration-200">
                    <h3 className="font-semibold text-lg mb-2 flex items-center gap-2">
                      {step.title}
                      <step.icon className="h-4 w-4 text-blue-400" />
                    </h3>
                    <p className="text-sm text-slate-400 leading-relaxed">{step.description}</p>
                  </div>
                </div>
              ))}
            </div>
            <div className="text-center mt-10">
              <button
                onClick={() => setAuthMode("register")}
                className="inline-flex items-center gap-2 px-8 py-3 rounded-lg font-semibold text-white bg-blue-600 hover:bg-blue-700 shadow-[0_1px_2px_rgba(0,0,0,0.1),0_4px_12px_rgba(37,99,235,0.25)] hover:shadow-[0_1px_2px_rgba(0,0,0,0.1),0_8px_20px_rgba(37,99,235,0.3)] transition-all duration-150 hover:-translate-y-px"
              >
                Start Free Trial
                <ArrowRight className="h-4 w-4" />
              </button>
            </div>
          </div>
        </section>

        {/* Integrations */}
        <section className="py-16 overflow-hidden bg-gradient-to-b from-background to-[#020617]">
          <div className="text-center mb-10 px-6">
            <div className="inline-flex items-center px-3.5 py-1.5 rounded-full border border-white/10 bg-white/5 text-slate-400 text-xs font-medium mb-4">
              Integrations
            </div>
            <h2 className="text-2xl md:text-[1.75rem] font-semibold mb-2 tracking-[-0.01em]">
              Works with Your Existing Stack
            </h2>
            <p className="text-sm text-slate-500">24+ connectors. Read-only. No agents required.</p>
          </div>
          <div className="relative group/marquee">
            <div className="absolute left-0 top-0 bottom-0 w-24 bg-gradient-to-r from-background to-transparent z-10 pointer-events-none" />
            <div className="absolute right-0 top-0 bottom-0 w-24 bg-gradient-to-l from-background to-transparent z-10 pointer-events-none" />
            <div
              className="flex animate-marquee gap-3 group-hover/marquee:[animation-play-state:paused]"
              style={{ animationDuration: "45s" }}
            >
              {[...integrations, ...integrations].map((item, i) => (
                <div
                  key={`${item.name}-${i}`}
                  className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-white/[0.03] border border-white/[0.06] flex-shrink-0 hover:bg-white/[0.06] transition-colors duration-200"
                >
                  <item.icon className="h-3.5 w-3.5 text-slate-500 flex-shrink-0" />
                  <span className="text-sm font-medium text-slate-400 whitespace-nowrap">{item.name}</span>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Capabilities */}
        <section id="features" className="py-24 px-6">
          <div className="max-w-5xl mx-auto">
            <div className="text-center mb-14">
              <div className="inline-flex items-center px-3.5 py-1.5 rounded-full border border-blue-500/30 bg-blue-500/10 text-blue-400 text-xs font-medium mb-4">
                Capabilities
              </div>
              <h2 className="text-[1.875rem] md:text-[2.25rem] font-bold tracking-[-0.02em] mb-3">
                Everything You Need to Succeed
              </h2>
              <p className="text-slate-400 max-w-xl mx-auto">
                Every capability is built to deliver a measurable result for your security team.
              </p>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
              {features.map((feature, index) => (
                <div
                  key={index}
                  className={`relative bg-white/[0.02] border border-white/[0.06] rounded-xl pl-5 pr-6 py-7 border-l-2 ${feature.accent} hover:bg-white/[0.04] hover:border-white/[0.1] transition-[background,border-color,box-shadow] duration-200 group`}
                >
                  <h3 className="font-semibold text-base mb-2 flex items-center gap-2">
                    <feature.icon className="h-4 w-4 text-slate-400 group-hover:text-blue-400 transition-colors duration-200" />
                    {feature.title}
                  </h3>
                  <p className="text-sm text-slate-500 leading-relaxed">{feature.description}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Testimonials */}
        <section className="pt-28 pb-20 px-6 bg-gradient-to-b from-[#0f172a] to-[#0c1220]">
          <div className="max-w-5xl mx-auto">
            <div className="text-center mb-14">
              <div className="inline-flex items-center px-3.5 py-1.5 rounded-full border border-amber-500/30 bg-amber-500/10 text-amber-400 text-xs font-medium mb-4">
                Customer Stories
              </div>
              <h2 className="text-[1.5rem] md:text-[1.75rem] font-bold italic font-serif mb-3">What Our Users Say</h2>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
              {testimonials.map((t, i) => (
                <div
                  key={i}
                  className={`bg-white/[0.02] border border-white/[0.06] rounded-xl p-7 flex flex-col hover:bg-white/[0.04] hover:border-white/[0.1] transition-[background,border-color] duration-200 ${i === 0 ? "md:mt-8" : i === 2 ? "md:-mt-4" : ""}`}
                >
                  <div className="flex gap-0.5 mb-4">
                    {Array.from({ length: t.rating }).map((_, si) => (
                      <Star key={si} className="h-3.5 w-3.5 fill-amber-400 text-amber-400" />
                    ))}
                  </div>
                  <p className="text-sm text-slate-300 leading-relaxed flex-1 mb-5 font-serif italic">
                    &ldquo;{t.quote}&rdquo;
                  </p>
                  <div className="flex items-center gap-3 pt-4 border-t border-white/[0.06]">
                    <div className="w-9 h-9 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-xs font-semibold text-blue-400">
                      {t.name
                        .split(" ")
                        .map((n) => n[0])
                        .join("")}
                    </div>
                    <div>
                      <p className="text-sm font-semibold">{t.name}</p>
                      <p className="text-xs text-slate-500">
                        {t.role}, {t.company}
                      </p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Pricing */}
        <section id="pricing" className="py-24 px-6">
          <div className="max-w-5xl mx-auto">
            <div className="text-center mb-14">
              <div className="inline-flex items-center px-3.5 py-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 text-emerald-400 text-xs font-medium mb-4">
                Pricing
              </div>
              <h2 className="text-[1.875rem] md:text-[2.25rem] font-bold tracking-[-0.02em] mb-3">
                Plans for Every Security Team
              </h2>
              <p className="text-slate-400 max-w-xl mx-auto">
                All prices in INR. Annual billing available with discounts. Start free, scale as you grow.
              </p>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              {[
                {
                  name: "Free Trial",
                  price: "\u20B90",
                  period: "/month",
                  description: "Evaluate the platform with limited capacity",
                  features: ["500 events/month", "2 connectors", "5K AI tokens", "Community support"],
                  cta: "Start Free",
                  highlight: false,
                },
                {
                  name: "Starter",
                  price: "\u20B915K",
                  period: "/month",
                  description: "For SMBs and growing security teams",
                  features: [
                    "50K events/month",
                    "10 connectors",
                    "100K AI tokens",
                    "Email support",
                    "Basic compliance",
                  ],
                  cta: "Get Started",
                  highlight: false,
                },
                {
                  name: "Growth",
                  price: "\u20B940K",
                  period: "/month",
                  description: "For mid-market enterprises scaling security ops",
                  features: [
                    "500K events/month",
                    "50 connectors",
                    "500K AI tokens",
                    "Priority support",
                    "Full compliance suite",
                    "MITRE ATT&CK mapping",
                  ],
                  cta: "Choose Growth",
                  highlight: true,
                  badge: "Most Popular",
                },
                {
                  name: "Enterprise",
                  price: "\u20B91L",
                  period: "/month",
                  description: "For large organizations with advanced needs",
                  features: [
                    "Unlimited events",
                    "Unlimited connectors",
                    "2M AI tokens",
                    "24/7 dedicated support",
                    "SSO & RBAC",
                    "Custom integrations",
                  ],
                  cta: "Contact Sales",
                  highlight: false,
                },
              ].map((plan) => (
                <div
                  key={plan.name}
                  className={`relative bg-white/[0.02] border rounded-xl p-6 flex flex-col ${
                    plan.highlight ? "border-blue-500/40 shadow-[0_0_30px_rgba(37,99,235,0.1)]" : "border-white/[0.06]"
                  } hover:bg-white/[0.04] hover:border-white/[0.1] transition-[background,border-color] duration-200`}
                >
                  {plan.badge && (
                    <div className="absolute -top-3 left-1/2 -translate-x-1/2">
                      <span className="px-3 py-1 rounded-full bg-blue-600 text-white text-[10px] font-semibold uppercase tracking-wide">
                        {plan.badge}
                      </span>
                    </div>
                  )}
                  <h3 className="font-semibold text-base mb-1">{plan.name}</h3>
                  <p className="text-xs text-slate-500 mb-4">{plan.description}</p>
                  <div className="flex items-baseline gap-1 mb-5">
                    <span className="text-2xl font-bold">{plan.price}</span>
                    <span className="text-sm text-slate-500">{plan.period}</span>
                  </div>
                  <ul className="space-y-2 mb-6 flex-1">
                    {plan.features.map((f) => (
                      <li key={f} className="flex items-center gap-2 text-sm text-slate-400">
                        <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500 flex-shrink-0" />
                        {f}
                      </li>
                    ))}
                  </ul>
                  <button
                    onClick={() => setAuthMode("register")}
                    className={`w-full py-2.5 rounded-lg text-sm font-semibold transition-all duration-150 ${
                      plan.highlight
                        ? "bg-blue-600 hover:bg-blue-700 text-white shadow-[0_1px_2px_rgba(0,0,0,0.1),0_4px_12px_rgba(37,99,235,0.25)]"
                        : "bg-white/5 hover:bg-white/10 text-white border border-white/15"
                    }`}
                  >
                    {plan.cta}
                  </button>
                </div>
              ))}
            </div>
            <p className="text-center text-xs text-slate-500 mt-6">
              Government &amp; PSU pricing available on request.{" "}
              <a href="mailto:sales@aricatech.com" className="text-blue-400 hover:underline">
                Contact sales
              </a>
            </p>
          </div>
        </section>

        {/* FAQ */}
        <section id="faq" className="py-20 px-6">
          <div className="max-w-3xl mx-auto">
            <div className="text-center mb-10">
              <div className="inline-flex items-center px-3.5 py-1.5 rounded-full border border-white/10 bg-white/5 text-slate-400 text-xs font-medium mb-4">
                FAQ
              </div>
              <h2 className="text-[1.875rem] md:text-[2rem] font-bold tracking-[-0.02em] mb-3">Common Questions</h2>
            </div>
            <div className="space-y-2">
              {faqs.map((faq, i) => (
                <FaqItem key={i} question={faq.q} answer={faq.a} />
              ))}
            </div>
          </div>
        </section>

        {/* CTA */}
        <section className="py-16 px-6">
          <div className="max-w-2xl mx-auto text-center">
            <div className="bg-white/[0.02] border border-white/[0.08] rounded-xl p-10 shadow-[0_8px_40px_rgba(0,0,0,0.3)]">
              <h2 className="text-[1.875rem] md:text-[2.25rem] font-bold tracking-[-0.02em] mb-4">
                Ready to Transform Your SOC?
              </h2>
              <p className="text-slate-400 mb-8 max-w-lg mx-auto">
                Join 50+ security teams that cut triage time by 90% and false positives by 70%. See results in your
                first week.
              </p>
              <div className="flex flex-wrap justify-center gap-3 mb-6">
                <button
                  onClick={() => setAuthMode("register")}
                  className="inline-flex items-center gap-2 px-8 py-3 rounded-lg font-semibold text-white bg-blue-600 hover:bg-blue-700 text-base shadow-[0_1px_2px_rgba(0,0,0,0.1),0_4px_12px_rgba(37,99,235,0.25)] hover:shadow-[0_1px_2px_rgba(0,0,0,0.1),0_8px_20px_rgba(37,99,235,0.3)] transition-all duration-150 hover:-translate-y-px"
                >
                  Start Free Trial
                  <ArrowRight className="h-4 w-4" />
                </button>
                <button
                  onClick={() => setAuthMode("login")}
                  className="inline-flex items-center px-8 py-3 rounded-lg font-medium text-white bg-white/5 hover:bg-white/10 text-base border border-white/15 hover:border-white/25 transition-all duration-200"
                >
                  Log In
                </button>
              </div>
              <div className="flex flex-wrap items-center justify-center gap-5 text-xs text-slate-500">
                <span className="flex items-center gap-1.5">
                  <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500" />
                  No credit card required
                </span>
                <span className="flex items-center gap-1.5">
                  <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500" />
                  Cancel anytime
                </span>
              </div>
            </div>
          </div>
        </section>

        {/* Further Reading */}
        <section className="py-20 px-6 border-t border-border/30">
          <div className="max-w-5xl mx-auto">
            <div className="text-center mb-10">
              <h2 className="text-[1.5rem] font-bold mb-3 tracking-[-0.01em]">Further Reading</h2>
              <p className="text-slate-500">Dive deeper into the future of security operations.</p>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <a
                href="/blog/automated-secops"
                className="block bg-white/[0.02] border border-white/[0.06] rounded-xl p-6 hover:bg-white/[0.04] hover:border-white/[0.1] transition-[background,border-color] duration-200"
              >
                <div className="w-9 h-9 rounded-lg bg-indigo-500/10 flex items-center justify-center mb-4">
                  <Brain className="h-4 w-4 text-indigo-400" />
                </div>
                <h3 className="font-semibold text-base mb-2">Automated SecOps Guide</h3>
                <p className="text-sm text-slate-500 leading-relaxed">
                  Discover the evolution from SIEM to Agentic SOC and how to eliminate alert fatigue.
                </p>
              </a>
              <a
                href="/product/agentic-soc"
                className="block bg-white/[0.02] border border-white/[0.06] rounded-xl p-6 hover:bg-white/[0.04] hover:border-white/[0.1] transition-[background,border-color] duration-200"
              >
                <div className="w-9 h-9 rounded-lg bg-blue-500/10 flex items-center justify-center mb-4">
                  <Workflow className="h-4 w-4 text-blue-400" />
                </div>
                <h3 className="font-semibold text-base mb-2">What is an Agentic SOC?</h3>
                <p className="text-sm text-slate-500 leading-relaxed">
                  Learn how AI agents are transforming Tier-1 triage and incident correlation.
                </p>
              </a>
              <a
                href="/product/comparison"
                className="block bg-white/[0.02] border border-white/[0.06] rounded-xl p-6 hover:bg-white/[0.04] hover:border-white/[0.1] transition-[background,border-color] duration-200"
              >
                <div className="w-9 h-9 rounded-lg bg-emerald-500/10 flex items-center justify-center mb-4">
                  <BarChart3 className="h-4 w-4 text-emerald-400" />
                </div>
                <h3 className="font-semibold text-base mb-2">Compare SIEMs</h3>
                <p className="text-sm text-slate-500 leading-relaxed">
                  See how SecureNexus compares against Microsoft Sentinel, Splunk, and IBM QRadar.
                </p>
              </a>
            </div>
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="border-t border-border/30 py-10 px-6">
        <div className="max-w-6xl mx-auto">
          <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-6 mb-8">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center">
                <img src={atsLogo} alt="SecureNexus" className="w-5 h-5 object-contain" />
              </div>
              <div>
                <span className="font-semibold text-sm">SecureNexus</span>
                <p className="text-[10px] text-slate-500">AI-Powered Security Operations</p>
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-3">
              {["SOC 2 Type II", "ISO 27001", "GDPR"].map((cert) => (
                <span
                  key={cert}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-border text-xs font-medium text-slate-400"
                >
                  <Shield className="h-3 w-3" />
                  {cert}
                </span>
              ))}
            </div>
          </div>
          <div className="pt-6 border-t border-border/30 flex flex-wrap items-center justify-between gap-4 text-xs text-slate-500">
            <span>&copy; {new Date().getFullYear()} Arica Technologies. All rights reserved.</span>
            <div className="flex items-center gap-4">
              <a href="#" className="hover:text-white transition-colors duration-150 font-medium">
                Privacy
              </a>
              <a href="#" className="hover:text-white transition-colors duration-150 font-medium">
                Terms
              </a>
              <a
                href="mailto:security@aricatech.com"
                className="hover:text-white transition-colors duration-150 font-medium"
              >
                Contact
              </a>
              <a
                href="https://github.com/prathamesh-ops-sudo/securenexus"
                target="_blank"
                rel="noopener noreferrer"
                className="hover:text-white transition-colors duration-150 font-medium"
              >
                GitHub
              </a>
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
    <div className="bg-white/[0.02] border border-white/[0.06] rounded-lg overflow-hidden hover:border-white/[0.1] transition-colors duration-200">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between p-5 text-left hover:bg-white/[0.02] transition-colors duration-150"
        aria-expanded={open}
      >
        <span className="text-sm font-semibold pr-4">{question}</span>
        {open ? (
          <ChevronUp className="h-4 w-4 text-slate-500 flex-shrink-0" />
        ) : (
          <ChevronDown className="h-4 w-4 text-slate-500 flex-shrink-0" />
        )}
      </button>
      {open && (
        <div className="px-5 pb-5 border-t border-white/[0.06] pt-4">
          <p className="text-sm text-slate-400 leading-relaxed">{answer}</p>
        </div>
      )}
    </div>
  );
}

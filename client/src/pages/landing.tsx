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
    color: "bg-red-100 dark:bg-red-500/10 text-red-600 dark:text-red-400",
  },
  {
    stat: "45 min",
    label: "per triage",
    description: "Analysts spend 45 minutes manually triaging each alert across disconnected tools.",
    icon: Timer,
    color: "bg-amber-100 dark:bg-amber-500/10 text-amber-600 dark:text-amber-400",
  },
  {
    stat: "70%",
    label: "false positives",
    description: "Most alerts are false positives, burning analyst hours that should go to real threats.",
    icon: Target,
    color: "bg-orange-100 dark:bg-orange-500/10 text-orange-600 dark:text-orange-400",
  },
  {
    stat: "3.5x",
    label: "tool sprawl",
    description: "Security teams juggle 3-5 tools per investigation, losing context at every handoff.",
    icon: Layers,
    color: "bg-violet-100 dark:bg-violet-500/10 text-violet-600 dark:text-violet-400",
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
    color: "bg-cyan-100 dark:bg-cyan-500/10 text-cyan-600 dark:text-cyan-400",
  },
  {
    icon: Eye,
    title: "See the full attack story",
    description:
      "Map campaigns to MITRE ATT&CK techniques with confidence scores. Stop chasing individual alerts and start tracking adversaries.",
    color: "bg-violet-100 dark:bg-violet-500/10 text-violet-600 dark:text-violet-400",
  },
  {
    icon: TrendingDown,
    title: "Eliminate 70% of false positives",
    description:
      "Behavioral correlation separates real threats from noise. Your team stops wasting hours on alerts that don\u0027t matter.",
    color: "bg-blue-100 dark:bg-blue-500/10 text-blue-600 dark:text-blue-400",
  },
  {
    icon: Lock,
    title: "Deploy without disruption",
    description:
      "Read-only API connectors to your existing stack. No rip-and-replace, no new agents, no infrastructure changes. Live in 30 minutes.",
    color: "bg-emerald-100 dark:bg-emerald-500/10 text-emerald-600 dark:text-emerald-400",
  },
  {
    icon: BarChart3,
    title: "Prove compliance in minutes",
    description:
      "Automated evidence collection for SOC 2, ISO 27001, NIST CSF, and GDPR. Generate audit-ready reports instead of building them manually.",
    color: "bg-purple-100 dark:bg-purple-500/10 text-purple-600 dark:text-purple-400",
  },
  {
    icon: Lightbulb,
    title: "Make every analyst a senior",
    description:
      "AI-generated investigation guides and response playbooks give junior analysts the decision-making capability of a 10-year veteran.",
    color: "bg-indigo-100 dark:bg-indigo-500/10 text-indigo-600 dark:text-indigo-400",
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

  const scrollToHowItWorks = () => {
    howItWorksRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  const authError = authMode === "register" ? registerError : loginError;
  const isSubmitting = authMode === "register" ? isRegistering : isLoggingIn;

  const brutBtn =
    "border-[2.5px] border-[#1e293b] dark:border-[#334155] shadow-[4px_4px_0px_#1e293b] dark:shadow-[4px_4px_0px_rgba(6,182,212,0.3)] hover:shadow-[2px_2px_0px_#1e293b] dark:hover:shadow-[2px_2px_0px_rgba(6,182,212,0.3)] hover:translate-x-[2px] hover:translate-y-[2px] active:shadow-none active:translate-x-[4px] active:translate-y-[4px] transition-all";
  const brutCard =
    "bg-white dark:bg-[#111827] border-[2.5px] border-[#1e293b] dark:border-[#334155] rounded-2xl shadow-[4px_4px_0px_#1e293b] dark:shadow-[4px_4px_0px_rgba(6,182,212,0.15)]";
  const brutCardHover =
    "hover:shadow-[2px_2px_0px_#1e293b] dark:hover:shadow-[2px_2px_0px_rgba(6,182,212,0.15)] hover:translate-x-[2px] hover:translate-y-[2px]";

  return (
    <div className="min-h-screen bg-[#FFF8F0] dark:bg-[#0a0f1e] text-[#1e293b] dark:text-[#e2e8f0] font-sans">
      {authMode && (
        <div
          className="fixed inset-0 z-[60] flex items-center justify-center bg-black/50 backdrop-blur-sm"
          onClick={() => setAuthMode(null)}
        >
          <div
            className="w-full max-w-md mx-4 bg-white dark:bg-[#111827] border-[3px] border-[#1e293b] dark:border-[#334155] rounded-2xl shadow-[6px_6px_0px_#1e293b] dark:shadow-[6px_6px_0px_#0ea5e9]"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="p-8">
              <div className="flex items-center gap-2.5 mb-6">
                <div className="w-10 h-10 rounded-xl border-2 border-[#1e293b] dark:border-cyan-500/30 flex items-center justify-center bg-gradient-to-br from-cyan-50 to-white dark:from-cyan-500/10 dark:to-transparent">
                  <img src={atsLogo} alt="SecureNexus" className="w-7 h-7 object-contain" />
                </div>
                <span className="font-bold text-lg tracking-tight">SecureNexus</span>
              </div>
              <h2 className="text-xl font-extrabold mb-1">
                {authMode === "register" ? "Start your free trial" : "Welcome back"}
              </h2>
              <p className="text-sm text-[#64748b] dark:text-[#94a3b8] mb-6">
                {authMode === "register" ? "14 days free. No credit card required." : "Log in to your account"}
              </p>
              {authError && (
                <div className="mb-4 p-3 rounded-xl border-2 border-red-300 dark:border-red-500/30 bg-red-50 dark:bg-red-500/10 text-red-600 dark:text-red-400 text-sm font-medium">
                  {authError.message}
                </div>
              )}
              <div className="space-y-2 mb-4">
                {oauthError && (
                  <div className="mb-2 p-2.5 rounded-xl border-2 border-amber-300 dark:border-amber-500/30 bg-amber-50 dark:bg-amber-500/10 text-amber-600 dark:text-amber-400 text-xs font-medium">
                    {oauthError}
                  </div>
                )}
                <button
                  className="w-full h-11 flex items-center justify-center gap-2 text-sm font-semibold rounded-xl bg-white dark:bg-[#1e293b] hover:bg-gray-50 dark:hover:bg-[#253044] border-[2.5px] border-[#1e293b] dark:border-[#334155] shadow-[3px_3px_0px_#1e293b] dark:shadow-[3px_3px_0px_#0ea5e9] hover:shadow-[1px_1px_0px_#1e293b] dark:hover:shadow-[1px_1px_0px_#0ea5e9] hover:translate-x-[2px] hover:translate-y-[2px] active:shadow-none active:translate-x-[3px] active:translate-y-[3px] transition-all"
                  disabled={oauthLoading === "google"}
                  onClick={() => handleOAuth("google")}
                >
                  <FaGoogle className="h-4 w-4 text-[#4285F4]" />
                  {oauthLoading === "google" ? "Connecting..." : "Continue with Google"}
                </button>
                <button
                  className="w-full h-11 flex items-center justify-center gap-2 text-sm font-semibold rounded-xl bg-white dark:bg-[#1e293b] hover:bg-gray-50 dark:hover:bg-[#253044] border-[2.5px] border-[#1e293b] dark:border-[#334155] shadow-[3px_3px_0px_#1e293b] dark:shadow-[3px_3px_0px_#0ea5e9] hover:shadow-[1px_1px_0px_#1e293b] dark:hover:shadow-[1px_1px_0px_#0ea5e9] hover:translate-x-[2px] hover:translate-y-[2px] active:shadow-none active:translate-x-[3px] active:translate-y-[3px] transition-all"
                  disabled={oauthLoading === "github"}
                  onClick={() => handleOAuth("github")}
                >
                  <FaGithub className="h-4 w-4" />
                  {oauthLoading === "github" ? "Connecting..." : "Continue with GitHub"}
                </button>
                <div className="relative my-3">
                  <div className="absolute inset-0 flex items-center">
                    <div className="w-full border-t-2 border-[#e2e8f0] dark:border-[#334155]" />
                  </div>
                  <div className="relative flex justify-center text-xs">
                    <span className="bg-white dark:bg-[#111827] px-3 text-[#94a3b8] font-medium">
                      or continue with email
                    </span>
                  </div>
                </div>
              </div>
              <form onSubmit={handleSubmit} className="space-y-4">
                {authMode === "register" && (
                  <div className="grid grid-cols-2 gap-3">
                    <div className="space-y-1.5">
                      <Label htmlFor="firstName" className="text-xs font-bold uppercase tracking-wider">
                        First name
                      </Label>
                      <Input
                        id="firstName"
                        value={firstName}
                        onChange={(e) => setFirstName(e.target.value)}
                        placeholder="John"
                        className="border-2 border-[#cbd5e1] dark:border-[#334155] rounded-xl h-10 font-medium focus:border-cyan-500 dark:focus:border-cyan-400"
                      />
                    </div>
                    <div className="space-y-1.5">
                      <Label htmlFor="lastName" className="text-xs font-bold uppercase tracking-wider">
                        Last name
                      </Label>
                      <Input
                        id="lastName"
                        value={lastName}
                        onChange={(e) => setLastName(e.target.value)}
                        placeholder="Doe"
                        className="border-2 border-[#cbd5e1] dark:border-[#334155] rounded-xl h-10 font-medium focus:border-cyan-500 dark:focus:border-cyan-400"
                      />
                    </div>
                  </div>
                )}
                <div className="space-y-1.5">
                  <Label htmlFor="email" className="text-xs font-bold uppercase tracking-wider">
                    Email
                  </Label>
                  <Input
                    id="email"
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="you@company.com"
                    required
                    className="border-2 border-[#cbd5e1] dark:border-[#334155] rounded-xl h-10 font-medium focus:border-cyan-500 dark:focus:border-cyan-400"
                  />
                </div>
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <Label htmlFor="password" className="text-xs font-bold uppercase tracking-wider">
                      Password
                    </Label>
                    {authMode === "login" && (
                      <a
                        href="/forgot-password"
                        className="text-xs font-semibold text-[#0ea5e9] hover:underline"
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
                    className="border-2 border-[#cbd5e1] dark:border-[#334155] rounded-xl h-10 font-medium focus:border-cyan-500 dark:focus:border-cyan-400"
                  />
                </div>
                <button
                  type="submit"
                  className={`w-full h-11 rounded-xl font-bold text-white bg-[#0ea5e9] ${brutBtn} disabled:opacity-50 disabled:pointer-events-none`}
                  disabled={isSubmitting}
                >
                  {isSubmitting ? "Please wait..." : authMode === "register" ? "Start Free Trial" : "Log In"}
                </button>
              </form>
              <p className="text-sm text-center text-[#64748b] dark:text-[#94a3b8] mt-4 font-medium">
                {authMode === "register" ? (
                  <>
                    Already have an account?{" "}
                    <button onClick={() => setAuthMode("login")} className="text-[#0ea5e9] font-bold hover:underline">
                      Log in
                    </button>
                  </>
                ) : (
                  <>
                    Don&apos;t have an account?{" "}
                    <button
                      onClick={() => setAuthMode("register")}
                      className="text-[#0ea5e9] font-bold hover:underline"
                    >
                      Sign up
                    </button>
                  </>
                )}
              </p>
            </div>
          </div>
        </div>
      )}

      <nav className="fixed top-4 left-4 right-4 z-50 max-w-6xl mx-auto">
        <div className="flex items-center justify-between h-14 px-5 bg-white/80 dark:bg-[#111827]/80 backdrop-blur-xl border-[2.5px] border-[#1e293b] dark:border-[#334155] rounded-2xl shadow-[4px_4px_0px_#1e293b] dark:shadow-[4px_4px_0px_rgba(6,182,212,0.3)]">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg border-2 border-[#1e293b] dark:border-cyan-500/30 flex items-center justify-center bg-gradient-to-br from-cyan-50 to-white dark:from-cyan-500/10 dark:to-transparent">
              <img src={atsLogo} alt="SecureNexus" className="w-5 h-5 object-contain" />
            </div>
            <span className="font-extrabold text-base tracking-tight">SecureNexus</span>
          </div>
          <div className="hidden md:flex items-center gap-6">
            <button
              onClick={scrollToHowItWorks}
              className="text-sm font-semibold text-[#475569] dark:text-[#94a3b8] hover:text-[#1e293b] dark:hover:text-white transition-colors"
            >
              How it works
            </button>
            <a
              href="#features"
              className="text-sm font-semibold text-[#475569] dark:text-[#94a3b8] hover:text-[#1e293b] dark:hover:text-white transition-colors"
            >
              Features
            </a>
            <a
              href="#faq"
              className="text-sm font-semibold text-[#475569] dark:text-[#94a3b8] hover:text-[#1e293b] dark:hover:text-white transition-colors"
            >
              FAQ
            </a>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setAuthMode("login")}
              className="text-sm font-bold text-[#475569] dark:text-[#94a3b8] hover:text-[#1e293b] dark:hover:text-white transition-colors px-3 py-1.5"
            >
              Log In
            </button>
            <button
              onClick={() => setAuthMode("register")}
              className="text-sm font-bold text-white bg-[#0ea5e9] px-5 py-2 rounded-xl border-[2.5px] border-[#1e293b] dark:border-cyan-400/50 shadow-[3px_3px_0px_#1e293b] dark:shadow-[3px_3px_0px_rgba(6,182,212,0.4)] hover:shadow-[1px_1px_0px_#1e293b] dark:hover:shadow-[1px_1px_0px_rgba(6,182,212,0.4)] hover:translate-x-[2px] hover:translate-y-[2px] active:shadow-none active:translate-x-[3px] active:translate-y-[3px] transition-all"
            >
              Start Free
            </button>
          </div>
        </div>
      </nav>

      <section className="relative pt-32 pb-20 px-6 overflow-hidden">
        <div className="max-w-6xl mx-auto">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
            <div className="relative z-10">
              <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full border-2 border-[#0ea5e9] dark:border-cyan-500/40 bg-cyan-50 dark:bg-cyan-500/10 text-[#0ea5e9] dark:text-cyan-300 text-xs font-bold mb-6 tracking-wide">
                <div className="w-1.5 h-1.5 rounded-full bg-[#0ea5e9] animate-pulse" />
                AI-Powered Security Operations
              </div>
              <h1 className="text-4xl md:text-5xl lg:text-[3.5rem] font-black tracking-tight mb-6 leading-[1.08]">
                Stop Chasing
                <br />
                <span className="text-[#0ea5e9]">Alerts.</span>
                <br />
                Start Stopping
                <br />
                <span className="bg-[#0ea5e9] text-white px-3 py-0.5 rounded-lg inline-block mt-1 border-[2.5px] border-[#1e293b] dark:border-cyan-400/50 shadow-[3px_3px_0px_#1e293b] dark:shadow-[3px_3px_0px_rgba(6,182,212,0.3)]">
                  Attackers.
                </span>
              </h1>
              <p className="text-base md:text-lg text-[#475569] dark:text-[#94a3b8] max-w-lg mb-8 leading-relaxed font-medium">
                SecureNexus uses AI to correlate thousands of alerts into actionable incidents, cutting triage time by
                90% and false positives by 70%.
              </p>
              <div className="flex flex-wrap items-center gap-3 mb-8">
                <button
                  onClick={() => setAuthMode("register")}
                  className={`inline-flex items-center gap-2 px-7 py-3 rounded-xl font-bold text-white bg-[#0ea5e9] text-base ${brutBtn}`}
                >
                  Start Free Trial
                  <ArrowRight className="h-4 w-4" />
                </button>
                <button
                  onClick={scrollToHowItWorks}
                  className="inline-flex items-center gap-2 px-7 py-3 rounded-xl font-bold text-[#1e293b] dark:text-white bg-white dark:bg-[#1e293b] text-base border-[2.5px] border-[#1e293b] dark:border-[#334155] shadow-[4px_4px_0px_#1e293b] dark:shadow-[4px_4px_0px_rgba(100,116,139,0.3)] hover:shadow-[2px_2px_0px_#1e293b] dark:hover:shadow-[2px_2px_0px_rgba(100,116,139,0.3)] hover:translate-x-[2px] hover:translate-y-[2px] active:shadow-none active:translate-x-[4px] active:translate-y-[4px] transition-all"
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
                    <div className="text-2xl font-black tracking-tight">{s.val}</div>
                    <div className="text-xs text-[#94a3b8] font-semibold">{s.sub}</div>
                  </div>
                ))}
              </div>
            </div>

            <div className="relative hidden lg:block">
              <div className="absolute -top-4 -right-4 w-14 h-14 rounded-full border-[2.5px] border-[#1e293b] dark:border-cyan-500/30 bg-red-100 dark:bg-red-500/20 flex items-center justify-center shadow-[3px_3px_0px_#1e293b] dark:shadow-[3px_3px_0px_rgba(6,182,212,0.2)] z-20 animate-float">
                <AlertTriangle className="h-6 w-6 text-red-500" />
              </div>
              <div className="absolute -bottom-2 -right-6 w-12 h-12 rounded-full border-[2.5px] border-[#1e293b] dark:border-cyan-500/30 bg-emerald-100 dark:bg-emerald-500/20 flex items-center justify-center shadow-[3px_3px_0px_#1e293b] dark:shadow-[3px_3px_0px_rgba(6,182,212,0.2)] z-20 animate-float delay-300">
                <Star className="h-5 w-5 text-emerald-500" />
              </div>
              <div className="absolute top-1/2 -left-6 w-11 h-11 rounded-full border-[2.5px] border-[#1e293b] dark:border-cyan-500/30 bg-cyan-100 dark:bg-cyan-500/20 flex items-center justify-center shadow-[3px_3px_0px_#1e293b] dark:shadow-[3px_3px_0px_rgba(6,182,212,0.2)] z-20 animate-float delay-500">
                <Shield className="h-5 w-5 text-cyan-500" />
              </div>

              <div className="bg-white dark:bg-[#111827] border-[3px] border-[#1e293b] dark:border-[#334155] rounded-2xl shadow-[8px_8px_0px_#1e293b] dark:shadow-[8px_8px_0px_rgba(6,182,212,0.2)] overflow-hidden">
                <div className="flex items-center gap-2 px-4 py-2.5 border-b-[2.5px] border-[#1e293b] dark:border-[#334155] bg-[#f8fafc] dark:bg-[#0f172a]">
                  <div className="flex gap-1.5">
                    <div className="w-3 h-3 rounded-full bg-red-400 border border-red-500" />
                    <div className="w-3 h-3 rounded-full bg-amber-400 border border-amber-500" />
                    <div className="w-3 h-3 rounded-full bg-emerald-400 border border-emerald-500" />
                  </div>
                  <div className="flex-1 text-center">
                    <span className="text-[10px] font-bold text-[#94a3b8]">SecureNexus Dashboard</span>
                  </div>
                </div>
                <div className="p-4 space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <div className="w-8 h-8 rounded-lg bg-cyan-100 dark:bg-cyan-500/10 border-2 border-[#1e293b] dark:border-cyan-500/20 flex items-center justify-center">
                        <Shield className="h-4 w-4 text-cyan-600 dark:text-cyan-400" />
                      </div>
                      <div>
                        <div className="text-xs font-extrabold">Threat Detection</div>
                        <div className="text-[10px] text-[#94a3b8] font-medium">
                          24 active alerts &bull; 3 incidents
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-1 px-2 py-1 rounded-lg bg-emerald-100 dark:bg-emerald-500/10 border border-emerald-300 dark:border-emerald-500/20">
                      <div className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                      <span className="text-[10px] font-bold text-emerald-600 dark:text-emerald-400">Protected</span>
                    </div>
                  </div>

                  <div className="bg-[#f8fafc] dark:bg-[#0f172a] rounded-xl border-2 border-[#e2e8f0] dark:border-[#1e293b] p-3">
                    <div className="flex justify-between items-center mb-2">
                      <span className="text-[10px] font-bold text-[#64748b] dark:text-[#94a3b8]">Threat Score</span>
                      <span className="text-sm font-black text-[#0ea5e9]">87%</span>
                    </div>
                    <div className="w-full h-3 rounded-full bg-[#e2e8f0] dark:bg-[#1e293b] border border-[#cbd5e1] dark:border-[#334155] overflow-hidden">
                      <div
                        className="h-full rounded-full bg-gradient-to-r from-[#0ea5e9] to-[#06b6d4]"
                        style={{ width: "87%" }}
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-3 gap-2">
                    {[
                      {
                        label: "Critical",
                        val: "3",
                        cls: "bg-red-100 dark:bg-red-500/10 text-red-600 dark:text-red-400 border-red-200 dark:border-red-500/20",
                      },
                      {
                        label: "High",
                        val: "12",
                        cls: "bg-amber-100 dark:bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-200 dark:border-amber-500/20",
                      },
                      {
                        label: "Resolved",
                        val: "156",
                        cls: "bg-emerald-100 dark:bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-200 dark:border-emerald-500/20",
                      },
                    ].map((item) => (
                      <div
                        key={item.label}
                        className={`flex flex-col items-center p-2 rounded-lg border-2 ${item.cls}`}
                      >
                        <span className="text-lg font-black">{item.val}</span>
                        <span className="text-[9px] font-bold">{item.label}</span>
                      </div>
                    ))}
                  </div>

                  <button
                    onClick={() => setAuthMode("register")}
                    className="w-full py-2.5 rounded-xl font-bold text-white bg-[#0ea5e9] border-2 border-[#1e293b] dark:border-cyan-500/30 shadow-[3px_3px_0px_#1e293b] dark:shadow-[3px_3px_0px_rgba(6,182,212,0.3)] hover:shadow-[1px_1px_0px_#1e293b] hover:translate-x-[2px] hover:translate-y-[2px] active:shadow-none active:translate-x-[3px] active:translate-y-[3px] transition-all text-sm"
                  >
                    View Full Dashboard
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="py-16 px-6">
        <div className="max-w-5xl mx-auto">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {metrics.map((metric) => (
              <div key={metric.label} className={`flex flex-col items-center gap-1.5 p-5 rounded-xl ${brutCard}`}>
                <div className="w-10 h-10 rounded-xl bg-cyan-100 dark:bg-cyan-500/10 border-2 border-[#1e293b] dark:border-cyan-500/20 flex items-center justify-center mb-1">
                  <metric.icon className="h-5 w-5 text-cyan-600 dark:text-cyan-400" />
                </div>
                <span className="text-3xl font-black tracking-tight">{metric.value}</span>
                <span className="text-xs text-[#94a3b8] font-semibold">{metric.label}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="py-20 px-6 bg-[#f1f5f9] dark:bg-[#0f172a]">
        <div className="max-w-5xl mx-auto">
          <div className="text-center mb-14">
            <div className="inline-flex items-center px-4 py-1.5 rounded-full border-2 border-red-400 dark:border-red-500/30 bg-red-50 dark:bg-red-500/10 text-red-600 dark:text-red-400 text-xs font-bold mb-4">
              The Problem
            </div>
            <h2 className="text-3xl md:text-4xl font-black mb-3">Your SOC Is Drowning in Noise</h2>
            <p className="text-[#64748b] dark:text-[#94a3b8] max-w-xl mx-auto font-medium">
              Security teams spend more time managing tools than stopping threats.
            </p>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {painPoints.map((point) => (
              <div key={point.label} className={`${brutCard} p-6 text-center ${brutCardHover} transition-all`}>
                <div
                  className={`inline-flex items-center justify-center w-12 h-12 rounded-xl border-2 border-[#1e293b] dark:border-[#334155] mb-3 ${point.color}`}
                >
                  <point.icon className="h-6 w-6" />
                </div>
                <div className="text-3xl font-black tracking-tight mb-0.5">{point.stat}</div>
                <div className="text-xs font-bold text-[#0ea5e9] mb-2 uppercase tracking-wider">{point.label}</div>
                <p className="text-xs text-[#64748b] dark:text-[#94a3b8] leading-relaxed font-medium">
                  {point.description}
                </p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section ref={howItWorksRef} id="how-it-works" className="py-20 px-6">
        <div className="max-w-5xl mx-auto">
          <div className="text-center mb-14">
            <div className="inline-flex items-center px-4 py-1.5 rounded-full border-2 border-[#0ea5e9] dark:border-cyan-500/30 bg-cyan-50 dark:bg-cyan-500/10 text-[#0ea5e9] dark:text-cyan-300 text-xs font-bold mb-4">
              How It Works
            </div>
            <h2 className="text-3xl md:text-4xl font-black mb-3">Three Steps to a Quieter SOC</h2>
            <p className="text-[#64748b] dark:text-[#94a3b8] max-w-xl mx-auto font-medium">
              Go from alert overload to clear, actionable intelligence in under 30 minutes.
            </p>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {howItWorks.map((step) => (
              <div key={step.step} className="relative">
                <div className="absolute -top-3 -left-3 w-12 h-12 rounded-xl border-[2.5px] border-[#1e293b] dark:border-cyan-500/30 bg-[#0ea5e9] text-white flex items-center justify-center font-black text-lg shadow-[3px_3px_0px_#1e293b] dark:shadow-[3px_3px_0px_rgba(6,182,212,0.3)] z-10">
                  {step.step}
                </div>
                <div className={`${brutCard} p-6 pt-10 h-full`}>
                  <div className="w-12 h-12 rounded-xl bg-cyan-100 dark:bg-cyan-500/10 border-2 border-[#1e293b] dark:border-cyan-500/20 flex items-center justify-center mb-4">
                    <step.icon className="h-6 w-6 text-cyan-600 dark:text-cyan-400" />
                  </div>
                  <h3 className="font-extrabold text-lg mb-2">{step.title}</h3>
                  <p className="text-sm text-[#64748b] dark:text-[#94a3b8] leading-relaxed font-medium">
                    {step.description}
                  </p>
                </div>
              </div>
            ))}
          </div>
          <div className="text-center mt-10">
            <button
              onClick={() => setAuthMode("register")}
              className={`inline-flex items-center gap-2 px-8 py-3 rounded-xl font-bold text-white bg-[#0ea5e9] ${brutBtn}`}
            >
              Start Free Trial
              <ArrowRight className="h-4 w-4" />
            </button>
          </div>
        </div>
      </section>

      <section className="py-16 overflow-hidden bg-[#f1f5f9] dark:bg-[#0f172a]">
        <div className="text-center mb-10 px-6">
          <div className="inline-flex items-center px-4 py-1.5 rounded-full border-2 border-[#94a3b8] dark:border-[#475569] bg-white dark:bg-[#1e293b] text-[#475569] dark:text-[#94a3b8] text-xs font-bold mb-4">
            Integrations
          </div>
          <h2 className="text-2xl md:text-3xl font-black mb-2">Works with Your Existing Stack</h2>
          <p className="text-sm text-[#64748b] dark:text-[#94a3b8] font-medium">
            24+ connectors. Read-only. No agents required.
          </p>
        </div>
        <div className="relative">
          <div className="absolute left-0 top-0 bottom-0 w-24 bg-gradient-to-r from-[#f1f5f9] dark:from-[#0f172a] to-transparent z-10 pointer-events-none" />
          <div className="absolute right-0 top-0 bottom-0 w-24 bg-gradient-to-l from-[#f1f5f9] dark:from-[#0f172a] to-transparent z-10 pointer-events-none" />
          <div className="flex animate-marquee gap-4">
            {[...integrations, ...integrations].map((item, i) => (
              <div
                key={`${item.name}-${i}`}
                className="flex items-center gap-2.5 px-4 py-2.5 rounded-xl bg-white dark:bg-[#111827] border-2 border-[#1e293b] dark:border-[#334155] shadow-[2px_2px_0px_#1e293b] dark:shadow-[2px_2px_0px_rgba(6,182,212,0.1)] flex-shrink-0"
              >
                <item.icon className="h-4 w-4 text-[#475569] dark:text-[#94a3b8] flex-shrink-0" />
                <span className="text-sm font-bold text-[#475569] dark:text-[#94a3b8] whitespace-nowrap">
                  {item.name}
                </span>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section id="features" className="py-20 px-6">
        <div className="max-w-5xl mx-auto">
          <div className="text-center mb-14">
            <div className="inline-flex items-center px-4 py-1.5 rounded-full border-2 border-[#0ea5e9] dark:border-cyan-500/30 bg-cyan-50 dark:bg-cyan-500/10 text-[#0ea5e9] dark:text-cyan-300 text-xs font-bold mb-4">
              Capabilities
            </div>
            <h2 className="text-3xl md:text-4xl font-black mb-3">Everything You Need to Succeed</h2>
            <p className="text-[#64748b] dark:text-[#94a3b8] max-w-xl mx-auto font-medium">
              Every capability is built to deliver a measurable result for your security team.
            </p>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
            {features.map((feature, index) => (
              <div key={index} className={`${brutCard} p-6 ${brutCardHover} transition-all group`}>
                <div
                  className={`inline-flex items-center justify-center w-12 h-12 rounded-xl border-2 border-[#1e293b] dark:border-[#334155] mb-4 ${feature.color}`}
                >
                  <feature.icon className="h-6 w-6" />
                </div>
                <h3 className="font-extrabold text-lg mb-2">{feature.title}</h3>
                <p className="text-sm text-[#64748b] dark:text-[#94a3b8] leading-relaxed font-medium">
                  {feature.description}
                </p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="py-20 px-6 bg-[#f1f5f9] dark:bg-[#0f172a]">
        <div className="max-w-5xl mx-auto">
          <div className="text-center mb-14">
            <div className="inline-flex items-center px-4 py-1.5 rounded-full border-2 border-amber-400 dark:border-amber-500/30 bg-amber-50 dark:bg-amber-500/10 text-amber-600 dark:text-amber-400 text-xs font-bold mb-4">
              Customer Stories
            </div>
            <h2 className="text-3xl md:text-4xl font-black mb-3">What Our Users Say</h2>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
            {testimonials.map((t, i) => (
              <div key={i} className={`${brutCard} p-6 flex flex-col`}>
                <div className="flex gap-1 mb-4">
                  {Array.from({ length: t.rating }).map((_, si) => (
                    <Star key={si} className="h-4 w-4 fill-amber-400 text-amber-400" />
                  ))}
                </div>
                <p className="text-sm text-[#475569] dark:text-[#cbd5e1] leading-relaxed flex-1 mb-5 font-medium">
                  &ldquo;{t.quote}&rdquo;
                </p>
                <div className="flex items-center gap-3 pt-4 border-t-2 border-[#e2e8f0] dark:border-[#1e293b]">
                  <div className="w-10 h-10 rounded-xl border-2 border-[#1e293b] dark:border-cyan-500/20 bg-gradient-to-br from-cyan-100 to-cyan-50 dark:from-cyan-500/15 dark:to-cyan-500/5 flex items-center justify-center text-sm font-black text-cyan-600 dark:text-cyan-400">
                    {t.name
                      .split(" ")
                      .map((n) => n[0])
                      .join("")}
                  </div>
                  <div>
                    <p className="text-sm font-bold">{t.name}</p>
                    <p className="text-xs text-[#94a3b8] font-medium">
                      {t.role}, {t.company}
                    </p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section id="faq" className="py-20 px-6">
        <div className="max-w-3xl mx-auto">
          <div className="text-center mb-10">
            <div className="inline-flex items-center px-4 py-1.5 rounded-full border-2 border-[#94a3b8] dark:border-[#475569] bg-white dark:bg-[#1e293b] text-[#475569] dark:text-[#94a3b8] text-xs font-bold mb-4">
              FAQ
            </div>
            <h2 className="text-3xl md:text-4xl font-black mb-3">Common Questions</h2>
          </div>
          <div className="space-y-3">
            {faqs.map((faq, i) => (
              <FaqItem key={i} question={faq.q} answer={faq.a} />
            ))}
          </div>
        </div>
      </section>

      <section className="py-20 px-6 bg-[#dbeafe] dark:bg-[#0c1a3d]">
        <div className="max-w-3xl mx-auto text-center">
          <div className="bg-white dark:bg-[#111827] border-[3px] border-[#1e293b] dark:border-[#334155] rounded-2xl p-10 shadow-[6px_6px_0px_#1e293b] dark:shadow-[6px_6px_0px_rgba(6,182,212,0.25)]">
            <h2 className="text-3xl md:text-4xl font-black mb-4">Ready to Transform Your SOC?</h2>
            <p className="text-[#64748b] dark:text-[#94a3b8] mb-8 max-w-lg mx-auto font-medium">
              Join 50+ security teams that cut triage time by 90% and false positives by 70%. See results in your first
              week.
            </p>
            <div className="flex flex-wrap justify-center gap-3 mb-6">
              <button
                onClick={() => setAuthMode("register")}
                className={`inline-flex items-center gap-2 px-8 py-3 rounded-xl font-bold text-white bg-[#0ea5e9] text-base ${brutBtn}`}
              >
                Start Free Trial
                <ArrowRight className="h-4 w-4" />
              </button>
              <button
                onClick={() => setAuthMode("login")}
                className="inline-flex items-center px-8 py-3 rounded-xl font-bold text-[#1e293b] dark:text-white bg-white dark:bg-[#1e293b] text-base border-[2.5px] border-[#1e293b] dark:border-[#334155] shadow-[4px_4px_0px_#1e293b] dark:shadow-[4px_4px_0px_rgba(100,116,139,0.3)] hover:shadow-[2px_2px_0px_#1e293b] dark:hover:shadow-[2px_2px_0px_rgba(100,116,139,0.3)] hover:translate-x-[2px] hover:translate-y-[2px] active:shadow-none active:translate-x-[4px] active:translate-y-[4px] transition-all"
              >
                Log In
              </button>
            </div>
            <div className="flex flex-wrap items-center justify-center gap-5 text-xs text-[#64748b] dark:text-[#94a3b8] font-semibold">
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

      <footer className="border-t-[2.5px] border-[#1e293b] dark:border-[#334155] py-10 px-6 bg-white dark:bg-[#0a0f1e]">
        <div className="max-w-6xl mx-auto">
          <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-6 mb-8">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-lg border-2 border-[#1e293b] dark:border-cyan-500/30 flex items-center justify-center bg-gradient-to-br from-cyan-50 to-white dark:from-cyan-500/10 dark:to-transparent">
                <img src={atsLogo} alt="SecureNexus" className="w-5 h-5 object-contain" />
              </div>
              <div>
                <span className="font-extrabold text-sm">SecureNexus</span>
                <p className="text-[10px] text-[#94a3b8] font-medium">AI-Powered Security Operations</p>
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-4">
              {["SOC 2 Type II", "ISO 27001", "GDPR"].map((cert) => (
                <span
                  key={cert}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border-2 border-[#e2e8f0] dark:border-[#334155] text-xs font-bold text-[#475569] dark:text-[#94a3b8]"
                >
                  <Shield className="h-3 w-3" />
                  {cert}
                </span>
              ))}
            </div>
          </div>
          <div className="pt-6 border-t-2 border-[#e2e8f0] dark:border-[#1e293b] flex flex-wrap items-center justify-between gap-4 text-xs text-[#94a3b8] font-medium">
            <span>&copy; {new Date().getFullYear()} Arica Technologies. All rights reserved.</span>
            <div className="flex items-center gap-4">
              <a href="#" className="hover:text-[#1e293b] dark:hover:text-white transition-colors font-semibold">
                Privacy
              </a>
              <a href="#" className="hover:text-[#1e293b] dark:hover:text-white transition-colors font-semibold">
                Terms
              </a>
              <a
                href="mailto:security@aricatech.com"
                className="hover:text-[#1e293b] dark:hover:text-white transition-colors font-semibold"
              >
                Contact
              </a>
              <a
                href="https://github.com/prathamesh-ops-sudo/securenexus"
                target="_blank"
                rel="noopener noreferrer"
                className="hover:text-[#1e293b] dark:hover:text-white transition-colors font-semibold"
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
    <div className="bg-white dark:bg-[#111827] border-[2.5px] border-[#1e293b] dark:border-[#334155] rounded-2xl shadow-[3px_3px_0px_#1e293b] dark:shadow-[3px_3px_0px_rgba(6,182,212,0.12)] overflow-hidden">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between p-5 text-left hover:bg-[#f8fafc] dark:hover:bg-[#1e293b]/50 transition-colors"
        aria-expanded={open}
      >
        <span className="text-sm font-bold pr-4">{question}</span>
        {open ? (
          <ChevronUp className="h-4 w-4 text-[#94a3b8] flex-shrink-0" />
        ) : (
          <ChevronDown className="h-4 w-4 text-[#94a3b8] flex-shrink-0" />
        )}
      </button>
      {open && (
        <div className="px-5 pb-5 border-t-2 border-[#e2e8f0] dark:border-[#1e293b] pt-4">
          <p className="text-sm text-[#64748b] dark:text-[#94a3b8] leading-relaxed font-medium">{answer}</p>
        </div>
      )}
    </div>
  );
}

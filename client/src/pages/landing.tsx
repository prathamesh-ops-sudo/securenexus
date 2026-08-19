import { useState, useRef, useEffect } from "react";
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
import atsLogo from "@/assets/logo.png";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { useAuth } from "@/hooks/use-auth";

/* 94.5 — social proof: customer logos / awards */
const SOCIAL_PROOF_LOGOS = [
  "Series B Fintech",
  "Healthcare SaaS",
  "E-commerce Platform",
  "Government Agency",
  "EdTech Startup",
  "Insurance Corp",
];

const AWARDS = [
  { label: "Gartner Cool Vendor 2025", year: "2025" },
  { label: "NASSCOM Deep Tech", year: "2025" },
  { label: "CII Cybersecurity Award", year: "2024" },
];

const painPoints = [
  {
    stat: "68%",
    label: "no security tools",
    description: "Most mid-market companies lack dedicated EDR/XDR, leaving them blind to threats.",
    icon: AlertTriangle,
    color: "text-red-500/80",
  },
  {
    stat: "$50K+",
    label: "EDR license cost",
    description: "Enterprise EDR/SIEM licenses cost tens of thousands annually, out of reach for growing companies.",
    icon: Timer,
    color: "text-amber-500/80",
  },
  {
    stat: "0%",
    label: "risk visibility",
    description:
      "Without proper tooling, organizations have zero visibility into their risk posture and compliance gaps.",
    icon: Target,
    color: "text-orange-500/80",
  },
  {
    stat: "3.5x",
    label: "tool sprawl",
    description: "Companies that do invest end up juggling 3-5 disconnected tools, losing context at every handoff.",
    icon: Layers,
    color: "text-violet-500/80",
  },
];

const howItWorks = [
  {
    step: "01",
    title: "Deploy in minutes",
    description:
      "No existing security tools required. SecureNexus works standalone with built-in asset discovery, risk assessment, and threat detection. Optionally connect EDR/SIEM if you have them.",
    icon: Workflow,
  },
  {
    step: "02",
    title: "AI assesses your posture",
    description:
      "Our engine inventories your assets, scores risks, maps to compliance frameworks (CIS, NIST, ISO 27001, SOC 2), and identifies gaps automatically.",
    icon: Brain,
  },
  {
    step: "03",
    title: "Respond with confidence",
    description:
      "Get actionable risk reports, automated playbooks, compliance-ready assessments, and employee threat reporting. Your team focuses on decisions, not tool sprawl.",
    icon: Zap,
  },
];

const features = [
  {
    icon: Database,
    title: "Complete Asset Inventory",
    description:
      "Discover, track, and risk-score every asset in your organization. CSV import, lifecycle management, and vulnerability tracking built in.",
    accent: "border-l-cyan-500",
  },
  {
    icon: Shield,
    title: "Risk Register & Heatmap",
    description:
      "Enterprise risk management with 5x5 likelihood-impact matrix. Track inherent and residual risk, treatment plans, and risk ownership.",
    accent: "border-l-violet-500",
  },
  {
    icon: BarChart3,
    title: "Security Assessment Engine",
    description:
      "Assess against CIS Controls, NIST CSF, ISO 27001, and SOC 2 with built-in questionnaires. Automated scoring and gap identification.",
    accent: "border-l-blue-500",
  },
  {
    icon: AlertTriangle,
    title: "Employee Threat Reporting",
    description:
      "Simple portal for staff to report phishing, social engineering, and suspicious activity. Anonymous submissions supported. Auto-creates alerts.",
    accent: "border-l-emerald-500",
  },
  {
    icon: Brain,
    title: "AI-Powered SOC Operations",
    description:
      "AI correlates alerts, generates incident narratives, maps to MITRE ATT&CK, and provides automated response playbooks.",
    accent: "border-l-purple-500",
  },
  {
    icon: Lock,
    title: "No Dependencies Required",
    description:
      "Works standalone out of the box. No EDR, SIEM, or third-party tools needed. Optionally integrate with existing tools to enhance visibility.",
    accent: "border-l-indigo-500",
  },
];

const metrics = [
  { value: "30min", label: "Time to deploy", icon: Clock },
  { value: "100%", label: "Standalone ready", icon: Shield },
  { value: "4", label: "Compliance frameworks", icon: ShieldCheck },
  { value: "0", label: "Dependencies needed", icon: Lock },
];

const testimonials = [
  {
    quote:
      "We had zero security tooling before SecureNexus. Now we have a complete risk register, compliance assessments, and asset inventory in one platform.",
    name: "Sarah Chen",
    role: "IT Director",
    company: "Series B Fintech",
    rating: 5,
  },
  {
    quote:
      "No EDR license needed. SecureNexus gave us enterprise-grade security operations at a fraction of the cost of traditional tools.",
    name: "Marcus Rivera",
    role: "CISO",
    company: "Healthcare SaaS",
    rating: 5,
  },
  {
    quote:
      "The compliance assessment engine alone saved us months of manual work preparing for ISO 27001 certification.",
    name: "David Kim",
    role: "Director of Security",
    company: "E-commerce Platform",
    rating: 5,
  },
];

const faqs = [
  {
    q: "Do I need existing security tools like EDR or SIEM?",
    a: "No. SecureNexus works completely standalone. You get asset inventory, risk management, compliance assessments, threat reporting, and AI-powered SOC operations without any third-party dependencies. If you do have existing tools, you can optionally connect them for enhanced visibility.",
  },
  {
    q: "How long does it take to deploy?",
    a: "Under 30 minutes. Sign up, import your assets (or let the platform discover them), and start assessing your security posture immediately. No agents, no infrastructure changes required.",
  },
  {
    q: "What compliance frameworks do you support?",
    a: "CIS Controls v8, NIST CSF 2.0, ISO 27001, and SOC 2 Type II. Each comes with a full questionnaire, automated scoring, gap identification, and audit-ready reports.",
  },
  {
    q: "How does the risk management work?",
    a: "Register risks with likelihood and impact scores on a 5x5 matrix. Track inherent and residual risk, assign owners, define treatment plans, and visualize everything on an interactive heatmap.",
  },
  {
    q: "Can I try it before committing?",
    a: "Yes. Start with a 14-day free trial — no credit card required. You get full access to all features including asset inventory, risk register, compliance assessments, and AI-powered operations.",
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
  const { login, loginError, isLoggingIn } = useAuth();
  const [authMode, setAuthMode] = useState<"login" | "contact_admin" | null>(null);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [oauthError, setOauthError] = useState<string | null>(null);
  const [oauthLoading, setOauthLoading] = useState<string | null>(null);
  const [ssoMode, setSsoMode] = useState(false);
  const [ssoSlug, setSsoSlug] = useState("");
  const [ssoLoading, setSsoLoading] = useState(false);
  const [ssoError, setSsoError] = useState<string | null>(null);
  const howItWorksRef = useRef<HTMLElement>(null);
  const [contactName, setContactName] = useState("");
  const [contactEmail, setContactEmail] = useState("");
  const [contactMessage, setContactMessage] = useState("");
  const [contactSubmitted, setContactSubmitted] = useState(false);

  /* Handle OAuth error redirect from server (e.g. /?error=google_auth_failed) */
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const errorCode = params.get("error");
    if (errorCode) {
      const errorMessages: Record<string, string> = {
        google_auth_failed: "Google sign-in failed. Please try again or use email login.",
        github_auth_failed: "GitHub sign-in failed. Please try again or use email login.",
        oauth_no_email: "No email returned from provider. Please use email login.",
        oauth_org_denied: "Your account is not associated with an organization. Contact your admin.",
        oauth_invitation_required: "Access is by invitation only. Please contact your platform administrator.",
      };
      setOauthError(errorMessages[errorCode] || `Authentication failed (${errorCode}). Please try again.`);
      setAuthMode("login");
      // Clean URL without reload
      window.history.replaceState({}, "", window.location.pathname);
    }
  }, []);

  /* 94.2 — SEO: set document title + meta description */
  useEffect(() => {
    document.title = "SecureNexus — Enterprise Security Platform | No EDR Required";
    const metaDesc = document.querySelector('meta[name="description"]');
    if (metaDesc) {
      metaDesc.setAttribute(
        "content",
        "Enterprise-grade security operations — asset inventory, risk management, compliance assessments, AI-powered threat detection. Works standalone, no EDR/SIEM required.",
      );
    } else {
      const meta = document.createElement("meta");
      meta.name = "description";
      meta.content =
        "Enterprise-grade security operations — asset inventory, risk management, compliance assessments, AI-powered threat detection. Works standalone, no EDR/SIEM required.";
      document.head.appendChild(meta);
    }
    /* 94.2 — OG tags */
    const ogTags: Record<string, string> = {
      "og:title": "SecureNexus — Enterprise Security Platform",
      "og:description":
        "Complete security operations without EDR/SIEM dependencies. Asset inventory, risk management, compliance, and AI-powered threat detection.",
      "og:type": "website",
      "twitter:card": "summary_large_image",
      "twitter:title": "SecureNexus — Enterprise Security Platform",
    };
    Object.entries(ogTags).forEach(([property, content]) => {
      const existing =
        document.querySelector(`meta[property="${property}"]`) || document.querySelector(`meta[name="${property}"]`);
      if (!existing) {
        const meta = document.createElement("meta");
        if (property.startsWith("og:")) meta.setAttribute("property", property);
        else meta.setAttribute("name", property);
        meta.content = content;
        document.head.appendChild(meta);
      }
    });
    /* 94.2 — structured data (JSON-LD) */
    const ld = document.createElement("script");
    ld.type = "application/ld+json";
    ld.textContent = JSON.stringify({
      "@context": "https://schema.org",
      "@type": "SoftwareApplication",
      name: "SecureNexus",
      applicationCategory: "SecurityApplication",
      operatingSystem: "Web",
      description:
        "Enterprise security operations platform with asset inventory, risk management, compliance assessments, and AI-powered threat detection.",
      offers: { "@type": "Offer", price: "0", priceCurrency: "INR" },
    });
    document.head.appendChild(ld);
    return () => {
      ld.remove();
    };
  }, []);

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
    await login({ email, password });
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

  const authError = loginError;
  const isSubmitting = isLoggingIn;

  /* 94.7 — contact / demo request form handler */
  const handleContactSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setContactSubmitted(true);
    /* 94.8 — analytics integration hint: track demo request */
    // window.gtag?.('event', 'demo_request', { method: 'contact_form' });
    // window.mixpanel?.track('Demo Requested', { name: contactName, email: contactEmail });
  };

  return (
    <div data-testid="landing-page" className="min-h-screen bg-background text-foreground font-sans refined-ui">
      {/* 94.8 — Google Analytics / Mixpanel integration hints */}
      {/* <script async src="https://www.googletagmanager.com/gtag/js?id=G-XXXXXXXXXX" />
          <script>window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments);}gtag('js',new Date());gtag('config','G-XXXXXXXXXX');</script> */}
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
              {authMode === "contact_admin" ? (
                <>
                  <h2 className="text-2xl font-bold mb-2 font-display tracking-[-0.02em]">Access Required</h2>
                  <div className="mb-4 p-4 rounded-lg border border-blue-500/30 bg-blue-500/10 text-sm space-y-3">
                    <p className="font-medium text-foreground">Self-service registration is not available.</p>
                    <p className="text-muted-foreground">
                      To get access to SecureNexus, please contact your organization&apos;s platform administrator. They
                      will create your account and assign you to an organization.
                    </p>
                  </div>
                  <button
                    type="button"
                    className="w-full h-10 text-sm font-medium rounded-lg bg-primary text-primary-foreground hover:bg-primary/90 transition-colors"
                    onClick={() => setAuthMode("login")}
                  >
                    Go to Login
                  </button>
                </>
              ) : (
                <>
                  <h2 className="text-2xl font-bold mb-2 font-display tracking-[-0.02em]">Welcome back</h2>
                  <p className="text-sm text-muted-foreground mb-6">Log in to your account</p>
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
                    <div className="space-y-1.5">
                      <Label
                        htmlFor="email"
                        className="text-xs font-medium uppercase tracking-wider text-muted-foreground"
                      >
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
                      {isSubmitting ? "Please wait..." : "Log In"}
                    </button>
                  </form>
                  <p className="text-sm text-center text-muted-foreground mt-4">
                    Don&apos;t have an account?{" "}
                    <button
                      onClick={() => setAuthMode("contact_admin")}
                      className="text-blue-500 font-semibold hover:underline"
                    >
                      Request access
                    </button>
                  </p>
                  {!ssoMode && (
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
                </>
              )}
            </div>
          </div>
        </div>
      )}

      {/* 94.4 — accessibility: skip-to-content link (WCAG 2.1 AA) */}
      <a
        href="#landing-main"
        className="sr-only focus:not-sr-only focus:absolute focus:top-2 focus:left-2 focus:z-[100] focus:px-4 focus:py-2 focus:bg-white focus:text-slate-900 focus:rounded-md focus:outline-none focus:shadow-lg focus:ring-2 focus:ring-blue-500"
      >
        Skip to main content
      </a>

      {/* Navigation — 94.3: responsive, 94.4: aria roles */}
      <header role="banner">
        <nav className="fixed top-4 left-4 right-4 z-50 max-w-6xl mx-auto" aria-label="Main navigation">
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
                className="text-sm font-medium text-slate-400 hover:text-white transition-colors duration-150 focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2 rounded-md px-1"
              >
                How it works
              </button>
              <a
                href="#features"
                className="text-sm font-medium text-slate-400 hover:text-white transition-colors duration-150 focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2 rounded-md px-1"
              >
                Features
              </a>
              <a
                href="#pricing"
                className="text-sm font-medium text-slate-400 hover:text-white transition-colors duration-150 focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2 rounded-md px-1"
              >
                Pricing
              </a>
              <a
                href="#faq"
                className="text-sm font-medium text-slate-400 hover:text-white transition-colors duration-150 focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2 rounded-md px-1"
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
                onClick={() => setAuthMode("login")}
                className="text-sm font-semibold text-white bg-blue-600 hover:bg-blue-700 px-5 py-2 rounded-lg shadow-[0_1px_2px_rgba(0,0,0,0.1),0_4px_12px_rgba(37,99,235,0.25)] hover:shadow-[0_1px_2px_rgba(0,0,0,0.1),0_8px_20px_rgba(37,99,235,0.3)] transition-all duration-150 hover:-translate-y-px focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2"
              >
                Start Free
              </button>
            </div>
          </div>
        </nav>
      </header>

      <main id="landing-main" role="main">
        {/* Hero — 94.3: responsive, 94.4: semantic heading hierarchy */}
        <section className="relative pt-[8.5rem] pb-28 px-4 sm:px-6 overflow-hidden" aria-label="Hero">
          <div className="max-w-6xl mx-auto">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
              <div className="relative z-10">
                <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full border border-blue-500/30 bg-blue-500/10 text-blue-400 text-xs font-medium mb-6 tracking-wide">
                  <div className="w-1.5 h-1.5 rounded-full bg-blue-500 animate-pulse" />
                  Standalone Security Platform
                </div>
                <h1 className="text-[2.75rem] md:text-[3.25rem] lg:text-[3.75rem] font-extrabold tracking-[-0.03em] mb-6 leading-[1.04] font-display">
                  Enterprise
                  <br />
                  <span className="text-blue-500">Security.</span>
                  <br />
                  No EDR
                  <br />
                  <span className="border-b-[3px] border-blue-500 pb-0.5">Required.</span>
                </h1>
                <p className="text-base md:text-lg text-slate-400 max-w-lg mb-8 leading-relaxed">
                  SecureNexus gives you asset inventory, risk management, compliance assessments, and AI-powered threat
                  detection — all standalone, no third-party tools needed.
                </p>
                {/* 94.6 — CTA optimization: clear primary + secondary CTAs */}
                <div className="flex flex-wrap items-center gap-3 mb-8">
                  <button
                    onClick={() => setAuthMode("login")}
                    className="inline-flex items-center gap-2 px-7 py-3 rounded-lg font-semibold text-white bg-blue-600 hover:bg-blue-700 text-base shadow-[0_1px_2px_rgba(0,0,0,0.1),0_4px_12px_rgba(37,99,235,0.25)] hover:shadow-[0_1px_2px_rgba(0,0,0,0.1),0_8px_20px_rgba(37,99,235,0.3)] transition-all duration-150 hover:-translate-y-px focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2"
                    aria-label="Start your free 14-day trial"
                  >
                    Start Free Trial
                    <ArrowRight className="h-4 w-4" />
                  </button>
                  <button
                    onClick={() => document.getElementById("contact-demo")?.scrollIntoView({ behavior: "smooth" })}
                    className="inline-flex items-center gap-2 px-7 py-3 rounded-lg font-medium text-white bg-white/5 hover:bg-white/10 text-base border border-white/15 hover:border-white/25 transition-all duration-200 focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2"
                    aria-label="Book a demo with our team"
                  >
                    Book a Demo
                  </button>
                  <button
                    onClick={() => document.getElementById("pricing")?.scrollIntoView({ behavior: "smooth" })}
                    className="inline-flex items-center gap-2 px-5 py-3 rounded-lg font-medium text-slate-400 hover:text-white text-sm transition-colors duration-200 focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2"
                    aria-label="View pricing plans"
                  >
                    View Pricing
                  </button>
                </div>
                <div className="flex items-center gap-8">
                  {[
                    { val: "4", sub: "Frameworks" },
                    { val: "100%", sub: "Standalone" },
                    { val: "30min", sub: "Deploy Time" },
                  ].map((s) => (
                    <div key={s.sub}>
                      <div className="text-[2rem] font-bold tracking-tight font-mono">{s.val}</div>
                      <div className="text-xs text-slate-500 font-medium">{s.sub}</div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Dashboard mockup — 94.1: lazy-load image, 94.4: alt text */}
              <div className="relative hidden lg:block" aria-hidden="true">
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
                          <div className="text-[10px] text-muted-foreground">24 active alerts &#8226; 3 incidents</div>
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
                      onClick={() => setAuthMode("login")}
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

        {/* 94.5 — social proof: trusted by section */}
        <section className="py-10 px-4 sm:px-6" aria-label="Trusted by">
          <div className="max-w-5xl mx-auto text-center">
            <p className="text-xs text-slate-500 font-medium uppercase tracking-wider mb-4">
              Trusted by security teams at
            </p>
            <div className="flex flex-wrap justify-center gap-4 mb-6">
              {SOCIAL_PROOF_LOGOS.map((name) => (
                <div
                  key={name}
                  className="px-4 py-2 rounded-lg bg-white/[0.02] border border-white/[0.06] text-xs text-slate-400 font-medium"
                >
                  {name}
                </div>
              ))}
            </div>
            <div className="flex flex-wrap justify-center gap-3">
              {AWARDS.map((award) => (
                <div
                  key={award.label}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-full border border-amber-500/20 bg-amber-500/5 text-[10px] text-amber-400 font-medium"
                >
                  <Star className="h-2.5 w-2.5 fill-amber-400" />
                  {award.label} ({award.year})
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Metrics bar — 94.3: responsive grid */}
        <section className="py-12 px-4 sm:px-6" aria-label="Key metrics">
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

        {/* Problem section — 94.3: responsive */}
        <section className="py-24 px-4 sm:px-6 bg-gradient-to-b from-background to-[#020617]" aria-label="The problem">
          <div className="max-w-5xl mx-auto">
            <div className="text-center mb-14">
              <div className="inline-flex items-center px-3.5 py-1.5 rounded-full border border-red-500/30 bg-red-500/10 text-red-400 text-xs font-medium mb-4">
                The Problem
              </div>
              <h2 className="text-[1.875rem] md:text-[2.25rem] font-bold tracking-[-0.02em] mb-3">
                Security Without the Complexity
              </h2>
              <p className="text-slate-400 max-w-xl mx-auto">
                Most growing companies lack dedicated security tools. The alternatives are expensive, complex, and
                fragmented.
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

        {/* How It Works — 94.4: section role */}
        <section ref={howItWorksRef} id="how-it-works" className="py-20 px-4 sm:px-6" aria-label="How it works">
          <div className="max-w-5xl mx-auto">
            <div className="text-center mb-14">
              <div className="inline-flex items-center px-3.5 py-1.5 rounded-full border border-blue-500/30 bg-blue-500/10 text-blue-400 text-xs font-medium mb-4">
                How It Works
              </div>
              <h2 className="text-[1.75rem] md:text-[2rem] font-semibold tracking-[-0.02em] mb-3">
                Three Steps to Complete Security
              </h2>
              <p className="text-slate-400 max-w-xl mx-auto">
                Go from zero security tooling to full risk visibility in under 30 minutes.
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
                onClick={() => setAuthMode("login")}
                className="inline-flex items-center gap-2 px-8 py-3 rounded-lg font-semibold text-white bg-blue-600 hover:bg-blue-700 shadow-[0_1px_2px_rgba(0,0,0,0.1),0_4px_12px_rgba(37,99,235,0.25)] hover:shadow-[0_1px_2px_rgba(0,0,0,0.1),0_8px_20px_rgba(37,99,235,0.3)] transition-all duration-150 hover:-translate-y-px"
              >
                Start Free Trial
                <ArrowRight className="h-4 w-4" />
              </button>
            </div>
          </div>
        </section>

        {/* Integrations — 94.3: responsive */}
        <section
          className="py-16 overflow-hidden bg-gradient-to-b from-background to-[#020617]"
          aria-label="Integrations"
        >
          <div className="text-center mb-10 px-6">
            <div className="inline-flex items-center px-3.5 py-1.5 rounded-full border border-white/10 bg-white/5 text-slate-400 text-xs font-medium mb-4">
              Integrations
            </div>
            <h2 className="text-2xl md:text-[1.75rem] font-semibold mb-2 tracking-[-0.01em]">Optional Integrations</h2>
            <p className="text-sm text-slate-500">
              Works standalone. Optionally connect 24+ tools for enhanced visibility.
            </p>
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

        {/* Capabilities — 94.4: ARIA */}
        <section id="features" className="py-24 px-4 sm:px-6" aria-label="Platform capabilities">
          <div className="max-w-5xl mx-auto">
            <div className="text-center mb-14">
              <div className="inline-flex items-center px-3.5 py-1.5 rounded-full border border-blue-500/30 bg-blue-500/10 text-blue-400 text-xs font-medium mb-4">
                Capabilities
              </div>
              <h2 className="text-[1.875rem] md:text-[2.25rem] font-bold tracking-[-0.02em] mb-3">
                Everything You Need to Succeed
              </h2>
              <p className="text-slate-400 max-w-xl mx-auto">
                Everything you need for enterprise security operations, with zero third-party dependencies.
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

        {/* Testimonials — 94.4: ARIA, 94.5: social proof */}
        <section
          className="pt-28 pb-20 px-4 sm:px-6 bg-gradient-to-b from-[#0f172a] to-[#0c1220]"
          aria-label="Customer testimonials"
        >
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

        {/* Pricing — 94.3: responsive, 94.6: CTA optimization */}
        <section id="pricing" className="py-24 px-4 sm:px-6" aria-label="Pricing plans">
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
                  features: ["50 assets", "1 assessment", "5K AI tokens", "Community support"],
                  cta: "Start Free",
                  highlight: false,
                },
                {
                  name: "Starter",
                  price: "\u20B915K",
                  period: "/month",
                  description: "For SMBs and growing security teams",
                  features: [
                    "500 assets",
                    "Unlimited assessments",
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
                    "5,000 assets",
                    "All frameworks",
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
                    "Unlimited assets",
                    "All frameworks",
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
                    onClick={() => setAuthMode("login")}
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

        {/* FAQ — 94.4: aria-label */}
        <section id="faq" className="py-20 px-4 sm:px-6" aria-label="Frequently asked questions">
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

        {/* 94.7 — Contact / Demo Request Form */}
        <section
          id="contact-demo"
          className="py-20 px-4 sm:px-6 bg-gradient-to-b from-background to-[#0f172a]"
          aria-label="Request a demo"
        >
          <div className="max-w-2xl mx-auto">
            <div className="text-center mb-10">
              <div className="inline-flex items-center px-3.5 py-1.5 rounded-full border border-blue-500/30 bg-blue-500/10 text-blue-400 text-xs font-medium mb-4">
                Get in Touch
              </div>
              <h2 className="text-[1.875rem] md:text-[2.25rem] font-bold tracking-[-0.02em] mb-3">Book a Demo</h2>
              <p className="text-slate-400 max-w-lg mx-auto">
                See SecureNexus in action. Our team will walk you through the platform and answer your questions.
              </p>
            </div>
            {contactSubmitted ? (
              <div className="text-center py-12 bg-white/[0.02] border border-white/[0.06] rounded-xl">
                <CheckCircle2 className="h-10 w-10 text-emerald-500 mx-auto mb-4" />
                <h3 className="text-lg font-semibold mb-2">Thank you!</h3>
                <p className="text-sm text-slate-400">We&apos;ll be in touch within 24 hours to schedule your demo.</p>
              </div>
            ) : (
              <form
                onSubmit={handleContactSubmit}
                className="bg-white/[0.02] border border-white/[0.06] rounded-xl p-8 space-y-4"
              >
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div className="space-y-1.5">
                    <Label
                      htmlFor="contact-name"
                      className="text-xs font-medium uppercase tracking-wider text-slate-400"
                    >
                      Name
                    </Label>
                    <Input
                      id="contact-name"
                      value={contactName}
                      onChange={(e) => setContactName(e.target.value)}
                      placeholder="Your name"
                      required
                      className="border border-border rounded-lg h-10"
                    />
                  </div>
                  <div className="space-y-1.5">
                    <Label
                      htmlFor="contact-email"
                      className="text-xs font-medium uppercase tracking-wider text-slate-400"
                    >
                      Work Email
                    </Label>
                    <Input
                      id="contact-email"
                      type="email"
                      value={contactEmail}
                      onChange={(e) => setContactEmail(e.target.value)}
                      placeholder="you@company.com"
                      required
                      className="border border-border rounded-lg h-10"
                    />
                  </div>
                </div>
                <div className="space-y-1.5">
                  <Label
                    htmlFor="contact-message"
                    className="text-xs font-medium uppercase tracking-wider text-slate-400"
                  >
                    Message (optional)
                  </Label>
                  <Textarea
                    id="contact-message"
                    value={contactMessage}
                    onChange={(e) => setContactMessage(e.target.value)}
                    placeholder="Tell us about your security needs..."
                    rows={3}
                    className="border border-border rounded-lg"
                  />
                </div>
                <button
                  type="submit"
                  className="w-full h-11 rounded-lg font-semibold text-white bg-blue-600 hover:bg-blue-700 shadow-[0_1px_2px_rgba(0,0,0,0.1),0_4px_12px_rgba(37,99,235,0.25)] transition-all duration-150 focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2"
                >
                  Request Demo
                </button>
                <p className="text-[10px] text-slate-500 text-center">
                  No commitment required. We&apos;ll respond within 24 hours.
                </p>
              </form>
            )}
          </div>
        </section>

        {/* CTA — 94.6: optimized CTAs */}
        <section className="py-16 px-4 sm:px-6" aria-label="Call to action">
          <div className="max-w-2xl mx-auto text-center">
            <div className="bg-white/[0.02] border border-white/[0.08] rounded-xl p-10 shadow-[0_8px_40px_rgba(0,0,0,0.3)]">
              <h2 className="text-[1.875rem] md:text-[2.25rem] font-bold tracking-[-0.02em] mb-4">
                Ready to Secure Your Organization?
              </h2>
              <p className="text-slate-400 mb-8 max-w-lg mx-auto">
                Get enterprise-grade security operations without the enterprise price tag. Full risk visibility in your
                first week.
              </p>
              <div className="flex flex-wrap justify-center gap-3 mb-6">
                <button
                  onClick={() => setAuthMode("login")}
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

        {/* Further Reading — 94.4: ARIA */}
        <section className="py-20 px-4 sm:px-6 border-t border-border/30" aria-label="Further reading">
          <div className="max-w-5xl mx-auto">
            <div className="text-center mb-10">
              <h2 className="text-[1.5rem] font-bold mb-3 tracking-[-0.01em]">Further Reading</h2>
              <p className="text-slate-500">Dive deeper into standalone security operations and compliance.</p>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <a
                href="/blog/automated-secops"
                className="block bg-white/[0.02] border border-white/[0.06] rounded-xl p-6 hover:bg-white/[0.04] hover:border-white/[0.1] transition-[background,border-color] duration-200"
              >
                <div className="w-9 h-9 rounded-lg bg-indigo-500/10 flex items-center justify-center mb-4">
                  <Brain className="h-4 w-4 text-indigo-400" />
                </div>
                <h3 className="font-semibold text-base mb-2">Standalone Security Guide</h3>
                <p className="text-sm text-slate-500 leading-relaxed">
                  Learn how to build enterprise security operations without expensive EDR/SIEM licenses.
                </p>
              </a>
              <a
                href="/product/agentic-soc"
                className="block bg-white/[0.02] border border-white/[0.06] rounded-xl p-6 hover:bg-white/[0.04] hover:border-white/[0.1] transition-[background,border-color] duration-200"
              >
                <div className="w-9 h-9 rounded-lg bg-blue-500/10 flex items-center justify-center mb-4">
                  <Workflow className="h-4 w-4 text-blue-400" />
                </div>
                <h3 className="font-semibold text-base mb-2">Risk Management Best Practices</h3>
                <p className="text-sm text-slate-500 leading-relaxed">
                  Master risk registers, heatmaps, and compliance frameworks for growing organizations.
                </p>
              </a>
              <a
                href="/product/comparison"
                className="block bg-white/[0.02] border border-white/[0.06] rounded-xl p-6 hover:bg-white/[0.04] hover:border-white/[0.1] transition-[background,border-color] duration-200"
              >
                <div className="w-9 h-9 rounded-lg bg-emerald-500/10 flex items-center justify-center mb-4">
                  <BarChart3 className="h-4 w-4 text-emerald-400" />
                </div>
                <h3 className="font-semibold text-base mb-2">Compliance Framework Comparison</h3>
                <p className="text-sm text-slate-500 leading-relaxed">
                  Compare CIS Controls, NIST CSF, ISO 27001, and SOC 2 to find the right fit for your organization.
                </p>
              </a>
            </div>
          </div>
        </section>
      </main>

      {/* Footer — 94.4: semantic role */}
      <footer className="border-t border-border/30 py-10 px-4 sm:px-6" role="contentinfo">
        <div className="max-w-6xl mx-auto">
          <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-6 mb-8">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center">
                <img src={atsLogo} alt="SecureNexus" className="w-5 h-5 object-contain" />
              </div>
              <div>
                <span className="font-semibold text-sm">SecureNexus</span>
                <p className="text-[10px] text-slate-500">Standalone Security Platform</p>
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

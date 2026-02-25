import { useState, useEffect } from "react";
import { Zap, Brain, Eye, ArrowRight, Lock, Activity, BarChart3, Globe, Layers, Shield, ShieldCheck, Radar, Flame, Cloud, Search, AlertTriangle, Database } from "lucide-react";
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

const features = [
  {
    icon: Brain,
    title: "AI-Powered Correlation",
    description: "Automatically cluster alerts by attacker behavior, not just static rules. Our AI engine mimics how senior analysts think.",
    gradient: "from-red-500/20 to-rose-500/20",
    iconColor: "text-red-400",
  },
  {
    icon: Eye,
    title: "Attacker-Centric View",
    description: "See threats through the attacker's lens. Map campaigns to MITRE ATT&CK techniques with confidence scores.",
    gradient: "from-orange-500/20 to-amber-500/20",
    iconColor: "text-orange-400",
  },
  {
    icon: Zap,
    title: "Instant Narratives",
    description: "Get AI-generated incident summaries in seconds, not hours. Reduce MTTD and MTTR with actionable intelligence.",
    gradient: "from-amber-500/20 to-orange-500/20",
    iconColor: "text-amber-400",
  },
  {
    icon: Lock,
    title: "Zero Trust Integration",
    description: "Read-only API connectors to your existing EDR, SIEM, and cloud security tools. No rip-and-replace required.",
    gradient: "from-emerald-500/20 to-teal-500/20",
    iconColor: "text-emerald-400",
  },
];

const stats = [
  { label: "Alert Sources", value: "24+", icon: Layers },
  { label: "MTTR Reduction", value: "35%", icon: Activity },
  { label: "Frameworks", value: "4", icon: BarChart3 },
  { label: "API Endpoints", value: "40+", icon: Globe },
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
  const [providers, setProviders] = useState<{ google: boolean; github: boolean }>({ google: false, github: false });

  useEffect(() => {
    fetch("/api/auth/providers").then(r => r.json()).then(d => setProviders({ google: !!d.google, github: !!d.github })).catch(() => {});
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (authMode === "register") {
      await register({ email, password, firstName, lastName });
    } else {
      await login({ email, password });
    }
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
                <img src={atsLogo} alt="ATS" className="w-8 h-8 object-contain" />
                <span className="font-semibold text-lg">SecureNexus</span>
              </div>
              <h2 className="text-xl font-bold mb-1">{authMode === "register" ? "Create an account" : "Welcome back"}</h2>
              <p className="text-sm text-muted-foreground mb-6">{authMode === "register" ? "Get started with SecureNexus" : "Log in to your account"}</p>
              {authError && (
                <div className="mb-4 p-3 rounded-md bg-destructive/10 text-destructive text-sm">
                  {authError.message}
                </div>
              )}
              {(providers.google || providers.github) && (
                <div className="space-y-2 mb-4">
                  {providers.google && (
                    <Button
                      variant="outline"
                      className="w-full h-10 gap-2 text-sm font-medium hover:bg-muted/50 transition-all"
                      onClick={() => { window.location.href = "/api/auth/google"; }}
                    >
                      <FaGoogle className="h-4 w-4 text-[#4285F4]" />
                      Continue with Google
                    </Button>
                  )}
                  {providers.github && (
                    <Button
                      variant="outline"
                      className="w-full h-10 gap-2 text-sm font-medium hover:bg-muted/50 transition-all"
                      onClick={() => { window.location.href = "/api/auth/github"; }}
                    >
                      <FaGithub className="h-4 w-4" />
                      Continue with GitHub
                    </Button>
                  )}
                  <div className="relative my-3">
                    <div className="absolute inset-0 flex items-center"><div className="w-full border-t border-border" /></div>
                    <div className="relative flex justify-center text-xs"><span className="bg-card px-2 text-muted-foreground">or continue with email</span></div>
                  </div>
                </div>
              )}
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
                  {isSubmitting ? "Please wait..." : authMode === "register" ? "Create Account" : "Log In"}
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
            <img src={atsLogo} alt="ATS" className="w-9 h-9 object-contain" />
            <span className="font-semibold text-lg tracking-tight" data-testid="text-logo">SecureNexus</span>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="ghost" onClick={() => setAuthMode("login")} data-testid="button-login">
              Log in
            </Button>
            <Button onClick={() => setAuthMode("register")} data-testid="button-get-started">
              Get Started <ArrowRight className="ml-1 h-4 w-4" />
            </Button>
          </div>
        </div>
      </nav>

      <section className="relative pt-36 pb-24 px-6 overflow-hidden">
        <div className="absolute inset-0 overflow-hidden pointer-events-none">
          <div className="absolute top-20 left-1/4 w-[500px] h-[500px] bg-primary/8 dark:bg-primary/12 rounded-full blur-[120px]" />
          <div className="absolute top-40 right-1/4 w-[400px] h-[400px] bg-primary/6 dark:bg-primary/10 rounded-full blur-[100px]" />
          <div className="absolute -bottom-20 left-1/2 -translate-x-1/2 w-[600px] h-[300px] bg-violet-500/5 dark:bg-violet-500/8 rounded-full blur-[100px]" />
        </div>

        <div className="max-w-4xl mx-auto text-center relative z-10">
          <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full gradient-badge text-xs font-medium mb-8 tracking-wide animate-fade-in glow-red-subtle" data-testid="text-badge">
            <div className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse" />
            AI-Powered Security Intelligence
          </div>
          <h1 className="text-4xl md:text-5xl lg:text-6xl font-bold tracking-tight mb-6 leading-[1.1] animate-fade-in-up" data-testid="text-hero-title">
            Stop chasing alerts.
            <br />
            <span className="bg-gradient-to-r from-red-500 via-rose-500 to-orange-500 bg-clip-text text-transparent">Start stopping attackers.</span>
          </h1>
          <p className="text-base md:text-lg text-muted-foreground max-w-2xl mx-auto mb-10 leading-relaxed animate-fade-in-up delay-200" data-testid="text-hero-description">
            SecureNexus unifies alerts from your EDR, SIEM, and cloud security tools, correlates them with AI, and delivers attacker-centric incident narratives in real time.
          </p>
          <div className="flex flex-wrap items-center justify-center gap-3 mb-14 animate-fade-in-up delay-300">
            <Button size="lg" onClick={() => setAuthMode("register")} data-testid="button-hero-cta" className="px-8">
              Start Free Trial
              <ArrowRight className="ml-2 h-4 w-4" />
            </Button>
            <Button size="lg" variant="outline" data-testid="button-demo" className="px-8">
              View Live Demo
            </Button>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 max-w-2xl mx-auto animate-fade-in-up delay-400">
            {stats.map((stat) => (
              <div key={stat.label} className="flex flex-col items-center gap-1 p-4 rounded-md gradient-card" data-testid={`stat-${stat.label.toLowerCase().replace(/\s/g, "-")}`}>
                <stat.icon className="h-4 w-4 text-muted-foreground mb-1" />
                <span className="text-2xl font-bold tracking-tight" data-testid={`value-${stat.label.toLowerCase().replace(/\s/g, "-")}`}>{stat.value}</span>
                <span className="text-[11px] text-muted-foreground">{stat.label}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="py-16 border-t overflow-hidden">
        <div className="text-center mb-10 px-6">
          <p className="text-xs uppercase tracking-widest text-muted-foreground mb-3 font-medium">Integrations</p>
          <h2 className="text-xl md:text-2xl font-bold mb-4">Connects to your existing stack</h2>
        </div>
        <div className="relative">
          <div className="absolute left-0 top-0 bottom-0 w-24 bg-gradient-to-r from-background to-transparent z-10 pointer-events-none" />
          <div className="absolute right-0 top-0 bottom-0 w-24 bg-gradient-to-l from-background to-transparent z-10 pointer-events-none" />
          <div className="flex animate-marquee gap-6" data-testid="marquee-integrations">
            {[...integrations, ...integrations].map((item, i) => (
              <div
                key={`${item.name}-${i}`}
                className="flex items-center gap-3 px-5 py-3 rounded-md gradient-card flex-shrink-0"
                data-testid={`integration-${item.name.toLowerCase().replace(/\s/g, "-")}-${i}`}
              >
                <item.icon className="h-5 w-5 text-muted-foreground flex-shrink-0" />
                <span className="text-sm font-medium text-muted-foreground whitespace-nowrap">{item.name}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="py-20 px-6">
        <div className="max-w-5xl mx-auto">
          <div className="text-center mb-14 animate-fade-in">
            <p className="text-xs uppercase tracking-widest text-primary mb-3 font-medium">Capabilities</p>
            <h2 className="text-2xl md:text-3xl font-bold mb-3" data-testid="text-features-title">Built for modern SOC teams</h2>
            <p className="text-muted-foreground max-w-xl mx-auto text-sm">
              Replace dashboard hopping and manual correlation with AI-driven security intelligence.
            </p>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {features.map((feature, index) => (
              <Card key={index} className="gradient-card group" data-testid={`card-feature-${index}`}>
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

      <section className="py-20 px-6 border-t">
        <div className="max-w-3xl mx-auto text-center relative">
          <div className="absolute inset-0 -z-10 overflow-hidden pointer-events-none">
            <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[400px] h-[200px] bg-red-500/8 dark:bg-red-500/12 rounded-full blur-[80px]" />
          </div>
          <p className="text-xs uppercase tracking-widest text-muted-foreground mb-3 font-medium">Get Started</p>
          <h2 className="text-2xl md:text-3xl font-bold mb-4">Ready to transform your SOC?</h2>
          <p className="text-muted-foreground mb-8 text-sm">
            Join security teams reducing their MTTR by 35% with AI-powered alert correlation.
          </p>
          <div className="flex flex-wrap items-center justify-center gap-3">
            <Button size="lg" onClick={() => setAuthMode("register")} data-testid="button-cta-bottom" className="px-8">
              Get Started Free
              <ArrowRight className="ml-2 h-4 w-4" />
            </Button>
          </div>
          <div className="flex flex-wrap items-center justify-center gap-6 mt-6 text-xs text-muted-foreground">
            <span>No credit card required</span>
            <span className="w-1 h-1 rounded-full bg-muted-foreground/30 hidden sm:block" />
            <span>SOC 2 Compliant</span>
            <span className="w-1 h-1 rounded-full bg-muted-foreground/30 hidden sm:block" />
            <span>14-day free trial</span>
          </div>
        </div>
      </section>

      <footer className="border-t py-8 px-6 relative">
        <div className="gradient-accent-line absolute top-0 left-0 right-0" />
        <div className="max-w-6xl mx-auto flex flex-wrap items-center justify-between gap-4 text-xs text-muted-foreground">
          <div className="flex items-center gap-2.5">
            <img src={atsLogo} alt="ATS" className="w-6 h-6 object-contain" />
            <span className="font-medium">SecureNexus</span>
          </div>
          <span>2025 SecureNexus. All rights reserved.</span>
        </div>
      </footer>
    </div>
  );
}

import { Shield, Zap, Brain, Eye, ArrowRight, Lock } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";

const features = [
  {
    icon: Brain,
    title: "AI-Powered Correlation",
    description: "Automatically cluster alerts by attacker behavior, not just static rules. Our AI engine mimics how senior analysts think.",
  },
  {
    icon: Eye,
    title: "Attacker-Centric View",
    description: "See threats through the attacker's lens. Map campaigns to MITRE ATT&CK techniques with confidence scores.",
  },
  {
    icon: Zap,
    title: "Instant Narratives",
    description: "Get AI-generated incident summaries in seconds, not hours. Reduce MTTD and MTTR with actionable intelligence.",
  },
  {
    icon: Lock,
    title: "Zero Trust Integration",
    description: "Read-only API connectors to your existing EDR, SIEM, and cloud security tools. No rip-and-replace required.",
  },
];

export default function LandingPage() {
  return (
    <div className="min-h-screen bg-background">
      <nav className="fixed top-0 left-0 right-0 z-50 backdrop-blur-md bg-background/80 border-b">
        <div className="max-w-6xl mx-auto px-4 h-14 flex items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <div className="flex items-center justify-center w-8 h-8 rounded-md bg-primary">
              <Shield className="h-4 w-4 text-primary-foreground" />
            </div>
            <span className="font-semibold tracking-tight" data-testid="text-logo">SecureNexus</span>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="ghost" asChild data-testid="button-login">
              <a href="/api/login">Log in</a>
            </Button>
            <Button asChild data-testid="button-get-started">
              <a href="/api/login">Get Started <ArrowRight className="ml-1 h-4 w-4" /></a>
            </Button>
          </div>
        </div>
      </nav>

      <section className="pt-32 pb-20 px-4">
        <div className="max-w-4xl mx-auto text-center">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-primary/10 text-primary text-xs font-medium mb-6" data-testid="text-badge">
            <Shield className="h-3 w-3" />
            AI-Powered Security Intelligence
          </div>
          <h1 className="text-4xl md:text-5xl lg:text-6xl font-bold tracking-tight mb-6 leading-tight" data-testid="text-hero-title">
            Stop chasing alerts.
            <br />
            <span className="text-muted-foreground">Start stopping attackers.</span>
          </h1>
          <p className="text-lg text-muted-foreground max-w-2xl mx-auto mb-8 leading-relaxed" data-testid="text-hero-description">
            SecureNexus unifies alerts from your EDR, SIEM, and cloud security tools, correlates them with AI, and delivers attacker-centric incident narratives in real time.
          </p>
          <div className="flex flex-wrap items-center justify-center gap-3 mb-12">
            <Button size="lg" asChild data-testid="button-hero-cta">
              <a href="/api/login">
                Start Free Trial
                <ArrowRight className="ml-1 h-4 w-4" />
              </a>
            </Button>
            <Button size="lg" variant="outline" data-testid="button-demo">
              View Live Demo
            </Button>
          </div>
          <div className="flex flex-wrap items-center justify-center gap-6 text-xs text-muted-foreground">
            <span>No credit card required</span>
            <span className="hidden sm:inline">|</span>
            <span>SOC 2 Compliant</span>
            <span className="hidden sm:inline">|</span>
            <span>14-day free trial</span>
          </div>
        </div>
      </section>

      <section className="py-20 px-4">
        <div className="max-w-5xl mx-auto">
          <div className="text-center mb-12">
            <h2 className="text-2xl md:text-3xl font-bold mb-3" data-testid="text-features-title">Built for modern SOC teams</h2>
            <p className="text-muted-foreground max-w-xl mx-auto">
              Replace dashboard hopping and manual correlation with AI-driven security intelligence.
            </p>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {features.map((feature, index) => (
              <Card key={index} className="hover-elevate" data-testid={`card-feature-${index}`}>
                <CardContent className="p-6">
                  <div className="flex items-center justify-center w-10 h-10 rounded-md bg-primary/10 mb-4">
                    <feature.icon className="h-5 w-5 text-primary" />
                  </div>
                  <h3 className="font-semibold mb-2">{feature.title}</h3>
                  <p className="text-sm text-muted-foreground leading-relaxed">{feature.description}</p>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      </section>

      <section className="py-20 px-4 border-t">
        <div className="max-w-3xl mx-auto text-center">
          <h2 className="text-2xl md:text-3xl font-bold mb-4">Ready to transform your SOC?</h2>
          <p className="text-muted-foreground mb-8">
            Join security teams reducing their MTTR by 35% with AI-powered alert correlation.
          </p>
          <Button size="lg" asChild data-testid="button-cta-bottom">
            <a href="/api/login">
              Get Started Free
              <ArrowRight className="ml-1 h-4 w-4" />
            </a>
          </Button>
        </div>
      </section>

      <footer className="border-t py-8 px-4">
        <div className="max-w-6xl mx-auto flex flex-wrap items-center justify-between gap-4 text-xs text-muted-foreground">
          <div className="flex items-center gap-2">
            <Shield className="h-3 w-3" />
            <span>SecureNexus</span>
          </div>
          <span>2025 SecureNexus. All rights reserved.</span>
        </div>
      </footer>
    </div>
  );
}

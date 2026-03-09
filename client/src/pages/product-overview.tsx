import { Brain, Shield, Zap, Eye, BarChart3, Layers, Lock, Activity, Target, Workflow, Users } from "lucide-react";
import ContentLayout from "./content-layout";

const features = [
  {
    icon: Brain,
    title: "AI-Powered Correlation Engine",
    description:
      "Clusters alerts by attacker behavior, maps to MITRE ATT&CK techniques, and generates incident narratives automatically. Reduces triage time from 45 minutes to under 5.",
    color: "bg-cyan-100 dark:bg-cyan-500/10 text-cyan-600 dark:text-cyan-400",
  },
  {
    icon: Eye,
    title: "Attacker-Centric Incident View",
    description:
      "See the full attack story instead of chasing individual alerts. Campaign-level visibility with confidence scoring and technique mapping across the kill chain.",
    color: "bg-violet-100 dark:bg-violet-500/10 text-violet-600 dark:text-violet-400",
  },
  {
    icon: Zap,
    title: "SOAR Automation & Playbooks",
    description:
      "Automated response playbooks with one-click actions. Containment, enrichment, and notification workflows execute in seconds, not hours.",
    color: "bg-amber-100 dark:bg-amber-500/10 text-amber-600 dark:text-amber-400",
  },
  {
    icon: Shield,
    title: "Multi-Tenant RBAC",
    description:
      "Enterprise-grade role-based access control with organization hierarchy. Supports MSSP parent-child models, SSO, and delegated administration.",
    color: "bg-emerald-100 dark:bg-emerald-500/10 text-emerald-600 dark:text-emerald-400",
  },
  {
    icon: BarChart3,
    title: "Compliance Automation",
    description:
      "Automated evidence collection and control mapping for SOC 2 Type II, ISO 27001, NIST CSF, and GDPR. Generate audit-ready reports in minutes.",
    color: "bg-purple-100 dark:bg-purple-500/10 text-purple-600 dark:text-purple-400",
  },
  {
    icon: Target,
    title: "MITRE ATT&CK Coverage",
    description:
      "Full MITRE ATT&CK v15 framework integration with technique-level detection coverage analysis, gap identification, and threat-informed defense mapping.",
    color: "bg-rose-100 dark:bg-rose-500/10 text-rose-600 dark:text-rose-400",
  },
];

const integrationCategories = [
  {
    category: "EDR / XDR",
    tools: ["CrowdStrike Falcon", "SentinelOne", "Microsoft Defender", "Carbon Black", "Palo Alto Cortex XDR"],
  },
  {
    category: "SIEM",
    tools: ["Splunk Enterprise Security", "IBM QRadar", "Elastic Security", "Rapid7 InsightIDR"],
  },
  {
    category: "Cloud Security",
    tools: ["AWS GuardDuty", "Wiz", "Zscaler", "Check Point CloudGuard"],
  },
  {
    category: "Network / IDS",
    tools: ["Wazuh", "Snort IDS", "Suricata", "Cisco Umbrella", "Darktrace"],
  },
];

const architectureSteps = [
  {
    step: "1",
    title: "Ingest",
    description:
      "Push via REST API or pull from 24+ connector integrations. Alerts are normalized into a unified schema with automatic deduplication.",
    icon: Layers,
  },
  {
    step: "2",
    title: "Correlate",
    description:
      "AI engine clusters alerts by attacker behavior patterns, maps to MITRE ATT&CK, and assigns confidence scores to each correlation.",
    icon: Brain,
  },
  {
    step: "3",
    title: "Investigate",
    description:
      "Automated threat enrichment, IOC extraction, and entity graph analysis. AI generates incident narratives and recommended response actions.",
    icon: Activity,
  },
  {
    step: "4",
    title: "Respond",
    description:
      "Execute playbooks with one-click containment, notification, and remediation. Full audit trail and incident lifecycle tracking.",
    icon: Workflow,
  },
];

const faqs = [
  {
    q: "What is SecureNexus?",
    a: "SecureNexus is an Agentic SOC platform that uses AI agents to autonomously detect, investigate, and respond to security threats. Built in India by Arica Technologies, it combines AI-powered alert correlation, SOAR automation, and MITRE ATT&CK mapping into a single platform for security operations teams.",
  },
  {
    q: "How does SecureNexus differ from a traditional SIEM?",
    a: "Traditional SIEMs collect and store logs, requiring analysts to manually investigate alerts. SecureNexus acts as an AI SOC analyst that automatically correlates alerts by attacker behavior, generates incident narratives, and executes response playbooks. It sits on top of your existing SIEM and adds autonomous investigation capabilities.",
  },
  {
    q: "What security tools does SecureNexus integrate with?",
    a: "SecureNexus integrates with 24+ security tools including CrowdStrike, Splunk, Palo Alto, AWS GuardDuty, Microsoft Defender, SentinelOne, Wiz, Wazuh, IBM QRadar, Elastic Security, and more. Both push-based API ingestion and pull-based connector polling are supported.",
  },
  {
    q: "Is SecureNexus suitable for small teams?",
    a: "Yes. SecureNexus offers a free tier for startups and small teams, with Pro ($49/month) and Enterprise ($199/month) plans for growing organizations. The AI-powered automation means even a team of 2-3 analysts can operate at the efficiency of a much larger SOC.",
  },
  {
    q: "How long does deployment take?",
    a: "Under 30 minutes. SecureNexus uses read-only API connectors to your existing stack. No agents to install, no infrastructure changes, no rip-and-replace. Connect your tools and start seeing correlated incidents immediately.",
  },
];

const articleSchema = {
  "@context": "https://schema.org",
  "@type": "WebPage",
  name: "SecureNexus Product Overview — Agentic SOC Platform",
  description:
    "SecureNexus is an Agentic SOC platform with AI-powered threat detection, automated incident response, SOAR automation, and MITRE ATT&CK mapping. Built in India by Arica Technologies.",
  url: "https://nexus.aricatech.xyz/product",
  publisher: {
    "@type": "Organization",
    name: "Arica Technologies",
    url: "https://aricatech.xyz",
  },
  speakable: {
    "@type": "SpeakableSpecification",
    cssSelector: ["header > p", "header > h1"],
  },
};

export default function ProductOverviewPage() {
  const brutCard =
    "bg-white dark:bg-[#111827] border-[2.5px] border-[#1e293b] dark:border-[#334155] rounded-2xl shadow-[4px_4px_0px_#1e293b] dark:shadow-[4px_4px_0px_rgba(6,182,212,0.15)]";

  return (
    <ContentLayout
      title="Product Overview"
      breadcrumbs={[{ label: "Home", href: "/" }, { label: "Product" }]}
      faqs={faqs}
      jsonLd={[articleSchema]}
    >
      <header className="mb-12">
        <h1 className="text-3xl md:text-5xl font-black mb-4 leading-tight">SecureNexus: The Agentic SOC Platform</h1>
        <p className="speakable-summary text-lg text-[#64748b] dark:text-[#94a3b8] font-medium max-w-2xl leading-relaxed">
          SecureNexus is an AI-powered security operations platform that autonomously detects, investigates, and
          responds to threats. Built in India by Arica Technologies for global enterprises, it replaces manual analyst
          workflows with intelligent automation.
        </p>
      </header>

      <section className="mb-16">
        <h2 className="text-2xl md:text-3xl font-black mb-6">How It Works</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {architectureSteps.map((step) => (
            <div key={step.step} className={`${brutCard} p-6`}>
              <div className="flex items-start gap-4">
                <div className="w-10 h-10 rounded-xl bg-cyan-100 dark:bg-cyan-500/10 flex items-center justify-center flex-shrink-0">
                  <step.icon className="h-5 w-5 text-cyan-600 dark:text-cyan-400" />
                </div>
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-xs font-bold text-cyan-600 dark:text-cyan-400">Step {step.step}</span>
                    <h3 className="font-extrabold">{step.title}</h3>
                  </div>
                  <p className="text-sm text-[#64748b] dark:text-[#94a3b8] leading-relaxed font-medium">
                    {step.description}
                  </p>
                </div>
              </div>
            </div>
          ))}
        </div>
      </section>

      <section className="mb-16">
        <h2 className="text-2xl md:text-3xl font-black mb-6">Core Capabilities</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {features.map((feature) => (
            <div key={feature.title} className={`${brutCard} p-6`}>
              <div className="flex items-start gap-4">
                <div className={`w-10 h-10 rounded-xl ${feature.color} flex items-center justify-center flex-shrink-0`}>
                  <feature.icon className="h-5 w-5" />
                </div>
                <div>
                  <h3 className="font-extrabold mb-1">{feature.title}</h3>
                  <p className="text-sm text-[#64748b] dark:text-[#94a3b8] leading-relaxed font-medium">
                    {feature.description}
                  </p>
                </div>
              </div>
            </div>
          ))}
        </div>
      </section>

      <section className="mb-16">
        <h2 className="text-2xl md:text-3xl font-black mb-6">Integrations</h2>
        <p className="text-[#64748b] dark:text-[#94a3b8] mb-6 font-medium">
          SecureNexus connects to 24+ security tools via both push-based API ingestion and pull-based connector polling.
        </p>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {integrationCategories.map((cat) => (
            <div key={cat.category} className={`${brutCard} p-5`}>
              <h3 className="font-extrabold text-sm mb-3">{cat.category}</h3>
              <ul className="space-y-1.5">
                {cat.tools.map((tool) => (
                  <li
                    key={tool}
                    className="flex items-center gap-2 text-sm text-[#64748b] dark:text-[#94a3b8] font-medium"
                  >
                    <Lock className="h-3 w-3 text-emerald-500 flex-shrink-0" />
                    {tool}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </section>

      <section className="mb-16">
        <h2 className="text-2xl md:text-3xl font-black mb-6">Built for Teams of Every Size</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {[
            {
              plan: "Free",
              price: "$0",
              description: "For startups and small teams getting started with security operations.",
              icon: Users,
            },
            {
              plan: "Pro",
              price: "$49/mo",
              description: "For growing teams that need advanced correlation and automation capabilities.",
              icon: Zap,
            },
            {
              plan: "Enterprise",
              price: "$199/mo",
              description: "For large SOCs and MSSPs requiring multi-tenant RBAC, SSO, and custom integrations.",
              icon: Shield,
            },
          ].map((tier) => (
            <div key={tier.plan} className={`${brutCard} p-6 text-center`}>
              <tier.icon className="h-8 w-8 mx-auto mb-3 text-cyan-600 dark:text-cyan-400" />
              <h3 className="font-extrabold text-lg">{tier.plan}</h3>
              <p className="text-2xl font-black text-cyan-600 dark:text-cyan-400 my-2">{tier.price}</p>
              <p className="text-xs text-[#64748b] dark:text-[#94a3b8] font-medium">{tier.description}</p>
            </div>
          ))}
        </div>
      </section>
    </ContentLayout>
  );
}

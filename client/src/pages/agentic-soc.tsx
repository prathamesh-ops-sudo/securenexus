import { Brain, Shield, Zap, Activity, Clock, TrendingDown, AlertTriangle, CheckCircle2, XCircle } from "lucide-react";
import ContentLayout from "./content-layout";

const comparisonData = [
  {
    feature: "Alert Triage",
    traditional: "Manual — analyst reviews each alert individually (45 min avg)",
    agentic: "Autonomous — AI clusters and triages alerts in seconds",
  },
  {
    feature: "Threat Correlation",
    traditional: "Rule-based — static correlation rules miss novel attacks",
    agentic: "Behavior-based — ML identifies attacker patterns across data sources",
  },
  {
    feature: "Incident Investigation",
    traditional: "Analyst-driven — hours of manual log pivoting and enrichment",
    agentic: "AI-driven — automated enrichment, IOC extraction, and narrative generation",
  },
  {
    feature: "Response Actions",
    traditional: "Manual playbooks — slow execution, human error risk",
    agentic: "Automated playbooks — one-click containment with full audit trail",
  },
  {
    feature: "MITRE ATT&CK Mapping",
    traditional: "Post-incident — manual technique assignment after the fact",
    agentic: "Real-time — automatic technique mapping with confidence scores",
  },
  {
    feature: "Scalability",
    traditional: "Linear — more alerts = more analysts needed",
    agentic: "Non-linear — AI handles 80%+ of workload regardless of alert volume",
  },
];

const benefits = [
  {
    icon: Clock,
    stat: "90%",
    label: "Faster Triage",
    description: "AI reduces average triage time from 45 minutes to under 5 minutes per alert.",
  },
  {
    icon: TrendingDown,
    stat: "70%",
    label: "Fewer False Positives",
    description: "Behavioral correlation separates real threats from noise before analysts see them.",
  },
  {
    icon: Activity,
    stat: "35%",
    label: "Lower MTTR",
    description: "Automated response playbooks and pre-built enrichment cut mean time to respond.",
  },
  {
    icon: AlertTriangle,
    stat: "80%+",
    label: "Workload Reduction",
    description: "AI agents handle Tier-1 analyst tasks, freeing humans for strategic decision-making.",
  },
];

const faqs = [
  {
    q: "What is an Agentic SOC?",
    a: "An Agentic SOC (Security Operations Center) is a next-generation security operations model where AI agents autonomously detect, investigate, and respond to threats. Unlike traditional SOCs that rely entirely on human analysts for alert triage and investigation, an Agentic SOC uses AI to handle 80%+ of Tier-1 analyst tasks — alert correlation, threat enrichment, MITRE ATT&CK mapping, and incident narrative generation — reducing manual workload and accelerating response times.",
  },
  {
    q: "How is an Agentic SOC different from a traditional SOC?",
    a: "A traditional SOC relies on human analysts to manually review every alert, correlate threats using static rules, and execute response playbooks step-by-step. An Agentic SOC uses AI agents that autonomously perform these tasks: clustering alerts by attacker behavior, generating incident narratives, mapping techniques to MITRE ATT&CK, and executing automated response actions. The result is 90% faster triage, 70% fewer false positives, and analysts freed to focus on strategic decisions.",
  },
  {
    q: "Does an Agentic SOC replace human analysts?",
    a: "No. An Agentic SOC augments human analysts by handling repetitive Tier-1 tasks (alert triage, log correlation, initial enrichment). This elevates analysts to focus on complex investigations, threat hunting, and strategic security decisions. Think of it as giving every junior analyst the decision-making support of a 10-year veteran.",
  },
  {
    q: "What is the difference between Agentic SOC and SOAR?",
    a: "SOAR (Security Orchestration, Automation, and Response) automates predefined workflows with if-then logic. An Agentic SOC goes further by using AI agents that reason about threats, adapt to novel attack patterns, and make autonomous decisions. SOAR automates known responses; an Agentic SOC reasons about unknown threats. SecureNexus includes both SOAR automation and agentic AI capabilities.",
  },
  {
    q: "How does SecureNexus implement the Agentic SOC model?",
    a: "SecureNexus implements the Agentic SOC model through its AI correlation engine powered by large language models on AWS Bedrock. The engine clusters alerts by attacker behavior patterns, maps to MITRE ATT&CK techniques with confidence scores, generates human-readable incident narratives, and recommends response actions. All of this happens autonomously, with analysts reviewing AI-generated insights rather than raw alerts.",
  },
  {
    q: "Is the Agentic SOC concept proven in production?",
    a: "Yes. SecureNexus is used by 50+ security teams that report 90% faster triage times and 70% reduction in false positives. The Agentic SOC model has been validated across industries including fintech, healthcare, and e-commerce, handling thousands of alerts per day with consistent accuracy.",
  },
];

const articleSchema = {
  "@context": "https://schema.org",
  "@type": "Article",
  headline: "What is an Agentic SOC? The Complete Guide (2026)",
  description:
    "An Agentic SOC is a security operations center where AI agents autonomously detect, investigate, and respond to threats. Learn how Agentic SOC differs from traditional SOCs and SOAR platforms.",
  author: {
    "@type": "Organization",
    name: "Arica Technologies",
    url: "https://aricatech.xyz",
  },
  publisher: {
    "@type": "Organization",
    name: "Arica Technologies",
    url: "https://aricatech.xyz",
  },
  url: "https://nexus.aricatech.xyz/product/agentic-soc",
  datePublished: "2026-01-15",
  dateModified: "2026-03-01",
  keywords: [
    "agentic SOC",
    "agentic security operations center",
    "autonomous SOC",
    "AI-powered SOC",
    "next-generation SOC",
  ],
  speakable: {
    "@type": "SpeakableSpecification",
    cssSelector: ["article > header > p", "article > section:first-of-type > p"],
  },
};

export default function AgenticSocPage() {
  const brutCard =
    "bg-white dark:bg-[#111827] border-[2.5px] border-[#1e293b] dark:border-[#334155] rounded-2xl shadow-[4px_4px_0px_#1e293b] dark:shadow-[4px_4px_0px_rgba(6,182,212,0.15)]";

  return (
    <ContentLayout
      title="What is an Agentic SOC?"
      breadcrumbs={[{ label: "Home", href: "/" }, { label: "Product", href: "/product" }, { label: "Agentic SOC" }]}
      faqs={faqs}
      jsonLd={[articleSchema]}
    >
      <article>
        <header className="mb-12">
          <div className="inline-flex items-center px-3 py-1 rounded-full border-2 border-cyan-300 dark:border-cyan-500/30 bg-cyan-50 dark:bg-cyan-500/10 text-cyan-700 dark:text-cyan-400 text-xs font-bold mb-4">
            Complete Guide
          </div>
          <h1 className="text-3xl md:text-5xl font-black mb-4 leading-tight">
            What is an Agentic SOC?
            <br />
            <span className="text-cyan-600 dark:text-cyan-400">The Complete Guide (2026)</span>
          </h1>
          <p className="speakable-summary text-lg text-[#64748b] dark:text-[#94a3b8] font-medium max-w-2xl leading-relaxed">
            An Agentic SOC is a security operations center where AI agents autonomously detect, investigate, and respond
            to threats — reducing manual analyst workload by 80% or more. This guide explains how Agentic SOC works, how
            it differs from traditional SOCs, and why it represents the future of security operations.
          </p>
        </header>

        <section className="mb-12">
          <h2 className="text-2xl md:text-3xl font-black mb-4">The Problem with Traditional SOCs</h2>
          <p className="text-[#64748b] dark:text-[#94a3b8] font-medium leading-relaxed mb-6">
            Traditional Security Operations Centers face a fundamental scaling problem. As organizations adopt more
            security tools and their attack surface grows, the volume of alerts grows exponentially — but analyst
            headcount grows linearly. The result is alert fatigue, missed threats, and burnout.
          </p>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
            {[
              { stat: "4,000+", label: "alerts/day average" },
              { stat: "45 min", label: "per manual triage" },
              { stat: "70%", label: "false positive rate" },
              { stat: "3-5", label: "tools per investigation" },
            ].map((item) => (
              <div key={item.label} className={`${brutCard} p-4 text-center`}>
                <div className="text-xl font-black text-cyan-600 dark:text-cyan-400">{item.stat}</div>
                <div className="text-xs text-[#94a3b8] font-semibold mt-1">{item.label}</div>
              </div>
            ))}
          </div>
          <p className="text-[#64748b] dark:text-[#94a3b8] font-medium leading-relaxed">
            The Agentic SOC model solves this by introducing AI agents that handle the repetitive, high-volume work of
            Tier-1 analysis. Instead of asking analysts to review every alert, AI agents correlate, triage, and enrich
            alerts autonomously — surfacing only the incidents that require human judgment.
          </p>
        </section>

        <section className="mb-12">
          <h2 className="text-2xl md:text-3xl font-black mb-4">Agentic SOC vs. Traditional SOC</h2>
          <p className="text-[#64748b] dark:text-[#94a3b8] font-medium leading-relaxed mb-6">
            The fundamental difference is autonomy. A traditional SOC is tool-assisted but human-driven. An Agentic SOC
            is AI-driven with human oversight.
          </p>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b-[2.5px] border-[#1e293b] dark:border-[#334155]">
                  <th className="text-left py-3 px-4 font-extrabold">Capability</th>
                  <th className="text-left py-3 px-4 font-extrabold text-red-600 dark:text-red-400">Traditional SOC</th>
                  <th className="text-left py-3 px-4 font-extrabold text-cyan-600 dark:text-cyan-400">Agentic SOC</th>
                </tr>
              </thead>
              <tbody>
                {comparisonData.map((row) => (
                  <tr key={row.feature} className="border-b border-[#e2e8f0] dark:border-[#1e293b]">
                    <td className="py-3 px-4 font-bold">{row.feature}</td>
                    <td className="py-3 px-4 text-[#64748b] dark:text-[#94a3b8] font-medium">
                      <span className="inline-flex items-center gap-1.5">
                        <XCircle className="h-3.5 w-3.5 text-red-500 flex-shrink-0" />
                        {row.traditional}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-[#64748b] dark:text-[#94a3b8] font-medium">
                      <span className="inline-flex items-center gap-1.5">
                        <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500 flex-shrink-0" />
                        {row.agentic}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <section className="mb-12">
          <h2 className="text-2xl md:text-3xl font-black mb-6">Measurable Impact</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {benefits.map((benefit) => (
              <div key={benefit.label} className={`${brutCard} p-6`}>
                <div className="flex items-start gap-4">
                  <div className="w-12 h-12 rounded-xl bg-cyan-100 dark:bg-cyan-500/10 flex items-center justify-center flex-shrink-0">
                    <benefit.icon className="h-6 w-6 text-cyan-600 dark:text-cyan-400" />
                  </div>
                  <div>
                    <div className="text-2xl font-black text-cyan-600 dark:text-cyan-400">{benefit.stat}</div>
                    <h3 className="font-extrabold">{benefit.label}</h3>
                    <p className="text-sm text-[#64748b] dark:text-[#94a3b8] font-medium mt-1">{benefit.description}</p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </section>

        <section className="mb-12">
          <h2 className="text-2xl md:text-3xl font-black mb-4">How SecureNexus Implements the Agentic SOC</h2>
          <p className="text-[#64748b] dark:text-[#94a3b8] font-medium leading-relaxed mb-6">
            SecureNexus is purpose-built as an Agentic SOC platform. Here is how the platform operationalizes the
            Agentic SOC model:
          </p>
          <div className="space-y-4">
            {[
              {
                icon: Brain,
                title: "AI Correlation Engine",
                text: "Powered by large language models on AWS Bedrock, the engine analyzes alert clusters, identifies attacker behavior patterns, and generates incident narratives with MITRE ATT&CK technique mapping and confidence scores.",
              },
              {
                icon: Shield,
                title: "Autonomous Triage Agent",
                text: "The triage agent processes incoming alerts in real-time, deduplicates them, assigns severity based on behavioral context, and routes them to the appropriate investigation workflow — all without human intervention.",
              },
              {
                icon: Zap,
                title: "Response Orchestration",
                text: "Pre-built and customizable playbooks execute containment, notification, and remediation actions automatically. Analysts approve or override AI recommendations, maintaining human oversight on critical decisions.",
              },
            ].map((item) => (
              <div key={item.title} className={`${brutCard} p-6`}>
                <div className="flex items-start gap-4">
                  <div className="w-10 h-10 rounded-xl bg-cyan-100 dark:bg-cyan-500/10 flex items-center justify-center flex-shrink-0">
                    <item.icon className="h-5 w-5 text-cyan-600 dark:text-cyan-400" />
                  </div>
                  <div>
                    <h3 className="font-extrabold mb-1">{item.title}</h3>
                    <p className="text-sm text-[#64748b] dark:text-[#94a3b8] leading-relaxed font-medium">
                      {item.text}
                    </p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </section>

        <section className="mb-12">
          <h2 className="text-2xl md:text-3xl font-black mb-4">Getting Started with an Agentic SOC</h2>
          <p className="text-[#64748b] dark:text-[#94a3b8] font-medium leading-relaxed mb-4">
            Adopting an Agentic SOC does not require replacing your existing security stack. SecureNexus integrates with
            your current tools via read-only API connectors. The implementation path is straightforward:
          </p>
          <ol className="space-y-3 text-[#64748b] dark:text-[#94a3b8] font-medium">
            {[
              "Connect your EDR, SIEM, and cloud security tools (under 30 minutes)",
              "AI correlation engine begins clustering and triaging alerts immediately",
              "Review AI-generated incident narratives and tune alert rules",
              "Enable automated response playbooks for known threat patterns",
              "Scale to full Agentic SOC operations over 2-4 weeks",
            ].map((step, i) => (
              <li key={i} className="flex items-start gap-3">
                <span className="w-6 h-6 rounded-full bg-cyan-100 dark:bg-cyan-500/10 flex items-center justify-center flex-shrink-0 text-xs font-bold text-cyan-600 dark:text-cyan-400">
                  {i + 1}
                </span>
                <span className="text-sm leading-relaxed">{step}</span>
              </li>
            ))}
          </ol>
        </section>
      </article>
    </ContentLayout>
  );
}

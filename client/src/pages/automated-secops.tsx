import { Activity, ArrowRight, Brain, Clock, Shield, Target, Workflow, Zap, ListChecks } from "lucide-react";
import ContentLayout from "./content-layout";

const evolutionSteps = [
  {
    phase: "1. Log Management",
    description: "Centralized syslog servers. Manual searching and rudimentary alerting. Reactive only.",
    years: "Before 2005",
  },
  {
    phase: "2. SIEM 1.0",
    description: "Rule-based correlation. High false positives. Focused primarily on compliance reporting.",
    years: "2005-2015",
  },
  {
    phase: "3. SIEM + SOAR",
    description:
      "Automated playbooks bolted onto SIEM alerts. Faster response but still overwhelmed by Tier-1 triage volume.",
    years: "2015-2023",
  },
  {
    phase: "4. Agentic SOC",
    description:
      "AI agents autonomously map attacker behavior, triage alerts intuitively without rules, and execute orchestrated response.",
    years: "2024-Present",
  },
];

const faqs = [
  {
    q: "What is an Automated Security Operations Center?",
    a: "An Automated Security Operations Center (Automated SecOps) is a modern approach to cybersecurity where artificial intelligence and orchestration (SOAR) handle the majority of Tier-1 and Tier-2 triage and response tasks autonomously, enabling human analysts to focus on higher-level threat hunting and strategic defense.",
  },
  {
    q: "How does Automated SecOps differ from a traditional SIEM?",
    a: "Traditional SIEM systems are primarily log aggregators that rely on human-written, static rules to generate alerts. This leads to high false positive rates and alert fatigue. Automated SecOps uses AI-driven behavioral analysis to understand the context of alerts, cluster them into comprehensive incident narratives, and map them to frameworks like MITRE ATT&CK without manual rule tuning.",
  },
  {
    q: "Will Automated SecOps replace security analysts?",
    a: "No. Automated SecOps is designed to augment analysts, not replace them. By automating the repetitive, high-volume tasks of alert triage, correlation, and initial enrichment (the 'heavy lifting'), human analysts are freed to perform complex investigations, approve critical response actions, and focus on strategic threat mitigation.",
  },
  {
    q: "What role does AI play in an Automated SOC?",
    a: "In an Automated SOC, AI handles complex reasoning tasks that traditional SOAR playbooks cannot. This includes natural language processing to generate incident narratives, behavioral clustering to identify novel attack campaigns, and predictive defense algorithms that anticipate adversary steps.",
  },
];

const articleSchema = {
  "@context": "https://schema.org",
  "@type": "Article",
  headline: "Automated Security Operations: From SIEM to Agentic SOC",
  description:
    "Explore the evolution of security operations from traditional SIEM to fully Automated SecOps and Agentic SOCs powered by AI. Learn how to eliminate alert fatigue.",
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
  url: "https://nexus.aricatech.xyz/blog/automated-secops",
  datePublished: "2026-03-05",
  dateModified: "2026-03-05",
  keywords: [
    "automated security operations",
    "automated secops",
    "next-gen SIEM",
    "SOAR automation",
    "AI SOC",
    "Agentic SOC",
  ],
};

export default function AutomatedSecopsPage() {
  const brutCard =
    "bg-white dark:bg-[#111827] border-[2.5px] border-[#1e293b] dark:border-[#334155] rounded-2xl shadow-[4px_4px_0px_#1e293b] dark:shadow-[4px_4px_0px_rgba(6,182,212,0.15)]";

  return (
    <ContentLayout
      title="Automated Security Operations"
      breadcrumbs={[{ label: "Home", href: "/" }, { label: "Blog", href: "/blog" }, { label: "Automated SecOps" }]}
      faqs={faqs}
      jsonLd={[articleSchema]}
    >
      <article>
        <header className="mb-12">
          <div className="inline-flex items-center px-3 py-1 rounded-full border-2 border-indigo-300 dark:border-indigo-500/30 bg-indigo-50 dark:bg-indigo-500/10 text-indigo-700 dark:text-indigo-400 text-xs font-bold mb-4">
            SecOps Strategy
          </div>
          <h1 className="text-3xl md:text-5xl font-black mb-4 leading-tight">
            Automated Security Operations:
            <br />
            <span className="text-indigo-600 dark:text-indigo-400">From SIEM to Agentic SOC</span>
          </h1>
          <p className="text-lg text-[#64748b] dark:text-[#94a3b8] font-medium max-w-2xl leading-relaxed">
            The era of manual alert triage is over. As attacker velocity increases and the cybersecurity talent shortage
            deepens, organizations are shifting from reactive SIEM tools to proactive, Automated SecOps platforms driven
            by AI agents.
          </p>
        </header>

        <section className="mb-12">
          <h2 className="text-2xl md:text-3xl font-black mb-4">The Evolution of the SOC</h2>
          <p className="text-[#64748b] dark:text-[#94a3b8] font-medium leading-relaxed mb-6">
            Security operations have evolved significantly over the past two decades. What started as basic log
            aggregation has now fundamentally transformed into autonomous, intelligent systems capable of reasoning.
          </p>
          <div className="space-y-4">
            {evolutionSteps.map((step, index) => (
              <div key={index} className={`${brutCard} p-5 flex items-start gap-4`}>
                <div className="w-12 h-12 rounded-xl bg-indigo-100 dark:bg-indigo-500/10 flex items-center justify-center flex-shrink-0">
                  <span className="font-black text-indigo-600 dark:text-indigo-400">{index + 1}</span>
                </div>
                <div>
                  <div className="flex justify-between items-center mb-1">
                    <h3 className="font-extrabold text-lg">{step.phase}</h3>
                    <span className="text-xs font-bold text-[#94a3b8] dark:text-[#64748b]">{step.years}</span>
                  </div>
                  <p className="text-sm text-[#64748b] dark:text-[#94a3b8] font-medium leading-relaxed">
                    {step.description}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </section>

        <section className="mb-12">
          <h2 className="text-2xl md:text-3xl font-black mb-6">Why Traditional SIEM is Broken</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className={`${brutCard} p-6 border-red-200 dark:border-red-900/30`}>
              <h3 className="flex items-center gap-2 font-extrabold text-red-600 dark:text-red-400 mb-3">
                <Target className="h-5 w-5" />
                Alert Fatigue
              </h3>
              <p className="text-sm text-[#64748b] dark:text-[#94a3b8] font-medium leading-relaxed">
                Traditional SIEMs rely on static threshold rules. If a user fails to log in 5 times, it triggers an
                alert. In enterprise environments, this approach generates thousands of false positives daily, drowning
                analysts in noise and masking actual targeted intrusions.
              </p>
            </div>
            <div className={`${brutCard} p-6 border-red-200 dark:border-red-900/30`}>
              <h3 className="flex items-center gap-2 font-extrabold text-red-600 dark:text-red-400 mb-3">
                <Clock className="h-5 w-5" />
                Slow Triage Times
              </h3>
              <p className="text-sm text-[#64748b] dark:text-[#94a3b8] font-medium leading-relaxed">
                Without context, an analyst takes an average of 45 minutes to investigate a single SIEM alert. They must
                manually pivot between the SIEM, EDR, firewall logs, and threat intelligence platforms to understand the
                scope of the incident.
              </p>
            </div>
          </div>
        </section>

        <section className="mb-12">
          <h2 className="text-2xl md:text-3xl font-black mb-6">The Anatomy of Automated SecOps</h2>
          <p className="text-[#64748b] dark:text-[#94a3b8] font-medium leading-relaxed mb-6">
            A modern Automated SecOps architecture—like the Agentic SOC built by SecureNexus—integrates three critical
            layers seamlessly.
          </p>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className={`${brutCard} p-6`}>
              <Brain className="h-8 w-8 text-indigo-500 mb-4" />
              <h3 className="font-extrabold text-lg mb-2">1. AI Alert Correlation</h3>
              <p className="text-sm text-[#64748b] dark:text-[#94a3b8] font-medium">
                Using Large Language Models (LLMs) to automatically understand the semantics of raw logs from dozens of
                tools, clustering related anomalies into a unified incident narrative based on attacker behavior.
              </p>
            </div>
            <div className={`${brutCard} p-6`}>
              <ListChecks className="h-8 w-8 text-indigo-500 mb-4" />
              <h3 className="font-extrabold text-lg mb-2">2. MITRE ATT&CK Mapping</h3>
              <p className="text-sm text-[#64748b] dark:text-[#94a3b8] font-medium">
                Real-time alignment of clustered behaviors to specific MITRE techniques, giving analysts immediate
                context into the adversary's goals, tactics, and current progress in the kill chain.
              </p>
            </div>
            <div className={`${brutCard} p-6`}>
              <Zap className="h-8 w-8 text-indigo-500 mb-4" />
              <h3 className="font-extrabold text-lg mb-2">3. SOAR Execution</h3>
              <p className="text-sm text-[#64748b] dark:text-[#94a3b8] font-medium">
                Executing automated playbooks instantly: isolating endpoints, suspending compromised accounts, and
                dropping malicious IPs at the firewall level without manual scripting.
              </p>
            </div>
          </div>
        </section>

        <section className="mb-12">
          <div className="bg-indigo-600 text-white rounded-2xl p-8 shadow-[6px_6px_0px_#1e293b] dark:shadow-[6px_6px_0px_rgba(79,70,229,0.25)]">
            <h2 className="text-2xl md:text-3xl font-black mb-4">Ready to automate your SOC?</h2>
            <p className="font-medium mb-6 opacity-90 max-w-xl text-indigo-50">
              Discover how SecureNexus helps security teams reduce alert triage times by 90% and lower false positive
              rates drastically using Agentic AI.
            </p>
            <a
              href="/"
              className="inline-flex items-center gap-2 bg-white text-indigo-600 px-6 py-3 rounded-xl font-bold border-2 border-transparent transition-transform hover:-translate-y-1 hover:shadow-lg"
            >
              Explore SecureNexus
              <ArrowRight className="h-4 w-4" />
            </a>
          </div>
        </section>
      </article>
    </ContentLayout>
  );
}

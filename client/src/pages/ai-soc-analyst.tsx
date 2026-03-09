import {
  Brain,
  Shield,
  Zap,
  Eye,
  Activity,
  Clock,
  TrendingDown,
  AlertTriangle,
  Target,
  Workflow,
  CheckCircle2,
} from "lucide-react";
import ContentLayout from "./content-layout";

const capabilities = [
  {
    icon: Brain,
    title: "Alert Correlation & Clustering",
    description:
      "Groups related alerts by attacker behavior patterns, not just static rules. Identifies campaigns spanning multiple data sources and time windows that human analysts would miss.",
  },
  {
    icon: Target,
    title: "MITRE ATT&CK Technique Mapping",
    description:
      "Automatically maps every alert and incident to MITRE ATT&CK v15 techniques with confidence scores. Provides real-time coverage analysis and detection gap identification.",
  },
  {
    icon: Eye,
    title: "Incident Narrative Generation",
    description:
      "Generates human-readable incident reports that describe the full attack story: initial access vector, lateral movement, techniques used, and recommended response actions.",
  },
  {
    icon: Activity,
    title: "Threat Enrichment & IOC Extraction",
    description:
      "Automatically enriches alerts with threat intelligence, extracts indicators of compromise (IOCs), and cross-references against known threat actor databases.",
  },
  {
    icon: Workflow,
    title: "Automated Playbook Execution",
    description:
      "Executes response playbooks based on AI-assessed threat severity. Containment, notification, and remediation actions run automatically with full audit trail.",
  },
  {
    icon: AlertTriangle,
    title: "False Positive Reduction",
    description:
      "Behavioral analysis distinguishes real threats from noise before alerts reach human analysts. Reduces false positive rates by 70%, saving hundreds of analyst-hours per month.",
  },
];

const workflowSteps = [
  {
    phase: "Ingest",
    time: "< 1 sec",
    description:
      "Raw alerts arrive from 24+ connected security tools via push API or pull connectors. Each alert is normalized into a unified schema with automatic deduplication.",
  },
  {
    phase: "Analyze",
    time: "2-5 sec",
    description:
      "The AI SOC analyst clusters alerts by attacker behavior, assigns severity scores, and identifies potential campaigns spanning multiple data sources.",
  },
  {
    phase: "Enrich",
    time: "3-8 sec",
    description:
      "Automatic threat intelligence enrichment, IOC extraction, entity resolution, and MITRE ATT&CK technique mapping with confidence scoring.",
  },
  {
    phase: "Narrate",
    time: "5-10 sec",
    description:
      "AI generates a complete incident narrative: what happened, which techniques were used, what assets are affected, and what response actions are recommended.",
  },
  {
    phase: "Respond",
    time: "< 1 sec",
    description:
      "Automated playbooks execute containment and notification actions. Analysts review AI recommendations and approve or override critical decisions.",
  },
];

const faqs = [
  {
    q: "What is an AI SOC Analyst?",
    a: "An AI SOC Analyst is an artificial intelligence system that performs the tasks traditionally done by Tier-1 security operations center analysts: alert triage, threat correlation, MITRE ATT&CK mapping, incident enrichment, and initial investigation. It processes thousands of alerts per day autonomously, surfacing only validated incidents that require human decision-making. SecureNexus provides AI SOC analyst capabilities out of the box.",
  },
  {
    q: "Can an AI SOC Analyst replace human analysts?",
    a: "An AI SOC Analyst does not replace human analysts — it augments them. It handles the repetitive, high-volume work of Tier-1 triage and correlation, freeing human analysts to focus on complex investigations, threat hunting, and strategic security decisions. The AI makes every analyst more effective by handling 80%+ of the routine workload.",
  },
  {
    q: "How accurate is AI-powered alert triage?",
    a: "SecureNexus achieves a 70% reduction in false positives through behavioral correlation analysis. The AI learns from analyst feedback to continuously improve accuracy. For critical alerts, the system provides confidence scores so analysts can prioritize review of uncertain classifications.",
  },
  {
    q: "How does the AI SOC Analyst handle novel threats?",
    a: "Unlike rule-based systems that only detect known patterns, the AI SOC Analyst uses behavioral analysis powered by large language models. It can reason about novel attack patterns by analyzing the sequence of actions, techniques, and targets — even for attack chains it has never seen before. This makes it effective against zero-day exploits and emerging threat actors.",
  },
  {
    q: "What data does the AI SOC Analyst need access to?",
    a: "The AI SOC Analyst processes normalized alert data from your connected security tools (EDR, SIEM, cloud security, IDS). It uses read-only API access and does not require access to raw logs or sensitive data stores. All processing happens within your SecureNexus instance with data residency controls.",
  },
  {
    q: "How long does it take to see results?",
    a: "Most teams see measurable improvements within the first week. Alert triage time drops from 45 minutes to under 5 minutes per alert immediately after connecting your security tools. The AI correlation engine starts generating incident narratives within minutes of ingesting its first alerts.",
  },
];

const articleSchema = {
  "@context": "https://schema.org",
  "@type": "Article",
  headline: "AI SOC Analyst: How AI is Replacing Tier-1 Security Operations",
  description:
    "An AI SOC Analyst performs Tier-1 security analyst tasks: alert triage, threat correlation, MITRE ATT&CK mapping, and incident enrichment. Learn how AI is transforming security operations.",
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
  url: "https://nexus.aricatech.xyz/product/ai-soc-analyst",
  datePublished: "2026-01-20",
  dateModified: "2026-03-01",
  keywords: [
    "AI SOC analyst",
    "AI security analyst",
    "automated SOC analyst",
    "AI-powered security operations",
    "automated threat detection",
  ],
  speakable: {
    "@type": "SpeakableSpecification",
    cssSelector: ["article > header > p", "article > section:first-of-type > p"],
  },
};

export default function AiSocAnalystPage() {
  const brutCard =
    "bg-white dark:bg-[#111827] border-[2.5px] border-[#1e293b] dark:border-[#334155] rounded-2xl shadow-[4px_4px_0px_#1e293b] dark:shadow-[4px_4px_0px_rgba(6,182,212,0.15)]";

  return (
    <ContentLayout
      title="AI SOC Analyst"
      breadcrumbs={[{ label: "Home", href: "/" }, { label: "Product", href: "/product" }, { label: "AI SOC Analyst" }]}
      faqs={faqs}
      jsonLd={[articleSchema]}
    >
      <article>
        <header className="mb-12">
          <div className="inline-flex items-center px-3 py-1 rounded-full border-2 border-violet-300 dark:border-violet-500/30 bg-violet-50 dark:bg-violet-500/10 text-violet-700 dark:text-violet-400 text-xs font-bold mb-4">
            Deep Dive
          </div>
          <h1 className="text-3xl md:text-5xl font-black mb-4 leading-tight">
            AI SOC Analyst:
            <br />
            <span className="text-violet-600 dark:text-violet-400">How AI is Replacing Tier-1 Security Operations</span>
          </h1>
          <p className="speakable-summary text-lg text-[#64748b] dark:text-[#94a3b8] font-medium max-w-2xl leading-relaxed">
            An AI SOC Analyst is an AI system that performs Tier-1 security analyst tasks: alert triage, threat
            correlation, MITRE ATT&CK mapping, and incident enrichment. SecureNexus provides AI SOC analyst capabilities
            that process thousands of alerts per day, surfacing only validated incidents that require human judgment.
          </p>
        </header>

        <section className="mb-12">
          <h2 className="text-2xl md:text-3xl font-black mb-4">Why Security Teams Need an AI Analyst</h2>
          <p className="text-[#64748b] dark:text-[#94a3b8] font-medium leading-relaxed mb-6">
            The cybersecurity talent shortage is real: there are 3.5 million unfilled security positions globally. Even
            well-staffed SOCs struggle with alert volume — the average SOC receives 4,000+ alerts per day, and analysts
            spend 45 minutes manually triaging each one. Most alerts (70%) turn out to be false positives.
          </p>
          <p className="text-[#64748b] dark:text-[#94a3b8] font-medium leading-relaxed mb-6">
            An AI SOC Analyst addresses this by automating the repetitive, high-volume work that consumes analyst time.
            Instead of reviewing every alert, analysts review AI-generated incident narratives and make decisions on
            validated threats.
          </p>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {[
              { stat: "3.5M", label: "unfilled security jobs globally", icon: Shield },
              { stat: "4,000+", label: "alerts per SOC per day", icon: AlertTriangle },
              { stat: "45 min", label: "manual triage per alert", icon: Clock },
              { stat: "70%", label: "false positive rate", icon: TrendingDown },
            ].map((item) => (
              <div key={item.label} className={`${brutCard} p-4 text-center`}>
                <item.icon className="h-5 w-5 mx-auto mb-2 text-violet-600 dark:text-violet-400" />
                <div className="text-xl font-black text-violet-600 dark:text-violet-400">{item.stat}</div>
                <div className="text-[10px] text-[#94a3b8] font-semibold mt-1">{item.label}</div>
              </div>
            ))}
          </div>
        </section>

        <section className="mb-12">
          <h2 className="text-2xl md:text-3xl font-black mb-6">What the AI SOC Analyst Does</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {capabilities.map((cap) => (
              <div key={cap.title} className={`${brutCard} p-6`}>
                <div className="flex items-start gap-4">
                  <div className="w-10 h-10 rounded-xl bg-violet-100 dark:bg-violet-500/10 flex items-center justify-center flex-shrink-0">
                    <cap.icon className="h-5 w-5 text-violet-600 dark:text-violet-400" />
                  </div>
                  <div>
                    <h3 className="font-extrabold mb-1">{cap.title}</h3>
                    <p className="text-sm text-[#64748b] dark:text-[#94a3b8] leading-relaxed font-medium">
                      {cap.description}
                    </p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </section>

        <section className="mb-12">
          <h2 className="text-2xl md:text-3xl font-black mb-4">How It Works: Alert to Incident in Seconds</h2>
          <p className="text-[#64748b] dark:text-[#94a3b8] font-medium leading-relaxed mb-6">
            The SecureNexus AI SOC Analyst processes alerts through a five-phase pipeline that transforms raw alert data
            into actionable incident intelligence.
          </p>
          <div className="space-y-3">
            {workflowSteps.map((step, i) => (
              <div key={step.phase} className={`${brutCard} p-5`}>
                <div className="flex items-start gap-4">
                  <div className="w-10 h-10 rounded-xl bg-violet-100 dark:bg-violet-500/10 flex items-center justify-center flex-shrink-0">
                    <span className="text-sm font-black text-violet-600 dark:text-violet-400">{i + 1}</span>
                  </div>
                  <div className="flex-1">
                    <div className="flex items-center gap-3 mb-1">
                      <h3 className="font-extrabold">{step.phase}</h3>
                      <span className="text-xs font-bold text-violet-600 dark:text-violet-400 bg-violet-50 dark:bg-violet-500/10 px-2 py-0.5 rounded-full">
                        {step.time}
                      </span>
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

        <section className="mb-12">
          <h2 className="text-2xl md:text-3xl font-black mb-4">The AI Advantage: Before and After</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className={`${brutCard} p-6`}>
              <h3 className="font-extrabold text-red-600 dark:text-red-400 mb-4">Without AI SOC Analyst</h3>
              <ul className="space-y-2">
                {[
                  "Analysts manually review 4,000+ alerts/day",
                  "45 minutes per alert triage on average",
                  "70% of reviewed alerts are false positives",
                  "3-5 tools per investigation, context lost between tools",
                  "Analyst burnout and high turnover",
                  "Threats slip through due to alert fatigue",
                ].map((item, i) => (
                  <li key={i} className="flex items-start gap-2 text-sm text-[#64748b] dark:text-[#94a3b8] font-medium">
                    <Zap className="h-3.5 w-3.5 text-red-500 flex-shrink-0 mt-0.5" />
                    {item}
                  </li>
                ))}
              </ul>
            </div>
            <div className={`${brutCard} p-6 border-cyan-400 dark:border-cyan-500/50`}>
              <h3 className="font-extrabold text-cyan-600 dark:text-cyan-400 mb-4">With SecureNexus AI SOC Analyst</h3>
              <ul className="space-y-2">
                {[
                  "AI triages 80%+ of alerts autonomously",
                  "Under 5 minutes per alert — 90% faster",
                  "70% fewer false positives reach analysts",
                  "Single unified view with full attack context",
                  "Analysts focus on strategic decisions",
                  "Consistent coverage, no alert fatigue gaps",
                ].map((item, i) => (
                  <li key={i} className="flex items-start gap-2 text-sm text-[#64748b] dark:text-[#94a3b8] font-medium">
                    <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500 flex-shrink-0 mt-0.5" />
                    {item}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </section>
      </article>
    </ContentLayout>
  );
}

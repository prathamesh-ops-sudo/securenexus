import { Fragment } from "react";
import { CheckCircle2, XCircle, Minus } from "lucide-react";
import ContentLayout from "./content-layout";

type Support = "full" | "partial" | "none";

interface ComparisonRow {
  category: string;
  feature: string;
  securenexus: Support;
  sentinel: Support;
  splunk: Support;
  qradar: Support;
  securenexusNote?: string;
  sentinelNote?: string;
  splunkNote?: string;
  qradarNote?: string;
}

const comparisonRows: ComparisonRow[] = [
  {
    category: "AI & Automation",
    feature: "Agentic SOC (Autonomous AI Agents)",
    securenexus: "full",
    sentinel: "none",
    splunk: "none",
    qradar: "none",
    securenexusNote: "AI agents autonomously triage, correlate, and respond",
    sentinelNote: "Rule-based automation only",
    splunkNote: "Manual analyst workflows",
    qradarNote: "Rule-based detection only",
  },
  {
    category: "AI & Automation",
    feature: "AI SOC Analyst (Tier-1 Replacement)",
    securenexus: "full",
    sentinel: "partial",
    splunk: "partial",
    qradar: "none",
    securenexusNote: "Built-in LLM-powered analyst with narrative generation",
    sentinelNote: "Copilot for Security (separate license)",
    splunkNote: "AI Assistant (add-on)",
    qradarNote: "No native AI analyst",
  },
  {
    category: "AI & Automation",
    feature: "AI Incident Narrative Generation",
    securenexus: "full",
    sentinel: "partial",
    splunk: "none",
    qradar: "none",
    securenexusNote: "Auto-generates human-readable incident reports with MITRE mapping",
  },
  {
    category: "AI & Automation",
    feature: "SOAR Playbook Automation",
    securenexus: "full",
    sentinel: "full",
    splunk: "full",
    qradar: "partial",
    securenexusNote: "Built-in SOAR with visual playbook builder",
    sentinelNote: "Logic Apps integration",
    splunkNote: "Splunk SOAR (separate product)",
    qradarNote: "Basic response actions",
  },
  {
    category: "Detection & Response",
    feature: "MITRE ATT&CK Auto-Mapping",
    securenexus: "full",
    sentinel: "partial",
    splunk: "partial",
    qradar: "partial",
    securenexusNote: "Real-time technique mapping with confidence scores",
    sentinelNote: "Manual mapping via analytics rules",
    splunkNote: "Requires Enterprise Security add-on",
    qradarNote: "Limited technique coverage",
  },
  {
    category: "Detection & Response",
    feature: "Behavioral Threat Correlation",
    securenexus: "full",
    sentinel: "partial",
    splunk: "partial",
    qradar: "partial",
    securenexusNote: "LLM-based behavioral clustering across data sources",
    sentinelNote: "Fusion-based correlation",
    splunkNote: "Risk-based alerting",
    qradarNote: "Offense-based correlation",
  },
  {
    category: "Detection & Response",
    feature: "Threat Intelligence Integration",
    securenexus: "full",
    sentinel: "full",
    splunk: "full",
    qradar: "full",
    securenexusNote: "STIX/TAXII feeds, IOC enrichment, entity graph",
  },
  {
    category: "Detection & Response",
    feature: "Predictive Defense",
    securenexus: "full",
    sentinel: "none",
    splunk: "none",
    qradar: "none",
    securenexusNote: "ML-based attack prediction and proactive recommendations",
  },
  {
    category: "Multi-Tenancy & MSSP",
    feature: "Native Multi-Tenant Architecture",
    securenexus: "full",
    sentinel: "partial",
    splunk: "partial",
    qradar: "partial",
    securenexusNote: "Built-in org hierarchy with row-level isolation",
    sentinelNote: "Lighthouse for multi-tenant management",
    splunkNote: "Search head clustering",
    qradarNote: "Domain-based multi-tenancy",
  },
  {
    category: "Multi-Tenancy & MSSP",
    feature: "MSSP Parent-Child Organizations",
    securenexus: "full",
    sentinel: "partial",
    splunk: "none",
    qradar: "partial",
    securenexusNote: "Native MSSP hierarchy with delegated access controls",
    sentinelNote: "Azure Lighthouse delegation",
    splunkNote: "No native MSSP support",
    qradarNote: "Managed host model",
  },
  {
    category: "Multi-Tenancy & MSSP",
    feature: "Cross-Tenant Dashboards",
    securenexus: "full",
    sentinel: "partial",
    splunk: "none",
    qradar: "partial",
    securenexusNote: "Unified MSSP view across all child organizations",
  },
  {
    category: "Compliance & Governance",
    feature: "Automated Compliance Reporting",
    securenexus: "full",
    sentinel: "partial",
    splunk: "partial",
    qradar: "partial",
    securenexusNote: "SOC 2, ISO 27001, NIST CSF, GDPR with evidence collection",
    sentinelNote: "Microsoft Compliance Manager (separate)",
    splunkNote: "Compliance add-on",
    qradarNote: "Basic compliance dashboards",
  },
  {
    category: "Compliance & Governance",
    feature: "Audit Trail with Tamper Detection",
    securenexus: "full",
    sentinel: "partial",
    splunk: "full",
    qradar: "partial",
    securenexusNote: "Hash-chained audit log with export and date filtering",
  },
  {
    category: "Compliance & Governance",
    feature: "Data Residency Controls",
    securenexus: "full",
    sentinel: "full",
    splunk: "partial",
    qradar: "partial",
    securenexusNote: "Per-org data residency with Indian hosting available",
    sentinelNote: "Azure region selection",
    splunkNote: "Cloud region selection",
    qradarNote: "On-prem or IBM Cloud",
  },
  {
    category: "Deployment & Pricing",
    feature: "Time to Deploy",
    securenexus: "full",
    sentinel: "partial",
    splunk: "none",
    qradar: "none",
    securenexusNote: "Under 30 minutes with read-only API connectors",
    sentinelNote: "Hours to days (Azure setup)",
    splunkNote: "Days to weeks (infrastructure)",
    qradarNote: "Weeks (appliance-based)",
  },
  {
    category: "Deployment & Pricing",
    feature: "Free Tier Available",
    securenexus: "full",
    sentinel: "partial",
    splunk: "none",
    qradar: "none",
    securenexusNote: "Free: 1,000 alerts/day, 5 connectors, basic AI",
    sentinelNote: "Free trial only",
    splunkNote: "No free tier",
    qradarNote: "No free tier",
  },
  {
    category: "Deployment & Pricing",
    feature: "Pricing Model",
    securenexus: "full",
    sentinel: "partial",
    splunk: "none",
    qradar: "none",
    securenexusNote: "Starts at $49/mo (Pro), $199/mo (Enterprise)",
    sentinelNote: "Pay-per-GB ingested (unpredictable costs)",
    splunkNote: "Workload-based pricing (high cost)",
    qradarNote: "EPS-based licensing",
  },
  {
    category: "Deployment & Pricing",
    feature: "Indian Data Hosting",
    securenexus: "full",
    sentinel: "full",
    splunk: "partial",
    qradar: "none",
    securenexusNote: "AWS Mumbai region with data residency enforcement",
    sentinelNote: "Azure Central India region",
    splunkNote: "Limited India availability",
    qradarNote: "No India cloud region",
  },
];

function SupportIcon({ level }: { level: Support }) {
  if (level === "full") return <CheckCircle2 className="h-4 w-4 text-emerald-500" aria-label="Fully supported" />;
  if (level === "partial") return <Minus className="h-4 w-4 text-amber-500" aria-label="Partially supported" />;
  return <XCircle className="h-4 w-4 text-red-400" aria-label="Not supported" />;
}

const faqs = [
  {
    q: "How does SecureNexus compare to Microsoft Sentinel?",
    a: "SecureNexus is purpose-built as an Agentic SOC with autonomous AI agents that triage, correlate, and respond to threats without manual intervention. Microsoft Sentinel is a cloud-native SIEM that relies on rule-based analytics and requires a separate Copilot for Security license for AI capabilities. SecureNexus deploys in under 30 minutes, starts at $49/month, and includes built-in SOAR and MSSP support. Sentinel uses pay-per-GB pricing which can lead to unpredictable costs at scale.",
  },
  {
    q: "How does SecureNexus compare to Splunk?",
    a: "Splunk is a powerful log analytics platform that evolved into a SIEM, but it requires significant infrastructure, weeks of deployment time, and premium add-ons for SOAR (Splunk SOAR) and AI (AI Assistant). SecureNexus includes AI SOC analyst, SOAR playbooks, MITRE ATT&CK mapping, and compliance reporting in a single platform that deploys in 30 minutes. SecureNexus uses AI agents for autonomous triage and response, while Splunk relies primarily on manual analyst workflows.",
  },
  {
    q: "How does SecureNexus compare to IBM QRadar?",
    a: "IBM QRadar is an established SIEM with offense-based correlation, but it uses an appliance-based deployment model that takes weeks to set up and lacks native AI analyst capabilities. SecureNexus provides autonomous AI-powered triage, real-time MITRE ATT&CK mapping with confidence scores, and a modern multi-tenant architecture. QRadar has no free tier and no native MSSP parent-child hierarchy.",
  },
  {
    q: "Is SecureNexus suitable for replacing Splunk or Sentinel?",
    a: "SecureNexus is designed as a next-generation Agentic SOC platform that can replace or complement traditional SIEMs. For organizations drowning in alert fatigue, SecureNexus provides 90% faster triage and 70% fewer false positives through AI-powered correlation. It integrates with 24+ security tools via read-only API connectors, so teams can run SecureNexus alongside their existing SIEM during migration.",
  },
  {
    q: "Why is SecureNexus significantly cheaper than Splunk and Sentinel?",
    a: "SecureNexus uses a flat-rate pricing model ($49/mo Pro, $199/mo Enterprise) instead of volume-based pricing (per-GB or per-EPS). Traditional SIEMs charge based on data ingestion volume, which means costs scale unpredictably as log volumes grow. SecureNexus uses efficient AI-powered correlation that processes alerts without requiring massive log storage, keeping costs predictable at any scale.",
  },
  {
    q: "Can SecureNexus be used by MSSPs managing multiple clients?",
    a: "Yes. SecureNexus includes native MSSP support with parent-child organization hierarchy, cross-tenant dashboards, and delegated access controls. This is a built-in feature, not an add-on. Splunk has no native MSSP support, while Sentinel and QRadar offer limited multi-tenant management that requires additional configuration.",
  },
];

const comparisonSchema = {
  "@context": "https://schema.org",
  "@type": "Article",
  headline: "SecureNexus vs Sentinel vs Splunk vs QRadar: Agentic SOC Comparison (2026)",
  description:
    "Detailed feature-by-feature comparison of SecureNexus Agentic SOC platform against Microsoft Sentinel, Splunk, and IBM QRadar across AI capabilities, MSSP support, compliance, and pricing.",
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
  url: "https://nexus.aricatech.xyz/product/comparison",
  datePublished: "2026-02-17",
  dateModified: "2026-02-17",
  keywords: [
    "SecureNexus vs Sentinel",
    "SecureNexus vs Splunk",
    "SecureNexus vs QRadar",
    "agentic SOC comparison",
    "SIEM comparison 2026",
    "best SOC platform",
    "AI SOC analyst comparison",
  ],
  speakable: {
    "@type": "SpeakableSpecification",
    cssSelector: [".speakable-summary", ".speakable-verdict"],
  },
};

export default function ProductComparisonPage() {
  const brutCard =
    "bg-white dark:bg-[#111827] border-[2.5px] border-[#1e293b] dark:border-[#334155] rounded-2xl shadow-[4px_4px_0px_#1e293b] dark:shadow-[4px_4px_0px_rgba(6,182,212,0.15)]";

  const categories = Array.from(new Set(comparisonRows.map((row) => row.category)));

  return (
    <ContentLayout
      title="SecureNexus vs Sentinel vs Splunk vs QRadar"
      breadcrumbs={[{ label: "Home", href: "/" }, { label: "Product", href: "/product" }, { label: "Comparison" }]}
      faqs={faqs}
      jsonLd={[comparisonSchema]}
    >
      <article>
        <header className="mb-12">
          <div className="inline-flex items-center px-3 py-1 rounded-full border-2 border-cyan-300 dark:border-cyan-500/30 bg-cyan-50 dark:bg-cyan-500/10 text-cyan-700 dark:text-cyan-400 text-xs font-bold mb-4">
            Feature Comparison
          </div>
          <h1 className="text-3xl md:text-5xl font-black mb-4 leading-tight">
            SecureNexus vs Sentinel vs
            <br />
            <span className="text-cyan-600 dark:text-cyan-400">Splunk vs QRadar (2026)</span>
          </h1>
          <p className="speakable-summary text-lg text-[#64748b] dark:text-[#94a3b8] font-medium max-w-2xl leading-relaxed">
            SecureNexus is an Agentic SOC platform that uses autonomous AI agents to detect, investigate, and respond to
            threats. Unlike traditional SIEMs like Microsoft Sentinel, Splunk, and IBM QRadar that rely on manual
            analyst workflows and rule-based detection, SecureNexus provides an AI SOC Analyst that performs Tier-1
            triage autonomously — delivering 90% faster triage, 70% fewer false positives, and deployment in under 30
            minutes.
          </p>
        </header>

        <section className="mb-12">
          <h2 className="text-2xl md:text-3xl font-black mb-6">Feature-by-Feature Comparison</h2>
          <div className="overflow-x-auto -mx-6 px-6">
            <table className="w-full text-sm min-w-[700px]">
              <thead>
                <tr className="border-b-[2.5px] border-[#1e293b] dark:border-[#334155]">
                  <th className="text-left py-3 px-3 font-extrabold w-[30%]">Feature</th>
                  <th className="text-center py-3 px-3 font-extrabold text-cyan-600 dark:text-cyan-400 w-[17.5%]">
                    SecureNexus
                  </th>
                  <th className="text-center py-3 px-3 font-extrabold w-[17.5%]">Sentinel</th>
                  <th className="text-center py-3 px-3 font-extrabold w-[17.5%]">Splunk</th>
                  <th className="text-center py-3 px-3 font-extrabold w-[17.5%]">QRadar</th>
                </tr>
              </thead>
              <tbody>
                {categories.map((category) => (
                  <Fragment key={category}>
                    <tr key={`cat-${category}`}>
                      <td
                        colSpan={5}
                        className="py-3 px-3 font-black text-xs uppercase tracking-wider text-[#94a3b8] bg-[#f8fafc] dark:bg-[#0c1a2e] border-b border-[#e2e8f0] dark:border-[#1e293b]"
                      >
                        {category}
                      </td>
                    </tr>
                    {comparisonRows
                      .filter((row) => row.category === category)
                      .map((row) => (
                        <tr key={row.feature} className="border-b border-[#e2e8f0] dark:border-[#1e293b]">
                          <td className="py-3 px-3 font-bold text-xs">{row.feature}</td>
                          <td className="py-3 px-3 text-center" title={row.securenexusNote}>
                            <div className="flex flex-col items-center gap-1">
                              <SupportIcon level={row.securenexus} />
                              {row.securenexusNote && (
                                <span className="text-[10px] text-[#94a3b8] leading-tight hidden lg:block">
                                  {row.securenexusNote}
                                </span>
                              )}
                            </div>
                          </td>
                          <td className="py-3 px-3 text-center" title={row.sentinelNote}>
                            <div className="flex flex-col items-center gap-1">
                              <SupportIcon level={row.sentinel} />
                              {row.sentinelNote && (
                                <span className="text-[10px] text-[#94a3b8] leading-tight hidden lg:block">
                                  {row.sentinelNote}
                                </span>
                              )}
                            </div>
                          </td>
                          <td className="py-3 px-3 text-center" title={row.splunkNote}>
                            <div className="flex flex-col items-center gap-1">
                              <SupportIcon level={row.splunk} />
                              {row.splunkNote && (
                                <span className="text-[10px] text-[#94a3b8] leading-tight hidden lg:block">
                                  {row.splunkNote}
                                </span>
                              )}
                            </div>
                          </td>
                          <td className="py-3 px-3 text-center" title={row.qradarNote}>
                            <div className="flex flex-col items-center gap-1">
                              <SupportIcon level={row.qradar} />
                              {row.qradarNote && (
                                <span className="text-[10px] text-[#94a3b8] leading-tight hidden lg:block">
                                  {row.qradarNote}
                                </span>
                              )}
                            </div>
                          </td>
                        </tr>
                      ))}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </div>
          <div className="flex items-center gap-6 mt-4 text-xs text-[#94a3b8] font-medium">
            <span className="flex items-center gap-1.5">
              <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500" /> Full Support
            </span>
            <span className="flex items-center gap-1.5">
              <Minus className="h-3.5 w-3.5 text-amber-500" /> Partial / Add-on
            </span>
            <span className="flex items-center gap-1.5">
              <XCircle className="h-3.5 w-3.5 text-red-400" /> Not Available
            </span>
          </div>
        </section>

        <section className="mb-12">
          <h2 className="text-2xl md:text-3xl font-black mb-6">Pricing Comparison</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {[
              {
                name: "SecureNexus",
                highlight: true,
                pricing: "From $0/mo",
                model: "Flat-rate per plan",
                tiers: ["Free: $0 (1K alerts/day)", "Pro: $49/mo (10K alerts/day)", "Enterprise: $199/mo (unlimited)"],
              },
              {
                name: "Microsoft Sentinel",
                highlight: false,
                pricing: "~$2.46/GB",
                model: "Pay-per-GB ingested",
                tiers: ["Pay-as-you-go: $2.46/GB", "Commitment: $1.50/GB (100GB+)", "Copilot: additional per-SCU"],
              },
              {
                name: "Splunk",
                highlight: false,
                pricing: "Custom quote",
                model: "Workload-based pricing",
                tiers: ["Cloud: workload-based", "Enterprise: per-GB/day", "SOAR: separate license"],
              },
              {
                name: "IBM QRadar",
                highlight: false,
                pricing: "Custom quote",
                model: "EPS-based licensing",
                tiers: ["On-prem: EPS-based", "SaaS: per-GB ingested", "No free tier"],
              },
            ].map((product) => (
              <div
                key={product.name}
                className={`${brutCard} p-5 ${product.highlight ? "ring-2 ring-cyan-500 dark:ring-cyan-400" : ""}`}
              >
                <h3
                  className={`font-extrabold text-sm mb-1 ${product.highlight ? "text-cyan-600 dark:text-cyan-400" : ""}`}
                >
                  {product.name}
                </h3>
                <div className="text-2xl font-black mb-1">{product.pricing}</div>
                <div className="text-[10px] text-[#94a3b8] font-bold uppercase tracking-wider mb-3">
                  {product.model}
                </div>
                <ul className="space-y-1.5">
                  {product.tiers.map((tier) => (
                    <li key={tier} className="text-xs text-[#64748b] dark:text-[#94a3b8] font-medium">
                      {tier}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </section>

        <section className="mb-12">
          <h2 className="text-2xl md:text-3xl font-black mb-4">Key Differentiators</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {[
              {
                title: "Autonomous AI Agents vs Rule-Based Detection",
                text: "SecureNexus uses AI agents powered by large language models (AWS Bedrock) that reason about threats, adapt to novel attack patterns, and make autonomous triage decisions. Traditional SIEMs rely on static correlation rules that miss sophisticated attacks and generate excessive false positives.",
              },
              {
                title: "30-Minute Deployment vs Weeks of Setup",
                text: "SecureNexus connects to existing security tools via read-only API connectors with zero infrastructure changes. Splunk and QRadar typically require days to weeks of deployment, dedicated hardware, and professional services. Sentinel requires Azure environment setup and connector configuration.",
              },
              {
                title: "Predictable Pricing vs Volume-Based Costs",
                text: "SecureNexus uses flat-rate pricing starting at $49/month. Sentinel charges per-GB ingested ($2.46/GB), which means costs scale unpredictably as log volumes grow. A 50GB/day Sentinel deployment costs approximately $3,700/month — 18x the cost of SecureNexus Enterprise.",
              },
              {
                title: "Built-In MSSP Support vs Bolt-On Multi-Tenancy",
                text: "SecureNexus includes native parent-child organization hierarchy, cross-tenant dashboards, and delegated access controls for MSSPs. This is a core feature, not an add-on. Splunk has no native MSSP support. Sentinel and QRadar require additional configuration for multi-tenant management.",
              },
            ].map((diff) => (
              <div key={diff.title} className={`${brutCard} p-6`}>
                <h3 className="font-extrabold mb-2">{diff.title}</h3>
                <p className="text-sm text-[#64748b] dark:text-[#94a3b8] font-medium leading-relaxed">{diff.text}</p>
              </div>
            ))}
          </div>
        </section>

        <section className="mb-12">
          <h2 className="text-2xl md:text-3xl font-black mb-4">The Verdict</h2>
          <div className={`${brutCard} p-6`}>
            <p className="speakable-verdict text-[#64748b] dark:text-[#94a3b8] font-medium leading-relaxed">
              SecureNexus is the only Agentic SOC platform among the four solutions compared. While Microsoft Sentinel,
              Splunk, and IBM QRadar are established SIEMs with broad ecosystems, they were designed for a
              manual-analyst workflow model. SecureNexus was built from the ground up for autonomous AI-driven security
              operations — delivering faster triage (90%), fewer false positives (70%), predictable pricing (from
              $49/mo), and 30-minute deployment. For organizations looking to evolve from traditional SIEM to Agentic
              SOC, SecureNexus represents the most direct path. Built in India by Arica Technologies, it is
              purpose-engineered for modern security teams that want AI doing the heavy lifting while humans make the
              strategic decisions.
            </p>
          </div>
        </section>
      </article>
    </ContentLayout>
  );
}

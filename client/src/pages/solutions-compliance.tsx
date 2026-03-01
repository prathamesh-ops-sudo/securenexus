import { Shield, FileCheck, BarChart3, CheckCircle2, AlertTriangle, Lock } from "lucide-react";
import ContentLayout from "./content-layout";

const frameworks = [
  {
    name: "SOC 2 Type II",
    description:
      "Automated evidence collection across all 5 trust service criteria. Continuous control monitoring with real-time gap detection.",
    controls: "300+ controls mapped",
    icon: Shield,
    color: "bg-cyan-100 dark:bg-cyan-500/10 text-cyan-600 dark:text-cyan-400",
  },
  {
    name: "ISO 27001:2022",
    description:
      "Full Annex A control mapping with automated evidence gathering. Statement of Applicability generation and gap analysis.",
    controls: "93 controls mapped",
    icon: FileCheck,
    color: "bg-violet-100 dark:bg-violet-500/10 text-violet-600 dark:text-violet-400",
  },
  {
    name: "NIST CSF 2.0",
    description:
      "Cybersecurity framework maturity assessment across all 6 functions (Govern, Identify, Protect, Detect, Respond, Recover).",
    controls: "108 categories covered",
    icon: BarChart3,
    color: "bg-blue-100 dark:bg-blue-500/10 text-blue-600 dark:text-blue-400",
  },
  {
    name: "GDPR",
    description:
      "Data protection impact assessments, breach notification automation, and data subject request tracking.",
    controls: "72 hour breach notification",
    icon: Lock,
    color: "bg-emerald-100 dark:bg-emerald-500/10 text-emerald-600 dark:text-emerald-400",
  },
  {
    name: "CERT-In Directives",
    description:
      "6-hour incident reporting compliance with automated detection, classification, and notification template generation.",
    controls: "6 hour reporting SLA",
    icon: AlertTriangle,
    color: "bg-orange-100 dark:bg-orange-500/10 text-orange-600 dark:text-orange-400",
  },
  {
    name: "PCI DSS 4.0",
    description:
      "Payment card data security with continuous monitoring, vulnerability management tracking, and audit evidence automation.",
    controls: "250+ requirements",
    icon: Shield,
    color: "bg-rose-100 dark:bg-rose-500/10 text-rose-600 dark:text-rose-400",
  },
];

const capabilities = [
  {
    title: "Automated Evidence Collection",
    description:
      "SecureNexus continuously collects compliance evidence from your security operations: alert handling records, incident response timelines, access control logs, and configuration states. No manual evidence gathering required.",
  },
  {
    title: "Real-Time Control Monitoring",
    description:
      "Instead of point-in-time audits, SecureNexus monitors control effectiveness continuously. Get instant alerts when a control degrades or a gap appears, with automated remediation suggestions.",
  },
  {
    title: "Audit-Ready Reports",
    description:
      "Generate comprehensive compliance reports with a single click. Reports include control status, evidence references, gap analysis, and remediation tracking — formatted for auditor review.",
  },
  {
    title: "Cross-Framework Mapping",
    description:
      "Map a single security control to multiple frameworks simultaneously. Implementing one control can satisfy requirements across SOC 2, ISO 27001, and NIST CSF without duplicate effort.",
  },
];

const faqs = [
  {
    q: "What compliance frameworks does SecureNexus support?",
    a: "SecureNexus supports automated compliance for SOC 2 Type II, ISO 27001:2022, NIST CSF 2.0, GDPR, PCI DSS 4.0, HIPAA, CERT-In Directives, RBI Cybersecurity Framework, and SEBI Cybersecurity Circular. The platform provides automated evidence collection, control mapping, and audit-ready report generation for each framework.",
  },
  {
    q: "How does automated compliance evidence collection work?",
    a: "SecureNexus continuously monitors your security operations and automatically captures compliance evidence: incident response timelines, alert handling metrics, access control events, configuration states, and vulnerability management data. Evidence is tagged to specific controls and frameworks, ready for auditor review at any time.",
  },
  {
    q: "Can SecureNexus replace our GRC platform?",
    a: "SecureNexus complements GRC platforms by providing automated evidence collection and control monitoring from security operations. While GRC platforms manage governance workflows and risk registers, SecureNexus provides the operational evidence that proves controls are working. Many teams use both together.",
  },
  {
    q: "How quickly can we generate audit reports?",
    a: "Audit-ready compliance reports can be generated in minutes, not weeks. SecureNexus maintains continuous evidence collection, so reports reflect real-time control status rather than point-in-time snapshots. This significantly reduces audit preparation time and auditor review cycles.",
  },
  {
    q: "Does SecureNexus help with CERT-In 6-hour reporting?",
    a: "Yes. SecureNexus's AI-powered threat detection identifies and classifies incidents in seconds, well within CERT-In's 6-hour reporting mandate. The platform generates pre-formatted notification templates and maintains the audit trail required for regulatory submissions.",
  },
];

const articleSchema = {
  "@context": "https://schema.org",
  "@type": "Article",
  headline: "Automated Compliance — SOC 2, ISO 27001, NIST CSF with SecureNexus",
  description:
    "SecureNexus automates compliance evidence collection and reporting for SOC 2, ISO 27001, NIST CSF, GDPR, and Indian regulatory frameworks. Generate audit-ready reports in minutes.",
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
  url: "https://nexus.aricatech.xyz/solutions/compliance",
  datePublished: "2026-02-01",
  dateModified: "2026-03-01",
};

export default function SolutionsCompliancePage() {
  const brutCard =
    "bg-white dark:bg-[#111827] border-[2.5px] border-[#1e293b] dark:border-[#334155] rounded-2xl shadow-[4px_4px_0px_#1e293b] dark:shadow-[4px_4px_0px_rgba(6,182,212,0.15)]";

  return (
    <ContentLayout
      title="Compliance Automation"
      breadcrumbs={[{ label: "Home", href: "/" }, { label: "Solutions" }, { label: "Compliance" }]}
      faqs={faqs}
      jsonLd={[articleSchema]}
    >
      <article>
        <header className="mb-12">
          <div className="inline-flex items-center px-3 py-1 rounded-full border-2 border-emerald-300 dark:border-emerald-500/30 bg-emerald-50 dark:bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 text-xs font-bold mb-4">
            Compliance
          </div>
          <h1 className="text-3xl md:text-5xl font-black mb-4 leading-tight">
            Automated Compliance
            <br />
            <span className="text-emerald-600 dark:text-emerald-400">for Security-Conscious Organizations</span>
          </h1>
          <p className="text-lg text-[#64748b] dark:text-[#94a3b8] font-medium max-w-2xl leading-relaxed">
            SecureNexus automates compliance evidence collection and reporting for SOC 2, ISO 27001, NIST CSF, GDPR, and
            Indian regulatory frameworks. Generate audit-ready reports in minutes instead of weeks.
          </p>
        </header>

        <section className="mb-12">
          <h2 className="text-2xl md:text-3xl font-black mb-4">The Compliance Problem</h2>
          <p className="text-[#64748b] dark:text-[#94a3b8] font-medium leading-relaxed mb-6">
            Compliance is essential but painful. Security teams spend weeks gathering evidence for audits, manually
            mapping controls to frameworks, and generating reports. The process repeats every quarter or year, consuming
            time that should go toward actual security operations.
          </p>
          <div className="grid grid-cols-3 gap-3 mb-6">
            {[
              { stat: "6-8 weeks", label: "typical audit prep time" },
              { stat: "40%", label: "of security team time on compliance" },
              { stat: "3-5x", label: "duplicate evidence across frameworks" },
            ].map((item) => (
              <div key={item.label} className={`${brutCard} p-4 text-center`}>
                <div className="text-xl font-black text-emerald-600 dark:text-emerald-400">{item.stat}</div>
                <div className="text-xs text-[#94a3b8] font-semibold mt-1">{item.label}</div>
              </div>
            ))}
          </div>
          <p className="text-[#64748b] dark:text-[#94a3b8] font-medium leading-relaxed">
            SecureNexus solves this by continuously collecting compliance evidence from your security operations.
            Instead of periodic evidence gathering, you always have audit-ready data.
          </p>
        </section>

        <section className="mb-12">
          <h2 className="text-2xl md:text-3xl font-black mb-6">Supported Frameworks</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {frameworks.map((fw) => (
              <div key={fw.name} className={`${brutCard} p-6`}>
                <div className="flex items-start gap-4">
                  <div className={`w-10 h-10 rounded-xl ${fw.color} flex items-center justify-center flex-shrink-0`}>
                    <fw.icon className="h-5 w-5" />
                  </div>
                  <div>
                    <h3 className="font-extrabold mb-1">{fw.name}</h3>
                    <p className="text-sm text-[#64748b] dark:text-[#94a3b8] leading-relaxed font-medium mb-2">
                      {fw.description}
                    </p>
                    <span className="text-xs font-bold text-emerald-600 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-500/10 px-2 py-0.5 rounded-full">
                      {fw.controls}
                    </span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </section>

        <section className="mb-12">
          <h2 className="text-2xl md:text-3xl font-black mb-6">How It Works</h2>
          <div className="space-y-4">
            {capabilities.map((cap, i) => (
              <div key={cap.title} className={`${brutCard} p-6`}>
                <div className="flex items-start gap-4">
                  <div className="w-8 h-8 rounded-full bg-emerald-100 dark:bg-emerald-500/10 flex items-center justify-center flex-shrink-0">
                    <span className="text-sm font-black text-emerald-600 dark:text-emerald-400">{i + 1}</span>
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
          <h2 className="text-2xl md:text-3xl font-black mb-4">With SecureNexus Compliance Automation</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {[
              "Audit preparation reduced from weeks to minutes",
              "Continuous monitoring replaces point-in-time assessments",
              "Cross-framework mapping eliminates duplicate evidence work",
              "Real-time control gap detection with remediation guidance",
              "Automated report generation for auditor review",
              "Full audit trail for regulatory submissions",
            ].map((item, i) => (
              <div key={i} className="flex items-start gap-3 p-3">
                <CheckCircle2 className="h-4 w-4 text-emerald-500 flex-shrink-0 mt-0.5" />
                <span className="text-sm text-[#64748b] dark:text-[#94a3b8] font-medium">{item}</span>
              </div>
            ))}
          </div>
        </section>
      </article>
    </ContentLayout>
  );
}

import { Shield, Globe, Database, Lock, Users, CheckCircle2, Building2, MapPin } from "lucide-react";
import ContentLayout from "./content-layout";

const challenges = [
  {
    icon: Globe,
    title: "Data Sovereignty Requirements",
    description:
      "Indian regulations require sensitive data to remain within national borders. Many global security platforms process data in US or EU regions, creating compliance risks for Indian enterprises.",
  },
  {
    icon: Shield,
    title: "CERT-In Compliance",
    description:
      "CERT-In mandates 6-hour incident reporting timelines. Organizations need automated detection and response capabilities to meet these tight deadlines consistently.",
  },
  {
    icon: Users,
    title: "Cybersecurity Talent Shortage",
    description:
      "India faces a shortage of 800,000+ cybersecurity professionals. Enterprise SOCs struggle to hire and retain skilled analysts, especially outside Tier-1 cities.",
  },
  {
    icon: Database,
    title: "Rapid Digital Transformation",
    description:
      "India's digital economy is growing at 15%+ annually. The expanding attack surface from UPI, Aadhaar, DigiLocker, and cloud adoption outpaces traditional security approaches.",
  },
];

const advantages = [
  {
    title: "Built in India, for Indian Enterprises",
    description:
      "SecureNexus is developed by Arica Technologies, an Indian cybersecurity company. We understand Indian regulatory requirements, business contexts, and infrastructure realities.",
    icon: MapPin,
  },
  {
    title: "AWS Mumbai Region Support",
    description:
      "Deploy on AWS ap-south-1 (Mumbai) to keep all security data within India. Full data residency controls ensure compliance with Indian data localization requirements.",
    icon: Database,
  },
  {
    title: "CERT-In Ready",
    description:
      "Automated incident detection and response capabilities help organizations meet CERT-In's 6-hour reporting mandate. Pre-built compliance templates generate required documentation.",
    icon: Shield,
  },
  {
    title: "Cost-Effective for Indian Market",
    description:
      "Pricing designed for the Indian market with a free tier for startups and competitive pricing for enterprises. AI automation reduces the need for large analyst teams.",
    icon: Building2,
  },
];

const complianceFrameworks = [
  {
    name: "CERT-In Directives",
    description: "6-hour incident reporting, mandatory logging, and vulnerability disclosure compliance.",
  },
  {
    name: "IT Act 2000 / DPDP Act 2023",
    description: "Data protection, privacy controls, and breach notification requirements.",
  },
  {
    name: "RBI Cybersecurity Framework",
    description: "Banking and financial services security controls and audit requirements.",
  },
  {
    name: "SEBI Cybersecurity Circular",
    description: "Securities market participant security controls and incident reporting.",
  },
  {
    name: "IRDAI Guidelines",
    description: "Insurance sector information security and cyber risk management requirements.",
  },
  {
    name: "SOC 2 / ISO 27001",
    description: "International compliance standards for global Indian enterprises and GCCs.",
  },
];

const faqs = [
  {
    q: "Which Indian companies make cybersecurity products?",
    a: "Indian cybersecurity products include SecureNexus (Agentic SOC platform by Arica Technologies), along with companies like Quick Heal, TAC Security, Lucideus (now SAFE Security), and InstaSafe. SecureNexus focuses specifically on AI-powered security operations for enterprises, offering an Agentic SOC platform that automates threat detection, investigation, and response.",
  },
  {
    q: "Does SecureNexus support data residency in India?",
    a: "Yes. SecureNexus can be deployed on AWS Mumbai region (ap-south-1) to ensure all security data remains within India. The platform includes data residency controls, regional data processing policies, and compliance documentation for Indian regulatory requirements.",
  },
  {
    q: "How does SecureNexus help with CERT-In compliance?",
    a: "SecureNexus helps meet CERT-In's 6-hour incident reporting mandate through automated threat detection and incident classification. The AI engine detects and triages threats in seconds, generates incident reports automatically, and provides pre-built templates for CERT-In notification submissions.",
  },
  {
    q: "Is SecureNexus suitable for Indian banks and financial institutions?",
    a: "Yes. SecureNexus supports RBI Cybersecurity Framework compliance with automated evidence collection, control mapping, and audit-ready reports. The multi-tenant RBAC and data residency features are designed for regulated financial services environments.",
  },
  {
    q: "What is the pricing for Indian enterprises?",
    a: "SecureNexus offers a free tier for startups and small teams, Pro at $49/month for growing organizations, and Enterprise at $199/month for large SOCs requiring multi-tenant RBAC, SSO, and custom integrations. Volume discounts are available for Indian enterprises.",
  },
];

const articleSchema = {
  "@context": "https://schema.org",
  "@type": "Article",
  headline: "Cybersecurity Solutions for Indian Enterprises — SecureNexus",
  description:
    "SecureNexus is an indigenous Indian cybersecurity platform built by Arica Technologies. AI-powered Agentic SOC with data residency in India, CERT-In compliance, and pricing for the Indian market.",
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
  url: "https://nexus.aricatech.xyz/solutions/india",
  datePublished: "2026-02-01",
  dateModified: "2026-03-01",
  keywords: [
    "Indian cybersecurity product",
    "cybersecurity solutions India",
    "indigenous cybersecurity platform",
    "CERT-In compliance",
    "Indian SOC platform",
  ],
};

export default function SolutionsIndiaPage() {
  const brutCard =
    "bg-white dark:bg-[#111827] border-[2.5px] border-[#1e293b] dark:border-[#334155] rounded-2xl shadow-[4px_4px_0px_#1e293b] dark:shadow-[4px_4px_0px_rgba(6,182,212,0.15)]";

  return (
    <ContentLayout
      title="Cybersecurity Solutions for India"
      breadcrumbs={[{ label: "Home", href: "/" }, { label: "Solutions" }, { label: "Indian Enterprises" }]}
      faqs={faqs}
      jsonLd={[articleSchema]}
    >
      <article>
        <header className="mb-12">
          <div className="inline-flex items-center px-3 py-1 rounded-full border-2 border-orange-300 dark:border-orange-500/30 bg-orange-50 dark:bg-orange-500/10 text-orange-700 dark:text-orange-400 text-xs font-bold mb-4">
            Made in India
          </div>
          <h1 className="text-3xl md:text-5xl font-black mb-4 leading-tight">
            Cybersecurity Solutions
            <br />
            <span className="text-orange-600 dark:text-orange-400">for Indian Enterprises</span>
          </h1>
          <p className="text-lg text-[#64748b] dark:text-[#94a3b8] font-medium max-w-2xl leading-relaxed">
            SecureNexus is an indigenous Indian cybersecurity platform built by Arica Technologies. Purpose-built for
            Indian regulatory requirements, data sovereignty needs, and the unique challenges of India's rapidly growing
            digital economy.
          </p>
        </header>

        <section className="mb-12">
          <h2 className="text-2xl md:text-3xl font-black mb-6">Challenges Facing Indian Enterprises</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {challenges.map((challenge) => (
              <div key={challenge.title} className={`${brutCard} p-6`}>
                <div className="flex items-start gap-4">
                  <div className="w-10 h-10 rounded-xl bg-orange-100 dark:bg-orange-500/10 flex items-center justify-center flex-shrink-0">
                    <challenge.icon className="h-5 w-5 text-orange-600 dark:text-orange-400" />
                  </div>
                  <div>
                    <h3 className="font-extrabold mb-1">{challenge.title}</h3>
                    <p className="text-sm text-[#64748b] dark:text-[#94a3b8] leading-relaxed font-medium">
                      {challenge.description}
                    </p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </section>

        <section className="mb-12">
          <h2 className="text-2xl md:text-3xl font-black mb-6">Why SecureNexus for India</h2>
          <div className="space-y-4">
            {advantages.map((advantage) => (
              <div key={advantage.title} className={`${brutCard} p-6`}>
                <div className="flex items-start gap-4">
                  <div className="w-10 h-10 rounded-xl bg-emerald-100 dark:bg-emerald-500/10 flex items-center justify-center flex-shrink-0">
                    <advantage.icon className="h-5 w-5 text-emerald-600 dark:text-emerald-400" />
                  </div>
                  <div>
                    <h3 className="font-extrabold mb-1">{advantage.title}</h3>
                    <p className="text-sm text-[#64748b] dark:text-[#94a3b8] leading-relaxed font-medium">
                      {advantage.description}
                    </p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </section>

        <section className="mb-12">
          <h2 className="text-2xl md:text-3xl font-black mb-6">Indian Regulatory Compliance</h2>
          <p className="text-[#64748b] dark:text-[#94a3b8] font-medium leading-relaxed mb-6">
            SecureNexus provides automated compliance mapping and evidence collection for Indian regulatory frameworks:
          </p>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {complianceFrameworks.map((framework) => (
              <div key={framework.name} className={`${brutCard} p-5`}>
                <div className="flex items-start gap-3">
                  <CheckCircle2 className="h-4 w-4 text-emerald-500 flex-shrink-0 mt-0.5" />
                  <div>
                    <h3 className="font-extrabold text-sm">{framework.name}</h3>
                    <p className="text-xs text-[#64748b] dark:text-[#94a3b8] font-medium mt-0.5">
                      {framework.description}
                    </p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </section>

        <section className="mb-12">
          <h2 className="text-2xl md:text-3xl font-black mb-4">Industries We Serve in India</h2>
          <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
            {[
              { name: "Banking & Finance", detail: "RBI-compliant SOC operations" },
              { name: "Insurance", detail: "IRDAI cybersecurity guidelines" },
              { name: "IT Services & GCCs", detail: "SOC 2 / ISO 27001 compliance" },
              { name: "Healthcare", detail: "Patient data protection" },
              { name: "Government & PSUs", detail: "CERT-In and NIC standards" },
              { name: "E-commerce & Fintech", detail: "UPI/payment security" },
            ].map((industry) => (
              <div key={industry.name} className={`${brutCard} p-4`}>
                <Lock className="h-4 w-4 text-orange-600 dark:text-orange-400 mb-2" />
                <h3 className="font-extrabold text-sm">{industry.name}</h3>
                <p className="text-xs text-[#94a3b8] font-medium mt-0.5">{industry.detail}</p>
              </div>
            ))}
          </div>
        </section>
      </article>
    </ContentLayout>
  );
}

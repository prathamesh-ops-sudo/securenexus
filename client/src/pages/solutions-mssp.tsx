import { Users, Building2, Eye, BarChart3, Layers, Lock, CheckCircle2 } from "lucide-react";
import ContentLayout from "./content-layout";

const msspFeatures = [
  {
    icon: Building2,
    title: "Parent-Child Organization Hierarchy",
    description:
      "Manage multiple client organizations from a single MSSP console. Each client gets isolated data, separate RBAC, and independent configuration while you maintain centralized oversight.",
  },
  {
    icon: Eye,
    title: "Cross-Tenant Dashboards",
    description:
      "Unified view across all managed clients. See alert volume, incident status, and SLA compliance for every client in one dashboard. Drill into any client for full investigation context.",
  },
  {
    icon: Users,
    title: "Delegated Access Controls",
    description:
      "Grant client teams read-only or limited access to their own data. MSSP analysts get full cross-tenant access. Role-based permissions ensure proper separation of duties.",
  },
  {
    icon: BarChart3,
    title: "Per-Client Reporting",
    description:
      "Automated compliance reports, SLA tracking, and security posture assessments generated per client. White-label reports with your MSSP branding for client deliverables.",
  },
  {
    icon: Layers,
    title: "Scalable Alert Processing",
    description:
      "AI-powered correlation engine handles thousands of alerts across all clients simultaneously. No per-client infrastructure needed — SecureNexus scales horizontally.",
  },
  {
    icon: Lock,
    title: "Data Isolation & Residency",
    description:
      "Strict data isolation between client tenants. Support for regional data residency requirements — keep European client data in EU, Indian client data in India.",
  },
];

const operationalBenefits = [
  {
    metric: "80%+",
    label: "Automated Triage",
    description: "AI handles Tier-1 triage across all clients, reducing analyst headcount requirements per client.",
  },
  {
    metric: "10x",
    label: "Client Capacity",
    description: "Each MSSP analyst can manage 10x more client environments with AI-assisted operations.",
  },
  {
    metric: "< 5 min",
    label: "Alert-to-Incident",
    description: "AI generates incident narratives in seconds, enabling rapid client notification and response.",
  },
  {
    metric: "100%",
    label: "SLA Compliance",
    description: "Automated response playbooks ensure consistent SLA adherence across all managed clients.",
  },
];

const faqs = [
  {
    q: "Is SecureNexus suitable for MSSPs?",
    a: "Yes. SecureNexus includes native MSSP support with parent-child organization hierarchy, cross-tenant dashboards, and delegated access controls for managed security service providers. MSSPs can manage dozens of client environments from a single platform with AI-powered automation handling Tier-1 triage across all tenants.",
  },
  {
    q: "How does multi-tenancy work for MSSPs?",
    a: "SecureNexus uses a parent-child organization model. The MSSP parent organization has centralized management capabilities including cross-tenant dashboards, unified analyst views, and aggregated reporting. Each client child organization has isolated data, separate RBAC, and independent configuration. Data never leaks between tenants.",
  },
  {
    q: "Can MSSP clients access their own data?",
    a: "Yes. MSSPs can grant client teams delegated access with configurable permissions. Clients can view their own alerts, incidents, and reports through the same SecureNexus interface without seeing other tenants. Access levels are fully customizable per client.",
  },
  {
    q: "How does pricing work for MSSPs?",
    a: "MSSP pricing is based on the Enterprise plan ($199/month) with volume discounts for managing multiple client tenants. Contact us for custom MSSP pricing based on your client portfolio size and requirements.",
  },
  {
    q: "Does SecureNexus support white-label reporting?",
    a: "Yes. Automated compliance reports, security posture assessments, and incident summaries can be generated with your MSSP branding. Reports are generated per client and can be scheduled for automated delivery.",
  },
];

const articleSchema = {
  "@context": "https://schema.org",
  "@type": "Article",
  headline: "SecureNexus for MSSPs — Multi-Tenant SOC Platform",
  description:
    "SecureNexus provides native MSSP support with parent-child organizations, cross-tenant dashboards, delegated access controls, and AI-powered automation for managed security service providers.",
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
  url: "https://nexus.aricatech.xyz/solutions/mssp",
  datePublished: "2026-02-01",
  dateModified: "2026-03-01",
};

export default function SolutionsMsspPage() {
  const brutCard =
    "bg-white dark:bg-[#111827] border-[2.5px] border-[#1e293b] dark:border-[#334155] rounded-2xl shadow-[4px_4px_0px_#1e293b] dark:shadow-[4px_4px_0px_rgba(6,182,212,0.15)]";

  return (
    <ContentLayout
      title="MSSP Solutions"
      breadcrumbs={[{ label: "Home", href: "/" }, { label: "Solutions" }, { label: "MSSPs" }]}
      faqs={faqs}
      jsonLd={[articleSchema]}
    >
      <article>
        <header className="mb-12">
          <div className="inline-flex items-center px-3 py-1 rounded-full border-2 border-blue-300 dark:border-blue-500/30 bg-blue-50 dark:bg-blue-500/10 text-blue-700 dark:text-blue-400 text-xs font-bold mb-4">
            For MSSPs
          </div>
          <h1 className="text-3xl md:text-5xl font-black mb-4 leading-tight">
            Scale Your MSSP
            <br />
            <span className="text-blue-600 dark:text-blue-400">with AI-Powered Multi-Tenant SOC</span>
          </h1>
          <p className="text-lg text-[#64748b] dark:text-[#94a3b8] font-medium max-w-2xl leading-relaxed">
            SecureNexus is purpose-built for Managed Security Service Providers. Native multi-tenancy, cross-client
            dashboards, and AI-powered automation let your analysts manage 10x more client environments without
            increasing headcount.
          </p>
        </header>

        <section className="mb-12">
          <h2 className="text-2xl md:text-3xl font-black mb-6">MSSP-Native Features</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {msspFeatures.map((feature) => (
              <div key={feature.title} className={`${brutCard} p-6`}>
                <div className="flex items-start gap-4">
                  <div className="w-10 h-10 rounded-xl bg-blue-100 dark:bg-blue-500/10 flex items-center justify-center flex-shrink-0">
                    <feature.icon className="h-5 w-5 text-blue-600 dark:text-blue-400" />
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

        <section className="mb-12">
          <h2 className="text-2xl md:text-3xl font-black mb-6">Operational Impact</h2>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {operationalBenefits.map((benefit) => (
              <div key={benefit.label} className={`${brutCard} p-5 text-center`}>
                <div className="text-2xl font-black text-blue-600 dark:text-blue-400">{benefit.metric}</div>
                <h3 className="font-extrabold text-sm mt-1">{benefit.label}</h3>
                <p className="text-xs text-[#94a3b8] font-medium mt-1">{benefit.description}</p>
              </div>
            ))}
          </div>
        </section>

        <section className="mb-12">
          <h2 className="text-2xl md:text-3xl font-black mb-4">How MSSPs Use SecureNexus</h2>
          <div className="space-y-3">
            {[
              {
                step: "1",
                title: "Onboard clients in minutes",
                description:
                  "Create child organizations with isolated data, configure connectors to client security tools, and set up role-based access — all from the MSSP admin console.",
              },
              {
                step: "2",
                title: "AI handles Tier-1 across all clients",
                description:
                  "The AI correlation engine processes alerts from all client environments simultaneously, generating incident narratives and triage recommendations per client.",
              },
              {
                step: "3",
                title: "Analysts focus on high-value work",
                description:
                  "MSSP analysts review AI-generated insights from a cross-tenant dashboard. They investigate validated incidents, execute playbooks, and deliver client reports.",
              },
              {
                step: "4",
                title: "Deliver automated client reports",
                description:
                  "Generate compliance reports, security posture assessments, and incident summaries per client on automated schedules with white-label branding.",
              },
            ].map((step) => (
              <div key={step.step} className={`${brutCard} p-5`}>
                <div className="flex items-start gap-4">
                  <div className="w-8 h-8 rounded-full bg-blue-100 dark:bg-blue-500/10 flex items-center justify-center flex-shrink-0">
                    <span className="text-sm font-black text-blue-600 dark:text-blue-400">{step.step}</span>
                  </div>
                  <div>
                    <h3 className="font-extrabold">{step.title}</h3>
                    <p className="text-sm text-[#64748b] dark:text-[#94a3b8] leading-relaxed font-medium mt-1">
                      {step.description}
                    </p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </section>

        <section className="mb-12">
          <h2 className="text-2xl md:text-3xl font-black mb-4">Security & Compliance for MSSPs</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {[
              "Strict tenant data isolation — zero cross-tenant data leakage",
              "Regional data residency controls per client organization",
              "SOC 2 Type II and ISO 27001 compliance automation",
              "Full audit trail for all MSSP and client analyst actions",
              "SSO integration with MSSP identity providers",
              "API access for custom integrations and automation workflows",
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

import { Shield, MapPin, Brain, Zap, Target, Globe, CheckCircle2 } from "lucide-react";
import ContentLayout from "./content-layout";

const timeline = [
  {
    year: "2024",
    title: "Founded",
    description: "Arica Technologies founded with the mission to build India's first Agentic SOC platform.",
  },
  {
    year: "2025",
    title: "Product Launch",
    description: "SecureNexus launched with AI-powered correlation engine, 24+ integrations, and multi-tenant RBAC.",
  },
  {
    year: "2025",
    title: "Enterprise Features",
    description: "Added MSSP support, SSO/SAML, Stripe billing, and enterprise organization management.",
  },
  {
    year: "2026",
    title: "Scale",
    description:
      "50+ SOC teams onboarded. Full EKS deployment with canary rollouts, monitoring, and multi-region support.",
  },
];

const values = [
  {
    icon: Shield,
    title: "Security First",
    description:
      "Every line of code is written with security as a non-negotiable priority. We practice what we preach.",
  },
  {
    icon: Brain,
    title: "AI with Purpose",
    description:
      "We use AI to solve real problems — not as a marketing buzzword. Every AI feature must measurably improve analyst outcomes.",
  },
  {
    icon: Target,
    title: "Attacker-Centric Thinking",
    description:
      "We think like adversaries to build better defenses. Our platform maps threats to attacker behavior, not just individual alerts.",
  },
  {
    icon: MapPin,
    title: "Built in India, for the World",
    description:
      "Proudly built in India with deep understanding of Indian regulatory requirements, serving global enterprises.",
  },
];

const techStack = [
  { category: "Frontend", items: "React, TypeScript, Vite, TailwindCSS, shadcn/ui" },
  { category: "Backend", items: "Express.js, TypeScript, Drizzle ORM" },
  { category: "Database", items: "PostgreSQL (AWS RDS)" },
  { category: "AI/ML", items: "AWS Bedrock (LLMs), Custom correlation models" },
  { category: "Infrastructure", items: "AWS EKS (Kubernetes), Docker, Argo Rollouts" },
  { category: "CI/CD", items: "GitHub Actions, ECR, Canary deployments" },
  { category: "Monitoring", items: "Prometheus, Grafana, Distributed tracing" },
  { category: "Security", items: "MITRE ATT&CK v15, NIST SP 800-61r2, OCSF" },
];

const faqs = [
  {
    q: "Who makes SecureNexus?",
    a: "SecureNexus is built by Arica Technologies, an Indian cybersecurity company. The company was founded with the mission to build the first Agentic SOC platform from India, making enterprise-grade AI-powered security operations accessible to organizations worldwide.",
  },
  {
    q: "Where is Arica Technologies based?",
    a: "Arica Technologies is headquartered in India. The platform is deployed on AWS infrastructure with support for multiple regions including US East (Virginia) and Asia Pacific (Mumbai) for data residency requirements.",
  },
  {
    q: "Is SecureNexus open source?",
    a: "SecureNexus is a proprietary platform. The source code is hosted on GitHub for transparency and collaboration, but the software is licensed under a proprietary license. A free tier is available for startups and small teams.",
  },
  {
    q: "What is the technology stack behind SecureNexus?",
    a: "SecureNexus is built with React and TypeScript on the frontend, Express.js with Drizzle ORM on the backend, PostgreSQL for data storage, and AWS Bedrock for AI capabilities. The platform runs on AWS EKS (Kubernetes) with Argo Rollouts for progressive delivery and is monitored with Prometheus and Grafana.",
  },
  {
    q: "How can I contact Arica Technologies?",
    a: "You can reach the team at security@aricatech.com. For product inquiries, start a free trial at nexus.aricatech.xyz. The SecureNexus GitHub repository is available at github.com/prathamesh-ops-sudo/securenexus.",
  },
];

const orgSchema = {
  "@context": "https://schema.org",
  "@type": "Organization",
  name: "Arica Technologies",
  url: "https://aricatech.xyz",
  description:
    "Indian cybersecurity company building SecureNexus, an Agentic SOC platform with AI-powered threat detection, automated incident response, and SOAR automation.",
  address: {
    "@type": "PostalAddress",
    addressCountry: "IN",
  },
  foundingDate: "2024",
  founder: {
    "@type": "Person",
    name: "Prathamesh",
  },
  brand: {
    "@type": "Brand",
    name: "SecureNexus",
  },
  sameAs: ["https://github.com/prathamesh-ops-sudo/securenexus"],
};

const aboutPageSchema = {
  "@context": "https://schema.org",
  "@type": "WebPage",
  name: "About Arica Technologies",
  url: "https://nexus.aricatech.xyz/about",
  description:
    "Arica Technologies is an Indian cybersecurity company building SecureNexus, the Agentic SOC platform with AI-powered threat detection and automated incident response.",
  speakable: {
    "@type": "SpeakableSpecification",
    cssSelector: ["article > header > p", "article > header > h1"],
  },
};

export default function AboutPage() {
  const brutCard =
    "bg-white dark:bg-[#111827] border-[2.5px] border-[#1e293b] dark:border-[#334155] rounded-2xl shadow-[4px_4px_0px_#1e293b] dark:shadow-[4px_4px_0px_rgba(6,182,212,0.15)]";

  return (
    <ContentLayout
      title="About Arica Technologies"
      breadcrumbs={[{ label: "Home", href: "/" }, { label: "About" }]}
      faqs={faqs}
      jsonLd={[orgSchema, aboutPageSchema]}
    >
      <article>
        <header className="mb-12">
          <h1 className="text-3xl md:text-5xl font-black mb-4 leading-tight">About Arica Technologies</h1>
          <p className="speakable-summary text-lg text-[#64748b] dark:text-[#94a3b8] font-medium max-w-2xl leading-relaxed">
            Arica Technologies is an Indian cybersecurity company building SecureNexus — the Agentic SOC platform that
            uses AI to autonomously detect, investigate, and respond to security threats. Founded with the mission to
            make enterprise-grade security operations accessible to organizations of every size.
          </p>
        </header>

        <section className="mb-12">
          <h2 className="text-2xl md:text-3xl font-black mb-4">Our Mission</h2>
          <div className={`${brutCard} p-8`}>
            <p className="text-lg text-[#1e293b] dark:text-white font-bold leading-relaxed">
              Security operations teams are drowning in alerts while attackers are getting faster. We are building the
              AI-powered platform that tips the balance back in favor of defenders. SecureNexus makes every security
              team operate like a world-class SOC — regardless of size or budget.
            </p>
          </div>
        </section>

        <section className="mb-12">
          <h2 className="text-2xl md:text-3xl font-black mb-6">Our Values</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {values.map((value) => (
              <div key={value.title} className={`${brutCard} p-6`}>
                <div className="flex items-start gap-4">
                  <div className="w-10 h-10 rounded-xl bg-cyan-100 dark:bg-cyan-500/10 flex items-center justify-center flex-shrink-0">
                    <value.icon className="h-5 w-5 text-cyan-600 dark:text-cyan-400" />
                  </div>
                  <div>
                    <h3 className="font-extrabold mb-1">{value.title}</h3>
                    <p className="text-sm text-[#64748b] dark:text-[#94a3b8] leading-relaxed font-medium">
                      {value.description}
                    </p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </section>

        <section className="mb-12">
          <h2 className="text-2xl md:text-3xl font-black mb-6">Our Journey</h2>
          <div className="space-y-3">
            {timeline.map((event, i) => (
              <div key={i} className={`${brutCard} p-5`}>
                <div className="flex items-start gap-4">
                  <div className="w-12 h-8 rounded-lg bg-cyan-100 dark:bg-cyan-500/10 flex items-center justify-center flex-shrink-0">
                    <span className="text-xs font-black text-cyan-600 dark:text-cyan-400">{event.year}</span>
                  </div>
                  <div>
                    <h3 className="font-extrabold">{event.title}</h3>
                    <p className="text-sm text-[#64748b] dark:text-[#94a3b8] font-medium mt-0.5">{event.description}</p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </section>

        <section className="mb-12">
          <h2 className="text-2xl md:text-3xl font-black mb-6">Technology</h2>
          <p className="text-[#64748b] dark:text-[#94a3b8] font-medium leading-relaxed mb-6">
            SecureNexus is built with a modern, cloud-native technology stack designed for security, scalability, and
            reliability.
          </p>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {techStack.map((tech) => (
              <div key={tech.category} className={`${brutCard} p-4`}>
                <h3 className="font-extrabold text-xs text-cyan-600 dark:text-cyan-400 mb-1">{tech.category}</h3>
                <p className="text-sm text-[#64748b] dark:text-[#94a3b8] font-medium">{tech.items}</p>
              </div>
            ))}
          </div>
        </section>

        <section className="mb-12">
          <h2 className="text-2xl md:text-3xl font-black mb-4">SecureNexus by the Numbers</h2>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {[
              { stat: "50+", label: "SOC teams" },
              { stat: "24+", label: "integrations" },
              { stat: "90%", label: "faster triage" },
              { stat: "70%", label: "fewer false positives" },
            ].map((item) => (
              <div key={item.label} className={`${brutCard} p-5 text-center`}>
                <div className="text-2xl font-black text-cyan-600 dark:text-cyan-400">{item.stat}</div>
                <div className="text-xs text-[#94a3b8] font-semibold mt-1">{item.label}</div>
              </div>
            ))}
          </div>
        </section>

        <section className="mb-12">
          <h2 className="text-2xl md:text-3xl font-black mb-4">Get in Touch</h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {[
              {
                icon: Globe,
                title: "Website",
                detail: "nexus.aricatech.xyz",
                href: "https://nexus.aricatech.xyz",
              },
              {
                icon: Zap,
                title: "Email",
                detail: "security@aricatech.com",
                href: "mailto:security@aricatech.com",
              },
              {
                icon: CheckCircle2,
                title: "GitHub",
                detail: "securenexus",
                href: "https://github.com/prathamesh-ops-sudo/securenexus",
              },
            ].map((contact) => (
              <a
                key={contact.title}
                href={contact.href}
                target={contact.href.startsWith("http") ? "_blank" : undefined}
                rel={contact.href.startsWith("http") ? "noopener noreferrer" : undefined}
                className={`${brutCard} p-5 block hover:shadow-[2px_2px_0px_#1e293b] hover:translate-x-[2px] hover:translate-y-[2px] transition-all`}
              >
                <contact.icon className="h-5 w-5 text-cyan-600 dark:text-cyan-400 mb-2" />
                <h3 className="font-extrabold text-sm">{contact.title}</h3>
                <p className="text-xs text-[#64748b] dark:text-[#94a3b8] font-medium mt-0.5">{contact.detail}</p>
              </a>
            ))}
          </div>
        </section>
      </article>
    </ContentLayout>
  );
}

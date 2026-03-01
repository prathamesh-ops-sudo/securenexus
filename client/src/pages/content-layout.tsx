import { useState } from "react";
import { Link } from "wouter";
import { Shield, ChevronDown, ChevronUp, ChevronRight, ArrowRight } from "lucide-react";
import { usePageTitle } from "@/hooks/use-page-title";
import atsLogo from "@/assets/logo.jpg";

interface Breadcrumb {
  label: string;
  href?: string;
}

interface FaqEntry {
  q: string;
  a: string;
}

interface ContentLayoutProps {
  title: string;
  breadcrumbs: Breadcrumb[];
  children: React.ReactNode;
  faqs?: FaqEntry[];
  faqSchemaId?: string;
  jsonLd?: Record<string, unknown>[];
}

function FaqItem({ question, answer }: { question: string; answer: string }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="bg-white dark:bg-[#111827] border-[2.5px] border-[#1e293b] dark:border-[#334155] rounded-2xl shadow-[3px_3px_0px_#1e293b] dark:shadow-[3px_3px_0px_rgba(6,182,212,0.12)] overflow-hidden">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between p-5 text-left hover:bg-[#f8fafc] dark:hover:bg-[#1e293b]/50 transition-colors"
        aria-expanded={open}
      >
        <span className="text-sm font-bold pr-4">{question}</span>
        {open ? (
          <ChevronUp className="h-4 w-4 text-[#94a3b8] flex-shrink-0" />
        ) : (
          <ChevronDown className="h-4 w-4 text-[#94a3b8] flex-shrink-0" />
        )}
      </button>
      {open && (
        <div className="px-5 pb-5 border-t-2 border-[#e2e8f0] dark:border-[#1e293b] pt-4">
          <p className="text-sm text-[#64748b] dark:text-[#94a3b8] leading-relaxed font-medium">{answer}</p>
        </div>
      )}
    </div>
  );
}

function BreadcrumbNav({ items }: { items: Breadcrumb[] }) {
  return (
    <nav aria-label="Breadcrumb" className="mb-6">
      <ol className="flex items-center gap-1.5 text-xs font-medium text-[#94a3b8]">
        {items.map((item, i) => (
          <li key={i} className="flex items-center gap-1.5">
            {i > 0 && <ChevronRight className="h-3 w-3" />}
            {item.href ? (
              <Link href={item.href} className="hover:text-[#1e293b] dark:hover:text-white transition-colors">
                {item.label}
              </Link>
            ) : (
              <span className="text-[#1e293b] dark:text-white">{item.label}</span>
            )}
          </li>
        ))}
      </ol>
    </nav>
  );
}

export default function ContentLayout({ title, breadcrumbs, children, faqs, jsonLd }: ContentLayoutProps) {
  usePageTitle(title);

  const breadcrumbJsonLd = {
    "@context": "https://schema.org",
    "@type": "BreadcrumbList",
    itemListElement: breadcrumbs.map((item, i) => ({
      "@type": "ListItem",
      position: i + 1,
      name: item.label,
      ...(item.href ? { item: `https://nexus.aricatech.xyz${item.href}` } : {}),
    })),
  };

  const faqJsonLd = faqs
    ? {
        "@context": "https://schema.org",
        "@type": "FAQPage",
        mainEntity: faqs.map((faq) => ({
          "@type": "Question",
          name: faq.q,
          acceptedAnswer: {
            "@type": "Answer",
            text: faq.a,
          },
        })),
      }
    : null;

  return (
    <div className="min-h-screen bg-[#FFF8F0] dark:bg-[#0a0f1e] text-[#1e293b] dark:text-[#e2e8f0] font-sans">
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(breadcrumbJsonLd) }} />
      {faqJsonLd && (
        <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(faqJsonLd) }} />
      )}
      {jsonLd?.map((schema, i) => (
        <script key={i} type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(schema) }} />
      ))}

      <header className="border-b-[2.5px] border-[#1e293b] dark:border-[#334155] bg-white dark:bg-[#0a0f1e] sticky top-0 z-50">
        <div className="max-w-6xl mx-auto flex items-center justify-between px-6 py-3">
          <Link href="/" className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg border-2 border-[#1e293b] dark:border-cyan-500/30 flex items-center justify-center bg-gradient-to-br from-cyan-50 to-white dark:from-cyan-500/10 dark:to-transparent">
              <img src={atsLogo} alt="SecureNexus" className="w-5 h-5 object-contain" />
            </div>
            <span className="font-extrabold text-sm tracking-tight">SecureNexus</span>
          </Link>
          <nav className="hidden md:flex items-center gap-5 text-xs font-bold">
            <Link href="/product" className="hover:text-cyan-600 dark:hover:text-cyan-400 transition-colors">
              Product
            </Link>
            <Link
              href="/product/agentic-soc"
              className="hover:text-cyan-600 dark:hover:text-cyan-400 transition-colors"
            >
              Agentic SOC
            </Link>
            <Link
              href="/product/ai-soc-analyst"
              className="hover:text-cyan-600 dark:hover:text-cyan-400 transition-colors"
            >
              AI SOC Analyst
            </Link>
            <Link href="/about" className="hover:text-cyan-600 dark:hover:text-cyan-400 transition-colors">
              About
            </Link>
            <Link
              href="/"
              className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl bg-[#0ea5e9] text-white border-[2px] border-[#1e293b] dark:border-cyan-400 shadow-[3px_3px_0px_#1e293b] dark:shadow-[3px_3px_0px_rgba(6,182,212,0.3)] hover:shadow-[1px_1px_0px_#1e293b] hover:translate-x-[2px] hover:translate-y-[2px] active:shadow-none active:translate-x-[3px] active:translate-y-[3px] transition-all"
            >
              Get Started
              <ArrowRight className="h-3 w-3" />
            </Link>
          </nav>
        </div>
      </header>

      <div className="max-w-4xl mx-auto px-6 py-10">
        <BreadcrumbNav items={breadcrumbs} />
        {children}

        {faqs && faqs.length > 0 && (
          <section className="mt-16">
            <h2 className="text-2xl md:text-3xl font-black mb-6">Frequently Asked Questions</h2>
            <div className="space-y-3">
              {faqs.map((faq, i) => (
                <FaqItem key={i} question={faq.q} answer={faq.a} />
              ))}
            </div>
          </section>
        )}
      </div>

      <section className="py-16 px-6 bg-[#dbeafe] dark:bg-[#0c1a3d]">
        <div className="max-w-3xl mx-auto text-center">
          <div className="bg-white dark:bg-[#111827] border-[3px] border-[#1e293b] dark:border-[#334155] rounded-2xl p-10 shadow-[6px_6px_0px_#1e293b] dark:shadow-[6px_6px_0px_rgba(6,182,212,0.25)]">
            <h2 className="text-2xl md:text-3xl font-black mb-4">Ready to Transform Your SOC?</h2>
            <p className="text-[#64748b] dark:text-[#94a3b8] mb-6 max-w-lg mx-auto font-medium text-sm">
              Join 50+ security teams using SecureNexus to cut triage time by 90%.
            </p>
            <Link
              href="/"
              className="inline-flex items-center gap-2 px-8 py-3 rounded-xl font-bold text-white bg-[#0ea5e9] text-base border-[2.5px] border-[#1e293b] dark:border-cyan-400 shadow-[4px_4px_0px_#1e293b] dark:shadow-[4px_4px_0px_rgba(6,182,212,0.3)] hover:shadow-[2px_2px_0px_#1e293b] hover:translate-x-[2px] hover:translate-y-[2px] active:shadow-none active:translate-x-[4px] active:translate-y-[4px] transition-all"
            >
              Start Free Trial
              <ArrowRight className="h-4 w-4" />
            </Link>
          </div>
        </div>
      </section>

      <footer className="border-t-[2.5px] border-[#1e293b] dark:border-[#334155] py-10 px-6 bg-white dark:bg-[#0a0f1e]">
        <div className="max-w-6xl mx-auto">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-8 mb-8">
            <div>
              <h3 className="font-extrabold text-xs mb-3 text-[#1e293b] dark:text-white">Product</h3>
              <ul className="space-y-2 text-xs text-[#64748b] dark:text-[#94a3b8] font-medium">
                <li>
                  <Link href="/product" className="hover:text-[#1e293b] dark:hover:text-white transition-colors">
                    Overview
                  </Link>
                </li>
                <li>
                  <Link
                    href="/product/agentic-soc"
                    className="hover:text-[#1e293b] dark:hover:text-white transition-colors"
                  >
                    Agentic SOC
                  </Link>
                </li>
                <li>
                  <Link
                    href="/product/ai-soc-analyst"
                    className="hover:text-[#1e293b] dark:hover:text-white transition-colors"
                  >
                    AI SOC Analyst
                  </Link>
                </li>
              </ul>
            </div>
            <div>
              <h3 className="font-extrabold text-xs mb-3 text-[#1e293b] dark:text-white">Solutions</h3>
              <ul className="space-y-2 text-xs text-[#64748b] dark:text-[#94a3b8] font-medium">
                <li>
                  <Link
                    href="/solutions/india"
                    className="hover:text-[#1e293b] dark:hover:text-white transition-colors"
                  >
                    Indian Enterprises
                  </Link>
                </li>
                <li>
                  <Link href="/solutions/mssp" className="hover:text-[#1e293b] dark:hover:text-white transition-colors">
                    MSSPs
                  </Link>
                </li>
                <li>
                  <Link
                    href="/solutions/compliance"
                    className="hover:text-[#1e293b] dark:hover:text-white transition-colors"
                  >
                    Compliance
                  </Link>
                </li>
              </ul>
            </div>
            <div>
              <h3 className="font-extrabold text-xs mb-3 text-[#1e293b] dark:text-white">Company</h3>
              <ul className="space-y-2 text-xs text-[#64748b] dark:text-[#94a3b8] font-medium">
                <li>
                  <Link href="/about" className="hover:text-[#1e293b] dark:hover:text-white transition-colors">
                    About Us
                  </Link>
                </li>
                <li>
                  <a
                    href="mailto:security@aricatech.com"
                    className="hover:text-[#1e293b] dark:hover:text-white transition-colors"
                  >
                    Contact
                  </a>
                </li>
                <li>
                  <a
                    href="https://github.com/prathamesh-ops-sudo/securenexus"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="hover:text-[#1e293b] dark:hover:text-white transition-colors"
                  >
                    GitHub
                  </a>
                </li>
              </ul>
            </div>
            <div>
              <h3 className="font-extrabold text-xs mb-3 text-[#1e293b] dark:text-white">Compliance</h3>
              <div className="flex flex-wrap gap-2">
                {["SOC 2", "ISO 27001", "GDPR"].map((cert) => (
                  <span
                    key={cert}
                    className="flex items-center gap-1 px-2 py-1 rounded-lg border-2 border-[#e2e8f0] dark:border-[#334155] text-[10px] font-bold text-[#475569] dark:text-[#94a3b8]"
                  >
                    <Shield className="h-2.5 w-2.5" />
                    {cert}
                  </span>
                ))}
              </div>
            </div>
          </div>
          <div className="pt-6 border-t-2 border-[#e2e8f0] dark:border-[#1e293b] text-xs text-[#94a3b8] font-medium">
            <span>&copy; {new Date().getFullYear()} Arica Technologies. All rights reserved.</span>
          </div>
        </div>
      </footer>
    </div>
  );
}

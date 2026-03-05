import { useEffect, useRef } from "react";
import { useLocation } from "wouter";

declare global {
  interface Window {
    gtag?: (...args: unknown[]) => void;
    dataLayer?: unknown[];
  }
}

const GA4_ID = import.meta.env.VITE_GA4_MEASUREMENT_ID as string | undefined;
const GSC_TOKEN = import.meta.env.VITE_GSC_VERIFICATION_TOKEN as string | undefined;

let ga4Initialized = false;

function initGA4() {
  if (ga4Initialized || !GA4_ID) return;
  ga4Initialized = true;

  const script = document.createElement("script");
  script.async = true;
  script.src = `https://www.googletagmanager.com/gtag/js?id=${encodeURIComponent(GA4_ID)}`;
  document.head.appendChild(script);

  window.dataLayer = window.dataLayer || [];
  window.gtag = function (...args: unknown[]) {
    window.dataLayer!.push(args);
  };
  window.gtag("js", new Date());
  window.gtag("config", GA4_ID, { send_page_view: false });
}

function initGSC() {
  if (!GSC_TOKEN) return;
  if (document.querySelector('meta[name="google-site-verification"]')) return;

  const meta = document.createElement("meta");
  meta.name = "google-site-verification";
  meta.content = GSC_TOKEN;
  document.head.appendChild(meta);
}

function sendPageView(path: string) {
  if (typeof window.gtag === "function") {
    window.gtag("event", "page_view", {
      page_path: path,
      page_title: document.title,
      page_location: window.location.origin + path,
    });
  }
}

export function usePageTracking() {
  const [location] = useLocation();
  const previousLocation = useRef<string | null>(null);

  useEffect(() => {
    initGA4();
    initGSC();
  }, []);

  useEffect(() => {
    if (location === previousLocation.current) return;
    previousLocation.current = location;
    const id = requestAnimationFrame(() => sendPageView(location));
    return () => cancelAnimationFrame(id);
  }, [location]);
}

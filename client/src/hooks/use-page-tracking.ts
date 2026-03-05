import { useEffect, useRef } from "react";
import { useLocation } from "wouter";

declare global {
  interface Window {
    gtag?: (...args: unknown[]) => void;
    dataLayer?: unknown[];
  }
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
    if (location === previousLocation.current) return;
    previousLocation.current = location;
    sendPageView(location);
  }, [location]);
}

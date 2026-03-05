import { useEffect, useRef } from "react";
import { useLocation } from "wouter";

declare global {
  interface Window {
    gtag?: (...args: unknown[]) => void;
    dataLayer?: unknown[];
  }
}

export function usePageTracking() {
  const [location] = useLocation();
  const previousLocation = useRef(location);

  useEffect(() => {
    if (location === previousLocation.current) return;
    previousLocation.current = location;

    if (typeof window.gtag === "function") {
      window.gtag("event", "page_view", {
        page_path: location,
        page_title: document.title,
        page_location: window.location.origin + location,
      });
    }
  }, [location]);
}

import { useEffect } from "react";

const BASE_TITLE = "SecureNexus — Agentic SOC Platform";

export function usePageTitle(pageTitle?: string) {
  useEffect(() => {
    document.title = pageTitle ? `${pageTitle} — SecureNexus` : BASE_TITLE;
    return () => {
      document.title = BASE_TITLE;
    };
  }, [pageTitle]);
}

import { useEffect } from "react";

const BASE_TITLE = "SecureNexus — Agentic SOC Platform";

export function usePageTitle(pageTitle?: string, exact: boolean = false) {
  useEffect(() => {
    if (!pageTitle) {
      document.title = BASE_TITLE;
    } else {
      document.title = exact ? pageTitle : `${pageTitle} — SecureNexus`;
    }
    return () => {
      document.title = BASE_TITLE;
    };
  }, [pageTitle, exact]);
}

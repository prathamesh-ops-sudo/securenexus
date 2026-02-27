import { useEffect, useRef } from "react";
import { useLocation } from "wouter";
import { useAuth } from "./use-auth";

const ROLE_LANDING_MAP: Record<string, string> = {
  owner: "/",
  admin: "/",
  analyst: "/alerts",
  read_only: "/analytics",
};

const LANDING_APPLIED_KEY = "securenexus.roleLanding.applied";

export function useRoleLanding() {
  const { user } = useAuth();
  const [location, navigate] = useLocation();
  const applied = useRef(false);

  useEffect(() => {
    if (applied.current || !user || location !== "/") return;
    const role = (user as Record<string, unknown>).role as string | undefined;
    if (!role) return;

    const already = sessionStorage.getItem(LANDING_APPLIED_KEY);
    if (already === "true") return;

    const target = ROLE_LANDING_MAP[role];
    if (target && target !== "/") {
      applied.current = true;
      sessionStorage.setItem(LANDING_APPLIED_KEY, "true");
      navigate(target, { replace: true });
    } else {
      sessionStorage.setItem(LANDING_APPLIED_KEY, "true");
    }
  }, [user, location, navigate]);
}

import { createContext, useContext } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, useEffect, useCallback } from "react";

const ORG_STORAGE_KEY = "securenexus.activeOrgId";

interface OrgMembership {
  id: string;
  orgId: string;
  userId: string;
  role: string;
  status: string;
  organization?: {
    id: string;
    name: string;
    slug: string;
    logoUrl?: string | null;
    industry?: string | null;
  } | null;
}

interface OrgContextValue {
  currentOrgId: string | null;
  currentOrg: OrgMembership["organization"] | null;
  currentRole: string | null;
  memberships: OrgMembership[];
  isLoading: boolean;
  needsOnboarding: boolean;
  switchOrg: (orgId: string) => void;
}

export const OrgContext = createContext<OrgContextValue>({
  currentOrgId: null,
  currentOrg: null,
  currentRole: null,
  memberships: [],
  isLoading: true,
  needsOnboarding: false,
  switchOrg: () => {},
});

export function useOrgContext() {
  return useContext(OrgContext);
}

export function useOrgContextProvider(): OrgContextValue {
  const queryClient = useQueryClient();
  const [activeOrgId, setActiveOrgId] = useState<string | null>(() => {
    try {
      return localStorage.getItem(ORG_STORAGE_KEY);
    } catch {
      return null;
    }
  });

  const { data, isLoading } = useQuery<{ userId: string; memberships: OrgMembership[] }>({
    queryKey: ["/api/auth/me"],
    retry: false,
    staleTime: 1000 * 60 * 2,
  });

  const memberships = data?.memberships ?? [];
  const needsOnboarding = !isLoading && data !== undefined && memberships.length === 0;

  const resolvedMembership = memberships.find((m) => m.orgId === activeOrgId) || memberships[0] || null;

  useEffect(() => {
    if (resolvedMembership && resolvedMembership.orgId !== activeOrgId) {
      setActiveOrgId(resolvedMembership.orgId);
      try {
        localStorage.setItem(ORG_STORAGE_KEY, resolvedMembership.orgId);
      } catch {
        /* ignore */
      }
    }
  }, [resolvedMembership, activeOrgId]);

  const switchOrg = useCallback(
    (orgId: string) => {
      setActiveOrgId(orgId);
      try {
        localStorage.setItem(ORG_STORAGE_KEY, orgId);
      } catch {
        /* ignore */
      }
      queryClient.invalidateQueries();
    },
    [queryClient],
  );

  return {
    currentOrgId: resolvedMembership?.orgId ?? null,
    currentOrg: resolvedMembership?.organization ?? null,
    currentRole: resolvedMembership?.role ?? null,
    memberships,
    isLoading,
    needsOnboarding,
    switchOrg,
  };
}

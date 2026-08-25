import { createContext, useContext } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, useEffect, useCallback, useMemo } from "react";
import { useAuth } from "./use-auth";
import { fetchPaginated } from "@/lib/queryClient";

const ORG_STORAGE_KEY = "securenexus.activeOrgId";

interface OrgMembership {
  id: string;
  orgId: string;
  userId: string;
  role: string;
  status: string;
  organization?: PlatformOrganization | null;
}

export interface PlatformOrganization {
  id: string;
  name: string;
  slug: string;
  logoUrl?: string | null;
  industry?: string | null;
  orgType?: string | null;
  deletedAt?: string | null;
}

interface OrgContextValue {
  currentOrgId: string | null;
  currentOrg: OrgMembership["organization"] | null;
  currentRole: string | null;
  memberships: OrgMembership[];
  availableOrganizations: PlatformOrganization[];
  availableOrganizationsLoading: boolean;
  availableOrganizationsError: boolean;
  isPlatformAdmin: boolean;
  hasTenantContext: boolean;
  isPlatformAdminReadOnly: boolean;
  isLoading: boolean;
  needsOnboarding: boolean;
  switchOrg: (orgId: string) => void;
  clearOrg: () => void;
}

export const OrgContext = createContext<OrgContextValue>({
  currentOrgId: null,
  currentOrg: null,
  currentRole: null,
  memberships: [],
  availableOrganizations: [],
  availableOrganizationsLoading: false,
  availableOrganizationsError: false,
  isPlatformAdmin: false,
  hasTenantContext: false,
  isPlatformAdminReadOnly: false,
  isLoading: true,
  needsOnboarding: false,
  switchOrg: () => {},
  clearOrg: () => {},
});

export function useOrgContext() {
  return useContext(OrgContext);
}

export function getInitialPlatformAdminOrgId(
  activeOrgId: string | null,
  isPlatformAdmin: boolean,
  availableOrganizations: Array<Pick<PlatformOrganization, "id">>,
): string | null {
  if (activeOrgId || !isPlatformAdmin) return activeOrgId;
  return availableOrganizations[0]?.id ?? null;
}

export function useOrgContextProvider(): OrgContextValue {
  const queryClient = useQueryClient();
  const { user } = useAuth();
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
  const isPlatformAdmin = !!user?.isSuperAdmin;
  const platformOrganizationsQuery = useQuery<{ items: PlatformOrganization[]; total: number }>({
    queryKey: ["/api/platform-admin/organizations", "tenant-picker"],
    queryFn: () =>
      fetchPaginated<PlatformOrganization>("/api/platform-admin/organizations", {
        limit: 200,
        offset: 0,
      }),
    enabled: isPlatformAdmin,
    retry: false,
    staleTime: 1000 * 60 * 2,
  });
  const availableOrganizations = platformOrganizationsQuery.data?.items ?? [];
  const needsOnboarding = !isLoading && data !== undefined && memberships.length === 0;

  const memberContext = useMemo(
    () => (activeOrgId ? memberships.find((m) => m.orgId === activeOrgId) || null : memberships[0] || null),
    [activeOrgId, memberships],
  );
  const selectedPlatformOrganization = useMemo(
    () =>
      isPlatformAdmin && activeOrgId
        ? availableOrganizations.find((organization) => organization.id === activeOrgId) || null
        : null,
    [activeOrgId, availableOrganizations, isPlatformAdmin],
  );
  const resolvedMembership = useMemo(
    () =>
      memberContext ||
      (selectedPlatformOrganization
        ? {
            id: `platform-read-only-${selectedPlatformOrganization.id}`,
            orgId: selectedPlatformOrganization.id,
            userId: data?.userId ?? "",
            role: "read_only",
            status: "active",
            organization: selectedPlatformOrganization,
          }
        : null),
    [data?.userId, memberContext, selectedPlatformOrganization],
  );
  const isPlatformAdminReadOnly = !!selectedPlatformOrganization && !memberContext;
  const hasTenantContext = !!resolvedMembership;

  useEffect(() => {
    if (
      isPlatformAdmin &&
      !platformOrganizationsQuery.isLoading &&
      !platformOrganizationsQuery.isError &&
      activeOrgId &&
      !selectedPlatformOrganization
    ) {
      setActiveOrgId(null);
      try {
        localStorage.removeItem(ORG_STORAGE_KEY);
      } catch {
        /* ignore */
      }
      return;
    }
    const initialPlatformAdminOrgId = getInitialPlatformAdminOrgId(
      activeOrgId,
      isPlatformAdmin,
      availableOrganizations,
    );
    if (initialPlatformAdminOrgId && initialPlatformAdminOrgId !== activeOrgId) {
      setActiveOrgId(initialPlatformAdminOrgId);
      try {
        localStorage.setItem(ORG_STORAGE_KEY, initialPlatformAdminOrgId);
      } catch {
        /* ignore */
      }
      return;
    }
    if (!isPlatformAdmin && resolvedMembership && resolvedMembership.orgId !== activeOrgId) {
      setActiveOrgId(resolvedMembership.orgId);
      try {
        localStorage.setItem(ORG_STORAGE_KEY, resolvedMembership.orgId);
      } catch {
        /* ignore */
      }
    }
  }, [
    activeOrgId,
    isPlatformAdmin,
    platformOrganizationsQuery.isError,
    platformOrganizationsQuery.isLoading,
    availableOrganizations,
    resolvedMembership,
    selectedPlatformOrganization,
  ]);

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

  const clearOrg = useCallback(() => {
    setActiveOrgId(null);
    try {
      localStorage.removeItem(ORG_STORAGE_KEY);
    } catch {
      /* ignore */
    }
    queryClient.invalidateQueries();
  }, [queryClient]);

  return {
    currentOrgId: resolvedMembership?.orgId ?? null,
    currentOrg: resolvedMembership?.organization ?? null,
    currentRole: resolvedMembership?.role ?? null,
    memberships,
    availableOrganizations,
    availableOrganizationsLoading: platformOrganizationsQuery.isLoading,
    availableOrganizationsError: platformOrganizationsQuery.isError,
    isPlatformAdmin,
    hasTenantContext,
    isPlatformAdminReadOnly,
    isLoading: isLoading || (isPlatformAdmin && platformOrganizationsQuery.isLoading),
    needsOnboarding,
    switchOrg,
    clearOrg,
  };
}

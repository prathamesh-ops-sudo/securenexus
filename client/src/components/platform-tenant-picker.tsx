import { Building2, Check, ChevronsUpDown, Loader2, X } from "lucide-react";
import { useOrgContext } from "@/hooks/use-org-context";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

interface PlatformTenantPickerProps {
  className?: string;
}

export function PlatformTenantPicker({ className = "" }: PlatformTenantPickerProps) {
  const {
    currentOrg,
    currentOrgId,
    memberships,
    availableOrganizations,
    availableOrganizationsLoading,
    availableOrganizationsError,
    isPlatformAdmin,
    switchOrg,
    clearOrg,
  } = useOrgContext();
  const organizations = isPlatformAdmin
    ? availableOrganizations
    : memberships.map((membership) => membership.organization).filter((organization) => organization != null);

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button
          className={`flex items-center gap-2 rounded-md border border-sidebar-border/50 bg-sidebar-accent/30 px-2 py-1.5 text-left transition-all hover:border-sidebar-border hover:bg-sidebar-accent/50 ${className}`}
          aria-label="Select tenant"
        >
          <Building2 className="h-3.5 w-3.5 shrink-0 text-cyan-400/70" aria-hidden="true" />
          <span className="flex-1 truncate text-[11px] font-medium">{currentOrg?.name || "Select a tenant"}</span>
          <ChevronsUpDown className="h-3 w-3 shrink-0 text-muted-foreground/40" aria-hidden="true" />
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-64" sideOffset={4}>
        <DropdownMenuLabel className="text-[10px] text-muted-foreground">
          {isPlatformAdmin ? "View tenant read-only" : "Select organization"}
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        {availableOrganizationsLoading && (
          <DropdownMenuItem disabled className="text-xs">
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
            Loading tenants…
          </DropdownMenuItem>
        )}
        {availableOrganizationsError && (
          <DropdownMenuItem disabled className="text-xs text-destructive">
            Unable to load tenants
          </DropdownMenuItem>
        )}
        {!availableOrganizationsLoading && !availableOrganizationsError && organizations.length === 0 && (
          <DropdownMenuItem disabled className="text-xs">
            No active tenants available
          </DropdownMenuItem>
        )}
        {!availableOrganizationsLoading &&
          !availableOrganizationsError &&
          organizations.map((organization) => (
            <DropdownMenuItem
              key={organization.id}
              onClick={() => switchOrg(organization.id)}
              className="flex items-center gap-2 text-xs"
            >
              <Building2 className="h-3.5 w-3.5 shrink-0" />
              <span className="flex-1 truncate">{organization.name || organization.id}</span>
              {organization.id === currentOrgId && <Check className="h-3.5 w-3.5 shrink-0 text-cyan-400" />}
            </DropdownMenuItem>
          ))}
        {currentOrgId && (
          <>
            <DropdownMenuSeparator />
            <DropdownMenuItem onClick={clearOrg} className="text-xs text-muted-foreground">
              <X className="h-3.5 w-3.5" />
              Clear selected tenant
            </DropdownMenuItem>
          </>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

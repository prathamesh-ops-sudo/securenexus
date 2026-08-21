import { Eye, X } from "lucide-react";
import { Link } from "wouter";
import { useOrgContext } from "@/hooks/use-org-context";

export function PlatformReadOnlyBanner() {
  const { currentOrg, isPlatformAdminReadOnly, clearOrg } = useOrgContext();

  if (!isPlatformAdminReadOnly || !currentOrg) return null;

  return (
    <div
      className="flex items-center gap-3 border-b border-amber-500/40 bg-amber-500/15 px-4 py-2 text-amber-100"
      role="status"
      aria-label="Platform administrator read-only tenant view"
    >
      <Eye className="h-4 w-4 shrink-0 text-amber-300" aria-hidden="true" />
      <p className="min-w-0 flex-1 truncate text-xs">
        <strong>Platform administrator · read-only view:</strong> {currentOrg.name}. Write operations are unavailable.
      </p>
      <Link href="/platform-admin" className="shrink-0 text-xs font-medium underline underline-offset-2">
        Platform administration
      </Link>
      <button
        type="button"
        onClick={clearOrg}
        className="inline-flex shrink-0 items-center gap-1 rounded px-2 py-1 text-xs hover:bg-amber-500/20"
        aria-label="Clear selected tenant"
      >
        <X className="h-3.5 w-3.5" aria-hidden="true" />
        Clear
      </button>
    </div>
  );
}

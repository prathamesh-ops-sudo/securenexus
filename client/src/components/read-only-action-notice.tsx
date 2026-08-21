import { Eye } from "lucide-react";
import { useOrgContext } from "@/hooks/use-org-context";

export function ReadOnlyActionNotice() {
  const { isPlatformAdminReadOnly } = useOrgContext();

  if (!isPlatformAdminReadOnly) return null;

  return (
    <p className="flex items-center gap-1.5 text-xs text-amber-400" role="status">
      <Eye className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
      Unavailable in the platform administrator read-only tenant view. This POST operation requires write-capable tenant
      access.
    </p>
  );
}

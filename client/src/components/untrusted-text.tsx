import { useState } from "react";
import { Eye, EyeOff } from "lucide-react";
import { useOrgContext } from "@/hooks/use-org-context";
import { hasMaskedUntrustedText, maskUntrustedText } from "@/lib/untrusted-content";
import { Button } from "@/components/ui/button";

interface UntrustedTextProps {
  value: string;
  className?: string;
  testId?: string;
  compact?: boolean;
}

const PRIVILEGED_ROLES = new Set(["owner", "admin"]);

export function UntrustedText({ value, className = "", testId, compact = false }: UntrustedTextProps) {
  const { currentRole } = useOrgContext();
  const [revealed, setRevealed] = useState(false);
  const maskedValue = maskUntrustedText(value);
  const hasMaskedValue = hasMaskedUntrustedText(value);
  const canReveal = PRIVILEGED_ROLES.has(currentRole ?? "");

  return (
    <div
      className={
        compact
          ? `flex min-w-0 items-center gap-1 text-amber-900 dark:text-amber-100 ${className}`
          : `rounded-md border border-amber-500/30 bg-amber-500/5 px-2 py-1.5 ${className}`
      }
      data-testid={testId}
    >
      <div
        className={
          compact
            ? "shrink-0 text-[10px] font-medium uppercase tracking-wider text-amber-700 dark:text-amber-300"
            : "mb-1 flex items-center gap-2 text-[10px] font-medium uppercase tracking-wider text-amber-700 dark:text-amber-300"
        }
      >
        <span>{compact ? "Untrusted:" : "Untrusted ingested text"}</span>
        {hasMaskedValue && !revealed && <span>secret values masked</span>}
      </div>
      <div className={`flex min-w-0 items-start gap-2 ${compact ? "flex-1" : ""}`}>
        <span className="min-w-0 flex-1 whitespace-pre-wrap break-words">{revealed ? value : maskedValue}</span>
        {canReveal && (
          <Button
            type="button"
            variant="ghost"
            size="sm"
            className="h-6 shrink-0 px-1.5 text-[10px]"
            onClick={() => setRevealed((current) => !current)}
            aria-label={revealed ? "Hide raw ingested text" : "Reveal raw ingested text"}
          >
            {revealed ? <EyeOff className="mr-1 h-3 w-3" /> : <Eye className="mr-1 h-3 w-3" />}
            {revealed ? "Hide raw" : "Reveal raw"}
          </Button>
        )}
      </div>
    </div>
  );
}

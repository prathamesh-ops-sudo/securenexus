import { useEffect, useState } from "react";
import { apiRequest } from "@/lib/queryClient";
import { X, Eye } from "lucide-react";
import { Button } from "@/components/ui/button";

export function ImpersonationBanner() {
  const [impersonating, setImpersonating] = useState<string | null>(null);
  const [expiresAt, setExpiresAt] = useState<string | null>(null);
  const [ending, setEnding] = useState(false);

  useEffect(() => {
    const email = sessionStorage.getItem("impersonatingAs");
    const expires = sessionStorage.getItem("impersonationExpires");
    if (email) {
      setImpersonating(email);
      setExpiresAt(expires);
    }
  }, []);

  useEffect(() => {
    if (!expiresAt) return;
    const remaining = new Date(expiresAt).getTime() - Date.now();
    if (remaining <= 0) {
      handleEnd();
      return;
    }
    const timer = setTimeout(() => handleEnd(), remaining);
    return () => clearTimeout(timer);
  }, [expiresAt]);

  const handleEnd = async () => {
    setEnding(true);
    try {
      const token = sessionStorage.getItem("impersonationToken");
      if (token) {
        await apiRequest("POST", "/api/platform-admin/impersonate/end", { impersonationToken: token });
      }
    } catch {
      // best-effort
    } finally {
      sessionStorage.removeItem("impersonationToken");
      sessionStorage.removeItem("impersonatingAs");
      sessionStorage.removeItem("impersonationExpires");
      setImpersonating(null);
      setEnding(false);
      window.location.reload();
    }
  };

  if (!impersonating) return null;

  return (
    <div className="bg-yellow-500 text-yellow-950 px-4 py-2 flex items-center justify-between text-sm font-medium z-50 relative">
      <div className="flex items-center gap-2">
        <Eye className="h-4 w-4" />
        <span>
          Impersonating <strong>{impersonating}</strong>
        </span>
        {expiresAt && (
          <span className="text-yellow-800 text-xs">(expires {new Date(expiresAt).toLocaleTimeString()})</span>
        )}
      </div>
      <Button
        variant="ghost"
        size="sm"
        className="h-6 px-2 text-yellow-950 hover:bg-yellow-600/30"
        onClick={handleEnd}
        disabled={ending}
      >
        <X className="h-3 w-3 mr-1" />
        {ending ? "Ending..." : "Exit Impersonation"}
      </Button>
    </div>
  );
}

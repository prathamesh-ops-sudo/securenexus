import { useState, useEffect } from "react";
import { useLocation, useSearch } from "wouter";
import { Users, ArrowLeft, CheckCircle2, Loader2, AlertTriangle, LogIn } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { useAuth } from "@/hooks/use-auth";
import atsLogo from "@/assets/logo.jpg";

export default function AcceptInvitationPage() {
  const [, navigate] = useLocation();
  const search = useSearch();
  const params = new URLSearchParams(search);
  const token = params.get("token") || "";
  const { user, isLoading: authLoading } = useAuth();

  const [isAccepting, setIsAccepting] = useState(false);
  const [isSuccess, setIsSuccess] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [orgName, setOrgName] = useState<string | null>(null);

  useEffect(() => {
    if (authLoading || !token || !user) return;

    const acceptInvitation = async () => {
      setIsAccepting(true);
      setError(null);
      try {
        const res = await fetch("/api/invitations/accept", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ token }),
        });

        const body = await res.json();

        if (!res.ok) {
          const msg = body.error || body.message || "Failed to accept invitation";
          setError(msg);
          return;
        }

        setOrgName(body.organization?.name || null);
        setIsSuccess(true);
      } catch {
        setError("Network error. Please try again.");
      } finally {
        setIsAccepting(false);
      }
    };

    acceptInvitation();
  }, [token, user, authLoading]);

  if (authLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#FFF8F0] dark:bg-[#0a0f1e] p-4">
        <Card className="w-full max-w-md border-[2.5px] border-[#1e293b] dark:border-[#334155] shadow-[6px_6px_0px_#1e293b] dark:shadow-[6px_6px_0px_rgba(6,182,212,0.3)] bg-white dark:bg-[#111827]">
          <CardContent className="p-8 space-y-4">
            <Skeleton className="h-8 w-48" />
            <Skeleton className="h-4 w-full" />
            <Skeleton className="h-10 w-full" />
          </CardContent>
        </Card>
      </div>
    );
  }

  if (!token) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#FFF8F0] dark:bg-[#0a0f1e] p-4">
        <Card className="w-full max-w-md border-[2.5px] border-[#1e293b] dark:border-[#334155] shadow-[6px_6px_0px_#1e293b] dark:shadow-[6px_6px_0px_rgba(6,182,212,0.3)] bg-white dark:bg-[#111827]">
          <CardContent className="p-8 space-y-4">
            <div className="flex items-center gap-3 p-4 rounded-xl border-2 border-amber-300 dark:border-amber-500/30 bg-amber-50 dark:bg-amber-500/10">
              <AlertTriangle className="h-5 w-5 text-amber-600 dark:text-amber-400 shrink-0" />
              <div>
                <p className="text-sm font-bold text-amber-700 dark:text-amber-300">Invalid invitation link</p>
                <p className="text-xs text-amber-600 dark:text-amber-400 mt-1">
                  This invitation link is missing the required token. Please check the link from your email.
                </p>
              </div>
            </div>
            <Button variant="ghost" className="w-full text-sm" onClick={() => navigate("/")}>
              <ArrowLeft className="h-4 w-4 mr-2" />
              Go to home
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (!user) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#FFF8F0] dark:bg-[#0a0f1e] p-4">
        <Card className="w-full max-w-md border-[2.5px] border-[#1e293b] dark:border-[#334155] shadow-[6px_6px_0px_#1e293b] dark:shadow-[6px_6px_0px_rgba(6,182,212,0.3)] bg-white dark:bg-[#111827]">
          <CardHeader className="space-y-3">
            <div className="flex items-center gap-2.5">
              <div className="w-10 h-10 rounded-xl border-2 border-[#1e293b] dark:border-cyan-500/30 flex items-center justify-center bg-gradient-to-br from-cyan-50 to-white dark:from-cyan-500/10 dark:to-transparent">
                <img src={atsLogo} alt="SecureNexus" className="w-7 h-7 object-contain" />
              </div>
              <span className="font-bold text-lg tracking-tight text-[#1e293b] dark:text-[#e2e8f0]">SecureNexus</span>
            </div>
            <CardTitle className="text-xl font-extrabold text-[#1e293b] dark:text-[#e2e8f0]">
              You've been invited
            </CardTitle>
            <CardDescription className="text-[#64748b] dark:text-[#94a3b8]">
              Sign in or create an account to accept this invitation and join the organization.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="flex items-center gap-3 p-4 rounded-xl border-2 border-cyan-300 dark:border-cyan-500/30 bg-cyan-50 dark:bg-cyan-500/10">
              <Users className="h-5 w-5 text-cyan-600 dark:text-cyan-400 shrink-0" />
              <p className="text-sm font-medium text-cyan-700 dark:text-cyan-300">
                After signing in, you'll automatically join the organization.
              </p>
            </div>
            <Button
              className="w-full h-11 font-bold border-[2.5px] border-[#1e293b] dark:border-[#334155] shadow-[4px_4px_0px_#1e293b] dark:shadow-[4px_4px_0px_rgba(6,182,212,0.3)] hover:shadow-[2px_2px_0px_#1e293b] dark:hover:shadow-[2px_2px_0px_rgba(6,182,212,0.3)] hover:translate-x-[2px] hover:translate-y-[2px] active:shadow-none active:translate-x-[4px] active:translate-y-[4px] transition-all bg-cyan-600 hover:bg-cyan-700 text-white"
              onClick={() => {
                sessionStorage.setItem("pendingInvitationToken", token);
                navigate("/");
              }}
            >
              <LogIn className="h-4 w-4 mr-2" />
              Sign in to accept invitation
            </Button>
            <p className="text-xs text-center text-[#94a3b8]">
              Don't have an account? You can register on the sign-in page.
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-[#FFF8F0] dark:bg-[#0a0f1e] p-4">
      <Card className="w-full max-w-md border-[2.5px] border-[#1e293b] dark:border-[#334155] shadow-[6px_6px_0px_#1e293b] dark:shadow-[6px_6px_0px_rgba(6,182,212,0.3)] bg-white dark:bg-[#111827]">
        <CardHeader className="space-y-3">
          <div className="flex items-center gap-2.5">
            <div className="w-10 h-10 rounded-xl border-2 border-[#1e293b] dark:border-cyan-500/30 flex items-center justify-center bg-gradient-to-br from-cyan-50 to-white dark:from-cyan-500/10 dark:to-transparent">
              <img src={atsLogo} alt="SecureNexus" className="w-7 h-7 object-contain" />
            </div>
            <span className="font-bold text-lg tracking-tight text-[#1e293b] dark:text-[#e2e8f0]">SecureNexus</span>
          </div>
          <CardTitle className="text-xl font-extrabold text-[#1e293b] dark:text-[#e2e8f0]">
            {isSuccess ? "Welcome aboard!" : isAccepting ? "Accepting invitation..." : "Invitation"}
          </CardTitle>
        </CardHeader>
        <CardContent>
          {isAccepting && (
            <div className="flex items-center justify-center gap-3 py-8">
              <Loader2 className="h-6 w-6 animate-spin text-cyan-600" />
              <p className="text-sm font-medium text-[#475569] dark:text-[#94a3b8]">Accepting your invitation...</p>
            </div>
          )}

          {isSuccess && (
            <div className="space-y-4">
              <div className="flex items-center gap-3 p-4 rounded-xl border-2 border-emerald-300 dark:border-emerald-500/30 bg-emerald-50 dark:bg-emerald-500/10">
                <CheckCircle2 className="h-5 w-5 text-emerald-600 dark:text-emerald-400 shrink-0" />
                <p className="text-sm font-medium text-emerald-700 dark:text-emerald-300">
                  You've successfully joined{orgName ? ` ${orgName}` : " the organization"}.
                </p>
              </div>
              <Button
                className="w-full h-11 font-bold border-[2.5px] border-[#1e293b] dark:border-[#334155] shadow-[4px_4px_0px_#1e293b] dark:shadow-[4px_4px_0px_rgba(6,182,212,0.3)] hover:shadow-[2px_2px_0px_#1e293b] dark:hover:shadow-[2px_2px_0px_rgba(6,182,212,0.3)] hover:translate-x-[2px] hover:translate-y-[2px] active:shadow-none active:translate-x-[4px] active:translate-y-[4px] transition-all bg-cyan-600 hover:bg-cyan-700 text-white"
                onClick={() => navigate("/")}
              >
                Go to dashboard
              </Button>
            </div>
          )}

          {error && !isAccepting && (
            <div className="space-y-4">
              <div className="flex items-center gap-3 p-4 rounded-xl border-2 border-red-300 dark:border-red-500/30 bg-red-50 dark:bg-red-500/10">
                <AlertTriangle className="h-5 w-5 text-red-600 dark:text-red-400 shrink-0" />
                <p className="text-sm font-medium text-red-700 dark:text-red-300">{error}</p>
              </div>
              <Button
                variant="outline"
                className="w-full border-[2px] border-[#1e293b] dark:border-[#334155] font-semibold"
                onClick={() => navigate("/")}
              >
                Go to dashboard
              </Button>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

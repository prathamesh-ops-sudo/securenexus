import { useState, useEffect } from "react";
import { useLocation, useSearch } from "wouter";
import { Lock, ArrowLeft, CheckCircle2, Loader2, AlertTriangle, Eye, EyeOff } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import atsLogo from "@/assets/logo.jpg";

export default function ResetPasswordPage() {
  const [, navigate] = useLocation();
  const search = useSearch();
  const params = new URLSearchParams(search);
  const token = params.get("token") || "";

  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isSuccess, setIsSuccess] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isValidating, setIsValidating] = useState(true);
  const [isTokenValid, setIsTokenValid] = useState(false);

  useEffect(() => {
    if (!token) {
      setIsValidating(false);
      return;
    }

    const validateToken = async () => {
      try {
        const res = await fetch(`/api/auth/reset-password/validate?token=${encodeURIComponent(token)}`);
        const body = await res.json();
        setIsTokenValid(body.data?.valid === true);
      } catch {
        setIsTokenValid(false);
      } finally {
        setIsValidating(false);
      }
    };

    validateToken();
  }, [token]);

  const passwordStrength = (() => {
    if (password.length === 0) return null;
    let score = 0;
    if (password.length >= 8) score++;
    if (password.length >= 12) score++;
    if (/[A-Z]/.test(password)) score++;
    if (/[0-9]/.test(password)) score++;
    if (/[^A-Za-z0-9]/.test(password)) score++;
    if (score <= 2) return { label: "Weak", color: "bg-red-500", width: "w-1/3" };
    if (score <= 3) return { label: "Fair", color: "bg-amber-500", width: "w-2/3" };
    return { label: "Strong", color: "bg-emerald-500", width: "w-full" };
  })();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (password.length < 8) {
      setError("Password must be at least 8 characters");
      return;
    }

    if (password !== confirmPassword) {
      setError("Passwords do not match");
      return;
    }

    setIsSubmitting(true);
    try {
      const res = await fetch("/api/auth/reset-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token, password }),
      });

      const body = await res.json();

      if (!res.ok) {
        const msg = body.errors?.[0]?.message || body.message || "Something went wrong";
        setError(msg);
        return;
      }

      setIsSuccess(true);
    } catch {
      setError("Network error. Please try again.");
    } finally {
      setIsSubmitting(false);
    }
  };

  if (isValidating) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#FFF8F0] dark:bg-[#0a0f1e] p-4">
        <Card className="w-full max-w-md border-[2.5px] border-[#1e293b] dark:border-[#334155] shadow-[6px_6px_0px_#1e293b] dark:shadow-[6px_6px_0px_rgba(6,182,212,0.3)] bg-white dark:bg-[#111827]">
          <CardContent className="p-8 space-y-4">
            <Skeleton className="h-8 w-48" />
            <Skeleton className="h-4 w-full" />
            <Skeleton className="h-10 w-full" />
            <Skeleton className="h-10 w-full" />
          </CardContent>
        </Card>
      </div>
    );
  }

  if (!token || !isTokenValid) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#FFF8F0] dark:bg-[#0a0f1e] p-4">
        <Card className="w-full max-w-md border-[2.5px] border-[#1e293b] dark:border-[#334155] shadow-[6px_6px_0px_#1e293b] dark:shadow-[6px_6px_0px_rgba(6,182,212,0.3)] bg-white dark:bg-[#111827]">
          <CardContent className="p-8 space-y-4">
            <div className="flex items-center gap-3 p-4 rounded-xl border-2 border-amber-300 dark:border-amber-500/30 bg-amber-50 dark:bg-amber-500/10">
              <AlertTriangle className="h-5 w-5 text-amber-600 dark:text-amber-400 shrink-0" />
              <div>
                <p className="text-sm font-bold text-amber-700 dark:text-amber-300">Invalid or expired link</p>
                <p className="text-xs text-amber-600 dark:text-amber-400 mt-1">
                  This password reset link is invalid or has expired. Please request a new one.
                </p>
              </div>
            </div>
            <Button className="w-full font-semibold" onClick={() => navigate("/forgot-password")}>
              Request new reset link
            </Button>
            <Button variant="ghost" className="w-full text-sm" onClick={() => navigate("/")}>
              <ArrowLeft className="h-4 w-4 mr-2" />
              Back to login
            </Button>
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
            {isSuccess ? "Password reset!" : "Create new password"}
          </CardTitle>
          <CardDescription className="text-[#64748b] dark:text-[#94a3b8]">
            {isSuccess
              ? "Your password has been successfully updated."
              : "Enter a new password for your account. Make sure it's at least 8 characters."}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isSuccess ? (
            <div className="space-y-4">
              <div className="flex items-center gap-3 p-4 rounded-xl border-2 border-emerald-300 dark:border-emerald-500/30 bg-emerald-50 dark:bg-emerald-500/10">
                <CheckCircle2 className="h-5 w-5 text-emerald-600 dark:text-emerald-400 shrink-0" />
                <p className="text-sm font-medium text-emerald-700 dark:text-emerald-300">
                  Your password has been reset. You can now log in with your new password.
                </p>
              </div>
              <Button
                className="w-full h-11 font-bold border-[2.5px] border-[#1e293b] dark:border-[#334155] shadow-[4px_4px_0px_#1e293b] dark:shadow-[4px_4px_0px_rgba(6,182,212,0.3)] hover:shadow-[2px_2px_0px_#1e293b] dark:hover:shadow-[2px_2px_0px_rgba(6,182,212,0.3)] hover:translate-x-[2px] hover:translate-y-[2px] active:shadow-none active:translate-x-[4px] active:translate-y-[4px] transition-all bg-cyan-600 hover:bg-cyan-700 text-white"
                onClick={() => navigate("/")}
              >
                Sign in to SecureNexus
              </Button>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="space-y-4">
              {error && (
                <div className="p-3 rounded-xl border-2 border-red-300 dark:border-red-500/30 bg-red-50 dark:bg-red-500/10 text-red-600 dark:text-red-400 text-sm font-medium">
                  {error}
                </div>
              )}
              <div className="space-y-2">
                <Label
                  htmlFor="password"
                  className="text-xs font-bold uppercase tracking-wider text-[#475569] dark:text-[#94a3b8]"
                >
                  New password
                </Label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-[#94a3b8]" />
                  <Input
                    id="password"
                    type={showPassword ? "text" : "password"}
                    placeholder="At least 8 characters"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="pl-10 pr-10 h-11 border-[2px] border-[#cbd5e1] dark:border-[#334155] bg-white dark:bg-[#0f172a] font-medium"
                    required
                    minLength={8}
                    autoFocus
                  />
                  <button
                    type="button"
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-[#94a3b8] hover:text-[#475569]"
                    onClick={() => setShowPassword(!showPassword)}
                    tabIndex={-1}
                  >
                    {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </button>
                </div>
                {passwordStrength && (
                  <div className="space-y-1">
                    <div className="h-1.5 bg-[#e2e8f0] dark:bg-[#1e293b] rounded-full overflow-hidden">
                      <div
                        className={`h-full ${passwordStrength.color} ${passwordStrength.width} rounded-full transition-all`}
                      />
                    </div>
                    <p className="text-xs text-[#94a3b8]">
                      Password strength: <span className="font-semibold">{passwordStrength.label}</span>
                    </p>
                  </div>
                )}
              </div>
              <div className="space-y-2">
                <Label
                  htmlFor="confirmPassword"
                  className="text-xs font-bold uppercase tracking-wider text-[#475569] dark:text-[#94a3b8]"
                >
                  Confirm password
                </Label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-[#94a3b8]" />
                  <Input
                    id="confirmPassword"
                    type={showPassword ? "text" : "password"}
                    placeholder="Re-enter your password"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    className="pl-10 h-11 border-[2px] border-[#cbd5e1] dark:border-[#334155] bg-white dark:bg-[#0f172a] font-medium"
                    required
                    minLength={8}
                  />
                </div>
                {confirmPassword && password !== confirmPassword && (
                  <p className="text-xs text-red-500 font-medium">Passwords do not match</p>
                )}
              </div>
              <Button
                type="submit"
                disabled={isSubmitting || password.length < 8 || password !== confirmPassword}
                className="w-full h-11 font-bold border-[2.5px] border-[#1e293b] dark:border-[#334155] shadow-[4px_4px_0px_#1e293b] dark:shadow-[4px_4px_0px_rgba(6,182,212,0.3)] hover:shadow-[2px_2px_0px_#1e293b] dark:hover:shadow-[2px_2px_0px_rgba(6,182,212,0.3)] hover:translate-x-[2px] hover:translate-y-[2px] active:shadow-none active:translate-x-[4px] active:translate-y-[4px] transition-all bg-cyan-600 hover:bg-cyan-700 text-white"
              >
                {isSubmitting ? (
                  <>
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                    Resetting...
                  </>
                ) : (
                  "Reset password"
                )}
              </Button>
            </form>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

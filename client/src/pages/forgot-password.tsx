import { useState } from "react";
import { useLocation } from "wouter";
import { Mail, ArrowLeft, CheckCircle2, Loader2 } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import atsLogo from "@/assets/logo.jpg";

export default function ForgotPasswordPage() {
  const [, navigate] = useLocation();
  const [email, setEmail] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isSuccess, setIsSuccess] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (!email.trim()) {
      setError("Please enter your email address");
      return;
    }

    setIsSubmitting(true);
    try {
      const res = await fetch("/api/auth/forgot-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email.trim().toLowerCase() }),
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
            {isSuccess ? "Check your email" : "Reset your password"}
          </CardTitle>
          <CardDescription className="text-[#64748b] dark:text-[#94a3b8]">
            {isSuccess
              ? "We've sent a password reset link to your email address."
              : "Enter the email address associated with your account and we'll send you a link to reset your password."}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isSuccess ? (
            <div className="space-y-4">
              <div className="flex items-center gap-3 p-4 rounded-xl border-2 border-emerald-300 dark:border-emerald-500/30 bg-emerald-50 dark:bg-emerald-500/10">
                <CheckCircle2 className="h-5 w-5 text-emerald-600 dark:text-emerald-400 shrink-0" />
                <p className="text-sm font-medium text-emerald-700 dark:text-emerald-300">
                  If an account with <strong>{email}</strong> exists, you will receive a password reset email shortly.
                </p>
              </div>
              <p className="text-xs text-[#94a3b8]">
                The link will expire in 60 minutes. Check your spam folder if you don't see it.
              </p>
              <Button
                variant="outline"
                className="w-full border-[2px] border-[#1e293b] dark:border-[#334155] font-semibold"
                onClick={() => navigate("/")}
              >
                <ArrowLeft className="h-4 w-4 mr-2" />
                Back to login
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
                  htmlFor="email"
                  className="text-xs font-bold uppercase tracking-wider text-[#475569] dark:text-[#94a3b8]"
                >
                  Email address
                </Label>
                <div className="relative">
                  <Mail className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-[#94a3b8]" />
                  <Input
                    id="email"
                    type="email"
                    placeholder="you@company.com"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="pl-10 h-11 border-[2px] border-[#cbd5e1] dark:border-[#334155] bg-white dark:bg-[#0f172a] font-medium"
                    required
                    autoFocus
                  />
                </div>
              </div>
              <Button
                type="submit"
                disabled={isSubmitting}
                className="w-full h-11 font-bold border-[2.5px] border-[#1e293b] dark:border-[#334155] shadow-[4px_4px_0px_#1e293b] dark:shadow-[4px_4px_0px_rgba(6,182,212,0.3)] hover:shadow-[2px_2px_0px_#1e293b] dark:hover:shadow-[2px_2px_0px_rgba(6,182,212,0.3)] hover:translate-x-[2px] hover:translate-y-[2px] active:shadow-none active:translate-x-[4px] active:translate-y-[4px] transition-all bg-cyan-600 hover:bg-cyan-700 text-white"
              >
                {isSubmitting ? (
                  <>
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                    Sending...
                  </>
                ) : (
                  "Send reset link"
                )}
              </Button>
              <Button
                type="button"
                variant="ghost"
                className="w-full text-sm font-medium text-[#64748b] hover:text-[#1e293b] dark:text-[#94a3b8] dark:hover:text-[#e2e8f0]"
                onClick={() => navigate("/")}
              >
                <ArrowLeft className="h-4 w-4 mr-2" />
                Back to login
              </Button>
            </form>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

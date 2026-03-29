import { useState, useEffect } from "react";
import { useLocation, useSearch } from "wouter";
import { Mail, ArrowLeft, CheckCircle2, Loader2, AlertTriangle, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import atsLogo from "@/assets/logo.png";

export default function VerifyEmailPage() {
  const [, navigate] = useLocation();
  const search = useSearch();
  const params = new URLSearchParams(search);
  const token = params.get("token") || "";

  const [isVerifying, setIsVerifying] = useState(false);
  const [isSuccess, setIsSuccess] = useState(false);
  const [alreadyVerified, setAlreadyVerified] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Resend form state
  const [resendEmail, setResendEmail] = useState("");
  const [isResending, setIsResending] = useState(false);
  const [resendMessage, setResendMessage] = useState<string | null>(null);

  useEffect(() => {
    if (!token) return;

    const verify = async () => {
      setIsVerifying(true);
      setError(null);
      try {
        const res = await fetch("/api/auth/verify-email", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ token }),
        });
        const body = await res.json();
        if (!res.ok) {
          const msg = body?.errors?.[0]?.message || body?.message || "Verification failed";
          setError(msg);
        } else if (body.data?.alreadyVerified) {
          setAlreadyVerified(true);
        } else {
          setIsSuccess(true);
        }
      } catch {
        setError("Network error. Please try again.");
      } finally {
        setIsVerifying(false);
      }
    };

    verify();
  }, [token]);

  const handleResend = async () => {
    if (!resendEmail) return;
    setIsResending(true);
    setResendMessage(null);
    try {
      const res = await fetch("/api/auth/resend-verification", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: resendEmail }),
      });
      const body = await res.json();
      setResendMessage(body.data?.message || "Verification email sent.");
    } catch {
      setResendMessage("Failed to resend. Please try again.");
    } finally {
      setIsResending(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-4">
      <div className="w-full max-w-md space-y-6">
        <div className="flex flex-col items-center gap-3">
          <img src={atsLogo} alt="SecureNexus" className="h-10 w-auto" />
          <h1 className="text-xl font-semibold text-foreground">Email Verification</h1>
        </div>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Mail className="h-5 w-5" />
              {isVerifying
                ? "Verifying..."
                : isSuccess
                  ? "Email Verified"
                  : alreadyVerified
                    ? "Already Verified"
                    : error
                      ? "Verification Failed"
                      : "Verify Your Email"}
            </CardTitle>
            <CardDescription>
              {isVerifying
                ? "Please wait while we verify your email address."
                : isSuccess
                  ? "Your email has been verified successfully."
                  : alreadyVerified
                    ? "Your email address was already verified."
                    : error
                      ? "We couldn't verify your email address."
                      : "Enter your email to receive a new verification link."}
            </CardDescription>
          </CardHeader>

          <CardContent className="space-y-4">
            {isVerifying && (
              <div className="flex items-center justify-center py-8">
                <Loader2 className="h-8 w-8 animate-spin text-primary" />
              </div>
            )}

            {isSuccess && (
              <div className="space-y-4">
                <div className="flex items-center justify-center py-4">
                  <CheckCircle2 className="h-12 w-12 text-emerald-500" />
                </div>
                <p className="text-sm text-center text-muted-foreground">You can now sign in to your account.</p>
                <Button className="w-full" onClick={() => navigate("/")}>
                  Go to Sign In
                </Button>
              </div>
            )}

            {alreadyVerified && (
              <div className="space-y-4">
                <div className="flex items-center justify-center py-4">
                  <CheckCircle2 className="h-12 w-12 text-blue-500" />
                </div>
                <p className="text-sm text-center text-muted-foreground">
                  Your email is already verified. You can sign in.
                </p>
                <Button className="w-full" onClick={() => navigate("/")}>
                  Go to Sign In
                </Button>
              </div>
            )}

            {error && (
              <div className="space-y-4">
                <div className="flex items-center justify-center py-4">
                  <AlertTriangle className="h-12 w-12 text-destructive" />
                </div>
                <p className="text-sm text-center text-destructive">{error}</p>

                <div className="border-t pt-4 space-y-3">
                  <p className="text-sm text-muted-foreground">Need a new verification link? Enter your email below.</p>
                  <div className="space-y-2">
                    <Label htmlFor="resend-email">Email address</Label>
                    <Input
                      id="resend-email"
                      type="email"
                      placeholder="you@company.com"
                      value={resendEmail}
                      onChange={(e) => setResendEmail(e.target.value)}
                    />
                  </div>
                  <Button
                    className="w-full"
                    variant="outline"
                    onClick={handleResend}
                    disabled={isResending || !resendEmail}
                  >
                    {isResending ? (
                      <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                    ) : (
                      <RefreshCw className="h-4 w-4 mr-2" />
                    )}
                    Resend Verification Email
                  </Button>
                  {resendMessage && <p className="text-sm text-muted-foreground text-center">{resendMessage}</p>}
                </div>
              </div>
            )}

            {/* No token provided — show resend form */}
            {!token && !isVerifying && !isSuccess && !alreadyVerified && !error && (
              <div className="space-y-4">
                <p className="text-sm text-muted-foreground">
                  Check your inbox for the verification link we sent when you registered. If you can't find it, enter
                  your email below to request a new one.
                </p>
                <div className="space-y-2">
                  <Label htmlFor="resend-email-notoken">Email address</Label>
                  <Input
                    id="resend-email-notoken"
                    type="email"
                    placeholder="you@company.com"
                    value={resendEmail}
                    onChange={(e) => setResendEmail(e.target.value)}
                  />
                </div>
                <Button className="w-full" onClick={handleResend} disabled={isResending || !resendEmail}>
                  {isResending ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Mail className="h-4 w-4 mr-2" />}
                  Send Verification Email
                </Button>
                {resendMessage && <p className="text-sm text-muted-foreground text-center">{resendMessage}</p>}
              </div>
            )}
          </CardContent>
        </Card>

        <div className="text-center">
          <Button variant="ghost" size="sm" onClick={() => navigate("/")}>
            <ArrowLeft className="h-4 w-4 mr-2" />
            Back to Sign In
          </Button>
        </div>
      </div>
    </div>
  );
}

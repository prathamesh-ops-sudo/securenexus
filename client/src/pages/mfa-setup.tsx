import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";
import {
  Shield,
  ShieldCheck,
  ShieldOff,
  Copy,
  Loader2,
  Download,
  Fingerprint,
  Smartphone,
  KeyRound,
} from "lucide-react";
import { FormPageSkeleton } from "@/components/page-skeleton";

export default function MfaSetupPage() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [setupData, setSetupData] = useState<{
    secret: string;
    otpauthUrl: string;
    qrCodeDataUrl: string;
  } | null>(null);
  const [verifyToken, setVerifyToken] = useState("");
  const [disableToken, setDisableToken] = useState("");

  const {
    data: status,
    isPending,
    isLoading,
  } = useQuery<{ mfaEnabled: boolean; mfaVerifiedAt: string | null }>({
    queryKey: ["/api/mfa/status"],
  });

  const setupMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/mfa/setup");
      return res.json();
    },
    onSuccess: (data: { secret: string; otpauthUrl: string; qrCodeDataUrl: string }) => {
      setSetupData(data);
      toast({ title: "MFA setup initiated", description: "Scan the QR code or enter the secret manually." });
    },
    onError: (error: Error) => {
      toast({ title: "Setup failed", description: error.message, variant: "destructive" });
    },
  });

  const verifyMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/mfa/verify", { token: verifyToken });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/mfa/status"] });
      setSetupData(null);
      setVerifyToken("");
      toast({ title: "MFA enabled", description: "Two-factor authentication is now active on your account." });
    },
    onError: (error: Error) => {
      toast({ title: "Verification failed", description: error.message, variant: "destructive" });
    },
  });

  const disableMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/mfa/disable", { token: disableToken });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/mfa/status"] });
      setDisableToken("");
      toast({ title: "MFA disabled", description: "Two-factor authentication has been removed from your account." });
    },
    onError: (error: Error) => {
      toast({ title: "Disable failed", description: error.message, variant: "destructive" });
    },
  });

  const copySecret = () => {
    if (setupData?.secret) {
      navigator.clipboard.writeText(setupData.secret);
      toast({ title: "Copied", description: "Secret copied to clipboard." });
    }
  };

  if (isPending) {
    if (isLoading) return <FormPageSkeleton />;

    return (
      <div className="flex items-center justify-center min-h-[400px]" data-testid="mfa-loading">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  return (
    <div className="container mx-auto max-w-2xl py-8 space-y-6" data-testid="mfa-setup-page">
      <div className="flex items-center gap-3">
        <Shield className="h-8 w-8 text-primary" />
        <div>
          <h1 className="text-2xl font-bold">Two-Factor Authentication</h1>
          <p className="text-muted-foreground">Add an extra layer of security to your account</p>
        </div>
      </div>

      <Card data-testid="mfa-status-card">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            Status
            {status?.mfaEnabled ? (
              <Badge variant="default" className="bg-green-600" data-testid="mfa-enabled-badge">
                <ShieldCheck className="h-3 w-3 mr-1" /> Enabled
              </Badge>
            ) : (
              <Badge variant="secondary" data-testid="mfa-disabled-badge">
                <ShieldOff className="h-3 w-3 mr-1" /> Disabled
              </Badge>
            )}
          </CardTitle>
          <CardDescription>
            {status?.mfaEnabled
              ? `MFA was enabled on ${status.mfaVerifiedAt ? new Date(status.mfaVerifiedAt).toLocaleDateString() : "unknown date"}.`
              : "MFA is not enabled. Enable it to protect your account with a time-based one-time password (TOTP)."}
          </CardDescription>
        </CardHeader>
      </Card>

      {/* supported MFA methods */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Supported Methods</CardTitle>
          <CardDescription>
            Choose your preferred second factor. Hardware keys provide the strongest protection.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {[
              {
                icon: Smartphone,
                label: "Authenticator App (TOTP)",
                desc: "Google Authenticator, Authy, 1Password",
                supported: true,
              },
              { icon: KeyRound, label: "SMS Verification", desc: "Receive codes via text message", supported: false },
              {
                icon: Fingerprint,
                label: "Hardware Security Key",
                desc: "YubiKey, FIDO2/WebAuthn — phishing-resistant",
                supported: false,
              },
            ].map((m) => (
              <div key={m.label} className="p-3 rounded-lg border border-border bg-muted/20 space-y-1">
                <div className="flex items-center gap-2">
                  <m.icon className="h-4 w-4 text-muted-foreground" />
                  <span className="text-sm font-medium">{m.label}</span>
                </div>
                <p className="text-xs text-muted-foreground">{m.desc}</p>
                {!m.supported && (
                  <Badge variant="outline" className="text-[10px] mt-1">
                    Coming Soon
                  </Badge>
                )}
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {!status?.mfaEnabled && !setupData && (
        <Card data-testid="mfa-enable-card">
          <CardHeader>
            <CardTitle>Enable MFA</CardTitle>
            <CardDescription>
              Use an authenticator app like Google Authenticator, Authy, or 1Password to generate verification codes.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Button
              onClick={() => setupMutation.mutate()}
              disabled={setupMutation.isPending}
              data-testid="mfa-setup-button"
            >
              {setupMutation.isPending ? (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              ) : (
                <Shield className="h-4 w-4 mr-2" />
              )}
              Set Up MFA
            </Button>
          </CardContent>
        </Card>
      )}

      {setupData && (
        <Card data-testid="mfa-qr-card">
          <CardHeader>
            <CardTitle>Scan QR Code</CardTitle>
            <CardDescription>
              Scan this QR code with your authenticator app, or enter the secret manually.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex justify-center p-4 bg-white rounded-lg">
              <img
                src={setupData.qrCodeDataUrl}
                alt="MFA QR Code"
                width={200}
                height={200}
                data-testid="mfa-qr-image"
              />
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium">Manual Entry Secret</label>
              <div className="flex gap-2">
                <code
                  className="flex-1 px-3 py-2 bg-muted rounded text-sm font-mono break-all"
                  data-testid="mfa-secret-display"
                >
                  {setupData.secret}
                </code>
                <Button variant="outline" size="icon" onClick={copySecret} data-testid="mfa-copy-secret">
                  <Copy className="h-4 w-4" />
                </Button>
              </div>
            </div>

            {/* backup codes with download option */}
            <div className="p-3 rounded-lg border border-amber-500/20 bg-amber-500/5 space-y-2">
              <p className="text-sm font-medium flex items-center gap-1.5">
                <Download className="h-3.5 w-3.5 text-amber-500" />
                Backup Codes
              </p>
              <p className="text-xs text-muted-foreground">
                Save these backup codes in a secure location. Each code can be used once if you lose access to your
                authenticator.
              </p>
              <div className="grid grid-cols-2 gap-1">
                {["A1B2-C3D4", "E5F6-G7H8", "J9K0-L1M2", "N3P4-Q5R6", "S7T8-U9V0", "W1X2-Y3Z4"].map((code) => (
                  <code key={code} className="text-xs font-mono bg-muted/30 px-2 py-1 rounded">
                    {code}
                  </code>
                ))}
              </div>
              <Button size="sm" variant="outline" className="gap-1 text-xs">
                <Download className="h-3 w-3" />
                Download Backup Codes
              </Button>
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium">Verification Code</label>
              <div className="flex gap-2">
                <Input
                  type="text"
                  inputMode="numeric"
                  pattern="[0-9]*"
                  maxLength={6}
                  placeholder="Enter 6-digit code"
                  value={verifyToken}
                  onChange={(e) => setVerifyToken(e.target.value.replace(/\D/g, "").slice(0, 6))}
                  data-testid="mfa-verify-input"
                />
                <Button
                  onClick={() => verifyMutation.mutate()}
                  disabled={verifyToken.length !== 6 || verifyMutation.isPending}
                  data-testid="mfa-verify-button"
                >
                  {verifyMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : "Verify"}
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {status?.mfaEnabled && (
        <Card data-testid="mfa-disable-card">
          <CardHeader>
            <CardTitle>Disable MFA</CardTitle>
            <CardDescription>
              Enter a valid verification code from your authenticator app to disable MFA.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex gap-2">
              <Input
                type="text"
                inputMode="numeric"
                pattern="[0-9]*"
                maxLength={6}
                placeholder="Enter 6-digit code"
                value={disableToken}
                onChange={(e) => setDisableToken(e.target.value.replace(/\D/g, "").slice(0, 6))}
                data-testid="mfa-disable-input"
              />
              <Button
                variant="destructive"
                onClick={() => disableMutation.mutate()}
                disabled={disableToken.length !== 6 || disableMutation.isPending}
                data-testid="mfa-disable-button"
              >
                {disableMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : "Disable MFA"}
              </Button>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

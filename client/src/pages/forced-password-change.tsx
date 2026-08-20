import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, CheckCircle2, Loader2, LockKeyhole, LogOut } from "lucide-react";
import { useLocation } from "wouter";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useAuth } from "@/hooks/use-auth";
import {
  buildChangePasswordInput,
  resolveForcedPasswordChangeAccountState,
  resolveLocalPasswordState,
  type ChangePasswordInput,
} from "@/lib/forced-password-change";
import { apiRequest } from "@/lib/queryClient";

export default function ForcedPasswordChangePage() {
  const { user, isLoading, isError, isFetching, refetch, logoutAsync, isLoggingOut } = useAuth();
  const [, setLocation] = useLocation();
  const queryClient = useQueryClient();
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [validationError, setValidationError] = useState<string | null>(null);
  const [logoutError, setLogoutError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  const changePasswordMutation = useMutation({
    mutationFn: async (input: ChangePasswordInput) => {
      const response = await apiRequest("POST", "/api/auth/change-password", input);
      return response.json();
    },
    onSuccess: async () => {
      setValidationError(null);
      setSuccess(true);
      await queryClient.invalidateQueries({ queryKey: ["/api/auth/user"] });
    },
  });

  function handleSubmit(event: React.FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    setValidationError(null);

    if (hasLocalPassword === undefined) {
      setValidationError("We are still checking your account. Please wait before changing your password.");
      return;
    }
    if (newPassword.length < 8) {
      setValidationError("Password must be at least 8 characters.");
      return;
    }
    if (newPassword !== confirmPassword) {
      setValidationError("New passwords do not match.");
      return;
    }

    changePasswordMutation.mutate(
      buildChangePasswordInput({
        currentPassword,
        newPassword,
        hasLocalPassword,
      }),
    );
  }

  async function handleLogout(): Promise<void> {
    setLogoutError(null);
    try {
      await logoutAsync();
      setLocation("/login");
    } catch (error) {
      setLogoutError(error instanceof Error ? error.message : "Unable to sign out. Please try again.");
    }
  }

  const errorMessage = validationError ?? changePasswordMutation.error?.message ?? null;
  const accountState = resolveForcedPasswordChangeAccountState({ user, isLoading, isError });
  const hasLocalPassword = resolveLocalPasswordState({ user, isLoading, isError });

  return (
    <div
      className="min-h-screen flex items-center justify-center bg-[#FFF8F0] dark:bg-[#0a0f1e] p-4"
      data-testid="forced-password-change-page"
    >
      <Card className="w-full max-w-md border-[2.5px] border-[#1e293b] dark:border-[#334155] shadow-[6px_6px_0px_#1e293b] dark:shadow-[6px_6px_0px_rgba(6,182,212,0.3)] bg-white dark:bg-[#111827]">
        <CardHeader className="space-y-3">
          <div className="w-10 h-10 rounded-xl border-2 border-[#1e293b] dark:border-cyan-500/30 flex items-center justify-center bg-gradient-to-br from-cyan-50 to-white dark:from-cyan-500/10 dark:to-transparent">
            <LockKeyhole className="h-5 w-5 text-cyan-600 dark:text-cyan-400" />
          </div>
          <CardTitle className="text-xl font-extrabold text-[#1e293b] dark:text-[#e2e8f0]">
            {success ? "Password changed" : "Change your password"}
          </CardTitle>
          <CardDescription className="text-[#64748b] dark:text-[#94a3b8]">
            {success
              ? "Your account is ready. SecureNexus is loading your workspace."
              : accountState === "error"
                ? "SecureNexus could not verify your account's password state. Retry the check before changing your password."
                : hasLocalPassword === undefined
                  ? "SecureNexus is checking your account's password state before allowing this security step."
                  : hasLocalPassword === false
                    ? "Your account does not have a local password. Set one now to complete the required security step before using SecureNexus."
                    : "For your security, change the temporary password before using SecureNexus."}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {success ? (
            <div className="flex items-center gap-3 p-4 rounded-xl border-2 border-emerald-300 dark:border-emerald-500/30 bg-emerald-50 dark:bg-emerald-500/10">
              <CheckCircle2 className="h-5 w-5 text-emerald-600 dark:text-emerald-400" />
              <p className="text-sm font-medium text-emerald-700 dark:text-emerald-300">
                Password updated successfully.
              </p>
            </div>
          ) : accountState === "error" ? (
            <div
              className="space-y-3 p-4 rounded-xl border-2 border-red-300 dark:border-red-500/30 bg-red-50 dark:bg-red-500/10"
              role="alert"
              aria-live="polite"
            >
              <div className="flex items-start gap-2 text-red-700 dark:text-red-300">
                <AlertTriangle className="h-5 w-5 mt-0.5 shrink-0" />
                <div>
                  <p className="text-sm font-semibold">We could not check your account.</p>
                  <p className="text-sm">
                    Your password state is unavailable right now. Retry the check before changing your password.
                  </p>
                </div>
              </div>
              <Button type="button" variant="outline" onClick={() => void refetch()} disabled={isFetching}>
                {isFetching && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                {isFetching ? "Retrying account check" : "Retry account check"}
              </Button>
            </div>
          ) : hasLocalPassword === undefined ? (
            <div
              className="flex items-center gap-3 p-4 rounded-xl border-2 border-slate-300 dark:border-slate-600 bg-slate-50 dark:bg-slate-800/50"
              role="status"
              aria-live="polite"
            >
              <Loader2 className="h-5 w-5 animate-spin text-slate-500 dark:text-slate-400" />
              <p className="text-sm font-medium text-slate-600 dark:text-slate-300">
                Checking your account before enabling password changes.
              </p>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="space-y-4">
              {errorMessage && (
                <div
                  className="flex items-start gap-2 p-3 rounded-xl border-2 border-red-300 dark:border-red-500/30 bg-red-50 dark:bg-red-500/10 text-red-600 dark:text-red-400 text-sm font-medium"
                  role="alert"
                >
                  <AlertTriangle className="h-4 w-4 mt-0.5 shrink-0" />
                  <span>{errorMessage}</span>
                </div>
              )}

              {hasLocalPassword === true && (
                <div className="space-y-2">
                  <Label htmlFor="current-password">Current password</Label>
                  <Input
                    id="current-password"
                    type="password"
                    autoComplete="current-password"
                    value={currentPassword}
                    onChange={(event) => setCurrentPassword(event.target.value)}
                    disabled={changePasswordMutation.isPending}
                  />
                </div>
              )}

              <div className="space-y-2">
                <Label htmlFor="new-password">New password</Label>
                <Input
                  id="new-password"
                  type="password"
                  autoComplete="new-password"
                  value={newPassword}
                  onChange={(event) => setNewPassword(event.target.value)}
                  disabled={changePasswordMutation.isPending}
                  aria-describedby="new-password-help"
                />
                <p id="new-password-help" className="text-xs text-muted-foreground">
                  Use at least 8 characters and meet any organization password requirements.
                </p>
              </div>

              <div className="space-y-2">
                <Label htmlFor="confirm-password">Confirm new password</Label>
                <Input
                  id="confirm-password"
                  type="password"
                  autoComplete="new-password"
                  value={confirmPassword}
                  onChange={(event) => setConfirmPassword(event.target.value)}
                  disabled={changePasswordMutation.isPending}
                />
              </div>

              <Button type="submit" className="w-full" disabled={changePasswordMutation.isPending}>
                {changePasswordMutation.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                Change password
              </Button>
            </form>
          )}
          <div className="mt-6 space-y-2 border-t border-slate-200 pt-4 dark:border-slate-700">
            <Button
              type="button"
              variant="ghost"
              className="w-full"
              onClick={() => void handleLogout()}
              disabled={isLoggingOut}
            >
              {isLoggingOut && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
              {!isLoggingOut && <LogOut className="h-4 w-4 mr-2" />}
              {isLoggingOut ? "Signing out" : "Sign out"}
            </Button>
            {logoutError && (
              <p className="text-sm text-center text-red-600 dark:text-red-400" role="alert">
                {logoutError}
              </p>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

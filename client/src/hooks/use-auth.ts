import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import type { AuthenticatedUser } from "@shared/models/auth";
import { extractApiError, clearCsrfTokenCache, fetchCsrfToken } from "../lib/queryClient";

async function fetchUser(): Promise<AuthenticatedUser | null> {
  const response = await fetch("/api/auth/user", {
    credentials: "include",
  });

  if (response.status === 401) {
    return null;
  }

  if (!response.ok) {
    throw new Error(`${response.status}: ${response.statusText}`);
  }

  const body = await response.json();
  return body.data ?? null;
}

async function loginFn(data: { email: string; password: string }): Promise<AuthenticatedUser> {
  const response = await fetch("/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify(data),
  });
  if (!response.ok) {
    const err = await response.json().catch(() => null);
    throw new Error(extractApiError(err, "Login failed"));
  }
  const body = await response.json();
  return body.data;
}

async function registerFn(data: {
  email: string;
  password: string;
  firstName?: string;
  lastName?: string;
}): Promise<AuthenticatedUser> {
  const response = await fetch("/api/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify(data),
  });
  if (!response.ok) {
    const err = await response.json().catch(() => null);
    throw new Error(extractApiError(err, "Registration failed"));
  }
  const body = await response.json();
  return body.data;
}

async function logoutFn(): Promise<void> {
  const csrfToken = await fetchCsrfToken();
  const response = await fetch("/api/logout", {
    method: "POST",
    headers: csrfToken ? { "X-CSRF-Token": csrfToken } : undefined,
    credentials: "include",
  });
  if (!response.ok) {
    throw new Error("Unable to sign out. Please try again.");
  }
  clearCsrfTokenCache();
}

export function useAuth() {
  const queryClient = useQueryClient();
  const {
    data: user,
    isLoading,
    isError,
    isFetching,
    refetch,
  } = useQuery<AuthenticatedUser | null>({
    queryKey: ["/api/auth/user"],
    queryFn: fetchUser,
    retry: false,
    staleTime: 1000 * 60 * 5,
  });

  const loginMutation = useMutation({
    mutationFn: loginFn,
    onSuccess: (user) => {
      queryClient.setQueryData(["/api/auth/user"], user);
    },
  });

  const registerMutation = useMutation({
    mutationFn: registerFn,
    onSuccess: (user) => {
      queryClient.setQueryData(["/api/auth/user"], user);
    },
  });

  const logoutMutation = useMutation({
    mutationFn: logoutFn,
    onSuccess: () => {
      queryClient.setQueryData(["/api/auth/user"], null);
    },
  });

  return {
    user,
    isLoading,
    isError,
    isFetching,
    refetch,
    isAuthenticated: !!user,
    login: loginMutation.mutateAsync,
    loginError: loginMutation.error,
    isLoggingIn: loginMutation.isPending,
    register: registerMutation.mutateAsync,
    registerError: registerMutation.error,
    isRegistering: registerMutation.isPending,
    logout: logoutMutation.mutate,
    logoutAsync: logoutMutation.mutateAsync,
    isLoggingOut: logoutMutation.isPending,
  };
}

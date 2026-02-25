import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import type { User } from "@shared/models/auth";

function extractEnvelopeError(body: unknown, fallback: string): string {
  if (typeof body === "object" && body !== null) {
    const envelope = body as { errors?: { message?: string }[] | null; message?: string };
    if (Array.isArray(envelope.errors) && envelope.errors.length > 0 && envelope.errors[0].message) {
      return envelope.errors[0].message;
    }
    if (envelope.message) return envelope.message;
  }
  return fallback;
}

async function fetchUser(): Promise<User | null> {
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
  return body.data !== undefined ? body.data : body;
}

async function loginFn(data: { email: string; password: string }): Promise<User> {
  const response = await fetch("/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify(data),
  });
  if (!response.ok) {
    const err = await response.json().catch(() => null);
    throw new Error(extractEnvelopeError(err, "Login failed"));
  }
  const body = await response.json();
  return body.data !== undefined ? body.data : body;
}

async function registerFn(data: {
  email: string;
  password: string;
  firstName?: string;
  lastName?: string;
}): Promise<User> {
  const response = await fetch("/api/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify(data),
  });
  if (!response.ok) {
    const err = await response.json().catch(() => null);
    throw new Error(extractEnvelopeError(err, "Registration failed"));
  }
  const body = await response.json();
  return body.data !== undefined ? body.data : body;
}

async function logoutFn(): Promise<void> {
  await fetch("/api/logout", { method: "POST", credentials: "include" });
}

export function useAuth() {
  const queryClient = useQueryClient();
  const { data: user, isLoading } = useQuery<User | null>({
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
    isAuthenticated: !!user,
    login: loginMutation.mutateAsync,
    loginError: loginMutation.error,
    isLoggingIn: loginMutation.isPending,
    register: registerMutation.mutateAsync,
    registerError: registerMutation.error,
    isRegistering: registerMutation.isPending,
    logout: logoutMutation.mutate,
    isLoggingOut: logoutMutation.isPending,
  };
}

import { getLoginUrl } from "@/const";
import { trpc } from "@/lib/trpc";
import { TRPCClientError } from "@trpc/client";
import { useCallback, useEffect, useMemo } from "react";

type UseAuthOptions = {
  redirectOnUnauthenticated?: boolean;
  redirectPath?: string;
};

const DEMO_USER = {
  id: 0,
  openId: "demo-user",
  name: "Utilisateur Démo",
  email: "demo@medicm.pro",
  role: "admin",
  isActive: true,
  healthCenterId: 1,
};

export function useAuth(options?: UseAuthOptions) {
  const { redirectOnUnauthenticated = false, redirectPath = getLoginUrl() } =
    options ?? {};
  const utils = trpc.useUtils();

  const isDemoMode = typeof window !== "undefined" && localStorage.getItem("demoMode") === "true";

  const meQuery = trpc.auth.me.useQuery(undefined, {
    retry: false,
    refetchOnWindowFocus: false,
    enabled: !isDemoMode,
  });

  const logoutMutation = trpc.auth.logout.useMutation({
    onSuccess: () => {
      utils.auth.me.setData(undefined, null);
    },
  });

  const logout = useCallback(async () => {
    if (isDemoMode) {
      localStorage.removeItem("demoMode");
      window.location.href = "/";
      return;
    }
    try {
      await logoutMutation.mutateAsync();
    } catch (error: unknown) {
      if (
        error instanceof TRPCClientError &&
        error.data?.code === "UNAUTHORIZED"
      ) {
        return;
      }
      throw error;
    } finally {
      utils.auth.me.setData(undefined, null);
      await utils.auth.me.invalidate();
    }
  }, [logoutMutation, utils, isDemoMode]);

  const state = useMemo(() => {
    const user = isDemoMode ? DEMO_USER : (meQuery.data ?? null);
    localStorage.setItem(
      "manus-runtime-user-info",
      JSON.stringify(user)
    );
    return {
      user,
      loading: !isDemoMode && (meQuery.isLoading || logoutMutation.isPending),
      error: meQuery.error ?? logoutMutation.error ?? null,
      isAuthenticated: Boolean(user),
      isDemoMode,
    };
  }, [
    meQuery.data,
    meQuery.error,
    meQuery.isLoading,
    logoutMutation.error,
    logoutMutation.isPending,
    isDemoMode,
  ]);

  useEffect(() => {
    if (!redirectOnUnauthenticated) return;
    if (state.loading) return;
    if (state.user) return;
    if (typeof window === "undefined") return;
    if (window.location.pathname === redirectPath) return;

    window.location.href = redirectPath
  }, [
    redirectOnUnauthenticated,
    redirectPath,
    state.loading,
    state.user,
  ]);

  return {
    ...state,
    refresh: () => !isDemoMode && meQuery.refetch(),
    logout,
  };
}

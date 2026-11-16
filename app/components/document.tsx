import { createContext, useContext, useSyncExternalStore } from "react";

export const NonceContext = createContext<string | undefined>(undefined);

export function useNonce(): string | undefined {
  return useContext(NonceContext);
}

function subscribeNever(): () => void {
  return () => {};
}

export function useRenderingDocument(): boolean {
  return useSyncExternalStore(
    subscribeNever,
    () => false,
    () => true,
  );
}

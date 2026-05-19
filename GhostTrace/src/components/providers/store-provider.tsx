'use client';

import { useEffect, type ReactNode } from 'react';
import { useStore } from '@/lib/mock/store';
import { bootstrapFromApi } from '@/lib/api/sync';
import { isApiEnabled } from '@/lib/api/config';

/** Hidrata API keys e sincroniza com FastAPI após rehydrate do Zustand. */
export function StoreProvider({ children }: { children: ReactNode }) {
  const hydrate = useStore((s) => s.hydrateAIProviders);

  useEffect(() => {
    hydrate();

    function runBootstrap() {
      if (isApiEnabled()) void bootstrapFromApi();
    }

    if (useStore.persist.hasHydrated()) {
      runBootstrap();
    }
    const unsub = useStore.persist.onFinishHydration(runBootstrap);
    return unsub;
  }, [hydrate]);

  return <>{children}</>;
}
